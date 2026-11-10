import Foundation
import Testing
@testable import HetznerKit

actor FakeSource: VulnerabilitySource {
    nonisolated let name: SourceName
    private let answers: [PackageQuery: [Advisory]]
    private let failure: SecuritySourceError?
    private(set) var calls: [[PackageQuery]] = []

    init(_ name: SourceName = .osv, answers: [PackageQuery: [Advisory]], failure: SecuritySourceError? = nil) {
        self.name = name
        self.answers = answers
        self.failure = failure
    }

    nonisolated func supports(_ query: PackageQuery) -> Bool {
        name == .osv || !query.isOperatingSystem
    }

    func lookup(_ queries: [PackageQuery]) async throws -> SourceLookup {
        calls.append(queries)
        if let failure { throw failure }
        return SourceLookup(advisories: Dictionary(uniqueKeysWithValues: queries.map { ($0, answers[$0] ?? []) }))
    }
}

actor FakeEnricher: EnrichmentSource {
    nonisolated let name = SourceName.kev
    private(set) var asked: Set<String> = []

    func enrichment(for cves: Set<String>) async throws -> EnrichmentLookup {
        asked = cves
        return EnrichmentLookup(values: ["CVE-2024-6119": Enrichment(knownExploited: KnownExploited(dateAdded: "2026-10-01", ransomware: false))])
    }
}

struct ScannerTests {
    static let openssl = PackageQuery(ecosystem: "Ubuntu:24.04:LTS", name: "openssl", version: "3.0.13-0ubuntu3.1")
    static let lodash = PackageQuery(ecosystem: "npm", name: "lodash", version: "4.17.20")

    static func report(updates: [AgentSecurity.Update], extra: [AgentSecurity.Package] = []) -> AgentSecurity {
        AgentSecurity(
            version: "0.3.0", time: date("2026-10-26T09:00:00Z"),
            os: .init(id: "ubuntu", versionID: "24.04", name: "Ubuntu 24.04.3 LTS", like: ["debian"]),
            packages: .init(manager: "dpkg", items: [
                .init(name: "libssl3t64", version: "3.0.13-0ubuntu3.1", source: "openssl", sourceVersion: "3.0.13-0ubuntu3.1"),
                .init(name: "openssl", version: "3.0.13-0ubuntu3.1", source: "openssl", sourceVersion: "3.0.13-0ubuntu3.1"),
            ] + extra),
            updates: .init(items: updates),
            checks: [SecurityCheck(id: SecurityCheck.ufw, status: .fail, title: "ufw firewall is off", detail: "ENABLED=no")],
            listening: [.init(address: "0.0.0.0", port: 5432), .init(address: "::", port: 7311)],
            projects: [.init(name: "app", path: "/srv/app", lockfiles: [
                .init(path: "package-lock.json", ecosystem: "npm", packages: [.init(name: "lodash", version: "4.17.20")]),
            ])]
        )
    }

    @Test func scansManyServersWithEachQueryOnce() async throws {
        let cve = Advisory(id: "CVE-2024-6119", aliases: ["UBUNTU-CVE-2024-6119"], summary: "x", severity: .medium, fixedVersion: "3.0.13-0ubuntu3.4")
        let ghsa = Advisory(id: "CVE-2021-23337", aliases: ["GHSA-35jh-r3h4-6jhm"], severity: .high, fixedVersion: "4.17.21")
        let osv = FakeSource(answers: [Self.openssl: [cve], Self.lodash: [ghsa]])
        let socket = FakeSource(.socket, answers: [Self.lodash: [Advisory(id: "SOCKET-didYouMean", severity: .medium, kind: .supplyChain, source: .socket)]])
        let enricher = FakeEnricher()
        let scanner = SecurityScanner(sources: [osv, socket], enrichers: [enricher], clock: { date("2026-10-26T10:00:00Z") })

        let fixing = AgentSecurity.Update(name: "libssl3t64", current: "3.0.13-0ubuntu3.1", available: "3.0.13-0ubuntu3.5", security: true)
        let targets = [
            SecurityTarget(serverID: 1, report: Self.report(updates: [fixing]), server: nil, firewalls: nil),
            SecurityTarget(serverID: 2, report: Self.report(updates: [], extra: [.init(name: "vim", version: "2:9.1.0016-1ubuntu7")]), server: nil, firewalls: nil),
        ]

        let offline = await scanner.scan(targets, settings: SecurityScanSettings(onlineChecks: false))
        #expect(await osv.calls.isEmpty)
        #expect(offline[1]?.findings.isEmpty == true)
        #expect(offline[1]?.pendingSecurityUpdates == 1)
        #expect(offline[1]?.sources.allSatisfy { $0.state == .skipped } == true)

        let results = await scanner.scan(
            targets, settings: SecurityScanSettings(onlineChecks: true),
            socket: SocketCredentials(token: "t", organization: "o")
        )
        let calls = await osv.calls
        #expect(calls.count == 1)
        #expect(calls[0].count == 3)
        #expect(Set(calls[0]).count == 3)
        #expect(await socket.calls.first == [Self.lodash])
        #expect(await enricher.asked == ["CVE-2024-6119", "CVE-2021-23337"])

        let first = try #require(results[1])
        let second = try #require(results[2])
        let opensslFinding = try #require(first.findings.first { $0.package.name == "openssl" })
        #expect(opensslFinding.package.binaries == ["libssl3t64", "openssl"])
        #expect(opensslFinding.advisories[0].isExploited)
        #expect(opensslFinding.advisories[0].severity == .high)
        #expect(opensslFinding.fixPending)
        #expect(opensslFinding.fixStatus(of: opensslFinding.advisories[0]) == .pending)
        #expect(second.findings.first { $0.package.name == "openssl" }?.fixStatus(of: cve) == .available)
        #expect(first.findings.first?.package.name == "openssl")

        let lodashFinding = try #require(first.findings.first { $0.package.name == "lodash" })
        #expect(lodashFinding.package.location == .lockfile(project: "app", path: "package-lock.json"))
        #expect(Set(lodashFinding.advisories.map(\.id)) == ["CVE-2021-23337", "SOCKET-didYouMean"])

        #expect(first.counts.high == 2)
        #expect(first.counts.medium == 1)
        #expect(first.exploitedCount == 1)
        #expect(first.fixableCount == 2)
        #expect(first.pendingFixCount == 1)
        #expect(first.source(.osv)?.state == .ok)
        #expect(first.source(.kev)?.state == .ok)
        #expect(first.source(.epss)?.state == .skipped)
        #expect(first.osEcosystem == "Ubuntu:24.04:LTS")
        #expect(first.checks.contains { $0.id == SecurityCheck.endOfLife && $0.status == .pass })

        let encoded = try JSONEncoder().encode(first)
        #expect(try JSONDecoder().decode(SecurityResult.self, from: encoded) == first)
    }

    @Test func failingSourceIsReportedAndScanContinues() async throws {
        let osv = FakeSource(answers: [:], failure: .network(host: "api.osv.dev"))
        let scanner = SecurityScanner(sources: [osv])
        let results = await scanner.scan(
            [SecurityTarget(serverID: 1, report: Self.report(updates: []), server: nil, firewalls: nil)],
            settings: SecurityScanSettings(onlineChecks: true)
        )
        #expect(results[1]?.source(.osv)?.state == .failed)
        #expect(results[1]?.source(.osv)?.message == "Could not reach api.osv.dev.")
        #expect(results[1]?.source(.socket)?.message == "No Socket API key.")
        #expect(results[1]?.findings.isEmpty == true)
    }
}

struct HostCheckTests {
    static let now = date("2026-10-26T10:00:00Z")

    static func host(firewalls: [Int64]?) -> Server {
        let base = server(1)
        return Server(
            id: 1, name: "web-1", status: .running, created: base.created,
            publicNet: PublicNet(ipv4: nil, ipv6: nil, floatingIps: [], firewalls: firewalls.map { $0.map { try! JSONDecoder().decode(
                PublicNet.FirewallRef.self, from: Data(#"{"id":\#($0),"status":"applied"}"#.utf8)) } }),
            serverType: base.serverType, location: base.location
        )
    }

    static func cloudFirewall(port: String?, sources: [String]) -> Firewall {
        Firewall(id: 7, name: "edge", created: now, rules: [
            .init(direction: "in", protocolName: "tcp", port: "22", sourceIps: ["0.0.0.0/0", "::/0"], destinationIps: []),
            .init(direction: "in", protocolName: "tcp", port: port, sourceIps: sources, destinationIps: []),
        ], appliedTo: [])
    }

    static func report(ufw: SecurityCheck.Status?, listening: [AgentSecurity.Listener], os: AgentSecurity.OS = .init(id: "ubuntu", versionID: "24.04")) -> AgentSecurity {
        AgentSecurity(
            version: "0.3.0", time: now, os: os, packages: .init(manager: "dpkg"), updates: .init(),
            checks: ufw.map { [SecurityCheck(id: SecurityCheck.ufw, status: $0, title: "", detail: "")] } ?? [],
            listening: listening
        )
    }

    static let listening: [AgentSecurity.Listener] = [
        .init(address: "0.0.0.0", port: 5432), .init(address: "::", port: 5432), .init(address: "0.0.0.0", port: 22),
        .init(address: "::", port: 7311), .init(address: "127.0.0.1", port: 6379), .init(address: "10.0.0.2", port: 3306),
        .init(address: "0.0.0.0", port: 8080), .init(address: "0.0.0.0", port: 4000),
    ]

    @Test func firewallNoneFailsOnlyWithoutCloudFirewallAndUfw() {
        let none = HostChecks.firewall(report: Self.report(ufw: .fail, listening: []), server: Self.host(firewalls: []), firewalls: [])
        #expect(none?.status == .fail)
        #expect(none?.title == "No firewall is active")
        #expect(none?.detail == "No Hetzner Cloud Firewall is attached and ufw is off.")
        #expect(HostChecks.firewall(report: Self.report(ufw: nil, listening: []), server: Self.host(firewalls: []), firewalls: [])?.status == .fail)
        #expect(HostChecks.firewall(report: Self.report(ufw: .pass, listening: []), server: Self.host(firewalls: []), firewalls: [])?.status == .pass)
        let cloud = HostChecks.firewall(report: Self.report(ufw: .fail, listening: []), server: Self.host(firewalls: [7]),
                                        firewalls: [Self.cloudFirewall(port: "80", sources: ["0.0.0.0/0"])])
        #expect(cloud?.status == .pass)
        #expect(cloud?.detail == "Hetzner Cloud Firewall: edge.")
        #expect(HostChecks.firewall(report: Self.report(ufw: .fail, listening: []), server: nil, firewalls: nil) == nil)
    }

    @Test func exposedPortsWithoutCloudFirewall() {
        let checks = HostChecks.exposedPorts(report: Self.report(ufw: .fail, listening: Self.listening), server: Self.host(firewalls: []),
                                             firewalls: [], agentPort: 7311)
        #expect(checks.map(\.id) == ["ports.exposed:5432", "ports.exposed:8080"])
        #expect(checks[0].status == .fail)
        #expect(checks[0].title == "PostgreSQL port 5432 is open to the internet")
        #expect(!checks[0].informational)
        #expect(checks[1].informational)
    }

    @Test func exposedPortsWithCloudFirewallRules() {
        let blocked = HostChecks.exposedPorts(report: Self.report(ufw: .fail, listening: Self.listening), server: Self.host(firewalls: [7]),
                                              firewalls: [Self.cloudFirewall(port: "80", sources: ["0.0.0.0/0"])], agentPort: 7311)
        #expect(blocked.map(\.id) == ["ports.exposed"])
        #expect(blocked[0].status == .pass)

        let open = HostChecks.exposedPorts(report: Self.report(ufw: .fail, listening: Self.listening), server: Self.host(firewalls: [7]),
                                           firewalls: [Self.cloudFirewall(port: "5000-6000", sources: ["::/0"])], agentPort: 7311)
        #expect(open.map(\.id) == ["ports.exposed:5432"])
        #expect(open[0].status == .fail)

        let office = HostChecks.exposedPorts(report: Self.report(ufw: .fail, listening: Self.listening), server: Self.host(firewalls: [7]),
                                             firewalls: [Self.cloudFirewall(port: "5432", sources: ["203.0.113.0/24"])], agentPort: 7311)
        #expect(office.map(\.status) == [.pass])

        let unknownRules = HostChecks.exposedPorts(report: Self.report(ufw: .fail, listening: Self.listening), server: Self.host(firewalls: [7]),
                                                   firewalls: nil, agentPort: 7311)
        #expect(unknownRules.first?.status == .unknown)

        let ufwOn = HostChecks.exposedPorts(report: Self.report(ufw: .pass, listening: Self.listening), server: Self.host(firewalls: []),
                                            firewalls: [], agentPort: 7311)
        #expect(ufwOn.first?.status == .unknown)
    }

    @Test func endOfLifeUsesTheBundledTable() {
        let focal = ReleaseSupport.lookup(id: "ubuntu", versionID: "20.04")?.check(now: Self.now)
        #expect(focal?.status == .fail)
        #expect(focal?.title == "Ubuntu 20.04 no longer gets security updates")
        #expect(focal?.detail.contains("May 2025") == true)
        #expect(ReleaseSupport.lookup(id: "ubuntu", versionID: "24.04")?.check(now: Self.now).status == .pass)
        #expect(ReleaseSupport.lookup(id: "ubuntu", versionID: "25.10")?.check(now: Self.now).status == .fail)
        let bookworm = ReleaseSupport.lookup(id: "debian", versionID: "12")?.check(now: Self.now)
        #expect(bookworm?.status == .pass)
        #expect(bookworm?.title == "Debian 12 gets security updates from Debian LTS")
        #expect(ReleaseSupport.lookup(id: "debian", versionID: "11")?.check(now: Self.now).status == .fail)
        #expect(ReleaseSupport.lookup(id: "debian", versionID: "13")?.check(now: Self.now).title == "Debian 13 gets security updates")
        #expect(ReleaseSupport.lookup(id: "fedora", versionID: "40") == nil)
        #expect(ReleaseSupport.lookup(id: "ubuntu", versionID: "99.04") == nil)
    }
}
