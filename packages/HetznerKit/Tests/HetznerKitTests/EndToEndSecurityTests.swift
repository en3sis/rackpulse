import Foundation
import Testing
@testable import HetznerKit

final class CountingTransport: HTTPTransport, @unchecked Sendable {
    private let lock = NSLock()
    private let inner: HTTPTransport
    private var hosts: [String: Int] = [:]

    init(_ inner: HTTPTransport = URLSessionTransport()) {
        self.inner = inner
    }

    var counts: [String: Int] { lock.withLock { hosts } }

    func reset() {
        lock.withLock { hosts = [:] }
    }

    func send(_ request: URLRequest) async throws -> (Data, HTTPURLResponse) {
        lock.withLock { hosts[request.url?.host() ?? "?", default: 0] += 1 }
        return try await inner.send(request)
    }
}

struct EndToEndSecurityTests {
    static let environment = ProcessInfo.processInfo.environment
    static let serverID: Int64 = 4242

    static func fabricatedServer() -> Server {
        Server(
            id: serverID,
            name: "e2e-noble",
            status: .running,
            created: date("2026-01-01T00:00:00Z"),
            publicNet: PublicNet(ipv4: nil, ipv6: nil, floatingIps: [], firewalls: []),
            serverType: ServerType(id: 1, name: "cax11", description: "CAX11", cores: 2, memory: 4, disk: 40, prices: [price("0.01", "5")]),
            location: Location(id: 1, name: "fsn1")
        )
    }

    static func describe(_ finding: Finding) -> String {
        let status: String
        if finding.fixPending {
            status = "pending \(finding.pendingVersion ?? "")"
        } else if let fixed = finding.fixedVersion {
            status = "fix \(fixed)"
        } else {
            status = "no fix"
        }
        let top = finding.visibleAdvisories.first ?? finding.advisories.first
        let kev = finding.knownExploited ? " KEV" : ""
        let epss = finding.highestEPSS.map { String(format: " EPSS %.3f", $0.probability) } ?? ""
        let place = finding.package.location == .system ? "system" : "lockfile"
        return "\(finding.severity.rawValue.padding(toLength: 8, withPad: " ", startingAt: 0)) \(finding.package.name) \(finding.package.version) [\(place)] "
            + "\(finding.visibleAdvisories.count)/\(finding.advisories.count) advisories, top \(top?.id ?? "-"), \(status)\(kev)\(epss)"
    }

    @Test(.enabled(if: environment["RACKPULSE_E2E"] == "1"))
    func agentToAlerts() async throws {
        let host = try #require(Self.environment["RACKPULSE_E2E_HOST"])
        let port = try #require(Self.environment["RACKPULSE_E2E_PORT"].flatMap(Int.init))
        let token = try #require(Self.environment["RACKPULSE_E2E_TOKEN"])
        let endpoint = AgentEndpoint(host: host, port: port)
        let clock = ContinuousClock()
        let started = clock.now

        await #expect(throws: AgentError.wrongKey) {
            try await AgentClient.pair(endpoint: endpoint, token: AgentClient.newToken())
        }
        let pairing = try await AgentClient.pair(endpoint: endpoint, token: token)
        #expect(pairing.version == "0.3.0")
        let wrongPin = AgentClient(endpoint: endpoint, token: token, fingerprint: String(repeating: "0", count: 64))
        await #expect(throws: AgentError.certificateChanged) { try await wrongPin.security() }

        let client = AgentClient(endpoint: endpoint, token: token, fingerprint: pairing.fingerprint)
        let report = try await client.security()
        let snapshot = try await client.snapshot()
        let fetched = clock.now

        let server = Self.fabricatedServer()
        let target = SecurityTarget(serverID: server.id, report: report, server: server, firewalls: [], agentPort: AgentEndpoint.defaultPort)
        let shared = Self.environment["RACKPULSE_E2E_CACHE"].map { URL(filePath: $0) }
        let cache = SecurityCache(database: try shared.map { try LocalDatabase(url: $0.appending(path: "rackpulse.sqlite")) } ?? LocalDatabase())
        let transport = CountingTransport()
        let scanner = SecurityScanner(cache: cache, transport: transport)
        let settings = SecurityScanSettings(onlineChecks: true, enrichment: true)

        let first = try #require(await scanner.scan([target], settings: settings)[server.id])
        let firstRequests = transport.counts
        let scanned = clock.now
        transport.reset()
        let second = try #require(await scanner.scan([target], settings: settings)[server.id])
        let secondRequests = transport.counts
        let rescanned = clock.now

        let result = first
        if let dump = Self.environment["RACKPULSE_E2E_DUMP"] {
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
            try encoder.encode(result).write(to: URL(filePath: dump))
        }
        let items = result.items
        let counts = result.counts
        print("E2E agent \(pairing.version), fingerprint \(pairing.fingerprint.prefix(16))…, OS \(result.osName ?? "?") -> \(result.osEcosystem ?? "nil")")
        print("E2E report: \(report.packages.items.count) dpkg packages, \(report.updates.items.count) updates (\(report.updates.securityCount) security), \(report.projects.count) projects, \(report.listening.count) listeners")
        print("E2E findings: \(result.findings.count) packages (\(result.systemFindings.count) system, \(result.dependencyFindings.count) lockfile), \(items.count) advisories visible")
        print("E2E severity: critical \(counts.critical), high \(counts.high), medium \(counts.medium), low \(counts.low), unknown \(counts.unknown); fixable \(result.fixableCount), pending fix \(result.pendingFixCount), KEV \(result.exploitedCount), malware \(result.malwareCount)")
        print("E2E pending updates \(result.pendingUpdates), security \(result.pendingSecurityUpdates)")
        for finding in result.findings.prefix(10) { print("E2E top  \(Self.describe(finding))") }
        for check in result.failingChecks { print("E2E fail \(check.id): \(check.title) (\(check.detail))") }
        for source in result.sources { print("E2E source \(source.source.rawValue): \(source.state.rawValue)\(source.message.map { " \($0)" } ?? "")") }
        print("E2E requests cold \(firstRequests.sorted { $0.key < $1.key }), warm \(secondRequests.sorted { $0.key < $1.key })")
        print("E2E time: agent \(fetched - started), scan \(scanned - fetched), rescan \(rescanned - scanned), total \(rescanned - started)")

        #expect(result.osEcosystem == "Ubuntu:24.04:LTS")
        let system = Dictionary(result.systemFindings.map { ($0.package.name, $0) }, uniquingKeysWith: { first, _ in first })
        for name in ["openssl", "curl", "sudo", "vim", "openssh"] {
            let finding = system[name]
            #expect(finding != nil, "no finding for \(name)")
            #expect(finding?.fixedVersion != nil, "no fixed version for \(name)")
        }
        #expect(system["openssl"]?.package.version == "3.0.13-0ubuntu3")
        #expect(items.contains { $0.advisory.severity >= .high })
        #expect(result.pendingSecurityUpdates > 0)
        #expect(result.findings.contains { $0.fixPending })
        #expect(system["openssl"]?.fixPending == true)

        let failing = Set(result.failingChecks.map(\.id))
        #expect(failing.contains(SecurityCheck.sshPasswordLogin))
        #expect(failing.contains(SecurityCheck.firewallNone))

        let dependencies = Set(result.dependencyFindings.map(\.package.name))
        #expect(dependencies.isSuperset(of: ["lodash", "minimist", "requests"]))
        #expect(result.dependencyFindings.allSatisfy { $0.fixedVersion != nil })

        #expect(result.source(.osv)?.state == .ok)
        #expect(result.source(.kev)?.state == .ok)
        #expect(result.source(.epss)?.state == .ok)
        #expect(result.source(.socket)?.state == .skipped)
        #expect(items.contains { $0.advisory.epss != nil })

        #expect(second.findings.count == result.findings.count)
        #expect(second.items.map(\.advisory.id) == items.map(\.advisory.id))
        #expect(secondRequests["api.osv.dev", default: 0] < max(1, firstRequests["api.osv.dev", default: 0]))
        #expect(secondRequests["www.cisa.gov", default: 0] == 0)

        let engine = RuleEngine(settings: AlertSettings(), calendar: utc)
        let now = Date()
        let agents = [server.id: AgentReport(current: snapshot, failures: 0)]
        let poll = PollSnapshot(time: now, servers: [server], agents: agents, security: [server.id: result])
        let (state, events) = engine.evaluate(poll, state: AlertState())
        let firing = Set(state.firing.map(\.id))
        for alert in state.firing where RuleKind.securityKinds.contains(alert.kind) { print("E2E alert \(alert.kind.rawValue) [\(alert.severity)] \(alert.title)") }
        #expect(firing.contains("vulnerability:\(server.id)"))
        #expect(firing.contains("hardening:\(server.id)"))
        #expect(!firing.contains("securityUpdates:\(server.id)"))
        #expect(events.count == state.firing.count)

        var later = poll
        later.time = now.addingTimeInterval(3 * 86_400 + 60)
        let (heldState, _) = engine.evaluate(later, state: state)
        let held = heldState.firing.first { $0.id == "securityUpdates:\(server.id)" }
        print("E2E after 3 days: \(held?.title ?? "securityUpdates did not fire")")
        #expect(held != nil)
    }
}
