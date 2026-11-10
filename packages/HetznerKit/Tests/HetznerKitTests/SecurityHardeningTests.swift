import Foundation
import Testing
@testable import HetznerKit

actor OverlapSource: VulnerabilitySource {
    nonisolated let name = SourceName.osv
    private var active = 0
    private(set) var most = 0
    private(set) var calls = 0

    nonisolated func supports(_ query: PackageQuery) -> Bool { true }

    func lookup(_ queries: [PackageQuery]) async throws -> SourceLookup {
        active += 1
        calls += 1
        most = max(most, active)
        try? await Task.sleep(for: .milliseconds(30))
        active -= 1
        return SourceLookup()
    }
}

struct SecurityHardeningTests {
    static let t0 = date("2026-10-26T10:00:00Z")
    static let lodash = PackageQuery(ecosystem: "npm", name: "lodash", version: "4.17.20")

    @Test func overlappingScansRunOneAtATime() async {
        let source = OverlapSource()
        let scanner = SecurityScanner(sources: [source])
        let target = SecurityTarget(serverID: 1, report: ScannerTests.report(updates: []), server: nil, firewalls: nil)
        let settings = SecurityScanSettings(onlineChecks: true)
        async let a = scanner.scan([target], settings: settings)
        async let b = scanner.scan([target], settings: settings)
        async let c = scanner.scan([target], settings: settings)
        let results = await [a, b, c]
        #expect(results.allSatisfy { $0[1] != nil })
        #expect(await source.calls == 3)
        #expect(await source.most == 1)
    }

    @Test func organizationSlugCannotChangeThePath() {
        for bad in ["", ".", "..", "../x", "a/b", "a?b", "a#b", "a@b", "a b", "-a", "_a", "ä", String(repeating: "a", count: 101)] {
            #expect(!SocketCredentials(token: "t", organization: bad).organizationIsValid, "\(bad)")
        }
        for good in ["acme", "acme-inc", "a.b_c", "A1", String(repeating: "a", count: 100)] {
            #expect(SocketCredentials(token: "t", organization: good).organizationIsValid, "\(good)")
        }
    }

    @Test func cacheRejectsInvalidNames() throws {
        let cache = temporaryCache()
        for bad in ["../x.json", "osv/../../x.json", "/tmp/x.json", "osv//x.json", "./x.json", ""] {
            #expect(cache.key(bad) == nil, "\(bad)")
            cache.write(["a": 1], to: bad)
            #expect(cache.read([String: Int].self, from: bad) == nil)
        }
        #expect(try cache.connection.query("SELECT COUNT(*) FROM security_cache") { $0.int(0) }.first == 0)
        #expect(cache.key("osv/GHSA-1.json") != nil)
    }

    @Test func cachePrunesTheOldestRecords() {
        let cache = temporaryCache()
        for index in 0..<5 { cache.write(["n": index], to: "osv/GHSA-\(index).json") }
        cache.write(["n": 9], to: "osv-queries.json")
        cache.prune(folder: "osv", keeping: 2)
        #expect(cache.count(folder: "osv") == 2)
        #expect(cache.read([String: Int].self, from: "osv/GHSA-4.json") == ["n": 4])
        #expect(cache.read([String: Int].self, from: "osv-queries.json") == ["n": 9])
    }

    @Test func cachedRecordWithAnotherIDIsRefetched() async throws {
        let cache = temporaryCache()
        defer { cache.clear() }
        cache.write(OSVRecord(id: "GHSA-other", modified: "2024-01-01T00:00:00Z"), to: OSVSource.recordPath("GHSA-wanted"))
        let transport = RouterTransport { request in
            if request.url!.path() == "/v1/querybatch" {
                return .init(body: json(["results": [["vulns": [["id": "GHSA-wanted", "modified": "2024-01-01T00:00:00Z"]]]]]))
            }
            return .init(body: json(["id": "GHSA-wanted", "modified": "2024-01-01T00:00:00Z", "summary": "real"]))
        }
        let source = OSVSource(cache: cache, transport: transport, clock: { Self.t0 }, sleep: { _ in })
        let lookup = try await source.lookup([Self.lodash])
        #expect(transport.requests.contains { $0.url!.path() == "/v1/vulns/GHSA-wanted" })
        #expect(lookup.advisories[Self.lodash]?.first?.id == "GHSA-wanted")
    }

    @Test func osvFallsBackToCachedResultsWhenOffline() async throws {
        let cache = temporaryCache()
        defer { cache.clear() }
        let offline = Clock(.distantPast)
        let transport = RouterTransport { request in
            if offline.now > .distantPast { return .init(status: 503, body: Data()) }
            if request.url!.path() == "/v1/querybatch" {
                return .init(body: json(["results": [["vulns": [["id": "GHSA-35jh-r3h4-6jhm", "modified": "2024-01-01T00:00:00Z"]]]]]))
            }
            return .init(body: try! fixture("osv-GHSA-35jh-r3h4-6jhm"))
        }
        let clock = Clock(Self.t0)
        let source = OSVSource(cache: cache, transport: transport, clock: { clock.now }, sleep: { _ in })
        let first = try await source.lookup([Self.lodash])
        #expect(first.advisories[Self.lodash]?.isEmpty == false)

        offline.advance(1)
        clock.advance(7 * 3_600)
        let second = try await source.lookup([Self.lodash])
        #expect(second.advisories[Self.lodash] == first.advisories[Self.lodash])
        #expect(second.problem?.contains("could not be checked") == true)

        let empty = OSVSource(cache: temporaryCache(), transport: transport, clock: { clock.now }, sleep: { _ in })
        await #expect(throws: SecuritySourceError.self) { try await empty.lookup([Self.lodash]) }
    }

    @Test func socketKeepsCachedAlertsWhenTheQuotaCallFails() async throws {
        let cache = temporaryCache()
        defer { cache.clear() }
        let down = Clock(.distantPast)
        let transport = RouterTransport { request in
            if down.now > .distantPast { return .init(status: 500, body: Data()) }
            if request.url!.path() == "/v0/quota" { return .init(body: json(["quota": 500, "maxQuota": 500])) }
            return .init(body: Data(#"{"inputPurl":"pkg:npm/evil@1.0.0","alerts":[{"type":"malware","severity":"critical"}]}"#.utf8))
        }
        let clock = Clock(Self.t0)
        let source = SocketSource(
            credentials: SocketCredentials(token: "t", organization: "acme"), cache: cache, transport: transport,
            clock: { clock.now }, sleep: { _ in }
        )
        let evil = PackageQuery(ecosystem: "npm", name: "evil", version: "1.0.0")
        let other = PackageQuery(ecosystem: "npm", name: "other", version: "1.0.0")
        _ = try await source.lookup([evil])

        down.advance(1)
        clock.advance(SocketSource.minimumInterval + 1)
        let lookup = try await source.lookup([evil, other])
        #expect(lookup.advisories[evil]?.first?.kind == .malware)
        #expect(lookup.problem?.contains("1 packages were not checked") == true)
    }

    @Test func agentCannotSpoofOrDuplicateHostChecks() {
        let spoofed = [
            SecurityCheck(id: SecurityCheck.firewallNone, status: .pass, title: "fake", detail: ""),
            SecurityCheck(id: "ports.exposed:5432", status: .pass, title: "fake", detail: ""),
            SecurityCheck(id: SecurityCheck.endOfLife, status: .pass, title: "fake", detail: ""),
            SecurityCheck(id: SecurityCheck.sshRootLogin, status: .fail, title: "first", detail: ""),
            SecurityCheck(id: SecurityCheck.sshRootLogin, status: .pass, title: "second", detail: ""),
        ]
        let host = [SecurityCheck(id: SecurityCheck.firewallNone, status: .fail, title: "No firewall is active", detail: "")]
        let merged = HostChecks.merge(agent: spoofed, host: host)
        #expect(merged.map(\.id) == [SecurityCheck.sshRootLogin, SecurityCheck.firewallNone])
        #expect(merged.map(\.title) == ["first", "No firewall is active"])
    }

    @Test func agentCheckTextIsCapped() throws {
        let long = String(repeating: "x", count: 50_000)
        let check = try JSONDecoder().decode(SecurityCheck.self, from: json(["id": "a", "status": "fail", "title": long, "detail": long]))
        #expect(check.title.count == SecurityCheck.titleLimit)
        #expect(check.detail.count == SecurityCheck.detailLimit)
    }

    static func failed(_ advisories: [Advisory] = [], updatesError: String? = nil, pending: Int = 0) -> SecurityResult {
        let base = SecurityRuleTests.result(pending: pending, advisories: advisories)
        return SecurityResult(
            serverID: 1, checkedAt: base.checkedAt, reportTime: base.reportTime, onlineChecks: true, findings: base.findings,
            pendingSecurityUpdates: pending, updatesError: updatesError,
            sources: [SourceStatus(source: .osv, state: updatesError == nil ? .failed : .ok, message: "Could not reach api.osv.dev.")]
        )
    }

    @Test func failedLookupDoesNotResolveOrRefireAlerts() {
        let engine = RuleEngine(settings: AlertSettings(), calendar: utc)
        let critical = Advisory(id: "CVE-2024-1", severity: .critical, fixedVersion: "3.0.14-1")
        var (state, events) = engine.evaluate(SecurityRuleTests.poll(Self.t0, SecurityRuleTests.result(advisories: [critical])), state: AlertState())
        #expect(state.firing.map(\.id) == ["vulnerability:1"])

        for minute in 1...5 {
            (state, events) = engine.evaluate(SecurityRuleTests.poll(Self.t0 + Double(minute) * 60, Self.failed()), state: state)
            #expect(events.isEmpty)
            #expect(state.firing.map(\.id) == ["vulnerability:1"])
        }

        let fresh = RuleEngine(settings: AlertSettings(), calendar: utc).evaluate(SecurityRuleTests.poll(Self.t0, Self.failed()), state: AlertState())
        #expect(fresh.1.isEmpty)
    }

    @Test func updateErrorKeepsTheWaitingTime() {
        let engine = RuleEngine(settings: AlertSettings(), calendar: utc)
        var (state, _) = engine.evaluate(SecurityRuleTests.poll(Self.t0, SecurityRuleTests.result(pending: 3)), state: AlertState())
        (state, _) = engine.evaluate(SecurityRuleTests.poll(Self.t0 + 86_400, Self.failed(updatesError: "apt failed")), state: state)
        let (_, events) = engine.evaluate(SecurityRuleTests.poll(Self.t0 + 3 * 86_400, SecurityRuleTests.result(pending: 3)), state: state)
        #expect(events.contains { if case .fired(let alert, _) = $0 { alert.id == "securityUpdates:1" } else { false } })
    }
}

struct ContainerHealthTests {
    @Test func exitedContainerWithStaleHealthIsNotUnhealthy() {
        let exited = AgentSnapshot.Container(id: "1", name: "web", image: "x", state: "exited", health: "unhealthy", exitCode: 0)
        let running = AgentSnapshot.Container(id: "2", name: "api", image: "x", state: "running", health: "unhealthy")
        #expect(!exited.isUnhealthy)
        #expect(running.isUnhealthy)
    }
}
