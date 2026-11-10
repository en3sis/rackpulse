import Foundation
import Testing
@testable import HetznerKit

struct SecurityRuleTests {
    static let t0 = date("2026-10-26T10:00:00Z")

    static func result(pending: Int = 0, advisories: [Advisory] = [], checks: [SecurityCheck] = []) -> SecurityResult {
        let package = InstalledPackage(
            query: PackageQuery(ecosystem: "Debian:12", name: "openssl", version: "3.0.11-1"),
            name: "openssl", version: "3.0.11-1", binaries: ["openssl"], location: .system
        )
        return SecurityResult(
            serverID: 1, checkedAt: t0, reportTime: t0, onlineChecks: true,
            findings: advisories.isEmpty ? [] : [Finding(package: package, advisories: advisories)],
            pendingSecurityUpdates: pending, checks: checks
        )
    }

    static func agent() -> AgentReport {
        AgentReport(current: AgentSnapshot(
            version: "0.3.0", time: t0,
            host: .init(hostname: "h", os: "", kernel: "", arch: "", serverID: nil, bootTime: t0, cores: 2, load: []),
            memory: .init(total: 100, available: 90, swapTotal: 0, swapFree: 0),
            disks: [], system: .init(rebootRequired: false, failedUnits: []), docker: nil
        ), failures: 0)
    }

    static func poll(_ time: Date, _ result: SecurityResult?, agent: AgentReport = agent()) -> PollSnapshot {
        PollSnapshot(time: time, servers: [server(1)], agents: [1: agent], security: result.map { [1: $0] } ?? [:])
    }

    @Test func defaultsMatchTheDesign() {
        let rules = Dictionary(uniqueKeysWithValues: RuleConfig.defaults.map { ($0.kind, $0) })
        #expect(rules[.vulnerability]?.threshold == 3)
        #expect(rules[.vulnerability]?.delivery == .push)
        #expect(rules[.securityUpdates]?.duration == TimeInterval(3 * 86_400))
        #expect(rules[.securityUpdates]?.delivery == .banner)
        #expect(rules[.hardening]?.delivery == .banner)
        #expect(RuleKind.securityKinds.allSatisfy { $0.needsAgent })
        #expect(ServerAlertOverride.kinds.contains(.vulnerability))
    }

    @Test func vulnerabilityFiresHoldsWithoutResultAndResolves() {
        let engine = RuleEngine(settings: AlertSettings(), calendar: utc)
        let critical = Advisory(id: "CVE-2024-1", severity: .critical, fixedVersion: "3.0.14-1")
        let critical2 = Advisory(id: "CVE-2024-2", severity: .critical, fixedVersion: "3.0.14-1")
        let unfixed = Advisory(id: "CVE-2024-3", severity: .critical)
        let medium = Advisory(id: "CVE-2024-4", severity: .medium, fixedVersion: "3.0.14-1")

        var (state, events) = engine.evaluate(Self.poll(Self.t0, Self.result(advisories: [unfixed, medium])), state: AlertState())
        #expect(state.firing.isEmpty)

        (state, events) = engine.evaluate(Self.poll(Self.t0 + 60, Self.result(advisories: [critical, critical2, unfixed])), state: state)
        #expect(state.firing.map(\.title) == ["server-1: 2 critical vulnerabilities have a fix"])
        #expect(state.firing.first?.severity == .critical)
        guard case .fired(_, let notify) = events.first else { Issue.record("expected fire"); return }
        #expect(notify)

        for minute in 2...4 {
            (state, events) = engine.evaluate(Self.poll(Self.t0 + Double(minute) * 60, nil), state: state)
            #expect(state.firing.map(\.id) == ["vulnerability:1"])
            #expect(events.isEmpty)
        }

        (state, events) = engine.evaluate(Self.poll(Self.t0 + 300, Self.result()), state: state)
        (state, events) = engine.evaluate(Self.poll(Self.t0 + 360, Self.result()), state: state)
        #expect(events == [.resolved(id: "vulnerability:1")])
        #expect(state.firing.isEmpty)
    }

    @Test func exploitedAndMalwareAlwaysFire() {
        var settings = AlertSettings()
        settings.rules = settings.rules.map { rule in
            var rule = rule
            if rule.kind == .vulnerability { rule.threshold = 4 }
            return rule
        }
        let engine = RuleEngine(settings: settings, calendar: utc)
        let exploited = Advisory(id: "CVE-2024-5", severity: .medium, knownExploited: KnownExploited(dateAdded: nil, ransomware: false))
        var (state, _) = engine.evaluate(Self.poll(Self.t0, Self.result(advisories: [exploited])), state: AlertState())
        #expect(state.firing.map(\.title) == ["server-1: 1 vulnerability is known to be exploited"])

        let malware = Advisory(id: "MAL-2025-1", severity: .critical, kind: .malware)
        (state, _) = engine.evaluate(Self.poll(Self.t0, Self.result(advisories: [malware])), state: AlertState())
        #expect(state.firing.map(\.title) == ["server-1: openssl is a malicious package"])

        let high = Advisory(id: "CVE-2024-6", severity: .high, fixedVersion: "2")
        (state, _) = engine.evaluate(Self.poll(Self.t0, Self.result(advisories: [high])), state: AlertState())
        #expect(state.firing.isEmpty)
    }

    @Test func securityUpdatesWaitForTheDuration() {
        let engine = RuleEngine(settings: AlertSettings(), calendar: utc)
        var (state, events) = engine.evaluate(Self.poll(Self.t0, Self.result(pending: 14)), state: AlertState())
        #expect(state.firing.isEmpty)
        (state, events) = engine.evaluate(Self.poll(Self.t0 + 86_400, nil), state: state)
        #expect(state.firing.isEmpty)
        (state, events) = engine.evaluate(Self.poll(Self.t0 + 2 * 86_400, Self.result(pending: 14)), state: state)
        #expect(state.firing.isEmpty)
        (state, events) = engine.evaluate(Self.poll(Self.t0 + 3 * 86_400 + 60, Self.result(pending: 14)), state: state)
        #expect(state.firing.map(\.title) == ["server-1: 14 security updates waiting for 3 days"])
        #expect(events.count == 1)
        guard case .fired(_, let notify) = events.first else { Issue.record("expected fire"); return }
        #expect(!notify)

        (state, _) = engine.evaluate(Self.poll(Self.t0 + 3 * 86_400 + 120, Self.result(pending: 0)), state: state)
        (state, events) = engine.evaluate(Self.poll(Self.t0 + 3 * 86_400 + 180, Self.result(pending: 0)), state: state)
        #expect(events == [.resolved(id: "securityUpdates:1")])
    }

    @Test func hardeningCountsFailingChecksAndSkipsInformational() {
        let engine = RuleEngine(settings: AlertSettings(), calendar: utc)
        let ssh = SecurityCheck(id: SecurityCheck.sshPasswordLogin, status: .fail, title: "SSH accepts passwords", detail: "")
        let host = SecurityCheck(id: SecurityCheck.dockerHostNetwork, status: .fail, title: "A container uses the host network", detail: "")
        let root = SecurityCheck(id: SecurityCheck.extraRoot, status: .pass, title: "Only root has UID 0", detail: "")
        var (state, _) = engine.evaluate(Self.poll(Self.t0, Self.result(checks: [ssh, host, root])), state: AlertState())
        #expect(state.firing.map(\.title) == ["server-1: SSH accepts passwords"])

        let ports = SecurityCheck(id: "ports.exposed:5432", status: .fail, title: "PostgreSQL port 5432 is open to the internet", detail: "")
        (state, _) = engine.evaluate(Self.poll(Self.t0 + 60, Self.result(checks: [ssh, ports, host])), state: state)
        #expect(state.firing.map(\.title) == ["server-1: SSH accepts passwords"])
        #expect(state.firing.map(\.id) == ["hardening:1"])

        (state, _) = engine.evaluate(Self.poll(Self.t0, Self.result(checks: [ssh, ports])), state: AlertState())
        #expect(state.firing.map(\.title) == ["server-1: 2 hardening checks fail"])

        let unreachable = AgentReport(current: nil, failures: 1)
        (state, _) = engine.evaluate(Self.poll(Self.t0 + 60, nil, agent: unreachable), state: state)
        #expect(state.firing.map(\.id) == ["hardening:1"])

        var log: [AlertEvent] = []
        for minute in 2...3 {
            let (next, events) = engine.evaluate(PollSnapshot(time: Self.t0 + Double(minute) * 60, servers: [server(1)]), state: state)
            state = next
            log += events
        }
        #expect(log == [.resolved(id: "hardening:1")])
    }
}
