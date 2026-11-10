import Foundation
import Testing
@testable import HetznerKit

struct FindingLedgerTests {
    static let t0 = date("2026-10-26T10:00:00Z")
    static let exploited = KnownExploited(dateAdded: nil, ransomware: false)

    static func result(
        _ advisories: [Advisory], at time: Date, checks: [SecurityCheck] = [], online: Bool = true, failed: Bool = false,
        osv: SourceStatus.State? = nil
    ) -> SecurityResult {
        let package = InstalledPackage(
            query: PackageQuery(ecosystem: "Debian:12", name: "openssl", version: "3.0.11-1"),
            name: "openssl", version: "3.0.11-1", binaries: ["openssl"], location: .system
        )
        return SecurityResult(
            serverID: 1, checkedAt: time, reportTime: time, onlineChecks: online,
            findings: advisories.isEmpty ? [] : [Finding(package: package, advisories: advisories)],
            checks: checks, sources: failed ? [SourceStatus(source: .osv, state: .failed)] : osv.map { [SourceStatus(source: .osv, state: $0)] } ?? []
        )
    }

    static func run(_ record: LedgerRecord, _ result: SecurityResult, settings: AlertSettings = AlertSettings()) -> LedgerOutcome {
        FindingLedger.reconcile(record, scan: FindingLedger.scan(result, settings: settings))
    }

    let critical = Advisory(id: "CVE-2024-1", severity: .critical, fixedVersion: "3.0.14-1")
    let high = Advisory(id: "CVE-2024-2", severity: .high, fixedVersion: "3.0.14-1")
    let medium = Advisory(id: "CVE-2024-3", severity: .medium, fixedVersion: "3.0.14-1")

    @Test func firstScanIsOneBaselineAndRepeatsAreSilent() {
        var outcome = Self.run(LedgerRecord(target: "t"), Self.result([critical, high, medium], at: Self.t0))
        #expect(outcome.baselineKinds.contains(.vulnerability))
        #expect(outcome.news(.vulnerability).map(\.entry.title) == ["CVE-2024-1 in openssl", "CVE-2024-2 in openssl"])
        #expect(outcome.record.entries.count == 3)

        outcome = Self.run(outcome.record, Self.result([critical, high, medium], at: Self.t0 + 1_800))
        #expect(outcome.news.isEmpty)
        #expect(outcome.baselineKinds.isEmpty)

        let same = Self.run(outcome.record, Self.result([critical, high, medium], at: Self.t0 + 1_800))
        #expect(!same.changed)
    }

    @Test func newFindingIsNewsAndNotBaseline() {
        let first = Self.run(LedgerRecord(target: "t"), Self.result([critical], at: Self.t0))
        let second = Self.run(first.record, Self.result([critical, high], at: Self.t0 + 1_800))
        #expect(second.baselineKinds.isEmpty)
        #expect(second.news.map(\.change) == [.new])
        #expect(second.news.first?.entry.key == "vulnerability|CVE-2024-2")
    }

    @Test func escalationNotifiesOnce() {
        let first = Self.run(LedgerRecord(target: "t"), Self.result([high], at: Self.t0))
        var promoted = high
        promoted.knownExploited = Self.exploited
        let second = Self.run(first.record, Self.result([promoted], at: Self.t0 + 1_800))
        #expect(second.news.map(\.change) == [.escalated])
        #expect(second.news.first?.wasUrgent == false)
        let notice = FindingNotice.compose(second.news, kind: .vulnerability, server: "web-1", baseline: false)
        #expect(notice?.title == "web-1: CVE-2024-2 in openssl is now known to be exploited")
        #expect(notice?.severity == .critical)

        let third = Self.run(second.record, Self.result([promoted], at: Self.t0 + 3_600))
        #expect(third.news.isEmpty)
    }

    @Test func epssAndRecordEditsAreNotEscalations() {
        let first = Self.run(LedgerRecord(target: "t"), Self.result([high], at: Self.t0))
        var edited = high
        edited.epss = EPSSScore(probability: 0.9, percentile: 0.99)
        edited.summary = "changed"
        #expect(Self.run(first.record, Self.result([edited], at: Self.t0 + 1_800)).news.isEmpty)
    }

    @Test func loweringTheThresholdNotifiesOnlyNewlyQualifying() {
        let first = Self.run(LedgerRecord(target: "t"), Self.result([critical, medium], at: Self.t0))
        #expect(first.news.count == 1)
        var settings = AlertSettings()
        settings.rules = settings.rules.map { rule in
            var rule = rule
            if rule.kind == .vulnerability { rule.threshold = Double(AdvisorySeverity.medium.rank) }
            return rule
        }
        let second = Self.run(first.record, Self.result([critical, medium], at: Self.t0 + 1_800), settings: settings)
        #expect(second.news.map(\.entry.key) == ["vulnerability|CVE-2024-3"])

        let sameScan = Self.run(first.record, Self.result([critical, medium], at: Self.t0), settings: settings)
        #expect(sameScan.news.map(\.entry.key) == ["vulnerability|CVE-2024-3"])
        #expect(sameScan.record.lastScan == Self.t0)
        #expect(sameScan.baselineKinds.isEmpty)
        #expect(!Self.run(sameScan.record, Self.result([critical, medium], at: Self.t0), settings: settings).changed)
    }

    @Test func enablingHardeningWithoutANewScanNotifies() {
        let fail = SecurityCheck(id: "ssh.passwordLogin", status: .fail, title: "SSH accepts passwords", detail: "")
        var off = AlertSettings()
        off.rules = off.rules.map { rule in
            var rule = rule
            if rule.kind == .hardening { rule.enabled = false }
            return rule
        }
        let first = Self.run(LedgerRecord(target: "t"), Self.result([], at: Self.t0, checks: [fail]), settings: off)
        #expect(first.news.isEmpty)
        let enabled = Self.run(first.record, Self.result([], at: Self.t0, checks: [fail]))
        #expect(enabled.news(.hardening).map(\.entry.title) == ["SSH accepts passwords"])
    }

    @Test func partialLookupNeverResolves() {
        let first = Self.run(LedgerRecord(target: "t"), Self.result([critical], at: Self.t0, osv: .ok))
        var record = first.record
        for step in 1...3 {
            let outcome = Self.run(record, Self.result([], at: Self.t0 + Double(step) * 900, osv: .partial))
            #expect(outcome.resolved.isEmpty)
            record = outcome.record
        }
        #expect(record.entries["vulnerability|CVE-2024-1"]?.isOpen == true)
    }

    @Test func newAliasThatChangesTheIdKeepsTheFinding() {
        let ghsa = Advisory(id: "GHSA-aaaa-bbbb-cccc", severity: .high, fixedVersion: "3.0.14-1")
        let first = Self.run(LedgerRecord(target: "t"), Self.result([ghsa], at: Self.t0))
        #expect(first.news.count == 1)
        let withCVE = Advisory(id: "CVE-2024-9", aliases: ["GHSA-aaaa-bbbb-cccc"], severity: .high, fixedVersion: "3.0.14-1")
        let second = Self.run(first.record, Self.result([withCVE], at: Self.t0 + 1_800))
        #expect(second.news.isEmpty)
        #expect(second.record.entries.keys.sorted() == ["vulnerability|CVE-2024-9"])
        #expect(second.resolved.isEmpty)
    }

    @Test func failedLookupNeverResolves() {
        let first = Self.run(LedgerRecord(target: "t"), Self.result([critical], at: Self.t0))
        var record = first.record
        for step in 1...3 {
            let outcome = Self.run(record, Self.result([], at: Self.t0 + Double(step) * 1_800, failed: true))
            #expect(outcome.resolved.isEmpty)
            record = outcome.record
        }
        #expect(record.entries["vulnerability|CVE-2024-1"]?.isOpen == true)
        let offline = Self.run(record, Self.result([], at: Self.t0 + 9_000, online: false))
        #expect(offline.resolved.isEmpty)
    }

    @Test func resolvesAfterTwoScansAndReopensSilentlyWithinAWeek() {
        let first = Self.run(LedgerRecord(target: "t"), Self.result([critical], at: Self.t0))
        let miss = Self.run(first.record, Self.result([], at: Self.t0 + 1_800))
        #expect(miss.resolved.isEmpty)
        let gone = Self.run(miss.record, Self.result([], at: Self.t0 + 3_600))
        #expect(gone.resolved.map(\.key) == ["vulnerability|CVE-2024-1"])
        #expect(!gone.record.openNotified(.vulnerability))

        let back = Self.run(gone.record, Self.result([critical], at: Self.t0 + 86_400))
        #expect(back.news.isEmpty)
        #expect(back.record.openNotified(.vulnerability))

        let goneAgain = Self.run(Self.run(back.record, Self.result([], at: Self.t0 + 90_000)).record, Self.result([], at: Self.t0 + 91_800))
        let later = Self.run(goneAgain.record, Self.result([critical], at: Self.t0 + 91_800 + 8 * 86_400))
        #expect(later.news.map(\.change) == [.reopened])
    }

    @Test func hardeningChecksAreTrackedByCheckID() {
        let fail = SecurityCheck(id: "ssh.passwordLogin", status: .fail, title: "SSH accepts passwords", detail: "")
        let info = SecurityCheck(id: "firewall.ufw", status: .fail, title: "ufw is off", detail: "", informational: true)
        let first = Self.run(LedgerRecord(target: "t"), Self.result([], at: Self.t0, checks: [fail, info]))
        #expect(first.news(.hardening).map(\.entry.title) == ["SSH accepts passwords"])
        let notice = FindingNotice.compose(first.news(.hardening), kind: .hardening, server: "web-1", baseline: true)
        #expect(notice?.title == "web-1: SSH accepts passwords")
        let fixed = Self.run(Self.run(first.record, Self.result([], at: Self.t0 + 1_800)).record, Self.result([], at: Self.t0 + 3_600))
        #expect(fixed.resolved.map(\.key) == ["hardening|ssh.passwordLogin"])
    }

    @Test func enablingOnlineChecksLaterIsABaseline() {
        let offline = Self.run(LedgerRecord(target: "t"), Self.result([], at: Self.t0, online: false))
        #expect(offline.baselineKinds == [.hardening])
        let online = Self.run(offline.record, Self.result([critical, high], at: Self.t0 + 1_800))
        #expect(online.baselineKinds == [.vulnerability])
        let notice = FindingNotice.compose(online.news(.vulnerability), kind: .vulnerability, server: "web-1", baseline: true)
        #expect(notice?.title == "web-1: 2 vulnerabilities found")
        #expect(notice?.body == "CVE-2024-1 in openssl (critical)\nCVE-2024-2 in openssl (high)")
    }

    @Test func malwareKeyIgnoresTheVersion() {
        let malware = Advisory(id: "MAL-2025-1", severity: .critical, kind: .malware)
        let package = { (version: String) in
            InstalledPackage(query: PackageQuery(ecosystem: "npm", name: "evil", version: version), name: "evil", version: version,
                             binaries: [], location: .system)
        }
        let a = SecurityResult(serverID: 1, checkedAt: Self.t0, reportTime: Self.t0, onlineChecks: true,
                               findings: [Finding(package: package("1.0.0"), advisories: [malware])])
        let b = SecurityResult(serverID: 1, checkedAt: Self.t0 + 60, reportTime: Self.t0, onlineChecks: true,
                               findings: [Finding(package: package("1.0.1"), advisories: [malware])])
        let first = Self.run(LedgerRecord(target: "t"), a)
        #expect(first.news.first?.entry.title == "evil is a malicious package")
        #expect(Self.run(first.record, b).news.isEmpty)
    }
}

struct NotificationPlannerTests {
    static let noon = date("2026-10-26T12:00:00Z")

    static func notice(_ id: String, kind: RuleKind? = .serverDown, title: String? = nil, delivery: Delivery = .push, at time: Date = noon) -> OutgoingNotification {
        OutgoingNotification(id: "p|\(id)", project: "p", target: "hetzner/p/server/1", kind: kind, snoozeID: id,
                             heading: "web-1", title: title ?? "web-1: \(id)", severity: .warning, delivery: delivery, created: time)
    }

    static func config(quiet: QuietHours? = nil) -> PlannerConfig {
        PlannerConfig(quietHours: quiet, summaryMinute: 9 * 60, calendar: utc)
    }

    static func securityConfig() -> PlannerConfig {
        var config = config()
        config.rateLimitedKinds = FindingLedger.kinds
        return config
    }

    @Test func sendsImmediatelyAndLogs() {
        let output = NotificationPlanner.plan([Self.notice("serverDown:1")], state: PlannerState(), config: Self.config(), now: Self.noon)
        #expect(output.post.map(\.id) == ["p|serverDown:1"])
        #expect(output.log.map(\.outcome) == [.sent])
        #expect(output.state.lastSent["p|serverDown:1"] == Self.noon)
    }

    @Test func quietHoursDelayAndFlushAsOneSummary() {
        let quiet = QuietHours(startMinute: 23 * 60, endMinute: 7 * 60)
        let night = date("2026-10-27T02:00:00Z")
        var output = NotificationPlanner.plan([Self.notice("a"), Self.notice("b")], state: PlannerState(), config: Self.config(quiet: quiet), now: night)
        #expect(output.post.isEmpty)
        #expect(output.log.map(\.outcome) == [.quietHours, .quietHours])

        output = NotificationPlanner.plan([], state: output.state, config: Self.config(quiet: quiet), now: night + 3_600)
        #expect(output.post.isEmpty)

        output = NotificationPlanner.plan([], state: output.state, config: Self.config(quiet: quiet), now: date("2026-10-27T07:01:00Z"))
        #expect(output.post.count == 1)
        #expect(output.post[0].title == "2 alerts during quiet hours")
        #expect(output.post[0].body == "web-1: b\nweb-1: a" || output.post[0].body == "web-1: a\nweb-1: b")
        #expect(output.post[0].snoozeID == nil)
        #expect(output.state.pending.isEmpty)
    }

    @Test func resolvedAlertsLeaveTheQueue() {
        let quiet = QuietHours(startMinute: 23 * 60, endMinute: 7 * 60)
        let night = date("2026-10-27T02:00:00Z")
        let output = NotificationPlanner.plan([Self.notice("a")], state: PlannerState(), config: Self.config(quiet: quiet), now: night)
        let (state, log) = NotificationPlanner.drop(["p|a"], from: output.state, now: night + 60)
        #expect(state.pending.isEmpty)
        #expect(log.map(\.outcome) == [.resolved])
    }

    @Test func securityGroupsAreRateLimitedPerServer() {
        let first = Self.notice("vulnerability:1", kind: .vulnerability, title: "web-1: CVE-1 in openssl")
        var output = NotificationPlanner.plan([first], state: PlannerState(), config: Self.securityConfig(), now: Self.noon)
        #expect(output.post.count == 1)

        let second = Self.notice("vulnerability:1", kind: .vulnerability, title: "web-1: CVE-2 in sudo", at: Self.noon + 1_800)
        output = NotificationPlanner.plan([second], state: output.state, config: Self.securityConfig(), now: Self.noon + 1_800)
        #expect(output.post.isEmpty)
        #expect(output.log.map(\.outcome) == [.rateLimited])

        let third = Self.notice("vulnerability:1", kind: .vulnerability, title: "web-1: CVE-3 in curl", at: Self.noon + 2_400)
        output = NotificationPlanner.plan([third], state: output.state, config: Self.securityConfig(), now: Self.noon + 2_400)
        #expect(output.post.isEmpty)

        output = NotificationPlanner.plan([], state: output.state, config: Self.securityConfig(), now: Self.noon + 3_601)
        #expect(output.post.count == 1)
        #expect(output.post[0].title == "web-1: 2 vulnerability alerts")
        #expect(output.post[0].body == "CVE-3 in curl\nCVE-2 in sudo")
    }

    @Test func mergedSecurityNotificationsCountFindingsNotTitles() {
        let items = { (names: [String]) in
            OutgoingNotification(id: "p|vulnerability:1", project: "p", target: "t", kind: .vulnerability, snoozeID: "vulnerability:1",
                                 heading: "web-1", title: "web-1: \(names.count) new vulnerabilities", severity: .warning,
                                 created: Self.noon, items: names)
        }
        var output = NotificationPlanner.plan([items(["CVE-1 in a", "CVE-2 in b"])], state: PlannerState(), config: Self.securityConfig(), now: Self.noon)
        output = NotificationPlanner.plan([items(["CVE-3 in c", "CVE-4 in d"])], state: output.state, config: Self.securityConfig(), now: Self.noon + 600)
        output = NotificationPlanner.plan([items(["CVE-5 in e", "CVE-6 in f"])], state: output.state, config: Self.securityConfig(), now: Self.noon + 1_200)
        output = NotificationPlanner.plan([], state: output.state, config: Self.securityConfig(), now: Self.noon + 3_601)
        #expect(output.post.map(\.title) == ["web-1: 4 vulnerability alerts"])
        #expect(output.post.first?.body == "CVE-5 in e\nCVE-6 in f\nCVE-3 in c\nCVE-4 in d")
    }

    @Test func snoozeRemovesQueuedNotifications() {
        let quiet = QuietHours(startMinute: 23 * 60, endMinute: 7 * 60)
        let night = date("2026-10-27T02:00:00Z")
        let output = NotificationPlanner.plan([Self.notice("a")], state: PlannerState(), config: Self.config(quiet: quiet), now: night)
        let (state, log) = NotificationPlanner.drop(["p|a"], from: output.state, now: night, outcome: .snoozed)
        #expect(state.pending.isEmpty)
        #expect(log.map(\.outcome) == [.snoozed])
    }

    @Test func rateLimitedKindsWaitForTheWindow() {
        var config = Self.config()
        config.rateLimitedKinds = [.container]
        let first = Self.notice("container:1", kind: .container, title: "web-1: api is unhealthy")
        var output = NotificationPlanner.plan([first], state: PlannerState(), config: config, now: Self.noon)
        #expect(output.post.count == 1)

        let second = Self.notice("container:1", kind: .container, title: "web-1: worker is unhealthy", at: Self.noon + 1_800)
        output = NotificationPlanner.plan([second], state: output.state, config: config, now: Self.noon + 1_800)
        #expect(output.post.isEmpty)
        #expect(output.log.map(\.outcome) == [.rateLimited])

        output = NotificationPlanner.plan([], state: output.state, config: config, now: Self.noon + 3_601)
        #expect(output.post.map(\.title) == ["web-1: worker is unhealthy"])
    }

    @Test func conditionAlertsAreNotRateLimited() {
        var output = NotificationPlanner.plan([Self.notice("serverDown:1")], state: PlannerState(), config: Self.config(), now: Self.noon)
        output = NotificationPlanner.plan([Self.notice("serverDown:1")], state: output.state, config: Self.config(), now: Self.noon + 600)
        #expect(output.post.count == 1)
    }

    @Test func burstsCollapseIntoOneSummary() {
        let many = (1...5).map { Self.notice("serverDown:\($0)") }
        let output = NotificationPlanner.plan(many, state: PlannerState(), config: Self.config(), now: Self.noon)
        #expect(output.post.count == 1)
        #expect(output.post[0].title == "5 new alerts")
        #expect(output.log.map(\.outcome) == Array(repeating: .summarized, count: 5))
        #expect(output.post[0].body.hasSuffix("And 0 more.") == false)
    }

    @Test func dailySummaryWaitsForItsTime() {
        let morning = date("2026-10-26T08:00:00Z")
        var output = NotificationPlanner.plan([Self.notice("rebootRequired:1", kind: .rebootRequired, delivery: .digest, at: morning)],
                                              state: PlannerState(), config: Self.config(), now: morning)
        #expect(output.post.isEmpty)
        #expect(output.log.map(\.outcome) == [.dailySummary])
        output = NotificationPlanner.plan([], state: output.state, config: Self.config(), now: date("2026-10-26T09:05:00Z"))
        #expect(output.post.map(\.title) == ["Daily summary: 1 alert"])
        output = NotificationPlanner.plan([Self.notice("rebootRequired:2", kind: .rebootRequired, delivery: .digest)],
                                          state: output.state, config: Self.config(), now: Self.noon)
        #expect(output.post.isEmpty)
        #expect(output.state.pending.count == 1)
    }

    @Test func popoverOnlyIsLoggedNotSent() {
        let output = NotificationPlanner.plan([Self.notice("rebootRequired:1", delivery: .banner)], state: PlannerState(), config: Self.config(), now: Self.noon)
        #expect(output.post.isEmpty)
        #expect(output.log.map(\.outcome) == [.popoverOnly])
    }
}

struct AlertStateResumeTests {
    @Test func savedStateDoesNotFireAgainAfterRelaunch() throws {
        let engine = RuleEngine(settings: AlertSettings(), calendar: utc)
        let t0 = date("2026-10-26T12:00:00Z")
        let down = PollSnapshot(time: t0, servers: [server(1, status: .off)])
        var (state, events) = engine.evaluate(down, state: AlertState())
        (state, events) = engine.evaluate(PollSnapshot(time: t0 + 60, servers: [server(1, status: .off)]), state: state)
        #expect(events.count == 1)

        let saved = try JSONDecoder().decode(AlertState.self, from: JSONEncoder().encode(state))
        let later = t0 + 3 * 3_600
        (_, events) = engine.evaluate(PollSnapshot(time: later, servers: [server(1, status: .off)]), state: saved.resumed(at: later))
        #expect(events.isEmpty)
    }

    @Test func staleDraftsAreDroppedButActiveAlertsSurvive() {
        var state = AlertState()
        state.tracks["serverDown:1"] = AlertState.Track(kind: .serverDown, serverID: 1, raised: 1)
        state.tracks["memory:1"] = AlertState.Track(
            kind: .memory, serverID: 1, raised: 5, cleared: 1, aboveSince: date("2026-10-24T12:00:00Z"),
            alert: FiringAlert(id: "memory:1", kind: .memory, severity: .warning, title: "web-1 memory", since: date("2026-10-24T12:00:00Z"))
        )
        state.tracks["securityUpdates:1"] = AlertState.Track(kind: .securityUpdates, serverID: 1, raised: 5, aboveSince: date("2026-10-24T12:00:00Z"))
        state.lastPoll = date("2026-10-26T12:00:00Z")
        state.snooze("cpu:1", until: date("2026-10-26T13:00:00Z"))
        state.snooze("diskSpace:/:1", until: date("2026-10-27T13:00:00Z"))

        let soon = state.resumed(at: date("2026-10-26T12:05:00Z"))
        #expect(soon.tracks.count == 3)

        let resumed = state.resumed(at: date("2026-10-26T18:00:00Z"))
        #expect(resumed.tracks["serverDown:1"] == nil)
        #expect(resumed.tracks["memory:1"]?.alert != nil)
        #expect(resumed.tracks["memory:1"]?.cleared == 0)
        #expect(resumed.isSnoozed("diskSpace:/:1", at: date("2026-10-26T18:00:00Z")))
        #expect(resumed.snoozed["cpu:1"] == nil)
        #expect(resumed.tracks["securityUpdates:1"]?.aboveSince == date("2026-10-24T12:00:00Z"))
    }

    @Test func quietHoursNoLongerSilenceTheEngine() {
        var settings = AlertSettings()
        settings.quietHours = QuietHours(startMinute: 0, endMinute: 24 * 60 - 1)
        let engine = RuleEngine(settings: settings, calendar: utc)
        let t0 = date("2026-10-26T12:00:00Z")
        var (state, events) = engine.evaluate(PollSnapshot(time: t0, servers: [server(1, status: .off)]), state: AlertState())
        (state, events) = engine.evaluate(PollSnapshot(time: t0 + 60, servers: [server(1, status: .off)]), state: state)
        guard case .fired(_, let notify) = events.first else { Issue.record("expected fire"); return }
        #expect(notify)
    }
}

struct LocalDatabaseTests {
    @Test func securityResultsRoundTrip() throws {
        let database = try LocalDatabase()
        try database.saveSecurityResults(["a": Data("1".utf8), "b": Data("2".utf8)])
        try database.saveSecurityResults(["a": Data("3".utf8)], removed: ["b"])
        #expect(try database.securityResults() == ["a": Data("3".utf8)])
        try database.clearSecurityResults()
        #expect(try database.securityResults().isEmpty)
    }

    @Test func upgradesAVersionOneFile() async throws {
        let folder = FileManager.default.temporaryDirectory.appendingPathComponent("rackpulse-v1-\(UUID().uuidString)", isDirectory: true)
        defer { try? FileManager.default.removeItem(at: folder) }
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
        let url = folder.appendingPathComponent("rackpulse.sqlite")
        let old = try SQLiteConnection(path: url.path)
        try old.execute("CREATE TABLE alert_state (project TEXT PRIMARY KEY, state BLOB NOT NULL, updated REAL NOT NULL); PRAGMA user_version = 1")
        let database = try LocalDatabase(url: url)
        try database.saveSecurityResults(["a": Data("1".utf8)])
        #expect(try database.securityResults().count == 1)
        #expect(try await database.ledger(target: "hetzner/p/server/1").entries.isEmpty)
        #expect(try database.connection.query("PRAGMA user_version") { $0.int(0) }.first == LocalDatabase.schemaVersion)
    }

    static func database() throws -> (LocalDatabase, URL) {
        let folder = FileManager.default.temporaryDirectory.appendingPathComponent("rackpulse-db-\(UUID().uuidString)", isDirectory: true)
        let url = folder.appendingPathComponent("rackpulse.sqlite")
        return (try LocalDatabase(url: url), folder)
    }

    @Test func roundTripsEverythingInOneCommit() async throws {
        let (database, folder) = try Self.database()
        defer { try? FileManager.default.removeItem(at: folder) }
        let t0 = date("2026-10-26T12:00:00Z")

        var state = AlertState()
        state.snooze("serverDown:1", until: t0 + 3_600)
        let outcome = FindingLedger.reconcile(
            LedgerRecord(target: "hetzner/p/server/1"),
            scan: LedgerScan(time: t0, signals: [
                FindingSignal(key: "vulnerability|CVE-1", kind: .vulnerability, title: "CVE-1 in openssl", rank: 4, exploited: true,
                              aliases: ["CVE-1", "GHSA-x"], qualifies: true),
                FindingSignal(key: "hardening|ssh", kind: .hardening, title: "SSH accepts passwords", qualifies: false),
            ], completeKinds: [.vulnerability, .hardening], rules: "v3,h")
        )
        var planner = PlannerState()
        planner.lastDailySummary = t0
        var commit = AlertCommit()
        commit.alertStates["p"] = state
        commit.ledgers = [outcome.record]
        commit.planner = planner
        commit.log = [NotificationRecord(time: t0, project: "p", target: "hetzner/p/server/1", kind: .vulnerability, group: "p|vulnerability:1",
                                         title: "web-1: CVE-1 in openssl", outcome: .sent)]
        try await database.commit(commit)

        let loaded = try await database.alertState(project: "p")
        #expect(loaded == state)
        #expect(try await database.ledger(target: "hetzner/p/server/1") == outcome.record)
        #expect(try await database.plannerState() == planner)
        #expect(try await database.log().map(\.outcome) == [.sent])
        #expect(try await database.ledger(target: "other").entries.isEmpty)

        let reopened = try LocalDatabase(url: folder.appendingPathComponent("rackpulse.sqlite"))
        #expect(try await reopened.ledger(target: "hetzner/p/server/1").entries.count == 2)
        #expect(try reopened.connection.query("PRAGMA user_version") { $0.int(0) }.first == LocalDatabase.schemaVersion)
    }

    @Test func keepsOnlyCurrentProjects() async throws {
        let (database, folder) = try Self.database()
        defer { try? FileManager.default.removeItem(at: folder) }
        let now = date("2026-10-26T12:00:00Z")
        var commit = AlertCommit()
        commit.alertStates = ["a": AlertState(), "b": AlertState()]
        commit.ledgers = [LedgerRecord(target: "hetzner/a/server/1", lastScan: now), LedgerRecord(target: "hetzner/b/server/2", lastScan: now)]
        try await database.commit(commit)
        try await database.keepProjects(["a"])
        #expect(try await database.alertState(project: "b") == nil)
        #expect(try await database.alertState(project: "a") != nil)
        #expect(try await database.ledger(target: "hetzner/b/server/2").lastScan == nil)
        #expect(try await database.ledger(target: "hetzner/a/server/1").lastScan == now)
    }

    @Test func prunesOldLogAndRemovedTargets() async throws {
        let (database, folder) = try Self.database()
        defer { try? FileManager.default.removeItem(at: folder) }
        let now = date("2026-10-26T12:00:00Z")
        var commit = AlertCommit()
        commit.ledgers = [LedgerRecord(target: "hetzner/p/server/1", lastScan: now), LedgerRecord(target: "hetzner/p/server/2", lastScan: now),
                          LedgerRecord(target: "hetzner/p_x/server/3", lastScan: now)]
        commit.log = [
            NotificationRecord(time: now - 100 * 86_400, project: "p", target: nil, kind: nil, group: "g", title: "old", outcome: .sent),
            NotificationRecord(time: now, project: "p", target: nil, kind: nil, group: "g", title: "new", outcome: .sent),
        ]
        try await database.commit(commit)
        try await database.prune(now: now)
        #expect(try await database.log().map(\.title) == ["new"])

        try await database.removeTargets(notIn: ["hetzner/p/server/1"], prefix: "hetzner/p/")
        #expect(try await database.ledger(target: "hetzner/p/server/2").lastScan == nil)
        #expect(try await database.ledger(target: "hetzner/p/server/1").lastScan == now)
        #expect(try await database.ledger(target: "hetzner/p_x/server/3").lastScan == now)
    }
}
