import Foundation
import Testing
@testable import HetznerKit

struct NotificationPlannerTests {
    static let noon = date("2026-10-26T12:00:00Z")

    static func notice(_ id: String, kind: RuleKind? = .serverDown, title: String? = nil, delivery: Delivery = .push, at time: Date = noon) -> OutgoingNotification {
        OutgoingNotification(id: "p|\(id)", project: "p", target: "hetzner/p/server/1", kind: kind, snoozeID: id,
                             heading: "web-1", title: title ?? "web-1: \(id)", severity: .warning, delivery: delivery, created: time)
    }

    static func config(quiet: QuietHours? = nil) -> PlannerConfig {
        PlannerConfig(quietHours: quiet, summaryMinute: 9 * 60, calendar: utc)
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
        state.lastPoll = date("2026-10-26T12:00:00Z")
        state.snooze("cpu:1", until: date("2026-10-26T13:00:00Z"))
        state.snooze("diskSpace:/:1", until: date("2026-10-27T13:00:00Z"))

        let soon = state.resumed(at: date("2026-10-26T12:05:00Z"))
        #expect(soon.tracks.count == 2)

        let resumed = state.resumed(at: date("2026-10-26T18:00:00Z"))
        #expect(resumed.tracks["serverDown:1"] == nil)
        #expect(resumed.tracks["memory:1"]?.alert != nil)
        #expect(resumed.tracks["memory:1"]?.cleared == 0)
        #expect(resumed.isSnoozed("diskSpace:/:1", at: date("2026-10-26T18:00:00Z")))
        #expect(resumed.snoozed["cpu:1"] == nil)
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
        var planner = PlannerState()
        planner.lastDailySummary = t0
        var commit = AlertCommit()
        commit.alertStates["p"] = state
        commit.planner = planner
        commit.log = [NotificationRecord(time: t0, project: "p", target: "hetzner/p/server/1", kind: .serverDown, group: "p|serverDown:1",
                                         title: "web-1 is off", outcome: .sent)]
        try await database.commit(commit)

        let loaded = try await database.alertState(project: "p")
        #expect(loaded == state)
        #expect(try await database.plannerState() == planner)
        #expect(try await database.log().map(\.outcome) == [.sent])

        let reopened = try LocalDatabase(url: folder.appendingPathComponent("rackpulse.sqlite"))
        #expect(try await reopened.alertState(project: "p") == state)
        #expect(try reopened.connection.query("PRAGMA user_version") { $0.int(0) }.first == LocalDatabase.schemaVersion)
    }

    @Test func keepsOnlyCurrentProjects() async throws {
        let (database, folder) = try Self.database()
        defer { try? FileManager.default.removeItem(at: folder) }
        var commit = AlertCommit()
        commit.alertStates = ["a": AlertState(), "b": AlertState()]
        try await database.commit(commit)
        try await database.keepProjects(["a"])
        #expect(try await database.alertState(project: "b") == nil)
        #expect(try await database.alertState(project: "a") != nil)
    }

    @Test func prunesOldLog() async throws {
        let (database, folder) = try Self.database()
        defer { try? FileManager.default.removeItem(at: folder) }
        let now = date("2026-10-26T12:00:00Z")
        var commit = AlertCommit()
        commit.log = [
            NotificationRecord(time: now - 100 * 86_400, project: "p", target: nil, kind: nil, group: "g", title: "old", outcome: .sent),
            NotificationRecord(time: now, project: "p", target: nil, kind: nil, group: "g", title: "new", outcome: .sent),
        ]
        try await database.commit(commit)
        try await database.prune(now: now)
        #expect(try await database.log().map(\.title) == ["new"])
    }
}
