import Foundation
import Testing
@testable import HetznerKit

struct EngineTests {
    let pricing = Pricing(
        currency: "EUR",
        vatRate: 19,
        primaryIps: [.init(type: .ipv4, prices: [price("0.001", "0.5")])],
        floatingIps: [],
        volumePerGBMonth: money("0.044"),
        serverBackupPercentage: 20
    )

    @Test func costIsHourlyTimesStartedHoursCappedAtMonthly() {
        let now = date("2026-10-11T10:30:00Z")
        let inventory = Inventory(
            servers: [
                server(1, created: date("2026-10-11T08:00:00Z"), backups: true),
                server(2, status: .off),
            ],
            volumes: [Volume(id: 9, name: "data", created: date("2026-01-01T00:00:00Z"), server: nil,
                             location: Location(id: 1, name: "fsn1"), size: 100)]
        )
        let report = CostEstimator(pricing: pricing).estimate(inventory, now: now)
        let line = { (kind: CostLine.Kind, id: Int64) in report.lines.first { $0.kind == kind && $0.resourceID == id }! }

        #expect(line(.server, 1).monthToDate == Decimal(string: "0.03"))
        #expect(line(.backup, 1).monthToDate == Decimal(string: "0.006"))
        #expect(line(.server, 2).monthToDate == Decimal(string: "2.51"))
        #expect(line(.server, 2).forecast == 5)
        #expect(line(.server, 2).idleReason != nil)
        #expect(line(.volume, 9).forecast == Decimal(string: "4.4"))
        #expect(line(.volume, 9).idleReason == "Detached")
    }

    @Test func historyKeepsHourlySamplesAndForecastsFullDate() {
        var history = UsageHistory()
        let start = date("2026-10-01T00:00:00Z")
        for hour in 0..<24 {
            let time = start.addingTimeInterval(Double(hour) * 3600)
            history.record(7, used: 100 + Double(hour), at: time)
            history.record(7, used: 999, at: time.addingTimeInterval(600))
        }
        #expect(history.samples[7]?.count == 24)
        let forecast = history.forecast(7, capacity: 100 + 23 + 48)
        #expect(abs((forecast?.daysUntilFull ?? 0) - 2) < 0.001)

        history.record(7, used: 200, at: start.addingTimeInterval(50 * 86_400))
        #expect(history.samples[7]?.count == 1)
    }

    @Test func uptimeKeepsWorstStatePerHourAndDay() {
        var history = UptimeHistory()
        let noon = date("2026-10-25T12:10:00Z")
        history.record(1, .up, at: noon)
        history.record(1, .down, at: noon.addingTimeInterval(600))
        history.record(1, .up, at: noon.addingTimeInterval(1200))
        history.record(1, .alert, at: date("2026-10-24T08:00:00Z"))

        let hours = history.hourly(1, endingAt: noon.addingTimeInterval(1800), count: 3)
        #expect(hours == [nil, nil, .down])
        let days = history.daily(1, endingAt: noon, count: 3, calendar: utc)
        #expect(days == [nil, .alert, .down])

        history.record(1, .up, at: noon.addingTimeInterval(40 * 86_400))
        #expect(history.hours[1]?.count == 1)
    }

    @Test func serverDownWaitsTwoPollsAndSkipsUserStops() {
        let engine = RuleEngine(settings: AlertSettings(), calendar: utc)
        let t0 = date("2026-10-25T12:00:00Z")
        let stop = ServerAction(id: 5, command: "shutdown_server", started: t0.addingTimeInterval(-300),
                                resources: [.init(id: 2, type: "server")])
        let servers = [server(1, status: .off), server(2, status: .off)]

        var state = AlertState()
        var events: [AlertEvent]
        (state, events) = engine.evaluate(PollSnapshot(time: t0, servers: servers, actions: [stop]), state: state)
        #expect(events.isEmpty)
        (state, events) = engine.evaluate(PollSnapshot(time: t0 + 60, servers: servers, actions: [stop]), state: state)
        #expect(events.count == 1)
        #expect(state.firing.map(\.id) == ["serverDown:1"])
    }

    @Test func agentOnlyServerSkipsServerDownAndSaysNotAnswering() {
        let engine = RuleEngine(settings: AlertSettings(), calendar: utc)
        let t0 = date("2026-10-25T12:00:00Z")
        var host = server(-1, status: .off)
        host.agentOnly = true
        let report = [Int64(-1): AgentReport(current: nil, failures: 3)]
        var state = AlertState()
        for step in 0..<2 {
            (state, _) = engine.evaluate(PollSnapshot(time: t0 + Double(step * 60), servers: [host], agents: report), state: state)
        }
        #expect(!state.firing.contains { $0.kind == .serverDown })

        var running = server(-2)
        running.agentOnly = true
        (state, _) = engine.evaluate(PollSnapshot(time: t0, servers: [running], agents: [-2: AgentReport(current: nil, failures: 3)]),
                                     state: AlertState())
        #expect(state.firing.first { $0.id == "agentUnreachable:-2" }?.title == "server--2 does not answer")
    }

    @Test func serverOverridesChangeThresholdOrMute() {
        var settings = AlertSettings()
        var custom = RuleConfig.defaults.first { $0.kind == .sustainedCPU }!
        custom.threshold = 50
        settings.servers[1] = ServerAlertOverride(mode: .custom, rules: [custom])
        settings.servers[2] = ServerAlertOverride(mode: .off)
        let engine = RuleEngine(settings: settings, calendar: utc)
        let now = date("2026-10-25T12:00:00Z")
        let points = (0..<11).map { MetricPoint(time: now.addingTimeInterval(Double($0 - 10) * 60), value: 60) }
        let metrics = ServerMetrics(start: now - 600, end: now, step: 60, series: [MetricSeries.cpu: points])
        let snapshot = PollSnapshot(
            time: now,
            servers: [server(1, cores: 1), server(2, status: .off, cores: 1), server(3, cores: 1)],
            metrics: [1: metrics, 3: metrics]
        )
        let (state, _) = engine.evaluate(snapshot, state: AlertState())
        #expect(state.firing.map(\.id) == ["sustainedCPU:1"])
    }

    @Test func rebuildFromCachedActionsFiresOnce() {
        let engine = RuleEngine(settings: AlertSettings(), calendar: utc)
        let t0 = date("2026-10-25T12:00:00Z")
        let old = ServerAction(id: 1, command: "rebuild_server", started: t0 - 3600, resources: [.init(id: 1, type: "server")])
        let fresh = ServerAction(id: 2, command: "rebuild_server", started: t0 + 30, resources: [.init(id: 1, type: "server")])
        let servers = [server(1)]

        var state = AlertState()
        var events: [AlertEvent]
        (state, events) = engine.evaluate(PollSnapshot(time: t0, servers: servers, actions: [old]), state: state)
        #expect(events.isEmpty)
        (state, events) = engine.evaluate(PollSnapshot(time: t0 + 240, servers: servers, actions: [fresh, old]), state: state)
        #expect(events.count == 1)
        (state, events) = engine.evaluate(PollSnapshot(time: t0 + 300, servers: servers, actions: [fresh, old]), state: state)
        #expect(events == [.resolved(id: "unexpectedChange:rebuild2")])
    }

    @Test func sustainedCPUUsesPerCoreValuesAndDoesNotFlap() {
        let engine = RuleEngine(settings: AlertSettings(), calendar: utc)
        let host = server(1, cores: 4)
        func poll(_ raw: Double, at now: Date) -> PollSnapshot {
            let points = (0..<11).map { MetricPoint(time: now.addingTimeInterval(Double($0 - 10) * 60), value: raw) }
            let metrics = ServerMetrics(start: now - 600, end: now, step: 60, series: [MetricSeries.cpu: points])
            return PollSnapshot(time: now, servers: [host], metrics: [1: metrics])
        }
        let t0 = date("2026-10-25T12:00:00Z")
        var state = AlertState()
        var log: [AlertEvent] = []
        for (minute, raw) in [(0, 300.0), (1, 360), (2, 330), (3, 335), (4, 200), (5, 200)].map({ ($0.0, $0.1) }) {
            let (next, events) = engine.evaluate(poll(raw, at: t0.addingTimeInterval(Double(minute) * 60)), state: state)
            state = next
            log += events
        }
        #expect(log.count == 2)
        guard case .fired(let alert, let notify) = log[0] else { Issue.record("expected fire"); return }
        #expect(alert.id == "sustainedCPU:1")
        #expect(notify)
        #expect(log[1] == .resolved(id: "sustainedCPU:1"))
    }
}
