import Foundation
import HetznerKit

@MainActor
final class AlertCenter {
    struct Delivery {
        var post: [OutgoingNotification] = []
        var remove: Set<String> = []
    }

    private static let saveInterval: TimeInterval = 300

    private let database: LocalDatabase
    private var planner = PlannerState()
    private var plannerLoaded = false
    private var ledgers: [String: LedgerRecord] = [:]
    private var savedStates: [UUID: AlertState] = [:]
    private var savedAt: [UUID: Date] = [:]
    private var restoring: [UUID: Task<AlertState?, Never>] = [:]
    private var pruned: Set<UUID> = []
    private var outgoing: [OutgoingNotification] = []
    private var removals: Set<String> = []
    private var snoozes: Set<String> = []
    private var commit = AlertCommit()
    private var flushing: Task<Delivery, Never>?

    init(database: LocalDatabase) {
        self.database = database
    }

    static func target(project: Project, server: Int64) -> String {
        "\(project.provider.targetPrefix)/\(project.id.uuidString)/server/\(server)"
    }

    static func notificationID(project: UUID, alert: String) -> String {
        "\(project.uuidString)|\(alert)"
    }

    func restore(_ project: UUID) async -> AlertState? {
        if let task = restoring[project] { return await task.value }
        let task = Task { @MainActor () -> AlertState? in
            guard let state = try? await database.alertState(project: project.uuidString) else { return nil }
            self.savedStates[project] = state
            return state.resumed(at: .now)
        }
        restoring[project] = task
        return await task.value
    }

    func forget(projects: Set<UUID>) {
        savedStates = savedStates.filter { projects.contains($0.key) }
        restoring = restoring.filter { projects.contains($0.key) }
        guard !projects.isEmpty else { return }
        let keep = Set(projects.map(\.uuidString))
        ledgers = ledgers.filter { keep.contains(String($0.key.split(separator: "/", omittingEmptySubsequences: false).dropFirst().first ?? "")) }
        Task { try? await database.keepProjects(keep) }
    }

    func snoozed(project: UUID, alert: String) {
        snoozes.insert(Self.notificationID(project: project, alert: alert))
    }

    func reloaded(_ project: UUID) {
        restoring[project] = nil
    }

    func collect(
        project: Project, poller: ProjectPoller, events: [AlertEvent], context: PollContext,
        findings: [Int64: SecurityResult], decisions: [Int64: DecisionCheck], subtitle: (Int64?) -> String
    ) async {
        let now = context.now
        let data = poller.data
        guard data.lastUpdated == now else { return }
        let key = project.id.uuidString
        let saved = savedStates[project.id]
        let stale = now.timeIntervalSince(savedAt[project.id] ?? .distantPast) >= Self.saveInterval
        if saved.map({ !$0.sameAlerts(as: data.alerts) }) ?? true || (stale && saved != data.alerts) {
            savedStates[project.id] = data.alerts
            savedAt[project.id] = now
            commit.alertStates[key] = data.alerts
        }

        for event in events {
            switch event {
            case .fired(let alert, let notify):
                guard !FindingLedger.kinds.contains(alert.kind) else { continue }
                let serverID = ProjectAlert(project: project, alert: alert).serverID
                let server = serverID.flatMap { id in data.servers.first { $0.id == id } }
                let rule = context.alertSettings.rule(alert.kind, server: serverID)
                let notification = OutgoingNotification(
                    id: Self.notificationID(project: project.id, alert: alert.id), project: key,
                    target: serverID.map { Self.target(project: project, server: $0) }, kind: alert.kind, snoozeID: alert.id,
                    heading: server?.name ?? project.name, title: alert.title, subtitle: subtitle(serverID),
                    body: "Started \(alert.since.formatted(date: .omitted, time: .shortened)). Rule: \(alert.kind.title).",
                    severity: alert.severity, delivery: rule?.delivery ?? .banner, created: now
                )
                if notify {
                    outgoing.append(notification)
                } else {
                    let outcome: DeliveryOutcome = data.alerts.isSnoozed(alert.id, at: now) ? .snoozed : .popoverOnly
                    commit.log.append(logEntry(notification, outcome, now))
                }
            case .resolved(let id):
                if let kind = RuleKind(rawValue: String(id.prefix { $0 != ":" })), FindingLedger.kinds.contains(kind) { continue }
                removals.insert(Self.notificationID(project: project.id, alert: id))
            }
        }

        await reconcileFindings(project: project, data: data, context: context, findings: findings, decisions: decisions, subtitle: subtitle)

        if pruned.insert(project.id).inserted {
            let targets = Set(data.servers.map { Self.target(project: project, server: $0.id) })
            try? await database.removeTargets(notIn: targets, prefix: "\(project.provider.targetPrefix)/\(key)/")
            ledgers = ledgers.filter { !$0.key.hasPrefix("\(project.provider.targetPrefix)/\(key)/") || targets.contains($0.key) }
        }
    }

    private func reconcileFindings(
        project: Project, data: ProjectData, context: PollContext, findings: [Int64: SecurityResult], decisions: [Int64: DecisionCheck],
        subtitle: (Int64?) -> String
    ) async {
        let now = context.now
        for (serverID, result) in findings.sorted(by: { $0.key < $1.key }) {
            guard let server = data.servers.first(where: { $0.id == serverID }) else { continue }
            let target = Self.target(project: project, server: serverID)
            if ledgers[target] == nil {
                let loaded = (try? await database.ledger(target: target)) ?? LedgerRecord(target: target)
                if ledgers[target] == nil { ledgers[target] = loaded }
            }
            guard let record = ledgers[target] else { continue }
            let scan = FindingLedger.scan(result, settings: context.alertSettings, decisions: decisions[serverID] ?? DecisionCheck())
            let outcome = FindingLedger.reconcile(record, scan: scan)
            guard outcome.changed else { continue }
            ledgers[target] = outcome.record
            commit.ledgers.removeAll { $0.target == target }
            commit.ledgers.append(outcome.record)

            for kind in [RuleKind.vulnerability, .hardening] {
                let trackID = "\(kind.rawValue):\(serverID)"
                let id = Self.notificationID(project: project.id, alert: trackID)
                let left = outcome.resolved.contains { $0.kind == kind } || outcome.ignored.contains { $0.kind == kind }
                if left && !outcome.record.openNotified(kind) {
                    removals.insert(id)
                }
                let news = outcome.news(kind)
                guard let notice = FindingNotice.compose(news, kind: kind, server: server.name, baseline: outcome.baselineKinds.contains(kind)) else { continue }
                let notification = OutgoingNotification(
                    id: id, project: project.id.uuidString, target: target, kind: kind, snoozeID: trackID,
                    heading: server.name, title: notice.title, subtitle: subtitle(serverID), body: notice.body,
                    severity: notice.severity, delivery: context.alertSettings.rule(kind, server: serverID)?.delivery ?? .banner, created: now,
                    items: notice.items
                )
                if data.alerts.isSnoozed(trackID, at: now) {
                    commit.log.append(logEntry(notification, .snoozed, now))
                } else {
                    outgoing.append(notification)
                }
            }
        }
    }

    func flush(_ settings: AlertSettings, now: Date = .now) async -> Delivery {
        let previous = flushing
        let task = Task { @MainActor in
            _ = await previous?.value
            return await self.performFlush(settings, now: now)
        }
        flushing = task
        return await task.value
    }

    private func performFlush(_ settings: AlertSettings, now: Date) async -> Delivery {
        if !plannerLoaded {
            plannerLoaded = true
            if let stored = try? await database.plannerState() { planner = stored }
            try? await database.prune(now: now)
        }
        let incoming = outgoing
        let remove = removals
        let snoozed = snoozes
        var change = commit
        outgoing = []
        removals = []
        snoozes = []
        commit = AlertCommit()

        let (unsnoozed, silenced) = NotificationPlanner.drop(snoozed, from: planner, now: now, outcome: .snoozed)
        let (kept, dropped) = NotificationPlanner.drop(remove, from: unsnoozed, now: now)
        let config = PlannerConfig(quietHours: settings.quietHours, summaryMinute: settings.dailySummaryMinute, rateLimitedKinds: FindingLedger.kinds)
        let output = NotificationPlanner.plan(incoming.filter { !remove.contains($0.id) }, state: kept, config: config, now: now)
        if output.state != planner { change.planner = output.state }
        planner = output.state
        change.log += silenced + dropped + output.log
        do {
            try await database.commit(change)
        } catch {
            requeue(change)
        }
        return Delivery(post: output.post, remove: remove)
    }

    private func requeue(_ failed: AlertCommit) {
        var merged = failed
        merged.alertStates.merge(commit.alertStates) { _, newer in newer }
        let newer = Set(commit.ledgers.map(\.target))
        merged.ledgers = failed.ledgers.filter { !newer.contains($0.target) } + commit.ledgers
        merged.planner = commit.planner ?? failed.planner
        merged.log = failed.log + commit.log
        commit = merged
    }

    private func logEntry(_ notification: OutgoingNotification, _ outcome: DeliveryOutcome, _ time: Date) -> NotificationRecord {
        NotificationRecord(time: time, project: notification.project, target: notification.target, kind: notification.kind,
                           group: notification.id, title: notification.title, outcome: outcome)
    }
}
