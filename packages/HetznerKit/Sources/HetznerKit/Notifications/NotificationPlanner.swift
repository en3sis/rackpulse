import Foundation

public enum DeliveryOutcome: String, Sendable, Hashable, Codable, CaseIterable {
    case sent, summarized, quietHours, dailySummary, rateLimited, snoozed, popoverOnly, resolved
}

public struct OutgoingNotification: Sendable, Hashable, Codable, Identifiable {
    public var id: String
    public var project: String
    public var target: String?
    public var kind: RuleKind?
    public var snoozeID: String?
    public var heading: String
    public var title: String
    public var subtitle: String
    public var body: String
    public var severity: Severity
    public var delivery: Delivery
    public var created: Date
    public var items: [String]

    public init(
        id: String, project: String, target: String? = nil, kind: RuleKind? = nil, snoozeID: String? = nil,
        heading: String, title: String, subtitle: String = "", body: String = "", severity: Severity,
        delivery: Delivery = .push, created: Date, items: [String] = []
    ) {
        self.id = id
        self.project = project
        self.target = target
        self.kind = kind
        self.snoozeID = snoozeID
        self.heading = heading
        self.title = title
        self.subtitle = subtitle
        self.body = body
        self.severity = severity
        self.delivery = delivery
        self.created = created
        self.items = items
    }

    public var thread: String { target ?? project }
    var covered: [String] { items.isEmpty ? [NotificationPlanner.strip(title, heading: heading)] : items }
    public var isSummary: Bool { kind == nil }

    func record(_ outcome: DeliveryOutcome, at time: Date) -> NotificationRecord {
        NotificationRecord(time: time, project: project, target: target, kind: kind, group: id, title: title, outcome: outcome)
    }
}

public struct PendingNotification: Sendable, Hashable, Codable {
    public var notification: OutgoingNotification
    public var reason: DeliveryOutcome
}

public struct PlannerState: Sendable, Hashable, Codable {
    public var pending: [PendingNotification] = []
    public var lastSent: [String: Date] = [:]
    public var lastDailySummary: Date?

    public init() {}

    public var pendingCount: Int { pending.count }
}

public struct PlannerConfig: Sendable {
    public var quietHours: QuietHours?
    public var summaryMinute: Int
    public var calendar: Calendar
    public var rateWindow: TimeInterval
    public var rateLimitedKinds: Set<RuleKind>
    public var burstLimit: Int

    public init(
        quietHours: QuietHours?, summaryMinute: Int = AlertSettings.defaultSummaryMinute, calendar: Calendar = .current,
        rateWindow: TimeInterval = 3_600, rateLimitedKinds: Set<RuleKind> = [], burstLimit: Int = 3
    ) {
        self.quietHours = quietHours
        self.summaryMinute = summaryMinute
        self.calendar = calendar
        self.rateWindow = rateWindow
        self.rateLimitedKinds = rateLimitedKinds
        self.burstLimit = burstLimit
    }
}

public struct PlannerOutput: Sendable {
    public let post: [OutgoingNotification]
    public let state: PlannerState
    public let log: [NotificationRecord]
}

public enum NotificationPlanner {
    public static let summaryLines = 5
    static let sentRetention: TimeInterval = 86_400

    public static func plan(_ incoming: [OutgoingNotification], state previous: PlannerState, config: PlannerConfig, now: Date) -> PlannerOutput {
        var state = previous
        var log: [NotificationRecord] = []
        var immediate: [OutgoingNotification] = []
        let quiet = config.quietHours?.contains(now, calendar: config.calendar) ?? false

        for notification in incoming {
            if notification.delivery == .banner {
                log.append(notification.record(.popoverOnly, at: now))
            } else if notification.delivery == .digest {
                state.pending.append(PendingNotification(notification: notification, reason: .dailySummary))
                log.append(notification.record(.dailySummary, at: now))
            } else if quiet {
                state.pending.append(PendingNotification(notification: notification, reason: .quietHours))
                log.append(notification.record(.quietHours, at: now))
            } else if rateLimited(notification, state: state, config: config, now: now) {
                state.pending.append(PendingNotification(notification: notification, reason: .rateLimited))
                log.append(notification.record(.rateLimited, at: now))
            } else {
                immediate.append(notification)
            }
        }

        let dailyDue = !quiet && dailySummaryDue(state.lastDailySummary, config: config, now: now)
        var afterQuiet: [OutgoingNotification] = []
        var daily: [OutgoingNotification] = []
        var keep: [PendingNotification] = []
        for item in state.pending {
            switch item.reason {
            case .quietHours where !quiet:
                afterQuiet.append(item.notification)
            case .rateLimited where !quiet && now.timeIntervalSince(state.lastSent[item.notification.id] ?? .distantPast) >= config.rateWindow:
                immediate.append(item.notification)
            case .dailySummary where dailyDue:
                daily.append(item.notification)
            default:
                keep.append(item)
            }
        }
        state.pending = keep
        if dailyDue { state.lastDailySummary = now }

        var post: [OutgoingNotification] = []
        func deliver(_ group: [OutgoingNotification], summary: (Int) -> String, id: String, always: Bool = false) {
            let merged = merge(group)
            guard !merged.isEmpty else { return }
            if merged.count == 1 && !always {
                post.append(merged[0])
                log.append(merged[0].record(.sent, at: now))
            } else {
                post.append(summarize(merged, id: id, title: summary(merged.count), now: now))
                log += merged.map { $0.record(.summarized, at: now) }
            }
            for notification in merged { state.lastSent[notification.id] = now }
        }

        let stamp = Int(now.timeIntervalSince1970)
        deliver(afterQuiet, summary: { "\($0) alerts during quiet hours" }, id: "summary|quiet|\(stamp)")
        deliver(daily, summary: { $0 == 1 ? "Daily summary: 1 alert" : "Daily summary: \($0) alerts" }, id: "summary|daily|\(stamp)", always: true)
        let ready = merge(immediate)
        if ready.count > config.burstLimit {
            deliver(ready, summary: { "\($0) new alerts" }, id: "summary|burst|\(stamp)")
        } else {
            for notification in ready { deliver([notification], summary: { _ in "" }, id: notification.id) }
        }

        state.lastSent = state.lastSent.filter { now.timeIntervalSince($0.value) < max(sentRetention, config.rateWindow) }
        return PlannerOutput(post: post, state: state, log: log)
    }

    public static func drop(
        _ ids: Set<String>, from state: PlannerState, now: Date, outcome: DeliveryOutcome = .resolved
    ) -> (PlannerState, [NotificationRecord]) {
        var next = state
        let dropped = state.pending.filter { ids.contains($0.notification.id) }
        next.pending.removeAll { ids.contains($0.notification.id) }
        return (next, dropped.map { $0.notification.record(outcome, at: now) })
    }

    static func rateLimited(_ notification: OutgoingNotification, state: PlannerState, config: PlannerConfig, now: Date) -> Bool {
        guard let kind = notification.kind, config.rateLimitedKinds.contains(kind) else { return false }
        if state.pending.contains(where: { $0.notification.id == notification.id && $0.reason == .rateLimited }) { return true }
        guard let last = state.lastSent[notification.id] else { return false }
        return now.timeIntervalSince(last) < config.rateWindow
    }

    static func dailySummaryDue(_ last: Date?, config: PlannerConfig, now: Date) -> Bool {
        let start = config.calendar.startOfDay(for: now)
        guard let scheduled = config.calendar.date(byAdding: .minute, value: config.summaryMinute, to: start), now >= scheduled else { return false }
        return (last ?? .distantPast) < scheduled
    }

    static func merge(_ notifications: [OutgoingNotification]) -> [OutgoingNotification] {
        var order: [String] = []
        var groups: [String: [OutgoingNotification]] = [:]
        for notification in notifications {
            if groups[notification.id] == nil { order.append(notification.id) }
            groups[notification.id, default: []].append(notification)
        }
        return order.compactMap { id in
            guard let group = groups[id]?.sorted(by: { $0.created < $1.created }), var latest = group.last else { return nil }
            guard group.count > 1 else { return latest }
            let items = unique(group.reversed().flatMap(\.covered))
            latest.severity = group.map(\.severity).max() ?? latest.severity
            latest.items = items
            guard items.count > 1 else { return latest }
            latest.title = "\(latest.heading): \(items.count) alerts"
            latest.body = lines(items)
            return latest
        }
    }

    static func summarize(_ notifications: [OutgoingNotification], id: String, title: String, now: Date) -> OutgoingNotification {
        let projects = Set(notifications.map(\.project))
        return OutgoingNotification(
            id: id, project: projects.count == 1 ? projects.first! : "", heading: "", title: title,
            subtitle: projects.count == 1 ? notifications[0].subtitle : "",
            body: lines(unique(notifications.map(\.title))),
            severity: notifications.map(\.severity).max() ?? .info, created: now
        )
    }

    static func lines(_ titles: [String]) -> String {
        let shown = titles.prefix(summaryLines)
        let more = titles.count > summaryLines ? ["And \(titles.count - summaryLines) more."] : []
        return (shown + more).joined(separator: "\n")
    }

    static func strip(_ title: String, heading: String) -> String {
        let prefix = "\(heading): "
        return !heading.isEmpty && title.hasPrefix(prefix) ? String(title.dropFirst(prefix.count)) : title
    }

    static func unique(_ values: [String]) -> [String] {
        var seen: Set<String> = []
        return values.filter { seen.insert($0).inserted }
    }
}
