import Foundation

public enum RuleKind: String, Sendable, Hashable, Codable, CaseIterable {
    case serverDown, sustainedCPU, storageBox, trafficQuota, diskIO, budget, unexpectedChange
    case diskSpace, memory, container, failedService, rebootRequired, agentUnreachable

    public static let agentKinds: [RuleKind] = [.diskSpace, .memory, .container, .failedService, .rebootRequired, .agentUnreachable]

    public var needsAgent: Bool { Self.agentKinds.contains(self) }
}

public enum Delivery: String, Sendable, Hashable, Codable {
    case push, digest, banner
}

public enum Severity: String, Sendable, Hashable, Codable, Comparable {
    case info, warning, critical

    private var rank: Int {
        switch self {
        case .info: 0
        case .warning: 1
        case .critical: 2
        }
    }

    public static func < (lhs: Severity, rhs: Severity) -> Bool { lhs.rank < rhs.rank }
}

public struct RuleConfig: Sendable, Hashable, Codable, Identifiable {
    public var kind: RuleKind
    public var enabled: Bool
    public var threshold: Double
    public var duration: TimeInterval
    public var secondaryThreshold: Double?
    public var delivery: Delivery

    public var id: RuleKind { kind }

    public init(
        kind: RuleKind,
        enabled: Bool,
        threshold: Double,
        duration: TimeInterval = 0,
        secondaryThreshold: Double? = nil,
        delivery: Delivery
    ) {
        self.kind = kind
        self.enabled = enabled
        self.threshold = threshold
        self.duration = duration
        self.secondaryThreshold = secondaryThreshold
        self.delivery = delivery
    }

    public static let defaults: [RuleConfig] = [
        RuleConfig(kind: .serverDown, enabled: true, threshold: 2, delivery: .push),
        RuleConfig(kind: .sustainedCPU, enabled: true, threshold: 85, duration: 600, delivery: .push),
        RuleConfig(kind: .storageBox, enabled: true, threshold: 0.85, secondaryThreshold: 14, delivery: .push),
        RuleConfig(kind: .trafficQuota, enabled: true, threshold: 0.8, delivery: .banner),
        RuleConfig(kind: .diskIO, enabled: false, threshold: 3, duration: 900, delivery: .banner),
        RuleConfig(kind: .budget, enabled: true, threshold: 0, delivery: .banner),
        RuleConfig(kind: .unexpectedChange, enabled: true, threshold: 0, delivery: .push),
        RuleConfig(kind: .diskSpace, enabled: true, threshold: 0.9, delivery: .push),
        RuleConfig(kind: .memory, enabled: true, threshold: 0.9, duration: 600, delivery: .push),
        RuleConfig(kind: .container, enabled: true, threshold: 3, delivery: .push),
        RuleConfig(kind: .failedService, enabled: true, threshold: 0, delivery: .push),
        RuleConfig(kind: .rebootRequired, enabled: true, threshold: 0, delivery: .banner),
        RuleConfig(kind: .agentUnreachable, enabled: true, threshold: 3, delivery: .push),
    ]
}

public struct QuietHours: Sendable, Hashable, Codable {
    public var startMinute: Int
    public var endMinute: Int

    public init(startMinute: Int, endMinute: Int) {
        self.startMinute = startMinute
        self.endMinute = endMinute
    }

    public func contains(_ date: Date, calendar: Calendar = .current) -> Bool {
        let parts = calendar.dateComponents([.hour, .minute], from: date)
        let minute = (parts.hour ?? 0) * 60 + (parts.minute ?? 0)
        if startMinute <= endMinute { return minute >= startMinute && minute < endMinute }
        return minute >= startMinute || minute < endMinute
    }
}

public struct ServerAlertOverride: Sendable, Hashable, Codable {
    public enum Mode: String, Sendable, Hashable, Codable, CaseIterable {
        case global, custom, off
    }

    public static let kinds: [RuleKind] = [.serverDown, .sustainedCPU, .trafficQuota, .diskIO] + RuleKind.agentKinds

    public var mode: Mode
    public var rules: [RuleConfig]

    public init(mode: Mode = .global, rules: [RuleConfig] = []) {
        self.mode = mode
        self.rules = rules
    }
}

public struct AlertSettings: Sendable, Hashable, Codable {
    public static let defaultSummaryMinute = 9 * 60

    public var rules: [RuleConfig]
    public var quietHours: QuietHours?
    public var budget: Decimal?
    public var clearAfter: Int
    public var summaryMinute: Int?
    public var servers: [Int64: ServerAlertOverride] = [:]

    enum CodingKeys: String, CodingKey {
        case rules, quietHours, budget, clearAfter, summaryMinute
    }

    public var dailySummaryMinute: Int {
        get { summaryMinute ?? Self.defaultSummaryMinute }
        set { summaryMinute = newValue }
    }

    public init(
        rules: [RuleConfig] = RuleConfig.defaults,
        quietHours: QuietHours? = nil,
        budget: Decimal? = nil,
        clearAfter: Int = 2
    ) {
        self.rules = rules
        self.quietHours = quietHours
        self.budget = budget
        self.clearAfter = clearAfter
    }

    public func rule(_ kind: RuleKind) -> RuleConfig? {
        rules.first { $0.kind == kind && $0.enabled }
    }

    public func rule(_ kind: RuleKind, server id: Int64?) -> RuleConfig? {
        guard let id, let override = servers[id], override.mode != .global else { return rule(kind) }
        guard override.mode == .custom else { return nil }
        guard let custom = override.rules.first(where: { $0.kind == kind }) else { return rule(kind) }
        return custom.enabled ? custom : nil
    }
}

public struct PollSnapshot: Sendable {
    public var time: Date
    public var servers: [Server]
    public var metrics: [Int64: ServerMetrics]
    public var iopsBaseline: [Int64: Double]
    public var actions: [ServerAction]
    public var volumes: [Volume]?
    public var firewalls: [Firewall]?
    public var storageBoxes: [StorageBox]?
    public var storageForecasts: [Int64: UsageForecast]
    public var costForecast: Decimal?
    public var agents: [Int64: AgentReport]

    public init(
        time: Date,
        servers: [Server],
        metrics: [Int64: ServerMetrics] = [:],
        iopsBaseline: [Int64: Double] = [:],
        actions: [ServerAction] = [],
        volumes: [Volume]? = nil,
        firewalls: [Firewall]? = nil,
        storageBoxes: [StorageBox]? = nil,
        storageForecasts: [Int64: UsageForecast] = [:],
        costForecast: Decimal? = nil,
        agents: [Int64: AgentReport] = [:]
    ) {
        self.time = time
        self.servers = servers
        self.metrics = metrics
        self.iopsBaseline = iopsBaseline
        self.actions = actions
        self.volumes = volumes
        self.firewalls = firewalls
        self.storageBoxes = storageBoxes
        self.storageForecasts = storageForecasts
        self.costForecast = costForecast
        self.agents = agents
    }
}

public struct AgentReport: Sendable, Hashable {
    public var current: AgentSnapshot?
    public var failures: Int

    public init(current: AgentSnapshot?, failures: Int) {
        self.current = current
        self.failures = failures
    }
}

public struct FiringAlert: Sendable, Hashable, Codable, Identifiable {
    public let id: String
    public let kind: RuleKind
    public let severity: Severity
    public let title: String
    public let since: Date

    public init(id: String, kind: RuleKind, severity: Severity, title: String, since: Date) {
        self.id = id
        self.kind = kind
        self.severity = severity
        self.title = title
        self.since = since
    }
}

public enum AlertEvent: Sendable, Hashable {
    case fired(FiringAlert, notify: Bool)
    case resolved(id: String)
}

public struct AlertState: Sendable, Hashable, Codable {
    struct Track: Sendable, Hashable, Codable {
        var kind: RuleKind
        var serverID: Int64?
        var raised = 0
        var cleared = 0
        var aboveSince: Date?
        var alert: FiringAlert?
    }

    struct Inventory: Sendable, Hashable, Codable {
        var servers: [Int64: String]
        var volumes: [Int64: String]?
        var firewalls: [Int64: String]?
    }

    var tracks: [String: Track] = [:]
    var inventory: Inventory?
    var lastPoll: Date?
    var newestAction: Date?
    public private(set) var snoozed: [String: Date] = [:]

    public init() {}

    public var firing: [FiringAlert] {
        tracks.values.compactMap(\.alert).sorted { ($0.severity, $1.since) > ($1.severity, $0.since) }
    }

    public var worstSeverity: Severity? { firing.map(\.severity).max() }

    public mutating func snooze(_ id: String, until date: Date) {
        snoozed[id] = date
    }

    public func isSnoozed(_ id: String, at now: Date) -> Bool {
        (snoozed[id] ?? .distantPast) > now
    }

    public static let resumeGap: TimeInterval = 15 * 60

    public var hasPolled: Bool { lastPoll != nil }

    public func sameAlerts(as other: AlertState) -> Bool {
        tracks == other.tracks && inventory == other.inventory && newestAction == other.newestAction && snoozed == other.snoozed
    }

    public func resumed(at now: Date) -> AlertState {
        var state = self
        state.snoozed = snoozed.filter { $0.value > now }
        guard let lastPoll, now.timeIntervalSince(lastPoll) > Self.resumeGap else { return state }
        for (id, track) in tracks where track.alert == nil {
            state.tracks[id] = nil
        }
        for (id, track) in state.tracks where track.alert != nil {
            state.tracks[id]?.cleared = 0
        }
        return state
    }
}
