import Foundation

public struct FindingDecision: Sendable, Hashable, Codable, Identifiable {
    public enum Reason: String, Sendable, Hashable, Codable, CaseIterable, Identifiable {
        case notAffected, acceptRisk, fixLater

        public var id: String { rawValue }

        public var title: String {
            switch self {
            case .notAffected: "Not affected"
            case .acceptRisk: "Accept risk"
            case .fixLater: "Fix later"
            }
        }
    }

    public enum End: Sendable, Hashable, Codable {
        case date(Date)
        case fixAvailable

        public var date: Date? {
            if case .date(let date) = self { return date }
            return nil
        }
    }

    public enum Lapse: String, Sendable, Hashable, Codable {
        case expired, fixAvailable, exploited, malware

        public var title: String {
            switch self {
            case .expired: "The ignore period ended"
            case .fixAvailable: "A fix is available"
            case .exploited: "It is now known to be exploited"
            case .malware: "It is now marked as malware"
            }
        }
    }

    public static let allServers = "*"
    public static let durations = [30, 90]
    public static let lapsedRetention: TimeInterval = 30 * 86_400
    public static let absentRetention: TimeInterval = 30 * 86_400

    public let id: UUID
    public var target: String
    public var key: String
    public var title: String
    public var reason: Reason
    public var note: String
    public var end: End
    public var created: Date
    public var exploited: Bool
    public var malware: Bool
    public var lastSeen: Date?

    public init(
        id: UUID = UUID(), target: String, key: String, title: String, reason: Reason, note: String = "", end: End, created: Date,
        exploited: Bool = false, malware: Bool = false, lastSeen: Date? = nil
    ) {
        self.id = id
        self.target = target
        self.key = key
        self.title = title
        self.reason = reason
        self.note = note
        self.end = end
        self.created = created
        self.exploited = exploited
        self.malware = malware
        self.lastSeen = lastSeen
    }

    public init(
        target: String, item: SecurityResult.Item, reason: Reason, note: String = "", end: End, created: Date, id: UUID = UUID()
    ) {
        self.init(
            id: id, target: target, key: item.key, title: Self.title(item), reason: reason,
            note: note.trimmingCharacters(in: .whitespacesAndNewlines), end: end, created: created,
            exploited: item.advisory.isExploited, malware: item.advisory.isMalware
        )
    }

    public enum Rule: Sendable, Hashable {
        case any
        case notAffectedOnly
        case never
    }

    public static let strictDays = 30

    public static func rule(_ advisory: Advisory) -> Rule {
        if advisory.isMalware { return .never }
        if advisory.isExploited || advisory.severity == .critical { return .notAffectedOnly }
        return .any
    }

    public static func make(
        target: String, item: SecurityResult.Item, reason: Reason, note: String = "", end: End, created: Date
    ) -> FindingDecision? {
        let decision = FindingDecision(target: target, item: item, reason: reason, note: note, end: end, created: created)
        switch rule(item.advisory) {
        case .never:
            return nil
        case .any:
            return decision
        case .notAffectedOnly:
            guard reason == .notAffected, !decision.note.isEmpty, let date = end.date,
                  date <= created.addingTimeInterval(TimeInterval(strictDays) * 86_400 + 60)
            else { return nil }
            return decision
        }
    }

    public static func end(days: Int, from date: Date) -> End {
        .date(date.addingTimeInterval(TimeInterval(days) * 86_400))
    }

    public static func title(_ item: SecurityResult.Item) -> String {
        item.advisory.isMalware
            ? "\(item.finding.package.name) is a malicious package"
            : "\(item.advisory.cves.first ?? item.advisory.id) in \(item.finding.package.name)"
    }

    public static func ledgerKey(_ itemKey: String) -> String {
        "vulnerability|\(itemKey)"
    }

    public var allServers: Bool { target == Self.allServers }

    public func applies(to target: String) -> Bool {
        allServers || self.target == target
    }

    public func lapse(_ facts: ItemFacts?, now: Date) -> Lapse? {
        if let date = end.date, now >= date { return .expired }
        guard let facts else { return nil }
        if facts.malware && !malware { return .malware }
        if facts.exploited && !exploited { return .exploited }
        if end == .fixAvailable && facts.fixAvailable { return .fixAvailable }
        return nil
    }

    public func removable(now: Date) -> Bool {
        if let date = end.date, now.timeIntervalSince(date) > Self.lapsedRetention { return true }
        return now.timeIntervalSince(max(lastSeen ?? created, created)) > Self.absentRetention
    }

    public static func seen(_ decisions: [FindingDecision], results: [String: SecurityResult]) -> Set<UUID> {
        let evidence = results.filter { $0.value.onlineChecks && !$0.value.incomplete }
        let facts = evidence.mapValues(Self.facts)
        var seen: Set<UUID> = []
        for decision in decisions {
            let targets = evidence.keys.filter(decision.applies(to:))
            if targets.isEmpty || targets.contains(where: { facts[$0]?[decision.key] != nil }) { seen.insert(decision.id) }
        }
        return seen
    }

    public struct ItemFacts: Sendable, Hashable {
        public var fixAvailable = false
        public var exploited = false
        public var malware = false

        public init(fixAvailable: Bool = false, exploited: Bool = false, malware: Bool = false) {
            self.fixAvailable = fixAvailable
            self.exploited = exploited
            self.malware = malware
        }
    }

    public static func facts(_ result: SecurityResult) -> [String: ItemFacts] {
        var facts: [String: ItemFacts] = [:]
        for finding in result.findings {
            for advisory in finding.advisories {
                let key = SecurityResult.Item(finding: finding, advisory: advisory).key
                var fact = facts[key] ?? ItemFacts()
                fact.fixAvailable = fact.fixAvailable || advisory.hasFix
                fact.exploited = fact.exploited || advisory.isExploited
                fact.malware = fact.malware || advisory.isMalware
                facts[key] = fact
            }
        }
        return facts
    }

    public static func check(_ decisions: [FindingDecision], target: String, result: SecurityResult?, now: Date) -> DecisionCheck {
        let facts = result.map(Self.facts) ?? [:]
        var check = DecisionCheck()
        let ordered = decisions.filter { $0.applies(to: target) }.sorted { ($0.allServers ? 1 : 0, $0.created) < ($1.allServers ? 1 : 0, $1.created) }
        for decision in ordered {
            if let lapse = decision.lapse(facts[decision.key], now: now) {
                if check.lapsed[decision.key] == nil { check.lapsed[decision.key] = DecisionCheck.Lapsed(decision: decision, lapse: lapse) }
            } else if check.active[decision.key] == nil {
                check.active[decision.key] = decision
            }
        }
        for key in check.active.keys { check.lapsed[key] = nil }
        return check
    }
}

public struct DecisionCheck: Sendable, Hashable {
    public struct Lapsed: Sendable, Hashable {
        public let decision: FindingDecision
        public let lapse: FindingDecision.Lapse
    }

    public var active: [String: FindingDecision] = [:]
    public var lapsed: [String: Lapsed] = [:]

    public init() {}

    public var ignoredKeys: Set<String> { Set(active.keys) }

    public func state(_ itemKey: String) -> FindingSignal.Ignore {
        if active[itemKey] != nil { return .active }
        if lapsed[itemKey] != nil { return .lapsed }
        return .none
    }

    public func isIgnored(_ item: SecurityResult.Item) -> Bool {
        active[item.key] != nil
    }
}

extension SecurityResult {
    public func ignoring(_ keys: Set<String>) -> SecurityResult {
        guard !keys.isEmpty else { return self }
        let kept = findings.compactMap { finding -> Finding? in
            let advisories = finding.advisories.filter { !keys.contains(Item(finding: finding, advisory: $0).key) }
            if advisories.count == finding.advisories.count { return finding }
            return advisories.isEmpty ? nil : Finding(package: finding.package, advisories: advisories, pendingVersion: finding.pendingVersion)
        }
        return SecurityResult(
            serverID: serverID, checkedAt: checkedAt, reportTime: reportTime, osName: osName, osEcosystem: osEcosystem,
            onlineChecks: onlineChecks, findings: kept, pendingUpdates: pendingUpdates, pendingSecurityUpdates: pendingSecurityUpdates,
            updatesError: updatesError, listsTime: listsTime, checks: checks, sources: sources, skippedKernelSources: skippedKernelSources
        )
    }
}
