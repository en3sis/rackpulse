import Foundation

public struct FindingSignal: Sendable, Hashable {
    public enum Ignore: String, Sendable, Hashable {
        case none, active, lapsed
    }

    public let key: String
    public let kind: RuleKind
    public let title: String
    public let rank: Int
    public let exploited: Bool
    public let malware: Bool
    public let aliases: [String]
    public let qualifies: Bool
    public let ignore: Ignore

    public init(
        key: String, kind: RuleKind, title: String, rank: Int = 0, exploited: Bool = false, malware: Bool = false,
        aliases: [String] = [], qualifies: Bool, ignore: Ignore = .none
    ) {
        self.key = key
        self.kind = kind
        self.title = title
        self.rank = rank
        self.exploited = exploited
        self.malware = malware
        self.aliases = aliases
        self.qualifies = qualifies
        self.ignore = ignore
    }

    public var urgent: Bool { exploited || malware }
}

public struct LedgerEntry: Sendable, Hashable, Codable {
    public var key: String
    public var kind: RuleKind
    public var title: String
    public var rank: Int
    public var exploited: Bool
    public var malware: Bool
    public var aliases: [String]
    public var firstSeen: Date
    public var lastSeen: Date
    public var missed: Int
    public var resolvedAt: Date?
    public var notifiedAt: Date?
    public var notifiedRank: Int?
    public var notifiedUrgent: Bool
    public var ignored: Bool

    public init(
        key: String, kind: RuleKind, title: String, rank: Int, exploited: Bool = false, malware: Bool = false, aliases: [String] = [],
        firstSeen: Date, lastSeen: Date, missed: Int = 0, resolvedAt: Date? = nil, notifiedAt: Date? = nil, notifiedRank: Int? = nil,
        notifiedUrgent: Bool = false, ignored: Bool = false
    ) {
        self.key = key
        self.kind = kind
        self.title = title
        self.rank = rank
        self.exploited = exploited
        self.malware = malware
        self.aliases = aliases
        self.firstSeen = firstSeen
        self.lastSeen = lastSeen
        self.missed = missed
        self.resolvedAt = resolvedAt
        self.notifiedAt = notifiedAt
        self.notifiedRank = notifiedRank
        self.notifiedUrgent = notifiedUrgent
        self.ignored = ignored
    }

    public var urgent: Bool { exploited || malware }
    public var isOpen: Bool { resolvedAt == nil }
}

public struct LedgerRecord: Sendable, Hashable {
    public let target: String
    public var lastScan: Date?
    public var scannedKinds: Set<RuleKind>
    public var rules: String
    public var entries: [String: LedgerEntry]

    public init(target: String, lastScan: Date? = nil, scannedKinds: Set<RuleKind> = [], rules: String = "", entries: [String: LedgerEntry] = [:]) {
        self.target = target
        self.lastScan = lastScan
        self.scannedKinds = scannedKinds
        self.rules = rules
        self.entries = entries
    }

    public func openNotified(_ kind: RuleKind) -> Bool {
        entries.values.contains { $0.kind == kind && $0.isOpen && $0.notifiedAt != nil }
    }
}

public struct LedgerScan: Sendable {
    public let time: Date
    public let signals: [FindingSignal]
    public let completeKinds: Set<RuleKind>
    public let rules: String

    public init(time: Date, signals: [FindingSignal], completeKinds: Set<RuleKind>, rules: String = "") {
        self.time = time
        self.signals = signals
        self.completeKinds = completeKinds
        self.rules = rules
    }
}

public struct FindingNews: Sendable, Hashable {
    public enum Change: String, Sendable, Hashable {
        case new, escalated, reopened
    }

    public let entry: LedgerEntry
    public let change: Change
    public let previousRank: Int?
    public let wasUrgent: Bool

    public init(entry: LedgerEntry, change: Change, previousRank: Int? = nil, wasUrgent: Bool = false) {
        self.entry = entry
        self.change = change
        self.previousRank = previousRank
        self.wasUrgent = wasUrgent
    }
}

public struct LedgerOutcome: Sendable {
    public let record: LedgerRecord
    public let news: [FindingNews]
    public let baselineKinds: Set<RuleKind>
    public let resolved: [LedgerEntry]
    public let ignored: [LedgerEntry]
    public let changed: Bool

    public func news(_ kind: RuleKind) -> [FindingNews] {
        news.filter { $0.entry.kind == kind }
    }
}

public enum FindingLedger {
    public static let kinds: Set<RuleKind> = [.vulnerability, .hardening]
    public static let missesToResolve = 2
    public static let reopenSilence: TimeInterval = 7 * 86_400
    public static let resolvedRetention: TimeInterval = 30 * 86_400

    public static func reconcile(_ record: LedgerRecord, scan: LedgerScan) -> LedgerOutcome {
        let rescore = record.lastScan.map { scan.time <= $0 } ?? false
        if rescore && scan.rules == record.rules {
            return LedgerOutcome(record: record, news: [], baselineKinds: [], resolved: [], ignored: [], changed: false)
        }
        let now = rescore ? (record.lastScan ?? scan.time) : scan.time
        var next = record
        next.rules = scan.rules
        var news: [FindingNews] = []
        var resolved: [LedgerEntry] = []
        var ignored: [LedgerEntry] = []
        let baseline = rescore ? [] : scan.completeKinds.subtracting(record.scannedKinds)
        var seen: Set<String> = []
        let scanKeys = Set(scan.signals.map(\.key))

        for signal in scan.signals where seen.insert(signal.key).inserted {
            if next.entries[signal.key] == nil, let moved = aliasMatch(signal, in: next.entries, excluding: scanKeys) {
                var entry = next.entries.removeValue(forKey: moved)!
                entry.key = signal.key
                next.entries[signal.key] = entry
            }
            var entry = next.entries[signal.key]
                ?? LedgerEntry(key: signal.key, kind: signal.kind, title: signal.title, rank: signal.rank,
                               exploited: signal.exploited, malware: signal.malware, firstSeen: now, lastSeen: now)
            var change: FindingNews.Change = entry.notifiedAt == nil ? .new : .escalated
            let wasIgnored = entry.ignored && entry.isOpen
            if let resolvedAt = entry.resolvedAt {
                if now.timeIntervalSince(resolvedAt) > reopenSilence {
                    entry.notifiedAt = nil
                    entry.notifiedRank = nil
                    entry.notifiedUrgent = false
                    change = .reopened
                }
                entry.resolvedAt = nil
            }
            entry.kind = signal.kind
            entry.title = signal.title
            entry.rank = signal.rank
            entry.exploited = signal.exploited
            entry.malware = signal.malware
            entry.aliases = Array(Set(entry.aliases).union(signal.aliases)).sorted()
            entry.lastSeen = now
            entry.missed = 0

            if signal.ignore == .active {
                if !wasIgnored { ignored.append(entry) }
                entry.ignored = true
                entry.notifiedAt = nil
                entry.notifiedRank = nil
                entry.notifiedUrgent = false
                next.entries[signal.key] = entry
                continue
            }
            entry.ignored = false
            if wasIgnored {
                if signal.ignore == .lapsed {
                    change = .reopened
                } else if signal.qualifies {
                    entry.notifiedAt = now
                    entry.notifiedRank = signal.rank
                    entry.notifiedUrgent = signal.urgent
                }
            }

            if signal.qualifies {
                let escalated = entry.notifiedAt != nil
                    && (signal.rank > (entry.notifiedRank ?? signal.rank) || (signal.urgent && !entry.notifiedUrgent))
                if entry.notifiedAt == nil || escalated {
                    let previousRank = entry.notifiedRank
                    let wasUrgent = entry.notifiedUrgent
                    entry.notifiedAt = now
                    entry.notifiedRank = max(signal.rank, entry.notifiedRank ?? 0)
                    entry.notifiedUrgent = entry.notifiedUrgent || signal.urgent
                    news.append(FindingNews(entry: entry, change: change, previousRank: previousRank, wasUrgent: wasUrgent))
                }
            }
            next.entries[signal.key] = entry
        }

        if !rescore {
            for (key, var entry) in next.entries where !seen.contains(key) {
                if let resolvedAt = entry.resolvedAt {
                    if now.timeIntervalSince(resolvedAt) > resolvedRetention { next.entries[key] = nil }
                    continue
                }
                guard scan.completeKinds.contains(entry.kind) else { continue }
                entry.missed += 1
                if entry.missed >= missesToResolve {
                    entry.resolvedAt = now
                    entry.ignored = false
                    resolved.append(entry)
                }
                next.entries[key] = entry
            }
            next.lastScan = now
            next.scannedKinds.formUnion(scan.completeKinds)
        }
        return LedgerOutcome(
            record: next,
            news: news.sorted { ($0.entry.urgent ? 1 : 0, $0.entry.rank, $1.entry.title) > ($1.entry.urgent ? 1 : 0, $1.entry.rank, $0.entry.title) },
            baselineKinds: baseline,
            resolved: resolved,
            ignored: ignored,
            changed: next != record
        )
    }

    static func aliasMatch(_ signal: FindingSignal, in entries: [String: LedgerEntry], excluding keys: Set<String>) -> String? {
        guard !signal.aliases.isEmpty else { return nil }
        let aliases = Set(signal.aliases)
        return entries.values
            .filter { $0.kind == signal.kind && !keys.contains($0.key) && !aliases.isDisjoint(with: $0.aliases) }
            .map(\.key).sorted().first
    }

    public static func scan(_ result: SecurityResult, settings: AlertSettings, decisions: DecisionCheck = DecisionCheck()) -> LedgerScan {
        var signals: [FindingSignal] = []
        var complete: Set<RuleKind> = [.hardening]
        let vulnerabilityRule = settings.rule(.vulnerability, server: result.serverID)
        let hardeningRule = settings.rule(.hardening, server: result.serverID)
        let minimum = AdvisorySeverity(rank: max(1, Int(vulnerabilityRule?.threshold ?? 0)))
        let lookupsComplete = !result.sources.contains { ($0.source == .osv || $0.source == .socket) && ($0.state == .failed || $0.state == .partial) }
        if result.onlineChecks && lookupsComplete { complete.insert(.vulnerability) }
        for item in result.items {
            let advisory = item.advisory
            let title = advisory.isMalware
                ? "\(item.finding.package.name) is a malicious package"
                : "\(advisory.cves.first ?? advisory.id) in \(item.finding.package.name)"
            let names = advisory.kind == .vulnerability ? ([advisory.id] + advisory.aliases) : []
            signals.append(FindingSignal(
                key: FindingDecision.ledgerKey(item.key), kind: .vulnerability, title: title, rank: advisory.severity.rank,
                exploited: advisory.isExploited, malware: advisory.isMalware, aliases: names,
                qualifies: vulnerabilityRule != nil && SecurityResult.alerts(item, minimum: minimum),
                ignore: decisions.state(item.key)
            ))
        }
        for check in result.failingChecks {
            signals.append(FindingSignal(key: "hardening|\(check.id)", kind: .hardening, title: check.title, qualifies: hardeningRule != nil))
        }
        let ignoring = decisions.active.isEmpty ? "" : ",i" + digest(decisions.active.keys.sorted())
        let rules = (vulnerabilityRule == nil ? "v-" : "v\(minimum.rank)") + (hardeningRule == nil ? ",h-" : ",h") + ignoring
        return LedgerScan(time: result.checkedAt, signals: signals, completeKinds: complete, rules: rules)
    }
}

extension FindingLedger {
    static func digest(_ keys: [String]) -> String {
        var hash: UInt64 = 0xcbf2_9ce4_8422_2325
        for byte in keys.joined(separator: "\n").utf8 {
            hash ^= UInt64(byte)
            hash = hash &* 0x0000_0100_0000_01b3
        }
        return String(hash, radix: 16)
    }
}

public enum FindingNotice {
    public static let listLimit = 3

    public static func compose(_ news: [FindingNews], kind: RuleKind, server name: String, baseline: Bool) -> (title: String, body: String, severity: Severity, items: [String])? {
        guard let first = news.first else { return nil }
        let severity: Severity = kind == .vulnerability && news.contains { $0.entry.urgent || $0.entry.rank >= AdvisorySeverity.critical.rank }
            ? .critical : .warning
        let title: String
        if news.count == 1 {
            title = "\(name): \(single(first, kind: kind))"
        } else if kind == .hardening {
            title = "\(name): \(news.count) hardening checks fail"
        } else if baseline {
            title = "\(name): \(news.count) vulnerabilities found"
        } else if news.allSatisfy({ $0.change == .escalated }) {
            title = "\(name): \(news.count) vulnerabilities got worse"
        } else if news.allSatisfy({ $0.change == .reopened }) {
            title = "\(name): \(news.count) vulnerabilities are back"
        } else {
            title = "\(name): \(news.count) new vulnerabilities"
        }
        let lines = news.count == 1 ? [detail(first)] : news.prefix(listLimit).map { line($0) }
        let more = news.count > listLimit ? ["And \(news.count - listLimit) more."] : []
        return (title, (lines + more).filter { !$0.isEmpty }.joined(separator: "\n"), severity, news.map { line($0) })
    }

    private static func single(_ news: FindingNews, kind: RuleKind) -> String {
        let entry = news.entry
        if kind == .vulnerability, news.change == .reopened { return "\(entry.title) is back" }
        guard kind == .vulnerability, news.change == .escalated else { return entry.title }
        if entry.exploited && !news.wasUrgent { return "\(entry.title) is now known to be exploited" }
        return "\(entry.title) is now \(AdvisorySeverity(rank: entry.rank).rawValue)"
    }

    private static func line(_ news: FindingNews) -> String {
        let label = labels(news.entry)
        return label.isEmpty ? news.entry.title : "\(news.entry.title) (\(label))"
    }

    private static func detail(_ news: FindingNews) -> String {
        let label = labels(news.entry)
        return label.isEmpty ? "" : label.prefix(1).uppercased() + label.dropFirst() + "."
    }

    private static func labels(_ entry: LedgerEntry) -> String {
        guard entry.kind == .vulnerability, !entry.malware else { return "" }
        var parts: [String] = []
        let severity = AdvisorySeverity(rank: entry.rank)
        if severity != .unknown { parts.append(severity.rawValue) }
        if entry.exploited { parts.append("known to be exploited") }
        return parts.joined(separator: ", ")
    }
}
