import Foundation

public enum FixStatus: String, Sendable, Hashable, Codable {
    case noFix, available, pending
}

public struct Finding: Sendable, Hashable, Codable, Identifiable {
    public let package: InstalledPackage
    public let advisories: [Advisory]
    public let pendingVersion: String?

    public init(package: InstalledPackage, advisories: [Advisory], pendingVersion: String? = nil) {
        self.package = package
        self.advisories = advisories.sorted(by: Advisory.ordered)
        self.pendingVersion = pendingVersion
    }

    public var id: String { package.id }
    public var ecosystem: String { package.query.ecosystem }
    public var visibleAdvisories: [Advisory] { advisories.filter { !$0.hidden } }
    public var hidden: Bool { visibleAdvisories.isEmpty }
    public var severity: AdvisorySeverity { (hidden ? advisories : visibleAdvisories).map(\.severity).max() ?? .unknown }
    public var knownExploited: Bool { advisories.contains(where: \.isExploited) }
    public var malware: Bool { advisories.contains(where: \.isMalware) }
    public var highestEPSS: EPSSScore? { advisories.compactMap(\.epss).max { $0.probability < $1.probability } }

    public var fixedVersion: String? {
        advisories.compactMap(\.fixedVersion).max { VersionOrder.isLess($0, $1, ecosystem: ecosystem) }
    }

    public var fixAvailable: Bool { fixedVersion != nil }

    public var fixPending: Bool {
        guard let fixedVersion, let pendingVersion else { return false }
        return !VersionOrder.isLess(pendingVersion, fixedVersion, ecosystem: ecosystem)
    }

    public func fixStatus(of advisory: Advisory) -> FixStatus {
        guard let fixed = advisory.fixedVersion else { return .noFix }
        if let pendingVersion, !VersionOrder.isLess(pendingVersion, fixed, ecosystem: ecosystem) { return .pending }
        return .available
    }

    static func ordered(_ lhs: Finding, _ rhs: Finding) -> Bool {
        let a = (lhs.malware ? 1 : 0, lhs.knownExploited ? 1 : 0, lhs.hidden ? 0 : 1, lhs.severity.rank, lhs.highestEPSS?.probability ?? 0)
        let b = (rhs.malware ? 1 : 0, rhs.knownExploited ? 1 : 0, rhs.hidden ? 0 : 1, rhs.severity.rank, rhs.highestEPSS?.probability ?? 0)
        if a != b { return a > b }
        return (lhs.package.name, lhs.id) < (rhs.package.name, rhs.id)
    }
}

public struct SeverityCounts: Sendable, Hashable, Codable {
    public var critical = 0
    public var high = 0
    public var medium = 0
    public var low = 0
    public var unknown = 0

    public init() {}

    public subscript(_ severity: AdvisorySeverity) -> Int {
        get {
            switch severity {
            case .critical: critical
            case .high: high
            case .medium: medium
            case .low: low
            case .unknown: unknown
            }
        }
        set {
            switch severity {
            case .critical: critical = newValue
            case .high: high = newValue
            case .medium: medium = newValue
            case .low: low = newValue
            case .unknown: unknown = newValue
            }
        }
    }

    public var total: Int { critical + high + medium + low + unknown }
}

public struct SourceStatus: Sendable, Hashable, Codable, Identifiable {
    public enum State: String, Sendable, Hashable, Codable {
        case ok, partial, failed, skipped
    }

    public let source: SourceName
    public let state: State
    public let message: String?
    public let checkedAt: Date?
    public let quota: SocketQuota?

    public init(source: SourceName, state: State, message: String? = nil, checkedAt: Date? = nil, quota: SocketQuota? = nil) {
        self.source = source
        self.state = state
        self.message = message
        self.checkedAt = checkedAt
        self.quota = quota
    }

    public var id: SourceName { source }
}

public struct SecurityResult: Sendable, Hashable, Codable {
    public let serverID: Int64
    public let checkedAt: Date
    public let reportTime: Date
    public let osName: String?
    public let osEcosystem: String?
    public let onlineChecks: Bool
    public let findings: [Finding]
    public let pendingUpdates: Int
    public let pendingSecurityUpdates: Int
    public let updatesError: String?
    public let listsTime: Date?
    public let checks: [SecurityCheck]
    public let sources: [SourceStatus]
    public let skippedKernelSources: [String]

    public init(
        serverID: Int64, checkedAt: Date, reportTime: Date, osName: String? = nil, osEcosystem: String? = nil,
        onlineChecks: Bool = false, findings: [Finding] = [], pendingUpdates: Int = 0, pendingSecurityUpdates: Int = 0,
        updatesError: String? = nil, listsTime: Date? = nil, checks: [SecurityCheck] = [], sources: [SourceStatus] = [],
        skippedKernelSources: [String] = []
    ) {
        self.serverID = serverID
        self.checkedAt = checkedAt
        self.reportTime = reportTime
        self.osName = osName
        self.osEcosystem = osEcosystem
        self.onlineChecks = onlineChecks
        self.findings = findings.sorted(by: Finding.ordered)
        self.pendingUpdates = pendingUpdates
        self.pendingSecurityUpdates = pendingSecurityUpdates
        self.updatesError = updatesError
        self.listsTime = listsTime
        self.checks = checks
        self.sources = sources
        self.skippedKernelSources = skippedKernelSources
    }

    public struct Item: Sendable, Hashable {
        public let finding: Finding
        public let advisory: Advisory

        public var key: String {
            advisory.kind == .vulnerability ? advisory.id : "\(finding.package.location.key)|\(finding.ecosystem)|\(finding.package.name)|\(advisory.id)"
        }
    }

    public var items: [Item] {
        var seen: Set<String> = []
        var result: [Item] = []
        for finding in findings {
            for advisory in finding.advisories where !advisory.hidden {
                let item = Item(finding: finding, advisory: advisory)
                if seen.insert(item.key).inserted { result.append(item) }
            }
        }
        return result
    }

    public var counts: SeverityCounts {
        var counts = SeverityCounts()
        for item in items { counts[item.advisory.severity] += 1 }
        return counts
    }

    public var exploitedCount: Int { items.filter { $0.advisory.isExploited }.count }
    public var malwareCount: Int { items.filter { $0.advisory.isMalware }.count }
    public var fixableCount: Int { items.filter { $0.advisory.hasFix }.count }
    public var pendingFixCount: Int { items.filter { $0.finding.fixStatus(of: $0.advisory) == .pending }.count }

    public var systemFindings: [Finding] { findings.filter { $0.package.location == .system } }
    public var dependencyFindings: [Finding] {
        findings.filter { if case .lockfile = $0.package.location { true } else { false } }
    }
    public var imageFindings: [Finding] {
        findings.filter { if case .image = $0.package.location { true } else { false } }
    }

    public var failingChecks: [SecurityCheck] { checks.filter(\.countsForAlert) }

    public var lookupFailed: Bool {
        onlineChecks && sources.contains { $0.state == .failed && ($0.source == .osv || $0.source == .socket) }
    }

    public var incomplete: Bool {
        onlineChecks && sources.contains { $0.state == .failed || $0.state == .partial }
    }

    public func alerting(minimum: AdvisorySeverity) -> [Item] {
        items.filter { Self.alerts($0, minimum: minimum) }
    }

    public static func alerts(_ item: Item, minimum: AdvisorySeverity) -> Bool {
        item.advisory.urgent || (item.advisory.severity >= minimum && minimum != .unknown && item.advisory.hasFix)
    }

    public func source(_ name: SourceName) -> SourceStatus? {
        sources.first { $0.source == name }
    }
}
