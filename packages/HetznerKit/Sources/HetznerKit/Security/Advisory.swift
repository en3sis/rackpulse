import Foundation

public enum AdvisorySeverity: String, Sendable, Hashable, Codable, Comparable, CaseIterable {
    case unknown, low, medium, high, critical

    public init(from decoder: Decoder) throws {
        self = AdvisorySeverity(rawValue: try decoder.singleValueContainer().decode(String.self)) ?? .unknown
    }

    public init(rank: Int) {
        self = Self.allCases.first { $0.rank == rank } ?? (rank > 4 ? .critical : .unknown)
    }

    public init(score: Double) {
        switch score {
        case 9...: self = .critical
        case 7..<9: self = .high
        case 4..<7: self = .medium
        case let value where value > 0: self = .low
        default: self = .unknown
        }
    }

    public var rank: Int {
        switch self {
        case .unknown: 0
        case .low: 1
        case .medium: 2
        case .high: 3
        case .critical: 4
        }
    }

    public static func < (lhs: AdvisorySeverity, rhs: AdvisorySeverity) -> Bool { lhs.rank < rhs.rank }
}

public enum AdvisoryKind: String, Sendable, Hashable, Codable {
    case vulnerability, malware, supplyChain

    public init(from decoder: Decoder) throws {
        self = AdvisoryKind(rawValue: try decoder.singleValueContainer().decode(String.self)) ?? .vulnerability
    }
}

public enum SourceName: String, Sendable, Hashable, Codable, CaseIterable, Identifiable {
    case osv, kev, epss, socket

    public var id: String { rawValue }

    public var title: String {
        switch self {
        case .osv: "OSV.dev"
        case .kev: "CISA Known Exploited Vulnerabilities"
        case .epss: "FIRST EPSS"
        case .socket: "Socket"
        }
    }

    public var host: String {
        switch self {
        case .osv: "api.osv.dev"
        case .kev: "www.cisa.gov"
        case .epss: "epss.empiricalsecurity.com"
        case .socket: "api.socket.dev"
        }
    }
}

public struct KnownExploited: Sendable, Hashable, Codable {
    public let dateAdded: String?
    public let ransomware: Bool

    public init(dateAdded: String?, ransomware: Bool) {
        self.dateAdded = dateAdded
        self.ransomware = ransomware
    }
}

public struct EPSSScore: Sendable, Hashable, Codable {
    public static let likelyPercentile = 0.95

    public let probability: Double
    public let percentile: Double

    public init(probability: Double, percentile: Double) {
        self.probability = probability
        self.percentile = percentile
    }

    public var likelyExploited: Bool { percentile >= Self.likelyPercentile }
}

public struct AdvisoryLink: Sendable, Hashable, Codable {
    public static let allowedHosts: Set<String> = [
        "osv.dev", "ubuntu.com", "security-tracker.debian.org", "nvd.nist.gov", "github.com", "socket.dev",
        "www.cve.org", "security.alpinelinux.org", "cisa.gov", "www.cisa.gov",
    ]

    public let title: String
    public let url: URL

    public init?(title: String, url: String) {
        guard let parsed = URL(string: url), Self.isAllowed(parsed) else { return nil }
        self.title = title
        self.url = parsed
    }

    public static func isAllowed(_ url: URL) -> Bool {
        guard url.scheme?.lowercased() == "https", let host = url.host()?.lowercased() else { return false }
        return allowedHosts.contains(host) && url.user() == nil && url.port == nil
    }
}

public struct Advisory: Sendable, Hashable, Codable, Identifiable {
    public var id: String
    public var aliases: [String]
    public var summary: String
    public var severity: AdvisorySeverity
    public var score: Double?
    public var fixedVersion: String?
    public var fixedBy: [String]
    public var published: Date?
    public var modified: Date?
    public var knownExploited: KnownExploited?
    public var epss: EPSSScore?
    public var kind: AdvisoryKind
    public var links: [AdvisoryLink]
    public var source: SourceName
    public var hidden: Bool

    public init(
        id: String, aliases: [String] = [], summary: String = "", severity: AdvisorySeverity = .unknown, score: Double? = nil,
        fixedVersion: String? = nil, fixedBy: [String] = [], published: Date? = nil, modified: Date? = nil,
        knownExploited: KnownExploited? = nil, epss: EPSSScore? = nil, kind: AdvisoryKind = .vulnerability,
        links: [AdvisoryLink] = [], source: SourceName = .osv, hidden: Bool = false
    ) {
        self.id = id
        self.aliases = aliases
        self.summary = summary
        self.severity = severity
        self.score = score
        self.fixedVersion = fixedVersion
        self.fixedBy = fixedBy
        self.published = published
        self.modified = modified
        self.knownExploited = knownExploited
        self.epss = epss
        self.kind = kind
        self.links = links
        self.source = source
        self.hidden = hidden
    }

    public var cves: [String] { ([id] + aliases).filter { $0.hasPrefix("CVE-") } }
    public var hasFix: Bool { fixedVersion != nil }
    public var isExploited: Bool { knownExploited != nil }
    public var isMalware: Bool { kind == .malware }

    public var urgent: Bool { isExploited || isMalware }

    mutating func apply(_ enrichment: Enrichment) {
        if let exploited = enrichment.knownExploited {
            knownExploited = exploited
            severity = max(severity, .high)
            hidden = false
        }
        if let score = enrichment.epss {
            epss = max(epss?.probability ?? -1, score.probability) == score.probability ? score : epss
        }
    }

    static func ordered(_ lhs: Advisory, _ rhs: Advisory) -> Bool {
        let a = (lhs.isMalware ? 1 : 0, lhs.isExploited ? 1 : 0, lhs.severity.rank, lhs.epss?.probability ?? 0)
        let b = (rhs.isMalware ? 1 : 0, rhs.isExploited ? 1 : 0, rhs.severity.rank, rhs.epss?.probability ?? 0)
        if a != b { return a > b }
        return lhs.id < rhs.id
    }
}

public struct Enrichment: Sendable, Hashable {
    public var knownExploited: KnownExploited?
    public var epss: EPSSScore?

    public init(knownExploited: KnownExploited? = nil, epss: EPSSScore? = nil) {
        self.knownExploited = knownExploited
        self.epss = epss
    }
}
