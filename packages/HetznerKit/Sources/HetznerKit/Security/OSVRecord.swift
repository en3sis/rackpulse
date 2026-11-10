import Foundation

struct OSVRecord: Sendable, Hashable, Codable {
    var id: String
    var modified: String?
    var published: String?
    var summary: String?
    var details: String?
    var aliases: [String]
    var upstream: [String]
    var related: [String]
    var severity: [Score]
    var databaseSpecific: DatabaseSpecific?
    var affected: [Affected]

    enum CodingKeys: String, CodingKey {
        case id, modified, published, summary, details, aliases, upstream, related, severity, affected
        case databaseSpecific = "database_specific"
    }

    init(
        id: String, modified: String? = nil, published: String? = nil, summary: String? = nil, details: String? = nil,
        aliases: [String] = [], upstream: [String] = [], related: [String] = [], severity: [Score] = [], databaseSpecific: DatabaseSpecific? = nil,
        affected: [Affected] = []
    ) {
        self.id = id
        self.modified = modified
        self.published = published
        self.summary = summary
        self.details = details
        self.aliases = aliases
        self.upstream = upstream
        self.related = related
        self.severity = severity
        self.databaseSpecific = databaseSpecific
        self.affected = affected
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        id = try container.decode(String.self, forKey: .id)
        modified = container.optional(String.self, forKey: .modified)
        published = container.optional(String.self, forKey: .published)
        summary = container.optional(String.self, forKey: .summary)
        details = container.optional(String.self, forKey: .details)
        aliases = container.lossy([String].self, forKey: .aliases)
        upstream = container.lossy([String].self, forKey: .upstream)
        related = container.lossy([String].self, forKey: .related)
        severity = container.lossy([Score].self, forKey: .severity)
        databaseSpecific = container.optional(DatabaseSpecific.self, forKey: .databaseSpecific)
        affected = container.lossy([Affected].self, forKey: .affected)
    }

    struct Score: Sendable, Hashable, Codable {
        var type: String
        var score: String
    }

    struct DatabaseSpecific: Sendable, Hashable, Codable {
        var severity: String?
        var cweIDs: [String]

        enum CodingKeys: String, CodingKey {
            case severity
            case cweIDs = "cwe_ids"
        }

        init(severity: String? = nil, cweIDs: [String] = []) {
            self.severity = severity
            self.cweIDs = cweIDs
        }

        init(from decoder: Decoder) throws {
            let container = try decoder.container(keyedBy: CodingKeys.self)
            severity = container.optional(String.self, forKey: .severity)
            cweIDs = container.lossy([String].self, forKey: .cweIDs)
        }
    }

    struct Affected: Sendable, Hashable, Codable {
        var package: Package
        var ranges: [Range]
        var ecosystemSpecific: EcosystemSpecific?

        enum CodingKeys: String, CodingKey {
            case package, ranges
            case ecosystemSpecific = "ecosystem_specific"
        }

        init(package: Package, ranges: [Range], ecosystemSpecific: EcosystemSpecific? = nil) {
            self.package = package
            self.ranges = ranges
            self.ecosystemSpecific = ecosystemSpecific
        }

        init(from decoder: Decoder) throws {
            let container = try decoder.container(keyedBy: CodingKeys.self)
            package = try container.decode(Package.self, forKey: .package)
            ranges = container.lossy([Range].self, forKey: .ranges)
            ecosystemSpecific = container.optional(EcosystemSpecific.self, forKey: .ecosystemSpecific)
        }
    }

    struct Package: Sendable, Hashable, Codable {
        var name: String
        var ecosystem: String
    }

    struct Range: Sendable, Hashable, Codable {
        var type: String?
        var events: [Event]

        init(type: String?, events: [Event]) {
            self.type = type
            self.events = events
        }

        enum CodingKeys: String, CodingKey {
            case type, events
        }

        init(from decoder: Decoder) throws {
            let container = try decoder.container(keyedBy: CodingKeys.self)
            type = container.optional(String.self, forKey: .type)
            events = container.lossy([Event].self, forKey: .events)
        }
    }

    struct Event: Sendable, Hashable, Codable {
        var introduced: String?
        var fixed: String?
        var lastAffected: String?

        enum CodingKeys: String, CodingKey {
            case introduced, fixed
            case lastAffected = "last_affected"
        }

        var point: String { introduced ?? fixed ?? lastAffected ?? "" }

        init(introduced: String? = nil, fixed: String? = nil, lastAffected: String? = nil) {
            self.introduced = introduced
            self.fixed = fixed
            self.lastAffected = lastAffected
        }

        init(from decoder: Decoder) throws {
            let container = try decoder.container(keyedBy: CodingKeys.self)
            introduced = container.optional(String.self, forKey: .introduced)
            fixed = container.optional(String.self, forKey: .fixed)
            lastAffected = container.optional(String.self, forKey: .lastAffected)
        }
    }

    struct EcosystemSpecific: Sendable, Hashable, Codable {
        var urgency: String?

        init(urgency: String? = nil) {
            self.urgency = urgency
        }

        enum CodingKeys: String, CodingKey {
            case urgency
        }

        init(from decoder: Decoder) throws {
            let container = try decoder.container(keyedBy: CodingKeys.self)
            urgency = container.optional(String.self, forKey: .urgency)
        }
    }

    static let detailsLimit = 600
    static let idLimit = 128
    static let idListLimit = 64
    static let severityLimit = 8
    static let affectedLimit = 256
    static let rangeLimit = 32
    static let eventLimit = 64
    static let versionLimit = 256

    func trimmed() -> OSVRecord {
        var copy = self
        copy.details = details.map { String($0.prefix(Self.detailsLimit)) }
        copy.summary = summary.map { String($0.prefix(Self.detailsLimit)) }
        copy.aliases = Self.ids(aliases)
        copy.upstream = Self.ids(upstream)
        copy.related = Self.ids(related)
        copy.severity = Array(severity.filter { $0.type.utf8.count <= 32 && $0.score.utf8.count <= 256 }.prefix(Self.severityLimit))
        copy.databaseSpecific = databaseSpecific.map {
            DatabaseSpecific(severity: $0.severity.map { String($0.prefix(32)) }, cweIDs: Self.ids($0.cweIDs))
        }
        copy.affected = Array(affected
            .filter { !$0.package.ecosystem.hasPrefix("Ubuntu:Pro:") && $0.package.name.utf8.count <= 256 && $0.package.ecosystem.utf8.count <= 64 }
            .prefix(Self.affectedLimit)
            .map { entry in
                var entry = entry
                entry.ranges = Array(entry.ranges.filter(\.usable).prefix(Self.rangeLimit).map { range in
                    var range = range
                    range.events = Array(range.events.filter { $0.point.utf8.count <= Self.versionLimit }.prefix(Self.eventLimit))
                    return range
                })
                entry.ecosystemSpecific = entry.ecosystemSpecific.map { EcosystemSpecific(urgency: $0.urgency.map { String($0.prefix(32)) }) }
                return entry
            })
        return copy
    }

    private static func ids(_ values: [String]) -> [String] {
        Array(values.filter { $0.utf8.count <= idLimit }.prefix(idListLimit))
    }

    var modifiedDate: Date? { modified.flatMap(OSVDate.parse) }
    var publishedDate: Date? { published.flatMap(OSVDate.parse) }

    static let noticePrefixes = ["USN-", "DSA-", "DLA-", "DTSA-", "ELA-"]
    static let distroPrefixes = ["UBUNTU-CVE-", "DEBIAN-CVE-", "ALPINE-CVE-"]

    var isNotice: Bool { Self.noticePrefixes.contains { id.hasPrefix($0) } }
    var isDistroRecord: Bool { Self.distroPrefixes.contains { id.hasPrefix($0) } }
    var isMalware: Bool { id.hasPrefix("MAL-") || (databaseSpecific?.cweIDs.contains("CWE-506") ?? false) }

    var cves: [String] {
        var result: [String] = []
        let linked = isNotice ? related.filter { value in Self.distroPrefixes.contains { value.hasPrefix($0) } } : []
        for value in [id] + aliases + upstream + linked {
            guard let cve = Self.cve(value), !result.contains(cve) else { continue }
            result.append(cve)
        }
        return result
    }

    static func cve(_ value: String) -> String? {
        if value.hasPrefix("CVE-") { return value }
        if distroPrefixes.contains(where: { value.hasPrefix($0) }), let range = value.range(of: "CVE-") {
            return String(value[range.lowerBound...])
        }
        return nil
    }

    var groupKeys: [String] {
        var keys = cves
        for value in [id] + aliases where value.hasPrefix("GHSA-") && !keys.contains(value) { keys.append(value) }
        if !keys.contains(id) { keys.append(id) }
        return keys
    }

    func matching(_ query: PackageQuery) -> [Affected] {
        affected.filter {
            $0.package.ecosystem == query.ecosystem
                && PackageQuery.normalizedName($0.package.name, ecosystem: query.ecosystem) == query.name
        }
    }

    func fixedVersion(for query: PackageQuery) -> String? {
        let ecosystem = query.ecosystem
        func less(_ a: String, _ b: String) -> Bool { VersionOrder.isLess(a, b, ecosystem: ecosystem) }
        func normalized(_ value: String) -> String { PackageQuery.normalizedVersion(value, ecosystem: ecosystem) }
        var newer: [String] = []
        var containing: [String] = []
        for range in matching(query).flatMap({ $0.ranges.filter(\.usable) }) {
            let events = range.events.sorted { a, b in
                switch (a.point, b.point) {
                case ("0", "0"): return false
                case ("0", _): return true
                case (_, "0"): return false
                default: return less(normalized(a.point), normalized(b.point))
                }
            }
            var start: String?
            for event in events {
                if let introduced = event.introduced {
                    start = normalized(introduced)
                } else if let fixed = event.fixed.map(normalized) {
                    if less(query.version, fixed) {
                        newer.append(fixed)
                        if let start, start == "0" || !less(query.version, start) { containing.append(fixed) }
                    }
                    start = nil
                } else if event.lastAffected != nil {
                    start = nil
                }
            }
        }
        return (containing.isEmpty ? newer : containing).min(by: less)
    }

    var ubuntuPriority: String? {
        severity.first { $0.type.caseInsensitiveCompare("Ubuntu") == .orderedSame }?.score.lowercased()
    }

    func debianUrgency(for query: PackageQuery) -> String? {
        matching(query).compactMap { $0.ecosystemSpecific?.urgency }.first?
            .lowercased().trimmingCharacters(in: CharacterSet(charactersIn: "* "))
    }

    var cvssVectors: [String] {
        severity.filter { $0.type == "CVSS_V3" }.map(\.score)
    }

    var cvssV4Vectors: [String] {
        severity.filter { $0.type == "CVSS_V4" }.map(\.score)
    }

    static func score(_ records: [OSVRecord]) -> Double? {
        records.lazy.flatMap(\.cvssVectors).compactMap(CVSS3.baseScore).first
            ?? records.lazy.flatMap(\.cvssV4Vectors).compactMap(CVSS4.baseScore).first
    }
}

extension OSVRecord.Range {
    var usable: Bool {
        guard let type else { return true }
        return type == "ECOSYSTEM" || type == "SEMVER"
    }
}

enum OSVDate {
    static func parse(_ text: String) -> Date? {
        if let date = JSON.parseDate(text) { return date }
        guard let dot = text.firstIndex(of: "."), let zone = text[dot...].firstIndex(where: { $0 == "Z" || $0 == "+" || $0 == "-" }) else {
            return nil
        }
        let fraction = text[text.index(after: dot)..<zone].prefix(3)
        return JSON.parseDate(String(text[..<dot]) + "." + fraction.padding(toLength: 3, withPad: "0", startingAt: 0) + text[zone...])
    }
}
