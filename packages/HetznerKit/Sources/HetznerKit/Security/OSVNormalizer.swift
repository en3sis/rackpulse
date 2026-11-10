import Foundation

enum OSVNormalizer {
    static let aliasLimit = 64
    static let linkLimit = 24

    static func advisories(_ records: [OSVRecord], for query: PackageQuery) -> [Advisory] {
        var parent: [String: String] = [:]
        func find(_ key: String) -> String {
            guard parent[key] != nil else {
                parent[key] = key
                return key
            }
            var root = key
            while let next = parent[root], next != root { root = next }
            var node = key
            while let next = parent[node], next != root {
                parent[node] = root
                node = next
            }
            return root
        }
        func union(_ a: String, _ b: String) {
            let x = find(a)
            let y = find(b)
            if x != y { parent[max(x, y)] = min(x, y) }
        }

        let unique = Dictionary(records.map { ($0.id, $0) }, uniquingKeysWith: { first, _ in first }).values.sorted { $0.id < $1.id }
        let notices = unique.filter(\.isNotice)
        let entries = unique.filter { !$0.isNotice }

        for record in entries {
            let keys = record.groupKeys
            for key in keys.dropFirst() { union(keys[0], key) }
            _ = find(keys[0])
        }
        var noticeGroups: [String: [OSVRecord]] = [:]
        for notice in notices {
            let keys = notice.cves.isEmpty ? [notice.id] : notice.cves
            for key in keys { noticeGroups[find(key), default: []].append(notice) }
        }

        var members: [String: [OSVRecord]] = [:]
        for record in entries { members[find(record.groupKeys[0]), default: []].append(record) }
        let roots = Set(members.keys).union(noticeGroups.keys)
        var keysByRoot: [String: [String]] = [:]
        for key in parent.keys { keysByRoot[find(key), default: []].append(key) }

        return roots.map { root in
            merge(
                records: members[root] ?? [],
                notices: Array(Set(noticeGroups[root] ?? [])).sorted { $0.id < $1.id },
                keys: keysByRoot[root] ?? [root],
                query: query
            )
        }.sorted(by: Advisory.ordered)
    }

    static func merge(records: [OSVRecord], notices: [OSVRecord], keys: [String], query: PackageQuery) -> Advisory {
        let ordered = records.sorted { rank($0) < rank($1) || (rank($0) == rank($1) && $0.id < $1.id) }
        let cves = keys.filter { $0.hasPrefix("CVE-") }.sorted()
        let ghsas = keys.filter { $0.hasPrefix("GHSA-") }.sorted()
        let primary = cves.first ?? ghsas.first ?? ordered.first?.id ?? notices.first?.id ?? keys.sorted().first ?? ""
        let everything = ordered + notices
        var aliases: [String] = []
        for value in cves + ghsas + ordered.map(\.id) + ordered.flatMap(\.aliases) where value != primary && !aliases.contains(value) {
            aliases.append(value)
        }

        let (severity, hidden) = rating(ordered + notices, query: query)
        let malware = everything.contains(where: \.isMalware)
        let score = OSVRecord.score(ordered + notices)
        let fixed = earliest(ordered.compactMap { $0.fixedVersion(for: query) }, query: query)
            ?? earliest(notices.compactMap { $0.fixedVersion(for: query) }, query: query)
        let lead = ordered.first ?? notices.first

        return Advisory(
            id: primary,
            aliases: Array(aliases.sorted().prefix(aliasLimit)),
            summary: summary(ordered, notices: notices),
            severity: malware ? .critical : severity,
            score: score,
            fixedVersion: fixed,
            fixedBy: notices.map(\.id).filter { $0 != primary },
            published: lead?.publishedDate,
            modified: everything.compactMap(\.modifiedDate).max(),
            kind: malware ? .malware : .vulnerability,
            links: Array(links(primary: primary, records: everything, cves: cves, ghsas: ghsas, query: query).prefix(linkLimit)),
            source: .osv,
            hidden: malware ? false : hidden
        )
    }

    private static func rank(_ record: OSVRecord) -> Int {
        if record.isDistroRecord { return 0 }
        if record.id.hasPrefix("GHSA-") { return 1 }
        if record.id.hasPrefix("CVE-") { return 3 }
        return 2
    }

    private static func earliest(_ versions: [String], query: PackageQuery) -> String? {
        versions.min { VersionOrder.isLess($0, $1, ecosystem: query.ecosystem) }
    }

    static func rating(_ records: [OSVRecord], query: PackageQuery) -> (AdvisorySeverity, Bool) {
        if query.isOperatingSystem {
            for record in records {
                if let priority = record.ubuntuPriority {
                    switch priority {
                    case "critical": return (.critical, false)
                    case "high": return (.high, false)
                    case "medium": return (.medium, false)
                    case "low": return (.low, false)
                    case "negligible": return (.low, true)
                    default: break
                    }
                }
                if let urgency = record.debianUrgency(for: query) {
                    switch urgency {
                    case "high": return (.high, false)
                    case "medium": return (.medium, false)
                    case "low": return (.low, false)
                    case "unimportant": return (.low, true)
                    default: break
                    }
                }
            }
        }
        for record in records {
            switch record.databaseSpecific?.severity?.uppercased() {
            case "CRITICAL": return (.critical, false)
            case "HIGH": return (.high, false)
            case "MODERATE", "MEDIUM": return (.medium, false)
            case "LOW": return (.low, false)
            default: continue
            }
        }
        if let score = OSVRecord.score(records) {
            return (AdvisorySeverity(score: score), false)
        }
        return (.unknown, false)
    }

    static func summary(_ records: [OSVRecord], notices: [OSVRecord]) -> String {
        let candidates = records.compactMap(\.summary) + records.compactMap { $0.details.map(firstParagraph) } + notices.compactMap(\.summary)
        guard let text = candidates.map(clean).first(where: { !$0.isEmpty }) else { return "" }
        guard text.count > 300 else { return text }
        let cut = text.prefix(300)
        let end = cut.lastIndex(of: " ") ?? cut.endIndex
        return String(cut[..<end]) + "..."
    }

    private static func firstParagraph(_ text: String) -> String {
        text.components(separatedBy: "\n\n").first ?? text
    }

    private static func clean(_ text: String) -> String {
        text.split(whereSeparator: \.isWhitespace).joined(separator: " ")
    }

    static func isSafeID(_ id: String) -> Bool {
        guard let first = id.unicodeScalars.first, CharacterSet.alphanumerics.contains(first), id.count <= 128 else { return false }
        return id.unicodeScalars.allSatisfy { $0.isASCII && (CharacterSet.alphanumerics.contains($0) || "-._".unicodeScalars.contains($0)) }
    }

    static func links(primary: String, records: [OSVRecord], cves: [String], ghsas: [String], query: PackageQuery) -> [AdvisoryLink] {
        var result: [AdvisoryLink] = []
        func add(_ title: String, _ url: String) {
            if let link = AdvisoryLink(title: title, url: url), !result.contains(link) { result.append(link) }
        }
        let ids = [primary] + records.map(\.id)
        for id in ids where isSafeID(id) && (id == primary || !id.hasPrefix("CVE-")) {
            if id == primary || !(OSVRecord.noticePrefixes + OSVRecord.distroPrefixes).contains(where: { id.hasPrefix($0) }) {
                add("OSV \(id)", "https://osv.dev/vulnerability/\(id)")
            }
        }
        for cve in cves where isSafeID(cve) {
            if query.ecosystem.hasPrefix("Ubuntu:") { add("Ubuntu \(cve)", "https://ubuntu.com/security/\(cve)") }
            if query.ecosystem.hasPrefix("Debian:") { add("Debian \(cve)", "https://security-tracker.debian.org/tracker/\(cve)") }
            if query.ecosystem.hasPrefix("Alpine:") { add("Alpine \(cve)", "https://security.alpinelinux.org/vuln/\(cve)") }
            add("NVD \(cve)", "https://nvd.nist.gov/vuln/detail/\(cve)")
        }
        for record in records where isSafeID(record.id) {
            if record.id.hasPrefix("USN-") { add(record.id, "https://ubuntu.com/security/notices/\(record.id)") }
            if ["DSA-", "DLA-", "DTSA-"].contains(where: { record.id.hasPrefix($0) }) {
                add(record.id, "https://security-tracker.debian.org/tracker/\(record.id)")
            }
        }
        for ghsa in ghsas where isSafeID(ghsa) { add(ghsa, "https://github.com/advisories/\(ghsa)") }
        return result
    }
}
