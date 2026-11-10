import Foundation

public struct SecurityReview: Sendable {
    public enum Fix: Sendable, Hashable {
        case command(String)
        case text(String)
    }

    public struct Group: Sendable, Hashable, Identifiable {
        public let finding: Finding
        public let items: [SecurityResult.Item]
        public let fix: Fix?

        public var id: String { finding.id }
        public var package: InstalledPackage { finding.package }
        public var location: String { SecurityReview.location(finding.package.location) }
        public var advisories: [Advisory] { items.map(\.advisory) }
        public var fixNow: Bool { items.contains(where: SecurityReview.fixNow) }
        public var hasFix: Bool { items.contains { $0.advisory.hasFix } }
        public var lowPriority: Bool { items.isEmpty }
        public var severity: AdvisorySeverity { advisories.map(\.severity).max() ?? finding.severity }
        public var exploited: Bool { advisories.contains(where: \.isExploited) }
        public var malware: Bool { advisories.contains(where: \.isMalware) }
        public var likelyExploited: Bool { !exploited && advisories.contains { $0.epss?.likelyExploited == true } }

        public var fixedVersion: String? {
            advisories.compactMap(\.fixedVersion).max { VersionOrder.isLess($0, $1, ecosystem: finding.ecosystem) }
        }
    }

    public static let imageScanVersion = "0.4.0"

    public let fixNow: [Group]
    public let withFix: [Group]
    public let noFix: [Group]
    public let lowPriority: [Group]
    public let ignored: [SecurityResult.Item]
    public let failingChecks: [SecurityCheck]

    public init(_ result: SecurityResult, ignoring keys: Set<String> = []) {
        var fixNow: [Group] = []
        var withFix: [Group] = []
        var noFix: [Group] = []
        var lowPriority: [Group] = []
        var ignored: [SecurityResult.Item] = []
        var seenIgnored: Set<String> = []
        for finding in result.findings {
            var items: [SecurityResult.Item] = []
            var skipped = false
            for advisory in finding.advisories where !advisory.hidden {
                let item = SecurityResult.Item(finding: finding, advisory: advisory)
                if keys.contains(item.key) {
                    skipped = true
                    if seenIgnored.insert(item.key).inserted { ignored.append(item) }
                } else {
                    items.append(item)
                }
            }
            if items.isEmpty && (skipped || !finding.hidden) { continue }
            let fixItems = items.isEmpty ? finding.advisories.map { SecurityResult.Item(finding: finding, advisory: $0) } : items
            let group = Group(finding: finding, items: items, fix: Self.fix(finding, items: fixItems, osEcosystem: result.osEcosystem))
            if group.lowPriority {
                lowPriority.append(group)
            } else if group.fixNow {
                fixNow.append(group)
            } else if group.hasFix {
                withFix.append(group)
            } else {
                noFix.append(group)
            }
        }
        self.fixNow = fixNow
        self.withFix = withFix
        self.noFix = noFix
        self.lowPriority = lowPriority
        self.ignored = ignored
        failingChecks = result.failingChecks
    }

    public var visible: [Group] { fixNow + withFix + noFix }

    public static func fixNow(_ item: SecurityResult.Item) -> Bool {
        let advisory = item.advisory
        return advisory.isExploited || advisory.isMalware || (advisory.severity == .critical && advisory.hasFix)
    }

    public static func location(_ location: PackageLocation) -> String {
        switch location {
        case .system: "Host"
        case .lockfile(_, let path): path
        case .image(_, let name, let path): path.map { "Image \(name), \($0)" } ?? "Image \(name)"
        }
    }

    static func validName(_ name: String, extra: Set<Character>, minimum: Int) -> Bool {
        guard name.count >= minimum, name.count <= 128, let first = name.first, first.isASCII, first.isLowercase || first.isNumber else { return false }
        return name.allSatisfy { $0.isASCII && ($0.isLowercase || $0.isNumber || extra.contains($0)) }
    }

    static func debianName(_ name: String) -> Bool {
        validName(name, extra: ["+", ".", "-"], minimum: 2)
    }

    static func alpineName(_ name: String) -> Bool {
        validName(name, extra: ["+", ".", "_", "-"], minimum: 1)
    }

    public static func fix(_ finding: Finding, items: [SecurityResult.Item], osEcosystem: String?) -> Fix? {
        guard let fixed = items.compactMap(\.advisory.fixedVersion).max(by: { VersionOrder.isLess($0, $1, ecosystem: finding.ecosystem) }) else {
            return nil
        }
        let package = finding.package
        switch package.location {
        case .system:
            let names = (package.binaries.isEmpty ? [package.name] : package.binaries).sorted()
            let ecosystem = osEcosystem ?? package.query.ecosystem
            if ecosystem.hasPrefix("Debian:") || ecosystem.hasPrefix("Ubuntu:") {
                guard names.allSatisfy(debianName) else { return nil }
                return .command("sudo apt install --only-upgrade \(names.joined(separator: " "))")
            }
            if ecosystem.hasPrefix("Alpine:") {
                guard names.allSatisfy(alpineName) else { return nil }
                return .command("sudo apk upgrade \(names.joined(separator: " "))")
            }
            return nil
        case .lockfile(_, let path):
            return .text("Upgrade \(package.name) to \(fixed) or later in \(path).")
        case .image(_, let name, _):
            return .text("Rebuild or pull image \(name) with \(package.name) \(fixed) or later, then recreate its containers.")
        }
    }

    public struct FleetAdvisory<Server: Hashable & Sendable>: Sendable, Hashable, Identifiable {
        public let key: String
        public let title: String
        public internal(set) var severity: AdvisorySeverity
        public internal(set) var fixNow: Bool
        public internal(set) var hasFix: Bool
        public internal(set) var exploited: Bool
        public internal(set) var malware: Bool
        public internal(set) var servers: [Server]

        public var id: String { key }
    }

    public struct FleetCheck<Server: Hashable & Sendable>: Sendable, Hashable, Identifiable {
        public let id: String
        public let title: String
        public let servers: [Server]
    }

    public static func fleet<Server: Hashable & Sendable>(
        _ entries: [(server: Server, result: SecurityResult, ignored: Set<String>)]
    ) -> (advisories: [FleetAdvisory<Server>], checks: [FleetCheck<Server>]) {
        var order: [String] = []
        var advisories: [String: FleetAdvisory<Server>] = [:]
        var checkOrder: [String] = []
        var checks: [String: (title: String, servers: [Server])] = [:]
        for entry in entries {
            var seen: Set<String> = []
            for finding in entry.result.findings {
                for advisory in finding.advisories where !advisory.hidden {
                    let item = SecurityResult.Item(finding: finding, advisory: advisory)
                    guard !entry.ignored.contains(item.key) else { continue }
                    if var builder = advisories[item.key] {
                        builder.severity = max(builder.severity, advisory.severity)
                        builder.fixNow = builder.fixNow || Self.fixNow(item)
                        builder.hasFix = builder.hasFix || advisory.hasFix
                        builder.exploited = builder.exploited || advisory.isExploited
                        builder.malware = builder.malware || advisory.isMalware
                        if seen.insert(item.key).inserted { builder.servers.append(entry.server) }
                        advisories[item.key] = builder
                    } else {
                        order.append(item.key)
                        seen.insert(item.key)
                        advisories[item.key] = FleetAdvisory(
                            key: item.key, title: FindingDecision.title(item), severity: advisory.severity, fixNow: Self.fixNow(item),
                            hasFix: advisory.hasFix, exploited: advisory.isExploited, malware: advisory.isMalware, servers: [entry.server]
                        )
                    }
                }
            }
            for check in entry.result.failingChecks {
                if checks[check.id] == nil {
                    checkOrder.append(check.id)
                    checks[check.id] = (check.title, [])
                }
                if checks[check.id]?.servers.contains(entry.server) == false { checks[check.id]?.servers.append(entry.server) }
            }
        }
        let grouped = order.compactMap { advisories[$0] }
        let sorted = grouped.sorted { lhs, rhs in
            let a = (lhs.fixNow ? 1 : 0, lhs.malware || lhs.exploited ? 1 : 0, lhs.hasFix ? 1 : 0, lhs.severity.rank, lhs.servers.count)
            let b = (rhs.fixNow ? 1 : 0, rhs.malware || rhs.exploited ? 1 : 0, rhs.hasFix ? 1 : 0, rhs.severity.rank, rhs.servers.count)
            if a != b { return a > b }
            return lhs.title < rhs.title
        }
        let failing = checkOrder.compactMap { id in checks[id].map { FleetCheck(id: id, title: $0.title, servers: $0.servers) } }
            .sorted { ($0.servers.count, $1.title) > ($1.servers.count, $0.title) }
        return (sorted, failing)
    }
}

public enum AgentVersion {
    public static func components(_ version: String) -> [Int]? {
        var text = Substring(version.trimmingCharacters(in: .whitespaces))
        if text.first == "v" || text.first == "V" { text = text.dropFirst() }
        let core = text.prefix { $0.isASCII && ($0.isNumber || $0 == ".") }
        let parts = core.split(separator: ".", omittingEmptySubsequences: false)
        guard !parts.isEmpty, parts.allSatisfy({ !$0.isEmpty }) else { return nil }
        let numbers = parts.compactMap { Int($0) }
        return numbers.count == parts.count ? numbers : nil
    }

    public static func isOlder(_ version: String, than minimum: String) -> Bool {
        guard let lhs = components(version), let rhs = components(minimum) else { return false }
        for index in 0..<max(lhs.count, rhs.count) {
            let a = index < lhs.count ? lhs[index] : 0
            let b = index < rhs.count ? rhs[index] : 0
            if a != b { return a < b }
        }
        return false
    }
}
