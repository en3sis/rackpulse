import Foundation

public enum PackageLocation: Sendable, Hashable, Codable {
    case system
    case lockfile(project: String, path: String)
    case image(id: String, name: String, path: String?)

    public var key: String {
        switch self {
        case .system: "system"
        case .lockfile(let project, let path): "lockfile:\(project):\(path)"
        case .image(let id, _, let path): "image:\(id):\(path ?? "")"
        }
    }

    var rank: Int {
        switch self {
        case .system: 0
        case .lockfile: 1
        case .image: 2
        }
    }
}

public struct InstalledPackage: Sendable, Hashable, Codable, Identifiable {
    public let query: PackageQuery
    public let name: String
    public let version: String
    public let binaries: [String]
    public let location: PackageLocation

    public init(query: PackageQuery, name: String, version: String, binaries: [String] = [], location: PackageLocation) {
        self.query = query
        self.name = name
        self.version = version
        self.binaries = binaries
        self.location = location
    }

    public var id: String { "\(location.key)|\(query.ecosystem)|\(name)|\(version)" }
}

public struct SecurityInventory: Sendable, Hashable {
    public let osEcosystem: String?
    public let packages: [InstalledPackage]
    public let skippedKernelSources: [String]

    static let kernelBinaryPrefixes = [
        "linux-image-", "linux-modules-", "linux-headers-", "linux-tools-", "linux-cloud-tools-",
        "linux-buildinfo-", "linux-kbuild-", "linux-libc-dev", "linux-source-", "linux-hwe-",
    ]
    static let packageLimit = 70_000
    static let kernelSourcePrefixes = ["linux-signed", "linux-meta", "linux-restricted-modules", "linux-lts", "linux-virt", "linux-edge", "linux-rpi"]

    public init(_ report: AgentSecurity) {
        let ecosystem = Self.osEcosystem(os: report.os, manager: report.packages.manager)
        osEcosystem = ecosystem
        var packages: [InstalledPackage] = []
        var skipped: [String] = []
        if let ecosystem {
            let kernel = Self.kernelSources(report.packages.items)
            skipped = kernel.sorted()
            packages += Self.systemPackages(report.packages.items, ecosystem: ecosystem, excluding: kernel, location: .system)
        }
        for project in report.projects {
            for lockfile in project.lockfiles {
                packages += Self.lockfilePackages(lockfile, location: .lockfile(project: project.name, path: lockfile.path))
            }
        }
        var seenImages: Set<String> = []
        for image in report.images where seenImages.insert(image.id).inserted {
            let name = image.displayName
            if let imageEcosystem = Self.osEcosystem(os: image.os, manager: image.packages.manager) {
                packages += Self.systemPackages(
                    image.packages.items, ecosystem: imageEcosystem, excluding: Self.kernelSources(image.packages.items),
                    location: .image(id: image.id, name: name, path: nil)
                )
            }
            for lockfile in image.lockfiles {
                packages += Self.lockfilePackages(lockfile, location: .image(id: image.id, name: name, path: lockfile.path))
            }
        }
        self.packages = Array(packages.sorted {
            ($0.location.rank, $0.location.key, $0.query) < ($1.location.rank, $1.location.key, $1.query)
        }.prefix(Self.packageLimit))
        skippedKernelSources = skipped
    }

    static func systemPackages(
        _ items: [AgentSecurity.Package], ecosystem: String, excluding kernel: Set<String>, location: PackageLocation
    ) -> [InstalledPackage] {
        var groups: [String: (source: String, version: String, binaries: [String])] = [:]
        for item in items where !kernel.contains(item.source) {
            let key = item.source + "\u{0}" + item.sourceVersion
            groups[key, default: (item.source, item.sourceVersion, [])].binaries.append(item.name)
        }
        return groups.values.map { group in
            InstalledPackage(
                query: PackageQuery(ecosystem: ecosystem, name: group.source, version: group.version),
                name: group.source, version: group.version,
                binaries: Array(Set(group.binaries)).sorted(), location: location
            )
        }
    }

    static func lockfilePackages(_ lockfile: AgentSecurity.Lockfile, location: PackageLocation) -> [InstalledPackage] {
        guard PackageQuery.languageEcosystems.contains(lockfile.ecosystem) else { return [] }
        var seen: Set<PackageQuery> = []
        var packages: [InstalledPackage] = []
        for dependency in lockfile.packages where !dependency.name.isEmpty && !dependency.version.isEmpty {
            let query = PackageQuery(ecosystem: lockfile.ecosystem, name: dependency.name, version: dependency.version)
            guard seen.insert(query).inserted else { continue }
            packages.append(InstalledPackage(query: query, name: dependency.name, version: dependency.version, location: location))
        }
        return packages
    }

    public var queries: Set<PackageQuery> { Set(packages.map(\.query)) }

    public static func osEcosystem(_ report: AgentSecurity) -> String? {
        osEcosystem(os: report.os, manager: report.packages.manager)
    }

    public static func osEcosystem(os: AgentSecurity.OS, manager: String?) -> String? {
        guard let id = os.id?.lowercased(), let version = os.versionID, !version.isEmpty else { return nil }
        let parts = version.split(separator: ".").map(String.init)
        switch (manager, id) {
        case ("dpkg", "ubuntu"):
            guard parts.count >= 2, let year = Int(parts[0]), Int(parts[1]) != nil else { return nil }
            let lts = parts[1] == "04" && year % 2 == 0
            return "Ubuntu:\(parts[0]).\(parts[1])" + (lts ? ":LTS" : "")
        case ("dpkg", "debian"):
            guard let major = parts.first, Int(major) != nil else { return nil }
            return "Debian:\(major)"
        case ("apk", "alpine"):
            guard parts.count >= 2, Int(parts[0]) != nil, Int(parts[1]) != nil else { return nil }
            return "Alpine:v\(parts[0]).\(parts[1])"
        default:
            return nil
        }
    }

    static func kernelSources(_ items: [AgentSecurity.Package]) -> Set<String> {
        var sources: Set<String> = []
        for item in items {
            if item.source == "linux" || kernelSourcePrefixes.contains(where: { item.source.hasPrefix($0) })
                || kernelBinaryPrefixes.contains(where: { item.name.hasPrefix($0) }) {
                sources.insert(item.source)
            }
        }
        return sources
    }
}
