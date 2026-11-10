import Foundation

public struct AgentSecurity: Sendable, Hashable, Codable {
    public enum Limit {
        public static let name = 256
        public static let path = 1_024
        public static let detail = 2_048
        public static let packages = 30_000
        public static let updates = 30_000
        public static let checks = 256
        public static let listening = 4_096
        public static let projects = 50
        public static let lockfiles = 50
        public static let dependencies = 50_000
        public static let images = 64
        public static let imagePackages = 20_000
        public static let imageNames = 32
        public static let containers = 256
        public static let shortList = 16
    }

    public let version: String
    public let time: Date
    public let os: OS
    public let packages: Packages
    public let updates: Updates
    public let kernel: Kernel
    public let checks: [SecurityCheck]
    public let listening: [Listener]
    public let projects: [Project]
    public let images: [Image]

    public init(
        version: String, time: Date, os: OS, packages: Packages, updates: Updates, kernel: Kernel = Kernel(),
        checks: [SecurityCheck] = [], listening: [Listener] = [], projects: [Project] = [], images: [Image] = []
    ) {
        self.version = version
        self.time = time
        self.os = os
        self.packages = packages
        self.updates = updates
        self.kernel = kernel
        self.checks = checks
        self.listening = listening
        self.projects = projects
        self.images = images
    }

    enum CodingKeys: String, CodingKey {
        case version, time, os, packages, updates, kernel, checks, listening, projects, images
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        version = container.optional(String.self, forKey: .version, limit: Limit.name) ?? ""
        time = try container.decode(Date.self, forKey: .time)
        os = container.optional(OS.self, forKey: .os) ?? OS()
        packages = container.optional(Packages.self, forKey: .packages) ?? Packages()
        updates = container.optional(Updates.self, forKey: .updates) ?? Updates()
        kernel = container.optional(Kernel.self, forKey: .kernel) ?? Kernel()
        checks = container.lossy([SecurityCheck].self, forKey: .checks, limit: Limit.checks).filter {
            $0.id.utf8.count <= Limit.name && ($0.source?.utf8.count ?? 0) <= Limit.path
        }
        listening = container.lossy([Listener].self, forKey: .listening, limit: Limit.listening)
        projects = container.lossy([Project].self, forKey: .projects, limit: Limit.projects)
        images = container.lossy([Image].self, forKey: .images, limit: Limit.images)
    }

    public struct OS: Sendable, Hashable, Codable {
        public let id: String?
        public let versionID: String?
        public let codename: String?
        public let name: String?
        public let like: [String]

        public init(id: String? = nil, versionID: String? = nil, codename: String? = nil, name: String? = nil, like: [String] = []) {
            self.id = id
            self.versionID = versionID
            self.codename = codename
            self.name = name
            self.like = like
        }

        enum CodingKeys: String, CodingKey {
            case id, versionID, codename, name, like
        }

        public init(from decoder: Decoder) throws {
            let container = try decoder.container(keyedBy: CodingKeys.self)
            id = container.optional(String.self, forKey: .id, limit: Limit.name)
            versionID = container.optional(String.self, forKey: .versionID, limit: Limit.name)
            codename = container.optional(String.self, forKey: .codename, limit: Limit.name)
            name = container.optional(String.self, forKey: .name, limit: Limit.name)
            like = container.strings(forKey: .like, limit: Limit.shortList, length: Limit.name)
        }
    }

    public struct Packages: Sendable, Hashable, Codable {
        public let manager: String?
        public let time: Date?
        public let error: String?
        public let items: [Package]

        public init(manager: String? = nil, time: Date? = nil, error: String? = nil, items: [Package] = []) {
            self.manager = manager
            self.time = time
            self.error = error
            self.items = items
        }

        enum CodingKeys: String, CodingKey {
            case manager, time, error, items
        }

        public init(from decoder: Decoder) throws {
            let container = try decoder.container(keyedBy: CodingKeys.self)
            manager = container.optional(String.self, forKey: .manager, limit: Limit.name)
            time = container.optional(Date.self, forKey: .time)
            error = container.optional(String.self, forKey: .error, limit: Limit.detail)
            items = container.lossy([Package].self, forKey: .items, limit: Limit.packages)
        }
    }

    public struct Package: Sendable, Hashable, Codable {
        public let name: String
        public let version: String
        public let source: String
        public let sourceVersion: String
        public let arch: String?

        public init(name: String, version: String, source: String? = nil, sourceVersion: String? = nil, arch: String? = nil) {
            self.name = name
            self.version = version
            self.source = source.flatMap { $0.isEmpty ? nil : $0 } ?? name
            self.sourceVersion = sourceVersion.flatMap { $0.isEmpty ? nil : $0 } ?? version
            self.arch = arch
        }

        enum CodingKeys: String, CodingKey {
            case name, version, source, sourceVersion, arch
        }

        public init(from decoder: Decoder) throws {
            let container = try decoder.container(keyedBy: CodingKeys.self)
            self.init(
                name: try container.capped(String.self, forKey: .name, limit: Limit.name),
                version: try container.capped(String.self, forKey: .version, limit: Limit.name),
                source: try container.capped(String?.self, forKey: .source, limit: Limit.name),
                sourceVersion: try container.capped(String?.self, forKey: .sourceVersion, limit: Limit.name),
                arch: try container.capped(String?.self, forKey: .arch, limit: Limit.name)
            )
        }
    }

    public struct Updates: Sendable, Hashable, Codable {
        public let time: Date?
        public let listsTime: Date?
        public let error: String?
        public let items: [Update]

        public init(time: Date? = nil, listsTime: Date? = nil, error: String? = nil, items: [Update] = []) {
            self.time = time
            self.listsTime = listsTime
            self.error = error
            self.items = items
        }

        enum CodingKeys: String, CodingKey {
            case time, listsTime, error, items
        }

        public init(from decoder: Decoder) throws {
            let container = try decoder.container(keyedBy: CodingKeys.self)
            time = container.optional(Date.self, forKey: .time)
            listsTime = container.optional(Date.self, forKey: .listsTime)
            error = container.optional(String.self, forKey: .error, limit: Limit.detail)
            items = container.lossy([Update].self, forKey: .items, limit: Limit.updates)
        }

        public var securityCount: Int { items.filter(\.security).count }
    }

    public struct Update: Sendable, Hashable, Codable {
        public let name: String
        public let current: String?
        public let available: String
        public let security: Bool
        public let origins: [String]

        public init(name: String, current: String?, available: String, security: Bool, origins: [String] = []) {
            self.name = name
            self.current = current
            self.available = available
            self.security = security
            self.origins = origins
        }

        enum CodingKeys: String, CodingKey {
            case name, current, available, security, origins
        }

        public init(from decoder: Decoder) throws {
            let container = try decoder.container(keyedBy: CodingKeys.self)
            name = try container.capped(String.self, forKey: .name, limit: Limit.name)
            current = try container.capped(String?.self, forKey: .current, limit: Limit.name)
            available = try container.capped(String.self, forKey: .available, limit: Limit.name)
            security = container.optional(Bool.self, forKey: .security) ?? false
            origins = container.strings(forKey: .origins, limit: Limit.shortList, length: Limit.name)
        }
    }

    public struct Kernel: Sendable, Hashable, Codable {
        public let running: String?
        public let latestInstalled: String?

        public init(running: String? = nil, latestInstalled: String? = nil) {
            self.running = running
            self.latestInstalled = latestInstalled
        }

        enum CodingKeys: String, CodingKey {
            case running, latestInstalled
        }

        public init(from decoder: Decoder) throws {
            let container = try decoder.container(keyedBy: CodingKeys.self)
            running = container.optional(String.self, forKey: .running, limit: Limit.name)
            latestInstalled = container.optional(String.self, forKey: .latestInstalled, limit: Limit.name)
        }
    }

    public struct Listener: Sendable, Hashable, Codable {
        public let `protocol`: String
        public let address: String
        public let port: Int

        public init(protocol: String = "tcp", address: String, port: Int) {
            self.protocol = `protocol`
            self.address = address
            self.port = port
        }

        enum CodingKeys: String, CodingKey {
            case `protocol`, address, port
        }

        public init(from decoder: Decoder) throws {
            let container = try decoder.container(keyedBy: CodingKeys.self)
            self.protocol = try container.capped(String?.self, forKey: .protocol, limit: Limit.name) ?? "tcp"
            address = try container.capped(String.self, forKey: .address, limit: Limit.name)
            port = try container.decode(Int.self, forKey: .port)
        }
    }

    public struct Project: Sendable, Hashable, Codable, Identifiable {
        public let name: String
        public let path: String
        public let error: String?
        public let lockfiles: [Lockfile]

        public init(name: String, path: String, error: String? = nil, lockfiles: [Lockfile] = []) {
            self.name = name
            self.path = path
            self.error = error
            self.lockfiles = lockfiles
        }

        public var id: String { path }

        enum CodingKeys: String, CodingKey {
            case name, path, error, lockfiles
        }

        public init(from decoder: Decoder) throws {
            let container = try decoder.container(keyedBy: CodingKeys.self)
            name = try container.capped(String?.self, forKey: .name, limit: Limit.name) ?? ""
            path = try container.capped(String?.self, forKey: .path, limit: Limit.path) ?? ""
            error = container.optional(String.self, forKey: .error, limit: Limit.detail)
            lockfiles = container.lossy([Lockfile].self, forKey: .lockfiles, limit: Limit.lockfiles)
        }
    }

    public struct Lockfile: Sendable, Hashable, Codable, Identifiable {
        public let path: String
        public let ecosystem: String
        public let packages: [Dependency]
        public let truncated: Bool

        public init(path: String, ecosystem: String, packages: [Dependency], truncated: Bool = false) {
            self.path = path
            self.ecosystem = ecosystem
            self.packages = packages
            self.truncated = truncated
        }

        public var id: String { path }

        enum CodingKeys: String, CodingKey {
            case path, ecosystem, packages, truncated
        }

        public init(from decoder: Decoder) throws {
            let container = try decoder.container(keyedBy: CodingKeys.self)
            path = try container.capped(String.self, forKey: .path, limit: Limit.path)
            ecosystem = try container.capped(String.self, forKey: .ecosystem, limit: Limit.name)
            packages = container.lossy([Dependency].self, forKey: .packages, limit: Limit.dependencies)
            truncated = container.optional(Bool.self, forKey: .truncated) ?? false
        }
    }

    public struct Image: Sendable, Hashable, Codable, Identifiable {
        public let id: String
        public let names: [String]
        public let containers: [String]
        public let created: Date?
        public let os: OS
        public let packages: Packages
        public let lockfiles: [Lockfile]
        public let error: String?

        public init(
            id: String, names: [String] = [], containers: [String] = [], created: Date? = nil, os: OS = OS(),
            packages: Packages = Packages(), lockfiles: [Lockfile] = [], error: String? = nil
        ) {
            self.id = id
            self.names = names
            self.containers = containers
            self.created = created
            self.os = os
            self.packages = packages
            self.lockfiles = lockfiles
            self.error = error
        }

        public var displayName: String {
            if let name = names.first(where: { !$0.contains("@") }) ?? names.first { return name }
            let digest = id.hasPrefix("sha256:") ? String(id.dropFirst(7)) : id
            return String(digest.prefix(12))
        }

        enum CodingKeys: String, CodingKey {
            case id, names, containers, created, os, packages, lockfiles, error
        }

        public init(from decoder: Decoder) throws {
            let container = try decoder.container(keyedBy: CodingKeys.self)
            id = try container.capped(String.self, forKey: .id, limit: Limit.name)
            names = container.strings(forKey: .names, limit: Limit.imageNames, length: Limit.name)
            containers = container.strings(forKey: .containers, limit: Limit.containers, length: Limit.name)
            created = container.optional(Date.self, forKey: .created)
            os = container.optional(OS.self, forKey: .os) ?? OS()
            let packages = container.optional(Packages.self, forKey: .packages) ?? Packages()
            self.packages = packages.items.count > Limit.imagePackages
                ? Packages(manager: packages.manager, time: packages.time, error: packages.error, items: Array(packages.items.prefix(Limit.imagePackages)))
                : packages
            lockfiles = container.lossy([Lockfile].self, forKey: .lockfiles, limit: Limit.lockfiles)
            error = container.optional(String.self, forKey: .error, limit: Limit.detail)
        }
    }

    public struct Dependency: Sendable, Hashable, Codable {
        public let name: String
        public let version: String

        public init(name: String, version: String) {
            self.name = name
            self.version = version
        }

        enum CodingKeys: String, CodingKey {
            case name, version
        }

        public init(from decoder: Decoder) throws {
            let container = try decoder.container(keyedBy: CodingKeys.self)
            name = try container.capped(String.self, forKey: .name, limit: Limit.name)
            version = try container.capped(String.self, forKey: .version, limit: Limit.name)
        }
    }

    public func check(_ id: String) -> SecurityCheck? {
        checks.first { $0.id == id }
    }
}
