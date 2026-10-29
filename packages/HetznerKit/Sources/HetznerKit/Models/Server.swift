import Foundation

public enum ServerStatus: String, Sendable, Hashable, Codable {
    case running, initializing, starting, stopping, off, deleting, migrating, rebuilding, unknown

    public init(from decoder: Decoder) throws {
        let raw = try decoder.singleValueContainer().decode(String.self)
        self = ServerStatus(rawValue: raw) ?? .unknown
    }
}

public struct Server: Sendable, Hashable, Decodable, Identifiable {
    public let id: Int64
    public let name: String
    public let status: ServerStatus
    public let created: Date
    public let publicNet: PublicNet
    public let serverType: ServerType
    public let location: Location
    public let backupWindow: String?
    public let outgoingTraffic: Int64?
    public let ingoingTraffic: Int64?
    public let includedTraffic: Int64?
    public let protection: Protection
    public let labels: [String: String]
    public let volumes: [Int64]?
    public let locked: Bool
    public let primaryDiskSize: Double
    public let privateNet: [PrivateAddress]?
    public var agentOnly = false

    public init(
        id: Int64,
        name: String,
        status: ServerStatus,
        created: Date,
        publicNet: PublicNet = PublicNet(ipv4: nil, ipv6: nil, floatingIps: [], firewalls: nil),
        serverType: ServerType,
        location: Location,
        backupWindow: String? = nil,
        outgoingTraffic: Int64? = nil,
        ingoingTraffic: Int64? = nil,
        includedTraffic: Int64? = nil,
        protection: Protection = Protection(delete: false, rebuild: false),
        labels: [String: String] = [:],
        volumes: [Int64]? = nil,
        locked: Bool = false,
        primaryDiskSize: Double = 0,
        privateNet: [PrivateAddress]? = nil
    ) {
        self.id = id
        self.name = name
        self.status = status
        self.created = created
        self.publicNet = publicNet
        self.serverType = serverType
        self.location = location
        self.backupWindow = backupWindow
        self.outgoingTraffic = outgoingTraffic
        self.ingoingTraffic = ingoingTraffic
        self.includedTraffic = includedTraffic
        self.protection = protection
        self.labels = labels
        self.volumes = volumes
        self.locked = locked
        self.primaryDiskSize = primaryDiskSize
        self.privateNet = privateNet
    }

    enum CodingKeys: String, CodingKey {
        case id, name, status, created, location, protection, labels, volumes, locked
        case publicNet = "public_net"
        case serverType = "server_type"
        case backupWindow = "backup_window"
        case outgoingTraffic = "outgoing_traffic"
        case ingoingTraffic = "ingoing_traffic"
        case includedTraffic = "included_traffic"
        case primaryDiskSize = "primary_disk_size"
        case privateNet = "private_net"
    }

    public struct PrivateAddress: Sendable, Hashable, Decodable {
        public let network: Int64
        public let ip: String

        public init(network: Int64, ip: String) {
            self.network = network
            self.ip = ip
        }
    }

    public struct Protection: Sendable, Hashable, Decodable {
        public let delete: Bool
        public let rebuild: Bool

        public init(delete: Bool, rebuild: Bool) {
            self.delete = delete
            self.rebuild = rebuild
        }
    }

    public var backupsEnabled: Bool { backupWindow != nil }

    public var trafficFraction: Double? {
        guard let outgoingTraffic, let includedTraffic, includedTraffic > 0 else { return nil }
        return Double(outgoingTraffic) / Double(includedTraffic)
    }
}

public struct PublicNet: Sendable, Hashable, Decodable {
    public let ipv4: Address?
    public let ipv6: Address?
    public let floatingIps: [Int64]
    public let firewalls: [FirewallRef]?

    public init(ipv4: Address?, ipv6: Address?, floatingIps: [Int64], firewalls: [FirewallRef]?) {
        self.ipv4 = ipv4
        self.ipv6 = ipv6
        self.floatingIps = floatingIps
        self.firewalls = firewalls
    }

    enum CodingKeys: String, CodingKey {
        case ipv4, ipv6, firewalls
        case floatingIps = "floating_ips"
    }

    public struct Address: Sendable, Hashable, Decodable {
        public let id: Int64?
        public let ip: String
        public let blocked: Bool

        public init(id: Int64?, ip: String, blocked: Bool) {
            self.id = id
            self.ip = ip
            self.blocked = blocked
        }
    }

    public struct FirewallRef: Sendable, Hashable, Decodable {
        public let id: Int64?
        public let status: String?
    }
}

public struct ServerType: Sendable, Hashable, Decodable {
    public let id: Int64
    public let name: String
    public let description: String
    public let cores: Double
    public let memory: Double
    public let disk: Double
    public let cpuType: String?
    public let prices: [LocationPrice]

    public init(
        id: Int64,
        name: String,
        description: String,
        cores: Double,
        memory: Double,
        disk: Double,
        cpuType: String? = nil,
        prices: [LocationPrice]
    ) {
        self.id = id
        self.name = name
        self.description = description
        self.cores = cores
        self.memory = memory
        self.disk = disk
        self.cpuType = cpuType
        self.prices = prices
    }

    enum CodingKeys: String, CodingKey {
        case id, name, description, cores, memory, disk, prices
        case cpuType = "cpu_type"
    }
}
