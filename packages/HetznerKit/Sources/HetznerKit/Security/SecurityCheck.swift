import Foundation

public struct SecurityCheck: Sendable, Hashable, Codable, Identifiable {
    public enum Status: String, Sendable, Hashable, Codable {
        case pass, fail, unknown

        public init(from decoder: Decoder) throws {
            self = Status(rawValue: try decoder.singleValueContainer().decode(String.self)) ?? .unknown
        }
    }

    public static let sshPasswordLogin = "ssh.passwordLogin"
    public static let sshRootLogin = "ssh.rootLogin"
    public static let automaticUpdates = "updates.automatic"
    public static let ufw = "firewall.ufw"
    public static let dockerPrivileged = "docker.privileged"
    public static let dockerSocketMount = "docker.socketMount"
    public static let dockerHostNetwork = "docker.hostNetwork"
    public static let dockerHostPID = "docker.hostPID"
    public static let dockerCapAdd = "docker.capAdd"
    public static let dockerRoot = "docker.root"
    public static let dockerLatestTag = "docker.latestTag"
    public static let dockerOldImage = "docker.oldImage"
    public static let extraRoot = "users.extraRoot"
    public static let kernelReboot = "kernel.reboot"
    public static let firewallNone = "firewall.none"
    public static let exposedPorts = "ports.exposed"
    public static let endOfLife = "os.endOfLife"

    static let titleLimit = 200
    static let detailLimit = 1_000

    public static let informationalIDs: Set<String> = [
        dockerHostNetwork, dockerCapAdd, dockerRoot, dockerLatestTag, dockerOldImage, kernelReboot, ufw,
    ]

    public let id: String
    public let status: Status
    public let title: String
    public let detail: String
    public let source: String?
    public let informational: Bool

    public init(id: String, status: Status, title: String, detail: String, source: String? = nil, informational: Bool? = nil) {
        self.id = id
        self.status = status
        self.title = title
        self.detail = detail
        self.source = source
        self.informational = informational ?? Self.informationalIDs.contains(id)
    }

    enum CodingKeys: String, CodingKey {
        case id, status, title, detail, source, informational
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            id: try container.decode(String.self, forKey: .id),
            status: container.optional(Status.self, forKey: .status) ?? .unknown,
            title: String((container.optional(String.self, forKey: .title) ?? "").prefix(Self.titleLimit)),
            detail: String((container.optional(String.self, forKey: .detail) ?? "").prefix(Self.detailLimit)),
            source: container.optional(String.self, forKey: .source),
            informational: container.optional(Bool.self, forKey: .informational)
        )
    }

    public var family: String {
        id.split(separator: ":", maxSplits: 1).first.map(String.init) ?? id
    }

    public var countsForAlert: Bool { status == .fail && !informational }
}
