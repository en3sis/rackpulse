import Foundation
import HetznerKit

enum CloudProvider: String, Codable {
    case hetzner
    case agent

    var name: String {
        switch self {
        case .hetzner: "Hetzner"
        case .agent: "Agent"
        }
    }

    var consoleName: String {
        switch self {
        case .hetzner: "Hetzner Console"
        case .agent: ""
        }
    }

    var hasAPI: Bool { self != .agent }

    var targetPrefix: String { rawValue }

    func consoleURL(_ project: Project) -> URL? {
        switch self {
        case .hetzner:
            URL(string: "https://console.hetzner.com/projects\(project.consoleID.map { "/\($0)" } ?? "")")
        case .agent:
            nil
        }
    }

    func firewallsURL(_ project: Project) -> URL? {
        switch self {
        case .hetzner:
            project.consoleID.flatMap { URL(string: "https://console.hetzner.com/projects/\($0)/firewalls") } ?? consoleURL(project)
        case .agent:
            nil
        }
    }

    func serverLinks(_ server: Server, project: Project) -> [ServerLink] {
        switch self {
        case .hetzner:
            let url = project.consoleID.flatMap { URL(string: "https://console.hetzner.com/projects/\($0)/servers/\(server.id)/overview") }
            guard let target = url ?? consoleURL(project) else { return [] }
            return [ServerLink(
                title: "Console",
                icon: "arrow.up.right.square",
                help: url == nil
                    ? "Opens your project list. Add the project's Console link in Settings to open this server directly."
                    : "Open this server in the \(consoleName)",
                url: target
            )]
        case .agent:
            return []
        }
    }
}

struct ServerLink: Identifiable {
    let title: String
    let icon: String
    let help: String
    let url: URL

    var id: String { title }
}

struct AgentHost: Codable, Hashable, Identifiable {
    let id: Int64
    var name: String?
    let addedAt: Date
    var hostname: String?
    var os: String?
    var cores: Int?
    var memory: Int64?
    var disk: Int64?

    var displayName: String {
        if let name, !name.isEmpty { return name }
        return hostname ?? "New server"
    }

    var summary: String {
        var parts: [String] = []
        if let os { parts.append(os) }
        if let cores { parts.append("\(cores) \(cores == 1 ? "core" : "cores")") }
        return parts.joined(separator: " · ")
    }

    func server(link: AgentLink?) -> Server {
        let address = link?.endpoint.host
        let isIPv6 = address.map { $0.contains(":") } ?? false
        let isIP = address.map { $0.contains(":") || $0.allSatisfy { $0.isNumber || $0 == "." } } ?? false
        let ip = isIP ? address.map { PublicNet.Address(id: nil, ip: $0, blocked: false) } : nil
        var server = Server(
            id: id,
            name: displayName,
            status: .running,
            created: addedAt,
            publicNet: PublicNet(ipv4: isIPv6 ? nil : ip, ipv6: isIPv6 ? ip : nil, floatingIps: [], firewalls: nil),
            serverType: ServerType(
                id: 0, name: "", description: [os, hostname].compactMap { $0 }.joined(separator: " · "),
                cores: Double(cores ?? 0), memory: Double(memory ?? 0) / 1_073_741_824, disk: Double(disk ?? 0) / 1_000_000_000,
                prices: []
            ),
            location: Location(id: 0, name: ""),
            primaryDiskSize: Double(disk ?? 0) / 1_000_000_000
        )
        server.agentOnly = true
        return server
    }

    mutating func learn(_ snapshot: AgentSnapshot) {
        hostname = snapshot.host.hostname
        os = snapshot.host.os
        cores = snapshot.host.cores
        memory = snapshot.memory.total
        disk = snapshot.disks.first { $0.mount == "/" }?.total ?? snapshot.disks.first?.total
    }
}

extension Project {
    var hasAPI: Bool { provider.hasAPI }
}
