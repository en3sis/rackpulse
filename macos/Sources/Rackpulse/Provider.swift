import Foundation
import HetznerKit

enum CloudProvider: String, Codable {
    case hetzner

    var name: String {
        switch self {
        case .hetzner: "Hetzner"
        }
    }

    var consoleName: String {
        switch self {
        case .hetzner: "Hetzner Console"
        }
    }

    func consoleURL(_ project: Project) -> URL {
        switch self {
        case .hetzner:
            URL(string: "https://console.hetzner.com/projects\(project.consoleID.map { "/\($0)" } ?? "")")!
        }
    }

    func firewallsURL(_ project: Project) -> URL {
        switch self {
        case .hetzner:
            project.consoleID.map { URL(string: "https://console.hetzner.com/projects/\($0)/firewalls")! } ?? consoleURL(project)
        }
    }

    func serverLinks(_ server: Server, project: Project) -> [ServerLink] {
        switch self {
        case .hetzner:
            let url = project.consoleID.map { URL(string: "https://console.hetzner.com/projects/\($0)/servers/\(server.id)/overview")! }
            return [ServerLink(
                title: "Console",
                icon: "arrow.up.right.square",
                help: url == nil
                    ? "Opens your project list. Add the project's Console link in Settings to open this server directly."
                    : "Open this server in the \(consoleName)",
                url: url ?? consoleURL(project)
            )]
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

extension Project {
    var provider: CloudProvider { .hetzner }
}
