import Foundation
import HetznerKit
import Observation

@MainActor
@Observable
final class UptimeStore {
    private(set) var history: UptimeHistory
    private let url: URL

    init() {
        let folder = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("Rackpulse", isDirectory: true)
        try? FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
        url = folder.appendingPathComponent("uptime.json")
        history = (try? Data(contentsOf: url)).flatMap { try? JSONDecoder().decode(UptimeHistory.self, from: $0) } ?? UptimeHistory()
    }

    func record(_ data: ProjectData, at time: Date) {
        let firing = data.alerts.firing
        var changed = false
        for server in data.servers {
            let alerts = firing.filter { $0.id.hasSuffix(":\(server.id)") && $0.severity > .info }
            let state: UptimeState
            if alerts.contains(where: { $0.kind == .serverDown || (server.agentOnly && $0.kind == .agentUnreachable) }) {
                state = .down
            } else if server.status != .running {
                state = .off
            } else if !alerts.isEmpty {
                state = .alert
            } else {
                state = .up
            }
            changed = history.record(server.id, state, at: time) || changed
        }
        if changed, let encoded = try? JSONEncoder().encode(history) {
            try? encoded.write(to: url, options: .atomic)
        }
    }
}
