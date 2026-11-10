import AppKit
import HetznerKit

@MainActor
struct Snapshots {
    let folder: URL
    let monitor: Monitor
    let store: ProjectStore
    let settings: SettingsStore
    let actions: AppActions
    let statusBar: StatusBarController
    let settingsWindow: SettingsWindow

    func run() async {
        try? FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
        for _ in 0..<60 where monitor.allProjectsCost == nil {
            try? await Task.sleep(for: .milliseconds(500))
        }
        let all = store.projects.flatMap { project in (monitor.poller(project.id)?.data.servers ?? []).map { (project.id, $0.id) } }
        let testAgent = ProcessInfo.processInfo.environment["RACKPULSE_AGENT_TEST"]
        let testServer = testAgent == nil ? nil : all.first { monitor.agents.link($0.0, $0.1) == nil }
        let paired = all.filter { monitor.agents.link($0.0, $0.1)?.isPaired == true }
        for _ in 0..<60 where paired.contains(where: { monitor.agents.state($0.0, $0.1)?.snapshot == nil }) {
            try? await Task.sleep(for: .milliseconds(500))
        }
        let shownServer = testServer ?? paired.first ?? all.first
        if let target = testAgent, let (project, server) = testServer {
            await pairTestAgent(target, project: project, server: server)
        }
        let original = settings.value.readout
        for readout in [MenuBarReadout.cpu, .cost, .alerts] {
            settings.value.readout = readout
            try? await Task.sleep(for: .milliseconds(400))
            capture(statusBar.statusButton, "menubar-\(readout.rawValue)")
        }
        settings.value.readout = original
        statusBar.show()
        var log: [String] = []
        for (name, appearance) in [("light", NSAppearance.Name.aqua), ("dark", .darkAqua)] {
            NSApp.appearance = NSAppearance(named: appearance)
            var routes: [(String, PanelRoute)] = [("servers", .servers), ("costs", .costs), ("security", .security), ("onboarding", .addProject)]
            if let (project, server) = shownServer {
                routes.append(("server", .server(project, server, .hour)))
                routes.append(("agent", .agent(project, server)))
                routes.append(("server-details", .serverTab(project, server, .details)))
                if monitor.agents.link(project, server)?.isPaired == true {
                    routes.append(("server-security", .serverTab(project, server, .security)))
                }
                if let docker = monitor.agents.state(project, server)?.snapshot?.docker {
                    routes.append(("server-docker", .serverTab(project, server, .docker)))
                    if let container = docker.containers.first(where: { $0.ports?.isEmpty == false }) ?? docker.containers.first {
                        routes.append(("container", .container(project, server, container.name)))
                    }
                }
                routes.append(("back", .servers))
            }
            let newest = store.projects.flatMap { project in
                (monitor.poller(project.id)?.data.servers ?? []).map { (project.id, $0) }
            }.max { $0.1.created < $1.1.created }
            if let (project, server) = newest {
                routes.append(("newest-7d", .server(project, server.id, .week)))
                routes.append(("back2", .servers))
            }
            let compact = settings.value.compactList
            settings.value.compactList = !compact
            actions.route = .servers
            try? await Task.sleep(for: .milliseconds(900))
            capture(statusBar.panel.contentView, "panel-servers-alternate-\(name)")
            settings.value.compactList = compact
            for (label, route) in routes {
                actions.route = route
                try? await Task.sleep(for: .milliseconds(900))
                capture(statusBar.panel.contentView, "panel-\(label)-\(name)")
                log.append("\(label)-\(name): \(statusBar.frames)")
            }
            actions.route = .servers
            statusBar.close()
            var pages: [(String, SettingsPage)] = [("general", .general), ("alerts", .alerts), ("security", .security), ("about", .about)]
            if let project = store.selected { pages.append(("project", .project(project.id))) }
            for (label, page) in pages {
                settings.requestedPage = page
                settingsWindow.show()
                try? await Task.sleep(for: .milliseconds(900))
                capture(settingsWindow.window?.contentView, "settings-\(label)-\(name)")
            }
            statusBar.show()
        }
        if let (project, server) = testServer {
            monitor.agents.remove(project, server)
        }
        try? log.joined(separator: "\n").write(to: folder.appendingPathComponent("frames.txt"), atomically: true, encoding: .utf8)
        NSApp.terminate(nil)
    }

    private func pairTestAgent(_ target: String, project: UUID, server: Int64) async {
        let parts = target.split(separator: ":")
        let port = parts.count > 1 ? Int(parts[1]) ?? AgentEndpoint.defaultPort : AgentEndpoint.defaultPort
        monitor.agents.prepare(project, server: server, address: .custom, host: String(parts[0]), port: port)
        let command = monitor.agents.installCommand(project, server) ?? ""
        try? command.write(to: folder.appendingPathComponent("agent-command.txt"), atomically: true, encoding: .utf8)
        for _ in 0..<120 where monitor.agents.link(project, server)?.isPaired != true {
            await monitor.agents.tryPair(project, server: server)
            try? await Task.sleep(for: .seconds(2))
        }
        let state = monitor.agents.state(project, server)
        let result = monitor.agents.link(project, server)?.isPaired == true
            ? "paired, containers: \(state?.snapshot?.docker?.containers.count ?? -1)"
            : "not paired: \(String(describing: state?.problem))"
        try? result.write(to: folder.appendingPathComponent("agent-result.txt"), atomically: true, encoding: .utf8)
        monitor.refreshNow()
        try? await Task.sleep(for: .seconds(4))
    }

    private func capture(_ view: NSView?, _ name: String) {
        guard let view else { return }
        let size = view.bounds.size
        func bitmap() -> NSBitmapImageRep? {
            let rep = NSBitmapImageRep(
                bitmapDataPlanes: nil, pixelsWide: Int(size.width * 2), pixelsHigh: Int(size.height * 2),
                bitsPerSample: 8, samplesPerPixel: 4, hasAlpha: true, isPlanar: false,
                colorSpaceName: .deviceRGB, bytesPerRow: 0, bitsPerPixel: 0
            )
            rep?.size = size
            return rep
        }
        guard let content = bitmap(), let output = bitmap() else { return }
        view.cacheDisplay(in: view.bounds, to: content)
        NSGraphicsContext.saveGraphicsState()
        NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: output)
        view.effectiveAppearance.performAsCurrentDrawingAppearance {
            NSColor.windowBackgroundColor.setFill()
            NSRect(origin: .zero, size: size).fill()
        }
        content.draw(in: NSRect(origin: .zero, size: size))
        NSGraphicsContext.restoreGraphicsState()
        guard let png = output.representation(using: .png, properties: [:]) else { return }
        try? png.write(to: folder.appendingPathComponent("\(name).png"))
    }
}
