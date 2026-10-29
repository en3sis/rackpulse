import HetznerKit
import SwiftUI

struct ServerList: View {
    let monitor: Monitor
    let store: ProjectStore
    var query = ""
    var highlighted: DetailTarget?
    var addServer: (UUID) -> Void = { _ in }
    let open: (UUID, Int64) -> Void

    var body: some View {
        let groups = store.scope.map { ($0, monitor.poller($0.id)) }
        VStack(spacing: 0) {
            ForEach(groups, id: \.0.id) { project, poller in
                if !query.isEmpty, let poller, Self.matches(project, poller, query, settings: monitor.settings).isEmpty {
                    EmptyView()
                } else {
                    let collapsed = groups.count > 1 && query.isEmpty && store.collapsed.contains(project.id)
                    if groups.count > 1 {
                        ProjectHeader(project: project, poller: poller, collapsed: collapsed) {
                            if store.collapsed.contains(project.id) { store.collapsed.remove(project.id) } else { store.collapsed.insert(project.id) }
                        }
                    }
                    if !collapsed {
                        group(project, poller)
                    }
                }
            }
        }
        .padding(.top, 4)
    }

    static func matches(_ project: Project, _ poller: ProjectPoller, _ query: String, settings: SettingsStore) -> [Server] {
        let words = query.lowercased().split(separator: " ")
        return poller.data.servers.filter { server in
            let environment = settings.environment(project: project.id, server: server)
            let haystack = [server.name, server.serverType.name, server.location.name, server.location.city, project.name,
                            environment == .none ? "" : environment.title]
                .joined(separator: " ").lowercased()
            return words.allSatisfy { haystack.contains($0) }
        }
    }

    @ViewBuilder
    private func group(_ project: Project, _ poller: ProjectPoller?) -> some View {
        if let poller, poller.data.lastUpdated != nil {
            let servers = query.isEmpty ? sorted(poller) : sorted(poller).filter { Self.matches(project, poller, query, settings: monitor.settings).contains($0) }
            if servers.isEmpty {
                if let url = project.provider.consoleURL(project) {
                    EmptyLine(text: "No servers in this project yet.", link: ("Open \(project.provider.consoleName)", url))
                } else {
                    EmptyLine(text: "No servers in this project yet.", link: nil, action: ("Add a server", { addServer(project.id) }))
                }
            }
            ForEach(Array(servers.enumerated()), id: \.element.id) { index, server in
                let alert = poller.visibleAlerts.first { $0.id.hasSuffix(":\(server.id)") }
                let divider = index < servers.count - 1
                let environment = monitor.settings.environment(project: project.id, server: server)
                let agent = monitor.agents.state(project.id, server.id)?.snapshot
                let address = server.agentOnly ? monitor.agents.link(project.id, server.id)?.endpoint.host : nil
                Button { open(project.id, server.id) } label: {
                    Group {
                        if monitor.settings.value.compactList {
                            CompactServerRow(
                                server: server,
                                environment: environment,
                                metrics: poller.data.metrics[server.id],
                                alert: alert,
                                threshold: monitor.settings.value.alertSettings(for: project).rule(.sustainedCPU, server: server.id)?.threshold,
                                showsDivider: divider,
                                agent: agent,
                                address: address
                            )
                        } else {
                            ServerRow(server: server, environment: environment, metrics: poller.data.metrics[server.id], alert: alert, showsDivider: divider,
                                      agent: agent, address: address)
                        }
                    }
                    .contentShape(Rectangle())
                    .background(highlighted == DetailTarget(project: project.id, server: server.id) ? Theme.card : .clear)
                }
                .buttonStyle(RowButtonStyle())
            }
        } else if poller?.problem != nil || poller == nil {
            EmptyLine(text: "Not loaded. See the message above.", link: nil)
        } else {
            ServerRowPlaceholder()
        }
    }

    private func sorted(_ poller: ProjectPoller) -> [Server] {
        let alerts = poller.visibleAlerts
        func rank(_ server: Server) -> Int {
            let worst = alerts.filter { $0.id.hasSuffix(":\(server.id)") }.map(\.severity).max()
            switch worst {
            case .critical: return 0
            case .warning: return 1
            default: return server.status == .running ? 3 : 2
            }
        }
        return poller.data.servers.sorted { (rank($0), $0.name.lowercased()) < (rank($1), $1.name.lowercased()) }
    }
}

struct FleetHeadline: View {
    let monitor: Monitor
    let store: ProjectStore
    var open: (ProjectAlert) -> Void = { _ in }

    @State private var expanded = false
    private static let collapsedCount = 2

    var body: some View {
        let pollers = store.scope.compactMap { monitor.poller($0.id) }
        let loaded = pollers.filter { $0.data.lastUpdated != nil }
        if !loaded.isEmpty {
            let servers = loaded.flatMap(\.data.servers)
            let down = servers.filter { $0.status != .running }.count
            let items = monitor.allAlerts
            let alerts = items.filter { $0.alert.severity > .info }.count
            let notices = items.count - alerts
            let worst = items.map(\.alert.severity).max()
            let healthy = down == 0 && alerts == 0
            let color = healthy ? (notices > 0 ? Theme.info : Theme.green) : worst.map(Theme.color) ?? Theme.orange
            if !healthy || !items.isEmpty {
                VStack(alignment: .leading, spacing: 10) {
                    HStack(spacing: 8) {
                        Image(systemName: healthy ? "checkmark.circle.fill" : "exclamationmark.circle.fill")
                            .font(.system(size: 15, weight: .semibold))
                            .foregroundStyle(healthy ? Theme.green : color)
                            .symbolEffect(.bounce, value: healthy)
                        Text(headline(servers: servers.count, down: down, alerts: alerts))
                            .font(.system(size: 13, weight: .semibold))
                            .lineLimit(1)
                        Spacer(minLength: 8)
                        HStack(spacing: 10) {
                            if let cpu = averageCPU(loaded) {
                                figure("cpu", Format.percent(cpu), help: "Average CPU across these servers right now")
                            }
                            if let cost = cost {
                                figure("banknote", cost, help: "Estimated cost this month")
                            }
                        }
                    }
                    if !items.isEmpty {
                        VStack(alignment: .leading, spacing: 8) {
                            ForEach(expanded ? items : Array(items.prefix(Self.collapsedCount))) { item in
                                row(item)
                            }
                            if items.count > Self.collapsedCount {
                                Button(expanded ? "Show less" : "Show \(items.count - Self.collapsedCount) more") {
                                    var transaction = Transaction(animation: nil)
                                    transaction.disablesAnimations = true
                                    withTransaction(transaction) { expanded.toggle() }
                                }
                                .buttonStyle(.plain)
                                .font(.system(size: 12, weight: .medium))
                                .foregroundStyle(Color.accentColor)
                                .padding(.leading, 23)
                            }
                        }
                        .transaction { $0.animation = nil }
                    }
                }
                .padding(.horizontal, 12)
                .padding(.vertical, 10)
                .background(color.opacity(healthy ? 0.08 : 0.1), in: RoundedRectangle(cornerRadius: 10))
                .overlay {
                    if !healthy { RoundedRectangle(cornerRadius: 10).stroke(color.opacity(0.3)) }
                }
                .padding(.horizontal, 16)
                .padding(.top, 10)
            }
        }
    }

    private func row(_ item: ProjectAlert) -> some View {
        let info = item.alert.severity == .info
        return HStack(alignment: .top, spacing: 8) {
            Image(systemName: info ? "info.circle.fill" : "exclamationmark.triangle.fill")
                .font(.system(size: 12))
                .foregroundStyle(Theme.color(item.alert.severity))
                .frame(width: 15)
                .padding(.top, 1)
            VStack(alignment: .leading, spacing: 1) {
                Text(item.alert.title)
                    .font(.system(size: 12, weight: info ? .regular : .semibold))
                    .foregroundStyle(Theme.text)
                    .fixedSize(horizontal: false, vertical: true)
                Text(subtitle(item))
                    .font(.system(size: 11))
                    .foregroundStyle(Theme.secondary)
            }
            .contentShape(Rectangle())
            .onTapGesture { open(item) }
            .help(item.serverID == nil ? "" : "Open the server")
            Spacer(minLength: 0)
            Button("Snooze") { monitor.snooze(item) }
                .buttonStyle(.plain)
                .font(.system(size: 11, weight: .medium))
                .foregroundStyle(Color.accentColor)
                .help("Hide this for 24 hours")
        }
    }

    private func subtitle(_ item: ProjectAlert) -> String {
        let started = "Started \(item.alert.since.formatted(date: .omitted, time: .shortened))"
        return store.scope.count == 1 && item.project.id == store.selectedID ? started : "\(item.project.name) · \(started)"
    }

    private func headline(servers: Int, down: Int, alerts: Int) -> String {
        var parts: [String] = []
        if down == 0 && alerts == 0 {
            parts.append(servers == 1 ? "1 server running" : "All \(servers) servers running")
        } else {
            if down > 0 { parts.append("\(down) not running") }
            if alerts > 0 { parts.append("\(alerts) alert\(alerts == 1 ? "" : "s")") }
        }
        return parts.joined(separator: " · ")
    }

    private func figure(_ icon: String, _ value: String, help: String) -> some View {
        HStack(spacing: 3) {
            Image(systemName: icon).font(.system(size: 10, weight: .semibold)).foregroundStyle(Theme.secondary)
            Text(value).font(.system(size: 12, weight: .semibold)).rolling(value)
        }
        .help(help)
    }

    private func averageCPU(_ pollers: [ProjectPoller]) -> Double? {
        let values = pollers.flatMap { poller in
            poller.data.servers.compactMap { poller.data.metrics[$0.id]?.cpuPercent(cores: $0.serverType.cores).last?.value }
        }
        return values.isEmpty ? nil : values.reduce(0, +) / Double(values.count)
    }

    private var cost: String? {
        let currency = monitor.pricing?.currency ?? "EUR"
        let amount: Decimal?
        if store.scope.count > 1 {
            amount = monitor.allProjectsCost?.monthToDate
        } else {
            amount = store.scope.first.flatMap { monitor.costReport(for: $0.id)?.monthToDate }
        }
        return amount.map { $0.formatted(.currency(code: currency).precision(.fractionLength(0))) }
    }
}

struct ProjectHeader: View {
    let project: Project
    let poller: ProjectPoller?
    var collapsed = false
    var toggle: () -> Void = {}

    var body: some View {
        Button(action: toggle) { content }
            .buttonStyle(.plain)
            .help(collapsed ? "Show servers" : "Hide servers")
    }

    private var content: some View {
        HStack(spacing: 6) {
            Image(systemName: project.icon)
                .font(.system(size: 11, weight: .semibold))
                .foregroundStyle(project.color.color)
            Text(project.name)
                .font(.system(size: 12, weight: .semibold))
                .lineLimit(1)
            ProviderTag(provider: project.provider)
            Spacer(minLength: 8)
            Text(summary)
                .font(.system(size: 11))
                .foregroundStyle(summaryColor)
            Image(systemName: "chevron.down")
                .font(.system(size: 10, weight: .semibold))
                .foregroundStyle(Theme.secondary)
                .rotationEffect(.degrees(collapsed ? -90 : 0))
        }
        .padding(.horizontal, 16)
        .padding(.top, 14)
        .padding(.bottom, 2)
        .contentShape(Rectangle())
    }

    private var summary: String {
        guard let poller, poller.data.lastUpdated != nil else { return "" }
        let alerts = poller.visibleAlerts.count
        if alerts > 0 { return "\(alerts) alert\(alerts == 1 ? "" : "s")" }
        let count = poller.data.servers.count
        let stopped = poller.data.servers.filter { $0.status != .running }.count
        let base = "\(count) server\(count == 1 ? "" : "s")"
        return stopped > 0 ? "\(base) · \(stopped) not running" : base
    }

    private var summaryColor: Color {
        guard let poller else { return Theme.secondary }
        return poller.visibleAlerts.map(\.severity).max().map(Theme.color) ?? Theme.secondary
    }
}

struct EmptyLine: View {
    let text: String
    let link: (String, URL)?
    var action: (String, () -> Void)?

    var body: some View {
        HStack(spacing: 8) {
            Text(text)
                .foregroundStyle(Theme.secondary)
            if let link {
                Link(link.0, destination: link.1)
            }
            if let action {
                Button(action.0, action: action.1).buttonStyle(.link)
            }
            Spacer(minLength: 0)
        }
        .font(.system(size: 12))
        .padding(.horizontal, 16)
        .padding(.vertical, 12)
    }
}

struct ServerRowPlaceholder: View {
    @State private var dim = false

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 8) {
                Circle().frame(width: 8, height: 8)
                bar(120, 12)
                bar(80, 10)
            }
            HStack(spacing: 12) {
                ForEach(0..<3, id: \.self) { _ in
                    VStack(alignment: .leading, spacing: 5) {
                        bar(44, 8)
                        bar(70, 14)
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                }
            }
            bar(nil, 5)
        }
        .foregroundStyle(Theme.card)
        .opacity(dim ? 0.5 : 1)
        .padding(.horizontal, 16)
        .padding(.vertical, 12)
        .onAppear {
            withAnimation(.easeInOut(duration: 0.9).repeatForever(autoreverses: true)) { dim = true }
        }
        .accessibilityLabel("Loading servers")
    }

    private func bar(_ width: CGFloat?, _ height: CGFloat) -> some View {
        RoundedRectangle(cornerRadius: height / 2)
            .frame(width: width, height: height)
            .frame(maxWidth: width == nil ? .infinity : nil, alignment: .leading)
    }
}

struct ServerRow: View {
    let server: Server
    let environment: ServerEnvironment
    let metrics: ServerMetrics?
    let alert: FiringAlert?
    let showsDivider: Bool
    var agent: AgentSnapshot?

    var address: String?

    private var cpu: [MetricPoint] { metrics?.cpuPercent(cores: server.serverType.cores) ?? [] }
    private var running: Bool { server.status == .running }

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 8) {
                Circle().fill(statusColor).frame(width: 8, height: 8)
                    .accessibilityLabel(statusLabel)
                Text(server.name).font(.system(size: 14, weight: .semibold)).lineLimit(1)
                EnvironmentBadge(environment: environment)
                Text(meta).font(.system(size: 12)).foregroundStyle(Theme.secondary).lineLimit(1)
                if server.agentOnly { AgentHostIcons(server: server, address: address) }
                Spacer(minLength: 0)
                Image(systemName: "chevron.right")
                    .font(.system(size: 10, weight: .semibold))
                    .foregroundStyle(.tertiary)
            }

            HStack(alignment: .top, spacing: 12) {
                if server.agentOnly && cpu.isEmpty && agent != nil {
                    metric("Load · 1 min", Format.load(agent?.host.load.first), help: "Update the agent to see CPU use.")
                } else {
                VStack(alignment: .leading, spacing: 3) {
                    caption("CPU · 1 h")
                    HStack(alignment: .bottom, spacing: 6) {
                        Text(running ? Format.percent(cpu.last?.value) : "Off")
                            .font(.system(size: 15, weight: .semibold))
                            .rolling(cpu.last?.value)
                            .foregroundStyle(cpuColor)
                        Sparkline(values: cpu.map(\.value), color: sparkColor)
                            .frame(width: 64, height: 18)
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                }
                if let agent, running {
                    let fullest = agent.disks.max { $0.usedFraction < $1.usedFraction }
                    metric("Memory", Format.percent(agent.memory.usedFraction * 100), warn: agent.memory.usedFraction >= 0.9)
                    metric("Disk", Format.percent(fullest.map { $0.usedFraction * 100 }),
                           warn: (fullest?.usedFraction ?? 0) >= 0.9, help: fullest.map { "Fullest file system: \($0.mount)" })
                } else if server.agentOnly {
                    metric("Memory", "-")
                    metric("Disk", "-")
                } else {
                    metric("Disk I/O", running ? Format.iops(metrics?.totalIOPS.last?.value) : "-")
                    metric("Net out", running ? Format.rate(metrics?.points(MetricSeries.networkBandwidthOut).last?.value) : "-")
                }
            }

            if let included = server.includedTraffic, included > 0 {
                let used = server.outgoingTraffic ?? 0
                let fraction = min(1, Double(used) / Double(included))
                VStack(spacing: 5) {
                    HStack {
                        caption("Traffic this period")
                        Spacer()
                        caption(Format.traffic(used, of: included))
                    }
                    GeometryReader { proxy in
                        ZStack(alignment: .leading) {
                            Capsule().fill(Theme.divider)
                            Capsule().fill(fraction > 0.8 ? Theme.orange : Theme.green)
                                .frame(width: max(fraction > 0 ? 4 : 0, proxy.size.width * fraction))
                        }
                    }
                    .frame(height: 5)
                }
            }
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 12)
        .overlay(alignment: .bottom) {
            if showsDivider { Theme.divider.frame(height: 1).padding(.horizontal, 16) }
        }
    }

    private var meta: String {
        let base = server.meta(address: address)
        return running ? base : "\(base) · \(statusLabel)"
    }

    private var statusLabel: String {
        switch server.status {
        case .running: alert == nil ? "Running" : "Running, alert"
        case .off: "Off"
        default: server.status.rawValue.capitalized
        }
    }

    private var statusColor: Color {
        if let alert { return Theme.color(alert.severity) }
        if server.agentOnly && agent == nil { return Theme.off }
        switch server.status {
        case .running: return Theme.green
        case .off: return Theme.off
        default: return Theme.orange
        }
    }

    private var sparkColor: Color {
        guard running else { return Theme.off }
        return (cpu.last?.value ?? 0) > 85 ? Theme.orange : Color.accentColor
    }

    private var cpuColor: Color {
        guard running else { return Theme.off }
        return (cpu.last?.value ?? 0) > 85 ? Theme.orange : Theme.text
    }

    private func caption(_ text: String) -> some View {
        Text(text).font(.system(size: 11)).foregroundStyle(Theme.secondary)
    }

    private func metric(_ title: String, _ value: String, warn: Bool = false, help: String? = nil) -> some View {
        VStack(alignment: .leading, spacing: 3) {
            caption(title).lineLimit(1)
            Text(value).font(.system(size: 15, weight: .semibold)).rolling(value)
                .foregroundStyle(warn ? Theme.orange : Theme.text)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .help(help ?? "")
    }
}

struct RowButtonStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        HoverRow(pressed: configuration.isPressed) { configuration.label }
    }
}

private struct HoverRow<Content: View>: View {
    let pressed: Bool
    @ViewBuilder let content: Content
    @State private var hovering = false

    var body: some View {
        content
            .background(Theme.card.opacity(pressed ? 1 : hovering ? 0.6 : 0))
            .onHover { hovering = $0 }
    }
}

struct Sparkline: View {
    let values: [Double]
    let color: Color

    private static let buckets = 24

    var body: some View {
        Canvas { context, size in
            let points = Self.smooth(values)
            let top = max(5, (points.max() ?? 0) * 1.25)
            let baseline = size.height - 1
            guard points.count > 1 else {
                var flat = Path()
                flat.move(to: CGPoint(x: 0, y: baseline))
                flat.addLine(to: CGPoint(x: size.width, y: baseline))
                context.stroke(flat, with: .color(color.opacity(0.5)), lineWidth: 1.5)
                return
            }
            let positions = points.enumerated().map { index, value in
                CGPoint(
                    x: size.width * CGFloat(index) / CGFloat(points.count - 1),
                    y: baseline - (size.height - 3) * CGFloat(value / top)
                )
            }
            var line = Path()
            line.addLines(positions)
            var area = line
            area.addLine(to: CGPoint(x: size.width, y: size.height))
            area.addLine(to: CGPoint(x: 0, y: size.height))
            area.closeSubpath()
            context.fill(area, with: .color(color.opacity(0.15)))
            context.stroke(line, with: .color(color), style: StrokeStyle(lineWidth: 1.5, lineCap: .round, lineJoin: .round))
        }
        .accessibilityHidden(true)
    }

    static func smooth(_ values: [Double]) -> [Double] {
        guard values.count > buckets else { return values }
        let size = Double(values.count) / Double(buckets)
        return (0..<buckets).map { bucket in
            let slice = values[Int(Double(bucket) * size)..<min(values.count, Int(Double(bucket + 1) * size))]
            return slice.reduce(0, +) / Double(max(slice.count, 1))
        }
    }
}

struct CompactServerRow: View {
    let server: Server
    let environment: ServerEnvironment
    let metrics: ServerMetrics?
    let alert: FiringAlert?
    let threshold: Double?
    let showsDivider: Bool
    var agent: AgentSnapshot?
    var address: String?

    private var running: Bool { server.status == .running }
    private var load: Double? { agent?.host.load.first }
    private var usesLoad: Bool { server.agentOnly && (metrics?.points(MetricSeries.cpu).isEmpty ?? true) && agent != nil }
    private var cpu: Double? {
        if usesLoad { return load.map { $0 / Double(max(1, agent?.host.cores ?? 1)) * 100 } }
        return metrics?.cpuPercent(cores: server.serverType.cores).last?.value
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 5) {
            HStack(spacing: 7) {
                Circle().fill(statusColor).frame(width: 7, height: 7)
                Text(server.name).font(.system(size: 13, weight: .semibold)).lineLimit(1)
                EnvironmentBadge(environment: environment)
                Spacer(minLength: 8)
                Text(usesLoad ? "Load \(Format.load(load))" : running ? Format.percent(cpu) : statusLabel)
                    .font(.system(size: 13, weight: .semibold))
                    .foregroundStyle(running ? barColor : Theme.off)
                    .rolling(cpu)
            }
            GeometryReader { proxy in
                ZStack(alignment: .leading) {
                    Capsule().fill(Theme.divider)
                    if running, let cpu {
                        Capsule().fill(barColor)
                            .frame(width: max(4, proxy.size.width * min(1, cpu / 100)))
                    }
                }
            }
            .frame(height: 4)
            HStack(spacing: 4) {
                Text(server.meta(address: address))
                    .lineLimit(1)
                if server.agentOnly { AgentHostIcons(server: server, address: address) }
                Spacer(minLength: 8)
                if usesLoad {
                    if let fullest = agent?.disks.max(by: { $0.usedFraction < $1.usedFraction }) {
                        Text("Disk \(Format.percent(fullest.usedFraction * 100))")
                    }
                } else if running {
                    Text("↑ \(Format.rate(metrics?.points(MetricSeries.networkBandwidthOut).last?.value))")
                        .rolling(metrics?.points(MetricSeries.networkBandwidthOut).last?.value)
                }
                if let fraction = server.trafficFraction, fraction >= 0.5 {
                    Text("· \(Int(fraction * 100))% traffic")
                        .foregroundStyle(fraction > 0.8 ? Theme.orange : Theme.secondary)
                }
            }
            .font(.system(size: 11))
            .foregroundStyle(Theme.secondary)
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 9)
        .overlay(alignment: .bottom) {
            if showsDivider { Theme.divider.frame(height: 1).padding(.horizontal, 16) }
        }
        .accessibilityElement(children: .combine)
    }

    private var statusLabel: String {
        server.status == .off ? "Off" : server.status.rawValue.capitalized
    }

    private var statusColor: Color {
        if let alert { return Theme.color(alert.severity) }
        if server.agentOnly && agent == nil { return Theme.off }
        switch server.status {
        case .running: return Theme.green
        case .off: return Theme.off
        default: return Theme.orange
        }
    }

    private var barColor: Color {
        guard let cpu else { return Theme.green }
        let limit = threshold ?? 85
        if cpu > limit { return Theme.red }
        if cpu > limit * 0.75 { return Theme.orange }
        return Theme.green
    }
}

extension Server {
    func meta(address: String?) -> String {
        guard agentOnly else { return "\(serverType.name.uppercased()) · \(Format.place(location))" }
        var parts: [String] = []
        if serverType.cores > 0 { parts.append("\(Int(serverType.cores)) \(serverType.cores == 1 ? "core" : "cores")") }
        if serverType.memory > 0 { parts.append(Format.memory(Int64(serverType.memory * 1_073_741_824))) }
        return parts.isEmpty ? "Waiting for the agent" : parts.joined(separator: " · ")
    }
}

struct AgentHostIcons: View {
    let server: Server
    let address: String?

    var body: some View {
        HStack(spacing: 4) {
            if !server.serverType.description.isEmpty {
                icon("desktopcomputer", server.serverType.description)
            }
            if let address, !address.isEmpty {
                icon("network", address)
            }
        }
    }

    private func icon(_ name: String, _ help: String) -> some View {
        Image(systemName: name)
            .font(.system(size: 10))
            .foregroundStyle(Theme.secondary)
            .help(help)
            .accessibilityLabel(help)
    }
}

struct ProviderTag: View {
    let provider: CloudProvider

    var body: some View {
        Text(provider.name)
            .font(.system(size: 9, weight: .semibold))
            .foregroundStyle(Theme.secondary)
            .padding(.horizontal, 5)
            .padding(.vertical, 1)
            .background(Theme.card, in: RoundedRectangle(cornerRadius: 4))
            .fixedSize()
    }
}
