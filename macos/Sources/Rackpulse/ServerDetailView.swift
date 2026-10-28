import Charts
import HetznerKit
import SwiftUI

enum MetricRange: String, CaseIterable, Identifiable, Codable {
    case hour = "1h"
    case sixHours = "6h"
    case day = "24h"
    case week = "7d"
    case month = "30d"

    var id: String { rawValue }

    var seconds: TimeInterval {
        switch self {
        case .hour: 3_600
        case .sixHours: 21_600
        case .day: 86_400
        case .week: 604_800
        case .month: 2_592_000
        }
    }

    var axisFormat: Date.FormatStyle {
        switch self {
        case .hour, .sixHours, .day: .dateTime.hour().minute()
        case .week, .month: .dateTime.month(.abbreviated).day()
        }
    }

    var hoverFormat: Date.FormatStyle {
        switch self {
        case .hour, .sixHours, .day: .dateTime.hour().minute()
        case .week, .month: .dateTime.month(.abbreviated).day().hour().minute()
        }
    }
}

enum ServerTab: String, Hashable {
    case overview, docker, details

    var title: String {
        switch self {
        case .overview: "Overview"
        case .docker: "Docker"
        case .details: "Details"
        }
    }
}

struct ServerDetailView: View {
    let server: Server
    let project: Project
    let poller: ProjectPoller
    let monitor: Monitor
    let openAgent: () -> Void
    let openContainer: (String) -> Void
    let back: () -> Void

    @Environment(AppActions.self) private var app

    init(server: Server, project: Project, poller: ProjectPoller, monitor: Monitor, range: MetricRange, tab: Binding<ServerTab>,
         openAgent: @escaping () -> Void, openContainer: @escaping (String) -> Void, back: @escaping () -> Void) {
        self.openAgent = openAgent
        self.openContainer = openContainer
        _tab = tab
        self.server = server
        self.project = project
        self.poller = poller
        self.monitor = monitor
        self.back = back
        _range = State(initialValue: range)
    }

    @State private var range: MetricRange
    @Binding private var tab: ServerTab
    @State private var metrics: ServerMetrics?
    @State private var failed = false
    @State private var actions: [ServerAction] = []
    @State private var firewalls: [Int64: String] = [:]
    @State private var copied: String?
    @State private var showsIP = false
    @State private var hover: Date?
    @State private var actionsLoaded = false
    @State private var confirming: PowerAction?
    @State private var powering = false
    @State private var powerMessage: String?
    @State private var memory: [MetricPoint] = []
    @State private var powerHistory: (actions: [ServerAction], complete: Bool)?
    private static let bootCommands: Set<String> = ["create_server", "start_server", "reboot_server", "reset_server", "rebuild_server"]
    private static let stopCommands: Set<String> = ["stop_server", "shutdown_server"]

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            header
            quickActions
                .padding(.horizontal, 16)
                .padding(.top, 12)
            if project.access == .readWrite && (confirming != nil || powerMessage != nil || PowerAction.available(for: server.status).isEmpty) {
                powerControls
                    .padding(.horizontal, 16)
                    .padding(.top, 8)
            }
            if tabs.count > 1 {
                SegmentedControl(selection: $tab, options: tabs.map { ($0, $0.title) })
                    .padding(.horizontal, 16)
                    .padding(.top, 14)
            }
            switch tab {
            case .overview: overview
            case .docker: docker
            case .details: details
            }

            Color.clear.frame(height: 14)
        }
        .onExitCommand(perform: back)
        .task(id: range) { await loadMetrics() }
        .onChange(of: range) { app.chartRange = range }
        .task(id: server.id) {
            async let recent = poller.recentActions(server: server.id)
            async let names = poller.firewallNames()
            async let power = poller.powerHistory(server: server.id)
            actions = await recent
            actionsLoaded = true
            firewalls = await names
            powerHistory = await power
        }
        .onChange(of: poller.data.lastUpdated) {
            if range == .hour { Task { await loadMetrics() } }
        }
    }

    private var tabs: [ServerTab] {
        var tabs: [ServerTab] = [.overview]
        if snapshot?.docker != nil { tabs.append(.docker) }
        tabs.append(.details)
        return tabs
    }

    private var snapshot: AgentSnapshot? {
        monitor.agents.state(project.id, server.id)?.snapshot
    }

    @ViewBuilder
    private var overview: some View {
        if hasAgent {
            AgentOverview(server: server, project: project, monitor: monitor, openSetup: openAgent, openDocker: { tab = .docker })
        }
        if !server.agentOnly || hasAgent {
        SectionHeader("Activity")
            .padding(.top, 18)
        SegmentedControl(selection: $range, options: MetricRange.allCases.map { ($0, $0.rawValue) })
            .padding(.horizontal, 16)
            .padding(.top, 2)
        if let note = newerThanRangeNote {
            Text(note)
                .font(.system(size: 11))
                .foregroundStyle(Theme.secondary)
                .padding(.horizontal, 16)
                .padding(.top, 6)
        }
        VStack(spacing: 14) {
            if showsActivity { cpuChart }
            if hasAgent { memoryChart }
            if showsActivity {
            pairChart(
                title: "Disk IOPS", detail: "read / write",
                first: ("Read", metrics?.points(MetricSeries.diskIOPSRead) ?? []),
                second: ("Write", metrics?.points(MetricSeries.diskIOPSWrite) ?? []),
                format: Format.iops
            )
            pairChart(
                title: "Network", detail: "in / out",
                first: ("In", metrics?.points(MetricSeries.networkBandwidthIn) ?? []),
                second: ("Out", metrics?.points(MetricSeries.networkBandwidthOut) ?? []),
                format: Format.rate
            )
            }
            if server.agentOnly && hasAgent && metrics != nil && !showsActivity && monitor.agents.needsUpdate(project.id, server.id) {
                Text("Update the agent on \(server.name) to see CPU, disk and network charts.")
                    .font(.system(size: 11))
                    .foregroundStyle(Theme.secondary)
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
        }
        .padding(.horizontal, 16)
        .padding(.top, 12)

        UptimeCard(timeline: timeline, hasAgent: hasAgent, agentOnly: server.agentOnly)
            .padding(.horizontal, 16)
            .padding(.top, 16)
        }

        if !hasAgent {
            SectionHeader("Inside the server")
                .padding(.top, 20)
            AgentInvitation(server: server, project: project, monitor: monitor, openSetup: openAgent)
                .padding(.horizontal, 16)
        }
    }

    @ViewBuilder
    private var docker: some View {
        if let docker = snapshot?.docker {
            DockerPanel(docker: docker, hostMemory: snapshot?.memory.total ?? 0, store: monitor.agents,
                        key: AgentStore.key(project.id, server.id), open: openContainer)
                .padding(.top, 14)
        }
    }

    @ViewBuilder
    private var details: some View {
        SectionHeader("Server")
            .padding(.top, 18)
        facts
            .padding(.horizontal, 16)

        SectionHeader("Disks")
            .padding(.top, 20)
        disks
            .padding(.horizontal, 16)

        if hasAgent {
            AgentSystemCard(server: server, project: project, monitor: monitor, openSetup: openAgent)
        }
    }

    private var header: some View {
        HStack(spacing: 10) {
            Button(action: back) {
                Image(systemName: "chevron.left")
                    .font(.system(size: 12, weight: .semibold))
                    .frame(width: 28, height: 28)
                    .background(Theme.card, in: RoundedRectangle(cornerRadius: 7))
                    .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .accessibilityLabel("Back to servers")
            .keyboardShortcut("[", modifiers: .command)

            VStack(alignment: .leading, spacing: 1) {
                HStack(spacing: 6) {
                    Circle().fill(statusColor).frame(width: 8, height: 8)
                    Text(server.name).font(.system(size: 14, weight: .semibold)).lineLimit(1)
                    if server.agentOnly { ProviderTag(provider: .agent) }
                    environmentMenu
                }
                Text(spec)
                    .font(.system(size: 12))
                    .foregroundStyle(Theme.secondary)
                    .lineLimit(1)
            }
            Spacer(minLength: 0)
            if project.access == .readWrite {
                powerMenu
            }
        }
        .padding(.horizontal, 16)
        .padding(.top, 14)
    }

    private var environmentMenu: some View {
        let environment = monitor.settings.environment(project: project.id, server: server)
        return Menu {
            EnvironmentPicker(settings: monitor.settings, project: project.id, server: server) { Text("Environment") }
                .pickerStyle(.inline)
        } label: {
            if environment == .none {
                Image(systemName: "tag")
                    .font(.system(size: 10, weight: .semibold))
                    .foregroundStyle(Theme.secondary)
                    .frame(width: 16, height: 16)
                    .contentShape(Rectangle())
            } else {
                EnvironmentBadge(environment: environment)
            }
        }
        .menuStyle(.button)
        .buttonStyle(.plain)
        .menuIndicator(.hidden)
        .fixedSize()
        .help("Environment")
    }

    private var powerMenu: some View {
        let actions = PowerAction.available(for: server.status)
        return Menu {
            ForEach(actions.filter { !$0.isDestructive }) { action in
                Button { confirming = action; powerMessage = nil } label: { Label(action.title, systemImage: action.icon) }
            }
            if actions.contains(where: \.isDestructive) {
                Divider()
                ForEach(actions.filter(\.isDestructive)) { action in
                    Button(role: .destructive) { confirming = action; powerMessage = nil } label: { Label(action.title, systemImage: action.icon) }
                }
            }
        } label: {
            Image(systemName: "power")
                .font(.system(size: 13, weight: .semibold))
                .frame(width: 28, height: 28)
                .background(Theme.card, in: RoundedRectangle(cornerRadius: 7))
                .contentShape(Rectangle())
        }
        .menuStyle(.button)
        .buttonStyle(.plain)
        .menuIndicator(.hidden)
        .fixedSize()
        .disabled(actions.isEmpty)
        .help("Power")
    }

    private var cpuChart: some View {
        let points = metrics?.cpuPercent(cores: server.serverType.cores) ?? []
        let average = points.isEmpty ? nil : points.map(\.value).reduce(0, +) / Double(points.count)
        let threshold = cpuThreshold
        let hot = threshold.map { (points.last?.value ?? 0) > $0 } ?? false
        let color = hot ? Theme.orange : Color.accentColor
        let picked = hover.flatMap { Self.nearest(points, to: $0) }
        let value = picked.map { "\(Format.percent($0.value)) at \($0.time.formatted(range.hoverFormat))" }
            ?? "\(Format.percent(points.last?.value)) now · avg \(Format.percent(average))"
        return chartBlock(
            title: "CPU",
            detail: nil,
            value: points.isEmpty ? nil : value,
            valueColor: hot ? Theme.orange : Theme.text,
            height: 76,
            empty: points.isEmpty
        ) {
            Chart {
                ForEach(points, id: \.time) { point in
                    AreaMark(x: .value("Time", point.time), y: .value("CPU", point.value))
                        .foregroundStyle(color.opacity(0.15))
                    LineMark(x: .value("Time", point.time), y: .value("CPU", point.value))
                        .foregroundStyle(color)
                        .lineStyle(StrokeStyle(lineWidth: 1.5))
                }
                if let picked {
                    hoverMarks(picked.time)
                    PointMark(x: .value("Time", picked.time), y: .value("CPU", picked.value))
                        .foregroundStyle(color)
                        .symbolSize(30)
                }
                if let threshold {
                    RuleMark(y: .value("Alert", threshold))
                        .foregroundStyle(Theme.orange.opacity(0.7))
                        .lineStyle(StrokeStyle(lineWidth: 1, dash: [3, 3]))
                        .annotation(position: .top, alignment: .trailing, spacing: 1) {
                            Text("\(Int(threshold))% alert").font(.system(size: 9)).foregroundStyle(Theme.secondary)
                        }
                }
            }
            .chartYScale(domain: 0...100)
            .chartXSelection(value: $hover)
            .chartYAxis {
                AxisMarks(position: .leading, values: [0, 50, 100]) { value in
                    AxisGridLine()
                    AxisValueLabel { Text("\(value.as(Int.self) ?? 0)%") }
                }
            }
            .chartXScale(domain: domain)
            .chartPlotStyle { $0.clipped() }
            .chartXAxis { timeAxis }
        }
    }

    private func pairChart(
        title: String,
        detail: String,
        first: (String, [MetricPoint]),
        second: (String, [MetricPoint]),
        format: @escaping (Double?) -> String
    ) -> some View {
        let empty = first.1.isEmpty && second.1.isEmpty
        let pickedFirst = hover.flatMap { Self.nearest(first.1, to: $0) }
        let pickedSecond = hover.flatMap { Self.nearest(second.1, to: $0) }
        let time = (pickedFirst ?? pickedSecond)?.time
        let value: String? = if empty {
            nil
        } else if let time {
            "\(format(pickedFirst?.value)) / \(format(pickedSecond?.value)) at \(time.formatted(range.hoverFormat))"
        } else {
            "\(format(first.1.last?.value)) / \(format(second.1.last?.value))"
        }
        return chartBlock(title: title, detail: detail, value: value, valueColor: Theme.text, height: 60, empty: empty) {
            Chart {
                ForEach([first, second], id: \.0) { name, points in
                    ForEach(points, id: \.time) { point in
                        LineMark(x: .value("Time", point.time), y: .value(title, point.value), series: .value("Series", name))
                            .foregroundStyle(by: .value("Series", name))
                            .lineStyle(StrokeStyle(lineWidth: 1.5))
                    }
                }
                if let time { hoverMarks(time) }
            }
            .chartXSelection(value: $hover)
            .chartForegroundStyleScale([first.0: Color.accentColor, second.0: Theme.orange])
            .chartLegend(position: .top, alignment: .trailing, spacing: 2)
            .chartYAxis {
                AxisMarks(position: .leading, values: .automatic(desiredCount: 2)) { value in
                    AxisGridLine()
                    AxisValueLabel { Text(format(value.as(Double.self))) }
                }
            }
            .chartXScale(domain: domain)
            .chartPlotStyle { $0.clipped() }
            .chartXAxis { timeAxis }
        }
    }

    private var showsActivity: Bool {
        !server.agentOnly || metrics.map { !$0.points(MetricSeries.cpu).isEmpty } ?? false
    }

    private var hasAgent: Bool {
        monitor.agents.link(project.id, server.id)?.isPaired == true
    }

    private var timeline: UptimeTimeline {
        UptimeTimeline(
            created: server.created,
            status: server.status,
            local: monitor.uptime.history.series(server.id),
            agent: monitor.agents.uptime(project.id, server.id),
            actions: powerHistory?.actions ?? [],
            actionsComplete: powerHistory?.complete ?? false,
            now: .now
        )
    }

    private var memoryChart: some View {
        let points = memory
        let picked = hover.flatMap { Self.nearest(points, to: $0) }
        let value = picked.map { "\(Format.percent($0.value)) at \($0.time.formatted(range.hoverFormat))" }
            ?? "\(Format.percent(points.last?.value)) now · peak \(Format.percent(points.map(\.value).max()))"
        return chartBlock(title: "Memory", detail: nil, value: points.isEmpty ? nil : value, valueColor: Theme.text, height: 60, empty: points.isEmpty) {
            Chart {
                ForEach(points, id: \.time) { point in
                    AreaMark(x: .value("Time", point.time), y: .value("Memory", point.value))
                        .foregroundStyle(Theme.info.opacity(0.12))
                    LineMark(x: .value("Time", point.time), y: .value("Memory", point.value))
                        .foregroundStyle(Theme.info)
                        .lineStyle(StrokeStyle(lineWidth: 1.5))
                }
                if let picked { hoverMarks(picked.time) }
            }
            .chartYScale(domain: 0...100)
            .chartXSelection(value: $hover)
            .chartYAxis {
                AxisMarks(position: .leading, values: [0, 50, 100]) { value in
                    AxisGridLine()
                    AxisValueLabel { Text("\(value.as(Int.self) ?? 0)%") }
                }
            }
            .chartXScale(domain: domain)
            .chartPlotStyle { $0.clipped() }
            .chartXAxis { timeAxis }
        }
    }

    private func loadMemory() async {
        guard hasAgent else { return }
        let since = Date.now.addingTimeInterval(-range.seconds)
        guard let history = await monitor.agents.history(project.id, server.id, since: since) else { return }
        memory = history.samples.filter { $0.t >= since }.map { MetricPoint(time: $0.t, value: $0.memory * 100) }
    }

    private func hoverMarks(_ time: Date) -> some ChartContent {
        RuleMark(x: .value("Time", time))
            .foregroundStyle(Theme.secondary.opacity(0.5))
            .lineStyle(StrokeStyle(lineWidth: 1))
    }

    private static func nearest(_ points: [MetricPoint], to date: Date) -> MetricPoint? {
        points.min { abs($0.time.timeIntervalSince(date)) < abs($1.time.timeIntervalSince(date)) }
    }

    private var timeAxis: some AxisContent {
        AxisMarks(values: ticks) { _ in
            AxisValueLabel(format: range.axisFormat, anchor: .top)
        }
    }

    private var domain: ClosedRange<Date> {
        let end = metrics?.end ?? .now
        let start = max(metrics?.start ?? end.addingTimeInterval(-range.seconds), server.created)
        return start < end ? start...end : end.addingTimeInterval(-60)...end
    }

    private var ticks: [Date] {
        let span = domain.upperBound.timeIntervalSince(domain.lowerBound)
        return [0.15, 0.5, 0.85].map { domain.lowerBound.addingTimeInterval(span * $0) }
    }

    private var newerThanRangeNote: String? {
        guard let start = metrics?.start, server.created > start else { return nil }
        let created = server.created.formatted(.dateTime.month(.abbreviated).day())
        return "Created \(created), so this shows \(Format.compactDuration(since: server.created))."
    }

    private func chartBlock(
        title: String,
        detail: String?,
        value: String?,
        valueColor: Color,
        height: CGFloat,
        empty: Bool,
        @ViewBuilder chart: () -> some View
    ) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 5) {
                Image(systemName: Self.chartIcons[title] ?? "chart.xyaxis.line")
                    .foregroundStyle(Theme.secondary)
                    .frame(width: 14)
                Text(title).foregroundStyle(Theme.text)
                if let detail { Text(detail).foregroundStyle(Theme.secondary) }
                Spacer()
                if let value { Text(value).fontWeight(.semibold).foregroundStyle(valueColor) }
            }
            .font(.system(size: 12))

            ZStack {
                if empty {
                    Text(placeholder)
                        .font(.system(size: 11))
                        .foregroundStyle(Theme.secondary)
                } else {
                    chart()
                }
            }
            .frame(height: height)
            .frame(maxWidth: .infinity)
        }
    }

    private var placeholder: String {
        if failed { return "Could not load metrics." }
        if metrics == nil { return "Loading…" }
        return server.status == .running ? "No data for this period." : "No data while the server is off."
    }

    @ViewBuilder
    private var facts: some View {
        if server.agentOnly { agentFacts } else { providerFacts }
    }

    private var agentFacts: some View {
        let link = monitor.agents.link(project.id, server.id)
        return LazyVGrid(columns: [GridItem(.flexible(), spacing: 8), GridItem(.flexible(), spacing: 8)], spacing: 8) {
            fact("Status", agentStatusText, icon: "power", accent: agentAnswering ? Theme.green : nil)
            fact("Address", link?.endpoint.display ?? "Not paired", icon: "network")
            fact("System", snapshot.map { "\($0.host.os) · \($0.host.arch)" } ?? "Unknown", icon: "cpu")
            fact("Kernel", snapshot?.host.kernel ?? "Unknown", icon: "gearshape.2")
            fact("Alerts", alertsText, icon: alertMode == .off ? "bell.slash" : "bell")
            fact("Agent", link?.version ?? "Not paired", icon: "antenna.radiowaves.left.and.right")
            if let report = monitor.costReport(for: project.id) {
                let user = monitor.costEstimator(for: project.id).userPrice(server.id)
                let spent = report.lines.filter { $0.kind == .server && $0.resourceID == server.id }.reduce(Decimal(0)) { $0 + $1.monthToDate }
                priceFact("Your price", user.map { "\(money($0, report.currency)) a month" } ?? "Add a price",
                          help: "This server has no list price. Click to enter the monthly price you pay.")
                if user != nil {
                    priceFact("Cost this month", money(spent, report.currency), help: "Estimated from your price since the start of the month.")
                }
            }
        }
    }

    private var agentAnswering: Bool {
        guard let state = monitor.agents.state(project.id, server.id) else { return false }
        return state.snapshot != nil && state.problem == nil && !agentUnreachable
    }

    private var agentUnreachable: Bool {
        poller.visibleAlerts.contains { $0.kind == .agentUnreachable && $0.id.hasSuffix(":\(server.id)") }
    }

    private var agentStatusText: String {
        guard hasAgent else { return "Not paired" }
        guard agentAnswering else { return "Not answering" }
        guard let boot = snapshot?.host.bootTime else { return "Answering" }
        return "Up \(Format.compactDuration(since: boot))"
    }

    private var providerFacts: some View {
        LazyVGrid(columns: [GridItem(.flexible(), spacing: 8), GridItem(.flexible(), spacing: 8)], spacing: 8) {
            fact("Status", statusText, icon: "power", accent: server.status == .running ? Theme.green : nil, help: statusHelp)
            fact("Traffic out", trafficText, icon: "arrow.up.arrow.down")
            ipFact
            fact("Alerts", alertsText, icon: alertMode == .off ? "bell.slash" : "bell")
            fact("Backups", server.backupWindow.map { "Enabled · \($0) UTC" } ?? "Off", icon: "clock.arrow.circlepath")
            fact("Firewall", firewallText, icon: "shield.lefthalf.filled")
            fact(lastActionTitle, lastActionText, icon: "bolt")
            fact("Protection", protectionText, icon: "lock", accent: server.protection.delete ? Theme.green : nil)
            if let report = monitor.costReport(for: project.id) {
                let estimator = monitor.costEstimator(for: project.id)
                let user = estimator.userPrice(server.id)
                let monthly = user ?? estimator.listPrice(server)?.priceMonthly.value(report.priceKind)
                let spent = report.lines.filter { ($0.kind == .server || $0.kind == .backup) && $0.resourceID == server.id }
                    .reduce(Decimal(0)) { $0 + $1.monthToDate }
                priceFact(user == nil ? "List price" : "Your price", monthly.map { "\(money($0, report.currency)) a month" } ?? "Unknown",
                          help: user == nil
                              ? "\(project.provider.name)'s list price for this server type. Click to enter the price you pay."
                              : "The monthly price you entered. Click to change or clear it.")
                priceFact("Cost this month", money(spent, report.currency),
                          help: "Estimated cost of this server and its backups since the start of the month.")
            }
        }
    }

    private func priceFact(_ title: String, _ value: String, help: String) -> some View {
        Button {
            monitor.settings.requestedPage = .project(project.id)
            app.showSettings()
        } label: {
            fact(title, value, icon: "banknote", help: help).contentShape(Rectangle())
        }
        .buttonStyle(.plain)
    }

    private var disks: some View {
        let volumes = poller.data.volumes.filter { $0.server == server.id }
        let local = server.primaryDiskSize > 0 ? server.primaryDiskSize : server.serverType.disk
        let mounts = snapshot?.disks ?? []
        let root = mounts.first { $0.mount == "/" }
        let volumeMounts = Dictionary(volumes.compactMap { volume in
            mounts.first { $0.mount.contains("HC_Volume_\(volume.id)") }.map { (volume.id, $0) }
        }, uniquingKeysWith: { first, _ in first })
        let matched = Set([root?.id].compactMap { $0 } + volumeMounts.values.map(\.id))
        let others = mounts.filter { !matched.contains($0.id) }
        return VStack(spacing: 0) {
            diskRow(icon: "internaldrive", name: server.agentOnly ? "Root" : "Local disk",
                    meta: server.agentOnly ? (root.map { "\($0.fs) · \($0.device)" } ?? "/") : "Included with \(server.serverType.name.uppercased())",
                    size: local, usage: root, divider: !volumes.isEmpty || !others.isEmpty)
            ForEach(Array(volumes.enumerated()), id: \.element.id) { index, volume in
                diskRow(
                    icon: "externaldrive",
                    name: volume.name,
                    meta: ["Volume", volume.format].compactMap { $0 }.joined(separator: " · "),
                    size: volume.size,
                    usage: volumeMounts[volume.id],
                    divider: index < volumes.count - 1 || !others.isEmpty
                )
            }
            ForEach(Array(others.enumerated()), id: \.element.id) { index, disk in
                diskRow(icon: "folder", name: disk.mount, meta: "\(disk.fs) · \(disk.device)",
                        size: nil, usage: disk, divider: index < others.count - 1)
            }
        }
        .background(Theme.card, in: RoundedRectangle(cornerRadius: 9))
    }

    private func diskRow(icon: String, name: String, meta: String, size: Double?, usage: AgentSnapshot.Disk?, divider: Bool) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 10) {
                Image(systemName: icon).foregroundStyle(Theme.secondary).frame(width: 18)
                VStack(alignment: .leading, spacing: 1) {
                    HStack(spacing: 6) {
                        Text(name).font(.system(size: 13, weight: .semibold)).lineLimit(1).truncationMode(.middle)
                        if usage?.readOnly == true {
                            Text("read-only").font(.system(size: 11)).foregroundStyle(Theme.red)
                        }
                    }
                    Text(meta).font(.system(size: 11)).foregroundStyle(Theme.secondary).lineLimit(1)
                }
                Spacer(minLength: 0)
                if let usage {
                    Text("\(Format.size(usage.used)) of \(Format.size(usage.used + usage.available))")
                        .font(.system(size: 12, weight: .semibold))
                        .foregroundStyle(usage.usedFraction >= 0.9 ? Theme.orange : Theme.text)
                } else if let size {
                    Text("\(Int(size)) GB").font(.system(size: 13, weight: .semibold))
                }
            }
            if let usage {
                UsageBar(fraction: usage.usedFraction, color: UsageBar.color(usage.usedFraction, warn: usage.readOnly))
                    .padding(.leading, 28)
            }
        }
        .padding(.horizontal, 10)
        .padding(.vertical, 8)
        .overlay(alignment: .bottom) {
            if divider { Theme.divider.frame(height: 1).padding(.horizontal, 10) }
        }
    }

    private var ipFact: some View {
        let ip = server.publicNet.ipv4?.ip
        return HStack(alignment: .bottom, spacing: 6) {
            VStack(alignment: .leading, spacing: 2) {
                Label("IPv4", systemImage: "network")
                    .font(.system(size: 11))
                    .foregroundStyle(Theme.secondary)
                    .labelStyle(FactLabelStyle())
                Text(ip.map { showsIP ? $0 : Self.mask($0) } ?? "None")
                    .font(.system(size: 13, weight: .semibold))
                    .lineLimit(1)
                    .textSelection(.enabled)
            }
            Spacer(minLength: 0)
            if ip != nil {
                iconButton(showsIP ? "eye.slash" : "eye", help: showsIP ? "Hide address" : "Show address") {
                    showsIP.toggle()
                }
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(.horizontal, 10)
        .padding(.vertical, 9)
        .background(Theme.card, in: RoundedRectangle(cornerRadius: 9))
    }

    private func iconButton(_ icon: String, help: String, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            Image(systemName: icon)
                .font(.system(size: 11, weight: .semibold))
                .foregroundStyle(Theme.secondary)
                .frame(width: 22, height: 22)
                .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .help(help)
        .accessibilityLabel(help)
    }

    private static func mask(_ ip: String) -> String {
        String(ip.map { $0.isNumber || $0.isLetter ? "•" : $0 })
    }

    private func fact(_ title: String, _ value: String, icon: String, accent: Color? = nil, help: String? = nil) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Label(title, systemImage: icon)
                .font(.system(size: 11, weight: accent == nil ? .regular : .semibold))
                .foregroundStyle(accent ?? Theme.secondary)
                .labelStyle(FactLabelStyle())
            Text(value).font(.system(size: 13, weight: .semibold)).foregroundStyle(Theme.text).lineLimit(1)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(.horizontal, 10)
        .padding(.vertical, 9)
        .background(Theme.card, in: RoundedRectangle(cornerRadius: 9))
        .tip(help)
    }

    private var spec: String {
        if server.agentOnly {
            let os = snapshot?.host.os ?? server.serverType.description.components(separatedBy: " · ").first ?? ""
            let parts = [os, server.meta(address: nil), project.name].filter { !$0.isEmpty && $0 != "Waiting for the agent" }
            return parts.joined(separator: " · ")
        }
        let type = server.serverType
        let cpu = type.cpuType == "dedicated" ? "dedicated vCPU" : "vCPU"
        return "\(type.name.uppercased()) · \(Int(type.cores)) \(cpu) · \(Int(type.memory)) GB · \(Int(type.disk)) GB · \(Format.place(server.location))"
    }

    private var statusColor: Color {
        if server.agentOnly { return agentAnswering ? Theme.green : hasAgent ? Theme.orange : Theme.off }
        return switch server.status {
        case .running: Theme.green
        case .off: Theme.off
        default: Theme.orange
        }
    }

    private var statusName: String {
        server.status == .off ? "Off" : server.status.rawValue.capitalized
    }

    private var stateSince: (date: Date, fromAction: Bool)? {
        guard actionsLoaded else { return nil }
        switch server.status {
        case .running:
            if let boot = actions.first(where: { Self.bootCommands.contains($0.command) && $0.status == "success" }) {
                return (boot.started, true)
            }
            return (server.created, false)
        case .off:
            return actions.first { Self.stopCommands.contains($0.command) }.map { ($0.started, true) }
        default:
            return nil
        }
    }

    private var statusText: String {
        guard let since = stateSince else { return statusName }
        return "\(statusName) · \(Format.compactDuration(since: since.date))"
    }

    private var statusHelp: String? {
        guard let since = stateSince else { return nil }
        let date = since.date.formatted(date: .abbreviated, time: .shortened)
        let source = since.fromAction
            ? "Counted from the last start, stop or restart made through \(project.provider.name)."
            : "Counted from when the server was created. Restarts from inside the OS are not visible to the API."
        return "\(statusName) for \(Format.exactDuration(since: since.date)). Since \(date). \(source)"
    }

    private var trafficText: String {
        guard let included = server.includedTraffic else { return "-" }
        return Format.traffic(server.outgoingTraffic ?? 0, of: included).replacingOccurrences(of: " / ", with: " of ")
    }

    private var firewallText: String {
        let refs = server.publicNet.firewalls ?? []
        guard !refs.isEmpty else { return "None" }
        return refs.map { ref in
            let name = ref.id.flatMap { firewalls[$0] } ?? "#\(ref.id.map(String.init) ?? "?")"
            return ref.status == "pending" ? "\(name) (pending)" : name
        }
        .joined(separator: ", ")
    }

    private var lastActionTitle: String {
        guard let action = actions.first else { return "Last action" }
        return "Last action · \(Self.age(action.started)) ago"
    }

    private var lastActionText: String {
        guard let action = actions.first else { return "None in 90 days" }
        let name = action.command
            .replacingOccurrences(of: "_server", with: "")
            .replacingOccurrences(of: "_", with: " ")
        return name.prefix(1).uppercased() + name.dropFirst()
    }

    private var protectionText: String {
        switch (server.protection.delete, server.protection.rebuild) {
        case (true, true): "Delete and rebuild locked"
        case (true, false): "Delete locked"
        case (false, true): "Rebuild locked"
        case (false, false): "Off"
        }
    }

    private static func age(_ date: Date) -> String {
        let seconds = Date.now.timeIntervalSince(date)
        if seconds < 3_600 { return "\(max(1, Int(seconds / 60))) min" }
        if seconds < 86_400 { return "\(Int(seconds / 3_600)) h" }
        return "\(Int(seconds / 86_400)) d"
    }

    private func loadMetrics() async {
        if server.agentOnly {
            let since = Date.now.addingTimeInterval(-range.seconds)
            let history = hasAgent ? await monitor.agents.history(project.id, server.id, since: since) : nil
            let samples = (history?.samples ?? []).filter { $0.t >= since }
            memory = samples.map { MetricPoint(time: $0.t, value: $0.memory * 100) }
            metrics = history?.metrics(cores: server.serverType.cores) ?? ServerMetrics(start: since, end: .now, step: 0, series: [:])
            failed = false
            return
        }
        async let agentMemory: Void = loadMemory()
        do {
            let loaded = try await poller.history(server: server.id, range: range)
            metrics = loaded
            failed = false
        } catch is CancellationError {
        } catch {
            failed = true
            metrics = metrics ?? ServerMetrics(start: .now, end: .now, step: 0, series: [:])
        }
        await agentMemory
    }

    private static let chartIcons = ["CPU": "cpu", "Memory": "memorychip", "Disk IOPS": "internaldrive", "Network": "network"]

    private var alertMode: ServerAlertOverride.Mode {
        monitor.settings.override(project: project.id, server: server.id).mode
    }

    private var alertsText: String {
        switch alertMode {
        case .global: "Global rules"
        case .custom: "Custom"
        case .off: "Off"
        }
    }

    private var cpuThreshold: Double? {
        monitor.settings.value.alertSettings(for: project).rule(.sustainedCPU, server: server.id)?.threshold
    }

    private var ipv6: String? {
        guard let network = server.publicNet.ipv6?.ip else { return nil }
        return network.hasSuffix("::/64") ? network.replacingOccurrences(of: "::/64", with: "::1") : network
    }

    private var quickActions: some View {
        let ipv4 = server.publicNet.ipv4?.ip
        let address = server.agentOnly ? monitor.agents.link(project.id, server.id)?.endpoint.host : ipv4
        let user = project.sshUser.isEmpty ? "root" : project.sshUser
        return HStack(spacing: 8) {
            QuickAction(title: "SSH", icon: "terminal", help: address.map { "ssh \(user)@\($0)" } ?? "No address") {
                if let address, let url = URL(string: "ssh://\(user)@\(address.contains(":") ? "[\(address)]" : address)") {
                    NSWorkspace.shared.open(url)
                }
            }
            .disabled(address == nil)
            if server.agentOnly {
                QuickAction(title: copied == "Address" ? "Copied" : "Copy IP", icon: "doc.on.doc", help: address ?? "No address") {
                    copy(address, label: "Address")
                }
                .disabled(address == nil)
            } else {
                QuickAction(title: copied == "IPv4" ? "Copied" : "IPv4", icon: "doc.on.doc", help: ipv4 ?? "No public IPv4") {
                    copy(ipv4, label: "IPv4")
                }
                .disabled(ipv4 == nil)
                QuickAction(title: copied == "IPv6" ? "Copied" : "IPv6", icon: "doc.on.doc", help: ipv6 ?? "No public IPv6") {
                    copy(ipv6, label: "IPv6")
                }
                .disabled(ipv6 == nil)
            }
            QuickAction(title: "Alerts", icon: alertMode == .off ? "bell.slash" : "bell.badge", help: "Alert settings for this server") {
                monitor.settings.requestedPage = .project(project.id)
                app.showSettings()
            }
            ForEach(project.provider.serverLinks(server, project: project)) { link in
                QuickAction(title: link.title, icon: link.icon, help: link.help) {
                    NSWorkspace.shared.open(link.url)
                }
            }
        }
    }

    private var powerControls: some View {
        VStack(alignment: .leading, spacing: 8) {
            if let action = confirming {
                VStack(alignment: .leading, spacing: 4) {
                    Text("\(action.title) \(server.name)?").font(.system(size: 13, weight: .semibold))
                    Text(action.detail).font(.system(size: 11)).foregroundStyle(Theme.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                HStack {
                    Button("Cancel") { confirming = nil }
                        .keyboardShortcut(.cancelAction)
                    Spacer()
                    if powering { ProgressView().controlSize(.small) }
                    Button(action.title) { run(action) }
                        .buttonStyle(.borderedProminent)
                        .tint(action.isDestructive ? Theme.red : Color.accentColor)
                        .disabled(powering)
                }
            } else {
                let actions = PowerAction.available(for: server.status)
                if actions.isEmpty {
                    Label("\(server.status.rawValue.capitalized)…", systemImage: "hourglass")
                        .font(.system(size: 12))
                        .foregroundStyle(Theme.secondary)
                }
            }
            if let powerMessage {
                Text(powerMessage).font(.system(size: 11)).foregroundStyle(Theme.secondary)
            }
        }
        .padding(10)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Theme.card, in: RoundedRectangle(cornerRadius: 10))
    }

    private func run(_ action: PowerAction) {
        powering = true
        Task {
            do {
                try await monitor.power(action, server: server.id, project: project.id)
                powerMessage = "\(action.title) sent. The status updates in a few seconds."
            } catch let error as HetznerError {
                powerMessage = error.code.map { "\(project.provider.name) refused: \($0)." } ?? "Could not send \(action.title.lowercased())."
            } catch {
                powerMessage = "Could not reach \(project.provider.name)."
            }
            powering = false
            confirming = nil
        }
    }

    private func copy(_ text: String?, label: String) {
        guard let text else { return }
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(text, forType: .string)
        copied = label
        Task {
            try? await Task.sleep(for: .seconds(1.5))
            if copied == label { copied = nil }
        }
    }
}

private struct QuickAction: View {
    let title: String
    let icon: String
    let help: String
    let action: () -> Void

    @Environment(\.isEnabled) private var enabled

    var body: some View {
        Button(action: action) {
            VStack(spacing: 4) {
                Image(systemName: icon)
                    .font(.system(size: 15, weight: .medium))
                    .foregroundStyle(Color.accentColor)
                    .frame(height: 18)
                Text(title)
                    .font(.system(size: 11, weight: .medium))
                    .foregroundStyle(Theme.text)
            }
            .frame(maxWidth: .infinity, minHeight: 48)
            .background(Theme.card, in: RoundedRectangle(cornerRadius: 10))
            .opacity(enabled ? 1 : 0.4)
            .contentShape(RoundedRectangle(cornerRadius: 10))
        }
        .buttonStyle(.plain)
        .help(help)
    }
}

private struct FactLabelStyle: LabelStyle {
    func makeBody(configuration: Configuration) -> some View {
        HStack(spacing: 4) {
            configuration.icon.frame(width: 12)
            configuration.title
        }
    }
}

extension PowerAction {
    var icon: String {
        switch self {
        case .start: "play"
        case .shutdown: "stop"
        case .reboot: "arrow.clockwise"
        case .powerOff: "bolt.slash"
        case .reset: "exclamationmark.arrow.circlepath"
        }
    }
}
