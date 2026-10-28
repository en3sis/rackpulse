import HetznerKit
import ServiceManagement
import SwiftUI

enum SettingsPage: Hashable {
    case general
    case alerts
    case about
    case project(UUID)
}

struct SettingsView: View {
    let store: ProjectStore
    let monitor: Monitor
    let settings: SettingsStore
    let updates: Updates

    @State private var page: SettingsPage? = .general
    @State private var adding = false
    @State private var removing: Project?

    private var selectedProject: Project? {
        if case .project(let id) = page { return store.project(id) }
        return nil
    }

    private var title: String {
        switch page {
        case .general: "General"
        case .alerts: "Alerts"
        case .about: "About"
        case .project: selectedProject?.name ?? "Settings"
        case nil: "Settings"
        }
    }

    var body: some View {
        NavigationSplitView {
            List(selection: $page) {
                Label("General", systemImage: "gearshape").tag(SettingsPage.general)
                Label("Alerts", systemImage: "bell.badge").tag(SettingsPage.alerts)
                Label("About", systemImage: "info.circle").tag(SettingsPage.about)
                Section("Projects") {
                    ForEach(store.projects) { project in
                        HStack(spacing: 8) {
                            Image(systemName: project.icon)
                                .fontWeight(.semibold)
                                .foregroundStyle(project.color.color)
                                .frame(width: 18)
                            Text(project.name).lineLimit(1)
                        }
                        .tag(SettingsPage.project(project.id))
                    }
                }
            }
            .listStyle(.sidebar)
            .safeAreaInset(edge: .bottom) {
                HStack(spacing: 2) {
                    Button { adding = true } label: { Image(systemName: "plus").frame(width: 20, height: 20) }
                        .help("Add a project")
                    Button { removing = selectedProject } label: { Image(systemName: "minus").frame(width: 20, height: 20) }
                        .disabled(selectedProject == nil)
                        .help("Remove the selected project")
                    Spacer()
                }
                .buttonStyle(.borderless)
                .padding(8)
            }
            .navigationSplitViewColumnWidth(min: 200, ideal: 220, max: 280)
        } detail: {
            switch page {
            case .general:
                GeneralPage(monitor: monitor, settings: settings)
            case .alerts:
                AlertsPage(monitor: monitor, settings: settings)
            case .about:
                AboutPage(updates: updates)
            case .project(let id):
                if let project = store.project(id) {
                    ProjectForm(store: store, settings: settings, project: project,
                                servers: monitor.pollers[project.id]?.data.servers ?? [],
                                reload: { monitor.reload(project.id) }) { removing = project }
                        .id(project.id)
                } else {
                    ContentUnavailableView("No Project Selected", systemImage: "server.rack")
                }
            case nil:
                ContentUnavailableView("Nothing Selected", systemImage: "gearshape")
            }
        }
        .navigationTitle(title)
        .frame(minWidth: 680, minHeight: 500)
        .onAppear(perform: showRequestedPage)
        .onChange(of: settings.requestedPage) { showRequestedPage() }
        .sheet(isPresented: $adding) {
            OnboardingView(store: store, canCancel: true) { added in
                adding = false
                if added {
                    monitor.projectChanged()
                    page = store.selectedID.map(SettingsPage.project)
                }
            }
            .frame(width: 400)
        }
        .confirmationDialog(
            "Remove \(removing?.name ?? "project")?",
            isPresented: Binding(get: { removing != nil }, set: { if !$0 { removing = nil } }),
            presenting: removing
        ) { project in
            Button("Remove", role: .destructive) {
                store.remove(project)
                monitor.projectChanged()
                page = .general
            }
        } message: { _ in
            Text("Rackpulse stops watching this project and deletes its token from your Keychain. The project on Hetzner is not changed.")
        }
    }
}

extension SettingsView {
    fileprivate func showRequestedPage() {
        guard let requested = settings.requestedPage else { return }
        page = requested
        settings.requestedPage = nil
    }
}

private struct GeneralPage: View {
    let monitor: Monitor
    let settings: SettingsStore

    @State private var launchAtLogin = SMAppService.mainApp.status == .enabled
    @Environment(AppActions.self) private var app

    var body: some View {
        Form {
            Section {
                Picker("Check every", selection: Binding(
                    get: { settings.value.pollInterval },
                    set: { settings.value.pollInterval = $0; monitor.settingsChanged() }
                )) {
                    ForEach(AppSettings.intervals, id: \.self) { Text(label($0)).tag($0) }
                }
            } header: {
                Text("Polling")
            } footer: {
                Text(budgetText).foregroundStyle(.secondary)
            }

            Section {
                Picker("Show next to the icon", selection: Binding(
                    get: { settings.value.readout },
                    set: { settings.value.readout = $0 }
                )) {
                    ForEach(MenuBarReadout.allCases.filter { settings.value.showsCosts || $0 != .cost }) { Text($0.title).tag($0) }
                }
            } header: {
                Text("Menu bar")
            } footer: {
                Text("The status dot always shows the worst alert across all projects.")
                    .foregroundStyle(.secondary)
            }

            Section {
                Picker("Default chart range", selection: Binding(
                    get: { settings.value.chartRange },
                    set: { settings.value.chartRange = $0 }
                )) {
                    ForEach(MetricRange.allCases) { Text($0.rawValue).tag($0) }
                }
            } header: {
                Text("Charts")
            } footer: {
                Text("Server pages open on this range. A range you pick on a server page applies to every server until you quit Rackpulse.")
                    .foregroundStyle(.secondary)
            }

            Section {
                Picker("Open the panel with", selection: Binding(
                    get: { settings.value.shortcut },
                    set: { settings.value.shortcut = $0; app.shortcutChanged() }
                )) {
                    ForEach(PanelShortcut.allCases) { Text($0.title).tag($0) }
                }
            } header: {
                Text("Keyboard")
            } footer: {
                Text("Works from any app. With the panel open, type to find a server.")
                    .foregroundStyle(.secondary)
            }

            Section("Startup") {
                Toggle("Open Rackpulse at login", isOn: Binding(
                    get: { launchAtLogin },
                    set: { value in
                        do {
                            if value { try SMAppService.mainApp.register() } else { try SMAppService.mainApp.unregister() }
                        } catch {}
                        launchAtLogin = SMAppService.mainApp.status == .enabled
                    }
                ))
            }

            Section {
                Toggle("Show cost estimates", isOn: Binding(
                    get: { settings.value.showsCosts },
                    set: { value in
                        settings.value.showsCosts = value
                        if !value && settings.value.readout == .cost { settings.value.readout = .none }
                    }
                ))
                Picker("Prices", selection: Binding(
                    get: { settings.value.priceKind },
                    set: { settings.value.priceKind = $0 }
                )) {
                    Text("Without VAT").tag(PriceKind.net)
                    Text("With VAT").tag(PriceKind.gross)
                }
                .disabled(!settings.value.showsCosts)
            } header: {
                Text("Costs")
            } footer: {
                Text("When off, Rackpulse hides the Costs tab and all cost amounts, and stops budget alerts.")
                    .foregroundStyle(.secondary)
            }

            Section {
                Toggle("Require Touch ID after sleep", isOn: Binding(
                    get: { settings.value.lockWithTouchID },
                    set: { settings.value.lockWithTouchID = $0 }
                ))
            } header: {
                Text("Security")
            } footer: {
                Text("When on, the panel stays locked after your Mac wakes until you unlock it with Touch ID or your password.")
                    .foregroundStyle(.secondary)
            }

            Section {
                Button("Open Notification Settings") {
                    NSWorkspace.shared.open(URL(string: "x-apple.systempreferences:com.apple.Notifications-Settings.extension")!)
                }
            } header: {
                Text("Notifications")
            } footer: {
                Text("Alerts set to Notification appear in Notification Center. Allow notifications for Rackpulse there.")
                    .foregroundStyle(.secondary)
            }
        }
        .formStyle(.grouped)
    }

    private func label(_ interval: TimeInterval) -> String {
        interval < 60 ? "\(Int(interval)) seconds" : interval == 60 ? "1 minute" : "\(Int(interval / 60)) minutes"
    }

    private var budgetText: String {
        let servers = monitor.pollers.values.map(\.data.servers.count).max() ?? 0
        let perHour = Int(3600 / settings.value.pollInterval) * (1 + servers) + 12 * 8
        return "Each poll costs one request plus one per running server. With \(servers) server\(servers == 1 ? "" : "s"), that is about \(perHour) of the 3,600 requests per hour each project's token allows. Volumes, IPs and firewalls refresh every 5 minutes."
    }
}

private struct AlertsPage: View {
    let monitor: Monitor
    let settings: SettingsStore

    @State private var previewKind = RuleKind.sustainedCPU

    var body: some View {
        Form {
            Section {
                Text("These rules apply to every server. To give one server its own thresholds or mute it, open its project page here, or use the Alerts button on the server's page.")
                    .foregroundStyle(.secondary)
            }
            ForEach(RuleKind.allCases.filter { $0 != .storageBox && !$0.needsAgent && (settings.value.showsCosts || $0 != .budget) }, id: \.self) { kind in
                Section {
                    RuleEditor(kind: kind, rule: ruleBinding(kind))
                }
            }
            ForEach(RuleKind.agentKinds, id: \.self) { kind in
                Section {
                    RuleEditor(kind: kind, rule: ruleBinding(kind))
                } header: {
                    if kind == RuleKind.agentKinds.first { Text("Rackpulse agent") }
                } footer: {
                    if kind == RuleKind.agentKinds.last {
                        Text("These rules use data from the Rackpulse agent. Servers without the agent are not checked.")
                            .foregroundStyle(.secondary)
                    }
                }
            }

            Section {
                HStack {
                    Picker("Preview", selection: $previewKind) {
                        ForEach(RuleKind.allCases.filter { $0 != .storageBox }, id: \.self) { Text($0.title).tag($0) }
                    }
                    Button("Send Notification") {
                        monitor.notifier.preview(previewKind, project: monitor.store.scope.first ?? Project(name: "Production"))
                    }
                }
            } header: {
                Text("Test")
            } footer: {
                Text("Sends a sample notification with made-up names, including the Snooze and Open buttons. If nothing appears, allow notifications for Rackpulse in System Settings.")
                    .foregroundStyle(.secondary)
            }

            Section {
                Toggle("Quiet hours", isOn: Binding(
                    get: { settings.value.alerts.quietHours != nil },
                    set: { settings.value.alerts.quietHours = $0 ? QuietHours(startMinute: 23 * 60, endMinute: 7 * 60) : nil }
                ))
                if settings.value.alerts.quietHours != nil {
                    DatePicker("From", selection: minuteBinding(\.startMinute), displayedComponents: .hourAndMinute)
                    DatePicker("To", selection: minuteBinding(\.endMinute), displayedComponents: .hourAndMinute)
                }
            } footer: {
                Text("During quiet hours alerts still show in the popover and the menu bar. Notifications wait and arrive as one summary when quiet hours end.")
                    .foregroundStyle(.secondary)
            }

            Section {
                DatePicker("Send at", selection: summaryBinding, displayedComponents: .hourAndMinute)
            } header: {
                Text("Daily summary")
            } footer: {
                Text("Rules set to Daily summary send one notification a day with everything new since the last one.")
                    .foregroundStyle(.secondary)
            }
        }
        .formStyle(.grouped)
    }

    private var summaryBinding: Binding<Date> {
        Binding(
            get: {
                Calendar.current.startOfDay(for: .now).addingTimeInterval(TimeInterval(settings.value.alerts.dailySummaryMinute * 60))
            },
            set: { date in
                let parts = Calendar.current.dateComponents([.hour, .minute], from: date)
                settings.value.alerts.dailySummaryMinute = (parts.hour ?? 0) * 60 + (parts.minute ?? 0)
            }
        )
    }

    private func ruleBinding(_ kind: RuleKind) -> Binding<RuleConfig> {
        Binding(
            get: { settings.rule(kind) },
            set: { value in settings.update(kind) { $0 = value } }
        )
    }

    private func minuteBinding(_ path: WritableKeyPath<QuietHours, Int>) -> Binding<Date> {
        Binding(
            get: {
                let minute = settings.value.alerts.quietHours?[keyPath: path] ?? 0
                return Calendar.current.startOfDay(for: .now).addingTimeInterval(TimeInterval(minute * 60))
            },
            set: { date in
                let parts = Calendar.current.dateComponents([.hour, .minute], from: date)
                settings.value.alerts.quietHours?[keyPath: path] = (parts.hour ?? 0) * 60 + (parts.minute ?? 0)
            }
        )
    }
}

struct RuleEditor: View {
    let kind: RuleKind
    @Binding var rule: RuleConfig
    var compact = false

    private static let durations: [TimeInterval] = [300, 600, 900, 1800]

    var body: some View {
        Toggle(isOn: $rule.enabled) {
            if compact {
                Text(kind.title)
            } else {
                VStack(alignment: .leading, spacing: 2) {
                    Text(kind.title)
                    Text(kind.summary).font(.caption).foregroundStyle(.secondary)
                }
            }
        }
        if rule.enabled {
            controls
            Picker("Deliver as", selection: $rule.delivery) {
                Text("Notification").tag(Delivery.push)
                Text("Daily summary").tag(Delivery.digest)
                Text("Popover only").tag(Delivery.banner)
            }
        }
    }

    @ViewBuilder
    private var controls: some View {
        switch kind {
        case .serverDown:
            Stepper("After \(Int(rule.threshold)) poll\(rule.threshold == 1 ? "" : "s")", value: $rule.threshold, in: 1...5)
        case .sustainedCPU:
            Stepper("Above \(Int(rule.threshold))%", value: $rule.threshold, in: 10...100, step: 5)
            durationPicker
        case .storageBox:
            Stepper("Above \(Int((rule.threshold * 100).rounded()))% used", value: $rule.threshold, in: 0.5...0.99, step: 0.01)
            Stepper("Or full within \(Int(rule.secondaryThreshold ?? 14)) days",
                    value: Binding(get: { rule.secondaryThreshold ?? 14 }, set: { rule.secondaryThreshold = $0 }),
                    in: 3...60)
        case .trafficQuota:
            Stepper("Above \(Int((rule.threshold * 100).rounded()))% of included traffic", value: $rule.threshold, in: 0.5...1, step: 0.05)
        case .diskIO:
            Stepper("Above \(Int(rule.threshold))× the 7-day median", value: $rule.threshold, in: 2...10)
            durationPicker
        case .budget:
            Text("Set the budget on each project's page.").foregroundStyle(.secondary)
        case .unexpectedChange, .failedService, .rebootRequired:
            EmptyView()
        case .diskSpace:
            Stepper("Above \(Int((rule.threshold * 100).rounded()))% used", value: $rule.threshold, in: 0.5...0.99, step: 0.01)
        case .memory:
            Stepper("Above \(Int((rule.threshold * 100).rounded()))% used", value: $rule.threshold, in: 0.5...0.99, step: 0.01)
            durationPicker
        case .container:
            Stepper("Restart loop after \(Int(rule.threshold)) restarts in an hour", value: $rule.threshold, in: 1...20)
        case .agentUnreachable:
            Stepper("After \(Int(rule.threshold)) poll\(rule.threshold == 1 ? "" : "s")", value: $rule.threshold, in: 1...10)
        }
    }

    private var durationPicker: some View {
        Picker("For at least", selection: $rule.duration) {
            ForEach(Self.durations, id: \.self) { Text("\(Int($0 / 60)) minutes").tag($0) }
        }
    }
}

private struct ServerEnvironmentsSection: View {
    let project: Project
    let servers: [Server]
    let settings: SettingsStore

    var body: some View {
        Section {
            if servers.isEmpty {
                Text("Servers appear here after the first poll.").foregroundStyle(.secondary)
            }
            ForEach(servers) { server in
                EnvironmentPicker(settings: settings, project: project.id, server: server) {
                    Label(server.name, systemImage: "server.rack")
                }
            }
        } header: {
            Text("Server environments")
        } footer: {
            Text("Automatic uses the server's env or environment label in Hetzner, for example env=prod. Production servers show a PROD tag in the list.")
                .foregroundStyle(.secondary)
        }
    }
}

private struct ServerPriceRow: View {
    let project: Project
    let server: Server
    let settings: SettingsStore

    var body: some View {
        let price = settings.price(project: project.id, server: server.id)
        LabeledContent {
            HStack(spacing: 6) {
                TextField("Monthly price", value: Binding(
                    get: { price },
                    set: { settings.setPrice($0, project: project.id, server: server.id) }
                ), format: .number.precision(.fractionLength(0...2)), prompt: Text(listPrice))
                .labelsHidden()
                .multilineTextAlignment(.trailing)
                .frame(width: 80)
                Text("a month").foregroundStyle(.secondary)
                Button {
                    settings.setPrice(nil, project: project.id, server: server.id)
                } label: {
                    Image(systemName: "xmark.circle.fill").foregroundStyle(.secondary)
                }
                .buttonStyle(.borderless)
                .help("Use the list price")
                .opacity(price == nil ? 0 : 1)
                .disabled(price == nil)
            }
        } label: {
            Label(server.name, systemImage: "server.rack")
        }
    }

    private var listPrice: String {
        guard let price = server.serverType.prices.price(at: server.location.name)?.priceMonthly.net else { return "List price" }
        return price.formatted(.number.precision(.fractionLength(2)))
    }
}

private struct ServerAlertsSection: View {
    let project: Project
    let servers: [Server]
    let settings: SettingsStore

    var body: some View {
        Section {
            if servers.isEmpty {
                Text("Servers appear here after the first poll.").foregroundStyle(.secondary)
            }
            ForEach(servers) { server in
                let override = settings.override(project: project.id, server: server.id)
                Picker(selection: Binding(
                    get: { override.mode },
                    set: { mode in
                        var next = override
                        next.mode = mode
                        if mode == .custom && next.rules.isEmpty {
                            next.rules = ServerAlertOverride.kinds.map { settings.rule($0) }
                        }
                        settings.setOverride(next, project: project.id, server: server.id)
                    }
                )) {
                    Text("Global rules").tag(ServerAlertOverride.Mode.global)
                    Text("Custom").tag(ServerAlertOverride.Mode.custom)
                    Text("Off").tag(ServerAlertOverride.Mode.off)
                } label: {
                    Label(server.name, systemImage: "server.rack")
                }
                if override.mode == .custom {
                    ForEach(ServerAlertOverride.kinds, id: \.self) { kind in
                        RuleEditor(kind: kind, rule: ruleBinding(kind, server: server.id), compact: true)
                            .padding(.leading, 20)
                    }
                }
            }
        } header: {
            Text("Server alerts")
        } footer: {
            Text("Global rules come from the Alerts page. Custom gives this server its own thresholds. Off mutes alerts for this server.")
                .foregroundStyle(.secondary)
        }
    }

    private func ruleBinding(_ kind: RuleKind, server: Int64) -> Binding<RuleConfig> {
        Binding(
            get: { settings.override(project: project.id, server: server).rules.first { $0.kind == kind } ?? settings.rule(kind) },
            set: { value in
                var next = settings.override(project: project.id, server: server)
                next.rules.removeAll { $0.kind == kind }
                next.rules.append(value)
                settings.setOverride(next, project: project.id, server: server)
            }
        )
    }
}

private struct ProjectForm: View {
    let store: ProjectStore
    let settings: SettingsStore
    let project: Project
    let servers: [Server]
    let remove: () -> Void

    @State private var name: String
    @State private var replacing = false
    let reload: () -> Void

    init(store: ProjectStore, settings: SettingsStore, project: Project, servers: [Server], reload: @escaping () -> Void, remove: @escaping () -> Void) {
        self.reload = reload
        self.store = store
        self.settings = settings
        self.project = project
        self.servers = servers
        self.remove = remove
        _name = State(initialValue: project.name)
    }

    var body: some View {
        Form {
            Section {
                TextField("Name", text: $name)
                    .onSubmit(saveName)
                    .onChange(of: name) { saveName() }
                LabeledContent("Color") {
                    HStack(spacing: 6) {
                        ForEach(ProjectColor.allCases) { option in
                            Button {
                                store.update(project.id) { $0.color = option }
                            } label: {
                                Circle()
                                    .fill(option.color)
                                    .frame(width: 18, height: 18)
                                    .overlay {
                                        if option == project.color {
                                            Circle().strokeBorder(Color(nsColor: .windowBackgroundColor), lineWidth: 2)
                                            Circle().strokeBorder(option.color, lineWidth: 1).padding(-2)
                                        }
                                    }
                            }
                            .buttonStyle(.plain)
                            .accessibilityLabel(option.title)
                            .help(option.title)
                        }
                    }
                }
                LabeledContent("Icon") {
                    LazyVGrid(columns: Array(repeating: GridItem(.fixed(28), spacing: 6), count: 9), spacing: 6) {
                        ForEach(Project.icons, id: \.self) { icon in
                            Button {
                                store.update(project.id) { $0.icon = icon }
                            } label: {
                                Image(systemName: icon)
                                    .font(.system(size: 14, weight: .semibold))
                                    .frame(width: 28, height: 28)
                                    .foregroundStyle(icon == project.icon ? Color.white : Color.primary)
                                    .background(
                                        icon == project.icon ? project.color.color : Color(nsColor: .quaternarySystemFill),
                                        in: RoundedRectangle(cornerRadius: 6)
                                    )
                            }
                            .buttonStyle(.plain)
                            .accessibilityLabel(icon)
                        }
                    }
                }
            } header: {
                HStack(spacing: 8) {
                    Image(systemName: project.icon).fontWeight(.semibold).foregroundStyle(project.color.color)
                    Text(project.name)
                }
                .font(.headline)
            }

            Section {
                if settings.value.showsCosts {
                    TextField("Monthly budget", value: Binding(
                        get: { project.budget },
                        set: { value in store.update(project.id) { $0.budget = value.flatMap { $0 > 0 ? $0 : nil } } }
                    ), format: .number.precision(.fractionLength(0...2)), prompt: Text("None"))
                    ForEach(servers) { server in
                        ServerPriceRow(project: project, server: server, settings: settings)
                    }
                } else {
                    Text("Cost estimates are off. Turn them on in General.").foregroundStyle(.secondary)
                }
            } header: {
                Text("Costs")
            } footer: {
                if settings.value.showsCosts {
                    Text("Rackpulse shows the budget on the Costs tab and alerts you when the month's forecast goes above it. For a server on an older price, enter the monthly price you pay. Leave it empty to use the list price, shown in grey. Amounts are in the currency of your Hetzner prices, without VAT.")
                        .foregroundStyle(.secondary)
                }
            }

            ServerEnvironmentsSection(project: project, servers: servers, settings: settings)

            ServerAlertsSection(project: project, servers: servers, settings: settings)

            Section {
                TextField("Console link", text: Binding(
                    get: { project.consoleID.map { "https://console.hetzner.com/projects/\($0)" } ?? "" },
                    set: { value in store.update(project.id) { $0.consoleID = Project.consoleID(from: value) } }
                ), prompt: Text("Paste any Console address from this project"))
                TextField("SSH user", text: Binding(
                    get: { project.sshUser },
                    set: { value in store.update(project.id) { $0.sshUser = value.trimmingCharacters(in: .whitespaces) } }
                ), prompt: Text("root"))
            } header: {
                Text("Quick access")
            } footer: {
                Text("The Console link lets the Console button open each server directly; the API doesn't share the project's Console number. The SSH button opens Terminal with ssh user@address.")
                    .foregroundStyle(.secondary)
            }

            Section {
                LabeledContent("Access", value: project.access.title)
                LabeledContent("Added", value: project.addedAt.formatted(date: .abbreviated, time: .omitted))
                LabeledContent("Stored in", value: "Keychain")
                Button("Replace Token…") { replacing = true }
            } header: {
                Text("Token")
            } footer: {
                Text(project.access == .readOnly
                     ? "Read only: Rackpulse shows status, metrics, costs and alerts. To start, stop or reboot servers from Rackpulse, replace it with a Read & Write token."
                     : "Read & write: Rackpulse can also start, shut down, reboot and power off servers. Each action asks you to confirm. Replace it with a Read token to turn controls off.")
                    .foregroundStyle(.secondary)
            }

            Section {
                Button(role: .destructive, action: remove) {
                    Text("Remove Project…").foregroundStyle(Theme.red)
                }
            } header: {
                Text("Remove project")
            } footer: {
                Text("Rackpulse stops watching this project and deletes its token from your Keychain. The project on Hetzner is not changed.")
                    .foregroundStyle(.secondary)
            }
        }
        .formStyle(.grouped)
        .sheet(isPresented: $replacing) {
            ReplaceTokenView(project: project) { token, access in
                try store.replaceToken(project.id, token: token, access: access)
                reload()
            }
            .frame(width: 400)
        }
    }

    private func saveName() {
        let trimmed = name.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty, trimmed != project.name else { return }
        store.update(project.id) { $0.name = trimmed }
    }
}

private struct ReplaceTokenView: View {
    let project: Project
    let save: (String, TokenAccess) throws -> Void

    @Environment(\.dismiss) private var dismiss
    @State private var token = ""
    @State private var checking = false
    @State private var message: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Replace the token for \(project.name)")
                .font(.headline)
            AccessComparison()
            SecureField("Paste the new token", text: $token)
                .textFieldStyle(.roundedBorder)
            if let message {
                Text(message).font(.callout).foregroundStyle(Theme.red)
            }
            HStack {
                Button("Cancel") { dismiss() }
                    .keyboardShortcut(.cancelAction)
                Spacer()
                if checking { ProgressView().controlSize(.small) }
                Button(checking ? "Checking token…" : "Verify and Save", action: verify)
                    .buttonStyle(.borderedProminent)
                    .disabled(checking || token.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                    .keyboardShortcut(.defaultAction)
            }
        }
        .padding(20)
    }

    private func verify() {
        let value = token.trimmingCharacters(in: .whitespacesAndNewlines)
        checking = true
        message = nil
        Task {
            let check = await TokenVerifier(client: HetznerClient(api: .cloud, token: value)).verify()
            checking = false
            guard let access = check.access else {
                message = check.explanation
                return
            }
            do {
                try save(value, access)
                dismiss()
            } catch {
                message = "The token could not be saved to the Keychain."
            }
        }
    }
}
