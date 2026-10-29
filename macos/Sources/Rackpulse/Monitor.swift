import AppKit
import HetznerKit
import LocalAuthentication
import Observation

@MainActor
@Observable
final class Monitor {
    let store: ProjectStore
    let settings: SettingsStore
    let notifier = Notifier()
    let uptime = UptimeStore()
    let agents = AgentStore()
    let alertCenter: AlertCenter

    private(set) var pollers: [UUID: ProjectPoller] = [:]
    private(set) var pricing: Pricing?
    private(set) var locked = false

    private var pricingFetched: Date?
    private var agentBaselines: [UUID: (fetched: Date, values: [Int64: Double])] = [:]
    private var reloads: Set<UUID> = []
    private var loop: Task<Void, Never>?
    private var asleep = false
    private var observers: [NSObjectProtocol] = []

    init(store: ProjectStore, settings: SettingsStore) {
        self.store = store
        self.settings = settings
        let folder = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("Rackpulse", isDirectory: true)
        alertCenter = AlertCenter(database: LocalDatabase.open(at: folder.appendingPathComponent("rackpulse.sqlite")))
        let center = NSWorkspace.shared.notificationCenter
        observers.append(center.addObserver(forName: NSWorkspace.willSleepNotification, object: nil, queue: .main) { [weak self] _ in
            MainActor.assumeIsolated { self?.sleeping() }
        })
        observers.append(center.addObserver(forName: NSWorkspace.didWakeNotification, object: nil, queue: .main) { [weak self] _ in
            MainActor.assumeIsolated {
                self?.asleep = false
                self?.restart()
            }
        })
        notifier.onSnooze = { [weak self] project, alert in
            self?.pollers[project]?.snooze(alert)
            self?.alertCenter.snoozed(project: project, alert: alert)
        }
        notifier.setUp()
        projectChanged()
    }

    func poller(_ id: UUID) -> ProjectPoller? {
        pollers[id]
    }

    var isRefreshing: Bool {
        store.scope.contains { pollers[$0.id]?.isLoading == true }
    }

    var lastUpdated: Date? {
        store.scope.compactMap { pollers[$0.id]?.data.lastUpdated }.min()
    }

    var rateLimit: RateLimit? {
        store.scope.compactMap { pollers[$0.id]?.data.rateLimit }.max { $0.usedFraction < $1.usedFraction }
    }

    var allAlerts: [ProjectAlert] {
        store.projects
            .flatMap { project in (pollers[project.id]?.visibleAlerts ?? []).map { ProjectAlert(project: project, alert: $0) } }
            .sorted { ($0.alert.severity, $1.alert.since) > ($1.alert.severity, $0.alert.since) }
    }

    func snooze(_ item: ProjectAlert) {
        pollers[item.project.id]?.snooze(item.alert.id)
        alertCenter.snoozed(project: item.project.id, alert: item.alert.id)
    }

    func refreshNow() {
        for project in store.scope {
            guard let poller = pollers[project.id] else { continue }
            Task { await poll(project, poller) }
        }
    }

    func live(_ project: UUID, _ server: Int64) async {
        var first = true
        while !Task.isCancelled {
            if !asleep, pollers[project]?.data.servers.first(where: { $0.id == server })?.status == .running {
                await agents.refreshLive(project, server, history: first)
                first = false
            }
            try? await Task.sleep(for: .seconds(5))
        }
    }

    func refreshIfStale() {
        for project in store.scope {
            guard let poller = pollers[project.id] else { continue }
            if let last = poller.data.lastUpdated, Date.now.timeIntervalSince(last) < 15 { continue }
            Task { await poll(project, poller) }
        }
    }

    var problem: String? {
        let showsName = store.scope.count > 1
        for project in store.scope {
            let text = pollers[project.id] == nil && project.hasAPI
                ? "The token for this project is missing from the Keychain. Add the project again."
                : pollers[project.id]?.problem
            if let text { return showsName ? "\(project.name): \(text)" : text }
        }
        return nil
    }

    var fleetCPU: (busiest: Double, average: Double)? {
        let values = store.projects.flatMap { project -> [Double] in
            guard let data = pollers[project.id]?.data else { return [] }
            return data.servers.compactMap { server in
                data.metrics[server.id]?.cpuPercent(cores: server.serverType.cores).last?.value
            }
        }
        guard let busiest = values.max() else { return nil }
        return (busiest, values.reduce(0, +) / Double(values.count))
    }

    var readoutText: String {
        switch settings.value.readout {
        case .none:
            return ""
        case .cpu:
            return fleetCPU.map { Format.percent($0.busiest) } ?? ""
        case .cost:
            let currency = pricing?.currency ?? "EUR"
            return allProjectsCost.map { $0.monthToDate.formatted(.currency(code: currency).precision(.fractionLength(0))) } ?? ""
        case .alerts:
            let count = allAlerts.count
            return count > 0 ? "\(count)" : ""
        }
    }

    var menuDot: NSColor? {
        let active = pollers.values.filter { $0.data.lastUpdated != nil || $0.problem != nil }
        guard !active.isEmpty else { return nil }
        var worst = active.flatMap(\.visibleAlerts).map(\.severity).max()
        if active.contains(where: { $0.problem != nil }) { worst = max(worst ?? .warning, .warning) }
        return .status(worst)
    }

    var allProjectsCost: (monthToDate: Decimal, forecast: Decimal)? {
        let reports = store.projects.map { costReport(for: $0.id) }
        guard !reports.isEmpty, reports.allSatisfy({ $0 != nil }) else { return nil }
        return (reports.reduce(0) { $0 + ($1?.monthToDate ?? 0) }, reports.reduce(0) { $0 + ($1?.forecast ?? 0) })
    }

    func costReport(for id: UUID) -> CostReport? {
        guard settings.value.showsCosts, let poller = pollers[id], pricing != nil || !poller.hasAPI,
              poller.data.resourcesFetched != nil else { return nil }
        let data = poller.data
        return costEstimator(for: id).estimate(data.inventory, now: .now)
    }

    func costEstimator(for id: UUID) -> CostEstimator {
        CostEstimator(pricing: pricing, priceKind: settings.value.priceKind, serverPrices: settings.value.serverPrices(for: id))
    }

    func projectChanged() {
        let ids = Set(store.projects.map(\.id))
        pollers = pollers.filter { ids.contains($0.key) }
        alertCenter.forget(projects: ids)
        for project in store.projects where !project.hasAPI && pollers[project.id] == nil {
            pollers[project.id] = ProjectPoller(agentProject: project.id)
            alertCenter.reloaded(project.id)
        }
        for project in store.projects where project.hasAPI && (pollers[project.id]?.access != project.access || reloads.contains(project.id)) {
            if let token = store.token(for: project) {
                pollers[project.id] = ProjectPoller(projectID: project.id, token: token, access: project.access)
                alertCenter.reloaded(project.id)
            }
        }
        reloads = []
        if !store.projects.isEmpty { notifier.requestAuthorization() }
        restart()
    }

    func reload(_ id: UUID) {
        reloads.insert(id)
        projectChanged()
    }

    func power(_ action: PowerAction, server id: Int64, project: UUID) async throws {
        guard let poller = pollers[project] else { throw HetznerError.invalidResponse }
        try await poller.power(action, server: id)
        Task { [weak self] in
            for delay in [3.0, 10.0, 25.0] {
                try? await Task.sleep(for: .seconds(delay))
                self?.restart()
            }
        }
    }

    func settingsChanged() {
        restart()
    }

    func unlock() async {
        let context = LAContext()
        var error: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error) else {
            locked = false
            return
        }
        if (try? await context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: "unlock Rackpulse")) == true {
            locked = false
        }
    }

    private func sleeping() {
        asleep = true
        if settings.value.lockWithTouchID { locked = true }
    }

    private func restart() {
        loop?.cancel()
        guard !pollers.isEmpty else { return }
        loop = Task { [weak self] in
            while !Task.isCancelled {
                guard let self else { return }
                if !self.asleep { await self.pollAll() }
                try? await Task.sleep(for: .seconds(self.settings.value.pollInterval))
            }
        }
    }

    private func pollAll() async {
        let now = Date.now
        if pricingFetched.map({ now.timeIntervalSince($0) > 86_400 }) ?? true,
           let pricing = await pollers.values.first(where: \.hasAPI)?.pricing() {
            self.pricing = pricing
            pricingFetched = now
        }
        var tasks: [Task<Void, Never>] = []
        for project in store.projects {
            guard let poller = pollers[project.id] else { continue }
            tasks.append(Task { @MainActor in await self.poll(project, poller, now: now, deliver: false) })
        }
        for task in tasks { await task.value }
        await deliverAlerts()
    }

    private func deliverAlerts() async {
        let delivery = await alertCenter.flush(settings.value.alerts)
        notifier.remove(delivery.remove)
        for notification in delivery.post { notifier.post(notification) }
    }

    private func poll(_ project: Project, _ poller: ProjectPoller, now: Date = .now, deliver: Bool = true) async {
        if let state = await alertCenter.restore(project.id) { poller.restore(state) }
        let serversKnown = !poller.data.servers.isEmpty
        let reports = await agents.poll(project.id, servers: poller.hasAPI ? poller.data.servers : hosts(project.id))
        if !poller.hasAPI { learnHosts(project.id) }
        let context = PollContext(
            now: now, pricing: settings.value.showsCosts ? pricing : nil, priceKind: settings.value.priceKind,
            serverPrices: settings.value.serverPrices(for: project.id),
            alertSettings: settings.value.alertSettings(for: project), agents: reports
        )
        let agentServers = poller.hasAPI ? [] : hosts(project.id)
        let activity = poller.hasAPI ? (metrics: [:], baseline: [:]) : await agentActivity(project.id, agentServers)
        let events = await poller.refresh(context, hosts: agentServers, activity: activity.metrics, baseline: activity.baseline)
        if poller.hasAPI, !serversKnown, !poller.data.servers.isEmpty {
            _ = await agents.poll(project.id, servers: poller.data.servers)
        }
        await alertCenter.collect(project: project, poller: poller, events: events, context: context) { serverID in
            subtitle(project, poller, serverID)
        }
        if poller.problem == nil {
            var data = poller.data
            if !poller.hasAPI { data.servers = data.servers.filter { agents.link(project.id, $0.id)?.isPaired == true } }
            uptime.record(data, at: .now)
        }
        if project.environment != .none, poller.problem == nil, poller.data.lastUpdated != nil {
            settings.adoptLegacyEnvironment(project.environment, project: project.id, servers: poller.data.servers)
            store.update(project.id) { $0.environment = .none }
        }
        if deliver { await deliverAlerts() }
    }

    private func hosts(_ id: UUID) -> [Server] {
        (store.project(id)?.hosts ?? []).map { $0.server(link: agents.link(id, $0.id)) }
    }

    private func agentActivity(_ project: UUID, _ servers: [Server]) async -> (metrics: [Int64: ServerMetrics], baseline: [Int64: Double]) {
        let now = Date.now
        let answering = servers.filter { agents.state(project, $0.id).map { $0.snapshot != nil && $0.problem == nil } ?? false }
        var metrics: [Int64: ServerMetrics] = [:]
        for server in answering {
            if let value = await agents.history(project, server.id, since: now.addingTimeInterval(-3_600))?.metrics(cores: server.serverType.cores) {
                metrics[server.id] = value
            }
        }
        if let saved = agentBaselines[project], now.timeIntervalSince(saved.fetched) < 3_600 {
            return (metrics, saved.values)
        }
        var baseline: [Int64: Double] = [:]
        for server in answering where metrics[server.id] != nil {
            let week = await agents.history(project, server.id, since: now.addingTimeInterval(-7 * 86_400))?.metrics(cores: server.serverType.cores)
            let values = (week?.totalIOPS ?? []).map(\.value).sorted()
            if !values.isEmpty { baseline[server.id] = values[values.count / 2] }
        }
        agentBaselines[project] = (now, baseline)
        return (metrics, baseline)
    }

    private func learnHosts(_ id: UUID) {
        guard let project = store.project(id) else { return }
        for host in project.hosts {
            guard let snapshot = agents.state(id, host.id)?.snapshot else { continue }
            var next = host
            next.learn(snapshot)
            if next != host { store.updateHost(id, host.id) { $0 = next } }
        }
    }

    func refreshHosts(_ id: UUID, poll shouldPoll: Bool = true) {
        guard let poller = pollers[id], !poller.hasAPI, let project = store.project(id) else { return }
        poller.setHosts(hosts(id))
        if shouldPoll { Task { await poll(project, poller) } }
    }

    func addHost(to id: UUID) -> Int64? {
        guard let host = store.addHost(to: id) else { return nil }
        refreshHosts(id)
        return host
    }

    func removeHost(_ id: UUID, _ host: Int64) {
        agents.remove(id, host)
        store.removeHost(id, host)
        refreshHosts(id)
    }

    func removeProject(_ project: Project) {
        for host in project.hosts { agents.remove(project.id, host.id) }
        store.remove(project)
        projectChanged()
    }

    private func subtitle(_ project: Project, _ poller: ProjectPoller, _ serverID: Int64?) -> String {
        guard let serverID, let server = poller.data.servers.first(where: { $0.id == serverID }) else { return project.name }
        return settings.environment(project: project.id, server: server).badge.map { "\(project.name) · \($0)" } ?? project.name
    }
}

struct ProjectAlert: Identifiable {
    let project: Project
    let alert: FiringAlert

    var id: String { "\(project.id.uuidString)|\(alert.id)" }

    var serverID: Int64? {
        guard ServerAlertOverride.kinds.contains(alert.kind) else { return nil }
        return alert.id.split(separator: ":").last.flatMap { Int64($0) }
    }
}
