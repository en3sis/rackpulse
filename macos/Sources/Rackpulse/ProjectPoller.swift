import Foundation
import HetznerKit
import Observation
import SwiftUI

struct ProjectData {
    var servers: [Server] = []
    var metrics: [Int64: ServerMetrics] = [:]
    var lastUpdated: Date?
    var rateLimit: RateLimit?
    var alerts = AlertState()
    var actions: [ServerAction] = []
    var actionsFetched: Date?
    var volumes: [Volume] = []
    var detachedSince: [Int64: Date] = [:]
    var primaryIPs: [PrimaryIP] = []
    var floatingIPs: [FloatingIP] = []
    var loadBalancers: [LoadBalancer] = []
    var resourcesFetched: Date?
    var firewalls: [Firewall] = []
    var firewallNames: [Int64: String]?
    var iopsBaseline: [Int64: Double] = [:]
    var baselineFetched: Date?

    var inventory: Inventory {
        Inventory(
            servers: servers, volumes: volumes, primaryIPs: primaryIPs,
            floatingIPs: floatingIPs, loadBalancers: loadBalancers
        )
    }
}

struct PollContext {
    let now: Date
    let pricing: Pricing?
    let priceKind: PriceKind
    let serverPrices: [Int64: Decimal]
    let alertSettings: AlertSettings
    var agents: [Int64: AgentReport] = [:]
}

@MainActor
@Observable
final class ProjectPoller {
    let projectID: UUID
    private(set) var data = ProjectData()
    private(set) var problem: String?

    let access: TokenAccess
    private let client: HetznerClient?
    private let controlClient: HetznerClient?
    private(set) var isLoading = false

    private static let slowInterval: TimeInterval = 300
    private static let baselineInterval: TimeInterval = 3_600

    init(projectID: UUID, token: String, access: TokenAccess) {
        self.projectID = projectID
        self.access = access
        client = HetznerClient(api: .cloud, token: token)
        controlClient = access == .readWrite ? HetznerClient(api: .cloud, token: token, access: .readWrite) : nil
    }

    init(agentProject projectID: UUID) {
        self.projectID = projectID
        access = .readOnly
        client = nil
        controlClient = nil
    }

    var hasAPI: Bool { client != nil }

    func setHosts(_ servers: [Server]) {
        guard client == nil else { return }
        data.servers = servers.sorted { $0.name.localizedStandardCompare($1.name) == .orderedAscending }
        if data.lastUpdated == nil { data.lastUpdated = .now }
    }

    func power(_ action: PowerAction, server id: Int64) async throws {
        guard let controlClient else { throw HetznerError.writeNotAllowed(action.path(server: id)) }
        try await controlClient.power(action, server: id)
    }

    var visibleAlerts: [FiringAlert] {
        data.alerts.firing.filter { !data.alerts.isSnoozed($0.id, at: .now) }
    }

    func snooze(_ id: String) {
        data.alerts.snooze(id, until: .now.addingTimeInterval(24 * 3600))
    }

    func restore(_ state: AlertState) {
        guard !data.alerts.hasPolled, !isLoading else { return }
        data.alerts = state
    }

    func pricing() async -> Pricing? {
        try? await client?.pricing()
    }

    func history(server id: Int64, range: MetricRange) async throws -> ServerMetrics {
        let now = Date.now
        let step = max(60, Int(range.seconds / 120))
        guard let client else { throw HetznerError.invalidResponse }
        return try await client.metrics(server: id, start: now.addingTimeInterval(-range.seconds), end: now, step: step)
    }

    func powerHistory(server id: Int64) async -> (actions: [ServerAction], complete: Bool)? {
        try? await client?.actions(server: id, since: Date.now.addingTimeInterval(-UptimeTimeline.window))
    }

    func recentActions(server id: Int64) async -> [ServerAction] {
        guard let client else { return [] }
        return (try? await client.actions(server: id)) ?? data.actions.filter { $0.targets(server: id) }
    }

    func firewallNames() async -> [Int64: String] {
        if let names = data.firewallNames { return names }
        guard let firewalls = try? await client?.firewalls() else { return [:] }
        let names = Dictionary(firewalls.map { ($0.id, $0.name) }, uniquingKeysWith: { first, _ in first })
        data.firewallNames = names
        return names
    }

    func refresh(_ context: PollContext, hosts: [Server] = [], activity: [Int64: ServerMetrics] = [:],
                 baseline: [Int64: Double] = [:]) async -> [AlertEvent] {
        guard !isLoading else { return [] }
        isLoading = true
        defer { isLoading = false }
        let now = context.now
        var next = data
        guard let client else {
            next.servers = hosts.sorted { $0.name.localizedStandardCompare($1.name) == .orderedAscending }
            next.metrics = activity
            next.iopsBaseline = baseline
            next.resourcesFetched = now
            let snapshot = PollSnapshot(time: now, servers: next.servers, metrics: activity, iopsBaseline: baseline, actions: [],
                                        volumes: nil, firewalls: nil, costForecast: Self.userForecast(next.servers, context), agents: context.agents)
            let (alerts, events) = RuleEngine(settings: context.alertSettings).evaluate(snapshot, state: next.alerts)
            next.alerts = alerts
            next.lastUpdated = now
            data = next
            problem = nil
            return events
        }
        do {
            let servers = try await client.servers()
            next.servers = servers.sorted { $0.name.localizedStandardCompare($1.name) == .orderedAscending }
            next.metrics = await Self.metrics(client, servers: servers, start: now.addingTimeInterval(-3600), end: now, step: 60)

            let stopped = Set(servers.filter { $0.status != .running }.map(\.id))
            let wasStopped = Set(data.servers.filter { $0.status != .running }.map(\.id))
            let statusChanged = !data.servers.isEmpty && stopped != wasStopped
            if statusChanged || Self.due(next.actionsFetched, every: Self.slowInterval, now: now),
               let actions = try? await client.recentServerActions() {
                next.actions = actions
                next.actionsFetched = now
            }

            if context.alertSettings.rule(.diskIO) != nil, Self.due(next.baselineFetched, every: Self.baselineInterval, now: now) {
                let week = await Self.metrics(client, servers: servers, start: now.addingTimeInterval(-7 * 86_400), end: now, step: nil, types: [.disk])
                next.iopsBaseline = week.compactMapValues { Self.median($0.totalIOPS.map(\.value)) }
                next.baselineFetched = now
            }

            let resourcesRefreshed = Self.due(next.resourcesFetched, every: Self.slowInterval, now: now)
            if resourcesRefreshed {
                await refreshResources(into: &next, now: now)
            }

            let costForecast = resourcesRefreshed && context.pricing != nil
                ? CostEstimator(pricing: context.pricing, priceKind: context.priceKind, serverPrices: context.serverPrices)
                    .estimate(next.inventory, now: now).forecast
                : nil
            let snapshot = PollSnapshot(
                time: now,
                servers: servers,
                metrics: next.metrics,
                iopsBaseline: next.iopsBaseline,
                actions: next.actions,
                volumes: resourcesRefreshed ? next.volumes : nil,
                firewalls: resourcesRefreshed ? next.firewalls : nil,
                costForecast: costForecast,
                agents: context.agents
            )
            let (alerts, events) = RuleEngine(settings: context.alertSettings).evaluate(snapshot, state: next.alerts)
            next.alerts = alerts
            next.lastUpdated = now
            next.rateLimit = await client.rateLimit
            data = next
            problem = nil
            return events
        } catch {
            data.rateLimit = await client.rateLimit
            problem = Self.describe(error)
            return []
        }
    }

    private func refreshResources(into next: inout ProjectData, now: Date) async {
        guard let client else { return }
        async let volumes = try? client.volumes()
        async let primaryIPs = try? client.primaryIPs()
        async let floatingIPs = try? client.floatingIPs()
        async let loadBalancers = try? client.loadBalancers()
        async let firewalls = try? client.firewalls()
        if let volumes = await volumes {
            next.volumes = volumes.sorted { $0.name.localizedStandardCompare($1.name) == .orderedAscending }
            if volumes.contains(where: { $0.server == nil }), let actions = try? await client.recentVolumeActions() {
                var since: [Int64: Date] = [:]
                for action in actions where action.command == "detach_volume" {
                    for resource in action.resources where resource.type == "volume" && since[resource.id] == nil {
                        since[resource.id] = action.started
                    }
                }
                next.detachedSince = since
            }
        }
        if let list = await primaryIPs { next.primaryIPs = list }
        if let list = await floatingIPs { next.floatingIPs = list }
        if let list = await loadBalancers { next.loadBalancers = list }
        if let list = await firewalls {
            next.firewalls = list
            next.firewallNames = Dictionary(list.map { ($0.id, $0.name) }, uniquingKeysWith: { first, _ in first })
        }
        next.resourcesFetched = now
    }

    private static func userForecast(_ servers: [Server], _ context: PollContext) -> Decimal? {
        guard context.serverPrices.keys.contains(where: { id in servers.contains { $0.id == id } }) else { return nil }
        return CostEstimator(pricing: nil, priceKind: context.priceKind, serverPrices: context.serverPrices)
            .estimate(Inventory(servers: servers), now: context.now).forecast
    }

    private static func due(_ last: Date?, every interval: TimeInterval, now: Date) -> Bool {
        last.map { now.timeIntervalSince($0) > interval } ?? true
    }

    private static func median(_ values: [Double]) -> Double? {
        guard !values.isEmpty else { return nil }
        let sorted = values.sorted()
        let middle = sorted.count / 2
        return sorted.count.isMultiple(of: 2) ? (sorted[middle - 1] + sorted[middle]) / 2 : sorted[middle]
    }

    private static func metrics(
        _ client: HetznerClient,
        servers: [Server],
        start: Date,
        end: Date,
        step: Int?,
        types: [MetricType] = MetricType.allCases
    ) async -> [Int64: ServerMetrics] {
        let running = servers.filter { $0.status == .running }.map(\.id)
        return await withTaskGroup(of: (Int64, ServerMetrics?).self) { group in
            for id in running {
                group.addTask {
                    (id, try? await client.metrics(server: id, types: types, start: start, end: end, step: step))
                }
            }
            var result: [Int64: ServerMetrics] = [:]
            for await (id, value) in group { result[id] = value }
            return result
        }
    }

    private static func describe(_ error: Error) -> String {
        switch error as? HetznerError {
        case .api(401, _, _):
            "Hetzner rejected the token. It may have been deleted in the Hetzner Console."
        case .rateLimited(let reset):
            "Hetzner rate limit reached. Retrying after \(reset?.formatted(date: .omitted, time: .shortened) ?? "a minute")."
        case .api(let status, let code, _):
            "Hetzner answered with an error (HTTP \(status), \(code))."
        default:
            "Could not reach Hetzner. Retrying at the next poll."
        }
    }
}
