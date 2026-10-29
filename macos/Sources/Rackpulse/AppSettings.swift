import Foundation
import HetznerKit
import Observation

enum MenuBarReadout: String, Codable, CaseIterable, Identifiable {
    case none, cpu, cost, alerts

    var id: String { rawValue }

    var title: String {
        switch self {
        case .none: "Nothing"
        case .cpu: "Busiest server's CPU"
        case .cost: "Cost this month"
        case .alerts: "Number of alerts"
        }
    }
}

struct AppSettings: Codable, Equatable {
    static let intervals: [TimeInterval] = [30, 60, 120, 300]

    var pollInterval: TimeInterval = 60
    var alerts = AlertSettings()
    var priceKind: PriceKind = .net
    var showsCosts = true
    var lockWithTouchID = false
    var readout: MenuBarReadout = .none
    var chartRange: MetricRange = .hour
    var shortcut: PanelShortcut = .controlOptionR
    var compactList = false
    var serverAlerts: [String: ServerAlertOverride] = [:]
    var serverEnvironments: [String: ServerEnvironment] = [:]
    var serverPrices: [String: Decimal] = [:]

    init() {}

    enum CodingKeys: String, CodingKey {
        case pollInterval, alerts, priceKind, showsCosts, lockWithTouchID, serverAlerts, readout, chartRange, shortcut, compactList
        case serverEnvironments, serverPrices
    }

    static func key(project: UUID, server: Int64) -> String {
        "\(project.uuidString):\(server)"
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        pollInterval = (try? container.decode(TimeInterval.self, forKey: .pollInterval)) ?? 60
        alerts = (try? container.decode(AlertSettings.self, forKey: .alerts)) ?? AlertSettings()
        priceKind = (try? container.decode(PriceKind.self, forKey: .priceKind)) ?? .net
        showsCosts = (try? container.decode(Bool.self, forKey: .showsCosts)) ?? true
        lockWithTouchID = (try? container.decode(Bool.self, forKey: .lockWithTouchID)) ?? false
        readout = (try? container.decode(MenuBarReadout.self, forKey: .readout)) ?? .none
        chartRange = (try? container.decode(MetricRange.self, forKey: .chartRange)) ?? .hour
        shortcut = (try? container.decode(PanelShortcut.self, forKey: .shortcut)) ?? .controlOptionR
        compactList = (try? container.decode(Bool.self, forKey: .compactList)) ?? false
        serverAlerts = (try? container.decode([String: ServerAlertOverride].self, forKey: .serverAlerts)) ?? [:]
        serverEnvironments = (try? container.decode([String: ServerEnvironment].self, forKey: .serverEnvironments)) ?? [:]
        serverPrices = (try? container.decode([String: Decimal].self, forKey: .serverPrices)) ?? [:]
        for rule in RuleConfig.defaults where !alerts.rules.contains(where: { $0.kind == rule.kind }) {
            alerts.rules.append(rule)
        }
    }

    func alertSettings(for project: Project) -> AlertSettings {
        var settings = alerts
        settings.budget = showsCosts ? project.budget : nil
        if !showsCosts, let index = settings.rules.firstIndex(where: { $0.kind == .budget }) {
            settings.rules[index].enabled = false
        }
        for (id, override) in Self.servers(serverAlerts, project: project.id) { settings.servers[id] = override }
        if !project.hasAPI {
            let providerKinds: Set<RuleKind> = [.serverDown, .storageBox, .trafficQuota, .unexpectedChange]
            for index in settings.rules.indices where providerKinds.contains(settings.rules[index].kind) {
                settings.rules[index].enabled = false
            }
        }
        return settings
    }

    func serverPrices(for project: UUID) -> [Int64: Decimal] {
        Self.servers(serverPrices, project: project)
    }

    private static func servers<Value>(_ values: [String: Value], project: UUID) -> [Int64: Value] {
        let prefix = "\(project.uuidString):"
        var result: [Int64: Value] = [:]
        for (key, value) in values where key.hasPrefix(prefix) {
            if let id = Int64(key.dropFirst(prefix.count)) { result[id] = value }
        }
        return result
    }
}

@MainActor
@Observable
final class SettingsStore {
    private static let key = "settings"

    var requestedPage: SettingsPage?

    var value: AppSettings {
        didSet {
            guard value != oldValue else { return }
            UserDefaults.standard.set(try? JSONEncoder().encode(value), forKey: Self.key)
        }
    }

    init() {
        value = UserDefaults.standard.data(forKey: Self.key)
            .flatMap { try? JSONDecoder().decode(AppSettings.self, from: $0) } ?? AppSettings()
    }

    func rule(_ kind: RuleKind) -> RuleConfig {
        value.alerts.rules.first { $0.kind == kind } ?? RuleConfig.defaults.first { $0.kind == kind }!
    }

    func override(project: UUID, server: Int64) -> ServerAlertOverride {
        value.serverAlerts[AppSettings.key(project: project, server: server)] ?? ServerAlertOverride()
    }

    func setOverride(_ override: ServerAlertOverride, project: UUID, server: Int64) {
        let key = AppSettings.key(project: project, server: server)
        value.serverAlerts[key] = override.mode == .global ? nil : override
    }

    func price(project: UUID, server: Int64) -> Decimal? {
        value.serverPrices[AppSettings.key(project: project, server: server)]
    }

    func setPrice(_ price: Decimal?, project: UUID, server: Int64) {
        value.serverPrices[AppSettings.key(project: project, server: server)] = price.flatMap { $0 > 0 ? $0 : nil }
    }

    func environmentChoice(project: UUID, server: Int64) -> ServerEnvironment? {
        value.serverEnvironments[AppSettings.key(project: project, server: server)]
    }

    func setEnvironment(_ environment: ServerEnvironment?, project: UUID, server: Int64) {
        value.serverEnvironments[AppSettings.key(project: project, server: server)] = environment
    }

    func environment(project: UUID, server: Server) -> ServerEnvironment {
        environmentChoice(project: project, server: server.id) ?? ServerEnvironment(labels: server.labels) ?? ServerEnvironment.none
    }

    func adoptLegacyEnvironment(_ environment: ServerEnvironment, project: UUID, servers: [Server]) {
        var environments = value.serverEnvironments
        for server in servers where ServerEnvironment(labels: server.labels) == nil {
            let key = AppSettings.key(project: project, server: server.id)
            if environments[key] == nil { environments[key] = environment }
        }
        value.serverEnvironments = environments
    }

    func update(_ kind: RuleKind, _ change: (inout RuleConfig) -> Void) {
        guard let index = value.alerts.rules.firstIndex(where: { $0.kind == kind }) else { return }
        change(&value.alerts.rules[index])
    }
}
