import Foundation

public struct RuleEngine: Sendable {
    public static let userStopCommands: Set<String> = ["shutdown_server", "stop_server"]
    static let heldKinds: Set<RuleKind> = [.memory, .securityUpdates]

    public let settings: AlertSettings
    public let calendar: Calendar

    public init(settings: AlertSettings, calendar: Calendar = .current) {
        self.settings = settings
        self.calendar = calendar
    }

    enum Level {
        case above, band, below, unknown
    }

    struct Observation {
        let id: String
        let kind: RuleKind
        var serverID: Int64? = nil
        let level: Level
        let severity: Severity
        let title: String
    }

    public func evaluate(_ snapshot: PollSnapshot, state previous: AlertState) -> (AlertState, [AlertEvent]) {
        var state = previous
        var events: [AlertEvent] = []
        let now = snapshot.time
        let evaluated = evaluatedKinds(snapshot)
        let observations = observe(snapshot, previous: previous)
        let byID = Dictionary(observations.map { ($0.id, $0) }, uniquingKeysWith: { first, _ in first })

        for (id, track) in state.tracks where settings.rule(track.kind, server: track.serverID) == nil {
            if track.alert != nil { events.append(.resolved(id: id)) }
            state.tracks[id] = nil
        }

        let ids = Set(byID.keys).union(state.tracks.filter { evaluated.contains($0.value.kind) }.keys)
        for id in ids.sorted() {
            let observation = byID[id]
            let serverID = observation?.serverID ?? state.tracks[id]?.serverID
            guard let kind = observation?.kind ?? state.tracks[id]?.kind, let rule = settings.rule(kind, server: serverID) else { continue }
            if observation == nil, kind.needsAgent, kind != .agentUnreachable, let serverID,
               snapshot.agents[serverID].map({ $0.current == nil }) == true {
                continue
            }
            if observation == nil, kind.needsSecurityResult, let serverID, snapshot.security[serverID] == nil,
               snapshot.agents[serverID] != nil, snapshot.servers.contains(where: { $0.id == serverID }) {
                continue
            }
            var track = state.tracks[id] ?? AlertState.Track(kind: kind, serverID: serverID)
            switch observation?.level ?? .below {
            case .above:
                track.raised += 1
                track.cleared = 0
                track.aboveSince = track.aboveSince ?? now
                let held = !Self.heldKinds.contains(rule.kind) || now.timeIntervalSince(track.aboveSince ?? now) >= rule.duration
                if track.alert == nil, track.raised >= raiseAfter(rule), held, let observation {
                    let alert = FiringAlert(id: id, kind: kind, severity: observation.severity, title: observation.title, since: now)
                    track.alert = alert
                    events.append(.fired(alert, notify: shouldNotify(alert, rule: rule, state: state, now: now)))
                }
            case .band:
                if track.alert == nil {
                    track.raised = 0
                    track.aboveSince = nil
                } else {
                    track.cleared = 0
                }
            case .unknown:
                break
            case .below:
                track.raised = 0
                track.aboveSince = nil
                if track.alert != nil {
                    track.cleared += 1
                    if track.cleared >= clearAfter(kind) {
                        track.alert = nil
                        events.append(.resolved(id: id))
                    }
                }
            }
            state.tracks[id] = track.alert == nil && track.raised == 0 ? nil : track
        }

        state.inventory = nextInventory(snapshot, previous: previous.inventory)
        state.lastPoll = now
        state.newestAction = [previous.newestAction, snapshot.actions.map(\.started).max()].compactMap { $0 }.max()
        return (state, events)
    }

    private func raiseAfter(_ rule: RuleConfig) -> Int {
        rule.kind == .serverDown ? max(1, Int(rule.threshold)) : 1
    }

    private func clearAfter(_ kind: RuleKind) -> Int {
        kind == .unexpectedChange ? 1 : max(1, settings.clearAfter)
    }

    private func shouldNotify(_ alert: FiringAlert, rule: RuleConfig, state: AlertState, now: Date) -> Bool {
        rule.delivery != .banner && !state.isSnoozed(alert.id, at: now)
    }

    private func evaluatedKinds(_ snapshot: PollSnapshot) -> Set<RuleKind> {
        var kinds: Set<RuleKind> = Set([.serverDown, .sustainedCPU, .trafficQuota, .diskIO, .unexpectedChange] + RuleKind.agentKinds)
        if snapshot.storageBoxes != nil { kinds.insert(.storageBox) }
        if snapshot.costForecast != nil { kinds.insert(.budget) }
        return kinds
    }

    private func observe(_ snapshot: PollSnapshot, previous: AlertState) -> [Observation] {
        var result: [Observation] = []
        let now = snapshot.time

        for server in snapshot.servers {
            if !server.agentOnly, settings.rule(.serverDown, server: server.id) != nil {
                let down = server.status != .running && !stoppedByUser(server, actions: snapshot.actions)
                result.append(Observation(
                    id: "serverDown:\(server.id)", kind: .serverDown, serverID: server.id, level: down ? .above : .below,
                    severity: .critical, title: "\(server.name) is \(server.status.rawValue)"
                ))
            }

            if let rule = settings.rule(.sustainedCPU, server: server.id), let metrics = snapshot.metrics[server.id] {
                let window = Self.window(metrics.cpuPercent(cores: server.serverType.cores), last: rule.duration, now: now)
                if let low = window?.map(\.value).min() {
                    result.append(Observation(
                        id: "sustainedCPU:\(server.id)", kind: .sustainedCPU, serverID: server.id,
                        level: Self.level(low, threshold: rule.threshold, band: 5),
                        severity: .warning,
                        title: "\(server.name) CPU above \(Int(rule.threshold))% for \(Int(rule.duration / 60)) min"
                    ))
                }
            }

            if let rule = settings.rule(.diskIO, server: server.id), let metrics = snapshot.metrics[server.id],
               let baseline = snapshot.iopsBaseline[server.id], baseline > 0 {
                let limit = baseline * rule.threshold
                if let low = Self.window(metrics.totalIOPS, last: rule.duration, now: now)?.map(\.value).min() {
                    result.append(Observation(
                        id: "diskIO:\(server.id)", kind: .diskIO, serverID: server.id,
                        level: Self.level(low, threshold: limit, band: limit * 0.1),
                        severity: .warning,
                        title: "\(server.name) disk I/O above \(rule.threshold.formatted())× its 7-day median"
                    ))
                }
            }

            if let rule = settings.rule(.trafficQuota, server: server.id), let fraction = server.trafficFraction {
                result.append(Observation(
                    id: "trafficQuota:\(server.id)", kind: .trafficQuota, serverID: server.id,
                    level: Self.level(fraction, threshold: rule.threshold, band: 0.02),
                    severity: .warning,
                    title: "\(server.name) used \(Int(fraction * 100))% of its included traffic"
                ))
            }
        }

        for server in snapshot.servers {
            if let report = snapshot.agents[server.id] {
                result += observeAgent(report, server: server, now: now)
            }
            if let security = snapshot.security[server.id] {
                result += observeSecurity(security, server: server)
            }
        }

        if let rule = settings.rule(.storageBox), let boxes = snapshot.storageBoxes {
            for box in boxes {
                let days = snapshot.storageForecasts[box.id]?.daysUntilFull
                let soon = rule.secondaryThreshold.map { limit in days.map { $0 < limit } ?? false } ?? false
                let level = soon ? .above : Self.level(box.usedFraction, threshold: rule.threshold, band: 0.03)
                let title = soon
                    ? "\(box.name) full in about \(Int((days ?? 0).rounded(.up))) days"
                    : "\(box.name) is \(Int(box.usedFraction * 100))% full"
                result.append(Observation(
                    id: "storageBox:\(box.id)", kind: .storageBox, level: level, severity: .critical, title: title
                ))
            }
        }

        if settings.rule(.budget) != nil, let budget = settings.budget, budget > 0, let forecast = snapshot.costForecast {
            let ratio = NSDecimalNumber(decimal: forecast / budget).doubleValue
            result.append(Observation(
                id: "budget", kind: .budget, level: Self.level(ratio, threshold: 1, band: 0.03),
                severity: .info, title: "Forecast is above your monthly budget"
            ))
        }

        if settings.rule(.unexpectedChange) != nil {
            result += changes(snapshot, previous: previous)
        }

        return result
    }

    private func observeAgent(_ report: AgentReport, server: Server, now: Date) -> [Observation] {
        var result: [Observation] = []
        let name = server.name

        if let rule = settings.rule(.agentUnreachable, server: server.id) {
            let unreachable = report.current == nil && server.status == .running && report.failures >= max(1, Int(rule.threshold))
            result.append(Observation(
                id: "agentUnreachable:\(server.id)", kind: .agentUnreachable, serverID: server.id,
                level: unreachable ? .above : .below, severity: .warning,
                title: server.agentOnly ? "\(name) does not answer" : "\(name) is running, but its agent does not answer"
            ))
        }
        guard let snapshot = report.current else { return result }

        if let rule = settings.rule(.diskSpace, server: server.id) {
            for disk in snapshot.disks {
                let fraction = max(disk.usedFraction, disk.inodesFraction)
                let level = disk.readOnly ? .above : Self.level(fraction, threshold: rule.threshold, band: 0.02)
                let title: String
                if disk.readOnly {
                    title = "\(name): \(disk.mount) is read-only"
                } else if disk.inodesFraction > disk.usedFraction {
                    title = "\(name): \(disk.mount) used \(Int(disk.inodesFraction * 100))% of its inodes"
                } else {
                    title = "\(name): \(disk.mount) is \(Int(disk.usedFraction * 100))% full"
                }
                result.append(Observation(
                    id: "diskSpace:\(disk.mount):\(server.id)", kind: .diskSpace, serverID: server.id, level: level,
                    severity: disk.readOnly || fraction >= 0.97 ? .critical : .warning, title: title
                ))
            }
        }

        if let rule = settings.rule(.memory, server: server.id) {
            result.append(Observation(
                id: "memory:\(server.id)", kind: .memory, serverID: server.id,
                level: Self.level(snapshot.memory.usedFraction, threshold: rule.threshold, band: 0.03), severity: .warning,
                title: "\(name) memory above \(Int((rule.threshold * 100).rounded()))% for \(Int(rule.duration / 60)) min"
            ))
        }

        if let rule = settings.rule(.container, server: server.id), let docker = snapshot.docker {
            for container in docker.containers {
                let title: String
                if container.isUnhealthy {
                    title = "\(name): \(container.name) is unhealthy"
                } else if container.state == "restarting" || container.restartsLastHour >= max(1, Int(rule.threshold)) {
                    title = "\(name): \(container.name) restarted \(container.restartsLastHour) times in the last hour"
                } else if container.crashed(within: 3_600, now: now) {
                    title = "\(name): \(container.name) stopped with exit code \(container.exitCode)"
                } else {
                    continue
                }
                result.append(Observation(
                    id: "container:\(container.name):\(server.id)", kind: .container, serverID: server.id,
                    level: .above, severity: .warning, title: title
                ))
            }
        }

        if settings.rule(.failedService, server: server.id) != nil {
            let units = snapshot.system.failedServices
            result.append(Observation(
                id: "failedService:\(server.id)", kind: .failedService, serverID: server.id,
                level: units.isEmpty ? .below : .above, severity: .warning,
                title: units.count == 1 ? "\(name): \(units[0]) failed" : "\(name): \(units.count) services failed"
            ))
        }

        if settings.rule(.rebootRequired, server: server.id) != nil {
            result.append(Observation(
                id: "rebootRequired:\(server.id)", kind: .rebootRequired, serverID: server.id,
                level: snapshot.system.rebootRequired ? .above : .below, severity: .info,
                title: "\(name) needs a reboot to finish updates"
            ))
        }
        return result
    }

    private func observeSecurity(_ security: SecurityResult, server: Server) -> [Observation] {
        var result: [Observation] = []
        let name = server.name

        if let rule = settings.rule(.securityUpdates, server: server.id) {
            let count = security.pendingSecurityUpdates
            let days = max(1, Int((rule.duration / 86_400).rounded()))
            result.append(Observation(
                id: "securityUpdates:\(server.id)", kind: .securityUpdates, serverID: server.id,
                level: count > 0 ? .above : security.updatesError == nil ? .below : .unknown, severity: .warning,
                title: "\(name): \(count) security \(count == 1 ? "update" : "updates") waiting for \(days) \(days == 1 ? "day" : "days")"
            ))
        }

        if let rule = settings.rule(.vulnerability, server: server.id) {
            let minimum = AdvisorySeverity(rank: max(1, Int(rule.threshold)))
            let items = security.alerting(minimum: minimum)
            let worst = items.contains { $0.advisory.urgent || $0.advisory.severity == .critical }
            result.append(Observation(
                id: "vulnerability:\(server.id)", kind: .vulnerability, serverID: server.id,
                level: !items.isEmpty ? .above : security.lookupFailed ? .unknown : .below, severity: worst ? .critical : .warning,
                title: Self.vulnerabilityTitle(items, server: name)
            ))
        }

        if settings.rule(.hardening, server: server.id) != nil {
            let failing = security.failingChecks
            result.append(Observation(
                id: "hardening:\(server.id)", kind: .hardening, serverID: server.id,
                level: failing.isEmpty ? .below : .above, severity: .warning,
                title: failing.count == 1 ? "\(name): \(failing[0].title)" : "\(name): \(failing.count) hardening checks fail"
            ))
        }
        return result
    }

    static func vulnerabilityTitle(_ items: [SecurityResult.Item], server name: String) -> String {
        let malware = items.filter { $0.advisory.isMalware }
        if malware.count == 1 { return "\(name): \(malware[0].finding.package.name) is a malicious package" }
        if malware.count > 1 { return "\(name): \(malware.count) malicious packages found" }
        let exploited = items.filter { $0.advisory.isExploited }.count
        if exploited == 1 { return "\(name): 1 vulnerability is known to be exploited" }
        if exploited > 1 { return "\(name): \(exploited) vulnerabilities are known to be exploited" }
        let levels = Set(items.map(\.advisory.severity)).sorted(by: >).map(\.rawValue).joined(separator: " and ")
        return items.count == 1
            ? "\(name): 1 \(levels) vulnerability has a fix"
            : "\(name): \(items.count) \(levels) vulnerabilities have a fix"
    }

    private func stoppedByUser(_ server: Server, actions: [ServerAction]) -> Bool {
        let latest = actions.filter { $0.targets(server: server.id) }.max { $0.started < $1.started }
        return latest.map { Self.userStopCommands.contains($0.command) } ?? false
    }

    private func changes(_ snapshot: PollSnapshot, previous: AlertState) -> [Observation] {
        guard let before = previous.inventory else { return [] }
        var result: [Observation] = []
        func change(_ id: String, _ title: String) {
            result.append(Observation(id: "unexpectedChange:\(id)", kind: .unexpectedChange, level: .above, severity: .info, title: title))
        }

        let servers = Dictionary(snapshot.servers.map { ($0.id, $0.name) }, uniquingKeysWith: { first, _ in first })
        for (id, name) in servers where before.servers[id] == nil { change("server+\(id)", "New server \(name)") }
        for (id, name) in before.servers where servers[id] == nil { change("server-\(id)", "Server \(name) was deleted") }

        if let volumes = snapshot.volumes, let old = before.volumes {
            for volume in volumes where old[volume.id] == nil { change("volume+\(volume.id)", "New volume \(volume.name)") }
            let current = Set(volumes.map(\.id))
            for (id, name) in old where !current.contains(id) { change("volume-\(id)", "Volume \(name) was deleted") }
        }

        if let firewalls = snapshot.firewalls, let old = before.firewalls {
            for firewall in firewalls where old[firewall.id].map({ $0 != Self.fingerprint(firewall) }) ?? true {
                change("firewall\(firewall.id)", "Firewall \(firewall.name) changed")
            }
        }

        if let seen = previous.newestAction {
            for action in snapshot.actions where action.command == "rebuild_server" && action.started > seen {
                let name = action.resources.first { $0.type == "server" }.flatMap { servers[$0.id] } ?? "A server"
                change("rebuild\(action.id)", "\(name) was rebuilt")
            }
        }
        return result
    }

    private func nextInventory(_ snapshot: PollSnapshot, previous: AlertState.Inventory?) -> AlertState.Inventory {
        AlertState.Inventory(
            servers: Dictionary(snapshot.servers.map { ($0.id, $0.name) }, uniquingKeysWith: { first, _ in first }),
            volumes: snapshot.volumes.map { Dictionary($0.map { ($0.id, $0.name) }, uniquingKeysWith: { first, _ in first }) }
                ?? previous?.volumes,
            firewalls: snapshot.firewalls.map { Dictionary($0.map { ($0.id, Self.fingerprint($0)) }, uniquingKeysWith: { first, _ in first }) }
                ?? previous?.firewalls
        )
    }

    static func fingerprint(_ firewall: Firewall) -> String {
        let rules = firewall.rules.map {
            [$0.direction, $0.protocolName, $0.port ?? "", $0.sourceIps.sorted().joined(separator: ","),
             $0.destinationIps.sorted().joined(separator: ",")].joined(separator: "|")
        }.sorted()
        let targets = firewall.appliedTo.map { "\($0.type):\($0.server?.id ?? 0):\($0.labelSelector?.selector ?? "")" }.sorted()
        return (rules + ["@"] + targets).joined(separator: ";")
    }

    static func window(_ points: [MetricPoint], last duration: TimeInterval, now: Date) -> [MetricPoint]? {
        let recent = points.filter { $0.time > now.addingTimeInterval(-duration) && $0.time <= now }
        guard recent.count >= 2, let first = recent.first, let last = recent.last else { return nil }
        let step = recent.count > 1 ? last.time.timeIntervalSince(first.time) / Double(recent.count - 1) : 0
        return last.time.timeIntervalSince(first.time) + step >= duration * 0.9 ? recent : nil
    }

    static func level(_ value: Double, threshold: Double, band: Double) -> Level {
        if value > threshold { return .above }
        if value > threshold - band { return .band }
        return .below
    }
}
