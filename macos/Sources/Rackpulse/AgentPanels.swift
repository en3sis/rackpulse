import HetznerKit
import SwiftUI

struct AgentNotice: View {
    enum Kind {
        case problem, warning, info

        var color: Color {
            switch self {
            case .problem: Theme.red
            case .warning: Theme.orange
            case .info: Theme.info
            }
        }

        var icon: String {
            switch self {
            case .problem, .warning: "exclamationmark.triangle.fill"
            case .info: "info.circle.fill"
            }
        }
    }

    let kind: Kind
    var title: String?
    let text: String
    var action: (title: String, run: () -> Void)?
    var commands: [String] = []
    var collapseKey: String?

    @State private var copied: String?
    @AppStorage("collapsedNotices") private var collapsedNotices = ""

    private var collapsed: Bool {
        guard let collapseKey else { return false }
        return collapsedNotices.split(separator: "\n").contains { $0 == collapseKey }
    }

    private var details: Bool { title != nil || !commands.isEmpty }

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(alignment: .firstTextBaseline, spacing: 8) {
                Image(systemName: kind.icon)
                    .font(.system(size: 11))
                    .foregroundStyle(kind.color)
                    .frame(width: 12)
                Text(title ?? text)
                    .font(.system(size: 12, weight: title == nil ? .regular : .semibold))
                    .lineLimit(collapsed ? 1 : nil)
                    .fixedSize(horizontal: false, vertical: true)
                Spacer(minLength: 0)
                if let action {
                    Button(action.title, action: action.run)
                        .buttonStyle(.plain)
                        .font(.system(size: 12, weight: .medium))
                        .foregroundStyle(Color.accentColor)
                }
                if collapseKey != nil {
                    Button(action: toggle) {
                        Image(systemName: "chevron.down")
                            .font(.system(size: 10, weight: .semibold))
                            .foregroundStyle(Theme.secondary)
                            .rotationEffect(.degrees(collapsed ? -90 : 0))
                            .frame(width: 16, height: 16)
                            .contentShape(Rectangle())
                    }
                    .buttonStyle(.plain)
                    .help(collapsed ? "Show details" : "Hide details")
                    .accessibilityLabel(collapsed ? "Show details" : "Hide details")
                }
            }
            .contentShape(Rectangle())
            .onTapGesture { if collapseKey != nil { toggle() } }
            if !collapsed && details {
                VStack(alignment: .leading, spacing: 6) {
                    if title != nil {
                        Text(text)
                            .font(.system(size: 12))
                            .foregroundStyle(Theme.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                    ForEach(commands, id: \.self, content: command)
                }
                .padding(.leading, 20)
            }
        }
        .padding(.horizontal, 10)
        .padding(.vertical, 8)
        .background(kind.color.opacity(0.1), in: RoundedRectangle(cornerRadius: 8))
    }

    private func toggle() {
        guard let collapseKey else { return }
        var keys = collapsedNotices.split(separator: "\n").map(String.init).filter { $0 != collapseKey }
        if !collapsed { keys.append(collapseKey) }
        withAnimation(.easeInOut(duration: 0.15)) { collapsedNotices = keys.joined(separator: "\n") }
    }

    private func command(_ value: String) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 8) {
            Text(value.trimmingCharacters(in: .whitespaces))
                .font(.system(size: 11, design: .monospaced))
                .fixedSize(horizontal: false, vertical: true)
                .textSelection(.enabled)
            Spacer(minLength: 0)
            Button(copied == value ? "Copied" : "Copy") {
                NSPasteboard.general.clearContents()
                NSPasteboard.general.setString(value, forType: .string)
                copied = value
                Task {
                    try? await Task.sleep(for: .seconds(1.5))
                    if copied == value { copied = nil }
                }
            }
            .buttonStyle(.plain)
            .font(.system(size: 11, weight: .medium))
            .foregroundStyle(copied == value ? Theme.green : Color.accentColor)
        }
        .padding(.horizontal, 8)
        .padding(.vertical, 5)
        .background(Theme.card, in: RoundedRectangle(cornerRadius: 6))
        .help(value)
    }
}

struct AgentOverview: View {
    let server: Server
    let project: Project
    let monitor: Monitor
    let openSetup: () -> Void
    let openDocker: () -> Void

    var body: some View {
        let store = monitor.agents
        let link = store.link(project.id, server.id)
        let state = store.state(project.id, server.id)
        let key = AgentStore.key(project.id, server.id)
        VStack(spacing: 8) {
            if let problem = state?.problem, let link {
                AgentNotice(kind: .warning, text: problem.text(link), action: ("Help", openSetup), collapseKey: "\(key)|problem")
            }
            if store.needsUpdate(project.id, server.id) {
                AgentNotice(
                    kind: .info,
                    title: "Agent update available",
                    text: "Version \(AgentStore.latestVersion). Run this on the server as root. It keeps the key and settings.",
                    commands: [AgentStore.updateCommand],
                    collapseKey: "\(key)|update|\(AgentStore.latestVersion)"
                )
            }
            if let snapshot = state?.snapshot {
                tiles(snapshot)
                let others = snapshot.disks.filter { $0.id != snapshot.systemDisk?.id && !$0.mount.hasPrefix("/boot") }
                if !others.isEmpty {
                    VStack(spacing: 0) {
                        ForEach(Array(others.enumerated()), id: \.element.id) { index, disk in
                            StorageRow(disk: disk, divider: index < others.count - 1)
                        }
                    }
                    .background(Theme.card, in: RoundedRectangle(cornerRadius: 9))
                }
                ForEach(Array(issues(snapshot).enumerated()), id: \.offset) { _, issue in issue }
            } else if state?.problem == nil {
                HStack(spacing: 8) {
                    ProgressView().controlSize(.small)
                    Text("Connecting to the agent…").font(.system(size: 12)).foregroundStyle(Theme.secondary)
                    Spacer(minLength: 0)
                }
                .padding(10)
                .background(Theme.card, in: RoundedRectangle(cornerRadius: 9))
            }
        }
        .padding(.horizontal, 16)
        .padding(.top, 12)
    }

    private func tiles(_ snapshot: AgentSnapshot) -> some View {
        let memory = snapshot.memory
        let system = snapshot.systemDisk
        return HStack(spacing: 8) {
            tile("Memory", icon: "memorychip", value: Format.percent(memory.usedFraction * 100),
                 detail: "\(Format.memory(memory.used)) of \(Format.memory(memory.total))", fraction: memory.usedFraction)
            if let system {
                tile(system.kindName ?? "Disk", icon: system.icon,
                     value: Format.percent(system.usedFraction * 100),
                     detail: "\(Format.size(system.used)) of \(Format.size(system.used + system.available))",
                     fraction: system.usedFraction)
                    .help(system.summary)
            }
            tile("Up", icon: "power", value: Format.compactDuration(since: snapshot.host.bootTime),
                 detail: snapshot.host.load.first.map { "load \(String(format: "%.2f", $0))" } ?? "", fraction: nil)
                .tip("Booted \(snapshot.host.bootTime.formatted(date: .abbreviated, time: .shortened)). \(snapshot.host.os), kernel \(snapshot.host.kernel)")
        }
    }

    private func tile(_ title: String, icon: String, value: String, detail: String, fraction: Double?) -> some View {
        VStack(alignment: .leading, spacing: 3) {
            Label(title, systemImage: icon)
                .font(.system(size: 11))
                .foregroundStyle(Theme.secondary)
                .labelStyle(CompactLabelStyle())
                .lineLimit(1)
            Text(value)
                .font(.system(size: 15, weight: .semibold))
                .foregroundStyle(fraction.map { $0 >= 0.85 ? UsageBar.color($0) : Theme.text } ?? Theme.text)
                .lineLimit(1)
                .rolling(value)
            if let fraction {
                UsageBar(fraction: fraction, color: UsageBar.color(fraction)).padding(.vertical, 2)
            }
            Text(detail).font(.system(size: 10)).foregroundStyle(Theme.secondary).lineLimit(1)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(.horizontal, 10)
        .padding(.vertical, 9)
        .background(Theme.card, in: RoundedRectangle(cornerRadius: 9))
    }

    private func issues(_ snapshot: AgentSnapshot) -> [AgentNotice] {
        let key = AgentStore.key(project.id, server.id)
        var result: [AgentNotice] = []
        for disk in snapshot.disks where disk.readOnly {
            result.append(AgentNotice(kind: .problem, text: "\(disk.mount) is read-only. The file system may have errors.",
                                      collapseKey: "\(key)|readonly|\(disk.mount)"))
        }
        for disk in snapshot.disks where !disk.readOnly && disk.usedFraction >= 0.9 {
            result.append(AgentNotice(kind: .warning, text: "\(disk.mount) is \(Format.percent(disk.usedFraction * 100)) full.",
                                      collapseKey: "\(key)|full|\(disk.mount)"))
        }
        for unit in snapshot.system.failedUnits {
            result.append(AgentNotice(
                kind: .problem,
                title: "\(unit) failed",
                text: "Run on the server: status shows why it failed, reset-failed clears it once fixed.",
                commands: ["sudo systemctl status \(unit)", "sudo systemctl reset-failed \(unit)"],
                collapseKey: "\(key)|failed|\(unit)"
            ))
        }
        let troubled = (snapshot.docker?.containers ?? []).filter { $0.isUnhealthy || $0.isRestartLoop || $0.crashed(within: 3_600, now: .now) }
        if !troubled.isEmpty {
            let names = troubled.prefix(2).map(\.name).joined(separator: ", ") + (troubled.count > 2 ? " and \(troubled.count - 2) more" : "")
            result.append(AgentNotice(kind: .warning, text: "Docker: \(names) need\(troubled.count == 1 ? "s" : "") attention.", action: ("Show", openDocker),
                                      collapseKey: "\(key)|docker"))
        }
        if snapshot.system.rebootRequired {
            result.append(AgentNotice(
                kind: .info,
                title: "Reboot needed",
                text: "Updates were installed that need a reboot.",
                commands: ["sudo reboot"],
                collapseKey: "\(key)|reboot"
            ))
        }
        return result
    }
}

struct AgentInvitation: View {
    let server: Server
    let project: Project
    let monitor: Monitor
    let openSetup: () -> Void

    var body: some View {
        let link = monitor.agents.link(project.id, server.id)
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 6) {
                Image(systemName: "memorychip").foregroundStyle(Theme.secondary)
                Text("Memory, disk space and Docker").font(.system(size: 12, weight: .semibold))
            }
            Text(link == nil
                 ? (server.agentOnly
                    ? "This server has no provider API. Install the Rackpulse agent to see it in Rackpulse."
                    : "The provider's API does not report what happens inside the server. Install the optional Rackpulse agent to see it here.")
                 : "Agent setup is not finished. Rackpulse is waiting for the agent at \(link?.place ?? "").")
                .font(.system(size: 11))
                .foregroundStyle(Theme.secondary)
                .fixedSize(horizontal: false, vertical: true)
            Button(link == nil ? "Set up agent" : "Continue setup", action: openSetup).controlSize(.small)
        }
        .padding(10)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Theme.card, in: RoundedRectangle(cornerRadius: 9))
    }
}

struct AgentSystemCard: View {
    let server: Server
    let project: Project
    let monitor: Monitor
    let openSetup: () -> Void

    @State private var confirmingRemove = false

    var body: some View {
        let store = monitor.agents
        let link = store.link(project.id, server.id)
        let state = store.state(project.id, server.id)
        HStack(spacing: 6) {
            Text("SYSTEM")
                .font(.system(size: 11, weight: .semibold))
                .tracking(0.6)
                .foregroundStyle(Theme.secondary)
            Spacer()
            if let seen = state?.seen {
                Text("Agent \(link?.version ?? "") · \(Format.ago(seen, now: .now))")
                    .font(.system(size: 10))
                    .foregroundStyle(Theme.secondary)
            }
            Menu {
                Button("Setup and firewall help", action: openSetup)
                Button("Change key…", action: openSetup)
                Button("Pair again") { store.pairAgain(project.id, server.id) }
                Divider()
                Button("Remove agent from Rackpulse…", role: .destructive) { confirmingRemove = true }
            } label: {
                Image(systemName: "ellipsis.circle").font(.system(size: 12)).foregroundStyle(Theme.secondary)
            }
            .menuStyle(.button)
            .buttonStyle(.plain)
            .menuIndicator(.hidden)
            .fixedSize()
        }
        .padding(.horizontal, 16)
        .padding(.top, 20)
        .padding(.bottom, 4)

        if confirmingRemove {
            VStack(alignment: .leading, spacing: 8) {
                Text("Remove the agent from Rackpulse?").font(.system(size: 13, weight: .semibold))
                Text("Rackpulse stops reading it and deletes its key. The agent keeps running on the server until you run sudo rackpulse-agent uninstall there.")
                    .font(.system(size: 12))
                    .foregroundStyle(Theme.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                HStack {
                    Button("Cancel") { confirmingRemove = false }
                        .keyboardShortcut(.cancelAction)
                    Spacer()
                    Button("Remove") {
                        confirmingRemove = false
                        store.remove(project.id, server.id)
                    }
                    .buttonStyle(.borderedProminent)
                    .tint(Theme.red)
                }
            }
            .padding(10)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(Theme.card, in: RoundedRectangle(cornerRadius: 10))
            .padding(.horizontal, 16)
            .padding(.bottom, 8)
        }

        if let snapshot = state?.snapshot {
            VStack(spacing: 0) {
                let memory = snapshot.memory
                usageRow(icon: "memorychip", title: "Memory", fraction: memory.usedFraction,
                         value: "\(Format.memory(memory.used)) of \(Format.memory(memory.total))", divider: true)
                if memory.swapTotal > 0 {
                    usageRow(icon: "arrow.left.arrow.right", title: "Swap", fraction: memory.swapFraction,
                             value: "\(Format.memory(memory.swapUsed)) of \(Format.memory(memory.swapTotal))", divider: true)
                }
                fact("Operating system", snapshot.host.os, divider: true)
                fact("Kernel", "\(snapshot.host.kernel) · \(snapshot.host.arch)", divider: true)
                fact("Booted", snapshot.host.bootTime.formatted(date: .abbreviated, time: .shortened), divider: true)
                fact("Load", snapshot.host.load.map { String(format: "%.2f", $0) }.joined(separator: "  ") + " · \(snapshot.host.cores) cores", divider: false)
            }
            .background(Theme.card, in: RoundedRectangle(cornerRadius: 9))
            .padding(.horizontal, 16)
        }
    }

    private func usageRow(icon: String, title: String, fraction: Double, value: String, divider: Bool) -> some View {
        VStack(alignment: .leading, spacing: 5) {
            HStack(spacing: 6) {
                Image(systemName: icon).foregroundStyle(Theme.secondary).frame(width: 16)
                Text(title).font(.system(size: 12, weight: .semibold))
                Spacer(minLength: 6)
                Text(value).font(.system(size: 12))
            }
            UsageBar(fraction: fraction, color: UsageBar.color(fraction))
        }
        .padding(.horizontal, 10)
        .padding(.vertical, 8)
        .overlay(alignment: .bottom) {
            if divider { Theme.divider.frame(height: 1).padding(.horizontal, 10) }
        }
    }

    private func fact(_ title: String, _ value: String, divider: Bool) -> some View {
        HStack {
            Text(title).foregroundStyle(Theme.secondary)
            Spacer(minLength: 8)
            Text(value).lineLimit(1).truncationMode(.middle).textSelection(.enabled)
        }
        .font(.system(size: 12))
        .padding(.horizontal, 10)
        .padding(.vertical, 7)
        .overlay(alignment: .bottom) {
            if divider { Theme.divider.frame(height: 1).padding(.horizontal, 10) }
        }
    }
}

struct DockerPanel: View {
    let docker: AgentSnapshot.Docker
    let hostMemory: Int64
    let store: AgentStore
    let key: String
    let open: (String) -> Void

    private static let collapseAbove = 12

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            if let error = docker.error {
                AgentNotice(kind: .warning, text: error)
                    .padding(.horizontal, 16)
                    .padding(.bottom, 10)
            }
            HStack {
                SectionTitle("Containers")
                Spacer()
                Text(summary).font(.system(size: 12)).foregroundStyle(Theme.secondary)
            }
            .padding(.horizontal, 16)
            .padding(.bottom, 4)
            if docker.containers.isEmpty {
                Text(docker.error == nil ? "No containers on this server." : "")
                    .font(.system(size: 13))
                    .foregroundStyle(Theme.secondary)
                    .padding(.horizontal, 16)
            }
            VStack(spacing: 10) {
                ForEach(groups, id: \.id) { group in
                    let expanded = isExpanded(group)
                    VStack(alignment: .leading, spacing: 0) {
                        Button { toggle(group, expanded: expanded) } label: {
                            HStack(spacing: 6) {
                                Image(systemName: "chevron.right")
                                    .font(.system(size: 10, weight: .semibold))
                                    .rotationEffect(.degrees(expanded ? 90 : 0))
                                    .frame(width: 12)
                                Image(systemName: group.symbol).font(.system(size: 12))
                                Text(group.name).font(.system(size: 13, weight: .semibold)).foregroundStyle(Theme.text)
                                if group.compose {
                                    Text("Compose").font(.system(size: 11))
                                }
                                Spacer(minLength: 6)
                                if group.troubled > 0 {
                                    Text("\(group.troubled) need attention").font(.system(size: 12)).foregroundStyle(Theme.orange)
                                }
                                Text(group.stopped ? "\(group.containers.count)" : "\(group.running) of \(group.containers.count) running")
                                    .font(.system(size: 12))
                            }
                            .foregroundStyle(Theme.secondary)
                            .padding(.horizontal, 10)
                            .padding(.vertical, 9)
                            .contentShape(Rectangle())
                        }
                        .buttonStyle(.plain)
                        if expanded {
                            ForEach(group.containers) { container in
                                Button { open(container.name) } label: {
                                    ContainerRow(container: container)
                                }
                                .buttonStyle(RowButtonStyle())
                            }
                        }
                    }
                    .background(Theme.card, in: RoundedRectangle(cornerRadius: 9))
                }
            }
            .padding(.horizontal, 16)

            if let disk = docker.disk {
                HStack {
                    SectionTitle("Disk usage")
                    Spacer()
                    Text("\(Format.size(disk.total)) · \(Format.size(disk.reclaimable)) reclaimable")
                        .font(.system(size: 12))
                        .foregroundStyle(Theme.secondary)
                }
                .padding(.horizontal, 16)
                .padding(.top, 20)
                .padding(.bottom, 4)
                VStack(spacing: 0) {
                    diskRow("Images", "square.stack.3d.down.right.fill", .blue, disk.images, reclaimable: disk.imagesReclaimable, divider: true)
                    diskRow("Volumes", "cylinder.fill", .orange, disk.volumes, reclaimable: disk.volumesReclaimable, divider: true)
                    diskRow("Build cache", "hammer.fill", .gray, disk.buildCache, reclaimable: disk.buildCacheReclaimable, divider: true)
                    diskRow("Container layers", "square.3.layers.3d", .teal, disk.containers, reclaimable: nil, divider: false)
                }
                .background(Theme.card, in: RoundedRectangle(cornerRadius: 9))
                .padding(.horizontal, 16)
                Text("Reclaimable space belongs to images and volumes no container uses, and to unused build cache. docker system prune removes it.")
                    .font(.system(size: 12))
                    .foregroundStyle(Theme.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                    .padding(.horizontal, 16)
                    .padding(.top, 6)
            }

            if !docker.volumes.isEmpty {
                HStack {
                    SectionTitle("Volumes")
                    Spacer()
                    if let time = docker.volumesTime {
                        Text("measured \(Format.compactDuration(since: time)) ago").font(.system(size: 12)).foregroundStyle(Theme.secondary)
                    }
                }
                .padding(.horizontal, 16)
                .padding(.top, 20)
                .padding(.bottom, 4)
                VStack(spacing: 0) {
                    let volumes = docker.volumes.sorted { $0.size > $1.size }
                    ForEach(Array(volumes.enumerated()), id: \.element.id) { index, volume in
                        HStack(spacing: 8) {
                            IconTile(symbol: "cylinder.fill", tint: .orange, size: 22)
                            VStack(alignment: .leading, spacing: 1) {
                                Text(volume.name).font(.system(size: 13, weight: .medium)).lineLimit(1).truncationMode(.middle)
                                Text(users(volume)).font(.system(size: 11)).foregroundStyle(Theme.secondary).lineLimit(1)
                            }
                            Spacer(minLength: 6)
                            Text(volume.size >= 0 ? Format.size(volume.size) : "-").font(.system(size: 13, weight: .semibold))
                        }
                        .padding(.horizontal, 10)
                        .padding(.vertical, 7)
                        .overlay(alignment: .bottom) {
                            if index < volumes.count - 1 { Theme.divider.frame(height: 1).padding(.horizontal, 10) }
                        }
                    }
                }
                .background(Theme.card, in: RoundedRectangle(cornerRadius: 9))
                .padding(.horizontal, 16)
            }
            Color.clear.frame(height: 4)
        }
    }

    private var summary: String {
        let running = docker.containers.filter(\.isRunning).count
        return "\(running) of \(docker.containers.count) running"
    }

    private struct Group: Identifiable {
        let id: String
        let name: String
        let compose: Bool
        let stopped: Bool
        let containers: [AgentSnapshot.Container]

        var running: Int { containers.filter(\.isRunning).count }
        var troubled: Int { containers.filter { ContainerRow.rank($0) == 0 }.count }
        var symbol: String { stopped ? "stop.circle" : compose ? "square.stack.3d.up" : "shippingbox" }
    }

    private var groups: [Group] {
        let stopped = docker.containers.filter { !$0.isRunning && ContainerRow.rank($0) != 0 }
        let active = docker.containers.filter { $0.isRunning || ContainerRow.rank($0) == 0 }
        let grouped = Dictionary(grouping: active) { $0.project ?? "" }
        var result = grouped.keys.sorted { ($0.isEmpty ? "~" : $0) < ($1.isEmpty ? "~" : $1) }.map { name in
            Group(
                id: "project:\(name)",
                name: name.isEmpty ? "Standalone" : name,
                compose: !name.isEmpty,
                stopped: false,
                containers: grouped[name, default: []].sorted { (ContainerRow.rank($0), $0.name) < (ContainerRow.rank($1), $1.name) }
            )
        }
        if !stopped.isEmpty {
            result.append(Group(id: "stopped", name: "Stopped", compose: false, stopped: true, containers: stopped.sorted { $0.name < $1.name }))
        }
        return result
    }

    private func isExpanded(_ group: Group) -> Bool {
        if let choice = store.dockerGroups["\(key)|\(group.id)"] { return choice }
        if group.troubled > 0 { return true }
        if group.stopped { return false }
        return docker.containers.count <= Self.collapseAbove
    }

    private func toggle(_ group: Group, expanded: Bool) {
        store.setDockerGroup("\(key)|\(group.id)", expanded: !expanded)
    }

    private func users(_ volume: AgentSnapshot.Volume) -> String {
        let names = docker.containers.filter { container in
            (container.mounts ?? []).contains { $0.name == volume.name }
        }.map(\.name)
        if !names.isEmpty { return "Used by \(names.joined(separator: ", "))" }
        return volume.containers == 0 ? "Not used by any container" : "Used by \(volume.containers) container\(volume.containers == 1 ? "" : "s")"
    }

    private func diskRow(_ title: String, _ symbol: String, _ tint: Color, _ size: Int64, reclaimable: Int64?, divider: Bool) -> some View {
        HStack(spacing: 10) {
            IconTile(symbol: symbol, tint: tint, size: 22)
            Text(title).font(.system(size: 13))
            Spacer(minLength: 8)
            if let reclaimable, reclaimable > 0 {
                Text("\(Format.size(reclaimable)) reclaimable").font(.system(size: 12)).foregroundStyle(Theme.secondary)
            }
            Text(size > 0 ? Format.size(size) : "None")
                .font(.system(size: 13, weight: size > 0 ? .semibold : .regular))
                .foregroundStyle(size > 0 ? Theme.text : Theme.secondary)
                .frame(minWidth: 52, alignment: .trailing)
        }
        .padding(.horizontal, 10)
        .padding(.vertical, 7)
        .overlay(alignment: .bottom) {
            if divider { Theme.divider.frame(height: 1).padding(.horizontal, 10) }
        }
    }
}

struct SectionTitle: View {
    let title: String

    init(_ title: String) {
        self.title = title
    }

    var body: some View {
        Text(title.uppercased())
            .font(.system(size: 11, weight: .semibold))
            .tracking(0.6)
            .foregroundStyle(Theme.secondary)
    }
}

struct ContainerRow: View {
    let container: AgentSnapshot.Container

    static func memoryShare(_ container: AgentSnapshot.Container, hostMemory: Int64) -> (fraction: Double, of: String)? {
        guard let memory = container.memory else { return nil }
        if let limit = container.memoryLimit, limit > 0 { return (Double(memory) / Double(limit), "of \(Format.memory(limit)) limit") }
        guard hostMemory > 0 else { return nil }
        return (Double(memory) / Double(hostMemory), "of \(Format.memory(hostMemory)) server")
    }

    nonisolated static func rank(_ container: AgentSnapshot.Container) -> Int {
        if container.isUnhealthy || container.isRestartLoop || container.crashed(within: 86_400, now: .now) { return 0 }
        return container.isRunning ? 1 : 2
    }

    var body: some View {
        let (color, status) = Self.describe(container)
        HStack(spacing: 10) {
            IconTile(symbol: "shippingbox.fill", tint: color, size: 22)
            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 6) {
                    Text(container.name).font(.system(size: 13, weight: .semibold)).lineLimit(1).truncationMode(.middle)
                    if let health = container.health, health != "healthy" {
                        HealthBadge(health: health)
                    }
                }
                Text(([Self.shortImage(container.image), status]).joined(separator: " · "))
                    .font(.system(size: 12))
                    .foregroundStyle(color == Theme.red || color == Theme.orange ? color : Theme.secondary)
                    .lineLimit(1)
                    .truncationMode(.middle)
            }
            Spacer(minLength: 8)
            if container.isRunning {
                VStack(alignment: .trailing, spacing: 2) {
                    Text(container.memory.map { Format.memory($0) } ?? "")
                        .font(.system(size: 12, weight: .medium))
                    if let cpu = container.cpu {
                        Text("\(Format.cpu(cpu)) CPU").font(.system(size: 11)).foregroundStyle(Theme.secondary)
                    }
                }
                .monospacedDigit()
            }
            Image(systemName: "chevron.right").font(.system(size: 10, weight: .semibold)).foregroundStyle(.tertiary)
        }
        .padding(.horizontal, 10)
        .padding(.vertical, 7)
        .contentShape(Rectangle())
        .overlay(alignment: .top) {
            Theme.divider.frame(height: 1).padding(.leading, 42).padding(.trailing, 10)
        }
    }

    static func shortImage(_ image: String) -> String {
        image.split(separator: "/").last.map(String.init) ?? image
    }

    static func describe(_ container: AgentSnapshot.Container) -> (Color, String) {
        if container.isRestartLoop { return (Theme.orange, "Restarted \(container.restartsLastHour)× in 1 h") }
        if container.isUnhealthy { return (Theme.red, "Unhealthy") }
        if container.isRunning {
            return (Theme.green, container.startedAt.map { "Up \(Format.compactDuration(since: $0))" } ?? "Running")
        }
        let since = container.finishedAt.map { " \(Format.compactDuration(since: $0)) ago" } ?? ""
        if container.crashed(within: 86_400, now: .now) { return (Theme.red, "Exited with code \(container.exitCode)\(since)") }
        if container.state == "exited" { return (Theme.off, "Stopped\(since)") }
        return (Theme.off, container.state.capitalized)
    }
}

struct HealthBadge: View {
    let health: String

    var body: some View {
        let color = health == "healthy" ? Theme.green : health == "unhealthy" ? Theme.red : Theme.orange
        Text(health.capitalized)
            .font(.system(size: 10, weight: .semibold))
            .foregroundStyle(color)
            .padding(.horizontal, 5)
            .padding(.vertical, 1)
            .background(color.opacity(0.12), in: Capsule())
    }
}

enum ContainerRange: String, CaseIterable, Hashable {
    case hour = "1h", day = "24h", week = "7d"

    var seconds: TimeInterval {
        switch self {
        case .hour: 3_600
        case .day: 86_400
        case .week: 604_800
        }
    }
}

struct IconTile: View {
    let symbol: String
    let tint: Color
    var size: CGFloat = 24

    var body: some View {
        Image(systemName: symbol)
            .font(.system(size: size * 0.46, weight: .semibold))
            .foregroundStyle(.white)
            .frame(width: size, height: size)
            .background(tint.gradient, in: RoundedRectangle(cornerRadius: size / 4, style: .continuous))
    }
}

struct InfoList<Content: View>: View {
    @ViewBuilder let content: Content

    var body: some View {
        VStack(spacing: 0) { content }
            .padding(.top, -1)
            .clipShape(RoundedRectangle(cornerRadius: 9))
            .background(Theme.card, in: RoundedRectangle(cornerRadius: 9))
            .padding(.horizontal, 16)
    }
}

struct InfoRow: View {
    let symbol: String
    let tint: Color
    let title: String
    var value: String = ""
    var detail: String?
    var monospaced = false

    var body: some View {
        HStack(spacing: 10) {
            IconTile(symbol: symbol, tint: tint)
            VStack(alignment: .leading, spacing: 1) {
                Text(title)
                    .font(.system(size: 13, weight: .medium, design: monospaced ? .monospaced : .default))
                    .lineLimit(1)
                    .truncationMode(.middle)
                    .textSelection(.enabled)
                if let detail, !detail.isEmpty {
                    Text(detail)
                        .font(.system(size: 11))
                        .foregroundStyle(Theme.secondary)
                        .lineLimit(1)
                        .truncationMode(.middle)
                }
            }
            Spacer(minLength: 8)
            Text(value)
                .font(.system(size: 13))
                .foregroundStyle(Theme.secondary)
                .lineLimit(1)
        }
        .padding(.horizontal, 10)
        .padding(.vertical, 7)
        .overlay(alignment: .top) {
            Theme.divider.frame(height: 1).padding(.leading, 44)
        }
    }
}

struct StorageRow: View {
    let disk: AgentSnapshot.Disk
    var divider = false

    var body: some View {
        VStack(alignment: .leading, spacing: 5) {
            HStack(spacing: 8) {
                Image(systemName: disk.icon)
                    .font(.system(size: 12))
                    .foregroundStyle(Theme.secondary)
                    .frame(width: 16)
                VStack(alignment: .leading, spacing: 1) {
                    HStack(spacing: 6) {
                        Text(disk.mount).font(.system(size: 12, weight: .semibold)).lineLimit(1).truncationMode(.middle)
                        if disk.readOnly {
                            Text("read-only").font(.system(size: 11)).foregroundStyle(Theme.red)
                        }
                    }
                    Text(disk.details).font(.system(size: 11)).foregroundStyle(Theme.secondary).lineLimit(1)
                }
                Spacer(minLength: 8)
                Text("\(Format.size(disk.used)) of \(Format.size(disk.used + disk.available))")
                    .font(.system(size: 12, weight: .semibold))
                    .foregroundStyle(disk.usedFraction >= 0.9 ? Theme.orange : Theme.text)
            }
            UsageBar(fraction: disk.usedFraction, color: UsageBar.color(disk.usedFraction, warn: disk.readOnly))
                .padding(.leading, 24)
        }
        .padding(.horizontal, 10)
        .padding(.vertical, 8)
        .overlay(alignment: .bottom) {
            if divider { Theme.divider.frame(height: 1).padding(.horizontal, 10) }
        }
        .help(disk.summary)
    }
}

extension AgentSnapshot {
    var systemDisk: Disk? {
        disks.first { $0.mount == "/" } ?? disks.max { $0.total < $1.total }
    }
}

extension AgentSnapshot.Disk {
    var kindName: String? {
        switch kind {
        case "sd": "SD card"
        case "emmc": "eMMC"
        case "nvme": "NVMe SSD"
        case "usb": "USB drive"
        case "ssd": "SSD"
        case "hdd": "Hard disk"
        case "virtual": "Virtual disk"
        case "ram": "RAM disk"
        case "image": "Disk image"
        case "raid": "RAID"
        case "mapped": "Mapped volume"
        default: nil
        }
    }

    var icon: String {
        switch kind {
        case "sd": "sdcard"
        case "emmc", "ram": "memorychip"
        case "usb": "externaldrive"
        case "raid": "square.stack.3d.up"
        case "image": "opticaldisc"
        default: "internaldrive"
        }
    }

    var details: String {
        [kindName, model, fs].compactMap { $0?.nonEmpty }.joined(separator: " · ")
    }

    var summary: String {
        [mount, details, device].filter { !$0.isEmpty }.joined(separator: " · ")
    }
}
