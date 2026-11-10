import HetznerKit
import SwiftUI

struct FleetSecurityView: View {
    let monitor: Monitor
    let store: ProjectStore
    let openSettings: () -> Void
    let open: (UUID, Int64) -> Void

    struct ServerRef: Hashable, Sendable {
        let project: UUID
        let id: Int64
        let name: String
    }

    private struct Row: Identifiable {
        let server: ServerRef
        let projectName: String
        var fixNow = 0
        var withFix = 0
        var noFix = 0
        var checks = 0
        var exploited = 0
        var malware = 0
        var severity = AdvisorySeverity.unknown
        var online = false

        var id: ServerRef { server }
        var clean: Bool { fixNow + withFix + noFix + checks == 0 }

        var rank: (Int, Int, Int, Int, Int) {
            (malware, exploited, fixNow, withFix, checks)
        }
    }

    private struct Fleet {
        var rows: [Row] = []
        var waiting: [ServerRef] = []
        var total = 0
        var checked = 0
        var online = 0
        var fixNow = 0
        var withFix = 0
        var checks = 0
    }

    private var fleet: Fleet {
        var fleet = Fleet()
        let now = Date.now
        for project in store.scope {
            guard let poller = monitor.poller(project.id) else { continue }
            for server in poller.data.servers {
                let ref = ServerRef(project: project.id, id: server.id, name: server.name)
                let paired = monitor.agents.link(project.id, server.id)?.isPaired == true
                guard let result = monitor.security.result(project.id, server.id) else {
                    if paired {
                        fleet.total += 1
                        fleet.waiting.append(ref)
                    }
                    continue
                }
                fleet.total += 1
                fleet.checked += 1
                if result.onlineChecks { fleet.online += 1 }
                let ignored = monitor.decisionCheck(project, server.id, now: now).ignoredKeys
                let grouped = SecurityReview.fleet([(server: ref, result: result, ignored: ignored)])
                var row = Row(server: ref, projectName: project.name)
                row.online = result.onlineChecks
                for advisory in grouped.advisories {
                    if advisory.fixNow { row.fixNow += 1 } else if advisory.hasFix { row.withFix += 1 } else { row.noFix += 1 }
                    if advisory.exploited { row.exploited += 1 }
                    if advisory.malware { row.malware += 1 }
                    row.severity = max(row.severity, advisory.severity)
                }
                row.checks = grouped.checks.count
                fleet.fixNow += row.fixNow
                fleet.withFix += row.withFix
                fleet.checks += row.checks
                fleet.rows.append(row)
            }
        }
        fleet.rows.sort { $0.rank != $1.rank ? $0.rank > $1.rank : $0.server.name.lowercased() < $1.server.name.lowercased() }
        fleet.waiting.sort { $0.name.lowercased() < $1.name.lowercased() }
        return fleet
    }

    private var onlineChecks: Bool {
        monitor.settings.value.security.onlineChecks
    }

    var body: some View {
        let fleet = fleet
        VStack(alignment: .leading, spacing: 0) {
            if fleet.total == 0 {
                AgentNotice(kind: .info, text: "Security checks need the Rackpulse agent. Open a server and set up the agent to check its packages and settings.")
                    .padding(.horizontal, 16)
                    .padding(.top, 14)
            } else if fleet.checked == 0 {
                coverage(fleet)
                notice("clock", color: Theme.secondary, title: "No results yet",
                       text: "Results show here after the first check of each server.")
                    .padding(.top, 12)
                if !onlineChecks {
                    checksOffNotice.padding(.top, 8)
                }
            } else {
                summary(fleet)
                coverage(fleet)
                if !onlineChecks {
                    checksOffNotice.padding(.top, 12)
                }
                serverList(fleet)
            }
        }
        .padding(.bottom, 14)
    }

    private func summary(_ fleet: Fleet) -> some View {
        HStack(spacing: 8) {
            SummaryTile.fixNow(fleet.fixNow)
            SummaryTile.fixAvailable(fleet.withFix)
            SummaryTile.checks(fleet.checks)
        }
        .fixedSize(horizontal: false, vertical: true)
        .padding(.horizontal, 16)
        .padding(.top, 14)
    }

    private func coverage(_ fleet: Fleet) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            statusRow("server.rack", color: fleet.checked > 0 ? Theme.green : Theme.secondary) {
                Text("\(fleet.checked) of \(fleet.total) \(fleet.total == 1 ? "server" : "servers") checked")
            }
            if !fleet.waiting.isEmpty {
                statusRow("clock", color: Theme.secondary) {
                    FlowLayout(spacing: 6) {
                        Text("Waiting for the first check:")
                        ForEach(fleet.waiting, id: \.self) { server in
                            Button { open(server.project, server.id) } label: {
                                Text(verbatim: server.name)
                                    .font(.system(size: 12, weight: .medium))
                                    .foregroundStyle(Color.accentColor)
                            }
                            .buttonStyle(.plain)
                            .help("Open the Security tab of this server")
                        }
                    }
                }
            }
            if onlineChecks && fleet.online < fleet.checked {
                statusRow("hourglass", color: Theme.secondary) {
                    Text("Vulnerability check pending on \(fleet.checked - fleet.online)")
                }
            }
        }
        .padding(.horizontal, 16)
        .padding(.top, 12)
    }

    @ViewBuilder
    private func serverList(_ fleet: Fleet) -> some View {
        HStack(spacing: 6) {
            Image(systemName: "server.rack")
                .font(.system(size: 10, weight: .semibold))
                .foregroundStyle(Theme.secondary)
            SectionTitle("Servers")
            Spacer()
        }
        .padding(.horizontal, 16)
        .padding(.top, 20)
        .padding(.bottom, 6)
        VStack(alignment: .leading, spacing: 0) {
            ForEach(Array(fleet.rows.enumerated()), id: \.element.id) { index, row in
                serverRow(row, multipleProjects: store.scope.count > 1)
                    .overlay(alignment: .top) {
                        if index > 0 { Theme.divider.frame(height: 1).padding(.horizontal, 10) }
                    }
            }
        }
        .background(Theme.card, in: RoundedRectangle(cornerRadius: 9))
        .padding(.horizontal, 16)
    }

    private func serverRow(_ row: Row, multipleProjects: Bool) -> some View {
        Button { open(row.server.project, row.server.id) } label: {
            HStack(alignment: .firstTextBaseline, spacing: 10) {
                Image(systemName: row.clean ? "checkmark.shield.fill" : "exclamationmark.shield.fill")
                    .font(.system(size: 14))
                    .foregroundStyle(color(row))
                    .frame(width: 18)
                VStack(alignment: .leading, spacing: 4) {
                    HStack(spacing: 6) {
                        Text(verbatim: row.server.name)
                            .font(.system(size: 13, weight: .semibold))
                            .lineLimit(1)
                        if multipleProjects {
                            Text(verbatim: row.projectName)
                                .font(.system(size: 11))
                                .foregroundStyle(Theme.secondary)
                                .lineLimit(1)
                        }
                        if row.malware > 0 { Tag(text: "Malware", color: Theme.red) }
                        if row.exploited > 0 { Tag(text: "Exploited", color: Theme.red) }
                        Spacer(minLength: 0)
                    }
                    if row.clean {
                        Text(row.online ? "No known vulnerabilities, all checks pass" : "All checks pass")
                            .font(.system(size: 12))
                            .foregroundStyle(Theme.secondary)
                    } else {
                        FlowLayout(spacing: 10) {
                            if row.fixNow > 0 { count(row.fixNow, "fix now", icon: "flame.fill", color: Theme.red) }
                            if row.withFix > 0 { count(row.withFix, "with a fix", icon: "arrow.up.circle.fill", color: Theme.orange) }
                            if row.noFix > 0 { count(row.noFix, "no fix yet", icon: "circle.dashed", color: Theme.secondary) }
                            if row.checks > 0 {
                                count(row.checks, row.checks == 1 ? "check failing" : "checks failing",
                                      icon: "exclamationmark.shield.fill", color: Theme.orange)
                            }
                        }
                    }
                }
                Image(systemName: "chevron.right")
                    .font(.system(size: 10, weight: .semibold))
                    .foregroundStyle(.tertiary)
            }
            .padding(.horizontal, 10)
            .padding(.vertical, 9)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .help("Open the Security tab of \(row.server.name)")
    }

    private func count(_ value: Int, _ label: String, icon: String, color: Color) -> some View {
        HStack(spacing: 4) {
            Image(systemName: icon)
                .font(.system(size: 10))
                .foregroundStyle(color)
            Text("\(value) \(label)")
                .font(.system(size: 12))
                .foregroundStyle(Theme.secondary)
        }
    }

    private func color(_ row: Row) -> Color {
        if row.malware > 0 || row.exploited > 0 || row.fixNow > 0 { return Theme.red }
        if row.withFix > 0 || row.checks > 0 { return Theme.orange }
        if row.noFix > 0 { return Theme.secondary }
        return Theme.green
    }

    private var checksOffNotice: some View {
        notice("shield.slash", color: Theme.secondary, title: "Vulnerability checks are off",
               text: "Turn them on to look up the installed packages on OSV.dev.",
               action: ("Open Settings", {
                   monitor.settings.requestedPage = .security
                   openSettings()
               }))
    }

    private func notice(_ icon: String, color: Color, title: String, text: String?, action: (String, () -> Void)? = nil) -> some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: icon)
                .font(.system(size: 15))
                .foregroundStyle(color)
                .frame(width: 20)
            VStack(alignment: .leading, spacing: 2) {
                Text(title).font(.system(size: 13, weight: .medium))
                if let text {
                    Text(text)
                        .font(.system(size: 12))
                        .foregroundStyle(Theme.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                if let action {
                    Button(action.0, action: action.1)
                        .controlSize(.small)
                        .padding(.top, 6)
                }
            }
            Spacer(minLength: 0)
        }
        .padding(10)
        .background(Theme.card, in: RoundedRectangle(cornerRadius: 9))
        .padding(.horizontal, 16)
    }

    private func statusRow<Content: View>(_ icon: String, color: Color, @ViewBuilder content: () -> Content) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 7) {
            Image(systemName: icon)
                .font(.system(size: 11))
                .foregroundStyle(color)
                .frame(width: 14)
            content()
                .font(.system(size: 12))
                .foregroundStyle(Theme.secondary)
        }
    }
}

struct SummaryTile: View {
    let title: String
    let detail: String
    let icon: String
    let count: Int
    let color: Color

    static func fixNow(_ count: Int) -> some View {
        SummaryTile(title: "Fix now", detail: "Critical or exploited", icon: "flame.fill", count: count, color: Theme.red)
            .help("Exploited or malicious packages, and critical vulnerabilities with a fix")
    }

    static func fixAvailable(_ count: Int) -> some View {
        SummaryTile(title: "Fix available", detail: "High severity or lower", icon: "arrow.up.circle.fill", count: count, color: Theme.orange)
            .help("Vulnerabilities with a fix that are not in Fix now")
    }

    static func checks(_ count: Int) -> some View {
        SummaryTile(title: "Checks failing", detail: "Server hardening", icon: "exclamationmark.shield.fill", count: count, color: Theme.orange)
            .help("Hardening checks on the server settings that do not pass")
    }

    private var tint: Color { count > 0 ? color : Theme.secondary }

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            VStack(alignment: .leading, spacing: 1) {
                Text(title)
                    .font(.system(size: 11, weight: .medium))
                    .foregroundStyle(Theme.text)
                Text(detail)
                    .font(.system(size: 10))
                    .foregroundStyle(Theme.secondary)
            }
            .lineLimit(1)
            .minimumScaleFactor(0.85)
            HStack(spacing: 8) {
                Image(systemName: icon)
                    .font(.system(size: 12, weight: .semibold))
                    .foregroundStyle(tint)
                    .frame(width: 26, height: 26)
                    .background(tint.opacity(0.2), in: RoundedRectangle(cornerRadius: 7))
                Text("\(count)")
                    .font(.system(size: 20, weight: .semibold))
                    .foregroundStyle(count > 0 ? color : Theme.secondary)
                    .lineLimit(1)
                    .minimumScaleFactor(0.7)
                    .rolling(count)
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .padding(10)
        .background(count > 0 ? color.opacity(0.12) : Theme.card, in: RoundedRectangle(cornerRadius: 10))
    }
}
