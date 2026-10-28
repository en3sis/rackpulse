import HetznerKit
import SwiftUI

struct CostSummary {
    let currency: String
    let priceKind: PriceKind
    let monthEnd: Date
    let monthToDate: Decimal
    let forecast: Decimal
    let budget: Decimal?
    let idle: [CostLine]
    let missing: [String]
    let hasUserPrices: Bool

    init(_ reports: [CostReport], budget: Decimal?) {
        currency = reports.first?.currency ?? "EUR"
        priceKind = reports.first?.priceKind ?? .net
        monthEnd = reports.first?.monthEnd ?? .now
        monthToDate = reports.reduce(0) { $0 + $1.monthToDate }
        forecast = reports.reduce(0) { $0 + $1.forecast }
        self.budget = budget
        idle = reports.flatMap { $0.lines.filter { $0.idleReason != nil && $0.kind != .backup } }
        missing = reports.flatMap(\.missingPrices)
        hasUserPrices = reports.contains { $0.lines.contains(where: \.userPrice) }
    }
}

struct CostsView: View {
    let monitor: Monitor
    let store: ProjectStore
    let openSettings: () -> Void
    let openServer: (UUID, Int64) -> Void
    @Binding var focus: UUID?

    var body: some View {
        if let id = focus, store.scope.count > 1, let project = store.project(id) {
            VStack(spacing: 0) {
                backBar(project)
                projectCosts(project)
            }
        } else if store.scope.count > 1 {
            allProjects
        } else if let project = store.scope.first {
            projectCosts(project)
        } else {
            CostsPlaceholder()
        }
    }

    @ViewBuilder
    private func projectCosts(_ project: Project) -> some View {
        if let poller = monitor.poller(project.id), let report = monitor.costReport(for: project.id) {
            let rows = CostRow.group(report, data: poller.data, project: project.id)
            content(CostSummary([report], budget: project.budget), rows: rows, title: "By resource",
                    empty: "Nothing billed in this project this month.", canSetBudget: true)
        } else {
            CostsPlaceholder()
        }
    }

    private func backBar(_ project: Project) -> some View {
        HStack(spacing: 10) {
            Button { focus = nil } label: {
                Image(systemName: "chevron.left")
                    .font(.system(size: 12, weight: .semibold))
                    .frame(width: 28, height: 28)
                    .background(Theme.card, in: RoundedRectangle(cornerRadius: 7))
                    .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .accessibilityLabel("Back to all projects")
            .keyboardShortcut("[", modifiers: .command)
            VStack(alignment: .leading, spacing: 1) {
                Text(project.name).font(.system(size: 14, weight: .semibold)).lineLimit(1)
                Text("Costs of this project. All projects stay selected.")
                    .font(.system(size: 11))
                    .foregroundStyle(Theme.secondary)
            }
            Spacer(minLength: 0)
        }
        .padding(.horizontal, 16)
        .padding(.top, 10)
        .onExitCommand { focus = nil }
    }

    @ViewBuilder
    private var allProjects: some View {
        let reports = store.projects.map { ($0, monitor.costReport(for: $0.id)) }
        if reports.allSatisfy({ $0.1 != nil }) {
            let budgets = store.projects.map(\.budget)
            let budget: Decimal? = budgets.allSatisfy { $0 != nil } ? budgets.reduce(0) { $0 + ($1 ?? 0) } : nil
            let rows = reports.compactMap { project, report in
                report.map { CostRow(project: project, report: $0, servers: monitor.poller(project.id)?.data.servers.count ?? 0) }
            }
            .sorted { $0.monthToDate > $1.monthToDate }
            content(CostSummary(reports.compactMap(\.1), budget: budget), rows: rows, title: "By project",
                    empty: "Nothing billed this month.", canSetBudget: false)
        } else {
            CostsPlaceholder()
        }
    }

    private func content(_ summary: CostSummary, rows: [CostRow], title: String, empty: String, canSetBudget: Bool) -> some View {
        let top = rows.map(\.monthToDate).max() ?? 0
        return VStack(alignment: .leading, spacing: 0) {
            header(summary, canSetBudget: canSetBudget)

            SectionHeader(title)
                .padding(.top, 16)

            if rows.isEmpty {
                EmptyLine(text: empty, link: nil)
            }
            ForEach(Array(rows.enumerated()), id: \.element.id) { index, row in
                let rowView = CostRowView(row: row, share: top > 0 ? fraction(row.monthToDate, of: top) : 0,
                                          currency: summary.currency, showsDivider: index < rows.count - 1)
                if let project = row.project {
                    Button { focus = project.id } label: { rowView.contentShape(Rectangle()) }
                        .buttonStyle(RowButtonStyle())
                        .help("Show \(row.name)")
                } else if let id = row.serverID, let project = row.projectID {
                    Button { openServer(project, id) } label: { rowView.contentShape(Rectangle()) }
                        .buttonStyle(RowButtonStyle())
                        .help("Open \(row.name)")
                } else {
                    rowView
                }
            }

            idleNote(summary)

            Text(disclaimer(summary))
                .font(.system(size: 11))
                .foregroundStyle(Theme.secondary)
                .fixedSize(horizontal: false, vertical: true)
                .padding(.horizontal, 16)
                .padding(.vertical, 12)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private func header(_ summary: CostSummary, canSetBudget: Bool) -> some View {
        let budget = summary.budget
        let scale = max(summary.forecast, budget ?? 0) * Decimal(1.08)
        let over = budget.map { $0 > 0 && summary.forecast > $0 } ?? false
        return VStack(alignment: .leading, spacing: 4) {
            Text("Month to date · estimate")
                .font(.system(size: 12))
                .foregroundStyle(Theme.secondary)
            HStack(alignment: .firstTextBaseline, spacing: 10) {
                Text(money(summary.monthToDate, summary.currency))
                    .font(.system(size: 30, weight: .bold))
                Text("→ \(money(summary.forecast, summary.currency)) by \(lastDay(summary.monthEnd))")
                    .font(.system(size: 13))
                    .foregroundStyle(over ? Theme.red : Theme.secondary)
            }

            GeometryReader { proxy in
                let width = proxy.size.width
                ZStack(alignment: .leading) {
                    Capsule().fill(Theme.divider)
                    Capsule().fill(Color.accentColor.opacity(0.35))
                        .frame(width: width * fraction(summary.forecast, of: scale))
                    Capsule().fill(Color.accentColor)
                        .frame(width: width * fraction(summary.monthToDate, of: scale))
                    if let budget, budget > 0 {
                        Rectangle()
                            .fill(Theme.text)
                            .frame(width: 2, height: 16)
                            .offset(x: width * fraction(budget, of: scale) - 1)
                    }
                }
                .frame(height: 8)
                .frame(maxHeight: .infinity)
            }
            .frame(height: 16)
            .padding(.top, 6)
            .accessibilityElement()
            .accessibilityLabel("Spent \(money(summary.monthToDate, summary.currency)), forecast \(money(summary.forecast, summary.currency))")

            HStack {
                legend(Color.accentColor, "Spent")
                legend(Color.accentColor.opacity(0.35), "Forecast")
                Spacer()
                if let budget, budget > 0 {
                    Text("Budget \(money(budget, summary.currency))")
                } else if canSetBudget {
                    Button("Set a budget", action: openSettings)
                        .buttonStyle(.plain)
                        .foregroundStyle(Color.accentColor)
                }
            }
            .font(.system(size: 11))
            .foregroundStyle(Theme.secondary)
        }
        .padding(.horizontal, 16)
        .padding(.top, 14)
    }

    @ViewBuilder
    private func idleNote(_ summary: CostSummary) -> some View {
        let idle = summary.idle
        if !idle.isEmpty {
            let total = idle.reduce(Decimal(0)) { $0 + $1.monthToDate }
            let items = idle.prefix(3).map { "\($0.name) (\($0.idleReason!.lowercased()), \(money($0.monthToDate, summary.currency)))" }
            let more = idle.count > 3 ? " and \(idle.count - 3) more" : ""
            HStack(alignment: .top, spacing: 8) {
                Image(systemName: "moon.zzz").foregroundStyle(Theme.info)
                Text("**Idle spend \(money(total, summary.currency)) this month:** \(items.joined(separator: ", "))\(more).")
                    .font(.system(size: 12))
                    .fixedSize(horizontal: false, vertical: true)
            }
            .padding(10)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(Theme.info.opacity(0.1), in: RoundedRectangle(cornerRadius: 10))
            .overlay(RoundedRectangle(cornerRadius: 10).stroke(Theme.info.opacity(0.3)))
            .padding(.horizontal, 16)
            .padding(.top, 12)
        }
    }

    private func legend(_ color: Color, _ text: String) -> some View {
        HStack(spacing: 4) {
            Circle().fill(color).frame(width: 7, height: 7)
            Text(text)
        }
    }

    private func lastDay(_ monthEnd: Date) -> String {
        var style = Date.FormatStyle.dateTime.month(.abbreviated).day()
        style.timeZone = .gmt
        return monthEnd.addingTimeInterval(-1).formatted(style)
    }

    private func disclaimer(_ summary: CostSummary) -> String {
        let vat = summary.priceKind == .gross ? "with VAT" : "without VAT"
        var text = store.scope.contains(where: \.hasAPI)
            ? "Estimated from list prices × hours each resource existed this month, \(vat). Hetzner has no billing API, so credits and traffic overage are not included."
            : "Estimated from the monthly prices you entered for these servers. Add a price in Settings to include a server."
        if summary.hasUserPrices {
            text += " Servers marked your price use the monthly price you entered."
        }
        if !summary.missing.isEmpty {
            text += " No price for: \(summary.missing.joined(separator: ", "))."
        }
        return text
    }
}

struct SectionHeader: View {
    let title: String

    init(_ title: String) {
        self.title = title
    }

    var body: some View {
        Text(title.uppercased())
            .font(.system(size: 11, weight: .semibold))
            .tracking(0.6)
            .foregroundStyle(Theme.secondary)
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(.horizontal, 16)
            .padding(.bottom, 4)
    }
}

private struct CostsPlaceholder: View {
    @State private var dim = false

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            RoundedRectangle(cornerRadius: 5).frame(width: 140, height: 10)
            RoundedRectangle(cornerRadius: 8).frame(width: 180, height: 30)
            Capsule().frame(height: 8)
            ForEach(0..<3, id: \.self) { _ in
                HStack {
                    RoundedRectangle(cornerRadius: 5).frame(width: 130, height: 12)
                    Spacer()
                    RoundedRectangle(cornerRadius: 5).frame(width: 60, height: 12)
                }
                .padding(.top, 8)
            }
        }
        .foregroundStyle(Theme.card)
        .opacity(dim ? 0.5 : 1)
        .padding(16)
        .onAppear {
            withAnimation(.easeInOut(duration: 0.9).repeatForever(autoreverses: true)) { dim = true }
        }
        .accessibilityLabel("Loading costs")
    }
}

func money(_ amount: Decimal, _ currency: String) -> String {
    amount.formatted(.currency(code: currency).precision(.fractionLength(2)))
}

private func fraction(_ value: Decimal, of total: Decimal) -> CGFloat {
    guard total > 0 else { return 0 }
    return CGFloat(min(1, max(0, NSDecimalNumber(decimal: value / total).doubleValue)))
}

struct CostRow: Identifiable {
    let id: String
    let name: String
    let meta: String
    let monthToDate: Decimal
    var serverID: Int64? = nil
    var projectID: UUID? = nil
    var project: Project? = nil

    init(id: String, name: String, meta: String, monthToDate: Decimal, serverID: Int64? = nil, projectID: UUID? = nil) {
        self.id = id
        self.name = name
        self.meta = meta
        self.monthToDate = monthToDate
        self.serverID = serverID
        self.projectID = projectID
    }

    init(project: Project, report: CostReport, servers: Int) {
        id = project.id.uuidString
        name = project.name
        meta = "\(servers) server\(servers == 1 ? "" : "s")"
        monthToDate = report.monthToDate
        self.project = project
    }

    static func group(_ report: CostReport, data: ProjectData, project: UUID) -> [CostRow] {
        var rows: [CostRow] = []
        let lines = report.lines

        for server in data.servers {
            let own = lines.filter { ($0.kind == .server || $0.kind == .backup) && $0.resourceID == server.id }
            guard !own.isEmpty else { continue }
            var meta = [server.serverType.name.uppercased()]
            if server.backupsEnabled { meta.append("backups") }
            if server.status == .off { meta.append("off") }
            if own.contains(where: \.userPrice) { meta.append("your price") }
            rows.append(CostRow(id: "server\(server.id)", name: server.name, meta: meta.joined(separator: " · "),
                                monthToDate: own.reduce(0) { $0 + $1.monthToDate }, serverID: server.id, projectID: project))
        }

        for line in lines where line.kind == .storageBox || line.kind == .loadBalancer {
            rows.append(CostRow(
                id: line.id,
                name: line.name,
                meta: line.kind == .storageBox ? "Storage Box" : "Load Balancer",
                monthToDate: line.monthToDate
            ))
        }

        let volumes = lines.filter { $0.kind == .volume }
        if !volumes.isEmpty {
            let size = data.volumes.reduce(0) { $0 + $1.size }
            rows.append(CostRow(id: "volumes", name: "Volumes",
                                meta: "\(volumes.count) volume\(volumes.count == 1 ? "" : "s") · \(Int(size)) GB",
                                monthToDate: volumes.reduce(0) { $0 + $1.monthToDate }))
        }

        let ips = lines.filter { $0.kind == .primaryIP || $0.kind == .floatingIP }
        if !ips.isEmpty {
            let primary = data.primaryIPs.count
            let floating = data.floatingIPs.count
            var parts: [String] = []
            if primary > 0 { parts.append("\(primary) primary") }
            if floating > 0 { parts.append("\(floating) floating") }
            rows.append(CostRow(id: "ips", name: "IP addresses", meta: parts.joined(separator: ", "),
                                monthToDate: ips.reduce(0) { $0 + $1.monthToDate }))
        }

        return rows.sorted { $0.monthToDate > $1.monthToDate }
    }
}

private struct CostRowView: View {
    let row: CostRow
    let share: CGFloat
    let currency: String
    let showsDivider: Bool

    var body: some View {
        HStack(spacing: 10) {
            if let project = row.project {
                Image(systemName: project.icon)
                    .font(.system(size: 13, weight: .semibold))
                    .foregroundStyle(project.color.color)
                    .frame(width: 18)
            }
            VStack(alignment: .leading, spacing: 1) {
                Text(row.name).font(.system(size: 13, weight: .semibold)).lineLimit(1)
                Text(row.meta).font(.system(size: 11)).foregroundStyle(Theme.secondary).lineLimit(1)
            }
            Spacer(minLength: 0)
            Capsule().fill(Theme.divider)
                .frame(width: 70, height: 4)
                .overlay(alignment: .leading) {
                    Capsule().fill(Theme.secondary).frame(width: 70 * share, height: 4)
                }
            Text(money(row.monthToDate, currency))
                .font(.system(size: 13, weight: .semibold))
                .frame(width: 72, alignment: .trailing)
            Image(systemName: "chevron.right")
                .font(.system(size: 10, weight: .semibold))
                .foregroundStyle(.tertiary)
                .opacity(row.serverID == nil && row.project == nil ? 0 : 1)
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 8)
        .overlay(alignment: .bottom) {
            if showsDivider { Theme.divider.frame(height: 1).padding(.horizontal, 16) }
        }
    }
}
