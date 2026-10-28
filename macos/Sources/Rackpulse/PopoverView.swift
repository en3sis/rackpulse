import HetznerKit
import SwiftUI

struct DetailTarget: Equatable {
    let project: UUID
    let server: Int64
    var range: MetricRange?
    var agent = false
    var tab = ServerTab.overview
    var container: String?
}

struct LiveTarget: Hashable {
    let project: UUID
    let server: Int64
}

struct PopoverView: View {
    let store: ProjectStore
    let monitor: Monitor
    let updates: Updates

    @State private var adding = false
    @Environment(AppActions.self) private var actions
    @State private var detail: DetailTarget?
    @State private var tab = Tab.servers
    @State private var costProject: UUID?
    @State private var switcherFrame: CGRect = .zero
    @State private var mainHeight: CGFloat = 0
    @State private var query = ""
    @State private var highlight = 0
    @FocusState private var keyboard: Bool
    @FocusState private var searching: Bool

    enum Tab: String, CaseIterable, Identifiable {
        case servers = "Servers"
        case costs = "Costs"

        var id: String { rawValue }
    }

    private var maxMainHeight: CGFloat {
        actions.screenHeight - 70
    }

    private var liveTarget: LiveTarget? {
        guard actions.visible, let detail else { return nil }
        return LiveTarget(project: detail.project, server: detail.server)
    }

    private var showsCosts: Bool {
        monitor.settings.value.showsCosts
    }

    private var showsFooter: Bool {
        !monitor.locked && !store.projects.isEmpty && !adding
    }

    var body: some View {
        VStack(spacing: 0) {
            ScrollView {
                main.onGeometryChange(for: CGFloat.self) { $0.size.height } action: { mainHeight = $0 }
            }
            .scrollBounceBehavior(.basedOnSize)
            .frame(height: mainHeight > maxMainHeight ? maxMainHeight : nil)
            .id(pageKey)
            if showsFooter { footer }
        }
        .frame(width: 390)
        .fixedSize(horizontal: false, vertical: true)
        .onGeometryChange(for: CGFloat.self) { $0.size.height } action: { actions.resize($0) }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .top)
        .background(Theme.panel)
        .focusable()
        .focusEffectDisabled()
        .focused($keyboard)
        .onKeyPress(phases: .down, action: handleKey)
        .onAppear { keyboard = true }
        .monospacedDigit()
        .onAppear { monitor.refreshIfStale() }
        .onChange(of: tab) { if tab != .costs { costProject = nil } }
        .onChange(of: store.showsAll) { costProject = nil }
        .onChange(of: actions.opened, initial: true) {
            costProject = nil
            if monitor.settings.value.compactList { monitor.settings.value.compactList = false }
        }
        .task(id: liveTarget) {
            guard let detail = liveTarget else { return }
            await monitor.live(detail.project, detail.server)
        }
        .onChange(of: actions.route) {
            guard let route = actions.route else { return }
            switch route {
            case .servers: tab = .servers; detail = nil; adding = false
            case .costs: tab = showsCosts ? .costs : .servers; detail = nil; adding = false
            case .server(let project, let id, let range): detail = DetailTarget(project: project, server: id, range: range); adding = false
            case .agent(let project, let id): detail = DetailTarget(project: project, server: id, agent: true); adding = false
            case .serverTab(let project, let id, let tab): detail = DetailTarget(project: project, server: id, tab: tab); adding = false
            case .container(let project, let id, let name): detail = DetailTarget(project: project, server: id, tab: .docker, container: name); adding = false
            case .addProject: adding = true
            }
            actions.route = nil
        }
    }

    private var main: some View {
        VStack(spacing: 0) {
            if monitor.locked {
                LockView { Task { await monitor.unlock() } }
            } else if store.projects.isEmpty || adding {
                OnboardingView(store: store, canCancel: !store.projects.isEmpty) { added in
                    adding = false
                    if added { monitor.projectChanged() }
                }
            } else if let detail, let project = store.project(detail.project), let poller = monitor.poller(detail.project),
                      let server = poller.data.servers.first(where: { $0.id == detail.server }) {
                if detail.agent {
                    AgentSetupView(server: server, project: project, monitor: monitor,
                                   firewalls: poller.data.firewallNames ?? [:]) { self.detail?.agent = false }
                } else if let name = detail.container {
                    ContainerDetailView(server: server, project: project, monitor: monitor, name: name) { self.detail?.container = nil }
                } else {
                    ServerDetailView(server: server, project: project, poller: poller, monitor: monitor,
                                     range: detail.range ?? actions.chartRange ?? monitor.settings.value.chartRange,
                                     tab: Binding(get: { self.detail?.tab ?? .overview }, set: { self.detail?.tab = $0 }),
                                     openAgent: { self.detail?.agent = true },
                                     openContainer: { self.detail?.container = $0 }) { self.detail = nil }
                }
            } else {
                header
                if showsCosts {
                    SegmentedControl(selection: $tab, options: Tab.allCases.map { ($0, $0.rawValue) })
                        .padding(.horizontal, 16)
                }
                if let problem = monitor.problem {
                    ProblemBanner(text: problem) { monitor.refreshNow() }
                }
                if query.isEmpty {
                    FleetHeadline(monitor: monitor, store: store, open: openAlert)
                }
                switch showsCosts ? tab : .servers {
                case .servers:
                    if !query.isEmpty { searchBar }
                    ServerList(monitor: monitor, store: store, query: query, highlighted: highlightedTarget) {
                        detail = DetailTarget(project: $0, server: $1)
                    }
                    .id(monitor.settings.value.compactList)
                case .costs:
                    CostsView(monitor: monitor, store: store, openSettings: openSettings,
                              openServer: { detail = DetailTarget(project: $0, server: $1) },
                              focus: $costProject)
                }
            }
        }
        .frame(width: 390)
    }

    private var header: some View {
        HStack {
            Button(action: showProjectMenu) {
                HStack(spacing: 6) {
                    if let project = single {
                        Image(systemName: project.icon)
                            .fontWeight(.semibold)
                            .foregroundStyle(project.color.color)
                        Text(project.name)
                            .font(.system(size: 14, weight: .semibold))
                            .lineLimit(1)
                    } else {
                        Image(systemName: "square.stack.3d.up")
                            .fontWeight(.semibold)
                            .foregroundStyle(Theme.text)
                        Text("All Projects")
                            .font(.system(size: 14, weight: .semibold))
                    }
                    Image(systemName: "chevron.down")
                        .font(.system(size: 9, weight: .semibold))
                        .foregroundStyle(Theme.secondary)
                }
                .frame(minHeight: 28)
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .fixedSize()
            .onGeometryChange(for: CGRect.self) { $0.frame(in: .global) } action: { switcherFrame = $0 }
            .help("Switch project")

            if Flavor.isDev { DevTag() }

            Spacer()

            if tab == .servers {
                Button {
                    var transaction = Transaction()
                    transaction.disablesAnimations = true
                    withTransaction(transaction) { monitor.settings.value.compactList.toggle() }
                } label: {
                    Image(systemName: monitor.settings.value.compactList ? "rectangle.expand.vertical" : "rectangle.compress.vertical")
                        .font(.system(size: 12, weight: .semibold))
                        .foregroundStyle(Theme.secondary)
                        .frame(width: 24, height: 24)
                        .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
                .help(monitor.settings.value.compactList ? "Show detailed rows" : "Show compact rows")
            }
            Button { monitor.refreshNow() } label: {
                HStack(spacing: 5) {
                    RefreshIcon(spinning: monitor.isRefreshing, problem: monitor.problem != nil)
                    TimelineView(.periodic(from: .now, by: 1)) { context in
                        Text(liveText(now: context.date))
                    }
                }
                .font(.system(size: 12))
                .foregroundStyle(Theme.secondary)
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .help("Refresh now (⌘R)")
        }
        .padding(.horizontal, 16)
        .padding(.top, 14)
        .padding(.bottom, 10)
    }

    private func liveText(now: Date) -> String {
        if monitor.problem != nil { return "Not updating" }
        guard let last = monitor.lastUpdated else { return "Loading" }
        return "Updated \(Format.ago(last, now: now))"
    }

    private var footer: some View {
        HStack {
            if let apiText {
                Text(apiText)
                    .font(.system(size: 11))
                    .lineLimit(1)
                    .minimumScaleFactor(0.8)
                    .foregroundStyle(Theme.secondary)
                    .help(store.scope.count > 1
                          ? "Requests used in the last hour by the busiest project's token. Hetzner allows 3,600 per hour per project."
                          : "Requests this project's token used in the last hour. Hetzner allows 3,600 per hour per project.")
            }
            Spacer()
            Group {
                Button("") { monitor.refreshNow() }.keyboardShortcut("r")
                Button("") { adding = true }.keyboardShortcut("n")
                Button("") { tab = .servers; detail = nil }.keyboardShortcut("1")
                Button("") { if showsCosts { tab = .costs; detail = nil } }.keyboardShortcut("2")
            }
            .frame(width: 0, height: 0)
            .opacity(0)
            .accessibilityHidden(true)
            footerButton("Settings", icon: "gearshape", key: "⌘,", action: openSettings)
                .keyboardShortcut(",")
            footerButton("Quit", icon: "power", key: "⌘Q") { NSApplication.shared.terminate(nil) }
                .keyboardShortcut("q")
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 6)
        .overlay(alignment: .top) { Theme.divider.frame(height: 1) }
    }

    private func footerButton(_ title: String, icon: String, key: String, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            HStack(spacing: 5) {
                Image(systemName: icon).font(.system(size: 11, weight: .medium))
                Text(title)
                Text(key)
                    .font(.system(size: 10, weight: .medium))
                    .padding(.horizontal, 4)
                    .padding(.vertical, 1)
                    .background(Theme.card, in: RoundedRectangle(cornerRadius: 4))
            }
            .font(.system(size: 12))
            .foregroundStyle(Theme.secondary)
            .lineLimit(1)
            .fixedSize()
            .frame(minHeight: 28)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
    }

    private func showProjectMenu() {
        let menu = NSMenu()
        let handler = MenuHandler()
        func add(_ title: String, image: NSImage?, checked: Bool = false, key: String = "", action: @escaping () -> Void) {
            let item = NSMenuItem(title: title, action: #selector(MenuHandler.run(_:)), keyEquivalent: key)
            item.target = handler
            item.tag = handler.actions.count
            handler.actions.append(action)
            item.image = image
            item.state = checked ? .on : .off
            menu.addItem(item)
        }
        func symbol(_ name: String) -> NSImage? {
            NSImage(systemSymbolName: name, accessibilityDescription: nil)?
                .withSymbolConfiguration(.init(pointSize: 14, weight: .semibold))
        }
        if store.projects.count > 1 {
            add("All Projects", image: symbol("square.stack.3d.up"), checked: store.showsAll) { selectAll() }
            menu.addItem(.separator())
        }
        for project in store.projects {
            add(project.name, image: project.menuImage, checked: !store.showsAll && store.selectedID == project.id) { select(project.id) }
        }
        menu.addItem(.separator())
        add("Add Project…", image: symbol("plus"), key: "n") { adding = true }
        add("Settings…", image: symbol("gearshape"), key: ",") { openSettings() }
        if updates.isAvailable {
            menu.addItem(.separator())
            add("Check for Updates…", image: symbol("arrow.triangle.2.circlepath")) { updates.check() }
        }
        guard let view = NSApp.keyWindow?.contentView else {
            menu.popUp(positioning: nil, at: NSEvent.mouseLocation, in: nil)
            return
        }
        let point = NSPoint(x: switcherFrame.minX - 6, y: view.bounds.height - switcherFrame.maxY - 4)
        menu.popUp(positioning: nil, at: point, in: view)
    }

    private var matches: [DetailTarget] {
        guard !query.isEmpty else { return [] }
        return store.scope.flatMap { project -> [DetailTarget] in
            guard let poller = monitor.poller(project.id) else { return [] }
            return ServerList.matches(project, poller, query, settings: monitor.settings).map { DetailTarget(project: project.id, server: $0.id) }
        }
    }

    private var highlightedTarget: DetailTarget? {
        let list = matches
        guard !list.isEmpty else { return nil }
        return list[min(highlight, list.count - 1)]
    }

    private var searchBar: some View {
        HStack(spacing: 8) {
            Image(systemName: "magnifyingglass").foregroundStyle(Theme.secondary)
            TextField("Find a server", text: $query)
                .textFieldStyle(.plain)
                .font(.system(size: 13, weight: .medium))
                .focused($searching)
                .onSubmit(openHighlighted)
                .onExitCommand(perform: clearSearch)
                .onKeyPress(.downArrow) {
                    highlight = min(highlight + 1, max(matches.count - 1, 0))
                    return .handled
                }
                .onKeyPress(.upArrow) {
                    highlight = max(highlight - 1, 0)
                    return .handled
                }
            let count = matches.count
            Text(count == 0 ? "No match" : "\(count) match\(count == 1 ? "" : "es") · ↩ opens")
                .font(.system(size: 11))
                .foregroundStyle(Theme.secondary)
                .fixedSize()
            Button(action: clearSearch) { Image(systemName: "xmark.circle.fill").foregroundStyle(Theme.secondary) }
                .buttonStyle(.plain)
                .focusable(false)
                .help("Clear (Esc)")
        }
        .padding(.horizontal, 10)
        .frame(height: 30)
        .background(Theme.card, in: RoundedRectangle(cornerRadius: 8))
        .padding(.horizontal, 16)
        .padding(.top, 10)
        .onChange(of: query) {
            highlight = 0
            if query.isEmpty { clearSearch() }
        }
    }

    private func clearSearch() {
        query = ""
        searching = false
        keyboard = true
    }

    private func openHighlighted() {
        guard let target = highlightedTarget else { return }
        detail = target
        clearSearch()
    }

    private func handleKey(_ press: KeyPress) -> KeyPress.Result {
        guard detail == nil, !adding, !monitor.locked, !store.projects.isEmpty, !searching else { return .ignored }
        if press.modifiers.contains(.command) || press.modifiers.contains(.control) { return .ignored }
        let text = press.characters.filter { $0.isLetter || $0.isNumber || $0 == "-" || $0 == "." || $0 == "_" }
        guard !text.isEmpty else { return .ignored }
        query += text
        highlight = 0
        tab = .servers
        DispatchQueue.main.async {
            searching = true
            DispatchQueue.main.async {
                (NSApp.keyWindow?.firstResponder as? NSTextView)?.moveToEndOfDocument(nil)
            }
        }
        return .handled
    }

    private var pageKey: String {
        if let detail { return "server\(detail.project)\(detail.server)\(detail.agent)\(detail.container ?? "")" }
        return adding ? "add" : tab.rawValue
    }

    private var single: Project? {
        store.scope.count == 1 ? store.scope.first : nil
    }

    private func select(_ id: UUID) {
        store.selectedID = id
        store.showsAll = false
        detail = nil
        monitor.refreshIfStale()
    }

    private func selectAll() {
        store.showsAll = true
        detail = nil
        monitor.refreshIfStale()
    }

    private func openAlert(_ item: ProjectAlert) {
        detail = item.serverID.map { DetailTarget(project: item.project.id, server: $0) }
    }

    private func openSettings() {
        actions.showSettings()
    }

    private var apiText: String? {
        guard let limit = monitor.rateLimit else { return nil }
        return "API \((limit.limit - limit.remaining).formatted()) / \(limit.limit.formatted()) /h"
    }
}

private struct ProblemBanner: View {
    let text: String
    let retry: () -> Void

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: "exclamationmark.triangle")
                .foregroundStyle(Theme.orange)
            Text(text)
                .font(.system(size: 12))
                .foregroundStyle(Theme.text)
                .fixedSize(horizontal: false, vertical: true)
            Spacer(minLength: 0)
            Button("Retry", action: retry)
                .buttonStyle(.plain)
                .font(.system(size: 12, weight: .medium))
                .foregroundStyle(Color.accentColor)
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 10)
        .background(Theme.orange.opacity(0.12), in: RoundedRectangle(cornerRadius: 10))
        .overlay(RoundedRectangle(cornerRadius: 10).stroke(Theme.orange.opacity(0.35)))
        .padding(.horizontal, 16)
        .padding(.top, 12)
    }
}

private final class MenuHandler: NSObject {
    var actions: [() -> Void] = []

    @objc func run(_ item: NSMenuItem) {
        actions[item.tag]()
    }
}

private struct RefreshIcon: View {
    let spinning: Bool
    let problem: Bool
    @State private var angle = 0.0
    private static let turn = Duration.milliseconds(800)

    var body: some View {
        Image(systemName: problem ? "exclamationmark.arrow.circlepath" : "arrow.clockwise")
            .font(.system(size: 11, weight: .semibold))
            .foregroundStyle(problem ? Theme.orange : Theme.secondary)
            .rotationEffect(.degrees(angle))
            .task(id: spinning) {
                while spinning, !Task.isCancelled {
                    withAnimation(.linear(duration: 0.8)) { angle += 360 }
                    try? await Task.sleep(for: Self.turn)
                }
            }
    }
}
