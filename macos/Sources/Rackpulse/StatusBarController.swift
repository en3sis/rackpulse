import AppKit
import Observation
import SwiftUI

@MainActor
@Observable
final class AppActions {
    var showSettings: () -> Void = {}
    var openPanel: () -> Void = {}
    var resize: (CGFloat) -> Void = { _ in }
    var route: PanelRoute?
    var screenHeight: CGFloat = 800
    var chartRange: MetricRange?
    var opened = 0
    var visible = false
    var shortcutChanged: () -> Void = {}
}

enum PanelRoute: Equatable {
    case servers
    case costs
    case server(UUID, Int64, MetricRange)
    case agent(UUID, Int64)
    case serverTab(UUID, Int64, ServerTab)
    case container(UUID, Int64, String)
    case addProject
    case addServer(UUID)
}

@MainActor
final class StatusBarController: NSObject {
    private let item = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
    let panel = MenuPanel()
    private let hosting: NSHostingView<AnyView>
    private var height: CGFloat = 420
    private let monitor: Monitor
    private let store: ProjectStore
    private let actions: AppActions
    private var clickMonitor: Any?
    private var lastResize = Date.distantPast
    private var closedAt = Date.distantPast
    private var mouseUpMonitor: Any?
    private var pendingFit: DispatchWorkItem?
    private static let settleDelay: TimeInterval = 0.12

    private static let width: CGFloat = 390

    init(store: ProjectStore, monitor: Monitor, updates: Updates, actions: AppActions) {
        self.store = store
        self.monitor = monitor
        self.actions = actions
        hosting = NSHostingView(rootView: AnyView(
            PopoverView(store: store, monitor: monitor, updates: updates)
                .environment(actions)
                .environment(\.controlActiveState, .key)
        ))
        super.init()

        hosting.sizingOptions = []

        hosting.autoresizingMask = [.width, .height]
        panel.contentView = Self.background(around: hosting)

        if let button = item.button {
            button.target = self
            button.action = #selector(toggle)
            button.sendAction(on: [.leftMouseDown, .rightMouseDown])
            button.toolTip = Flavor.name
        }
        actions.openPanel = { [weak self] in self?.show() }
        panel.onCancel = { [weak self] in self?.close() }
        NotificationCenter.default.addObserver(forName: NSWindow.didResizeNotification, object: panel, queue: .main) { [weak self] _ in
            MainActor.assumeIsolated { self?.layoutContent() }
        }
        NotificationCenter.default.addObserver(forName: NSWindow.didBecomeKeyNotification, object: nil, queue: .main) { [weak self] note in
            let window = (note.object as AnyObject?).map(ObjectIdentifier.init)
            MainActor.assumeIsolated {
                guard let self, let window, window != ObjectIdentifier(self.panel) else { return }
                if let icon = self.item.button?.window, window == ObjectIdentifier(icon) { return }
                self.close()
            }
        }
        actions.resize = { [weak self] height in self?.requestFit(height) }
        trackIcon()
    }

    private static let cornerRadius: CGFloat = 16

    private static func background(around content: NSView) -> NSView {
        let container = NSView()
        container.wantsLayer = true
        container.layer?.cornerRadius = cornerRadius
        container.layer?.cornerCurve = .continuous
        container.layer?.masksToBounds = true
        let backdrop = NSVisualEffectView()
        backdrop.material = .menu
        backdrop.blendingMode = .behindWindow
        backdrop.state = .active
        backdrop.autoresizingMask = [.width, .height]
        content.autoresizingMask = [.width, .height]
        container.addSubview(backdrop)
        container.addSubview(content)
        return container
    }

    @objc func toggle() {
        if panel.isVisible {
            close()
        } else if Date.now.timeIntervalSince(closedAt) > 0.3 {
            show()
        }
    }

    func show() {
        guard let frame = placement(height: height) else { return }
        panel.setFrame(frame, display: true)
        layoutContent()
        actions.opened += 1
        actions.visible = true
        panel.makeKeyAndOrderFront(nil)
        item.button?.highlight(true)
        DispatchQueue.main.async { [weak self] in self?.keepHighlight() }
        mouseUpMonitor = NSEvent.addLocalMonitorForEvents(matching: [.leftMouseUp, .rightMouseUp]) { [weak self] event in
            DispatchQueue.main.async {
                self?.keepHighlight()
                if let monitor = self?.mouseUpMonitor { NSEvent.removeMonitor(monitor) }
                self?.mouseUpMonitor = nil
            }
            return event
        }
        monitor.refreshIfStale()
        clickMonitor = NSEvent.addGlobalMonitorForEvents(matching: [.leftMouseDown, .rightMouseDown]) { [weak self] _ in
            MainActor.assumeIsolated { self?.close() }
        }
    }

    private func keepHighlight() {
        guard panel.isVisible else { return }
        item.button?.highlight(true)
    }

    func close() {
        if panel.isVisible { closedAt = .now }
        panel.orderOut(nil)
        actions.visible = false
        item.button?.highlight(false)
        if let clickMonitor { NSEvent.removeMonitor(clickMonitor) }
        clickMonitor = nil
    }

    var statusButton: NSView? { item.button }

    var frames: String {
        let container = panel.contentView
        let parts = (container?.subviews ?? []).map { "\(type(of: $0)) \($0.frame)" }
        return "panel \(panel.frame) reported \(height) container \(container?.frame ?? .zero) " + parts.joined(separator: " | ")
    }

    private func layoutContent() {
        guard let container = panel.contentView else { return }
        let bounds = NSRect(origin: .zero, size: panel.frame.size)
        if container.frame != bounds { container.frame = bounds }
        for view in container.subviews where view.frame != bounds { view.frame = bounds }
        panel.invalidateShadow()
    }

    private func requestFit(_ height: CGFloat) {
        pendingFit?.cancel()
        let now = Date.now
        let settled = now.timeIntervalSince(lastResize) > Self.settleDelay
        lastResize = now
        if settled {
            fit(height: height)
            DispatchQueue.main.async { [weak self] in self?.fit(height: height) }
        } else {
            let work = DispatchWorkItem { [weak self] in self?.fit(height: height) }
            pendingFit = work
            DispatchQueue.main.asyncAfter(deadline: .now() + Self.settleDelay, execute: work)
        }
    }

    private func fit(height: CGFloat) {
        guard height > 0 else { return }
        self.height = height
        guard panel.isVisible, let frame = placement(height: height), frame != panel.frame else { return }
        panel.setFrame(frame, display: true, animate: false)
        layoutContent()
    }

    private func placement(height: CGFloat) -> NSRect? {
        guard let button = item.button, let buttonWindow = button.window, let screen = buttonWindow.screen else { return nil }
        let anchor = buttonWindow.convertToScreen(button.convert(button.bounds, to: nil))
        var visible = screen.visibleFrame
        if let limit = ProcessInfo.processInfo.environment["RACKPULSE_SCREEN_HEIGHT"].flatMap(Double.init) {
            visible.origin.y = visible.maxY - limit
            visible.size.height = limit
        }
        actions.screenHeight = visible.height
        let top = min(anchor.minY - 5, visible.maxY)
        let fitted = min(height, top - visible.minY - 8).rounded()
        let x = min(max(anchor.midX - Self.width / 2, visible.minX + 8), visible.maxX - Self.width - 8)
        return NSRect(x: x.rounded(), y: top - fitted, width: Self.width, height: fitted)
    }

    private func trackIcon() {
        withObservationTracking {
            guard let button = item.button else { return }
            button.image = StatusIcon.image(dot: store.projects.isEmpty ? nil : monitor.menuDot)
            let text = store.projects.isEmpty ? "" : monitor.readoutText
            button.imagePosition = text.isEmpty ? .imageOnly : .imageLeading
            button.attributedTitle = NSAttributedString(string: text.isEmpty ? "" : " \(text)", attributes: [
                .font: NSFont.monospacedDigitSystemFont(ofSize: 13, weight: .medium),
                .baselineOffset: 0.5,
            ])
        } onChange: { [weak self] in
            Task { @MainActor in self?.trackIcon() }
        }
    }
}

final class MenuPanel: NSPanel {
    init() {
        super.init(contentRect: .zero, styleMask: [.borderless, .nonactivatingPanel], backing: .buffered, defer: false)
        isFloatingPanel = true
        level = .popUpMenu
        hasShadow = true
        backgroundColor = .clear
        isOpaque = false
        hidesOnDeactivate = false
        isReleasedWhenClosed = false
        collectionBehavior = [.canJoinAllSpaces, .fullScreenAuxiliary, .transient]
    }

    var onCancel: (() -> Void)?

    override var canBecomeKey: Bool { true }

    override func cancelOperation(_ sender: Any?) {
        onCancel?()
    }
}

@MainActor
final class SettingsWindow {
    private(set) var window: NSWindow?
    private let makeView: () -> AnyView

    init(makeView: @escaping () -> AnyView) {
        self.makeView = makeView
    }

    func show() {
        if window == nil {
            let controller = NSHostingController(rootView: makeView())
            controller.sceneBridgingOptions = [.toolbars, .title]
            let window = NSWindow(contentViewController: controller)
            window.title = "Rackpulse Settings"
            window.styleMask = [.titled, .closable, .miniaturizable, .resizable, .fullSizeContentView]
            window.toolbar = NSToolbar()
            window.toolbarStyle = .unified
            let visible = NSScreen.main?.visibleFrame.size ?? NSSize(width: 1_440, height: 900)
            window.setContentSize(NSSize(width: min(880, visible.width - 80), height: min(680, visible.height - 80)))
            window.isReleasedWhenClosed = false
            window.center()
            self.window = window
        }
        NSApp.activate()
        window?.makeKeyAndOrderFront(nil)
    }
}
