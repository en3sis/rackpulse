import Foundation
import Observation
import Sparkle

@MainActor
@Observable
final class Updates {
    static let version = Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "0.0.0"
    static let isDev = ProcessInfo.processInfo.environment["RACKPULSE_DEV"] != nil

    @ObservationIgnored private let controller: SPUStandardUpdaterController?
    private(set) var lastCheck: Date?
    private(set) var checksAutomatically = false

    var isAvailable: Bool { controller != nil }

    init() {
        let key = Bundle.main.object(forInfoDictionaryKey: "SUPublicEDKey") as? String ?? ""
        guard !Self.isDev, !Flavor.isDev, !key.isEmpty else {
            controller = nil
            return
        }
        controller = SPUStandardUpdaterController(startingUpdater: true, updaterDelegate: nil, userDriverDelegate: nil)
        refresh()
    }

    func check() {
        controller?.checkForUpdates(nil)
        refresh()
    }

    func setChecksAutomatically(_ value: Bool) {
        controller?.updater.automaticallyChecksForUpdates = value
        refresh()
    }

    func refresh() {
        guard let updater = controller?.updater else { return }
        lastCheck = updater.lastUpdateCheckDate
        checksAutomatically = updater.automaticallyChecksForUpdates
    }
}
