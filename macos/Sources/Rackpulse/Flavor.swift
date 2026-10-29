import SwiftUI

enum Flavor {
    private static func value(_ key: String) -> String? {
        Bundle.main.object(forInfoDictionaryKey: key) as? String
    }

    static let isDev = value("RackpulseFlavor") == "dev"
    static let name = isDev ? "Rackpulse Dev" : "Rackpulse"
    static let commit = value("RackpulseCommit") ?? ""
    static let agentURL = value("RackpulseAgentURL") ?? "https://rackpulse.app/agent"
    static let keychainSuffix = isDev ? ".dev" : ""
}

struct DevTag: View {
    var body: some View {
        Text("DEV")
            .font(.system(size: 9, weight: .heavy))
            .foregroundStyle(.white)
            .padding(.horizontal, 5)
            .padding(.vertical, 2)
            .background(Capsule().fill(Theme.orange))
            .help("Rackpulse Dev \(Updates.version) (\(Flavor.commit))")
    }
}
