import AppKit
import SwiftUI

struct AboutPage: View {
    let updates: Updates

    private static let links: [(title: String, symbol: String, url: String)] = [
        ("Website", "globe", "https://rackpulse.app"),
        ("Discord", "bubble.left.and.bubble.right.fill", "https://discord.gg/s4AzG5sc36"),
        ("X", "at", "https://x.com/en3sis"),
    ]

    var body: some View {
        Form {
            Section {
                VStack(spacing: 6) {
                    Image(nsImage: NSApp.applicationIconImage)
                        .resizable()
                        .frame(width: 96, height: 96)
                        .padding(.bottom, 8)
                    HStack(spacing: 6) {
                        Text(Flavor.name).font(.system(size: 22, weight: .semibold))
                        if Flavor.isDev { DevTag() }
                    }
                    Text(Flavor.isDev ? "Version \(Updates.version) (\(Flavor.commit))" : "Version \(Updates.version)")
                        .font(.system(size: 12)).foregroundStyle(.secondary)
                    Text("A menu bar app for your servers.\nNo account, no analytics, no telemetry.")
                        .font(.system(size: 13))
                        .foregroundStyle(.secondary)
                        .multilineTextAlignment(.center)
                        .padding(.top, 10)
                    Text("Questions, bugs, and ideas are welcome.")
                        .font(.system(size: 12))
                        .foregroundStyle(.secondary)
                        .padding(.top, 14)
                    HStack(spacing: 8) {
                        ForEach(Self.links, id: \.title) { link in
                            Button {
                                if let url = URL(string: link.url) { NSWorkspace.shared.open(url) }
                            } label: {
                                Label(link.title, systemImage: link.symbol)
                            }
                            .controlSize(.large)
                        }
                    }
                    .padding(.top, 4)
                    Text("MIT licence. Not affiliated with any hosting provider.")
                        .font(.system(size: 11))
                        .foregroundStyle(.tertiary)
                        .padding(.top, 14)
                }
                .frame(maxWidth: .infinity)
                .padding(.vertical, 18)
            }

            Section {
                if updates.isAvailable {
                    Toggle("Check for updates automatically", isOn: Binding(
                        get: { updates.checksAutomatically },
                        set: { updates.setChecksAutomatically($0) }
                    ))
                    LabeledContent("Last checked") {
                        Text(updates.lastCheck.map { $0.formatted(date: .abbreviated, time: .shortened) } ?? "Never")
                    }
                    HStack {
                        Spacer()
                        Button("Check for Updates…") { updates.check() }
                    }
                } else {
                    Text(Flavor.isDev ? "Rackpulse Dev does not update itself. Run make dev-build for a new build." : "Updates are off in development builds.").foregroundStyle(.secondary)
                }
            } header: {
                Text("Updates")
            } footer: {
                Text("Rackpulse checks once a day and asks before it installs anything. Every update is signed and notarized by Apple.")
                    .foregroundStyle(.secondary)
            }
        }
        .formStyle(.grouped)
        .onAppear { updates.refresh() }
    }
}
