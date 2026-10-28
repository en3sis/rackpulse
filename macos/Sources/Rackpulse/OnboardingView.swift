import HetznerKit
import SwiftUI

struct CloudProjectForm: View {
    let store: ProjectStore
    let canCancel: Bool
    var back: (() -> Void)?
    let done: (Bool) -> Void

    @State private var name = ""
    @State private var token = ""
    @State private var checking = false
    @State private var message: String?

    private var trimmedToken: String { token.trimmingCharacters(in: .whitespacesAndNewlines) }
    private var trimmedName: String { name.trimmingCharacters(in: .whitespacesAndNewlines) }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            VStack(alignment: .leading, spacing: 8) {
                FormTitle(text: "Add a cloud project", back: back)
                HStack(spacing: 6) {
                    Text("Provider").foregroundStyle(Theme.secondary)
                    Text("Hetzner Cloud").fontWeight(.medium)
                }
                .font(.system(size: 12))
                Text("Rackpulse needs an API token for each project.")
                    .font(.system(size: 12))
                    .foregroundStyle(Theme.secondary)
                VStack(alignment: .leading, spacing: 4) {
                    step(1, "Open the project in the Hetzner Console.")
                    step(2, "Go to Security, then API tokens, then Generate API token.")
                    step(3, "Choose the permission and copy the token.")
                }
                AccessComparison()
                HStack(spacing: 16) {
                    Link(destination: URL(string: "https://console.hetzner.com/projects")!) {
                        Label("Hetzner Console", systemImage: "arrow.up.right.square")
                    }
                    Link(destination: URL(string: "https://docs.hetzner.com/cloud/api/getting-started/generating-api-token")!) {
                        Label("How to create a token", systemImage: "book")
                    }
                }
                .font(.system(size: 12, weight: .medium))
            }

            field("Project name") {
                TextField("Production", text: $name)
            }
            field("API token") {
                SecureField("Paste the token", text: $token)
            }

            if let message {
                Text(message)
                    .font(.system(size: 12))
                    .foregroundStyle(Theme.red)
                    .fixedSize(horizontal: false, vertical: true)
            }

            HStack {
                if canCancel {
                    Button("Cancel") { done(false) }
                        .keyboardShortcut(.cancelAction)
                }
                Spacer()
                if checking { ProgressView().controlSize(.small) }
                Button(checking ? "Checking token…" : "Verify and Save", action: verify)
                    .buttonStyle(.borderedProminent)
                    .disabled(!canSubmit)
                .keyboardShortcut(.defaultAction)
            }

            Text("Rackpulse checks what the token can do before saving it, and stores it in your Keychain only. You can replace it later in Settings.")
                .font(.system(size: 11))
                .foregroundStyle(Theme.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
        .controlSize(.large)
        .padding(18)
    }

    private var canSubmit: Bool { !checking && !trimmedName.isEmpty && !trimmedToken.isEmpty }

    private func step(_ number: Int, _ text: String) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 6) {
            Text("\(number).").foregroundStyle(Theme.secondary)
            Text(text).fixedSize(horizontal: false, vertical: true)
        }
        .font(.system(size: 12))
    }

    private func field(_ title: String, @ViewBuilder input: () -> some View) -> some View {
        VStack(alignment: .leading, spacing: 5) {
            Text(title).font(.system(size: 11)).foregroundStyle(Theme.secondary)
            input()
                .textFieldStyle(.roundedBorder)
        }
    }

    private func verify() {
        let token = trimmedToken
        let name = trimmedName
        checking = true
        message = nil
        Task {
            let check = await TokenVerifier(client: HetznerClient(api: .cloud, token: token)).verify()
            checking = false
            guard check.isAccepted else {
                message = check.explanation
                return
            }
            do {
                try store.add(name: name, token: token, access: check.access ?? .readOnly)
                done(true)
            } catch {
                message = "The token could not be saved to the Keychain."
            }
        }
    }
}

struct AccessComparison: View {
    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            option(
                icon: "eye", title: "Read",
                text: "Status, metrics, costs and alerts. Rackpulse can't change anything."
            )
            option(
                icon: "power", title: "Read & Write",
                text: "Also start, shut down, reboot and power off servers from Rackpulse. Each action asks you to confirm."
            )
        }
        .padding(10)
        .background(Theme.card, in: RoundedRectangle(cornerRadius: 9))
    }

    private func option(icon: String, title: String, text: String) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 8) {
            Image(systemName: icon).foregroundStyle(Color.accentColor).frame(width: 16)
            VStack(alignment: .leading, spacing: 1) {
                Text(title).font(.system(size: 12, weight: .semibold))
                Text(text).font(.system(size: 11)).foregroundStyle(Theme.secondary).fixedSize(horizontal: false, vertical: true)
            }
        }
    }
}
