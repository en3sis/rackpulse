import SwiftUI

struct OnboardingView: View {
    let monitor: Monitor
    let canCancel: Bool
    var agentProject: UUID?
    let done: (Bool) -> Void
    let openAgent: (UUID, Int64) -> Void

    private enum Step { case choose, providers, cloud, agent }

    @State private var step: Step
    @State private var choice = Step.cloud

    init(monitor: Monitor, canCancel: Bool, agentProject: UUID? = nil, done: @escaping (Bool) -> Void,
         openAgent: @escaping (UUID, Int64) -> Void) {
        self.monitor = monitor
        self.canCancel = canCancel
        self.agentProject = agentProject
        self.done = done
        self.openAgent = openAgent
        _step = State(initialValue: agentProject == nil ? .choose : .agent)
    }

    var body: some View {
        switch step {
        case .choose: chooser
        case .providers:
            ProviderPicker(cancel: canCancel ? { done(false) } : nil, back: { step = .choose }, next: { step = .cloud })
        case .cloud:
            CloudProjectForm(store: monitor.store, canCancel: canCancel, back: { step = .providers }, done: done)
        case .agent:
            AgentServerForm(monitor: monitor, project: agentProject, back: agentProject == nil ? { step = .choose } : nil,
                            cancel: canCancel ? { done(false) } : nil, added: openAgent)
        }
    }

    private var chooser: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Add servers").font(.system(size: 15, weight: .semibold))
            option(.cloud, icon: "cloud", title: "Cloud provider",
                   text: "Connect a cloud project with an API token. Rackpulse lists its servers and shows costs, traffic and power controls.")
            option(.agent, icon: "cpu", title: "Server with the agent",
                   text: "Any Linux server: home lab, bare metal or another cloud. Install the Rackpulse agent and pair it by address. No provider account.")
            HStack {
                if canCancel {
                    Button("Cancel") { done(false) }
                        .keyboardShortcut(.cancelAction)
                }
                Spacer()
                Button("Continue") { step = choice == .cloud ? .providers : choice }
                    .buttonStyle(.borderedProminent)
                    .keyboardShortcut(.defaultAction)
            }
        }
        .controlSize(.large)
        .padding(18)
    }

    private func option(_ value: Step, icon: String, title: String, text: String) -> some View {
        let selected = choice == value
        return Button { choice = value } label: {
            HStack(alignment: .top, spacing: 10) {
                Image(systemName: icon)
                    .font(.system(size: 17, weight: .medium))
                    .foregroundStyle(Color.accentColor)
                    .frame(width: 22)
                VStack(alignment: .leading, spacing: 4) {
                    Text(title).font(.system(size: 13, weight: .semibold))
                    Text(text)
                        .font(.system(size: 11))
                        .foregroundStyle(Theme.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                Spacer(minLength: 0)
                Image(systemName: selected ? "largecircle.fill.circle" : "circle")
                    .foregroundStyle(selected ? Color.accentColor : Theme.secondary)
            }
            .padding(12)
            .background(Theme.card, in: RoundedRectangle(cornerRadius: 10))
            .overlay(RoundedRectangle(cornerRadius: 10).stroke(selected ? Color.accentColor : .clear, lineWidth: 1.5))
            .contentShape(RoundedRectangle(cornerRadius: 10))
        }
        .buttonStyle(.plain)
    }
}

struct CloudService: Identifiable {
    let name: String
    let logo: String?
    let color: Color
    let available: Bool

    var id: String { name }

    static let all = [
        CloudService(name: "Hetzner Cloud", logo: "M0 0v24h24V0H0zm4.602 4.025h2.244c.509 0 .716.215.716.717v5.64h8.883v-5.64c0-.509.215-.717.717-.717h2.229c.5 0 .71.23.724.717v14.516c0 .509-.215.717-.717.717h-2.23c-.51 0-.717-.215-.717-.717v-5.735H7.562v5.735c0 .516-.215.717-.716.717H4.602c-.51 0-.717-.208-.717-.717V4.742c0-.509.207-.717.717-.717z",
                     color: Color(red: 0.835, green: 0.047, blue: 0.176), available: true),
        CloudService(name: "AWS", logo: nil, color: .primary, available: false),
        CloudService(name: "DigitalOcean", logo: "M12.04 0C5.408-.02.005 5.37.005 11.992h4.638c0-4.923 4.882-8.731 10.064-6.855a6.95 6.95 0 014.147 4.148c1.889 5.177-1.924 10.055-6.84 10.064v-4.61H7.391v4.623h4.61V24c7.86 0 13.967-7.588 11.397-15.83-1.115-3.59-3.985-6.446-7.575-7.575A12.8 12.8 0 0012.039 0zM7.39 19.362H3.828v3.564H7.39zm-3.563 0v-2.978H.85v2.978z",
                     color: Color(red: 0, green: 0.502, blue: 1), available: false),
        CloudService(name: "Railway", logo: "M.113 10.27A13.026 13.026 0 000 11.48h18.23c-.064-.125-.15-.237-.235-.347-3.117-4.027-4.793-3.677-7.19-3.78-.8-.034-1.34-.048-4.524-.048-1.704 0-3.555.005-5.358.01-.234.63-.459 1.24-.567 1.737h9.342v1.216H.113v.002zm18.26 2.426H.009c.02.326.05.645.094.961h16.955c.754 0 1.179-.429 1.315-.96zm-17.318 4.28s2.81 6.902 10.93 7.024c4.855 0 9.027-2.883 10.92-7.024H1.056zM11.988 0C7.5 0 3.593 2.466 1.531 6.108l4.75-.005v-.002c3.71 0 3.849.016 4.573.047l.448.016c1.563.052 3.485.22 4.996 1.364.82.621 2.007 1.99 2.712 2.965.654.902.842 1.94.396 2.934-.408.914-1.289 1.458-2.353 1.458H.391s.099.42.249.886h22.748A12.026 12.026 0 0024 12.005C24 5.377 18.621 0 11.988 0z",
                     color: .primary, available: false),
    ]
}

struct ProviderPicker: View {
    var cancel: (() -> Void)?
    let back: () -> Void
    let next: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            FormTitle(text: "Choose a provider", back: back)
            Text("More providers are on the way.")
                .font(.system(size: 12))
                .foregroundStyle(Theme.secondary)
            LazyVGrid(columns: [GridItem(.flexible(), spacing: 10), GridItem(.flexible(), spacing: 10)], spacing: 10) {
                ForEach(CloudService.all) { card($0) }
            }
            HStack {
                if let cancel {
                    Button("Cancel", action: cancel)
                        .keyboardShortcut(.cancelAction)
                }
                Spacer()
                Button("Continue", action: next)
                    .buttonStyle(.borderedProminent)
                    .keyboardShortcut(.defaultAction)
            }
        }
        .controlSize(.large)
        .padding(18)
    }

    private func card(_ service: CloudService) -> some View {
        Button(action: next) {
            VStack(spacing: 8) {
                ProviderLogo(svgPath: service.logo, size: 30)
                    .foregroundStyle(service.available ? service.color : Theme.secondary)
                    .opacity(service.available ? 1 : 0.6)
                    .frame(height: 34)
                Text(service.name)
                    .font(.system(size: 12, weight: .semibold))
                    .foregroundStyle(service.available ? Theme.text : Theme.secondary)
                Text(service.available ? "Available" : "Coming soon")
                    .font(.system(size: 10, weight: .medium))
                    .foregroundStyle(service.available ? Color.accentColor : Theme.secondary)
                    .padding(.horizontal, 7)
                    .padding(.vertical, 2)
                    .background(service.available ? Color.accentColor.opacity(0.12) : Theme.card, in: Capsule())
            }
            .frame(maxWidth: .infinity)
            .padding(.vertical, 14)
            .background(Theme.card, in: RoundedRectangle(cornerRadius: 10))
            .overlay(RoundedRectangle(cornerRadius: 10).stroke(service.available ? Color.accentColor : .clear, lineWidth: 1.5))
            .contentShape(RoundedRectangle(cornerRadius: 10))
        }
        .buttonStyle(.plain)
        .disabled(!service.available)
        .accessibilityLabel(service.available ? service.name : "\(service.name), coming soon")
    }
}

struct ProviderLogo: View {
    let svgPath: String?
    let size: CGFloat

    @MainActor private static var cache: [String: NSImage] = [:]

    var body: some View {
        if let image = svgPath.flatMap(Self.image) {
            Image(nsImage: image)
                .renderingMode(.template)
                .resizable()
                .interpolation(.high)
                .frame(width: size, height: size)
        } else {
            Image(systemName: "cloud.fill")
                .font(.system(size: size * 0.75))
                .frame(width: size, height: size)
        }
    }

    @MainActor private static func image(_ path: String) -> NSImage? {
        if let cached = cache[path] { return cached }
        let svg = "<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 24 24\"><path d=\"\(path)\"/></svg>"
        guard let image = NSImage(data: Data(svg.utf8)) else { return nil }
        image.isTemplate = true
        cache[path] = image
        return image
    }
}

struct AgentServerForm: View {
    let monitor: Monitor
    var project: UUID?
    var back: (() -> Void)?
    var cancel: (() -> Void)?
    let added: (UUID, Int64) -> Void

    @State private var selection: UUID?
    @State private var projectName = ""
    @State private var serverName = ""

    private var agentProjects: [Project] { monitor.store.projects.filter { !$0.hasAPI } }
    private var trimmedProject: String { projectName.trimmingCharacters(in: .whitespacesAndNewlines) }
    private var canAdd: Bool { (selection != nil || !trimmedProject.isEmpty) && !trimmedServer.isEmpty }
    private var trimmedServer: String { serverName.trimmingCharacters(in: .whitespacesAndNewlines) }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            VStack(alignment: .leading, spacing: 8) {
                FormTitle(text: "Add a server with the agent", back: back)
                Text("Next you get the install command. Rackpulse finds the server by its name and pairs as soon as the agent runs. OS, cores, memory and disk come from the agent.")
                    .font(.system(size: 12))
                    .foregroundStyle(Theme.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }

            field("Project") {
                Picker("Project", selection: $selection) {
                    ForEach(agentProjects) { project in
                        Text(project.name).tag(UUID?.some(project.id))
                    }
                    if !agentProjects.isEmpty { Divider() }
                    Text("New project").tag(UUID?.none)
                }
                .labelsHidden()
            }
            if selection == nil {
                field("Project name") {
                    TextField("Home lab", text: $projectName)
                        .textFieldStyle(.roundedBorder)
                }
            }
            field("Server name") {
                TextField("web-1", text: $serverName)
                    .textFieldStyle(.roundedBorder)
            }
            Text("Its name in Tailscale or on your network, usually its hostname.")
                .font(.system(size: 11))
                .foregroundStyle(Theme.secondary)

            HStack {
                if let cancel {
                    Button("Cancel", action: cancel)
                        .keyboardShortcut(.cancelAction)
                }
                Spacer()
                Button("Continue", action: add)
                    .buttonStyle(.borderedProminent)
                    .disabled(!canAdd)
                    .keyboardShortcut(.defaultAction)
            }
        }
        .controlSize(.large)
        .padding(18)
        .onAppear { selection = project ?? agentProjects.first?.id }
    }

    private func field(_ title: String, @ViewBuilder input: () -> some View) -> some View {
        VStack(alignment: .leading, spacing: 5) {
            Text(title).font(.system(size: 11)).foregroundStyle(Theme.secondary)
            input()
        }
    }

    private func add() {
        let id: UUID
        if let selection {
            id = selection
        } else {
            id = monitor.store.addAgentProject(name: trimmedProject).id
            monitor.projectChanged()
        }
        guard let host = monitor.addHost(to: id) else { return }
        monitor.store.updateHost(id, host) { $0.name = trimmedServer }
        monitor.refreshHosts(id, poll: false)
        monitor.store.selectedID = id
        added(id, host)
    }
}

struct FormTitle: View {
    let text: String
    var back: (() -> Void)?

    var body: some View {
        HStack(spacing: 8) {
            if let back {
                Button(action: back) {
                    Image(systemName: "chevron.left")
                        .font(.system(size: 12, weight: .semibold))
                        .frame(width: 24, height: 24)
                        .background(Theme.card, in: RoundedRectangle(cornerRadius: 6))
                        .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
                .accessibilityLabel("Back")
            }
            Text(text).font(.system(size: 15, weight: .semibold))
        }
    }
}
