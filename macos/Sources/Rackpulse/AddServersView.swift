import SwiftUI

struct OnboardingView: View {
    let monitor: Monitor
    let canCancel: Bool
    var agentProject: UUID?
    let done: (Bool) -> Void
    let openAgent: (UUID, Int64) -> Void

    private enum Step { case choose, cloud, agent }

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
        case .cloud:
            CloudProjectForm(store: monitor.store, canCancel: canCancel, back: { step = .choose }, done: done)
        case .agent:
            AgentServerForm(monitor: monitor, project: agentProject, back: agentProject == nil ? { step = .choose } : nil,
                            cancel: canCancel ? { done(false) } : nil, added: openAgent)
        }
    }

    private var chooser: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Add servers").font(.system(size: 15, weight: .semibold))
            option(.cloud, icon: "cloud", title: "Cloud provider",
                   text: "Connect a Hetzner Cloud project with an API token. Rackpulse lists its servers and shows costs, traffic and power controls.")
            option(.agent, icon: "cpu", title: "Server with the agent",
                   text: "Any Linux server: home lab, bare metal or another cloud. Install the Rackpulse agent and pair it by address. No provider account.")
            HStack {
                if canCancel {
                    Button("Cancel") { done(false) }
                        .keyboardShortcut(.cancelAction)
                }
                Spacer()
                Button("Continue") { step = choice }
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
    private var canAdd: Bool { selection != nil || !trimmedProject.isEmpty }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            VStack(alignment: .leading, spacing: 8) {
                FormTitle(text: "Add a server with the agent", back: back)
                Text("Next you choose how this Mac reaches the server and get the install command. The name, OS, cores, memory and disk come from the agent after pairing.")
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
                TextField("Optional, the server's hostname by default", text: $serverName)
                    .textFieldStyle(.roundedBorder)
            }

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
        let name = serverName.trimmingCharacters(in: .whitespacesAndNewlines)
        if !name.isEmpty {
            monitor.store.updateHost(id, host) { $0.name = name }
            monitor.refreshHosts(id, poll: false)
        }
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
