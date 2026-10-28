import AppKit
import HetznerKit
import SwiftUI

enum AgentRoute: Hashable {
    case tailscale, privateNetwork, publicIP, other

    static let options: [(AgentRoute, String)] = [
        (.tailscale, "Tailscale"), (.privateNetwork, "Private"), (.publicIP, "Public IP"), (.other, "Other"),
    ]
}

struct AgentSetupView: View {
    let server: Server
    let project: Project
    let monitor: Monitor
    let firewalls: [Int64: String]
    let back: () -> Void

    @State private var route: AgentRoute = .publicIP
    @State private var publicAddress: AgentAddress = .publicIPv4
    @State private var tailnetHost = ""
    @State private var custom = ""
    @State private var port = String(AgentEndpoint.defaultPort)
    @State private var copied: String?
    @State private var tries = 0
    @State private var showsFacts = false
    @State private var editing = false
    @State private var removing = false
    @State private var onlyThisMac = false
    @State private var macAddress: String?
    @State private var lookingUp = false
    @State private var macOnTailscale = MacNetwork.onTailscale

    private var store: AgentStore { monitor.agents }
    private var link: AgentLink? { store.link(project.id, server.id) }
    private var state: AgentState? { store.state(project.id, server.id) }
    private var paired: Bool { link?.isPaired == true }
    private var portNumber: Int { Int(port).flatMap { (1...65_535).contains($0) ? $0 : nil } ?? AgentEndpoint.defaultPort }
    private var publicAddresses: [AgentAddress] { [.publicIPv4, .publicIPv6].filter { $0.host(for: server) != nil } }
    private var stuck: Bool { !paired && tries >= 10 && state?.problem != nil }

    private var agentOnly: Bool { !project.hasAPI }

    private var address: AgentAddress {
        if agentOnly, route == .publicIP { return custom.contains(":") ? .publicIPv6 : .publicIPv4 }
        return switch route {
        case .tailscale: .tailscale
        case .privateNetwork: .privateNetwork
        case .publicIP: publicAddress
        case .other: .custom
        }
    }

    private var host: String {
        if agentOnly, route == .publicIP || route == .privateNetwork { return custom.trimmingCharacters(in: .whitespaces) }
        return switch route {
        case .tailscale: tailnetHost.trimmingCharacters(in: .whitespaces)
        case .other: custom.trimmingCharacters(in: .whitespaces)
        case .privateNetwork, .publicIP: address.host(for: server) ?? ""
        }
    }

    private var command: String? {
        guard !host.isEmpty else { return nil }
        return store.installCommand(project.id, server.id, address: address, host: host, port: portNumber)
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            header
            if paired && !editing {
                connected
            } else {
                setup
            }
            Color.clear.frame(height: 14)
        }
        .padding(.horizontal, 16)
        .onExitCommand(perform: back)
        .onAppear(perform: load)
        .onChange(of: route) { save() }
        .onChange(of: publicAddress) { save() }
        .onChange(of: tailnetHost) { save() }
        .onChange(of: custom) { save() }
        .onChange(of: port) { save() }
        .onChange(of: onlyThisMac) { lookUpMac() }
        .onChange(of: paired) { if agentOnly && paired { monitor.refreshHosts(project.id) } }
        .task(id: link?.endpoint) {
            tries = 0
            while !Task.isCancelled, link.map({ !$0.isPaired }) ?? false {
                await store.tryPair(project.id, server: server.id)
                tries += 1
                macOnTailscale = MacNetwork.onTailscale
                try? await Task.sleep(for: .seconds(3))
            }
        }
    }

    private var header: some View {
        HStack(spacing: 10) {
            Button(action: back) {
                Image(systemName: "chevron.left")
                    .font(.system(size: 12, weight: .semibold))
                    .frame(width: 28, height: 28)
                    .background(Theme.card, in: RoundedRectangle(cornerRadius: 7))
                    .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .accessibilityLabel("Back to \(server.name)")
            .keyboardShortcut("[", modifiers: .command)
            VStack(alignment: .leading, spacing: 1) {
                Text(paired ? (editing ? "Change address" : "Agent") : "Set up the agent")
                    .font(.system(size: 14, weight: .semibold))
                Text(server.name).font(.system(size: 12)).foregroundStyle(Theme.secondary).lineLimit(1)
            }
            Spacer(minLength: 0)
            if paired && !editing {
                if state?.problem == nil {
                    badge("Connected", Theme.green)
                } else {
                    badge("Not answering", Theme.orange)
                }
            } else if stuck {
                badge("Not reachable", Theme.orange)
            }
        }
        .padding(.top, 14)
    }

    private func badge(_ text: String, _ color: Color) -> some View {
        HStack(spacing: 5) {
            Circle().fill(color).frame(width: 6, height: 6)
            Text(text).font(.system(size: 11, weight: .medium))
        }
        .padding(.horizontal, 8)
        .padding(.vertical, 3)
        .background(color.opacity(0.14), in: Capsule())
    }

    @ViewBuilder
    private var setup: some View {
        if !paired {
            Text(agentOnly
                 ? "The agent reports memory, disk space, Docker containers and 30 days of uptime. It is read-only and changes nothing on the server."
                 : "Adds memory, disk space, Docker containers and 30 days of uptime. The agent is read-only, and Rackpulse works without it.")
                .font(.system(size: 12))
                .foregroundStyle(Theme.secondary)
                .fixedSize(horizontal: false, vertical: true)
                .padding(.top, 10)
            facts.padding(.top, 8)
        }
        title("How this Mac reaches \(server.name)")
        SegmentedControl(selection: $route, options: AgentRoute.options)
        routeDetails.padding(.top, 10)
        if let command {
            if route == .publicIP {
                title("Allow the port")
                if agentOnly {
                    card {
                        caption("Allow TCP \(portNumber) in the server's firewall, and in your provider's firewall if it has one. Allow only this Mac's address if you can.")
                    }
                } else {
                    firewallCard
                }
            }
            title("Run on the server")
            code(command, masked: true)
            Text(commandNote)
                .font(.system(size: 11))
                .foregroundStyle(Theme.secondary)
                .fixedSize(horizontal: false, vertical: true)
                .padding(.top, 6)
        }
        if editing {
            HStack(spacing: 8) {
                Spacer(minLength: 0)
                Button("Cancel") { editing = false }
                Button("Use this address") {
                    store.move(project.id, server.id, address: address, host: host, port: portNumber)
                    editing = false
                }
                .buttonStyle(.borderedProminent)
                .disabled(host.isEmpty)
            }
            .controlSize(.small)
            .padding(.top, 14)
        } else if link != nil {
            waiting.padding(.top, 14)
            if stuck, let problem = state?.problem, let link { checks(problem, link) }
        }
        if !editing {
            HStack {
                Spacer(minLength: 0)
                Button(role: .destructive) {
                    store.remove(project.id, server.id)
                    if agentOnly { monitor.removeHost(project.id, server.id) }
                    back()
                } label: {
                    Text(agentOnly ? "Remove server" : "Cancel setup").foregroundStyle(Theme.red)
                }
                .controlSize(.small)
            }
            .padding(.top, 14)
        }
    }

    @ViewBuilder
    private var routeDetails: some View {
        if agentOnly, route == .publicIP || route == .privateNetwork {
            card {
                field("Address") {
                    TextField(route == .publicIP ? "203.0.113.10" : "10.0.0.5", text: $custom).frame(width: 200)
                }
                field("Port") { portField }
                caption(route == .publicIP
                        ? "The server's public IPv4 or IPv6 address."
                        : "Your Mac must reach this address, for example through a VPN.")
            }
        } else {
            routeOptions
        }
    }

    @ViewBuilder
    private var routeOptions: some View {
        switch route {
        case .tailscale:
            card {
                if macOnTailscale {
                    notice("checkmark.circle.fill", Theme.green, "Tailscale is on for this Mac",
                           "The agent listens only on the server's Tailscale address. No cloud firewall rule is needed.")
                } else {
                    notice("exclamationmark.circle.fill", Theme.orange, "Tailscale is not running on this Mac",
                           "Start Tailscale on this Mac. Rackpulse reaches \(server.name) through your tailnet.")
                }
                Divider()
                field("Server") { TextField(server.name, text: $tailnetHost).frame(width: 180) }
                field("Port") { portField }
                caption("Its MagicDNS name or Tailscale IP address.")
            }
        case .privateNetwork:
            card {
                if let ip = AgentAddress.privateNetwork.host(for: server) {
                    field("Address") { Text(ip).font(.system(size: 12, design: .monospaced)).textSelection(.enabled) }
                    field("Port") { portField }
                    caption("Your Mac must reach the private network, for example through a VPN server in it.")
                } else {
                    caption("\(server.name) is not in a private network.")
                }
            }
        case .publicIP:
            card {
                if publicAddresses.isEmpty {
                    caption("\(server.name) has no public IP address.")
                } else {
                    field("Address") {
                        Picker("Address", selection: $publicAddress) {
                            ForEach(publicAddresses) { option in
                                Text("\(option == .publicIPv4 ? "IPv4" : "IPv6")  \(option.host(for: server) ?? "")").tag(option)
                            }
                        }
                        .labelsHidden()
                        .fixedSize()
                    }
                    field("Port") { portField }
                }
            }
        case .other:
            card {
                field("Address") { TextField("10.8.0.5 or web-1.vpn.example", text: $custom).frame(width: 200) }
                field("Port") { portField }
                caption("A VPN or other address this Mac can reach.")
            }
        }
    }

    private var portField: some View {
        TextField("7311", text: $port).frame(width: 70).help("TCP port, 7311 by default")
    }

    private var commandNote: String {
        let scope = switch route {
        case .tailscale: "The agent listens only on the server's Tailscale address, and the installer allows the port on tailscale0 if ufw is active."
        case .privateNetwork: "The agent listens only on the private address, and the installer allows the port in ufw if it is active."
        case .publicIP: "The installer opens the port in ufw if it is active."
        case .other: "The installer allows the port in ufw if it is active."
        }
        return "Copy includes the hidden key. \(scope)"
    }

    private var firewallCard: some View {
        let attached = (server.publicNet.firewalls ?? []).compactMap { ref in ref.id.map { firewalls[$0] ?? "#\($0)" } }
        return card {
            HStack(spacing: 8) {
                Image(systemName: "shield.lefthalf.filled").foregroundStyle(Theme.secondary).frame(width: 16)
                VStack(alignment: .leading, spacing: 1) {
                    Text(attached.isEmpty ? "No Hetzner Cloud Firewall" : attached.joined(separator: ", "))
                        .font(.system(size: 12, weight: .semibold))
                    Text(attached.isEmpty
                         ? "Port \(portNumber) is open to the internet once the agent runs."
                         : "Add an inbound rule: TCP \(portNumber)")
                        .font(.system(size: 11))
                        .foregroundStyle(Theme.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                Spacer(minLength: 0)
                Button {
                    if let firewallsURL { NSWorkspace.shared.open(firewallsURL) }
                } label: {
                    Label(attached.isEmpty ? "Add a firewall" : "Open in Console", systemImage: "arrow.up.right")
                }
                .controlSize(.small)
            }
            Divider()
            HStack(spacing: 8) {
                Image(systemName: "laptopcomputer").foregroundStyle(Theme.secondary).frame(width: 16)
                VStack(alignment: .leading, spacing: 1) {
                    Text("Only from this Mac").font(.system(size: 12))
                    Text(sourceText)
                        .font(.system(size: 11, design: onlyThisMac && macAddress != nil ? .monospaced : .default))
                        .foregroundStyle(Theme.secondary)
                        .textSelection(.enabled)
                }
                Spacer(minLength: 0)
                Toggle("Only from this Mac", isOn: $onlyThisMac)
                    .labelsHidden()
                    .toggleStyle(.switch)
                    .controlSize(.small)
            }
        }
    }

    private var sourceText: String {
        guard onlyThisMac else { return "Source: any address" }
        if let macAddress { return "Source \(macAddress)/\(macAddress.contains(":") ? 128 : 32)" }
        return lookingUp ? "Finding this Mac's public address…" : "Could not find this Mac's public address"
    }

    private var waiting: some View {
        card {
            HStack(spacing: 10) {
                ProgressView().controlSize(.small)
                VStack(alignment: .leading, spacing: 2) {
                    Text("Waiting for the agent").font(.system(size: 12, weight: .semibold))
                    Text("\(link?.endpoint.display ?? host) · checking every 3 seconds")
                        .font(.system(size: 11))
                        .foregroundStyle(Theme.secondary)
                }
                Spacer(minLength: 0)
            }
        }
    }

    private enum Check { case passed, failed, unknown }

    @ViewBuilder
    private func checks(_ problem: AgentProblem, _ link: AgentLink) -> some View {
        let unreachable = [AgentProblem.agent(.timedOut), .agent(.unreachable), .agent(.invalidAddress)].contains(problem)
        title("Checks")
        card {
            if !agentOnly {
                checkRow(server.status == .running ? .passed : .failed, "Server is running")
                Divider()
            }
            checkRow(unreachable ? .failed : .passed, "This Mac reaches \(link.endpoint.display)") {
                if unreachable && route == .publicIP, let firewallsURL {
                    Button("Open firewall") { NSWorkspace.shared.open(firewallsURL) }.controlSize(.small)
                }
            }
            Divider()
            checkRow(unreachable ? .unknown : .failed, "The agent answers")
            Text(problem.text(link))
                .font(.system(size: 11))
                .foregroundStyle(Theme.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
        title("On the server")
        code("sudo rackpulse-agent status", masked: false)
        caption("Shows whether the agent runs and which address and port it listens on.").padding(.top, 6)
        if route != .tailscale {
            HStack(spacing: 4) {
                Text("Is \(server.name) on a tailnet?").foregroundStyle(Theme.secondary)
                Button("Use Tailscale instead") { route = .tailscale }.buttonStyle(.link)
            }
            .font(.system(size: 12))
            .padding(.top, 12)
        }
    }

    private func checkRow(_ check: Check, _ text: String, @ViewBuilder action: () -> some View = { EmptyView() }) -> some View {
        HStack(spacing: 8) {
            switch check {
            case .passed: Image(systemName: "checkmark.circle.fill").foregroundStyle(Theme.green).frame(width: 16)
            case .failed: Image(systemName: "xmark.circle.fill").foregroundStyle(Theme.red).frame(width: 16)
            case .unknown: Image(systemName: "circle.dashed").foregroundStyle(Theme.secondary).frame(width: 16)
            }
            Text(text).font(.system(size: 12)).lineLimit(1).truncationMode(.middle)
            Spacer(minLength: 0)
            action()
        }
        .frame(minHeight: 22)
    }

    @ViewBuilder
    private var connected: some View {
        if let link {
            card {
                row("Connection", link.address.title)
                Divider()
                row("Address", link.endpoint.display)
                if let version = link.version {
                    Divider()
                    row("Version", version)
                }
                if let seen = state?.seen {
                    Divider()
                    row("Last report", Format.ago(seen, now: .now))
                }
                if let pairedAt = link.pairedAt {
                    Divider()
                    row("Paired", pairedAt.formatted(date: .abbreviated, time: .omitted))
                }
            }
            .padding(.top, 14)
            if let problem = state?.problem {
                card(tint: Theme.orange) {
                    notice("exclamationmark.triangle.fill", Theme.orange, "The agent is not answering", problem.text(link))
                    if problem == .agent(.certificateChanged) {
                        Button("Pair again") { store.pairAgain(project.id, server.id) }.controlSize(.small)
                    }
                }
                .padding(.top, 10)
            }
            if link.isRotating, let command = store.rotationCommand(project.id, server.id) {
                rotation(command)
            } else if store.needsUpdate(project.id, server.id) {
                card(tint: Theme.info) {
                    notice("arrow.up.circle.fill", Theme.info, "Agent \(AgentStore.latestVersion) is available",
                           "Run this on the server. It keeps the key and settings.")
                    code(AgentStore.updateCommand, masked: false)
                }
                .padding(.top, 10)
            }
            facts.padding(.top, 14)
            if removing {
                removal
            } else {
                HStack(spacing: 8) {
                    Button("Change key") { store.startRotation(project.id, server.id) }
                        .disabled(link.isRotating)
                    Button("Change address") {
                        apply(link)
                        editing = true
                    }
                    Spacer(minLength: 0)
                    Button {
                        removing = true
                    } label: {
                        Text("Remove agent…").foregroundStyle(Theme.red)
                    }
                }
                .controlSize(.small)
                .padding(.top, 16)
            }
        }
    }

    private func rotation(_ command: String) -> some View {
        card {
            notice("key.fill", Theme.secondary, "New key",
                   "Run this on the server. It installs a new key and updates the agent. The old key stops working as soon as it runs.")
            code(command, masked: true)
            HStack(spacing: 8) {
                ProgressView().controlSize(.small)
                Text("Waiting for the agent to use the new key…").font(.system(size: 12, weight: .semibold))
                Spacer(minLength: 0)
                Button("Cancel") { store.cancelRotation(project.id, server.id) }.controlSize(.small)
            }
        }
        .padding(.top, 10)
        .task(id: link?.isRotating) {
            while !Task.isCancelled, link?.isRotating == true {
                await store.tryRotation(project.id, server: server.id)
                try? await Task.sleep(for: .seconds(3))
            }
        }
    }

    private var removal: some View {
        card(tint: Theme.red) {
            notice("trash", Theme.red, "Remove the agent",
                   "Run this on the server to remove the agent, its user, its data and its ufw rule. Then remove any cloud firewall rule for the port.")
            code("sudo rackpulse-agent uninstall", masked: false)
            HStack(spacing: 8) {
                Spacer(minLength: 0)
                Button("Cancel") { removing = false }
                Button(role: .destructive) {
                    store.remove(project.id, server.id)
                    if agentOnly { monitor.removeHost(project.id, server.id) }
                    back()
                } label: {
                    Text("Remove from Rackpulse").foregroundStyle(Theme.red)
                }
            }
            .controlSize(.small)
        }
        .padding(.top, 16)
    }

    private var facts: some View {
        DisclosureGroup(isExpanded: $showsFacts) {
            VStack(alignment: .leading, spacing: 7) {
                fact("lock.shield", "Read-only. The agent cannot run commands or change anything on the server.")
                fact("arrow.down.left.circle", "Your Mac connects to the agent over HTTPS on one TCP port. The server never connects to your Mac.")
                fact("key", "Only Rackpulse with this server's key can read it. The key is stored in your Keychain, and Rackpulse checks the agent's certificate on every connection.")
                fact("clock.arrow.circlepath", "It keeps 30 days of history on the server, so uptime and charts fill in after your Mac sleeps.")
                fact("shippingbox", "To list containers it joins the docker group, which can control Docker. The agent only reads from Docker.")
            }
            .padding(.top, 6)
        } label: {
            Text("How it works").font(.system(size: 12, weight: .medium))
        }
    }

    private func fact(_ icon: String, _ text: String) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 8) {
            Image(systemName: icon).foregroundStyle(Theme.secondary).frame(width: 16)
            Text(text).fixedSize(horizontal: false, vertical: true)
        }
        .font(.system(size: 11.5))
    }

    private func title(_ text: String) -> some View {
        Text(text.uppercased())
            .font(.system(size: 11, weight: .semibold))
            .tracking(0.6)
            .foregroundStyle(Theme.secondary)
            .lineLimit(1)
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(.top, 16)
            .padding(.bottom, 6)
    }

    private func card(tint: Color? = nil, @ViewBuilder content: () -> some View) -> some View {
        VStack(alignment: .leading, spacing: 8) { content() }
            .padding(10)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(tint.map { $0.opacity(0.12) } ?? Theme.card, in: RoundedRectangle(cornerRadius: 9))
    }

    private func notice(_ icon: String, _ color: Color, _ heading: String, _ detail: String) -> some View {
        HStack(alignment: .top, spacing: 8) {
            Image(systemName: icon).foregroundStyle(color).frame(width: 16)
            VStack(alignment: .leading, spacing: 2) {
                Text(heading).font(.system(size: 12, weight: .semibold))
                Text(detail)
                    .font(.system(size: 11))
                    .foregroundStyle(Theme.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }

    private func field(_ label: String, @ViewBuilder content: () -> some View) -> some View {
        HStack {
            Text(label).font(.system(size: 12))
            Spacer(minLength: 8)
            content().textFieldStyle(.roundedBorder).font(.system(size: 12))
        }
    }

    private func row(_ label: String, _ value: String) -> some View {
        HStack {
            Text(label).foregroundStyle(Theme.secondary)
            Spacer(minLength: 8)
            Text(value).lineLimit(1).truncationMode(.middle).textSelection(.enabled)
        }
        .font(.system(size: 12))
    }

    private func caption(_ text: String) -> some View {
        Text(text)
            .font(.system(size: 11))
            .foregroundStyle(Theme.secondary)
            .fixedSize(horizontal: false, vertical: true)
    }

    private func code(_ text: String, masked: Bool) -> some View {
        HStack(alignment: .top, spacing: 8) {
            Text(masked ? AgentStore.masked(text) : text)
                .font(.system(size: 11, design: .monospaced))
                .fixedSize(horizontal: false, vertical: true)
                .frame(maxWidth: .infinity, alignment: .leading)
            Button {
                NSPasteboard.general.clearContents()
                NSPasteboard.general.setString(text, forType: .string)
                copied = text
                Task {
                    try? await Task.sleep(for: .seconds(1.5))
                    if copied == text { copied = nil }
                }
            } label: {
                Label(copied == text ? "Copied" : "Copy", systemImage: copied == text ? "checkmark" : "doc.on.doc")
            }
            .controlSize(.small)
        }
        .padding(8)
        .background(Theme.card, in: RoundedRectangle(cornerRadius: 7))
    }

    private var firewallsURL: URL? {
        project.provider.firewallsURL(project)
    }

    private func lookUpMac() {
        guard onlyThisMac, macAddress == nil, !lookingUp else { return }
        lookingUp = true
        Task {
            macAddress = await MacNetwork.publicAddress()
            lookingUp = false
        }
    }

    private func load() {
        tailnetHost = agentOnly ? "" : server.name
        publicAddress = publicAddresses.first ?? .publicIPv4
        if let link {
            apply(link)
        } else {
            route = macOnTailscale ? .tailscale : publicAddresses.isEmpty && !agentOnly ? .other : .publicIP
            save()
        }
    }

    private func apply(_ link: AgentLink) {
        port = String(link.endpoint.port)
        if agentOnly { custom = link.endpoint.host }
        switch link.address {
        case .publicIPv4, .publicIPv6:
            route = .publicIP
            publicAddress = link.address
        case .tailscale:
            route = .tailscale
            tailnetHost = link.endpoint.host
        case .privateNetwork:
            route = .privateNetwork
        case .custom:
            route = .other
            custom = link.endpoint.host
        }
    }

    private func save() {
        guard !paired, !host.isEmpty else { return }
        store.prepare(project.id, server: server.id, address: address, host: host, port: portNumber)
    }
}

struct UsageBar: View {
    let fraction: Double
    let color: Color

    static func color(_ fraction: Double, warn: Bool = false) -> Color {
        warn || fraction >= 0.95 ? Theme.red : fraction >= 0.85 ? Theme.orange : Theme.green
    }

    var body: some View {
        GeometryReader { proxy in
            ZStack(alignment: .leading) {
                Capsule().fill(Theme.divider.opacity(0.6))
                Capsule().fill(color).frame(width: max(3, proxy.size.width * min(1, max(0, fraction))))
            }
        }
        .frame(height: 4)
    }
}

struct CompactLabelStyle: LabelStyle {
    func makeBody(configuration: Configuration) -> some View {
        HStack(spacing: 4) {
            configuration.icon
            configuration.title
        }
    }
}
