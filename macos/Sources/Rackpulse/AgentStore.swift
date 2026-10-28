import Foundation
import HetznerKit
import Observation

enum AgentAddress: String, Codable, CaseIterable, Identifiable {
    case publicIPv4, publicIPv6, tailscale, privateNetwork, custom

    var id: String { rawValue }

    var title: String {
        switch self {
        case .publicIPv4: "Public IPv4"
        case .publicIPv6: "Public IPv6"
        case .tailscale: "Tailscale"
        case .privateNetwork: "Private network"
        case .custom: "Other address"
        }
    }

    var isPublic: Bool { self == .publicIPv4 || self == .publicIPv6 }

    func host(for server: Server) -> String? {
        switch self {
        case .publicIPv4: server.publicNet.ipv4?.ip
        case .publicIPv6: server.publicNet.ipv6.map { $0.ip.replacingOccurrences(of: "::/64", with: "::1") }
        case .tailscale: server.name
        case .privateNetwork: server.privateNet?.first?.ip
        case .custom: nil
        }
    }
}

struct AgentLink: Codable, Hashable {
    var address: AgentAddress
    var endpoint: AgentEndpoint
    var fingerprint: String?
    var version: String?
    var pairedAt: Date?
    var rotating: Bool?

    var isPaired: Bool { fingerprint != nil }
    var isRotating: Bool { rotating == true }

    var place: String {
        switch address {
        case .publicIPv4: "the public IPv4 address, port \(endpoint.port)"
        case .publicIPv6: "the public IPv6 address, port \(endpoint.port)"
        case .privateNetwork: "the private network address, port \(endpoint.port)"
        case .tailscale, .custom: endpoint.display
        }
    }
}

enum AgentProblem: Equatable {
    case agent(AgentError)
    case otherServer(Int64)
    case noKey

    func text(_ link: AgentLink) -> String {
        let place = link.place
        let endpoint = link.endpoint
        return switch self {
        case .agent(.refused):
            "Nothing answers on port \(endpoint.port). The agent is not running, or the server's firewall rejects the port."
        case .agent(.timedOut):
            "No answer from \(place). A firewall is probably dropping the connection. Check the port rule."
        case .agent(.unreachable):
            "Could not reach \(place) from this Mac."
        case .agent(.invalidAddress):
            "The address \(endpoint.host) could not be found."
        case .agent(.notAgent):
            "Something answers on \(place), but it is not the Rackpulse agent."
        case .agent(.wrongKey):
            "The agent on this server uses a different key. Run the install command shown here again."
        case .agent(.certificateChanged):
            "The agent's certificate changed. If you reinstalled it, pair again. Otherwise something else may be answering on this address."
        case .agent(.invalidResponse):
            "The agent sent an answer Rackpulse does not understand. Update the agent."
        case .otherServer(let id):
            "The agent at \(place) runs on another server (ID \(id))."
        case .noKey:
            "The pairing key is missing from the Keychain. Remove the agent and set it up again."
        }
    }
}

struct AgentState {
    var snapshot: AgentSnapshot?
    var seen: Date?
    var failures = 0
    var problem: AgentProblem?
    var lastAttempt: Date?
}

@MainActor
@Observable
final class AgentStore {
    static let latestVersion = Bundle.main.object(forInfoDictionaryKey: "RackpulseAgentVersion") as? String ?? ""
    static let installURL = "\(Flavor.agentURL)/install.sh"
    private static let linksKey = "agentLinks"
    private static let historyInterval: TimeInterval = 900

    private(set) var links: [String: AgentLink]
    private(set) var states: [String: AgentState] = [:]
    private(set) var uptime: [String: AgentUptime]
    private(set) var dockerGroups: [String: Bool] = UserDefaults.standard.dictionary(forKey: "dockerGroups") as? [String: Bool] ?? [:]

    @ObservationIgnored private var tokens: [String: String] = [:]
    @ObservationIgnored private var clients: [String: AgentClient] = [:]
    @ObservationIgnored private var historyFetched: [String: Date] = [:]
    @ObservationIgnored private var pairing: Set<String> = []
    @ObservationIgnored private var refreshing: Set<String> = []
    @ObservationIgnored private let uptimeURL: URL

    init() {
        links = UserDefaults.standard.data(forKey: Self.linksKey)
            .flatMap { try? JSONDecoder().decode([String: AgentLink].self, from: $0) } ?? [:]
        let folder = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("Rackpulse", isDirectory: true)
        try? FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
        uptimeURL = folder.appendingPathComponent("agent-uptime.json")
        uptime = (try? Data(contentsOf: uptimeURL)).flatMap { try? JSONDecoder().decode([String: AgentUptime].self, from: $0) } ?? [:]
    }

    static func key(_ project: UUID, _ server: Int64) -> String {
        "\(project.uuidString):\(server)"
    }

    func link(_ project: UUID, _ server: Int64) -> AgentLink? {
        links[Self.key(project, server)]
    }

    func state(_ project: UUID, _ server: Int64) -> AgentState? {
        states[Self.key(project, server)]
    }

    func uptime(_ project: UUID, _ server: Int64) -> AgentUptime? {
        uptime[Self.key(project, server)]
    }

    func token(_ project: UUID, _ server: Int64) -> String? {
        token(Self.key(project, server))
    }

    static let updateCommand = " curl -fsSL \(installURL) | sudo sh"

    func needsUpdate(_ project: UUID, _ server: Int64) -> Bool {
        guard let version = link(project, server)?.version else { return false }
        return version.compare(Self.latestVersion, options: .numeric) == .orderedAscending
    }

    func installCommand(_ project: UUID, _ server: Int64) -> String? {
        guard let link = link(project, server), let token = token(project, server) else { return nil }
        return Self.command(link: link, token: token)
    }

    func installCommand(_ project: UUID, _ server: Int64, address: AgentAddress, host: String, port: Int) -> String? {
        guard let token = token(project, server) else { return nil }
        return Self.command(link: AgentLink(address: address, endpoint: AgentEndpoint(host: host, port: port)), token: token)
    }

    static func masked(_ command: String) -> String {
        command.replacing(/rb1_[A-Za-z0-9_-]+/, with: "rb1_••••••••")
    }

    func rotationCommand(_ project: UUID, _ server: Int64) -> String? {
        let key = Self.key(project, server)
        guard let link = links[key], link.isRotating, let token = token(Self.nextKey(key)) else { return nil }
        return Self.command(link: link, token: token)
    }

    private static func nextKey(_ key: String) -> String {
        "\(key):next"
    }

    private static func command(link: AgentLink, token: String) -> String {
        var command = " curl -fsSL \(installURL) | sudo sh -s -- --pair \(token)"
        if link.endpoint.port != AgentEndpoint.defaultPort { command += " --port \(link.endpoint.port)" }
        if link.address == .tailscale {
            command += " --listen tailscale"
        } else if !link.address.isPublic, isIPAddress(link.endpoint.host) {
            command += " --listen \(link.endpoint.host)"
        }
        return command
    }

    func startRotation(_ project: UUID, _ server: Int64) {
        let key = Self.key(project, server)
        guard links[key]?.isPaired == true else { return }
        let next = AgentClient.newToken()
        guard (try? Keychain.save(next, account: Self.nextKey(key), service: Keychain.agentService)) != nil else { return }
        tokens[Self.nextKey(key)] = next
        links[key]?.rotating = true
        persist()
    }

    func cancelRotation(_ project: UUID, _ server: Int64) {
        let key = Self.key(project, server)
        Keychain.delete(account: Self.nextKey(key), service: Keychain.agentService)
        tokens[Self.nextKey(key)] = nil
        links[key]?.rotating = nil
        persist()
    }

    func tryRotation(_ project: UUID, server: Int64) async {
        let key = Self.key(project, server)
        guard let link = links[key], link.isRotating, let next = token(Self.nextKey(key)), !pairing.contains(key) else { return }
        pairing.insert(key)
        defer { pairing.remove(key) }
        guard let result = try? await AgentClient.pair(endpoint: link.endpoint, token: next, timeout: 5),
              links[key]?.isRotating == true,
              (try? Keychain.save(next, account: key, service: Keychain.agentService)) != nil
        else { return }
        Keychain.delete(account: Self.nextKey(key), service: Keychain.agentService)
        tokens[key] = next
        tokens[Self.nextKey(key)] = nil
        links[key]?.fingerprint = result.fingerprint
        links[key]?.version = result.version
        links[key]?.rotating = nil
        clients[key] = nil
        states[key]?.problem = nil
        states[key]?.failures = 0
        persist()
    }

    func prepare(_ project: UUID, server: Int64, address: AgentAddress, host: String, port: Int) {
        let key = Self.key(project, server)
        if token(key) == nil {
            let token = AgentClient.newToken()
            guard (try? Keychain.save(token, account: key, service: Keychain.agentService)) != nil else { return }
            tokens[key] = token
        }
        var link = links[key] ?? AgentLink(address: address, endpoint: AgentEndpoint(host: host, port: port))
        let endpoint = AgentEndpoint(host: host.trimmingCharacters(in: .whitespacesAndNewlines), port: port)
        guard link.address != address || link.endpoint != endpoint || links[key] == nil else { return }
        link.address = address
        link.endpoint = endpoint
        links[key] = link
        clients[key] = nil
        states[key]?.problem = nil
        states[key]?.failures = 0
        persist()
    }

    func move(_ project: UUID, _ server: Int64, address: AgentAddress, host: String, port: Int) {
        let key = Self.key(project, server)
        guard links[key] != nil else { return }
        links[key]?.address = address
        links[key]?.endpoint = AgentEndpoint(host: host.trimmingCharacters(in: .whitespacesAndNewlines), port: port)
        clients[key] = nil
        states[key]?.problem = nil
        states[key]?.failures = 0
        persist()
    }

    func pairAgain(_ project: UUID, _ server: Int64) {
        let key = Self.key(project, server)
        links[key]?.fingerprint = nil
        clients[key] = nil
        states[key] = AgentState()
        persist()
    }

    func remove(_ project: UUID, _ server: Int64) {
        let key = Self.key(project, server)
        Keychain.delete(account: key, service: Keychain.agentService)
        Keychain.delete(account: Self.nextKey(key), service: Keychain.agentService)
        tokens[Self.nextKey(key)] = nil
        tokens[key] = nil
        links[key] = nil
        states[key] = nil
        clients[key] = nil
        uptime[key] = nil
        historyFetched[key] = nil
        persist()
        saveUptime()
    }

    @discardableResult
    private func adoptTailscaleName(_ key: String, _ snapshot: AgentSnapshot) -> Bool {
        guard let link = links[key], link.address == .tailscale,
              let name = snapshot.host.tailscale?.name, !name.isEmpty,
              !link.endpoint.host.contains("."), !link.endpoint.host.contains(":"),
              link.endpoint.host.lowercased() != name.lowercased()
        else { return false }
        links[key]?.endpoint.host = name
        clients[key] = nil
        return true
    }

    func tryPair(_ project: UUID, server: Int64) async {
        let key = Self.key(project, server)
        guard let link = links[key], !link.isPaired, !pairing.contains(key) else { return }
        guard let token = token(key) else {
            states[key, default: AgentState()].problem = .noKey
            return
        }
        pairing.insert(key)
        defer { pairing.remove(key) }
        states[key, default: AgentState()].lastAttempt = .now
        do {
            let result = try await AgentClient.pair(endpoint: link.endpoint, token: token, timeout: 5)
            let client = AgentClient(endpoint: link.endpoint, token: token, fingerprint: result.fingerprint)
            let snapshot = try await client.snapshot().normalized()
            if server > 0, let other = snapshot.host.serverID, other != server {
                fail(key, .otherServer(other))
                return
            }
            guard links[key]?.endpoint == link.endpoint else { return }
            links[key]?.fingerprint = result.fingerprint
            links[key]?.version = snapshot.version
            links[key]?.pairedAt = .now
            clients[key] = client
            states[key] = AgentState(snapshot: snapshot, seen: .now)
            historyFetched[key] = nil
            adoptTailscaleName(key, snapshot)
            persist()
            await refreshHistory(key, client: client)
        } catch let error as AgentError {
            fail(key, .agent(error))
        } catch {
            fail(key, .agent(.unreachable))
        }
    }

    func poll(_ project: UUID, servers: [Server]) async -> [Int64: AgentReport] {
        let prefix = "\(project.uuidString):"
        let byID = Dictionary(servers.map { ($0.id, $0) }, uniquingKeysWith: { first, _ in first })
        var reports: [Int64: AgentReport] = [:]
        var fetches: [(String, Int64, AgentClient)] = []

        for (key, link) in links where key.hasPrefix(prefix) {
            guard let id = Int64(key.dropFirst(prefix.count)), let server = byID[id] else { continue }
            if !link.isPaired {
                let recent = states[key]?.lastAttempt.map { Date.now.timeIntervalSince($0) < 20 } ?? false
                if server.status == .running, !recent { Task { await tryPair(project, server: id) } }
                continue
            }
            guard server.status == .running else {
                reports[id] = AgentReport(current: nil, failures: 0)
                continue
            }
            if link.isRotating { await tryRotation(project, server: id) }
            guard let link = links[key], let client = client(key, link: link) else {
                states[key, default: AgentState()].problem = .noKey
                continue
            }
            fetches.append((key, id, client))
        }

        let results = await withTaskGroup(of: (String, Int64, Result<AgentSnapshot, AgentError>).self) { group in
            for (key, id, client) in fetches {
                group.addTask {
                    do {
                        return (key, id, .success(try await client.snapshot().normalized()))
                    } catch let error as AgentError {
                        return (key, id, .failure(error))
                    } catch {
                        return (key, id, .failure(.unreachable))
                    }
                }
            }
            var all: [(String, Int64, Result<AgentSnapshot, AgentError>)] = []
            for await result in group { all.append(result) }
            return all
        }

        for (key, id, result) in results {
            switch result {
            case .success(let snapshot) where id > 0 && snapshot.host.serverID.map({ $0 != id }) ?? false:
                fail(key, .otherServer(snapshot.host.serverID ?? 0))
            case .success(let snapshot):
                states[key] = AgentState(snapshot: snapshot, seen: .now)
                if adoptTailscaleName(key, snapshot) { persist() }
                if links[key]?.version != snapshot.version {
                    links[key]?.version = snapshot.version
                    persist()
                }
            case .failure(let error):
                fail(key, .agent(error))
            }
            reports[id] = AgentReport(current: states[key]?.problem == nil ? states[key]?.snapshot : nil, failures: states[key]?.failures ?? 0)
            if case .success = result, let client = clients[key],
               historyFetched[key].map({ Date.now.timeIntervalSince($0) > Self.historyInterval }) ?? true {
                await refreshHistory(key, client: client)
            }
        }
        return reports
    }

    func refreshLive(_ project: UUID, _ server: Int64, history: Bool) async {
        let key = Self.key(project, server)
        guard let link = links[key], link.isPaired, !link.isRotating, !refreshing.contains(key),
              let client = client(key, link: link)
        else { return }
        refreshing.insert(key)
        defer { refreshing.remove(key) }
        guard let snapshot = try? await client.snapshot().normalized(),
              server < 0 || snapshot.host.serverID.map({ $0 == server }) ?? true,
              links[key]?.endpoint == link.endpoint
        else { return }
        states[key] = AgentState(snapshot: snapshot, seen: .now)
        if links[key]?.version != snapshot.version {
            links[key]?.version = snapshot.version
            persist()
        }
        if history, historyFetched[key].map({ Date.now.timeIntervalSince($0) > 60 }) ?? true {
            await refreshHistory(key, client: client)
        }
    }

    func history(_ project: UUID, _ server: Int64, since: Date) async -> AgentHistory? {
        let key = Self.key(project, server)
        guard let link = links[key], let client = client(key, link: link) else { return nil }
        return try? await client.history(since: since)
    }

    func setDockerGroup(_ id: String, expanded: Bool) {
        dockerGroups[id] = expanded
        UserDefaults.standard.set(dockerGroups, forKey: "dockerGroups")
    }

    func containerHistory(_ project: UUID, _ server: Int64, name: String, since: Date) async -> ContainerHistory? {
        let key = Self.key(project, server)
        guard let link = links[key], let client = client(key, link: link) else { return nil }
        return try? await client.containerHistory(name: name, since: since)
    }

    private func refreshHistory(_ key: String, client: AgentClient) async {
        let now = Date.now
        let since = uptime[key].map { $0.asOf.addingTimeInterval(-7_200) } ?? now.addingTimeInterval(-UptimeTimeline.window)
        guard let history = try? await client.history(since: since) else { return }
        historyFetched[key] = now
        let fresh = history.uptime(asOf: min(now, history.time ?? now))
        uptime[key] = uptime[key].map { $0.merged(with: fresh, keepingAfter: now.addingTimeInterval(-UptimeTimeline.window)) } ?? fresh
        saveUptime()
    }

    private func fail(_ key: String, _ problem: AgentProblem) {
        var state = states[key] ?? AgentState()
        state.failures += 1
        state.problem = problem
        states[key] = state
    }

    private func client(_ key: String, link: AgentLink) -> AgentClient? {
        if let client = clients[key], client.endpoint == link.endpoint { return client }
        guard let fingerprint = link.fingerprint, let token = token(key) else { return nil }
        let client = AgentClient(endpoint: link.endpoint, token: token, fingerprint: fingerprint)
        clients[key] = client
        return client
    }

    private func token(_ key: String) -> String? {
        if let token = tokens[key] { return token }
        let token = Keychain.read(account: key, service: Keychain.agentService)
        tokens[key] = token
        return token
    }

    private func persist() {
        UserDefaults.standard.set(try? JSONEncoder().encode(links), forKey: Self.linksKey)
    }

    private func saveUptime() {
        if let data = try? JSONEncoder().encode(uptime) { try? data.write(to: uptimeURL, options: .atomic) }
    }

    static func isIPAddress(_ text: String) -> Bool {
        var v4 = in_addr()
        var v6 = in6_addr()
        return inet_pton(AF_INET, text, &v4) == 1 || inet_pton(AF_INET6, text, &v6) == 1
    }
}
