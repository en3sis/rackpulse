import Foundation

public struct SocketCredentials: Sendable, Hashable, CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public let token: String
    public let organization: String

    public init(token: String, organization: String) {
        self.token = token.trimmingCharacters(in: .whitespacesAndNewlines)
        self.organization = organization.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    public var description: String { "Socket key for \(organization)" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { Mirror(self, children: ["organization": organization]) }

    public var organizationIsValid: Bool {
        guard let first = organization.unicodeScalars.first, first.isASCII, CharacterSet.alphanumerics.contains(first) else { return false }
        return organization.count <= 100
            && organization.unicodeScalars.allSatisfy { $0.isASCII && (CharacterSet.alphanumerics.contains($0) || "-._".unicodeScalars.contains($0)) }
    }
}

public struct SocketQuota: Sendable, Hashable, Codable {
    public let quota: Int
    public let maxQuota: Int
    public let nextWindowRefresh: Date?
    public let checkedAt: Date?

    public init(quota: Int, maxQuota: Int, nextWindowRefresh: Date?, checkedAt: Date? = nil) {
        self.quota = quota
        self.maxQuota = maxQuota
        self.nextWindowRefresh = nextWindowRefresh
        self.checkedAt = checkedAt
    }

    public var callsLeft: Int { max(0, quota) / SocketSource.callCost }

    func spending(_ units: Int) -> SocketQuota {
        SocketQuota(quota: max(0, quota - units), maxQuota: maxQuota, nextWindowRefresh: nextWindowRefresh, checkedAt: checkedAt)
    }
}

public actor SocketSource: VulnerabilitySource {
    public static let callCost = 100
    public static let batchLimit = 1024
    public static let cleanLifetime: TimeInterval = 86_400
    public static let flaggedLifetime: TimeInterval = 6 * 3_600
    public static let unansweredLifetime: TimeInterval = 6 * 3_600
    public static let retention: TimeInterval = 7 * 86_400
    public static let minimumInterval: TimeInterval = 900
    public static let quotaInterval: TimeInterval = 900
    public static let serverScanLimit = 200
    public static let serverDayLimit = 1_000
    static let file = "socket.json"
    static let limit = 50_000
    static let unknownServer: Int64 = -1

    public nonisolated let name = SourceName.socket
    private let credentials: SocketCredentials
    private let cache: SecurityCache
    private let http: SecurityHTTP
    private let clock: @Sendable () -> Date
    private var state: State?

    struct State: Sendable, Codable {
        var lastCall: Date?
        var blockedUntil: Date?
        var entries: [String: Entry] = [:]
        var quota: SocketQuota?
        var usage: [String: Usage] = [:]

        init() {}

        enum CodingKeys: String, CodingKey {
            case lastCall, blockedUntil, entries, quota, usage
        }

        init(from decoder: Decoder) throws {
            let container = try decoder.container(keyedBy: CodingKeys.self)
            lastCall = container.optional(Date.self, forKey: .lastCall)
            blockedUntil = container.optional(Date.self, forKey: .blockedUntil)
            entries = container.optional([String: Entry].self, forKey: .entries) ?? [:]
            quota = container.optional(SocketQuota.self, forKey: .quota)
            usage = container.optional([String: Usage].self, forKey: .usage) ?? [:]
        }
    }

    struct Entry: Sendable, Codable {
        var time: Date
        var advisories: [Advisory]
        var unanswered: Bool?

        init(time: Date, advisories: [Advisory], unanswered: Bool? = nil) {
            self.time = time
            self.advisories = advisories
            self.unanswered = unanswered
        }

        var lifetime: TimeInterval {
            if unanswered == true { return SocketSource.unansweredLifetime }
            return advisories.isEmpty ? SocketSource.cleanLifetime : SocketSource.flaggedLifetime
        }

        func isFresh(at now: Date) -> Bool {
            time <= now && now.timeIntervalSince(time) < lifetime
        }
    }

    struct Usage: Sendable, Codable {
        var start: Date
        var count: Int
    }

    public init(
        credentials: SocketCredentials,
        cache: SecurityCache,
        transport: HTTPTransport = URLSessionTransport(),
        clock: @escaping @Sendable () -> Date = { Date() },
        sleep: @escaping @Sendable (TimeInterval) async throws -> Void = { try await Task.sleep(for: .seconds($0)) }
    ) {
        self.credentials = credentials
        self.cache = cache
        self.clock = clock
        http = SecurityHTTP(transport: transport, sleep: sleep, clock: clock)
    }

    public nonisolated func supports(_ query: PackageQuery) -> Bool {
        !query.isOperatingSystem && query.purl != nil
    }

    public func verify() async throws -> SocketQuota {
        let (data, response) = try await http.send(try authorized(URL(string: "https://api.socket.dev/v0/quota")!), attempts: 2)
        switch response.statusCode {
        case 200: break
        case 401, 403: throw SecuritySourceError.unauthorized
        default: throw SecuritySourceError.status(response.statusCode, host: SourceName.socket.host)
        }
        guard let parsed = Self.parseQuota(data) else { throw SecuritySourceError.invalidResponse(host: SourceName.socket.host) }
        let quota = SocketQuota(quota: parsed.quota, maxQuota: parsed.maxQuota, nextWindowRefresh: parsed.nextWindowRefresh, checkedAt: clock())
        var current = loadState()
        current.quota = quota
        save(current)
        return quota
    }

    public var lastQuota: SocketQuota? {
        loadState().quota
    }

    private func loadState() -> State {
        state ?? cache.read(State.self, from: Self.file) ?? State()
    }

    private func save(_ current: State) {
        var current = current
        current.entries = SecurityCache.bounded(current.entries, limit: Self.limit) { $0.time }
        state = current
        cache.write(current, to: Self.file)
    }

    private func quota(_ current: inout State, now: Date) async throws -> SocketQuota {
        if let quota = current.quota, let checked = quota.checkedAt, checked <= now, now.timeIntervalSince(checked) < Self.quotaInterval {
            return quota
        }
        let quota = try await verify()
        current.quota = quota
        return quota
    }

    public func lookup(_ queries: [PackageQuery]) async throws -> SourceLookup {
        try await lookup(queries, origins: [:])
    }

    public func lookup(_ queries: [PackageQuery], origins: [PackageQuery: Set<Int64>]) async throws -> SourceLookup {
        guard credentials.organizationIsValid else { throw SecuritySourceError.invalidOrganization }
        let now = clock()
        var current = loadState()
        current.entries = current.entries.filter { now.timeIntervalSince($0.value.time) < Self.retention && $0.value.time <= now }
        current.usage = current.usage.filter { now.timeIntervalSince($0.value.start) < 86_400 && $0.value.start <= now }
        defer { save(current) }

        var byPurl: [String: PackageQuery] = [:]
        var owners: [String: Set<Int64>] = [:]
        for query in queries where supports(query) {
            guard let purl = query.purl else { continue }
            byPurl[purl] = byPurl[purl] ?? query
            owners[purl, default: []].formUnion(origins[query].flatMap { $0.isEmpty ? nil : $0 } ?? [Self.unknownServer])
        }
        let waiting = byPurl.keys.filter { current.entries[$0]?.isFresh(at: now) != true }.sorted()
        var problem: String?
        var skipped = false

        if !waiting.isEmpty {
            if let blocked = current.blockedUntil, blocked > now {
                problem = "\(waiting.count) packages wait for the next check after \(blocked.formatted(date: .omitted, time: .shortened))."
            } else if let last = current.lastCall, now.timeIntervalSince(last) < Self.minimumInterval, last <= now {
                let next = last.addingTimeInterval(Self.minimumInterval)
                problem = "\(waiting.count) packages wait for the next check after \(next.formatted(date: .omitted, time: .shortened))."
            } else {
                do {
                    let quota: SocketQuota
                    do {
                        quota = try await self.quota(&current, now: now)
                    } catch is CancellationError {
                        throw CancellationError()
                    } catch {
                        current.lastCall = now
                        throw error
                    }
                    if quota.quota < Self.callCost {
                        if let refresh = quota.nextWindowRefresh, refresh > now { current.blockedUntil = refresh }
                        skipped = true
                        problem = "Socket quota is too low for this scan (\(max(0, quota.quota)) left)."
                    } else {
                        var usage = current.usage
                        let (batch, capped) = Self.select(waiting, owners: owners, usage: &usage, now: now)
                        if batch.isEmpty {
                            problem = Self.capMessage(capped)
                        } else {
                            let lines: [Line]
                            do {
                                lines = try await send(batch)
                                current.lastCall = now
                                current.usage = usage
                                current.quota = quota.spending(Self.callCost)
                            } catch SecuritySourceError.rateLimited(let until) {
                                current.lastCall = now
                                current.usage = usage
                                current.blockedUntil = until ?? now.addingTimeInterval(3_600)
                                current.quota = quota.spending(quota.quota)
                                throw SecuritySourceError.quotaExhausted(until: current.blockedUntil)
                            } catch is CancellationError {
                                throw CancellationError()
                            } catch {
                                current.lastCall = now
                                throw error
                            }
                            var answered: Set<String> = []
                            for line in lines {
                                switch line {
                                case .artifact(let purl, let artifact):
                                    guard let query = byPurl[purl] else { continue }
                                    answered.insert(purl)
                                    current.entries[purl] = Entry(time: now, advisories: Self.advisories(artifact, query: query))
                                case .error(let purl, let retryable):
                                    guard byPurl[purl] != nil, !retryable else { continue }
                                    answered.insert(purl)
                                    current.entries[purl] = Entry(time: now, advisories: [])
                                }
                            }
                            let echoed = Set(lines.map { line -> String in
                                switch line {
                                case .artifact(let purl, _), .error(let purl, _): purl
                                }
                            })
                            for purl in batch where !echoed.contains(purl) {
                                answered.insert(purl)
                                current.entries[purl] = Entry(time: now, advisories: [], unanswered: true)
                            }
                            let left = waiting.count - answered.count - capped
                            problem = [left > 0 ? "\(left) packages wait for the next check." : nil, capped > 0 ? Self.capMessage(capped) : nil]
                                .compactMap { $0 }.joined(separator: " ")
                            if problem?.isEmpty == true { problem = nil }
                        }
                    }
                } catch let error as SecuritySourceError where byPurl.keys.contains(where: { current.entries[$0] != nil }) {
                    problem = "\(waiting.count) packages were not checked. \(error.message)"
                }
            }
        }

        var advisories: [PackageQuery: [Advisory]] = [:]
        for (purl, query) in byPurl {
            guard let entry = current.entries[purl] else { continue }
            advisories[query, default: []] += entry.advisories
        }
        return SourceLookup(advisories: advisories, problem: problem, quota: current.quota, skipped: skipped)
    }

    static func capMessage(_ count: Int) -> String {
        "\(count) packages were not sent to Socket. Each server can send \(serverScanLimit) packages per scan and \(serverDayLimit) per day."
    }

    static func select(_ waiting: [String], owners: [String: Set<Int64>], usage: inout [String: Usage], now: Date) -> (batch: [String], capped: Int) {
        var queues: [Int64: [String]] = [:]
        for purl in waiting {
            for owner in owners[purl] ?? [unknownServer] { queues[owner, default: []].append(purl) }
        }
        let servers = queues.keys.sorted()
        var positions: [Int64: Int] = [:]
        var taken: [Int64: Int] = [:]
        var chosen: [String] = []
        var chosenSet: Set<String> = []
        func allowance(_ server: Int64) -> Bool {
            (taken[server] ?? 0) < serverScanLimit && (usage[String(server)]?.count ?? 0) < serverDayLimit
        }
        var progressed = true
        while progressed && chosen.count < batchLimit {
            progressed = false
            for server in servers where chosen.count < batchLimit && allowance(server) {
                guard let queue = queues[server] else { continue }
                var position = positions[server] ?? 0
                while position < queue.count, chosenSet.contains(queue[position]) { position += 1 }
                positions[server] = position + 1
                guard position < queue.count else { continue }
                chosen.append(queue[position])
                chosenSet.insert(queue[position])
                taken[server, default: 0] += 1
                usage[String(server), default: Usage(start: now, count: 0)].count += 1
                progressed = true
            }
        }
        let capped = waiting.filter { purl in
            !chosenSet.contains(purl) && (owners[purl] ?? [unknownServer]).allSatisfy { !allowance($0) }
        }.count
        return (chosen, capped)
    }

    private func authorized(_ url: URL, method: String = "GET", body: Data? = nil) throws -> URLRequest {
        try http.request(url, method: method, body: body, headers: ["Authorization": "Bearer \(credentials.token)"])
    }

    private func send(_ purls: [String]) async throws -> [Line] {
        var components = URLComponents(string: "https://api.socket.dev")!
        components.path = "/v0/orgs/\(credentials.organization)/purl"
        components.queryItems = [URLQueryItem(name: "alerts", value: "true"), URLQueryItem(name: "compact", value: "true")]
        guard let url = components.url else { throw SecuritySourceError.invalidOrganization }
        let body = try SecurityHTTP.encoder().encode(["components": purls.map { ["purl": $0] }])
        let (data, response) = try await http.send(try authorized(url, method: "POST", body: body), attempts: 1)
        switch response.statusCode {
        case 200: return Self.parse(data)
        case 401, 403: throw SecuritySourceError.unauthorized
        case 404: throw SecuritySourceError.organizationNotFound
        case 429: throw SecuritySourceError.rateLimited(until: http.retryAfter(response).map { clock().addingTimeInterval($0) })
        default: throw SecuritySourceError.status(response.statusCode, host: SourceName.socket.host)
        }
    }

    enum Line: Sendable {
        case artifact(purl: String, Artifact)
        case error(purl: String, retryable: Bool)
    }

    struct Artifact: Sendable, Decodable {
        struct Alert: Sendable, Decodable {
            let type: String
            let severity: String?
        }

        let inputPurl: String?
        let type: String?
        let namespace: String?
        let name: String?
        let version: String?
        let alerts: [Alert]

        enum CodingKeys: String, CodingKey {
            case inputPurl, type, namespace, name, version, alerts
        }

        init(from decoder: Decoder) throws {
            let container = try decoder.container(keyedBy: CodingKeys.self)
            inputPurl = container.optional(String.self, forKey: .inputPurl)
            type = container.optional(String.self, forKey: .type)
            namespace = container.optional(String.self, forKey: .namespace)
            name = container.optional(String.self, forKey: .name)
            version = container.optional(String.self, forKey: .version)
            alerts = container.lossy([Alert].self, forKey: .alerts)
        }
    }

    struct ErrorLine: Decodable {
        struct Value: Decodable {
            let inputPurl: String?
            let retryable: Bool?
        }

        let type: String
        let value: Value?

        enum CodingKeys: String, CodingKey {
            case type = "_type"
            case value
        }
    }

    static func parse(_ data: Data) -> [Line] {
        var lines: [Line] = []
        let decoder = JSONDecoder()
        for raw in data.split(separator: UInt8(ascii: "\n")) where !raw.allSatisfy({ $0 == 32 || $0 == 13 }) {
            let line = Data(raw)
            if let error = try? decoder.decode(ErrorLine.self, from: line) {
                if error.type == "purlError", let purl = error.value?.inputPurl {
                    lines.append(.error(purl: purl, retryable: error.value?.retryable ?? false))
                }
                continue
            }
            guard let artifact = try? decoder.decode(Artifact.self, from: line), let purl = artifact.inputPurl else { continue }
            lines.append(.artifact(purl: purl, artifact))
        }
        return lines
    }

    static func parseQuota(_ data: Data) -> SocketQuota? {
        struct Raw: Decodable {
            let quota: Int
            let maxQuota: Int?
            let nextWindowRefresh: String?
        }
        guard let raw = try? JSONDecoder().decode(Raw.self, from: data) else { return nil }
        return SocketQuota(quota: raw.quota, maxQuota: raw.maxQuota ?? raw.quota, nextWindowRefresh: raw.nextWindowRefresh.flatMap(OSVDate.parse))
    }

    static let summaries: [String: String] = [
        "malware": "Socket flags this package as malware.",
        "gptMalware": "Socket's AI scan flags this package as possible malware.",
        "didYouMean": "The name is close to a popular package. It may be a typosquat.",
        "troll": "The package contains protestware.",
        "installScripts": "The package runs scripts when it is installed.",
        "obfuscatedFile": "The package contains obfuscated code.",
    ]

    static func severity(_ text: String?) -> AdvisorySeverity {
        switch text?.lowercased() {
        case "critical": .critical
        case "high": .high
        case "middle", "medium": .medium
        case "low": .low
        default: .unknown
        }
    }

    static func advisories(_ artifact: Artifact, query: PackageQuery) -> [Advisory] {
        var result: [Advisory] = []
        for alert in artifact.alerts {
            guard let summary = summaries[alert.type], !result.contains(where: { $0.id == "SOCKET-\(alert.type)" }) else { continue }
            let malware = alert.type == "malware" || alert.type == "gptMalware"
            let severity = malware ? .critical : Self.severity(alert.severity)
            guard malware || alert.type == "didYouMean" || severity >= .high else { continue }
            result.append(Advisory(
                id: "SOCKET-\(alert.type)",
                summary: summary,
                severity: severity,
                kind: malware ? .malware : .supplyChain,
                links: link(query).map { [$0] } ?? [],
                source: .socket
            ))
        }
        return result.sorted(by: Advisory.ordered)
    }

    static func link(_ query: PackageQuery) -> AdvisoryLink? {
        let type: String? = switch query.ecosystem {
        case "npm": "npm"
        case "PyPI": "pypi"
        case "Go": "go"
        case "crates.io": "cargo"
        case "Packagist": "composer"
        case "RubyGems": "gem"
        default: nil
        }
        guard let type, let name = query.name.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) else { return nil }
        return AdvisoryLink(title: "Socket \(query.name)", url: "https://socket.dev/\(type)/package/\(name)")
    }
}
