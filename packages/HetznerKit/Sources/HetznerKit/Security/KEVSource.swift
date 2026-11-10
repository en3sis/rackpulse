import Foundation

public actor KEVSource: EnrichmentSource {
    public static let feed = URL(string: "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")!
    public static let lifetime: TimeInterval = 86_400
    static let file = "kev.json"

    public nonisolated let name = SourceName.kev
    private let cache: SecurityCache
    private let http: SecurityHTTP
    private let clock: @Sendable () -> Date
    private var state: State?

    struct State: Sendable, Codable {
        var fetched: Date
        var etag: String?
        var lastModified: String?
        var entries: [String: KnownExploited]
    }

    public init(
        cache: SecurityCache,
        transport: HTTPTransport = URLSessionTransport(),
        clock: @escaping @Sendable () -> Date = { Date() },
        sleep: @escaping @Sendable (TimeInterval) async throws -> Void = { try await Task.sleep(for: .seconds($0)) }
    ) {
        self.cache = cache
        self.clock = clock
        http = SecurityHTTP(transport: transport, sleep: sleep, clock: clock)
    }

    public func enrichment(for cves: Set<String>) async throws -> EnrichmentLookup {
        var problem: String?
        var current = state ?? cache.read(State.self, from: Self.file)
        let now = clock()
        if current.map({ now.timeIntervalSince($0.fetched) >= Self.lifetime || $0.fetched > now }) ?? true {
            do {
                current = try await refresh(current, now: now)
                cache.write(current, to: Self.file)
            } catch is CancellationError {
                throw CancellationError()
            } catch {
                guard current != nil else { throw error }
                problem = "Using the list from \(current!.fetched.formatted(date: .abbreviated, time: .omitted)). " + ((error as? SecuritySourceError)?.message ?? "")
            }
        }
        state = current
        let entries = current?.entries ?? [:]
        var values: [String: Enrichment] = [:]
        for cve in cves {
            if let entry = entries[cve] { values[cve] = Enrichment(knownExploited: entry) }
        }
        return EnrichmentLookup(values: values, problem: problem)
    }

    private func refresh(_ current: State?, now: Date) async throws -> State {
        var headers: [String: String] = [:]
        if current != nil, let etag = current?.etag { headers["If-None-Match"] = etag }
        if current != nil, let modified = current?.lastModified { headers["If-Modified-Since"] = modified }
        let (data, response) = try await http.send(try http.request(Self.feed, headers: headers))
        if response.statusCode == 304, var current {
            current.fetched = now
            return current
        }
        guard response.statusCode == 200 else { throw SecuritySourceError.status(response.statusCode, host: SourceName.kev.host) }
        guard let entries = Self.parse(data) else { throw SecuritySourceError.invalidResponse(host: SourceName.kev.host) }
        return State(
            fetched: now,
            etag: response.value(forHTTPHeaderField: "ETag"),
            lastModified: response.value(forHTTPHeaderField: "Last-Modified"),
            entries: entries
        )
    }

    struct Feed: Decodable {
        struct Entry: Decodable {
            let cveID: String
            let dateAdded: String?
            let knownRansomwareCampaignUse: String?

            enum CodingKeys: String, CodingKey {
                case cveID, dateAdded, knownRansomwareCampaignUse
            }

            init(from decoder: Decoder) throws {
                let container = try decoder.container(keyedBy: CodingKeys.self)
                cveID = try container.decode(String.self, forKey: .cveID)
                dateAdded = container.optional(String.self, forKey: .dateAdded)
                knownRansomwareCampaignUse = container.optional(String.self, forKey: .knownRansomwareCampaignUse)
            }
        }

        let vulnerabilities: [Entry]

        enum CodingKeys: String, CodingKey {
            case vulnerabilities
        }

        init(from decoder: Decoder) throws {
            let container = try decoder.container(keyedBy: CodingKeys.self)
            guard container.contains(.vulnerabilities) else {
                throw DecodingError.keyNotFound(CodingKeys.vulnerabilities, .init(codingPath: [], debugDescription: "Missing list"))
            }
            vulnerabilities = container.lossy([Entry].self, forKey: .vulnerabilities)
        }
    }

    static func parse(_ data: Data) -> [String: KnownExploited]? {
        guard let feed = try? JSONDecoder().decode(Feed.self, from: data) else { return nil }
        var entries: [String: KnownExploited] = [:]
        for entry in feed.vulnerabilities where entry.cveID.hasPrefix("CVE-") {
            entries[entry.cveID] = KnownExploited(
                dateAdded: entry.dateAdded,
                ransomware: entry.knownRansomwareCampaignUse?.caseInsensitiveCompare("Known") == .orderedSame
            )
        }
        return entries
    }
}
