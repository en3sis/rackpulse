import Foundation

public actor OSVSource: VulnerabilitySource {
    public static let batchLimit = 1000
    public static let queryLifetime: TimeInterval = 6 * 3_600
    public static let maxPagesPerQuery = 5
    public static let concurrency = 8
    static let queriesFile = "osv-queries.json"
    static let recordsFolder = "osv"
    static let queryLimit = 100_000
    static let recordLimit = 30_000

    public nonisolated let name = SourceName.osv
    private let cache: SecurityCache
    private let http: SecurityHTTP
    private let clock: @Sendable () -> Date
    private var queries: [String: CachedQuery]?

    struct CachedQuery: Sendable, Codable {
        var time: Date
        var vulns: [Listed]
        var truncated: Bool
    }

    struct Listed: Sendable, Hashable, Codable {
        var id: String
        var modified: String?
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

    public nonisolated func supports(_ query: PackageQuery) -> Bool {
        PackageQuery.isSupported(query.ecosystem)
    }

    public func lookup(_ input: [PackageQuery]) async throws -> SourceLookup {
        let wanted = Array(Set(input.filter(supports))).sorted()
        guard !wanted.isEmpty else { return SourceLookup() }
        let now = clock()
        var known = queries ?? cache.read([String: CachedQuery].self, from: Self.queriesFile) ?? [:]
        var problems: [String] = []

        let stale = wanted.filter { query in known[query.key].map { now.timeIntervalSince($0.time) >= Self.queryLifetime || $0.time > now } ?? true }
        var failures = 0
        var lastError: Error?
        for chunk in stride(from: 0, to: stale.count, by: Self.batchLimit).map({ Array(stale[$0..<min($0 + Self.batchLimit, stale.count)]) }) {
            do {
                for (query, result) in try await batch(chunk) {
                    known[query.key] = CachedQuery(time: now, vulns: result.vulns, truncated: result.truncated)
                }
            } catch is CancellationError {
                throw CancellationError()
            } catch {
                failures += chunk.count
                lastError = error
            }
        }
        if failures > 0, !wanted.contains(where: { known[$0.key] != nil }), let lastError { throw lastError }
        if failures > 0 { problems.append("\(failures) packages could not be checked: \(Self.describe(lastError))") }

        let listed = wanted.compactMap { known[$0.key] }
        let truncated = wanted.filter { known[$0.key]?.truncated == true }
        if !truncated.isEmpty {
            problems.append("Only the first \(Self.maxPagesPerQuery * Self.batchLimit) results were read for \(truncated.map(\.name).joined(separator: ", ")).")
        }
        let needed = Dictionary(listed.flatMap(\.vulns).map { ($0.id, $0) }, uniquingKeysWith: { first, _ in first })
        let (records, missing) = await loadRecords(Array(needed.values))
        if missing > 0 { problems.append("\(missing) advisories could not be loaded.") }

        var advisories: [PackageQuery: [Advisory]] = [:]
        for query in wanted {
            guard let entry = known[query.key] else { continue }
            let found = entry.vulns.compactMap { records[$0.id] }
            advisories[query] = found.isEmpty ? [] : OSVNormalizer.advisories(found, for: query)
        }

        let bounded = SecurityCache.bounded(known.filter { now.timeIntervalSince($0.value.time) < 7 * 86_400 }, limit: Self.queryLimit) { $0.time }
        queries = bounded
        cache.write(bounded, to: Self.queriesFile)
        cache.prune(folder: Self.recordsFolder, keeping: Self.recordLimit)
        return SourceLookup(advisories: advisories, problem: problems.isEmpty ? nil : problems.joined(separator: " "))
    }

    private static func describe(_ error: Error?) -> String {
        (error as? SecuritySourceError)?.message ?? "Unknown error."
    }

    struct BatchQuery: Encodable {
        struct Package: Encodable {
            let name: String
            let ecosystem: String
        }

        let package: Package
        let version: String
        let pageToken: String?

        enum CodingKeys: String, CodingKey {
            case package, version
            case pageToken = "page_token"
        }
    }

    struct BatchRequest: Encodable {
        let queries: [BatchQuery]
    }

    struct BatchResponse: Decodable {
        struct Result: Decodable {
            let vulns: [Listed]
            let nextPageToken: String?

            enum CodingKeys: String, CodingKey {
                case vulns
                case nextPageToken = "next_page_token"
            }

            init(from decoder: Decoder) throws {
                let container = try decoder.container(keyedBy: CodingKeys.self)
                vulns = container.lossy([Listed].self, forKey: .vulns)
                nextPageToken = container.optional(String.self, forKey: .nextPageToken).flatMap { $0.isEmpty ? nil : $0 }
            }
        }

        let results: [Result]
    }

    func batch(_ chunk: [PackageQuery]) async throws -> [PackageQuery: (vulns: [Listed], truncated: Bool)] {
        var collected = Dictionary(uniqueKeysWithValues: chunk.map { ($0, (vulns: [Listed](), truncated: false)) })
        var pending: [(PackageQuery, String?)] = chunk.map { ($0, nil) }
        var pages: [PackageQuery: Int] = [:]
        while !pending.isEmpty {
            let page = Array(pending.prefix(Self.batchLimit))
            pending.removeFirst(page.count)
            let body = BatchRequest(queries: page.map {
                BatchQuery(package: .init(name: $0.0.name, ecosystem: $0.0.ecosystem), version: $0.0.version, pageToken: $0.1)
            })
            let request = try http.request(
                URL(string: "https://api.osv.dev/v1/querybatch")!, method: "POST", body: try SecurityHTTP.encoder().encode(body)
            )
            let (data, response) = try await http.send(request)
            guard response.statusCode == 200 else { throw SecuritySourceError.status(response.statusCode, host: "api.osv.dev") }
            guard let decoded = try? JSONDecoder().decode(BatchResponse.self, from: data), decoded.results.count == page.count else {
                throw SecuritySourceError.invalidResponse(host: "api.osv.dev")
            }
            for ((query, _), result) in zip(page, decoded.results) {
                collected[query]?.vulns += result.vulns
                guard let token = result.nextPageToken else { continue }
                let count = (pages[query] ?? 1) + 1
                pages[query] = count
                if count > Self.maxPagesPerQuery {
                    collected[query]?.truncated = true
                } else {
                    pending.append((query, token))
                }
            }
        }
        return collected
    }

    private func loadRecords(_ listed: [Listed]) async -> ([String: OSVRecord], Int) {
        var records: [String: OSVRecord] = [:]
        var stale: [String: OSVRecord] = [:]
        var fetch: [Listed] = []
        for item in listed where OSVNormalizer.isSafeID(item.id) {
            let cached = cache.read(OSVRecord.self, from: Self.recordPath(item.id)).flatMap { $0.id == item.id ? $0 : nil }
            if let cached, Self.isFresh(cached, listed: item) {
                records[item.id] = cached
            } else {
                stale[item.id] = cached
                fetch.append(item)
            }
        }
        var missing = 0
        let http = http
        let cache = cache
        await withTaskGroup(of: (String, OSVRecord?).self) { group in
            var iterator = fetch.makeIterator()
            func next() -> Bool {
                guard let item = iterator.next() else { return false }
                group.addTask {
                    let record = try? await Self.fetchRecord(item.id, http: http)
                    if let record { cache.write(record, to: Self.recordPath(item.id)) }
                    return (item.id, record)
                }
                return true
            }
            for _ in 0..<Self.concurrency where next() {}
            while let (id, record) = await group.next() {
                if let record = record ?? stale[id] { records[id] = record } else { missing += 1 }
                _ = next()
            }
        }
        return (records, missing)
    }

    static func recordPath(_ id: String) -> String {
        "\(recordsFolder)/\(id).json"
    }

    static func isFresh(_ record: OSVRecord, listed: Listed) -> Bool {
        guard let wanted = listed.modified else { return true }
        if let have = record.modifiedDate, let want = OSVDate.parse(wanted) { return have >= want }
        return record.modified == wanted
    }

    static func fetchRecord(_ id: String, http: SecurityHTTP) async throws -> OSVRecord? {
        guard OSVNormalizer.isSafeID(id), let url = URL(string: "https://api.osv.dev/v1/vulns/\(id)") else { return nil }
        let (data, response) = try await http.send(try http.request(url))
        guard response.statusCode == 200 else { return nil }
        guard let record = try? JSONDecoder().decode(OSVRecord.self, from: data), record.id == id else { return nil }
        return record.trimmed()
    }
}
