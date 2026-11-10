import Foundation

public actor EPSSSource: EnrichmentSource {
    public static let feed = URL(string: "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz")!
    public static let lifetime: TimeInterval = 86_400
    public static let retryDelay: TimeInterval = 3_600
    static let file = "epss-scores.bin"
    static let legacyFile = "epss.json"
    static let redirectLimit = 3

    public struct Limits: Sendable {
        public var compressed: Int
        public var decompressed: Int
        public var rows: Int

        public static let standard = Limits(compressed: 32 << 20, decompressed: 160 << 20, rows: 2_000_000)

        public init(compressed: Int, decompressed: Int, rows: Int) {
            self.compressed = compressed
            self.decompressed = decompressed
            self.rows = rows
        }
    }

    public nonisolated let name = SourceName.epss
    private let cache: SecurityCache
    private let http: SecurityHTTP
    private let clock: @Sendable () -> Date
    private let limits: Limits
    private var table: EPSSTable?
    private var loaded = false
    private var lastFailure: (time: Date, error: Error)?

    public init(
        cache: SecurityCache,
        transport: HTTPTransport = URLSessionTransport(),
        clock: @escaping @Sendable () -> Date = { Date() },
        sleep: @escaping @Sendable (TimeInterval) async throws -> Void = { try await Task.sleep(for: .seconds($0)) },
        limits: Limits = .standard
    ) {
        self.cache = cache
        self.clock = clock
        self.limits = limits
        http = SecurityHTTP(transport: transport, sleep: sleep, clock: clock)
    }

    public func enrichment(for cves: Set<String>) async throws -> EnrichmentLookup {
        let now = clock()
        if !loaded {
            loaded = true
            table = cache.data(Self.file).flatMap(EPSSTable.init(encoded:))
            cache.remove(Self.legacyFile)
        }
        var problem: String?
        if table.map({ now.timeIntervalSince($0.meta.fetched) >= Self.lifetime || $0.meta.fetched > now }) ?? true {
            if let lastFailure, now.timeIntervalSince(lastFailure.time) < Self.retryDelay, lastFailure.time <= now {
                guard let table else { throw lastFailure.error }
                problem = Self.stale(table, error: lastFailure.error)
            } else {
                do {
                    let fresh = try await refresh(table, now: now)
                    table = fresh
                    lastFailure = nil
                    cache.store(fresh.encoded(), as: Self.file)
                } catch is CancellationError {
                    throw CancellationError()
                } catch {
                    lastFailure = (now, error)
                    guard let table else { throw error }
                    problem = Self.stale(table, error: error)
                }
            }
        }
        var values: [String: Enrichment] = [:]
        if let table {
            for cve in cves {
                if let score = table.score(for: cve) { values[cve] = Enrichment(epss: score) }
            }
        }
        return EnrichmentLookup(values: values, problem: problem)
    }

    private static func stale(_ table: EPSSTable, error: Error) -> String {
        "Using the scores from \(table.meta.fetched.formatted(date: .abbreviated, time: .omitted)). " + ((error as? SecuritySourceError)?.message ?? "")
    }

    private func refresh(_ current: EPSSTable?, now: Date) async throws -> EPSSTable {
        var url = Self.feed
        var headers: [String: String] = [:]
        if let current, current.meta.source == nil {
            if let etag = current.meta.etag { headers["If-None-Match"] = etag }
            if let modified = current.meta.lastModified { headers["If-Modified-Since"] = modified }
        }
        for _ in 0...Self.redirectLimit {
            let (data, response) = try await http.send(try http.request(url, headers: headers))
            switch response.statusCode {
            case 301, 302, 303, 307, 308:
                guard let next = Self.redirect(response, from: url) else { throw SecuritySourceError.invalidResponse(host: SourceName.epss.host) }
                let source = next.lastPathComponent
                if var current, current.meta.source == source {
                    current.meta.fetched = now
                    return current
                }
                url = next
                headers = [:]
            case 304:
                guard var current else { throw SecuritySourceError.invalidResponse(host: SourceName.epss.host) }
                current.meta.fetched = now
                return current
            case 200:
                guard data.count <= limits.compressed else { throw SecuritySourceError.invalidResponse(host: SourceName.epss.host) }
                var table = try EPSSTable.parse(gzip: data, limits: limits)
                table.meta.fetched = now
                table.meta.source = url == Self.feed ? nil : url.lastPathComponent
                table.meta.etag = response.value(forHTTPHeaderField: "ETag")
                table.meta.lastModified = response.value(forHTTPHeaderField: "Last-Modified")
                return table
            default:
                throw SecuritySourceError.status(response.statusCode, host: SourceName.epss.host)
            }
        }
        throw SecuritySourceError.invalidResponse(host: SourceName.epss.host)
    }

    static func redirect(_ response: HTTPURLResponse, from url: URL) -> URL? {
        guard let location = response.value(forHTTPHeaderField: "Location"), location.utf8.count <= 512,
              let next = URL(string: location, relativeTo: url)?.absoluteURL,
              next.scheme == "https", next.host() == feed.host(), next.user() == nil, next.port == nil,
              next.query == nil, next.lastPathComponent.hasSuffix(".csv.gz"), next.pathComponents.count == 2
        else { return nil }
        return next
    }
}

struct EPSSTable: Sendable {
    struct Meta: Sendable, Codable {
        var fetched: Date
        var source: String?
        var scoreDate: String?
        var modelVersion: String?
        var etag: String?
        var lastModified: String?
    }

    static let magic = Data("EPS1".utf8)
    static let rowSize = 16
    static let scale = 1_000_000.0

    var meta: Meta
    let rows: Data

    var count: Int { rows.count / Self.rowSize }

    init(meta: Meta, rows: Data) {
        self.meta = meta
        self.rows = rows
    }

    init?(encoded data: Data) {
        guard data.count >= 8, data.prefix(4) == Self.magic else { return nil }
        let length = data.dropFirst(4).prefix(4).enumerated().reduce(0) { $0 | Int($1.element) << (8 * $1.offset) }
        let rowStart = 8 + length
        guard length <= 4_096, data.count >= rowStart, (data.count - rowStart) % Self.rowSize == 0,
              let meta = try? JSONDecoder().decode(Meta.self, from: data.subdata(in: data.startIndex + 8..<data.startIndex + rowStart))
        else { return nil }
        self.meta = meta
        rows = data.subdata(in: data.startIndex + rowStart..<data.endIndex)
    }

    func encoded() -> Data {
        let json = (try? JSONEncoder().encode(meta)) ?? Data("{}".utf8)
        var data = Self.magic
        withUnsafeBytes(of: UInt32(json.count).littleEndian) { data.append(contentsOf: $0) }
        data.append(json)
        data.append(rows)
        return data
    }

    static func key(_ cve: String) -> UInt64? {
        let bytes = Array(cve.utf8)
        guard bytes.count >= 13, bytes.count <= 18, bytes.starts(with: Array("CVE-".utf8)), bytes[8] == UInt8(ascii: "-") else { return nil }
        let year = bytes[4..<8]
        let number = bytes[9...]
        guard year.allSatisfy(Digits.isDigit), number.allSatisfy(Digits.isDigit) else { return nil }
        let y = year.reduce(UInt64(0)) { $0 * 10 + UInt64($1 - 48) }
        let n = number.reduce(UInt64(0)) { $0 * 10 + UInt64($1 - 48) }
        guard n <= UInt64(UInt32.max) else { return nil }
        return y << 32 | n
    }

    func score(for cve: String) -> EPSSScore? {
        guard let key = Self.key(cve) else { return nil }
        return rows.withUnsafeBytes { raw -> EPSSScore? in
            var low = 0
            var high = count
            while low < high {
                let middle = (low + high) / 2
                let found = UInt64(littleEndian: raw.loadUnaligned(fromByteOffset: middle * Self.rowSize, as: UInt64.self))
                if found == key {
                    let probability = UInt32(littleEndian: raw.loadUnaligned(fromByteOffset: middle * Self.rowSize + 8, as: UInt32.self))
                    let percentile = UInt32(littleEndian: raw.loadUnaligned(fromByteOffset: middle * Self.rowSize + 12, as: UInt32.self))
                    return EPSSScore(probability: Double(probability) / Self.scale, percentile: Double(percentile) / Self.scale)
                }
                if found < key { low = middle + 1 } else { high = middle }
            }
            return nil
        }
    }

    static func parse(gzip data: Data, limits: EPSSSource.Limits) throws -> EPSSTable {
        var parser = Parser(rowLimit: limits.rows)
        do {
            try Gzip.decompress(data, limit: limits.decompressed) { try parser.feed($0) }
            try parser.finish()
        } catch let error as SecuritySourceError {
            throw error
        } catch {
            throw SecuritySourceError.invalidResponse(host: SourceName.epss.host)
        }
        guard !parser.rows.isEmpty else { throw SecuritySourceError.invalidResponse(host: SourceName.epss.host) }
        return parser.table()
    }

    struct Parser {
        struct Row {
            var key: UInt64
            var probability: UInt32
            var percentile: UInt32
        }

        enum Failure: Error {
            case tooManyRows
        }

        static let lineLimit = 512

        let rowLimit: Int
        var rows: [Row] = []
        var line: [UInt8] = []
        var overflow = false
        var scoreDate: String?
        var modelVersion: String?

        init(rowLimit: Int) {
            self.rowLimit = rowLimit
        }

        mutating func feed(_ buffer: UnsafeBufferPointer<UInt8>) throws {
            for byte in buffer {
                if byte == UInt8(ascii: "\n") {
                    if !overflow { try handle(line) }
                    line.removeAll(keepingCapacity: true)
                    overflow = false
                } else if !overflow {
                    if line.count >= Self.lineLimit { overflow = true } else { line.append(byte) }
                }
            }
        }

        mutating func finish() throws {
            if !overflow, !line.isEmpty { try handle(line) }
            line = []
        }

        mutating func handle(_ raw: [UInt8]) throws {
            var bytes = raw[...]
            if bytes.last == UInt8(ascii: "\r") { bytes.removeLast() }
            guard let first = bytes.first else { return }
            if first == UInt8(ascii: "#") {
                comment(String(decoding: bytes.dropFirst(), as: UTF8.self))
                return
            }
            let fields = bytes.split(separator: UInt8(ascii: ","), omittingEmptySubsequences: false)
            guard fields.count == 3, let key = EPSSTable.key(String(decoding: fields[0], as: UTF8.self)),
                  let probability = Self.fraction(fields[1]), let percentile = Self.fraction(fields[2])
            else { return }
            guard rows.count < rowLimit else { throw Failure.tooManyRows }
            rows.append(Row(key: key, probability: probability, percentile: percentile))
        }

        mutating func comment(_ text: String) {
            for pair in text.split(separator: ",") {
                let parts = pair.split(separator: ":", maxSplits: 1).map { String($0.prefix(64)) }
                guard parts.count == 2 else { continue }
                if parts[0] == "score_date" { scoreDate = parts[1] }
                if parts[0] == "model_version" { modelVersion = parts[1] }
            }
        }

        static func fraction(_ field: ArraySlice<UInt8>) -> UInt32? {
            guard !field.isEmpty, field.count <= 32,
                  field.allSatisfy({ Digits.isDigit($0) || $0 == UInt8(ascii: ".") || $0 == UInt8(ascii: "e") || $0 == UInt8(ascii: "E") || $0 == UInt8(ascii: "-") }),
                  let value = Double(String(decoding: field, as: UTF8.self)), value.isFinite, value >= 0, value <= 1
            else { return nil }
            return UInt32((value * EPSSTable.scale).rounded())
        }

        func table() -> EPSSTable {
            let sorted = rows.sorted { $0.key < $1.key }
            var data = Data(capacity: sorted.count * EPSSTable.rowSize)
            var previous: UInt64?
            for row in sorted where row.key != previous {
                previous = row.key
                withUnsafeBytes(of: row.key.littleEndian) { data.append(contentsOf: $0) }
                withUnsafeBytes(of: row.probability.littleEndian) { data.append(contentsOf: $0) }
                withUnsafeBytes(of: row.percentile.littleEndian) { data.append(contentsOf: $0) }
            }
            return EPSSTable(
                meta: EPSSTable.Meta(fetched: .distantPast, scoreDate: scoreDate, modelVersion: modelVersion),
                rows: data
            )
        }
    }
}
