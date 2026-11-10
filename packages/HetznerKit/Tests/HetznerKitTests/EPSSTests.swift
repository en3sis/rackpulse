import Compression
import Foundation
import Testing
@testable import HetznerKit

func gzip(_ data: Data, name: String? = nil, extra: Data? = nil, comment: String? = nil, headerCRC: Bool = false) -> Data {
    let input = [UInt8](data)
    var output = [UInt8](repeating: 0, count: input.count + 1_024)
    let size = compression_encode_buffer(&output, output.count, input, input.count, nil, COMPRESSION_ZLIB)
    var flags: UInt8 = 0
    if headerCRC { flags |= 0x02 }
    if extra != nil { flags |= 0x04 }
    if name != nil { flags |= 0x08 }
    if comment != nil { flags |= 0x10 }
    var header: [UInt8] = [0x1f, 0x8b, 8, flags, 0, 0, 0, 0, 0, 3]
    if let extra { header += [UInt8(extra.count & 0xFF), UInt8(extra.count >> 8)] + [UInt8](extra) }
    if let name { header += Array(name.utf8) + [0] }
    if let comment { header += Array(comment.utf8) + [0] }
    if headerCRC {
        let crc = CRC32.checksum(Data(header))
        header += [UInt8(crc & 0xFF), UInt8((crc >> 8) & 0xFF)]
    }
    var result = Data(header)
    result.append(contentsOf: output[0..<size])
    let crc = CRC32.checksum(data)
    let length = UInt32(truncatingIfNeeded: data.count)
    for value in [crc, length] { withUnsafeBytes(of: value.littleEndian) { result.append(contentsOf: $0) } }
    return result
}

func gunzip(_ data: Data, limit: Int = 1 << 20) throws -> Data {
    var output = Data()
    try Gzip.decompress(data, limit: limit) { output.append($0) }
    return output
}

func epssCSV(_ rows: [(String, String, String)], date: String = "2026-11-03") -> Data {
    var text = "#model_version:v2026.06.15,score_date:\(date)T12:00:27Z\ncve,epss,percentile\n"
    for row in rows { text += "\(row.0),\(row.1),\(row.2)\n" }
    return Data(text.utf8)
}

struct EPSSTests {
    static let sample = epssCSV([
        ("CVE-1999-0001", "0.04753", "0.91894"),
        ("CVE-2021-44228", "0.99999", "1.0"),
        ("CVE-2024-10000", "0.00012", "0.01000"),
        ("CVE-2024-9999", "0.66", "0.99"),
        ("not-a-cve", "0.5", "0.5"),
        ("CVE-2024-0002", "2.5", "0.5"),
        ("CVE-2024-0003", "0.1", ""),
    ])

    @Test func readsGzipHeadersAndTrailers() throws {
        let text = Data(String(repeating: "cve,epss,percentile\n", count: 5_000).utf8)
        #expect(try gunzip(gzip(text)) == text)
        #expect(try gunzip(gzip(text, name: "epss_scores-2026-11-03.csv", extra: Data([1, 2, 3]), comment: "x", headerCRC: true)) == text)
        #expect(try gunzip(gzip(Data())) == Data())

        let fixture = try Data(contentsOf: try #require(Bundle.module.url(forResource: "epss-sample.csv", withExtension: "gz", subdirectory: "Fixtures")))
        let csv = try gunzip(fixture)
        #expect(String(decoding: csv, as: UTF8.self).hasPrefix("#model_version:"))
    }

    @Test func rejectsBrokenGzip() throws {
        let good = gzip(Self.sample)
        var badCRC = good
        badCRC[badCRC.count - 8] ^= 0xFF
        var badSize = good
        badSize[badSize.count - 1] ^= 0x01
        var badMagic = good
        badMagic[0] = 0
        var badMethod = good
        badMethod[2] = 7
        var reserved = good
        reserved[3] = 0x20
        var badHeaderCRC = gzip(Self.sample, name: "x", headerCRC: true)
        badHeaderCRC[13] ^= 0xFF
        var corrupt = good
        for index in 12..<min(40, corrupt.count - 8) { corrupt[index] = 0xFF }

        #expect(throws: Gzip.Failure.checksum) { try gunzip(badCRC) }
        #expect(throws: Gzip.Failure.size) { try gunzip(badSize) }
        #expect(throws: Gzip.Failure.header) { try gunzip(badMagic) }
        #expect(throws: Gzip.Failure.header) { try gunzip(badMethod) }
        #expect(throws: Gzip.Failure.header) { try gunzip(reserved) }
        #expect(throws: Gzip.Failure.header) { try gunzip(badHeaderCRC) }
        #expect(throws: (any Error).self) { try gunzip(corrupt) }
        #expect(throws: (any Error).self) { try gunzip(good.prefix(good.count - 3)) }
        #expect(throws: (any Error).self) { try gunzip(good.prefix(good.count / 2)) }
        #expect(throws: (any Error).self) { try gunzip(good + Data([0])) }
        #expect(throws: (any Error).self) { try gunzip(Data([0x1f, 0x8b, 8, 0x08, 0, 0, 0, 0, 0, 3, 65, 65, 65, 65, 65, 65, 65, 65, 65])) }
        #expect(throws: Gzip.Failure.tooLarge) { try gunzip(gzip(Data(count: 200_000)), limit: 100_000) }
    }

    @Test func parsesRowsAndLooksThemUp() throws {
        let table = try EPSSTable.parse(gzip: gzip(Self.sample), limits: .standard)
        #expect(table.count == 4)
        #expect(table.meta.scoreDate == "2026-11-03T12:00:27Z")
        #expect(table.meta.modelVersion == "v2026.06.15")
        #expect(table.score(for: "CVE-2021-44228") == EPSSScore(probability: 0.99999, percentile: 1.0))
        #expect(table.score(for: "CVE-2024-9999") == EPSSScore(probability: 0.66, percentile: 0.99))
        #expect(table.score(for: "CVE-2024-10000")?.probability == 0.00012)
        #expect(table.score(for: "CVE-2024-0002") == nil)
        #expect(table.score(for: "CVE-2024-0003") == nil)
        #expect(table.score(for: "CVE-2030-0001") == nil)
        #expect(table.score(for: "CVE-1999-0001")?.percentile == 0.91894)
        #expect(table.score(for: "nonsense") == nil)

        let decoded = try #require(EPSSTable(encoded: table.encoded()))
        #expect(decoded.count == 4)
        #expect(decoded.score(for: "CVE-2021-44228") == table.score(for: "CVE-2021-44228"))
        #expect(EPSSTable(encoded: Data("EPS1".utf8)) == nil)
        #expect(EPSSTable(encoded: table.encoded().dropLast(3)) == nil)

        let tiny = EPSSSource.Limits(compressed: 1 << 20, decompressed: 1 << 20, rows: 2)
        #expect(throws: SecuritySourceError.invalidResponse(host: SourceName.epss.host)) { try EPSSTable.parse(gzip: gzip(Self.sample), limits: tiny) }
        #expect(throws: SecuritySourceError.invalidResponse(host: SourceName.epss.host)) { try EPSSTable.parse(gzip: gzip(Data("cve,epss,percentile\n".utf8)), limits: .standard) }
    }

    @Test func downloadsTheDailyFileOnceAndSendsNoCVEs() async throws {
        let hits = Locked<[String]>([])
        let body = Locked(gzip(Self.sample))
        let file = Locked("epss_scores-2026-11-03.csv.gz")
        let transport = RouterTransport { request in
            hits.mutate { $0.append(request.url!.absoluteString) }
            if request.url!.path() == "/epss_scores-current.csv.gz" { return .init(status: 302, body: Data(), headers: ["Location": file.value]) }
            if request.url!.path() == "/" + file.value { return .init(body: body.value) }
            return .init(status: 404, body: Data())
        }
        let clock = Clock(date("2026-11-04T10:00:00Z"))
        let cache = temporaryCache()
        let source = EPSSSource(cache: cache, transport: transport, clock: { clock.now }, sleep: { _ in })

        let first = try await source.enrichment(for: ["CVE-2021-44228", "CVE-2024-9999", "CVE-2030-0001"])
        #expect(first.problem == nil)
        #expect(first.values["CVE-2021-44228"]?.epss?.likelyExploited == true)
        #expect(first.values["CVE-2024-9999"]?.epss == EPSSScore(probability: 0.66, percentile: 0.99))
        #expect(first.values["CVE-2030-0001"] == nil)
        #expect(hits.value == [
            "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz",
            "https://epss.empiricalsecurity.com/epss_scores-2026-11-03.csv.gz",
        ])
        #expect(transport.requests.allSatisfy { !($0.url!.absoluteString.contains("CVE")) && $0.httpBody == nil })

        clock.advance(3_600)
        _ = try await source.enrichment(for: ["CVE-2021-44228"])
        #expect(hits.value.count == 2)

        clock.advance(24 * 3_600)
        let same = try await source.enrichment(for: ["CVE-2021-44228"])
        #expect(same.values["CVE-2021-44228"] != nil)
        #expect(hits.value.count == 3)

        file.set("epss_scores-2026-11-05.csv.gz")
        body.set(gzip(epssCSV([("CVE-2021-44228", "0.5", "0.5")], date: "2026-11-05")))
        clock.advance(25 * 3_600)
        let next = try await source.enrichment(for: ["CVE-2021-44228"])
        #expect(next.values["CVE-2021-44228"]?.epss?.probability == 0.5)
        #expect(hits.value.count == 5)

        let reopened = EPSSSource(cache: cache, transport: RouterTransport { _ in .init(status: 500, body: Data()) }, clock: { clock.now }, sleep: { _ in })
        let cached = try await reopened.enrichment(for: ["CVE-2021-44228"])
        #expect(cached.values["CVE-2021-44228"]?.epss?.probability == 0.5)
        #expect(cached.problem == nil)
    }

    @Test func fallsBackToCachedScoresAndWaitsBeforeRetrying() async throws {
        let failing = Locked(false)
        let hits = Locked<[String]>([])
        let transport = RouterTransport { request in
            hits.mutate { $0.append(request.url!.path()) }
            if failing.value { return .init(status: 503, body: Data()) }
            if request.url!.path() == "/epss_scores-current.csv.gz" { return .init(status: 302, body: Data(), headers: ["Location": "/epss_scores-2026-11-03.csv.gz"]) }
            return .init(body: gzip(Self.sample))
        }
        let clock = Clock(date("2026-11-04T10:00:00Z"))
        let source = EPSSSource(cache: temporaryCache(), transport: transport, clock: { clock.now }, sleep: { _ in })
        _ = try await source.enrichment(for: ["CVE-2021-44228"])

        failing.set(true)
        clock.advance(25 * 3_600)
        let stale = try await source.enrichment(for: ["CVE-2021-44228"])
        #expect(stale.values["CVE-2021-44228"] != nil)
        #expect(stale.problem?.hasPrefix("Using the scores from") == true)
        let count = hits.value.count
        clock.advance(600)
        let again = try await source.enrichment(for: ["CVE-2021-44228"])
        #expect(again.problem != nil)
        #expect(hits.value.count == count)

        let empty = EPSSSource(cache: temporaryCache(), transport: transport, clock: { clock.now }, sleep: { _ in })
        await #expect(throws: SecuritySourceError.self) { try await empty.enrichment(for: ["CVE-2021-44228"]) }
    }

    @Test func refusesRedirectsAwayFromTheFeedAndBadFiles() async throws {
        let clock = Clock(date("2026-11-04T10:00:00Z"))
        for location in ["https://evil.example/epss.csv.gz", "http://epss.empiricalsecurity.com/x.csv.gz", "/a/b.csv.gz", "/epss.txt", "https://epss.empiricalsecurity.com:8443/x.csv.gz"] {
            let transport = RouterTransport { request in
                if request.url!.path() == "/epss_scores-current.csv.gz" { return .init(status: 302, body: Data(), headers: ["Location": location]) }
                return .init(body: gzip(Self.sample))
            }
            let source = EPSSSource(cache: temporaryCache(), transport: transport, clock: { clock.now }, sleep: { _ in })
            await #expect(throws: SecuritySourceError.invalidResponse(host: SourceName.epss.host), "\(location)") { try await source.enrichment(for: ["CVE-2021-44228"]) }
            #expect(transport.requests.count == 1)
        }

        var corrupt = gzip(Self.sample)
        corrupt[corrupt.count - 6] ^= 0x55
        for body in [corrupt, Data("not gzip".utf8), Data(count: 2_000)] {
            let transport = RouterTransport { _ in .init(body: body) }
            let limits = EPSSSource.Limits(compressed: 1_000, decompressed: 1 << 20, rows: 100)
            let source = EPSSSource(cache: temporaryCache(), transport: transport, clock: { clock.now }, sleep: { _ in }, limits: limits)
            await #expect(throws: SecuritySourceError.invalidResponse(host: SourceName.epss.host)) { try await source.enrichment(for: ["CVE-2021-44228"]) }
        }
        #expect(SecurityHTTP.allowedHosts.contains("epss.empiricalsecurity.com"))
        #expect(!SecurityHTTP.allowedHosts.contains("api.first.org"))
    }
}

final class Locked<Value>: @unchecked Sendable {
    private let lock = NSLock()
    private var current: Value

    init(_ value: Value) {
        current = value
    }

    var value: Value { lock.withLock { current } }

    func set(_ value: Value) {
        lock.withLock { current = value }
    }

    func mutate(_ change: (inout Value) -> Void) {
        lock.withLock { change(&current) }
    }
}
