import Foundation
import Testing
@testable import HetznerKit

struct OSVTests {
    @Test func ubuntuRecordsMergeIntoOneCVEWithTheUbuntuRating() throws {
        let query = PackageQuery(ecosystem: "Ubuntu:24.04:LTS", name: "openssl", version: "3.0.13-0ubuntu3.1")
        let advisories = OSVNormalizer.advisories([try osvRecord("UBUNTU-CVE-2024-6119"), try osvRecord("USN-6986-1")], for: query)
        #expect(advisories.count == 1)
        let advisory = try #require(advisories.first)
        #expect(advisory.id == "CVE-2024-6119")
        #expect(advisory.aliases.contains("UBUNTU-CVE-2024-6119"))
        #expect(!advisory.aliases.contains("USN-6986-1"))
        #expect(advisory.fixedBy == ["USN-6986-1"])
        #expect(advisory.severity == .medium)
        #expect(advisory.score == 7.5)
        #expect(advisory.fixedVersion == "3.0.13-0ubuntu3.4")
        #expect(!advisory.summary.isEmpty)
        let urls = advisory.links.map(\.url.absoluteString)
        #expect(urls.contains("https://ubuntu.com/security/CVE-2024-6119"))
        #expect(urls.contains("https://ubuntu.com/security/notices/USN-6986-1"))
        #expect(urls.contains("https://nvd.nist.gov/vuln/detail/CVE-2024-6119"))
        #expect(urls.allSatisfy { $0.hasPrefix("https://") })
    }

    @Test func fixedVersionComesFromTheMatchingEcosystemOnly() throws {
        let record = try osvRecord("UBUNTU-CVE-2024-6119")
        let jammy = PackageQuery(ecosystem: "Ubuntu:22.04:LTS", name: "openssl", version: "3.0.2-0ubuntu1.10")
        #expect(record.fixedVersion(for: jammy) == "3.0.2-0ubuntu1.18")
        let fips = PackageQuery(ecosystem: "Ubuntu:Pro:FIPS-preview:22.04:LTS", name: "openssl", version: "3.0.2-0ubuntu1.12+Fips1")
        #expect(record.fixedVersion(for: fips) == nil)
        #expect(record.trimmed().affected.allSatisfy { !$0.package.ecosystem.hasPrefix("Ubuntu:Pro:") })
        let nodejs = PackageQuery(ecosystem: "Ubuntu:24.04:LTS", name: "nodejs", version: "18.19.1+dfsg-6ubuntu5")
        #expect(record.fixedVersion(for: nodejs) == nil)
    }

    @Test func debianUrgencyFallsThroughToCVSSAndNoticeAttaches() throws {
        let query = PackageQuery(ecosystem: "Debian:12", name: "openssl", version: "3.0.11-1~deb12u2")
        let advisories = OSVNormalizer.advisories([try osvRecord("DEBIAN-CVE-2024-6119"), try osvRecord("DSA-5764-1")], for: query)
        #expect(advisories.count == 1)
        #expect(advisories[0].id == "CVE-2024-6119")
        #expect(advisories[0].severity == .high)
        #expect(advisories[0].fixedVersion == "3.0.14-1~deb12u2")
        #expect(advisories[0].fixedBy == ["DSA-5764-1"])
        #expect(advisories[0].links.map(\.url.absoluteString).contains("https://security-tracker.debian.org/tracker/DSA-5764-1"))

        var unimportant = try osvRecord("DEBIAN-CVE-2024-6119")
        unimportant.affected[0].ecosystemSpecific = .init(urgency: "unimportant")
        let hidden = OSVNormalizer.advisories([unimportant], for: query)
        #expect(hidden[0].severity == .low)
        #expect(hidden[0].hidden)
    }

    @Test func languageRecordsUseGHSAAndEcosystemRanges() throws {
        let lodash = PackageQuery(ecosystem: "npm", name: "lodash", version: "4.17.20")
        let ghsa = OSVNormalizer.advisories([try osvRecord("GHSA-35jh-r3h4-6jhm")], for: lodash)[0]
        #expect(ghsa.id == "CVE-2021-23337")
        #expect(ghsa.aliases == ["GHSA-35jh-r3h4-6jhm"])
        #expect(ghsa.severity == .high)
        #expect(ghsa.score == 7.2)
        #expect(ghsa.fixedVersion == "4.17.21")
        #expect(ghsa.links.map(\.url.absoluteString).contains("https://github.com/advisories/GHSA-35jh-r3h4-6jhm"))
        let template = PackageQuery(ecosystem: "npm", name: "lodash.template", version: "4.5.0")
        #expect(OSVNormalizer.advisories([try osvRecord("GHSA-35jh-r3h4-6jhm")], for: template)[0].fixedVersion == nil)

        let requests = PackageQuery(ecosystem: "PyPI", name: "Requests", version: "2.19.0")
        let pysec = OSVNormalizer.advisories([try osvRecord("PYSEC-2018-28")], for: requests)[0]
        #expect(pysec.id == "CVE-2018-18074")
        #expect(pysec.fixedVersion == "2.20.0")
        #expect(pysec.severity == .unknown)
        #expect(pysec.aliases.contains("GHSA-x84v-xcm2-53pg"))

        let text = PackageQuery(ecosystem: "Go", name: "golang.org/x/text", version: "v0.3.0")
        let go = OSVNormalizer.advisories([try osvRecord("GO-2020-0015")], for: text)[0]
        #expect(go.id == "CVE-2020-14040")
        #expect(go.fixedVersion == "0.3.3")

        let stream = PackageQuery(ecosystem: "npm", name: "flatmap-stream", version: "0.1.1")
        let malware = OSVNormalizer.advisories([try osvRecord("MAL-2025-20690")], for: stream)[0]
        #expect(malware.kind == .malware)
        #expect(malware.severity == .critical)
        #expect(malware.fixedVersion == nil)
    }

    @Test func dedupGroupsByCVEAcrossGHSAAndPYSEC() {
        let query = PackageQuery(ecosystem: "PyPI", name: "pkg", version: "1.0")
        let affected = [OSVRecord.Affected(package: .init(name: "pkg", ecosystem: "PyPI"), ranges: [
            .init(type: "ECOSYSTEM", events: [.init(introduced: "0"), .init(fixed: "1.1")]),
        ])]
        let records = [
            OSVRecord(id: "PYSEC-2024-1", aliases: ["CVE-2024-1", "GHSA-aaaa-bbbb-cccc"], affected: affected),
            OSVRecord(id: "GHSA-aaaa-bbbb-cccc", summary: "Bad thing", aliases: ["CVE-2024-1"],
                      databaseSpecific: .init(severity: "MODERATE"), affected: affected),
            OSVRecord(id: "GHSA-dddd-eeee-ffff", summary: "Other", affected: affected),
        ]
        let advisories = OSVNormalizer.advisories(records, for: query)
        #expect(advisories.map(\.id).sorted() == ["CVE-2024-1", "GHSA-dddd-eeee-ffff"])
        let merged = advisories.first { $0.id == "CVE-2024-1" }
        #expect(merged?.summary == "Bad thing")
        #expect(merged?.severity == .medium)
        #expect(merged?.aliases == ["GHSA-aaaa-bbbb-cccc", "PYSEC-2024-1"])
        #expect(merged?.fixedVersion == "1.1")
    }

    @Test func noticeLinkedOnlyThroughRelatedMergesIntoItsCVE() {
        let query = PackageQuery(ecosystem: "Ubuntu:24.04:LTS", name: "sudo", version: "1.9.15p5-3ubuntu5")
        let affected = [OSVRecord.Affected(package: .init(name: "sudo", ecosystem: "Ubuntu:24.04:LTS"), ranges: [
            .init(type: "ECOSYSTEM", events: [.init(introduced: "0"), .init(fixed: "1.9.15p5-3ubuntu5.24.04.4")]),
        ])]
        let records = [
            OSVRecord(id: "UBUNTU-CVE-2026-35535", upstream: ["CVE-2026-35535"], affected: affected),
            OSVRecord(id: "USN-8092-1", related: ["UBUNTU-CVE-2026-35535"], affected: affected),
            OSVRecord(id: "GHSA-aaaa-bbbb-cccc", related: ["UBUNTU-CVE-2026-1"], affected: affected),
        ]
        let advisories = OSVNormalizer.advisories(records, for: query)
        #expect(advisories.map(\.id).sorted() == ["CVE-2026-35535", "GHSA-aaaa-bbbb-cccc"])
        #expect(advisories.first { $0.id == "CVE-2026-35535" }?.fixedBy == ["USN-8092-1"])
    }

    @Test func batchesChunksPaginatesAndCaches() async throws {
        let ghsa = try fixture("osv-GHSA-35jh-r3h4-6jhm")
        let mal = try fixture("osv-MAL-2025-20690")
        let transport = RouterTransport { request in
            let path = request.url!.path()
            if path == "/v1/vulns/GHSA-35jh-r3h4-6jhm" { return .init(body: ghsa) }
            if path == "/v1/vulns/MAL-2025-20690" { return .init(body: mal) }
            guard path == "/v1/querybatch",
                  let body = try? JSONSerialization.jsonObject(with: request.httpBody!) as? [String: Any],
                  let queries = body["queries"] as? [[String: Any]] else { return .init(status: 400, body: Data()) }
            let results: [[String: Any]] = queries.map { query in
                let name = (query["package"] as? [String: Any])?["name"] as? String
                guard name == "lodash" else { return [:] }
                if query["page_token"] as? String == "next" {
                    return ["vulns": [["id": "MAL-2025-20690", "modified": "2025-08-14T18:52:04Z"]]]
                }
                return ["vulns": [["id": "GHSA-35jh-r3h4-6jhm", "modified": "2024-01-01T00:00:00Z"]], "next_page_token": "next"]
            }
            return .init(body: json(["results": results]))
        }
        let clock = Clock(date("2026-10-26T10:00:00Z"))
        let source = OSVSource(cache: temporaryCache(), transport: transport, clock: { clock.now }, sleep: { _ in })
        let queries = (0..<1_000).map { PackageQuery(ecosystem: "npm", name: "pkg\($0)", version: "1.0.0") }
            + [PackageQuery(ecosystem: "npm", name: "lodash", version: "4.17.20")]

        let lookup = try await source.lookup(queries)
        let batches = transport.requests.filter { $0.url!.path() == "/v1/querybatch" }
        let sizes = batches.map { ((try? JSONSerialization.jsonObject(with: $0.httpBody!) as? [String: Any])?["queries"] as? [Any])?.count ?? 0 }
        #expect(sizes == [1_000, 1, 1])
        #expect(transport.requests.count == 5)
        #expect(lookup.problem == nil)
        let lodash = try #require(lookup.advisories[PackageQuery(ecosystem: "npm", name: "lodash", version: "4.17.20")])
        #expect(Set(lodash.map(\.id)) == ["CVE-2021-23337", "MAL-2025-20690"])
        #expect(lookup.advisories[queries[0]] == [])

        _ = try await source.lookup(queries)
        #expect(transport.requests.count == 5)

        clock.advance(7 * 3_600)
        _ = try await source.lookup(queries)
        #expect(transport.requests.count == 8)
        #expect(!transport.requests.dropFirst(5).contains { $0.url!.path().hasPrefix("/v1/vulns/") })
    }

    @Test func retriesServerErrorsAndHonorsRetryAfter() async throws {
        let sleeps = Sleeps()
        let counter = Clock(.distantPast)
        let transport = RouterTransport { _ in
            counter.advance(1)
            if counter.now == Date.distantPast.addingTimeInterval(1) { return .init(status: 503, body: Data(), headers: ["Retry-After": "2"]) }
            return .init(body: json(["results": [[:]]]))
        }
        let source = OSVSource(cache: temporaryCache(), transport: transport, sleep: { sleeps.record($0) })
        let lookup = try await source.lookup([PackageQuery(ecosystem: "npm", name: "a", version: "1")])
        #expect(sleeps.values == [2])
        #expect(lookup.advisories.count == 1)

        let limited = OSVSource(
            cache: temporaryCache(),
            transport: RouterTransport { _ in .init(status: 429, body: Data(), headers: ["Retry-After": "600"]) },
            sleep: { _ in }
        )
        await #expect(throws: SecuritySourceError.self) {
            try await limited.lookup([PackageQuery(ecosystem: "npm", name: "a", version: "1")])
        }
    }

    @Test func corruptCacheEntriesAreIgnored() throws {
        let cache = temporaryCache()
        cache.store(Data("{not json".utf8), as: "osv-queries.json")
        #expect(cache.read([String: Int].self, from: "osv-queries.json") == nil)
        #expect(try cache.connection.query("SELECT COUNT(*) FROM security_cache") { $0.int(0) }.first == 0)
        cache.write(["a": 1], to: "x/y.json")
        #expect(cache.read([String: Int].self, from: "x/y.json") == ["a": 1])
        cache.clear()
        #expect(cache.read([String: Int].self, from: "x/y.json") == nil)
    }
}
