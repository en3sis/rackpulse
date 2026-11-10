import Foundation
import Testing
@testable import HetznerKit

struct LiveSecurityTests {
    @Test(.enabled(if: ProcessInfo.processInfo.environment["RACKPULSE_LIVE"] == "1"))
    func osvAnswersRealQueries() async throws {
        let cache = temporaryCache()
        defer { cache.clear() }
        let openssl = PackageQuery(ecosystem: "Ubuntu:24.04:LTS", name: "openssl", version: "3.0.13-0ubuntu3.1")
        let vim = PackageQuery(ecosystem: "Ubuntu:24.04:LTS", name: "vim", version: "2:9.1.0016-1ubuntu7")
        let zlib = PackageQuery(ecosystem: "Ubuntu:24.04:LTS", name: "zlib", version: "1:1.3.dfsg-3.1ubuntu2")
        let lodash = PackageQuery(ecosystem: "npm", name: "lodash", version: "4.17.20")
        let express = PackageQuery(ecosystem: "npm", name: "express", version: "4.17.1")
        let text = PackageQuery(ecosystem: "Go", name: "golang.org/x/text", version: "v0.3.0")
        let binutils = PackageQuery(ecosystem: "Ubuntu:24.04:LTS", name: "binutils", version: "2.42-4ubuntu2")

        let source = OSVSource(cache: cache)
        let lookup = try await source.lookup([openssl, vim, zlib, lodash, express, text, binutils])
        for (query, advisories) in lookup.advisories.sorted(by: { $0.key < $1.key }) {
            let fixable = advisories.filter(\.hasFix).count
            let worst = advisories.map(\.severity).max() ?? .unknown
            print("LIVE \(query.ecosystem) \(query.name) \(query.version): \(advisories.count) advisories, \(fixable) with a fix, worst \(worst.rawValue)")
        }
        print("LIVE problem: \(lookup.problem ?? "none")")

        let cve = try #require(lookup.advisories[openssl]?.first { $0.id == "CVE-2024-6119" })
        #expect(cve.fixedVersion == "3.0.13-0ubuntu3.4")
        #expect(cve.fixedBy.contains("USN-6986-1"))
        #expect(lookup.advisories[lodash]?.contains { $0.id == "CVE-2021-23337" && $0.fixedVersion == "4.17.21" } == true)
        #expect(lookup.advisories[text]?.contains { $0.id == "CVE-2020-14040" } == true)
        #expect(lookup.advisories[vim]?.isEmpty == false)
        #expect(lookup.advisories[binutils]?.contains { !$0.hasFix } == true)

        let kev = try await KEVSource(cache: cache).enrichment(for: ["CVE-2021-44228"])
        #expect(kev.values["CVE-2021-44228"]?.knownExploited != nil)
        let epss = try await EPSSSource(cache: cache).enrichment(for: ["CVE-2021-44228", "CVE-2024-6119"])
        #expect(epss.values["CVE-2021-44228"]?.epss != nil)
        print("LIVE EPSS CVE-2021-44228 \(epss.values["CVE-2021-44228"]?.epss.map { "\($0.probability) / \($0.percentile)" } ?? "none")")
    }

    @Test(.enabled(if: ProcessInfo.processInfo.environment["RACKPULSE_LIVE"] == "1"))
    func epssDailyFileLoads() async throws {
        let cache = temporaryCache()
        defer { cache.clear() }
        let source = EPSSSource(cache: cache)
        let lookup = try await source.enrichment(for: ["CVE-2021-44228"])
        #expect(lookup.problem == nil)
        #expect(lookup.values["CVE-2021-44228"]?.epss?.likelyExploited == true)
    }
}
