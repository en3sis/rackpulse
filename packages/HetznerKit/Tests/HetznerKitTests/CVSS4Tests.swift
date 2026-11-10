import Foundation
import Testing
@testable import HetznerKit

struct CVSS4Tests {
    @Test func matchesTheReferenceCalculator() throws {
        let data = try fixture("cvss4-base-vectors")
        let object = try #require(try JSONSerialization.jsonObject(with: data) as? [String: Any])
        let rows = try #require(object["vectors"] as? [[Any]])
        #expect(rows.count > 1_000)
        for row in rows {
            let vector = try #require(row[0] as? String)
            let score = try #require((row[1] as? NSNumber)?.doubleValue)
            #expect(CVSS4.baseScore(vector) == score, "\(vector)")
        }
    }

    @Test(arguments: [
        ("CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 7.3),
        ("CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:A/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N", 4.6),
        ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:N/VI:N/VA:N/SC:L/SI:L/SA:N", 5.1),
        ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:L/SI:L/SA:N", 6.9),
        ("CVSS:4.0/AV:L/AC:L/AT:N/PR:H/UI:N/VC:N/VI:N/VA:N/SC:H/SI:N/SA:N", 5.9),
        ("CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H", 9.4),
        ("CVSS:4.0/AV:A/AC:L/AT:N/PR:N/UI:N/VC:N/VI:L/VA:N/SC:H/SI:N/SA:H", 6.4),
        ("CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N", 7.1),
        ("CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N", 8.2),
        ("CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:P/VC:N/VI:N/VA:N/SC:L/SI:L/SA:N", 5.1),
        ("CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:A/VC:H/VI:H/VA:H/SC:L/SI:L/SA:N", 8.5),
        ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N", 5.1),
        ("CVSS:4.0/AV:N/AC:L/AT:P/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 7.7),
        ("CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 8.5),
        ("CVSS:4.0/AV:P/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:H/SA:N/S:P/V:D", 8.3),
        ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H", 10.0),
        ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N", 0.0),
    ])
    func publishedExamples(_ vector: String, _ score: Double) {
        #expect(CVSS4.baseScore(vector) == score)
    }

    @Test func rejectsMalformedVectors() {
        #expect(CVSS4.baseScore("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == nil)
        #expect(CVSS4.baseScore("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N") == nil)
        #expect(CVSS4.baseScore("CVSS:4.0/AV:X/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N") == nil)
        #expect(CVSS4.baseScore("CVSS:4.0/AV:N/AV:L/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N") == nil)
        #expect(CVSS4.baseScore("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:S/SA:N") == nil)
        #expect(CVSS4.baseScore("") == nil)
        #expect(CVSS3.baseScore("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N") == nil)
    }

    @Test func threatAndEnvironmentalMetricsDoNotChangeTheBaseScore() {
        let base = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
        #expect(CVSS4.baseScore(base + "/E:U/CR:L/MAV:P") == CVSS4.baseScore(base))
    }

    func record(_ id: String, _ scores: [(String, String)]) -> OSVRecord {
        OSVRecord(id: id, severity: scores.map { OSVRecord.Score(type: $0.0, score: $0.1) }, affected: [
            .init(package: .init(name: "pkg", ecosystem: "npm"), ranges: [.init(type: "SEMVER", events: [.init(introduced: "0"), .init(fixed: "2.0.0")])]),
        ])
    }

    @Test func versionFourOnlyAdvisoriesGetASeverity() {
        let query = PackageQuery(ecosystem: "npm", name: "pkg", version: "1.0.0")
        let advisory = OSVNormalizer.advisories([record("GHSA-aaaa-bbbb-cccc", [("CVSS_V4", "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N")])], for: query)[0]
        #expect(advisory.score == 7.1)
        #expect(advisory.severity == .high)
    }

    @Test func versionThreeWinsWhenBothExist() {
        let query = PackageQuery(ecosystem: "npm", name: "pkg", version: "1.0.0")
        let both = record("GHSA-aaaa-bbbb-cccc", [
            ("CVSS_V4", "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"),
            ("CVSS_V3", "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"),
        ])
        let advisory = OSVNormalizer.advisories([both], for: query)[0]
        #expect(advisory.score == 6.1)
        #expect(advisory.severity == .medium)

        let unscorable = record("GHSA-dddd-eeee-ffff", [("CVSS_V3", "CVSS:3.1/broken"), ("CVSS_V4", "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H")])
        #expect(OSVNormalizer.advisories([unscorable], for: query)[0].severity == .critical)
    }
}
