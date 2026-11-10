import Foundation
import Testing
@testable import HetznerKit

struct VersionTests {
    @Test(arguments: [
        ("1.0", "1.1", -1),
        ("1:1.0", "2.0", 1),
        ("0:1.0", "1.0", 0),
        ("1.0-0", "1.0", 0),
        ("1.01", "1.1", 0),
        ("1.0~rc1", "1.0", -1),
        ("1.0~~", "1.0~~a", -1),
        ("1.0~~a", "1.0~", -1),
        ("1.0~", "1.0", -1),
        ("1.0", "1.0a", -1),
        ("1.0a", "1.0b", -1),
        ("1.0", "1.0+b1", -1),
        ("1.0-1", "1.0-2", -1),
        ("1.2.3-1", "1.2.3-1.1", -1),
        ("7.6p1-4", "7.6-4", 1),
        ("2:9.0.1378-2", "9.1.0016-1ubuntu7", 1),
        ("3.0.13-0ubuntu3.4", "3.0.13-0ubuntu3.16", -1),
        ("3.0.14-1~deb12u2", "3.0.11-1~deb12u2", 1),
        ("1:1.3.dfsg-3.1ubuntu2.2", "1:1.3.dfsg-3.1ubuntu2.3", -1),
        ("1:2.38.1-5+deb12u3", "1:2.38.1-5+deb12u2", 1),
        ("2026c-0+deb12u1", "2026e-0+deb12u1", -1),
    ])
    func dpkgOrder(_ lhs: String, _ rhs: String, _ expected: Int) {
        #expect(DebianVersion.compare(lhs, rhs) == expected)
        #expect(DebianVersion.compare(rhs, lhs) == -expected)
    }

    @Test(arguments: [
        ("4.17.20", "4.17.21", -1),
        ("1.0.0-beta", "1.0.0", -1),
        ("v0.3.0", "0.3.0", 0),
        ("2.20.0", "2.19.0", 1),
        ("1.10", "1.9", 1),
        ("2.0rc1", "2.0", -1),
        ("1.0", "1.0.1", -1),
        ("1.2.3+build5", "1.2.3", 0),
    ])
    func genericOrder(_ lhs: String, _ rhs: String, _ expected: Int) {
        #expect(VersionOrder.compare(lhs, rhs, ecosystem: "npm") == expected)
    }

    @Test(arguments: [
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5),
        ("CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H", 7.2),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),
        ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H", 9.9),
        ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8),
        ("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N", 5.9),
        ("CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N", 4.7),
        ("CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N", 0.0),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:P/RL:O", 9.8),
    ])
    func cvssBaseScore(_ vector: String, _ score: Double) {
        #expect(CVSS3.baseScore(vector) == score)
    }

    @Test func cvssRejectsBadVectors() {
        #expect(CVSS3.baseScore("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N") == nil)
        #expect(CVSS3.baseScore("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/C:H/I:H/A:H") == nil)
        #expect(CVSS3.baseScore("CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == nil)
        #expect(CVSS3.baseScore("CVSS:3.1/AV:N/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == nil)
        #expect(AdvisorySeverity(score: 9.0) == .critical)
        #expect(AdvisorySeverity(score: 6.9) == .medium)
        #expect(AdvisorySeverity(score: 0.1) == .low)
        #expect(AdvisorySeverity(rank: 3) == .high)
    }
}
