import Foundation
import Testing
@testable import HetznerKit

struct EcosystemVersionTests {
    func expectOrdered(_ versions: [String], ecosystem: String, sourceLocation: SourceLocation = #_sourceLocation) {
        for (i, a) in versions.enumerated() {
            for (j, b) in versions.enumerated() {
                let want = i == j ? 0 : (i < j ? -1 : 1)
                #expect(VersionOrder.compare(a, b, ecosystem: ecosystem) == want, "\(a) vs \(b)", sourceLocation: sourceLocation)
            }
        }
    }

    @Test(arguments: [
        ("0.1.0_alpha", "0.1.0_alpha", 0),
        ("0.1.0_alpha2", "0.1.0_alpha", 1),
        ("1.3_alpha", "1.3_alpha2", -1),
        ("0.10.1_rc1", "0.9.11", 1),
        ("3.1_p16", "3.1_p17", -1),
        ("2.3.0b-r1", "2.3.0b-r2", -1),
        ("1.06-r6", "006", -1),
        ("1.02", "1.03-r1", -1),
        ("4.2.52_p4-r2", "1.02.07", 1),
        ("2.2.39-r1", "1.0.4-r3", 1),
        ("1.2.2-r1", "1.2.2", 1),
        ("1.1a", "1.3a", -1),
        ("1.0", "1.0bc", -1),
        ("1.0_rc1", "1.0", -1),
        ("1.0_alpha", "1.0_beta", -1),
        ("1.0_beta", "1.0_pre", -1),
        ("1.0_pre", "1.0_rc", -1),
        ("1.0_rc9", "1.0", -1),
        ("1.0", "1.0_cvs", -1),
        ("1.0_cvs", "1.0_svn", -1),
        ("1.0_svn", "1.0_git", -1),
        ("1.0_git", "1.0_hg", -1),
        ("1.0_hg", "1.0_p", -1),
        ("1.0_p1", "1.0-r1", 1),
        ("1.0a", "1.0", 1),
        ("1.0a", "1.0b", -1),
        ("1.0", "1.0-r1", -1),
        ("3.1.4-r5", "3.1.4-r10", -1),
        ("3.3.2-r0", "3.3.2-r1", -1),
        ("1.01", "1.1", -1),
        ("1.0", "1.0.1", -1),
        ("99999999999999999999999", "1", -1),
    ])
    func alpineOrder(_ lhs: String, _ rhs: String, _ expected: Int) {
        #expect(VersionOrder.compare(lhs, rhs, ecosystem: "Alpine:v3.20") == expected)
        #expect(VersionOrder.compare(rhs, lhs, ecosystem: "Alpine:v3.20") == -expected)
    }

    @Test func alpineValidity() {
        #expect(AlpineVersion.isValid("1.2.3_rc1-r0"))
        #expect(AlpineVersion.isValid("0.1_pre2~1234abcd"))
        #expect(AlpineVersion.isValid("0.1_git20240101_pre1"))
        #expect(!AlpineVersion.isValid("1.0_foo"))
        #expect(!AlpineVersion.isValid("1.0-1"))
        #expect(!AlpineVersion.isValid(""))
    }

    @Test func pythonOrder() {
        expectOrdered([
            "1.0.dev456", "1.0a1", "1.0a2.dev456", "1.0a12.dev456", "1.0a12", "1.0b1.dev456", "1.0b2", "1.0b2.post345.dev456",
            "1.0b2.post345", "1.0b2-346", "1.0c1.dev456", "1.0c1", "1.0rc2", "1.0c3", "1.0", "1.0+abc.5", "1.0+abc.7", "1.0+5",
            "1.0.post456.dev34", "1.0.post456", "1.0.15", "1.1.dev1", "1.2+abc", "1.2+0", "1.2+1.abc", "1.2+1.1", "1.2+123456",
            "1.2.r32+123456", "1.2.rev33+123456", "1!1.0.dev0", "1!1.0", "1!1.2.rev33+123456",
        ], ecosystem: "PyPI")
    }

    @Test(arguments: [
        ("1.0-ALPHA1", "1.0a1"),
        ("1.0.0", "1.0.0"),
        ("v1.0", "1.0"),
        ("1.0-1", "1.0.post1"),
        ("1.0.rev1", "1.0.post1"),
        ("1.0-r", "1.0.post0"),
        ("1.0c1", "1.0rc1"),
        ("1.0-preview2", "1.0rc2"),
        ("1.0.DEV", "1.0.dev0"),
        ("1.0+Ubuntu-1", "1.0+ubuntu.1"),
        (" 1.0 ", "1.0"),
        ("01.02", "1.2"),
        ("0!1.0", "1.0"),
        ("2!1.0_beta_2", "2!1.0b2"),
    ])
    func pythonNormalisation(_ input: String, _ expected: String) {
        #expect(PythonVersion.normalized(input) == expected)
        #expect(VersionOrder.compare(input, expected, ecosystem: "PyPI") == 0)
    }

    @Test func pythonEqualityIgnoresTrailingZeros() {
        #expect(VersionOrder.compare("1.0.0", "1", ecosystem: "PyPI") == 0)
        #expect(PythonVersion.normalized("not a version") == nil)
        #expect(PythonVersion.normalized("1.0+") == nil)
    }

    @Test func semverOrder() {
        let precedence = ["1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-alpha.beta", "1.0.0-beta", "1.0.0-beta.2", "1.0.0-beta.11", "1.0.0-rc.1", "1.0.0", "2.0.0", "2.1.0", "2.1.1"]
        expectOrdered(precedence, ecosystem: "npm")
        expectOrdered(precedence, ecosystem: "crates.io")
        for (greater, lesser) in [
            ("0.0.0", "0.0.0-foo"), ("0.10.0", "0.9.0"), ("v0.99.0", "0.10.0"), ("1.2.3", "1.2.3-asdf"), ("1.2.3", "1.2.3-4"),
            ("1.2.3", "1.2.3-4-foo"), ("1.2.3-5-foo", "1.2.3-5"), ("1.2.3-5", "1.2.3-4"), ("1.2.3-5-foo", "1.2.3-5-Foo"),
            ("3.0.0", "2.7.2+asdf"), ("1.2.3-a.10", "1.2.3-a.5"), ("1.2.3-a.b", "1.2.3-a.5"), ("1.2.3-a.b", "1.2.3-a"),
            ("1.2.3-a.b.c.10.d.5", "1.2.3-a.b.c.5.d.100"), ("1.2.3-r2", "1.2.3-r100"), ("1.2.3-r100", "1.2.3-R2"),
        ] {
            #expect(VersionOrder.compare(greater, lesser, ecosystem: "npm") == 1, "\(greater) > \(lesser)")
        }
        #expect(VersionOrder.compare("1.2.3+build.5", "1.2.3", ecosystem: "npm") == 0)
        #expect(VersionOrder.compare("18446744073709551616.0.0", "18446744073709551615.0.0", ecosystem: "npm") == 1)
    }

    @Test func goOrder() {
        expectOrdered([
            "v0.0.0-20190101000000-abcdefabcdef", "v0.1.0", "v1.0.0-alpha", "v1.0.0-alpha.1", "v1.0.0-alpha.beta", "v1.0.0-beta",
            "v1.0.0-beta.2", "v1.0.0-beta.11", "v1.0.0-rc.1", "v1.0.0", "v1.2.0", "v1.2.3-456", "v1.2.3-456.789", "v1.2.3-456-789",
            "v1.2.3-456a", "v1.2.3-pre", "v1.2.3-pre.0.20190101000000-abcdefabcdef", "v1.2.3-pre.1", "v1.2.3-zzz", "v1.2.3",
            "v1.2.4-0.20190101000000-abcdefabcdef", "v1.2.4-0.20200101000000-abcdefabcdef", "v1.2.4", "v2.0.0+incompatible.x", "v2.1.0",
        ].filter { $0 != "v2.0.0+incompatible.x" }, ecosystem: "Go")
        for (a, b) in [("v1", "v1.0.0"), ("v1.2", "v1.2.0"), ("v1.2.3-pre+meta", "v1.2.3-pre"), ("v2.0.0+incompatible", "2.0.0"), ("1.21.0", "v1.21.0")] {
            #expect(VersionOrder.compare(a, b, ecosystem: "Go") == 0, "\(a) == \(b)")
        }
        #expect(SemanticVersion.compare("v1.2-pre", "v1.2.0", shortForms: true) == nil)
        #expect(SemanticVersion.compare("v1", "v1.0.0", shortForms: false) == nil)
    }

    @Test(arguments: [
        ("1.0", "1.0.0", 0),
        ("1.0", "1.0.a", 1),
        ("1.8.2", "0.0.0", 1),
        ("1.8.2", "1.8.2.a", 1),
        ("1.8.2.b", "1.8.2.a", 1),
        ("1.8.2.a", "1.8.2", -1),
        ("1.8.2.a10", "1.8.2.a9", 1),
        ("", "0", 0),
        ("0.beta.1", "0.0.beta.1", 0),
        ("0.0.beta", "0.0.beta.1", -1),
        ("0.0.beta", "0.beta.1", -1),
        ("5.a", "5.0.0.rc2", -1),
        ("5.x", "5.0.0.rc2", 1),
        ("1.0.0-alpha", "1.0.0-alpha.1", -1),
        ("1.0.0-alpha.1", "1.0.0-beta.2", -1),
        ("1.0.0-beta.2", "1.0.0-beta.11", -1),
        ("1.0.0-beta.11", "1.0.0-rc.1", -1),
        ("1.0.0-rc1", "1.0.0", -1),
        ("1.0.0-1", "1", -1),
        ("1.2.b1", "1.2.b.1", 0),
        ("1.0.0.pre", "1.0.0", -1),
        ("7.0.8.1", "7.0.8", 1),
        ("6.1.7.10", "6.1.7.9", 1),
    ])
    func rubyOrder(_ lhs: String, _ rhs: String, _ expected: Int) {
        #expect(VersionOrder.compare(lhs, rhs, ecosystem: "RubyGems") == expected)
        #expect(VersionOrder.compare(rhs, lhs, ecosystem: "RubyGems") == -expected)
    }

    @Test(arguments: [
        ("1.25.0-beta2.1", "1.25.0-b.3", -1),
        ("1.25.0-b2.1", "1.25.0beta.3", -1),
        ("1.25.0-b-2.1", "1.25.0-rc", -1),
        ("1.25.0-beta2.1", "1.25.0-b.2.1", 0),
        ("1.25.0beta2.1", "1.25.0-b2.1", 0),
        ("1.26.0", "dev-foo", 1),
        ("1.0.0", "1.2-dev", -1),
        ("1.0.0-dev", "1.0.0-alpha", -1),
        ("1.0.0-alpha", "1.0.0-beta", -1),
        ("1.0.0-beta", "1.0.0-RC1", -1),
        ("1.0.0-RC1", "1.0.0", -1),
        ("1.0.0", "1.0.0-patch1", -1),
        ("1.0.0-p1", "1.0.0-pl2", -1),
        ("1.0.0-stable", "1.0.0", 0),
        ("v2.0.0", "2.0", 0),
        ("1.0.0-rc1", "1.0.0-RC1", 0),
        ("1.0", "1.0.0.0", 0),
        ("5.4.10", "5.4.9", 1),
    ])
    func composerOrder(_ lhs: String, _ rhs: String, _ expected: Int) {
        #expect(VersionOrder.compare(lhs, rhs, ecosystem: "Packagist") == expected)
        #expect(VersionOrder.compare(rhs, lhs, ecosystem: "Packagist") == -expected)
    }

    @Test(arguments: [
        ("1.0.0", "1.0.0.0"),
        ("1.2.3.4", "1.2.3.4"),
        ("1.0.0RC1dev", "1.0.0.0-RC1-dev"),
        ("1.0.0-rC15-dev", "1.0.0.0-RC15-dev"),
        ("1.0.0.RC.15-dev", "1.0.0.0-RC15-dev"),
        ("1.0.0.pl3-dev", "1.0.0.0-patch3-dev"),
        ("1.0-dev", "1.0.0.0-dev"),
        ("0", "0.0.0.0"),
        ("99999", "99999.0.0.0"),
        ("10.4.13beta.2", "10.4.13.0-beta2"),
        ("v1.13.11-beta.0", "1.13.11.0-beta0"),
        ("10.4.13-b5", "10.4.13.0-beta5"),
        ("1.0.0-beta.5+foo", "1.0.0.0-beta5"),
        ("DEV-FOOBAR", "dev-FOOBAR"),
        ("master", "dev-master"),
    ])
    func composerNormalisation(_ input: String, _ expected: String) {
        #expect(ComposerVersion.normalize(input) == expected)
    }

    @Test func routesEveryEcosystem() {
        #expect(VersionOrder.compare("1.0_rc1", "1.0", ecosystem: "Alpine:v3.20") == -1)
        #expect(VersionOrder.compare("1.0_rc1", "1.0", ecosystem: "Debian:12") == 1)
        #expect(VersionOrder.compare("1.0.dev0", "1.0a0", ecosystem: "PyPI") == -1)
        #expect(VersionOrder.compare("1.0.0.pre", "1.0.0", ecosystem: "RubyGems") == -1)
        #expect(VersionOrder.compare("1.0.0-patch1", "1.0.0", ecosystem: "Packagist") == 1)
        #expect(VersionOrder.compare("1.0.0-patch1", "1.0.0", ecosystem: "npm") == -1)
        #expect(VersionOrder.compare("2.0rc1", "2.0", ecosystem: "Unknown") == -1)
    }

    @Test func fixAndPendingUseTheEcosystemOrder() {
        let query = PackageQuery(ecosystem: "Alpine:v3.20", name: "openssl", version: "3.3.2_rc1-r0")
        let record = OSVRecord(id: "ALPINE-CVE-2024-1", affected: [
            .init(package: .init(name: "openssl", ecosystem: "Alpine:v3.20"), ranges: [
                .init(type: "ECOSYSTEM", events: [.init(introduced: "0"), .init(fixed: "3.3.2-r0")]),
            ]),
        ])
        #expect(record.fixedVersion(for: query) == "3.3.2-r0")
        let package = InstalledPackage(query: query, name: "openssl", version: query.version, location: .system)
        let finding = Finding(package: package, advisories: [Advisory(id: "CVE-2024-1", fixedVersion: "3.3.2-r0")], pendingVersion: "3.3.2-r1")
        #expect(finding.fixPending)
        let early = Finding(package: package, advisories: [Advisory(id: "CVE-2024-1", fixedVersion: "3.3.2-r0")], pendingVersion: "3.3.2_rc2-r0")
        #expect(!early.fixPending)
    }

    @Test func fixComesFromTheRangeThatContainsTheInstalledVersion() {
        let query = PackageQuery(ecosystem: "PyPI", name: "pkg", version: "2.1")
        let record = OSVRecord(id: "GHSA-aaaa-bbbb-cccc", affected: [
            .init(package: .init(name: "pkg", ecosystem: "PyPI"), ranges: [
                .init(type: "ECOSYSTEM", events: [.init(introduced: "2.5"), .init(fixed: "2.6")]),
                .init(type: "ECOSYSTEM", events: [.init(fixed: "3.0"), .init(introduced: "0")]),
            ]),
        ])
        #expect(record.fixedVersion(for: query) == "3.0")
        let older = PackageQuery(ecosystem: "PyPI", name: "pkg", version: "2.5.1")
        #expect(record.fixedVersion(for: older) == "2.6")
        let unknown = OSVRecord(id: "GHSA-dddd-eeee-ffff", affected: [
            .init(package: .init(name: "pkg", ecosystem: "PyPI"), ranges: [.init(type: "ECOSYSTEM", events: [.init(introduced: "5.0"), .init(fixed: "5.1")])]),
        ])
        #expect(unknown.fixedVersion(for: query) == "5.1")
    }
}
