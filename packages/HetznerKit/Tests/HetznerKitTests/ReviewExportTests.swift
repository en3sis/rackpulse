import Foundation
import Testing
@testable import HetznerKit

struct SecurityReviewTests {
    static let t0 = FindingLedgerTests.t0
    static let exploited = KnownExploited(dateAdded: nil, ransomware: false)

    static func package(_ name: String, _ version: String, ecosystem: String = "Ubuntu:24.04:LTS", binaries: [String] = [],
                        location: PackageLocation = .system) -> InstalledPackage {
        InstalledPackage(query: PackageQuery(ecosystem: ecosystem, name: name, version: version), name: name, version: version,
                         binaries: binaries, location: location)
    }

    static func sample() -> SecurityResult {
        let sudo = Finding(package: package("sudo", "1.9.15p5-3ubuntu5", binaries: ["sudo"]), advisories: [
            Advisory(id: "CVE-2025-32463", summary: "Local privilege escalation via chroot", severity: .critical, score: 9.3, fixedVersion: "1.9.15p5-3ubuntu5.1"),
        ])
        let openssl = Finding(package: package("openssl", "3.0.13-0ubuntu3", binaries: ["openssl", "libssl3t64"]), advisories: [
            Advisory(id: "CVE-2024-2", severity: .high, fixedVersion: "3.0.13-0ubuntu3.4"),
            Advisory(id: "CVE-2024-3", severity: .medium),
        ])
        let lodash = Finding(package: package("lodash", "4.17.20", ecosystem: "npm", location: .lockfile(project: "shop", path: "/srv/shop/package-lock.json")),
                             advisories: [Advisory(id: "GHSA-35jh", aliases: ["CVE-2021-23337"], severity: .high, fixedVersion: "4.17.21")])
        let imageLocation = PackageLocation.image(id: "sha256:abc", name: "nginx:1.25", path: nil)
        let zlib = Finding(package: package("zlib", "1.2.13-r0", ecosystem: "Alpine:v3.19", binaries: ["zlib"], location: imageLocation), advisories: [
            Advisory(id: "CVE-2023-45853", severity: .critical, fixedVersion: "1.2.13-r1", knownExploited: exploited),
        ])
        let quiet = Finding(package: package("bash", "5.2"), advisories: [Advisory(id: "CVE-2024-8", severity: .low, hidden: true)])
        let evil = Finding(package: package("evil;rm", "1.0", binaries: ["evil;rm"]), advisories: [Advisory(id: "CVE-2024-5", severity: .high, fixedVersion: "1.1")])
        return SecurityResult(
            serverID: 1, checkedAt: t0, reportTime: t0, osName: "Ubuntu 24.04 LTS", osEcosystem: "Ubuntu:24.04:LTS", onlineChecks: true,
            findings: [sudo, openssl, lodash, zlib, quiet, evil], pendingSecurityUpdates: 2,
            checks: [SecurityCheck(id: "ssh.passwordLogin", status: .fail, title: "SSH accepts passwords", detail: "PasswordAuthentication yes")]
        )
    }

    @Test func groupsByPackageAndLocation() {
        let review = SecurityReview(Self.sample())
        #expect(review.fixNow.map(\.package.name) == ["zlib", "sudo"])
        #expect(Set(review.withFix.map(\.package.name)) == ["openssl", "lodash", "evil;rm"])
        #expect(review.lowPriority.map(\.package.name) == ["bash"])
        #expect(review.failingChecks.count == 1)
        let locations = Dictionary(uniqueKeysWithValues: review.visible.map { ($0.package.name, $0.location) })
        #expect(locations["sudo"] == "Host")
        #expect(locations["lodash"] == "/srv/shop/package-lock.json")
        #expect(locations["zlib"] == "Image nginx:1.25")
    }

    @Test func fixCommandsOnlyUseSafeNames() {
        let review = SecurityReview(Self.sample())
        let fixes = Dictionary(uniqueKeysWithValues: review.visible.map { ($0.package.name, $0.fix) })
        #expect(fixes["openssl"] == .command("sudo apt install --only-upgrade libssl3t64 openssl"))
        #expect(fixes["sudo"] == .command("sudo apt install --only-upgrade sudo"))
        #expect(fixes["evil;rm"] == .some(nil))
        #expect(fixes["lodash"] == .text("Upgrade lodash to 4.17.21 or later in /srv/shop/package-lock.json."))
        #expect(fixes["zlib"] == .text("Rebuild or pull image nginx:1.25 with zlib 1.2.13-r1 or later, then recreate its containers."))

        let alpine = Finding(package: Self.package("busybox", "1.36.1-r15", ecosystem: "Alpine:v3.19", binaries: ["busybox", "ssl_client"]),
                             advisories: [Advisory(id: "CVE-1", severity: .high, fixedVersion: "1.36.1-r16")])
        let items = alpine.advisories.map { SecurityResult.Item(finding: alpine, advisory: $0) }
        #expect(SecurityReview.fix(alpine, items: items, osEcosystem: "Alpine:v3.19") == .command("sudo apk upgrade busybox ssl_client"))
        #expect(SecurityReview.fix(alpine, items: [], osEcosystem: "Alpine:v3.19") == nil)
        #expect(!SecurityReview.debianName("Sudo"))
        #expect(!SecurityReview.debianName("a b"))
        #expect(!SecurityReview.debianName("-rf"))
        #expect(SecurityReview.debianName("libstdc++6"))
    }

    @Test func ignoredItemsLeaveTheGroups() {
        let review = SecurityReview(Self.sample(), ignoring: ["CVE-2025-32463", "CVE-2024-2"])
        #expect(review.fixNow.map(\.package.name) == ["zlib"])
        #expect(review.noFix.map(\.package.name) == ["openssl"])
        #expect(review.ignored.map(\.advisory.id) == ["CVE-2025-32463", "CVE-2024-2"])
    }

    @Test func fleetGroupsByAdvisoryAndPutsFixNowFirst() {
        let first = Self.sample()
        let second = SecurityResult(serverID: 2, checkedAt: Self.t0, reportTime: Self.t0, osEcosystem: "Ubuntu:24.04:LTS", onlineChecks: true,
                                    findings: [first.findings.first { $0.package.name == "sudo" }!],
                                    checks: first.checks)
        let fleet = SecurityReview.fleet([
            (server: "web-1", result: first, ignored: []),
            (server: "web-2", result: second, ignored: []),
            (server: "worker-1", result: second, ignored: ["CVE-2025-32463"]),
        ])
        #expect(fleet.advisories.map(\.title).prefix(2) == ["CVE-2023-45853 in zlib", "CVE-2025-32463 in sudo"])
        #expect(fleet.advisories[1].servers == ["web-1", "web-2"])
        #expect(fleet.advisories.prefix(2).allSatisfy { $0.fixNow })
        #expect(!fleet.advisories.contains { $0.key == "CVE-2024-8" })
        #expect(fleet.checks.map(\.servers) == [["web-1", "web-2", "worker-1"]])
    }

    @Test func agentVersionsCompareByNumber() {
        #expect(AgentVersion.isOlder("0.3.9", than: "0.4.0"))
        #expect(AgentVersion.isOlder("v0.3.12", than: "0.4.0"))
        #expect(!AgentVersion.isOlder("0.10.0", than: "0.4.0"))
        #expect(!AgentVersion.isOlder("0.4.0", than: "0.4.0"))
        #expect(!AgentVersion.isOlder("0.4", than: "0.4.0"))
        #expect(!AgentVersion.isOlder("0.4.0-dev", than: "0.4.0"))
        #expect(!AgentVersion.isOlder("1.0.0", than: "0.4.0"))
        #expect(!AgentVersion.isOlder("", than: "0.4.0"))
        #expect(!AgentVersion.isOlder("dev", than: "0.4.0"))
    }
}

struct SecurityExportTests {
    static let t0 = FindingLedgerTests.t0
    static let id = UUID(uuidString: "6F2C3D4E-1A2B-4C5D-8E9F-0A1B2C3D4E5F")!

    static func decisions(_ result: SecurityResult) -> [FindingDecision] {
        let items = result.items
        let sudo = items.first { $0.advisory.id == "CVE-2025-32463" }!
        let openssl = items.first { $0.advisory.id == "CVE-2024-3" }!
        let lodash = items.first { $0.advisory.id == "GHSA-35jh" }!
        return [
            FindingDecision(target: "t", item: sudo, reason: .notAffected, note: "No | chroot users", end: FindingDecision.end(days: 90, from: t0),
                            created: t0, id: UUID(uuidString: "00000000-0000-0000-0000-000000000001")!),
            FindingDecision(target: FindingDecision.allServers, item: openssl, reason: .fixLater, end: .fixAvailable, created: t0 + 1,
                            id: UUID(uuidString: "00000000-0000-0000-0000-000000000002")!),
            FindingDecision(target: "t", item: lodash, reason: .acceptRisk, note: "Internal tool", end: FindingDecision.end(days: 30, from: t0),
                            created: t0 + 2, id: UUID(uuidString: "00000000-0000-0000-0000-000000000003")!),
        ]
    }

    @Test func purlsCoverOSAndLanguagePackages() {
        let deb = SecurityReviewTests.package("openssl", "1:3.0.13+ds-1", ecosystem: "Debian:12")
        #expect(SecurityExport.purl(deb) == "pkg:deb/debian/openssl@1%3A3.0.13%2Bds-1?arch=source&distro=debian-12")
        let ubuntu = SecurityReviewTests.package("sudo", "1.9.15p5-3ubuntu5")
        #expect(SecurityExport.purl(ubuntu) == "pkg:deb/ubuntu/sudo@1.9.15p5-3ubuntu5?arch=source&distro=ubuntu-24.04")
        let apk = SecurityReviewTests.package("zlib", "1.2.13-r0", ecosystem: "Alpine:v3.19")
        #expect(SecurityExport.purl(apk) == "pkg:apk/alpine/zlib@1.2.13-r0?distro=alpine-3.19")
        let npm = SecurityReviewTests.package("@types/node", "20.1.0", ecosystem: "npm")
        #expect(SecurityExport.purl(npm) == "pkg:npm/%40types/node@20.1.0")
        #expect(SecurityExport.purl(SecurityReviewTests.package("x", "1", ecosystem: "Pub")) == nil)
    }

    @Test func markdownReportListsFindingsChecksAndIgnores() {
        let result = SecurityReviewTests.sample()
        let check = FindingDecision.check(Self.decisions(result), target: "t", result: result, now: Self.t0 + 60)
        let report = SecurityExport.markdown(server: "web-1", result: result, decisions: check, now: Self.t0 + 60)
        #expect(report.hasPrefix("# Security report for web-1\n"))
        #expect(report.contains("| Fix now | 1 |"))
        #expect(report.contains("| Ignored | 3 |"))
        #expect(report.contains("### zlib 1.2.13-r0 (Image nginx:1.25)"))
        #expect(report.contains("- Fix: `sudo apt install --only-upgrade libssl3t64 openssl`"))
        #expect(!report.contains("evil;rm`"))
        #expect(report.contains("- Fail: **SSH accepts passwords**: PasswordAuthentication yes"))
        #expect(report.contains("| CVE-2025-32463 in sudo | Not affected | No \\| chroot users | 2027-01-24 | This server | 2026-10-26 |"))
        #expect(report.contains("| CVE-2024-3 in openssl | Fix later |   | When a fix is available | All servers | 2026-10-26 |"))
        #expect(!report.contains("\u{2014}"))
    }

    @Test func agentPromptListsFixesWithoutAdvisoryText() {
        let result = SecurityReviewTests.sample()
        let prompt = SecurityExport.agentPrompt(server: "web-1", host: "10.0.0.2", result: result, decisions: DecisionCheck())
        #expect(prompt.hasPrefix("# Fix security findings on web-1\n"))
        #expect(prompt.contains("Server: web-1 (10.0.0.2), Ubuntu 24.04 LTS."))
        #expect(prompt.contains("- **zlib** 1.2.13-r0 in Image nginx:1.25, upgrade to 1.2.13-r1 or later. CVE-2023-45853 (critical, exploited)."))
        #expect(prompt.contains("Suggested: `sudo apt install --only-upgrade sudo`"))
        #expect(prompt.contains("- `ssh.passwordLogin` SSH accepts passwords: PasswordAuthentication yes"))
        #expect(!prompt.contains("Local privilege escalation"))
        #expect(!prompt.contains("bash"))
        #expect(!prompt.contains("\u{2014}"))
        let short = SecurityExport.agentPrompt(server: "web-1", host: nil, result: result, decisions: DecisionCheck(), limit: 2)
        #expect(short.contains("3 more packages have a fix and are not listed."))
    }

    @Test func cycloneDXListsEveryPackageWithPurls() throws {
        let report = AgentSecurity(
            version: "0.4.0", time: Self.t0, os: AgentSecurity.OS(id: "ubuntu", versionID: "24.04"),
            packages: AgentSecurity.Packages(manager: "dpkg", items: [
                AgentSecurity.Package(name: "libssl3t64", version: "3.0.13-0ubuntu3", source: "openssl"),
                AgentSecurity.Package(name: "openssl", version: "3.0.13-0ubuntu3"),
                AgentSecurity.Package(name: "sudo", version: "1.9.15p5-3ubuntu5"),
            ]),
            updates: AgentSecurity.Updates(),
            projects: [AgentSecurity.Project(name: "shop", path: "/srv/shop", lockfiles: [
                AgentSecurity.Lockfile(path: "/srv/shop/package-lock.json", ecosystem: "npm", packages: [AgentSecurity.Dependency(name: "lodash", version: "4.17.20")]),
            ])],
            images: [AgentSecurity.Image(
                id: "sha256:abc", names: ["nginx:1.25"], containers: ["web"], os: AgentSecurity.OS(id: "alpine", versionID: "3.19.1"),
                packages: AgentSecurity.Packages(manager: "apk", items: [AgentSecurity.Package(name: "zlib", version: "1.2.13-r0")])
            )]
        )
        let inventory = SecurityInventory(report)
        #expect(inventory.packages.count == 4)
        let data = try SecurityExport.cycloneDX(server: "web-1", inventory: inventory, serial: Self.id, now: Self.t0)
        let json = try #require(try JSONSerialization.jsonObject(with: data) as? [String: Any])
        #expect(json["bomFormat"] as? String == "CycloneDX")
        #expect(json["specVersion"] as? String == "1.6")
        #expect(json["serialNumber"] as? String == "urn:uuid:6f2c3d4e-1a2b-4c5d-8e9f-0a1b2c3d4e5f")
        let components = try #require(json["components"] as? [[String: Any]])
        let nested = components.flatMap { ($0["components"] as? [[String: Any]]) ?? [] }
        let libraries = components.filter { $0["type"] as? String == "library" } + nested
        #expect(libraries.count == inventory.packages.count)
        #expect(libraries.allSatisfy { ($0["purl"] as? String)?.hasPrefix("pkg:") == true })
        #expect(components.contains { $0["type"] as? String == "container" })
        #expect(try SecurityExport.cycloneDX(server: "web-1", inventory: inventory, serial: Self.id, now: Self.t0) == data)
    }

    @Test func openVEXMapsReasonsToStatuses() throws {
        let result = SecurityReviewTests.sample()
        let data = try SecurityExport.openVEX(server: "web-1", result: result, decisions: Self.decisions(result), id: Self.id, now: Self.t0)
        let json = try #require(try JSONSerialization.jsonObject(with: data) as? [String: Any])
        #expect(json["@context"] as? String == "https://openvex.dev/ns/v0.2.0")
        #expect(json["@id"] as? String == "urn:uuid:6f2c3d4e-1a2b-4c5d-8e9f-0a1b2c3d4e5f")
        let statements = try #require(json["statements"] as? [[String: Any]])
        #expect(statements.map { $0["status"] as? String } == ["not_affected", "affected", "affected"])
        #expect(statements[0]["impact_statement"] as? String == "No | chroot users")
        #expect(statements[1]["action_statement"] as? String == "Update when a fix is available.")
        #expect(statements[2]["action_statement"] as? String == "Risk accepted until 2026-11-25.")
        #expect(statements[2]["status_notes"] as? String == "Internal tool")
        let lodash = try #require(statements[2]["vulnerability"] as? [String: Any])
        #expect(lodash["name"] as? String == "CVE-2021-23337")
        #expect(lodash["aliases"] as? [String] == ["GHSA-35jh"])
        let products = try #require(statements[0]["products"] as? [[String: Any]])
        #expect(products.first?["@id"] as? String == "pkg:deb/ubuntu/sudo@1.9.15p5-3ubuntu5?arch=source&distro=ubuntu-24.04")
        let missing = try SecurityExport.openVEX(server: "web-1", result: nil, decisions: Self.decisions(result), id: Self.id, now: Self.t0)
        #expect((try JSONSerialization.jsonObject(with: missing) as? [String: Any])?["statements"] as? [Any] != nil)
    }
}
