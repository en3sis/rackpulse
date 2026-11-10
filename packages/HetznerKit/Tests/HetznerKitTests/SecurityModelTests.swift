import Foundation
import Testing
@testable import HetznerKit

struct SecurityModelTests {
    @Test func decodesRealAgentPayloads() throws {
        let ubuntu = try agentSecurity("agent-security-ubuntu")
        #expect(ubuntu.version == "0.3.0")
        #expect(ubuntu.os.versionID == "24.04")
        #expect(ubuntu.packages.manager == "dpkg")
        #expect(ubuntu.packages.items.count == 140)
        #expect(ubuntu.updates.securityCount > 0)
        #expect(ubuntu.kernel.latestInstalled == nil)
        #expect(ubuntu.check(SecurityCheck.sshPasswordLogin)?.status == .unknown)
        #expect(ubuntu.check(SecurityCheck.dockerHostNetwork)?.informational == true)
        #expect(ubuntu.check(SecurityCheck.dockerPrivileged)?.countsForAlert == true)
        #expect(ubuntu.projects.first?.lockfiles.first?.packages.count == 3)

        let debian = try agentSecurity("agent-security-debian")
        #expect(debian.os.like.isEmpty)
        #expect(debian.updates.items.first?.origins == ["Debian-Security:12/oldstable-security"])
        #expect(debian.projects.isEmpty)
    }

    @Test func imagesBecomeInventoryWithImageLocation() throws {
        let json = #"""
        {"version":"0.4.0","time":1793700000,"os":{"id":"ubuntu","versionID":"24.04"},
         "packages":{"manager":"dpkg","items":[{"name":"openssl","version":"3.0.13-0ubuntu3","source":"openssl","sourceVersion":"3.0.13-0ubuntu3"}]},
         "updates":{"items":[{"name":"libssl3","available":"9.9.9","security":true}]},
         "images":[
          {"id":"sha256:aaaa1111bbbb2222","names":["postgres:16"],"containers":["db"],"created":1790000000,
           "os":{"id":"debian","versionID":"12"},
           "packages":{"manager":"dpkg","items":[{"name":"libssl3","version":"3.0.11-1~deb12u2","source":"openssl","sourceVersion":"3.0.11-1~deb12u2"}]},
           "lockfiles":[{"path":"/app/package-lock.json","ecosystem":"npm","packages":[{"name":"lodash","version":"4.17.20"}]}],
           "error":null},
          {"id":"sha256:aaaa1111bbbb2222","names":["postgres:16"],"containers":["db2"]},
          {"names":["broken"]}
         ]}
        """#
        let report = try AgentJSON.decoder().decode(AgentSecurity.self, from: Data(json.utf8))
        #expect(report.images.count == 2)
        #expect(report.images.first?.displayName == "postgres:16")
        #expect(AgentSecurity.Image(id: "sha256:0123456789abcdef").displayName == "0123456789ab")

        let inventory = SecurityInventory(report)
        let image = PackageLocation.image(id: "sha256:aaaa1111bbbb2222", name: "postgres:16", path: nil)
        let imageLock = PackageLocation.image(id: "sha256:aaaa1111bbbb2222", name: "postgres:16", path: "/app/package-lock.json")
        #expect(inventory.packages.first?.location == .system)
        #expect(inventory.packages.filter { $0.location == image }.map(\.query) == [
            PackageQuery(ecosystem: "Debian:12", name: "openssl", version: "3.0.11-1~deb12u2"),
        ])
        #expect(inventory.packages.filter { $0.location == imageLock }.map(\.name) == ["lodash"])

        let old = try AgentJSON.decoder().decode(AgentSecurity.self, from: Data(#"{"time":1}"#.utf8))
        #expect(old.images.isEmpty)
    }

    @Test func rebootAndUfwChecksShowButDoNotAlert() throws {
        let json = #"""
        [{"id":"kernel.reboot","status":"fail","title":"A newer kernel is installed","detail":"6.8.0-88","source":null},
         {"id":"firewall.ufw","status":"fail","title":"ufw firewall is off","detail":"ENABLED=no","source":"/etc/ufw/ufw.conf"},
         {"id":"ssh.passwordLogin","status":"fail","title":"SSH accepts passwords","detail":"PasswordAuthentication yes","source":null}]
        """#
        let checks = try JSONDecoder().decode([SecurityCheck].self, from: Data(json.utf8))
        let t0 = date("2026-10-26T10:00:00Z")
        let result = SecurityResult(serverID: 1, checkedAt: t0, reportTime: t0, checks: checks)
        #expect(checks.allSatisfy { $0.status == .fail })
        #expect(result.failingChecks.map(\.id) == [SecurityCheck.sshPasswordLogin])
    }

    @Test func agentStatusCodesMapToErrors() {
        #expect(AgentClient.error(status: 200) == nil)
        #expect(AgentClient.error(status: 401) == .wrongKey)
        #expect(AgentClient.error(status: 404) == .invalidResponse)
        #expect(AgentClient.error(status: 404, notFound: .unsupported) == .unsupported)
        #expect(AgentClient.error(status: 503) == .invalidResponse)
        #expect(AgentClient.error(status: 503, unavailable: .notReady) == .notReady)
        #expect(AgentClient.error(status: 500, notFound: .unsupported, unavailable: .notReady) == .invalidResponse)
    }

    @Test func decodesLenientlyWithNullsUnknownFieldsAndMissingSections() throws {
        let json = #"""
        {"version":"0.4.0","time":1761480000,"future":{"x":1},
         "os":{"id":null,"versionID":null,"codename":null,"name":null},
         "packages":{"manager":null,"time":0,"error":"Unsupported","items":null},
         "updates":{"time":1,"listsTime":null,"error":null,"items":[
           {"name":"a","current":null,"available":"1","security":true,"origins":[]},
           {"name":"broken"}]},
         "checks":[{"id":"new.check","status":"warn","title":"T","detail":"D","source":null,"extra":true},{"bad":1}],
         "listening":[{"protocol":"tcp","address":"0.0.0.0","port":5432}],
         "projects":[{"name":"x","path":"/srv/x","error":"Permission denied","lockfiles":[]}]}
        """#
        let report = try AgentJSON.decoder().decode(AgentSecurity.self, from: Data(json.utf8))
        #expect(report.os.id == nil)
        #expect(report.os.like.isEmpty)
        #expect(report.packages.items.isEmpty)
        #expect(report.updates.items.count == 1)
        #expect(report.updates.items[0].current == nil)
        #expect(report.kernel.running == nil)
        #expect(report.checks.map(\.id) == ["new.check"])
        #expect(report.checks[0].status == .unknown)
        #expect(report.projects[0].error == "Permission denied")
        #expect(SecurityInventory(report).packages.isEmpty)

        let roundTrip = try JSONDecoder().decode(AgentSecurity.self, from: JSONEncoder().encode(report))
        #expect(roundTrip == report)
    }

    @Test func mapsEcosystems() {
        func ecosystem(_ id: String?, _ version: String?, manager: String? = "dpkg") -> String? {
            SecurityInventory.osEcosystem(AgentSecurity(
                version: "0.3.0", time: .now, os: .init(id: id, versionID: version),
                packages: .init(manager: manager), updates: .init()
            ))
        }
        #expect(ecosystem("ubuntu", "24.04") == "Ubuntu:24.04:LTS")
        #expect(ecosystem("ubuntu", "22.04") == "Ubuntu:22.04:LTS")
        #expect(ecosystem("ubuntu", "24.10") == "Ubuntu:24.10")
        #expect(ecosystem("ubuntu", "25.04") == "Ubuntu:25.04")
        #expect(ecosystem("debian", "12") == "Debian:12")
        #expect(ecosystem("debian", "11.9") == "Debian:11")
        #expect(ecosystem("alpine", "3.20.3", manager: "apk") == "Alpine:v3.20")
        #expect(ecosystem("linuxmint", "21.3") == nil)
        #expect(ecosystem("debian", nil) == nil)
        #expect(ecosystem("ubuntu", "24.04", manager: nil) == nil)
    }

    @Test func buildsQueriesFromSourcePackagesAndLockfiles() {
        let report = AgentSecurity(
            version: "0.3.0", time: .now, os: .init(id: "ubuntu", versionID: "24.04"),
            packages: .init(manager: "dpkg", items: [
                .init(name: "libssl3t64", version: "3.0.13-0ubuntu3.4", source: "openssl", sourceVersion: "3.0.13-0ubuntu3.4"),
                .init(name: "openssl", version: "3.0.13-0ubuntu3.4", source: "openssl", sourceVersion: "3.0.13-0ubuntu3.4"),
                .init(name: "vim", version: "2:9.1.0016-1ubuntu7", source: "vim", sourceVersion: "2:9.1.0016-1ubuntu7"),
                .init(name: "adduser", version: "3.137ubuntu1"),
                .init(name: "linux-image-6.8.0-85-generic", version: "6.8.0-85.85", source: "linux-signed", sourceVersion: "6.8.0-85.85"),
                .init(name: "linux-libc-dev", version: "6.8.0-85.85", source: "linux", sourceVersion: "6.8.0-85.85"),
                .init(name: "linux-firmware", version: "20240318.git3b128b60-0ubuntu2", source: "linux-firmware"),
            ]),
            updates: .init(),
            projects: [.init(name: "app", path: "/srv/app", lockfiles: [
                .init(path: "requirements.txt", ecosystem: "PyPI", packages: [.init(name: "Django_REST.framework", version: "3.14.0")]),
                .init(path: "go.mod", ecosystem: "Go", packages: [.init(name: "golang.org/x/text", version: "v0.3.0")]),
                .init(path: "package-lock.json", ecosystem: "npm", packages: [
                    .init(name: "@babel/core", version: "7.24.0"), .init(name: "lodash", version: "4.17.20"), .init(name: "lodash", version: "4.17.20"),
                ]),
                .init(path: "pom.txt", ecosystem: "Bogus", packages: [.init(name: "x", version: "1")]),
            ])]
        )
        let inventory = SecurityInventory(report)
        let system = inventory.packages.filter { $0.location == .system }
        #expect(system.map(\.name) == ["adduser", "linux-firmware", "openssl", "vim"])
        #expect(system.first { $0.name == "openssl" }?.binaries == ["libssl3t64", "openssl"])
        #expect(system.first { $0.name == "vim" }?.query.version == "2:9.1.0016-1ubuntu7")
        #expect(inventory.skippedKernelSources == ["linux", "linux-signed"])

        let queries = inventory.packages.map(\.query)
        #expect(queries.contains(PackageQuery(ecosystem: "PyPI", name: "django-rest-framework", version: "3.14.0")))
        let go = queries.first { $0.ecosystem == "Go" }
        #expect(go?.version == "0.3.0")
        #expect(go?.purl == "pkg:golang/golang.org/x/text@v0.3.0")
        #expect(queries.first { $0.name == "@babel/core" }?.purl == "pkg:npm/%40babel/core@7.24.0")
        #expect(queries.filter { $0.name == "lodash" }.count == 1)
        #expect(!queries.contains { $0.ecosystem == "Bogus" })
        #expect(PackageQuery(ecosystem: "Ubuntu:24.04:LTS", name: "openssl", version: "1").purl == nil)
        #expect(PackageQuery(ecosystem: "Packagist", name: "laravel/framework", version: "v10.0.0").purl == "pkg:composer/laravel/framework@10.0.0")
    }

    @Test func onlyEcosystemsTheAgentParsesAreQueried() {
        #expect(PackageQuery.languageEcosystems == ["npm", "PyPI", "Go", "crates.io", "Packagist", "RubyGems"])
        for ecosystem in ["Maven", "NuGet"] {
            let query = PackageQuery(ecosystem: ecosystem, name: "org.example:lib", version: "1.0.0")
            #expect(!PackageQuery.isSupported(ecosystem))
            #expect(query.purl == nil)
            #expect(SocketSource.link(query) == nil)
            let lockfile = AgentSecurity.Lockfile(path: "x", ecosystem: ecosystem, packages: [.init(name: "a", version: "1")])
            #expect(SecurityInventory.lockfilePackages(lockfile, location: .system).isEmpty)
        }
    }

    @Test func linksOnlyUseAllowedHosts() {
        #expect(AdvisoryLink(title: "x", url: "https://osv.dev/vulnerability/CVE-2024-1") != nil)
        #expect(AdvisoryLink(title: "x", url: "http://osv.dev/vulnerability/CVE-2024-1") == nil)
        #expect(AdvisoryLink(title: "x", url: "https://evil.example/osv.dev") == nil)
        #expect(AdvisoryLink(title: "x", url: "https://user@osv.dev/") == nil)
        #expect(OSVNormalizer.isSafeID("UBUNTU-CVE-2024-6119"))
        #expect(!OSVNormalizer.isSafeID("../etc/passwd"))
        #expect(!OSVNormalizer.isSafeID("A/B"))
    }
}
