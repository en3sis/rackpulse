import Foundation
import Testing
@testable import HetznerKit

struct ReportLimitTests {
    typealias Limit = AgentSecurity.Limit

    func decode(_ object: [String: Any]) throws -> AgentSecurity {
        var report = object
        report["time"] = report["time"] ?? 1_761_480_000
        return try AgentJSON.decoder().decode(AgentSecurity.self, from: json(report))
    }

    func text(_ count: Int) -> String {
        String(repeating: "a", count: count)
    }

    @Test func dropsItemsWithOversizedStrings() throws {
        let report = try decode([
            "version": text(Limit.name + 1),
            "os": ["id": "debian", "versionID": text(Limit.name + 1), "like": ["debian", text(Limit.name + 1)]],
            "packages": ["manager": "dpkg", "error": text(Limit.detail + 1), "items": [
                ["name": "ok", "version": text(Limit.name)],
                ["name": text(Limit.name + 1), "version": "1"],
                ["name": "long-version", "version": text(Limit.name + 1)],
                ["name": "long-source", "version": "1", "source": text(Limit.name + 1)],
            ]],
            "updates": ["items": [
                ["name": "a", "available": "2", "origins": [text(Limit.name + 1), "Debian"]],
                ["name": "b", "available": text(Limit.name + 1)],
            ]],
            "projects": [
                ["name": "app", "path": "/srv/app", "error": text(Limit.detail + 1), "lockfiles": [
                    ["path": text(Limit.path), "ecosystem": "npm", "packages": [
                        ["name": "left-pad", "version": "1.0.0"], ["name": text(Limit.name + 1), "version": "1.0.0"],
                    ]],
                    ["path": text(Limit.path + 1), "ecosystem": "npm", "packages": [["name": "x", "version": "1"]]],
                ]],
                ["name": "far", "path": text(Limit.path + 1)],
            ],
            "images": [
                ["id": "sha256:1", "names": [text(Limit.name + 1), "nginx:1.27"]],
                ["id": text(Limit.name + 1)],
            ],
            "listening": [["address": text(Limit.name + 1), "port": 1], ["address": "0.0.0.0", "port": 22]],
            "checks": [["id": text(Limit.name + 1), "status": "fail"], ["id": "ok", "status": "pass"]],
        ])
        #expect(report.version == "")
        #expect(report.os.versionID == nil)
        #expect(report.os.like == ["debian"])
        #expect(report.packages.error == nil)
        #expect(report.packages.items.map(\.name) == ["ok"])
        #expect(report.updates.items.map(\.name) == ["a"])
        #expect(report.updates.items[0].origins == ["Debian"])
        #expect(report.projects.map(\.name) == ["app"])
        #expect(report.projects[0].error == nil)
        #expect(report.projects[0].lockfiles.count == 1)
        #expect(report.projects[0].lockfiles[0].packages.map(\.name) == ["left-pad"])
        #expect(report.images.map(\.id) == ["sha256:1"])
        #expect(report.images[0].names == ["nginx:1.27"])
        #expect(report.listening.map(\.port) == [22])
        #expect(report.checks.map(\.id) == ["ok"])
    }

    @Test func capsListSizesPerSection() throws {
        let dependencies = (0..<10).map { ["name": "d\($0)", "version": "1"] }
        let lockfiles = (0..<(Limit.lockfiles + 5)).map { ["path": "l\($0)/package-lock.json", "ecosystem": "npm", "packages": dependencies] as [String: Any] }
        let images = (0..<(Limit.images + 5)).map { index -> [String: Any] in
            ["id": "sha256:\(index)", "names": (0..<(Limit.imageNames + 3)).map { "n\($0)" }, "lockfiles": lockfiles]
        }
        let report = try decode([
            "projects": (0..<(Limit.projects + 5)).map { ["name": "p\($0)", "path": "/srv/p\($0)", "lockfiles": lockfiles] as [String: Any] },
            "images": images,
            "checks": (0..<(Limit.checks + 5)).map { ["id": "c\($0)", "status": "pass"] },
            "os": ["like": (0..<40).map { "l\($0)" }],
        ])
        #expect(report.projects.count == Limit.projects)
        #expect(report.projects.allSatisfy { $0.lockfiles.count == Limit.lockfiles })
        #expect(report.images.count == Limit.images)
        #expect(report.images.allSatisfy { $0.names.count == Limit.imageNames && $0.lockfiles.count == Limit.lockfiles })
        #expect(report.checks.count == Limit.checks)
        #expect(report.os.like.count == Limit.shortList)
        #expect(SecurityInventory(report).packages.count <= SecurityInventory.packageLimit)
    }

    @Test func capsPackagesInReportsAndImages() throws {
        let items = (0..<(Limit.packages + 10)).map { ["name": "p\($0)", "version": "1"] }
        let report = try decode([
            "os": ["id": "debian", "versionID": "12"],
            "packages": ["manager": "dpkg", "items": items],
            "images": [["id": "sha256:1", "os": ["id": "alpine", "versionID": "3.20.1"], "packages": ["manager": "apk", "items": items]]],
        ])
        #expect(report.packages.items.count == Limit.packages)
        #expect(report.images[0].packages.items.count == Limit.imagePackages)
        #expect(report.images[0].packages.manager == "apk")
    }

    @Test func keepsReleasedReportsDecodingUnchanged() throws {
        for name in ["agent-security-ubuntu", "agent-security-debian"] {
            let data = try fixture(name)
            let report = try AgentJSON.decoder().decode(AgentSecurity.self, from: data)
            let raw = try #require(try JSONSerialization.jsonObject(with: data) as? [String: Any])
            let packages = (raw["packages"] as? [String: Any])?["items"] as? [Any] ?? []
            let updates = (raw["updates"] as? [String: Any])?["items"] as? [Any] ?? []
            #expect(report.packages.items.count == packages.count)
            #expect(report.updates.items.count == updates.count)
            #expect(report.checks.count == (raw["checks"] as? [Any])?.count ?? 0)
            #expect(report.projects.count == (raw["projects"] as? [Any])?.count ?? 0)
        }
    }
}
