import Foundation
import Testing
@testable import HetznerKit

struct SplitMix64: RandomNumberGenerator {
    var state: UInt64

    init(seed: UInt64) {
        state = seed
    }

    mutating func next() -> UInt64 {
        state &+= 0x9E37_79B9_7F4A_7C15
        var z = state
        z = (z ^ (z >> 30)) &* 0xBF58_476D_1CE4_E5B9
        z = (z ^ (z >> 27)) &* 0x94D0_49BB_1331_11EB
        return z ^ (z >> 31)
    }
}

enum Mutation: CaseIterable {
    case byteFlip, truncation, insertion, hugeString, deepNesting, typeSwap, duplicateKeys, longArray
}

struct Mutator {
    static let deepMarker = "deep-nesting-marker"

    var rng: SplitMix64

    init(seed: UInt64) {
        rng = SplitMix64(seed: seed)
    }

    mutating func int(_ range: Range<Int>) -> Int {
        Int.random(in: range, using: &rng)
    }

    mutating func mutate(_ data: Data, _ mutation: Mutation) -> Data {
        switch mutation {
        case .byteFlip:
            var bytes = [UInt8](data)
            for _ in 0..<int(1..<16) where !bytes.isEmpty {
                bytes[int(0..<bytes.count)] ^= UInt8(1 << int(0..<8))
            }
            return Data(bytes)
        case .truncation:
            return data.prefix(int(0..<max(1, data.count)))
        case .insertion:
            var bytes = [UInt8](data)
            let noise: [UInt8] = Array("{}[]\":,\\0123456789eE+-.tfn \u{0}\u{FF}".utf8)
            for _ in 0..<int(1..<12) {
                bytes.insert(noise[int(0..<noise.count)], at: int(0..<(bytes.count + 1)))
            }
            return Data(bytes)
        case .hugeString, .deepNesting, .typeSwap, .duplicateKeys, .longArray:
            guard let tree = try? JSONSerialization.jsonObject(with: data, options: [.fragmentsAllowed]) else { return data }
            if mutation == .duplicateKeys { return Data(write(tree, duplicates: true).utf8) }
            var counter = 0
            let target = int(0..<max(1, count(tree)))
            let mutated = replace(tree, counter: &counter, target: target, mutation: mutation)
            var text = write(mutated, duplicates: false)
            if mutation == .deepNesting, let marker = text.range(of: Self.quote(Self.deepMarker)) {
                let depth = [64, 300, 600, 5_000][int(0..<4)]
                let (open, close) = int(0..<2) == 0 ? ("[", "]") : ("{\"k\":", "}")
                text.replaceSubrange(marker, with: String(repeating: open, count: depth) + "1" + String(repeating: close, count: depth))
            }
            return Data(text.utf8)
        }
    }

    func count(_ node: Any) -> Int {
        if let array = node as? [Any] { return 1 + array.reduce(0) { $0 + count($1) } }
        if let object = node as? [String: Any] { return 1 + object.values.reduce(0) { $0 + count($1) } }
        return 1
    }

    mutating func replace(_ node: Any, counter: inout Int, target: Int, mutation: Mutation) -> Any {
        if counter == target {
            counter += 1
            return apply(node, mutation)
        }
        counter += 1
        if let array = node as? [Any] {
            var result: [Any] = []
            for element in array { result.append(replace(element, counter: &counter, target: target, mutation: mutation)) }
            return result
        }
        if let object = node as? [String: Any] {
            var result: [String: Any] = [:]
            for key in object.keys.sorted() { result[key] = replace(object[key]!, counter: &counter, target: target, mutation: mutation) }
            return result
        }
        return node
    }

    mutating func apply(_ node: Any, _ mutation: Mutation) -> Any {
        switch mutation {
        case .hugeString:
            let lengths = [257, 1_025, 2_049, 100_000]
            return String(repeating: "A", count: lengths[int(0..<lengths.count)])
        case .deepNesting:
            return Self.deepMarker
        case .typeSwap:
            let swaps: [Any] = [42, -1, 1e308, 0.5, "x", "", [Any](), [String: Any](), NSNull(), true, false]
            return swaps[int(0..<swaps.count)]
        case .longArray:
            guard let array = node as? [Any], let first = array.first else { return [Any](repeating: node, count: 5_000) }
            return [Any](repeating: first, count: [5_000, 31_000][int(0..<2)])
        default:
            return node
        }
    }

    mutating func write(_ node: Any, duplicates: Bool) -> String {
        if let array = node as? [Any] {
            var parts: [String] = []
            for element in array { parts.append(write(element, duplicates: duplicates)) }
            return "[" + parts.joined(separator: ",") + "]"
        }
        if let object = node as? [String: Any] {
            var parts: [String] = []
            for key in object.keys.sorted() {
                parts.append(Self.quote(key) + ":" + write(object[key]!, duplicates: duplicates))
                if duplicates, int(0..<4) == 0 {
                    let other: Any = int(0..<2) == 0 ? "dup" : NSNull()
                    parts.append(Self.quote(key) + ":" + write(other, duplicates: false))
                }
            }
            return "{" + parts.joined(separator: ",") + "}"
        }
        if let string = node as? String { return Self.quote(string) }
        if let number = node as? NSNumber {
            if CFGetTypeID(number) == CFBooleanGetTypeID() { return number.boolValue ? "true" : "false" }
            return number.stringValue
        }
        return "null"
    }

    static func quote(_ text: String) -> String {
        var result = "\""
        for scalar in text.unicodeScalars {
            switch scalar {
            case "\"": result += "\\\""
            case "\\": result += "\\\\"
            case let value where value.value < 0x20: result += String(format: "\\u%04x", value.value)
            default: result.unicodeScalars.append(scalar)
            }
        }
        return result + "\""
    }

    mutating func version() -> String {
        let alphabet = Array("0123456789012345.-_+~:!abcdeprvxzRCα ")
        switch int(0..<6) {
        case 0: return String(repeating: "9", count: int(20..<400))
        case 1: return "1." + String(repeating: "0", count: int(1..<300)) + "_rc" + String(repeating: "9", count: 30)
        default: return String((0..<int(0..<24)).map { _ in alphabet[int(0..<alphabet.count)] })
        }
    }
}

struct FuzzTests {
    typealias Limit = AgentSecurity.Limit

    static let seeds: [UInt64] = Array(1...40)
    static let ecosystems = ["Alpine:v3.20", "Debian:12", "Ubuntu:24.04:LTS", "npm", "crates.io", "Go", "PyPI", "RubyGems", "Packagist", "Unknown"]

    func checkReport(_ report: AgentSecurity) {
        func short(_ text: String?) -> Bool { (text?.utf8.count ?? 0) <= Limit.name }
        #expect(short(report.version))
        #expect(report.packages.items.count <= Limit.packages)
        #expect(report.packages.items.allSatisfy { short($0.name) && short($0.version) && short($0.source) && short($0.sourceVersion) && short($0.arch) })
        #expect((report.packages.error?.utf8.count ?? 0) <= Limit.detail)
        #expect(report.updates.items.count <= Limit.updates)
        #expect(report.updates.items.allSatisfy { short($0.name) && short($0.available) && short($0.current) && $0.origins.count <= Limit.shortList })
        #expect(report.checks.count <= Limit.checks)
        #expect(report.listening.count <= Limit.listening)
        #expect(report.os.like.count <= Limit.shortList && short(report.os.id) && short(report.os.versionID))
        #expect(report.projects.count <= Limit.projects)
        for project in report.projects {
            #expect(project.path.utf8.count <= Limit.path && short(project.name) && project.lockfiles.count <= Limit.lockfiles)
            for lockfile in project.lockfiles {
                #expect(lockfile.path.utf8.count <= Limit.path && lockfile.packages.count <= Limit.dependencies)
                #expect(lockfile.packages.allSatisfy { short($0.name) && short($0.version) })
            }
        }
        #expect(report.images.count <= Limit.images)
        for image in report.images {
            #expect(short(image.id) && image.names.count <= Limit.imageNames && image.containers.count <= Limit.containers)
            #expect(image.packages.items.count <= Limit.imagePackages && image.lockfiles.count <= Limit.lockfiles)
        }

        let inventory = SecurityInventory(report)
        #expect(inventory.packages.count <= SecurityInventory.packageLimit)
        #expect(inventory.packages.allSatisfy { short($0.name) && short($0.version) && $0.query.name.utf8.count <= Limit.name * 3 })
        for (a, b) in zip(inventory.packages.prefix(50), inventory.packages.dropFirst().prefix(50)) {
            let order = VersionOrder.compare(a.version, b.version, ecosystem: a.query.ecosystem)
            #expect((-1...1).contains(order))
        }
    }

    @Test func agentReportsSurviveMutation() throws {
        let fixtures = try ["agent-security-ubuntu", "agent-security-debian"].map { try fixture($0) }
        var decoded = 0
        for seed in Self.seeds {
            var mutator = Mutator(seed: seed)
            for (index, data) in fixtures.enumerated() {
                for mutation in Mutation.allCases {
                    if mutation == .longArray && (seed + UInt64(index)) % 4 != 0 { continue }
                    let input = mutator.mutate(data, mutation)
                    guard let report = try? AgentJSON.decoder().decode(AgentSecurity.self, from: input) else { continue }
                    decoded += 1
                    checkReport(report)
                }
            }
        }
        #expect(decoded > 0)
    }

    @Test func oversizedSectionsAreCapped() throws {
        let data = try fixture("agent-security-ubuntu")
        var tree = try #require(try JSONSerialization.jsonObject(with: data) as? [String: Any])
        var packages = try #require(tree["packages"] as? [String: Any])
        let item = try #require((packages["items"] as? [Any])?.first)
        packages["items"] = [Any](repeating: item, count: Limit.packages + 500)
        tree["packages"] = packages
        tree["images"] = [Any](repeating: ["id": "sha256:1", "names": [Any](repeating: "n", count: 100), "packages": packages], count: 3)
        var mutator = Mutator(seed: 7)
        let report = try AgentJSON.decoder().decode(AgentSecurity.self, from: Data(mutator.write(tree, duplicates: false).utf8))
        #expect(report.packages.items.count == Limit.packages)
        #expect(report.images.allSatisfy { $0.packages.items.count == Limit.imagePackages && $0.names.count == Limit.imageNames })
        checkReport(report)
    }

    @Test func osvRecordsSurviveMutation() throws {
        let names = ["DEBIAN-CVE-2024-6119", "DSA-5764-1", "GHSA-35jh-r3h4-6jhm", "GO-2020-0015", "MAL-2025-20690", "PYSEC-2018-28", "UBUNTU-CVE-2024-6119", "USN-6986-1"]
        let fixtures = try names.map { try fixture("osv-\($0)") }
        let originals = try fixtures.map { try JSONDecoder().decode(OSVRecord.self, from: $0) }
        var normalized = 0
        for seed in Self.seeds {
            var mutator = Mutator(seed: seed &* 31)
            var records: [OSVRecord] = []
            for data in fixtures {
                let mutation = Mutation.allCases[mutator.int(0..<Mutation.allCases.count)]
                if mutation == .longArray && seed % 3 != 0 { continue }
                guard let record = try? JSONDecoder().decode(OSVRecord.self, from: mutator.mutate(data, mutation)) else { continue }
                let trimmed = record.trimmed()
                #expect(trimmed.aliases.count <= OSVRecord.idListLimit && trimmed.related.count <= OSVRecord.idListLimit)
                #expect(trimmed.affected.count <= OSVRecord.affectedLimit)
                #expect(trimmed.affected.allSatisfy { $0.ranges.count <= OSVRecord.rangeLimit && $0.ranges.allSatisfy { $0.events.count <= OSVRecord.eventLimit } })
                #expect((trimmed.details?.count ?? 0) <= OSVRecord.detailsLimit)
                records.append(trimmed)
            }
            for original in originals {
                guard let package = original.affected.first?.package else { continue }
                for version in ["0", "1.0.0", "3.0.11-1~deb12u2", mutator.version()] {
                    let query = PackageQuery(ecosystem: package.ecosystem, name: package.name, version: version)
                    let advisories = OSVNormalizer.advisories(records, for: query)
                    normalized += 1
                    #expect(advisories.count <= records.count)
                    for advisory in advisories {
                        #expect(advisory.aliases.count <= OSVNormalizer.aliasLimit)
                        #expect(advisory.links.count <= OSVNormalizer.linkLimit)
                        #expect(advisory.summary.count <= 303)
                        #expect((advisory.fixedVersion?.utf8.count ?? 0) <= OSVRecord.versionLimit)
                        #expect(advisory.score.map { (0...10).contains($0) } ?? true)
                    }
                }
            }
        }
        #expect(normalized > 0)
    }

    @Test func versionComparisonsStayConsistent() {
        var mutator = Mutator(seed: 99)
        for _ in 0..<400 {
            let a = mutator.version()
            let b = mutator.version()
            for ecosystem in Self.ecosystems {
                let forward = VersionOrder.compare(a, b, ecosystem: ecosystem)
                #expect((-1...1).contains(forward))
                #expect(VersionOrder.compare(b, a, ecosystem: ecosystem) == -forward, "\(ecosystem) \(a) \(b)")
                #expect(VersionOrder.compare(a, a, ecosystem: ecosystem) == 0, "\(ecosystem) \(a)")
            }
        }
    }

    @Test func scoresAndDownloadsSurviveMutation() throws {
        var mutator = Mutator(seed: 5)
        let vector = Data("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N".utf8)
        let legacy = Data("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H".utf8)
        for _ in 0..<300 {
            for kind in [Mutation.byteFlip, .truncation, .insertion] {
                let text = String(decoding: mutator.mutate(vector, kind), as: UTF8.self)
                #expect(CVSS4.baseScore(text).map { (0...10).contains($0) } ?? true)
                let old = String(decoding: mutator.mutate(legacy, kind), as: UTF8.self)
                #expect(CVSS3.baseScore(old).map { (0...10).contains($0) } ?? true)
            }
        }
        let archive = gzip(EPSSTests.sample)
        let limits = EPSSSource.Limits(compressed: 1 << 20, decompressed: 1 << 20, rows: 100)
        for _ in 0..<300 {
            let kind = [Mutation.byteFlip, .truncation, .insertion][mutator.int(0..<3)]
            if let table = try? EPSSTable.parse(gzip: mutator.mutate(archive, kind), limits: limits) {
                #expect(table.count <= limits.rows)
            }
        }
    }
}
