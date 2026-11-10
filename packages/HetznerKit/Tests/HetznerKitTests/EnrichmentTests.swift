import Foundation
import Testing
@testable import HetznerKit

struct EnrichmentTests {
    @Test func kevParsesFeedAndUsesConditionalRequests() async throws {
        let feed = try fixture("kev")
        let transport = RouterTransport { request in
            if request.value(forHTTPHeaderField: "If-None-Match") == "\"v1\"" { return .init(status: 304, body: Data()) }
            return .init(body: feed, headers: ["ETag": "\"v1\"", "Last-Modified": "Sun, 26 Oct 2026 08:00:00 GMT"])
        }
        let clock = Clock(date("2026-10-26T10:00:00Z"))
        let source = KEVSource(cache: temporaryCache(), transport: transport, clock: { clock.now }, sleep: { _ in })

        let first = try await source.enrichment(for: ["CVE-2021-44228", "CVE-2023-4863", "CVE-1999-0001"])
        #expect(first.values["CVE-2021-44228"]?.knownExploited?.ransomware == true)
        #expect(first.values["CVE-2023-4863"]?.knownExploited?.ransomware == false)
        #expect(first.values["CVE-2023-4863"]?.knownExploited?.dateAdded != nil)
        #expect(first.values["CVE-1999-0001"] == nil)

        _ = try await source.enrichment(for: ["CVE-2021-44228"])
        #expect(transport.requests.count == 1)

        clock.advance(25 * 3_600)
        let second = try await source.enrichment(for: ["CVE-2021-44228"])
        #expect(transport.requests.count == 2)
        #expect(transport.requests[1].value(forHTTPHeaderField: "If-None-Match") == "\"v1\"")
        #expect(second.values["CVE-2021-44228"] != nil)
        #expect(transport.requests[0].url?.host() == "www.cisa.gov")
    }

    @Test func socketParsesNDJSONIncludingErrors() {
        let body = """
        {"type":"npm","name":"evil","version":"1.0.0","inputPurl":"pkg:npm/evil@1.0.0","alerts":[{"type":"malware","severity":"critical","category":"supplyChainRisk"},{"type":"cve","severity":"high"}],"score":{"overall":0.1}}
        {"type":"npm","name":"expres","version":"1.0.0","inputPurl":"pkg:npm/expres@1.0.0","alerts":[{"type":"didYouMean","severity":"middle"},{"type":"installScripts","severity":"low"}]}
        {"type":"npm","name":"ok","version":"1.0.0","inputPurl":"pkg:npm/ok@1.0.0","alerts":[{"type":"obfuscatedFile","severity":"high"},{"type":"unknownFuture","severity":"critical"}]}
        {"_type":"purlError","value":{"error":"not found","inputPurl":"pkg:npm/missing@1.0.0"}}
        {"_type":"purlError","value":{"error":"timeout","inputPurl":"pkg:npm/slow@1.0.0","retryable":true}}
        {"_type":"summary","value":{"purl_input":5}}
        not json at all

        """
        let lines = SocketSource.parse(Data(body.utf8))
        #expect(lines.count == 5)
        var artifacts: [String: SocketSource.Artifact] = [:]
        var errors: [String: Bool] = [:]
        for line in lines {
            switch line {
            case .artifact(let purl, let artifact): artifacts[purl] = artifact
            case .error(let purl, let retryable): errors[purl] = retryable
            }
        }
        #expect(errors == ["pkg:npm/missing@1.0.0": false, "pkg:npm/slow@1.0.0": true])

        let evil = SocketSource.advisories(artifacts["pkg:npm/evil@1.0.0"]!, query: PackageQuery(ecosystem: "npm", name: "evil", version: "1.0.0"))
        #expect(evil.map(\.id) == ["SOCKET-malware"])
        #expect(evil[0].kind == .malware)
        #expect(evil[0].severity == .critical)
        #expect(evil[0].links.first?.url.absoluteString == "https://socket.dev/npm/package/evil")

        let typo = SocketSource.advisories(artifacts["pkg:npm/expres@1.0.0"]!, query: PackageQuery(ecosystem: "npm", name: "expres", version: "1.0.0"))
        #expect(typo.map(\.id) == ["SOCKET-didYouMean"])
        #expect(typo[0].severity == .medium)
        #expect(typo[0].kind == .supplyChain)

        let ok = SocketSource.advisories(artifacts["pkg:npm/ok@1.0.0"]!, query: PackageQuery(ecosystem: "npm", name: "ok", version: "1.0.0"))
        #expect(ok.map(\.id) == ["SOCKET-obfuscatedFile"])
    }

    @Test func socketRespectsIntervalAndNeverLeaksTheToken() async throws {
        let token = "sktsec_supersecret"
        let body = #"{"inputPurl":"pkg:npm/evil@1.0.0","alerts":[{"type":"malware","severity":"critical"}]}"#
        let transport = RouterTransport { request in
            if request.url!.path() == "/v0/quota" { return .init(body: json(["quota": 500, "maxQuota": 500, "nextWindowRefresh": NSNull()])) }
            return .init(body: Data(body.utf8))
        }
        let clock = Clock(date("2026-10-26T10:00:00Z"))
        let credentials = SocketCredentials(token: token, organization: "acme")
        let source = SocketSource(credentials: credentials, cache: temporaryCache(), transport: transport, clock: { clock.now }, sleep: { _ in })
        let evil = PackageQuery(ecosystem: "npm", name: "evil", version: "1.0.0")
        let other = PackageQuery(ecosystem: "npm", name: "other", version: "2.0.0")
        let os = PackageQuery(ecosystem: "Debian:12", name: "openssl", version: "3.0.11-1")

        let first = try await source.lookup([evil, other, os])
        #expect(first.advisories[evil]?.first?.kind == .malware)
        #expect(first.problem == nil)
        #expect(first.advisories[other]?.isEmpty == true)
        let post = try #require(transport.requests.last)
        #expect(post.url?.absoluteString == "https://api.socket.dev/v0/orgs/acme/purl?alerts=true&compact=true")
        #expect(post.value(forHTTPHeaderField: "Authorization") == "Bearer \(token)")
        let purls = String(decoding: post.httpBody!, as: UTF8.self)
        #expect(purls.contains("pkg:npm/evil@1.0.0") && !purls.contains("openssl"))

        clock.advance(60)
        let late = PackageQuery(ecosystem: "npm", name: "late", version: "1.0.0")
        let second = try await source.lookup([evil, other, late])
        #expect(transport.requests.count == 2)
        #expect(second.advisories[evil]?.isEmpty == false)
        #expect(second.problem?.contains("1 packages wait") == true)

        #expect(!String(describing: credentials).contains(token))
        #expect(!String(reflecting: credentials).contains(token))
        var dumped = ""
        dump(credentials, to: &dumped)
        #expect(!dumped.contains(token))

        let rejected = SocketSource(
            credentials: credentials, cache: temporaryCache(),
            transport: RouterTransport { _ in .init(status: 401, body: Data(token.utf8)) }, sleep: { _ in }
        )
        do {
            _ = try await rejected.lookup([evil])
            Issue.record("expected an error")
        } catch {
            #expect(error as? SecuritySourceError == .unauthorized)
            #expect(!String(describing: error).contains(token))
            #expect(!((error as? SecuritySourceError)?.message.contains(token) ?? true))
        }

        let bad = SocketSource(credentials: SocketCredentials(token: token, organization: "../x"), cache: temporaryCache(), transport: transport)
        await #expect(throws: SecuritySourceError.invalidOrganization) { try await bad.lookup([evil]) }
    }
}
