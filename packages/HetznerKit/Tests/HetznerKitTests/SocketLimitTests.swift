import Foundation
import Testing
@testable import HetznerKit

struct SocketLimitTests {
    static let t0 = date("2026-11-04T10:00:00Z")

    enum Failure: Sendable {
        case status(Int)
        case offline
    }

    final class FakeSocket: HTTPTransport, @unchecked Sendable {
        private let lock = NSLock()
        private var remaining: Int
        private var flagged: Set<String>
        private var silent: Set<String>
        private var failure: Failure?
        private(set) var quotaCalls = 0
        private(set) var batches: [[String]] = []
        private(set) var attempts = 0

        init(quota: Int, flagged: Set<String> = [], silent: Set<String> = []) {
            remaining = quota
            self.flagged = flagged
            self.silent = silent
        }

        var transport: HTTPTransport { self }

        func setQuota(_ value: Int) {
            lock.withLock { remaining = value }
        }

        func fail(_ value: Failure?) {
            lock.withLock { failure = value }
        }

        func send(_ request: URLRequest) async throws -> (Data, HTTPURLResponse) {
            let failure: Failure? = lock.withLock {
                guard request.url!.path() != "/v0/quota" else { return nil }
                attempts += 1
                return self.failure
            }
            if case .offline = failure { throw URLError(.notConnectedToInternet) }
            let reply: StubTransport.Reply = if case .status(let code) = failure { .init(status: code, body: Data()) } else { reply(request) }
            return (reply.body, HTTPURLResponse(url: request.url!, statusCode: reply.status, httpVersion: nil, headerFields: reply.headers)!)
        }

        func reply(_ request: URLRequest) -> StubTransport.Reply {
            lock.withLock {
                if request.url!.path() == "/v0/quota" {
                    quotaCalls += 1
                    return .init(body: json(["quota": remaining, "maxQuota": 1_000, "nextWindowRefresh": "2026-11-04T11:00:00Z"]))
                }
                remaining -= SocketSource.callCost
                let body = try! JSONSerialization.jsonObject(with: request.httpBody!) as! [String: [[String: String]]]
                let purls = body["components"]!.map { $0["purl"]! }
                batches.append(purls)
                let lines = purls.filter { !silent.contains($0) }.map { purl -> String in
                    let alerts = flagged.contains(purl) ? #"[{"type":"malware","severity":"critical"}]"# : "[]"
                    return #"{"inputPurl":"\#(purl)","alerts":\#(alerts)}"#
                }
                return .init(body: Data(lines.joined(separator: "\n").utf8))
            }
        }
    }

    static func packages(_ prefix: String, _ count: Int) -> [PackageQuery] {
        (0..<count).map { PackageQuery(ecosystem: "npm", name: "\(prefix)\($0)", version: "1.0.0") }
    }

    func source(_ fake: FakeSocket, _ clock: Clock, cache: SecurityCache = temporaryCache()) -> SocketSource {
        SocketSource(credentials: SocketCredentials(token: "t", organization: "acme"), cache: cache, transport: fake.transport, clock: { clock.now }, sleep: { _ in })
    }

    @Test func readsTheQuotaAtMostEveryFifteenMinutes() async throws {
        let fake = FakeSocket(quota: 500)
        let clock = Clock(Self.t0)
        let socket = source(fake, clock)
        let verified = try await socket.verify()
        #expect(verified.quota == 500)
        #expect(verified.checkedAt == Self.t0)

        clock.advance(300)
        let first = try await socket.lookup(Self.packages("a", 2))
        #expect(fake.quotaCalls == 1)
        #expect(fake.batches.count == 1)
        #expect(first.quota?.quota == 400)
        #expect(first.quota?.callsLeft == 4)
        #expect(first.skipped == false)

        clock.advance(SocketSource.minimumInterval)
        let second = try await socket.lookup(Self.packages("b", 2))
        #expect(fake.quotaCalls == 2)
        #expect(fake.batches.count == 2)
        #expect(second.quota?.quota == 300)
        #expect(await socket.lastQuota?.quota == 300)
    }

    @Test func skipsWhenTheQuotaIsTooLow() async throws {
        let fake = FakeSocket(quota: 80)
        let clock = Clock(Self.t0)
        let lodash = PackageQuery(ecosystem: "npm", name: "lodash", version: "4.17.21")
        let scanner = SecurityScanner(
            sources: [FakeSource(.osv, answers: [:])],
            socketFactory: { credentials in
                SocketSource(credentials: credentials, cache: temporaryCache(), transport: fake.transport, clock: { clock.now }, sleep: { _ in })
            },
            clock: { clock.now }
        )
        let report = AgentSecurity(version: "0.4.0", time: Self.t0, os: .init(), packages: .init(), updates: .init(), projects: [
            .init(name: "app", path: "/srv/app", lockfiles: [.init(path: "package-lock.json", ecosystem: "npm", packages: [.init(name: lodash.name, version: lodash.version)])]),
        ])
        let results = await scanner.scan(
            [SecurityTarget(serverID: 1, report: report, server: nil, firewalls: nil)],
            settings: SecurityScanSettings(onlineChecks: true), socket: SocketCredentials(token: "t", organization: "acme")
        )
        let status = try #require(results[1]?.source(.socket))
        #expect(status.state == .skipped)
        #expect(status.message == "Socket quota is too low for this scan (80 left).")
        #expect(status.quota?.quota == 80)
        #expect(status.quota?.callsLeft == 0)
        #expect(fake.batches.isEmpty)
        #expect(results[1]?.incomplete == false)
    }

    @Test func capsPackagesPerServerPerScanAndPerDay() async throws {
        let fake = FakeSocket(quota: 100_000)
        let clock = Clock(Self.t0)
        let socket = source(fake, clock)
        let flood = Self.packages("fake", 1_500)
        let honest = Self.packages("real", 3)
        var origins: [PackageQuery: Set<Int64>] = [:]
        for query in flood { origins[query] = [1] }
        for query in honest { origins[query] = [2] }
        let shared = PackageQuery(ecosystem: "npm", name: "shared", version: "1.0.0")
        origins[shared] = [1, 2]
        let all = flood + honest + [shared]

        let first = try await socket.lookup(all, origins: origins)
        let sent = try #require(fake.batches.last)
        #expect(sent.count == SocketSource.serverScanLimit + 4)
        #expect(honest.allSatisfy { sent.contains($0.purl!) })
        #expect(sent.contains(shared.purl!))
        #expect(first.problem?.contains("were not sent to Socket") == true)

        for _ in 0..<10 {
            clock.advance(SocketSource.minimumInterval + 1)
            _ = try await socket.lookup(all, origins: origins)
        }
        let fromFlood = fake.batches.flatMap { $0 }.filter { $0.hasPrefix("pkg:npm/fake") }
        #expect(fromFlood.count == SocketSource.serverDayLimit)
        #expect(Set(fromFlood).count == fromFlood.count)
        let last = try await socket.lookup(all, origins: origins)
        #expect(last.problem?.contains("1000 per day") == true)

        clock.advance(86_400)
        _ = try await socket.lookup(all, origins: origins)
        #expect(fake.batches.last?.filter { $0.hasPrefix("pkg:npm/fake") }.count == SocketSource.serverScanLimit)
    }

    @Test func keepsCleanVerdictsLongerThanFlaggedOnes() async throws {
        let evil = PackageQuery(ecosystem: "npm", name: "evil", version: "1.0.0")
        let clean = PackageQuery(ecosystem: "npm", name: "clean", version: "1.0.0")
        let fake = FakeSocket(quota: 10_000, flagged: [evil.purl!])
        let clock = Clock(Self.t0)
        let socket = source(fake, clock)
        _ = try await socket.lookup([evil, clean])
        #expect(fake.batches.count == 1)

        clock.advance(SocketSource.flaggedLifetime + 60)
        let refreshed = try await socket.lookup([evil, clean])
        #expect(fake.batches.last == [evil.purl!])
        #expect(refreshed.advisories[evil]?.first?.kind == .malware)

        clock.advance(60)
        let blocked = try await socket.lookup([evil, clean])
        #expect(fake.batches.count == 2)
        #expect(blocked.advisories[evil]?.first?.kind == .malware)

        clock.advance(SocketSource.cleanLifetime)
        _ = try await socket.lookup([evil, clean])
        #expect(Set(fake.batches.last ?? []) == [evil.purl!, clean.purl!])
    }

    @Test func flaggedVerdictsStayVisibleWhileARefreshWaits() async throws {
        let evil = PackageQuery(ecosystem: "npm", name: "evil", version: "1.0.0")
        let fake = FakeSocket(quota: 10_000, flagged: [evil.purl!])
        let clock = Clock(Self.t0)
        let socket = source(fake, clock)
        _ = try await socket.lookup([evil])
        fake.setQuota(0)
        clock.advance(SocketSource.flaggedLifetime + SocketSource.quotaInterval)
        let lookup = try await socket.lookup([evil])
        #expect(lookup.skipped)
        #expect(lookup.advisories[evil]?.first?.kind == .malware)
    }

    @Test func oldStoredDataStillDecodes() throws {
        let cache = temporaryCache()
        cache.store(Data(#"{"lastCall":0,"entries":{"pkg:npm/x@1.0.0":{"time":0,"advisories":[]}}}"#.utf8), as: SocketSource.file)
        let state = try #require(cache.read(SocketSource.State.self, from: SocketSource.file))
        #expect(state.entries.count == 1)
        #expect(state.quota == nil)
        #expect(state.usage.isEmpty)

        let status = try JSONDecoder().decode(SourceStatus.self, from: Data(#"{"source":"socket","state":"ok","message":null}"#.utf8))
        #expect(status.quota == nil)
        let quota = try JSONDecoder().decode(SocketQuota.self, from: Data(#"{"quota":300,"maxQuota":500}"#.utf8))
        #expect(quota.checkedAt == nil)
        #expect(quota.callsLeft == 3)

        let stored = SourceStatus(source: .socket, state: .ok, quota: SocketQuota(quota: 200, maxQuota: 500, nextWindowRefresh: nil, checkedAt: Self.t0))
        #expect(try JSONDecoder().decode(SourceStatus.self, from: JSONEncoder().encode(stored)) == stored)
    }

    @Test(arguments: [Failure.status(500), Failure.offline])
    func failedCallsDoNotUseTheDailyCapAndWaitBeforeRetrying(_ failure: Failure) async throws {
        let fake = FakeSocket(quota: 100_000)
        fake.fail(failure)
        let clock = Clock(Self.t0)
        let cache = temporaryCache()
        let socket = source(fake, clock, cache: cache)
        let queries = Self.packages("p", 300)
        let origins = Dictionary(uniqueKeysWithValues: queries.map { ($0, Set<Int64>([1])) })

        await #expect(throws: SecuritySourceError.self) { try await socket.lookup(queries, origins: origins) }
        #expect(fake.attempts == 1)
        #expect(cache.read(SocketSource.State.self, from: SocketSource.file)?.usage.isEmpty == true)

        clock.advance(60)
        let waiting = try await socket.lookup(queries, origins: origins)
        #expect(fake.attempts == 1)
        #expect(waiting.problem?.contains("wait for the next check after") == true)

        fake.fail(nil)
        clock.advance(SocketSource.minimumInterval)
        _ = try await socket.lookup(queries, origins: origins)
        #expect(fake.attempts == 2)
        #expect(fake.batches.last?.count == SocketSource.serverScanLimit)
        #expect(cache.read(SocketSource.State.self, from: SocketSource.file)?.usage["1"]?.count == SocketSource.serverScanLimit)
    }

    @Test func unansweredPackagesWaitBeforeTheyAreSentAgain() async throws {
        let quiet = PackageQuery(ecosystem: "npm", name: "quiet", version: "1.0.0")
        let loud = PackageQuery(ecosystem: "npm", name: "loud", version: "1.0.0")
        let fake = FakeSocket(quota: 10_000, silent: [quiet.purl!])
        let clock = Clock(Self.t0)
        let socket = source(fake, clock)

        let first = try await socket.lookup([quiet, loud])
        #expect(Set(fake.batches.last ?? []) == [quiet.purl!, loud.purl!])
        #expect(first.problem == nil)
        #expect(first.advisories[quiet]?.isEmpty == true)

        clock.advance(SocketSource.minimumInterval + 1)
        _ = try await socket.lookup([quiet, loud])
        #expect(fake.batches.count == 1)

        clock.advance(SocketSource.unansweredLifetime)
        _ = try await socket.lookup([quiet, loud])
        #expect(fake.batches.count == 2)
        #expect(fake.batches.last == [quiet.purl!])
    }
}
