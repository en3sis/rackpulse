import Foundation
import Testing
@testable import HetznerKit

struct FindingDecisionTests {
    static let t0 = FindingLedgerTests.t0
    static let target = "hetzner/p/server/1"
    static let exploited = KnownExploited(dateAdded: nil, ransomware: false)

    let critical = Advisory(id: "CVE-2024-1", severity: .critical, fixedVersion: "3.0.14-1")
    let high = Advisory(id: "CVE-2024-2", severity: .high, fixedVersion: "3.0.14-1")
    let unfixed = Advisory(id: "CVE-2024-9", severity: .high)

    static func result(_ advisories: [Advisory], at time: Date) -> SecurityResult {
        FindingLedgerTests.result(advisories, at: time)
    }

    static func item(_ result: SecurityResult, _ id: String) -> SecurityResult.Item {
        result.items.first { $0.advisory.id == id }!
    }

    static func decide(
        _ result: SecurityResult, _ id: String, reason: FindingDecision.Reason = .acceptRisk, end: FindingDecision.End? = nil,
        target: String = target, at time: Date = t0
    ) -> FindingDecision {
        FindingDecision(target: target, item: item(result, id), reason: reason, end: end ?? FindingDecision.end(days: 30, from: time), created: time)
    }

    static func run(_ record: LedgerRecord, _ result: SecurityResult, _ decisions: [FindingDecision], now: Date? = nil) -> LedgerOutcome {
        let check = FindingDecision.check(decisions, target: target, result: result, now: now ?? result.checkedAt)
        return FindingLedger.reconcile(record, scan: FindingLedger.scan(result, settings: AlertSettings(), decisions: check))
    }

    @Test func activeDecisionsHideItemsFromTheResult() {
        let result = Self.result([critical, high], at: Self.t0)
        let decision = Self.decide(result, "CVE-2024-1")
        let check = FindingDecision.check([decision], target: Self.target, result: result, now: Self.t0 + 60)
        #expect(check.ignoredKeys == ["CVE-2024-1"])
        let visible = result.ignoring(check.ignoredKeys)
        #expect(visible.items.map(\.advisory.id) == ["CVE-2024-2"])
        #expect(visible.counts.critical == 0)
        #expect(result.ignoring([]).items.count == 2)
        #expect(FindingDecision.check([decision], target: "hetzner/p/server/2", result: result, now: Self.t0).active.isEmpty)
    }

    @Test func allServersScopeAppliesEverywhere() {
        let result = Self.result([critical], at: Self.t0)
        let decision = Self.decide(result, "CVE-2024-1", target: FindingDecision.allServers)
        #expect(FindingDecision.check([decision], target: "hetzner/q/server/9", result: result, now: Self.t0).state("CVE-2024-1") == .active)
    }

    @Test func lapsesOnExpiryFixExploitAndMalware() {
        let result = Self.result([unfixed], at: Self.t0)
        let dated = Self.decide(result, "CVE-2024-9")
        #expect(dated.lapse(FindingDecision.facts(result)["CVE-2024-9"], now: Self.t0 + 29 * 86_400) == nil)
        #expect(dated.lapse(FindingDecision.facts(result)["CVE-2024-9"], now: Self.t0 + 30 * 86_400) == .expired)

        let untilFix = Self.decide(result, "CVE-2024-9", end: .fixAvailable)
        #expect(untilFix.lapse(FindingDecision.facts(result)["CVE-2024-9"], now: Self.t0 + 400 * 86_400) == nil)
        var fixed = unfixed
        fixed.fixedVersion = "3.0.15-1"
        #expect(untilFix.lapse(FindingDecision.facts(Self.result([fixed], at: Self.t0))["CVE-2024-9"], now: Self.t0) == .fixAvailable)

        var listed = unfixed
        listed.knownExploited = Self.exploited
        #expect(untilFix.lapse(FindingDecision.facts(Self.result([listed], at: Self.t0))["CVE-2024-9"], now: Self.t0) == .exploited)
        let alreadyListed = Self.decide(Self.result([listed], at: Self.t0), "CVE-2024-9", end: .fixAvailable)
        #expect(alreadyListed.exploited)
        #expect(alreadyListed.lapse(FindingDecision.facts(Self.result([listed], at: Self.t0))["CVE-2024-9"], now: Self.t0) == nil)

        var malware = unfixed
        malware.kind = .malware
        #expect(dated.lapse(FindingDecision.ItemFacts(malware: true), now: Self.t0) == .malware)
        #expect(dated.lapse(nil, now: Self.t0) == nil)
        var seen = dated
        seen.lastSeen = Self.t0 + 58 * 86_400
        #expect(!seen.removable(now: Self.t0 + 59 * 86_400))
        #expect(seen.removable(now: Self.t0 + 61 * 86_400))
    }

    @Test func serverDecisionWinsOverALapsedFleetDecision() {
        let result = Self.result([critical], at: Self.t0)
        let fleet = Self.decide(result, "CVE-2024-1", end: FindingDecision.end(days: 30, from: Self.t0 - 40 * 86_400), target: FindingDecision.allServers)
        let server = Self.decide(result, "CVE-2024-1")
        let check = FindingDecision.check([fleet, server], target: Self.target, result: result, now: Self.t0 + 60)
        #expect(check.state("CVE-2024-1") == .active)
        #expect(check.active["CVE-2024-1"]?.id == server.id)
        let lapsed = FindingDecision.check([fleet], target: Self.target, result: result, now: Self.t0 + 60)
        #expect(lapsed.state("CVE-2024-1") == .lapsed)
        #expect(lapsed.lapsed["CVE-2024-1"]?.lapse == .expired)
    }

    @Test func ignoringBeforeTheFirstNoticeSendsNothing() {
        let result = Self.result([critical, high], at: Self.t0)
        let decision = Self.decide(result, "CVE-2024-1")
        let first = Self.run(LedgerRecord(target: Self.target), result, [decision])
        #expect(first.news.map(\.entry.key) == ["vulnerability|CVE-2024-2"])
        #expect(first.record.entries["vulnerability|CVE-2024-1"]?.ignored == true)
        #expect(first.record.entries["vulnerability|CVE-2024-1"]?.notifiedAt == nil)

        var record = first.record
        for step in 1...20 {
            record = Self.run(record, Self.result([critical, high], at: Self.t0 + Double(step) * 86_400), [decision]).record
        }
        #expect(record.entries["vulnerability|CVE-2024-1"]?.isOpen == true)
    }

    @Test func ignoringANotifiedFindingRemovesItAndExpiryBringsItBack() {
        let first = Self.run(LedgerRecord(target: Self.target), Self.result([critical], at: Self.t0), [])
        #expect(first.record.openNotified(.vulnerability))
        let decision = Self.decide(Self.result([critical], at: Self.t0), "CVE-2024-1", at: Self.t0 + 60)

        let ignored = Self.run(first.record, Self.result([critical], at: Self.t0), [decision], now: Self.t0 + 60)
        #expect(ignored.changed)
        #expect(ignored.news.isEmpty)
        #expect(ignored.ignored.map(\.key) == ["vulnerability|CVE-2024-1"])
        #expect(!ignored.record.openNotified(.vulnerability))

        let still = Self.run(ignored.record, Self.result([critical], at: Self.t0 + 86_400), [decision])
        #expect(still.news.isEmpty)

        let expired = Self.run(still.record, Self.result([critical], at: Self.t0 + 86_400), [decision], now: Self.t0 + 31 * 86_400)
        #expect(expired.news.map(\.change) == [.reopened])
        let notice = FindingNotice.compose(expired.news, kind: .vulnerability, server: "web-1", baseline: false)
        #expect(notice?.title == "web-1: CVE-2024-1 in openssl is back")
        #expect(expired.record.entries["vulnerability|CVE-2024-1"]?.ignored == false)

        let after = Self.run(expired.record, Self.result([critical], at: Self.t0 + 32 * 86_400), [decision])
        #expect(after.news.isEmpty)
    }

    @Test func newExploitRevokesTheIgnoreAndNotifies() {
        let base = Self.result([high], at: Self.t0)
        let decision = Self.decide(base, "CVE-2024-2")
        let first = Self.run(LedgerRecord(target: Self.target), base, [decision])
        #expect(first.news.isEmpty)
        var listed = high
        listed.knownExploited = Self.exploited
        let second = Self.run(first.record, Self.result([listed], at: Self.t0 + 86_400), [decision])
        #expect(second.news.map(\.change) == [.reopened])
        #expect(second.news.first?.entry.exploited == true)
    }

    @Test func unignoringByHandIsSilentAndNotLaterNew() {
        let first = Self.run(LedgerRecord(target: Self.target), Self.result([critical], at: Self.t0), [])
        let decision = Self.decide(Self.result([critical], at: Self.t0), "CVE-2024-1")
        let ignored = Self.run(first.record, Self.result([critical], at: Self.t0 + 1_800), [decision])
        let removed = Self.run(ignored.record, Self.result([critical], at: Self.t0 + 1_800), [])
        #expect(removed.changed)
        #expect(removed.news.isEmpty)
        #expect(removed.record.openNotified(.vulnerability))
        let later = Self.run(removed.record, Self.result([critical], at: Self.t0 + 3_600), [])
        #expect(later.news.isEmpty)
    }

    @Test func ignoredFindingsStillResolveWhenFixed() {
        let decision = Self.decide(Self.result([critical], at: Self.t0), "CVE-2024-1")
        let first = Self.run(LedgerRecord(target: Self.target), Self.result([critical], at: Self.t0), [decision])
        let miss = Self.run(first.record, Self.result([], at: Self.t0 + 1_800), [decision])
        let gone = Self.run(miss.record, Self.result([], at: Self.t0 + 3_600), [decision])
        #expect(gone.resolved.map(\.key) == ["vulnerability|CVE-2024-1"])
    }

    @Test func aResolvedIgnoredFindingThatReturnsLaterNotifies() {
        let decision = Self.decide(Self.result([critical], at: Self.t0), "CVE-2024-1")
        let first = Self.run(LedgerRecord(target: Self.target), Self.result([critical], at: Self.t0), [decision])
        #expect(first.news.isEmpty)
        let miss = Self.run(first.record, Self.result([], at: Self.t0 + 86_400), [decision])
        let gone = Self.run(miss.record, Self.result([], at: Self.t0 + 2 * 86_400), [decision])
        #expect(gone.resolved.map(\.key) == ["vulnerability|CVE-2024-1"])
        #expect(gone.record.entries["vulnerability|CVE-2024-1"]?.ignored == false)

        let expiry = Self.t0 + 31 * 86_400
        var pruned = [decision]
        pruned.removeAll { $0.removable(now: expiry + 31 * 86_400) }
        #expect(pruned.isEmpty)

        let back = Self.run(gone.record, Self.result([critical], at: Self.t0 + 20 * 86_400), pruned)
        #expect(back.news.map(\.change) == [.reopened])
        let soon = Self.run(gone.record, Self.result([critical], at: Self.t0 + 3 * 86_400), [])
        #expect(soon.news.map(\.change) == [.new])
    }

    @Test func staleIgnoredFlagOnAResolvedEntryIsNotSilent() {
        let entry = LedgerEntry(key: "vulnerability|CVE-2024-1", kind: .vulnerability, title: "CVE-2024-1 in openssl", rank: 4,
                                firstSeen: Self.t0, lastSeen: Self.t0, resolvedAt: Self.t0 + 86_400, ignored: true)
        let record = LedgerRecord(target: Self.target, lastScan: Self.t0 + 86_400, scannedKinds: [.vulnerability, .hardening], rules: "v3,h",
                                  entries: [entry.key: entry])
        let back = Self.run(record, Self.result([critical], at: Self.t0 + 20 * 86_400), [])
        #expect(back.news.map(\.change) == [.reopened])
    }

    @Test func absentDecisionsBecomeRemovable() {
        let present = Self.result([unfixed], at: Self.t0)
        let empty = Self.result([], at: Self.t0)
        let untilFix = Self.decide(present, "CVE-2024-9", end: .fixAvailable)
        let fleet = Self.decide(present, "CVE-2024-9", end: .fixAvailable, target: FindingDecision.allServers)
        let other = "hetzner/p/server/2"

        #expect(FindingDecision.seen([untilFix, fleet], results: [Self.target: present]) == [untilFix.id, fleet.id])
        #expect(FindingDecision.seen([untilFix, fleet], results: [Self.target: empty, other: present]) == [fleet.id])
        #expect(FindingDecision.seen([untilFix, fleet], results: [Self.target: empty, other: empty]).isEmpty)
        let offline = FindingLedgerTests.result([], at: Self.t0, online: false)
        #expect(FindingDecision.seen([untilFix], results: [Self.target: offline]) == [untilFix.id])
        let failed = FindingLedgerTests.result([], at: Self.t0, failed: true)
        #expect(FindingDecision.seen([untilFix], results: [Self.target: failed]) == [untilFix.id])
        #expect(FindingDecision.seen([untilFix], results: [:]) == [untilFix.id])

        #expect(!untilFix.removable(now: Self.t0 + 29 * 86_400))
        #expect(untilFix.removable(now: Self.t0 + 31 * 86_400))
        var recent = untilFix
        recent.lastSeen = Self.t0 + 20 * 86_400
        #expect(!recent.removable(now: Self.t0 + 49 * 86_400))
        #expect(recent.removable(now: Self.t0 + 51 * 86_400))
    }

    @Test func severalReturningFindingsShareOneTitle() {
        let news = [critical, high].map { advisory in
            FindingNews(entry: LedgerEntry(key: advisory.id, kind: .vulnerability, title: "\(advisory.id) in openssl", rank: advisory.severity.rank,
                                           firstSeen: Self.t0, lastSeen: Self.t0), change: .reopened)
        }
        #expect(FindingNotice.compose(news, kind: .vulnerability, server: "web-1", baseline: false)?.title == "web-1: 2 vulnerabilities are back")
    }
}

struct DecisionStorageTests {
    static let t0 = FindingLedgerTests.t0

    @Test func decisionsRoundTripAndReplaceBySameTargetAndKey() throws {
        let database = try LocalDatabase()
        let first = FindingDecision(target: "hetzner/p/server/1", key: "CVE-1", title: "CVE-1 in openssl", reason: .acceptRisk, note: "Behind VPN",
                                    end: .date(Self.t0 + 86_400), created: Self.t0, exploited: true)
        let fleet = FindingDecision(target: FindingDecision.allServers, key: "CVE-2", title: "CVE-2 in sudo", reason: .notAffected,
                                    end: .fixAvailable, created: Self.t0 + 1, malware: false)
        try database.saveDecision(first)
        try database.saveDecision(fleet)
        #expect(try database.decisions() == [first, fleet])

        let replaced = FindingDecision(target: "hetzner/p/server/1", key: "CVE-1", title: "CVE-1 in openssl", reason: .fixLater,
                                       end: .date(Self.t0 + 90 * 86_400), created: Self.t0 + 2)
        try database.saveDecision(replaced)
        #expect(try database.decisions() == [fleet, replaced])
        try database.deleteDecisions([fleet.id])
        #expect(try database.decisions() == [replaced])
        try database.markDecisionsSeen([replaced.id], at: Self.t0 + 3)
        #expect(try database.decisions().first?.lastSeen == Self.t0 + 3)
    }

    @Test func removedServersAndProjectsDropTheirDecisions() async throws {
        let database = try LocalDatabase()
        for (target, key) in [("hetzner/a/server/1", "K1"), ("hetzner/a/server/2", "K2"), ("hetzner/b/server/3", "K3"), (FindingDecision.allServers, "K4")] {
            try database.saveDecision(FindingDecision(target: target, key: key, title: key, reason: .acceptRisk, end: .fixAvailable, created: Self.t0))
        }
        try await database.removeTargets(notIn: ["hetzner/a/server/1"], prefix: "hetzner/a/")
        #expect(try database.decisions().map(\.key).sorted() == ["K1", "K3", "K4"])
        try await database.keepProjects(["a"])
        #expect(try database.decisions().map(\.key).sorted() == ["K1", "K4"])
    }

    @Test func ignoredFlagIsStored() async throws {
        let database = try LocalDatabase()
        let entry = LedgerEntry(key: "vulnerability|CVE-1", kind: .vulnerability, title: "CVE-1 in openssl", rank: 4,
                                firstSeen: Self.t0, lastSeen: Self.t0, ignored: true)
        var commit = AlertCommit()
        commit.ledgers = [LedgerRecord(target: "hetzner/p/server/1", lastScan: Self.t0, entries: [entry.key: entry])]
        try await database.commit(commit)
        #expect(try await database.ledger(target: "hetzner/p/server/1").entries[entry.key]?.ignored == true)
    }

    static let versionOne = """
        CREATE TABLE alert_state (project TEXT PRIMARY KEY, state BLOB NOT NULL, updated REAL NOT NULL);
        CREATE TABLE meta (key TEXT PRIMARY KEY, value BLOB NOT NULL);
        CREATE TABLE notification_log (
            id INTEGER PRIMARY KEY, time REAL NOT NULL, project TEXT NOT NULL, target TEXT, kind TEXT,
            grp TEXT NOT NULL, title TEXT NOT NULL, outcome TEXT NOT NULL
        );
        CREATE INDEX notification_log_time ON notification_log (time);
        """

    static let versionTwo = """
        CREATE TABLE ledger_target (target TEXT PRIMARY KEY, last_scan REAL, scanned_kinds TEXT NOT NULL DEFAULT '', rules TEXT NOT NULL DEFAULT '');
        CREATE TABLE finding (
            target TEXT NOT NULL, key TEXT NOT NULL, kind TEXT NOT NULL, title TEXT NOT NULL,
            rank INTEGER NOT NULL, exploited INTEGER NOT NULL, malware INTEGER NOT NULL, first_seen REAL NOT NULL, last_seen REAL NOT NULL,
            missed INTEGER NOT NULL, resolved_at REAL, notified_at REAL, notified_rank INTEGER, notified_urgent INTEGER NOT NULL,
            aliases TEXT NOT NULL DEFAULT '',
            PRIMARY KEY (target, key)
        ) WITHOUT ROWID;
        CREATE TABLE security_result (key TEXT PRIMARY KEY, entry BLOB NOT NULL, updated REAL NOT NULL);
        CREATE TABLE security_cache (name TEXT PRIMARY KEY, value BLOB NOT NULL, updated REAL NOT NULL);
        CREATE INDEX security_cache_updated ON security_cache (updated);
        """

    static func upgrade(_ setup: String) async throws {
        let folder = FileManager.default.temporaryDirectory.appendingPathComponent("rackpulse-up-\(UUID().uuidString)", isDirectory: true)
        defer { try? FileManager.default.removeItem(at: folder) }
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
        let url = folder.appendingPathComponent("rackpulse.sqlite")
        let old = try SQLiteConnection(path: url.path)
        try old.execute(setup)
        let state = try JSONEncoder().encode(AlertState())
        try old.run("INSERT INTO alert_state (project, state, updated) VALUES ('p', ?, 0)", [.blob(state)])
        try old.run("INSERT INTO notification_log (time, project, grp, title, outcome) VALUES (?, 'p', 'g', 'old', 'sent')", [.date(Self.t0)])
        let hasFindings = try old.query("SELECT name FROM sqlite_master WHERE name = 'finding'") { $0.text(0) }.isEmpty == false
        if hasFindings {
            try old.run("INSERT INTO ledger_target (target, last_scan, scanned_kinds, rules) VALUES ('hetzner/p/server/1', ?, 'vulnerability', 'v3,h')",
                        [.date(Self.t0)])
            try old.run("""
                INSERT INTO finding (target, key, kind, title, rank, exploited, malware, first_seen, last_seen, missed, notified_at, notified_rank, notified_urgent, aliases)
                VALUES ('hetzner/p/server/1', 'vulnerability|CVE-1', 'vulnerability', 'CVE-1 in openssl', 4, 0, 0, ?, ?, 0, ?, 4, 0, 'CVE-1')
                """, [.date(Self.t0), .date(Self.t0), .date(Self.t0)])
            try old.run("INSERT INTO security_result (key, entry, updated) VALUES ('a', ?, 0)", [.blob(Data("1".utf8))])
        }

        let database = try LocalDatabase(url: url)
        let tables = try database.connection.query("SELECT name FROM sqlite_master WHERE type = 'table'") { $0.text(0) }.compactMap { $0 }
        #expect(tables.contains("finding_decision"))
        #expect(try database.connection.query("PRAGMA user_version") { $0.int(0) }.first == 3)
        #expect(try await database.alertState(project: "p") != nil)
        #expect(try await database.log().map(\.title) == ["old"])
        let ledger = try await database.ledger(target: "hetzner/p/server/1")
        if hasFindings {
            #expect(try database.securityResults() == ["a": Data("1".utf8)])
            #expect(ledger.rules == "v3,h")
            #expect(ledger.entries["vulnerability|CVE-1"]?.notifiedRank == 4)
            #expect(ledger.entries["vulnerability|CVE-1"]?.ignored == false)
        } else {
            #expect(ledger.entries.isEmpty)
        }
        try database.saveDecision(FindingDecision(target: "hetzner/p/server/1", key: "CVE-1", title: "CVE-1 in openssl", reason: .notAffected,
                                                  end: .fixAvailable, created: Self.t0))
        #expect(try database.decisions().count == 1)

        let again = try LocalDatabase(url: url)
        #expect(try again.decisions().count == 1)
    }

    @Test func upgradesAVersionTwoFile() async throws {
        try await Self.upgrade(Self.versionOne + Self.versionTwo + "PRAGMA user_version = 2;")
    }

    @Test func upgradesAVersionOneFileToDecisions() async throws {
        try await Self.upgrade(Self.versionOne + "PRAGMA user_version = 1;")
    }
}

struct IgnoreRuleTests {
    static let t0 = FindingLedgerTests.t0
    static let target = FindingDecisionTests.target

    static func item(_ advisory: Advisory) -> SecurityResult.Item {
        FindingDecisionTests.item(FindingDecisionTests.result([advisory], at: t0), advisory.id)
    }

    static func make(_ advisory: Advisory, reason: FindingDecision.Reason, note: String = "", end: FindingDecision.End) -> FindingDecision? {
        FindingDecision.make(target: target, item: item(advisory), reason: reason, note: note, end: end, created: t0)
    }

    @Test func highSeverityAllowsAnyReasonAndEnd() {
        let high = Advisory(id: "CVE-2024-2", severity: .high)
        #expect(FindingDecision.rule(high) == .any)
        #expect(Self.make(high, reason: .acceptRisk, end: FindingDecision.end(days: 90, from: Self.t0)) != nil)
        #expect(Self.make(high, reason: .fixLater, end: .fixAvailable) != nil)
    }

    @Test(arguments: [false, true])
    func criticalOrExploitedNeedsNotAffectedANoteAndThirtyDays(exploited: Bool) {
        var advisory = Advisory(id: "CVE-2024-1", severity: exploited ? .high : .critical)
        if exploited { advisory.knownExploited = FindingDecisionTests.exploited }
        let thirty = FindingDecision.end(days: 30, from: Self.t0)
        #expect(FindingDecision.rule(advisory) == .notAffectedOnly)
        #expect(Self.make(advisory, reason: .notAffected, note: "Decoder not used", end: thirty) != nil)
        #expect(Self.make(advisory, reason: .notAffected, note: "  ", end: thirty) == nil)
        #expect(Self.make(advisory, reason: .acceptRisk, note: "Later", end: thirty) == nil)
        #expect(Self.make(advisory, reason: .notAffected, note: "Decoder not used", end: FindingDecision.end(days: 90, from: Self.t0)) == nil)
        #expect(Self.make(advisory, reason: .notAffected, note: "Decoder not used", end: .fixAvailable) == nil)
    }

    @Test func malwareCannotBeIgnored() {
        var malware = Advisory(id: "MAL-2024-1", severity: .critical)
        malware.kind = .malware
        #expect(FindingDecision.rule(malware) == .never)
        #expect(Self.make(malware, reason: .notAffected, note: "Test", end: FindingDecision.end(days: 30, from: Self.t0)) == nil)
    }
}
