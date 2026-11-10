import Foundation

public struct NotificationRecord: Sendable, Hashable, Codable {
    public var time: Date
    public var project: String
    public var target: String?
    public var kind: RuleKind?
    public var group: String
    public var title: String
    public var outcome: DeliveryOutcome

    public init(time: Date, project: String, target: String?, kind: RuleKind?, group: String, title: String, outcome: DeliveryOutcome) {
        self.time = time
        self.project = project
        self.target = target
        self.kind = kind
        self.group = group
        self.title = title
        self.outcome = outcome
    }
}

public struct AlertCommit: Sendable {
    public var alertStates: [String: AlertState] = [:]
    public var ledgers: [LedgerRecord] = []
    public var planner: PlannerState?
    public var log: [NotificationRecord] = []

    public init() {}

    public var isEmpty: Bool { alertStates.isEmpty && ledgers.isEmpty && planner == nil && log.isEmpty }
}

public actor LocalDatabase {
    public static let schemaVersion = 3
    public static let logRetention: TimeInterval = 90 * 86_400

    nonisolated let connection: SQLiteConnection

    public init(url: URL) throws {
        try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        connection = try SQLiteConnection(path: url.path)
        try Self.migrate(connection)
    }

    public init() throws {
        connection = try SQLiteConnection(path: ":memory:")
        try Self.migrate(connection)
    }

    public static func open(at url: URL) -> LocalDatabase {
        if let database = try? LocalDatabase(url: url) { return database }
        return try! LocalDatabase()
    }

    static func migrate(_ connection: SQLiteConnection) throws {
        try connection.execute("PRAGMA journal_mode = WAL")
        try connection.transaction {
            let version = try connection.query("PRAGMA user_version") { $0.int(0) }.first ?? 0
            guard version < schemaVersion else { return }
            if version < 1 {
                try connection.execute("""
                    CREATE TABLE IF NOT EXISTS alert_state (project TEXT PRIMARY KEY, state BLOB NOT NULL, updated REAL NOT NULL);
                    CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value BLOB NOT NULL);
                    CREATE TABLE IF NOT EXISTS notification_log (
                        id INTEGER PRIMARY KEY, time REAL NOT NULL, project TEXT NOT NULL, target TEXT, kind TEXT,
                        grp TEXT NOT NULL, title TEXT NOT NULL, outcome TEXT NOT NULL
                    );
                    CREATE INDEX IF NOT EXISTS notification_log_time ON notification_log (time);
                    """)
            }
            if version < 2 {
                try connection.execute("""
                    CREATE TABLE IF NOT EXISTS ledger_target (target TEXT PRIMARY KEY, last_scan REAL, scanned_kinds TEXT NOT NULL DEFAULT '', rules TEXT NOT NULL DEFAULT '');
                    CREATE TABLE IF NOT EXISTS finding (
                        target TEXT NOT NULL, key TEXT NOT NULL, kind TEXT NOT NULL, title TEXT NOT NULL,
                        rank INTEGER NOT NULL, exploited INTEGER NOT NULL, malware INTEGER NOT NULL, first_seen REAL NOT NULL, last_seen REAL NOT NULL,
                        missed INTEGER NOT NULL, resolved_at REAL, notified_at REAL, notified_rank INTEGER, notified_urgent INTEGER NOT NULL,
                        aliases TEXT NOT NULL DEFAULT '',
                        PRIMARY KEY (target, key)
                    ) WITHOUT ROWID;
                    CREATE TABLE IF NOT EXISTS security_result (key TEXT PRIMARY KEY, entry BLOB NOT NULL, updated REAL NOT NULL);
                    CREATE TABLE IF NOT EXISTS security_cache (name TEXT PRIMARY KEY, value BLOB NOT NULL, updated REAL NOT NULL);
                    CREATE INDEX IF NOT EXISTS security_cache_updated ON security_cache (updated);
                    """)
            }
            if version < 3 {
                try connection.execute("""
                    CREATE TABLE IF NOT EXISTS finding_decision (
                        id TEXT PRIMARY KEY, target TEXT NOT NULL, key TEXT NOT NULL, title TEXT NOT NULL, reason TEXT NOT NULL,
                        note TEXT NOT NULL DEFAULT '', until REAL, until_fix INTEGER NOT NULL DEFAULT 0, created REAL NOT NULL,
                        exploited INTEGER NOT NULL DEFAULT 0, malware INTEGER NOT NULL DEFAULT 0, last_seen REAL,
                        UNIQUE (target, key)
                    );
                    ALTER TABLE finding ADD COLUMN ignored INTEGER NOT NULL DEFAULT 0;
                    """)
            }
            try connection.execute("PRAGMA user_version = \(schemaVersion)")
        }
    }

    public nonisolated func securityResults() throws -> [String: Data] {
        let rows = try connection.query("SELECT key, entry FROM security_result") { ($0.text(0) ?? "", $0.data(1)) }
        return Dictionary(rows, uniquingKeysWith: { first, _ in first })
    }

    public nonisolated func saveSecurityResults(_ changed: [String: Data], removed: Set<String> = []) throws {
        guard !changed.isEmpty || !removed.isEmpty else { return }
        try connection.transaction {
            for (key, entry) in changed {
                try connection.run(
                    "INSERT INTO security_result (key, entry, updated) VALUES (?, ?, ?) ON CONFLICT(key) DO UPDATE SET entry = excluded.entry, updated = excluded.updated",
                    [.text(key), .blob(entry), .date(.now)]
                )
            }
            for key in removed {
                try connection.run("DELETE FROM security_result WHERE key = ?", [.text(key)])
            }
        }
    }

    public nonisolated func clearSecurityResults() throws {
        try connection.run("DELETE FROM security_result")
    }

    public func alertState(project: String) throws -> AlertState? {
        try connection.query("SELECT state FROM alert_state WHERE project = ?", [.text(project)]) { row in
            try JSONDecoder().decode(AlertState.self, from: row.data(0))
        }.first
    }

    public func ledger(target: String) throws -> LedgerRecord {
        let scan = try connection.query("SELECT last_scan, scanned_kinds, rules FROM ledger_target WHERE target = ?", [.text(target)]) { row in
            (row.date(0), row.text(1), row.text(2))
        }.first
        let entries = try connection.query(
            """
            SELECT key, kind, title, rank, exploited, malware, first_seen, last_seen, missed, resolved_at, notified_at, notified_rank, notified_urgent, aliases,
                   ignored
            FROM finding WHERE target = ?
            """,
            [.text(target)]
        ) { row -> LedgerEntry? in
            guard let kind = RuleKind(rawValue: row.text(1) ?? "") else { return nil }
            return LedgerEntry(
                key: row.text(0) ?? "", kind: kind, title: row.text(2) ?? "", rank: row.int(3),
                exploited: row.int(4) != 0, malware: row.int(5) != 0,
                aliases: (row.text(13) ?? "").split(separator: " ").map(String.init),
                firstSeen: row.date(6) ?? .distantPast, lastSeen: row.date(7) ?? .distantPast, missed: row.int(8),
                resolvedAt: row.date(9), notifiedAt: row.date(10), notifiedRank: row.optionalInt(11), notifiedUrgent: row.int(12) != 0,
                ignored: row.int(14) != 0
            )
        }.compactMap { $0 }
        let kinds = Set((scan?.1 ?? "").split(separator: ",").compactMap { RuleKind(rawValue: String($0)) })
        return LedgerRecord(
            target: target, lastScan: scan?.0, scannedKinds: kinds, rules: scan?.2 ?? "",
            entries: Dictionary(entries.map { ($0.key, $0) }, uniquingKeysWith: { first, _ in first })
        )
    }

    public func plannerState() throws -> PlannerState {
        try connection.query("SELECT value FROM meta WHERE key = 'planner'", []) { row in
            try JSONDecoder().decode(PlannerState.self, from: row.data(0))
        }.first ?? PlannerState()
    }

    public func log(limit: Int = 200) throws -> [NotificationRecord] {
        try connection.query(
            "SELECT time, project, target, kind, grp, title, outcome FROM notification_log ORDER BY time DESC, id DESC LIMIT ?",
            [.int(limit)]
        ) { row in
            NotificationRecord(
                time: row.date(0) ?? .distantPast, project: row.text(1) ?? "", target: row.text(2),
                kind: row.text(3).flatMap(RuleKind.init(rawValue:)), group: row.text(4) ?? "", title: row.text(5) ?? "",
                outcome: DeliveryOutcome(rawValue: row.text(6) ?? "") ?? .sent
            )
        }
    }

    public func commit(_ change: AlertCommit) throws {
        guard !change.isEmpty else { return }
        try connection.transaction {
            let encoder = JSONEncoder()
            for (project, state) in change.alertStates {
                try connection.run(
                    "INSERT INTO alert_state (project, state, updated) VALUES (?, ?, ?) ON CONFLICT(project) DO UPDATE SET state = excluded.state, updated = excluded.updated",
                    [.text(project), .blob(try encoder.encode(state)), .date(.now)]
                )
            }
            for record in change.ledgers {
                try write(record)
            }
            if let planner = change.planner {
                try connection.run(
                    "INSERT INTO meta (key, value) VALUES ('planner', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                    [.blob(try encoder.encode(planner))]
                )
            }
            for entry in change.log {
                try connection.run(
                    "INSERT INTO notification_log (time, project, target, kind, grp, title, outcome) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    [.date(entry.time), .text(entry.project), entry.target.map(SQLiteValue.text) ?? .null,
                     entry.kind.map { .text($0.rawValue) } ?? .null, .text(entry.group), .text(entry.title), .text(entry.outcome.rawValue)]
                )
            }
        }
    }

    public func prune(now: Date = .now) throws {
        try connection.run("DELETE FROM notification_log WHERE time < ?", [.date(now.addingTimeInterval(-Self.logRetention))])
    }

    public func keepProjects(_ projects: Set<String>) throws {
        let states = try connection.query("SELECT project FROM alert_state", []) { $0.text(0) }.compactMap { $0 }
        let targets = try connection.query("SELECT target FROM ledger_target", []) { $0.text(0) }.compactMap { $0 }
        try connection.transaction {
            for project in states where !projects.contains(project) {
                try connection.run("DELETE FROM alert_state WHERE project = ?", [.text(project)])
            }
            for target in targets {
                let parts = target.split(separator: "/", omittingEmptySubsequences: false)
                guard parts.count > 1, !projects.contains(String(parts[1])) else { continue }
                try connection.run("DELETE FROM finding WHERE target = ?", [.text(target)])
                try connection.run("DELETE FROM ledger_target WHERE target = ?", [.text(target)])
            }
            let decided = try connection.query("SELECT DISTINCT target FROM finding_decision", []) { $0.text(0) }.compactMap { $0 }
            for target in decided {
                let parts = target.split(separator: "/", omittingEmptySubsequences: false)
                guard parts.count > 1, !projects.contains(String(parts[1])) else { continue }
                try connection.run("DELETE FROM finding_decision WHERE target = ?", [.text(target)])
            }
        }
    }

    public func removeTargets(notIn targets: Set<String>, prefix: String) throws {
        let known = try connection.query("SELECT target FROM ledger_target WHERE target LIKE ? ESCAPE '\\'", [.text(Self.likePrefix(prefix))]) { $0.text(0) }
        let decided = try connection.query("SELECT DISTINCT target FROM finding_decision WHERE target LIKE ? ESCAPE '\\'", [.text(Self.likePrefix(prefix))]) { $0.text(0) }
        try connection.transaction {
            for case let target? in known where !targets.contains(target) {
                try connection.run("DELETE FROM finding WHERE target = ?", [.text(target)])
                try connection.run("DELETE FROM ledger_target WHERE target = ?", [.text(target)])
            }
            for case let target? in decided where !targets.contains(target) {
                try connection.run("DELETE FROM finding_decision WHERE target = ?", [.text(target)])
            }
        }
    }

    public nonisolated func decisions() throws -> [FindingDecision] {
        try connection.query(
            "SELECT id, target, key, title, reason, note, until, until_fix, created, exploited, malware, last_seen FROM finding_decision ORDER BY created"
        ) { row -> FindingDecision? in
            guard let id = row.text(0).flatMap(UUID.init(uuidString:)), let reason = row.text(4).flatMap(FindingDecision.Reason.init(rawValue:)) else {
                return nil
            }
            let end: FindingDecision.End
            if row.int(7) != 0 {
                end = .fixAvailable
            } else if let until = row.date(6) {
                end = .date(until)
            } else {
                return nil
            }
            return FindingDecision(
                id: id, target: row.text(1) ?? "", key: row.text(2) ?? "", title: row.text(3) ?? "", reason: reason, note: row.text(5) ?? "",
                end: end, created: row.date(8) ?? .distantPast, exploited: row.int(9) != 0, malware: row.int(10) != 0, lastSeen: row.date(11)
            )
        }.compactMap { $0 }
    }

    public nonisolated func saveDecision(_ decision: FindingDecision) throws {
        try connection.transaction {
            try connection.run("DELETE FROM finding_decision WHERE target = ? AND key = ?", [.text(decision.target), .text(decision.key)])
            try connection.run(
                """
                INSERT INTO finding_decision (id, target, key, title, reason, note, until, until_fix, created, exploited, malware, last_seen)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [.text(decision.id.uuidString), .text(decision.target), .text(decision.key), .text(decision.title), .text(decision.reason.rawValue),
                 .text(decision.note), decision.end.date.map(SQLiteValue.date) ?? .null, .int(decision.end == .fixAvailable ? 1 : 0),
                 .date(decision.created), .int(decision.exploited ? 1 : 0), .int(decision.malware ? 1 : 0),
                 decision.lastSeen.map(SQLiteValue.date) ?? .null]
            )
        }
    }

    public nonisolated func markDecisionsSeen(_ ids: Set<UUID>, at time: Date) throws {
        guard !ids.isEmpty else { return }
        try connection.transaction {
            for id in ids {
                try connection.run("UPDATE finding_decision SET last_seen = ? WHERE id = ?", [.date(time), .text(id.uuidString)])
            }
        }
    }

    public nonisolated func deleteDecisions(_ ids: Set<UUID>) throws {
        guard !ids.isEmpty else { return }
        try connection.transaction {
            for id in ids {
                try connection.run("DELETE FROM finding_decision WHERE id = ?", [.text(id.uuidString)])
            }
        }
    }

    private func write(_ record: LedgerRecord) throws {
        try connection.run(
            "INSERT INTO ledger_target (target, last_scan, scanned_kinds, rules) VALUES (?, ?, ?, ?) ON CONFLICT(target) DO UPDATE SET last_scan = excluded.last_scan, scanned_kinds = excluded.scanned_kinds, rules = excluded.rules",
            [.text(record.target), record.lastScan.map(SQLiteValue.date) ?? .null, .text(record.scannedKinds.map(\.rawValue).sorted().joined(separator: ",")),
             .text(record.rules)]
        )
        try connection.run("DELETE FROM finding WHERE target = ?", [.text(record.target)])
        for entry in record.entries.values {
            try connection.run(
                """
                INSERT INTO finding (target, key, kind, title, rank, exploited, malware, first_seen, last_seen, missed, resolved_at, notified_at, notified_rank, notified_urgent, aliases, ignored)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [.text(record.target), .text(entry.key), .text(entry.kind.rawValue), .text(entry.title), .int(entry.rank),
                 .int(entry.exploited ? 1 : 0), .int(entry.malware ? 1 : 0), .date(entry.firstSeen), .date(entry.lastSeen), .int(entry.missed),
                 entry.resolvedAt.map(SQLiteValue.date) ?? .null, entry.notifiedAt.map(SQLiteValue.date) ?? .null,
                 entry.notifiedRank.map(SQLiteValue.int) ?? .null, .int(entry.notifiedUrgent ? 1 : 0), .text(entry.aliases.joined(separator: " ")),
                 .int(entry.ignored ? 1 : 0)]
            )
        }
    }

    static func likePrefix(_ prefix: String) -> String {
        prefix.replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "%", with: "\\%")
            .replacingOccurrences(of: "_", with: "\\_") + "%"
    }
}

