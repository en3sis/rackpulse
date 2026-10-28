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
    public var planner: PlannerState?
    public var log: [NotificationRecord] = []

    public init() {}

    public var isEmpty: Bool { alertStates.isEmpty && planner == nil && log.isEmpty }
}

public actor LocalDatabase {
    public static let schemaVersion = 1
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
            try connection.execute("PRAGMA user_version = \(schemaVersion)")
        }
    }

    public func alertState(project: String) throws -> AlertState? {
        try connection.query("SELECT state FROM alert_state WHERE project = ?", [.text(project)]) { row in
            try JSONDecoder().decode(AlertState.self, from: row.data(0))
        }.first
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
        try connection.transaction {
            for project in states where !projects.contains(project) {
                try connection.run("DELETE FROM alert_state WHERE project = ?", [.text(project)])
            }
        }
    }
}
