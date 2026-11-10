import Foundation

public struct SecurityCache: Sendable {
    let connection: SQLiteConnection

    public init(database: LocalDatabase) {
        connection = database.connection
    }

    func key(_ name: String) -> String? {
        let parts = name.split(separator: "/", omittingEmptySubsequences: false)
        guard !parts.isEmpty, parts.allSatisfy({ !$0.isEmpty && $0 != "." && $0 != ".." }) else { return nil }
        return name
    }

    func data(_ name: String) -> Data? {
        guard let key = key(name) else { return nil }
        return (try? connection.query("SELECT value FROM security_cache WHERE name = ?", [.text(key)]) { $0.data(0) })?.first
    }

    func read<T: Decodable>(_ type: T.Type, from name: String) -> T? {
        guard let data = data(name) else { return nil }
        do {
            return try JSONDecoder().decode(type, from: data)
        } catch {
            remove(name)
            return nil
        }
    }

    func write<T: Encodable>(_ value: T, to name: String) {
        guard let data = try? JSONEncoder().encode(value) else { return }
        store(data, as: name)
    }

    func store(_ data: Data, as name: String) {
        guard let key = key(name) else { return }
        try? connection.run(
            "INSERT INTO security_cache (name, value, updated) VALUES (?, ?, ?) ON CONFLICT(name) DO UPDATE SET value = excluded.value, updated = excluded.updated",
            [.text(key), .blob(data), .date(.now)]
        )
    }

    func remove(_ name: String) {
        guard let key = key(name) else { return }
        try? connection.run("DELETE FROM security_cache WHERE name = ?", [.text(key)])
    }

    func prune(folder: String, keeping limit: Int) {
        guard let key = key(folder) else { return }
        try? connection.run(
            """
            DELETE FROM security_cache WHERE name IN (
                SELECT name FROM security_cache WHERE name LIKE ? ESCAPE '\\' ORDER BY updated DESC LIMIT -1 OFFSET ?
            )
            """,
            [.text(LocalDatabase.likePrefix(key + "/")), .int(max(0, limit))]
        )
    }

    func count(folder: String) -> Int {
        guard let key = key(folder) else { return 0 }
        return (try? connection.query("SELECT COUNT(*) FROM security_cache WHERE name LIKE ? ESCAPE '\\'", [.text(LocalDatabase.likePrefix(key + "/"))]) { $0.int(0) })?.first ?? 0
    }

    public func clear() {
        try? connection.run("DELETE FROM security_cache")
    }

    static func bounded<Value>(_ entries: [String: Value], limit: Int, date: (Value) -> Date) -> [String: Value] {
        guard entries.count > limit else { return entries }
        let kept = entries.sorted { date($0.value) > date($1.value) }.prefix(limit)
        return Dictionary(uniqueKeysWithValues: kept.map { ($0.key, $0.value) })
    }
}
