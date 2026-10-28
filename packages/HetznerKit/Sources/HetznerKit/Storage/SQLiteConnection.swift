import Foundation
import SQLite3

public enum DatabaseError: Error, Equatable {
    case open(String)
    case statement(String)
}

enum SQLiteValue {
    case null
    case int(Int)
    case text(String)
    case blob(Data)
    case date(Date)
}

struct SQLiteRow {
    let statement: OpaquePointer

    func text(_ column: Int32) -> String? {
        guard sqlite3_column_type(statement, column) != SQLITE_NULL, let raw = sqlite3_column_text(statement, column) else { return nil }
        return String(cString: raw)
    }

    func int(_ column: Int32) -> Int {
        Int(sqlite3_column_int64(statement, column))
    }

    func optionalInt(_ column: Int32) -> Int? {
        sqlite3_column_type(statement, column) == SQLITE_NULL ? nil : int(column)
    }

    func date(_ column: Int32) -> Date? {
        sqlite3_column_type(statement, column) == SQLITE_NULL
            ? nil
            : Date(timeIntervalSince1970: sqlite3_column_double(statement, column))
    }

    func data(_ column: Int32) -> Data {
        let count = Int(sqlite3_column_bytes(statement, column))
        guard count > 0, let bytes = sqlite3_column_blob(statement, column) else { return Data() }
        return Data(bytes: bytes, count: count)
    }
}

final class SQLiteConnection: @unchecked Sendable {
    private static let transient = unsafeBitCast(-1, to: sqlite3_destructor_type.self)
    private let db: OpaquePointer
    private let lock = NSRecursiveLock()

    init(path: String) throws {
        var pointer: OpaquePointer?
        let flags = SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_NOMUTEX
        guard sqlite3_open_v2(path, &pointer, flags, nil) == SQLITE_OK, let pointer else {
            let message = pointer.map { String(cString: sqlite3_errmsg($0)) } ?? "cannot open \(path)"
            sqlite3_close(pointer)
            throw DatabaseError.open(message)
        }
        db = pointer
        sqlite3_busy_timeout(db, 2_000)
    }

    deinit {
        sqlite3_close(db)
    }

    func execute(_ sql: String) throws {
        try lock.withLock {
            var error: UnsafeMutablePointer<CChar>?
            guard sqlite3_exec(db, sql, nil, nil, &error) == SQLITE_OK else {
                let message = error.map { String(cString: $0) } ?? "SQL error"
                sqlite3_free(error)
                throw DatabaseError.statement(message)
            }
        }
    }

    func transaction<T>(_ body: () throws -> T) throws -> T {
        try lock.withLock {
            try execute("BEGIN IMMEDIATE")
            do {
                let result = try body()
                try execute("COMMIT")
                return result
            } catch {
                try? execute("ROLLBACK")
                throw error
            }
        }
    }

    func run(_ sql: String, _ values: [SQLiteValue] = []) throws {
        try lock.withLock {
            let statement = try prepare(sql, values)
            defer { sqlite3_finalize(statement) }
            guard sqlite3_step(statement) == SQLITE_DONE else { throw failure() }
        }
    }

    func query<T>(_ sql: String, _ values: [SQLiteValue] = [], _ map: (SQLiteRow) throws -> T) throws -> [T] {
        try lock.withLock {
            let statement = try prepare(sql, values)
            defer { sqlite3_finalize(statement) }
            var result: [T] = []
            while true {
                let step = sqlite3_step(statement)
                if step == SQLITE_DONE { break }
                guard step == SQLITE_ROW else { throw failure() }
                result.append(try map(SQLiteRow(statement: statement)))
            }
            return result
        }
    }

    private func prepare(_ sql: String, _ values: [SQLiteValue]) throws -> OpaquePointer {
        var statement: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &statement, nil) == SQLITE_OK, let statement else { throw failure() }
        for (offset, value) in values.enumerated() {
            let index = Int32(offset + 1)
            let code: Int32 = switch value {
            case .null: sqlite3_bind_null(statement, index)
            case .int(let number): sqlite3_bind_int64(statement, index, Int64(number))
            case .text(let text): sqlite3_bind_text(statement, index, text, -1, Self.transient)
            case .date(let date): sqlite3_bind_double(statement, index, date.timeIntervalSince1970)
            case .blob(let data):
                data.withUnsafeBytes { sqlite3_bind_blob(statement, index, $0.baseAddress, Int32(data.count), Self.transient) }
            }
            guard code == SQLITE_OK else {
                sqlite3_finalize(statement)
                throw failure()
            }
        }
        return statement
    }

    private func failure() -> DatabaseError {
        .statement(String(cString: sqlite3_errmsg(db)))
    }
}
