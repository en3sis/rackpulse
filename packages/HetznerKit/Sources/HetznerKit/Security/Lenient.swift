import Foundation

struct Skipped: Decodable {
    init(from decoder: Decoder) throws {}
}

extension KeyedDecodingContainer {
    func lossy<T: Decodable>(_ type: [T].Type, forKey key: Key, limit: Int = .max) -> [T] {
        guard var nested = try? nestedUnkeyedContainer(forKey: key) else { return [] }
        var items: [T] = []
        while !nested.isAtEnd && items.count < limit {
            if let item = try? nested.decode(T.self) {
                items.append(item)
            } else if (try? nested.decode(Skipped.self)) == nil {
                break
            }
        }
        return items
    }

    func optional<T: Decodable>(_ type: T.Type, forKey key: Key) -> T? {
        (try? decodeIfPresent(type, forKey: key)) ?? nil
    }

    func optional(_ type: String.Type, forKey key: Key, limit: Int) -> String? {
        optional(String.self, forKey: key).flatMap { $0.utf8.count <= limit ? $0 : nil }
    }

    func capped(_ type: String.Type, forKey key: Key, limit: Int) throws -> String {
        let value = try decode(String.self, forKey: key)
        guard value.utf8.count <= limit else { throw tooLong(key) }
        return value
    }

    func capped(_ type: String?.Type, forKey key: Key, limit: Int) throws -> String? {
        guard let value = optional(String.self, forKey: key) else { return nil }
        guard value.utf8.count <= limit else { throw tooLong(key) }
        return value
    }

    func strings(forKey key: Key, limit: Int, length: Int) -> [String] {
        lossy([String].self, forKey: key, limit: limit * 4).filter { $0.utf8.count <= length }.prefix(limit).map { $0 }
    }

    private func tooLong(_ key: Key) -> DecodingError {
        DecodingError.dataCorruptedError(forKey: key, in: self, debugDescription: "Value is too long")
    }
}
