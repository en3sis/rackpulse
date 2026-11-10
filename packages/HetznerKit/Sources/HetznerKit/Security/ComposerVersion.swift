import Foundation

public enum ComposerVersion {
    public static func compare(_ lhs: String, _ rhs: String) -> Int? {
        phpCompare(Array(normalize(lhs).utf8)[...], Array(normalize(rhs).utf8)[...])
    }

    public static func normalize(_ version: String) -> String {
        var text = version.trimmingCharacters(in: .whitespaces)
        if ["master", "trunk", "default"].contains(text) { text = "dev-" + text }
        if text.lowercased().hasPrefix("dev-") { return "dev-" + text.dropFirst(4) }
        if let plus = text.firstIndex(of: "+"), !text[..<plus].isEmpty, !text.contains(where: { $0 == "," || $0.isWhitespace }) {
            text = String(text[..<plus])
        }
        if let classical = classical(text) { return classical }
        if let first = text.first, first == "v" || first == "V", text.dropFirst().first?.isNumber == true { return String(text.dropFirst()) }
        return text
    }

    static func classical(_ version: String) -> String? {
        var rest = Array(version.utf8)[...]
        if let first = rest.first, Digits.lower(first) == UInt8(ascii: "v") { rest.removeFirst() }
        let major = rest.prefix { Digits.isDigit($0) }
        guard (1...5).contains(major.count) else { return nil }
        rest.removeFirst(major.count)
        var parts = [major]
        while parts.count < 4, rest.first == UInt8(ascii: "."), let next = rest.dropFirst().first, Digits.isDigit(next) {
            rest.removeFirst()
            let digits = rest.prefix { Digits.isDigit($0) }
            rest.removeFirst(digits.count)
            parts.append(digits)
        }
        var normalized = parts.map { String(decoding: $0, as: UTF8.self) }.joined(separator: ".")
        normalized += String(repeating: ".0", count: 4 - parts.count)
        guard let modifier = modifier(rest) else { return nil }
        if let stability = modifier.stability {
            if stability == "stable" { return normalized }
            normalized += "-" + expand(stability) + modifier.number
        }
        if modifier.dev { normalized += "-dev" }
        return normalized
    }

    static func modifier(_ input: ArraySlice<UInt8>) -> (stability: String?, number: String, dev: Bool)? {
        var start = input
        if let first = start.first, first == UInt8(ascii: ".") || first == UInt8(ascii: "_") || first == UInt8(ascii: "-") { start.removeFirst() }
        for option in ["stable", "beta", "b", "rc", "alpha", "a", "patch", "pl", "p"] {
            let lowered = start.prefix(option.utf8.count).map(Digits.lower)
            guard lowered.elementsEqual(option.utf8) else { continue }
            let original = String(decoding: start.prefix(option.utf8.count), as: UTF8.self)
            var rest = start.dropFirst(option.utf8.count)
            var number: [UInt8] = []
            while true {
                var probe = rest
                if let first = probe.first, first == UInt8(ascii: ".") || first == UInt8(ascii: "-") { probe.removeFirst() }
                let digits = probe.prefix { Digits.isDigit($0) }
                guard !digits.isEmpty else { break }
                number += rest.prefix(rest.count - probe.count) + digits
                rest = probe.dropFirst(digits.count)
            }
            if let dev = dev(rest) {
                let trimmed = number.drop { $0 == UInt8(ascii: ".") || $0 == UInt8(ascii: "-") }
                return (original, String(decoding: trimmed, as: UTF8.self), dev)
            }
        }
        if let dev = dev(start) { return (nil, "", dev) }
        if let dev = dev(input) { return (nil, "", dev) }
        return nil
    }

    private static func dev(_ input: ArraySlice<UInt8>) -> Bool? {
        if input.isEmpty { return false }
        var rest = input
        if let first = rest.first, first == UInt8(ascii: ".") || first == UInt8(ascii: "-") { rest.removeFirst() }
        return rest.map(Digits.lower).elementsEqual("dev".utf8) ? true : nil
    }

    private static func expand(_ stability: String) -> String {
        switch stability.lowercased() {
        case "a": "alpha"
        case "b": "beta"
        case "p", "pl": "patch"
        case "rc": "RC"
        default: stability.lowercased()
        }
    }

    static func canonical(_ version: ArraySlice<UInt8>) -> [UInt8] {
        guard var previous = version.first else { return [] }
        var result: [UInt8] = [previous]
        func isDigit(_ byte: UInt8) -> Bool { Digits.isDigit(byte) }
        func isNonDigit(_ byte: UInt8) -> Bool { !Digits.isDigit(byte) && byte != UInt8(ascii: ".") }
        for byte in version.dropFirst() {
            let last = result.last
            if byte == UInt8(ascii: "-") || byte == UInt8(ascii: "_") || byte == UInt8(ascii: "+") {
                if last != UInt8(ascii: ".") { result.append(UInt8(ascii: ".")) }
            } else if (isNonDigit(previous) && isDigit(byte)) || (isDigit(previous) && isNonDigit(byte)) {
                if last != UInt8(ascii: ".") { result.append(UInt8(ascii: ".")) }
                result.append(byte)
            } else if !Digits.isAlphanumeric(byte) {
                if last != UInt8(ascii: ".") { result.append(UInt8(ascii: ".")) }
            } else {
                result.append(byte)
            }
            previous = byte
        }
        if result.last == UInt8(ascii: ".") { result.removeLast() }
        return result
    }

    static let specialForms: [(String, Int)] = [
        ("dev", 0), ("alpha", 1), ("a", 1), ("beta", 2), ("b", 2), ("RC", 3), ("rc", 3), ("#", 4), ("pl", 5), ("p", 5),
    ]

    static func special(_ form: ArraySlice<UInt8>) -> Int {
        specialForms.first { form.starts(with: $0.0.utf8) }?.1 ?? -1
    }

    static func specialOrder(_ a: ArraySlice<UInt8>, _ b: ArraySlice<UInt8>) -> Int {
        (special(a) - special(b)).signum()
    }

    static let marker = Array("#N#".utf8)[...]

    static func phpCompare(_ first: ArraySlice<UInt8>, _ second: ArraySlice<UInt8>, depth: Int = 0) -> Int {
        if first.isEmpty || second.isEmpty {
            return first.isEmpty && second.isEmpty ? 0 : (first.isEmpty ? -1 : 1)
        }
        let a = (first.first == UInt8(ascii: "#") ? Array(first) : canonical(first)).split(separator: UInt8(ascii: "."), omittingEmptySubsequences: false)
        let b = (second.first == UInt8(ascii: "#") ? Array(second) : canonical(second)).split(separator: UInt8(ascii: "."), omittingEmptySubsequences: false)
        var index = 0
        var order = 0
        while index < a.count && index < b.count {
            let p = a[index]
            let q = b[index]
            let x = p.first ?? 0
            let y = q.first ?? 0
            if Digits.isDigit(x) && Digits.isDigit(y) {
                order = Digits.compare(p.prefix(while: Digits.isDigit), q.prefix(while: Digits.isDigit))
            } else if !Digits.isDigit(x) && !Digits.isDigit(y) {
                order = specialOrder(p, q)
            } else if Digits.isDigit(x) {
                order = specialOrder(marker, q)
            } else {
                order = specialOrder(p, marker)
            }
            if order != 0 { break }
            let more = index + 1 < a.count && index + 1 < b.count
            index += 1
            if !more { break }
        }
        guard order == 0, depth < 8 else { return order }
        if index < a.count {
            let rest = Array(a[index...].joined(separator: [UInt8(ascii: ".")]))[...]
            return rest.first.map(Digits.isDigit) == true ? 1 : phpCompare(rest, marker, depth: depth + 1)
        }
        if index < b.count {
            let rest = Array(b[index...].joined(separator: [UInt8(ascii: ".")]))[...]
            return rest.first.map(Digits.isDigit) == true ? -1 : phpCompare(marker, rest, depth: depth + 1)
        }
        return 0
    }
}
