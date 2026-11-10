import Foundation

public enum SemanticVersion {
    typealias Part = ArraySlice<UInt8>

    struct Parsed {
        var core: [Part]
        var prerelease: [Part]
    }

    public static func compare(_ lhs: String, _ rhs: String, shortForms: Bool) -> Int? {
        guard let a = parse(lhs, shortForms: shortForms), let b = parse(rhs, shortForms: shortForms) else { return nil }
        return compare(a, b)
    }

    static func compare(_ a: Parsed, _ b: Parsed) -> Int {
        for (x, y) in zip(a.core, b.core) {
            let order = Digits.compare(x, y)
            if order != 0 { return order }
        }
        switch (a.prerelease.isEmpty, b.prerelease.isEmpty) {
        case (true, true): return 0
        case (true, false): return 1
        case (false, true): return -1
        case (false, false): break
        }
        for (x, y) in zip(a.prerelease, b.prerelease) {
            let order = identifier(x, y)
            if order != 0 { return order }
        }
        if a.prerelease.count != b.prerelease.count { return a.prerelease.count < b.prerelease.count ? -1 : 1 }
        return 0
    }

    private static func identifier(_ a: Part, _ b: Part) -> Int {
        let numericA = a.allSatisfy(Digits.isDigit)
        let numericB = b.allSatisfy(Digits.isDigit)
        switch (numericA, numericB) {
        case (true, true): return Digits.compare(a, b)
        case (true, false): return -1
        case (false, true): return 1
        case (false, false): return Digits.bytes(a, b)
        }
    }

    static func parse(_ version: String, shortForms: Bool) -> Parsed? {
        var bytes = Array(version.utf8)[...]
        while let first = bytes.first, first == 32 || first == UInt8(ascii: "=") { bytes.removeFirst() }
        while let last = bytes.last, last == 32 { bytes.removeLast() }
        if let first = bytes.first, first == UInt8(ascii: "v") || first == UInt8(ascii: "V") { bytes.removeFirst() }
        var build = false
        if let plus = bytes.firstIndex(of: UInt8(ascii: "+")) {
            guard isIdentifierList(bytes[(plus + 1)...]) else { return nil }
            build = true
            bytes = bytes[..<plus]
        }
        var prerelease: [Part] = []
        if let dash = bytes.firstIndex(of: UInt8(ascii: "-")) {
            let tail = bytes[(dash + 1)...]
            guard isIdentifierList(tail) else { return nil }
            prerelease = tail.split(separator: UInt8(ascii: "."), omittingEmptySubsequences: false)
            bytes = bytes[..<dash]
        }
        let core = bytes.split(separator: UInt8(ascii: "."), omittingEmptySubsequences: false)
        guard core.allSatisfy({ !$0.isEmpty && $0.allSatisfy(Digits.isDigit) }) else { return nil }
        guard core.count == 3 || (shortForms && core.count < 3 && prerelease.isEmpty && !build) else { return nil }
        return Parsed(core: core + Array(repeating: [UInt8(ascii: "0")][...], count: 3 - core.count), prerelease: prerelease)
    }

    private static func isIdentifierList(_ bytes: Part) -> Bool {
        let parts = bytes.split(separator: UInt8(ascii: "."), omittingEmptySubsequences: false)
        return parts.allSatisfy { !$0.isEmpty && $0.allSatisfy { Digits.isAlphanumeric($0) || $0 == UInt8(ascii: "-") } }
    }
}
