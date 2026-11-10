import Foundation

public enum DebianVersion {
    public static func compare(_ lhs: String, _ rhs: String) -> Int {
        let a = parse(lhs)
        let b = parse(rhs)
        if a.epoch != b.epoch { return a.epoch < b.epoch ? -1 : 1 }
        let upstream = verrevcmp(a.upstream, b.upstream)
        if upstream != 0 { return upstream.signum() }
        return verrevcmp(a.revision, b.revision).signum()
    }

    public static func isLess(_ lhs: String, _ rhs: String) -> Bool {
        compare(lhs, rhs) < 0
    }

    static func parse(_ version: String) -> (epoch: Int, upstream: [UInt8], revision: [UInt8]) {
        var rest = Substring(version.trimmingCharacters(in: .whitespaces))
        var epoch = 0
        if let colon = rest.firstIndex(of: ":"), let value = Int(rest[..<colon]) {
            epoch = value
            rest = rest[rest.index(after: colon)...]
        }
        var revision: Substring = ""
        if let dash = rest.lastIndex(of: "-") {
            revision = rest[rest.index(after: dash)...]
            rest = rest[..<dash]
        }
        return (epoch, Array(rest.utf8), Array(revision.utf8))
    }

    private static func order(_ byte: UInt8?) -> Int {
        guard let byte else { return 0 }
        if isDigit(byte) { return 0 }
        if isLetter(byte) { return Int(byte) }
        if byte == UInt8(ascii: "~") { return -1 }
        return Int(byte) + 256
    }

    private static func isDigit(_ byte: UInt8) -> Bool { byte >= 48 && byte <= 57 }
    private static func isLetter(_ byte: UInt8) -> Bool { (byte >= 65 && byte <= 90) || (byte >= 97 && byte <= 122) }

    static func verrevcmp(_ a: [UInt8], _ b: [UInt8]) -> Int {
        var i = 0
        var j = 0
        func at(_ array: [UInt8], _ index: Int) -> UInt8? { index < array.count ? array[index] : nil }
        while i < a.count || j < b.count {
            var firstDiff = 0
            while (at(a, i).map { !isDigit($0) } ?? false) || (at(b, j).map { !isDigit($0) } ?? false) {
                let ac = order(at(a, i))
                let bc = order(at(b, j))
                if ac != bc { return ac - bc }
                i += 1
                j += 1
            }
            while at(a, i) == UInt8(ascii: "0") { i += 1 }
            while at(b, j) == UInt8(ascii: "0") { j += 1 }
            while let x = at(a, i), let y = at(b, j), isDigit(x), isDigit(y) {
                if firstDiff == 0 { firstDiff = Int(x) - Int(y) }
                i += 1
                j += 1
            }
            if let x = at(a, i), isDigit(x) { return 1 }
            if let y = at(b, j), isDigit(y) { return -1 }
            if firstDiff != 0 { return firstDiff }
        }
        return 0
    }
}
