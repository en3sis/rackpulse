import Foundation

public enum VersionOrder {
    public static func compare(_ lhs: String, _ rhs: String, ecosystem: String) -> Int {
        if ecosystem.hasPrefix("Alpine:") { return AlpineVersion.compare(lhs, rhs) }
        if PackageQuery.isOperatingSystem(ecosystem) { return DebianVersion.compare(lhs, rhs) }
        let ordered: Int? = switch ecosystem {
        case "PyPI": PythonVersion.compare(lhs, rhs)
        case "npm", "crates.io": SemanticVersion.compare(lhs, rhs, shortForms: false)
        case "Go": SemanticVersion.compare(lhs, rhs, shortForms: true)
        case "RubyGems": RubyVersion.compare(lhs, rhs)
        case "Packagist": ComposerVersion.compare(lhs, rhs)
        default: nil
        }
        return ordered ?? generic(lhs, rhs)
    }

    public static func isLess(_ lhs: String, _ rhs: String, ecosystem: String) -> Bool {
        compare(lhs, rhs, ecosystem: ecosystem) < 0
    }

    enum Token: Equatable {
        case number(String)
        case text(String)
    }

    static func generic(_ lhs: String, _ rhs: String) -> Int {
        let a = tokens(lhs)
        let b = tokens(rhs)
        var index = 0
        while index < a.count || index < b.count {
            switch (index < a.count ? a[index] : nil, index < b.count ? b[index] : nil) {
            case (.number(let x), .number(let y)):
                let order = Digits.compare(Array(x.utf8)[...], Array(y.utf8)[...])
                if order != 0 { return order }
            case (.text(let x), .text(let y)):
                if x != y { return x < y ? -1 : 1 }
            case (.number, .text):
                return 1
            case (.text, .number):
                return -1
            case (nil, .text?):
                return 1
            case (.text?, nil):
                return -1
            case (nil, .number?):
                return -1
            case (.number?, nil):
                return 1
            case (nil, nil):
                return 0
            }
            index += 1
        }
        return 0
    }

    static func tokens(_ version: String) -> [Token] {
        var text = version.lowercased()
        if text.hasPrefix("v"), text.dropFirst().first?.isNumber == true { text.removeFirst() }
        if let plus = text.firstIndex(of: "+") { text = String(text[..<plus]) }
        var result: [Token] = []
        var current = ""
        var digits = false
        func flush() {
            guard !current.isEmpty else { return }
            result.append(digits ? .number(current) : .text(current))
            current = ""
        }
        for character in text {
            if character.isASCII && character.isNumber {
                if !digits { flush() }
                digits = true
                current.append(character)
            } else if character.isASCII && character.isLetter {
                if digits { flush() }
                digits = false
                current.append(character)
            } else {
                flush()
            }
        }
        flush()
        return result
    }
}

enum Digits {
    static func isDigit(_ byte: UInt8) -> Bool { byte >= 48 && byte <= 57 }
    static func isLetter(_ byte: UInt8) -> Bool { (byte >= 65 && byte <= 90) || (byte >= 97 && byte <= 122) }
    static func isAlphanumeric(_ byte: UInt8) -> Bool { isDigit(byte) || isLetter(byte) }
    static func lower(_ byte: UInt8) -> UInt8 { byte >= 65 && byte <= 90 ? byte + 32 : byte }

    static func compare(_ a: ArraySlice<UInt8>, _ b: ArraySlice<UInt8>) -> Int {
        let x = a.drop { $0 == UInt8(ascii: "0") }
        let y = b.drop { $0 == UInt8(ascii: "0") }
        if x.count != y.count { return x.count < y.count ? -1 : 1 }
        return bytes(x, y)
    }

    static func bytes(_ a: ArraySlice<UInt8>, _ b: ArraySlice<UInt8>) -> Int {
        for (x, y) in zip(a, b) where x != y { return x < y ? -1 : 1 }
        if a.count != b.count { return a.count < b.count ? -1 : 1 }
        return 0
    }

    static func isZero(_ a: ArraySlice<UInt8>) -> Bool {
        a.allSatisfy { $0 == UInt8(ascii: "0") }
    }
}
