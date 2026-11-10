import Foundation

public enum AlpineVersion {
    enum Token: Int {
        case initialDigit, digit, letter, suffix, suffixNumber, commitHash, revision, end, invalid
    }

    enum Suffix: Int {
        case invalid, alpha, beta, pre, rc, none, cvs, svn, git, hg, p
    }

    struct State {
        var token = Token.initialDigit
        var suffix = Suffix.invalid
        var number: UInt64 = 0
        var value: ArraySlice<UInt8> = []
    }

    struct Cursor {
        var bytes: ArraySlice<UInt8>

        mutating func digits(into state: inout State) {
            let original = bytes
            let start = bytes.startIndex
            var number: UInt64 = 0
            var overflow = false
            while let byte = bytes.first, Digits.isDigit(byte) {
                let (product, multiplied) = number.multipliedReportingOverflow(by: 10)
                let (sum, added) = product.addingReportingOverflow(UInt64(byte - 48))
                overflow = overflow || multiplied || added
                number = sum
                bytes.removeFirst()
            }
            if overflow || bytes.startIndex == start {
                state.token = .invalid
                state.value = []
                return
            }
            state.number = number
            state.value = original[start..<bytes.startIndex]
        }

        mutating func span(_ allowed: (UInt8) -> Bool) -> ArraySlice<UInt8> {
            let original = bytes
            while let byte = bytes.first, allowed(byte) { bytes.removeFirst() }
            return original[original.startIndex..<bytes.startIndex]
        }
    }

    public static func compare(_ lhs: String, _ rhs: String) -> Int {
        var a = Cursor(bytes: Array(lhs.utf8)[...])
        var b = Cursor(bytes: Array(rhs.utf8)[...])
        var ta = State()
        var tb = State()
        a.digits(into: &ta)
        b.digits(into: &tb)
        while ta.token == tb.token && ta.token.rawValue < Token.end.rawValue {
            let order = compare(ta, tb)
            if order != 0 { return order }
            next(&ta, &a)
            next(&tb, &b)
        }
        if ta.token == tb.token { return 0 }
        if ta.token == .suffix && ta.suffix.rawValue < Suffix.none.rawValue { return -1 }
        if tb.token == .suffix && tb.suffix.rawValue < Suffix.none.rawValue { return 1 }
        if ta.token.rawValue > tb.token.rawValue { return -1 }
        if tb.token.rawValue > ta.token.rawValue { return 1 }
        return 0
    }

    public static func isValid(_ version: String) -> Bool {
        var cursor = Cursor(bytes: Array(version.utf8)[...])
        var state = State()
        cursor.digits(into: &state)
        while state.token.rawValue < Token.end.rawValue { next(&state, &cursor) }
        return state.token == .end
    }

    static func compare(_ a: State, _ b: State) -> Int {
        let x: UInt64
        let y: UInt64
        switch a.token {
        case .digit where a.value.first == UInt8(ascii: "0") || b.value.first == UInt8(ascii: "0"):
            return Digits.bytes(a.value, b.value)
        case .digit, .initialDigit, .suffixNumber, .revision:
            x = a.number
            y = b.number
        case .letter:
            x = UInt64(a.value.first ?? 0)
            y = UInt64(b.value.first ?? 0)
        case .suffix:
            x = UInt64(a.suffix.rawValue)
            y = UInt64(b.suffix.rawValue)
        default:
            return Digits.bytes(a.value, b.value)
        }
        if x < y { return -1 }
        if x > y { return 1 }
        return 0
    }

    static func next(_ state: inout State, _ cursor: inout Cursor) {
        guard let first = cursor.bytes.first else {
            state.token = .end
            return
        }
        switch first {
        case UInt8(ascii: "a")...UInt8(ascii: "z"):
            guard state.token.rawValue <= Token.digit.rawValue else { return invalid(&state) }
            state.value = cursor.bytes.prefix(1)
            state.token = .letter
            cursor.bytes.removeFirst()
        case UInt8(ascii: "."), UInt8(ascii: "0")...UInt8(ascii: "9"):
            if first == UInt8(ascii: ".") {
                guard state.token.rawValue <= Token.digit.rawValue else { return invalid(&state) }
                cursor.bytes.removeFirst()
            }
            switch state.token {
            case .initialDigit, .digit: state.token = .digit
            case .suffix: state.token = .suffixNumber
            default: return invalid(&state)
            }
            cursor.digits(into: &state)
        case UInt8(ascii: "_"):
            guard state.token.rawValue <= Token.suffixNumber.rawValue else { return invalid(&state) }
            cursor.bytes.removeFirst()
            state.value = cursor.span { $0 >= UInt8(ascii: "a") && $0 <= UInt8(ascii: "z") }
            state.suffix = suffix(state.value)
            guard state.suffix != .invalid else { return invalid(&state) }
            state.token = .suffix
        case UInt8(ascii: "~"):
            guard state.token.rawValue < Token.commitHash.rawValue else { return invalid(&state) }
            cursor.bytes.removeFirst()
            state.value = cursor.span { Digits.isDigit($0) || ($0 >= UInt8(ascii: "a") && $0 <= UInt8(ascii: "f")) }
            guard !state.value.isEmpty else { return invalid(&state) }
            state.token = .commitHash
        case UInt8(ascii: "-"):
            guard state.token.rawValue < Token.revision.rawValue, cursor.bytes.starts(with: [UInt8(ascii: "-"), UInt8(ascii: "r")]) else {
                return invalid(&state)
            }
            cursor.bytes.removeFirst(2)
            state.token = .revision
            cursor.digits(into: &state)
        default:
            invalid(&state)
        }
    }

    private static func invalid(_ state: inout State) {
        state.token = .invalid
    }

    static let suffixNames: [Suffix: String] = [
        .alpha: "alpha", .beta: "beta", .pre: "pre", .rc: "rc", .cvs: "cvs", .svn: "svn", .git: "git", .hg: "hg", .p: "p",
    ]

    static func suffix(_ value: ArraySlice<UInt8>) -> Suffix {
        guard let first = value.first else { return .invalid }
        let candidate: Suffix
        switch first {
        case UInt8(ascii: "a"): candidate = .alpha
        case UInt8(ascii: "b"): candidate = .beta
        case UInt8(ascii: "c"): candidate = .cvs
        case UInt8(ascii: "g"): candidate = .git
        case UInt8(ascii: "h"): candidate = .hg
        case UInt8(ascii: "p"): candidate = value.count > 1 ? .pre : .p
        case UInt8(ascii: "r"): candidate = .rc
        case UInt8(ascii: "s"): candidate = .svn
        default: return .invalid
        }
        return value.elementsEqual((suffixNames[candidate] ?? "").utf8) ? candidate : .invalid
    }
}
