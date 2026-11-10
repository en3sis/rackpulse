import Foundation

public enum RubyVersion {
    enum Segment: Equatable {
        case number(ArraySlice<UInt8>)
        case text(ArraySlice<UInt8>)

        var isZero: Bool {
            if case .number(let digits) = self { return Digits.isZero(digits) }
            return false
        }
    }

    public static func compare(_ lhs: String, _ rhs: String) -> Int? {
        guard let a = canonical(lhs), let b = canonical(rhs) else { return nil }
        return compare(a, b)
    }

    static func compare(_ lhs: [Segment], _ rhs: [Segment]) -> Int {
        let limit = min(lhs.count, rhs.count)
        var index = 0
        while index < limit {
            let order = segmentOrder(lhs[index], rhs[index])
            index += 1
            if order != 0 { return order }
        }
        if index < lhs.count {
            for segment in lhs[index...] {
                if case .text = segment { return -1 }
                if !segment.isZero { return 1 }
            }
        } else {
            for segment in rhs[index...] {
                if case .text = segment { return 1 }
                if !segment.isZero { return -1 }
            }
        }
        return 0
    }

    private static func segmentOrder(_ a: Segment, _ b: Segment) -> Int {
        switch (a, b) {
        case (.number(let x), .number(let y)): Digits.compare(x, y)
        case (.text(let x), .text(let y)): Digits.bytes(x, y)
        case (.text, .number): -1
        case (.number, .text): 1
        }
    }

    static func isCorrect(_ bytes: ArraySlice<UInt8>) -> Bool {
        guard !bytes.isEmpty else { return true }
        var rest = bytes
        guard let first = rest.first, Digits.isDigit(first) else { return false }
        while let byte = rest.first, Digits.isDigit(byte) { rest.removeFirst() }
        while rest.first == UInt8(ascii: ".") {
            rest.removeFirst()
            let start = rest.count
            while let byte = rest.first, Digits.isAlphanumeric(byte) { rest.removeFirst() }
            if rest.count == start { return false }
        }
        if rest.first == UInt8(ascii: "-") {
            rest.removeFirst()
            for part in rest.split(separator: UInt8(ascii: "."), omittingEmptySubsequences: false) {
                guard !part.isEmpty, part.allSatisfy({ Digits.isAlphanumeric($0) || $0 == UInt8(ascii: "-") }) else { return false }
            }
            return true
        }
        return rest.isEmpty
    }

    static func canonical(_ version: String) -> [Segment]? {
        var bytes = Array(version.utf8)[...]
        while let first = bytes.first, first == 32 || (9...13).contains(first) { bytes.removeFirst() }
        while let last = bytes.last, last == 32 || (9...13).contains(last) { bytes.removeLast() }
        guard isCorrect(bytes) else { return nil }
        if bytes.isEmpty { bytes = [UInt8(ascii: "0")] }
        var text: [UInt8] = []
        for byte in bytes {
            if byte == UInt8(ascii: "-") { text += Array(".pre.".utf8) } else { text.append(byte) }
        }
        let prerelease = text.contains(where: Digits.isLetter)
        text = stripTrailingZeros(text)
        if prerelease { text = stripZerosBeforeLetters(text) }
        return segments(text[...])
    }

    private static func stripTrailingZeros(_ text: [UInt8]) -> [UInt8] {
        var start = text.count
        while start > 0, text[start - 1] == UInt8(ascii: ".") || text[start - 1] == UInt8(ascii: "0") { start -= 1 }
        while start < text.count {
            if start > 0, Digits.isLetter(text[start - 1]) || text[start - 1] == UInt8(ascii: ".") { return Array(text[..<start]) }
            start += 1
        }
        return text
    }

    private static func stripZerosBeforeLetters(_ text: [UInt8]) -> [UInt8] {
        var index = 0
        while index < text.count {
            if index == 0 || text[index - 1] == UInt8(ascii: ".") {
                var end = index
                while end < text.count, text[end] == UInt8(ascii: "0") || text[end] == UInt8(ascii: ".") { end += 1 }
                if end > index, end < text.count, Digits.isLetter(text[end]) {
                    return Array(text[..<index] + text[end...])
                }
            }
            index += 1
        }
        return text
    }

    private static func segments(_ text: ArraySlice<UInt8>) -> [Segment] {
        var result: [Segment] = []
        var rest = text
        while let first = rest.first {
            let start = rest
            if Digits.isDigit(first) {
                while let byte = rest.first, Digits.isDigit(byte) { rest.removeFirst() }
                result.append(.number(start[start.startIndex..<rest.startIndex]))
            } else if Digits.isLetter(first) {
                while let byte = rest.first, Digits.isLetter(byte) { rest.removeFirst() }
                result.append(.text(start[start.startIndex..<rest.startIndex]))
            } else {
                rest.removeFirst()
            }
        }
        return result
    }
}
