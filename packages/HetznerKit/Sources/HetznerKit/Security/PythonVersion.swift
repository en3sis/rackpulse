import Foundation

public enum PythonVersion {
    typealias Number = ArraySlice<UInt8>

    struct Parsed {
        var epoch: Number = []
        var release: [Number] = []
        var pre: (letter: String, number: Number)?
        var post: Number?
        var dev: Number?
        var local: [Number]?
    }

    public static func compare(_ lhs: String, _ rhs: String) -> Int? {
        guard let a = parse(lhs), let b = parse(rhs) else { return nil }
        return compare(a, b)
    }

    public static func normalized(_ version: String) -> String? {
        guard let parsed = parse(version) else { return nil }
        var text = ""
        if !Digits.isZero(parsed.epoch) { text += number(parsed.epoch) + "!" }
        text += parsed.release.map(number).joined(separator: ".")
        if let pre = parsed.pre { text += pre.letter + number(pre.number) }
        if let post = parsed.post { text += ".post" + number(post) }
        if let dev = parsed.dev { text += ".dev" + number(dev) }
        if let local = parsed.local { text += "+" + local.map { String(decoding: $0, as: UTF8.self) }.joined(separator: ".") }
        return text
    }

    private static func number(_ digits: Number) -> String {
        let trimmed = digits.drop { $0 == UInt8(ascii: "0") }
        return trimmed.isEmpty ? "0" : String(decoding: trimmed, as: UTF8.self)
    }

    static func compare(_ a: Parsed, _ b: Parsed) -> Int {
        let epoch = Digits.compare(a.epoch, b.epoch)
        if epoch != 0 { return epoch }
        let left = trimmed(a.release)
        let right = trimmed(b.release)
        for (x, y) in zip(left, right) {
            let order = Digits.compare(x, y)
            if order != 0 { return order }
        }
        if left.count != right.count { return left.count < right.count ? -1 : 1 }
        let suffixA = suffix(a)
        let suffixB = suffix(b)
        for (x, y) in zip(suffixA, suffixB) {
            let order = x.rank != y.rank ? (x.rank < y.rank ? -1 : 1) : Digits.compare(x.number, y.number)
            if order != 0 { return order }
        }
        switch (a.local, b.local) {
        case (nil, nil): return 0
        case (nil, _?): return -1
        case (_?, nil): return 1
        case (let x?, let y?):
            for (p, q) in zip(x, y) {
                let order = localOrder(p, q)
                if order != 0 { return order }
            }
            return x.count == y.count ? 0 : (x.count < y.count ? -1 : 1)
        }
    }

    private static func trimmed(_ release: [Number]) -> ArraySlice<Number> {
        var end = release.endIndex
        while end > release.startIndex, Digits.isZero(release[end - 1]) { end -= 1 }
        return release[..<end]
    }

    private static func suffix(_ version: Parsed) -> [(rank: Int, number: Number)] {
        let preRank: (Int, Number)
        if version.pre == nil, version.post == nil, version.dev != nil {
            preRank = (-1, [])
        } else if let pre = version.pre {
            preRank = (["a": 0, "b": 1, "rc": 2][pre.letter] ?? 2, pre.number)
        } else {
            preRank = (3, [])
        }
        return [
            preRank,
            (version.post == nil ? 0 : 1, version.post ?? []),
            (version.dev == nil ? 1 : 0, version.dev ?? []),
        ]
    }

    private static func localOrder(_ a: Number, _ b: Number) -> Int {
        let numericA = a.allSatisfy(Digits.isDigit)
        let numericB = b.allSatisfy(Digits.isDigit)
        switch (numericA, numericB) {
        case (true, true): return Digits.compare(a, b)
        case (true, false): return 1
        case (false, true): return -1
        case (false, false): return Digits.bytes(a, b)
        }
    }

    static func parse(_ version: String) -> Parsed? {
        let bytes = Array(version.utf8).map(Digits.lower)
        var scanner = Scanner(bytes: bytes[...])
        scanner.skipWhitespace()
        var parsed = Parsed()
        scanner.take("v")
        guard let first = scanner.digits() else { return nil }
        if scanner.take("!") {
            parsed.epoch = first
            guard let release = scanner.digits() else { return nil }
            parsed.release = [release]
        } else {
            parsed.release = [first]
        }
        while scanner.peek(0) == UInt8(ascii: "."), let next = scanner.peek(1), Digits.isDigit(next) {
            scanner.advance(1)
            if let part = scanner.digits() { parsed.release.append(part) }
        }

        let beforePre = scanner
        scanner.separator()
        if let letter = scanner.word(["alpha", "a", "beta", "b", "preview", "pre", "c", "rc"]) {
            scanner.separator()
            let normalized = ["alpha": "a", "beta": "b", "c": "rc", "pre": "rc", "preview": "rc"][letter] ?? letter
            parsed.pre = (normalized, scanner.digits() ?? [])
        } else {
            scanner = beforePre
        }

        let beforePost = scanner
        if scanner.take("-"), let number = scanner.digits() {
            parsed.post = number
        } else {
            scanner = beforePost
            scanner.separator()
            if scanner.word(["post", "rev", "r"]) != nil {
                scanner.separator()
                parsed.post = scanner.digits() ?? []
            } else {
                scanner = beforePost
            }
        }

        let beforeDev = scanner
        scanner.separator()
        if scanner.word(["dev"]) != nil {
            scanner.separator()
            parsed.dev = scanner.digits() ?? []
        } else {
            scanner = beforeDev
        }

        if scanner.take("+") {
            var segments: [Number] = []
            repeat {
                guard let segment = scanner.alphanumerics() else { return nil }
                segments.append(segment)
            } while scanner.separator()
            parsed.local = segments
        }
        scanner.skipWhitespace()
        return scanner.atEnd ? parsed : nil
    }

    struct Scanner {
        var bytes: ArraySlice<UInt8>

        var atEnd: Bool { bytes.isEmpty }

        func peek(_ offset: Int) -> UInt8? {
            let index = bytes.startIndex + offset
            return index < bytes.endIndex ? bytes[index] : nil
        }

        mutating func advance(_ count: Int) {
            bytes.removeFirst(min(count, bytes.count))
        }

        @discardableResult
        mutating func take(_ character: Unicode.Scalar) -> Bool {
            guard bytes.first == UInt8(ascii: character) else { return false }
            bytes.removeFirst()
            return true
        }

        @discardableResult
        mutating func separator() -> Bool {
            guard let first = bytes.first, first == UInt8(ascii: ".") || first == UInt8(ascii: "_") || first == UInt8(ascii: "-") else { return false }
            bytes.removeFirst()
            return true
        }

        mutating func skipWhitespace() {
            while let first = bytes.first, first == 32 || (9...13).contains(first) { bytes.removeFirst() }
            while let last = bytes.last, last == 32 || (9...13).contains(last) { bytes.removeLast() }
        }

        mutating func digits() -> Number? {
            let start = bytes
            while let first = bytes.first, Digits.isDigit(first) { bytes.removeFirst() }
            let taken = start[start.startIndex..<bytes.startIndex]
            return taken.isEmpty ? nil : taken
        }

        mutating func alphanumerics() -> Number? {
            let start = bytes
            while let first = bytes.first, Digits.isAlphanumeric(first) { bytes.removeFirst() }
            let taken = start[start.startIndex..<bytes.startIndex]
            return taken.isEmpty ? nil : taken
        }

        mutating func word(_ options: [String]) -> String? {
            for option in options where bytes.starts(with: option.utf8) {
                bytes.removeFirst(option.utf8.count)
                return option
            }
            return nil
        }
    }
}
