import Foundation

public enum CVSS4 {
    static let allowed: [String: Set<String>] = [
        "AV": ["N", "A", "L", "P"], "AC": ["L", "H"], "AT": ["N", "P"], "PR": ["N", "L", "H"], "UI": ["N", "P", "A"],
        "VC": ["H", "L", "N"], "VI": ["H", "L", "N"], "VA": ["H", "L", "N"], "SC": ["H", "L", "N"], "SI": ["H", "L", "N"], "SA": ["H", "L", "N"],
    ]

    public static func baseScore(_ vector: String) -> Double? {
        let parts = vector.trimmingCharacters(in: .whitespaces).split(separator: "/").map(String.init)
        guard parts.first == "CVSS:4.0", parts.count <= 64 else { return nil }
        var metrics: [String: String] = [:]
        for part in parts.dropFirst() {
            let pair = part.split(separator: ":", maxSplits: 1).map(String.init)
            guard pair.count == 2, metrics[pair[0]] == nil else { return nil }
            metrics[pair[0]] = pair[1]
        }
        var selected: [String: String] = ["E": "A", "CR": "H", "IR": "H", "AR": "H"]
        for (metric, values) in allowed {
            guard let value = metrics[metric], values.contains(value) else { return nil }
            selected[metric] = value
        }
        return score(selected)
    }

    static func macroVector(_ m: [String: String]) -> String {
        let eq1: Int
        if m["AV"] == "N" && m["PR"] == "N" && m["UI"] == "N" {
            eq1 = 0
        } else if (m["AV"] == "N" || m["PR"] == "N" || m["UI"] == "N") && m["AV"] != "P" {
            eq1 = 1
        } else {
            eq1 = 2
        }
        let eq2 = m["AC"] == "L" && m["AT"] == "N" ? 0 : 1
        let eq3: Int
        if m["VC"] == "H" && m["VI"] == "H" {
            eq3 = 0
        } else if m["VC"] == "H" || m["VI"] == "H" || m["VA"] == "H" {
            eq3 = 1
        } else {
            eq3 = 2
        }
        let eq4: Int
        if m["MSI"] == "S" || m["MSA"] == "S" {
            eq4 = 0
        } else if m["SC"] == "H" || m["SI"] == "H" || m["SA"] == "H" {
            eq4 = 1
        } else {
            eq4 = 2
        }
        let eq5 = m["E"] == "A" ? 0 : (m["E"] == "P" ? 1 : 2)
        let eq6 = (m["CR"] == "H" && m["VC"] == "H") || (m["IR"] == "H" && m["VI"] == "H") || (m["AR"] == "H" && m["VA"] == "H") ? 0 : 1
        return "\(eq1)\(eq2)\(eq3)\(eq4)\(eq5)\(eq6)"
    }

    static let levels: [String: [String: Double]] = [
        "AV": ["N": 0.0, "A": 0.1, "L": 0.2, "P": 0.3],
        "PR": ["N": 0.0, "L": 0.1, "H": 0.2],
        "UI": ["N": 0.0, "P": 0.1, "A": 0.2],
        "AC": ["L": 0.0, "H": 0.1],
        "AT": ["N": 0.0, "P": 0.1],
        "VC": ["H": 0.0, "L": 0.1, "N": 0.2],
        "VI": ["H": 0.0, "L": 0.1, "N": 0.2],
        "VA": ["H": 0.0, "L": 0.1, "N": 0.2],
        "SC": ["H": 0.1, "L": 0.2, "N": 0.3],
        "SI": ["S": 0.0, "H": 0.1, "L": 0.2, "N": 0.3],
        "SA": ["S": 0.0, "H": 0.1, "L": 0.2, "N": 0.3],
        "CR": ["H": 0.0, "M": 0.1, "L": 0.2],
        "IR": ["H": 0.0, "M": 0.1, "L": 0.2],
        "AR": ["H": 0.0, "M": 0.1, "L": 0.2],
    ]

    static let distanceOrder = ["AV", "PR", "UI", "AC", "AT", "VC", "VI", "VA", "SC", "SI", "SA", "CR", "IR", "AR"]

    static let maxComposed: [Int: [Int: [String]]] = [
        1: [0: ["AV:N/PR:N/UI:N/"], 1: ["AV:A/PR:N/UI:N/", "AV:N/PR:L/UI:N/", "AV:N/PR:N/UI:P/"], 2: ["AV:P/PR:N/UI:N/", "AV:A/PR:L/UI:P/"]],
        2: [0: ["AC:L/AT:N/"], 1: ["AC:H/AT:N/", "AC:L/AT:P/"]],
        4: [0: ["SC:H/SI:S/SA:S/"], 1: ["SC:H/SI:H/SA:H/"], 2: ["SC:L/SI:L/SA:L/"]],
        5: [0: ["E:A/"], 1: ["E:P/"], 2: ["E:U/"]],
    ]

    static let maxComposedEQ3: [Int: [Int: [String]]] = [
        0: [0: ["VC:H/VI:H/VA:H/CR:H/IR:H/AR:H/"], 1: ["VC:H/VI:H/VA:L/CR:M/IR:M/AR:H/", "VC:H/VI:H/VA:H/CR:M/IR:M/AR:M/"]],
        1: [
            0: ["VC:L/VI:H/VA:H/CR:H/IR:H/AR:H/", "VC:H/VI:L/VA:H/CR:H/IR:H/AR:H/"],
            1: [
                "VC:L/VI:H/VA:L/CR:H/IR:M/AR:H/", "VC:L/VI:H/VA:H/CR:H/IR:M/AR:M/", "VC:H/VI:L/VA:H/CR:M/IR:H/AR:M/",
                "VC:H/VI:L/VA:L/CR:M/IR:H/AR:H/", "VC:L/VI:L/VA:H/CR:H/IR:H/AR:M/",
            ],
        ],
        2: [1: ["VC:L/VI:L/VA:L/CR:H/IR:H/AR:H/"]],
    ]

    static let maxSeverity: [Int: [Int: Double]] = [
        1: [0: 1, 1: 4, 2: 5],
        2: [0: 1, 1: 2],
        4: [0: 6, 1: 5, 2: 4],
    ]

    static let maxSeverityEQ3EQ6: [Int: [Int: Double]] = [0: [0: 7, 1: 6], 1: [0: 8, 1: 8], 2: [1: 10]]

    static func metrics(_ text: String) -> [String: String] {
        var result: [String: String] = [:]
        for part in text.split(separator: "/") {
            let pair = part.split(separator: ":", maxSplits: 1)
            if pair.count == 2 { result[String(pair[0])] = String(pair[1]) }
        }
        return result
    }

    static func score(_ m: [String: String]) -> Double? {
        if ["VC", "VI", "VA", "SC", "SI", "SA"].allSatisfy({ m[$0] == "N" }) { return 0 }
        let macro = macroVector(m)
        guard var value = lookup[macro] else { return nil }
        let digits = macro.compactMap { $0.wholeNumberValue }
        let (eq1, eq2, eq3, eq4, eq5, eq6) = (digits[0], digits[1], digits[2], digits[3], digits[4], digits[5])
        func key(_ values: Int...) -> String { values.map(String.init).joined() }

        let lowerEQ1 = lookup[key(eq1 + 1, eq2, eq3, eq4, eq5, eq6)]
        let lowerEQ2 = lookup[key(eq1, eq2 + 1, eq3, eq4, eq5, eq6)]
        let lowerEQ3EQ6: Double?
        if eq3 == 0 && eq6 == 0 {
            let left = lookup[key(eq1, eq2, eq3, eq4, eq5, eq6 + 1)]
            let right = lookup[key(eq1, eq2, eq3 + 1, eq4, eq5, eq6)]
            if let left, let right, left > right { lowerEQ3EQ6 = left } else { lowerEQ3EQ6 = right }
        } else if eq3 == 1 && eq6 == 0 {
            lowerEQ3EQ6 = lookup[key(eq1, eq2, eq3, eq4, eq5, eq6 + 1)]
        } else if (eq3 == 1 && eq6 == 1) || (eq3 == 0 && eq6 == 1) {
            lowerEQ3EQ6 = lookup[key(eq1, eq2, eq3 + 1, eq4, eq5, eq6)]
        } else {
            lowerEQ3EQ6 = lookup[key(eq1, eq2, eq3 + 1, eq4, eq5, eq6 + 1)]
        }
        let lowerEQ4 = lookup[key(eq1, eq2, eq3, eq4 + 1, eq5, eq6)]
        let lowerEQ5 = lookup[key(eq1, eq2, eq3, eq4, eq5 + 1, eq6)]

        guard let eq1Maxes = maxComposed[1]?[eq1], let eq2Maxes = maxComposed[2]?[eq2], let eq3Maxes = maxComposedEQ3[eq3]?[eq6],
              let eq4Maxes = maxComposed[4]?[eq4], let eq5Maxes = maxComposed[5]?[eq5]
        else { return nil }
        var candidates: [String] = []
        for a in eq1Maxes { for b in eq2Maxes { for c in eq3Maxes { for d in eq4Maxes { for e in eq5Maxes { candidates.append(a + b + c + d + e) } } } } }

        var distance: [String: Double] = [:]
        for candidate in candidates {
            let maximum = metrics(candidate)
            distance = [:]
            for metric in distanceOrder {
                guard let table = levels[metric], let own = m[metric].flatMap({ table[$0] }), let top = maximum[metric].flatMap({ table[$0] }) else { return nil }
                distance[metric] = own - top
            }
            if !distance.values.contains(where: { $0 < 0 }) { break }
        }
        func d(_ metric: String) -> Double { distance[metric] ?? 0 }

        let currentEQ1 = d("AV") + d("PR") + d("UI")
        let currentEQ2 = d("AC") + d("AT")
        let currentEQ3EQ6 = d("VC") + d("VI") + d("VA") + d("CR") + d("IR") + d("AR")
        let currentEQ4 = d("SC") + d("SI") + d("SA")
        let step = 0.1

        guard let severityEQ1 = maxSeverity[1]?[eq1], let severityEQ2 = maxSeverity[2]?[eq2],
              let severityEQ3EQ6 = maxSeverityEQ3EQ6[eq3]?[eq6], let severityEQ4 = maxSeverity[4]?[eq4]
        else { return nil }

        var existing = 0.0
        var normalizedEQ1 = 0.0
        var normalizedEQ2 = 0.0
        var normalizedEQ3EQ6 = 0.0
        var normalizedEQ4 = 0.0
        var normalizedEQ5 = 0.0
        if let lower = lowerEQ1 {
            existing += 1
            normalizedEQ1 = (value - lower) * (currentEQ1 / (severityEQ1 * step))
        }
        if let lower = lowerEQ2 {
            existing += 1
            normalizedEQ2 = (value - lower) * (currentEQ2 / (severityEQ2 * step))
        }
        if let lower = lowerEQ3EQ6 {
            existing += 1
            normalizedEQ3EQ6 = (value - lower) * (currentEQ3EQ6 / (severityEQ3EQ6 * step))
        }
        if let lower = lowerEQ4 {
            existing += 1
            normalizedEQ4 = (value - lower) * (currentEQ4 / (severityEQ4 * step))
        }
        if let lower = lowerEQ5 {
            existing += 1
            normalizedEQ5 = (value - lower) * 0
        }
        let mean = existing == 0 ? 0 : (normalizedEQ1 + normalizedEQ2 + normalizedEQ3EQ6 + normalizedEQ4 + normalizedEQ5) / existing
        value -= mean
        value = min(max(value, 0), 10)
        return (value * 10).rounded(.toNearestOrAwayFromZero) / 10
    }

    static let lookup: [String: Double] = [
        "000000": 10.0, "000001": 9.9, "000010": 9.8, "000011": 9.5, "000020": 9.5, "000021": 9.2, "000100": 10.0, "000101": 9.6,
        "000110": 9.3, "000111": 8.7, "000120": 9.1, "000121": 8.1, "000200": 9.3, "000201": 9.0, "000210": 8.9, "000211": 8.0,
        "000220": 8.1, "000221": 6.8, "001000": 9.8, "001001": 9.5, "001010": 9.5, "001011": 9.2, "001020": 9.0, "001021": 8.4,
        "001100": 9.3, "001101": 9.2, "001110": 8.9, "001111": 8.1, "001120": 8.1, "001121": 6.5, "001200": 8.8, "001201": 8.0,
        "001210": 7.8, "001211": 7.0, "001220": 6.9, "001221": 4.8, "002001": 9.2, "002011": 8.2, "002021": 7.2, "002101": 7.9,
        "002111": 6.9, "002121": 5.0, "002201": 6.9, "002211": 5.5, "002221": 2.7, "010000": 9.9, "010001": 9.7, "010010": 9.5,
        "010011": 9.2, "010020": 9.2, "010021": 8.5, "010100": 9.5, "010101": 9.1, "010110": 9.0, "010111": 8.3, "010120": 8.4,
        "010121": 7.1, "010200": 9.2, "010201": 8.1, "010210": 8.2, "010211": 7.1, "010220": 7.2, "010221": 5.3, "011000": 9.5,
        "011001": 9.3, "011010": 9.2, "011011": 8.5, "011020": 8.5, "011021": 7.3, "011100": 9.2, "011101": 8.2, "011110": 8.0,
        "011111": 7.2, "011120": 7.0, "011121": 5.9, "011200": 8.4, "011201": 7.0, "011210": 7.1, "011211": 5.2, "011220": 5.0,
        "011221": 3.0, "012001": 8.6, "012011": 7.5, "012021": 5.2, "012101": 7.1, "012111": 5.2, "012121": 2.9, "012201": 6.3,
        "012211": 2.9, "012221": 1.7, "100000": 9.8, "100001": 9.5, "100010": 9.4, "100011": 8.7, "100020": 9.1, "100021": 8.1,
        "100100": 9.4, "100101": 8.9, "100110": 8.6, "100111": 7.4, "100120": 7.7, "100121": 6.4, "100200": 8.7, "100201": 7.5,
        "100210": 7.4, "100211": 6.3, "100220": 6.3, "100221": 4.9, "101000": 9.4, "101001": 8.9, "101010": 8.8, "101011": 7.7,
        "101020": 7.6, "101021": 6.7, "101100": 8.6, "101101": 7.6, "101110": 7.4, "101111": 5.8, "101120": 5.9, "101121": 5.0,
        "101200": 7.2, "101201": 5.7, "101210": 5.7, "101211": 5.2, "101220": 5.2, "101221": 2.5, "102001": 8.3, "102011": 7.0,
        "102021": 5.4, "102101": 6.5, "102111": 5.8, "102121": 2.6, "102201": 5.3, "102211": 2.1, "102221": 1.3, "110000": 9.5,
        "110001": 9.0, "110010": 8.8, "110011": 7.6, "110020": 7.6, "110021": 7.0, "110100": 9.0, "110101": 7.7, "110110": 7.5,
        "110111": 6.2, "110120": 6.1, "110121": 5.3, "110200": 7.7, "110201": 6.6, "110210": 6.8, "110211": 5.9, "110220": 5.2,
        "110221": 3.0, "111000": 8.9, "111001": 7.8, "111010": 7.6, "111011": 6.7, "111020": 6.2, "111021": 5.8, "111100": 7.4,
        "111101": 5.9, "111110": 5.7, "111111": 5.7, "111120": 4.7, "111121": 2.3, "111200": 6.1, "111201": 5.2, "111210": 5.7,
        "111211": 2.9, "111220": 2.4, "111221": 1.6, "112001": 7.1, "112011": 5.9, "112021": 3.0, "112101": 5.8, "112111": 2.6,
        "112121": 1.5, "112201": 2.3, "112211": 1.3, "112221": 0.6, "200000": 9.3, "200001": 8.7, "200010": 8.6, "200011": 7.2,
        "200020": 7.5, "200021": 5.8, "200100": 8.6, "200101": 7.4, "200110": 7.4, "200111": 6.1, "200120": 5.6, "200121": 3.4,
        "200200": 7.0, "200201": 5.4, "200210": 5.2, "200211": 4.0, "200220": 4.0, "200221": 2.2, "201000": 8.5, "201001": 7.5,
        "201010": 7.4, "201011": 5.5, "201020": 6.2, "201021": 5.1, "201100": 7.2, "201101": 5.7, "201110": 5.5, "201111": 4.1,
        "201120": 4.6, "201121": 1.9, "201200": 5.3, "201201": 3.6, "201210": 3.4, "201211": 1.9, "201220": 1.9, "201221": 0.8,
        "202001": 6.4, "202011": 5.1, "202021": 2.0, "202101": 4.7, "202111": 2.1, "202121": 1.1, "202201": 2.4, "202211": 0.9,
        "202221": 0.4, "210000": 8.8, "210001": 7.5, "210010": 7.3, "210011": 5.3, "210020": 6.0, "210021": 5.0, "210100": 7.3,
        "210101": 5.5, "210110": 5.9, "210111": 4.0, "210120": 4.1, "210121": 2.0, "210200": 5.4, "210201": 4.3, "210210": 4.5,
        "210211": 2.2, "210220": 2.0, "210221": 1.1, "211000": 7.5, "211001": 5.5, "211010": 5.8, "211011": 4.5, "211020": 4.0,
        "211021": 2.1, "211100": 6.1, "211101": 5.1, "211110": 4.8, "211111": 1.8, "211120": 2.0, "211121": 0.9, "211200": 4.6,
        "211201": 1.8, "211210": 1.7, "211211": 0.7, "211220": 0.8, "211221": 0.2, "212001": 5.3, "212011": 2.4, "212021": 1.4,
        "212101": 2.4, "212111": 1.2, "212121": 0.5, "212201": 1.0, "212211": 0.3, "212221": 0.1,
    ]
}
