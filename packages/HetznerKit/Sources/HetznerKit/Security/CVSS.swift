import Foundation

public enum CVSS3 {
    public static func baseScore(_ vector: String) -> Double? {
        let parts = vector.trimmingCharacters(in: .whitespaces).split(separator: "/").map(String.init)
        guard let prefix = parts.first, prefix == "CVSS:3.0" || prefix == "CVSS:3.1" else { return nil }
        var metrics: [String: String] = [:]
        for part in parts.dropFirst() {
            let pair = part.split(separator: ":", maxSplits: 1).map(String.init)
            guard pair.count == 2, metrics[pair[0]] == nil else { return nil }
            metrics[pair[0]] = pair[1]
        }
        guard
            let scope = metrics["S"], scope == "U" || scope == "C",
            let attackVector = value(metrics["AV"], ["N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2]),
            let complexity = value(metrics["AC"], ["L": 0.77, "H": 0.44]),
            let privileges = value(metrics["PR"], scope == "C" ? ["N": 0.85, "L": 0.68, "H": 0.5] : ["N": 0.85, "L": 0.62, "H": 0.27]),
            let interaction = value(metrics["UI"], ["N": 0.85, "R": 0.62]),
            let confidentiality = value(metrics["C"], impactWeights),
            let integrity = value(metrics["I"], impactWeights),
            let availability = value(metrics["A"], impactWeights)
        else { return nil }

        let changed = scope == "C"
        let iss = 1 - (1 - confidentiality) * (1 - integrity) * (1 - availability)
        let impact = changed ? 7.52 * (iss - 0.029) - 3.25 * pow(iss - 0.02, 15) : 6.42 * iss
        let exploitability = 8.22 * attackVector * complexity * privileges * interaction
        guard impact > 0 else { return 0 }
        let raw = changed ? min(1.08 * (impact + exploitability), 10) : min(impact + exploitability, 10)
        return prefix == "CVSS:3.1" ? roundUp31(raw) : roundUp30(raw)
    }

    private static let impactWeights: [String: Double] = ["H": 0.56, "L": 0.22, "N": 0]

    private static func value(_ key: String?, _ table: [String: Double]) -> Double? {
        key.flatMap { table[$0] }
    }

    static func roundUp31(_ value: Double) -> Double {
        let scaled = Int((value * 100_000).rounded())
        if scaled % 10_000 == 0 { return Double(scaled) / 100_000 }
        return (Double(scaled / 10_000) + 1) / 10
    }

    static func roundUp30(_ value: Double) -> Double {
        (value * 10).rounded(.up) / 10
    }
}
