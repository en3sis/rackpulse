import Foundation
import HetznerKit

enum Format {
    static func rate(_ bytesPerSecond: Double?) -> String {
        guard let value = bytesPerSecond else { return "-" }
        if value >= 1_000_000 { return String(format: "%.1f MB/s", value / 1_000_000) }
        if value >= 1_000 { return String(format: "%.0f KB/s", value / 1_000) }
        return String(format: "%.0f B/s", value)
    }

    static func iops(_ value: Double?) -> String {
        guard let value else { return "-" }
        if value >= 1_000 { return String(format: "%.1fk /s", value / 1_000) }
        return String(format: "%.0f /s", value)
    }

    static func percent(_ value: Double?) -> String {
        guard let value else { return "-" }
        return String(format: "%.0f%%", value)
    }

    static func traffic(_ used: Int64, of included: Int64) -> String {
        "\(size(used)) / \(size(included))"
    }

    static func size(_ bytes: Int64) -> String {
        let tib = Double(bytes) / 1_099_511_627_776
        if tib >= 1 { return tib >= 10 || tib == tib.rounded() ? String(format: "%.0f TB", tib) : String(format: "%.1f TB", tib) }
        let gib = Double(bytes) / 1_073_741_824
        if gib >= 10 { return String(format: "%.0f GB", gib) }
        if gib >= 1 { return String(format: "%.1f GB", gib) }
        let mib = Double(bytes) / 1_048_576
        if mib >= 1 { return String(format: "%.0f MB", mib) }
        return String(format: "%.0f KB", max(1, Double(bytes) / 1_024))
    }

    static func cpu(_ value: Double?) -> String {
        guard let value else { return "-" }
        if value <= 0 { return "0%" }
        if value < 0.1 { return "<0.1%" }
        if value < 10 { return String(format: "%.1f%%", value) }
        return String(format: "%.0f%%", value)
    }

    static func memory(_ bytes: Int64) -> String {
        let gib = Double(bytes) / 1_073_741_824
        if gib >= 10 { return String(format: "%.0f GB", gib) }
        if gib >= 1 { return String(format: "%.1f GB", gib) }
        return String(format: "%.0f MB", Double(bytes) / 1_048_576)
    }

    static func ago(_ date: Date, now: Date) -> String {
        let seconds = max(0, Int(now.timeIntervalSince(date)))
        if seconds < 10 { return "just now" }
        if seconds < 60 { return "\(seconds)s ago" }
        if seconds < 3_600 { return "\(seconds / 60) min ago" }
        if seconds < 86_400 { return "\(seconds / 3_600) h ago" }
        return "\(plural(seconds / 86_400, "day")) ago"
    }

    static func place(_ location: Location) -> String {
        let city = location.city.split(separator: ",").first.map(String.init) ?? location.name
        return "\(flag(location.country)) \(city.isEmpty ? location.name : city)"
    }

    static func flag(_ country: String) -> String {
        let base: UInt32 = 0x1F1E6 - 65
        let scalars = country.uppercased().unicodeScalars.compactMap { UnicodeScalar(base + $0.value) }
        guard scalars.count == 2 else { return "" }
        return String(String.UnicodeScalarView(scalars))
    }

    static func compactDuration(since date: Date, now: Date = .now) -> String {
        let seconds = max(0, now.timeIntervalSince(date))
        if seconds < 3_600 { return "\(max(1, Int(seconds / 60))) min" }
        if seconds < 86_400 { return "\(Int(seconds / 3_600)) h" }
        let parts = Calendar.current.dateComponents([.year, .month, .day], from: date, to: now)
        if let years = parts.year, years > 0 { return plural(years, "year") }
        if let months = parts.month, months > 0 { return plural(months, "month") }
        return plural(parts.day ?? 1, "day")
    }

    static func exactDuration(since date: Date, now: Date = .now) -> String {
        let parts = Calendar.current.dateComponents([.year, .month, .day, .hour, .minute], from: date, to: now)
        var text: [String] = []
        if let years = parts.year, years > 0 { text.append(plural(years, "year")) }
        if let months = parts.month, months > 0 { text.append(plural(months, "month")) }
        if let days = parts.day, days > 0 { text.append(plural(days, "day")) }
        if let hours = parts.hour, hours > 0 { text.append("\(hours)h") }
        if text.isEmpty { text.append("\(max(1, parts.minute ?? 0)) min") }
        return text.joined(separator: ", ")
    }

    private static func plural(_ value: Int, _ unit: String) -> String {
        "\(value) \(unit)\(value == 1 ? "" : "s")"
    }
}
