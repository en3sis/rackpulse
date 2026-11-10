import Foundation

public struct ReleaseSupport: Sendable, Hashable {
    public let distro: String
    public let version: String
    public let standardEnd: Date
    public let ltsEnd: Date?

    public var securityEnd: Date { ltsEnd ?? standardEnd }

    public static func lookup(id: String?, versionID: String?) -> ReleaseSupport? {
        guard let id = id?.lowercased(), let versionID else { return nil }
        switch id {
        case "ubuntu":
            let parts = versionID.split(separator: ".")
            guard parts.count >= 2 else { return nil }
            let version = "\(parts[0]).\(parts[1])"
            return ubuntu[version].map { ReleaseSupport(distro: "Ubuntu", version: version, standardEnd: day($0), ltsEnd: nil) }
        case "debian":
            guard let major = versionID.split(separator: ".").first.map(String.init) else { return nil }
            return debian[major].map { ReleaseSupport(distro: "Debian", version: major, standardEnd: day($0.0), ltsEnd: day($0.1)) }
        default:
            return nil
        }
    }

    static let ubuntu: [String: String] = [
        "16.04": "2021-04-30",
        "18.04": "2023-05-31",
        "20.04": "2025-05-31",
        "20.10": "2021-07-22",
        "21.04": "2022-01-20",
        "21.10": "2022-07-14",
        "22.04": "2027-05-31",
        "22.10": "2023-07-20",
        "23.04": "2024-01-20",
        "23.10": "2024-07-12",
        "24.04": "2029-05-31",
        "24.10": "2025-07-10",
        "25.04": "2026-01-17",
        "25.10": "2026-07-01",
        "26.04": "2031-05-29",
        "26.10": "2027-07-01",
    ]

    static let debian: [String: (String, String)] = [
        "9": ("2020-07-06", "2022-06-30"),
        "10": ("2022-09-10", "2024-06-30"),
        "11": ("2024-08-14", "2026-08-31"),
        "12": ("2026-07-12", "2028-06-30"),
        "13": ("2028-08-09", "2030-06-30"),
    ]

    static func day(_ text: String) -> Date {
        let parts = text.split(separator: "-").compactMap { Int($0) }
        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = .gmt
        let start = calendar.date(from: DateComponents(year: parts[0], month: parts[1], day: parts[2]))!
        return start.addingTimeInterval(86_400 - 1)
    }

    static func month(_ date: Date) -> String {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = .gmt
        formatter.dateFormat = "MMMM yyyy"
        return formatter.string(from: date)
    }

    public func check(now: Date) -> SecurityCheck {
        let name = "\(distro) \(version)"
        if let ltsEnd {
            if now > ltsEnd {
                return SecurityCheck(
                    id: SecurityCheck.endOfLife, status: .fail, title: "\(name) no longer gets security updates",
                    detail: "Debian LTS support ended in \(Self.month(ltsEnd)). Upgrade to a newer Debian release."
                )
            }
            if now > standardEnd {
                return SecurityCheck(
                    id: SecurityCheck.endOfLife, status: .pass, title: "\(name) gets security updates from Debian LTS",
                    detail: "Regular security support ended in \(Self.month(standardEnd)). Debian LTS covers it until \(Self.month(ltsEnd))."
                )
            }
            return SecurityCheck(
                id: SecurityCheck.endOfLife, status: .pass, title: "\(name) gets security updates",
                detail: "Security support until \(Self.month(standardEnd)), then Debian LTS until \(Self.month(ltsEnd))."
            )
        }
        if now > standardEnd {
            return SecurityCheck(
                id: SecurityCheck.endOfLife, status: .fail, title: "\(name) no longer gets security updates",
                detail: "Standard support ended in \(Self.month(standardEnd)). Upgrade to a newer release, or use Ubuntu Pro for extended updates."
            )
        }
        return SecurityCheck(
            id: SecurityCheck.endOfLife, status: .pass, title: "\(name) gets security updates",
            detail: "Standard support until \(Self.month(standardEnd))."
        )
    }
}
