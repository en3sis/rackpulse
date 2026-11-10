import Foundation

public struct PackageQuery: Sendable, Hashable, Codable, Comparable {
    public static let languageEcosystems: Set<String> = ["npm", "PyPI", "Go", "crates.io", "Packagist", "RubyGems"]

    public let ecosystem: String
    public let name: String
    public let version: String

    public init(ecosystem: String, name: String, version: String) {
        self.ecosystem = ecosystem
        self.name = Self.normalizedName(name, ecosystem: ecosystem)
        self.version = Self.normalizedVersion(version, ecosystem: ecosystem)
    }

    public static func < (lhs: PackageQuery, rhs: PackageQuery) -> Bool {
        (lhs.ecosystem, lhs.name, lhs.version) < (rhs.ecosystem, rhs.name, rhs.version)
    }

    public var key: String { "\(ecosystem)|\(name)|\(version)" }

    public var isOperatingSystem: Bool { Self.isOperatingSystem(ecosystem) }

    public static func isOperatingSystem(_ ecosystem: String) -> Bool {
        ecosystem.hasPrefix("Ubuntu:") || ecosystem.hasPrefix("Debian:") || ecosystem.hasPrefix("Alpine:")
    }

    public static func isSupported(_ ecosystem: String) -> Bool {
        isOperatingSystem(ecosystem) || languageEcosystems.contains(ecosystem)
    }

    public static func normalizedName(_ name: String, ecosystem: String) -> String {
        guard ecosystem == "PyPI" else { return name }
        var result = ""
        var pendingSeparator = false
        for character in name.lowercased() {
            if character == "-" || character == "_" || character == "." {
                pendingSeparator = true
            } else {
                if pendingSeparator, !result.isEmpty { result.append("-") }
                pendingSeparator = false
                result.append(character)
            }
        }
        return result
    }

    public static func normalizedVersion(_ version: String, ecosystem: String) -> String {
        switch ecosystem {
        case "Go", "Packagist":
            if version.hasPrefix("v"), version.dropFirst().first?.isNumber == true { return String(version.dropFirst()) }
            return version
        default:
            return version
        }
    }

    public var purlType: String? {
        switch ecosystem {
        case "npm": "npm"
        case "PyPI": "pypi"
        case "Go": "golang"
        case "crates.io": "cargo"
        case "Packagist": "composer"
        case "RubyGems": "gem"
        default: nil
        }
    }

    public var purl: String? {
        guard let type = purlType, !name.isEmpty, !version.isEmpty else { return nil }
        let segments = name.split(separator: "/", omittingEmptySubsequences: true).map(String.init)
        guard !segments.isEmpty else { return nil }
        let path = segments.map(Self.encode).joined(separator: "/")
        let shownVersion = ecosystem == "Go" ? "v" + version : version
        return "pkg:\(type)/\(path)@\(Self.encode(shownVersion))"
    }

    private static let purlAllowed = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~")

    private static func encode(_ text: String) -> String {
        text.addingPercentEncoding(withAllowedCharacters: purlAllowed) ?? text
    }
}
