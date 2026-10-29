import Darwin
import Foundation

enum MacNetwork {
    static var onTailscale: Bool {
        var list: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&list) == 0, let first = list else { return false }
        defer { freeifaddrs(list) }
        for entry in sequence(first: first, next: { $0.pointee.ifa_next }) {
            guard let address = entry.pointee.ifa_addr, address.pointee.sa_family == UInt8(AF_INET) else { continue }
            let ip = address.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { UInt32(bigEndian: $0.pointee.sin_addr.s_addr) }
            if ip & 0xFFC0_0000 == 0x6440_0000 { return true }
        }
        return false
    }

    private static func text(_ buffer: [CChar]) -> String {
        String(decoding: buffer.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }, as: UTF8.self)
    }

    static func tailscaleIPv4() -> String? {
        var list: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&list) == 0, let first = list else { return nil }
        defer { freeifaddrs(list) }
        for entry in sequence(first: first, next: { $0.pointee.ifa_next }) {
            guard let address = entry.pointee.ifa_addr, address.pointee.sa_family == UInt8(AF_INET) else { continue }
            let ip = address.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { UInt32(bigEndian: $0.pointee.sin_addr.s_addr) }
            guard ip & 0xFFC0_0000 == 0x6440_0000 else { continue }
            var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
            getnameinfo(address, socklen_t(address.pointee.sa_len), &host, socklen_t(host.count), nil, 0, NI_NUMERICHOST)
            return text(host)
        }
        return nil
    }

    static func tailnetSuffix() async -> String? {
        await Task.detached {
            guard let ip = tailscaleIPv4() else { return nil }
            var address = sockaddr_in()
            address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
            address.sin_family = sa_family_t(AF_INET)
            inet_pton(AF_INET, ip, &address.sin_addr)
            var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
            let status = withUnsafePointer(to: &address) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    getnameinfo($0, socklen_t(MemoryLayout<sockaddr_in>.size), &host, socklen_t(host.count), nil, 0, NI_NAMEREQD)
                }
            }
            guard status == 0 else { return nil }
            let name = text(host).trimmingCharacters(in: CharacterSet(charactersIn: "."))
            let labels = name.split(separator: ".")
            guard labels.count >= 3, name.hasSuffix(".ts.net") else { return nil }
            return labels.dropFirst().joined(separator: ".")
        }.value
    }

    static func tailnetName(_ text: String, suffix: String?) -> String {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty, !trimmed.contains("."), !trimmed.contains(":"), let suffix else { return trimmed }
        let label = trimmed.lowercased()
            .replacingOccurrences(of: " ", with: "-")
            .replacingOccurrences(of: "_", with: "-")
            .filter { $0.isLetter || $0.isNumber || $0 == "-" }
        return label.isEmpty ? trimmed : "\(label).\(suffix)"
    }

    static func publicAddress() async -> String? {
        guard let url = URL(string: "https://rackpulse.app/cdn-cgi/trace"),
              let (data, _) = try? await URLSession.shared.data(from: url),
              let text = String(data: data, encoding: .utf8),
              let line = text.split(separator: "\n").first(where: { $0.hasPrefix("ip=") })
        else { return nil }
        return String(line.dropFirst(3))
    }
}

extension String {
    var nonEmpty: String? { isEmpty ? nil : self }
}
