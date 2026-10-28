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

    static func publicAddress() async -> String? {
        guard let url = URL(string: "https://rackpulse.app/cdn-cgi/trace"),
              let (data, _) = try? await URLSession.shared.data(from: url),
              let text = String(data: data, encoding: .utf8),
              let line = text.split(separator: "\n").first(where: { $0.hasPrefix("ip=") })
        else { return nil }
        return String(line.dropFirst(3))
    }
}
