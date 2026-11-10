import Foundation

public enum HostChecks {
    public struct RiskyPort: Sendable, Hashable {
        public let port: Int
        public let service: String?
        public let informational: Bool
    }

    public static let ignoredPorts: Set<Int> = [22, 80, 443]

    public static let riskyPorts: [Int: RiskyPort] = Dictionary(uniqueKeysWithValues: [
        RiskyPort(port: 3306, service: "MySQL", informational: false),
        RiskyPort(port: 5432, service: "PostgreSQL", informational: false),
        RiskyPort(port: 6379, service: "Redis", informational: false),
        RiskyPort(port: 27017, service: "MongoDB", informational: false),
        RiskyPort(port: 9200, service: "Elasticsearch", informational: false),
        RiskyPort(port: 9300, service: "Elasticsearch", informational: false),
        RiskyPort(port: 11211, service: "Memcached", informational: false),
        RiskyPort(port: 2375, service: "Docker API", informational: false),
        RiskyPort(port: 2376, service: "Docker API", informational: false),
        RiskyPort(port: 5984, service: "CouchDB", informational: false),
        RiskyPort(port: 8086, service: "InfluxDB", informational: false),
        RiskyPort(port: 9000, service: nil, informational: false),
        RiskyPort(port: 9090, service: "Prometheus", informational: false),
        RiskyPort(port: 15672, service: "RabbitMQ management", informational: false),
        RiskyPort(port: 5601, service: "Kibana", informational: false),
        RiskyPort(port: 8500, service: "Consul", informational: false),
        RiskyPort(port: 2379, service: "etcd", informational: false),
        RiskyPort(port: 8080, service: nil, informational: true),
        RiskyPort(port: 8443, service: nil, informational: true),
    ].map { ($0.port, $0) })

    public static func evaluate(
        report: AgentSecurity, server: Server?, firewalls: [Firewall]?, agentPort: Int = AgentEndpoint.defaultPort, now: Date
    ) -> [SecurityCheck] {
        var checks: [SecurityCheck] = []
        if let check = firewall(report: report, server: server, firewalls: firewalls) { checks.append(check) }
        checks += exposedPorts(report: report, server: server, firewalls: firewalls, agentPort: agentPort)
        if let support = ReleaseSupport.lookup(id: report.os.id, versionID: report.os.versionID) {
            checks.append(support.check(now: now))
        }
        return checks
    }

    public static func isHostCheck(_ id: String) -> Bool {
        id == SecurityCheck.firewallNone || id == SecurityCheck.endOfLife
            || id == SecurityCheck.exposedPorts || id.hasPrefix(SecurityCheck.exposedPorts + ":")
    }

    public static func merge(agent: [SecurityCheck], host: [SecurityCheck]) -> [SecurityCheck] {
        var seen: Set<String> = []
        return (agent.filter { !isHostCheck($0.id) } + host).filter { seen.insert($0.id).inserted }
    }

    static func attachedFirewalls(_ server: Server?) -> [Int64]? {
        guard let refs = server?.publicNet.firewalls else { return nil }
        return refs.compactMap(\.id)
    }

    static func ufwEnabled(_ report: AgentSecurity) -> Bool {
        report.check(SecurityCheck.ufw)?.status == .pass
    }

    public static func firewall(report: AgentSecurity, server: Server?, firewalls: [Firewall]?) -> SecurityCheck? {
        let ufw = report.check(SecurityCheck.ufw)
        guard let attached = attachedFirewalls(server) else {
            if ufw?.status == .pass {
                return SecurityCheck(id: SecurityCheck.firewallNone, status: .pass, title: "A firewall is active", detail: "ufw is on.")
            }
            return nil
        }
        if !attached.isEmpty {
            let names = attached.compactMap { id in firewalls?.first { $0.id == id }?.name }
            let detail = names.isEmpty
                ? "A Hetzner Cloud Firewall is attached."
                : "Hetzner Cloud Firewall: \(names.joined(separator: ", "))."
            return SecurityCheck(id: SecurityCheck.firewallNone, status: .pass, title: "A firewall is active", detail: detail)
        }
        if ufw?.status == .pass {
            return SecurityCheck(id: SecurityCheck.firewallNone, status: .pass, title: "A firewall is active", detail: "ufw is on.")
        }
        let ufwText = ufw == nil ? "ufw is not installed" : ufw?.status == .fail ? "ufw is off" : "ufw could not be checked"
        return SecurityCheck(
            id: SecurityCheck.firewallNone, status: .fail, title: "No firewall is active",
            detail: "No Hetzner Cloud Firewall is attached and \(ufwText)."
        )
    }

    public static func exposedPorts(report: AgentSecurity, server: Server?, firewalls: [Firewall]?, agentPort: Int) -> [SecurityCheck] {
        var ports: [Int: String] = [:]
        for listener in report.listening where listener.protocol == "tcp" {
            guard listener.port != agentPort, !ignoredPorts.contains(listener.port), riskyPorts[listener.port] != nil,
                  isPublic(listener.address) else { continue }
            if ports[listener.port] == nil { ports[listener.port] = listener.address }
        }
        let attached = attachedFirewalls(server)
        let rules: [Firewall.Rule]? = attached.flatMap { ids in
            guard !ids.isEmpty else { return [] }
            guard let firewalls else { return nil }
            let matched = firewalls.filter { ids.contains($0.id) }
            return matched.count == ids.count ? matched.flatMap(\.rules) : nil
        }
        let ufw = ufwEnabled(report)
        var checks: [SecurityCheck] = []
        for port in ports.keys.sorted() {
            guard let risky = riskyPorts[port], let address = ports[port] else { continue }
            let label = risky.service.map { "\($0) port \(port)" } ?? "Port \(port)"
            let id = "\(SecurityCheck.exposedPorts):\(port)"
            let listening = "Listening on \(display(address, port: port))."
            if let attached, !attached.isEmpty {
                guard let rules else {
                    checks.append(SecurityCheck(
                        id: id, status: .unknown, title: "\(label) might be open to the internet",
                        detail: "\(listening) The Cloud Firewall rules could not be loaded.", informational: risky.informational
                    ))
                    continue
                }
                guard allows(rules, port: port) else { continue }
                checks.append(SecurityCheck(
                    id: id, status: .fail, title: "\(label) is open to the internet",
                    detail: "\(listening) A Cloud Firewall rule allows it from any address.", informational: risky.informational
                ))
            } else if attached == nil || ufw {
                checks.append(SecurityCheck(
                    id: id, status: .unknown, title: "\(label) might be open to the internet",
                    detail: ufw ? "\(listening) ufw is on, but Rackpulse cannot read its rules." : "\(listening) The Cloud Firewall could not be checked.",
                    informational: risky.informational
                ))
            } else {
                checks.append(SecurityCheck(
                    id: id, status: .fail, title: "\(label) is open to the internet",
                    detail: "\(listening) No Cloud Firewall blocks it.", informational: risky.informational
                ))
            }
        }
        if checks.isEmpty, attached != nil || ufw {
            checks.append(SecurityCheck(
                id: SecurityCheck.exposedPorts, status: .pass, title: "No database or admin ports are open to the internet",
                detail: "Checked the ports the server listens on against the firewall."
            ))
        }
        return checks
    }

    static func allows(_ rules: [Firewall.Rule], port: Int) -> Bool {
        rules.contains { rule in
            rule.direction == "in" && rule.protocolName == "tcp"
                && rule.sourceIps.contains { $0 == "0.0.0.0/0" || $0 == "::/0" }
                && portMatches(rule.port, port)
        }
    }

    static func portMatches(_ spec: String?, _ port: Int) -> Bool {
        guard let spec = spec?.trimmingCharacters(in: .whitespaces), !spec.isEmpty, spec != "any" else { return true }
        let bounds = spec.split(separator: "-").compactMap { Int($0.trimmingCharacters(in: .whitespaces)) }
        if bounds.count == 1 { return bounds[0] == port }
        if bounds.count == 2 { return bounds[0] <= port && port <= bounds[1] }
        return false
    }

    static func display(_ address: String, port: Int) -> String {
        address.contains(":") ? "[\(address)]:\(port)" : "\(address):\(port)"
    }

    static func isPublic(_ address: String) -> Bool {
        let lower = address.lowercased()
        if lower == "0.0.0.0" || lower == "::" { return true }
        if lower.hasPrefix("::ffff:") { return isPublic(String(lower.dropFirst(7))) }
        if lower.contains(":") {
            if lower == "::1" || lower.hasPrefix("fe8") || lower.hasPrefix("fe9") || lower.hasPrefix("fea") || lower.hasPrefix("feb") { return false }
            if lower.hasPrefix("fc") || lower.hasPrefix("fd") { return false }
            return true
        }
        let octets = lower.split(separator: ".").compactMap { Int($0) }
        guard octets.count == 4 else { return false }
        switch (octets[0], octets[1]) {
        case (10, _), (127, _): return false
        case (172, 16...31): return false
        case (192, 168): return false
        case (169, 254): return false
        case (100, 64...127): return false
        default: return true
        }
    }
}
