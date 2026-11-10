import Foundation

public struct SecurityTarget: Sendable {
    public let serverID: Int64
    public let report: AgentSecurity
    public let server: Server?
    public let firewalls: [Firewall]?
    public let agentPort: Int

    public init(serverID: Int64, report: AgentSecurity, server: Server?, firewalls: [Firewall]?, agentPort: Int = AgentEndpoint.defaultPort) {
        self.serverID = serverID
        self.report = report
        self.server = server
        self.firewalls = firewalls
        self.agentPort = agentPort
    }
}

public struct SecurityScanSettings: Sendable, Hashable, Codable {
    public var onlineChecks: Bool
    public var enrichment: Bool

    public init(onlineChecks: Bool = false, enrichment: Bool = true) {
        self.onlineChecks = onlineChecks
        self.enrichment = enrichment
    }
}

public actor SecurityScanner {
    public typealias SocketFactory = @Sendable (SocketCredentials) -> any VulnerabilitySource

    private let sources: [any VulnerabilitySource]
    private let enrichers: [any EnrichmentSource]
    private let socketFactory: SocketFactory?
    private let clock: @Sendable () -> Date
    private var socket: (credentials: SocketCredentials, source: any VulnerabilitySource)?
    private var running: Task<[Int64: SecurityResult], Never>?

    public init(cache: SecurityCache, transport: HTTPTransport = URLSessionTransport(), clock: @escaping @Sendable () -> Date = { Date() }) {
        sources = [OSVSource(cache: cache, transport: transport, clock: clock)]
        enrichers = [KEVSource(cache: cache, transport: transport, clock: clock), EPSSSource(cache: cache, transport: transport, clock: clock)]
        socketFactory = { SocketSource(credentials: $0, cache: cache, transport: transport, clock: clock) }
        self.clock = clock
    }

    public init(
        sources: [any VulnerabilitySource],
        enrichers: [any EnrichmentSource] = [],
        socketFactory: SocketFactory? = nil,
        clock: @escaping @Sendable () -> Date = { Date() }
    ) {
        self.sources = sources
        self.enrichers = enrichers
        self.socketFactory = socketFactory
        self.clock = clock
    }

    public func verifySocket(_ credentials: SocketCredentials) async throws -> SocketQuota {
        guard let source = socketSource(credentials) as? SocketSource else { throw SecuritySourceError.hostNotAllowed }
        return try await source.verify()
    }

    public func scan(
        _ targets: [SecurityTarget], settings: SecurityScanSettings, socket credentials: SocketCredentials? = nil
    ) async -> [Int64: SecurityResult] {
        let previous = running
        let task = Task {
            _ = await previous?.value
            return await self.perform(targets, settings: settings, credentials: credentials)
        }
        running = task
        let result = await withTaskCancellationHandler { await task.value } onCancel: { task.cancel() }
        if running == task { running = nil }
        return result
    }

    private func socketSource(_ credentials: SocketCredentials) -> (any VulnerabilitySource)? {
        if let socket, socket.credentials == credentials { return socket.source }
        guard let socketFactory else { return nil }
        let source = socketFactory(credentials)
        socket = (credentials, source)
        return source
    }

    private func perform(_ targets: [SecurityTarget], settings: SecurityScanSettings, credentials: SocketCredentials?) async -> [Int64: SecurityResult] {
        let now = clock()
        let inventories = targets.map { SecurityInventory($0.report) }
        let queries = Array(Set(inventories.flatMap(\.queries))).sorted()
        var origins: [PackageQuery: Set<Int64>] = [:]
        for (target, inventory) in zip(targets, inventories) {
            for query in inventory.queries { origins[query, default: []].insert(target.serverID) }
        }

        var active: [any VulnerabilitySource] = sources.filter { $0.name != .socket || credentials != nil }
        if let credentials, !active.contains(where: { $0.name == .socket }), let socket = socketSource(credentials) {
            active.append(socket)
        }

        var statuses: [SourceName: SourceStatus] = [:]
        var advisories: [PackageQuery: [Advisory]] = [:]
        for source in active where settings.onlineChecks {
            let supported = queries.filter(source.supports)
            do {
                let lookup = try await source.lookup(supported, origins: origins)
                for (query, found) in lookup.advisories { advisories[query, default: []] += found }
                let state: SourceStatus.State = lookup.skipped ? .skipped : (lookup.problem == nil ? .ok : .partial)
                statuses[source.name] = SourceStatus(source: source.name, state: state, message: lookup.problem, checkedAt: now, quota: lookup.quota)
            } catch {
                let quota = await (source as? SocketSource)?.lastQuota
                statuses[source.name] = SourceStatus(source: source.name, state: .failed, message: Self.message(error), checkedAt: now, quota: quota)
            }
        }

        if settings.onlineChecks, settings.enrichment, !enrichers.isEmpty {
            let cves = Set(advisories.values.flatMap { $0.flatMap(\.cves) })
            var enrichment: [String: Enrichment] = [:]
            for enricher in enrichers {
                do {
                    let lookup = cves.isEmpty ? EnrichmentLookup() : try await enricher.enrichment(for: cves)
                    for (cve, value) in lookup.values {
                        var merged = enrichment[cve] ?? Enrichment()
                        merged.knownExploited = merged.knownExploited ?? value.knownExploited
                        merged.epss = merged.epss ?? value.epss
                        enrichment[cve] = merged
                    }
                    statuses[enricher.name] = SourceStatus(
                        source: enricher.name, state: lookup.problem == nil ? .ok : .partial, message: lookup.problem, checkedAt: now
                    )
                } catch {
                    statuses[enricher.name] = SourceStatus(source: enricher.name, state: .failed, message: Self.message(error), checkedAt: now)
                }
            }
            for (query, list) in advisories {
                advisories[query] = list.map { advisory in
                    var copy = advisory
                    for cve in advisory.cves { if let value = enrichment[cve] { copy.apply(value) } }
                    return copy
                }
            }
        }

        let sourceList = SourceName.allCases.map { name in
            statuses[name] ?? SourceStatus(source: name, state: .skipped, message: Self.skipReason(name, settings: settings, credentials: credentials))
        }

        var results: [Int64: SecurityResult] = [:]
        for (target, inventory) in zip(targets, inventories) {
            results[target.serverID] = result(
                target, inventory: inventory, advisories: advisories, sources: sourceList, settings: settings, now: now
            )
        }
        return results
    }

    private func result(
        _ target: SecurityTarget, inventory: SecurityInventory, advisories: [PackageQuery: [Advisory]],
        sources: [SourceStatus], settings: SecurityScanSettings, now: Date
    ) -> SecurityResult {
        let report = target.report
        let updates = Dictionary(grouping: report.updates.items, by: \.name)
        var findings: [Finding] = []
        for package in inventory.packages {
            guard let found = advisories[package.query], !found.isEmpty else { continue }
            let binaries = package.location == .system ? package.binaries : []
            let pending = binaries.flatMap { updates[$0] ?? [] }.map(\.available)
                .max { VersionOrder.isLess($0, $1, ecosystem: package.query.ecosystem) }
            findings.append(Finding(package: package, advisories: Self.merged(found), pendingVersion: pending))
        }
        return SecurityResult(
            serverID: target.serverID,
            checkedAt: now,
            reportTime: report.time,
            osName: report.os.name,
            osEcosystem: inventory.osEcosystem,
            onlineChecks: settings.onlineChecks,
            findings: findings,
            pendingUpdates: report.updates.items.count,
            pendingSecurityUpdates: report.updates.securityCount,
            updatesError: report.updates.error,
            listsTime: report.updates.listsTime,
            checks: HostChecks.merge(agent: report.checks, host: HostChecks.evaluate(
                report: report, server: target.server, firewalls: target.firewalls, agentPort: target.agentPort, now: now
            )),
            sources: sources,
            skippedKernelSources: inventory.skippedKernelSources
        )
    }

    static func merged(_ advisories: [Advisory]) -> [Advisory] {
        var byID: [String: Advisory] = [:]
        var order: [String] = []
        for advisory in advisories {
            let key = "\(advisory.source.rawValue)|\(advisory.id)"
            if byID[key] == nil { order.append(key) }
            byID[key] = byID[key] ?? advisory
        }
        return order.compactMap { byID[$0] }
    }

    static func message(_ error: Error) -> String {
        if let error = error as? SecuritySourceError { return error.message }
        if error is CancellationError { return "The check was cancelled." }
        return "The check failed."
    }

    static func skipReason(_ name: SourceName, settings: SecurityScanSettings, credentials: SocketCredentials?) -> String {
        if !settings.onlineChecks { return "Online checks are off." }
        switch name {
        case .kev, .epss: return settings.enrichment ? "Nothing to check." : "Turned off."
        case .socket: return credentials == nil ? "No Socket API key." : "Nothing to check."
        case .osv: return "Nothing to check."
        }
    }
}
