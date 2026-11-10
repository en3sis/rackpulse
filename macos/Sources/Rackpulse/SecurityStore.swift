import CryptoKit
import Foundation
import HetznerKit
import Observation

enum SocketCheck: Equatable {
    case quota(SocketQuota)
    case failed(String)
}

struct SecurityCandidate {
    let key: String
    let target: SecurityTarget
    let digest: String
    let context: Int?
}

@MainActor
@Observable
final class SecurityStore {
    static let keychainService = "dev.rackpulse.socket-key"
    private static let keychainAccount = "token"
    private static let staleAfter: TimeInterval = 6 * 3_600
    private static let retryAfter: TimeInterval = 900
    private static let debounce: Duration = .seconds(1.5)

    private struct Entry: Codable {
        var result: SecurityResult
        var digest: String
        var settings: String
        var firewalls: Bool?
    }

    private var entries: [String: Entry]
    private(set) var scanning = false
    private(set) var hasSocketToken: Bool

    @ObservationIgnored private var contexts: [String: Int] = [:]
    @ObservationIgnored private var forced: Set<String> = []
    @ObservationIgnored private var removedDuringScan: Set<String> = []
    @ObservationIgnored private var pending: [String: SecurityCandidate] = [:]
    @ObservationIgnored private var drain: Task<Void, Never>?
    @ObservationIgnored private var saving: Task<Void, Never>?
    @ObservationIgnored private var socketToken: String?
    @ObservationIgnored private var scanner: SecurityScanner
    @ObservationIgnored private let cache: SecurityCache
    @ObservationIgnored private let database: LocalDatabase
    @ObservationIgnored private let settings: SettingsStore

    init(settings: SettingsStore, database: LocalDatabase, folder: URL) {
        self.settings = settings
        self.database = database
        cache = SecurityCache(database: database)
        scanner = SecurityScanner(cache: cache)
        Self.importFiles(from: folder, into: database)
        let decoder = JSONDecoder()
        entries = ((try? database.securityResults()) ?? [:]).compactMapValues { try? decoder.decode(Entry.self, from: $0) }
        socketToken = Keychain.read(account: Self.keychainAccount, service: Self.keychainService)
        hasSocketToken = socketToken != nil
    }

    private static func importFiles(from folder: URL, into database: LocalDatabase) {
        let manager = FileManager.default
        let results = folder.appendingPathComponent("security-results.json")
        if let data = try? Data(contentsOf: results) {
            let encoder = JSONEncoder()
            let decoded = (try? JSONDecoder().decode([String: Entry].self, from: data)) ?? [:]
            if (try? database.saveSecurityResults(decoded.compactMapValues { try? encoder.encode($0) })) != nil {
                try? manager.removeItem(at: results)
            }
        }
        try? manager.removeItem(at: folder.appendingPathComponent("security", isDirectory: true))
    }

    func result(_ project: UUID, _ server: Int64) -> SecurityResult? {
        entries[AgentStore.key(project, server)]?.result
    }

    func results(_ project: UUID, digest: (String) -> String?) -> [Int64: SecurityResult] {
        let prefix = "\(project.uuidString):"
        let current = settingsKey
        var found: [Int64: SecurityResult] = [:]
        for (key, entry) in entries where key.hasPrefix(prefix) && entry.settings == current && entry.digest == digest(key) {
            if let id = Int64(key.dropFirst(prefix.count)) { found[id] = entry.result }
        }
        return found
    }

    var latest: SecurityResult? {
        entries.values.map(\.result).max { $0.checkedAt < $1.checkedAt }
    }

    func schedule(_ candidates: [SecurityCandidate]) {
        let now = Date.now
        let current = settingsKey
        for candidate in candidates {
            let previous = contexts[candidate.key]
            if let context = candidate.context { contexts[candidate.key] = context }
            let contextChanged = previous != nil && candidate.context != nil && previous != candidate.context
            if contextChanged { forced.insert(candidate.key) }
            if isDue(candidate, settings: current, now: now) { pending[candidate.key] = candidate }
        }
        startDrain()
    }

    private func isDue(_ candidate: SecurityCandidate, settings current: String, now: Date) -> Bool {
        if forced.contains(candidate.key) { return true }
        guard let entry = entries[candidate.key] else { return true }
        let age = now.timeIntervalSince(entry.result.checkedAt)
        return entry.digest != candidate.digest || entry.settings != current || age > Self.staleAfter
            || (entry.firewalls != true && candidate.target.firewalls != nil)
            || (entry.result.incomplete && age > Self.retryAfter)
    }

    func force(_ key: String) {
        forced.insert(key)
    }

    func remove(_ key: String) {
        pending[key] = nil
        forced.remove(key)
        contexts[key] = nil
        if scanning { removedDuringScan.insert(key) }
        guard entries.removeValue(forKey: key) != nil else { return }
        save([key])
    }

    func keep(projects: Set<UUID>) {
        let stale = entries.keys.filter { key in
            !projects.contains { key.hasPrefix("\($0.uuidString):") }
        }
        for key in stale { remove(key) }
    }

    func clearCache() {
        cache.clear()
        scanner = SecurityScanner(cache: cache)
        entries = [:]
        contexts = [:]
        try? database.clearSecurityResults()
    }

    @discardableResult
    func saveSocketToken(_ token: String) -> Bool {
        let value = token.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !value.isEmpty,
              (try? Keychain.save(value, account: Self.keychainAccount, service: Self.keychainService)) != nil
        else { return false }
        socketToken = value
        hasSocketToken = true
        forced.formUnion(entries.keys)
        return true
    }

    func removeSocketToken() {
        Keychain.delete(account: Self.keychainAccount, service: Self.keychainService)
        socketToken = nil
        hasSocketToken = false
    }

    func verifySocket(token typed: String, organization: String) async -> SocketCheck {
        let typed = typed.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let token = typed.isEmpty ? socketToken : typed else { return .failed("Paste a Socket API token first.") }
        let credentials = SocketCredentials(token: token, organization: organization)
        guard credentials.organizationIsValid else {
            return .failed(credentials.organization.isEmpty ? "Enter your organization slug first." : SecuritySourceError.invalidOrganization.message)
        }
        do {
            return .quota(try await scanner.verifySocket(credentials))
        } catch let error as SecuritySourceError {
            return .failed(error.message)
        } catch {
            return .failed("The check failed.")
        }
    }

    private var socketCredentials: SocketCredentials? {
        guard let socketToken else { return nil }
        let credentials = SocketCredentials(token: socketToken, organization: settings.value.socketOrganization)
        return credentials.organizationIsValid ? credentials : nil
    }

    private var settingsKey: String {
        let scan = settings.value.security
        return "\(scan.onlineChecks)|\(scan.enrichment)|\(socketCredentials?.organization ?? "")"
    }

    private func startDrain() {
        guard drain == nil, !pending.isEmpty else { return }
        scanning = true
        drain = Task {
            try? await Task.sleep(for: Self.debounce)
            await run()
            drain = nil
            scanning = false
            startDrain()
        }
    }

    private func run() async {
        let key = settingsKey
        let now = Date.now
        let batch = pending.values.filter { isDue($0, settings: key, now: now) }
        pending = [:]
        guard !batch.isEmpty else { return }
        removedDuringScan = []
        let found = await scanner.scan(batch.map(\.target), settings: settings.value.security, socket: socketCredentials)
        var changed: Set<String> = []
        for candidate in batch where !removedDuringScan.contains(candidate.key) {
            guard let result = found[candidate.target.serverID] else { continue }
            entries[candidate.key] = Entry(result: result, digest: candidate.digest, settings: key, firewalls: candidate.target.firewalls != nil)
            forced.remove(candidate.key)
            changed.insert(candidate.key)
        }
        removedDuringScan = []
        save(changed)
    }

    private func save(_ keys: Set<String>) {
        guard !keys.isEmpty else { return }
        let snapshot = entries.filter { keys.contains($0.key) }
        let removed = keys.subtracting(snapshot.keys)
        let database = database
        let previous = saving
        saving = Task.detached(priority: .utility) {
            await previous?.value
            let encoder = JSONEncoder()
            let encoded = snapshot.compactMapValues { try? encoder.encode($0) }
            try? database.saveSecurityResults(encoded, removed: removed)
        }
    }

    private struct DigestInput: Encodable {
        let os: AgentSecurity.OS
        let packages: [AgentSecurity.Package]
        let packagesError: String?
        let updates: [AgentSecurity.Update]
        let updatesError: String?
        let listsTime: Date?
        let kernel: AgentSecurity.Kernel
        let checks: [SecurityCheck]
        let listening: [AgentSecurity.Listener]
        let projects: [AgentSecurity.Project]
        let images: [DigestImage]
    }

    private struct DigestImage: Encodable {
        let id: String
        let names: [String]
        let os: AgentSecurity.OS
        let packages: [AgentSecurity.Package]
        let packagesError: String?
        let lockfiles: [AgentSecurity.Lockfile]
        let error: String?
    }

    nonisolated static func digest(_ report: AgentSecurity) -> String {
        let input = DigestInput(
            os: report.os, packages: report.packages.items, packagesError: report.packages.error,
            updates: report.updates.items, updatesError: report.updates.error, listsTime: report.updates.listsTime,
            kernel: report.kernel, checks: report.checks, listening: report.listening, projects: report.projects,
            images: report.images.map {
                DigestImage(id: $0.id, names: $0.names, os: $0.os, packages: $0.packages.items, packagesError: $0.packages.error,
                            lockfiles: $0.lockfiles, error: $0.error)
            }
        )
        let encoder = JSONEncoder()
        encoder.outputFormatting = .sortedKeys
        let data = (try? encoder.encode(input)) ?? Data()
        return SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }
}
