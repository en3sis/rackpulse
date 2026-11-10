import Foundation
import HetznerKit
import Observation

@MainActor
@Observable
final class DecisionStore {
    private(set) var decisions: [FindingDecision]

    @ObservationIgnored private let database: LocalDatabase
    @ObservationIgnored private var maintained: Date?

    static let maintenanceInterval: TimeInterval = 3_600

    init(database: LocalDatabase) {
        self.database = database
        decisions = (try? database.decisions()) ?? []
    }

    func maintain(results: [String: SecurityResult], now: Date = .now) {
        if let maintained, now.timeIntervalSince(maintained) < Self.maintenanceInterval { return }
        maintained = now
        let seen = FindingDecision.seen(decisions, results: results)
        if (try? database.markDecisionsSeen(seen, at: now)) != nil {
            for index in decisions.indices where seen.contains(decisions[index].id) { decisions[index].lastSeen = now }
        }
        prune(now: now)
    }

    func check(target: String, result: SecurityResult?, now: Date = .now) -> DecisionCheck {
        FindingDecision.check(decisions, target: target, result: result, now: now)
    }

    func ignore(_ decision: FindingDecision) {
        guard (try? database.saveDecision(decision)) != nil else { return }
        decisions.removeAll { $0.target == decision.target && $0.key == decision.key }
        decisions.append(decision)
    }

    func unignore(_ decision: FindingDecision) {
        guard (try? database.deleteDecisions([decision.id])) != nil else { return }
        decisions.removeAll { $0.id == decision.id }
    }

    func prune(now: Date = .now) {
        let stale = Set(decisions.filter { $0.removable(now: now) }.map(\.id))
        guard !stale.isEmpty, (try? database.deleteDecisions(stale)) != nil else { return }
        decisions.removeAll { stale.contains($0.id) }
    }

    func keep(projects: Set<UUID>) {
        decisions.removeAll { decision in
            let parts = decision.target.split(separator: "/", omittingEmptySubsequences: false)
            return !decision.allServers && parts.count > 1 && !projects.contains { $0.uuidString == parts[1] }
        }
    }
}
