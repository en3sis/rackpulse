import Foundation
import Testing
@testable import HetznerKit

final class RouterTransport: HTTPTransport, @unchecked Sendable {
    typealias Route = @Sendable (URLRequest) -> StubTransport.Reply

    private let lock = NSLock()
    private let route: Route
    private var log: [URLRequest] = []

    init(_ route: @escaping Route) {
        self.route = route
    }

    var requests: [URLRequest] { lock.withLock { log } }

    func send(_ request: URLRequest) async throws -> (Data, HTTPURLResponse) {
        lock.withLock { log.append(request) }
        let reply = route(request)
        let response = HTTPURLResponse(url: request.url!, statusCode: reply.status, httpVersion: nil, headerFields: reply.headers)!
        return (reply.body, response)
    }
}

final class Clock: @unchecked Sendable {
    private let lock = NSLock()
    private var current: Date

    init(_ start: Date) {
        current = start
    }

    var now: Date { lock.withLock { current } }

    func advance(_ seconds: TimeInterval) {
        lock.withLock { current = current.addingTimeInterval(seconds) }
    }
}

final class Sleeps: @unchecked Sendable {
    private let lock = NSLock()
    private var log: [TimeInterval] = []

    var values: [TimeInterval] { lock.withLock { log } }

    func record(_ value: TimeInterval) {
        lock.withLock { log.append(value) }
    }
}

func temporaryCache() -> SecurityCache {
    SecurityCache(database: try! LocalDatabase())
}

func osvRecord(_ id: String) throws -> OSVRecord {
    try JSONDecoder().decode(OSVRecord.self, from: fixture("osv-\(id)"))
}

func agentSecurity(_ name: String) throws -> AgentSecurity {
    try AgentJSON.decoder().decode(AgentSecurity.self, from: fixture(name))
}

func json(_ object: Any) -> Data {
    try! JSONSerialization.data(withJSONObject: object)
}
