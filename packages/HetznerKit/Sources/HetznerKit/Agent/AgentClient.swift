import CryptoKit
import Foundation
import Network

public struct AgentEndpoint: Sendable, Hashable, Codable {
    public static let defaultPort = 7311

    public var host: String
    public var port: Int

    public init(host: String, port: Int = AgentEndpoint.defaultPort) {
        self.host = host
        self.port = port
    }

    public var display: String {
        host.contains(":") ? "[\(host)]:\(port)" : "\(host):\(port)"
    }
}

public enum AgentError: Error, Sendable, Equatable {
    case invalidAddress
    case refused
    case timedOut
    case unreachable
    case notAgent
    case wrongKey
    case certificateChanged
    case invalidResponse
    case unsupported
    case notReady
}

public struct AgentPairing: Sendable, Hashable {
    public let fingerprint: String
    public let version: String
}

public final class AgentClient: Sendable {
    public static let tokenPrefix = "rb1_"

    public let endpoint: AgentEndpoint
    private let token: String
    private let fingerprint: String

    public init(endpoint: AgentEndpoint, token: String, fingerprint: String) {
        self.endpoint = endpoint
        self.token = token
        self.fingerprint = fingerprint
    }

    public static func newToken() -> String {
        tokenPrefix + SymmetricKey(size: .bits256).withUnsafeBytes { Data($0) }.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    public static func proof(token: String, nonce: String, fingerprint: String) -> String {
        let key = SymmetricKey(data: Data(token.utf8))
        let message = Data("rackpulse-agent-v1|\(nonce)|\(fingerprint)".utf8)
        return HMAC<SHA256>.authenticationCode(for: message, using: key).hex
    }

    public static func pair(endpoint: AgentEndpoint, token: String, timeout: TimeInterval = 6) async throws -> AgentPairing {
        let nonce = SymmetricKey(size: .bits256).withUnsafeBytes { Data($0).hex }
        let exchange = AgentExchange(endpoint: endpoint, target: "/v1/hello?nonce=\(nonce)", token: nil, pinned: nil)
        let (raw, fingerprint) = try await exchange.run(timeout: timeout)
        guard let (status, body) = try? AgentExchange.parse(raw), status == 200,
              let hello = try? AgentJSON.decoder().decode(AgentHello.self, from: body),
              hello.agent == "rackpulse-agent"
        else { throw AgentError.notAgent }
        guard hello.proof.lowercased() == proof(token: token, nonce: nonce, fingerprint: fingerprint) else {
            throw AgentError.wrongKey
        }
        return AgentPairing(fingerprint: fingerprint, version: hello.version)
    }

    public func snapshot() async throws -> AgentSnapshot {
        try await get("/v1/snapshot")
    }

    public func history(since: Date) async throws -> AgentHistory {
        let hour = Int(since.timeIntervalSince1970) / 3_600 * 3_600
        return try await get("/v1/history?since=\(hour)")
    }

    public func containerHistory(name: String, since: Date) async throws -> ContainerHistory {
        let hour = Int(since.timeIntervalSince1970) / 3_600 * 3_600
        let encoded = name.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed.subtracting(CharacterSet(charactersIn: "&=+"))) ?? name
        return try await get("/v1/containers/history?name=\(encoded)&since=\(hour)")
    }

    public func security() async throws -> AgentSecurity {
        try await get("/v1/security", timeout: 30, notFound: .unsupported, unavailable: .notReady)
    }

    static func error(status: Int, notFound: AgentError = .invalidResponse, unavailable: AgentError = .invalidResponse) -> AgentError? {
        switch status {
        case 200: nil
        case 401: .wrongKey
        case 404: notFound
        case 503: unavailable
        default: .invalidResponse
        }
    }

    private func get<T: Decodable>(
        _ target: String, timeout: TimeInterval = 10, notFound: AgentError = .invalidResponse, unavailable: AgentError = .invalidResponse
    ) async throws -> T {
        let exchange = AgentExchange(endpoint: endpoint, target: target, token: token, pinned: fingerprint)
        let (raw, _) = try await exchange.run(timeout: timeout)
        let (status, body) = try AgentExchange.parse(raw)
        if let error = Self.error(status: status, notFound: notFound, unavailable: unavailable) { throw error }
        do {
            return try AgentJSON.decoder().decode(T.self, from: body)
        } catch {
            throw AgentError.invalidResponse
        }
    }
}

final class AgentExchange: @unchecked Sendable {
    static let limit = 16 << 20

    private let connection: NWConnection
    private let queue = DispatchQueue(label: "dev.rackpulse.agent")
    private let request: Data
    private let pin: Pin
    private var buffer = Data()
    private var continuation: CheckedContinuation<(Data, String), Error>?

    init(endpoint: AgentEndpoint, target: String, token: String?, pinned: String?) {
        var head = "GET \(target) HTTP/1.0\r\nHost: \(endpoint.display)\r\nUser-Agent: Rackpulse\r\nAccept: application/json\r\n"
        if let token { head += "Authorization: Bearer \(token)\r\n" }
        request = Data((head + "\r\n").utf8)

        let pin = Pin(expected: pinned)
        self.pin = pin
        let tls = NWProtocolTLS.Options()
        sec_protocol_options_set_min_tls_protocol_version(tls.securityProtocolOptions, .TLSv13)
        sec_protocol_options_set_verify_block(tls.securityProtocolOptions, { metadata, _, complete in
            var leaf: SecCertificate?
            sec_protocol_metadata_access_peer_certificate_chain(metadata) { certificate in
                if leaf == nil { leaf = sec_certificate_copy_ref(certificate).takeRetainedValue() }
            }
            guard let leaf else { return complete(false) }
            complete(pin.check(Data(SHA256.hash(data: SecCertificateCopyData(leaf) as Data)).hex))
        }, queue)
        let port = NWEndpoint.Port(rawValue: UInt16(clamping: endpoint.port)) ?? 7311
        connection = NWConnection(host: NWEndpoint.Host(endpoint.host), port: port, using: NWParameters(tls: tls, tcp: NWProtocolTCP.Options()))
    }

    func run(timeout: TimeInterval) async throws -> (Data, String) {
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                queue.async {
                    self.continuation = continuation
                    self.connection.stateUpdateHandler = { state in self.handle(state) }
                    self.connection.start(queue: self.queue)
                    self.queue.asyncAfter(deadline: .now() + timeout) { self.finish(.failure(AgentError.timedOut)) }
                }
            }
        } onCancel: {
            queue.async { self.finish(.failure(CancellationError())) }
        }
    }

    private func handle(_ state: NWConnection.State) {
        switch state {
        case .ready:
            connection.send(content: request, completion: .contentProcessed { [weak self] error in
                guard let self else { return }
                if let error { self.finish(.failure(self.map(error))) } else { self.receive() }
            })
        case .waiting(let error), .failed(let error):
            finish(.failure(map(error)))
        default:
            break
        }
    }

    private func receive() {
        connection.receive(minimumIncompleteLength: 1, maximumLength: 1 << 16) { [weak self] data, _, complete, error in
            guard let self else { return }
            if let data { self.buffer.append(data) }
            if self.buffer.count > Self.limit {
                self.finish(.failure(AgentError.invalidResponse))
            } else if complete || (error != nil && !self.buffer.isEmpty) {
                self.finish(.success(self.buffer))
            } else if let error {
                self.finish(.failure(self.map(error)))
            } else {
                self.receive()
            }
        }
    }

    private func finish(_ result: Result<Data, Error>) {
        guard let continuation else { return }
        self.continuation = nil
        connection.stateUpdateHandler = nil
        connection.cancel()
        switch result {
        case .success(let data):
            if let fingerprint = pin.seen {
                continuation.resume(returning: (data, fingerprint))
            } else {
                continuation.resume(throwing: AgentError.notAgent)
            }
        case .failure(let error):
            continuation.resume(throwing: error)
        }
    }

    private func map(_ error: NWError) -> AgentError {
        switch error {
        case .posix(let code) where code == .ECONNREFUSED: .refused
        case .posix(let code) where code == .ETIMEDOUT: .timedOut
        case .dns: .invalidAddress
        case .tls: pin.mismatched ? .certificateChanged : .notAgent
        default: pin.mismatched ? .certificateChanged : .unreachable
        }
    }

    final class Pin: @unchecked Sendable {
        let expected: String?
        private(set) var seen: String?
        private(set) var mismatched = false

        init(expected: String?) {
            self.expected = expected
        }

        func check(_ fingerprint: String) -> Bool {
            seen = fingerprint
            mismatched = expected.map { $0 != fingerprint } ?? false
            return !mismatched
        }
    }

    static func parse(_ raw: Data) throws -> (Int, Data) {
        guard let split = raw.range(of: Data("\r\n\r\n".utf8)) else { throw AgentError.invalidResponse }
        let lines = String(decoding: raw[..<split.lowerBound], as: UTF8.self).components(separatedBy: "\r\n")
        let parts = lines.first?.split(separator: " ") ?? []
        guard parts.count >= 2, parts[0].hasPrefix("HTTP/"), let status = Int(parts[1]) else { throw AgentError.invalidResponse }
        let body = Data(raw[split.upperBound...])
        let chunked = lines.dropFirst().contains { $0.lowercased().replacingOccurrences(of: " ", with: "") == "transfer-encoding:chunked" }
        return (status, chunked ? try dechunk(body) : body)
    }

    static func dechunk(_ data: Data) throws -> Data {
        var output = Data()
        var rest = data[...]
        let separator = Data("\r\n".utf8)
        while let line = rest.range(of: separator) {
            let sizeText = String(decoding: rest[..<line.lowerBound], as: UTF8.self).split(separator: ";").first ?? ""
            guard let size = Int(sizeText.trimmingCharacters(in: .whitespaces), radix: 16) else { throw AgentError.invalidResponse }
            if size == 0 { return output }
            let start = line.upperBound
            guard rest.distance(from: start, to: rest.endIndex) >= size + 2 else { throw AgentError.invalidResponse }
            let end = rest.index(start, offsetBy: size)
            output.append(rest[start..<end])
            rest = rest[rest.index(end, offsetBy: 2)...]
        }
        throw AgentError.invalidResponse
    }
}

extension Sequence where Element == UInt8 {
    var hex: String { map { String(format: "%02x", $0) }.joined() }
}

extension HashedAuthenticationCode {
    var hex: String { Data(self).hex }
}
