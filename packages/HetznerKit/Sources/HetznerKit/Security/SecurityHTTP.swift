import Foundation

public enum SecuritySourceError: Error, Sendable, Equatable {
    case network(host: String)
    case status(Int, host: String)
    case rateLimited(until: Date?)
    case unauthorized
    case quotaExhausted(until: Date?)
    case organizationNotFound
    case invalidOrganization
    case invalidResponse(host: String)
    case hostNotAllowed

    public var message: String {
        switch self {
        case .network(let host): "Could not reach \(host)."
        case .status(let code, let host): "\(host) answered with HTTP \(code)."
        case .rateLimited(let until):
            until.map { "Too many requests. Try again after \($0.formatted(date: .omitted, time: .shortened))." } ?? "Too many requests. Try again later."
        case .unauthorized: "The API key was rejected."
        case .quotaExhausted(let until):
            until.map { "The API quota is used up until \($0.formatted(date: .abbreviated, time: .shortened))." } ?? "The API quota is used up."
        case .organizationNotFound: "No organization with this name for this API key."
        case .invalidOrganization: "The organization name can only contain letters, digits, dots, dashes and underscores."
        case .invalidResponse(let host): "\(host) sent an answer Rackpulse does not understand."
        case .hostNotAllowed: "Rackpulse only sends requests to fixed hosts."
        }
    }
}

struct SecurityHTTP: Sendable {
    static let allowedHosts: Set<String> = Set(SourceName.allCases.map(\.host))
    static let longestWait: TimeInterval = 60

    static func encoder() -> JSONEncoder {
        let encoder = JSONEncoder()
        encoder.outputFormatting = .withoutEscapingSlashes
        return encoder
    }

    let transport: HTTPTransport
    let sleep: @Sendable (TimeInterval) async throws -> Void
    let clock: @Sendable () -> Date

    init(
        transport: HTTPTransport,
        sleep: @escaping @Sendable (TimeInterval) async throws -> Void = { try await Task.sleep(for: .seconds($0)) },
        clock: @escaping @Sendable () -> Date = { Date() }
    ) {
        self.transport = transport
        self.sleep = sleep
        self.clock = clock
    }

    func request(_ url: URL, method: String = "GET", body: Data? = nil, headers: [String: String] = [:]) throws -> URLRequest {
        guard url.scheme == "https", let host = url.host(), Self.allowedHosts.contains(host), url.user() == nil else {
            throw SecuritySourceError.hostNotAllowed
        }
        var request = URLRequest(url: url)
        request.httpMethod = method
        request.httpBody = body
        request.setValue("Rackpulse", forHTTPHeaderField: "User-Agent")
        if body != nil { request.setValue("application/json", forHTTPHeaderField: "Content-Type") }
        for (key, value) in headers { request.setValue(value, forHTTPHeaderField: key) }
        return request
    }

    func send(_ request: URLRequest, attempts: Int = 4) async throws -> (Data, HTTPURLResponse) {
        guard let url = request.url, url.scheme == "https", let host = url.host(), Self.allowedHosts.contains(host) else {
            throw SecuritySourceError.hostNotAllowed
        }
        var attempt = 0
        while true {
            attempt += 1
            let reply: (Data, HTTPURLResponse)
            do {
                reply = try await transport.send(request)
            } catch is CancellationError {
                throw CancellationError()
            } catch {
                if Task.isCancelled { throw CancellationError() }
                guard attempt < attempts else { throw SecuritySourceError.network(host: host) }
                try await sleep(backoff(attempt))
                continue
            }
            let status = reply.1.statusCode
            guard status == 429 || (500...599).contains(status) else { return reply }
            let wait = retryAfter(reply.1)
            if status == 429, attempt >= attempts || (wait ?? 0) > Self.longestWait {
                throw SecuritySourceError.rateLimited(until: wait.map { clock().addingTimeInterval($0) })
            }
            guard attempt < attempts, (wait ?? 0) <= Self.longestWait else {
                throw SecuritySourceError.status(status, host: host)
            }
            try await sleep(wait ?? backoff(attempt))
        }
    }

    private func backoff(_ attempt: Int) -> TimeInterval {
        pow(2, Double(attempt - 1))
    }

    func retryAfter(_ response: HTTPURLResponse) -> TimeInterval? {
        guard let value = response.value(forHTTPHeaderField: "Retry-After")?.trimmingCharacters(in: .whitespaces) else { return nil }
        if let seconds = TimeInterval(value) { return max(0, seconds) }
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = TimeZone(identifier: "GMT")
        formatter.dateFormat = "EEE, dd MMM yyyy HH:mm:ss zzz"
        return formatter.date(from: value).map { max(0, $0.timeIntervalSince(clock())) }
    }
}
