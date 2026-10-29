import Foundation

public struct AgentSnapshot: Sendable, Hashable, Codable {
    public let version: String
    public let time: Date
    public let host: Host
    public let memory: Memory
    public let disks: [Disk]
    public let system: System
    public let docker: Docker?
    public let activity: Activity?

    public init(version: String, time: Date, host: Host, memory: Memory, disks: [Disk], system: System, docker: Docker?,
                activity: Activity? = nil) {
        self.version = version
        self.time = time
        self.host = host
        self.memory = memory
        self.disks = disks
        self.system = system
        self.docker = docker
        self.activity = activity
    }

    public struct Activity: Sendable, Hashable, Codable {
        public let cpu: Double
    }

    public var reportsReadOnly: Bool {
        version.compare("0.1.1", options: .numeric) != .orderedAscending
    }

    public func normalized() -> AgentSnapshot {
        guard !reportsReadOnly else { return self }
        let disks = disks.map {
            Disk(mount: $0.mount, device: $0.device, fs: $0.fs, total: $0.total, used: $0.used, available: $0.available,
                 inodesTotal: $0.inodesTotal, inodesUsed: $0.inodesUsed, readOnly: false)
        }
        return AgentSnapshot(version: version, time: time, host: host, memory: memory, disks: disks, system: system, docker: docker, activity: activity)
    }

    public struct Host: Sendable, Hashable, Codable {
        public let hostname: String
        public let os: String
        public let kernel: String
        public let arch: String
        public let serverID: Int64?
        public let bootTime: Date
        public let cores: Int
        public let load: [Double]
        public let tailscale: Tailscale?

        public struct Tailscale: Sendable, Hashable, Codable {
            public let name: String?
            public let ip: String?

            public init(name: String?, ip: String?) {
                self.name = name
                self.ip = ip
            }
        }

        public init(hostname: String, os: String, kernel: String, arch: String, serverID: Int64?, bootTime: Date, cores: Int, load: [Double],
                    tailscale: Tailscale? = nil) {
            self.hostname = hostname
            self.os = os
            self.kernel = kernel
            self.arch = arch
            self.serverID = serverID
            self.bootTime = bootTime
            self.cores = cores
            self.load = load
            self.tailscale = tailscale
        }
    }

    public struct Memory: Sendable, Hashable, Codable {
        public let total: Int64
        public let available: Int64
        public let swapTotal: Int64
        public let swapFree: Int64

        public init(total: Int64, available: Int64, swapTotal: Int64, swapFree: Int64) {
            self.total = total
            self.available = available
            self.swapTotal = swapTotal
            self.swapFree = swapFree
        }

        public var used: Int64 { max(0, total - available) }
        public var usedFraction: Double { total > 0 ? Double(used) / Double(total) : 0 }
        public var swapUsed: Int64 { max(0, swapTotal - swapFree) }
        public var swapFraction: Double { swapTotal > 0 ? Double(swapUsed) / Double(swapTotal) : 0 }
    }

    public struct Disk: Sendable, Hashable, Codable, Identifiable {
        public let mount: String
        public let device: String
        public let fs: String
        public let total: Int64
        public let used: Int64
        public let available: Int64
        public let inodesTotal: Int64
        public let inodesUsed: Int64
        public let readOnly: Bool

        public init(
            mount: String, device: String, fs: String, total: Int64, used: Int64, available: Int64,
            inodesTotal: Int64 = 0, inodesUsed: Int64 = 0, readOnly: Bool = false
        ) {
            self.mount = mount
            self.device = device
            self.fs = fs
            self.total = total
            self.used = used
            self.available = available
            self.inodesTotal = inodesTotal
            self.inodesUsed = inodesUsed
            self.readOnly = readOnly
        }

        public var id: String { device }
        public var usedFraction: Double {
            let usable = used + available
            return usable > 0 ? Double(used) / Double(usable) : 0
        }
        public var inodesFraction: Double { inodesTotal > 0 ? Double(inodesUsed) / Double(inodesTotal) : 0 }
    }

    public struct System: Sendable, Hashable, Codable {
        public let rebootRequired: Bool
        public let failedUnits: [String]

        public init(rebootRequired: Bool, failedUnits: [String]) {
            self.rebootRequired = rebootRequired
            self.failedUnits = failedUnits
        }
    }

    public struct Docker: Sendable, Hashable, Codable {
        public let error: String?
        public let containers: [Container]
        public let volumes: [Volume]
        public let volumesTime: Date?
        public let disk: DiskUsage?

        public init(error: String?, containers: [Container], volumes: [Volume], volumesTime: Date?, disk: DiskUsage? = nil) {
            self.error = error
            self.containers = containers
            self.volumes = volumes
            self.volumesTime = volumesTime
            self.disk = disk
        }

        enum CodingKeys: String, CodingKey {
            case error, containers, volumes, volumesTime, disk
        }

        public init(from decoder: Decoder) throws {
            let container = try decoder.container(keyedBy: CodingKeys.self)
            error = try container.decodeIfPresent(String.self, forKey: .error)
            containers = try container.decodeIfPresent([Container].self, forKey: .containers) ?? []
            volumes = try container.decodeIfPresent([Volume].self, forKey: .volumes) ?? []
            volumesTime = try container.decodeIfPresent(Date.self, forKey: .volumesTime)
            disk = try? container.decodeIfPresent(DiskUsage.self, forKey: .disk)
        }
    }

    public struct DiskUsage: Sendable, Hashable, Codable {
        public let images: Int64
        public let imagesReclaimable: Int64
        public let buildCache: Int64
        public let buildCacheReclaimable: Int64
        public let volumes: Int64
        public let volumesReclaimable: Int64
        public let containers: Int64

        public var total: Int64 { images + buildCache + volumes + containers }
        public var reclaimable: Int64 { imagesReclaimable + buildCacheReclaimable + volumesReclaimable }
    }

    public struct Container: Sendable, Hashable, Codable, Identifiable {
        public let id: String
        public let name: String
        public let image: String
        public let project: String?
        public let state: String
        public let health: String?
        public let exitCode: Int
        public let startedAt: Date?
        public let finishedAt: Date?
        public let restartCount: Int
        public let restartsLastHour: Int
        public let cpu: Double?
        public let memory: Int64?
        public let memoryLimit: Int64?
        public let ports: [Port]?
        public let mounts: [Mount]?
        public let networks: [String]?
        public let createdAt: Date?
        public let healthLog: HealthLog?

        public struct Port: Sendable, Hashable, Codable {
            public let `private`: Int
            public let `public`: Int?
            public let type: String
            public let ip: String?

            public init(private: Int, public: Int?, type: String = "tcp", ip: String? = nil) {
                self.private = `private`
                self.public = `public`
                self.type = type
                self.ip = ip
            }
        }

        public struct Mount: Sendable, Hashable, Codable {
            public let type: String
            public let name: String?
            public let source: String?
            public let destination: String
            public let readOnly: Bool?

            public init(type: String, name: String? = nil, source: String? = nil, destination: String, readOnly: Bool? = nil) {
                self.type = type
                self.name = name
                self.source = source
                self.destination = destination
                self.readOnly = readOnly
            }
        }

        public struct HealthLog: Sendable, Hashable, Codable {
            public let exitCode: Int
            public let output: String
            public let time: Date?
        }

        public init(
            id: String, name: String, image: String, project: String? = nil, state: String, health: String? = nil,
            exitCode: Int = 0, startedAt: Date? = nil, finishedAt: Date? = nil, restartCount: Int = 0,
            restartsLastHour: Int = 0, cpu: Double? = nil, memory: Int64? = nil, memoryLimit: Int64? = nil,
            ports: [Port]? = nil, mounts: [Mount]? = nil, networks: [String]? = nil, createdAt: Date? = nil, healthLog: HealthLog? = nil
        ) {
            self.id = id
            self.name = name
            self.image = image
            self.project = project
            self.state = state
            self.health = health
            self.exitCode = exitCode
            self.startedAt = startedAt
            self.finishedAt = finishedAt
            self.restartCount = restartCount
            self.restartsLastHour = restartsLastHour
            self.cpu = cpu
            self.memory = memory
            self.memoryLimit = memoryLimit
            self.ports = ports
            self.mounts = mounts
            self.networks = networks
            self.createdAt = createdAt
            self.healthLog = healthLog
        }

        public static let stopSignals: Set<Int> = [0, 130, 137, 143]

        public var isRunning: Bool { state == "running" }
        public var isUnhealthy: Bool { isRunning && health == "unhealthy" }
        public var isRestartLoop: Bool { state == "restarting" || restartsLastHour >= 3 }

        public func crashed(within interval: TimeInterval, now: Date) -> Bool {
            guard state == "exited" || state == "dead", !Self.stopSignals.contains(exitCode) else { return false }
            return finishedAt.map { now.timeIntervalSince($0) < interval } ?? false
        }
    }

    public struct Volume: Sendable, Hashable, Codable, Identifiable {
        public let name: String
        public let size: Int64
        public let containers: Int

        public init(name: String, size: Int64, containers: Int) {
            self.name = name
            self.size = size
            self.containers = containers
        }

        public var id: String { name }
    }
}

public struct AgentHistory: Sendable, Hashable, Codable {
    public let time: Date?
    public let coverageStart: Date
    public let hours: [Int64: Int]
    public let step: Int
    public let samples: [Sample]

    public init(coverageStart: Date, hours: [Int64: Int], step: Int, samples: [Sample], time: Date? = nil) {
        self.time = time
        self.coverageStart = coverageStart
        self.hours = hours
        self.step = step
        self.samples = samples
    }

    enum CodingKeys: String, CodingKey {
        case time, coverageStart, hours, step, samples
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        time = try container.decodeIfPresent(Date.self, forKey: .time)
        coverageStart = try container.decode(Date.self, forKey: .coverageStart)
        let raw = try container.decodeIfPresent([String: Int].self, forKey: .hours) ?? [:]
        hours = Dictionary(raw.compactMap { key, value in Int64(key).map { ($0, value) } }, uniquingKeysWith: max)
        step = try container.decodeIfPresent(Int.self, forKey: .step) ?? 300
        samples = try container.decodeIfPresent([Sample].self, forKey: .samples) ?? []
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encodeIfPresent(time, forKey: .time)
        try container.encode(coverageStart, forKey: .coverageStart)
        try container.encode(Dictionary(uniqueKeysWithValues: hours.map { (String($0.key), $0.value) }), forKey: .hours)
        try container.encode(step, forKey: .step)
        try container.encode(samples, forKey: .samples)
    }

    public struct Sample: Sendable, Hashable, Codable {
        public let t: Date
        public let memory: Double
        public let swap: Double
        public let disk: Double
        public let load: Double
        public var cpu: Double?
        public var diskReadIOPS: Double?
        public var diskWriteIOPS: Double?
        public var diskReadBytes: Double?
        public var diskWriteBytes: Double?
        public var netInBytes: Double?
        public var netOutBytes: Double?

        public init(t: Date, memory: Double, swap: Double, disk: Double, load: Double) {
            self.t = t
            self.memory = memory
            self.swap = swap
            self.disk = disk
            self.load = load
        }
    }

    public var hasActivity: Bool {
        samples.contains { $0.cpu != nil }
    }

    public func metrics(cores: Double, from start: Date? = nil, to end: Date? = nil) -> ServerMetrics? {
        let samples = start.map { start in self.samples.filter { $0.t >= start } } ?? self.samples
        guard samples.contains(where: { $0.cpu != nil }), let first = samples.first, let last = samples.last else { return nil }
        func series(_ value: (Sample) -> Double?) -> [MetricPoint] {
            samples.compactMap { sample in value(sample).map { MetricPoint(time: sample.t, value: $0) } }
        }
        let scale = max(cores, 1)
        return ServerMetrics(start: start ?? first.t, end: max(end ?? last.t, last.t), step: Double(step), series: [
            MetricSeries.cpu: series { $0.cpu.map { $0 * scale } },
            MetricSeries.diskIOPSRead: series(\.diskReadIOPS),
            MetricSeries.diskIOPSWrite: series(\.diskWriteIOPS),
            MetricSeries.diskBandwidthRead: series(\.diskReadBytes),
            MetricSeries.diskBandwidthWrite: series(\.diskWriteBytes),
            MetricSeries.networkBandwidthIn: series(\.netInBytes),
            MetricSeries.networkBandwidthOut: series(\.netOutBytes),
        ])
    }

    public func uptime(asOf date: Date) -> AgentUptime {
        AgentUptime(coverageStart: coverageStart, hours: hours, asOf: date)
    }
}

public struct AgentUptime: Sendable, Hashable, Codable {
    public var coverageStart: Date
    public var hours: [Int64: Int]
    public var asOf: Date

    public init(coverageStart: Date, hours: [Int64: Int], asOf: Date) {
        self.coverageStart = coverageStart
        self.hours = hours
        self.asOf = asOf
    }

    public func merged(with newer: AgentUptime, keepingAfter cutoff: Date) -> AgentUptime {
        var hours = self.hours
        for (hour, minutes) in newer.hours { hours[hour] = max(hours[hour] ?? 0, minutes) }
        let oldest = Int64(cutoff.timeIntervalSince1970)
        return AgentUptime(
            coverageStart: min(coverageStart, newer.coverageStart),
            hours: hours.filter { $0.key >= oldest },
            asOf: max(asOf, newer.asOf)
        )
    }
}

public struct ContainerHistory: Sendable, Hashable, Decodable {
    public let time: Date?
    public let step: Int
    public let samples: [Sample]

    public struct Sample: Sendable, Hashable, Decodable {
        public let t: Date
        public let cpu: Double?
        public let memory: Int64?
    }
}

public struct AgentHello: Sendable, Hashable, Decodable {
    public let agent: String
    public let version: String
    public let proof: String
}

enum AgentJSON {
    static func decoder() -> JSONDecoder {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .secondsSince1970
        return decoder
    }
}
