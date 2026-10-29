import Foundation
import Testing
@testable import HetznerKit

struct AgentTests {
    @Test func proofMatchesHMACOverNonceAndFingerprint() {
        let proof = AgentClient.proof(token: "rb1_key", nonce: "ab", fingerprint: "cd")
        #expect(proof == "5d0152a01ec90e3a2bb4b8ff9d4d3ea9383740440aaa615cc99dcdbbcdaba102")
        #expect(proof != AgentClient.proof(token: "rb1_other", nonce: "ab", fingerprint: "cd"))
        #expect(proof != AgentClient.proof(token: "rb1_key", nonce: "ab", fingerprint: "ce"))
        #expect(AgentClient.newToken().hasPrefix("rb1_"))
        #expect(AgentClient.newToken().count == 47)
    }

    @Test func decodesAgentSnapshotAndHistory() throws {
        let json = #"""
        {"version":"0.1.0","time":1761480000,
         "host":{"hostname":"web-1","os":"Ubuntu","kernel":"6.8","arch":"arm64","serverID":null,"bootTime":1758000000,"cores":4,"load":[0.1,0.2,0.3]},
         "memory":{"total":8000,"available":2000,"swapTotal":0,"swapFree":0},
         "disks":[{"mount":"/","device":"/dev/sda1","fs":"ext4","total":100,"used":91,"available":9,"inodesTotal":10,"inodesUsed":1,"readOnly":false}],
         "system":{"rebootRequired":true,"failedUnits":["nginx.service"]},
         "docker":{"error":null,"containers":[{"id":"1","name":"web","image":"x","project":null,"state":"running","health":null,"exitCode":0,
           "startedAt":1761400000,"finishedAt":null,"restartCount":0,"restartsLastHour":0,"cpu":null,"memory":null,"memoryLimit":null}],
           "volumes":[],"volumesTime":null}}
        """#
        let snapshot = try AgentJSON.decoder().decode(AgentSnapshot.self, from: Data(json.utf8))
        #expect(snapshot.memory.usedFraction == 0.75)
        #expect(snapshot.disks[0].usedFraction == 0.91)
        #expect(snapshot.docker?.containers.first?.isRunning == true)

        let history = try AgentJSON.decoder().decode(AgentHistory.self, from: Data(
            #"{"coverageStart":1761400000,"hours":{"1761476400":60},"step":300,"samples":[]}"#.utf8
        ))
        #expect(history.hours[1_761_476_400] == 60)
        #expect(snapshot.host.tailscale == nil)
    }

    @Test func agentHistoryBecomesServerMetrics() throws {
        let json = #"{"coverageStart":1761400000,"step":60,"samples":[{"t":1761480000,"memory":0.5,"swap":0,"disk":0.4,"load":0.2,"cpu":25,"diskReadIOPS":3,"diskWriteIOPS":5,"netOutBytes":1200},{"t":1761480060,"memory":0.5,"swap":0,"disk":0.4,"load":0.2}]}"#
        let history = try AgentJSON.decoder().decode(AgentHistory.self, from: Data(json.utf8))
        let metrics = try #require(history.metrics(cores: 4))
        #expect(metrics.cpuPercent(cores: 4).map(\.value) == [25])
        #expect(metrics.totalIOPS.map(\.value) == [8])
        #expect(metrics.points(MetricSeries.networkBandwidthOut).map(\.value) == [1200])

        let start = Date(timeIntervalSince1970: 1761479000)
        let end = Date(timeIntervalSince1970: 1761480100)
        let ranged = try #require(history.metrics(cores: 4, from: start, to: end))
        #expect(ranged.start == start && ranged.end == end)
        #expect(history.metrics(cores: 4, from: Date(timeIntervalSince1970: 1761480030)) == nil)

        let old = try AgentJSON.decoder().decode(AgentHistory.self, from: Data(
            #"{"coverageStart":1761400000,"step":60,"samples":[{"t":1761480000,"memory":0.5,"swap":0,"disk":0.4,"load":0.2}]}"#.utf8
        ))
        #expect(old.metrics(cores: 4) == nil)
    }

    @Test func decodesTailscaleNameAndAddress() throws {
        let json = #"{"hostname":"web-1","os":"","kernel":"","arch":"","serverID":null,"bootTime":1758000000,"cores":2,"load":[],"tailscale":{"name":"web-1.tail0000.ts.net","ip":"100.64.0.7"}}"#
        let host = try AgentJSON.decoder().decode(AgentSnapshot.Host.self, from: Data(json.utf8))
        #expect(host.tailscale?.name == "web-1.tail0000.ts.net")
        #expect(host.tailscale?.ip == "100.64.0.7")
    }

    @Test func stoppedContainersAreNeverUnhealthy() {
        let running = AgentSnapshot.Container(id: "1", name: "api", image: "x", state: "running", health: "unhealthy")
        let stopped = AgentSnapshot.Container(id: "2", name: "api.old", image: "x", state: "exited", health: "unhealthy")
        #expect(running.isUnhealthy)
        #expect(!stopped.isUnhealthy)
    }

    @Test func timelinePrefersAgentThenRackpulseThenHetzner() {
        let created = date("2026-10-20T00:00:00Z")
        let now = date("2026-10-26T10:30:00Z")
        let hour = { (text: String) in UptimeHistory.hour(date(text)) }
        let key = { (text: String) in Int64(hour(text)) * 3_600 }
        let agent = AgentUptime(
            coverageStart: date("2026-10-25T00:00:00Z"),
            hours: [key("2026-10-25T08:00:00Z"): 60, key("2026-10-25T09:00:00Z"): 30, key("2026-10-25T10:00:00Z"): 59],
            asOf: now
        )
        let actions = [
            ServerAction(id: 1, command: "shutdown_server", started: date("2026-10-23T12:00:00Z"),
                         finished: date("2026-10-23T12:01:00Z"), resources: []),
            ServerAction(id: 2, command: "start_server", started: date("2026-10-23T15:00:00Z"), resources: []),
        ]
        let timeline = UptimeTimeline(
            created: created, status: .running,
            local: [hour("2026-10-24T05:00:00Z"): .alert],
            agent: agent, actions: actions, actionsComplete: true, now: now
        )
        let at = { (text: String) in timeline.hours[hour(text)] }

        #expect(at("2026-10-19T23:00:00Z") == nil)
        #expect(at("2026-10-22T03:00:00Z") == UptimeEntry(.up, .hetzner))
        #expect(at("2026-10-23T13:00:00Z") == UptimeEntry(.off, .hetzner))
        #expect(at("2026-10-24T05:00:00Z") == UptimeEntry(.alert, .rackpulse))
        #expect(at("2026-10-25T08:00:00Z") == UptimeEntry(.up, .agent))
        #expect(at("2026-10-25T09:00:00Z") == UptimeEntry(.down, .agent))
        #expect(at("2026-10-25T10:00:00Z") == UptimeEntry(.up, .agent))
        #expect(at("2026-10-25T11:00:00Z") == UptimeEntry(.down, .agent))
    }

    @Test func agentAlertsHoldWhileAgentIsUnreachable() {
        let host = server(1)
        let snapshot = { (current: AgentSnapshot?, failures: Int) in
            PollSnapshot(time: .now, servers: [host], agents: [1: AgentReport(current: current, failures: failures)])
        }
        let full = AgentSnapshot(
            version: "0.1.0", time: .now,
            host: .init(hostname: "h", os: "", kernel: "", arch: "", serverID: nil, bootTime: .now, cores: 2, load: []),
            memory: .init(total: 100, available: 50, swapTotal: 0, swapFree: 0),
            disks: [.init(mount: "/", device: "/dev/sda1", fs: "ext4", total: 100, used: 95, available: 5)],
            system: .init(rebootRequired: false, failedUnits: []),
            docker: nil
        )
        let engine = RuleEngine(settings: AlertSettings())
        var (state, events) = engine.evaluate(snapshot(full, 0), state: AlertState())
        #expect(state.firing.map(\.id) == ["diskSpace:/:1"])
        #expect(events.count == 1)

        for failures in 1...2 {
            (state, events) = engine.evaluate(snapshot(nil, failures), state: state)
            #expect(state.firing.map(\.id) == ["diskSpace:/:1"])
            #expect(events.isEmpty)
        }
        (state, _) = engine.evaluate(snapshot(nil, 3), state: state)
        #expect(Set(state.firing.map(\.id)) == ["diskSpace:/:1", "agentUnreachable:1"])
    }
}
