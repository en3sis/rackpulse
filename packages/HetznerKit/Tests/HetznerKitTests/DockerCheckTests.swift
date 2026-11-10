import Foundation
import Testing
@testable import HetznerKit

struct DockerCheckTests {
    @Test func dockerChecksAlertOnlyForEscapeRisks() throws {
        let ids = [
            SecurityCheck.dockerPrivileged, SecurityCheck.dockerSocketMount, SecurityCheck.dockerHostPID,
            SecurityCheck.dockerHostNetwork, SecurityCheck.dockerCapAdd, SecurityCheck.dockerRoot,
            SecurityCheck.dockerLatestTag, SecurityCheck.dockerOldImage,
        ]
        let checks = ids.map { "{\"id\":\"\($0)\",\"status\":\"fail\",\"title\":\"t\",\"detail\":\"web\",\"source\":null}" }
        let json = #"{"version":"0.4.0","time":1793700000,"os":{},"packages":{"items":[]},"updates":{"items":[]},"checks":["#
            + checks.joined(separator: ",") + "]}"
        let report = try AgentJSON.decoder().decode(AgentSecurity.self, from: Data(json.utf8))
        let alerting = Set(report.checks.filter(\.countsForAlert).map(\.id))
        #expect(alerting == [SecurityCheck.dockerPrivileged, SecurityCheck.dockerSocketMount, SecurityCheck.dockerHostPID])
        #expect(report.check(SecurityCheck.dockerRoot)?.informational == true)
        #expect(report.check(SecurityCheck.dockerLatestTag)?.informational == true)
        #expect(report.check(SecurityCheck.dockerOldImage)?.informational == true)
        #expect(report.check(SecurityCheck.dockerCapAdd)?.informational == true)
        #expect(!HostChecks.isHostCheck(SecurityCheck.dockerHostPID))
    }
}
