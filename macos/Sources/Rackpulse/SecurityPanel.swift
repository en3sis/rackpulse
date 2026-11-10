import AppKit
import HetznerKit
import SwiftUI
import UniformTypeIdentifiers

struct SecurityPanel: View {
    let server: Server
    let project: Project
    let monitor: Monitor

    @Environment(AppActions.self) private var app
    @State private var toggled: Set<String> = []
    @State private var showsAll: Set<String> = []
    @State private var showsLowPriority = false
    @State private var showsIgnored = false
    @State private var editing: String?
    @State private var exportProblem: String?
    @State private var promptCopied = false

    private static let rowLimit = 8
    private static let listsWarningAge: TimeInterval = 3 * 86_400
    static let upgradeCommand = "sudo apt update && sudo apt upgrade"

    var body: some View {
        let feed = monitor.agents.securityFeed(project.id, server.id)
        let result = monitor.security.result(project.id, server.id)
        VStack(alignment: .leading, spacing: 0) {
            if feed?.unsupported == true {
                AgentNotice(
                    kind: .info,
                    title: "Update the agent to see security checks",
                    text: "Security checks need agent \(AgentStore.latestVersion) or later."
                        + (monitor.agents.link(project.id, server.id)?.version.map { " This server runs \($0)." } ?? "")
                        + " Run this on the server as root. It keeps the key and settings.",
                    commands: [AgentStore.updateCommand]
                )
                .padding(.horizontal, 16)
            } else if let result {
                let decisions = monitor.decisionCheck(project, server.id)
                let review = SecurityReview(result, ignoring: decisions.ignoredKeys)
                imageNotice(feed)
                summary(result, review: review, decisions: decisions, report: feed?.report)
                updates(result, report: feed?.report)
                if result.onlineChecks { vulnerabilities(result, review: review, decisions: decisions) }
                hardening(result)
                images(result, review: review, report: feed?.report)
                dependencies(result, review: review, report: feed?.report)
                footer(result)
            } else if feed?.notReady == true {
                AgentNotice(kind: .info, text: "The agent is still collecting security data. It will show in a few minutes.")
                    .padding(.horizontal, 16)
            } else if feed?.problem != nil {
                AgentNotice(kind: .warning, text: "Could not read security data from the agent. Rackpulse tries again in a few minutes.")
                    .padding(.horizontal, 16)
            } else {
                HStack(spacing: 8) {
                    ProgressView().controlSize(.small)
                    Text("Checking security…").font(.system(size: 12)).foregroundStyle(Theme.secondary)
                    Spacer(minLength: 0)
                }
                .padding(10)
                .background(Theme.card, in: RoundedRectangle(cornerRadius: 9))
                .padding(.horizontal, 16)
            }
        }
        .padding(.top, 14)
    }

    private var checking: Bool {
        monitor.security.scanning || monitor.agents.isFetchingSecurity(project.id, server.id)
    }

    private var onlineChecks: Bool {
        monitor.settings.value.security.onlineChecks
    }

    private var target: String {
        AlertCenter.target(project: project, server: server.id)
    }

    @ViewBuilder
    private func imageNotice(_ feed: SecurityFeed?) -> some View {
        if let version = monitor.agents.link(project.id, server.id)?.version ?? feed?.report?.version,
           AgentVersion.isOlder(version, than: SecurityReview.imageScanVersion),
           monitor.agents.state(project.id, server.id)?.snapshot?.docker != nil {
            AgentNotice(
                kind: .info,
                title: "Update the agent to scan container images",
                text: "Image scans need agent \(SecurityReview.imageScanVersion) or later. This server runs \(version)."
                    + " Run this on the server as root. It keeps the key and settings.",
                commands: [AgentStore.updateCommand]
            )
            .padding(.horizontal, 16)
            .padding(.bottom, 10)
        }
    }

    @ViewBuilder
    private func summary(_ result: SecurityResult, review: SecurityReview, decisions: DecisionCheck, report: AgentSecurity?) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            if !onlineChecks {
                VStack(alignment: .leading, spacing: 8) {
                    HStack(spacing: 6) {
                        Image(systemName: "checkmark.shield").foregroundStyle(Theme.secondary)
                        Text("Vulnerability checks are off").font(.system(size: 12, weight: .semibold))
                    }
                    Text("Turn them on to check installed packages, app dependencies and container images against public vulnerability databases. Rackpulse sends package names and versions to OSV.dev, never server names or addresses.")
                        .font(.system(size: 11))
                        .foregroundStyle(Theme.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                    Button("Turn on") {
                        monitor.settings.value.security.onlineChecks = true
                        monitor.scheduleSecurity()
                    }
                    .controlSize(.small)
                }
                .padding(10)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(Theme.card, in: RoundedRectangle(cornerRadius: 9))
            } else if result.onlineChecks {
                HStack(spacing: 8) {
                    SummaryTile.fixNow(review.fixNow.count)
                    SummaryTile.fixAvailable(review.withFix.count)
                    SummaryTile.checks(review.failingChecks.count)
                }
                .fixedSize(horizontal: false, vertical: true)
                let tags = summaryTags(review)
                if !tags.isEmpty {
                    HStack(spacing: 6) {
                        ForEach(tags, id: \.text) { tag in Tag(text: tag.text, color: tag.color, icon: tag.icon) }
                        Spacer(minLength: 0)
                    }
                }
            }
            HStack(spacing: 8) {
                if result.onlineChecks && (!review.fixNow.isEmpty || !review.withFix.isEmpty || !review.failingChecks.isEmpty) {
                    promptButton(result, decisions: decisions)
                }
                Spacer(minLength: 6)
                exportMenu(result, decisions: decisions, report: report)
            }
            .padding(.top, 2)
            HStack(spacing: 6) {
                Image(systemName: "clock")
                    .font(.system(size: 10))
                    .foregroundStyle(Theme.secondary)
                Text(checkedText(result))
                    .font(.system(size: 11))
                    .foregroundStyle(Theme.secondary)
                if checking {
                    ProgressView().controlSize(.mini)
                    Text("Checking…").font(.system(size: 11)).foregroundStyle(Theme.secondary)
                } else {
                    Button("Check now") { monitor.checkSecurity(project.id, server.id) }
                        .buttonStyle(.plain)
                        .font(.system(size: 11, weight: .medium))
                        .foregroundStyle(Color.accentColor)
                }
                Spacer(minLength: 0)
            }
            .frame(minHeight: 16)
            if let exportProblem {
                Text(verbatim: exportProblem).font(.system(size: 11)).foregroundStyle(Theme.orange)
            }
        }
        .padding(.horizontal, 16)
    }

    private func promptButton(_ result: SecurityResult, decisions: DecisionCheck) -> some View {
        Button {
                let host = monitor.agents.link(project.id, server.id)?.endpoint.host
                let text = SecurityExport.agentPrompt(server: server.name, host: host, result: result, decisions: decisions)
                NSPasteboard.general.clearContents()
                NSPasteboard.general.setString(text, forType: .string)
                promptCopied = true
            } label: {
                Label(promptCopied ? "Copied" : "Copy AI fix prompt", systemImage: promptCopied ? "checkmark" : "sparkles")
        }
        .controlSize(.small)
        .help("Copies a Markdown task for an AI agent with this server's packages to fix, fixed versions and failing checks")
        .task(id: promptCopied) {
            guard promptCopied else { return }
            try? await Task.sleep(for: .seconds(2))
            promptCopied = false
        }
    }

    private func exportMenu(_ result: SecurityResult, decisions: DecisionCheck, report: AgentSecurity?) -> some View {
        Menu {
            Button("Markdown report…") {
                let text = SecurityExport.markdown(server: server.name, result: result, decisions: decisions, now: .now)
                save(Data(text.utf8), suffix: "security", type: "md")
            }
            Button("CycloneDX SBOM…") {
                guard let report else { return }
                guard let data = try? SecurityExport.cycloneDX(server: server.name, inventory: SecurityInventory(report), serial: UUID(), now: .now) else {
                    exportProblem = "Could not create the SBOM."
                    return
                }
                save(data, suffix: "sbom.cdx", type: "json")
            }
            .disabled(report == nil)
            Button("OpenVEX ignores…") {
                guard let data = try? SecurityExport.openVEX(
                    server: server.name, result: result, decisions: Array(decisions.active.values), id: UUID(), now: .now
                ) else {
                    exportProblem = "Could not create the OpenVEX file."
                    return
                }
                save(data, suffix: "ignores.openvex", type: "json")
            }
            .disabled(decisions.active.isEmpty)
        } label: {
            Label("Export", systemImage: "square.and.arrow.up")
        }
        .menuStyle(.button)
        .controlSize(.small)
        .fixedSize()
        .help(report == nil ? "The SBOM needs the latest agent report. It is fetched again in a few minutes." : "Save a report of this server")
    }

    private func save(_ data: Data, suffix: String, type: String) {
        let panel = NSSavePanel()
        let base = String(server.name.map { $0.isLetter || $0.isNumber || $0 == "-" || $0 == "_" || $0 == "." ? $0 : "-" })
        panel.nameFieldStringValue = "\(base.isEmpty ? "server" : base)-\(suffix).\(type)"
        panel.allowedContentTypes = [UTType(filenameExtension: type) ?? .data]
        panel.canCreateDirectories = true
        panel.isExtensionHidden = false
        exportProblem = nil
        app.holdOpen = true
        NSApp.activate()
        panel.begin { response in
            MainActor.assumeIsolated {
                app.holdOpen = false
                if response == .OK, let url = panel.url {
                    do {
                        try data.write(to: url, options: .atomic)
                    } catch {
                        exportProblem = "Could not save \(url.lastPathComponent)."
                    }
                }
                app.openPanel()
            }
        }
    }

    private func checkedText(_ result: SecurityResult) -> String {
        if onlineChecks && !result.onlineChecks { return "Vulnerability check pending" }
        return "Checked \(Format.compactDuration(since: result.checkedAt)) ago"
    }

    private func summaryTags(_ review: SecurityReview) -> [(text: String, color: Color, icon: String)] {
        var tags: [(text: String, color: Color, icon: String)] = []
        let items = review.visible.flatMap(\.items)
        var seen: Set<String> = []
        let unique = items.filter { seen.insert($0.key).inserted }
        let malware = unique.filter { $0.advisory.isMalware }.count
        let exploited = unique.filter { $0.advisory.isExploited }.count
        let likely = unique.filter { !$0.advisory.isExploited && $0.advisory.epss?.likelyExploited == true }.count
        if malware > 0 { tags.append(("\(malware) malware", Theme.red, "ladybug.fill")) }
        if exploited > 0 { tags.append(("\(exploited) exploited", Theme.red, "flame.fill")) }
        if likely > 0 { tags.append(("\(likely) likely exploited", Theme.orange, "flame")) }
        return tags
    }

    @ViewBuilder
    private func updates(_ result: SecurityResult, report: AgentSecurity?) -> some View {
        let count = result.pendingSecurityUpdates
        let packages = (report?.updates.items ?? []).filter(\.security).sorted { $0.name < $1.name }
        sectionHeader("Security updates", icon: "arrow.down.circle.fill", color: count > 0 ? Theme.orange : Theme.secondary,
                      trailing: count == 0 ? nil : "\(count) waiting")
        VStack(alignment: .leading, spacing: 0) {
            if let error = result.updatesError {
                messageRow(icon: "exclamationmark.triangle.fill", color: Theme.orange, text: error)
            }
            if let lists = result.listsTime, Date.now.timeIntervalSince(lists) > Self.listsWarningAge {
                messageRow(
                    icon: "exclamationmark.triangle.fill", color: Theme.orange,
                    text: "Package lists are \(Format.compactDuration(since: lists)) old. sudo apt update refreshes them."
                )
            }
            if count > 0 {
                HStack(spacing: 8) {
                    Text(Self.upgradeCommand)
                        .font(.system(size: 12, design: .monospaced))
                        .lineLimit(1)
                        .textSelection(.enabled)
                    Spacer(minLength: 6)
                    CopyButton(text: Self.upgradeCommand)
                }
                .padding(.horizontal, 10)
                .padding(.vertical, 8)
                .overlay(alignment: .top) { divider }
                if !packages.isEmpty {
                    let expanded = isExpanded("updates", default: false)
                    disclosure(expanded ? "Hide packages" : "Show \(packages.count) \(packages.count == 1 ? "package" : "packages")", expanded: expanded) {
                        toggle("updates")
                    }
                    if expanded {
                        let shown = limited(packages, key: "updates")
                        ForEach(shown, id: \.name) { update in
                            HStack(spacing: 8) {
                                Text(verbatim: update.name).font(.system(size: 13, weight: .medium)).lineLimit(1).truncationMode(.middle)
                                Spacer(minLength: 6)
                                Text(verbatim: "\(update.current ?? "new") → \(update.available)")
                                    .font(.system(size: 12))
                                    .foregroundStyle(Theme.secondary)
                                    .lineLimit(1)
                                    .truncationMode(.head)
                            }
                            .padding(.horizontal, 10)
                            .padding(.vertical, 6)
                            .overlay(alignment: .top) { divider }
                        }
                        showAllRow(total: packages.count, shown: shown.count, key: "updates")
                    }
                }
            } else {
                Text(result.pendingUpdates > 0
                     ? "No security updates waiting. \(result.pendingUpdates) other \(result.pendingUpdates == 1 ? "update is" : "updates are") available."
                     : "No updates waiting.")
                    .font(.system(size: 12))
                    .foregroundStyle(Theme.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                    .padding(.horizontal, 10)
                    .padding(.vertical, 8)
                    .overlay(alignment: .top) { divider }
            }
        }
        .padding(.top, -1)
        .clipShape(RoundedRectangle(cornerRadius: 9))
        .background(Theme.card, in: RoundedRectangle(cornerRadius: 9))
        .padding(.horizontal, 16)
    }

    @ViewBuilder
    private func vulnerabilities(_ result: SecurityResult, review: SecurityReview, decisions: DecisionCheck) -> some View {
        let ignored = ignoredDecisions(review: review, decisions: decisions)
        if review.visible.isEmpty && review.lowPriority.isEmpty {
            sectionHeader("Vulnerabilities", icon: "checkmark.shield.fill", color: Theme.green, trailing: nil)
            Label("No known vulnerabilities on this server.", systemImage: "checkmark.circle.fill")
                .font(.system(size: 12))
                .foregroundStyle(Theme.secondary)
                .padding(.horizontal, 16)
        }
        if !review.fixNow.isEmpty {
            sectionHeader("Fix now", icon: "flame.fill", color: Theme.red, trailing: Self.packages(review.fixNow.count))
            groupList(review.fixNow, low: [], key: "fixNow")
        }
        if !review.withFix.isEmpty {
            sectionHeader("Fix available", icon: "arrow.up.circle.fill", color: Theme.orange, trailing: Self.packages(review.withFix.count))
            groupList(review.withFix, low: [], key: "withFix")
        }
        if !review.noFix.isEmpty || !review.lowPriority.isEmpty {
            sectionHeader("No fix yet", icon: "circle.dashed", color: Theme.secondary,
                          trailing: review.noFix.isEmpty ? nil : Self.packages(review.noFix.count))
            noFixList(review)
        }
        if !ignored.isEmpty {
            VStack(alignment: .leading, spacing: 0) {
                disclosure(showsIgnored ? "Hide ignored" : "Show ignored (\(ignored.count))", expanded: showsIgnored) {
                    showsIgnored.toggle()
                }
                .padding(.top, -1)
                if showsIgnored {
                    ForEach(ignored) { decision in
                        IgnoredRow(decision: decision) { monitor.unignore(decision, project: project) }
                    }
                }
            }
            .clipShape(RoundedRectangle(cornerRadius: 9))
            .background(Theme.card, in: RoundedRectangle(cornerRadius: 9))
            .padding(.horizontal, 16)
            .padding(.top, 10)
        }
    }

    private func ignoredDecisions(review: SecurityReview, decisions: DecisionCheck) -> [FindingDecision] {
        let present = Set(review.ignored.map(\.key))
        return decisions.active.values
            .filter { present.contains($0.key) || !$0.allServers }
            .sorted { ($0.title, $0.created) < ($1.title, $1.created) }
    }

    private static func packages(_ count: Int) -> String {
        count == 1 ? "1 package" : "\(count) packages"
    }

    @ViewBuilder
    private func noFixList(_ review: SecurityReview) -> some View {
        let expanded = isExpanded("noFixSection", default: false)
        if expanded {
            groupList(review.noFix, low: review.lowPriority, key: "noFix", collapse: { toggle("noFixSection") })
        } else {
            let total = review.noFix.isEmpty ? review.lowPriority.count : review.noFix.count
            VStack(alignment: .leading, spacing: 0) {
                disclosure("Show \(Self.packages(total))", expanded: false) { toggle("noFixSection") }
                    .padding(.top, -1)
            }
            .clipShape(RoundedRectangle(cornerRadius: 9))
            .background(Theme.card, in: RoundedRectangle(cornerRadius: 9))
            .padding(.horizontal, 16)
            Text("No fixed version is published for these yet. Rackpulse moves them up when a fix ships.")
                .font(.system(size: 11))
                .foregroundStyle(Theme.secondary)
                .fixedSize(horizontal: false, vertical: true)
                .padding(.horizontal, 16)
                .padding(.top, 6)
        }
    }

    private func groupList(
        _ groups: [SecurityReview.Group], low: [SecurityReview.Group], key: String, collapse: (() -> Void)? = nil
    ) -> some View {
        let all = showsLowPriority ? groups + low : groups
        let shown = limited(all, key: key)
        return VStack(alignment: .leading, spacing: 0) {
            ForEach(shown) { group in
                let id = "\(key):\(group.id)"
                GroupRow(
                    group: group,
                    expanded: isExpanded("group:\(id)", default: false),
                    showsAll: showsAll.contains("advisories:\(id)"),
                    editing: editing.flatMap { $0.hasPrefix("\(id)|") ? String($0.dropFirst(id.count + 1)) : nil },
                    toggle: { toggle("group:\(id)") },
                    showAll: { showsAll.insert("advisories:\(id)") },
                    startIgnore: { editing = "\(id)|\($0)" },
                    cancelIgnore: { editing = nil },
                    ignore: { item, reason, end, everywhere, note in
                        guard let decision = FindingDecision.make(
                            target: everywhere ? FindingDecision.allServers : target, item: item, reason: reason, note: note, end: end, created: .now
                        ) else { return }
                        editing = nil
                        monitor.ignore(decision, project: project)
                    }
                )
            }
            showAllRow(total: all.count, shown: shown.count, key: key)
            if !low.isEmpty {
                disclosure(showsLowPriority ? "Hide low priority" : "Show \(low.count) low priority", expanded: showsLowPriority) {
                    showsLowPriority.toggle()
                }
            }
            if let collapse {
                disclosure("Hide these packages", expanded: true, action: collapse)
            }
        }
        .padding(.top, -1)
        .clipShape(RoundedRectangle(cornerRadius: 9))
        .background(Theme.card, in: RoundedRectangle(cornerRadius: 9))
        .padding(.horizontal, 16)
    }

    @ViewBuilder
    private func hardening(_ result: SecurityResult) -> some View {
        let checks = result.checks.sorted { (Self.rank($0), $0.title) < (Self.rank($1), $1.title) }
        let failing = result.failingChecks.count
        sectionHeader("Hardening", icon: failing == 0 ? "checkmark.shield.fill" : "exclamationmark.shield.fill",
                      color: failing == 0 ? Theme.green : Theme.orange,
                      trailing: failing == 0 ? "No problems" : "\(failing) \(failing == 1 ? "problem" : "problems")")
        if checks.isEmpty {
            Text("The agent reported no checks.")
                .font(.system(size: 13))
                .foregroundStyle(Theme.secondary)
                .padding(.horizontal, 16)
        } else {
            let open = checks.filter { $0.status != .pass }
            let passing = checks.filter { $0.status == .pass }
            let showsPassing = isExpanded("passingChecks", default: open.isEmpty)
            VStack(alignment: .leading, spacing: 0) {
                ForEach(open) { check in CheckRow(check: check) }
                if showsPassing {
                    ForEach(passing) { check in CheckRow(check: check) }
                }
                if !passing.isEmpty && !open.isEmpty {
                    disclosure(showsPassing ? "Hide passing checks" : "Show \(passing.count) passing \(passing.count == 1 ? "check" : "checks")",
                               expanded: showsPassing) { toggle("passingChecks") }
                }
            }
            .padding(.top, -1)
            .clipShape(RoundedRectangle(cornerRadius: 9))
            .background(Theme.card, in: RoundedRectangle(cornerRadius: 9))
            .padding(.horizontal, 16)
        }
    }

    private static func rank(_ check: SecurityCheck) -> Int {
        switch check.status {
        case .fail: check.informational ? 1 : 0
        case .unknown: 2
        case .pass: 3
        }
    }

    private struct ScannedImage: Identifiable {
        let id: String
        let name: String
        let containers: [String]?
        let error: String?
        let packages: Int?
    }

    private func scannedImages(_ result: SecurityResult, report: AgentSecurity?) -> [ScannedImage] {
        if let report {
            var seen: Set<String> = []
            return report.images.filter { seen.insert($0.id).inserted }.map { image in
                ScannedImage(
                    id: image.id, name: image.displayName, containers: image.containers, error: image.error ?? image.packages.error,
                    packages: image.packages.items.count + image.lockfiles.reduce(0) { $0 + $1.packages.count }
                )
            }
        }
        var seen: Set<String> = []
        return result.imageFindings.compactMap { finding in
            guard case .image(let id, let name, _) = finding.package.location, seen.insert(id).inserted else { return nil }
            return ScannedImage(id: id, name: name, containers: nil, error: nil, packages: nil)
        }
    }

    @ViewBuilder
    private func images(_ result: SecurityResult, review: SecurityReview, report: AgentSecurity?) -> some View {
        let images = scannedImages(result, report: report)
        if !images.isEmpty {
            sectionHeader("Images", icon: "shippingbox.fill", color: Theme.secondary, trailing: "\(images.count) scanned")
            let shown = limited(images, key: "images")
            VStack(alignment: .leading, spacing: 0) {
                ForEach(shown) { image in
                    let vulnerable = review.visible.filter {
                        if case .image(let id, _, _) = $0.package.location { return id == image.id }
                        return false
                    }
                    let worst = vulnerable.map(\.severity).max()
                    VStack(alignment: .leading, spacing: 2) {
                        HStack(spacing: 6) {
                            Image(systemName: "shippingbox").font(.system(size: 12)).foregroundStyle(Theme.secondary)
                            Text(verbatim: image.name)
                                .font(.system(size: 13, weight: .semibold))
                                .lineLimit(1)
                                .truncationMode(.middle)
                            Spacer(minLength: 6)
                            if image.error != nil {
                                Text("Cannot read").font(.system(size: 12)).foregroundStyle(Theme.orange)
                            } else if !vulnerable.isEmpty {
                                Text("\(vulnerable.count) vulnerable").font(.system(size: 12)).foregroundStyle(worst?.color ?? Theme.secondary)
                            } else if result.onlineChecks {
                                Text("No known issues").font(.system(size: 12)).foregroundStyle(Theme.secondary)
                            } else if let packages = image.packages {
                                Text(Self.packages(packages)).font(.system(size: 12)).foregroundStyle(Theme.secondary)
                            }
                        }
                        if let containers = image.containers {
                            Text(verbatim: containers.isEmpty ? "No containers use it" : "Containers: \(containers.joined(separator: ", "))")
                                .font(.system(size: 12))
                                .foregroundStyle(Theme.secondary)
                                .lineLimit(2)
                                .truncationMode(.tail)
                                .padding(.leading, 18)
                        }
                        if let error = image.error {
                            Text(verbatim: error)
                                .font(.system(size: 12))
                                .foregroundStyle(Theme.orange)
                                .fixedSize(horizontal: false, vertical: true)
                                .padding(.leading, 18)
                        }
                    }
                    .padding(.horizontal, 10)
                    .padding(.vertical, 7)
                    .overlay(alignment: .top) { divider }
                }
                showAllRow(total: images.count, shown: shown.count, key: "images")
            }
            .padding(.top, -1)
            .clipShape(RoundedRectangle(cornerRadius: 9))
            .background(Theme.card, in: RoundedRectangle(cornerRadius: 9))
            .padding(.horizontal, 16)
        }
    }

    private struct DependencyProject: Identifiable {
        let name: String
        var path: String?
        let error: String?
        let lockfiles: [(path: String, ecosystem: String?, packages: Int?, truncated: Bool)]
        var id: String { name }
    }

    static func accessCommand(_ path: String) -> String? {
        guard path.hasPrefix("/"), path.count > 1, !path.contains("//"),
              path.range(of: #"^[A-Za-z0-9._/-]+$"#, options: .regularExpression) != nil,
              !path.split(separator: "/").contains(where: { $0 == ".." || $0 == "." })
        else { return nil }
        var parents: [String] = []
        var current = (path as NSString).deletingLastPathComponent
        while current != "/" && !current.isEmpty {
            parents.insert(current, at: 0)
            current = (current as NSString).deletingLastPathComponent
        }
        var command = "sudo setfacl -m u:rackpulse:rX \(path)"
        if !parents.isEmpty { command = "sudo setfacl -m u:rackpulse:x \(parents.joined(separator: " ")) && " + command }
        return command
    }

    private func dependencyProjects(_ result: SecurityResult, report: AgentSecurity?) -> [DependencyProject] {
        if let report {
            return report.projects.map { project in
                DependencyProject(
                    name: project.name, path: project.path, error: project.error,
                    lockfiles: project.lockfiles.map { ($0.path, $0.ecosystem, $0.packages.count, $0.truncated) }
                )
            }
        }
        var paths: [String: [String]] = [:]
        for finding in result.dependencyFindings {
            if case .lockfile(let project, let path) = finding.package.location, !(paths[project]?.contains(path) ?? false) {
                paths[project, default: []].append(path)
            }
        }
        return paths.keys.sorted().map { name in
            DependencyProject(name: name, error: nil, lockfiles: (paths[name] ?? []).sorted().map { ($0, nil, nil, false) })
        }
    }

    @ViewBuilder
    private func dependencies(_ result: SecurityResult, review: SecurityReview, report: AgentSecurity?) -> some View {
        let projects = dependencyProjects(result, report: report)
        if !projects.isEmpty {
            sectionHeader("App dependencies", icon: "square.stack.3d.up.fill", color: Theme.secondary, trailing: "\(projects.count) Compose \(projects.count == 1 ? "project" : "projects")")
            VStack(spacing: 10) {
                ForEach(projects) { project in
                    dependencyCard(project, result: result, review: review)
                }
            }
            .padding(.horizontal, 16)
        }
    }

    private func dependencyCard(_ project: DependencyProject, result: SecurityResult, review: SecurityReview) -> some View {
        let vulnerable = review.visible.filter {
            if case .lockfile(let name, _) = $0.package.location { return name == project.name }
            return false
        }
        let worst = vulnerable.map(\.severity).max()
        let key = "project:\(project.name)"
        let expanded = isExpanded(key, default: project.error != nil)
        let summary: (String, Color) = if project.error != nil {
            ("Cannot read", Theme.orange)
        } else if !vulnerable.isEmpty {
            ("\(vulnerable.count) vulnerable", worst?.color ?? Theme.secondary)
        } else if result.onlineChecks {
            ("No known issues", Theme.secondary)
        } else {
            ("\(project.lockfiles.count) \(project.lockfiles.count == 1 ? "lockfile" : "lockfiles")", Theme.secondary)
        }
        return VStack(alignment: .leading, spacing: 0) {
            Button { toggle(key) } label: {
                HStack(spacing: 6) {
                    Image(systemName: "chevron.right")
                        .font(.system(size: 10, weight: .semibold))
                        .rotationEffect(.degrees(expanded ? 90 : 0))
                        .frame(width: 12)
                    Image(systemName: "square.stack.3d.up").font(.system(size: 12))
                    Text(verbatim: project.name).font(.system(size: 13, weight: .semibold)).foregroundStyle(Theme.text).lineLimit(1)
                    Spacer(minLength: 6)
                    Text(summary.0).font(.system(size: 12)).foregroundStyle(summary.1)
                }
                .foregroundStyle(Theme.secondary)
                .padding(.horizontal, 10)
                .padding(.vertical, 9)
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            if expanded {
                if let error = project.error {
                    VStack(alignment: .leading, spacing: 2) {
                        Text(verbatim: error).font(.system(size: 12)).foregroundStyle(Theme.orange)
                        if error.localizedCaseInsensitiveContains("permission") {
                            Text("The agent runs as the rackpulse user and cannot read this folder.")
                                .font(.system(size: 12))
                                .foregroundStyle(Theme.secondary)
                            if let command = project.path.flatMap(Self.accessCommand) {
                                Text("To give it access, run this on the server. It lets the agent read this folder and pass through the folders above it without listing them. It needs the acl package.")
                                    .font(.system(size: 12))
                                    .foregroundStyle(Theme.secondary)
                                    .padding(.top, 4)
                                HStack(alignment: .top, spacing: 8) {
                                    Text(verbatim: command)
                                        .font(.system(size: 11, design: .monospaced))
                                        .textSelection(.enabled)
                                    Spacer(minLength: 6)
                                    CopyButton(text: command)
                                }
                                .padding(8)
                                .background(Theme.card, in: RoundedRectangle(cornerRadius: 7))
                                .padding(.top, 4)
                            }
                        }
                    }
                    .fixedSize(horizontal: false, vertical: true)
                    .padding(.horizontal, 10)
                    .padding(.vertical, 7)
                    .overlay(alignment: .top) { divider }
                }
                if project.error == nil && project.lockfiles.isEmpty {
                    Text("No supported lockfiles found.")
                        .font(.system(size: 12))
                        .foregroundStyle(Theme.secondary)
                        .padding(.horizontal, 10)
                        .padding(.vertical, 7)
                        .overlay(alignment: .top) { divider }
                }
                ForEach(project.lockfiles, id: \.path) { lockfile in
                    let count = vulnerable.filter { $0.package.location == .lockfile(project: project.name, path: lockfile.path) }.count
                    HStack(spacing: 6) {
                        Image(systemName: "doc.text").font(.system(size: 11)).foregroundStyle(Theme.secondary)
                        Text(verbatim: lockfile.path).font(.system(size: 12, weight: .medium)).lineLimit(1).truncationMode(.middle)
                        Spacer(minLength: 6)
                        Text(lockfileDetail(lockfile, vulnerable: count))
                            .font(.system(size: 11))
                            .foregroundStyle(Theme.secondary)
                            .lineLimit(1)
                    }
                    .padding(.horizontal, 10)
                    .padding(.vertical, 6)
                    .overlay(alignment: .top) { divider }
                }
            }
        }
        .background(Theme.card, in: RoundedRectangle(cornerRadius: 9))
    }

    private func lockfileDetail(_ lockfile: (path: String, ecosystem: String?, packages: Int?, truncated: Bool), vulnerable: Int) -> String {
        var parts: [String] = []
        if let ecosystem = lockfile.ecosystem { parts.append(ecosystem) }
        if let packages = lockfile.packages { parts.append("\(packages) \(packages == 1 ? "package" : "packages")\(lockfile.truncated ? ", cut off" : "")") }
        if vulnerable > 0 { parts.append("\(vulnerable) vulnerable") }
        return parts.joined(separator: " · ")
    }

    @ViewBuilder
    private func footer(_ result: SecurityResult) -> some View {
        let sources = result.onlineChecks ? result.sources.filter { $0.state != .skipped } : []
        let kernel = result.onlineChecks && !result.skippedKernelSources.isEmpty
        if !sources.isEmpty {
            let failed = sources.filter { $0.state == .failed }
            let partial = sources.filter { $0.state == .partial }
            let warning = !failed.isEmpty || !partial.isEmpty
            let details = sources.map(Self.sourceLine)
                + (kernel ? ["Kernel packages are checked through pending updates, not the vulnerability database."] : [])
            HStack(spacing: 5) {
                Image(systemName: warning ? "exclamationmark.triangle.fill" : "info.circle")
                    .foregroundStyle(warning ? Theme.orange : Theme.secondary)
                Text(Self.sourcesSummary(total: sources.count, failed: failed.count, partial: partial.count))
                    .foregroundStyle(warning ? Theme.orange : Theme.secondary)
            }
            .font(.system(size: 11))
            .tip(details.joined(separator: "\n"))
            .padding(.horizontal, 16)
            .padding(.top, 16)
        }
    }

    static func sourcesSummary(total: Int, failed: Int, partial: Int) -> String {
        if failed > 0 { return failed == 1 ? "1 data source failed" : "\(failed) data sources failed" }
        if partial > 0 { return partial == 1 ? "1 data source partly checked" : "\(partial) data sources partly checked" }
        return total == 1 ? "Checked with 1 data source" : "Checked with \(total) data sources"
    }

    static func sourceLine(_ status: SourceStatus) -> String {
        let message = status.message.map { " \($0)" } ?? ""
        return switch status.state {
        case .ok: "\(status.source.title): checked"
        case .partial: "\(status.source.title): partly checked.\(message)"
        case .failed: "\(status.source.title): failed.\(message)"
        case .skipped: "\(status.source.title): skipped.\(message)"
        }
    }

    private func sectionHeader(_ title: String, icon: String, color: Color, trailing: String?) -> some View {
        HStack(spacing: 6) {
            Image(systemName: icon)
                .font(.system(size: 11, weight: .semibold))
                .foregroundStyle(color)
                .frame(width: 14)
            SectionTitle(title)
            Spacer()
            if let trailing {
                Text(trailing).font(.system(size: 12)).foregroundStyle(Theme.secondary)
            }
        }
        .padding(.horizontal, 16)
        .padding(.top, 20)
        .padding(.bottom, 4)
    }

    private func messageRow(icon: String, color: Color, text: String) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 8) {
            Image(systemName: icon).font(.system(size: 11)).foregroundStyle(color)
            Text(verbatim: text).font(.system(size: 12)).fixedSize(horizontal: false, vertical: true)
            Spacer(minLength: 0)
        }
        .padding(.horizontal, 10)
        .padding(.vertical, 8)
        .overlay(alignment: .top) { divider }
    }

    private func disclosure(_ title: String, expanded: Bool, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            HStack(spacing: 6) {
                Image(systemName: "chevron.right")
                    .font(.system(size: 10, weight: .semibold))
                    .rotationEffect(.degrees(expanded ? 90 : 0))
                    .frame(width: 12)
                Text(title).font(.system(size: 12, weight: .medium))
                Spacer(minLength: 0)
            }
            .foregroundStyle(Color.accentColor)
            .padding(.horizontal, 10)
            .padding(.vertical, 7)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .overlay(alignment: .top) { divider }
    }

    @ViewBuilder
    private func showAllRow(total: Int, shown: Int, key: String) -> some View {
        if total > shown {
            Button { showsAll.insert(key) } label: {
                Text("Show all \(total)")
                    .font(.system(size: 12, weight: .medium))
                    .foregroundStyle(Color.accentColor)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(.horizontal, 10)
                    .padding(.vertical, 7)
                    .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .overlay(alignment: .top) { divider }
        }
    }

    private var divider: some View {
        Theme.divider.frame(height: 1).padding(.horizontal, 10)
    }

    private func limited<Element>(_ items: [Element], key: String) -> [Element] {
        showsAll.contains(key) || items.count <= Self.rowLimit + 1 ? items : Array(items.prefix(Self.rowLimit))
    }

    private func isExpanded(_ id: String, default value: Bool) -> Bool {
        value != toggled.contains(id)
    }

    private func toggle(_ id: String) {
        if toggled.contains(id) { toggled.remove(id) } else { toggled.insert(id) }
    }
}

private struct GroupRow: View {
    let group: SecurityReview.Group
    let expanded: Bool
    let showsAll: Bool
    let editing: String?
    let toggle: () -> Void
    let showAll: () -> Void
    let startIgnore: (String) -> Void
    let cancelIgnore: () -> Void
    let ignore: (SecurityResult.Item, FindingDecision.Reason, FindingDecision.End, Bool, String) -> Void

    private static let advisoryLimit = 5

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            Button(action: toggle) {
                HStack(spacing: 8) {
                    Image(systemName: "chevron.right")
                        .font(.system(size: 10, weight: .semibold))
                        .foregroundStyle(Theme.secondary)
                        .rotationEffect(.degrees(expanded ? 90 : 0))
                        .frame(width: 12)
                    VStack(alignment: .leading, spacing: 2) {
                        HStack(spacing: 6) {
                            Text(verbatim: group.package.name)
                                .font(.system(size: 13, weight: .semibold))
                                .lineLimit(1)
                                .truncationMode(.middle)
                            if group.malware { Tag(text: "Malware", color: Theme.red) }
                            if group.exploited {
                                Tag(text: "Exploited", color: Theme.red)
                            } else if group.likelyExploited {
                                Tag(text: "Likely exploited", color: Theme.orange)
                            }
                        }
                        Text(verbatim: detailText)
                            .font(.system(size: 12))
                            .foregroundStyle(Theme.secondary)
                            .lineLimit(1)
                            .truncationMode(.middle)
                    }
                    Spacer(minLength: 6)
                    VStack(alignment: .trailing, spacing: 4) {
                        SeverityBadge(severity: group.severity)
                        fixBadge
                    }
                }
                .padding(.horizontal, 10)
                .padding(.vertical, 7)
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            if expanded {
                fix
                let items = group.lowPriority
                    ? group.finding.advisories.map { (advisory: $0, item: nil as SecurityResult.Item?) }
                    : group.items.map { (advisory: $0.advisory, item: Optional($0)) }
                let shown = showsAll || items.count <= Self.advisoryLimit + 1 ? items : Array(items.prefix(Self.advisoryLimit))
                ForEach(shown, id: \.advisory) { entry in
                    AdvisoryRow(
                        advisory: entry.advisory, status: group.finding.fixStatus(of: entry.advisory),
                        ignore: entry.item.flatMap { item in
                            FindingDecision.rule(item.advisory) == .never ? nil : { startIgnore(item.key) }
                        }
                    )
                    if let item = entry.item, editing == item.key {
                        IgnoreForm(item: item, cancel: cancelIgnore) { reason, end, everywhere, note in
                            ignore(item, reason, end, everywhere, note)
                        }
                        .padding(.leading, 30)
                        .padding(.trailing, 10)
                        .padding(.bottom, 8)
                    }
                }
                if shown.count < items.count {
                    Button(action: showAll) {
                        Text("Show all \(items.count) advisories")
                            .font(.system(size: 12, weight: .medium))
                            .foregroundStyle(Color.accentColor)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .padding(.leading, 30)
                            .padding(.trailing, 10)
                            .padding(.vertical, 6)
                            .contentShape(Rectangle())
                    }
                    .buttonStyle(.plain)
                }
            }
        }
        .overlay(alignment: .top) {
            Theme.divider.frame(height: 1).padding(.horizontal, 10)
        }
    }

    @ViewBuilder
    private var fix: some View {
        switch group.fix {
        case .command(let command):
            fixBox {
                HStack(alignment: .top, spacing: 8) {
                    Text(verbatim: command)
                        .font(.system(size: 11, design: .monospaced))
                        .lineLimit(3)
                        .fixedSize(horizontal: false, vertical: true)
                        .textSelection(.enabled)
                    Spacer(minLength: 6)
                    CopyButton(text: command)
                }
            }
        case .text(let text):
            fixBox {
                Text(verbatim: text)
                    .font(.system(size: 12))
                    .fixedSize(horizontal: false, vertical: true)
                    .textSelection(.enabled)
            }
        case nil:
            EmptyView()
        }
    }

    private func fixBox<Content: View>(@ViewBuilder content: () -> Content) -> some View {
        HStack(alignment: .top, spacing: 8) {
            Image(systemName: "wrench.and.screwdriver.fill")
                .font(.system(size: 11))
                .foregroundStyle(Theme.info)
                .frame(width: 14)
            VStack(alignment: .leading, spacing: 3) {
                Text("How to fix")
                    .font(.system(size: 11, weight: .semibold))
                    .foregroundStyle(Theme.secondary)
                content()
            }
            Spacer(minLength: 0)
        }
        .padding(8)
        .background(Theme.info.opacity(0.08), in: RoundedRectangle(cornerRadius: 7))
        .padding(.leading, 30)
        .padding(.trailing, 10)
        .padding(.bottom, 4)
    }

    private var fixedVersion: String? {
        group.fixedVersion ?? group.finding.fixedVersion
    }

    private var detailText: String {
        let base = "\(group.location) · \(group.package.version)"
        guard !group.finding.fixPending, let fixedVersion else { return base }
        return "\(base) · Fixed in \(fixedVersion)"
    }

    @ViewBuilder
    private var fixBadge: some View {
        if group.finding.fixPending {
            Tag(text: "Update waiting", color: Theme.info, icon: "clock")
                .help("The fixed version is downloaded on this server but not installed yet")
        } else if fixedVersion != nil {
            Tag(text: "Fix available", color: Theme.green, icon: "checkmark.circle.fill")
                .help("Upgrading the package fixes this")
        } else {
            Tag(text: "No fix yet", color: Theme.secondary, icon: "xmark.circle")
                .help("No fixed version is published yet")
        }
    }
}

private struct AdvisoryRow: View {
    let advisory: Advisory
    let status: FixStatus
    var ignore: (() -> Void)?

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack(spacing: 6) {
                Text(verbatim: advisory.id)
                    .font(.system(size: 12, weight: .semibold))
                    .lineLimit(1)
                    .textSelection(.enabled)
                SeverityBadge(severity: advisory.severity)
                if advisory.hidden { Tag(text: "Low priority", color: Theme.secondary) }
                Spacer(minLength: 0)
                if let score = advisory.score {
                    Text(String(format: "CVSS %.1f", score)).font(.system(size: 11)).foregroundStyle(Theme.secondary)
                }
            }
            if !advisory.summary.isEmpty {
                Text(verbatim: advisory.summary)
                    .font(.system(size: 12))
                    .foregroundStyle(Theme.secondary)
                    .lineLimit(5)
                    .fixedSize(horizontal: false, vertical: true)
            }
            FlowLayout(spacing: 10) {
                Label(fixDetail, systemImage: fixIcon)
                    .foregroundStyle(status == .noFix ? Theme.secondary : Theme.green)
                if let exploited = advisory.knownExploited {
                    Label(exploited.ransomware == true ? "Exploited, used by ransomware" : "Known to be exploited", systemImage: "flame.fill")
                        .foregroundStyle(Theme.red)
                }
            }
            .font(.system(size: 11, weight: .medium))
            let links = advisory.links.filter { AdvisoryLink.isAllowed($0.url) }
            if !links.isEmpty || ignore != nil {
                HStack(alignment: .center, spacing: 8) {
                    FlowLayout(spacing: 6) {
                        ForEach(links, id: \.url) { link in
                            LinkChip(title: shortTitle(link.title), url: link.url)
                        }
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                    if let ignore {
                        Button(action: ignore) {
                            Label("Ignore…", systemImage: "eye.slash")
                        }
                        .controlSize(.small)
                        .help("Hide this vulnerability for a while, with a reason")
                    }
                }
                .padding(.top, 2)
            }
        }
        .padding(.leading, 30)
        .padding(.trailing, 10)
        .padding(.vertical, 6)
    }

    private func shortTitle(_ title: String) -> String {
        let suffix = " \(advisory.id)"
        return title.hasSuffix(suffix) ? String(title.dropLast(suffix.count)) : title
    }

    private var fixIcon: String {
        switch status {
        case .pending: "clock"
        case .available: "checkmark.circle.fill"
        case .noFix: "xmark.circle"
        }
    }

    private var fixDetail: String {
        var text: String
        switch status {
        case .pending: text = "Fixed in \(advisory.fixedVersion ?? ""), update waiting on this server"
        case .available: text = "Fixed in \(advisory.fixedVersion ?? "")"
        case .noFix: text = "No fix yet"
        }
        if !advisory.fixedBy.isEmpty { text += " · " + advisory.fixedBy.joined(separator: ", ") }
        return text
    }
}

private struct LinkChip: View {
    let title: String
    let url: URL

    var body: some View {
        Button {
            guard AdvisoryLink.isAllowed(url) else { return }
            NSWorkspace.shared.open(url)
        } label: {
            HStack(spacing: 3) {
                Text(verbatim: title)
                Image(systemName: "arrow.up.right")
                    .font(.system(size: 8, weight: .bold))
            }
            .font(.system(size: 11, weight: .medium))
            .foregroundStyle(Color.accentColor)
            .padding(.horizontal, 7)
            .padding(.vertical, 3)
            .background(Color.accentColor.opacity(0.1), in: Capsule())
            .contentShape(Capsule())
        }
        .buttonStyle(.plain)
        .help("Open \(url.host() ?? url.absoluteString)")
    }
}

private struct IgnoreForm: View {
    let item: SecurityResult.Item
    let cancel: () -> Void
    let save: (FindingDecision.Reason, FindingDecision.End, Bool, String) -> Void

    private enum Ending: Hashable {
        case days(Int)
        case fix
    }

    @State private var reason = FindingDecision.Reason.notAffected
    @State private var ending = Ending.days(30)
    @State private var everywhere = false
    @State private var note = ""

    private static let noteLimit = 500

    private var strict: Bool {
        FindingDecision.rule(item.advisory) == .notAffectedOnly
    }

    private var canSave: Bool {
        !strict || !note.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
    }

    private var strictText: String {
        let kind = item.advisory.isExploited ? "Known exploited" : "Critical"
        return "\(kind) vulnerabilities can only be ignored as Not affected, for up to \(FindingDecision.strictDays) days, with a note."
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(verbatim: "Ignore \(FindingDecision.title(item))")
                .font(.system(size: 12, weight: .semibold))
                .lineLimit(1)
                .truncationMode(.middle)
            if strict {
                Label(strictText, systemImage: "exclamationmark.shield.fill")
                    .font(.system(size: 11))
                    .foregroundStyle(Theme.orange)
                    .fixedSize(horizontal: false, vertical: true)
            } else {
                SegmentedControl(selection: $reason, options: FindingDecision.Reason.allCases.map { ($0, $0.title) })
            }
            HStack(spacing: 8) {
                Picker("Ends", selection: $ending) {
                    ForEach(FindingDecision.durations.filter { !strict || $0 <= FindingDecision.strictDays }, id: \.self) { days in
                        Text("\(days) days").tag(Ending.days(days))
                    }
                    if !item.advisory.hasFix && !strict {
                        Text("Until a fix is available").tag(Ending.fix)
                    }
                }
                .fixedSize()
                Spacer(minLength: 6)
                Picker("Scope", selection: $everywhere) {
                    Text("This server").tag(false)
                    Text("All servers").tag(true)
                }
                .labelsHidden()
                .fixedSize()
            }
            .font(.system(size: 12))
            .controlSize(.small)
            TextField(strict ? "Why it does not apply (required)" : "Note (optional)", text: $note)
                .textFieldStyle(.roundedBorder)
                .font(.system(size: 12))
                .controlSize(.small)
                .onChange(of: note) { if note.count > Self.noteLimit { note = String(note.prefix(Self.noteLimit)) } }
            HStack(spacing: 8) {
                Text(reason == .notAffected ? "The finding does not apply to this server." : "The finding stays a risk until it is fixed.")
                    .font(.system(size: 11))
                    .foregroundStyle(Theme.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                Spacer(minLength: 6)
                Button("Cancel", action: cancel).controlSize(.small)
                Button("Ignore") {
                    let end: FindingDecision.End = switch ending {
                    case .days(let days): FindingDecision.end(days: days, from: .now)
                    case .fix: .fixAvailable
                    }
                    save(strict ? .notAffected : reason, end, everywhere, note)
                }
                .controlSize(.small)
                .keyboardShortcut(.defaultAction)
                .disabled(!canSave)
            }
        }
        .padding(10)
        .background(Theme.card, in: RoundedRectangle(cornerRadius: 8))
    }
}

private struct IgnoredRow: View {
    let decision: FindingDecision
    let unignore: () -> Void

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 8) {
            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 6) {
                    Text(verbatim: decision.title)
                        .font(.system(size: 13, weight: .medium))
                        .lineLimit(1)
                        .truncationMode(.middle)
                    if decision.allServers { Tag(text: "All servers", color: Theme.secondary) }
                }
                Text(verbatim: "\(decision.reason.title) · \(endText)")
                    .font(.system(size: 12))
                    .foregroundStyle(Theme.secondary)
                if !decision.note.isEmpty {
                    Text(verbatim: decision.note)
                        .font(.system(size: 12))
                        .foregroundStyle(Theme.secondary)
                        .lineLimit(3)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            Spacer(minLength: 6)
            Button("Unignore", action: unignore)
                .buttonStyle(.plain)
                .font(.system(size: 12, weight: .medium))
                .foregroundStyle(Color.accentColor)
        }
        .padding(.horizontal, 10)
        .padding(.vertical, 7)
        .overlay(alignment: .top) {
            Theme.divider.frame(height: 1).padding(.horizontal, 10)
        }
    }

    private var endText: String {
        switch decision.end {
        case .date(let date): "Until \(date.formatted(date: .abbreviated, time: .omitted))"
        case .fixAvailable: "Until a fix is available"
        }
    }
}

private struct CheckRow: View {
    let check: SecurityCheck

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 10) {
            Image(systemName: icon.0)
                .font(.system(size: 13))
                .foregroundStyle(icon.1)
                .frame(width: 16)
            VStack(alignment: .leading, spacing: 2) {
                Text(verbatim: check.title)
                    .font(.system(size: 13, weight: .medium))
                    .fixedSize(horizontal: false, vertical: true)
                if !check.detail.isEmpty {
                    Text(verbatim: check.detail)
                        .font(.system(size: 12))
                        .foregroundStyle(Theme.secondary)
                        .lineLimit(2)
                        .truncationMode(.middle)
                        .textSelection(.enabled)
                }
                if check.status == .fail, let hint = Self.hints[check.family] {
                    if hint.command {
                        HStack(spacing: 8) {
                            Text(verbatim: hint.text)
                                .font(.system(size: 11, design: .monospaced))
                                .lineLimit(2)
                                .fixedSize(horizontal: false, vertical: true)
                                .textSelection(.enabled)
                            Spacer(minLength: 6)
                            CopyButton(text: hint.text)
                        }
                        .padding(.top, 2)
                    } else {
                        Text(hint.text)
                            .font(.system(size: 12))
                            .fixedSize(horizontal: false, vertical: true)
                            .textSelection(.enabled)
                    }
                }
            }
            Spacer(minLength: 0)
        }
        .padding(.horizontal, 10)
        .padding(.vertical, 7)
        .overlay(alignment: .top) {
            Theme.divider.frame(height: 1).padding(.horizontal, 10)
        }
    }

    private var icon: (String, Color) {
        switch check.status {
        case .pass: ("checkmark.circle.fill", Theme.green)
        case .fail: check.informational ? ("info.circle.fill", Theme.info) : ("exclamationmark.circle.fill", Theme.orange)
        case .unknown: ("questionmark.circle", Theme.secondary)
        }
    }

    private static let hints: [String: (text: String, command: Bool)] = [
        SecurityCheck.sshPasswordLogin: ("Set PasswordAuthentication no in /etc/ssh/sshd_config.d/ and run sudo systemctl reload ssh.", false),
        SecurityCheck.sshRootLogin: ("Set PermitRootLogin prohibit-password in /etc/ssh/sshd_config.d/ and run sudo systemctl reload ssh.", false),
        SecurityCheck.automaticUpdates: ("sudo apt install unattended-upgrades && sudo dpkg-reconfigure -plow unattended-upgrades", true),
        SecurityCheck.firewallNone: ("Attach a Hetzner Cloud Firewall or enable ufw.", false),
        SecurityCheck.exposedPorts: ("Close the port in the Cloud Firewall or bind the service to 127.0.0.1.", false),
        SecurityCheck.dockerPrivileged: ("Remove privileged: true and add only the capabilities the container needs.", false),
        SecurityCheck.dockerSocketMount: ("Remove the docker.sock mount. A container with it can control every container on the server.", false),
        SecurityCheck.dockerHostNetwork: ("Use a bridge network and publish only the ports the container needs.", false),
        SecurityCheck.dockerHostPID: ("Remove pid: host. The container can see and signal every process on the server.", false),
        SecurityCheck.dockerCapAdd: ("Keep only the added capabilities the container needs, and remove the rest from cap_add.", false),
        SecurityCheck.dockerRoot: ("Set user: to a non-root user in the Compose file or the image.", false),
        SecurityCheck.dockerLatestTag: ("Pin the image to a version tag or a digest, so updates happen when you choose.", false),
        SecurityCheck.dockerOldImage: ("Pull a newer image and recreate the container to get its security fixes.", false),
        SecurityCheck.extraRoot: ("Remove the account or give it a UID other than 0.", false),
        SecurityCheck.kernelReboot: ("Reboot the server to load the new kernel.", false),
        SecurityCheck.endOfLife: ("Upgrade to a supported release.", false),
    ]
}

struct SeverityBadge: View {
    let severity: AdvisorySeverity

    var body: some View {
        Tag(text: severity.title, color: severity.color)
    }
}

struct Tag: View {
    let text: String
    let color: Color
    var icon: String?

    var body: some View {
        HStack(spacing: 3) {
            if let icon { Image(systemName: icon).font(.system(size: 8, weight: .bold)) }
            Text(text)
        }
        .font(.system(size: 10, weight: .semibold))
        .foregroundStyle(color)
        .lineLimit(1)
        .fixedSize()
        .padding(.horizontal, 5)
        .padding(.vertical, 1)
        .background(color.opacity(0.12), in: Capsule())
    }
}

struct CopyButton: View {
    let text: String

    @State private var copied = false

    var body: some View {
        Button(copied ? "Copied" : "Copy") {
            NSPasteboard.general.clearContents()
            NSPasteboard.general.setString(text, forType: .string)
            copied = true
            Task {
                try? await Task.sleep(for: .seconds(1.5))
                copied = false
            }
        }
        .buttonStyle(.plain)
        .font(.system(size: 12, weight: .medium))
        .foregroundStyle(copied ? Theme.green : Color.accentColor)
        .fixedSize()
    }
}

struct FlowLayout: Layout {
    var spacing: CGFloat = 8

    func sizeThatFits(proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) -> CGSize {
        let rows = arrange(width: proposal.width ?? .infinity, subviews: subviews)
        return CGSize(width: rows.map(\.width).max() ?? 0, height: rows.reduce(0) { $0 + $1.height } + spacing / 2 * CGFloat(max(0, rows.count - 1)))
    }

    func placeSubviews(in bounds: CGRect, proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) {
        var y = bounds.minY
        for row in arrange(width: bounds.width, subviews: subviews) {
            var x = bounds.minX
            for index in row.indices {
                let size = subviews[index].sizeThatFits(.unspecified)
                subviews[index].place(at: CGPoint(x: x, y: y), proposal: ProposedViewSize(size))
                x += size.width + spacing
            }
            y += row.height + spacing / 2
        }
    }

    private struct Row {
        var indices: [Int] = []
        var width: CGFloat = 0
        var height: CGFloat = 0
    }

    private func arrange(width: CGFloat, subviews: Subviews) -> [Row] {
        var rows: [Row] = []
        var row = Row()
        for index in subviews.indices {
            let size = subviews[index].sizeThatFits(.unspecified)
            let needed = row.indices.isEmpty ? size.width : row.width + spacing + size.width
            if needed > width, !row.indices.isEmpty {
                rows.append(row)
                row = Row()
            }
            row.width = row.indices.isEmpty ? size.width : row.width + spacing + size.width
            row.height = max(row.height, size.height)
            row.indices.append(index)
        }
        if !row.indices.isEmpty { rows.append(row) }
        return rows
    }
}

extension AdvisorySeverity {
    var title: String {
        switch self {
        case .critical: "Critical"
        case .high: "High"
        case .medium: "Medium"
        case .low: "Low"
        case .unknown: "Unrated"
        }
    }

    var color: Color {
        switch self {
        case .critical: Theme.red
        case .high: Theme.orange
        case .medium: Theme.yellow
        case .low: Theme.off
        case .unknown: Theme.secondary
        }
    }
}
