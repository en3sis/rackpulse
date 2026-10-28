import HetznerKit
import SwiftUI

struct UptimeStrip: View {
    let states: [UptimeState?]
    var height: CGFloat = 16
    var spacing: CGFloat = 2
    @Binding var hovered: Int?

    var body: some View {
        HStack(spacing: spacing) {
            ForEach(states.indices, id: \.self) { index in
                RoundedRectangle(cornerRadius: min(2, height / 4))
                    .fill(Self.color(states[index]))
                    .overlay(alignment: .top) {
                        if states[index] == .alert {
                            Theme.orange.frame(height: max(2, height / 5))
                        }
                    }
                    .clipShape(RoundedRectangle(cornerRadius: min(2, height / 4)))
                    .opacity(hovered == nil || hovered == index ? 1 : 0.55)
                    .frame(height: height)
            }
        }
        .contentShape(Rectangle())
        .onContinuousHover { phase in
            switch phase {
            case .active(let point):
                hovered = states.isEmpty ? nil : min(states.count - 1, max(0, Int(point.x / max(1, width) * CGFloat(states.count))))
            case .ended:
                hovered = nil
            }
        }
        .onGeometryChange(for: CGFloat.self) { $0.size.width } action: { width = $0 }
        .accessibilityElement()
        .accessibilityLabel(summary)
    }

    @State private var width: CGFloat = 1

    private var summary: String {
        let known = states.compactMap { $0 }
        let up = known.filter { $0 == .up }.count
        return known.isEmpty ? "No history yet" : "Running in \(up) of \(known.count) recorded periods"
    }

    static func color(_ state: UptimeState?) -> Color {
        switch state {
        case .up, .alert: Theme.green
        case .down: Theme.red
        case .off: Theme.off.opacity(0.6)
        case nil: Theme.card
        }
    }

    static func title(_ state: UptimeState?) -> String {
        switch state {
        case .up: "Running"
        case .alert: "Running with an alert"
        case .down: "Down"
        case .off: "Stopped"
        case nil: "No data"
        }
    }
}

struct UptimeCard: View {
    enum Span: String, CaseIterable {
        case day = "24h", month = "30d"
    }

    let timeline: UptimeTimeline
    let hasAgent: Bool
    var agentOnly = false

    @State private var span = Span.day
    @State private var hovered: Int?

    var body: some View {
        let now = Date.now
        let entries = span == .day ? timeline.hourly(endingAt: now) : timeline.daily(endingAt: now)
        let states = entries.map { $0?.state }
        VStack(alignment: .leading, spacing: 7) {
            HStack(alignment: .firstTextBaseline, spacing: 8) {
                Text("Uptime").font(.system(size: 12)).foregroundStyle(Theme.secondary)
                Spacer(minLength: 8)
                toggle
            }
            HStack(alignment: .firstTextBaseline, spacing: 8) {
                Text(percent(states) ?? "-")
                    .font(.system(size: 17, weight: .semibold))
                    .rolling(percent(states))
                Spacer(minLength: 8)
                if let index = hovered, index < entries.count {
                    Text("\(label(index, now: now)) · \(describe(entries[index]))")
                        .font(.system(size: 11, weight: .medium))
                        .lineLimit(1)
                } else {
                    HStack(spacing: 4) {
                        Text(since.map { "Tracked since \($0.formatted(.dateTime.month(.abbreviated).day()))" } ?? "No history yet")
                        Image(systemName: "info.circle")
                    }
                    .font(.system(size: 11))
                    .foregroundStyle(Theme.secondary)
                    .tip(note(states))
                }
            }
            UptimeStrip(states: states, height: 10, spacing: span == .day ? 2 : 2.5, hovered: $hovered)
        }
        .padding(10)
        .background(Theme.card, in: RoundedRectangle(cornerRadius: 9))
    }

    private var toggle: some View {
        HStack(spacing: 2) {
            ForEach(Span.allCases, id: \.self) { option in
                Button {
                    span = option
                    hovered = nil
                } label: {
                    Text(option.rawValue)
                        .font(.system(size: 11, weight: span == option ? .semibold : .regular))
                        .foregroundStyle(span == option ? Theme.text : Theme.secondary)
                        .padding(.horizontal, 7)
                        .padding(.vertical, 2)
                        .background {
                            if span == option { RoundedRectangle(cornerRadius: 5).fill(Theme.selectedTab) }
                        }
                        .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
            }
        }
    }

    private var since: Date? {
        timeline.hours.keys.min().map { Date(timeIntervalSince1970: Double($0) * 3_600) }
    }

    private func label(_ index: Int, now: Date) -> String {
        switch span {
        case .day:
            let start = Calendar.current.date(byAdding: .hour, value: index - 23, to: now) ?? now
            return start.formatted(.dateTime.hour().minute())
        case .month:
            let day = Calendar.current.date(byAdding: .day, value: index - 29, to: now) ?? now
            return day.formatted(.dateTime.month(.abbreviated).day())
        }
    }

    private func note(_ states: [UptimeState?]) -> String {
        let known = states.compactMap { $0 }.count
        let coverage = known < states.count
            ? "\(known) of \(states.count) \(span == .day ? "hours" : "days") have data. "
            : ""
        let source = hasAgent
            ? "From the agent on the server, which records every minute the server runs."
            : "From Hetzner's start and stop history and Rackpulse's own checks. A crash inside the server is not visible to Hetzner; the Rackpulse agent records it."
        if agentOnly {
            return coverage + "From the agent on the server, which records every minute the server runs. An orange mark means the server was running but had an alert. Hover the bars for details."
        }
        return coverage + source + " Stops you made through Hetzner show in grey, and an orange mark means the server was running but had an alert. Hover the bars for details."
    }

    private func describe(_ entry: UptimeEntry?) -> String {
        guard let entry else { return "No data" }
        let state = UptimeStrip.title(entry.state)
        switch entry.source {
        case .agent:
            guard let minutes = entry.minutes, minutes.running < minutes.expected else { return "\(state), from the agent" }
            return "\(state) · ran \(minutes.running) of \(minutes.expected) min"
        case .rackpulse: return "\(state), seen by Rackpulse"
        case .hetzner: return entry.state == .off ? "\(state) through Hetzner" : "\(state), per Hetzner"
        }
    }

    private func percent(_ states: [UptimeState?]) -> String? {
        let known = states.compactMap { $0 }
        guard !known.isEmpty else { return nil }
        let running = known.filter { $0 == .up || $0 == .alert }.count
        let value = Double(running) / Double(known.count) * 100
        return value == 100 || value == 0 ? Format.percent(value) : String(format: "%.1f%%", value)
    }
}
