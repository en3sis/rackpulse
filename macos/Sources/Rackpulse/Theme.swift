import HetznerKit
import SwiftUI

enum Theme {
    static let card = Color(nsColor: .quaternarySystemFill)
    static let panel = Color(nsColor: .controlBackgroundColor).opacity(0.82)
    static let divider = Color(nsColor: .separatorColor)
    static let selectedTab = Color(nsColor: .controlColor)
    static let text = Color.primary
    static let secondary = Color.secondary
    static let green = Color(nsColor: .systemGreen)
    static let orange = Color(nsColor: .systemOrange)
    static let yellow = Color(nsColor: .systemYellow)
    static let red = Color(nsColor: .systemRed)
    static let off = Color(nsColor: .systemGray)
    static let info = Color(nsColor: .systemBlue)

    static func color(_ severity: Severity) -> Color {
        switch severity {
        case .critical: red
        case .warning: orange
        case .info: info
        }
    }
}

extension NSColor {
    static func status(_ severity: Severity?) -> NSColor {
        switch severity {
        case .critical: .systemRed
        case .warning: .systemOrange
        case .info, nil: .systemGreen
        }
    }
}
