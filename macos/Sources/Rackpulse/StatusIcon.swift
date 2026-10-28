import AppKit

enum StatusIcon {
    private static let size = NSSize(width: 20, height: 16)

    static func image(dot: NSColor?) -> NSImage {
        let dot = dot ?? (Flavor.isDev ? NSColor.systemGray : nil)
        let image = NSImage(size: size, flipped: false) { _ in
            let glyph = dot == nil ? NSColor.black : NSColor.labelColor
            glyph.setFill()
            rack().fill()
            if Flavor.isDev { devTag() }
            if let dot {
                let center = NSPoint(x: 15.5, y: Flavor.isDev ? 11.4 : 4)
                NSGraphicsContext.current?.compositingOperation = .clear
                NSBezierPath(ovalIn: NSRect(x: center.x - 4.6, y: center.y - 4.6, width: 9.2, height: 9.2)).fill()
                NSGraphicsContext.current?.compositingOperation = .sourceOver
                dot.setFill()
                NSBezierPath(ovalIn: NSRect(x: center.x - 3.2, y: center.y - 3.2, width: 6.4, height: 6.4)).fill()
            }
            return true
        }
        image.isTemplate = dot == nil
        image.accessibilityDescription = Flavor.name
        return image
    }

    private static func devTag() {
        let tag = NSRect(x: 1.5, y: 0.2, width: 15, height: 5.4)
        NSColor.systemOrange.setFill()
        NSBezierPath(roundedRect: tag, xRadius: 1.6, yRadius: 1.6).fill()
        let text = NSAttributedString(string: "DEV", attributes: [
            .font: NSFont.systemFont(ofSize: 5.2, weight: .black),
            .foregroundColor: NSColor.white,
            .kern: 0.5,
        ])
        let bounds = text.size()
        text.draw(at: NSPoint(x: tag.midX - bounds.width / 2 + 0.25, y: tag.midY - bounds.height / 2 + 0.1))
    }

    private static func rack() -> NSBezierPath {
        let path = NSBezierPath()
        path.windingRule = .evenOdd
        let unitHeight: CGFloat = 4.2
        let gap: CGFloat = 1.3
        for index in (Flavor.isDev ? 1 : 0)..<3 {
            let y = 1 + CGFloat(index) * (unitHeight + gap)
            let unit = NSRect(x: 1.5, y: y, width: 15, height: unitHeight)
            path.append(NSBezierPath(roundedRect: unit, xRadius: 1.4, yRadius: 1.4))
            path.append(NSBezierPath(ovalIn: NSRect(x: 3.4, y: y + 1.35, width: 1.5, height: 1.5)))
            path.append(NSBezierPath(roundedRect: NSRect(x: 6.6, y: y + 1.5, width: 6.4, height: 1.2), xRadius: 0.6, yRadius: 0.6))
        }
        return path
    }
}
