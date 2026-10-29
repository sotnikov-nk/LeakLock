// Renders the app icon into an .iconset directory.
// Usage: swift scripts/make-icon.swift <output.iconset>
import AppKit

let output = CommandLine.arguments.count > 1 ? CommandLine.arguments[1] : "AppIcon.iconset"
try? FileManager.default.createDirectory(atPath: output, withIntermediateDirectories: true)

func color(_ r: CGFloat, _ g: CGFloat, _ b: CGFloat, _ a: CGFloat = 1) -> NSColor {
    NSColor(srgbRed: r / 255, green: g / 255, blue: b / 255, alpha: a)
}

func rounded(_ rect: NSRect, _ radius: CGFloat) -> NSBezierPath {
    NSBezierPath(roundedRect: rect, xRadius: radius, yRadius: radius)
}

/// Draws the icon on a 1024×1024 canvas (macOS icon grid: 824 pt body, 100 pt margin):
/// a circuit breaker labelled VPN with its lever down, i.e. tripped.
func drawIcon() {
    let body = NSRect(x: 100, y: 100, width: 824, height: 824)
    let squircle = rounded(body, 186)

    // Soft drop shadow under the body.
    NSGraphicsContext.saveGraphicsState()
    let shadow = NSShadow()
    shadow.shadowColor = NSColor.black.withAlphaComponent(0.28)
    shadow.shadowOffset = NSSize(width: 0, height: -12)
    shadow.shadowBlurRadius = 28
    shadow.set()
    color(20, 24, 31).setFill()
    squircle.fill()
    NSGraphicsContext.restoreGraphicsState()

    // Dark slate body.
    NSGradient(colors: [color(58, 66, 80), color(20, 24, 31)])!.draw(in: squircle, angle: -90)

    // Glass sheen across the top half and a thin bright rim.
    NSGraphicsContext.saveGraphicsState()
    squircle.addClip()
    NSGradient(colors: [NSColor.white.withAlphaComponent(0.12), NSColor.white.withAlphaComponent(0)])!
        .draw(in: NSRect(x: 100, y: 512, width: 824, height: 412), angle: -90)
    NSGraphicsContext.restoreGraphicsState()
    let rim = rounded(body.insetBy(dx: 3, dy: 3), 183)
    rim.lineWidth = 6
    NSColor.white.withAlphaComponent(0.14).setStroke()
    rim.stroke()

    // Breaker housing.
    let housing = rounded(NSRect(x: 322, y: 200, width: 380, height: 624), 56)
    NSGraphicsContext.saveGraphicsState()
    let housingShadow = NSShadow()
    housingShadow.shadowColor = NSColor.black.withAlphaComponent(0.35)
    housingShadow.shadowOffset = NSSize(width: 0, height: -10)
    housingShadow.shadowBlurRadius = 24
    housingShadow.set()
    color(217, 221, 228).setFill()
    housing.fill()
    NSGraphicsContext.restoreGraphicsState()
    NSGradient(colors: [NSColor.white, color(217, 221, 228)])!.draw(in: housing, angle: -90)

    // Label.
    let font = NSFont.systemFont(ofSize: 44, weight: .bold)
    let label = NSAttributedString(string: "VPN", attributes: [.font: font, .foregroundColor: color(42, 47, 56)])
    let size = label.size()
    label.draw(at: NSPoint(x: 512 - size.width / 2, y: 754 + font.descender))

    // Lever slot and the lever, down: the breaker has tripped.
    color(42, 47, 56).setFill()
    rounded(NSRect(x: 392, y: 300, width: 240, height: 424), 36).fill()
    NSGradient(colors: [color(255, 138, 61), color(226, 71, 15)])!
        .draw(in: rounded(NSRect(x: 412, y: 320, width: 200, height: 184), 28), angle: -90)
    NSColor.white.withAlphaComponent(0.45).setFill()
    rounded(NSRect(x: 440, y: 458, width: 144, height: 18), 9).fill()

    // Indicator.
    color(226, 71, 15).setFill()
    NSBezierPath(ovalIn: NSRect(x: 494, y: 230, width: 36, height: 36)).fill()
}

func render(pixels: Int) -> Data {
    let rep = NSBitmapImageRep(
        bitmapDataPlanes: nil, pixelsWide: pixels, pixelsHigh: pixels,
        bitsPerSample: 8, samplesPerPixel: 4, hasAlpha: true, isPlanar: false,
        colorSpaceName: .deviceRGB, bytesPerRow: 0, bitsPerPixel: 0
    )!
    rep.size = NSSize(width: pixels, height: pixels)
    NSGraphicsContext.saveGraphicsState()
    let ctx = NSGraphicsContext(bitmapImageRep: rep)!
    NSGraphicsContext.current = ctx
    ctx.imageInterpolation = .high
    let scale = CGFloat(pixels) / 1024
    ctx.cgContext.scaleBy(x: scale, y: scale)
    drawIcon()
    NSGraphicsContext.restoreGraphicsState()
    return rep.representation(using: .png, properties: [:])!
}

for base in [16, 32, 128, 256, 512] {
    for factor in [1, 2] {
        let name = factor == 1 ? "icon_\(base)x\(base).png" : "icon_\(base)x\(base)@2x.png"
        try render(pixels: base * factor).write(to: URL(fileURLWithPath: "\(output)/\(name)"))
    }
}
print("Wrote \(output)")
