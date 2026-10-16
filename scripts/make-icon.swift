// Renders the app icon into an .iconset directory.
// Usage: swift scripts/make-icon.swift <output.iconset>
import AppKit

let output = CommandLine.arguments.count > 1 ? CommandLine.arguments[1] : "AppIcon.iconset"
try? FileManager.default.createDirectory(atPath: output, withIntermediateDirectories: true)

func color(_ r: CGFloat, _ g: CGFloat, _ b: CGFloat, _ a: CGFloat = 1) -> NSColor {
    NSColor(srgbRed: r / 255, green: g / 255, blue: b / 255, alpha: a)
}

/// Draws the icon on a 1024×1024 canvas (macOS icon grid: 824 pt body, 100 pt margin).
func drawIcon() {
    let body = NSRect(x: 100, y: 100, width: 824, height: 824)
    let squircle = NSBezierPath(roundedRect: body, xRadius: 186, yRadius: 186)

    // Soft drop shadow under the body.
    NSGraphicsContext.saveGraphicsState()
    let shadow = NSShadow()
    shadow.shadowColor = NSColor.black.withAlphaComponent(0.28)
    shadow.shadowOffset = NSSize(width: 0, height: -12)
    shadow.shadowBlurRadius = 28
    shadow.set()
    color(30, 60, 190).setFill()
    squircle.fill()
    NSGraphicsContext.restoreGraphicsState()

    // Deep blue body.
    NSGradient(colors: [color(72, 140, 255), color(36, 82, 230), color(22, 40, 150)],
               atLocations: [0, 0.55, 1], colorSpace: .sRGB)!
        .draw(in: squircle, angle: -90)

    // Glass sheen across the top half and a thin bright rim.
    NSGraphicsContext.saveGraphicsState()
    squircle.addClip()
    NSGradient(colors: [NSColor.white.withAlphaComponent(0.32), NSColor.white.withAlphaComponent(0)])!
        .draw(in: NSRect(x: 100, y: 512, width: 824, height: 412), angle: -90)
    NSGraphicsContext.restoreGraphicsState()
    let rim = NSBezierPath(roundedRect: body.insetBy(dx: 3, dy: 3), xRadius: 183, yRadius: 183)
    rim.lineWidth = 6
    NSColor.white.withAlphaComponent(0.22).setStroke()
    rim.stroke()

    // Shield.
    let shield = NSBezierPath()
    shield.move(to: NSPoint(x: 512, y: 790))
    shield.curve(to: NSPoint(x: 722, y: 712), controlPoint1: NSPoint(x: 588, y: 752), controlPoint2: NSPoint(x: 656, y: 724))
    shield.line(to: NSPoint(x: 722, y: 540))
    shield.curve(to: NSPoint(x: 512, y: 238), controlPoint1: NSPoint(x: 722, y: 396), controlPoint2: NSPoint(x: 622, y: 296))
    shield.curve(to: NSPoint(x: 302, y: 540), controlPoint1: NSPoint(x: 402, y: 296), controlPoint2: NSPoint(x: 302, y: 396))
    shield.line(to: NSPoint(x: 302, y: 712))
    shield.curve(to: NSPoint(x: 512, y: 790), controlPoint1: NSPoint(x: 368, y: 724), controlPoint2: NSPoint(x: 436, y: 752))
    shield.close()

    NSGraphicsContext.saveGraphicsState()
    let shieldShadow = NSShadow()
    shieldShadow.shadowColor = NSColor.black.withAlphaComponent(0.25)
    shieldShadow.shadowOffset = NSSize(width: 0, height: -10)
    shieldShadow.shadowBlurRadius = 24
    shieldShadow.set()
    NSColor.white.withAlphaComponent(0.6).setFill()
    shield.fill()
    NSGraphicsContext.restoreGraphicsState()

    // Left half solid white: the half-filled shield reads as "guarded".
    NSGraphicsContext.saveGraphicsState()
    NSBezierPath(rect: NSRect(x: 0, y: 0, width: 512, height: 1024)).addClip()
    NSColor.white.setFill()
    shield.fill()
    NSGraphicsContext.restoreGraphicsState()
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
