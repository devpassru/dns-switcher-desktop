import AppKit
import CoreGraphics
import Foundation

// Generates all Tauri 2 app icons (PNGs, .icns, .ico) and tray icons (tray-active.png, tray-inactive.png)
let outputDir = CommandLine.arguments.count > 1 ? CommandLine.arguments[1] : "src-tauri/icons"
let fm = FileManager.default
try fm.createDirectory(atPath: outputDir, withIntermediateDirectories: true)

func makeBitmap(size: Int) -> NSBitmapImageRep {
    let rep = NSBitmapImageRep(
        bitmapDataPlanes: nil,
        pixelsWide: size,
        pixelsHigh: size,
        bitsPerSample: 8,
        samplesPerPixel: 4,
        hasAlpha: true,
        isPlanar: false,
        colorSpaceName: .deviceRGB,
        bytesPerRow: 0,
        bitsPerPixel: 0
    )!
    rep.size = NSSize(width: size, height: size)
    return rep
}

func renderAppIcon(size: Int) -> Data {
    let rep = makeBitmap(size: size)
    NSGraphicsContext.saveGraphicsState()
    NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: rep)
    let ctx = NSGraphicsContext.current!.cgContext

    let s = CGFloat(size)
    let margin = s * 0.095
    let rect = CGRect(x: margin, y: margin, width: s - margin * 2, height: s - margin * 2)
    let radius = rect.width * 0.225

    ctx.saveGState()
    ctx.setShadow(
        offset: CGSize(width: 0, height: -s * 0.02),
        blur: s * 0.045,
        color: NSColor(calibratedWhite: 0, alpha: 0.38).cgColor
    )
    let bgPath = CGPath(roundedRect: rect, cornerWidth: radius, cornerHeight: radius, transform: nil)
    ctx.addPath(bgPath)
    ctx.setFillColor(NSColor(calibratedRed: 0.07, green: 0.10, blue: 0.22, alpha: 1.0).cgColor)
    ctx.fillPath()
    ctx.restoreGState()

    ctx.saveGState()
    ctx.addPath(bgPath)
    ctx.clip()

    let colorSpace = CGColorSpaceCreateDeviceRGB()
    let gradColors = [
        NSColor(calibratedRed: 0.06, green: 0.09, blue: 0.22, alpha: 1.0).cgColor,
        NSColor(calibratedRed: 0.09, green: 0.22, blue: 0.48, alpha: 1.0).cgColor,
        NSColor(calibratedRed: 0.05, green: 0.48, blue: 0.72, alpha: 1.0).cgColor
    ] as CFArray
    let locations: [CGFloat] = [0.0, 0.55, 1.0]
    let gradient = CGGradient(colorsSpace: colorSpace, colors: gradColors, locations: locations)!
    ctx.drawLinearGradient(
        gradient,
        start: CGPoint(x: rect.minX, y: rect.minY),
        end: CGPoint(x: rect.maxX, y: rect.maxY),
        options: []
    )

    let glowColors = [
        NSColor(calibratedRed: 0.25, green: 0.85, blue: 1.0, alpha: 0.35).cgColor,
        NSColor(calibratedRed: 0.25, green: 0.85, blue: 1.0, alpha: 0.0).cgColor
    ] as CFArray
    let glowGrad = CGGradient(colorsSpace: colorSpace, colors: glowColors, locations: [0.0, 1.0])!
    ctx.drawRadialGradient(
        glowGrad,
        startCenter: CGPoint(x: rect.maxX - rect.width * 0.22, y: rect.maxY - rect.height * 0.20),
        startRadius: 0,
        endCenter: CGPoint(x: rect.maxX - rect.width * 0.22, y: rect.maxY - rect.height * 0.20),
        endRadius: rect.width * 0.65,
        options: []
    )

    let symbolPointSize = rect.width * 0.54
    let config = NSImage.SymbolConfiguration(pointSize: symbolPointSize, weight: .semibold)
        .applying(.init(paletteColors: [
            NSColor.white,
            NSColor(calibratedRed: 0.38, green: 0.92, blue: 1.0, alpha: 1.0)
        ]))
    if let sym = NSImage(systemSymbolName: "network.badge.shield.half.filled", accessibilityDescription: nil)?
        .withSymbolConfiguration(config) {
        let symSize = sym.size
        let drawRect = CGRect(
            x: rect.midX - symSize.width / 2 + s * 0.015,
            y: rect.midY - symSize.height / 2 - s * 0.01,
            width: symSize.width,
            height: symSize.height
        )
        ctx.saveGState()
        ctx.setShadow(
            offset: CGSize(width: 0, height: -s * 0.012),
            blur: s * 0.03,
            color: NSColor(calibratedRed: 0.02, green: 0.05, blue: 0.14, alpha: 0.55).cgColor
        )
        sym.draw(in: drawRect)
        ctx.restoreGState()
    }

    ctx.addPath(bgPath)
    ctx.setStrokeColor(NSColor(calibratedWhite: 1.0, alpha: 0.22).cgColor)
    ctx.setLineWidth(max(1.0, s * 0.012))
    ctx.strokePath()

    ctx.restoreGState()
    NSGraphicsContext.restoreGraphicsState()
    return rep.representation(using: .png, properties: [:])!
}

func renderTrayIcon(active: Bool, size: Int = 32) -> Data {
    let rep = makeBitmap(size: size)
    NSGraphicsContext.saveGraphicsState()
    NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: rep)
    let ctx = NSGraphicsContext.current!.cgContext
    ctx.setAllowsAntialiasing(true)
    ctx.setShouldAntialias(true)

    let s = CGFloat(size)
    let symbolName = active ? "network.badge.shield.half.filled" : "network.slash"
    let baseConfig = NSImage.SymbolConfiguration(pointSize: s * 0.72, weight: .semibold)
    let config: NSImage.SymbolConfiguration = active
        ? baseConfig.applying(.init(paletteColors: [
            NSColor.white,
            NSColor(calibratedRed: 0.25, green: 0.78, blue: 1.0, alpha: 1.0)
        ]))
        : baseConfig.applying(.init(paletteColors: [
            NSColor(calibratedWhite: 0.78, alpha: 0.95),
            NSColor(calibratedWhite: 0.55, alpha: 0.6)
        ]))

    if let sym = NSImage(systemSymbolName: symbolName, accessibilityDescription: nil)?
        .withSymbolConfiguration(config) {
        let symSize = sym.size
        let drawRect = CGRect(
            x: (s - symSize.width) / 2.0,
            y: (s - symSize.height) / 2.0,
            width: symSize.width,
            height: symSize.height
        )
        sym.draw(in: drawRect)
    }

    NSGraphicsContext.restoreGraphicsState()
    return rep.representation(using: .png, properties: [:])!
}

// Write PNG icons needed by Tauri
let pngTargets: [(String, Int)] = [
    ("32x32.png", 32),
    ("128x128.png", 128),
    ("128x128@2x.png", 256),
    ("icon.png", 512)
]
for (name, px) in pngTargets {
    try renderAppIcon(size: px).write(to: URL(fileURLWithPath: "\(outputDir)/\(name)"))
}

// Write tray icons
try renderTrayIcon(active: true, size: 32).write(to: URL(fileURLWithPath: "\(outputDir)/tray-active.png"))
try renderTrayIcon(active: false, size: 32).write(to: URL(fileURLWithPath: "\(outputDir)/tray-inactive.png"))

// Write Windows ICO (containing PNG frames: 16, 32, 48, 256)
let icoSizes = [16, 32, 48, 256]
let icoFrames = icoSizes.map { ($0, renderAppIcon(size: $0)) }
var icoData = Data()
// ICONDIR: reserved(2)=0, type(2)=1, count(2)
icoData.append(contentsOf: [0x00, 0x00, 0x01, 0x00])
let count = UInt16(icoFrames.count)
icoData.append(UInt8(count & 0xFF))
icoData.append(UInt8((count >> 8) & 0xFF))

var offset = UInt32(6 + 16 * icoFrames.count)
for (px, png) in icoFrames {
    let dim: UInt8 = px >= 256 ? 0 : UInt8(px)
    icoData.append(dim) // width
    icoData.append(dim) // height
    icoData.append(0)   // colorCount
    icoData.append(0)   // reserved
    icoData.append(contentsOf: [0x01, 0x00]) // planes = 1
    icoData.append(contentsOf: [0x20, 0x00]) // bitCount = 32
    var len = UInt32(png.count).littleEndian
    withUnsafeBytes(of: &len) { icoData.append(contentsOf: $0) }
    var off = offset.littleEndian
    withUnsafeBytes(of: &off) { icoData.append(contentsOf: $0) }
    offset += UInt32(png.count)
}
for (_, png) in icoFrames {
    icoData.append(png)
}
try icoData.write(to: URL(fileURLWithPath: "\(outputDir)/icon.ico"))

// Write macOS ICNS using iconutil
let tmpDir = NSTemporaryDirectory() + "DNSSwitcherDesktop-\(ProcessInfo.processInfo.globallyUniqueString)"
let iconsetPath = "\(tmpDir)/AppIcon.iconset"
try fm.createDirectory(atPath: iconsetPath, withIntermediateDirectories: true)
defer { try? fm.removeItem(atPath: tmpDir) }

let icnsSizes: [(String, Int)] = [
    ("icon_16x16.png", 16),
    ("icon_16x16@2x.png", 32),
    ("icon_32x32.png", 32),
    ("icon_32x32@2x.png", 64),
    ("icon_128x128.png", 128),
    ("icon_128x128@2x.png", 256),
    ("icon_256x256.png", 256),
    ("icon_256x256@2x.png", 512),
    ("icon_512x512.png", 512),
    ("icon_512x512@2x.png", 1024)
]
for (name, px) in icnsSizes {
    try renderAppIcon(size: px).write(to: URL(fileURLWithPath: "\(iconsetPath)/\(name)"))
}
let proc = Process()
proc.executableURL = URL(fileURLWithPath: "/usr/bin/iconutil")
proc.arguments = ["-c", "icns", iconsetPath, "-o", "\(outputDir)/icon.icns"]
try proc.run()
proc.waitUntilExit()
guard proc.terminationStatus == 0 else {
    fputs("iconutil failed with status \(proc.terminationStatus)\n", stderr)
    exit(1)
}
print("Generated all icons in \(outputDir)")
