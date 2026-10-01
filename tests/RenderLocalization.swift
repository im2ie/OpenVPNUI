import AppKit
import SwiftUI

// Compile with -D RENDER_PREVIEW and the application sources. Uses synthetic
// in-memory data only: no preferences, profiles, Keychain or helper requests.
@main struct RenderLocalization {
    @MainActor static func main() throws {
        guard CommandLine.arguments.count == 2 else { return }
        let output = URL(fileURLWithPath: CommandLine.arguments[1], isDirectory: true)
        try FileManager.default.createDirectory(at: output, withIntermediateDirectories: true)
        let app = NSApplication.shared
        app.setActivationPolicy(.accessory); app.appearance = NSAppearance(named: .aqua)
        let model = AppModel(preview: true)
        let profile = Profile(id: "example", name: "Example VPN", configuration: "client\ndev tun\nremote vpn.example.test 1194\n", dnsRules: [], useSnapshotDNS: false)
        model.store.profiles = [profile]; model.selected = profile.id
        model.helperAvailable = true; model.helperVersion = "0.2.3"
        model.groups = ["admin", "staff"]; model.allowedGroups = ["admin"]
        model.interfaces = "utun0"
        model.statuses[profile.id] = SessionStatus(id: profile.id, state: "disconnected", message: "Disconnected")
        model.logs = ["OpenVPN 2.6.23 x86_64-apple-darwin", "Synthetic preview — no connection requested"]
        model.store.certificates = [CertificateRecord(id: "example-cert", name: "Example client", subject: "CN=Example Client", issuer: "CN=Example CA", sha1: String(repeating: "AB", count: 20), sha256: String(repeating: "CD", count: 32), notBefore: "2026-01-01", notAfter: "2027-01-01", algorithm: "RSA", bits: 4096, certificate: "", chain: ["CN=Example Client", "CN=Example CA"], hasPrivateKey: true)]
        model.certificateSelection = "example-cert"
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys]
        let original = try encoder.encode(model.store)
        let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 1120, height: 760), styleMask: [.titled], backing: .buffered, defer: false)
        window.title = "OpenVPNUI localization preview"

        func render<V: View>(_ content: V, name: String, size: NSSize) throws {
            let host = NSHostingView(rootView: content.environment(\.locale, model.language.locale))
            host.frame = NSRect(origin: .zero, size: size)
            window.setContentSize(size); window.contentView = host; window.orderFront(nil)
            RunLoop.main.run(until: Date().addingTimeInterval(0.4))
            host.layoutSubtreeIfNeeded()
            guard let bitmap = host.bitmapImageRepForCachingDisplay(in: host.bounds) else { throw VPNError("Cannot render preview") }
            host.cacheDisplay(in: host.bounds, to: bitmap)
            guard let data = bitmap.representation(using: .png, properties: [:]) else { throw VPNError("Cannot encode preview") }
            try data.write(to: output.appendingPathComponent(name + ".png"))
        }
        for language in AppLanguage.allCases {
            model.setLanguage(language)
            for page in ["settings", "connections", "certificates", "requests"] {
                model.page = page
                try render(MainView(model: model), name: language.rawValue + "-" + page, size: NSSize(width: 1120, height: 760))
            }
            try render(ProfileEditor(model: model, profile: profile), name: language.rawValue + "-profile", size: NSSize(width: 720, height: 610))
            try render(CSRView(model: model), name: language.rawValue + "-csr", size: NSSize(width: 570, height: 460))
            model.credentialsFor = profile.id
            try render(LoginView(model: model), name: language.rawValue + "-login", size: NSSize(width: 480, height: 420))
            model.credentialsFor = nil
        }
        // Existing rendered views must react without being recreated or losing data.
        model.page = "settings"; model.setLanguage(.english)
        let live = NSHostingView(rootView: SettingsView(model: model))
        live.frame = NSRect(x: 0, y: 0, width: 760, height: 680); window.contentView = live
        RunLoop.main.run(until: Date().addingTimeInterval(0.2))
        model.setLanguage(.ukrainian)
        RunLoop.main.run(until: Date().addingTimeInterval(0.3))
        live.layoutSubtreeIfNeeded()
        if let bitmap = live.bitmapImageRepForCachingDisplay(in: live.bounds) {
            live.cacheDisplay(in: live.bounds, to: bitmap)
            try bitmap.representation(using: .png, properties: [:])?.write(to: output.appendingPathComponent("live-switch-uk.png"))
        }
        guard try encoder.encode(model.store) == original, model.statuses[profile.id]?.state == "disconnected" else { throw VPNError("Language change modified connection data") }
        window.orderOut(nil)
        try Data("PASS: English/Ukrainian screens rendered; live switch preserved profile and session data; helper access disabled\n".utf8).write(to: output.appendingPathComponent("result.txt"))
    }
}
