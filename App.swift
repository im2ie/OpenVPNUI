import AppKit
import SwiftUI
import UserNotifications

struct MainView: View {
    @ObservedObject var model: AppModel
    var body: some View {
        NavigationSplitView {
            VStack(spacing: 0) {
                List(selection: $model.page) {
                    Label(L("Connections"), systemImage: "network").tag("connections")
                    Label(L("Certificates"), systemImage: "person.badge.key").tag("certificates")
                    Label(L("Certificate requests"), systemImage: "doc.badge.plus").tag("requests")
                    Label(L("Settings and service"), systemImage: "gearshape").tag("settings")
                }.frame(height: 160)
                Divider()
                List(selection: $model.selected) {
                    ForEach(model.store.profiles) { profile in
                        HStack {
                            Circle().fill(model.statuses[profile.id]?.state == "connected" ? .green : model.isActive(profile.id) ? .orange : .gray).frame(width: 8, height: 8)
                            VStack(alignment: .leading) { Text(profile.name); Text(model.statuses[profile.id]?.localizedMessage ?? L("Disconnected")).font(.caption).foregroundStyle(.secondary).lineLimit(2) }
                        }.tag(profile.id).contextMenu {
                            Button(L("Connect")) { model.begin(profile.id) }.disabled(model.isActive(profile.id))
                            Button(L("Disconnect")) { model.stop(profile.id) }.disabled(!model.isActive(profile.id))
                            Divider(); Button(L("Settings…")) { model.editing = profile }; Button(L("Duplicate…")) { model.duplicate(profile) }; Button(L("Export…")) { model.exportProfile(profile) }; Button(L("Delete…"), role: .destructive) { model.deleteProfile(profile) }.disabled(model.isActive(profile.id))
                        }
                    }
                }.onChange(of: model.selected) { _, _ in model.page = "connections"; model.logs = []; model.poll() }
                HStack {
                    Menu { Button(L("New profile…")) { model.newProfile() }; Button(L("Import .openvpn / .ovpn…")) { model.openFiles() }; Button(L("Import migration folder…")) { model.choosePrepared() } } label: { Label(L("Add"), systemImage: "plus") }
                    Spacer()
                }.padding(12)
            }.navigationTitle("OpenVPNUI Mac").navigationSplitViewColumnWidth(min: 230, ideal: 270)
        } detail: {
            VStack(spacing: 0) {
                if !model.helperAvailable { Label(model.serviceError.isEmpty ? L("Service unavailable — install the .pkg package") : Localization.message(model.serviceError), systemImage: "exclamationmark.triangle").font(.callout).foregroundStyle(.orange).padding(12).frame(maxWidth: .infinity, alignment: .leading).background(.orange.opacity(0.07)) }
                if !model.helperVersion.isEmpty && model.helperVersion != "0.2.3" { Text(L("Update the system service using the version 0.2.3 installer.")).foregroundStyle(.orange).padding(8) }
                switch model.page {
                case "certificates": CertificatesView(model: model)
                case "requests": RequestsView(model: model)
                case "settings": SettingsView(model: model)
                default: ConnectionView(model: model)
                }
                if model.busy { HStack { ProgressView().controlSize(.small); Text(L("Processing…")).font(.caption); Spacer() }.padding(10) }
            }
        }.frame(minWidth: 940, minHeight: 640)
        .sheet(item: $model.editing) { ProfileEditor(model: model, profile: $0) }
        .sheet(isPresented: $model.showingCSR) { CSRView(model: model) }
        .sheet(isPresented: Binding(get: { model.credentialsFor != nil }, set: { if !$0 { model.cancelLogin() } })) { LoginView(model: model) }
        .alert("OpenVPNUI Mac", isPresented: Binding(get: { model.error != nil }, set: { if !$0 { model.error = nil } })) { Button("OK") { model.error = nil } } message: { Text(Localization.message(model.error ?? "")) }
        .onOpenURL { url in
            if url.scheme == "openvpnui", url.host == "connect" { let id = url.lastPathComponent; if safeID(id) { model.selected = id; model.page = "connections"; model.begin(id) } }
            else if url.isFileURL { model.importFile(url) }
        }
    }
}
struct ConnectionView: View {
    @ObservedObject var model: AppModel
    var body: some View {
        if let profile = model.store.profiles.first(where: { $0.id == model.selected }) {
            let status = model.statuses[profile.id]
            VStack(alignment: .leading, spacing: 16) {
                HStack {
                    Image(systemName: status?.state == "connected" ? "lock.shield.fill" : "shield").font(.system(size: 32)).foregroundStyle(status?.state == "connected" ? .green : .blue)
                    VStack(alignment: .leading) { Text(profile.name).font(.title2.bold()); Text(status?.localizedMessage ?? L("Disconnected")).foregroundStyle(.secondary) }
                    Spacer()
                    if model.isActive(profile.id) { Button(status?.state == "connected" ? L("Disconnect") : L("Cancel")) { model.stop(profile.id) }.disabled(status?.state == "disconnecting") }
                    else { Button(L("Connect")) { model.begin(profile.id) }.buttonStyle(.borderedProminent).disabled(!model.helperAvailable || model.busy) }
                    Button { model.editing = profile } label: { Image(systemName: "slider.horizontal.3") }.help(L("Profile settings")).disabled(model.isActive(profile.id))
                }
                GroupBox {
                    Grid(alignment: .leading, horizontalSpacing: 24, verticalSpacing: 9) {
                        GridRow { Text(L("Interface")).foregroundStyle(.secondary); Text(status?.interface ?? "—"); Text(L("VPN address")).foregroundStyle(.secondary); Text(status?.address ?? "—") }
                        GridRow { Text(L("Received")).foregroundStyle(.secondary); Text(bytes(status?.bytesIn ?? 0)); Text(L("Sent")).foregroundStyle(.secondary); Text(bytes(status?.bytesOut ?? 0)) }
                        GridRow { Text(L("Download")).foregroundStyle(.secondary); Text(bytes(UInt64(max(0, status?.rateIn ?? 0))) + L("/s")); Text(L("Upload")).foregroundStyle(.secondary); Text(bytes(UInt64(max(0, status?.rateOut ?? 0))) + L("/s")) }
                        if let connected = status?.connectedAt { GridRow { Text(L("Connected since")).foregroundStyle(.secondary); Text(connected, style: .time); Text(L("Server")).foregroundStyle(.secondary); Text(status?.remoteAddress ?? "—") }; GridRow { Text(L("Duration")).foregroundStyle(.secondary); Text(connected, style: .timer); Text(""); Text("") } }
                    }.font(.callout).textSelection(.enabled).frame(maxWidth: .infinity, alignment: .leading).padding(5)
                }
                if let code = status?.errorCode { Label(errorTitle(code), systemImage: "exclamationmark.triangle").foregroundStyle(.orange) }
                DisclosureGroup(L("DNS: {0}", String(describing: profile.useSnapshotDNS ? L("profile rules") : L("server settings")))) {
                    let rules = status?.dns ?? (profile.useSnapshotDNS ? profile.dnsRules : [])
                    if rules.isEmpty { Text(L("Settings will appear after connecting.")).font(.caption).foregroundStyle(.secondary) }
                    ForEach(Array(rules.enumerated()), id: \.offset) { _, rule in HStack { Text(rule.domains.joined(separator: ", ")); Spacer(); Text(rule.servers.joined(separator: ", ")) }.font(.caption.monospaced()).textSelection(.enabled) }
                }
                HStack {
                    Toggle(L("Log"), isOn: $model.showLog).toggleStyle(.switch).controlSize(.small)
                    Spacer()
                    if model.showLog {
                        Toggle(L("Auto-scroll"), isOn: Binding(get: { model.store.preferences.logAutoScroll }, set: { model.store.preferences.logAutoScroll = $0; model.persist() })).toggleStyle(.checkbox)
                        Button("−") { model.store.preferences.logFontSize = max(9, model.store.preferences.logFontSize - 1); model.persist() }.help(L("Decrease font size"))
                        Button("+") { model.store.preferences.logFontSize = min(24, model.store.preferences.logFontSize + 1); model.persist() }.help(L("Increase font size"))
                        Menu { Button(L("Copy")) { model.copy(model.logs.joined(separator: "\n")) }; Button(L("Save…")) { model.exportText(model.logs.joined(separator: "\n"), name: "openvpn.log") }; Button(L("Clear")) { model.clearLog() } } label: { Image(systemName: "ellipsis.circle") }
                    }
                }
                if model.showLog {
                    ScrollViewReader { proxy in
                        ScrollView([.vertical, .horizontal]) {
                            VStack(alignment: .leading, spacing: 0) {
                                Text(model.logs.isEmpty ? L("The connection log is empty.") : model.logs.joined(separator: "\n")).font(.system(size: model.store.preferences.logFontSize, design: .monospaced)).textSelection(.enabled).frame(maxWidth: .infinity, alignment: .leading)
                                Color.clear.frame(height: 1).id("end")
                            }.padding(12)
                        }.background(Color(nsColor: .textBackgroundColor)).clipShape(RoundedRectangle(cornerRadius: 8))
                        .onChange(of: model.logs) { _, _ in if model.store.preferences.logAutoScroll { proxy.scrollTo("end", anchor: .bottom) } }
                    }
                } else { Spacer() }
                Text(model.engine + L(" · service ") + model.helperVersion).font(.caption).foregroundStyle(.secondary)
            }.padding(24)
        } else {
            ContentUnavailableView { Label(L("Connections"), systemImage: "network") } description: { Text(L("Add an .openvpn / .ovpn file or create a profile.")) } actions: { Button(L("Import…")) { model.openFiles() }; Button(L("Create…")) { model.newProfile() } }
        }
    }
    func bytes(_ value: UInt64) -> String { ByteCountFormatter.string(fromByteCount: Int64(min(value, UInt64(Int64.max))), countStyle: .binary) }
    func errorTitle(_ code: String) -> String { ["Password": L("Authentication failed"), "Certificate": L("Certificate verification failed"), "HostUncontactable": L("Server unreachable"), "NoAvailableInterface": L("Could not create the VPN interface")][code] ?? code }
}

struct ProfileEditor: View {
    @ObservedObject var model: AppModel
    @State var profile: Profile
    @State var settings: ProfileSettings
    @State var dnsText: String
    @State var tab = 0
    @State var matching = Set<String>()
    init(model: AppModel, profile: Profile) { self.model = model; _profile = State(initialValue: profile); _settings = State(initialValue: profile.settings ?? ProfileSettings()); _dnsText = State(initialValue: profile.dnsRules.map { $0.domains.joined(separator: ", ") + " = " + $0.servers.joined(separator: ", ") }.joined(separator: "\n")) }
    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text(L("Connection settings")).font(.title2.bold())
            TabView(selection: $tab) {
                Form {
                    TextField(L("Name"), text: $profile.name)
                    HStack { Text(profile.caData == nil ? L("No CA selected") : L("CA loaded")); Spacer(); Button(L("Choose CA…")) { chooseCA() }; Button(L("View CA…")) { showCA() }.disabled(profile.caData == nil) }
                    Picker(L("Client certificate"), selection: Binding(get: { profile.certificateID ?? "" }, set: { profile.certificateID = $0.isEmpty ? nil : $0 })) {
                        Text(L("Not selected")).tag("")
                        ForEach(model.store.certificates.filter { $0.hasPrivateKey }) { cert in Text(cert.name + (matching.contains(cert.id) ? " ✓" : L(" — CA/validity not verified"))).tag(cert.id) }
                    }
                    Text(L("✓ — The certificate chain was verified against the profile CA. View details and import certificates under Certificates.")).font(.caption).foregroundStyle(.secondary)
                    Picker(L("VPN password"), selection: $settings.authSave) { ForEach(SavePolicy.allCases) { Text($0.title).tag($0) } }.disabled(settings.lockAuthSave)
                    Picker(L("Key password"), selection: $settings.keySave) { ForEach(SavePolicy.allCases) { Text($0.title).tag($0) } }.disabled(settings.lockKeySave)
                    Toggle(L("Connect when the app starts"), isOn: $settings.autoStart).disabled(settings.lockAutoStart)
                    Toggle(L("Reconnect after sleep"), isOn: $settings.reconnectAfterWake)
                    Toggle(L("Reconnect after a network interruption"), isOn: $settings.reconnectAfterNetworkChange)
                    if settings.lockAutoStart || settings.lockAuthSave || settings.lockKeySave { Label(L("Some settings are locked by the profile author"), systemImage: "lock").font(.caption) }
                    Button(L("Forget saved VPN credentials")) { model.forgetPasswords(profile) }
                }.formStyle(.grouped).tabItem { Text(L("General")) }.tag(0)
                VStack(alignment: .leading, spacing: 12) {
                    Toggle(L("Use custom DNS rules"), isOn: $profile.useSnapshotDNS)
                    Text(L("One line per rule: domain, domain = DNS IP, DNS IP. When disabled, rules come from the VPN server.")).font(.caption).foregroundStyle(.secondary)
                    TextEditor(text: $dnsText).font(.system(.body, design: .monospaced)).border(.secondary.opacity(0.3)).disabled(!profile.useSnapshotDNS)
                    Button(L("Use rules from Windows migration")) { dnsText = model.store.observedDNS.map { $0.domains.joined(separator: ", ") + " = " + $0.servers.joined(separator: ", ") }.joined(separator: "\n"); profile.useSnapshotDNS = true }.disabled(model.store.observedDNS.isEmpty)
                    Toggle(L("Require configured Split DNS for a successful connection"), isOn: $settings.requireSplitDNS)
                }.padding(16).tabItem { Text("DNS") }.tag(1)
                VStack(alignment: .leading) {
                    Text(L("OpenVPN configuration")).font(.headline)
                    Text(L("Certificates and TLS files are imported with the profile. Edit network settings here.")).font(.caption).foregroundStyle(.secondary)
                    TextEditor(text: $profile.configuration).font(.system(.body, design: .monospaced)).border(.secondary.opacity(0.3))
                    if let assets = profile.assets, !assets.isEmpty { Text(L("TLS files: ") + assets.keys.sorted().joined(separator: ", ")).font(.caption) }
                }.padding(16).tabItem { Text("OpenVPN") }.tag(2)
            }
            HStack { Spacer(); Button(L("Cancel")) { model.editing = nil }.keyboardShortcut(.cancelAction); Button(L("Save")) { save() }.buttonStyle(.borderedProminent).keyboardShortcut(.defaultAction).disabled(model.busy || model.isActive(profile.id)) }
        }.padding(24).frame(width: 720, height: 610).onAppear { refreshMatches() }
    }
    func refreshMatches() { guard let ca = profile.caData else { matching = []; return }; matching = Set(model.store.certificates.filter { $0.hasPrivateKey && model.certificates.matches($0, ca: ca) }.map(\.id)) }
    func chooseCA() { let panel = NSOpenPanel(); panel.title = L("CA certificate (PEM/DER)"); panel.prompt = L("Choose"); if panel.runModal() == .OK, let url = panel.url { do { profile.caData = try normalizedCA(readBounded(url, max: 100_000)); refreshMatches() } catch { model.error = error.localizedDescription } } }
    func showCA() { guard let ca = profile.caData else { return }; let alert = NSAlert(); alert.messageText = L("CA certificate"); let text = NSTextView(frame: NSRect(x: 0, y: 0, width: 500, height: 240)); text.string = String(decoding: ca, as: UTF8.self); text.isEditable = false; text.font = .monospacedSystemFont(ofSize: 11, weight: .regular); let scroll = NSScrollView(frame: text.frame); scroll.documentView = text; scroll.hasVerticalScroller = true; alert.accessoryView = scroll; alert.runModal() }
    func save() {
        do {
            let lines = dnsText.components(separatedBy: .newlines).filter { !$0.trimmingCharacters(in: .whitespaces).isEmpty }
            profile.dnsRules = try lines.map { line in let pair = line.components(separatedBy: "="); guard pair.count == 2 else { throw VPNError("DNS format: domain = DNS IP") }; func values(_ s: String) -> [String] { s.split(whereSeparator: { $0 == "," || $0.isWhitespace }).map(String.init) }; return DNSRule(domains: values(pair[0]), servers: values(pair[1])) }
            profile.settings = settings; model.saveProfile(profile)
        } catch { model.error = error.localizedDescription }
    }
}

struct LoginView: View {
    @ObservedObject var model: AppModel
    var body: some View {
        let profile = model.store.profiles.first { $0.id == model.credentialsFor }
        let challenge = model.credentialsFor.flatMap { model.statuses[$0]?.challenge }
        let settings = profile?.settings ?? ProfileSettings()
        VStack(alignment: .leading, spacing: 16) {
            Text(challenge == nil ? L("VPN connection") : L("Credentials required")).font(.title2.bold())
            Text(profile?.name ?? "").font(.headline)
            if challenge == nil { Text(L("Before connecting, disconnect this VPN on your other workstation.")).font(.callout).foregroundStyle(.secondary) }
            if challenge != "Private Key" && (challenge?.contains("Proxy") == true || (profile.map(needsUsername) ?? true)) {
                TextField(challenge?.contains("Proxy") == true ? L("Proxy username") : L("Username"), text: $model.username)
                SecureField(L("VPN password"), text: $model.password)
                if settings.authSave == .choose && challenge?.contains("Proxy") != true { Picker(L("Save VPN password"), selection: $model.authChoice) { ForEach([SavePolicy.none, .session, .persistent]) { Text($0.title).tag($0) } } }
            }
            if challenge == nil || challenge == "Private Key" {
                SecureField(L("Certificate password"), text: $model.keyPassword)
                if settings.keySave == .choose { Picker(L("Save key password"), selection: $model.keyChoice) { ForEach([SavePolicy.none, .session, .persistent]) { Text($0.title).tag($0) } } }
                if model.keyChoice == .persistent { Text(L("If the certificate password is already in Keychain, you can leave this field empty.")).font(.caption).foregroundStyle(.secondary) }
            }
            if let text = model.credentialsFor.flatMap({ model.statuses[$0]?.challengeText }) { Text(text).font(.callout); SecureField(L("Response / one-time code"), text: $model.challengeResponse) }
            HStack { Spacer(); Button(L("Cancel")) { model.cancelLogin() }.keyboardShortcut(.cancelAction); Button(L("Continue")) { model.connect() }.buttonStyle(.borderedProminent).keyboardShortcut(.defaultAction) }
        }.padding(24).frame(width: 480)
    }
}
struct CertificatesView: View {
    @ObservedObject var model: AppModel
    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack { Text(L("Certificates")).font(.title2.bold()); Spacer(); Button(L("Import…")) { model.importCertificate() }.disabled(model.busy); Button(L("Create request…")) { model.showingCSR = true } }
            HSplitView {
                List(selection: $model.certificateSelection) { ForEach(model.store.certificates) { certificate in VStack(alignment: .leading) { Label(certificate.name, systemImage: certificate.hasPrivateKey ? "key.fill" : "checkmark.seal"); Text(certificate.notAfter).font(.caption).foregroundStyle(.secondary) }.tag(certificate.id) } }.frame(minWidth: 190, idealWidth: 220)
                if let certificate = model.store.certificates.first(where: { $0.id == model.certificateSelection }) {
                    ScrollView {
                        VStack(alignment: .leading, spacing: 12) {
                            Text(certificate.name).font(.title3.bold()); LabeledContent(L("Private key"), value: certificate.hasPrivateKey ? L("Present, P12 encrypted") : L("None"))
                            Text(L("Subject\n") + certificate.subject); Text(L("Issuer\n") + certificate.issuer)
                            Text(L("Valid from {0}\nUntil {1}", String(describing: certificate.notBefore), String(describing: certificate.notAfter)))
                            Text(L("{0} · {1} bits", String(describing: certificate.algorithm), String(describing: certificate.bits)))
                            Text("SHA-1\n" + certificate.sha1).font(.caption.monospaced()); Text("SHA-256\n" + certificate.sha256).font(.caption.monospaced())
                            DisclosureGroup(L("Certificate chain: {0}", String(describing: certificate.chain.count))) { Text(certificate.chain.joined(separator: "\n")).font(.caption.monospaced()) }
                            HStack { Menu(L("Export")) { Button(L("Public certificate…")) { model.exportCertificate(certificate, includeKey: false) }; Button(L("P12 with private key…")) { model.exportCertificate(certificate, includeKey: true) }.disabled(!certificate.hasPrivateKey) }; Button(L("Change password…")) { model.changePassword(certificate) }.disabled(!certificate.hasPrivateKey) }
                            Button(L("Delete…"), role: .destructive) { model.deleteCertificate(certificate) }
                        }.textSelection(.enabled).frame(maxWidth: .infinity, alignment: .leading).padding(16)
                    }.frame(minWidth: 340)
                } else { ContentUnavailableView(L("Select a certificate"), systemImage: "person.badge.key").frame(minWidth: 340) }
            }
        }.padding(24)
    }
}
struct RequestsView: View {
    @ObservedObject var model: AppModel
    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack { Text(L("Certificate requests")).font(.title2.bold()); Spacer(); Button(L("Create CSR…")) { model.showingCSR = true }.disabled(model.busy) }
            Text(L("Request private keys are stored encrypted. Send the CSR to your CA and import the signed response.")).font(.callout).foregroundStyle(.secondary)
            List(selection: $model.pendingSelection) { ForEach(model.store.enrollments) { request in HStack { Text(request.commonName); Spacer(); Text(request.algorithm).foregroundStyle(.secondary); Text(request.createdAt, style: .date) }.tag(request.id) } }.frame(height: 150)
            if let request = model.store.enrollments.first(where: { $0.id == model.pendingSelection }) {
                ScrollView { Text(request.request).font(.body.monospaced()).textSelection(.enabled).frame(maxWidth: .infinity, alignment: .leading).padding(12) }.background(Color(nsColor: .textBackgroundColor))
                HStack { Button(L("Copy CSR")) { model.copy(request.request) }; Button(L("Save CSR…")) { model.exportText(request.request, name: "request.csr") }; Button(L("Import CA response…")) { model.completeCSR(request) }.buttonStyle(.borderedProminent).disabled(model.busy); Spacer(); Button(L("Delete…"), role: .destructive) { model.deleteCSR(request) } }
            } else { Spacer() }
        }.padding(24)
    }
}
struct CSRView: View {
    @ObservedObject var model: AppModel
    @State var fields = ["", "", "", "", "", "", ""]
    @State var algorithm = "RSA4096"
    var labels: [String] { [L("Common name (CN)"), L("Organization"), L("Organizational unit"), L("City"), L("State / province"), L("Country (2 letters)"), L("Email")] }
    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text(L("Client certificate request")).font(.title2.bold())
            Form { ForEach(0..<7, id: \.self) { i in TextField(labels[i], text: $fields[i]) }; Picker(L("Algorithm"), selection: $algorithm) { Text("RSA 4096").tag("RSA4096"); Text("ECDSA P-384").tag("ECDSA_P384") } }
            Text(L("Purpose: Client Authentication. The private key stays on this Mac.")).font(.caption).foregroundStyle(.secondary)
            HStack { Spacer(); Button(L("Cancel")) { model.showingCSR = false }.disabled(model.busy); Button(L("Create")) { model.createCSR(fields: fields, algorithm: algorithm) }.buttonStyle(.borderedProminent).disabled(model.busy || fields[0].isEmpty || fields[5].count != 2) }
        }.padding(24).frame(width: 570)
    }
}
struct SettingsView: View {
    @ObservedObject var model: AppModel
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                Text(L("Settings and service")).font(.title2.bold())
                GroupBox(L("General")) {
                    VStack(alignment: .leading, spacing: 12) {
                        Picker(L("Language"), selection: Binding(get: { model.language }, set: model.setLanguage)) {
                            ForEach(AppLanguage.allCases) { Text($0.name).tag($0) }
                        }
                        Text(L("Some macOS menus and dialogs use the selected language after restarting the app.")).font(.caption).foregroundStyle(.secondary)
                        Toggle(L("Launch at macOS login"), isOn: Binding(get: { model.store.preferences.autoLaunch }, set: model.autoLaunch))
                        Toggle(L("Notify when connection status changes"), isOn: Binding(get: { model.store.preferences.notifications }, set: model.enableNotifications))
                        Text(L("Configure automatic connection and recovery separately for each profile.")).font(.caption).foregroundStyle(.secondary)
                        Text(L("Interfaces: ") + (model.interfaces.isEmpty ? L("no utun interfaces") : model.interfaces)).textSelection(.enabled)
                        Text(L("macOS creates a utun interface automatically for each tunnel.")).font(.caption).foregroundStyle(.secondary)
                    }.frame(maxWidth: .infinity, alignment: .leading).padding(8)
                }
                GroupBox(L("Service access")) {
                    VStack(alignment: .leading, spacing: 10) {
                        Text(L("Allowed user groups on this Mac. Changes require administrator authorization; the admin group always retains access.")).font(.callout).foregroundStyle(.secondary)
                        LazyVGrid(columns: [GridItem(.adaptive(minimum: 180), alignment: .leading)], alignment: .leading) {
                            ForEach(model.groups, id: \.self) { group in Toggle(group, isOn: Binding(get: { group == "admin" || model.allowedGroups.contains(group) }, set: { if $0 { model.allowedGroups.insert(group) } else { model.allowedGroups.remove(group) } })).disabled(group == "admin") }
                        }
                        HStack { Button(L("Save access settings…")) { model.saveAccess() }; Button(L("Refresh")) { model.loadService() }; Spacer(); Button(L("Restart service…")) { model.restartService() } }
                    }.padding(8)
                }
                GroupBox(L("About")) {
                    VStack(alignment: .leading, spacing: 8) {
                        Text("OpenVPNUI Mac 0.2.3 · Intel x86_64").font(.headline)
                        Text(model.engine + L(" · system service ") + model.helperVersion)
                        Link(L("Original OpenVPNUI project"), destination: URL(string: "https://github.com/esptl/OpenVPNUI")!)
                        Button(L("Component licenses")) { if let url = Bundle.main.resourceURL?.appendingPathComponent("Licenses") { NSWorkspace.shared.open(url) } }
                    }.frame(maxWidth: .infinity, alignment: .leading).padding(8)
                }
            }.padding(24)
        }.onAppear { model.loadService() }
    }
}
final class AppDelegate: NSObject, NSApplicationDelegate, UNUserNotificationCenterDelegate {
    func applicationDidFinishLaunching(_ notification: Notification) { UNUserNotificationCenter.current().delegate = self }
    func userNotificationCenter(_ center: UNUserNotificationCenter, willPresent notification: UNNotification, withCompletionHandler completionHandler: @escaping (UNNotificationPresentationOptions) -> Void) { completionHandler([.banner, .sound]) }
}
struct TrayView: View {
    @ObservedObject var model: AppModel
    @Environment(\.openWindow) var openWindow
    var body: some View {
        ForEach(model.store.profiles) { profile in
            Menu(profile.name + " · " + (model.statuses[profile.id]?.localizedMessage ?? L("Disconnected"))) {
                Button(model.isActive(profile.id) ? L("Disconnect") : L("Connect")) { if model.isActive(profile.id) { model.stop(profile.id) } else { openWindow(id: "main"); NSApp.activate(ignoringOtherApps: true); model.begin(profile.id) } }
                Button(L("Show log")) { model.selected = profile.id; model.page = "connections"; model.showLog = true; openWindow(id: "main"); NSApp.activate(ignoringOtherApps: true) }
            }
        }
        Divider(); Button(L("Connect all")) { openWindow(id: "main"); NSApp.activate(ignoringOtherApps: true); model.connectAll() }; Button(L("Disconnect all")) { model.stopAll() }
        Divider(); Button(L("Show app")) { openWindow(id: "main"); NSApp.activate(ignoringOtherApps: true) }; Button(L("Quit…")) { model.quit() }
    }
}
#if !RENDER_PREVIEW
@main struct VPNApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) var delegate
    @StateObject private var model = AppModel()
    init() { Localization.configure() }
    var body: some Scene {
        Window("OpenVPNUI Mac", id: "main") { MainView(model: model).environment(\.locale, model.language.locale).onAppear {
            if CommandLine.arguments.contains("--smoke-test") { DispatchQueue.main.asyncAfter(deadline: .now() + 3) { let ok = NSApp.windows.contains { $0.isVisible && $0.contentView != nil }; if let index = CommandLine.arguments.firstIndex(of: "--smoke-result"), CommandLine.arguments.count > index + 1 { try? Data((ok ? "PASS: window created, no VPN requested\n" : "FAIL\n").utf8).write(to: URL(fileURLWithPath: CommandLine.arguments[index + 1])) }; NSApp.terminate(nil) } }
        } }.defaultSize(width: 1120, height: 760).commands {
            CommandGroup(replacing: .appTermination) { Button(L("Quit OpenVPNUI Mac…")) { model.quit() }.keyboardShortcut("q") }
            CommandGroup(after: .newItem) { Button(L("Import profile…")) { model.openFiles() }.keyboardShortcut("o"); Button(L("New connection…")) { model.newProfile() }.keyboardShortcut("n") }
        }
        MenuBarExtra("OpenVPNUI Mac", systemImage: model.statuses.values.contains { $0.state == "connected" } ? "lock.shield.fill" : model.statuses.keys.contains(where: model.isActive) ? "arrow.triangle.2.circlepath" : "shield") { TrayView(model: model).environment(\.locale, model.language.locale) }
    }
}
#endif
