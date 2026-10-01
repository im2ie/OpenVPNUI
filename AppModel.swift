import AppKit
import SwiftUI
import Network
import UserNotifications
import ServiceManagement

@MainActor final class AppModel: ObservableObject {
    @Published var store = ProfileStore()
    @Published var statuses: [String: SessionStatus] = [:]
    @Published var selected: String?
    @Published var page = "connections"
    @Published var error: String?
    @Published var busy = false
    @Published var helperAvailable = false
    @Published var serviceError = ""
    @Published var engine = "OpenVPN 2.6.23"
    @Published var helperVersion = ""
    @Published var credentialsFor: String?
    @Published var username = ""
    @Published var password = ""
    @Published var keyPassword = ""
    @Published var challengeResponse = ""
    @Published var authChoice: SavePolicy = .session
    @Published var keyChoice: SavePolicy = .session
    @Published var editing: Profile?
    @Published var certificateSelection: String?
    @Published var showingCSR = false
    @Published var logs: [String] = []
    @Published var showLog = true
    @Published var groups: [String] = []
    @Published var allowedGroups = Set<String>()
    @Published var interfaces = ""
    @Published var pendingSelection: String?
    let root = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Library/Application Support/OpenVPNUI Mac")
    var certificates: CertificateManager { CertificateManager(root: root) }
    var authSession: [String: LoginCredentials] = [:], keySession: [String: String] = [:]
    var reconnect = Set<String>(), connectQueue: [String] = []
    var timer: Timer?, monitor = NWPathMonitor(), hadNetwork = true, sleeping = false, polling = false
    var legacyMigrationNeeded = false
    var smoke: Bool { CommandLine.arguments.contains("--smoke-test") || CommandLine.arguments.contains("--preview") }
    init() {
        do {
            let file = root.appendingPathComponent("profiles.json")
            if FileManager.default.fileExists(atPath: file.path) {
                store = try JSONDecoder().decode(ProfileStore.self, from: readBounded(file, max: 16_000_000))
                legacyMigrationNeeded = store.certificates.isEmpty && FileManager.default.fileExists(atPath: root.appendingPathComponent("client.p12").path)
            }
            selected = store.profiles.first?.id
        } catch { self.error = "Не удалось прочитать профили: " + error.localizedDescription }
        timer = Timer.scheduledTimer(withTimeInterval: 1, repeats: true) { [weak self] _ in Task { @MainActor in self?.poll() } }
        NSWorkspace.shared.notificationCenter.addObserver(forName: NSWorkspace.willSleepNotification, object: nil, queue: .main) { [weak self] _ in Task { @MainActor in self?.prepareSleep() } }
        NSWorkspace.shared.notificationCenter.addObserver(forName: NSWorkspace.didWakeNotification, object: nil, queue: .main) { [weak self] _ in Task { @MainActor in self?.wake() } }
        monitor.pathUpdateHandler = { [weak self] path in Task { @MainActor in self?.networkChanged(path.status == .satisfied) } }; monitor.start(queue: DispatchQueue(label: "vpn.network"))
        DispatchQueue.main.async { self.startup() }
    }
    func startup() {
        let args = CommandLine.arguments
        if smoke { poll(); return }
        if store.preferences.notifications {
            UNUserNotificationCenter.current().getNotificationSettings { settings in
                if settings.authorizationStatus == .notDetermined { UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound]) { _, _ in } }
            }
        }
        if legacyMigrationNeeded { migrateLegacy() }
        if let index = args.firstIndex(of: "--import"), args.count > index + 1 { importPrepared(URL(fileURLWithPath: args[index + 1])); return }
        poll()
        DispatchQueue.main.asyncAfter(deadline: .now() + 2) {
            if self.error == nil { self.connectQueue += self.store.profiles.filter { ($0.settings ?? ProfileSettings()).autoStart && !self.isActive($0.id) }.map(\.id); self.nextConnection() }
        }
    }
    func save() throws {
        let target = root.appendingPathComponent("profiles.json")
        if let previous = try? readBounded(target, max: 16_000_000) { try privateWrite(previous, to: root.appendingPathComponent("profiles.previous.json")) }
        try privateWrite(JSONEncoder().encode(store), to: target)
    }
    func persist() { do { try save() } catch { self.error = error.localizedDescription } }
    func migrateLegacy() {
        do {
            let pass = try Vault.read("certificate-" + NSUserName(), service: "OpenVPNUI Mac P12")
            var record = try certificates.inspect(root.appendingPathComponent("client.p12"), password: pass); record.generatedPassword = true
            try privateWrite(readBounded(root.appendingPathComponent("client.p12")), to: certificates.identity(record.id))
            try Vault.save(pass, account: "key-" + record.id)
            let ca = try readBounded(root.appendingPathComponent("ca.pem"))
            store.certificates = [record]
            for i in store.profiles.indices { store.profiles[i].certificateID = record.id; store.profiles[i].caData = ca; store.profiles[i].settings = ProfileSettings() }
            try save(); legacyMigrationNeeded = false
        } catch { self.error = "Миграция сертификата: " + error.localizedDescription }
    }
    func work<T>(_ action: @escaping () throws -> T, then: @escaping (T) -> Void) {
        busy = true
        DispatchQueue.global(qos: .userInitiated).async {
            let result = Result(catching: action)
            Task { @MainActor in self.busy = false; switch result { case .success(let value): then(value); case .failure(let failure): self.error = failure.localizedDescription } }
        }
    }
    func request(_ value: Request, completion: @escaping (Result<Response, Error>) -> Void) {
        DispatchQueue.global(qos: .userInitiated).async { let result = Result { try helperCall(value) }; Task { @MainActor in completion(result) } }
    }
    func action(_ value: Request) {
        request(value) { result in
            switch result { case .success(let response): if !response.ok { self.error = response.error }; self.poll()
            case .failure(let failure): self.error = failure.localizedDescription }
        }
    }
    func poll() {
        guard !polling else { return }; polling = true
        request(Request(action: "status")) { result in
            self.polling = false
            switch result {
            case .success(let response):
                self.helperAvailable = response.ok; self.serviceError = response.error ?? ""; self.engine = response.engine ?? self.engine; self.helperVersion = response.helperVersion ?? "0.1.0"
                if response.ok {
                    let previous = self.statuses
                    self.statuses = Dictionary(uniqueKeysWithValues: response.sessions.map { ($0.id, $0) })
                    for status in response.sessions {
                        if previous[status.id]?.state != status.state, ["connected", "error", "disconnected"].contains(status.state), previous[status.id] != nil { self.notify(status) }
                    }
                    if self.credentialsFor == nil, let status = response.sessions.first(where: { $0.state == "credentials" && $0.challenge != nil }) { self.begin(status.id, challenge: true) }
                    if !self.sleeping && self.hadNetwork {
                        for id in Array(self.reconnect) where !self.isActive(id) { self.reconnect.remove(id); self.connectQueue.append(id) }
                        self.nextConnection()
                    }
                }
            case .failure(let failure): self.helperAvailable = false; self.serviceError = failure.localizedDescription
            }
            if let id = self.selected, self.showLog, self.statuses[id] != nil {
                self.request(Request(action: "log", id: id)) { result in if self.selected == id, case .success(let response) = result, response.ok { self.logs = response.log ?? [] } }
            }
        }
    }
    func notify(_ status: SessionStatus) {
        guard store.preferences.notifications, !smoke else { return }
        let content = UNMutableNotificationContent(); content.title = store.profiles.first { $0.id == status.id }?.name ?? "OpenVPNUI Mac"; content.body = status.message
        UNUserNotificationCenter.current().add(UNNotificationRequest(identifier: UUID().uuidString, content: content, trigger: nil)) { _ in }
    }
    func enableNotifications(_ enabled: Bool) {
        store.preferences.notifications = enabled; persist()
        if enabled { UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound]) { _, _ in } }
    }
    func autoLaunch(_ enabled: Bool) {
        do { if enabled { try SMAppService.mainApp.register() } else { try SMAppService.mainApp.unregister() }; store.preferences.autoLaunch = enabled; try save() }
        catch { self.error = "Автозапуск: " + error.localizedDescription }
    }
    func isActive(_ id: String) -> Bool { !["disconnected", "error"].contains(statuses[id]?.state ?? "disconnected") }
    func openFiles() {
        let panel = NSOpenPanel(); panel.title = "Импорт профилей .openvpn / .ovpn"; panel.allowsMultipleSelection = true
        if panel.runModal() == .OK { for url in panel.urls { importFile(url) } }
    }
    func importFile(_ url: URL) {
        do {
            let imported = try importConnectionFile(url); defer { if let temporary = imported.temporaryDirectory { try? FileManager.default.removeItem(at: temporary) } }; var profile = imported.profile
            if let certificate = imported.certificateFile {
                guard let pass = askPassword("Пароль импортируемого закрытого ключа", detail: "Для файла без пароля оставьте поле пустым.") else { return }
                let record = try certificates.importIdentity(certificate, key: imported.keyFile, password: pass)
                addCertificate(record); profile.certificateID = record.id; profile.settings?.keySave = .persistent
                for file in [imported.certificateFile, imported.keyFile].compactMap({ $0 }) where file.deletingLastPathComponent().lastPathComponent.hasPrefix("openvpn-import-") { try? FileManager.default.removeItem(at: file.deletingLastPathComponent()) }
            } else {
                profile.certificateID = store.certificates.first { $0.hasPrivateKey && $0.sha1.caseInsensitiveCompare(profile.sourceThumbprint ?? "") == .orderedSame }?.id
                if profile.certificateID == nil, let ca = profile.caData { profile.certificateID = store.certificates.first { $0.hasPrivateKey && certificates.matches($0, ca: ca) }?.id }
            }
            store.profiles.append(profile); selected = profile.id; page = "connections"; try save(); editing = profile
        } catch { self.error = error.localizedDescription }
    }
    func choosePrepared() {
        let panel = NSOpenPanel(); panel.title = "Подготовленная папка миграции"; panel.canChooseFiles = false; panel.canChooseDirectories = true
        if panel.runModal() == .OK, let url = panel.url { importPrepared(url) }
    }
    func importPrepared(_ folder: URL) {
        let manager = certificates
        work({ () -> (ProfileStore, CertificateRecord, Data) in
            var imported = try JSONDecoder().decode(ProfileStore.self, from: readBounded(folder.appendingPathComponent("mac-profiles.json"), max: 16_000_000))
            guard !imported.profiles.isEmpty, Set(imported.profiles.map(\.id)).count == imported.profiles.count else { throw VPNError("Неверный набор профилей") }
            for i in imported.profiles.indices { guard safeID(imported.profiles[i].id) else { throw VPNError("Неверный ID профиля") }; imported.profiles[i].configuration = try validatedConfiguration(imported.profiles[i].configuration); try validateDNS(imported.profiles[i].dnsRules) }
            try validateDNS(imported.observedDNS)
            let ca = try normalizedCA(readBounded(folder.appendingPathComponent("ca.pem")))
            let record = try manager.importIdentity(folder.appendingPathComponent("client.p12"), password: "")
            return (imported, record, ca)
        }) { imported, record, ca in
            self.addCertificate(record)
            for var profile in imported.profiles {
                profile.caData = ca; profile.certificateID = record.id; profile.settings = profile.settings ?? ProfileSettings()
                if let i = self.store.profiles.firstIndex(where: { $0.id == profile.id }) {
                    if self.isActive(profile.id) { self.error = "Профиль уже подключён; его настройки сохранены без замены."; continue }; self.store.profiles[i] = profile
                } else { self.store.profiles.append(profile) }
            }
            self.store.observedDNS = imported.observedDNS; self.selected = imported.profiles.first?.id; self.persist()
        }
    }
    func newProfile() {
        editing = Profile(id: UUID().uuidString.lowercased(), name: "Новое подключение", configuration: "client\ndev tun\nproto udp\nremote vpn.example.com 1194\nremote-cert-tls server\nverify-x509-name vpn.example.com name\nauth-user-pass\nnobind\npersist-key\npersist-tun\n", dnsRules: [], useSnapshotDNS: false, settings: ProfileSettings())
    }
    func saveProfile(_ profile: Profile) {
        do {
            var profile = profile
            guard !profile.name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty, !isActive(profile.id) else { throw VPNError("Отключите профиль перед изменением настроек") }
            profile.configuration = try validatedConfiguration(profile.configuration); try validateDNS(profile.dnsRules)
            let settings = profile.settings ?? ProfileSettings()
            if settings.keySave != .persistent, let record = store.certificates.first(where: { $0.id == profile.certificateID }), record.generatedPassword {
                guard changePassword(record) else { return }
            }
            if let i = store.profiles.firstIndex(where: { $0.id == profile.id }) {
                let old = store.profiles[i].settings ?? ProfileSettings()
                guard (!old.lockAutoStart || old.autoStart == settings.autoStart), (!old.lockAuthSave || old.authSave == settings.authSave), (!old.lockKeySave || old.keySave == settings.keySave) else { throw VPNError("Настройки заблокированы автором профиля") }
                store.profiles[i] = profile
            } else { store.profiles.append(profile) }
            if settings.authSave != .persistent && settings.authSave != .choose { Vault.remove("auth-" + profile.id) }
            if settings.authSave == .none { authSession.removeValue(forKey: profile.id) }
            if let id = profile.certificateID, settings.keySave == .none || settings.keySave == .session {
                if !store.profiles.contains(where: { $0.id != profile.id && $0.certificateID == id && [.persistent, .choose].contains(($0.settings ?? ProfileSettings()).keySave) }) { Vault.remove("key-" + id) }
            }
            try save(); selected = profile.id; editing = nil
        } catch { self.error = error.localizedDescription }
    }
    func duplicate(_ profile: Profile) { var copy = profile; copy.id = UUID().uuidString.lowercased(); copy.name += " — копия"; copy.settings?.autoStart = false; editing = copy }
    func deleteProfile(_ profile: Profile) {
        guard !isActive(profile.id), confirm("Удалить «\(profile.name)»?", detail: "Сертификат останется в хранилище.") else { return }
        store.profiles.removeAll { $0.id == profile.id }; authSession.removeValue(forKey: profile.id); Vault.remove("auth-" + profile.id); selected = store.profiles.first?.id; persist()
    }
    func exportProfile(_ profile: Profile) {
        let panel = NSSavePanel(); panel.title = "Экспорт профиля (.openvpn или .ovpn)"; panel.nameFieldStringValue = profile.name + ".openvpn"
        if panel.runModal() == .OK, let url = panel.url { do { var p = profile; p.sourceThumbprint = store.certificates.first { $0.id == p.certificateID }?.sha1 ?? p.sourceThumbprint; try exportConnection(p, to: url) } catch { self.error = error.localizedDescription } }
    }
    func addCertificate(_ record: CertificateRecord) { if let i = store.certificates.firstIndex(where: { $0.id == record.id }) { store.certificates[i] = record } else { store.certificates.append(record) }; certificateSelection = record.id }
    func importCertificate() {
        let panel = NSOpenPanel(); panel.title = "Сертификат P12/PFX, PEM, CER/CRT или P7B"
        guard panel.runModal() == .OK, let file = panel.url else { return }
        let ext = file.pathExtension.lowercased(); var key: URL?
        if !["p12", "pfx"].contains(ext) {
            let sibling = file.deletingPathExtension().appendingPathExtension("key")
            if FileManager.default.fileExists(atPath: sibling.path) { key = sibling }
            else {
                let alert = NSAlert(); alert.messageText = "Импорт сертификата"; alert.informativeText = "Для клиентского сертификата укажите закрытый ключ. Сертификат CA можно сохранить без ключа."; alert.addButton(withTitle: "Выбрать ключ…"); alert.addButton(withTitle: "Без ключа"); alert.addButton(withTitle: "Отмена")
                let choice = alert.runModal(); if choice == .alertThirdButtonReturn { return }; if choice == .alertFirstButtonReturn { let p = NSOpenPanel(); p.title = "Закрытый ключ PEM"; guard p.runModal() == .OK else { return }; key = p.url }
            }
        }
        let manager = certificates
        if !["p12", "pfx"].contains(ext) && key == nil { work({ try manager.inspect(file) }) { record in self.addCertificate(record); self.persist() }; return }
        guard let pass = askPassword("Пароль исходного ключа", detail: "Оставьте пустым для файла без пароля. Копия будет зашифрована; пароль сохранится в Связке ключей.") else { return }
        let sourceKey = key
        work({ try manager.importIdentity(file, key: sourceKey, password: pass) }) { record in self.addCertificate(record); self.persist() }
    }
    @discardableResult func changePassword(_ record: CertificateRecord) -> Bool {
        guard !store.profiles.contains(where: { $0.certificateID == record.id && isActive($0.id) }) else { error = "Перед сменой пароля отключите профили, использующие этот сертификат."; return false }
        do {
            let old = (try? Vault.read("key-" + record.id)) ?? askPassword("Текущий пароль сертификата", detail: record.name)
            guard let old, let fresh = askPassword("Новый пароль сертификата", detail: "Не менее 8 символов. Запомните его: он понадобится при политике «Не сохранять»."), let repeatPass = askPassword("Повторите новый пароль", detail: record.name) else { return false }
            guard fresh == repeatPass else { throw VPNError("Пароли не совпали") }
            let updated = try certificates.replacePassword(record, old: old, new: fresh); addCertificate(updated); persist(); return true
        } catch { self.error = error.localizedDescription; return false }
    }
    func deleteCertificate(_ record: CertificateRecord) {
        guard !store.profiles.contains(where: { $0.certificateID == record.id }) else { error = "Сначала снимите выбор этого сертификата во всех профилях."; return }
        guard confirm("Удалить сертификат «\(record.name)»?", detail: "Локальная копия закрытого ключа будет удалена.") else { return }
        do { let file = certificates.identity(record.id); if FileManager.default.fileExists(atPath: file.path) { try FileManager.default.removeItem(at: file) }; Vault.remove("key-" + record.id); keySession.removeValue(forKey: record.id); store.certificates.removeAll { $0.id == record.id }; persist() } catch { self.error = error.localizedDescription }
    }
    func exportCertificate(_ record: CertificateRecord, includeKey: Bool) {
        let panel = NSSavePanel(); panel.nameFieldStringValue = "certificate." + (includeKey ? "p12" : "pem")
        guard panel.runModal() == .OK, let file = panel.url else { return }
        do {
            if includeKey {
                guard let old = (try? Vault.read("key-" + record.id)) ?? askPassword("Пароль сертификата", detail: record.name), let new = askPassword("Пароль экспортируемого P12", detail: "Не менее 8 символов.") else { return }
                let tmp = root.appendingPathComponent(UUID().uuidString + ".p12"); defer { try? FileManager.default.removeItem(at: tmp) }
                _ = try certificates.call(["--protect", certificates.identity(record.id).path, tmp.path], passwords: [old, new]); try privateWrite(readBounded(tmp), to: file)
            } else { try privateWrite(Data((record.certificate + record.chain.joined(separator: "\n")).utf8), to: file) }
        } catch { self.error = error.localizedDescription }
    }
    func createCSR(fields: [String], algorithm: String) {
        let manager = certificates
        work({ try manager.createRequest(fields: fields, algorithm: algorithm) }) { request in self.store.enrollments.append(request); self.pendingSelection = request.id; self.showingCSR = false; self.persist() }
    }
    func completeCSR(_ enrollment: EnrollmentRecord) {
        let panel = NSOpenPanel(); panel.title = "Ответ CA: CER/CRT/PEM/P7B"
        guard panel.runModal() == .OK, let file = panel.url else { return }; let manager = certificates
        work({ try manager.completeRequest(enrollment, response: file) }) { record in
            self.addCertificate(record); self.store.enrollments.removeAll { $0.id == enrollment.id }; self.persist(); try? manager.deleteRequest(enrollment)
        }
    }
    func deleteCSR(_ enrollment: EnrollmentRecord) {
        guard confirm("Удалить запрос и его закрытый ключ?", detail: "Ответ CA для этого запроса больше нельзя будет импортировать.") else { return }
        do { try certificates.deleteRequest(enrollment); store.enrollments.removeAll { $0.id == enrollment.id }; persist() } catch { self.error = error.localizedDescription }
    }
    func exportText(_ text: String, name: String) { let panel = NSSavePanel(); panel.nameFieldStringValue = name; if panel.runModal() == .OK, let file = panel.url { do { try privateWrite(Data(text.utf8), to: file) } catch { self.error = error.localizedDescription } } }
    func copy(_ text: String) { NSPasteboard.general.clearContents(); NSPasteboard.general.setString(text, forType: .string) }
    func begin(_ id: String, challenge: Bool = false) {
        guard credentialsFor == nil, let profile = store.profiles.first(where: { $0.id == id }) else { return }
        guard profile.certificateID != nil, profile.caData != nil else { error = "Выберите сертификат и CA в настройках профиля."; editing = profile; return }
        let settings = profile.settings ?? ProfileSettings()
        credentialsFor = id; username = ""; password = ""; keyPassword = ""; challengeResponse = ""
        authChoice = settings.authSave == .choose ? .session : settings.authSave; keyChoice = settings.keySave == .choose ? .session : settings.keySave
        if !challenge {
            var cached: LoginCredentials?
            if settings.authSave == .session { cached = authSession[id] }
            if settings.authSave == .persistent, let raw = try? Vault.read("auth-" + id) { cached = try? JSONDecoder().decode(LoginCredentials.self, from: Data(raw.utf8)) }
            if let cached { username = cached.username; password = cached.password }
            if let certID = profile.certificateID {
                if settings.keySave == .persistent { keyPassword = (try? Vault.read("key-" + certID)) ?? "" }
                if settings.keySave == .session { keyPassword = keySession[certID] ?? "" }
            }
            if (!needsUsername(profile) || !password.isEmpty), !keyPassword.isEmpty, settings.authSave != .choose, settings.keySave != .choose { connect() }
        } else if statuses[id]?.challenge?.contains("Proxy") == true { authChoice = .none
        } else if statuses[id]?.challenge == "Private Key", let certID = profile.certificateID, settings.keySave == .persistent {
            keyPassword = (try? Vault.read("key-" + certID)) ?? ""
        }
    }
    func connect() {
        guard let id = credentialsFor, let profile = store.profiles.first(where: { $0.id == id }), let certID = profile.certificateID else { return }
        do {
            let challenge = statuses[id]?.challenge
            if keyPassword.isEmpty, keyChoice == .persistent { keyPassword = (try? Vault.read("key-" + certID)) ?? "" }
            if keyPassword.isEmpty, keyChoice == .session { keyPassword = keySession[certID] ?? "" }
            if challenge == nil && keyPassword.isEmpty { throw VPNError("Введите пароль клиентского сертификата") }
            if challenge == nil && needsUsername(profile) && (username.isEmpty || password.isEmpty) { throw VPNError("Введите логин и пароль VPN") }
            if (challenge == nil || challenge == "Auth") && !password.isEmpty {
                if authChoice == .session { authSession[id] = LoginCredentials(username: username, password: password) }
                else { authSession.removeValue(forKey: id) }
                if authChoice == .persistent { let data = try JSONEncoder().encode(LoginCredentials(username: username, password: password)); try Vault.save(String(decoding: data, as: UTF8.self), account: "auth-" + id) }
                else { Vault.remove("auth-" + id) }
            }
            if keyChoice == .session && !keyPassword.isEmpty { keySession[certID] = keyPassword }
            if keyChoice == .persistent && !keyPassword.isEmpty { try Vault.save(keyPassword, account: "key-" + certID) }
            let value = Request(action: challenge == nil ? "start" : "credentials", id: id, profile: challenge == nil ? profile : nil, ca: challenge == nil ? profile.caData : nil, p12: challenge == nil ? try readBounded(certificates.identity(certID), max: 500_000) : nil, username: username, password: password.isEmpty ? nil : password, keyPassword: keyPassword.isEmpty ? nil : keyPassword, retainAuth: authChoice != .none, retainKey: keyChoice != .none, challengeResponse: challengeResponse)
            credentialsFor = nil; password = ""; keyPassword = ""; challengeResponse = ""
            action(value)
        } catch { self.error = error.localizedDescription }
    }
    func cancelLogin() { if let id = credentialsFor, statuses[id]?.challenge != nil { stop(id) }; credentialsFor = nil; password = ""; keyPassword = ""; challengeResponse = ""; nextConnection() }
    func connectAll() { connectQueue += store.profiles.filter { !isActive($0.id) }.map(\.id); nextConnection() }
    func nextConnection() { guard credentialsFor == nil, !busy, !connectQueue.isEmpty, helperAvailable, !smoke else { return }; let id = connectQueue.removeFirst(); if !isActive(id) { begin(id) } }
    func stop(_ id: String) { reconnect.remove(id); connectQueue.removeAll { $0 == id }; action(Request(action: "stop", id: id)) }
    func stopAll() { reconnect = []; connectQueue = []; for id in statuses.keys where isActive(id) { stop(id) } }
    func prepareSleep() {
        sleeping = true
        for profile in store.profiles where isActive(profile.id) {
            if (profile.settings ?? ProfileSettings()).reconnectAfterWake { reconnect.insert(profile.id) }; action(Request(action: "stop", id: profile.id))
        }
    }
    func wake() { sleeping = false; poll() }
    func networkChanged(_ available: Bool) {
        if hadNetwork && !available && !sleeping {
            for profile in store.profiles where isActive(profile.id) {
                if (profile.settings ?? ProfileSettings()).reconnectAfterNetworkChange { reconnect.insert(profile.id) }; action(Request(action: "stop", id: profile.id))
            }
        }
        hadNetwork = available; if available { poll() }
    }
    func clearLog() { if let id = selected { action(Request(action: "clear-log", id: id)); logs = [] } }
    func loadService() {
        request(Request(action: "access")) { result in if case .success(let response) = result, response.ok { self.groups = response.groups ?? []; self.allowedGroups = Set(response.accessPolicy?.groups ?? []) } else { self.error = "Не удалось прочитать настройки доступа" } }
        do { let result = try runTool(URL(fileURLWithPath: "/sbin/ifconfig"), ["-l"]); interfaces = String(decoding: result.output, as: UTF8.self).split(whereSeparator: { $0.isWhitespace }).filter { $0.hasPrefix("utun") }.joined(separator: ", ") } catch { interfaces = error.localizedDescription }
    }
    func saveAccess() { do { let token = try administratorAuthorization(); action(Request(action: "set-access", authorization: token, accessPolicy: AccessPolicy(groups: allowedGroups.sorted()))) } catch { self.error = error.localizedDescription } }
    func restartService() { guard confirm("Перезапустить службу?", detail: "Все VPN-соединения будут отключены.") else { return }; do { action(Request(action: "restart", authorization: try administratorAuthorization())) } catch { self.error = error.localizedDescription } }
    func forgetPasswords(_ profile: Profile) { Vault.remove("auth-" + profile.id); authSession.removeValue(forKey: profile.id); if let id = profile.certificateID { keySession.removeValue(forKey: id) }; error = "Сохранённые данные VPN удалены. Пароль шифрования сертификата управляется отдельно в разделе «Сертификаты»." }
    func quit() {
        if statuses.keys.contains(where: isActive) {
            let alert = NSAlert(); alert.messageText = "Завершить OpenVPNUI Mac?"; alert.informativeText = "Соединения может поддерживать системная служба. Для запросов новых паролей и восстановления после сна оставьте приложение запущенным."; alert.addButton(withTitle: "Оставить VPN и выйти"); alert.addButton(withTitle: "Отключить VPN и выйти"); alert.addButton(withTitle: "Отмена")
            switch alert.runModal() { case .alertFirstButtonReturn: NSApp.terminate(nil); case .alertSecondButtonReturn: stopAll(); DispatchQueue.main.asyncAfter(deadline: .now() + 2) { NSApp.terminate(nil) }; default: break }
        } else { NSApp.terminate(nil) }
    }
    func confirm(_ title: String, detail: String = "") -> Bool { let alert = NSAlert(); alert.messageText = title; alert.informativeText = detail; alert.addButton(withTitle: "Продолжить"); alert.addButton(withTitle: "Отмена"); return alert.runModal() == .alertFirstButtonReturn }
    func askPassword(_ title: String, detail: String) -> String? { let alert = NSAlert(); alert.messageText = title; alert.informativeText = detail; let field = NSSecureTextField(frame: NSRect(x: 0, y: 0, width: 340, height: 24)); alert.accessoryView = field; alert.addButton(withTitle: "Продолжить"); alert.addButton(withTitle: "Отмена"); let result = alert.runModal() == .alertFirstButtonReturn ? field.stringValue : nil; field.stringValue = ""; return result }
}
