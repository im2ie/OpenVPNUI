import AppKit
import SwiftUI
import UserNotifications

struct MainView: View {
    @ObservedObject var model: AppModel
    var body: some View {
        NavigationSplitView {
            VStack(spacing: 0) {
                List(selection: $model.page) {
                    Label("Подключения", systemImage: "network").tag("connections")
                    Label("Сертификаты", systemImage: "person.badge.key").tag("certificates")
                    Label("Запросы сертификатов", systemImage: "doc.badge.plus").tag("requests")
                    Label("Настройки и служба", systemImage: "gearshape").tag("settings")
                }.frame(height: 160)
                Divider()
                List(selection: $model.selected) {
                    ForEach(model.store.profiles) { profile in
                        HStack {
                            Circle().fill(model.statuses[profile.id]?.state == "connected" ? .green : model.isActive(profile.id) ? .orange : .gray).frame(width: 8, height: 8)
                            VStack(alignment: .leading) { Text(profile.name); Text(model.statuses[profile.id]?.message ?? "Отключено").font(.caption).foregroundStyle(.secondary).lineLimit(2) }
                        }.tag(profile.id).contextMenu {
                            Button("Подключить") { model.begin(profile.id) }.disabled(model.isActive(profile.id))
                            Button("Отключить") { model.stop(profile.id) }.disabled(!model.isActive(profile.id))
                            Divider(); Button("Настройки…") { model.editing = profile }; Button("Дублировать…") { model.duplicate(profile) }; Button("Экспорт…") { model.exportProfile(profile) }; Button("Удалить…", role: .destructive) { model.deleteProfile(profile) }.disabled(model.isActive(profile.id))
                        }
                    }
                }.onChange(of: model.selected) { _, _ in model.page = "connections"; model.logs = []; model.poll() }
                HStack {
                    Menu { Button("Новый профиль…") { model.newProfile() }; Button("Импорт .openvpn / .ovpn…") { model.openFiles() }; Button("Импорт папки миграции…") { model.choosePrepared() } } label: { Label("Добавить", systemImage: "plus") }
                    Spacer()
                }.padding(12)
            }.navigationTitle("OpenVPNUI Mac").navigationSplitViewColumnWidth(min: 230, ideal: 270)
        } detail: {
            VStack(spacing: 0) {
                if !model.helperAvailable { Label(model.serviceError.isEmpty ? "Служба недоступна — установите пакет .pkg" : model.serviceError, systemImage: "exclamationmark.triangle").font(.callout).foregroundStyle(.orange).padding(12).frame(maxWidth: .infinity, alignment: .leading).background(.orange.opacity(0.07)) }
                if !model.helperVersion.isEmpty && model.helperVersion != "0.2.1" { Text("Обновите системную службу установщиком версии 0.2.1.").foregroundStyle(.orange).padding(8) }
                switch model.page {
                case "certificates": CertificatesView(model: model)
                case "requests": RequestsView(model: model)
                case "settings": SettingsView(model: model)
                default: ConnectionView(model: model)
                }
                if model.busy { HStack { ProgressView().controlSize(.small); Text("Обработка…").font(.caption); Spacer() }.padding(10) }
            }
        }.frame(minWidth: 940, minHeight: 640)
        .sheet(item: $model.editing) { ProfileEditor(model: model, profile: $0) }
        .sheet(isPresented: $model.showingCSR) { CSRView(model: model) }
        .sheet(isPresented: Binding(get: { model.credentialsFor != nil }, set: { if !$0 { model.cancelLogin() } })) { LoginView(model: model) }
        .alert("OpenVPNUI Mac", isPresented: Binding(get: { model.error != nil }, set: { if !$0 { model.error = nil } })) { Button("OK") { model.error = nil } } message: { Text(model.error ?? "") }
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
                    VStack(alignment: .leading) { Text(profile.name).font(.title2.bold()); Text(status?.message ?? "Отключено").foregroundStyle(.secondary) }
                    Spacer()
                    if model.isActive(profile.id) { Button(status?.state == "connected" ? "Отключить" : "Отменить") { model.stop(profile.id) }.disabled(status?.state == "disconnecting") }
                    else { Button("Подключить") { model.begin(profile.id) }.buttonStyle(.borderedProminent).disabled(!model.helperAvailable || model.busy) }
                    Button { model.editing = profile } label: { Image(systemName: "slider.horizontal.3") }.help("Настройки профиля").disabled(model.isActive(profile.id))
                }
                GroupBox {
                    Grid(alignment: .leading, horizontalSpacing: 24, verticalSpacing: 9) {
                        GridRow { Text("Интерфейс").foregroundStyle(.secondary); Text(status?.interface ?? "—"); Text("Адрес VPN").foregroundStyle(.secondary); Text(status?.address ?? "—") }
                        GridRow { Text("Получено").foregroundStyle(.secondary); Text(bytes(status?.bytesIn ?? 0)); Text("Отправлено").foregroundStyle(.secondary); Text(bytes(status?.bytesOut ?? 0)) }
                        GridRow { Text("Приём").foregroundStyle(.secondary); Text(bytes(UInt64(max(0, status?.rateIn ?? 0))) + "/с"); Text("Передача").foregroundStyle(.secondary); Text(bytes(UInt64(max(0, status?.rateOut ?? 0))) + "/с") }
                        if let connected = status?.connectedAt { GridRow { Text("Подключён с").foregroundStyle(.secondary); Text(connected, style: .time); Text("Сервер").foregroundStyle(.secondary); Text(status?.remoteAddress ?? "—") }; GridRow { Text("Длительность").foregroundStyle(.secondary); Text(connected, style: .timer); Text(""); Text("") } }
                    }.font(.callout).textSelection(.enabled).frame(maxWidth: .infinity, alignment: .leading).padding(5)
                }
                if let code = status?.errorCode { Label(errorTitle(code), systemImage: "exclamationmark.triangle").foregroundStyle(.orange) }
                DisclosureGroup("DNS: \(profile.useSnapshotDNS ? "правила профиля" : "параметры сервера")") {
                    let rules = status?.dns ?? (profile.useSnapshotDNS ? profile.dnsRules : [])
                    if rules.isEmpty { Text("Параметры появятся после подключения.").font(.caption).foregroundStyle(.secondary) }
                    ForEach(Array(rules.enumerated()), id: \.offset) { _, rule in HStack { Text(rule.domains.joined(separator: ", ")); Spacer(); Text(rule.servers.joined(separator: ", ")) }.font(.caption.monospaced()).textSelection(.enabled) }
                }
                HStack {
                    Toggle("Журнал", isOn: $model.showLog).toggleStyle(.switch).controlSize(.small)
                    Spacer()
                    if model.showLog {
                        Toggle("Прокрутка", isOn: Binding(get: { model.store.preferences.logAutoScroll }, set: { model.store.preferences.logAutoScroll = $0; model.persist() })).toggleStyle(.checkbox)
                        Button("−") { model.store.preferences.logFontSize = max(9, model.store.preferences.logFontSize - 1); model.persist() }.help("Уменьшить шрифт")
                        Button("+") { model.store.preferences.logFontSize = min(24, model.store.preferences.logFontSize + 1); model.persist() }.help("Увеличить шрифт")
                        Menu { Button("Копировать") { model.copy(model.logs.joined(separator: "\n")) }; Button("Сохранить…") { model.exportText(model.logs.joined(separator: "\n"), name: "openvpn.log") }; Button("Очистить") { model.clearLog() } } label: { Image(systemName: "ellipsis.circle") }
                    }
                }
                if model.showLog {
                    ScrollViewReader { proxy in
                        ScrollView([.vertical, .horizontal]) {
                            VStack(alignment: .leading, spacing: 0) {
                                Text(model.logs.isEmpty ? "Журнал соединения пуст." : model.logs.joined(separator: "\n")).font(.system(size: model.store.preferences.logFontSize, design: .monospaced)).textSelection(.enabled).frame(maxWidth: .infinity, alignment: .leading)
                                Color.clear.frame(height: 1).id("end")
                            }.padding(12)
                        }.background(Color(nsColor: .textBackgroundColor)).clipShape(RoundedRectangle(cornerRadius: 8))
                        .onChange(of: model.logs) { _, _ in if model.store.preferences.logAutoScroll { proxy.scrollTo("end", anchor: .bottom) } }
                    }
                } else { Spacer() }
                Text(model.engine + " · служба " + model.helperVersion).font(.caption).foregroundStyle(.secondary)
            }.padding(24)
        } else {
            ContentUnavailableView { Label("Подключения", systemImage: "network") } description: { Text("Добавьте файл .openvpn / .ovpn или создайте профиль.") } actions: { Button("Импортировать…") { model.openFiles() }; Button("Создать…") { model.newProfile() } }
        }
    }
    func bytes(_ value: UInt64) -> String { ByteCountFormatter.string(fromByteCount: Int64(min(value, UInt64(Int64.max))), countStyle: .binary) }
    func errorTitle(_ code: String) -> String { ["Password": "Ошибка авторизации", "Certificate": "Ошибка проверки сертификата", "HostUncontactable": "Сервер недоступен", "NoAvailableInterface": "Не удалось создать интерфейс VPN"][code] ?? code }
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
            Text("Настройки подключения").font(.title2.bold())
            TabView(selection: $tab) {
                Form {
                    TextField("Название", text: $profile.name)
                    HStack { Text(profile.caData == nil ? "CA не выбран" : "CA загружен"); Spacer(); Button("Выбрать CA…") { chooseCA() }; Button("Просмотреть CA…") { showCA() }.disabled(profile.caData == nil) }
                    Picker("Клиентский сертификат", selection: Binding(get: { profile.certificateID ?? "" }, set: { profile.certificateID = $0.isEmpty ? nil : $0 })) {
                        Text("Не выбран").tag("")
                        ForEach(model.store.certificates.filter { $0.hasPrivateKey }) { cert in Text(cert.name + (matching.contains(cert.id) ? " ✓" : " — CA/срок не подтверждён")).tag(cert.id) }
                    }
                    Text("✓ — цепочка сертификата проверена по CA профиля. Подробности и импорт доступны в разделе «Сертификаты».").font(.caption).foregroundStyle(.secondary)
                    Picker("Пароль VPN", selection: $settings.authSave) { ForEach(SavePolicy.allCases) { Text($0.title).tag($0) } }.disabled(settings.lockAuthSave)
                    Picker("Пароль ключа", selection: $settings.keySave) { ForEach(SavePolicy.allCases) { Text($0.title).tag($0) } }.disabled(settings.lockKeySave)
                    Toggle("Подключаться при запуске приложения", isOn: $settings.autoStart).disabled(settings.lockAutoStart)
                    Toggle("Восстанавливать соединение после сна", isOn: $settings.reconnectAfterWake)
                    Toggle("Восстанавливать после потери сети", isOn: $settings.reconnectAfterNetworkChange)
                    if settings.lockAutoStart || settings.lockAuthSave || settings.lockKeySave { Label("Часть настроек заблокирована автором профиля", systemImage: "lock").font(.caption) }
                    Button("Забыть сохранённые данные VPN") { model.forgetPasswords(profile) }
                }.formStyle(.grouped).tabItem { Text("Основные") }.tag(0)
                VStack(alignment: .leading, spacing: 12) {
                    Toggle("Использовать заданные DNS-правила", isOn: $profile.useSnapshotDNS)
                    Text("Одна строка: домен, домен = IP DNS, IP DNS. При выключенном параметре правила берутся с VPN-сервера.").font(.caption).foregroundStyle(.secondary)
                    TextEditor(text: $dnsText).font(.system(.body, design: .monospaced)).border(.secondary.opacity(0.3)).disabled(!profile.useSnapshotDNS)
                    Button("Взять правила из миграции Windows") { dnsText = model.store.observedDNS.map { $0.domains.joined(separator: ", ") + " = " + $0.servers.joined(separator: ", ") }.joined(separator: "\n"); profile.useSnapshotDNS = true }.disabled(model.store.observedDNS.isEmpty)
                    Toggle("Считать подключение успешным только при настроенном Split DNS", isOn: $settings.requireSplitDNS)
                }.padding(16).tabItem { Text("DNS") }.tag(1)
                VStack(alignment: .leading) {
                    Text("Конфигурация OpenVPN").font(.headline)
                    Text("Сертификаты и TLS-файлы импортируются вместе с профилем. Изменяйте сетевые параметры здесь.").font(.caption).foregroundStyle(.secondary)
                    TextEditor(text: $profile.configuration).font(.system(.body, design: .monospaced)).border(.secondary.opacity(0.3))
                    if let assets = profile.assets, !assets.isEmpty { Text("TLS-файлы: " + assets.keys.sorted().joined(separator: ", ")).font(.caption) }
                }.padding(16).tabItem { Text("OpenVPN") }.tag(2)
            }
            HStack { Spacer(); Button("Отмена") { model.editing = nil }.keyboardShortcut(.cancelAction); Button("Сохранить") { save() }.buttonStyle(.borderedProminent).keyboardShortcut(.defaultAction).disabled(model.busy || model.isActive(profile.id)) }
        }.padding(24).frame(width: 720, height: 610).onAppear { refreshMatches() }
    }
    func refreshMatches() { guard let ca = profile.caData else { matching = []; return }; matching = Set(model.store.certificates.filter { $0.hasPrivateKey && model.certificates.matches($0, ca: ca) }.map(\.id)) }
    func chooseCA() { let panel = NSOpenPanel(); panel.title = "Сертификат CA (PEM/DER)"; if panel.runModal() == .OK, let url = panel.url { do { profile.caData = try normalizedCA(readBounded(url, max: 100_000)); refreshMatches() } catch { model.error = error.localizedDescription } } }
    func showCA() { guard let ca = profile.caData else { return }; let alert = NSAlert(); alert.messageText = "Сертификат CA"; let text = NSTextView(frame: NSRect(x: 0, y: 0, width: 500, height: 240)); text.string = String(decoding: ca, as: UTF8.self); text.isEditable = false; text.font = .monospacedSystemFont(ofSize: 11, weight: .regular); let scroll = NSScrollView(frame: text.frame); scroll.documentView = text; scroll.hasVerticalScroller = true; alert.accessoryView = scroll; alert.runModal() }
    func save() {
        do {
            let lines = dnsText.components(separatedBy: .newlines).filter { !$0.trimmingCharacters(in: .whitespaces).isEmpty }
            profile.dnsRules = try lines.map { line in let pair = line.components(separatedBy: "="); guard pair.count == 2 else { throw VPNError("Формат DNS: домен = IP DNS") }; func values(_ s: String) -> [String] { s.split(whereSeparator: { $0 == "," || $0.isWhitespace }).map(String.init) }; return DNSRule(domains: values(pair[0]), servers: values(pair[1])) }
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
            Text(challenge == nil ? "Подключение VPN" : "Требуются данные авторизации").font(.title2.bold())
            Text(profile?.name ?? "").font(.headline)
            if challenge == nil { Text("Перед подключением отключите этот VPN на другой рабочей станции.").font(.callout).foregroundStyle(.secondary) }
            if challenge != "Private Key" && (challenge?.contains("Proxy") == true || (profile.map(needsUsername) ?? true)) {
                TextField(challenge?.contains("Proxy") == true ? "Логин прокси" : "Логин", text: $model.username)
                SecureField("Пароль VPN", text: $model.password)
                if settings.authSave == .choose && challenge?.contains("Proxy") != true { Picker("Сохранение пароля VPN", selection: $model.authChoice) { ForEach([SavePolicy.none, .session, .persistent]) { Text($0.title).tag($0) } } }
            }
            if challenge == nil || challenge == "Private Key" {
                SecureField("Пароль сертификата", text: $model.keyPassword)
                if settings.keySave == .choose { Picker("Сохранение пароля ключа", selection: $model.keyChoice) { ForEach([SavePolicy.none, .session, .persistent]) { Text($0.title).tag($0) } } }
                if model.keyChoice == .persistent { Text("Если пароль сертификата уже есть в Связке ключей, поле можно оставить пустым.").font(.caption).foregroundStyle(.secondary) }
            }
            if let text = model.credentialsFor.flatMap({ model.statuses[$0]?.challengeText }) { Text(text).font(.callout); SecureField("Ответ / одноразовый код", text: $model.challengeResponse) }
            HStack { Spacer(); Button("Отмена") { model.cancelLogin() }.keyboardShortcut(.cancelAction); Button("Продолжить") { model.connect() }.buttonStyle(.borderedProminent).keyboardShortcut(.defaultAction) }
        }.padding(24).frame(width: 480)
    }
}
struct CertificatesView: View {
    @ObservedObject var model: AppModel
    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack { Text("Сертификаты").font(.title2.bold()); Spacer(); Button("Импортировать…") { model.importCertificate() }.disabled(model.busy); Button("Создать запрос…") { model.showingCSR = true } }
            HSplitView {
                List(selection: $model.certificateSelection) { ForEach(model.store.certificates) { certificate in VStack(alignment: .leading) { Label(certificate.name, systemImage: certificate.hasPrivateKey ? "key.fill" : "checkmark.seal"); Text(certificate.notAfter).font(.caption).foregroundStyle(.secondary) }.tag(certificate.id) } }.frame(minWidth: 190, idealWidth: 220)
                if let certificate = model.store.certificates.first(where: { $0.id == model.certificateSelection }) {
                    ScrollView {
                        VStack(alignment: .leading, spacing: 12) {
                            Text(certificate.name).font(.title3.bold()); LabeledContent("Закрытый ключ", value: certificate.hasPrivateKey ? "Есть, P12 зашифрован" : "Нет")
                            Text("Субъект\n" + certificate.subject); Text("Издатель\n" + certificate.issuer)
                            Text("Действителен с \(certificate.notBefore)\nДо \(certificate.notAfter)")
                            Text("\(certificate.algorithm) · \(certificate.bits) бит")
                            Text("SHA-1\n" + certificate.sha1).font(.caption.monospaced()); Text("SHA-256\n" + certificate.sha256).font(.caption.monospaced())
                            DisclosureGroup("Цепочка: \(certificate.chain.count) сертификатов") { Text(certificate.chain.joined(separator: "\n")).font(.caption.monospaced()) }
                            HStack { Menu("Экспорт") { Button("Открытый сертификат…") { model.exportCertificate(certificate, includeKey: false) }; Button("P12 с закрытым ключом…") { model.exportCertificate(certificate, includeKey: true) }.disabled(!certificate.hasPrivateKey) }; Button("Сменить пароль…") { model.changePassword(certificate) }.disabled(!certificate.hasPrivateKey) }
                            Button("Удалить…", role: .destructive) { model.deleteCertificate(certificate) }
                        }.textSelection(.enabled).frame(maxWidth: .infinity, alignment: .leading).padding(16)
                    }.frame(minWidth: 340)
                } else { ContentUnavailableView("Выберите сертификат", systemImage: "person.badge.key").frame(minWidth: 340) }
            }
        }.padding(24)
    }
}
struct RequestsView: View {
    @ObservedObject var model: AppModel
    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack { Text("Запросы сертификатов").font(.title2.bold()); Spacer(); Button("Создать CSR…") { model.showingCSR = true }.disabled(model.busy) }
            Text("Закрытые ключи запросов хранятся зашифрованными. Передайте CSR своему CA и импортируйте подписанный ответ.").font(.callout).foregroundStyle(.secondary)
            List(selection: $model.pendingSelection) { ForEach(model.store.enrollments) { request in HStack { Text(request.commonName); Spacer(); Text(request.algorithm).foregroundStyle(.secondary); Text(request.createdAt, style: .date) }.tag(request.id) } }.frame(height: 150)
            if let request = model.store.enrollments.first(where: { $0.id == model.pendingSelection }) {
                ScrollView { Text(request.request).font(.body.monospaced()).textSelection(.enabled).frame(maxWidth: .infinity, alignment: .leading).padding(12) }.background(Color(nsColor: .textBackgroundColor))
                HStack { Button("Копировать CSR") { model.copy(request.request) }; Button("Сохранить CSR…") { model.exportText(request.request, name: "request.csr") }; Button("Импортировать ответ CA…") { model.completeCSR(request) }.buttonStyle(.borderedProminent).disabled(model.busy); Spacer(); Button("Удалить…", role: .destructive) { model.deleteCSR(request) } }
            } else { Spacer() }
        }.padding(24)
    }
}
struct CSRView: View {
    @ObservedObject var model: AppModel
    @State var fields = ["", "", "", "", "", "", ""]
    @State var algorithm = "RSA4096"
    let labels = ["Общее имя (CN)", "Организация", "Подразделение", "Город", "Область / штат", "Страна (2 буквы)", "Email"]
    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Запрос клиентского сертификата").font(.title2.bold())
            Form { ForEach(0..<7, id: \.self) { i in TextField(labels[i], text: $fields[i]) }; Picker("Алгоритм", selection: $algorithm) { Text("RSA 4096").tag("RSA4096"); Text("ECDSA P-384").tag("ECDSA_P384") } }
            Text("Назначение: Client Authentication. Закрытый ключ останется на этом Mac.").font(.caption).foregroundStyle(.secondary)
            HStack { Spacer(); Button("Отмена") { model.showingCSR = false }.disabled(model.busy); Button("Создать") { model.createCSR(fields: fields, algorithm: algorithm) }.buttonStyle(.borderedProminent).disabled(model.busy || fields[0].isEmpty || fields[5].count != 2) }
        }.padding(24).frame(width: 570)
    }
}
struct SettingsView: View {
    @ObservedObject var model: AppModel
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                Text("Настройки и служба").font(.title2.bold())
                GroupBox("Общие") {
                    VStack(alignment: .leading, spacing: 12) {
                        Toggle("Запускать при входе в macOS", isOn: Binding(get: { model.store.preferences.autoLaunch }, set: model.autoLaunch))
                        Toggle("Уведомлять об изменении соединения", isOn: Binding(get: { model.store.preferences.notifications }, set: model.enableNotifications))
                        Text("Автоподключение и восстановление задаются отдельно в каждом профиле.").font(.caption).foregroundStyle(.secondary)
                        Text("Интерфейсы: " + (model.interfaces.isEmpty ? "нет utun" : model.interfaces)).textSelection(.enabled)
                        Text("macOS создаёт интерфейс utun для каждого туннеля автоматически.").font(.caption).foregroundStyle(.secondary)
                    }.frame(maxWidth: .infinity, alignment: .leading).padding(8)
                }
                GroupBox("Доступ к службе") {
                    VStack(alignment: .leading, spacing: 10) {
                        Text("Разрешённые группы пользователей этого Mac. Изменение требует авторизации администратора; группа admin сохраняет доступ.").font(.callout).foregroundStyle(.secondary)
                        LazyVGrid(columns: [GridItem(.adaptive(minimum: 180), alignment: .leading)], alignment: .leading) {
                            ForEach(model.groups, id: \.self) { group in Toggle(group, isOn: Binding(get: { group == "admin" || model.allowedGroups.contains(group) }, set: { if $0 { model.allowedGroups.insert(group) } else { model.allowedGroups.remove(group) } })).disabled(group == "admin") }
                        }
                        HStack { Button("Сохранить доступ…") { model.saveAccess() }; Button("Обновить") { model.loadService() }; Spacer(); Button("Перезапустить службу…") { model.restartService() } }
                    }.padding(8)
                }
                GroupBox("О приложении") {
                    VStack(alignment: .leading, spacing: 8) {
                        Text("OpenVPNUI Mac 0.2.1 · Intel x86_64").font(.headline)
                        Text(model.engine + " · системная служба " + model.helperVersion)
                        Link("Исходный проект OpenVPNUI", destination: URL(string: "https://github.com/esptl/OpenVPNUI")!)
                        Button("Лицензии компонентов") { if let url = Bundle.main.resourceURL?.appendingPathComponent("Licenses") { NSWorkspace.shared.open(url) } }
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
            Menu(profile.name + " · " + (model.statuses[profile.id]?.message ?? "Отключено")) {
                Button(model.isActive(profile.id) ? "Отключить" : "Подключить") { if model.isActive(profile.id) { model.stop(profile.id) } else { openWindow(id: "main"); NSApp.activate(ignoringOtherApps: true); model.begin(profile.id) } }
                Button("Показать журнал") { model.selected = profile.id; model.page = "connections"; model.showLog = true; openWindow(id: "main"); NSApp.activate(ignoringOtherApps: true) }
            }
        }
        Divider(); Button("Подключить все") { openWindow(id: "main"); NSApp.activate(ignoringOtherApps: true); model.connectAll() }; Button("Отключить все") { model.stopAll() }
        Divider(); Button("Показать приложение") { openWindow(id: "main"); NSApp.activate(ignoringOtherApps: true) }; Button("Завершить…") { model.quit() }
    }
}
#if !RENDER_PREVIEW
@main struct VPNApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) var delegate
    @StateObject private var model = AppModel()
    var body: some Scene {
        Window("OpenVPNUI Mac", id: "main") { MainView(model: model).onAppear {
            if CommandLine.arguments.contains("--smoke-test") { DispatchQueue.main.asyncAfter(deadline: .now() + 3) { let ok = NSApp.windows.contains { $0.isVisible && $0.contentView != nil }; if let index = CommandLine.arguments.firstIndex(of: "--smoke-result"), CommandLine.arguments.count > index + 1 { try? Data((ok ? "PASS: window created, no VPN requested\n" : "FAIL\n").utf8).write(to: URL(fileURLWithPath: CommandLine.arguments[index + 1])) }; NSApp.terminate(nil) } }
        } }.defaultSize(width: 1120, height: 760).commands {
            CommandGroup(replacing: .appTermination) { Button("Завершить OpenVPNUI Mac…") { model.quit() }.keyboardShortcut("q") }
            CommandGroup(after: .newItem) { Button("Импортировать профиль…") { model.openFiles() }.keyboardShortcut("o"); Button("Новое подключение…") { model.newProfile() }.keyboardShortcut("n") }
        }
        MenuBarExtra("OpenVPNUI Mac", systemImage: model.statuses.values.contains { $0.state == "connected" } ? "lock.shield.fill" : model.statuses.keys.contains(where: model.isActive) ? "arrow.triangle.2.circlepath" : "shield") { TrayView(model: model) }
    }
}
#endif
