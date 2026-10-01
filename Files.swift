import Foundation
#if canImport(FoundationXML)
import FoundationXML
#endif
import Security

struct ProcessResult { let status: Int32; let output: Data; let error: Data }
func runTool(_ executable: URL, _ arguments: [String], input: Data = Data(), timeout: Double = 60, limit: Int = 2_000_000) throws -> ProcessResult {
    let process = Process(); process.executableURL = executable; process.arguments = arguments
    let stdin = Pipe(), stdout = Pipe(), stderr = Pipe(); process.standardInput = stdin; process.standardOutput = stdout; process.standardError = stderr
    let done = DispatchSemaphore(value: 0); process.terminationHandler = { _ in done.signal() }
    try process.run()
    let group = DispatchGroup(), lock = NSLock(); var output = Data(), error = Data(); var overflow = false
    for (handle, isError) in [(stdout.fileHandleForReading, false), (stderr.fileHandleForReading, true)] {
        group.enter(); DispatchQueue.global().async {
            defer { group.leave() }
            while let chunk = try? handle.read(upToCount: 16384), !chunk.isEmpty {
                lock.lock()
                if (isError ? error.count : output.count) + chunk.count > limit { overflow = true; if process.isRunning { process.terminate() } }
                else if isError { error.append(chunk) } else { output.append(chunk) }
                lock.unlock()
            }
        }
    }
    try? stdin.fileHandleForWriting.write(contentsOf: input); try? stdin.fileHandleForWriting.close()
    if done.wait(timeout: .now() + timeout) == .timedOut { if process.isRunning { process.terminate() }; if done.wait(timeout: .now() + 2) == .timedOut { kill(process.processIdentifier, SIGKILL) }; throw VPNError("Операция превысила допустимое время") }
    group.wait(); if overflow { throw VPNError("Файл превышает допустимый размер") }
    return ProcessResult(status: process.terminationStatus, output: output, error: error)
}
func readBounded(_ url: URL, max: Int = 2_000_000) throws -> Data {
    let attributes = try FileManager.default.attributesOfItem(atPath: url.path)
    guard ((attributes[.size] as? NSNumber)?.intValue ?? (max + 1)) <= max else { throw VPNError("Файл слишком большой") }
    guard attributes[.type] as? FileAttributeType == .typeRegular else { throw VPNError("Ожидается обычный файл") }
    let handle = try FileHandle(forReadingFrom: url); defer { try? handle.close() }
    let data = try handle.read(upToCount: max + 1) ?? Data()
    guard data.count <= max else { throw VPNError("Файл слишком большой") }; return data
}
func privateWrite(_ data: Data, to url: URL) throws {
    try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    try data.write(to: url, options: .atomic); guard chmod(url.path, 0o600) == 0 else { throw VPNError("Не удалось защитить локальный файл") }
}
func normalizedCA(_ data: Data) throws -> Data {
    if let text = String(data: data, encoding: .utf8), text.contains("-----BEGIN CERTIFICATE-----") { return data }
    guard SecCertificateCreateWithData(nil, data as CFData) != nil else { throw VPNError("Неверный сертификат CA") }
    return Data(("-----BEGIN CERTIFICATE-----\n" + data.base64EncodedString(options: [.lineLength64Characters, .endLineWithLineFeed]) + "\n-----END CERTIFICATE-----\n").utf8)
}

final class ConnectionXML: NSObject, XMLParserDelegate {
    var fields: [String: String] = [:]; var element = ""; var depth = 0; var error: Error?
    func parser(_ parser: XMLParser, didStartElement elementName: String, namespaceURI: String?, qualifiedName qName: String?, attributes attributeDict: [String: String]) { depth += 1; if depth > 16 { parser.abortParsing(); error = VPNError("Слишком глубокая структура XML") }; element = elementName.components(separatedBy: ":").last ?? elementName }
    func parser(_ parser: XMLParser, foundCharacters string: String) { fields[element, default: ""] += string }
    func parser(_ parser: XMLParser, didEndElement elementName: String, namespaceURI: String?, qualifiedName qName: String?) { depth -= 1; element = "" }
    func parser(_ parser: XMLParser, parseErrorOccurred parseError: Error) { error = parseError }
    func parse(_ data: Data) throws {
        guard data.count <= 512_000, let text = String(data: data, encoding: .utf8), !text.uppercased().contains("<!DOCTYPE"), !text.uppercased().contains("<!ENTITY") else { throw VPNError("Небезопасный или слишком большой XML") }
        let parser = XMLParser(data: data); parser.shouldResolveExternalEntities = false; parser.delegate = self
        guard parser.parse(), error == nil else { throw VPNError("Неверный формат config.xml") }
    }
}
func xmlEscape(_ s: String) -> String {
    s.replacingOccurrences(of: "&", with: "&amp;").replacingOccurrences(of: "<", with: "&lt;").replacingOccurrences(of: ">", with: "&gt;").replacingOccurrences(of: "\"", with: "&quot;")
}

struct ImportResult { var profile: Profile; var certificateFile: URL?; var keyFile: URL?; var temporaryDirectory: URL? }
func importConnectionFile(_ url: URL, caOverride: Data? = nil) throws -> ImportResult {
    let ext = url.pathExtension.lowercased()
    if ["openvpn", "connection"].contains(ext) {
        _ = try readBounded(url)
        let extracted = try runTool(URL(fileURLWithPath: "/usr/bin/unzip"), ["-p", url.path, "config.xml"], limit: 512_000)
        guard extracted.status == 0 else { throw VPNError("Не удалось прочитать config.xml из .openvpn") }
        let xml = ConnectionXML(); try xml.parse(extracted.output)
        guard let name = xml.fields["ConnectionName"], let configuration = xml.fields["ConfigurationData"], let encoded = xml.fields["AuthorityCertData"], let ca = Data(base64Encoded: encoded, options: .ignoreUnknownCharacters) else { throw VPNError("В .openvpn нет обязательных полей") }
        var settings = ProfileSettings()
        settings.autoStart = xml.fields["AutoStart"]?.trimmingCharacters(in: .whitespacesAndNewlines) == "true"
        settings.authSave = SavePolicy(rawValue: xml.fields["AuthSaveLevel"] ?? "None") ?? .none
        settings.keySave = SavePolicy(rawValue: xml.fields["KeyAuthSaveLevel"] ?? "None") ?? .none
        settings.lockAutoStart = xml.fields["LockAutoStart"] == "true"; settings.lockAuthSave = xml.fields["LockAuthSaveLevel"] == "true"; settings.lockKeySave = xml.fields["LockKeyAuthSaveLevel"] == "true"
        let temporary = FileManager.default.temporaryDirectory.appendingPathComponent("openvpn-unpack-" + UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: temporary) }
        let config = temporary.appendingPathComponent("connection.ovpn")
        // Native packages carry their CA separately; no external certificate paths are read.
        let stripped = try configuration.components(separatedBy: .newlines).filter { line in
            let op = try tokens(line).first ?? ""
            return !["ca", "cert", "key", "pkcs12"].contains(op)
        }.joined(separator: "\n")
        try privateWrite(Data(stripped.utf8), to: config)
        var result = try importConnectionFile(config)
        result.profile.name = name; result.profile.caData = try normalizedCA(ca); result.profile.settings = settings
        result.profile.sourceThumbprint = xml.fields["CertificateThumbPrint"]
        return result
    }
    guard ["ovpn", "conf"].contains(ext), let text = String(data: try readBounded(url), encoding: .utf8) else { throw VPNError("Поддерживаются .openvpn, .connection, .ovpn и .conf") }
    var ca: Data? = caOverride; var certificateURL: URL?; var keyURL: URL?; var assets: [String: Data] = [:]; var lines: [String] = []
    var block: String?; var content: [String] = []
    let assetNames = ["tls-auth", "tls-crypt", "tls-crypt-v2", "crl-verify", "extra-certs"]
    let temporary = FileManager.default.temporaryDirectory.appendingPathComponent("openvpn-import-" + UUID().uuidString)
    func localFile(_ path: String) -> URL { path.hasPrefix("/") ? URL(fileURLWithPath: path) : url.deletingLastPathComponent().appendingPathComponent(path) }
    for line in text.components(separatedBy: .newlines) {
        let trimmed = line.trimmingCharacters(in: .whitespaces)
        if let active = block {
            if trimmed == "</\(active)>" {
                let data = Data((content.joined(separator: "\n") + "\n").utf8)
                if active == "ca" { ca = try normalizedCA(data) }
                else if active == "cert" || active == "key" { let path = temporary.appendingPathComponent(active + ".pem"); try privateWrite(data, to: path); if active == "cert" { certificateURL = path } else { keyURL = path } }
                else { assets[active] = data; if !lines.contains(where: { (try? tokens($0).first) == active }) { lines.append(active + " [inline]") } }
                block = nil; content = []; continue
            }
            content.append(line); continue
        }
        if trimmed.hasPrefix("<"), trimmed.hasSuffix(">") {
            let type = String(trimmed.dropFirst().dropLast()); guard (["ca", "cert", "key"] + assetNames).contains(type) else { throw VPNError("Неподдерживаемый inline-блок: \(type)") }; block = type; continue
        }
        let t = try tokens(line); guard let op = t.first else { lines.append(line); continue }
        if ["ca", "cert", "key", "pkcs12"].contains(op) {
            guard t.count == 2 else { throw VPNError("Неверная ссылка на сертификат") }; if t[1] == "[inline]" { continue }
            if op == "ca", caOverride != nil { continue }
            let path = localFile(t[1]); let data = try readBounded(path)
            if op == "ca" { ca = try normalizedCA(data) } else if op == "key" { keyURL = path } else { certificateURL = path }
            continue
        }
        if assetNames.contains(op) {
            guard t.count >= 2 else { throw VPNError("Неверная ссылка на TLS-файл") }; if t[1] == "[inline]" { lines.append(line); continue }
            assets[op] = try readBounded(localFile(t[1]), max: 128_000)
            lines.append(op + " [inline]" + (t.count > 2 ? " " + t.dropFirst(2).joined(separator: " ") : "")); continue
        }
        lines.append(line)
    }
    guard block == nil else { throw VPNError("Незакрытый inline-блок") }
    let profile = Profile(id: UUID().uuidString.lowercased(), name: url.deletingPathExtension().lastPathComponent, configuration: try translatedConfiguration(lines.joined(separator: "\n")), dnsRules: [], useSnapshotDNS: false, caData: ca, settings: ProfileSettings(), assets: assets)
    return ImportResult(profile: profile, certificateFile: certificateURL, keyFile: keyURL, temporaryDirectory: temporary)
}
func translatedConfiguration(_ text: String) throws -> String {
    var lines: [String] = []
    for line in text.components(separatedBy: .newlines) {
        let t = try tokens(line); if let op = t.first, ["dev-node", "windows-driver", "cryptoapicert", "block-outside-dns", "register-dns", "ca", "cert", "key", "pkcs12"].contains(op) { continue }
        lines.append(line)
    }
    return try validatedConfiguration(lines.joined(separator: "\n"))
}
func exportConnection(_ profile: Profile, to url: URL) throws {
    guard let ca = profile.caData else { throw VPNError("В профиле не выбран CA") }
    var configuration = try profile.configuration.components(separatedBy: .newlines).map { line -> String in
        let t = try tokens(line); guard let op = t.first else { return "" }
        return ([op] + t.dropFirst().map { value in value.contains(where: { $0.isWhitespace || $0 == "\"" || $0 == "\\" }) ? ovpnQuote(value) : value }).joined(separator: " ")
    }.joined(separator: "\n")
    for (type, data) in profile.assets ?? [:] { guard let asset = String(data: data, encoding: .utf8) else { throw VPNError("TLS-файл нельзя экспортировать как текст") }; configuration += "\n<\(type)>\n" + asset + (asset.hasSuffix("\n") ? "" : "\n") + "</\(type)>\n" }
    if ["ovpn", "conf"].contains(url.pathExtension.lowercased()) {
        let text = configuration + "\n<ca>\n" + (String(data: ca, encoding: .utf8) ?? "") + "</ca>\n"
        try privateWrite(Data(text.utf8), to: url); return
    }
    let settings = profile.settings ?? ProfileSettings()
    let xml = """
    <?xml version="1.0" encoding="utf-8"?>
    <ConnectionDefinitionFile xmlns="http://schemas.datacontract.org/2004/07/Esp.Tools.OpenVPN.ConnectionFile" xmlns:i="http://www.w3.org/2001/XMLSchema-instance">
    <AuthorityCertData>\(ca.base64EncodedString())</AuthorityCertData><CertificateThumbPrint>\(xmlEscape(profile.sourceThumbprint ?? ""))</CertificateThumbPrint><ConfigurationData>\(xmlEscape(configuration))</ConfigurationData><ConnectionName>\(xmlEscape(profile.name))</ConnectionName><FileConfig><AuthSaveLevel>\(settings.authSave.rawValue)</AuthSaveLevel><AutoStart>\(settings.autoStart)</AutoStart><KeyAuthSaveLevel>\(settings.keySave.rawValue)</KeyAuthSaveLevel><Locks><LockAuthSaveLevel>\(settings.lockAuthSave)</LockAuthSaveLevel><LockAutoStart>\(settings.lockAutoStart)</LockAutoStart><LockKeyAuthSaveLevel>\(settings.lockKeySave)</LockKeyAuthSaveLevel></Locks></FileConfig></ConnectionDefinitionFile>
    """
    let temporary = FileManager.default.temporaryDirectory.appendingPathComponent("openvpn-export-" + UUID().uuidString)
    try privateWrite(Data(xml.utf8), to: temporary.appendingPathComponent("config.xml")); defer { try? FileManager.default.removeItem(at: temporary) }
    let result = try runTool(URL(fileURLWithPath: "/usr/bin/zip"), ["-j", "-", temporary.appendingPathComponent("config.xml").path], limit: 2_000_000)
    guard result.status == 0 else { throw VPNError("Не удалось создать .openvpn") }; try privateWrite(result.output, to: url)
}
