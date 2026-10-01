import Foundation
import Darwin

let helperID = "com.local.openvpnui.helper"
let installRoot = "/Library/Application Support/OpenVPNUI Mac"
let socketPath = "/var/run/openvpnui-mac.sock"
let runtimeRoot = "/var/run/openvpnui-mac"

struct VPNError: Error, LocalizedError {
    let text: String
    init(_ text: String) { self.text = text }
    var errorDescription: String? { text }
}
struct DNSRule: Codable, Equatable {
    var domains: [String]
    var servers: [String]
}
struct Profile: Codable, Identifiable {
    var id: String
    var name: String
    var configuration: String
    var dnsRules: [DNSRule]
    var useSnapshotDNS: Bool
    var caData: Data?
    var certificateID: String?
    var settings: ProfileSettings?
    var assets: [String: Data]?
    var sourceThumbprint: String?
}
struct ProfileStore: Codable {
    var profiles: [Profile]
    var observedDNS: [DNSRule]
    var certificates: [CertificateRecord] = []
    var enrollments: [EnrollmentRecord] = []
    var preferences = Preferences()
    init(profiles: [Profile] = [], observedDNS: [DNSRule] = []) { self.profiles = profiles; self.observedDNS = observedDNS }
    enum CodingKeys: String, CodingKey { case profiles, observedDNS, certificates, enrollments, preferences }
    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        profiles = try c.decodeIfPresent([Profile].self, forKey: .profiles) ?? []
        observedDNS = try c.decodeIfPresent([DNSRule].self, forKey: .observedDNS) ?? []
        certificates = try c.decodeIfPresent([CertificateRecord].self, forKey: .certificates) ?? []
        enrollments = try c.decodeIfPresent([EnrollmentRecord].self, forKey: .enrollments) ?? []
        preferences = try c.decodeIfPresent(Preferences.self, forKey: .preferences) ?? Preferences()
    }
}
enum SavePolicy: String, Codable, CaseIterable, Identifiable {
    case none = "None", session = "Session", persistent = "Persistent", choose = "Both"
    var id: String { rawValue }
    var title: String { switch self { case .none: return "Не сохранять"; case .session: return "На время сеанса"; case .persistent: return "В Связке ключей"; case .choose: return "Спрашивать при входе" } }
}
struct ProfileSettings: Codable, Equatable {
    var autoStart = false
    var authSave: SavePolicy = .none
    var keySave: SavePolicy = .persistent
    var reconnectAfterWake = true
    var reconnectAfterNetworkChange = true
    var lockAutoStart = false
    var lockAuthSave = false
    var lockKeySave = false
    var requireSplitDNS = true
}
struct Preferences: Codable {
    var notifications = true
    var autoLaunch = false
    var logFontSize: Double = 12
    var logAutoScroll = true
}
struct CertificateRecord: Codable, Identifiable {
    var id: String
    var name: String
    var subject: String
    var issuer: String
    var sha1: String
    var sha256: String
    var notBefore: String
    var notAfter: String
    var algorithm: String
    var bits: Int
    var certificate: String
    var chain: [String]
    var hasPrivateKey: Bool
    var generatedPassword: Bool = false
}
struct EnrollmentRecord: Codable, Identifiable {
    var id: String
    var commonName: String
    var algorithm: String
    var request: String
    var createdAt: Date
}
struct DNSState: Codable {
    var rules: [DNSRule]
    var interface: String
    var address: String?
}
struct AccessPolicy: Codable {
    var groups: [String]
}
struct Request: Codable {
    var action: String
    var id: String?
    var profile: Profile?
    var ca: Data?
    var p12: Data?
    var username: String?
    var password: String?
    var keyPassword: String?
    var retainAuth: Bool?
    var retainKey: Bool?
    var authorization: Data?
    var accessPolicy: AccessPolicy?
    var challengeResponse: String?
}
struct SessionStatus: Codable, Identifiable {
    var id: String
    var state: String
    var challenge: String?
    var message: String
    var connectedAt: Date?
    var interface: String?
    var address: String?
    var remoteAddress: String?
    var dns: [DNSRule]?
    var bytesIn: UInt64?
    var bytesOut: UInt64?
    var rateIn: Double?
    var rateOut: Double?
    var errorCode: String?
    var challengeText: String?
}
struct Response: Codable {
    var ok: Bool
    var error: String?
    var sessions: [SessionStatus]
    var engine: String?
    var log: [String]?
    var groups: [String]?
    var accessPolicy: AccessPolicy?
    var helperVersion: String?
}

func logLineRedacted(_ text: String, secrets: [String] = []) -> String {
    var line = String(text.prefix(8192))
    let lowered = line.lowercased()
    if lowered.contains("-----begin") && lowered.contains("private key") { return "[Закрытый ключ скрыт]" }
    if ["auth_token", "auth-token", "password '", "password=", "password:", ">password:", "pkcs12_password"].contains(where: { lowered.contains($0) }) { return "[Событие авторизации: секретные данные скрыты]" }
    for secret in secrets where !secret.isEmpty { line = line.replacingOccurrences(of: secret, with: "[скрыто]") }
    return line
}

func isIPAddress(_ value: String) -> Bool {
    var v4 = in_addr(); var v6 = in6_addr()
    return value.withCString { inet_pton(AF_INET, $0, &v4) == 1 || inet_pton(AF_INET6, $0, &v6) == 1 }
}
func validDomain(_ value: String) -> Bool {
    guard value.count <= 253, value.contains("."), !value.hasSuffix(".") else { return false }
    return value.split(separator: ".", omittingEmptySubsequences: false).allSatisfy {
        !$0.isEmpty && $0.count <= 63 && $0.first != "-" && $0.last != "-" &&
        $0.unicodeScalars.allSatisfy { CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-").contains($0) }
    }
}
func validateDNS(_ rules: [DNSRule]) throws {
    guard rules.count <= 32 else { throw VPNError("Too many DNS rules") }
    var seen = Set<String>()
    for rule in rules {
        guard !rule.domains.isEmpty, !rule.servers.isEmpty, rule.domains.count <= 32, rule.servers.count <= 8 else { throw VPNError("Invalid DNS rule size") }
        for domain in rule.domains {
            guard validDomain(domain), seen.insert(domain.lowercased()).inserted else { throw VPNError("Invalid or duplicate DNS domain") }
        }
        for server in rule.servers {
            guard isIPAddress(server), server != "0.0.0.0", server != "::", server != "::1", !server.hasPrefix("127.") else { throw VPNError("Invalid DNS server") }
        }
    }
}
func dnsPoliciesConflict(_ requested: [DNSRule], existing: DNSRule, managedByThisApp: Bool) -> Bool {
    let overlap = requested.filter { !Set($0.domains.map { $0.lowercased() }).isDisjoint(with: existing.domains.map { $0.lowercased() }) }
    return overlap.contains { !managedByThisApp || Set($0.servers) != Set(existing.servers) }
}

// Tokenize OpenVPN syntax without invoking a shell.
func tokens(_ line: String) throws -> [String] {
    var result: [String] = []; var current = ""; var quote: Character?; var escaped = false; var started = false
    for char in line {
        if escaped { current.append(char); escaped = false; started = true; continue }
        if char == "\\", quote != "'" { escaped = true; started = true; continue }
        if let q = quote { if char == q { quote = nil } else { current.append(char) }; started = true; continue }
        if char == "\"" || char == "'" { quote = char; started = true; continue }
        if char == "#" || char == ";", !started { break }
        if char.isWhitespace { if started { result.append(current); current = ""; started = false }; continue }
        current.append(char); started = true
    }
    guard quote == nil, !escaped else { throw VPNError("Unclosed quote in VPN configuration") }
    if started { result.append(current) }
    return result
}
func ovpnQuote(_ text: String) -> String {
    "\"" + text.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"") + "\""
}
func safeID(_ id: String) -> Bool {
    !id.isEmpty && id.count <= 64 && id.allSatisfy { $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "-") }
}

// A strict allowlist prevents an imported profile from executing root commands,
// loading plugins, writing arbitrary files, or overriding helper-owned options.
func validatedConfiguration(_ text: String) throws -> String {
    guard text.utf8.count <= 64_000 else { throw VPNError("VPN configuration is too large") }
    let flags: Set<String> = ["client", "nobind", "persist-key", "persist-tun", "push-peer-info", "remote-random", "float", "remote-random-hostname", "route-nopull", "pull", "fast-io", "tcp-nodelay", "auth-nocache", "disable-occ", "mute-replay-warnings"]
    let single: Set<String> = ["remote-cert-tls", "verify-x509-name", "dev", "proto", "resolv-retry", "link-mtu", "tun-mtu", "verb", "cipher", "data-ciphers", "data-ciphers-fallback", "auth", "tls-version-min", "connect-retry", "connect-timeout", "reneg-sec", "ping", "ping-restart", "tls-cipher", "tls-ciphersuites", "tls-cert-profile", "tls-version-max", "key-direction", "sndbuf", "rcvbuf", "connect-retry-max", "auth-retry", "allow-compression", "compress", "inactive", "replay-window", "hand-window", "tran-window"]
    let numeric: Set<String> = ["link-mtu", "tun-mtu", "verb", "connect-retry", "connect-timeout", "reneg-sec", "ping", "ping-restart"]
    var result: [String] = []; var remoteCount = 0; var serverTLS = false; var nameTLS = false; var client = false; var tun = false
    for line in text.components(separatedBy: .newlines) {
        let t = try tokens(line); if t.isEmpty { continue }; let op = t[0]
        guard t.allSatisfy({ !$0.contains("\n") && !$0.contains("\r") && !$0.contains("\0") }) else { throw VPNError("Invalid configuration value") }
        if flags.contains(op) { guard t.count == 1 else { throw VPNError("Invalid flag") }; if op == "client" { client = true } }
        else if op == "auth-user-pass" { guard t.count == 1 else { throw VPNError("File-based passwords are not supported") } }
        else if op == "ca" || op == "pkcs12" { guard t.count == 2 else { throw VPNError("Invalid certificate reference") }; continue }
        else if ["tls-auth", "tls-crypt", "tls-crypt-v2", "crl-verify", "extra-certs"].contains(op) { guard (2...3).contains(t.count), t[1] == "[inline]", t.count == 2 || (op == "tls-auth" && ["0", "1"].contains(t[2])) else { throw VPNError("TLS assets must be imported into the profile") } }
        else if ["route", "route-ipv6", "redirect-gateway", "redirect-private", "route-gateway", "route-metric", "route-delay", "dhcp-option", "dns", "mssfix", "explicit-exit-notify", "keepalive", "pull-filter", "peer-fingerprint", "http-proxy", "http-proxy-option", "socks-proxy", "static-challenge"].contains(op) {
            guard (1...8).contains(t.count), t.dropFirst().allSatisfy({ $0.count <= 512 && !$0.hasPrefix("--") }) else { throw VPNError("Invalid network option") }
            if op == "http-proxy", t.count > 4 { throw VPNError("Proxy credentials must be entered interactively") }
            if op == "http-proxy", t.count == 4, !["auto", "auto-nct", "stdin"].contains(t[3]) { throw VPNError("Proxy credential files are not supported; use stdin") }
            if op == "socks-proxy", t.count > 3 { throw VPNError("Proxy credentials must be entered interactively") }
        }
        else if op == "remote" {
            guard (2...4).contains(t.count), t[1].count <= 253, t[1].unicodeScalars.allSatisfy({ CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-:").contains($0) }), !t[1].hasPrefix("-") else { throw VPNError("Invalid VPN endpoint") }
            if t.count >= 3 { guard let port = Int(t[2]), (1...65535).contains(port) else { throw VPNError("Invalid VPN port") } }
            if t.count == 4 { guard ["udp", "udp4", "udp6", "tcp-client", "tcp4-client", "tcp6-client"].contains(t[3]) else { throw VPNError("Invalid transport") } }
            remoteCount += 1
        } else if single.contains(op) {
            guard t.count == 2 || (op == "verify-x509-name" && t.count == 3) else { throw VPNError("Invalid VPN option") }
            if numeric.contains(op) { guard let n = Int(t[1]), n >= 0, n <= 86400 else { throw VPNError("Invalid numeric VPN option") }; if op == "verb", Int(t[1])! > 4 { throw VPNError("Verbose logging is disabled to protect credentials") } }
            if op == "dev" { guard t[1] == "tun" else { throw VPNError("Only TUN is supported") }; tun = true }
            if op == "proto" { guard ["udp", "udp4", "udp6", "tcp-client", "tcp4-client", "tcp6-client"].contains(t[1]) else { throw VPNError("Invalid transport") } }
            if op == "remote-cert-tls" { guard t[1] == "server" else { throw VPNError("Server certificate verification is required") }; serverTLS = true }
            if op == "verify-x509-name" { guard !t[1].isEmpty, t.count == 2 || ["name", "subject"].contains(t[2]) else { throw VPNError("Invalid TLS name verification") }; nameTLS = true }
            if op == "tls-version-min" { guard ["1.2", "1.3"].contains(t[1]) else { throw VPNError("TLS 1.2 or newer is required") } }
        } else { throw VPNError("Unsupported VPN option: \(op)") }
        result.append(t.map(ovpnQuote).joined(separator: " "))
    }
    guard client, tun, serverTLS, nameTLS, (1...8).contains(remoteCount) else { throw VPNError("Incomplete client configuration or missing TLS verification") }
    return result.joined(separator: "\n") + "\n"
}

func needsUsername(_ profile: Profile) -> Bool { profile.configuration.components(separatedBy: .newlines).contains { (try? tokens($0).first) == "auth-user-pass" } }

func connectUnix(_ path: String) throws -> Int32 {
    let fd = socket(AF_UNIX, SOCK_STREAM, 0); guard fd >= 0 else { throw VPNError("Cannot create local socket") }
    var address = sockaddr_un(); address.sun_family = sa_family_t(AF_UNIX)
    guard path.utf8.count < MemoryLayout.size(ofValue: address.sun_path) else { close(fd); throw VPNError("Socket path too long") }
    withUnsafeMutablePointer(to: &address.sun_path) { pointer in
        pointer.withMemoryRebound(to: CChar.self, capacity: 104) { _ = strcpy($0, path) }
    }
    address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
    let connected = withUnsafePointer(to: &address) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.connect(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) } }
    guard connected == 0 else { close(fd); throw VPNError("Системный помощник не установлен или не запущен. Установите пакет .pkg.") }
    var timeout = timeval(tv_sec: 5, tv_usec: 0)
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
    var noSigPipe: Int32 = 1; setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &noSigPipe, socklen_t(MemoryLayout<Int32>.size))
    return fd
}
func writeAll(_ fd: Int32, _ data: Data) throws {
    try data.withUnsafeBytes { bytes in
        var offset = 0
        while offset < bytes.count {
            let count = Darwin.write(fd, bytes.baseAddress!.advanced(by: offset), bytes.count - offset)
            if count < 0 && errno == EINTR { continue }
            guard count > 0 else { throw VPNError("Local communication failed") }; offset += count
        }
    }
}
func readFrame(_ fd: Int32) throws -> Data {
    var result = Data(); var byte: UInt8 = 0
    while result.count <= 2_000_000 {
        let count = Darwin.read(fd, &byte, 1)
        if count < 0 && errno == EINTR { continue }
        guard count == 1 else { throw VPNError("Local communication interrupted") }
        if byte == 10 { return result }; result.append(byte)
    }
    throw VPNError("Local request is too large")
}
func helperCall(_ request: Request) throws -> Response {
    let fd = try connectUnix(socketPath); defer { close(fd) }
    var data = try JSONEncoder().encode(request); data.append(10); try writeAll(fd, data)
    return try JSONDecoder().decode(Response.self, from: readFrame(fd))
}

func parsePushedDNS(_ env: [String: String]) throws -> [DNSRule] {
    let ids = Set(env.keys.compactMap { key -> Int? in
        let pieces = key.split(separator: "_"); return pieces.count >= 4 && pieces[0] == "dns" && pieces[1] == "server" ? Int(pieces[2]) : nil
    }).sorted()
    func values(_ prefix: String) -> [String] { env.keys.filter { $0.hasPrefix(prefix) && Int($0.dropFirst(prefix.count)) != nil }.sorted { Int($0.dropFirst(prefix.count))! < Int($1.dropFirst(prefix.count))! }.compactMap { env[$0] } }
    var rules: [DNSRule] = []
    for id in ids {
        let prefix = "dns_server_\(id)_"
        guard env[prefix + "transport"] == nil || env[prefix + "transport"] == "plain", env[prefix + "dnssec"] != "yes", values(prefix + "port_").allSatisfy({ $0 == "53" }) else { throw VPNError("Unsupported DNS transport, port or required DNSSEC") }
        let domains = values(prefix + "resolve_domain_").map { $0.lowercased() }
        guard !domains.isEmpty else { throw VPNError("Server requested full DNS; split DNS domains are required") }
        rules.append(DNSRule(domains: domains, servers: values(prefix + "address_")))
    }
    if ids.isEmpty {
        var servers: [String] = []; var domains: [String] = []
        for value in values("foreign_option_") {
            let parts = value.split(separator: " ").map(String.init)
            if parts.count == 3 && parts[0] == "dhcp-option" {
                if ["DNS", "DNS6"].contains(parts[1]) { servers.append(parts[2]) }
                if ["DOMAIN", "DOMAIN-SEARCH"].contains(parts[1]) { domains.append(parts[2].lowercased()) }
            }
        }
        if !servers.isEmpty { guard !domains.isEmpty else { throw VPNError("Server requested DNS without split domains") }; rules.append(DNSRule(domains: Array(Set(domains)).sorted(), servers: Array(Set(servers)).sorted())) }
    }
    try validateDNS(rules); return rules
}
