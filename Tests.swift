import Foundation

func require(_ value: Bool, _ message: String) throws { if !value { throw VPNError(message) } }
func rejects(_ block: () throws -> Void, _ name: String) throws {
    do { try block() } catch { return }; throw VPNError("Unsafe input accepted: " + name)
}
@main struct Tests {
    static func main() throws {
        try testLocalization()
        let base = """
        client
        remote-cert-tls server
        verify-x509-name "corporate vpn" name
        dev tun
        proto udp
        remote vpn.example.test 1194
        auth-user-pass
        cipher AES-256-GCM
        ca ../../ignored.pem
        pkcs12 ../../ignored.p12
        """
        let clean = try validatedConfiguration(base)
        try require(!clean.contains("ignored"), "Certificate paths were not replaced")
        try require(try validatedConfiguration(clean) == clean, "Configuration normalization is not idempotent")
        for option in ["up /bin/sh", "plugin /tmp/evil", "config /tmp/evil", "management 127.0.0.1 1234", "log /etc/evil", "dev-node tap0", "auth-user-pass /tmp/secret", "route-up /tmp/x", "daemon", "script-security 3", "verify-x509-name x name-prefix", "remote-cert-tls client", "dev tap", "verb 9", "tls-version-min 1.0"] {
            try rejects({ _ = try validatedConfiguration(base + "\n" + option) }, option)
        }
        try rejects({ _ = try validatedConfiguration(base.replacingOccurrences(of: "remote-cert-tls server", with: "")) }, "missing TLS")
        try require(try tokens("verify-x509-name 'a b' name # comment") == ["verify-x509-name", "a b", "name"], "OpenVPN tokenization")
        try rejects({ _ = try tokens("remote \"unterminated") }, "bad quote")
        let modern = ["dns_server_1_address_1": "192.0.2.53", "dns_server_1_resolve_domain_1": "internal.example.test", "dns_server_2_address_1": "2001:db8::53", "dns_server_2_resolve_domain_1": "second.example.test"]
        let rules = try parsePushedDNS(modern); try require(rules.count == 2, "Modern pushed DNS")
        let legacy = try parsePushedDNS(["foreign_option_1": "dhcp-option DNS 192.0.2.53", "foreign_option_2": "dhcp-option DOMAIN internal.example.test"]); try require(legacy.count == 1, "Legacy DNS")
        for domain in ["*", ".", "x';shell.example", "bad..example", "-bad.example", "bad.example\n"] { try rejects({ try validateDNS([DNSRule(domains: [domain], servers: ["192.0.2.53"])]) }, "DNS domain") }
        try rejects({ _ = try parsePushedDNS(["dns_server_1_address_1": "192.0.2.53"]) }, "unscoped DNS")
        try rejects({ _ = try parsePushedDNS(["foreign_option_1": "dhcp-option DNS 192.0.2.53"]) }, "unscoped legacy DNS")
        for pair in [("dns_server_1_transport", "DoH"), ("dns_server_1_dnssec", "yes"), ("dns_server_1_port_1", "5353")] { var env = modern; env[pair.0] = pair.1; try rejects({ _ = try parsePushedDNS(env) }, "unsupported DNS security/port") }
        try rejects({ try validateDNS([DNSRule(domains: ["internal.example.test"], servers: ["127.0.0.1"])]) }, "loopback resolver")
        try rejects({ try validateDNS(rules + rules) }, "duplicate DNS domains")
        try require(!dnsPoliciesConflict(rules, existing: rules[0], managedByThisApp: true), "Same DNS policy across two app tunnels must coexist")
        try require(dnsPoliciesConflict(rules, existing: DNSRule(domains: rules[0].domains, servers: ["192.0.2.54"]), managedByThisApp: true), "Different resolver must conflict")
        try require(dnsPoliciesConflict(rules, existing: rules[0], managedByThisApp: false), "Foreign policy must be preserved")
        try require(safeID("profile-1") && !safeID("../../root") && !safeID("p\n"), "Profile ID validation")
        let temporary = FileManager.default.temporaryDirectory.appendingPathComponent("openvpn-file-tests-" + UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: temporary) }
        let ca = Data("-----BEGIN CERTIFICATE-----\nVEVTVA==\n-----END CERTIFICATE-----\n".utf8)
        var settings = ProfileSettings(); settings.autoStart = true; settings.authSave = .choose; settings.keySave = .session; settings.lockAutoStart = true; settings.lockAuthSave = true
        let original = Profile(id: "fixture", name: "Test & <Corporate>", configuration: try validatedConfiguration(base + "\ntls-auth [inline] 1"), dnsRules: [], useSnapshotDNS: false, caData: ca, settings: settings, assets: ["tls-auth": Data("test-static-key\n".utf8)], sourceThumbprint: "ABC123")
        let archive = temporary.appendingPathComponent("roundtrip.openvpn")
        try exportConnection(original, to: archive)
        let imported = try importConnectionFile(archive)
        try require(imported.profile.name == original.name && imported.profile.caData == ca, "Native package name and CA round trip")
        try require(imported.profile.settings == settings && imported.profile.sourceThumbprint == "ABC123", "Native settings and locks round trip")
        try require(imported.profile.assets?["tls-auth"] == original.assets?["tls-auth"], "Native TLS key preservation")
        try require(imported.profile.configuration.contains("\"tls-auth\" \"[inline]\" \"1\""), "TLS key direction preserved")
        let plain = temporary.appendingPathComponent("roundtrip.ovpn"); try exportConnection(original, to: plain)
        let ovpn = try importConnectionFile(plain)
        try require(ovpn.profile.caData == ca && ovpn.profile.assets?["tls-auth"] == original.assets?["tls-auth"], "OVPN inline CA and TLS assets round trip")
        try rejects({ let xml = ConnectionXML(); try xml.parse(Data("<!DOCTYPE a [<!ENTITY s SYSTEM 'file:///etc/passwd'>]><a>&s;</a>".utf8)) }, "XML external entity")
        let oldStore = try JSONDecoder().decode(ProfileStore.self, from: Data("{\"profiles\":[],\"observedDNS\":[]}".utf8))
        try require(oldStore.certificates.isEmpty && oldStore.enrollments.isEmpty, "Backward-compatible profile store")
        try require(!logLineRedacted("password=hidden").contains("hidden"), "Credential log redaction")
        try require(!logLineRedacted("my specific secret", secrets: ["specific secret"]).contains("specific secret"), "Known secret redaction")
        print("PASS: native .openvpn and .ovpn round trip, CA, TLS assets, key direction, settings locks, XML rejection, legacy store, log redaction")
        if CommandLine.arguments.count == 2 {
            let store = try JSONDecoder().decode(ProfileStore.self, from: Data(contentsOf: URL(fileURLWithPath: CommandLine.arguments[1])))
            for profile in store.profiles { _ = try validatedConfiguration(profile.configuration); try validateDNS(profile.dnsRules) }; try validateDNS(store.observedDNS)
            print("PASS: provided profiles validate without printing their contents")
        }
        print("PASS: configuration allowlist, TLS requirements, quoted syntax, path replacement, modern/legacy split DNS, conflict validation, unsafe input rejection")
    }
}
