import Foundation
import Darwin
import SystemConfiguration
import Security

let fm = FileManager.default
let stateLock = NSRecursiveLock()
var sessions: [String: Session] = [:]
var ownerUID: uid_t?
var lastClientSeen = Date()
let dnsPrefix = "State:/Network/Service/OpenVPNUI-Mac-"

func withLock<T>(_ block: () throws -> T) rethrows -> T { stateLock.lock(); defer { stateLock.unlock() }; return try block() }
func privateDirectory(_ path: String) throws { try fm.createDirectory(atPath: path, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700]) }
func writePrivate(_ data: Data, _ path: String) throws { try data.write(to: URL(fileURLWithPath: path), options: .atomic); guard chmod(path, 0o600) == 0 else { throw VPNError("Cannot protect VPN material") } }
func store() throws -> SCDynamicStore { guard let s = SCDynamicStoreCreate(nil, "OpenVPNUI Mac" as CFString, nil, nil) else { throw VPNError("Cannot access system DNS store") }; return s }
func removeDNS(_ session: String) throws {
    let fd = open(runtimeRoot + "/dns.lock", O_CREAT | O_RDWR | O_NOFOLLOW, 0o600); guard fd >= 0, flock(fd, LOCK_EX) == 0 else { throw VPNError("Cannot lock DNS state") }; defer { flock(fd, LOCK_UN); close(fd) }
    let s = try store(); let pattern = "^" + NSRegularExpression.escapedPattern(for: dnsPrefix + session + "-") + ".*/DNS$"
    let keys = SCDynamicStoreCopyKeyList(s, pattern as CFString) as? [String] ?? []
    for key in keys { guard SCDynamicStoreRemoveValue(s, key as CFString) else { throw VPNError("DNS cleanup failed") } }
}
func applyDNS(_ session: String, _ rules: [DNSRule], interface: String) throws {
    let fd = open(runtimeRoot + "/dns.lock", O_CREAT | O_RDWR | O_NOFOLLOW, 0o600); guard fd >= 0, flock(fd, LOCK_EX) == 0 else { throw VPNError("Cannot lock DNS state") }; defer { flock(fd, LOCK_UN); close(fd) }
    try validateDNS(rules)
    guard interface.range(of: "^utun[0-9]+$", options: .regularExpression) != nil else { throw VPNError("Unexpected tunnel interface") }
    let s = try store()
    let existingKeys = SCDynamicStoreCopyKeyList(s, "State:/Network/Service/.*/DNS" as CFString) as? [String] ?? []
    let ownPrefix = dnsPrefix + session + "-"
    for key in existingKeys where !key.hasPrefix(ownPrefix) {
        let values = SCDynamicStoreCopyValue(s, key as CFString) as? [String: Any] ?? [:]
        let domains = values["SupplementalMatchDomains"] as? [String] ?? []
        let addresses = values["ServerAddresses"] as? [String] ?? []
        guard !dnsPoliciesConflict(rules, existing: DNSRule(domains: domains, servers: addresses), managedByThisApp: key.hasPrefix(dnsPrefix)) else { throw VPNError("A conflicting DNS policy for this domain already exists") }
    }
    // Snapshot prior values and use one SystemConfiguration transaction.
    var updates: [String: Any] = [:]
    for (index, rule) in rules.enumerated() {
        updates[ownPrefix + "\(index)/DNS"] = ["ServerAddresses": rule.servers, "SupplementalMatchDomains": rule.domains, "SupplementalMatchOrders": rule.domains.map { _ in 101000 }, "SupplementalMatchDomainsNoSearch": 1, "InterfaceName": interface]
    }
    let oldKeys = existingKeys.filter { $0.hasPrefix(ownPrefix) && updates[$0] == nil }
    guard SCDynamicStoreSetMultiple(s, updates as CFDictionary, oldKeys as CFArray, nil) else { throw VPNError("DNS policy transaction failed") }
}

func dnsHook(_ args: [String]) throws {
    guard geteuid() == 0, args.count >= 2, UUID(uuidString: args[1]) != nil else { throw VPNError("Invalid DNS hook invocation") }
    let sid = args[1]
    if args[0] == "--dns-down" { try removeDNS(sid); try? fm.removeItem(atPath: runtimeRoot + "/" + sid + "/dns-ready.json"); return }
    guard args[0] == "--dns-up" else { throw VPNError("Invalid DNS action") }
    let env = ProcessInfo.processInfo.environment
    let snapshot = URL(fileURLWithPath: runtimeRoot + "/" + sid + "/dns.json")
    let fallback = try JSONDecoder().decode([DNSRule].self, from: Data(contentsOf: snapshot))
    let pushed = try parsePushedDNS(env)
    let rules = fallback.isEmpty ? pushed : fallback
    try applyDNS(sid, rules, interface: env["dev"] ?? "")
    try writePrivate(try JSONEncoder().encode(DNSState(rules: rules, interface: env["dev"] ?? "", address: env["ifconfig_local"])), runtimeRoot + "/" + sid + "/dns-ready.json")
}

final class Session {
    let id: String; let sid = UUID().uuidString.lowercased(); let uid: uid_t
    let process = Process(); let managementLock = NSLock()
    var managementFD: Int32 = -1
    var status: SessionStatus
    var username: String?; var password: String?; var keyPassword: String?
    var canceled = false
    var failureMessage: String?
    var retainAuth = false, retainKey = false, requireDNS = true
    var log: [String] = [], outputBuffer = ""
    var logBytes = 0
    var lastBytes: (UInt64, UInt64, Date)?
    var secretValues: [String] = []
    func appendLog(_ line: String) {
        withLock {
            let clean = logLineRedacted(line, secrets: secretValues); log.append(clean); logBytes += clean.utf8.count
            while log.count > 2000 || logBytes > 500_000 { logBytes -= log.removeFirst().utf8.count }
            let lower = line.lowercased()
            if lower.contains("auth_failed") { status.errorCode = "Password" }
            else if lower.contains("verify error") || lower.contains("certificate verify failed") { status.errorCode = "Certificate" }
            else if lower.contains("resolve: cannot resolve") || lower.contains("tls key negotiation failed") { status.errorCode = "HostUncontactable" }
            else if lower.contains("cannot open tun") { status.errorCode = "NoAvailableInterface" }
        }
    }
    func receiveOutput(_ data: Data) {
        withLock {
            outputBuffer += String(decoding: data, as: UTF8.self)
            while let end = outputBuffer.firstIndex(of: "\n") { let line = String(outputBuffer[..<end]); outputBuffer.removeSubrange(...end); appendLog(line) }
            if outputBuffer.utf8.count > 8192 { outputBuffer = "" }
        }
    }
    func captureOutput(from pipe: Pipe) {
        pipe.fileHandleForReading.readabilityHandler = { [weak self] handle in
            // read(upToCount:) waits for a full buffer or EOF on macOS pipes.
            // Read what is available so short diagnostic lines appear immediately.
            let data = handle.availableData
            if data.isEmpty { handle.readabilityHandler = nil; return }
            self?.receiveOutput(data)
        }
    }
    var directory: String { runtimeRoot + "/" + sid }
    init(profile: Profile, uid: uid_t) { self.id = profile.id; self.uid = uid; self.status = SessionStatus(id: profile.id, state: "starting", challenge: nil, message: "Starting OpenVPN", connectedAt: nil) }
    func send(_ command: String) throws {
        managementLock.lock(); defer { managementLock.unlock() }
        guard managementFD >= 0 else { throw VPNError("VPN management channel is not ready") }
        try writeAll(managementFD, Data((command + "\n").utf8))
    }
    func credentials(_ request: Request) throws {
        for value in [request.username, request.password, request.keyPassword, request.challengeResponse].compactMap({ $0 }) {
            guard value.utf8.count <= 4096, !value.contains("\n"), !value.contains("\r"), !value.contains("\0") else { throw VPNError("Invalid credential value") }
        }
        withLock {
            if let value = request.username { username = value }
            if let value = request.password { password = value; if !value.isEmpty { secretValues.append(value) } }
            if let value = request.keyPassword { keyPassword = value; if !value.isEmpty { secretValues.append(value) } }
            retainAuth = request.retainAuth ?? retainAuth; retainKey = request.retainKey ?? retainKey
            if let response = request.challengeResponse, !response.isEmpty {
                secretValues.append(response)
                if status.challengeText != nil, let p = password { password = "SCRV1:" + Data(p.utf8).base64EncodedString() + ":" + Data(response.utf8).base64EncodedString() }
            }
        }
        if let challenge = withLock({ status.challenge }) { try answer(challenge) }
    }
    func answer(_ challenge: String) throws {
        if ["Auth", "HTTP Proxy", "SOCKS Proxy"].contains(challenge) {
            guard let u = withLock({ username }), let p = withLock({ password }) else { return }
            try send("username " + ovpnQuote(challenge) + " " + ovpnQuote(u)); try send("password " + ovpnQuote(challenge) + " " + ovpnQuote(p))
            withLock { if !retainAuth { password = nil }; status.challenge = nil; status.challengeText = nil; status.state = "connecting" }
        } else if challenge == "Private Key" {
            guard let p = withLock({ keyPassword }) else { return }
            try send("password \"Private Key\" " + ovpnQuote(p))
            withLock { if !retainKey { keyPassword = nil }; status.challenge = nil; status.state = "connecting" }
        }
    }
    func handle(_ line: String) {
        guard !withLock({ canceled }) else { return }
        do {
            if line.hasPrefix(">PASSWORD:Verification Failed:") {
                withLock { password = nil; keyPassword = nil; status.state = "credentials"; status.challenge = line.contains("Private Key") ? "Private Key" : "Auth"; status.message = "Authentication rejected. Enter your credentials again." }
            } else if line.hasPrefix(">PASSWORD:Need '") {
                let parts = line.components(separatedBy: "'"); guard parts.count >= 2 else { return }; let challenge = parts[1]
                guard ["Auth", "Private Key", "HTTP Proxy", "SOCKS Proxy"].contains(challenge) else { stop(failure: "This authentication method requires additional support"); return }
                withLock { status.challenge = challenge; status.state = "credentials"; status.message = challenge == "Auth" ? "VPN username and password required" : "Certificate password required" }
                if challenge.contains("Proxy") { withLock { username = nil; password = nil } }
                else if let range = line.range(of: " SC:") { withLock { status.challengeText = String(line[range.upperBound...]); password = nil } }
                else { try answer(challenge) }
            } else if line.hasPrefix(">BYTECOUNT:") {
                let values = line.dropFirst(11).split(separator: ",")
                if values.count == 2, let incoming = UInt64(values[0]), let outgoing = UInt64(values[1]) {
                    withLock {
                        let now = Date()
                        if let previous = lastBytes { let dt = max(0.1, now.timeIntervalSince(previous.2)); status.rateIn = Double(incoming >= previous.0 ? incoming - previous.0 : 0) / dt; status.rateOut = Double(outgoing >= previous.1 ? outgoing - previous.1 : 0) / dt }
                        lastBytes = (incoming, outgoing, now); status.bytesIn = incoming; status.bytesOut = outgoing
                    }
                }
            } else if line.hasPrefix(">STATE:") {
                let parts = line.dropFirst(7).split(separator: ",", omittingEmptySubsequences: false)
                if parts.count >= 2 {
                    let state = String(parts[1])
                    withLock {
                        if state == "CONNECTED" {
                            let file = URL(fileURLWithPath: directory + "/dns-ready.json")
                            guard let data = try? Data(contentsOf: file), let dns = try? JSONDecoder().decode(DNSState.self, from: data), !requireDNS || !dns.rules.isEmpty else {
                                stop(failure: "Split DNS is not configured. Check the server DNS settings or imported Windows DNS rules."); return
                            }
                            status.state = "connected"; status.challenge = nil; status.message = dns.rules.isEmpty ? "VPN connected" : "VPN connected · Split DNS active"; status.connectedAt = Date()
                            status.interface = dns.interface; status.address = dns.address ?? (parts.count > 3 ? String(parts[3]) : nil); status.dns = dns.rules
                            status.remoteAddress = parts.count > 4 ? String(parts[4]) : nil; status.errorCode = nil
                        }
                        else if state == "RECONNECTING" {
                            status.state = "reconnecting"
                            status.message = parts.count > 2 && !parts[2].isEmpty ? "Reconnecting: " + logLineRedacted(String(parts[2]), secrets: secretValues) : "Reconnecting"
                        }
                        else if state != "EXITING", status.challenge == nil {
                            status.state = "connecting"
                            status.message = ["RESOLVE": "Resolving the VPN server address", "TCP_CONNECT": "Connecting to the VPN server", "WAIT": "Waiting for the VPN server to respond", "AUTH": "Verifying credentials and certificate", "AUTH_PENDING": "Waiting for authentication approval", "GET_CONFIG": "Receiving settings from the server", "ASSIGN_IP": "Configuring the VPN address", "ADD_ROUTES": "Configuring routes and DNS"][state] ?? "Establishing a secure connection"
                        }
                    }
                }
            } else if line.hasPrefix(">FATAL:") { withLock { status.state = "error"; status.message = "OpenVPN exited with an error. Check the profile, certificate and DNS settings."; failureMessage = status.message } }
        } catch { stop(failure: "VPN management channel error") }
    }
    func start(_ request: Request) throws {
        guard let profile = request.profile, let ca = request.ca, let p12 = request.p12, ca.count <= 100_000, (1...500_000).contains(p12.count), String(data: ca, encoding: .utf8)?.contains("-----BEGIN CERTIFICATE-----") == true else { throw VPNError("Missing VPN certificates") }
        var configuration = try validatedConfiguration(profile.configuration)
        requireDNS = (profile.settings ?? ProfileSettings()).requireSplitDNS
        for kind in ["tls-auth", "tls-crypt", "tls-crypt-v2", "crl-verify", "extra-certs"] {
            let lines = try configuration.components(separatedBy: .newlines).map { line -> String in
                var t = try tokens(line)
                if t.first == kind {
                    guard let data = profile.assets?[kind], (1...128_000).contains(data.count) else { throw VPNError("Missing TLS asset: " + kind) }
                    try privateDirectory(directory); try writePrivate(data, directory + "/" + kind + ".pem")
                    t[1] = directory + "/" + kind + ".pem"; return t.map(ovpnQuote).joined(separator: " ")
                }
                return line
            }
            configuration = lines.joined(separator: "\n")
        }
        let rules = profile.useSnapshotDNS ? profile.dnsRules : []; try validateDNS(rules)
        try privateDirectory(directory)
        try writePrivate(ca, directory + "/ca.pem"); try writePrivate(p12, directory + "/client.p12"); try writePrivate(try JSONEncoder().encode(rules), directory + "/dns.json")
        let helper = "/Library/PrivilegedHelperTools/" + helperID
        let config = configuration + "ca " + ovpnQuote(directory + "/ca.pem") + "\npkcs12 " + ovpnQuote(directory + "/client.p12") + "\n"
        try writePrivate(Data(config.utf8), directory + "/client.ovpn")
        process.executableURL = URL(fileURLWithPath: installRoot + "/Engine/openvpn")
        process.arguments = ["--config", directory + "/client.ovpn", "--dev-node", "utun", "--management", directory + "/management.sock", "unix", "--management-hold", "--management-query-passwords", "--auth-retry", "interact", "--auth-nocache", "--script-security", "2", "--route-up", helper + " --dns-up " + sid, "--route-pre-down", helper + " --dns-down " + sid, "--down", helper + " --dns-down " + sid, "--down-pre", "--up-restart", "--verb", "3"]
        process.environment = ["PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C", "OPENSSL_CONF": "/dev/null", "OPENSSL_MODULES": installRoot + "/Engine/modules"]
        process.currentDirectoryURL = URL(fileURLWithPath: directory)
        // Keep a bounded in-memory log. Never store credentials or raw management commands.
        let output = Pipe(); process.standardOutput = output; process.standardError = output
        captureOutput(from: output)
        process.terminationHandler = { [weak self] p in
            guard let self else { return }
            output.fileHandleForReading.readabilityHandler = nil
            self.managementLock.lock(); if self.managementFD >= 0 { shutdown(self.managementFD, SHUT_RDWR); close(self.managementFD); self.managementFD = -1 }; self.managementLock.unlock()
            do { try removeDNS(self.sid) } catch { withLock { self.failureMessage = "Could not remove the DNS policy. Restart the service and check DNS." } }
            try? fm.removeItem(atPath: self.directory)
            withLock { self.password = nil; self.keyPassword = nil; self.status.challenge = nil; self.status.connectedAt = nil; self.status.rateIn = 0; self.status.rateOut = 0; self.secretValues = []
                if let failure = self.failureMessage { self.status.state = "error"; self.status.message = failure }
                else if self.canceled { self.status.state = "disconnected"; self.status.message = "Disconnected" }
                else { self.status.state = "error"; self.status.message = "Connection ended (code \(p.terminationStatus)). Check credentials and settings." }
            }
        }
        try credentials(request)
        try process.run()
        DispatchQueue.global().async { [weak self] in
            guard let self else { return }
            do {
                var fd: Int32 = -1
                for _ in 0..<100 {
                    if !self.process.isRunning || withLock({ self.canceled }) { return }
                    if fm.fileExists(atPath: self.directory + "/management.sock") { fd = (try? connectUnix(self.directory + "/management.sock")) ?? -1; if fd >= 0 { break } }
                    Thread.sleep(forTimeInterval: 0.1)
                }
                guard fd >= 0 else { throw VPNError("Management channel timeout") }
                self.managementLock.lock(); self.managementFD = fd; self.managementLock.unlock()
                var timeout = timeval(tv_sec: 0, tv_usec: 0); setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
                try self.send("state on"); try self.send("bytecount 1"); try self.send("hold release")
                while self.process.isRunning { let line = try readFrame(fd); if let text = String(data: line, encoding: .utf8) { self.handle(text) } }
            } catch { if self.process.isRunning && !withLock({ self.canceled }) { self.stop(failure: "Could not control OpenVPN") } }
        }
    }
    func stop(failure: String? = nil) {
        let shouldStop = withLock { () -> Bool in
            guard !canceled else { return false }
            canceled = true; failureMessage = failure; password = nil; keyPassword = nil; status.state = "disconnecting"; status.message = "Disconnecting and cleaning up DNS"
            if let failure { appendLog("OpenVPNUI: " + failure) }
            return true
        }
        guard shouldStop else { return }
        if process.isRunning {
            process.terminate()
            DispatchQueue.global().asyncAfter(deadline: .now() + 5) { [weak self] in guard let self else { return }; if self.process.isRunning { kill(self.process.processIdentifier, SIGKILL) } }
        } else { try? removeDNS(sid); try? fm.removeItem(atPath: directory); withLock { status.state = failureMessage == nil ? "disconnected" : "error"; status.message = failureMessage ?? "Disconnected" } }
    }
}

func authorizedUID(_ fd: Int32) throws -> uid_t {
    var uid: uid_t = 0; var gid: gid_t = 0
    guard getpeereid(fd, &uid, &gid) == 0, uid >= 501 else { throw VPNError("Unauthorized local client") }
    var console = stat(); guard lstat("/dev/console", &console) == 0, console.st_uid == uid else { throw VPNError("Only the active Mac user may control VPN") }
    return uid
}
func loadAccessPolicy() -> AccessPolicy {
    guard let data = try? Data(contentsOf: URL(fileURLWithPath: installRoot + "/access.json")), let value = try? JSONDecoder().decode(AccessPolicy.self, from: data) else { return AccessPolicy(groups: ["staff"]) }
    return value
}
func localGroups() -> [String] {
    var groups: [String] = []; setgrent(); defer { endgrent() }
    while let entry = getgrent() { let name = String(cString: entry.pointee.gr_name); if !name.hasPrefix("_") { groups.append(name) } }
    return Array(Set(groups)).sorted()
}
func userHasAccess(_ uid: uid_t) -> Bool {
    guard let user = getpwuid(uid) else { return false }
    let name = String(cString: user.pointee.pw_name); var count: Int32 = 128; var groups = [gid_t](repeating: 0, count: 128)
    let result = name.withCString { getgrouplist($0, Int32(user.pointee.pw_gid), &groups, &count) }
    guard result >= 0 else { return false }
    let allowed = Set((loadAccessPolicy().groups + ["admin"]).compactMap { getgrnam($0)?.pointee.gr_gid })
    return !allowed.isDisjoint(with: groups.prefix(Int(count)))
}
func handleRequest(_ request: Request, uid: uid_t) throws -> Response {
    try withLock {
        lastClientSeen = Date()
        if request.action == "access" { return Response(ok: true, sessions: [], groups: localGroups(), accessPolicy: loadAccessPolicy(), helperVersion: "0.2.3") }
        if request.action == "set-access" {
            try verifyAdministratorAuthorization(request.authorization)
            guard let policy = request.accessPolicy, policy.groups.count <= 128, policy.groups.allSatisfy({ localGroups().contains($0) }) else { throw VPNError("Unknown group") }
            try writePrivate(try JSONEncoder().encode(policy), installRoot + "/access.json")
            for session in sessions.values where session.process.isRunning && !userHasAccess(session.uid) { session.stop() }
            return Response(ok: true, sessions: [], accessPolicy: policy)
        }
        if request.action == "restart" {
            try verifyAdministratorAuthorization(request.authorization)
            sessions.values.forEach { $0.stop() }
            DispatchQueue.global().asyncAfter(deadline: .now() + 6) { exit(0) }
            return Response(ok: true, sessions: [])
        }
        guard userHasAccess(uid) else { throw VPNError("Your group is not allowed to manage VPN connections. Change access in the service settings.") }
        if request.action == "status" { return Response(ok: true, error: nil, sessions: sessions.values.filter { $0.uid == uid }.map(\.status).sorted { $0.id < $1.id }, engine: "OpenVPN 2.6.23", helperVersion: "0.2.3") }
        guard let id = request.id, safeID(id) else { throw VPNError("Invalid profile identifier") }
        if request.action == "start" {
            guard request.profile?.id == id, ownerUID == nil || ownerUID == uid else { throw VPNError("VPN is in use by another Mac user") }
            if let old = sessions[id], old.process.isRunning { throw VPNError("This profile is already running") }
            let session = Session(profile: request.profile!, uid: uid); sessions[id] = session; ownerUID = uid
            do { try session.start(request) } catch { sessions.removeValue(forKey: id); try? removeDNS(session.sid); try? fm.removeItem(atPath: session.directory); throw error }
        } else {
            guard let session = sessions[id], session.uid == uid else { throw VPNError("Unknown VPN session") }
            if request.action == "log" { return Response(ok: true, sessions: [session.status], log: session.log) }
            if request.action == "clear-log" { session.log = []; session.logBytes = 0; return Response(ok: true, sessions: [session.status], log: []) }
            if request.action == "stop" { session.stop() }
            else if request.action == "credentials" { try session.credentials(request) }
            else { throw VPNError("Unknown action") }
        }
        return Response(ok: true, error: nil, sessions: sessions.values.filter { $0.uid == uid }.map(\.status), engine: "OpenVPN 2.6.23", helperVersion: "0.2.3")
    }
}

#if !HELPER_TEST
@main struct HelperMain {
    static func main() {
        signal(SIGPIPE, SIG_IGN)
        let args = Array(CommandLine.arguments.dropFirst())
        if args.first == "--dns-up" || args.first == "--dns-down" {
            do { try dnsHook(args); exit(0) } catch { fputs("OpenVPNUI: DNS policy operation failed.\n", stderr); exit(1) }
        }
        guard args.isEmpty, geteuid() == 0 else { fputs("This helper is managed by the installer and launchd.\n", stderr); exit(1) }
        do {
            try privateDirectory(runtimeRoot)
            // A restart must not leave old VPN engines using abandoned DNS state.
            // The service's launchd job uses AbandonProcessGroup=false so children
            // are terminated before a new helper starts.
            let s = try store(); for key in SCDynamicStoreCopyKeyList(s, "^State:/Network/Service/OpenVPNUI-Mac-.*/DNS$" as CFString) as? [String] ?? [] { _ = SCDynamicStoreRemoveValue(s, key as CFString) }
            for file in try fm.contentsOfDirectory(atPath: runtimeRoot) { if UUID(uuidString: file) != nil { try fm.removeItem(atPath: runtimeRoot + "/" + file) } }
            unlink(socketPath)
            let listener = socket(AF_UNIX, SOCK_STREAM, 0); guard listener >= 0 else { throw VPNError("Cannot create service socket") }
            var address = sockaddr_un(); address.sun_family = sa_family_t(AF_UNIX); address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
            withUnsafeMutablePointer(to: &address.sun_path) { $0.withMemoryRebound(to: CChar.self, capacity: 104) { _ = strcpy($0, socketPath) } }
            let result = withUnsafePointer(to: &address) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(listener, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) } }
            guard result == 0, chmod(socketPath, 0o666) == 0, listen(listener, 8) == 0 else { throw VPNError("Cannot bind service socket") }
            DispatchQueue.global().async {
                while true {
                    Thread.sleep(forTimeInterval: 2)
                    var console = stat(); _ = lstat("/dev/console", &console)
                    withLock { for session in sessions.values where session.process.isRunning && (session.uid != console.st_uid) { session.stop() }
                        if !sessions.values.contains(where: { $0.process.isRunning }) { ownerUID = nil }
                    }
                }
            }
            while true {
                let fd = accept(listener, nil, nil); if fd < 0 { continue }
                DispatchQueue.global().async {
                    defer { close(fd) }; var timeout = timeval(tv_sec: 5, tv_usec: 0); setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size)); setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
                    let response: Response
                    do { let uid = try authorizedUID(fd); let request = try JSONDecoder().decode(Request.self, from: readFrame(fd)); response = try handleRequest(request, uid: uid) }
                    catch { response = Response(ok: false, error: (error as? VPNError)?.text ?? "Could not process the local request", sessions: [], engine: nil) }
                    if var data = try? JSONEncoder().encode(response) { data.append(10); try? writeAll(fd, data) }
                }
            }
        } catch { fputs("OpenVPNUI system helper startup failed.\n", stderr); exit(1) }
    }
}

#endif
