import Foundation
import Darwin

func check(_ value: Bool, _ message: String) throws { if !value { throw VPNError(message) } }
@main struct HelperTests {
    static func main() throws {
        let profile = Profile(id: "test", name: "test", configuration: "", dnsRules: [], useSnapshotDNS: false)
        let session = Session(profile: profile, uid: getuid())
        var descriptors = [Int32](repeating: -1, count: 2)
        guard socketpair(AF_UNIX, SOCK_STREAM, 0, &descriptors) == 0 else { throw VPNError("socketpair") }
        session.managementFD = descriptors[0]; defer { close(descriptors[0]); close(descriptors[1]) }
        try session.credentials(Request(action: "credentials", username: "test-user", password: "one-time-password", keyPassword: "private-secret", retainAuth: false, retainKey: false))
        session.handle(">PASSWORD:Need 'Auth' username/password")
        let first = String(decoding: try readFrame(descriptors[1]), as: UTF8.self); let second = String(decoding: try readFrame(descriptors[1]), as: UTF8.self)
        try check(first == "username \"Auth\" \"test-user\"" && second == "password \"Auth\" \"one-time-password\"", "Management auth response")
        try check(session.password == nil && session.status.challenge == nil, "Do not retain one-time password")
        session.handle(">PASSWORD:Need 'Private Key' password")
        let keyResponse = String(decoding: try readFrame(descriptors[1]), as: UTF8.self)
        try check(keyResponse == "password \"Private Key\" \"private-secret\"" && session.keyPassword == nil, "Private-key response is one-time")
        try session.credentials(Request(action: "credentials", username: "test-user", password: "retained-secret", retainAuth: true))
        session.handle(">PASSWORD:Need 'Auth' username/password"); _ = try readFrame(descriptors[1]); _ = try readFrame(descriptors[1])
        try check(session.password == "retained-secret", "Session auth must survive renegotiation")
        session.handle(">PASSWORD:Verification Failed: 'Auth'")
        try check(session.password == nil && session.status.state == "credentials", "Failed auth clears cached password")
        session.status.challenge = nil
        session.handle(">PASSWORD:Need 'Auth' username/password SC:0,One-time code")
        try check(session.status.challengeText != nil && session.password == nil, "Static challenge needs explicit answer")
        try session.credentials(Request(action: "credentials", username: "test-user", password: "base-password", challengeResponse: "123456"))
        _ = try readFrame(descriptors[1]); let sc = String(decoding: try readFrame(descriptors[1]), as: UTF8.self)
        try check(sc.contains("SCRV1:" + Data("base-password".utf8).base64EncodedString() + ":" + Data("123456".utf8).base64EncodedString()), "Static challenge encoding")
        session.handle(">PASSWORD:Need 'HTTP Proxy' username/password")
        try check(session.password == nil && session.username == nil && session.status.challenge == "HTTP Proxy", "Never send VPN credentials to proxy")
        try session.credentials(Request(action: "credentials", username: "proxy-user", password: "proxy-password", retainAuth: false))
        let proxyUser = String(decoding: try readFrame(descriptors[1]), as: UTF8.self); let proxyPassword = String(decoding: try readFrame(descriptors[1]), as: UTF8.self)
        try check(proxyUser.contains("\"HTTP Proxy\" \"proxy-user\"") && proxyPassword.contains("\"HTTP Proxy\" \"proxy-password\""), "Proxy credentials use separate management realm")
        try check(session.password == nil, "Proxy password must not become VPN password")
        session.handle(">BYTECOUNT:1024,2048"); session.lastBytes = (1024, 2048, Date().addingTimeInterval(-1)); session.handle(">BYTECOUNT:2048,4096")
        try check(session.status.bytesIn == 2048 && session.status.bytesOut == 4096 && (session.status.rateIn ?? 0) > 900, "Traffic statistics")
        session.status.challenge = nil
        session.handle(">STATE:123,WAIT,,,,,,")
        try check(session.status.message == "Waiting for the VPN server to respond", "Show the current connection phase")
        session.handle(">STATE:124,RECONNECTING,tls-error,,,,,")
        try check(session.status.message.contains("tls-error"), "Show the reconnect reason")
        let liveLog = Session(profile: profile, uid: getuid())
        let pipe = Pipe(); liveLog.captureOutput(from: pipe)
        defer { pipe.fileHandleForReading.readabilityHandler = nil; try? pipe.fileHandleForWriting.close() }
        try pipe.fileHandleForWriting.write(contentsOf: Data("TLS Error: key negotiation failed\n".utf8))
        let logDeadline = Date().addingTimeInterval(2)
        while withLock({ liveLog.log.isEmpty }) && Date() < logDeadline { Thread.sleep(forTimeInterval: 0.01) }
        try check(withLock({ liveLog.log.first == "TLS Error: key negotiation failed" }), "Short log lines must arrive while OpenVPN is still running")
        session.canceled = true; session.failureMessage = "Split DNS is not configured"; session.status.state = "disconnecting"
        session.stop(failure: "Could not control OpenVPN")
        session.handle(">STATE:125,WAIT,,,,,,")
        try check(session.failureMessage == "Split DNS is not configured" && session.status.state == "disconnecting", "Expected shutdown must preserve the original failure and state")
        session.receiveOutput(Data("line with retained-secret\nAUTH_FAILED\n".utf8))
        try check(!session.log.joined().contains("retained-secret") && session.status.errorCode == "Password", "Logs redact auth and classify errors")
        for _ in 0..<2100 { session.appendLog(String(repeating: "x", count: 512)) }
        try check(session.log.count <= 2000 && session.logBytes <= 500_000, "Bounded log fits IPC frame")
        do { try verifyAdministratorAuthorization(nil); throw VPNError("Missing admin authorization accepted") } catch let failure as VPNError { try check(failure.text == "Administrator authorization required", "Admin operation must require authorization") }
        print("PASS: management auth, key prompts, retry, one-time/session retention, static challenge, traffic, live pipe logs, connection phases, original shutdown errors, bounded redacted log, admin authorization requirement")
    }
}
