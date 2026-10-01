import Foundation

@main struct CLI {
    static func main() {
        do { try run(Array(CommandLine.arguments.dropFirst())) }
        catch { fputs("OpenVPNUI: \(error.localizedDescription)\n", stderr); exit(1) }
    }
    static func run(_ args: [String]) throws {
        guard let action = args.first else { help(); return }
        if ["help", "--help", "-h"].contains(action) { help(); return }
        if action == "makefile" {
            guard args.count == 5 else { throw VPNError("makefile INPUT.ovpn CA.pem NAME OUTPUT.openvpn") }
            let source = URL(fileURLWithPath: args[1]); let ca = try normalizedCA(readBounded(URL(fileURLWithPath: args[2]))); var result = try importConnectionFile(source, caOverride: ca)
            defer { if let temp = result.temporaryDirectory { try? FileManager.default.removeItem(at: temp) } }
            guard result.certificateFile == nil && result.keyFile == nil else { throw VPNError("Ключи импортируются через приложение; makefile создаёт профиль без закрытого ключа") }
            result.profile.caData = ca; result.profile.name = args[3]
            try exportConnection(result.profile, to: URL(fileURLWithPath: args[4])); print("Profile created."); return
        }
        if action == "start" {
            guard args.count == 2, safeID(args[1]) else { throw VPNError("start PROFILE_ID") }
            let result = try runTool(URL(fileURLWithPath: "/usr/bin/open"), ["openvpnui://connect/" + args[1]])
            guard result.status == 0 else { throw VPNError("Не удалось открыть приложение для авторизации") }; return
        }
        let response: Response
        if action == "list" || action == "status" {
            response = try helperCall(Request(action: "status")); guard response.ok else { throw VPNError(response.error ?? "Service unavailable") }
            let root = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Library/Application Support/OpenVPNUI Mac/profiles.json")
            let store = try JSONDecoder().decode(ProfileStore.self, from: readBounded(root, max: 16_000_000))
            for profile in store.profiles { let state = response.sessions.first { $0.id == profile.id }?.state ?? "disconnected"; print("\(profile.id)\t\(state)\t\(profile.name)") }; return
        }
        guard ["stop", "log", "clear-log"].contains(action), args.count == 2, safeID(args[1]) else { throw VPNError("Неизвестная команда. Используйте --help.") }
        response = try helperCall(Request(action: action, id: args[1])); guard response.ok else { throw VPNError(response.error ?? "Command failed") }
        if action == "log" { print((response.log ?? []).joined(separator: "\n")) } else { print("OK") }
    }
    static func help() {
        print("""
        OpenVPNUI Mac command line
          list / status             Profiles and connection states
          start PROFILE_ID          Open local authorization window and connect
          stop PROFILE_ID           Disconnect a profile
          log PROFILE_ID            Read connection log
          clear-log PROFILE_ID      Clear connection log
          makefile INPUT.ovpn CA.pem NAME OUTPUT.openvpn
        Passwords are entered only in the application, never as command arguments.
        """)
    }
}
