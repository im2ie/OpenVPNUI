import Foundation

struct CertificateManager {
    let root: URL
    var tool: URL { Bundle.main.url(forResource: "p12tool", withExtension: nil) ?? Bundle.main.executableURL!.deletingLastPathComponent().appendingPathComponent("p12tool") }
    func identity(_ id: String) -> URL { root.appendingPathComponent("identities/" + id + ".p12") }
    func pendingKey(_ id: String) -> URL { root.appendingPathComponent("requests/" + id + ".key") }
    func call(_ args: [String], passwords: [String] = []) throws -> Data {
        guard passwords.allSatisfy({ $0.utf8.count <= 4096 && !$0.contains("\n") && !$0.contains("\r") && !$0.contains("\0") }) else { throw VPNError("Invalid characters in password") }
        let result = try runTool(tool, args, input: Data((passwords.joined(separator: "\n") + "\n").utf8), timeout: 120)
        guard result.status == 0 else {
            let messages: [Int32: String] = [4: "The new password must contain at least 8 characters", 5: "Could not read the certificate", 6: "Incorrect password or private key format", 9: "Could not create the file", 12: "Check the certificate request fields", 16: "The certificate does not match the profile CA or has expired", 17: "The CA response does not match the private key"]
            throw VPNError(messages[result.status] ?? "Certificate processing failed (\(result.status))")
        }
        return result.output
    }
    func inspect(_ file: URL, password: String? = nil) throws -> CertificateRecord {
        try JSONDecoder().decode(CertificateRecord.self, from: call([password == nil ? "--inspect-cert" : "--inspect", file.path], passwords: password.map { [$0] } ?? []))
    }
    func importIdentity(_ file: URL, key: URL? = nil, password: String, newPassword: String? = nil) throws -> CertificateRecord {
        _ = try readBounded(file); if let key { _ = try readBounded(key) }
        let fresh = try newPassword ?? Vault.randomPassword()
        let temporary = root.appendingPathComponent("import-" + UUID().uuidString + ".p12")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: temporary) }
        if let key { _ = try call(["--import-pem", file.path, key.path, temporary.path], passwords: [password, fresh]) }
        else { _ = try call(["--protect", file.path, temporary.path], passwords: [password, fresh]) }
        var record = try inspect(temporary, password: fresh); record.generatedPassword = newPassword == nil
        let target = identity(record.id); let previous = try? Data(contentsOf: target); let previousPassword = try? Vault.read("key-" + record.id)
        do { try Vault.save(fresh, account: "key-" + record.id); try privateWrite(readBounded(temporary), to: target) }
        catch { if let previous { try? privateWrite(previous, to: target) }; if let previousPassword { try? Vault.save(previousPassword, account: "key-" + record.id) } else { Vault.remove("key-" + record.id) }; throw error }
        return record
    }
    func replacePassword(_ record: CertificateRecord, old: String, new: String) throws -> CertificateRecord {
        try importIdentity(identity(record.id), password: old, newPassword: new)
    }
    func createRequest(fields: [String], algorithm: String) throws -> EnrollmentRecord {
        guard fields.count == 7, !fields[0].isEmpty, fields[5].count == 2 else { throw VPNError("Enter a name and a two-letter country code") }
        let id = UUID().uuidString.lowercased(), pass = try Vault.randomPassword(); let key = pendingKey(id)
        let csr = root.appendingPathComponent("requests/" + id + ".csr")
        try FileManager.default.createDirectory(at: key.deletingLastPathComponent(), withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        do {
            _ = try call(["--csr", key.path, csr.path, algorithm] + fields, passwords: [pass])
            try Vault.save(pass, account: "request-" + id)
            return EnrollmentRecord(id: id, commonName: fields[0], algorithm: algorithm, request: String(decoding: try readBounded(csr), as: UTF8.self), createdAt: Date())
        } catch { try? FileManager.default.removeItem(at: key); try? FileManager.default.removeItem(at: csr); throw error }
    }
    func completeRequest(_ request: EnrollmentRecord, response: URL) throws -> CertificateRecord {
        let keyPass = try Vault.read("request-" + request.id)
        return try importIdentity(response, key: pendingKey(request.id), password: keyPass)
    }
    func deleteRequest(_ request: EnrollmentRecord) throws {
        for ext in ["key", "csr"] { let file = root.appendingPathComponent("requests/" + request.id + "." + ext); if FileManager.default.fileExists(atPath: file.path) { try FileManager.default.removeItem(at: file) } }
        Vault.remove("request-" + request.id)
    }
    func matches(_ record: CertificateRecord, ca: Data) -> Bool {
        let temporary = FileManager.default.temporaryDirectory.appendingPathComponent("certificate-check-" + UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: temporary) }
        do {
            let cert = temporary.appendingPathComponent("certificate.pem"), authority = temporary.appendingPathComponent("ca.pem")
            try privateWrite(Data((record.certificate + record.chain.joined(separator: "\n")).utf8), to: cert); try privateWrite(ca, to: authority)
            _ = try call(["--matches-cert-ca", cert.path, authority.path]); return true
        } catch { return false }
    }
}
