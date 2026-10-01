import Foundation
import Security

enum Vault {
    static let service = "OpenVPNUI Mac Credentials"
    static func read(_ account: String, service: String = service) throws -> String {
        let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service, kSecAttrAccount as String: account, kSecReturnData as String: true, kSecMatchLimit as String: kSecMatchLimitOne]
        var result: CFTypeRef?; let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess, let data = result as? Data, let text = String(data: data, encoding: .utf8) else { throw VPNError("Пароль не найден в Связке ключей (\(status))") }; return text
    }
    static func save(_ text: String, account: String) throws {
        let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service, kSecAttrAccount as String: account]
        let attributes: [String: Any] = [kSecValueData as String: Data(text.utf8), kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly]
        let status = SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
        if status == errSecItemNotFound { var add = query; attributes.forEach { add[$0] = $1 }; guard SecItemAdd(add as CFDictionary, nil) == errSecSuccess else { throw VPNError("Не удалось сохранить пароль в Связке ключей") } }
        else if status != errSecSuccess { throw VPNError("Не удалось обновить пароль (\(status))") }
    }
    static func remove(_ account: String) { SecItemDelete([kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service, kSecAttrAccount as String: account] as CFDictionary) }
    static func randomPassword() throws -> String {
        var data = [UInt8](repeating: 0, count: 48); guard SecRandomCopyBytes(kSecRandomDefault, data.count, &data) == errSecSuccess else { throw VPNError("Генератор случайных чисел недоступен") }; return Data(data).base64EncodedString()
    }
}
struct LoginCredentials: Codable { var username: String; var password: String }

func administratorAuthorization() throws -> Data {
    var authorization: AuthorizationRef?
    guard AuthorizationCreate(nil, nil, [], &authorization) == errAuthorizationSuccess, let authorization else { throw VPNError("Не удалось запросить права администратора") }
    defer { AuthorizationFree(authorization, []) }
    let status: OSStatus = "system.privilege.admin".withCString { name in
        var item = AuthorizationItem(name: name, valueLength: 0, value: nil, flags: 0)
        return withUnsafeMutablePointer(to: &item) { pointer in
            var rights = AuthorizationRights(count: 1, items: pointer)
            return AuthorizationCopyRights(authorization, &rights, nil, [.interactionAllowed, .extendRights, .preAuthorize], nil)
        }
    }
    guard status == errAuthorizationSuccess else { throw VPNError("Права администратора не получены (\(status))") }
    var external = AuthorizationExternalForm(); guard AuthorizationMakeExternalForm(authorization, &external) == errAuthorizationSuccess else { throw VPNError("Не удалось передать авторизацию помощнику") }
    return withUnsafeBytes(of: external) { Data($0) }
}
func verifyAdministratorAuthorization(_ data: Data?) throws {
    guard let data, data.count == MemoryLayout<AuthorizationExternalForm>.size else { throw VPNError("Administrator authorization required") }
    var external = AuthorizationExternalForm(); _ = withUnsafeMutableBytes(of: &external) { data.copyBytes(to: $0) }
    var authorization: AuthorizationRef?; guard AuthorizationCreateFromExternalForm(&external, &authorization) == errAuthorizationSuccess, let authorization else { throw VPNError("Invalid administrator authorization") }; defer { AuthorizationFree(authorization, []) }
    let status: OSStatus = "system.privilege.admin".withCString { name in
        var item = AuthorizationItem(name: name, valueLength: 0, value: nil, flags: 0)
        return withUnsafeMutablePointer(to: &item) { pointer in var rights = AuthorizationRights(count: 1, items: pointer); return AuthorizationCopyRights(authorization, &rights, nil, [.extendRights], nil) }
    }
    guard status == errAuthorizationSuccess else { throw VPNError("Administrator authorization was not granted") }
}
