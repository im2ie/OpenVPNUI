import Foundation

func testLocalization() throws {
    let suite = "OpenVPNUI.LocalizationTests." + UUID().uuidString
    let defaults = UserDefaults(suiteName: suite)!
    defer { defaults.removePersistentDomain(forName: suite); Localization.language = .english }
    defaults.set(["ru"], forKey: "AppleLanguages")
    try require(Localization.savedLanguage(in: defaults) == .english, "First launch defaults to English even on a Russian Mac")
    defaults.set("unsupported-language", forKey: Localization.preferenceKey)
    try require(Localization.savedLanguage(in: defaults) == .english, "Unknown saved language falls back to English")
    Localization.select(.russian, defaults: defaults)
    let reloaded = UserDefaults(suiteName: suite)!
    try require(Localization.savedLanguage(in: reloaded) == .russian && reloaded.stringArray(forKey: "AppleLanguages") == ["ru"], "Language choice survives a new preferences instance")
    try require(L("Connections") == "Подключения" && SavePolicy.persistent.title == "В Связке ключей", "UI and password policies use the selected language")
    let status = SessionStatus(id: "fixture", state: "connecting", message: "Waiting for the VPN server to respond")
    let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys]
    let wire = try encoder.encode(status)
    try require(status.localizedMessage == "Ожидание ответа VPN-сервера", "Helper status is localized at display time")
    try require(VPNError("Unsupported VPN option: plugin").localizedDescription == "Неподдерживаемый параметр VPN: plugin", "Parameterized helper errors are translated")
    try require(Localization.message("Reconnecting: tls-error") == "Повторное подключение: tls-error", "Reconnect reason is preserved")
    try require(Localization.message("Server MFA prompt: %s {0}\nВведите код") == "Server MFA prompt: %s {0}\nВведите код", "Unknown server text is preserved verbatim")
    let inserted = "Customer {1} %s / Компания"
    try require(Localization.format("{0} then {1}", arguments: [inserted, "last"]) == inserted + " then last", "User text is never interpreted as a format string")
    try require(L("Certificate chain: {0}", "21") == "Цепочка: 21 сертификатов", "Numeric arguments survive localization")
    Localization.select(.english, defaults: defaults)
    try require(status.localizedMessage == status.message && (try encoder.encode(status)) == wire, "Switching language never modifies helper wire data")
    try require(Localization.message("Ожидание ответа VPN-сервера") == status.message, "Old helper messages render in English during an upgrade")
    try require(L("Language") == "Language" && Localization.savedLanguage(in: reloaded) == .english, "Switch back to English persists")
    let regex = try NSRegularExpression(pattern: #"\{[0-9]+\}"#)
    func placeholders(_ value: String) -> [String] {
        regex.matches(in: value, range: NSRange(value.startIndex..., in: value)).map { (value as NSString).substring(with: $0.range) }.sorted()
    }
    for (key, translation) in russianTranslations {
        try require(!translation.isEmpty && placeholders(key) == placeholders(translation), "Translation placeholder mismatch: " + key)
        try require(!key.unicodeScalars.contains { (0x0400...0x04FF).contains($0.value) }, "English catalog key contains Cyrillic: " + key)
    }
    print("PASS: English default, saved Russian/English choice, live status/error translation, legacy helper compatibility, safe interpolation and catalog placeholders")
}
