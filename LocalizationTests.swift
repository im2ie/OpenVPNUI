import Foundation

func testLocalization() throws {
    let suite = "OpenVPNUI.LocalizationTests." + UUID().uuidString
    let defaults = UserDefaults(suiteName: suite)!
    defer { defaults.removePersistentDomain(forName: suite); Localization.language = .english }
    defaults.set(["uk"], forKey: "AppleLanguages")
    try require(Localization.savedLanguage(in: defaults) == .english, "First launch defaults to English even on a Ukrainian Mac")
    defaults.set("unsupported-language", forKey: Localization.preferenceKey)
    try require(Localization.savedLanguage(in: defaults) == .english, "Unknown saved language falls back to English")
    try require(AppLanguage.allCases.map(\.rawValue) == ["en", "uk"] && AppLanguage.ukrainian.name == "Українська", "Only English and Ukrainian are selectable")
    defaults.set("ru", forKey: Localization.preferenceKey)
    try require(Localization.savedLanguage(in: defaults) == .ukrainian, "A saved Russian choice migrates to Ukrainian")
    Localization.select(Localization.savedLanguage(in: defaults), defaults: defaults)
    let reloaded = UserDefaults(suiteName: suite)!
    try require(Localization.savedLanguage(in: reloaded) == .ukrainian && reloaded.string(forKey: Localization.preferenceKey) == "uk" && reloaded.stringArray(forKey: "AppleLanguages") == ["uk"], "Language choice survives a new preferences instance")
    try require(L("Connections") == "Підключення" && SavePolicy.persistent.title == "У В’язці ключів", "UI and password policies use the selected language")
    let status = SessionStatus(id: "fixture", state: "connecting", message: "Waiting for the VPN server to respond")
    let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys]
    let wire = try encoder.encode(status)
    try require(status.localizedMessage == "Очікування відповіді VPN-сервера", "Helper status is localized at display time")
    try require(VPNError("Unsupported VPN option: plugin").localizedDescription == "Непідтримуваний параметр VPN: plugin", "Parameterized helper errors are translated")
    try require(Localization.message("Reconnecting: tls-error") == "Повторне підключення: tls-error", "Reconnect reason is preserved")
    try require(Localization.message("Server MFA prompt: %s {0}\nВведіть код") == "Server MFA prompt: %s {0}\nВведіть код", "Unknown server text is preserved verbatim")
    let inserted = "Customer {1} %s / Компанія"
    try require(Localization.format("{0} then {1}", arguments: [inserted, "last"]) == inserted + " then last", "User text is never interpreted as a format string")
    try require(L("Certificate chain: {0}", "21") == "Сертифікатів у ланцюжку: 21", "Numeric arguments survive localization")
    Localization.select(.english, defaults: defaults)
    try require(status.localizedMessage == status.message && (try encoder.encode(status)) == wire, "Switching language never modifies helper wire data")
    try require(Localization.message("Очікування відповіді VPN-сервера") == status.message, "Already localized messages can switch back to English")
    try require(L("Language") == "Language" && Localization.savedLanguage(in: reloaded) == .english, "Switch back to English persists")
    Localization.select(.ukrainian, defaults: defaults)
    try require(Localization.savedLanguage(in: reloaded) == .ukrainian, "Explicit Ukrainian choice persists")
    let regex = try NSRegularExpression(pattern: #"\{[0-9]+\}"#)
    func placeholders(_ value: String) -> [String] {
        regex.matches(in: value, range: NSRange(value.startIndex..., in: value)).map { (value as NSString).substring(with: $0.range) }.sorted()
    }
    for (key, translation) in ukrainianTranslations {
        try require(!translation.isEmpty && placeholders(key) == placeholders(translation), "Translation placeholder mismatch: " + key)
        try require(!key.unicodeScalars.contains { (0x0400...0x04FF).contains($0.value) }, "English catalog key contains Cyrillic: " + key)
    }
    print("PASS: English default, saved Ukrainian/English choice, live status/error translation, saved ru-to-uk migration, safe interpolation and catalog placeholders")
}
