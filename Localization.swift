import Foundation

enum AppLanguage: String, CaseIterable, Identifiable {
    case english = "en", ukrainian = "uk"
    var id: String { rawValue }
    var name: String { self == .english ? "English" : "Українська" }
    var locale: Locale { Locale(identifier: rawValue) }
}

enum Localization {
    static let preferenceKey = "interfaceLanguage"
    private static let lock = NSLock()
    private static var selected: AppLanguage = .english
    static var language: AppLanguage {
        get { lock.lock(); defer { lock.unlock() }; return selected }
        set { lock.lock(); defer { lock.unlock() }; selected = newValue }
    }

    // This app's preference is independent of the Mac's language and profile data.
    static func savedLanguage(in defaults: UserDefaults = .standard) -> AppLanguage {
        let saved = defaults.string(forKey: preferenceKey)
        // Ukrainian replaces the Russian option offered by version 0.2.2.
        if saved == "ru" { return .ukrainian }
        return saved.flatMap(AppLanguage.init(rawValue:)) ?? .english
    }
    static func select(_ value: AppLanguage, defaults: UserDefaults = .standard) {
        language = value
        defaults.set(value.rawValue, forKey: preferenceKey)
        defaults.set([value.rawValue], forKey: "AppleLanguages")
    }
    static func configure() { select(savedLanguage()) }

    private static let placeholder = try! NSRegularExpression(pattern: #"\{([0-9]+)\}"#)
    static func format(_ template: String, arguments: [String]) -> String {
        let source = template as NSString
        var result = template
        // Replace from the end once; argument text is never interpreted as a template.
        for match in placeholder.matches(in: template, range: NSRange(location: 0, length: source.length)).reversed() {
            guard let index = Int(source.substring(with: match.range(at: 1))), arguments.indices.contains(index), let range = Range(match.range, in: result) else { continue }
            result.replaceSubrange(range, with: arguments[index])
        }
        return result
    }
    static func text(_ key: String, arguments: [String] = [], language: AppLanguage? = nil) -> String {
        let template = (language ?? self.language) == .ukrainian ? ukrainianTranslations[key] ?? key : key
        return format(template, arguments: arguments)
    }

    private struct MessagePattern {
        let key: String
        let expression: NSRegularExpression
        let indices: [Int]
        init(key: String, template: String) {
            self.key = key
            let source = template as NSString
            var pattern = "\\A", end = 0, indices: [Int] = []
            for match in placeholder.matches(in: template, range: NSRange(location: 0, length: source.length)) {
                pattern += NSRegularExpression.escapedPattern(for: source.substring(with: NSRange(location: end, length: match.range.location - end))) + "(.*?)"
                indices.append(Int(source.substring(with: match.range(at: 1)))!)
                end = NSMaxRange(match.range)
            }
            pattern += NSRegularExpression.escapedPattern(for: source.substring(from: end)) + "\\z"
            self.indices = indices
            expression = try! NSRegularExpression(pattern: pattern, options: [.dotMatchesLineSeparators])
        }
        func arguments(in value: String) -> [String]? {
            let source = value as NSString
            guard let match = expression.firstMatch(in: value, range: NSRange(location: 0, length: source.length)) else { return nil }
            var args = [String](repeating: "", count: (indices.max() ?? -1) + 1)
            for (group, index) in indices.enumerated() { args[index] = source.substring(with: match.range(at: group + 1)) }
            return args
        }
    }
    private static let reverse = Dictionary(ukrainianTranslations.map { ($0.value, $0.key) }, uniquingKeysWith: { first, _ in first })
    private static let patterns: [MessagePattern] = ukrainianTranslations.keys.filter { $0.contains("{0}") }.sorted { $0.count > $1.count }.flatMap { key in
        [MessagePattern(key: key, template: key), MessagePattern(key: key, template: ukrainianTranslations[key]!)]
    }

    // The helper's wire messages stay in English. Render owned messages at the UI
    // boundary using the selected English or Ukrainian catalog.
    // Server challenges, log lines and user-supplied profile data remain verbatim.
    static func message(_ value: String) -> String {
        if ukrainianTranslations[value] != nil { return text(value) }
        if let key = reverse[value] { return text(key) }
        for pattern in patterns {
            if let arguments = pattern.arguments(in: value) { return text(pattern.key, arguments: arguments) }
        }
        return value
    }
}

func L(_ key: String, _ arguments: String...) -> String { Localization.text(key, arguments: arguments) }
