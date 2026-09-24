import Foundation

/// The only app-level persisted setting: which relay to talk to. Identity keys,
/// contacts and chats live in the web view's localStorage, managed (and
/// encrypted) by the bundled client — never here.
enum Prefs {
    private static let relayKey = "relay_http_origin"

    static func relay(_ defaults: UserDefaults = .standard) -> RelayUrls? {
        guard let stored = defaults.string(forKey: relayKey) else { return nil }
        return RelayUrls.parse(stored)
    }

    static func setRelay(_ relay: RelayUrls, _ defaults: UserDefaults = .standard) {
        defaults.set(relay.httpOrigin, forKey: relayKey)
    }
}
