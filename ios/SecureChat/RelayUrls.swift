import Foundation

/// The relay the app talks to, split into the exact origins the client and the
/// CSP need. Port of `android/.../RelayUrls.kt`, with one iOS-specific rule:
/// plain `http` is accepted for a LOOPBACK host only.
///
/// Why stricter than Android: the page is a secure context, so WebKit's
/// mixed-content blocker refuses `ws://` to anything but loopback, and App
/// Transport Security refuses cleartext below that (Info.plist allows local
/// networking only). A LAN or `.onion` http relay therefore could never
/// connect; refusing it at input time is a clear error instead of a silent
/// dead app. (There is no Tor on iOS in this app, so `.onion` is out either
/// way — see ios/README.md.)
struct RelayUrls: Equatable {
    let httpOrigin: String  // e.g. https://relay.example.com (fetch /api)
    let wsOrigin: String    // e.g. wss://relay.example.com   (client appends /ws)

    /// Letters, digits, dot and hyphen. The parsed value is interpolated into
    /// the injected script and the CSP, so a permissive host is a code-execution
    /// vector (2026-07-08 Android pentest, Finding 1). Checked on the
    /// PERCENT-ENCODED host, so an encoded delimiter fails here too.
    private static let safeHost = CharacterSet(charactersIn:
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-")

    private static let loopbackHosts: Set<String> = ["127.0.0.1", "localhost"]

    static func parse(_ raw: String) -> RelayUrls? {
        var text = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        while text.hasSuffix("/") { text.removeLast() }
        guard !text.isEmpty, text.count <= 300 else { return nil }
        guard let c = URLComponents(string: text) else { return nil }
        guard let scheme = c.scheme?.lowercased(), scheme == "http" || scheme == "https" else { return nil }
        guard let host = c.percentEncodedHost, !host.isEmpty,
              host.unicodeScalars.allSatisfy({ safeHost.contains($0) }) else { return nil }
        // No credentials, and an origin only: no path, query or fragment.
        guard c.percentEncodedUser == nil, c.percentEncodedPassword == nil else { return nil }
        guard c.percentEncodedPath.isEmpty, c.percentEncodedQuery == nil,
              c.percentEncodedFragment == nil else { return nil }
        if scheme == "http" && !loopbackHosts.contains(host.lowercased()) { return nil }
        var portPart = ""
        if let port = c.port {
            guard (1...65535).contains(port) else { return nil }
            portPart = ":\(port)"
        }
        let ws = scheme == "https" ? "wss" : "ws"
        return RelayUrls(httpOrigin: "\(scheme)://\(host)\(portPart)",
                         wsOrigin: "\(ws)://\(host)\(portPart)")
    }
}
