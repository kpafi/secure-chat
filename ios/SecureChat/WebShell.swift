import Foundation
import WebKit

/// The local origin the bundled client is served from.
///
/// WKWebView refuses to let an app handle `https://` itself, so unlike Android
/// (`https://secure-chat.internal` via WebViewAssetLoader) the iOS shell serves
/// the client from a custom URL scheme through `AppSchemeHandler`. WebKit treats
/// a scheme registered with `setURLSchemeHandler` as a secure context, which is
/// what `crypto.subtle` needs; the simulator test suite asserts it
/// (`InPageTests.testSecureContextAndWebCrypto`) rather than taking it on trust.
///
/// The relay allow-lists exactly this origin (`backend/config.py`
/// `IOS_WEBVIEW_ORIGIN`; `backend/tests/test_csp_hash.py` guards the two copies).
enum AppOrigin {
    static let scheme = "secure-chat"
    static let host = "app"
    static let origin = "secure-chat://app"
    static let indexURL = URL(string: "secure-chat://app/index.html")!

    static func isAppURL(_ url: URL?) -> Bool {
        guard let url = url else { return false }
        return url.scheme?.lowercased() == scheme && url.host == host && url.port == nil
            && url.user == nil && url.password == nil
    }

    static func isIndex(_ url: URL?) -> Bool {
        isAppURL(url) && url?.path == indexURL.path
    }
}

/// Builds the WKWebView the client runs in. Shared by the app and the simulator
/// tests, so the tests exercise the exact configuration that ships.
enum WebShell {
    /// SHA-256 of the inline import map in `client/index.html`, pinned in
    /// `script-src`. Identical to the web and Android copies; drift is caught
    /// by `backend/tests/test_csp_hash.py::test_ios_importmap_hash_matches`.
    static let importMapHash = "sha256-6Sm2nhNvoa7gr7uuY2hbAbpdWhIlL15/wXLm4dhO9UQ="

    /// The bundled client: `<App>.app/web`, copied from `../client` at build time
    /// by `scripts/sync-web.sh`.
    static var webRoot: URL {
        Bundle.main.bundleURL.appendingPathComponent("web", isDirectory: true)
    }

    /// Same policy as the Android shell (MainActivity.csp): nothing but the
    /// bundled files and the one configured relay is reachable.
    static func csp(relay: RelayUrls?) -> String {
        let connect = relay.map { "\($0.httpOrigin) \($0.wsOrigin)" } ?? ""
        return "default-src 'none'; " +
            "script-src 'self' '\(importMapHash)'; " +
            "style-src 'self'; " +
            "connect-src 'self' \(connect); " +
            "img-src 'self' data:; " +
            "base-uri 'none'; " +
            "form-action 'none'; " +
            "frame-ancestors 'none'"
    }

    /// The document-start script: the relay config and the protected pad-floor
    /// bridge. See `FloorBridge` for why the floor goes through `prompt()`.
    ///
    /// Everything here runs before any page script, so the builtins it touches
    /// (`prompt`, `Function.prototype.bind`, `Object.defineProperty`,
    /// `Object.freeze`) are still pristine — the same reasoning as the Android
    /// shell's H-A capture, which this mirrors line for line where it can.
    static func documentStartScript(relay: RelayUrls) -> String {
        // JSONSerialization escapes the values; RelayUrls.parse already
        // whitelists the host charset (the primary defence, 2026-07-08 F1).
        let config: [String: String] = ["api": relay.httpOrigin, "ws": relay.wsOrigin + "/ws"]
        let data = (try? JSONSerialization.data(withJSONObject: config, options: [.sortedKeys])) ?? Data("null".utf8)
        let json = String(decoding: data, as: UTF8.self)
        let mark = FloorBridge.jsPrefixLiteral
        let sep = FloorBridge.jsSeparatorLiteral
        return """
        window.__SECURE_CHAT_RELAY__ = \(json);
        (function () {
          var p = window.prompt;
          var ok = typeof p === 'function';
          if (ok) {
            // Bound NOW: a later `window.prompt = fake` cannot reach this copy.
            var ask0 = p.bind(window);
            // The answer is a decimal string. It becomes a number through unary
            // plus (a language operator, no global behind it) and is accepted
            // only as an int32 — no parseInt/Number/RegExp, all of which a page
            // script could poison (Android fix review round 2, H-1). Anything
            // else is TAMPERED (-2), never "no floor".
            var ask = function (op, id, v) {
              if (typeof id !== 'string') return -2;
              var r = ask0('\(mark)' + op + '\(sep)' + id + '\(sep)' + v);
              if (typeof r !== 'string' || r.length === 0 || r.length > 20) return -2;
              var n = +r;
              return ((n | 0) === n) ? n : -2;
            };
            Object.defineProperty(window, '__SECURE_CHAT_PAD_FLOOR__', {
              value: Object.freeze({
                read: function (id) { return ask('read', id, 0); },
                bump: function (id, v) { return ask('bump', id, v | 0); }
              }),
              writable: false, configurable: false, enumerable: false
            });
          }
          Object.defineProperty(window, '__SECURE_CHAT_NATIVE_FLOOR__', {
            value: ok ? true : 'unavailable',
            writable: false, configurable: false, enumerable: false
          });
        })();
        """
    }

    /// The probe run after the page loads (Android `verifyRelayConfig`, L-10):
    /// both halves of the document-start script must have landed.
    static let verifyScript =
        "!!window.__SECURE_CHAT_RELAY__ && window.__SECURE_CHAT_NATIVE_FLOOR__ === true " +
        "&& typeof (window.__SECURE_CHAT_PAD_FLOOR__||{}).read === 'function' " +
        "&& typeof (window.__SECURE_CHAT_PAD_FLOOR__||{}).bump === 'function'"

    /// A configuration with the scheme handler and the document-start script.
    /// `relay` is read on every index.html response, so a relay change followed
    /// by `install(relay:into:)` and a reload re-pins the CSP.
    @MainActor
    static func configuration(
        relay: @escaping () -> RelayUrls?,
        dataStore: WKWebsiteDataStore = .default()
    ) -> WKWebViewConfiguration {
        let config = WKWebViewConfiguration()
        let handler = AppSchemeHandler(root: webRoot, csp: { WebShell.csp(relay: relay()) })
        config.setURLSchemeHandler(handler, forURLScheme: AppOrigin.scheme)
        config.websiteDataStore = dataStore
        config.preferences.javaScriptCanOpenWindowsAutomatically = false
        config.dataDetectorTypes = []
        config.allowsInlineMediaPlayback = false
        config.suppressesIncrementalRendering = false
        if let r = relay() { install(relay: r, into: config.userContentController) }
        return config
    }

    /// (Re)install the document-start script for `relay`.
    @MainActor
    static func install(relay: RelayUrls, into controller: WKUserContentController) {
        controller.removeAllUserScripts()
        controller.addUserScript(WKUserScript(
            source: documentStartScript(relay: relay),
            injectionTime: .atDocumentStart,
            forMainFrameOnly: true
        ))
    }

    @MainActor
    static func makeWebView(configuration: WKWebViewConfiguration) -> WKWebView {
        let wv = WKWebView(frame: .zero, configuration: configuration)
        // Web Inspector exposes the page (and its localStorage identity blob) —
        // debug builds only, like the Android shell's remote debugging.
        #if DEBUG
        wv.isInspectable = true
        #else
        wv.isInspectable = false
        #endif
        wv.allowsLinkPreview = false
        wv.allowsBackForwardNavigationGestures = false
        wv.isOpaque = false
        wv.backgroundColor = Theme.bg
        wv.scrollView.backgroundColor = Theme.bg
        return wv
    }

    /// True when `frame` is our own page's main frame — the only frame allowed
    /// to raise dialogs or reach the floor.
    @MainActor
    static func isAppMainFrame(_ frame: WKFrameInfo) -> Bool {
        frame.isMainFrame
            && frame.securityOrigin.protocol == AppOrigin.scheme
            && frame.securityOrigin.host == AppOrigin.host
    }
}
