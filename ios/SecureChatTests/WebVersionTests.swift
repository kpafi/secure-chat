import UIKit
import WebKit
import XCTest
@testable import SecureChat

/// The WEB version on iOS WebKit — what a user gets from Safari or the Home
/// Screen web app: the client served by the relay itself (same origin, the
/// relay's own CSP), in a plain WKWebView with none of the app shell's
/// injections. It pins that the web client works on iOS WebKit and that the
/// Home Screen pieces (manifest, icons, meta tags, manifest-src) are served.
///
/// What this cannot show: Safari's standalone (home-screen) mode itself — no
/// API drives "Add to Home Screen". The CI also opens the page in Mobile
/// Safari for a screenshot.
@MainActor
final class WebVersionTests: XCTestCase {
    private var webView: WKWebView?

    override func tearDown() async throws {
        webView?.removeFromSuperview()
        webView = nil
    }

    func testRelayServedWebClientRunsOnIOSWebKit() async throws {
        let relay = try XCTUnwrap(Prefs.relay(), "SC_TEST_RELAY not set")
        let url = try XCTUnwrap(URL(string: relay.httpOrigin + "/"))
        guard let window = TestApp.window else { return XCTFail("no window") }

        let config = WKWebViewConfiguration()
        config.websiteDataStore = .nonPersistent()
        let wv = WKWebView(frame: window.bounds, configuration: config)
        window.addSubview(wv)
        webView = wv
        wv.load(URLRequest(url: url))
        let page = Page(wv, label: "web")
        try await page.waitUntil("document.readyState === 'complete' && !!document.querySelector('#idCreate')", timeout: 30)

        let r = try await page.eval("""
            const out = {
              secure: isSecureContext,
              shell: window.__SECURE_CHAT_RELAY__ === undefined && window.__SECURE_CHAT_NATIVE_FLOOR__ === undefined,
              manifestLink: document.querySelector('link[rel=manifest]')?.getAttribute('href'),
              touchIcon: document.querySelector('link[rel=apple-touch-icon]')?.getAttribute('href'),
              theme: document.querySelector('meta[name=theme-color]')?.content,
              capable: document.querySelector('meta[name=apple-mobile-web-app-capable]')?.content,
              viewport: document.querySelector('meta[name=viewport]')?.content,
            };
            try {
              const k = await crypto.subtle.generateKey({ name: 'Ed25519' }, false, ['sign', 'verify']);
              out.ed25519 = !!k.privateKey;
            } catch (e) { out.ed25519 = String(e); }
            const idx = await fetch('index.html', { cache: 'no-store' });
            out.csp = idx.headers.get('content-security-policy');
            const mr = await fetch(out.manifestLink);
            out.manifestType = mr.headers.get('content-type');
            const m = await mr.json();
            out.display = m.display; out.startUrl = m.start_url; out.name = m.name;
            out.icons = [];
            for (const i of m.icons.concat([{ src: out.touchIcon }])) {
              const ir = await fetch(i.src);
              out.icons.push(ir.status + ' ' + ir.headers.get('content-type'));
            }
            return out;
            """) as? [String: Any]
        XCTAssertEqual(r?["secure"] as? Bool, true, "\(String(describing: r))")
        XCTAssertEqual(r?["shell"] as? Bool, true, "this must be the plain web client, not the app shell")
        XCTAssertEqual(r?["ed25519"] as? Bool, true, "\(String(describing: r))")
        XCTAssertEqual(r?["manifestLink"] as? String, "manifest.webmanifest")
        XCTAssertEqual(r?["touchIcon"] as? String, "icons/icon-180.png")
        XCTAssertEqual(r?["theme"] as? String, "#0d1117")
        XCTAssertEqual(r?["capable"] as? String, "yes")
        // Without viewport-fit=cover every env(safe-area-inset-*) is 0 and the
        // tab bar would sit under the home indicator in standalone mode.
        XCTAssertTrue((r?["viewport"] as? String)?.contains("viewport-fit=cover") == true, "\(String(describing: r?["viewport"]))")
        XCTAssertTrue((r?["csp"] as? String)?.contains("manifest-src 'self'") == true, "\(String(describing: r?["csp"]))")
        XCTAssertTrue((r?["manifestType"] as? String)?.hasPrefix("application/manifest+json") == true)
        XCTAssertEqual(r?["display"] as? String, "standalone")
        XCTAssertEqual(r?["name"] as? String, "secure-chat")
        XCTAssertEqual(r?["icons"] as? [String], Array(repeating: "200 image/png", count: 4))

        // A user's first steps in the web version: create an identity, register.
        try await page.type("#idPass", "ios web passphrase — test only")
        try await page.click("#idCreate")
        try await page.waitUntil("!document.querySelector('#idExport').hidden", timeout: 60)
        let name = "ios-web-" + String(UInt64(Date().timeIntervalSince1970 * 1000) % 1_679_616, radix: 36)
        try await page.type("#username", name)
        try await page.click("#register")
        try await page.waitUntil("/registered/i.test(document.querySelector('#accountStatus').textContent)", timeout: 45)
        try await Task.sleep(nanoseconds: 600_000_000)
        TestApp.screenshot("30-web-version-registered", view: window)
    }
}
