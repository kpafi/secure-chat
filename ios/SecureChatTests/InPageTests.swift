import UIKit
import WebKit
import XCTest
@testable import SecureChat

/// Checks run INSIDE the shipped web view configuration, against the bundled
/// client, on the simulator. Each one pins an assumption the iOS port rests on
/// that cannot be checked anywhere but in real WebKit.
@MainActor
final class InPageTests: XCTestCase {
    private var vc: MainViewController!
    private var page: Page!

    override func setUp() async throws {
        (vc, page) = try await TestApp.mainPage()
    }

    /// The custom scheme must be a secure context, or crypto.subtle is absent
    /// and nothing works. Also records the Origin the relay will see.
    func test01SecureContextAndWebCrypto() async throws {
        let r = try await page.eval("""
            const out = { secure: isSecureContext, origin: location.origin, subtle: !!(crypto && crypto.subtle) };
            try {
              const k = await crypto.subtle.generateKey({ name: 'Ed25519' }, false, ['sign', 'verify']);
              const sig = await crypto.subtle.sign({ name: 'Ed25519' }, k.privateKey, new Uint8Array([1, 2, 3]));
              out.ed25519 = sig.byteLength === 64;
            } catch (e) { out.ed25519 = String(e); }
            try {
              const e = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits']);
              out.ecdh = !!e.privateKey;
            } catch (e) { out.ecdh = String(e); }
            return out;
            """) as? [String: Any]
        XCTAssertEqual(r?["secure"] as? Bool, true, "\(String(describing: r))")
        XCTAssertEqual(r?["subtle"] as? Bool, true)
        XCTAssertEqual(r?["ed25519"] as? Bool, true, "\(String(describing: r))")
        XCTAssertEqual(r?["ecdh"] as? Bool, true, "\(String(describing: r))")
        XCTAssertEqual(r?["origin"] as? String, AppOrigin.origin)
        TestApp.screenshot("01-first-screen")
    }

    /// The document-start script landed, and the floor behaves like Android's:
    /// monotone, frozen, non-deletable, and immune to a later prompt swap.
    func test02NativeFloorBridge() async throws {
        let r = try await page.eval("""
            const f = window.__SECURE_CHAT_PAD_FLOOR__;
            const id = Array.from(crypto.getRandomValues(new Uint8Array(16)), b => b.toString(16).padStart(2, '0')).join('');
            const out = {};
            out.marker = window.__SECURE_CHAT_NATIVE_FLOOR__;
            out.frozen = Object.isFrozen(f);
            out.deleted = delete window.__SECURE_CHAT_PAD_FLOOR__;
            out.markerDeleted = delete window.__SECURE_CHAT_NATIVE_FLOOR__;
            out.stillThere = window.__SECURE_CHAT_PAD_FLOOR__ === f;
            out.absent = f.read(id);
            out.b5 = f.bump(id, 5);
            out.b3 = f.bump(id, 3);
            out.neg = f.bump(id, -1);
            out.r = f.read(id);
            out.badId = f.read('bad id!');
            out.nonString = f.read({ toString() { return id; } });
            // A page script swapping prompt afterwards must not reach the floor.
            const realPrompt = window.prompt;
            window.prompt = () => '0';
            out.afterSwap = f.read(id);
            window.prompt = realPrompt;
            try { f.read = () => 0; } catch (e) {}
            out.afterOverwrite = f.read(id);
            // The client's own capture path (nativefloor.js) sees the same.
            const nf = \(Page.importModule("nativefloor.js"));
            const cap = nf.captureNativeFloor();
            out.capBroken = !!cap.broken;
            out.capRead = cap.read(id);
            return out;
            """) as? [String: Any]
        XCTAssertEqual(r?["marker"] as? Bool, true, "\(String(describing: r))")
        XCTAssertEqual(r?["frozen"] as? Bool, true)
        XCTAssertEqual(r?["deleted"] as? Bool, false)
        XCTAssertEqual(r?["markerDeleted"] as? Bool, false)
        XCTAssertEqual(r?["stillThere"] as? Bool, true)
        XCTAssertEqual(r?["absent"] as? Int, -1)
        XCTAssertEqual(r?["b5"] as? Int, 5)
        XCTAssertEqual(r?["b3"] as? Int, 5)
        XCTAssertEqual(r?["neg"] as? Int, 5)
        XCTAssertEqual(r?["r"] as? Int, 5)
        XCTAssertEqual(r?["badId"] as? Int, -2)
        XCTAssertEqual(r?["nonString"] as? Int, -2)
        XCTAssertEqual(r?["afterSwap"] as? Int, 5)
        XCTAssertEqual(r?["afterOverwrite"] as? Int, 5)
        XCTAssertEqual(r?["capBroken"] as? Bool, false)
        XCTAssertEqual(r?["capRead"] as? Int, 5)
    }

    /// The CSP header from the scheme handler is enforced: no eval, no
    /// injected inline script, no connection anywhere but the relay.
    func test03ContentSecurityPolicyIsEnforced() async throws {
        let r = try await page.eval("""
            const out = { violations: [] };
            const onV = (e) => out.violations.push(e.effectiveDirective || e.violatedDirective);
            document.addEventListener('securitypolicyviolation', onV);
            try { eval('1'); out.eval = 'allowed'; } catch (e) { out.eval = 'blocked'; }
            const s = document.createElement('script');
            s.textContent = 'window.__inlineRan = 1;';
            document.body.appendChild(s);
            out.inline = window.__inlineRan === 1 ? 'ran' : 'blocked';
            try { await fetch('https://example.com/'); out.fetch = 'allowed'; } catch (e) { out.fetch = 'blocked'; }
            await new Promise(r => setTimeout(r, 300));
            document.removeEventListener('securitypolicyviolation', onV);
            return out;
            """) as? [String: Any]
        XCTAssertEqual(r?["eval"] as? String, "blocked", "\(String(describing: r))")
        XCTAssertEqual(r?["inline"] as? String, "blocked")
        XCTAssertEqual(r?["fetch"] as? String, "blocked")
        let v = (r?["violations"] as? [String]) ?? []
        XCTAssertTrue(v.contains("connect-src"), "\(v)")
    }

    /// The relay (a local one in CI) is reachable over fetch (CORS for the iOS
    /// origin) and WebSocket (WS origin allow-list, mixed-content rules).
    func test04RelayReachable() async throws {
        let r = try await page.eval("""
            const R = window.__SECURE_CHAT_RELAY__;
            const out = { api: R.api, ws: R.ws };
            try {
              const res = await fetch(R.api + '/healthz');
              out.healthz = res.status;
            } catch (e) { out.healthz = String(e); }
            out.wsOpen = await new Promise((resolve) => {
              let done = false;
              const finish = (v) => { if (!done) { done = true; resolve(v); } };
              try {
                const ws = new WebSocket(R.ws);
                ws.onopen = () => { finish(true); ws.close(); };
                ws.onerror = () => finish('error');
                ws.onclose = (e) => finish('closed ' + e.code);
              } catch (e) { finish(String(e)); }
              setTimeout(() => finish('timeout'), 10000);
            });
            return out;
            """) as? [String: Any]
        XCTAssertEqual(r?["healthz"] as? Int, 200, "\(String(describing: r))")
        XCTAssertEqual(r?["wsOpen"] as? Bool, true, "\(String(describing: r))")
    }

    /// Secret prompts are masked natively; the marker is stripped; OK returns
    /// the typed text to the page.
    func test05SecretPromptIsMasked() async throws {
        try await page.eval("""
            window.__promptResult = 'pending';
            setTimeout(() => { window.__promptResult = prompt('[secure-chat:secret] Enter the pad passphrase'); }, 50);
            return true;
            """)
        let alert = try await TestApp.presentedAlert(message: "Enter the pad passphrase")
        XCTAssertNotNil(alert, "no native prompt appeared")
        guard let alert = alert else { return }
        XCTAssertEqual(alert.message, "Enter the pad passphrase")
        XCTAssertEqual(alert.textFields?.first?.isSecureTextEntry, true)
        TestApp.screenshot("05-secret-prompt")
        alert.textFields?.first?.text = "typed secret"
        let ok = alert.actions.first { $0.style == .default }!
        alert.dismiss(animated: false)
        TestApp.tap(ok)
        try await page.waitUntil("window.__promptResult === 'typed secret'", timeout: 5)
    }

    /// A plain prompt is not masked; Cancel returns null.
    func test06PlainPromptAndConfirm() async throws {
        try await page.eval("""
            window.__plain = 'pending';
            setTimeout(() => { window.__plain = prompt('Name this pad'); }, 50);
            return true;
            """)
        guard let alert = try await TestApp.presentedAlert(message: "Name this pad") else { return XCTFail("no prompt") }
        XCTAssertEqual(alert.textFields?.first?.isSecureTextEntry, false)
        let cancel = alert.actions.first { $0.style == .cancel }!
        alert.dismiss(animated: false)
        TestApp.tap(cancel)
        try await page.waitUntil("window.__plain === null", timeout: 5)

        try await page.eval("""
            window.__conf = 'pending';
            setTimeout(() => { window.__conf = confirm('Remove this identity from the device?'); }, 50);
            return true;
            """)
        guard let c = try await TestApp.presentedAlert(message: "Remove this identity from the device?") else { return XCTFail("no confirm") }
        TestApp.screenshot("06-confirm")
        let yes = c.actions.first { $0.style == .default }!
        c.dismiss(animated: false)
        TestApp.tap(yes)
        try await page.waitUntil("window.__conf === true", timeout: 5)
    }

    /// A prompt carrying the floor prefix is never shown, even malformed, and
    /// answers TAMPERED (pentest iOS-1 coverage gap).
    func test065MalformedFloorPromptIsNeverShown() async throws {
        let r = try await page.eval("""
            return [
              prompt('\\u0001secure-chat-floor\\u0001drop\\u0001abc\\u00010'),
              prompt('\\u0001secure-chat-floor\\u0001'),
              prompt('\\u0001secure-chat-floor\\u0001read\\u0001a\\u0001b\\u00010'),
            ];
            """) as? [String]
        XCTAssertEqual(r, ["-2", "-2", "-2"])
        let alert = try await TestApp.presentedAlert(timeout: 1)
        XCTAssertNil(alert, "a floor message reached the screen")
    }

    /// Marker for the cold-relaunch probe in CI (DebugHooks.SC_PERSIST_PROBE).
    func test07StorageMarkerForRelaunchProbe() async throws {
        let ok = try await page.bool("localStorage.setItem('sc.ci.persist', 'persist-ok'); return localStorage.getItem('sc.ci.persist') === 'persist-ok';")
        XCTAssertTrue(ok)
    }

    /// Native chrome for the design review: the relay prompt, the privacy
    /// shield, and the refusal screen.
    func test08NativeScreens() async throws {
        vc.promptForRelay(initial: false)
        if let a = try await TestApp.presentedAlert(message: "Where your encrypted messages are passed on. The relay only ever sees ciphertext.") {
            TestApp.screenshot("08-relay-settings")
            a.dismiss(animated: false)
        } else {
            XCTFail("relay prompt did not appear")
        }
        try await Task.sleep(nanoseconds: 300_000_000)

        if let scene = TestApp.window?.windowScene, let sd = TestApp.sceneDelegate {
            sd.sceneWillResignActive(scene)
            let shield = try XCTUnwrap(sd.shieldWindow, "no shield window")
            XCTAssertFalse(shield.isHidden)
            // Above alerts and the keyboard (hot review B2).
            XCTAssertGreaterThan(shield.windowLevel.rawValue, UIWindow.Level.alert.rawValue)
            XCTAssertEqual(shield.rootViewController?.view.accessibilityViewIsModal, true)
            TestApp.screenshot("08-privacy-shield", view: shield)
            sd.sceneDidBecomeActive(scene)
            XCTAssertNil(sd.shieldWindow)
        }

        let refused = MainViewController()
        let host = UINavigationController(rootViewController: refused)
        host.view.frame = TestApp.window?.bounds ?? CGRect(x: 0, y: 0, width: 393, height: 852)
        host.loadViewIfNeeded()
        refused.loadViewIfNeeded()
        refused.refuseToRun()
        XCTAssertNil(refused.webView)
        XCTAssertTrue(refused.refusedToRun)
        host.view.layoutIfNeeded()
        TestApp.screenshot("08-refused", view: host.view)
    }

    /// Off-origin navigation and pop-ups are refused. Runs last in this class:
    /// if the policy were broken it would take the page away.
    func test99NavigationStaysOnOrigin() async throws {
        let r = try await page.eval("""
            const before = location.href;
            const w = window.open('https://example.com/');
            location.href = 'https://example.com/';
            await new Promise(r => setTimeout(r, 1500));
            return { popup: w === null, same: location.href === before };
            """) as? [String: Any]
        XCTAssertEqual(r?["popup"] as? Bool, true)
        XCTAssertEqual(r?["same"] as? Bool, true)
        XCTAssertTrue(AppOrigin.isIndex(vc.webView?.url))
    }
}
