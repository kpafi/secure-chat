import UIKit
import WebKit
import XCTest
@testable import SecureChat

/// Two users on the iOS shell, end to end, against a real relay — the core of
/// e2e/two-user-flow.mjs: onboard (identity + register), add by handle, async
/// sealed chat both ways. Alice is the app's own web view; Bob is a second web
/// view built by the SAME `WebShell.configuration` with a non-persistent
/// store, so both sides run the shipped configuration.
///
/// This exercises, in real WebKit: Ed25519 + ML-DSA identity, ECDH + ML-KEM
/// sealed envelopes, cross-origin /api (CORS for secure-chat://app), and the
/// native floor for the per-identity contact and chat stores.
@MainActor
final class TwoUserE2ETests: XCTestCase {
    private let run = String(UInt64(Date().timeIntervalSince1970 * 1000) % 1_679_616, radix: 36)
    private var bobView: WKWebView?
    private var bobUI: ShellUIDelegate?
    private var bobNav: ShellNavigationDelegate?

    override func tearDown() async throws {
        bobView?.removeFromSuperview()
        bobView = nil
    }

    private func onboard(_ page: Page, name: String, pass: String) async throws -> (username: String, handle: String) {
        try await page.waitUntil("document.querySelector('#idCreate') && !document.querySelector('#idCreate').hidden", timeout: 20)
        try await page.type("#idPass", pass)
        try await page.click("#idCreate")
        try await page.waitUntil("!document.querySelector('#idExport').hidden", timeout: 60)
        let username = "\(name)-\(run)"
        try await page.type("#username", username)
        try await page.click("#register")
        try await page.waitUntil("/registered/i.test(document.querySelector('#accountStatus').textContent)", timeout: 45)
        try await Task.sleep(nanoseconds: 1_500_000_000)
        let handle = try await page.string(
            "return localStorage.getItem('sc.username.v1') + '#' + localStorage.getItem('sc.lookuptoken.v1');") ?? ""
        XCTAssertTrue(handle.hasPrefix(username + "#"), handle)
        return (username, handle)
    }

    private func messages(_ page: Page) async throws -> [String] {
        (try await page.eval("""
            const chats = \(Page.importModule("chats.js"));
            try { return chats.list().flatMap((c) => c.messages.map((m) => m.text)); } catch { return []; }
            """) as? [String]) ?? []
    }

    private func waitForMessage(_ page: Page, _ text: String, timeout: TimeInterval = 45) async throws -> [String] {
        let deadline = Date().addingTimeInterval(timeout)
        var got: [String] = []
        while Date() < deadline {
            got = try await messages(page)
            if got.contains(text) { return got }
            try await Task.sleep(nanoseconds: 2_000_000_000)
        }
        return got
    }

    private func addContact(_ page: Page, handle: String) async throws {
        try await page.view("users")
        try await page.type("#addHandle", handle)
        try await page.click("#addContact")
        try await page.waitUntil("document.querySelectorAll('#userList li:not(.empty)').length > 0", timeout: 30)
    }

    func testTwoUsersChatBothWays() async throws {
        let (vc, alice) = try await TestApp.mainPage()
        guard let window = TestApp.window else { return XCTFail("no window") }

        // Bob: same configuration, own in-memory storage, attached to the
        // window (a detached web view gets its timers throttled).
        let config = WebShell.configuration(relay: { Prefs.relay() }, dataStore: .nonPersistent())
        let wv = WebShell.makeWebView(configuration: config)
        let ui = ShellUIDelegate(presenter: vc, floor: PadFloor.shared)
        let nav = ShellNavigationDelegate(presenter: vc)
        wv.uiDelegate = ui
        wv.navigationDelegate = nav
        wv.frame = window.bounds
        window.insertSubview(wv, at: 0)
        bobView = wv; bobUI = ui; bobNav = nav
        wv.load(URLRequest(url: AppOrigin.indexURL))
        let bob = Page(wv, label: "bob")
        try await bob.waitUntil("document.readyState === 'complete' && window.__SECURE_CHAT_NATIVE_FLOOR__ === true", timeout: 20)

        let a = try await onboard(alice, name: "ios-alice", pass: "ios e2e alice passphrase — test only")
        TestApp.screenshot("10-alice-registered")
        let b = try await onboard(bob, name: "ios-bob", pass: "ios e2e bob passphrase — test only")

        // Alice adds Bob by handle and writes first.
        try await addContact(alice, handle: b.handle)
        TestApp.screenshot("11-alice-users")
        try await alice.view("chats")
        try await alice.eval("""
            const s = document.querySelector('#chatNew');
            s.value = u; s.dispatchEvent(new Event('change', { bubbles: true }));
            return s.value;
            """, ["u": b.username])
        try await alice.click("#chatStart")
        try await alice.waitUntil("!document.querySelector('#chatConvo').hidden", timeout: 20)
        try await alice.type("#chatText", "hello bob, from the iOS app")
        try await alice.click("#chatSend")

        try await bob.view("chats")
        let bobGot = try await waitForMessage(bob, "hello bob, from the iOS app")
        XCTAssertTrue(bobGot.contains("hello bob, from the iOS app"), "\(bobGot)")

        // Bob adds Alice and replies.
        try await addContact(bob, handle: a.handle)
        try await bob.view("chats")
        try await bob.eval("""
            const row = document.querySelector('#chatList li:not(.empty) > .chatrow-open');
            if (row) row.click();
            await new Promise((r) => setTimeout(r, 700));
            return !!row;
            """)
        try await bob.type("#chatText", "hi alice, got it on iOS")
        try await bob.click("#chatSend")

        let aliceGot = try await waitForMessage(alice, "hi alice, got it on iOS")
        XCTAssertTrue(aliceGot.contains("hi alice, got it on iOS"), "\(aliceGot)")
        try await Task.sleep(nanoseconds: 800_000_000)
        TestApp.screenshot("12-alice-conversation")

        // Bob's view, for the design review.
        wv.superview?.bringSubviewToFront(wv)
        try await Task.sleep(nanoseconds: 500_000_000)
        TestApp.screenshot("13-bob-conversation")
        window.sendSubviewToBack(wv)
    }
}
