import UIKit
import WebKit
import XCTest
@testable import SecureChat

/// Drives one page of the bundled client from a hosted test — the Swift
/// counterpart of the puppeteer `page.evaluate` helpers in e2e/.
@MainActor
final class Page {
    let webView: WKWebView
    let label: String

    init(_ webView: WKWebView, label: String) {
        self.webView = webView
        self.label = label
    }

    /// Run `body` as an async function in the page and return its result
    /// round-tripped through JSON (so `undefined` never reaches Swift).
    ///
    /// Only the plain Obj-C `evaluateJavaScript(_:completionHandler:)` is
    /// used: `callAsyncJavaScript`'s Swift form lives in the WebKit overlay
    /// (libswiftWebKit.dylib), which the iOS 18 simulator runtime does not
    /// ship, so a test bundle using it fails to load (CI run 2). The promise
    /// is started with one call and its settled value polled with another.
    @discardableResult
    func eval(_ body: String, _ args: [String: Any] = [:], timeout: TimeInterval = 90) async throws -> Any? {
        let argData = try JSONSerialization.data(withJSONObject: args)
        let argJSON = String(decoding: argData, as: UTF8.self)
        let key = "t" + UUID().uuidString.replacingOccurrences(of: "-", with: "")
        // Each argument becomes a const of the same name inside the body.
        let decls = args.keys.sorted().map { "const \($0) = __a[\"\($0)\"];" }.joined(separator: " ")
        let start = """
        (function () {
          const R = (window.__scTest = window.__scTest || {});
          R['\(key)'] = null;
          const __args = \(argJSON);
          (async (__a) => { \(decls) \(body) })(__args).then(
            (v) => { R['\(key)'] = JSON.stringify({ ok: v === undefined ? null : v }); },
            (e) => { R['\(key)'] = JSON.stringify({ err: String(e && e.stack || e) }); });
          return 1;
        })()
        """
        _ = try await evaluate(start)
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            if let text = try await evaluate("(window.__scTest || {})['\(key)'] || ''") as? String, !text.isEmpty {
                _ = try? await evaluate("delete window.__scTest['\(key)']; 1")
                let obj = try JSONSerialization.jsonObject(with: Data(text.utf8)) as? [String: Any]
                if let err = obj?["err"] as? String {
                    throw NSError(domain: "Page.eval", code: 1, userInfo: [NSLocalizedDescriptionKey: "[\(label)] \(err)"])
                }
                let value = obj?["ok"]
                return value is NSNull ? nil : value
            }
            try await Task.sleep(nanoseconds: 50_000_000)
        }
        throw NSError(domain: "Page.eval", code: 2, userInfo: [NSLocalizedDescriptionKey: "[\(label)] eval timed out"])
    }

    /// One plain `evaluateJavaScript` call; the script must return a value.
    private func evaluate(_ script: String) async throws -> Any? {
        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Any?, Error>) in
            webView.evaluateJavaScript(script) { value, error in
                if let error = error { cont.resume(throwing: error) } else { cont.resume(returning: value) }
            }
        }
    }

    func bool(_ body: String, _ args: [String: Any] = [:]) async throws -> Bool {
        (try await eval(body, args) as? Bool) == true
    }

    func string(_ body: String, _ args: [String: Any] = [:]) async throws -> String? {
        try await eval(body, args) as? String
    }

    /// Poll `expr` (a JS expression) until truthy.
    func waitUntil(_ expr: String, timeout: TimeInterval = 45, _ args: [String: Any] = [:],
                   file: StaticString = #filePath, line: UInt = #line) async throws {
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            if (try? await bool("return !!(\(expr));", args)) == true { return }
            try await Task.sleep(nanoseconds: 250_000_000)
        }
        XCTFail("[\(label)] timed out waiting for: \(expr)", file: file, line: line)
        throw CancellationError()
    }

    func type(_ selector: String, _ text: String) async throws {
        let ok = try await bool("""
            const el = document.querySelector(sel);
            if (!el) return false;
            el.focus();
            el.value = text;
            el.dispatchEvent(new Event('input', { bubbles: true }));
            el.dispatchEvent(new Event('change', { bubbles: true }));
            return true;
            """, ["sel": selector, "text": text])
        XCTAssertTrue(ok, "[\(label)] no element \(selector)")
    }

    func click(_ selector: String) async throws {
        let ok = try await bool("""
            const el = document.querySelector(sel);
            if (!el) return false;
            el.click();
            return true;
            """, ["sel": selector])
        XCTAssertTrue(ok, "[\(label)] no element \(selector)")
    }

    func view(_ name: String) async throws {
        try await click(".navitem[data-view=\"\(name)\"]")
        try await Task.sleep(nanoseconds: 400_000_000)
    }

    /// Import a client module by absolute URL (the page's own module instance).
    static func importModule(_ file: String) -> String {
        "await import(new URL('\(file)', document.baseURI).href)"
    }
}

@MainActor
enum TestApp {
    static var window: UIWindow? {
        UIApplication.shared.connectedScenes
            .compactMap { ($0 as? UIWindowScene)?.windows.first(where: { $0.isKeyWindow }) }
            .first
    }

    static var sceneDelegate: SceneDelegate? {
        UIApplication.shared.connectedScenes.first?.delegate as? SceneDelegate
    }

    /// The app's own view controller, once its client has loaded. 90 s: the
    /// first test runs right after a cold simulator boot, and in CI run 11 the
    /// first load alone took longer than the earlier 30 s (all 41 later
    /// tests, on the same page, passed).
    static func mainPage(timeout: TimeInterval = 90) async throws -> (MainViewController, Page) {
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            if let nav = window?.rootViewController as? UINavigationController,
               let vc = nav.viewControllers.first as? MainViewController,
               let wv = vc.webView, AppOrigin.isIndex(wv.url), !wv.isLoading {
                let page = Page(wv, label: "app")
                if (try? await page.bool("return !!window.__SECURE_CHAT_RELAY__ && document.readyState === 'complete';")) == true {
                    return (vc, page)
                }
            }
            try await Task.sleep(nanoseconds: 250_000_000)
        }
        // A failure, not a skip: a skipped suite would read as green.
        XCTFail("the app's client never loaded — is SC_TEST_RELAY set?")
        throw CancellationError()
    }

    /// Save a PNG of the key window to $SC_SHOT_DIR (the CI uploads the folder).
    static func screenshot(_ name: String, view: UIView? = nil) {
        guard let dir = ProcessInfo.processInfo.environment["SC_SHOT_DIR"], !dir.isEmpty,
              let target = view ?? window else { return }
        let renderer = UIGraphicsImageRenderer(bounds: target.bounds)
        let image = renderer.image { ctx in
            // drawHierarchy needs an on-screen view; an off-window one (the
            // refusal screen) is rendered from its layer instead.
            if target.window != nil || target is UIWindow {
                _ = target.drawHierarchy(in: target.bounds, afterScreenUpdates: true)
            } else {
                target.layer.render(in: ctx.cgContext)
            }
        }
        guard let data = image.pngData() else { return }
        let url = URL(fileURLWithPath: dir).appendingPathComponent("\(name).png")
        try? FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
        try? data.write(to: url)
    }

    /// Fire a UIAlertAction's handler (tests only: there is no public API).
    static func tap(_ action: UIAlertAction) {
        typealias Handler = @convention(block) (UIAlertAction) -> Void
        guard let block = action.value(forKey: "handler") else { return }
        let handler = unsafeBitCast(block as AnyObject, to: Handler.self)
        handler(action)
    }

    /// The alert on screen, skipping one still being presented or dismissed
    /// (a previous test's alert can linger for a frame), optionally the one
    /// showing `message`.
    static func presentedAlert(message: String? = nil, timeout: TimeInterval = 5) async throws -> UIAlertController? {
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            var top = window?.rootViewController
            while let next = top?.presentedViewController { top = next }
            if let alert = top as? UIAlertController, !alert.isBeingPresented, !alert.isBeingDismissed,
               message == nil || alert.message == message {
                return alert
            }
            try await Task.sleep(nanoseconds: 100_000_000)
        }
        return nil
    }
}
