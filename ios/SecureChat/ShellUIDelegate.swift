import UIKit
import WebKit

/// Native dialogs for the page's `alert` / `confirm` / `prompt`, and the pad
/// floor channel (`FloorBridge`), which also arrives as a `prompt`.
///
/// Without a WKUIDelegate the web view drops JS dialogs: `confirm()` returns
/// false and `prompt()` null, so Forget identity, Verify, mode changes and pad
/// passphrases silently do nothing — the same trap the Android shell's
/// WebChromeClient exists for.
@MainActor
final class ShellUIDelegate: NSObject, WKUIDelegate {
    /// Prefix the bundled client puts on a prompt whose answer is a SECRET
    /// (client/app.js `SECRET_PROMPT_MARK`, pentest 2026-07-25 F-08). The client
    /// adds it only when `__SECURE_CHAT_RELAY__` is set, i.e. inside the app.
    static let secretPromptMark = "[secure-chat:secret] "

    weak var presenter: UIViewController?
    private let floor: PadFloor?

    init(presenter: UIViewController?, floor: PadFloor?) {
        self.presenter = presenter
        self.floor = floor
    }

    /// Where to present: the top of the presenter's chain, if on screen and
    /// able to present right now. nil means "answer the page without UI"
    /// (cancel / false / null): a refused `present` would drop the alert and,
    /// with it, WebKit's completion handler (pentest iOS-1 L-2).
    private func top() -> UIViewController? {
        var vc = presenter
        while let next = vc?.presentedViewController { vc = next }
        guard let top = vc, top.viewIfLoaded?.window != nil,
              !top.isBeingPresented, !top.isBeingDismissed else { return nil }
        return top
    }

    // No pop-ups, ever: window.open / target=_blank get nothing.
    func webView(_ webView: WKWebView, createWebViewWith configuration: WKWebViewConfiguration,
                 for navigationAction: WKNavigationAction, windowFeatures: WKWindowFeatures) -> WKWebView? {
        nil
    }

    func webView(_ webView: WKWebView, runJavaScriptAlertPanelWithMessage message: String,
                 initiatedByFrame frame: WKFrameInfo, completionHandler: @escaping () -> Void) {
        guard WebShell.isAppMainFrame(frame), let top = top() else { completionHandler(); return }
        let a = UIAlertController(title: nil, message: message, preferredStyle: .alert)
        a.addAction(UIAlertAction(title: "OK", style: .default) { _ in completionHandler() })
        top.present(a, animated: true)
    }

    func webView(_ webView: WKWebView, runJavaScriptConfirmPanelWithMessage message: String,
                 initiatedByFrame frame: WKFrameInfo, completionHandler: @escaping (Bool) -> Void) {
        guard WebShell.isAppMainFrame(frame), let top = top() else { completionHandler(false); return }
        let a = UIAlertController(title: nil, message: message, preferredStyle: .alert)
        a.addAction(UIAlertAction(title: "Cancel", style: .cancel) { _ in completionHandler(false) })
        a.addAction(UIAlertAction(title: "OK", style: .default) { _ in completionHandler(true) })
        top.present(a, animated: true)
    }

    func webView(_ webView: WKWebView, runJavaScriptTextInputPanelWithPrompt prompt: String,
                 defaultText: String?, initiatedByFrame frame: WKFrameInfo,
                 completionHandler: @escaping (String?) -> Void) {
        // The floor channel first: never shown, answered only for our page.
        if FloorBridge.isFloorMessage(prompt) {
            guard WebShell.isAppMainFrame(frame) else {
                completionHandler(String(PadFloor.tampered))
                return
            }
            completionHandler(FloorBridge.answer(prompt, floor: floor))
            return
        }
        guard WebShell.isAppMainFrame(frame), let top = top() else { completionHandler(nil); return }

        // Audit 2026-07-18 L-02 / pentest 2026-07-25 F-08: mask secrets. The
        // explicit mark decides; the word "passphrase" is a fail-SECURE
        // fallback that can add masking, never remove it (as on Android).
        let marked = prompt.hasPrefix(Self.secretPromptMark)
        let secret = marked || prompt.range(of: "passphrase", options: .caseInsensitive) != nil
        let shown = marked ? String(prompt.dropFirst(Self.secretPromptMark.count)) : prompt

        let a = UIAlertController(title: nil, message: shown, preferredStyle: .alert)
        a.addTextField { field in
            field.isSecureTextEntry = secret
            field.text = defaultText
            field.autocorrectionType = .no
            field.autocapitalizationType = .none
            field.spellCheckingType = .no
            field.smartDashesType = .no
            field.smartQuotesType = .no
            field.accessibilityLabel = secret ? "Secret" : "Answer"
        }
        a.addAction(UIAlertAction(title: "Cancel", style: .cancel) { _ in completionHandler(nil) })
        a.addAction(UIAlertAction(title: "OK", style: .default) { [weak a] _ in
            completionHandler(a?.textFields?.first?.text ?? "")
        })
        top.present(a, animated: true)
    }
}
