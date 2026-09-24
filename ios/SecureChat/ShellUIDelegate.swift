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
    /// able to present right now; nil while a presentation or dismissal is
    /// still animating (or nothing is on screen).
    private func top() -> UIViewController? {
        var vc = presenter
        while let next = vc?.presentedViewController { vc = next }
        guard let top = vc, top.viewIfLoaded?.window != nil,
              !top.isBeingPresented, !top.isBeingDismissed else { return nil }
        return top
    }

    /// Present `alert` as soon as UIKit can. A page often raises its next
    /// dialog the moment the previous one is answered, while that alert is
    /// still animating away; answering it "cancel" there would silently skip
    /// a confirmation the user never saw (CI run 5). So wait for the chain to
    /// settle — up to ~1.5 s — and only then give up: `fallback` answers the
    /// page, and `Once` guarantees WebKit's handler runs exactly once either
    /// way (a dropped handler raises NSInternalInconsistencyException —
    /// pentest iOS-1 L-2, cold review r1 M1).
    private func show(_ alert: UIAlertController, attempt: Int = 0, fallback: @escaping () -> Void) {
        guard let top = top() else {
            if attempt >= 30 || presenter?.viewIfLoaded?.window == nil { fallback(); return }
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.05) { [weak self] in
                guard let self = self else { fallback(); return }
                self.show(alert, attempt: attempt + 1, fallback: fallback)
            }
            return
        }
        top.present(alert, animated: true)
        DispatchQueue.main.async {
            if alert.presentingViewController == nil && !alert.isBeingPresented { fallback() }
        }
    }

    // No pop-ups, ever: window.open / target=_blank get nothing.
    func webView(_ webView: WKWebView, createWebViewWith configuration: WKWebViewConfiguration,
                 for navigationAction: WKNavigationAction, windowFeatures: WKWindowFeatures) -> WKWebView? {
        nil
    }

    func webView(_ webView: WKWebView, runJavaScriptAlertPanelWithMessage message: String,
                 initiatedByFrame frame: WKFrameInfo, completionHandler: @escaping () -> Void) {
        let done = Once<Void> { _ in completionHandler() }
        guard WebShell.isAppMainFrame(frame) else { done.run(()); return }
        let a = UIAlertController(title: nil, message: message, preferredStyle: .alert)
        a.addAction(UIAlertAction(title: "OK", style: .default) { _ in done.run(()) })
        show(a) { done.run(()) }
    }

    func webView(_ webView: WKWebView, runJavaScriptConfirmPanelWithMessage message: String,
                 initiatedByFrame frame: WKFrameInfo, completionHandler: @escaping (Bool) -> Void) {
        let done = Once<Bool>(completionHandler)
        guard WebShell.isAppMainFrame(frame) else { done.run(false); return }
        let a = UIAlertController(title: nil, message: message, preferredStyle: .alert)
        a.addAction(UIAlertAction(title: "Cancel", style: .cancel) { _ in done.run(false) })
        a.addAction(UIAlertAction(title: "OK", style: .default) { _ in done.run(true) })
        show(a) { done.run(false) }
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
        let done = Once<String?>(completionHandler)
        guard WebShell.isAppMainFrame(frame) else { done.run(nil); return }

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
            field.placeholder = secret ? "Passphrase" : nil
            field.accessibilityLabel = secret ? "Passphrase" : "Answer"
        }
        a.addAction(UIAlertAction(title: "Cancel", style: .cancel) { _ in done.run(nil) })
        a.addAction(UIAlertAction(title: "OK", style: .default) { [weak a] _ in
            done.run(a?.textFields?.first?.text ?? "")
        })
        show(a) { done.run(nil) }
    }
}

/// Calls the wrapped completion handler at most once.
final class Once<T> {
    private var handler: ((T) -> Void)?
    init(_ handler: @escaping (T) -> Void) { self.handler = handler }
    func run(_ value: T) {
        let h = handler
        handler = nil
        h?(value)
    }
}
