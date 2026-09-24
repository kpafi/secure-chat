import UIKit
import WebKit

/// Navigation policy, the post-load config probe, and file export.
@MainActor
final class ShellNavigationDelegate: NSObject, WKNavigationDelegate, WKDownloadDelegate {
    weak var presenter: UIViewController?
    /// Called after index.html finishes loading with the probe's verdict.
    var onClientLoaded: ((WKWebView, Bool) -> Void)?
    /// The web content process died (memory pressure, crash).
    var onProcessTerminated: ((WKWebView) -> Void)?

    private var destinations: [ObjectIdentifier: URL] = [:]

    init(presenter: UIViewController?) {
        self.presenter = presenter
    }

    // Keep every navigation inside the app origin, in the main frame; never
    // hand a URL to Safari or another app. Matched on the PARSED scheme+host
    // (2026-07-08 Android pentest, Finding 2: a string prefix would accept
    // `secure-chat://app.evil/`). The one exception is a download the page
    // asks for from its own blob: URL (pad export, `a download`).
    func webView(_ webView: WKWebView, decidePolicyFor action: WKNavigationAction,
                 decisionHandler: @escaping (WKNavigationActionPolicy) -> Void) {
        let url = action.request.url
        if action.shouldPerformDownload {
            let fromUs = WebShell.isAppMainFrame(action.sourceFrame)
            let blob = url?.absoluteString.hasPrefix("blob:\(AppOrigin.origin)/") == true
            decisionHandler(fromUs && blob ? .download : .cancel)
            return
        }
        let mainFrame = action.targetFrame?.isMainFrame == true
        decisionHandler(mainFrame && AppOrigin.isAppURL(url) ? .allow : .cancel)
    }

    func webView(_ webView: WKWebView, decidePolicyFor response: WKNavigationResponse,
                 decisionHandler: @escaping (WKNavigationResponsePolicy) -> Void) {
        decisionHandler(response.isForMainFrame && !AppOrigin.isAppURL(response.response.url) ? .cancel : .allow)
    }

    func webView(_ webView: WKWebView, navigationAction: WKNavigationAction, didBecome download: WKDownload) {
        download.delegate = self
    }

    func webView(_ webView: WKWebView, navigationResponse: WKNavigationResponse, didBecome download: WKDownload) {
        // Only action-initiated blob downloads are allowed (above).
        download.cancel { _ in }
    }

    // Probe that the document-start script landed (Android L-10).
    func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
        guard AppOrigin.isIndex(webView.url) else { return }
        webView.evaluateJavaScript(WebShell.verifyScript) { [weak self] result, _ in
            self?.onClientLoaded?(webView, (result as? Bool) == true)
        }
    }

    func webViewWebContentProcessDidTerminate(_ webView: WKWebView) {
        onProcessTerminated?(webView)
    }

    // MARK: - Export (WKDownloadDelegate)

    func download(_ download: WKDownload, decideDestinationUsing response: URLResponse,
                  suggestedFilename: String, completionHandler: @escaping (URL?) -> Void) {
        let dir = Exports.root.appendingPathComponent(UUID().uuidString, isDirectory: true)
        do {
            try FileManager.default.createDirectory(
                at: dir, withIntermediateDirectories: true,
                attributes: [.protectionKey: FileProtectionType.complete])
        } catch {
            completionHandler(nil)
            return
        }
        let dest = dir.appendingPathComponent(Exports.safeFilename(suggestedFilename))
        destinations[ObjectIdentifier(download)] = dest
        completionHandler(dest)
    }

    func downloadDidFinish(_ download: WKDownload) {
        guard let file = destinations.removeValue(forKey: ObjectIdentifier(download)) else { return }
        let dir = file.deletingLastPathComponent()
        guard let presenter = presenter, presenter.viewIfLoaded?.window != nil else {
            try? FileManager.default.removeItem(at: dir)
            return
        }
        let sheet = UIActivityViewController(activityItems: [file], applicationActivities: nil)
        sheet.completionWithItemsHandler = { _, _, _, _ in
            try? FileManager.default.removeItem(at: dir)
        }
        sheet.popoverPresentationController?.sourceView = presenter.view
        sheet.popoverPresentationController?.sourceRect = CGRect(
            x: presenter.view.bounds.midX, y: presenter.view.bounds.midY, width: 1, height: 1)
        var top: UIViewController = presenter
        while let next = top.presentedViewController { top = next }
        top.present(sheet, animated: true)
    }

    func download(_ download: WKDownload, didFailWithError error: Error, resumeData: Data?) {
        if let file = destinations.removeValue(forKey: ObjectIdentifier(download)) {
            try? FileManager.default.removeItem(at: file.deletingLastPathComponent())
        }
    }
}

/// Where exports are staged. Not actor-bound: pure file-system helpers.
enum Exports {
    /// Exports go to a per-download folder in tmp and are handed to the share
    /// sheet; the file is deleted when the sheet closes. `Exports.clean()` at
    /// launch removes anything a crash left behind.
    static var root: URL {
        FileManager.default.temporaryDirectory.appendingPathComponent("exports", isDirectory: true)
    }

    static func clean() {
        try? FileManager.default.removeItem(at: root)
    }

    static func safeFilename(_ suggested: String) -> String {
        let allowed = CharacterSet(charactersIn:
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-")
        var name = String(String.UnicodeScalarView(suggested.unicodeScalars.map { allowed.contains($0) ? $0 : "_" }))
        while name.hasPrefix(".") { name.removeFirst() }
        if name.count > 100 { name = String(name.suffix(100)) }
        return name.isEmpty ? "secure-chat-export.json" : name
    }
}
