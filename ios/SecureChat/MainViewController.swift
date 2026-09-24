import UIKit
import WebKit

/// Native shell around the audited secure-chat web client — the iOS port of
/// `android/.../MainActivity.kt`.
///
/// SECURITY MODEL (unchanged from Android). The whole point of the app versus
/// the browser is to stop trusting a server to serve honest code: the client
/// is BUNDLED in the app and served from a local origin by `AppSchemeHandler`;
/// the relay is only a WebSocket/HTTP endpoint for opaque ciphertext. The app
/// supplies what the same-origin web build got for free:
///   1. the relay location, injected before any page script runs;
///   2. the CSP, stamped on index.html with connect-src pinned to that relay;
///   3. a pad floor the page cannot lower (`PadFloor`, via `FloorBridge`).
@MainActor
final class MainViewController: UIViewController {
    private(set) var webView: WKWebView?
    private(set) lazy var uiDelegate = ShellUIDelegate(presenter: self, floor: PadFloor.shared)
    private(set) lazy var navDelegate = ShellNavigationDelegate(presenter: self)
    /// Latched once the "cannot start securely" screen is up (Android refuseToRun).
    private(set) var refusedToRun = false
    private var startedLoading = false

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = Theme.bg

        // The page draws its own header (wordmark + tabs), so the native bar
        // carries no title — only the menu. Relay settings must stay reachable
        // natively: it is the only way out of a wrong relay address, when the
        // page cannot load at all (same call as the Android action bar).
        let more = UIBarButtonItem(image: UIImage(systemName: "ellipsis.circle"), menu: makeMenu())
        more.accessibilityLabel = "App menu"
        navigationItem.rightBarButtonItem = more
        navigationItem.backButtonDisplayMode = .minimal

        let config = WebShell.configuration(relay: { Prefs.relay() })
        let wv = WebShell.makeWebView(configuration: config)
        wv.uiDelegate = uiDelegate
        wv.navigationDelegate = navDelegate
        wv.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(wv)
        // Inside the safe area: the page does not use viewport-fit=cover, so
        // the notch and home-indicator strips are native bg, not page.
        NSLayoutConstraint.activate([
            wv.topAnchor.constraint(equalTo: view.safeAreaLayoutGuide.topAnchor),
            wv.bottomAnchor.constraint(equalTo: view.safeAreaLayoutGuide.bottomAnchor),
            wv.leadingAnchor.constraint(equalTo: view.safeAreaLayoutGuide.leadingAnchor),
            wv.trailingAnchor.constraint(equalTo: view.safeAreaLayoutGuide.trailingAnchor),
        ])
        webView = wv

        navDelegate.onClientLoaded = { [weak self] _, ok in
            guard let self = self else { return }
            if ok { self.clientLoaded() } else { self.refuseToRun() }
        }
        navDelegate.onProcessTerminated = { [weak self] _ in
            // The unlocked identity and live sessions were in that process and
            // are gone either way; reload to the locked start screen.
            guard let self = self, !self.refusedToRun, let relay = Prefs.relay() else { return }
            self.load(relay)
        }
    }

    override func viewDidAppear(_ animated: Bool) {
        super.viewDidAppear(animated)
        guard !startedLoading else { return }
        startedLoading = true
        if let relay = Prefs.relay() { load(relay) } else { promptForRelay(initial: true) }
    }

    /// Point the client at `relay`, (re)install the document-start script, load.
    func load(_ relay: RelayUrls) {
        guard !refusedToRun, let wv = webView else { return }
        WebShell.install(relay: relay, into: wv.configuration.userContentController)
        wv.load(URLRequest(url: AppOrigin.indexURL, cachePolicy: .reloadIgnoringLocalCacheData))
    }

    private func clientLoaded() {
        #if DEBUG
        DebugHooks.clientLoaded(self)
        #endif
    }

    /// Fail LOUDLY (Android L-10): take the web view away so no half-configured
    /// client stays usable, and say why. iOS apps do not quit themselves, so
    /// the explanation stays on screen instead of a Close button.
    func refuseToRun() {
        guard !refusedToRun else { return }
        refusedToRun = true
        webView?.stopLoading()
        webView?.removeFromSuperview()
        webView = nil
        navigationItem.rightBarButtonItem = nil

        let title = UILabel()
        title.text = "Cannot start securely"
        title.font = .preferredFont(forTextStyle: .title2)
        title.adjustsFontForContentSizeCategory = true
        title.textColor = Theme.fg
        title.numberOfLines = 0
        title.accessibilityTraits = .header
        let body = UILabel()
        body.text = "The app sets up the encrypted client before any page code runs, and that " +
            "step did not complete on this device. Continuing would load a client that cannot " +
            "reach the relay or protect one-time pads, so secure-chat has stopped. Update iOS " +
            "and reinstall the app."
        body.font = .preferredFont(forTextStyle: .body)
        body.adjustsFontForContentSizeCategory = true
        body.textColor = Theme.muted
        body.numberOfLines = 0
        let stack = UIStackView(arrangedSubviews: [title, body])
        stack.axis = .vertical
        stack.spacing = 12
        stack.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(stack)
        NSLayoutConstraint.activate([
            stack.leadingAnchor.constraint(equalTo: view.readableContentGuide.leadingAnchor),
            stack.trailingAnchor.constraint(equalTo: view.readableContentGuide.trailingAnchor),
            stack.centerYAnchor.constraint(equalTo: view.safeAreaLayoutGuide.centerYAnchor),
        ])
    }

    private func makeMenu() -> UIMenu {
        UIMenu(children: [
            UIAction(title: "Reload", image: UIImage(systemName: "arrow.clockwise")) { [weak self] _ in
                guard let self = self, !self.refusedToRun else { return }
                if let relay = Prefs.relay() { self.load(relay) } else { self.promptForRelay(initial: true) }
            },
            UIAction(title: "Relay settings", image: UIImage(systemName: "server.rack")) { [weak self] _ in
                self?.promptForRelay(initial: false)
            },
        ])
    }

    /// Ask for the relay address. On first run there is no Cancel: the app
    /// cannot do anything without one.
    func promptForRelay(initial: Bool, text: String? = nil, error: String? = nil) {
        guard !refusedToRun else { return }
        let message = (error.map { $0 + "\n\n" } ?? "") +
            "The relay only ever sees opaque ciphertext. It must use https (TLS); " +
            "http:// works only for a loopback address (127.0.0.1) when testing."
        let a = UIAlertController(title: "Relay address", message: message, preferredStyle: .alert)
        a.addTextField { f in
            f.placeholder = "https://relay.example.com"
            f.text = text ?? Prefs.relay()?.httpOrigin
            f.keyboardType = .URL
            f.textContentType = .URL
            f.autocapitalizationType = .none
            f.autocorrectionType = .no
            f.spellCheckingType = .no
            f.clearButtonMode = .whileEditing
            f.accessibilityLabel = "Relay address"
        }
        if !initial {
            a.addAction(UIAlertAction(title: "Cancel", style: .cancel))
        }
        let save = UIAlertAction(title: "Save", style: .default) { [weak self, weak a] _ in
            guard let self = self else { return }
            let typed = a?.textFields?.first?.text ?? ""
            guard let relay = RelayUrls.parse(typed) else {
                // UIAlertController always dismisses on a tap, so re-ask with
                // the typed text and the reason, rather than lose both.
                self.promptForRelay(initial: initial, text: typed,
                                    error: "That is not a relay address this app can use: enter https://host (no path).")
                return
            }
            Prefs.setRelay(relay)
            self.load(relay)
        }
        a.addAction(save)
        a.preferredAction = save
        var top: UIViewController = navigationController ?? self
        while let next = top.presentedViewController { top = next }
        top.present(a, animated: true)
    }
}
