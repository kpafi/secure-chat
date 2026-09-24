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
    private var crashTimes: [Date] = []
    private var reloadWhenActive = false
    private var crashView: UIView?
    var isShowingCrashLoop: Bool { crashView != nil }

    @objc private func appBecameActive() {
        guard reloadWhenActive, !refusedToRun, let relay = Prefs.relay() else { return }
        reloadWhenActive = false
        load(relay, userInitiated: false)
    }

    /// The page's process died repeatedly in the foreground. Not the
    /// security refusal: nothing is misconfigured, and "reinstall" would
    /// wipe identity and pads (pentest iOS-2 L-B). Offer to try again.
    private func showCrashLoop() {
        guard crashView == nil, let wv = webView else { return }
        wv.isHidden = true
        var config = UIContentUnavailableConfiguration.empty()
        config.image = UIImage(systemName: "exclamationmark.arrow.triangle.2.circlepath")
        config.imageProperties.tintColor = Theme.muted
        config.text = "secure-chat stopped responding"
        config.textProperties.color = Theme.fg
        config.secondaryText = "The page restarted several times in a row. Your identity and chats " +
            "are still on this device. Try again, or close secure-chat and open it again."
        config.secondaryTextProperties.color = Theme.muted
        var button = UIButton.Configuration.filled()
        button.title = "Try again"
        button.baseBackgroundColor = Theme.accentFill   // hot review r2 M1: 4.6:1
        button.baseForegroundColor = .white
        config.button = button
        config.buttonProperties.primaryAction = UIAction { [weak self] _ in self?.retryAfterCrashLoop() }
        let v = UIContentUnavailableView(configuration: config)
        v.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(v)
        NSLayoutConstraint.activate([
            v.topAnchor.constraint(equalTo: view.safeAreaLayoutGuide.topAnchor),
            v.bottomAnchor.constraint(equalTo: view.bottomAnchor),
            v.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            v.trailingAnchor.constraint(equalTo: view.trailingAnchor),
        ])
        crashView = v
        UIAccessibility.post(notification: .screenChanged, argument: v)
    }

    private func retryAfterCrashLoop() {
        if let relay = Prefs.relay() { load(relay) } else { promptForRelay(initial: true) }
    }

    /// Dynamic Type for the page (cold review r1 M5). WKWebView ignores the
    /// system text size, unlike Android's WebView, so the page is zoomed with
    /// it: the whole layout scales, as with browser zoom.
    static func pageZoom(for category: UIContentSizeCategory) -> CGFloat {
        switch category {
        case .extraSmall: return 0.85
        case .small: return 0.9
        case .medium: return 0.95
        case .large: return 1.0
        case .extraLarge: return 1.1
        case .extraExtraLarge: return 1.2
        case .extraExtraExtraLarge: return 1.3
        case .accessibilityMedium: return 1.45
        case .accessibilityLarge: return 1.6
        case .accessibilityExtraLarge: return 1.75
        case .accessibilityExtraExtraLarge: return 1.9
        case .accessibilityExtraExtraExtraLarge: return 2.0
        default: return 1.0
        }
    }

    /// The zoom actually applied: the Dynamic Type factor, capped so the page
    /// never gets narrower than 320 CSS px — the width the web UI was reviewed
    /// down to (hot review M3; 2.0 on a 393pt phone left 196 px).
    static func appliedZoom(for category: UIContentSizeCategory, width: CGFloat) -> CGFloat {
        let wanted = pageZoom(for: category)
        guard width > 0 else { return min(wanted, 1) }
        return min(wanted, max(1, width / 320))
    }

    private func applyTextSize() {
        guard let wv = webView else { return }
        let z = Self.appliedZoom(for: traitCollection.preferredContentSizeCategory, width: wv.bounds.width)
        if abs(wv.pageZoom - z) > 0.001 { wv.pageZoom = z }
    }

    override func viewDidLayoutSubviews() {
        super.viewDidLayoutSubviews()
        applyTextSize()
    }

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
        // An app, not a page: no pinch or double-tap zoom (text size follows
        // Dynamic Type instead), and no white overscroll behind the page.
        wv.underPageBackgroundColor = Theme.bg
        view.addSubview(wv)
        // Inside the safe area: the page does not use viewport-fit=cover, so
        // the notch and home-indicator strips are native bg, not page.
        // Bottom follows the keyboard (keyboardLayoutGuide sits on the safe
        // area while it is hidden), so the page's fixed tab bar and composer
        // stay above it — Android's adjustResize, not an overlaid keyboard.
        NSLayoutConstraint.activate([
            wv.topAnchor.constraint(equalTo: view.safeAreaLayoutGuide.topAnchor),
            wv.bottomAnchor.constraint(equalTo: view.keyboardLayoutGuide.topAnchor),
            wv.leadingAnchor.constraint(equalTo: view.safeAreaLayoutGuide.leadingAnchor),
            wv.trailingAnchor.constraint(equalTo: view.safeAreaLayoutGuide.trailingAnchor),
        ])
        webView = wv
        applyTextSize()
        registerForTraitChanges([UITraitPreferredContentSizeCategory.self]) { (self: Self, _) in
            self.applyTextSize()
        }

        navDelegate.onClientLoaded = { [weak self] wv, ok in
            guard let self = self else { return }
            // No pinch or double-tap zoom. After load: the recogniser does not
            // exist earlier, and WebKit resets zoom limits per load (r2 m3).
            wv.scrollView.pinchGestureRecognizer?.isEnabled = false
            wv.scrollView.minimumZoomScale = 1
            wv.scrollView.maximumZoomScale = 1
            if ok { self.clientLoaded() } else { self.refuseToRun() }
        }
        navDelegate.onProcessTerminated = { [weak self] _ in
            // The unlocked identity and live sessions were in that process and
            // are gone either way; reload to the locked start screen — but not
            // forever: a page that kills its process on every load gets three
            // tries a minute, then the refusal screen.
            guard let self = self, !self.refusedToRun, let relay = Prefs.relay() else { return }
            // Pentest iOS-2 L-B: the system kills a background web process
            // under memory pressure; that is not a crash loop and must not
            // count. Reload when the app is back in front instead.
            guard UIApplication.shared.applicationState == .active else {
                self.reloadWhenActive = true
                return
            }
            let now = Date()
            self.crashTimes = self.crashTimes.filter { now.timeIntervalSince($0) < 60 } + [now]
            if self.crashTimes.count > 3 { self.showCrashLoop(); return }
            self.load(relay, userInitiated: false)
        }
        NotificationCenter.default.addObserver(
            self, selector: #selector(appBecameActive),
            name: UIApplication.didBecomeActiveNotification, object: nil)
    }

    override func viewDidAppear(_ animated: Bool) {
        super.viewDidAppear(animated)
        guard !startedLoading else { return }
        startedLoading = true
        if let relay = Prefs.relay() { load(relay) } else { promptForRelay(initial: true) }
    }

    /// Point the client at `relay`, (re)install the document-start script, load.
    /// `userInitiated`: Reload, a saved relay, Try again, first launch. Only
    /// those clear the crash-loop state; the automatic reload after a process
    /// death must not, or the limit never trips (pentest iOS-3 F2).
    func load(_ relay: RelayUrls, userInitiated: Bool = true) {
        guard !refusedToRun, let wv = webView else { return }
        if userInitiated {
            // Leave the crash-loop screen behind (hot review r2 M2).
            crashView?.removeFromSuperview()
            crashView = nil
            crashTimes = []
            wv.isHidden = false
        }
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

        // A native empty state (hot review M5), bar hidden: there is nothing
        // left to operate. UIContentUnavailableView scrolls and follows
        // Dynamic Type by itself.
        navigationController?.setNavigationBarHidden(true, animated: false)
        var config = UIContentUnavailableConfiguration.empty()
        config.image = UIImage(systemName: "lock.trianglebadge.exclamationmark")
        config.imageProperties.tintColor = Theme.muted
        config.text = "Cannot start securely"
        config.textProperties.color = Theme.fg
        config.secondaryText = "The app sets up the encrypted client before any page code runs, and that " +
            "step did not complete on this device. Continuing would load a client that cannot " +
            "reach the relay or protect one-time pads, so secure-chat has stopped. Update iOS " +
            "and reinstall the app."
        config.secondaryTextProperties.color = Theme.muted
        let empty = UIContentUnavailableView(configuration: config)
        empty.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(empty)
        NSLayoutConstraint.activate([
            empty.topAnchor.constraint(equalTo: view.topAnchor),
            empty.bottomAnchor.constraint(equalTo: view.bottomAnchor),
            empty.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            empty.trailingAnchor.constraint(equalTo: view.trailingAnchor),
        ])
        UIAccessibility.post(notification: .screenChanged, argument: empty)
    }

    private func makeMenu() -> UIMenu {
        UIMenu(children: [
            UIAction(title: "Reload", image: UIImage(systemName: "arrow.clockwise")) { [weak self] _ in
                guard let self = self, !self.refusedToRun else { return }
                if let relay = Prefs.relay() { self.load(relay) } else { self.promptForRelay(initial: true) }
            },
            UIAction(title: "Relay settings…", image: UIImage(systemName: "server.rack")) { [weak self] _ in
                self?.promptForRelay(initial: false)
            },
        ])
    }

    /// Ask for the relay address. On first run there is no Cancel: the app
    /// cannot do anything without one.
    func promptForRelay(initial: Bool, text: String? = nil, error: String? = nil) {
        guard !refusedToRun else { return }
        // Short by default (hot review m3); the transport rule only when the
        // typed address broke it.
        let message = error ?? "Where your encrypted messages are passed on. The relay only ever sees ciphertext."
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
                                    error: "Use https://host (no path). http:// works only for 127.0.0.1 or localhost, when testing.")
                return
            }
            Prefs.setRelay(relay)
            self.load(relay)
        }
        a.addAction(save)
        a.preferredAction = save
        presentWhenSettled(a)
    }

    /// Present once no presentation or dismissal is animating (the same
    /// lesson as ShellUIDelegate.show, CI runs 5 and 6: presenting over an
    /// alert that is still animating away silently drops the new one).
    private func presentWhenSettled(_ vc: UIViewController, attempt: Int = 0) {
        guard !refusedToRun else { return }   // pentest iOS-3 I-2
        var top: UIViewController = navigationController ?? self
        while let next = top.presentedViewController { top = next }
        if top.isBeingPresented || top.isBeingDismissed {
            guard attempt < 30 else { return }
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.05) { [weak self] in
                self?.presentWhenSettled(vc, attempt: attempt + 1)
            }
            return
        }
        top.present(vc, animated: true)
    }
}
