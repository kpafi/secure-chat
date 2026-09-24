import UIKit

/// Window setup and the privacy shield.
///
/// Android sets FLAG_SECURE (pentest 2026-08-07 F-ANDROID-003): a blank recents
/// card and no screenshots or recordings of the window. iOS has no public
/// equivalent, so this does what iOS allows, and ios/README.md says what it
/// does not:
///  * the app-switcher snapshot is taken after `sceneWillResignActive`, so a
///    cover goes up there and comes down on `sceneDidBecomeActive`;
///  * while the screen is being recorded, mirrored or AirPlayed
///    (`UIScreen.isCaptured`), the cover stays up;
///  * the cover is a separate window at alert level + 1, so alerts are
///    behind it. The system keyboard is NOT: it lives in its own window above
///    every app window (pentest iOS-2 L-C). So while the screen is being
///    captured, editing ends and any keyboard that tries to appear is
///    dismissed again (not for the app switcher, whose snapshot has no
///    keyboard);
///  * a SCREENSHOT cannot be prevented or even announced beforehand — the OS
///    only reports it after the fact. Not covered.
final class SceneDelegate: UIResponder, UIWindowSceneDelegate {
    var window: UIWindow?
    /// Its own window above alerts and the keyboard (hot review B2): a
    /// subview of the app window would leave a page alert, the relay alert
    /// or the keyboard with its suggestions drawn on top of the cover.
    private(set) var shieldWindow: UIWindow?
    private var captureObserver: NSObjectProtocol?
    private var keyboardObserver: NSObjectProtocol?

    func scene(_ scene: UIScene, willConnectTo session: UISceneSession,
               options connectionOptions: UIScene.ConnectionOptions) {
        guard let windowScene = scene as? UIWindowScene else { return }
        let window = UIWindow(windowScene: windowScene)
        let nav = UINavigationController(rootViewController: MainViewController())
        let appearance = UINavigationBarAppearance()
        appearance.configureWithOpaqueBackground()
        appearance.backgroundColor = Theme.bg  // the page head is --bg (hot review B1)
        appearance.shadowColor = .clear
        nav.navigationBar.standardAppearance = appearance
        nav.navigationBar.scrollEdgeAppearance = appearance
        nav.navigationBar.compactAppearance = appearance
        nav.navigationBar.tintColor = Theme.fg
        window.rootViewController = nav
        window.overrideUserInterfaceStyle = .dark
        window.backgroundColor = Theme.bg
        window.makeKeyAndVisible()
        self.window = window

        captureObserver = NotificationCenter.default.addObserver(
            forName: UIScreen.capturedDidChangeNotification, object: nil, queue: .main
        ) { [weak self] _ in
            MainActor.assumeIsolated { self?.updateShield(active: UIApplication.shared.applicationState == .active) }
        }
        keyboardObserver = NotificationCenter.default.addObserver(
            forName: UIResponder.keyboardWillShowNotification, object: nil, queue: .main
        ) { [weak self] _ in
            MainActor.assumeIsolated {
                guard let self = self, self.shieldWindow != nil, self.isCaptured else { return }
                self.window?.endEditing(true)
            }
        }
        updateShield(active: true)
    }

    func sceneWillResignActive(_ scene: UIScene) { updateShield(active: false) }
    func sceneDidBecomeActive(_ scene: UIScene) { updateShield(active: true) }
    func sceneDidEnterBackground(_ scene: UIScene) { updateShield(active: false) }

    private var isCaptured: Bool {
        window?.windowScene?.screen.isCaptured ?? false
    }

    private func updateShield(active: Bool) {
        let cover = !active || isCaptured
        if cover { showShield() } else { hideShield() }
    }

    private func showShield() {
        guard let scene = window?.windowScene else { return }
        if let shield = shieldWindow {
            // Already up: keep the note and label current (recording may
            // have started or stopped since).
            (shield.rootViewController?.view.subviews.first(where: { $0 is UILabel }) as? UILabel)?.isHidden = !isCaptured
            if isCaptured { window?.endEditing(true) }
            shield.rootViewController?.view.accessibilityLabel = shieldLabel
            return
        }
        // The keyboard is not in the app-switcher snapshot, so only end
        // editing when a recording could see it; otherwise pulling down
        // Control Center would cost the composer its focus (hot review r2 m2).
        if isCaptured { window?.endEditing(true) }

        let vc = UIViewController()
        let v = vc.view!
        v.backgroundColor = Theme.bg
        // The app icon's own padlock (a vector template asset), not SF lock.
        let lock = UIImageView(image: UIImage(named: "Padlock"))
        lock.tintColor = Theme.accent
        lock.contentMode = .scaleAspectFit
        lock.translatesAutoresizingMaskIntoConstraints = false
        lock.isAccessibilityElement = false
        v.addSubview(lock)
        // While recording/mirroring the user is looking at this: say why.
        let note = UILabel()
        note.text = "Hidden while the screen is being recorded or shared"
        note.textColor = Theme.muted
        note.font = .preferredFont(forTextStyle: .callout)
        note.adjustsFontForContentSizeCategory = true
        note.numberOfLines = 0
        note.textAlignment = .center
        note.isHidden = !isCaptured
        note.translatesAutoresizingMaskIntoConstraints = false
        v.addSubview(note)
        NSLayoutConstraint.activate([
            lock.centerXAnchor.constraint(equalTo: v.centerXAnchor),
            lock.centerYAnchor.constraint(equalTo: v.centerYAnchor, constant: -16),
            lock.widthAnchor.constraint(equalToConstant: 64),
            lock.heightAnchor.constraint(equalToConstant: 64),
            note.topAnchor.constraint(equalTo: lock.bottomAnchor, constant: 20),
            note.leadingAnchor.constraint(equalTo: v.readableContentGuide.leadingAnchor),
            note.trailingAnchor.constraint(equalTo: v.readableContentGuide.trailingAnchor),
        ])
        // Hide what is underneath from VoiceOver too while covered.
        v.accessibilityViewIsModal = true
        v.isAccessibilityElement = true
        v.accessibilityLabel = shieldLabel

        let w = UIWindow(windowScene: scene)
        w.windowLevel = .alert + 1
        w.overrideUserInterfaceStyle = .dark
        w.backgroundColor = Theme.bg
        w.rootViewController = vc
        w.isHidden = false
        shieldWindow = w
        UIAccessibility.post(notification: .screenChanged, argument: v)
    }

    private var shieldLabel: String {
        isCaptured ? "secure-chat is hidden while the screen is being recorded or shared" : "secure-chat"
    }

    private func hideShield() {
        guard let w = shieldWindow else { return }
        w.isHidden = true
        shieldWindow = nil
        UIAccessibility.post(notification: .screenChanged, argument: nil)
    }
}
