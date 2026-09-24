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
///  * a SCREENSHOT cannot be prevented or even announced beforehand — the OS
///    only reports it after the fact. Not covered.
final class SceneDelegate: UIResponder, UIWindowSceneDelegate {
    var window: UIWindow?
    private var shield: UIView?
    private var captureObserver: NSObjectProtocol?

    func scene(_ scene: UIScene, willConnectTo session: UISceneSession,
               options connectionOptions: UIScene.ConnectionOptions) {
        guard let windowScene = scene as? UIWindowScene else { return }
        let window = UIWindow(windowScene: windowScene)
        let nav = UINavigationController(rootViewController: MainViewController())
        let appearance = UINavigationBarAppearance()
        appearance.configureWithOpaqueBackground()
        appearance.backgroundColor = Theme.bgTop
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
        guard let window = window else { return }
        if let shield = shield {
            // Already up: keep the label current (recording may have started).
            (shield.subviews.first(where: { $0 is UILabel }) as? UILabel)?.isHidden = !isCaptured
            shield.accessibilityLabel = shieldLabel
            return
        }
        let v = UIView(frame: window.bounds)
        v.autoresizingMask = [.flexibleWidth, .flexibleHeight]
        v.backgroundColor = Theme.bg
        let lock = UIImageView(image: UIImage(systemName: "lock.fill"))
        lock.tintColor = Theme.accent
        lock.contentMode = .scaleAspectFit
        lock.translatesAutoresizingMaskIntoConstraints = false
        lock.isAccessibilityElement = false
        v.addSubview(lock)
        NSLayoutConstraint.activate([
            lock.centerXAnchor.constraint(equalTo: v.centerXAnchor),
            lock.centerYAnchor.constraint(equalTo: v.centerYAnchor),
            lock.widthAnchor.constraint(equalToConstant: 44),
            lock.heightAnchor.constraint(equalToConstant: 44),
        ])
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
            note.topAnchor.constraint(equalTo: lock.bottomAnchor, constant: 16),
            note.leadingAnchor.constraint(equalTo: v.readableContentGuide.leadingAnchor),
            note.trailingAnchor.constraint(equalTo: v.readableContentGuide.trailingAnchor),
        ])
        // Hide what is underneath from VoiceOver too while covered.
        v.accessibilityViewIsModal = true
        v.isAccessibilityElement = true
        v.accessibilityLabel = shieldLabel
        window.addSubview(v)
        shield = v
        UIAccessibility.post(notification: .screenChanged, argument: v)
    }

    private var shieldLabel: String {
        isCaptured ? "secure-chat is hidden while the screen is being recorded or shared" : "secure-chat"
    }

    private func hideShield() {
        guard let shield = shield else { return }
        shield.removeFromSuperview()
        self.shield = nil
        UIAccessibility.post(notification: .screenChanged, argument: nil)
    }
}
