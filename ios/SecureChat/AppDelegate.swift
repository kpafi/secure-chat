import UIKit

@main
final class AppDelegate: UIResponder, UIApplicationDelegate {
    func application(_ application: UIApplication,
                     didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?) -> Bool {
        // A pad export left behind by a crash must not linger in tmp.
        Exports.clean()
        // Pentest iOS-1 M-1: Android forbids cloud backup and device transfer
        // (allowBackup=false, data_extraction_rules.xml, L-6). iOS backs up
        // Library/ by default, and the web view keeps the client's storage —
        // identity blob, pads, contact and chat stores — under Library/WebKit.
        WebDataBackup.exclude()
        #if DEBUG
        DebugHooks.applyLaunchEnvironment()
        #endif
        return true
    }

    func application(_ application: UIApplication,
                     configurationForConnecting connectingSceneSession: UISceneSession,
                     options: UIScene.ConnectionOptions) -> UISceneConfiguration {
        let config = UISceneConfiguration(name: "Default Configuration", sessionRole: connectingSceneSession.role)
        config.delegateClass = SceneDelegate.self
        return config
    }
}

/// Keeps the web view's storage out of iCloud / Finder backups and device
/// migration, like the Android app. Applied at every launch, before the web
/// view exists, so a directory WebKit creates later inherits the flag.
enum WebDataBackup {
    static var directory: URL? {
        FileManager.default.urls(for: .libraryDirectory, in: .userDomainMask).first?
            .appendingPathComponent("WebKit", isDirectory: true)
    }

    @discardableResult
    static func exclude() -> Bool {
        guard var dir = directory else { return false }
        do {
            try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
            var values = URLResourceValues()
            values.isExcludedFromBackup = true
            try dir.setResourceValues(values)
            return true
        } catch {
            return false
        }
    }
}
