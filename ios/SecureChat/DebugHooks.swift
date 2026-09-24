#if DEBUG
import UIKit
import WebKit

/// Debug-build-only hooks for the simulator CI run. Compiled out of Release
/// (the whole file is `#if DEBUG`), so the shipped app has none of this.
enum DebugHooks {
    /// `SC_TEST_RELAY`: preset the relay so the test run skips the first-run
    /// prompt (xcodebuild passes it as TEST_RUNNER_SC_TEST_RELAY).
    static func applyLaunchEnvironment() {
        let env = ProcessInfo.processInfo.environment
        if let raw = env["SC_TEST_RELAY"], let relay = RelayUrls.parse(raw) {
            Prefs.setRelay(relay)
        }
    }

    /// `SC_PERSIST_PROBE`: on a cold launch, write what localStorage holds under
    /// `sc.ci.persist` to Documents/persist-probe.txt, so CI can prove the
    /// client's storage survives an app restart.
    @MainActor
    static func clientLoaded(_ vc: MainViewController) {
        guard ProcessInfo.processInfo.environment["SC_PERSIST_PROBE"] == "1", let wv = vc.webView else { return }
        wv.evaluateJavaScript("localStorage.getItem('sc.ci.persist') || 'MISSING'") { result, error in
            let text = (result as? String) ?? "ERROR \(String(describing: error))"
            if let docs = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first {
                try? text.write(to: docs.appendingPathComponent("persist-probe.txt"), atomically: true, encoding: .utf8)
            }
        }
    }
}
#endif
