import UIKit
import WebKit
import XCTest
@testable import SecureChat

/// The web-process crash-loop limit (pentest iOS-2 L-B, iOS-3 F2). Runs last
/// (class names sort alphabetically): it reloads the app's page several times.
@MainActor
final class ZCrashLoopTests: XCTestCase {
    func testFourForegroundDeathsInAMinuteShowTheCrashScreenAndTryAgainClearsIt() async throws {
        let (vc, _) = try await TestApp.mainPage()
        let wv = try XCTUnwrap(vc.webView)
        let terminated = try XCTUnwrap(vc.navDelegate.onProcessTerminated)
        XCTAssertEqual(UIApplication.shared.applicationState, .active)

        for i in 1...3 {
            terminated(wv)
            XCTAssertFalse(vc.isShowingCrashLoop, "limit tripped after \(i) deaths")
        }
        terminated(wv)
        XCTAssertTrue(vc.isShowingCrashLoop, "4 deaths in a minute must show the crash screen (F2)")
        XCTAssertTrue(wv.isHidden)
        XCTAssertFalse(vc.refusedToRun, "a crash loop is not the security refusal")
        TestApp.screenshot("14-crash-loop")

        // Try again (a user-initiated load) clears it and shows the page.
        vc.load(try XCTUnwrap(Prefs.relay()))
        XCTAssertFalse(vc.isShowingCrashLoop)
        XCTAssertFalse(wv.isHidden)
        _ = try await TestApp.mainPage()
    }
}
