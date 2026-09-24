import XCTest
@testable import SecureChat

/// Port of android/app/src/test/.../RelayUrlsTest.kt, plus the iOS-only rule
/// (http is loopback-only). The rejection payloads are the live ones from the
/// 2026-07-08 Android pentest Finding 1 (relay address → JS execution).
final class RelayUrlsTests: XCTestCase {
    func testParsesHttpsHost() {
        let r = RelayUrls.parse("https://relay.example.com")
        XCTAssertEqual(r?.httpOrigin, "https://relay.example.com")
        XCTAssertEqual(r?.wsOrigin, "wss://relay.example.com")
    }

    func testParsesLoopbackWithPort() {
        let r = RelayUrls.parse("http://127.0.0.1:8000")
        XCTAssertEqual(r?.httpOrigin, "http://127.0.0.1:8000")
        XCTAssertEqual(r?.wsOrigin, "ws://127.0.0.1:8000")
        XCTAssertEqual(RelayUrls.parse("http://localhost:8000")?.wsOrigin, "ws://localhost:8000")
    }

    func testTrimsTrailingSlashAndWhitespace() {
        XCTAssertEqual(RelayUrls.parse("  https://relay.example.com/ \n")?.httpOrigin, "https://relay.example.com")
    }

    func testHttpOnlyForLoopback() {
        XCTAssertNil(RelayUrls.parse("http://relay.example.com"))
        XCTAssertNil(RelayUrls.parse("http://192.168.1.10:8000"))
        XCTAssertNil(RelayUrls.parse("http://abcdefghij234567.onion"))
        XCTAssertNil(RelayUrls.parse("http://127.0.0.1.evil.com"))
    }

    func testRejectsInjectionPayloads() {
        XCTAssertNil(RelayUrls.parse("http://y\"};window.__pwn=1;%2f%2f"))
        XCTAssertNil(RelayUrls.parse("https://host%2f%2fevil"))
        XCTAssertNil(RelayUrls.parse("https://host%22quote"))
        XCTAssertNil(RelayUrls.parse("https://ho\"st"))
        XCTAssertNil(RelayUrls.parse("https://ho{st}"))
        XCTAssertNil(RelayUrls.parse("https://ho;st"))
        XCTAssertNil(RelayUrls.parse("https://ho st"))
        XCTAssertNil(RelayUrls.parse("https://[::1]:8000"))
        XCTAssertNil(RelayUrls.parse("https://relay.example.com' 'unsafe-inline"))
    }

    func testRejectsOtherShapes() {
        XCTAssertNil(RelayUrls.parse("ftp://relay.example.com"))
        XCTAssertNil(RelayUrls.parse("javascript:alert(1)"))
        XCTAssertNil(RelayUrls.parse("https://user:pass@relay.example.com"))
        XCTAssertNil(RelayUrls.parse("https://relay.example.com/path"))
        XCTAssertNil(RelayUrls.parse("https://relay.example.com?q=1"))
        XCTAssertNil(RelayUrls.parse("https://relay.example.com#f"))
        XCTAssertNil(RelayUrls.parse(""))
        XCTAssertNil(RelayUrls.parse("   "))
        XCTAssertNil(RelayUrls.parse("https://"))
        XCTAssertNil(RelayUrls.parse("https://relay.example.com:0"))
        XCTAssertNil(RelayUrls.parse("https://relay.example.com:70000"))
    }

    func testCspPinsExactlyTheRelay() {
        let csp = WebShell.csp(relay: RelayUrls.parse("https://relay.example.com:8443"))
        XCTAssertTrue(csp.contains("connect-src 'self' https://relay.example.com:8443 wss://relay.example.com:8443;"))
        XCTAssertTrue(csp.contains("script-src 'self' '\(WebShell.importMapHash)';"))
        XCTAssertTrue(csp.hasPrefix("default-src 'none';"))
        XCTAssertFalse(csp.contains("unsafe"))
    }

    @MainActor
    func testPageZoomFollowsDynamicType() {
        XCTAssertEqual(MainViewController.pageZoom(for: .large), 1.0)
        XCTAssertGreaterThan(MainViewController.pageZoom(for: .accessibilityExtraExtraExtraLarge), 1.5)
        XCTAssertLessThan(MainViewController.pageZoom(for: .extraSmall), 1.0)
    }

    /// Hot review M3: never narrower than the 320 px the web UI was reviewed at.
    @MainActor
    func testAppliedZoomKeepsA320PxViewport() {
        XCTAssertEqual(MainViewController.appliedZoom(for: .large, width: 393), 1.0)
        let z = MainViewController.appliedZoom(for: .accessibilityExtraExtraExtraLarge, width: 393)
        XCTAssertGreaterThanOrEqual(393 / z, 320 - 0.001)
        XCTAssertGreaterThan(z, 1.2)
        XCTAssertEqual(MainViewController.appliedZoom(for: .extraSmall, width: 393), 0.85)
    }
}
