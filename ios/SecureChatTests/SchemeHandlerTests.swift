import XCTest
@testable import SecureChat

@MainActor
final class SchemeHandlerTests: XCTestCase {
    private var handler: AppSchemeHandler!

    override func setUp() async throws {
        handler = AppSchemeHandler(root: WebShell.webRoot, csp: { "x" })
    }

    private func resolves(_ s: String) -> Bool {
        guard let url = URL(string: s) else { return false }
        return handler.resolve(url) != nil
    }

    func testBundledClientIsPresent() {
        XCTAssertTrue(resolves("secure-chat://app/index.html"))
        XCTAssertTrue(resolves("secure-chat://app/app.js"))
        XCTAssertTrue(resolves("secure-chat://app/style.css"))
        XCTAssertTrue(resolves("secure-chat://app/vendor/@noble/post-quantum/ml-dsa.js"))
    }

    func testTestsAndManifestsAreNotBundled() {
        XCTAssertFalse(resolves("secure-chat://app/crypto.test.mjs"))
        XCTAssertFalse(resolves("secure-chat://app/integration.test.mjs"))
        XCTAssertFalse(resolves("secure-chat://app/package.json"))
        XCTAssertFalse(resolves("secure-chat://app/package-lock.json"))
    }

    func testTraversalAndOddShapesAreRefused() {
        for s in [
            "secure-chat://app/",
            "secure-chat://app",
            "secure-chat://app/../Info.plist",
            "secure-chat://app/%2e%2e/Info.plist",
            "secure-chat://app/..%2fInfo.plist",
            "secure-chat://app/vendor/../index.html",
            "secure-chat://app/./index.html",
            "secure-chat://app//index.html",
            "secure-chat://app/index%2ehtml",
            "secure-chat://app/.hidden",
            "secure-chat://app/vendor",
            "secure-chat://app.evil/index.html",
            "secure-chat://evil/index.html",
            "secure-chat://app:1/index.html",
            "secure-chat://u@app/index.html",
            "https://app/index.html",
        ] {
            XCTAssertFalse(resolves(s), s)
        }
    }

    func testMimeTypes() {
        XCTAssertEqual(AppSchemeHandler.mimeType(for: URL(fileURLWithPath: "/a/app.js")), "text/javascript; charset=utf-8")
        XCTAssertEqual(AppSchemeHandler.mimeType(for: URL(fileURLWithPath: "/a/x.mjs")), "text/javascript; charset=utf-8")
        XCTAssertEqual(AppSchemeHandler.mimeType(for: URL(fileURLWithPath: "/a/index.html")), "text/html; charset=utf-8")
        XCTAssertEqual(AppSchemeHandler.mimeType(for: URL(fileURLWithPath: "/a/x.bin")), "application/octet-stream")
    }

    func testExportFilenamesAreSanitised() {
        XCTAssertEqual(Exports.safeFilename("secure-chat-pad-abc.json"), "secure-chat-pad-abc.json")
        XCTAssertEqual(Exports.safeFilename("../../etc/passwd"), "_.._etc_passwd")
        XCTAssertEqual(Exports.safeFilename(".hidden"), "hidden")
        XCTAssertEqual(Exports.safeFilename(""), "secure-chat-export.json")
    }
}
