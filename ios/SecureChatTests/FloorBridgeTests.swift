import CryptoKit
import XCTest
@testable import SecureChat

final class FloorBridgeTests: XCTestCase {
    private let p = FloorBridge.prefix

    func testParsesReadAndBump() {
        let id = String(repeating: "a", count: 32)
        XCTAssertEqual(FloorBridge.parse("\(p)read\u{1}\(id)\u{1}0"), .read(id: id))
        XCTAssertEqual(FloorBridge.parse("\(p)bump\u{1}contacts:\(id)\u{1}42"), .bump(id: "contacts:\(id)", value: 42))
        XCTAssertEqual(FloorBridge.parse("\(p)bump\u{1}\(id)\u{1}-3"), .bump(id: id, value: -3))
    }

    func testRejectsMalformed() {
        let id = String(repeating: "a", count: 32)
        for bad in [
            "read\u{1}\(id)\u{1}0",                   // no prefix
            "\(p)read\u{1}\(id)",                     // too few parts
            "\(p)read\u{1}\(id)\u{1}0\u{1}x",         // too many parts
            "\(p)drop\u{1}\(id)\u{1}0",               // unknown op (no lowering, no delete)
            "\(p)clear\u{1}\(id)\u{1}0",
            "\(p)bump\u{1}\(id)\u{1} 5",              // whitespace
            "\(p)bump\u{1}\(id)\u{1}+5",
            "\(p)bump\u{1}\(id)\u{1}1e3",
            "\(p)bump\u{1}\(id)\u{1}0x10",
            "\(p)bump\u{1}\(id)\u{1}",
            "\(p)bump\u{1}\(id)\u{1}2147483648",      // > int32
            "\(p)bump\u{1}\(id)\u{1}٣",               // non-ASCII digit
            "\(p)read\u{1}\u{1}0",                    // empty id
            "\(p)read\u{1}bad id\u{1}0",
            "\(p)read\u{1}../x\u{1}0",
            "\(p)read\u{1}\(String(repeating: "a", count: 161))\u{1}0",
        ] {
            XCTAssertNil(FloorBridge.parse(bad), bad.debugDescription)
        }
    }

    func testMalformedAnswersTamperedNeverAbsent() {
        let floor = PadFloor(fileURL: tmpFile(), keyProvider: { SymmetricKey(size: .bits256) })
        XCTAssertEqual(FloorBridge.answer("\(p)nonsense", floor: floor), "-2")
        XCTAssertEqual(FloorBridge.answer("\(p)read\u{1}abc\u{1}0", floor: nil), "-2")
    }

    func testDocumentStartScriptEscapesConfigAndCapturesPrompt() {
        let s = WebShell.documentStartScript(relay: RelayUrls.parse("https://relay.example.com")!)
        XCTAssertTrue(s.hasPrefix("window.__SECURE_CHAT_RELAY__ = {\"api\":\"https:\\/\\/relay.example.com\",\"ws\":\"wss:\\/\\/relay.example.com\\/ws\"};")
                      || s.hasPrefix("window.__SECURE_CHAT_RELAY__ = {\"api\":\"https://relay.example.com\",\"ws\":\"wss://relay.example.com/ws\"};"), s)
        XCTAssertTrue(s.contains("var p = window.prompt;"))
        XCTAssertTrue(s.contains("'\\u0001secure-chat-floor\\u0001'"))
        XCTAssertFalse(s.contains("parseInt"))
        XCTAssertFalse(s.contains("Number("))
    }

    private func tmpFile() -> URL {
        FileManager.default.temporaryDirectory.appendingPathComponent("floor-\(UUID().uuidString).json")
    }
}
