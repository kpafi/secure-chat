import Foundation

/// The JS ⇄ native channel for the pad floor.
///
/// WHY `prompt()`. The client's floor API (`client/nativefloor.js`) is
/// synchronous: `read(id)` returns a number, on Android straight from a
/// `@JavascriptInterface`. WKWebView has no synchronous script-message channel
/// (`WKScriptMessageHandlerWithReply` answers with a Promise), and making the
/// floor async would mean rewriting every at-rest store's rollback check —
/// code with a long pentest history — for one platform. `window.prompt()` is
/// the one synchronous JS → native call WebKit offers: the page blocks until
/// `WKUIDelegate`'s text-input panel handler answers. The document-start script
/// (`WebShell.documentStartScript`) captures `prompt` before any page script
/// runs and republishes a frozen `{read, bump}` that speaks this protocol.
///
/// WHAT THAT EXPOSES. Any script in our page can call `prompt()` with this
/// prefix directly — exactly as any script on Android can call
/// `SecureChatPadFloor.read/bump` directly. That is fine for the same reason:
/// the protocol has no lowering operation and no deletion. `bump` takes a max.
///
/// A message with the prefix is NEVER shown to the user, even when malformed,
/// and is answered only for our own page's main frame.
enum FloorBridge {
    static let prefix = "\u{1}secure-chat-floor\u{1}"
    static let separator: Character = "\u{1}"
    /// The same two strings as JS string-literal text for the injected script.
    static let jsPrefixLiteral = "\\u0001secure-chat-floor\\u0001"
    static let jsSeparatorLiteral = "\\u0001"

    enum Request: Equatable {
        case read(id: String)
        case bump(id: String, value: Int64)
    }

    /// Floor ids the client uses: `<32 hex>`, `recv:<hex>`, `exported:<hex>`,
    /// `contacts:<hex>`, `chats:<hex>` (see client/nativefloor.js). Anything
    /// outside this charset or length is refused, not normalised.
    private static let idAllowed = CharacterSet(charactersIn:
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789:_-")

    static func isFloorMessage(_ message: String) -> Bool {
        message.hasPrefix(prefix)
    }

    /// Parse a prompt message. nil for anything malformed; the caller answers
    /// TAMPERED so a broken call can never read as "no floor".
    static func parse(_ message: String) -> Request? {
        guard message.hasPrefix(prefix) else { return nil }
        let body = message.dropFirst(prefix.count)
        let parts = body.split(separator: separator, omittingEmptySubsequences: false)
        guard parts.count == 3 else { return nil }
        let op = String(parts[0]), id = String(parts[1]), raw = String(parts[2])
        guard !id.isEmpty, id.count <= 160,
              id.unicodeScalars.allSatisfy({ idAllowed.contains($0) }) else { return nil }
        // An int32 in plain decimal, optional leading '-': no whitespace, no
        // '+', no exponent, no hex. A negative bump is answered like Android's
        // (PadFloor.bump returns the current floor and writes nothing).
        let digits = raw.hasPrefix("-") ? raw.dropFirst() : Substring(raw)
        guard !digits.isEmpty, digits.count <= 10,
              digits.unicodeScalars.allSatisfy({ asciiDigits.contains($0) }),
              let value = Int64(raw), value <= Int64(Int32.max), value >= Int64(Int32.min) else { return nil }
        switch op {
        case "read": return .read(id: id)
        case "bump": return .bump(id: id, value: value)
        default: return nil
        }
    }

    /// Handle one floor prompt. Always returns a decimal string the injected
    /// wrapper turns into a number; malformed input answers TAMPERED.
    static func answer(_ message: String, floor: PadFloor?) -> String {
        guard let floor = floor, let req = parse(message) else {
            return String(PadFloor.tampered)
        }
        switch req {
        case .read(let id): return String(floor.read(id))
        case .bump(let id, let value): return String(floor.bump(id, value))
        }
    }
}
