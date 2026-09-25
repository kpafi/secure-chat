import CryptoKit
import Foundation
import Security

/// Monotonic, tamper-evident floors for the at-rest stores — the iOS port of
/// `android/app/src/main/java/org/securechat/app/PadFloor.kt`. Read that file
/// first: the threat model, the namespace (`<padId>`, `recv:`, `exported:`,
/// `contacts:`, `chats:`) and the H-1 "no lowering operation, no deletion"
/// rule are the same, and deliberately so.
///
/// STORAGE, and how it differs from Android:
///  * Records live in a small JSON file in Application Support, one
///    `"<value>:<base64 tag>"` string per id — the same record format as the
///    Android SharedPreferences entry. The file is excluded from backup (the
///    Android app has `allowBackup=false`), so a backup restore cannot bring an
///    old floor back.
///  * The tag is HMAC-SHA-256 over `secure-chat/otp-pad-floor/v1\0id\0value`
///    (identical to Android), keyed by 32 random bytes kept in the Keychain as
///    `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`: never synced, never
///    migrated to another device, not in any backup that restores elsewhere.
///  * Difference, stated plainly: the Android key lives in the AndroidKeyStore
///    and is non-exportable; iOS has no Keychain HMAC key that the app cannot
///    read (the Secure Enclave only does P-256), so here the app process can
///    read the key. The JS context cannot — it reaches the floor only through
///    `FloorBridge`, which has no key access — so the property the floor
///    exists for holds: the page cannot lower or forge a floor. An attacker
///    with code execution in the app PROCESS (not the page) can; on Android
///    such an attacker can at least use the Keystore key as an oracle, so the
///    gap is small, but it is a gap.
///  * The Keychain outlives an uninstall; the records file does not. A
///    reinstall therefore starts with no floors (ABSENT), as on Android — the
///    old key is simply reused; values, not the key, are what reset.
///  * File access alone can delete the records file (every floor then reads
///    ABSENT, which the client treats as destruction where a floor is expected
///    and fails closed) or edit it (the MAC fails: TAMPERED). It cannot forge a
///    lower value. It CAN replay an older copy of the whole file, because the
///    MAC binds (id, value), not time — true of PadFloor.kt too (pentest
///    iOS-1 I-1). An older copy never leaves the device (excluded from backup),
///    so that takes a jailbroken device that kept one.
///  * Size is bounded (`maxRecords`): page JS could otherwise bump fresh ids
///    until every call parses a huge file (pentest iOS-1 I-2).
///
/// A records file that exists but cannot be parsed makes EVERY read TAMPERED
/// and refuses every write — a corrupted file must not be healed into a valid
/// one by the next legitimate save, the same rule Android applies per record.
/// ASCII 0-9 only (`CharacterSet.decimalDigits` also admits other scripts).
let asciiDigits = CharacterSet(charactersIn: "0123456789")

final class PadFloor {
    static let absent: Int64 = -1
    static let tampered: Int64 = -2
    /// Package 4: `bump`'s answer for a value outside `0...maxValue`, as
    /// PadFloor.kt's INVALID (-4) and NATIVE_INVALID in client/nativefloor.js.
    static let invalid: Int64 = -4
    /// The int32 range the JS side validates (FLOOR_MAX / PadFloor.kt MAX_VALUE).
    static let maxValue: Int64 = Int64(Int32.max)

    private static let macContext = "secure-chat/otp-pad-floor/v1"
    private static let keychainService = "org.securechat.app.pad-floor"
    private static let keychainAccount = "hmac/v1"
    /// The client keeps a handful of floors per pad and two per identity.
    static let maxRecords = 4096

    private let fileURL: URL
    private let keyProvider: () -> SymmetricKey?
    private let lock = NSLock()

    /// The app's floor. nil only if Application Support cannot be located.
    static let shared: PadFloor? = {
        guard let dir = try? FileManager.default.url(
            for: .applicationSupportDirectory, in: .userDomainMask,
            appropriateFor: nil, create: true
        ) else { return nil }
        let file = dir.appendingPathComponent("secure-chat-pad-floors.json")
        // Pentest iOS-1 L-1: if records exist, the key that signed them must
        // exist too. Minting a fresh key then would turn every record
        // permanently TAMPERED without anything having been tampered with;
        // refuse instead (still TAMPERED, fail closed, but no new key is
        // written, so restoring the Keychain restores the floors).
        // The key is cached once found: one Keychain query per launch, not
        // one per floor call on the main thread.
        var cached: SymmetricKey?
        return PadFloor(fileURL: file, keyProvider: {
            if let k = cached { return k }
            cached = PadFloor.keychainKey(create: !FileManager.default.fileExists(atPath: file.path))
            return cached
        })
    }()

    init(fileURL: URL, keyProvider: @escaping () -> SymmetricKey?) {
        self.fileURL = fileURL
        self.keyProvider = keyProvider
    }

    // MARK: - Public API (mirrors PadFloor.kt)

    func read(_ id: String) -> Int64 {
        lock.lock(); defer { lock.unlock() }
        guard let records = loadRecords() else { return Self.tampered }
        return verify(id: id, raw: records[id])
    }

    /// Raise the floor for `id` to `value` if higher. Never lowers. Returns the
    /// floor in force afterwards, TAMPERED (and writes nothing) if the stored
    /// one did not verify, or INVALID for a value outside `0...maxValue`.
    ///
    /// Package 4: a negative value used to be answered with the CURRENT floor,
    /// as if it were a harmless read — the Android side made that a refusal in
    /// package 3 (a generation of 2^31 passed as `v | 0` arrived negative and
    /// was silently dropped, freezing the floor). client/nativefloor.js now
    /// refuses such a value before the bridge, but the native side must not
    /// depend on it: the same value is INVALID here as on Android.
    func bump(_ id: String, _ value: Int64) -> Int64 {
        if value < 0 || value > Self.maxValue { return Self.invalid }
        lock.lock(); defer { lock.unlock() }
        guard var records = loadRecords() else { return Self.tampered }
        let current = verify(id: id, raw: records[id])
        if current == Self.tampered { return Self.tampered }
        let next = current == Self.absent ? value : max(current, value)
        if next == current { return current }
        if current == Self.absent && records.count >= Self.maxRecords { return Self.tampered }
        guard let tag = tag(id: id, value: next) else { return Self.tampered }
        records[id] = "\(next):\(tag.base64EncodedString())"
        guard store(records) else { return Self.tampered }
        return next
    }

    // Pentest 2026-07-29 H-1 (Android): there is deliberately NO clear/remove/
    // reset. See the note at the end of PadFloor.kt before adding one.

    // MARK: - Records

    /// nil = the file exists but is unreadable or malformed (fail closed).
    /// An absent file is an empty record set.
    private func loadRecords() -> [String: String]? {
        guard FileManager.default.fileExists(atPath: fileURL.path) else { return [:] }
        guard let data = try? Data(contentsOf: fileURL),
              let obj = try? JSONSerialization.jsonObject(with: data),
              let dict = obj as? [String: String] else { return nil }
        return dict
    }

    private func store(_ records: [String: String]) -> Bool {
        guard let data = try? JSONSerialization.data(withJSONObject: records, options: [.sortedKeys]) else {
            return false
        }
        do {
            try data.write(to: fileURL, options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication])
            // An atomic write replaces the file, so the flag is set every time.
            var url = fileURL
            var values = URLResourceValues()
            values.isExcludedFromBackup = true
            try url.setResourceValues(values)
            return true
        } catch {
            return false
        }
    }

    private func verify(id: String, raw: String?) -> Int64 {
        guard let raw = raw else { return Self.absent }
        guard let sep = raw.firstIndex(of: ":"), sep != raw.startIndex else { return Self.tampered }
        let valueText = raw[raw.startIndex..<sep]
        guard valueText.unicodeScalars.allSatisfy({ asciiDigits.contains($0) }),
              let value = Int64(valueText), value >= 0 else { return Self.tampered }
        guard let tagData = Data(base64Encoded: String(raw[raw.index(after: sep)...])),
              let key = keyProvider() else { return Self.tampered }
        // Constant-time comparison (CryptoKit).
        let ok = HMAC<SHA256>.isValidAuthenticationCode(
            tagData, authenticating: Self.message(id: id, value: value), using: key)
        return ok ? value : Self.tampered
    }

    private func tag(id: String, value: Int64) -> Data? {
        guard let key = keyProvider() else { return nil }
        let mac = HMAC<SHA256>.authenticationCode(for: Self.message(id: id, value: value), using: key)
        return Data(mac)
    }

    /// MAC over id AND value, so a floor cannot be lifted from one id and
    /// replayed under another (the P-01 lesson, as on Android).
    static func message(id: String, value: Int64) -> Data {
        Data("\(macContext)\u{0}\(id)\u{0}\(value)".utf8)
    }

    // MARK: - Keychain

    /// The HMAC key, created on first use. nil if the Keychain is unavailable
    /// (e.g. before first unlock) — every operation then answers TAMPERED.
    static func keychainKey(create: Bool = true) -> SymmetricKey? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService,
            kSecAttrAccount as String: keychainAccount,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        var out: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &out)
        if status == errSecSuccess, let data = out as? Data, data.count == 32 {
            return SymmetricKey(data: data)
        }
        guard status == errSecItemNotFound, create else { return nil }

        var bytes = [UInt8](repeating: 0, count: 32)
        guard SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) == errSecSuccess else { return nil }
        let data = Data(bytes)
        let add: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService,
            kSecAttrAccount as String: keychainAccount,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
            kSecAttrSynchronizable as String: false,
            kSecValueData as String: data,
        ]
        let addStatus = SecItemAdd(add as CFDictionary, nil)
        if addStatus == errSecSuccess { return SymmetricKey(data: data) }
        if addStatus == errSecDuplicateItem {
            // Lost a race with another caller: use the key that won.
            var again: CFTypeRef?
            if SecItemCopyMatching(query as CFDictionary, &again) == errSecSuccess,
               let d = again as? Data, d.count == 32 {
                return SymmetricKey(data: d)
            }
        }
        return nil
    }
}
