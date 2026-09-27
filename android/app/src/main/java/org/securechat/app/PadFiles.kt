package org.securechat.app

import android.webkit.JavascriptInterface
import java.security.SecureRandom
import java.util.concurrent.atomic.AtomicReference

/**
 * Handing an exported one-time pad file out of the app: the native half of the
 * OTP transfer sheets (design/research/reviews/otp-transfer-brief.md, 5 and 9).
 *
 * WHY THIS EXISTS. The web client exports a pad by clicking an `<a download>`
 * on a `blob:` URL. A WebView has no download manager and cannot fetch `blob:`
 * URLs natively, so on Android the file was silently dropped — after the pad
 * had already been latched as exported (latch first, file second, by design).
 * The user was told "Exported." and had nothing to give their contact.
 *
 * WHAT CROSSES. Two methods, each taking a file NAME and the file TEXT, each
 * returning at once with a request id; the outcome arrives later through
 * [resultScript]. No passphrase, no pad bytes in the clear (the text is the
 * transfer-passphrase-encrypted envelope), no path, no MIME type, no intent
 * extra, nothing to read back. Everything here is validated on the native side
 * whatever the page checked, because the page is exactly the party this
 * surface must not trust.
 *
 * WHAT PAGE JAVASCRIPT CAN DO WITH IT, stated plainly (any script running in
 * the page reaches the bridge, like the pad floor): ask for the system share
 * sheet or the system save dialog for ONE file whose name is a timestamp and
 * whose content has the exact shape of a pad export, one request at a time.
 * Nothing leaves the device and nothing is written outside app-private cache
 * until the USER picks a target in system UI. It cannot choose where a file
 * goes, name it, give it another type, read any file, or add to the intent.
 * An attacker who already runs script in the page holds the pad passphrase
 * prompt, the decrypted pad and the whole chat — handing out a file the user
 * has to tap through two system screens to deliver is not a new capability.
 */
object PadFileRules {
    /**
     * Brief 7: `secure-chat-pad-YYYY-MM-DD-HHMM.json`, the export's local time.
     * Each `#` is one ASCII digit, every other character is itself, and the
     * length is exact — so no trailing newline, path separator or second
     * extension can ride along.
     *
     * Not a regex (cold critic r2 mi-7). It was one, with `[0-9]` because on
     * Android java.util.regex is ICU, where `\d` is any Unicode decimal digit
     * (Arabic-Indic, Devanagari, …). But the JVM tests run OpenJDK's engine,
     * where `\d` is ASCII-only, so a `\d` slipping back in was invisible to
     * every test. A character-by-character check means the same thing on both,
     * and a digit test that admitted Unicode digits (`Char.isDigit()`) fails
     * PadFilesTest on the JVM too.
     */
    const val NAME_TEMPLATE = "secure-chat-pad-####-##-##-####.json"

    /**
     * The PBKDF2 iteration count `exportPad()` always writes: KDF_ITERS in
     * client/otp.js (android-source.test.mjs holds the two equal). Pentest r1
     * F7: the envelope used to admit any 1–9 digit count, so a page could hand
     * out a file whose import runs a PBKDF2 of minutes (or of one round).
     */
    const val KDF_ITERS = 600000

    // The envelope exactly as `exportPad()` writes it with JSON.stringify:
    // these literals, in this order, around three standard (btoa) base64 runs —
    // salt (16 random bytes), iv (12 random bytes), ct.
    private const val HEAD = "{\"fmt\":\"secure-chat-otp-pad\",\"v\":1,\"kdf\":{\"salt\":\""
    private const val AFTER_SALT = "\",\"iters\":$KDF_ITERS},\"iv\":\""
    private const val AFTER_IV = "\",\"ct\":\""
    private const val TAIL = "\"}"
    const val SALT_BYTES = 16
    const val IV_BYTES = 12

    /**
     * Is [text] exactly the pad-file envelope? Stricter than "parses as JSON
     * with these keys": a lenient parser (org.json takes single quotes,
     * unquoted names, trailing garbage) would let the page put arbitrary bytes
     * into a file the user then carries to another device. Matching the
     * canonical text admits only strings that are valid JSON with exactly
     * those keys, and nothing else.
     *
     * Pentest r1: a hand-written, single-pass scanner, NOT a regex. On Android
     * java.util.regex is ICU, whose backtracking stack has a fixed limit, and
     * the JVM unit tests run OpenJDK's engine instead — a 1.4 MB `ct` run that
     * overflowed ICU would fail every real Share/Save while every test passed.
     * This is O(n), allocation-free, and behaves the same on both.
     * client/android-source.test.mjs holds the real `exportPad()` output to the
     * same skeleton as the fixture PadFilesTest accepts, so client and native
     * cannot drift apart unnoticed.
     */
    fun isEnvelope(text: String): Boolean {
        var i = 0
        fun literal(s: String): Boolean {
            if (!text.startsWith(s, i)) return false
            i += s.length
            return true
        }
        // One base64 run as btoa writes it: alphabet characters, then at most
        // two '=', a positive multiple of 4 in all; for a known byte count,
        // exactly the length and padding btoa gives that many bytes.
        fun base64(bytes: Int?): Boolean {
            val start = i
            while (i < text.length && isBase64Char(text[i])) i++
            var pad = 0
            while (pad < 2 && i < text.length && text[i] == '=') { i++; pad++ }
            val n = i - start
            if (n == 0 || n % 4 != 0) return false
            return bytes == null || (n == 4 * ((bytes + 2) / 3) && pad == (3 - bytes % 3) % 3)
        }
        return literal(HEAD) && base64(SALT_BYTES) && literal(AFTER_SALT) && base64(IV_BYTES) &&
            literal(AFTER_IV) && base64(null) && literal(TAIL) && i == text.length
    }

    private fun isBase64Char(c: Char): Boolean =
        c in 'A'..'Z' || c in 'a'..'z' || c in '0'..'9' || c == '+' || c == '/'

    /**
     * 4 MiB, the same cap `importPad()` applies (audit 2026-07-18 L-01). The
     * largest genuine export (a 1 MiB pad) is ~1.4 MiB. The envelope is ASCII
     * only, so characters and UTF-8 bytes are the same count; the byte count is
     * still what is checked, after a cheap length pre-check.
     */
    const val MAX_BYTES = 4 * 1024 * 1024

    fun validName(name: String?): Boolean {
        if (name == null || name.length != NAME_TEMPLATE.length) return false
        for (i in NAME_TEMPLATE.indices) {
            val t = NAME_TEMPLATE[i]
            val c = name[i]
            if (if (t == '#') c !in '0'..'9' else c != t) return false
        }
        return true
    }

    fun validText(text: String?): Boolean {
        if (text == null || text.length > MAX_BYTES) return false
        if (text.toByteArray(Charsets.UTF_8).size > MAX_BYTES) return false
        return isEnvelope(text)
    }

    fun valid(name: String?, text: String?): Boolean = validName(name) && validText(text)
}

/** The outcomes the shell ever reports. A fixed set: nothing from the page. */
object PadFileOutcome {
    const val SHARED = "shared"
    const val SAVED = "saved"
    const val CANCELLED = "cancelled"
    const val ERROR = "error"
    val ALL = setOf(SHARED, SAVED, CANCELLED, ERROR)
}

class PadFileRequest(val kind: Kind, val id: String, val name: String, val text: String) {
    enum class Kind { SHARE, SAVE }
}

/**
 * The JS-facing bridge, published to the page at document-start as the frozen
 * `window.__SECURE_CHAT_FILES__` (see MainActivity.loadWithRelay).
 *
 * `@JavascriptInterface` methods run on the WebView's bridge thread, not the
 * main thread. They only validate and claim the one request slot, then hand
 * the request to [start], which must post to the main thread. Parameters are
 * nullable: JS can pass `null`, and a non-null Kotlin parameter would throw
 * inside the bridge instead of answering [INVALID].
 */
class PadFilesBridge(private val start: (PadFileRequest) -> Unit) {
    companion object {
        const val BUSY = "busy"
        const val INVALID = "invalid"
        private val ID = Regex("[0-9a-f]{16}")
        private val random = SecureRandom()

        fun newId(): String {
            val b = ByteArray(8)
            random.nextBytes(b)
            return b.joinToString("") { "%02x".format(it.toInt() and 0xff) }
        }

        /**
         * The ONLY JavaScript the shell evaluates for this feature. Built from
         * our own hex id and a constant outcome, both checked here, so no string
         * that came from the page is ever interpolated into script. The `&&`
         * guard means a page without the receiver (or a reloaded page) is a
         * no-op rather than an exception.
         */
        fun resultScript(id: String, outcome: String): String {
            require(ID.matches(id)) { "request id must be 16 lowercase hex" }
            require(outcome in PadFileOutcome.ALL) { "unknown outcome" }
            return "window.__SECURE_CHAT_FILES_RESULT__ && " +
                "window.__SECURE_CHAT_FILES_RESULT__(\"$id\", \"$outcome\")"
        }
    }

    // One request at a time, across both methods: the id of the request in
    // flight, or null. A page cannot stack share sheets or save dialogs.
    private val inFlight = AtomicReference<String?>(null)

    @JavascriptInterface
    fun share(name: String?, text: String?): String = request(PadFileRequest.Kind.SHARE, name, text)

    @JavascriptInterface
    fun save(name: String?, text: String?): String = request(PadFileRequest.Kind.SAVE, name, text)

    private fun request(kind: PadFileRequest.Kind, name: String?, text: String?): String {
        if (inFlight.get() != null) return BUSY          // cheap, before validating up to 4 MiB
        if (!PadFileRules.valid(name, text)) return INVALID
        val id = newId()
        if (!inFlight.compareAndSet(null, id)) return BUSY
        start(PadFileRequest(kind, id, name!!, text!!))
        return id
    }

    /** Release the slot held by [id]. False (and nothing changes) for any other id. */
    fun finish(id: String): Boolean = inFlight.compareAndSet(id, null)

    fun pending(): String? = inFlight.get()
}
