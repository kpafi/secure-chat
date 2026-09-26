package org.securechat.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The pad-file bridge's native validation (PadFiles.kt), as pure functions:
 * everything the page hands over is checked here whatever the page checked,
 * because page script is the party this surface must not trust.
 */
class PadFilesTest {

    private val name = "secure-chat-pad-2026-09-26-1432.json"

    /** The envelope exactly as exportPad() writes it (JSON.stringify, btoa). */
    private fun envelope(
        salt: String = "AAECAwQFBgcICQoLDA0ODw==",
        iters: String = "600000",
        iv: String = "AAECAwQFBgcICQoL",
        ct: String = "q83vASNFZ4mrze8BI0VniQ+/",
    ) = """{"fmt":"secure-chat-otp-pad","v":1,"kdf":{"salt":"$salt","iters":$iters},"iv":"$iv","ct":"$ct"}"""

    // --- the file name (brief 7) --------------------------------------------

    @Test
    fun acceptsTheExactNamePattern() {
        assertTrue(PadFileRules.validName(name))
        assertTrue(PadFileRules.validName("secure-chat-pad-0000-00-00-0000.json"))
    }

    @Test
    fun refusesEveryOtherName() {
        for (bad in listOf(
            null, "",
            "secure-chat-pad-2026-09-26.json",                 // no time
            "secure-chat-pad-2026-09-26-14320.json",           // 5-digit time
            "secure-chat-pad-2026-09-26-1432.JSON",
            "secure-chat-pad-2026-09-26-1432.json.html",
            "secure-chat-pad-2026-09-26-1432.txt",
            "secure-chat-pad-2026-09-26-1432.json\n",          // `$` before a final newline
            "\nsecure-chat-pad-2026-09-26-1432.json",
            "../secure-chat-pad-2026-09-26-1432.json",         // path traversal
            "x/secure-chat-pad-2026-09-26-1432.json",
            "secure-chat-pad-2026-09-26-1432.json/..",
            "secure-chat-pad-2026-09-26-1432.json\u0000.png",
            "secure-chat-pad-٢٠٢٦-09-26-1432.json", // Arabic-Indic digits: `\d` on ICU
            "secure-chat-pad-２０２６-09-26-1432.json",          // fullwidth digits
            "Secure-chat-pad-2026-09-26-1432.json",
            "secure-chat-pad-Alice-2026-09-26-1432.json",       // a label: brief 7 says neutral
        )) {
            assertFalse("must refuse ${bad?.replace("\n", "\\n")}", PadFileRules.validName(bad))
        }
    }

    // --- the file text: the exact envelope, at most 4 MiB ---------------------

    @Test
    fun acceptsTheCanonicalEnvelope() {
        assertTrue(PadFileRules.validText(envelope()))
        assertTrue(PadFileRules.valid(name, envelope()))
    }

    @Test
    fun refusesAnythingThatIsNotTheEnvelope() {
        val good = envelope()
        for (bad in listOf(
            null, "", "{}", "null",
            good.replace("secure-chat-otp-pad", "secure-chat-identity"),       // other fmt
            good.replace("\"v\":1", "\"v\":2"),
            good.replace("\"v\":1", "\"v\":\"1\""),
            good.dropLast(1) + ",\"extra\":\"<script>\"}",                       // extra top-level key
            good.replace(",\"ct\":\"q83vASNFZ4mrze8BI0VniQ+/\"", ""),           // missing key
            good + "\n",                                                         // trailing byte
            good + "<html>",                                                     // trailing garbage
            " $good",                                                            // leading byte
            good.replace("\"", "'"),                                             // lenient-parser JSON
            good.replace(",\"iv\"", ", \"iv\""),                                  // whitespace
            envelope(iters = "0"),
            envelope(iters = "-1"),
            envelope(iters = "6e5"),
            envelope(iters = "1234567890"),                                      // > 9 digits
            envelope(ct = ""),                                                   // empty base64
            envelope(ct = "abc\\u0022"),                                         // JSON escape
            envelope(ct = "abc-_"),                                              // base64url, not btoa
            envelope(ct = "ab==c"),                                              // padding mid-string
            envelope(ct = "abc==="),                                             // three pad chars
            envelope(salt = "é"),                                                // non-ASCII
        )) {
            assertFalse("must refuse ${bad?.take(80)}", PadFileRules.validText(bad))
        }
    }

    @Test
    fun capsTheTextAtFourMiB() {
        val over = PadFileRules.MAX_BYTES - envelope(ct = "").length + 1   // one byte over with ct filled
        val fits = envelope(ct = "A".repeat(over - 1))
        assertEquals(PadFileRules.MAX_BYTES, fits.length)
        assertTrue("exactly 4 MiB is accepted", PadFileRules.validText(fits))
        assertFalse("4 MiB + 1 is refused", PadFileRules.validText(envelope(ct = "A".repeat(over))))
        assertEquals(4 * 1024 * 1024, PadFileRules.MAX_BYTES)
    }

    // --- the bridge: one request at a time, ids, the result script -----------

    @Test
    fun bridgeRefusesInvalidInputWithoutStartingAnything() {
        val started = mutableListOf<PadFileRequest>()
        val bridge = PadFilesBridge { started += it }
        assertEquals(PadFilesBridge.INVALID, bridge.share("../../etc/passwd", envelope()))
        assertEquals(PadFilesBridge.INVALID, bridge.save(name, "{\"fmt\":\"secure-chat-otp-pad\"}"))
        assertEquals(PadFilesBridge.INVALID, bridge.share(null, null))
        assertTrue(started.isEmpty())
        assertNull("an invalid request claims no slot", bridge.pending())
    }

    @Test
    fun bridgeRunsOneRequestAtATime() {
        val started = mutableListOf<PadFileRequest>()
        val bridge = PadFilesBridge { started += it }
        val id = bridge.share(name, envelope())
        assertTrue("an id is 16 lowercase hex: $id", Regex("[0-9a-f]{16}").matches(id))
        assertEquals(1, started.size)
        assertEquals(PadFileRequest.Kind.SHARE, started[0].kind)
        assertEquals(id, started[0].id)
        assertEquals(name, started[0].name)

        assertEquals("share while busy", PadFilesBridge.BUSY, bridge.share(name, envelope()))
        assertEquals("save while busy", PadFilesBridge.BUSY, bridge.save(name, envelope()))
        assertEquals(1, started.size)

        assertFalse("another id cannot release the slot", bridge.finish("0123456789abcdef"))
        assertEquals(PadFilesBridge.BUSY, bridge.save(name, envelope()))
        assertTrue(bridge.finish(id))
        assertFalse("a request is answered once", bridge.finish(id))

        val id2 = bridge.save(name, envelope())
        assertNotEquals(id, id2)
        assertEquals(PadFileRequest.Kind.SAVE, started[1].kind)
    }

    @Test
    fun resultScriptInterpolatesOnlyOurIdAndAFixedOutcome() {
        assertEquals(
            "window.__SECURE_CHAT_FILES_RESULT__ && window.__SECURE_CHAT_FILES_RESULT__(\"0123456789abcdef\", \"shared\")",
            PadFilesBridge.resultScript("0123456789abcdef", PadFileOutcome.SHARED),
        )
        for (o in PadFileOutcome.ALL) PadFilesBridge.resultScript("0123456789abcdef", o)
        assertEquals(setOf("shared", "saved", "cancelled", "error"), PadFileOutcome.ALL)
        assertThrows(IllegalArgumentException::class.java) {
            PadFilesBridge.resultScript("\"); alert(1); (\"", PadFileOutcome.SHARED)
        }
        assertThrows(IllegalArgumentException::class.java) {
            PadFilesBridge.resultScript("0123456789ABCDEF", PadFileOutcome.SHARED)
        }
        assertThrows(IllegalArgumentException::class.java) {
            PadFilesBridge.resultScript("0123456789abcdef", "shared\"); alert(1); (\"")
        }
    }
}
