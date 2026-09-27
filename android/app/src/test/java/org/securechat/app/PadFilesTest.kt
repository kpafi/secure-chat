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
            "secure-chat-pad-2026-09-26-\u0967\u096a\u0969\u0968.json", // Devanagari digits
            "secure-chat-pad-2026-\u06f0\u06f9-26-1432.json", // Extended Arabic-Indic digits
            "secure-chat-pad-2026-09-26-1432.jso",             // one short
            "secure-chat-pad-2026-09-27-1432.jsoX",            // right length, LAST character wrong (pentest r4 G4)
            "Xecure-chat-pad-2026-09-27-1432.json",            // right length, first character wrong
            "secure-chat-pad-2026-09-26-1432.jsonx",
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
            envelope(iters = "600001"),                                          // not KDF_ITERS (F7)
            envelope(iters = "60000"),
            envelope(iters = "1"),
            envelope(iters = "6000000"),
            envelope(salt = "AAECAwQFBgcICQoLDA0O"),                             // 20 chars: not 16 bytes
            envelope(salt = "AAECAwQFBgcICQoLDA0ODw==AAAA"),                     // 28 chars
            envelope(iv = "AAECAwQFBgcICQ=="),                                   // 16 chars, but 10 bytes
            envelope(iv = "AAECAwQFBgcICQoLDA0O"),                               // 15 bytes
            envelope(ct = ""),                                                   // empty base64
            envelope(ct = "abc\\u0022"),                                         // JSON escape
            envelope(ct = "abc-_"),                                              // base64url, not btoa
            envelope(ct = "ab==c"),                                              // padding mid-string
            envelope(ct = "abc==="),                                             // three pad chars
            envelope(ct = "AAAAA==="),                                           // three pad chars, 8 in all
            envelope(ct = "a==="),
            envelope(ct = "abcde"),                                              // not a multiple of 4
            envelope(ct = "abc"),
            envelope(salt = "é"),                                                // non-ASCII
        )) {
            assertFalse("must refuse ${bad?.take(80)}", PadFileRules.validText(bad))
        }
    }

    @Test
    fun capsTheTextAtFourMiB() {
        // The longest valid ct (a multiple of 4) that fits, and the next one.
        val room = PadFileRules.MAX_BYTES - envelope(ct = "").length
        val fits = envelope(ct = "A".repeat(room - room % 4))
        assertTrue(fits.length <= PadFileRules.MAX_BYTES && fits.length > PadFileRules.MAX_BYTES - 4)
        assertTrue("a valid envelope up to 4 MiB is accepted", PadFileRules.validText(fits))
        assertFalse("the next valid size, over 4 MiB, is refused by the cap",
            PadFileRules.validText(envelope(ct = "A".repeat(room - room % 4 + 4))))
        assertEquals(4 * 1024 * 1024, PadFileRules.MAX_BYTES)
    }

    // Pentest r1: the check is a linear scan, not a regex (ICU's backtracking
    // stack on the device is not what the JVM tests run). A worst case for a
    // backtracking engine — a 4 MiB alphabet run that fails at the very end —
    // is answered at once, and so is the largest real export.
    @Test
    fun theEnvelopeCheckIsLinearOnFourMiB() {
        val room = PadFileRules.MAX_BYTES - envelope(ct = "").length
        val run = "A".repeat(room - room % 4 - 4)
        val t0 = System.nanoTime()
        assertFalse(PadFileRules.validText(envelope(ct = run + "AAA!")))
        assertFalse(PadFileRules.validText(envelope(ct = run + "AA=A")))
        assertTrue(PadFileRules.validText(envelope(ct = run + "AA==")))
        assertTrue("three 4 MiB scans in under 2 s", System.nanoTime() - t0 < 2_000_000_000L)
    }

    // The committed fixture is the real exportPad() output (client/otp.js);
    // client/android-source.test.mjs checks that exportPad still writes the
    // same skeleton, so this ties the native check to the client.
    @Test
    fun acceptsARealExportPadFile() {
        val fixture = javaClass.getResource("pad-export-fixture.json")!!.readText()
        assertTrue(PadFileRules.validText(fixture))
        assertTrue(fixture.contains("\"iters\":${PadFileRules.KDF_ITERS}},"))
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
