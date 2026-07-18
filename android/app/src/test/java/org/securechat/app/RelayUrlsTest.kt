package org.securechat.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

/**
 * Regression tests for [RelayUrls.parse]. Robolectric provides a real
 * android.net.Uri, so these exercise the actual parser (including Uri's
 * percent-decoding into .host) rather than a stub.
 *
 * The rejection cases below are the live payloads from the 2026-07-08 Android
 * pentest Finding 1 (relay-address string -> arbitrary JS execution). Before the
 * host-charset whitelist they parsed successfully and their unescaped value was
 * interpolated into injected JS / the CSP header; they must now be rejected.
 */
@RunWith(RobolectricTestRunner::class)
class RelayUrlsTest {

    // --- Legitimate relays still parse to the expected origins ---------------

    @Test
    fun parsesHttpsHost() {
        val r = RelayUrls.parse("https://relay.example.com")!!
        assertEquals("https://relay.example.com", r.httpOrigin)
        assertEquals("wss://relay.example.com", r.wsOrigin)
    }

    @Test
    fun parsesLoopbackWithPort() {
        val r = RelayUrls.parse("http://127.0.0.1:8000")!!
        assertEquals("http://127.0.0.1:8000", r.httpOrigin)
        assertEquals("ws://127.0.0.1:8000", r.wsOrigin)
    }

    @Test
    fun parsesOnion() {
        val r = RelayUrls.parse("http://abcdefghij234567.onion")!!
        assertEquals("http://abcdefghij234567.onion", r.httpOrigin)
        assertEquals("ws://abcdefghij234567.onion", r.wsOrigin)
    }

    @Test
    fun trimsTrailingSlash() {
        assertEquals("https://relay.example.com", RelayUrls.parse("https://relay.example.com/")!!.httpOrigin)
    }

    // --- Finding 1 payloads: injection via a permissive host ------------------

    @Test
    fun rejectsJsInjectionMarkerPayload() {
        // The pentest's PoC 1: after Uri decoding the host carried `"};window...`
        assertNull(RelayUrls.parse("http://y\"};window.__pwn=1;%2f%2f"))
    }

    @Test
    fun rejectsPercentEncodedDelimiters() {
        assertNull(RelayUrls.parse("http://host%2f%2fevil"))
        assertNull(RelayUrls.parse("http://host%22quote"))
    }

    @Test
    fun rejectsQuoteBraceSemicolonSpaceInHost() {
        assertNull(RelayUrls.parse("http://ho\"st"))
        assertNull(RelayUrls.parse("http://ho{st}"))
        assertNull(RelayUrls.parse("http://ho;st"))
        assertNull(RelayUrls.parse("http://ho st"))
    }

    // --- Other rejection cases ------------------------------------------------

    @Test
    fun rejectsNonHttpScheme() {
        assertNull(RelayUrls.parse("ftp://relay.example.com"))
        assertNull(RelayUrls.parse("javascript:alert(1)"))
    }

    @Test
    fun rejectsCredentialsInAuthority() {
        assertNull(RelayUrls.parse("https://user:pass@relay.example.com"))
    }

    @Test
    fun rejectsPathQueryFragment() {
        assertNull(RelayUrls.parse("https://relay.example.com/path"))
        assertNull(RelayUrls.parse("https://relay.example.com?q=1"))
        assertNull(RelayUrls.parse("https://relay.example.com#f"))
    }

    @Test
    fun rejectsEmptyAndMissingHost() {
        assertNull(RelayUrls.parse(""))
        assertNull(RelayUrls.parse("   "))
        assertNull(RelayUrls.parse("https://"))
    }
}
