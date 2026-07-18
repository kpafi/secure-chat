package org.securechat.app

import android.net.Uri

/**
 * The relay location the app talks to, split into the exact origins the client
 * and the CSP need. Parsing is strict: an http(s) scheme, a host, and no path —
 * a relay is an origin, not a URL into one.
 */
data class RelayUrls(
    val httpOrigin: String, // e.g. https://relay.example.com  (used for /api fetch)
    val wsOrigin: String,   // e.g. wss://relay.example.com    (client appends /ws)
) {
    companion object {
        // A relay host may only contain characters that are unambiguous in a
        // hostname. android.net.Uri does NOT validate host characters — it
        // happily returns `"`, `;`, `{`, `}`, spaces, and percent-decoded
        // delimiters in .host. Because the parsed value is later interpolated
        // into injected JS and the CSP header, a permissive host is an arbitrary
        // code-execution vector (see the 2026-07-08 Android pentest, Finding 1).
        // Whitelist letters, digits, dot and hyphen; that covers DNS names and
        // IPv4/.onion, and rejects IPv6 literals ("[...]") — unneeded here.
        private val SAFE_HOST = Regex("^[A-Za-z0-9.-]+$")

        fun parse(raw: String): RelayUrls? {
            val text = raw.trim().trimEnd('/')
            if (text.isEmpty()) return null
            val uri = runCatching { Uri.parse(text) }.getOrNull() ?: return null
            val scheme = uri.scheme?.lowercase() ?: return null
            if (scheme != "http" && scheme != "https") return null
            val host = uri.host ?: return null
            if (host.isEmpty()) return null
            // Fail closed on any host character outside the safe set. This is the
            // primary defense: it stops the parsed value from ever carrying quote,
            // brace, semicolon, or delimiter characters downstream.
            if (!SAFE_HOST.matches(host)) return null
            // Reject credentials in the authority (user:pass@host).
            if (uri.userInfo != null) return null
            // Reject anything carrying a path/query/fragment: origins only.
            if (!uri.path.isNullOrEmpty() || uri.query != null || uri.fragment != null) return null

            val portPart = if (uri.port != -1) ":${uri.port}" else ""
            val wsScheme = if (scheme == "https") "wss" else "ws"
            return RelayUrls(
                httpOrigin = "$scheme://$host$portPart",
                wsOrigin = "$wsScheme://$host$portPart",
            )
        }
    }
}
