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
        fun parse(raw: String): RelayUrls? {
            val text = raw.trim().trimEnd('/')
            if (text.isEmpty()) return null
            val uri = runCatching { Uri.parse(text) }.getOrNull() ?: return null
            val scheme = uri.scheme?.lowercase() ?: return null
            if (scheme != "http" && scheme != "https") return null
            val host = uri.host ?: return null
            if (host.isEmpty()) return null
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
