package org.securechat.app

import android.content.Context

/**
 * The only app-level persisted state: which relay to talk to. The user's
 * identity keys and pins live in the WebView's localStorage (managed by the
 * bundled client), never here.
 */
object Prefs {
    private const val FILE = "secure_chat_prefs"
    private const val KEY_RELAY = "relay_http_origin"

    fun relay(context: Context): RelayUrls? {
        val stored = context.getSharedPreferences(FILE, Context.MODE_PRIVATE)
            .getString(KEY_RELAY, null) ?: return null
        return RelayUrls.parse(stored)
    }

    fun setRelay(context: Context, relay: RelayUrls) {
        context.getSharedPreferences(FILE, Context.MODE_PRIVATE)
            .edit().putString(KEY_RELAY, relay.httpOrigin).apply()
    }
}
