package org.securechat.app

import android.annotation.SuppressLint
import android.net.Uri
import android.os.Bundle
import android.text.InputType
import android.webkit.WebResourceRequest
import android.webkit.WebResourceResponse
import android.webkit.WebView
import android.webkit.WebViewClient
import android.widget.EditText
import android.widget.Toast
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.webkit.ScriptHandler
import androidx.webkit.WebViewAssetLoader
import androidx.webkit.WebViewCompat
import androidx.webkit.WebViewFeature
import org.securechat.app.databinding.ActivityMainBinding

/**
 * Native shell around the audited secure-chat web client.
 *
 * SECURITY MODEL. The whole point of the app (vs. the browser) is to stop
 * trusting a server to serve honest code: the client — identity keys, all four
 * cipher modes, the ratchet — is BUNDLED in the APK (assets/web) and served to
 * the WebView from a local secure origin via [WebViewAssetLoader]. The relay is
 * reached only as a dumb WebSocket/HTTP endpoint that carries opaque ciphertext.
 *
 * Two things the app supplies that the same-origin web deployment got for free:
 *   1. the relay location — injected as `window.__SECURE_CHAT_RELAY__` before any
 *      page script runs (the client falls back to same-origin when it is absent);
 *   2. the Content-Security-Policy — set as a response header on the bundled
 *      index.html, with connect-src pinned to exactly the configured relay host,
 *      so the page can talk to the relay and nothing else.
 */
class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding
    private lateinit var assetLoader: WebViewAssetLoader
    private var relayScript: ScriptHandler? = null

    // Local secure origin the bundled client is served from. Treated as a secure
    // context by WebView, so window.crypto.subtle is available.
    private val appOrigin = "https://appassets.androidplatform.net"
    private val indexUrl = "$appOrigin/assets/web/index.html"

    // SHA-256 of the inline import map in index.html, pinned in script-src. Must
    // match the value the backend serves (guarded there by test_csp_hash.py); it
    // is identical because the bundled index.html is a copy of the web one.
    private val importMapHash = "sha256-8alK18bvJunVDTi6IeRPvle6KjTYfSgRbp5alxxa+M8="

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        assetLoader = WebViewAssetLoader.Builder()
            .addPathHandler("/assets/", WebViewAssetLoader.AssetsPathHandler(this))
            .build()

        configureWebView()

        val relay = Prefs.relay(this)
        if (relay == null) promptForRelay(initial = true) else loadWithRelay(relay)
    }

    @SuppressLint("SetJavaScriptEnabled")
    private fun configureWebView() {
        val wv = binding.webview
        wv.settings.apply {
            javaScriptEnabled = true      // the client IS JavaScript
            domStorageEnabled = true      // localStorage: encrypted identity blob + pins
            allowFileAccess = false
            allowContentAccess = false
            cacheMode = android.webkit.WebSettings.LOAD_NO_CACHE
        }
        WebView.setWebContentsDebuggingEnabled(true) // debug build aid

        wv.webViewClient = object : WebViewClient() {
            override fun shouldInterceptRequest(
                view: WebView, request: WebResourceRequest,
            ): WebResourceResponse? {
                val response = assetLoader.shouldInterceptRequest(request.url) ?: return null
                // Stamp the CSP onto the main document as it leaves the loader.
                if (request.url.path?.endsWith("/index.html") == true) {
                    val headers = HashMap(response.responseHeaders ?: emptyMap())
                    headers["Content-Security-Policy"] = csp(Prefs.relay(view.context))
                    response.responseHeaders = headers
                }
                return response
            }

            // Keep every navigation inside the app origin; never hand a URL to an
            // external browser (the relay is reached via fetch/WebSocket, not nav).
            override fun shouldOverrideUrlLoading(
                view: WebView, request: WebResourceRequest,
            ): Boolean = request.url.toString().startsWith(appOrigin).not()
        }
    }

    /** Point the client at [relay], (re)inject the config script, and load. */
    private fun loadWithRelay(relay: RelayUrls) {
        relayScript?.remove()
        val js = "window.__SECURE_CHAT_RELAY__ = " +
            "{api:\"${relay.httpOrigin}\", ws:\"${relay.wsOrigin}/ws\"};"
        if (WebViewFeature.isFeatureSupported(WebViewFeature.DOCUMENT_START_SCRIPT)) {
            relayScript = WebViewCompat.addDocumentStartJavaScript(
                binding.webview, js, setOf(appOrigin),
            )
        }
        binding.webview.loadUrl(indexUrl)
    }

    private fun csp(relay: RelayUrls?): String {
        val connect = if (relay != null) "${relay.httpOrigin} ${relay.wsOrigin}" else ""
        return "default-src 'none'; " +
            "script-src 'self' '$importMapHash'; " +
            "style-src 'self'; " +
            "connect-src 'self' $connect; " +
            "img-src 'self' data:; " +
            "base-uri 'none'; " +
            "form-action 'none'; " +
            "frame-ancestors 'none'"
    }

    private fun promptForRelay(initial: Boolean) {
        val input = EditText(this).apply {
            inputType = InputType.TYPE_TEXT_VARIATION_URI
            hint = getString(R.string.relay_hint)
            setText(Prefs.relay(this@MainActivity)?.httpOrigin ?: "")
        }
        val dialog = AlertDialog.Builder(this)
            .setTitle(R.string.relay_dialog_title)
            .setMessage(R.string.relay_dialog_msg)
            .setView(input)
            .setPositiveButton(R.string.save, null) // set below so it can not-dismiss on error
            .apply { if (!initial) setNegativeButton(R.string.cancel, null) }
            .setCancelable(!initial)
            .create()
        dialog.setOnShowListener {
            dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener {
                val parsed = RelayUrls.parse(input.text.toString())
                if (parsed == null) {
                    Toast.makeText(this, R.string.bad_relay, Toast.LENGTH_LONG).show()
                } else {
                    Prefs.setRelay(this, parsed)
                    dialog.dismiss()
                    loadWithRelay(parsed)
                }
            }
        }
        dialog.show()
    }

    override fun onCreateOptionsMenu(menu: android.view.Menu): Boolean {
        menuInflater.inflate(R.menu.main, menu)
        return true
    }

    override fun onOptionsItemSelected(item: android.view.MenuItem): Boolean = when (item.itemId) {
        R.id.action_reload -> { binding.webview.reload(); true }
        R.id.action_relay -> { promptForRelay(initial = false); true }
        else -> super.onOptionsItemSelected(item)
    }

    @Deprecated("Deprecated in Java")
    override fun onBackPressed() {
        if (binding.webview.canGoBack()) binding.webview.goBack() else super.onBackPressed()
    }
}
