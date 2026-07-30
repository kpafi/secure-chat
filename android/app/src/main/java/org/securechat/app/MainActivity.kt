package org.securechat.app

import android.annotation.SuppressLint
import android.net.Uri
import android.os.Bundle
import android.text.InputType
import android.webkit.JsPromptResult
import android.webkit.JsResult
import android.webkit.WebChromeClient
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
import org.json.JSONObject
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
    // Latched once the "this WebView cannot run us" dialog is up, so the blank
    // page we load behind it cannot re-trigger the check and stack dialogs.
    private var refusedToRun = false

    // Local secure origin the bundled client is served from. Treated as a secure
    // context by WebView, so window.crypto.subtle is available. We set an
    // app-specific virtual domain (via WebViewAssetLoader.setDomain below) rather
    // than androidx.webkit's shared DEFAULT_DOMAIN ("appassets.androidplatform.net",
    // which every default WebViewAssetLoader app presents) so this origin uniquely
    // identifies our app to the relay's WS/CORS allow-list — see 2026-07-08
    // pentest Finding 4. It is a reserved-style name that never resolves publicly.
    private val appHost = "secure-chat.internal"
    private val appOrigin = "https://$appHost"
    private val indexUrl = "$appOrigin/assets/web/index.html"

    // SHA-256 of the inline import map in index.html, pinned in script-src. Must
    // match the value the backend serves (guarded there by test_csp_hash.py); it
    // is identical because the bundled index.html is a copy of the web one.
    private val importMapHash = "sha256-6Sm2nhNvoa7gr7uuY2hbAbpdWhIlL15/wXLm4dhO9UQ="

    companion object {
        /**
         * Prefix the bundled client puts on a window.prompt() whose answer is a
         * SECRET, so the shell masks the input instead of guessing from the
         * wording (pentest 2026-07-25 F-08). Must match SECRET_PROMPT_MARK in
         * client/app.js; the client only adds it when running inside the app.
         */
        const val SECRET_PROMPT_MARK = "[secure-chat:secret] "
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)
        // The web client renders its own header (wordmark + drawer button), so
        // showing the native title too gave the app two stacked "secure-chat"
        // bars. Drop the native title but KEEP the bar: its overflow holds
        // Reload and Relay settings, and Relay settings is the only way to
        // recover from a wrong relay address, when the page will not load at all.
        supportActionBar?.setDisplayShowTitleEnabled(false)

        assetLoader = WebViewAssetLoader.Builder()
            .setDomain(appHost)
            .addPathHandler("/assets/", WebViewAssetLoader.AssetsPathHandler(this))
            .build()

        configureWebView()

        // Pentest 2026-07-26 L-10: injecting the relay config is not optional.
        // Without DOCUMENT_START_SCRIPT the client loads with RELAY == null and
        // FAILS SILENTLY in two ways: every fetch/WS goes to the app's own
        // virtual origin (secure-chat.internal, which does not resolve) with an
        // opaque error, and promptSecret() stops marking secret prompts, so
        // passphrase masking degrades to the substring guess F-08 retired.
        // Refuse to run rather than hand the user a client that cannot work.
        if (!WebViewFeature.isFeatureSupported(WebViewFeature.DOCUMENT_START_SCRIPT)) {
            refuseToRun()
            return
        }

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
        // Remote debugging exposes the WebView (and its localStorage identity
        // blob) over the devtools socket — only ever in debug builds.
        if (BuildConfig.DEBUG) WebView.setWebContentsDebuggingEnabled(true)

        // Pentest 2026-07-28 F-1: the OTP rollback floor cannot live in
        // localStorage, because every key there is deletable by whoever holds the
        // JS context. PadFloor keeps it in app-private storage under an
        // AndroidKeyStore HMAC, monotone and forge-resistant. Only reachable from
        // this WebView's asset origin; see PadFloor.kt for what it does and does
        // not buy. The client feature-detects it, so the browser build is
        // unaffected (and keeps the residual, documented in README).
        wv.addJavascriptInterface(PadFloorBridge(this), "SecureChatPadFloor")

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
            // Match on the PARSED scheme+host, not a string prefix: startsWith
            // would accept "https://secure-chat.internal.evil.com/..." and let the
            // WebView navigate off-origin (2026-07-08 pentest Finding 2).
            override fun shouldOverrideUrlLoading(
                view: WebView, request: WebResourceRequest,
            ): Boolean {
                val url = request.url
                val sameOrigin = url.scheme == "https" && url.host == appHost
                return !sameOrigin
            }

            // Only the client page is checked: about:blank (loaded by
            // refuseToRun) must not re-enter the check.
            override fun onPageFinished(view: WebView, url: String?) {
                if (url == indexUrl) verifyRelayConfig()
            }
        }

        // Without a WebChromeClient the WebView SUPPRESSES JavaScript dialogs:
        // window.confirm()/prompt() return false/null immediately, so the
        // client's confirmations (Forget identity, verify contact, mode change,
        // pad passphrases) silently do nothing. Provide native dialogs so those
        // flows work in the app exactly as they do in a browser. The messages
        // are app-local (from our bundled client), never from the relay.
        wv.webChromeClient = object : WebChromeClient() {
            override fun onJsAlert(
                view: WebView, url: String?, message: String?, result: JsResult,
            ): Boolean {
                AlertDialog.Builder(this@MainActivity)
                    .setMessage(message)
                    .setCancelable(false)
                    .setPositiveButton(android.R.string.ok) { _, _ -> result.confirm() }
                    .show()
                return true
            }

            override fun onJsConfirm(
                view: WebView, url: String?, message: String?, result: JsResult,
            ): Boolean {
                AlertDialog.Builder(this@MainActivity)
                    .setMessage(message)
                    .setCancelable(false)
                    .setPositiveButton(android.R.string.ok) { _, _ -> result.confirm() }
                    .setNegativeButton(android.R.string.cancel) { _, _ -> result.cancel() }
                    .show()
                return true
            }

            override fun onJsPrompt(
                view: WebView, url: String?, message: String?, defaultValue: String?,
                result: JsPromptResult,
            ): Boolean {
                // Audit 2026-07-18 L-02: the client requests chat passphrases via
                // window.prompt(); a plain text field shows them to anyone
                // shoulder-surfing, so secret input must be masked.
                //
                // Pentest 2026-07-25 F-08: this used to guess by searching the
                // message for the word "passphrase", which would silently
                // un-mask a secret as soon as a prompt was reworded. The
                // bundled client now marks secret prompts explicitly (see
                // promptSecret in app.js) and we strip the marker before
                // display. The old substring check is kept only as a
                // fail-SECURE fallback: it can add masking, never remove it.
                val marked = message?.startsWith(SECRET_PROMPT_MARK) == true
                val secret = marked || message?.contains("passphrase", ignoreCase = true) == true
                val shown = if (marked) message!!.removePrefix(SECRET_PROMPT_MARK) else message
                val input = EditText(this@MainActivity).apply {
                    inputType = if (secret) {
                        InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
                    } else {
                        InputType.TYPE_CLASS_TEXT
                    }
                    setText(defaultValue ?: "")
                }
                AlertDialog.Builder(this@MainActivity)
                    .setMessage(shown)
                    .setView(input)
                    .setCancelable(false)
                    .setPositiveButton(android.R.string.ok) { _, _ -> result.confirm(input.text.toString()) }
                    .setNegativeButton(android.R.string.cancel) { _, _ -> result.cancel() }
                    .show()
                return true
            }
        }
    }

    /** Point the client at [relay], (re)inject the config script, and load. */
    private fun loadWithRelay(relay: RelayUrls) {
        relayScript?.remove()
        // Build the config as JSON so the origins are properly escaped rather than
        // hand-interpolated into a JS string literal. RelayUrls.parse already
        // whitelists the host charset (the primary fix), but escaping here means
        // this injection point stays safe even if a raw value ever reaches it.
        val config = JSONObject()
            .put("api", relay.httpOrigin)
            .put("ws", "${relay.wsOrigin}/ws")
        // Pentest 2026-07-29 H-1, second half: the client used to decide "is there
        // a native pad floor?" by feature-detecting `window.SecureChatPadFloor`,
        // an attacker-WRITABLE global. `delete window.SecureChatPadFloor` at
        // document-start therefore read as "plain browser" and disabled the F-1
        // floor with no error at all — a silent downgrade of the one control the
        // JS context is not supposed to be able to reach.
        //
        // The marker below says "this build HAS a native floor". It is defined
        // non-writable and non-configurable, so unlike the bridge global it
        // cannot be deleted or overwritten from JS: an attacker can still remove
        // the bridge, but they can no longer hide that it was supposed to be
        // there, and otp.js then fails CLOSED instead of quietly continuing.
        // Injected in the same document-start script as the relay config, so it
        // lands before any page script runs and is covered by the same
        // DOCUMENT_START_SCRIPT check and the same verify-after-load probe.
        val js = """
            window.__SECURE_CHAT_RELAY__ = $config;
            Object.defineProperty(window, '__SECURE_CHAT_NATIVE_FLOOR__', {
              value: true, writable: false, configurable: false, enumerable: false
            });
        """.trimIndent()
        // Checked in onCreate too; re-checked here because promptForRelay() also
        // reaches this path, and loading the client without the config is the
        // silent failure L-10 is about.
        if (!WebViewFeature.isFeatureSupported(WebViewFeature.DOCUMENT_START_SCRIPT)) {
            refuseToRun()
            return
        }
        relayScript = WebViewCompat.addDocumentStartJavaScript(
            binding.webview, js, setOf(appOrigin),
        )
        binding.webview.loadUrl(indexUrl)
    }

    /**
     * Verify the injected config actually reached the page (L-10). The feature
     * check above covers the known cause, but this catches any other reason the
     * script did not run — an origin-allow-list mismatch, a WebView that
     * advertises the feature and drops it — by asking the loaded page itself.
     * evaluateJavascript is a shell-level injection, so the page CSP does not
     * block it.
     */
    private fun verifyRelayConfig() {
        // Both halves of the document-start script must have landed, AND the pad
        // floor bridge must be callable from the page (2026-07-29 H-1). A build
        // that advertises a native floor it cannot actually reach is worse than
        // the browser build, because otp.js will fail closed on every pad.
        binding.webview.evaluateJavascript(
            "!!window.__SECURE_CHAT_RELAY__ && window.__SECURE_CHAT_NATIVE_FLOOR__ === true " +
                "&& typeof (window.SecureChatPadFloor||{}).read === 'function' " +
                "&& typeof (window.SecureChatPadFloor||{}).bump === 'function'",
        ) { result -> if (result != "true") refuseToRun() }
    }

    /**
     * Fail LOUDLY: blank the WebView so no half-configured client is left usable
     * behind the dialog, explain why, and close on acknowledgement.
     */
    private fun refuseToRun() {
        // verifyRelayConfig's callback is asynchronous, so the activity may be
        // gone by the time we get here; showing a dialog on a dead window throws.
        if (refusedToRun || isFinishing || isDestroyed) return
        refusedToRun = true
        binding.webview.loadUrl("about:blank")
        AlertDialog.Builder(this)
            .setTitle(R.string.webview_unsupported_title)
            .setMessage(R.string.webview_unsupported_msg)
            .setCancelable(false)
            .setPositiveButton(R.string.close) { _, _ -> finish() }
            .show()
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
