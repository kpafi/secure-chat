package org.securechat.app

import android.os.Looper
import android.widget.TextView
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import org.robolectric.Shadows.shadowOf
import org.robolectric.shadows.ShadowDialog

/**
 * Regression test for pentest 2026-07-26 L-10: on a WebView without
 * DOCUMENT_START_SCRIPT the shell cannot inject `window.__SECURE_CHAT_RELAY__`,
 * and it used to load the client anyway — every request then went to the app's
 * own unresolvable virtual origin and passphrase masking degraded to the
 * substring guess F-08 retired, both with no visible sign. The shell must now
 * refuse to load the client and say so.
 *
 * Robolectric's WebView provider advertises no androidx.webkit features, so
 * simply starting the activity exercises the unsupported path.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class UnsupportedWebViewTest {

    @Test
    fun refusesToLoadTheClientAndExplainsWhy() {
        val controller = Robolectric.buildActivity(MainActivity::class.java)
        val activity = controller.setup().get()
        shadowOf(Looper.getMainLooper()).idle()

        // ShadowDialog, not ShadowAlertDialog: this is an androidx AppCompat
        // dialog, which the framework shadow does not track. Assert on the
        // rendered message so a pass cannot come from the relay-address prompt
        // the activity would otherwise show on first run.
        val dialog = ShadowDialog.getLatestDialog()
        assertNotNull("expected a failure dialog, got none", dialog)
        assertTrue("the failure must be visible, not silent", dialog.isShowing)
        assertEquals(
            activity.getString(R.string.webview_unsupported_msg),
            dialog.findViewById<TextView>(android.R.id.message)?.text?.toString(),
        )

        // The client page must NOT have been loaded: a client without the relay
        // config cannot work, which is the whole point of the finding.
        val loaded = shadowOf(activity.findViewById<android.webkit.WebView>(R.id.webview)).lastLoadedUrl
        assertEquals("about:blank", loaded)
    }
}
