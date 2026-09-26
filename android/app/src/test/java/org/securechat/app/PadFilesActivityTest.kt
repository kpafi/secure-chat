package org.securechat.app

import android.app.Activity
import android.content.Intent
import android.net.Uri
import android.os.Looper
import android.webkit.ValueCallback
import android.webkit.WebChromeClient
import android.webkit.WebView
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config
import java.io.ByteArrayOutputStream
import java.io.File
import java.time.Duration

/**
 * The Android half of the OTP transfer sheets, driven through the real
 * MainActivity: Import's file chooser (brief 6/9) and Export's Share / Save
 * (brief 5/9). Robolectric's WebView has no DOCUMENT_START_SCRIPT, so the page
 * itself never loads here (UnsupportedWebViewTest) — but the WebChromeClient
 * and the bridge are installed before that check, which is what is exercised.
 * The script the shell evaluates is observed via ShadowWebView.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class PadFilesActivityTest {

    private val name = "secure-chat-pad-2026-09-26-1432.json"
    private val text =
        """{"fmt":"secure-chat-otp-pad","v":1,"kdf":{"salt":"AAECAwQFBgcICQoLDA0ODw==","iters":600000},""" +
            """"iv":"AAECAwQFBgcICQoL","ct":"q83vASNFZ4mrze8BI0VniQ+/"}"""

    private lateinit var activity: MainActivity
    private lateinit var webview: WebView
    private lateinit var bridge: PadFilesBridge

    @Before
    fun start() {
        // Test artefact only: FileProvider caches each authority's roots in a
        // static map, and Robolectric gives every test a new cacheDir in the
        // same class loader — the second test would find the first one's root.
        // On a device cacheDir does not move.
        (androidx.core.content.FileProvider::class.java.getDeclaredField("sCache")
            .apply { isAccessible = true }.get(null) as HashMap<*, *>).clear()
        activity = Robolectric.buildActivity(MainActivity::class.java).setup().get()
        idle()
        webview = activity.findViewById(R.id.webview)
        bridge = shadowOf(webview).getJavascriptInterface("SecureChatFiles") as PadFilesBridge
    }

    private fun idle() = shadowOf(Looper.getMainLooper()).idle()

    private fun lastScript(): String? = shadowOf(webview).lastEvaluatedJavascript

    private fun params(mode: Int = WebChromeClient.FileChooserParams.MODE_OPEN) =
        object : WebChromeClient.FileChooserParams() {
            override fun getMode() = mode
            override fun getAcceptTypes() = arrayOf("application/json", ".json", ".txt")
            override fun isCaptureEnabled() = false
            override fun getTitle(): CharSequence? = null
            override fun getFilenameHint(): String? = null
            override fun createIntent(): Intent = Intent()
        }

    /** A ValueCallback that records every answer it gets. */
    private class Recorder : ValueCallback<Array<Uri>> {
        val answers = mutableListOf<List<Uri>?>()
        override fun onReceiveValue(value: Array<Uri>?) { answers += value?.toList() }
    }

    private fun chooser(cb: Recorder, mode: Int = WebChromeClient.FileChooserParams.MODE_OPEN): Boolean =
        shadowOf(webview).webChromeClient.onShowFileChooser(webview, cb, params(mode))

    private fun nextStarted(): Intent {
        val started = shadowOf(activity).nextStartedActivityForResult
        assertNotNull("expected an activity to be started for a result", started)
        return started.intent
    }

    private fun result(started: Intent, code: Int, data: Intent?) {
        shadowOf(activity).receiveResult(started, code, data)
        idle()
    }

    // --- Import: onShowFileChooser --------------------------------------------

    @Test
    fun fileChooserOpensTheDocumentPickerForAnyTypeAndHandsBackOnlyThePick() {
        val cb = Recorder()
        assertTrue("the chooser is handled (not the WebView's silent default)", chooser(cb))
        val started = nextStarted()
        assertEquals(Intent.ACTION_OPEN_DOCUMENT, started.action)
        assertTrue(started.hasCategory(Intent.CATEGORY_OPENABLE))
        assertEquals("*/*", started.type)            // Quick Share delivers octet-stream
        assertFalse(started.getBooleanExtra(Intent.EXTRA_ALLOW_MULTIPLE, false))
        assertTrue("local roots only (N-M1)", started.getBooleanExtra(Intent.EXTRA_LOCAL_ONLY, false))
        assertTrue("nothing answered before the pick", cb.answers.isEmpty())

        val picked = Uri.parse("content://com.android.providers.downloads.documents/document/42")
        result(started, Activity.RESULT_OK, Intent().setData(picked))
        assertEquals(listOf<List<Uri>?>(listOf(picked)), cb.answers)
    }

    @Test
    fun cancelledPickerAnswersNullExactlyOnce() {
        val cb = Recorder()
        chooser(cb)
        val started = nextStarted()
        result(started, Activity.RESULT_CANCELED, null)
        assertEquals(listOf<List<Uri>?>(null), cb.answers)
        // A stray second result must not answer the callback again.
        result(started, Activity.RESULT_OK, Intent().setData(Uri.parse("content://x/y")))
        assertEquals(1, cb.answers.size)
    }

    @Test
    fun aSecondChooserCancelsTheFirstCallback() {
        val first = Recorder()
        val second = Recorder()
        chooser(first)
        nextStarted()
        chooser(second)
        assertEquals("the old callback is answered (null) at once", listOf<List<Uri>?>(null), first.answers)
        val started = nextStarted()
        val picked = Uri.parse("content://p/doc/1")
        result(started, Activity.RESULT_OK, Intent().setData(picked))
        assertEquals(listOf<List<Uri>?>(listOf(picked)), second.answers)
        assertEquals("…and never again", 1, first.answers.size)
    }

    @Test
    fun onlyOpenModeIsServed() {
        val cb = Recorder()
        assertTrue(chooser(cb, WebChromeClient.FileChooserParams.MODE_SAVE))
        assertEquals(listOf<List<Uri>?>(null), cb.answers)
        assertNull(shadowOf(activity).nextStartedActivityForResult)
    }

    // --- Export: Share --------------------------------------------------------

    private fun shareDir() = File(activity.cacheDir, MainActivity.SHARE_DIR)

    @Test
    fun shareHandsOneFileProviderUriToTheChooserWithAReadGrantOnly() {
        val id = bridge.share(name, text)
        idle()
        val chooser = nextStarted()
        assertEquals(Intent.ACTION_CHOOSER, chooser.action)
        val send = chooser.getParcelableExtra(Intent.EXTRA_INTENT, Intent::class.java)!!
        assertEquals(Intent.ACTION_SEND, send.action)
        assertEquals("application/json", send.type)
        val uri = send.getParcelableExtra(Intent.EXTRA_STREAM, Uri::class.java)!!
        assertEquals("content", uri.scheme)
        assertEquals("${activity.packageName}.files", uri.authority)
        assertEquals(uri, send.clipData!!.getItemAt(0).uri)
        assertTrue(send.flags and Intent.FLAG_GRANT_READ_URI_PERMISSION != 0)
        assertEquals("no write grant", 0, send.flags and Intent.FLAG_GRANT_WRITE_URI_PERMISSION)
        assertEquals(setOf(Intent.EXTRA_STREAM), send.extras!!.keySet())
        val files = shareDir().listFiles()!!.toList()
        assertEquals(listOf(name), files.map { it.name })
        assertEquals(text, files[0].readText())
        assertEquals(PadFilesBridge.BUSY, bridge.save(name, text))
        assertEquals(id, bridge.pending())
    }

    @Test
    fun shareWithoutAChosenTargetIsCancelledAfterTheGraceAndTheFileIsGone() {
        val id = bridge.share(name, text)
        idle()
        val chooser = nextStarted()
        result(chooser, Activity.RESULT_CANCELED, null)
        assertEquals("not answered before the grace period", id, bridge.pending())
        shadowOf(Looper.getMainLooper()).idleFor(Duration.ofMillis(MainActivity.SHARE_GRACE_MS))
        assertEquals(PadFilesBridge.resultScript(id, PadFileOutcome.CANCELLED), lastScript())
        assertNull(bridge.pending())
        assertTrue("nobody holds a grant: the file is deleted", shareDir().listFiles().isNullOrEmpty())
    }

    @Test
    fun shareWithAChosenTargetIsSharedAndTheFileStaysForTheTarget() {
        val id = bridge.share(name, text)
        idle()
        val chooser = nextStarted()
        // What the system chooser does with our IntentSender on a pick.
        activity.sendBroadcast(
            Intent("${activity.packageName}.action.PAD_SHARE_CHOSEN").setPackage(activity.packageName)
                .putExtra("org.securechat.app.extra.PAD_FILE_REQUEST", id),
        )
        idle()
        assertEquals("not before the chooser has returned", id, bridge.pending())
        result(chooser, Activity.RESULT_CANCELED, null)      // what a chooser really returns
        assertEquals(PadFilesBridge.resultScript(id, PadFileOutcome.SHARED), lastScript())
        assertNull(bridge.pending())
        assertEquals(listOf(name), shareDir().listFiles()!!.map { it.name })
    }

    @Test
    fun aLateChosenBroadcastWithinTheGraceStillCountsAsShared() {
        val id = bridge.share(name, text)
        idle()
        result(nextStarted(), Activity.RESULT_CANCELED, null)
        activity.sendBroadcast(
            Intent("${activity.packageName}.action.PAD_SHARE_CHOSEN").setPackage(activity.packageName)
                .putExtra("org.securechat.app.extra.PAD_FILE_REQUEST", id),
        )
        idle()
        assertEquals(PadFilesBridge.resultScript(id, PadFileOutcome.SHARED), lastScript())
        shadowOf(Looper.getMainLooper()).idleFor(Duration.ofMillis(MainActivity.SHARE_GRACE_MS))
        assertEquals("the grace timer does not answer a second time",
            PadFilesBridge.resultScript(id, PadFileOutcome.SHARED), lastScript())
    }

    @Test
    fun aChosenBroadcastForAnotherRequestIsIgnored() {
        val id = bridge.share(name, text)
        idle()
        val chooser = nextStarted()
        activity.sendBroadcast(
            Intent("${activity.packageName}.action.PAD_SHARE_CHOSEN").setPackage(activity.packageName)
                .putExtra("org.securechat.app.extra.PAD_FILE_REQUEST", "0123456789abcdef"),
        )
        idle()
        result(chooser, Activity.RESULT_CANCELED, null)
        shadowOf(Looper.getMainLooper()).idleFor(Duration.ofMillis(MainActivity.SHARE_GRACE_MS))
        assertEquals(PadFilesBridge.resultScript(id, PadFileOutcome.CANCELLED), lastScript())
    }

    @Test
    fun aNewShareClearsTheOldFileAndAStartClearsTheDirectory() {
        val stale = File(shareDir().apply { mkdirs() }, "secure-chat-pad-2020-01-01-0000.json")
        stale.writeText("old")
        val id = bridge.share(name, text)
        idle()
        assertEquals(listOf(name), shareDir().listFiles()!!.map { it.name })
        bridge.finish(id)
        // A fresh start empties it before anything else runs.
        File(shareDir(), "secure-chat-pad-2020-01-01-0000.json").writeText("old")
        Robolectric.buildActivity(MainActivity::class.java).setup()
        idle()
        assertTrue(shareDir().listFiles().isNullOrEmpty())
    }

    // --- Export: Save ---------------------------------------------------------

    private fun awaitScript(): String? {
        val until = System.nanoTime() + 5_000_000_000L
        while (System.nanoTime() < until) {
            idle()
            if (bridge.pending() == null) return lastScript()
            Thread.sleep(10)
        }
        return null
    }

    @Test
    fun saveCreatesAJsonDocumentWithTheSuggestedNameAndWritesTheText() {
        val id = bridge.save(name, text)
        idle()
        val started = nextStarted()
        assertEquals(Intent.ACTION_CREATE_DOCUMENT, started.action)
        assertEquals("application/json", started.type)
        assertEquals(name, started.getStringExtra(Intent.EXTRA_TITLE))
        assertTrue("no cloud roots (N-M1)", started.getBooleanExtra(Intent.EXTRA_LOCAL_ONLY, false))
        assertTrue(started.hasCategory(Intent.CATEGORY_OPENABLE))

        val doc = Uri.parse("content://com.android.externalstorage.documents/document/primary%3ADownload%2F$name")
        val out = ByteArrayOutputStream()
        shadowOf(activity.contentResolver).registerOutputStream(doc, out)
        result(started, Activity.RESULT_OK, Intent().setData(doc))
        assertEquals(PadFilesBridge.resultScript(id, PadFileOutcome.SAVED), awaitScript())
        assertEquals(text, out.toString(Charsets.UTF_8.name()))
    }

    @Test
    fun cancelledSaveIsCancelled() {
        val id = bridge.save(name, text)
        idle()
        result(nextStarted(), Activity.RESULT_CANCELED, null)
        assertEquals(PadFilesBridge.resultScript(id, PadFileOutcome.CANCELLED), lastScript())
        assertNull(bridge.pending())
    }

    @Test
    fun aFailedWriteIsAnError() {
        val id = bridge.save(name, text)
        idle()
        val doc = Uri.parse("content://p/doc/broken")
        shadowOf(activity.contentResolver).registerOutputStreamSupplier(doc) {
            object : java.io.OutputStream() {
                override fun write(b: Int) = throw java.io.IOException("disk full")
                override fun write(b: ByteArray, off: Int, len: Int) = throw java.io.IOException("disk full")
            }
        }
        result(nextStarted(), Activity.RESULT_OK, Intent().setData(doc))
        assertEquals(PadFilesBridge.resultScript(id, PadFileOutcome.ERROR), awaitScript())
    }

    @Test
    fun invalidRequestsStartNothing() {
        assertEquals(PadFilesBridge.INVALID, bridge.share("../../shared_prefs/x.xml", text))
        assertEquals(PadFilesBridge.INVALID, bridge.save(name, "<html>"))
        idle()
        assertNull(shadowOf(activity).nextStartedActivityForResult)
        assertTrue(shareDir().listFiles().isNullOrEmpty())
    }
}
