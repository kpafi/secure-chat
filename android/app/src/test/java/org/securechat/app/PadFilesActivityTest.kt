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
import org.junit.Assert.assertNotEquals
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

    private lateinit var controller: org.robolectric.android.controller.ActivityController<MainActivity>
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
        controller = Robolectric.buildActivity(MainActivity::class.java).setup()
        activity = controller.get()
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
        // …and neither may the next chooser's "cancel the pending one" step:
        // an answered callback must no longer count as pending (mutant J5).
        chooser(Recorder())
        assertEquals("an answered callback is never answered again", 1, cb.answers.size)
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

    // Pentest r1 F4: only another app's content:// document reaches the page.
    @Test
    fun pickerResultsThatAreNotAnotherAppsDocumentAreDropped() {
        for (bad in listOf(
            Uri.parse("file:///data/data/org.securechat.app/app_webview/Default/Local%20Storage/leveldb/000003.log"),
            Uri.parse("content://${activity.packageName}.files/pad-share/0123456789abcdef/$name"),
            Uri.parse("http://example.com/pad.json"),
            // Another provider of OURS (merged in from androidx.startup): refused by
            // package, not only by the FileProvider's authority.
            Uri.parse("content://${activity.packageName}.androidx-startup/x"),
            // Pentest r2 R2-5: user-qualified forms of our own providers.
            Uri.parse("content://0@${activity.packageName}.files/pad-share/0123456789abcdef/$name"),
            Uri.parse("content://0@${activity.packageName}.androidx-startup/x"),
        )) {
            val cb = Recorder()
            chooser(cb)
            result(nextStarted(), Activity.RESULT_OK, Intent().setData(bad))
            assertEquals("must not reach the page: $bad", listOf<List<Uri>?>(null), cb.answers)
        }
    }

    // --- Export: Share --------------------------------------------------------

    private fun shareDir() = File(activity.cacheDir, MainActivity.SHARE_DIR)

    /** Every file under pad-share, as a path relative to it. */
    private fun shared(): List<String> =
        shareDir().walk().filter { it.isFile }.map { it.relativeTo(shareDir()).path }.sorted().toList()

    /** What the system chooser sends through our IntentSender on a pick. */
    private fun chosenIntent(id: String) =
        Intent("${activity.packageName}.action.PAD_SHARE_CHOSEN").setPackage(activity.packageName)
            .setData(Uri.fromParts(MainActivity.SHARE_SCHEME, id, null))

    private fun chosen(id: String, from: MainActivity = activity) {
        from.sendBroadcast(chosenIntent(id))
        idle()
    }

    private fun sendOf(chooser: Intent) = chooser.getParcelableExtra(Intent.EXTRA_INTENT, Intent::class.java)!!
    private fun streamOf(chooser: Intent) = sendOf(chooser).getParcelableExtra(Intent.EXTRA_STREAM, Uri::class.java)!!

    /** Share, pick a target, return: a completed "shared". Returns the chooser intent. */
    private fun shareAndPick(t: String = text): Pair<String, Intent> {
        val id = bridge.share(name, t)
        idle()
        val chooser = nextStarted()
        chosen(id)
        result(chooser, Activity.RESULT_CANCELED, null)
        assertEquals(PadFilesBridge.resultScript(id, PadFileOutcome.SHARED), lastScript())
        return id to chooser
    }

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
        assertEquals("the URI is unique to the request (F1), the target sees the neutral name",
            "/pad-share/$id/$name", uri.path)
        assertEquals(listOf("$id/$name"), shared())
        assertEquals(text, File(shareDir(), "$id/$name").readText())
        assertEquals(PadFilesBridge.BUSY, bridge.save(name, text))
        assertEquals(id, bridge.pending())
    }

    @Test
    fun shareWithoutAChosenTargetIsCancelledAfterTheGraceAndTheFileLivesOutItsTtl() {
        val id = bridge.share(name, text)
        idle()
        val chooser = nextStarted()
        result(chooser, Activity.RESULT_CANCELED, null)
        assertEquals("not answered before the grace period", id, bridge.pending())
        shadowOf(Looper.getMainLooper()).idleFor(Duration.ofMillis(MainActivity.SHARE_GRACE_MS))
        assertEquals(PadFilesBridge.resultScript(id, PadFileOutcome.CANCELLED), lastScript())
        assertNull(bridge.pending())
        // Fix round 2 (cold critic mi-4): "cancelled" may be wrong — the pick
        // broadcast can arrive late — so the file is NOT deleted (nor revoked)
        // now; it lives out SHARE_TTL_MS like a shared one.
        assertEquals(listOf("$id/$name"), shared())
        File(shareDir(), id).setLastModified(System.currentTimeMillis() - MainActivity.SHARE_TTL_MS)
        shadowOf(Looper.getMainLooper()).idleFor(Duration.ofMillis(MainActivity.SHARE_TTL_MS + 1000))
        assertTrue("…and then it goes", shareDir().listFiles().isNullOrEmpty())
    }

    @Test
    fun aPickReportedAfterCancelledIsNotACorrectionAndTheFileSurvives() {
        val id = bridge.share(name, text)
        idle()
        result(nextStarted(), Activity.RESULT_CANCELED, null)
        shadowOf(Looper.getMainLooper()).idleFor(Duration.ofMillis(MainActivity.SHARE_GRACE_MS))
        assertEquals(PadFilesBridge.resultScript(id, PadFileOutcome.CANCELLED), lastScript())
        chosen(id)                                             // Android held the broadcast back
        assertEquals("answered once: no second script", PadFilesBridge.resultScript(id, PadFileOutcome.CANCELLED), lastScript())
        assertEquals("the target that was picked can still read the file", listOf("$id/$name"), shared())
    }

    @Test
    fun shareWithAChosenTargetIsSharedAndTheFileStaysForTheTarget() {
        val id = bridge.share(name, text)
        idle()
        val chooser = nextStarted()
        // What the system chooser does with our IntentSender on a pick.
        chosen(id)
        assertEquals("not before the chooser has returned", id, bridge.pending())
        result(chooser, Activity.RESULT_CANCELED, null)      // what a chooser really returns
        assertEquals(PadFilesBridge.resultScript(id, PadFileOutcome.SHARED), lastScript())
        assertNull(bridge.pending())
        assertEquals(listOf("$id/$name"), shared())
    }

    @Test
    fun aLateChosenBroadcastWithinTheGraceStillCountsAsShared() {
        val id = bridge.share(name, text)
        idle()
        result(nextStarted(), Activity.RESULT_CANCELED, null)
        chosen(id)
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
        chosen("0123456789abcdef")
        // …and the r1 form (the id as an extra, no data) is not ours any more.
        activity.sendBroadcast(Intent("${activity.packageName}.action.PAD_SHARE_CHOSEN").setPackage(activity.packageName)
            .putExtra("org.securechat.app.extra.PAD_FILE_REQUEST", id))
        idle()
        result(chooser, Activity.RESULT_CANCELED, null)
        shadowOf(Looper.getMainLooper()).idleFor(Duration.ofMillis(MainActivity.SHARE_GRACE_MS))
        assertEquals(PadFilesBridge.resultScript(id, PadFileOutcome.CANCELLED), lastScript())
    }

    // Pentest r1 F1: two shares with the same (minute-resolution) name used to
    // hand out the SAME URI, so a grant still held on the first read the second.
    // Fix round 2 (cold mi-4, pentest R2-7a): and the second share no longer
    // deletes the first — "Send it again" must not cut off a send in progress.
    @Test
    fun aSecondShareGetsItsOwnUriAndLeavesTheFirstForItsTarget() {
        val (idA, chA) = shareAndPick()
        val uriA = streamOf(chA)
        val textB = text.replace("q83vASNFZ4mrze8BI0VniQ+/", "BBBBBBBBBBBBBBBBBBBBBBBB")
        val idB = bridge.share(name, textB)
        idle()
        val uriB = streamOf(nextStarted())
        assertNotEquals("a new URI per request", uriA, uriB)
        assertEquals(name, uriB.lastPathSegment)
        assertEquals("both files, each under its own request", listOf("$idA/$name", "$idB/$name").sorted(), shared())
        assertEquals(text, File(shareDir(), "$idA/$name").readText())
        assertEquals("the first URI still names the first file", "/pad-share/$idA/$name", uriA.path)
    }

    // Pentest r2 R2-7a: a share in a SECOND instance deleted the first
    // instance's share before its user had even picked a target.
    @Test
    fun aShareInASecondInstanceLeavesTheFirstInstancesShare() {
        val idA = bridge.share(name, text)
        idle()
        nextStarted()                                          // A's chooser is open
        val other = Robolectric.buildActivity(MainActivity::class.java).setup().get()
        idle()
        val idB = (shadowOf(other.findViewById<WebView>(R.id.webview))
            .getJavascriptInterface("SecureChatFiles") as PadFilesBridge).share(name, text)
        idle()
        assertEquals(listOf("$idA/$name", "$idB/$name").sorted(), shared())
    }

    // Pentest r2 R2-7b: a restart within SHARE_TTL_MS kept the file with no
    // timer at all; the start now arms one for it.
    @Test
    fun aStartArmsTheTimerForAYoungShare() {
        val young = File(shareDir(), "0123456789abcdef").apply { mkdirs() }
        File(young, name).writeText(text)
        young.setLastModified(System.currentTimeMillis() - MainActivity.SHARE_TTL_MS + 60_000)
        Robolectric.buildActivity(MainActivity::class.java).setup()
        idle()
        assertEquals("not yet due", listOf("0123456789abcdef/$name"), shared())
        young.setLastModified(System.currentTimeMillis() - MainActivity.SHARE_TTL_MS - 1000)  // a minute later
        shadowOf(Looper.getMainLooper()).idleFor(Duration.ofMillis(61_000 + 1000))
        assertTrue("the start's timer removed it", shared().isEmpty())
    }

    // Pentest r1 F2: a second instance of the activity, or a recreation, used
    // to empty pad-share and so delete a file a lazy target had yet to read.
    @Test
    fun aNewInstanceKeepsARecentShareAndPurgesAnExpiredOne() {
        val (id, _) = shareAndPick()
        val old = File(shareDir(), "0123456789abcdef").apply { mkdirs() }
        File(old, name).writeText(text)
        old.setLastModified(System.currentTimeMillis() - MainActivity.SHARE_TTL_MS - 1000)
        Robolectric.buildActivity(MainActivity::class.java).setup()
        idle()
        assertEquals("the recent share survives, the expired one does not", listOf("$id/$name"), shared())
    }

    @Test
    fun aSharedFileIsPurgedAfterItsLifetime() {
        val (id, _) = shareAndPick()
        assertEquals(listOf("$id/$name"), shared())
        File(shareDir(), id).setLastModified(System.currentTimeMillis() - MainActivity.SHARE_TTL_MS)
        shadowOf(Looper.getMainLooper()).idleFor(Duration.ofMillis(MainActivity.SHARE_TTL_MS + 1000))
        assertTrue("no pad file lies around past SHARE_TTL_MS", shared().isEmpty())
    }

    // Pentest r1 F2 (second half) and F5: each share has its OWN chosen-target
    // PendingIntent (a shared one had its request id rewritten by the next
    // share in another instance), and it is immutable.
    @Test
    fun eachShareHasItsOwnImmutableChosenCallback() {
        val idA = bridge.share(name, text)
        idle()
        nextStarted()
        val other = Robolectric.buildActivity(MainActivity::class.java).setup().get()
        idle()
        val otherBridge = shadowOf(other.findViewById<WebView>(R.id.webview))
            .getJavascriptInterface("SecureChatFiles") as PadFilesBridge
        val idB = otherBridge.share(name, text)
        idle()
        val pis = listOf(idA, idB).map { lookUp(it) }
        assertTrue("one PendingIntent per share, found by its own id", pis.all { it != null })
        assertEquals(setOf(idA, idB), pis.map { shadowOf(it!!).savedIntent.data!!.schemeSpecificPart }.toSet())
        assertNotEquals(pis[0], pis[1])
        for (pi in pis) {
            assertTrue("immutable (F5)", shadowOf(pi!!).isImmutable)
            assertTrue("one shot", shadowOf(pi).flags and android.app.PendingIntent.FLAG_ONE_SHOT != 0)
        }
    }

    private fun lookUp(id: String): android.app.PendingIntent? = android.app.PendingIntent.getBroadcast(
        activity, 0, chosenIntent(id),
        android.app.PendingIntent.FLAG_NO_CREATE or android.app.PendingIntent.FLAG_IMMUTABLE or
            android.app.PendingIntent.FLAG_ONE_SHOT,
    )

    // Pentest r2 R2-6: a PendingIntent that survived from an earlier process
    // (its chooser was open when the process died) must never be the one a new
    // share gets. With the id as data, a new share's PendingIntent is its own.
    @Test
    fun aSurvivingPendingIntentFromAnEarlierProcessIsNeverReused() {
        val stale = "ffffffffffffffff"
        for (rc in 0..3) {  // what an earlier process left: the r1 form (requestCode n, id as an extra)
            android.app.PendingIntent.getBroadcast(activity, rc,
                Intent("${activity.packageName}.action.PAD_SHARE_CHOSEN").setPackage(activity.packageName)
                    .putExtra("org.securechat.app.extra.PAD_FILE_REQUEST", stale),
                android.app.PendingIntent.FLAG_ONE_SHOT or android.app.PendingIntent.FLAG_IMMUTABLE)
        }
        val id = bridge.share(name, text)
        idle()
        val chooser = nextStarted()
        val mine = lookUp(id)
        assertNotNull(mine)
        assertEquals(id, shadowOf(mine!!).savedIntent.data!!.schemeSpecificPart)
        chosen(stale)                                          // the stale one fires
        result(chooser, Activity.RESULT_CANCELED, null)
        shadowOf(Looper.getMainLooper()).idleFor(Duration.ofMillis(MainActivity.SHARE_GRACE_MS))
        assertEquals("a stale pick is not ours", PadFilesBridge.resultScript(id, PadFileOutcome.CANCELLED), lastScript())
    }

    // Cold critic mi-5: a configuration change while Share / Save is open used
    // to recreate the activity and reload the page (the pad latched as
    // exported, the file gone). These are all taken in place now.
    @Test
    fun aConfigurationChangeKeepsTheActivityAndTheShareInFlight() {
        val id = bridge.share(name, text)
        idle()
        val chooser = nextStarted()
        val c = android.content.res.Configuration(activity.resources.configuration)
        c.uiMode = android.content.res.Configuration.UI_MODE_NIGHT_YES or android.content.res.Configuration.UI_MODE_TYPE_NORMAL
        c.setLocale(java.util.Locale.GERMANY)
        c.fontScale = 1.3f
        c.densityDpi = c.densityDpi + 40
        c.smallestScreenWidthDp = c.smallestScreenWidthDp + 100
        c.screenLayout = c.screenLayout xor android.content.res.Configuration.SCREENLAYOUT_SIZE_MASK
        c.navigation = android.content.res.Configuration.NAVIGATION_TRACKBALL
        c.keyboard = android.content.res.Configuration.KEYBOARD_QWERTY
        c.mcc = c.mcc + 1
        controller.configurationChange(c)
        idle()
        assertTrue("the same activity, not a recreated one", controller.get() === activity)
        assertEquals(id, bridge.pending())
        chosen(id)
        result(chooser, Activity.RESULT_CANCELED, null)
        assertEquals(PadFilesBridge.resultScript(id, PadFileOutcome.SHARED), lastScript())
    }

    // Pentest r1 MH: a request that reaches a finishing activity is released,
    // not started.
    @Test
    fun aRequestReachingAFinishingActivityStartsNothingAndFreesTheSlot() {
        activity.finish()
        assertEquals(16, bridge.share(name, text).length)
        idle()
        assertNull(shadowOf(activity).nextStartedActivityForResult)
        assertNull("the slot is free again", bridge.pending())
        assertTrue(shared().isEmpty())
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

    // Pentest r1 F4: the save result is written only if it is another app's document.
    @Test
    fun aSaveResultThatIsNotAnotherAppsDocumentIsNotWritten() {
        val victim = File(activity.filesDir, "victim.txt").apply { writeText("PRECIOUS") }
        for (bad in listOf(Uri.fromFile(victim), Uri.parse("content://${activity.packageName}.files/pad-share/x/$name"))) {
            val id = bridge.save(name, text)
            idle()
            result(nextStarted(), Activity.RESULT_OK, Intent().setData(bad))
            assertEquals(PadFilesBridge.resultScript(id, PadFileOutcome.ERROR), awaitScript())
        }
        assertEquals("PRECIOUS", victim.readText())
    }

    // Pentest r1 F3 / r2 A5, behaviourally: Save opens the document "wt", so an
    // existing, LONGER file the user chose to overwrite is truncated — no tail
    // of the old content after the envelope.
    @Test
    fun saveOverALongerFileTruncatesIt() {
        val old = File(activity.filesDir, "existing.json").apply { writeText("X".repeat(5000)) }
        ModeRecordingProvider.modes.clear()
        ModeRecordingProvider.file = old
        Robolectric.buildContentProvider(ModeRecordingProvider::class.java).create(
            android.content.pm.ProviderInfo().apply {
                authority = "com.example.documents"; packageName = "com.example.documents"
                name = ModeRecordingProvider::class.java.name; exported = true
            },
        )
        val id = bridge.save(name, text)
        idle()
        result(nextStarted(), Activity.RESULT_OK, Intent().setData(Uri.parse("content://com.example.documents/document/1")))
        assertEquals(PadFilesBridge.resultScript(id, PadFileOutcome.SAVED), awaitScript())
        assertEquals(listOf("wt"), ModeRecordingProvider.modes)
        assertEquals("exactly the envelope, nothing of the old file after it", text, old.readText())
    }
}

/**
 * A documents provider that records the MODE each file is opened with and
 * serves one real file (pentest r2 A5: "wt" had only a source-text pin).
 * Registered under a foreign package, as DocumentsUI's providers are.
 */
class ModeRecordingProvider : android.content.ContentProvider() {
    companion object {
        val modes = mutableListOf<String>()
        lateinit var file: File
    }
    override fun openFile(uri: Uri, mode: String): android.os.ParcelFileDescriptor {
        modes += mode
        return android.os.ParcelFileDescriptor.open(file, android.os.ParcelFileDescriptor.parseMode(mode))
    }
    override fun onCreate() = true
    override fun query(u: Uri, p: Array<String>?, s: String?, a: Array<String>?, o: String?): android.database.Cursor? = null
    override fun getType(u: Uri): String = "application/json"
    override fun insert(u: Uri, v: android.content.ContentValues?): Uri? = null
    override fun delete(u: Uri, s: String?, a: Array<String>?) = 0
    override fun update(u: Uri, v: android.content.ContentValues?, s: String?, a: Array<String>?) = 0
}
