package org.securechat.app

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import android.webkit.JavascriptInterface
import java.security.KeyStore
import javax.crypto.KeyGenerator
import javax.crypto.Mac
import javax.crypto.SecretKey

/**
 * Monotonic, tamper-evident consumption floors for OTP pads — the fix for the
 * 2026-07-28 F-1 finding.
 *
 * WHY THIS EXISTS. The OTP rollback tripwire (`sc.otp.wm.v1.*`) lives in
 * localStorage, and every localStorage key is independently deletable by anyone
 * holding the JS context — a compromised page, WebView debugging, the CDP path.
 * For a v3 blob the floor is also mirrored INSIDE the pad's AEAD, so deleting the
 * record is caught. For a v2-shaped blob there is no such mirror, so the entire
 * defence collapsed to one deletable plaintext key: restore a v2 snapshot, delete
 * three keys, and the pad unlocks at offset 0 — a full two-time pad.
 *
 * No arrangement of localStorage keys can fix that: distinguishing "genuinely
 * old" from "restored old" needs state the attacker cannot edit, and there is
 * none inside localStorage. So the floor moves out here.
 *
 * WHAT THIS BUYS, precisely — the bar moves from "any localStorage write" to
 * "app-data file access, and even then you can only destroy, not rewind":
 *  * Unreachable from JS except through this interface, which has no lowering
 *    operation. [bump] takes a max; there is deliberately no setter, and — since
 *    2026-07-29 H-1 — no deletion either. Both halves of that sentence were
 *    false when it was first written: the bridge exposed an unauthenticated
 *    `clear(padId)` five lines below it. See the note at the end of the object.
 *  * Authenticated with an HMAC key generated in the AndroidKeyStore, which is
 *    non-exportable (hardware-backed where the device offers it). An attacker
 *    with file access CANNOT forge a lower value — the MAC will not verify.
 *  * Deletion is not silent — and this is now actually enforced, on the JS side,
 *    by a flag INSIDE the pad's own AEAD (`nativeFloor` in the v3 blob) saying a
 *    floor was in force when the pad was last written. A pad carrying that flag
 *    whose floor now reads ABSENT is refused. Before that flag existed the claim
 *    was wrong: deleting the record made [read] return [ABSENT], which the
 *    client treated as "plain browser, no floor", so the tripwire disappeared
 *    without a word. Deletion is destruction, and destruction must fail closed.
 *
 * WHAT IT DOES NOT BUY, stated plainly: this is not absolute. An attacker with
 * root can delete the prefs file (and, with the app uninstalled, the Keystore key
 * with it). They cannot rewind a floor, and they cannot delete one without the
 * JS side noticing — but they can destroy. Destruction fails closed, which is the
 * direction we want. `allowBackup=false` plus the L-6 dataExtractionRules already
 * close the backup and device-transfer routes, so this means on-device root.
 *
 * NOT a secret store. The values are consumption offsets, not key material;
 * confidentiality is irrelevant here, integrity is everything. That is why this
 * is an HMAC over plain SharedPreferences rather than EncryptedSharedPreferences
 * — it needs no extra dependency, and encrypting a counter would protect the
 * wrong property.
 */
object PadFloor {
    private const val FILE = "secure_chat_pad_floors"
    private const val KEY_ALIAS = "secure-chat/otp-pad-floor/hmac/v1"
    private const val KEYSTORE = "AndroidKeyStore"

    /** Absent — no floor recorded for this pad. Distinct from a floor of 0. */
    const val ABSENT = -1L

    /** Present but the MAC did not verify: forged or corrupted. Fails closed. */
    const val TAMPERED = -2L

    /**
     * ROUND-3 F-4. A bump whose `SharedPreferences.commit()` returned false —
     * the in-memory map moved, but the durable write did NOT land (unwritable
     * file, full disk). A BUMP-ONLY signal: [read] never returns this, because
     * `read` is backed by the same in-memory map that `commit()` already
     * mutated, so a read-back cannot tell a failed commit from a healthy one.
     * Only the discarded boolean from `commit()` carries that fact, and this is
     * how it now crosses to the JS side (which reacts by failing the save, so
     * `app.js` — persist-before-transmit, P-04 — never releases the keystream).
     */
    const val COMMIT_FAILED = -3L

    private fun prefs(ctx: Context) = ctx.getSharedPreferences(FILE, Context.MODE_PRIVATE)

    /**
     * The HMAC key, created on first use. Non-exportable: it never leaves the
     * Keystore, so the MAC cannot be recomputed off-device for a forged value.
     */
    private fun mackey(): SecretKey {
        val ks = KeyStore.getInstance(KEYSTORE).apply { load(null) }
        (ks.getEntry(KEY_ALIAS, null) as? KeyStore.SecretKeyEntry)?.let { return it.secretKey }
        val gen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_HMAC_SHA256, KEYSTORE)
        gen.init(
            KeyGenParameterSpec.Builder(KEY_ALIAS, KeyProperties.PURPOSE_SIGN)
                .setDigests(KeyProperties.DIGEST_SHA256)
                // Deliberately NOT setUserAuthenticationRequired: the floor must be
                // readable on every unlock, including before any biometric prompt,
                // or the tripwire becomes a usability cliff and gets disabled.
                .build(),
        )
        return gen.generateKey()
    }

    /**
     * MAC over padId AND value together, so a floor cannot be lifted from one pad
     * and replayed under another id — the P-01 lesson, applied here.
     */
    private fun tag(padId: String, value: Long): String {
        val mac = Mac.getInstance("HmacSHA256").apply { init(mackey()) }
        val msg = "secure-chat/otp-pad-floor/v1\u0000$padId\u0000$value"
        return Base64.encodeToString(mac.doFinal(msg.toByteArray()), Base64.NO_WRAP)
    }

    private fun constantTimeEquals(a: String, b: String): Boolean {
        if (a.length != b.length) return false
        var diff = 0
        for (i in a.indices) diff = diff or (a[i].code xor b[i].code)
        return diff == 0
    }

    fun read(ctx: Context, padId: String): Long {
        val raw = prefs(ctx).getString(padId, null) ?: return ABSENT
        val sep = raw.indexOf(':')
        if (sep <= 0) return TAMPERED
        val value = raw.substring(0, sep).toLongOrNull() ?: return TAMPERED
        if (value < 0) return TAMPERED
        return if (constantTimeEquals(raw.substring(sep + 1), tag(padId, value))) value else TAMPERED
    }

    /**
     * Raise the floor to [value] if it is higher. Never lowers. Returns the floor
     * in force afterwards, or [TAMPERED] if the stored one did not verify (in
     * which case nothing is written — a forged record must not be healed into a
     * valid one by the next legitimate save), or [COMMIT_FAILED] if the durable
     * write did not land (see below).
     */
    fun bump(ctx: Context, padId: String, value: Long): Long {
        if (value < 0) return read(ctx, padId)
        val current = read(ctx, padId)
        if (current == TAMPERED) return TAMPERED
        val next = if (current == ABSENT) value else maxOf(current, value)
        if (next == current) return current
        // ROUND-3 F-4. `commit()`'s boolean used to be DISCARDED here, and `next`
        // was returned unconditionally. `commit()` writes the in-memory map
        // synchronously and does NOT roll it back when the disk write fails, and
        // [read] is backed by that very map — so a frozen/unwritable prefs file
        // let a caller `bump` a floor, `read` it back HEALTHY in the same process,
        // and never learn that nothing reached disk. On the JS side that defeated
        // armFloors' read-back guard (the floor "moved"), the save reported
        // success, `app.js` transmitted (P-04), and after a restart the durable
        // floor was 0 — re-importing the pristine pad respent the same keystream:
        // a two-time pad, the one failure OTP cannot survive.
        //
        // The boolean is the ONLY place that failure is observable, so it is
        // surfaced now rather than swallowed. We do NOT throw across JNI (a
        // JavascriptInterface exception is delivered to JS opaquely); a distinct
        // sentinel the JS side inspects is the reliable channel. `read` is
        // untouched, so it still only yields ABSENT / TAMPERED / value ≥ 0.
        val committed = prefs(ctx).edit().putString(padId, "$next:${tag(padId, next)}").commit()
        return if (committed) next else COMMIT_FAILED
    }

    // Pentest 2026-07-29 H-1: there is deliberately NO clear/remove/reset here.
    //
    // A `clear(padId)` used to exist, commented "only for a pad the user
    // genuinely forgets AND re-exchanges", and PadFloorBridge exposed it
    // straight to JS with no authentication. That single method falsified both
    // halves of the contract above and voided the whole F-1 guarantee: snapshot
    // a pad blob and its watermark, call clear() once, and the pad reopens at
    // the rolled-back offset with no prompt and no error — full keystream
    // reuse. Nothing in client/ ever called it.
    //
    // The legitimate case it was written for does not need it. A pad the user
    // re-exchanges is a NEW pad with a new padId (the id is derived from the
    // pad material), so it has no floor to clear. If a genuine need for a
    // lowering operation ever appears, it must not be reachable from JS — the
    // JS context is precisely the attacker in this threat model.
}

/**
 * The JS-facing bridge. Deliberately tiny: one read and one monotone bump, both
 * integers, no secrets crossing. `addJavascriptInterface` has a bad history, so
 * the surface is kept to what the tripwire needs and nothing more. There is no
 * lowering operation and no deletion — see the note above; adding one here
 * reopens 2026-07-29 H-1.
 *
 * Reachable only from the WebViewAssetLoader origin (a non-resolving virtual
 * host serving APK assets), which is the same trust boundary the client's own
 * localStorage sits behind.
 */
class PadFloorBridge(private val ctx: Context) {
    // Fix review round 2 (H-1): these return LONG, not String.
    //
    // They used to hand back decimal strings, which meant the JS side had to
    // call `parseInt` to get a number — and `parseInt` is a writable global. An
    // attacker who could not touch the (now frozen) bridge could still assign
    // `globalThis.parseInt` and have every floor read as 0 or -1, which is the
    // whole control, defeated one property assignment downstream of the part
    // that was hardened. Returning a number removes the parse step, and with it
    // that surface. Long maps to a JS number; pad offsets are far below 2^53.
    @JavascriptInterface
    fun read(padId: String): Long = PadFloor.read(ctx, padId)

    @JavascriptInterface
    fun bump(padId: String, value: Long): Long = PadFloor.bump(ctx, padId, value)
}
