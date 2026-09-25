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
 * NAMESPACE (pentest 2026-08-07). The floor is a generic string-keyed monotone
 * counter — the MAC covers `id\u0000value` — so the client now keeps more than
 * one per pad, and floors for other stores, without any change here:
 *   <padId>            OTP send offset (F-1)
 *   recv:<padId>       OTP receive high-water mark (F-ATREST-001)
 *   exported:<padId>   OTP exported flag, 0/1 (F-ATREST-002)
 *   contacts:<idHash>  contact-store generation per identity (F-ATREST-003/004)
 *   chats:<idHash>     chat-store generation per identity (F-ATREST-005)
 * Pad ids are validated to 32 hex characters on the JS side, so a pad file
 * cannot address another namespace. See client/nativefloor.js.
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
     * Package 3 (ROUND-3 F-4): [bump]'s answer when `SharedPreferences.commit()`
     * returned false, i.e. the new value did NOT reach disk. Must match
     * NATIVE_COMMIT_FAILED in client/nativefloor.js.
     */
    const val COMMIT_FAILED = -3L

    /**
     * Package 3 (7b): [bump]'s answer for a value outside `0..MAX_VALUE`. Must
     * match NATIVE_INVALID in client/nativefloor.js.
     */
    const val INVALID = -4L

    /**
     * The highest value a floor may hold: the int32 range the JS side can
     * validate without a poisonable global (`(v | 0) === v`). Must match
     * FLOOR_MAX in client/nativefloor.js.
     */
    const val MAX_VALUE = 0x7fffffffL

    /**
     * Latched by the first failed `commit()` of this process. See [bump]: after a
     * failed commit the in-memory map is ahead of the file, so no later answer
     * from this object can be trusted to describe what a restart will see.
     */
    @Volatile
    private var commitFailed = false

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
     * valid one by the next legitimate save), [INVALID] for a value outside
     * `0..MAX_VALUE`, or [COMMIT_FAILED] if the new value did not reach disk.
     *
     * Package 3 (7b int32 ceiling). A negative [value] used to be answered with
     * the current floor, as if it were a harmless no-op. The JS side passed
     * `v | 0`, so a generation of 2^31 arrived here NEGATIVE and was silently
     * dropped: the floor froze at its last value while the store went on
     * counting, and every later rollback was undetectable. Now it is a refusal,
     * which the JS side turns into a failed save.
     *
     * Package 3 (ROUND-3 F-4). `commit()` returns false when the write did not
     * reach disk, and that boolean used to be DISCARDED — `next` came back as if
     * it had been stored. The JS side then sealed a blob claiming the floor, and
     * after a restart the floor was absent or behind: a pad refused as
     * "deleted", a contact store locked with no override. The answer is now
     * [COMMIT_FAILED]. It is also LATCHED for the rest of the process:
     * SharedPreferences applies an edit to its in-memory map before writing the
     * file and does not undo that on failure, so after one failed commit [read]
     * reports values a restart will not see. A second bump of the same value
     * would find `next == current` and return success without writing anything
     * — the exact false claim this fixes. Until the app restarts, every bump
     * fails and every save that depends on one fails loudly.
     */
    fun bump(ctx: Context, padId: String, value: Long): Long {
        if (value < 0 || value > MAX_VALUE) return INVALID
        if (commitFailed) return COMMIT_FAILED
        val current = read(ctx, padId)
        if (current == TAMPERED) return TAMPERED
        val next = if (current == ABSENT) value else maxOf(current, value)
        if (next == current) return current
        val committed = prefs(ctx).edit().putString(padId, "$next:${tag(padId, next)}").commit()
        if (!committed) {
            commitFailed = true
            return COMMIT_FAILED
        }
        return next
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
