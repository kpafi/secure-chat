// One-time-pad lifecycle for secure-chat's OTP mode.
//
// This module owns everything AROUND the pad — generation, the encrypted
// export/import file that two people carry between their devices in person, and
// on-device persistence of the pad bytes + consumption offsets. The actual
// encrypt/decrypt (the XOR + one-time HMAC) lives in crypto.js (OtpPad); the two
// are kept apart so crypto.js stays storage-agnostic and easy to audit.
//
// SECURITY NOTES.
//  * A pad is a shared secret for EXACTLY TWO devices. Never import the same pad
//    file on more than one device on each side: two devices sharing a role would
//    draw the same pad bytes and destroy the one-time guarantee.
//  * A pad is generated once (role 0 = the device that generates + exports) and
//    imported once (role 1). Roles decide which half of the pad each side sends
//    from, so no byte is ever used to encrypt twice.
//  * Export is only allowed on a PRISTINE pad (nothing sent/received yet).
//    Exporting a partly-used pad would hand the peer zeroed regions, which XOR
//    back to plaintext — so we refuse it.
//  * The export file is encrypted with a passphrase the two people agree on in
//    person, so it is safe to move over Bluetooth / USB / cloud / QR: an
//    interceptor of the transfer cannot read the pad without that passphrase.

// ---- small byte/encoding helpers (kept local so this module stands alone) ---

function b64(bytes) {
  let bin = "";
  const u = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  for (let i = 0; i < u.length; i++) bin += String.fromCharCode(u[i]);
  return btoa(bin);
}
function unb64(s) {
  const bin = atob(s);
  const u = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i);
  return u;
}
const encU = new TextEncoder();
const decU = new TextDecoder();

// PBKDF2 work factor for the export file at rest (matches AES256 mode / OWASP).
const KDF_ITERS = 600000;

// localStorage schema.
const LS_INDEX = "sc.otp.index.v1";            // [{padId,label,regionSize,role,createdAt}]
const padKey = (id) => `sc.otp.pad.v1.${id}`;  // full record incl. bytes + offsets
// M-01 rollback tripwire: a SEPARATE monotonic high-water mark of the highest
// sendOffset ever persisted for a pad. AES-GCM stops a stored blob from being
// EDITED, but a local attacker can copy an entire OLD valid blob back to resume
// at a lower offset and reuse consumed keystream (a two-time pad). We refuse to
// unlock a pad whose stored sendOffset is below this watermark. This catches a
// targeted restore of just the pad blob; a full-storage rollback that also
// reverts the watermark is inherent to untrusted browser storage and out of
// scope (documented) — it needs OS-level trusted monotonic storage.
//
// Pentest 2026-07-27 H-3 + M-7 — what that tripwire actually was, and is now.
//
// It used to be ONE plaintext decimal string, and `readHW` returned 0 for a
// missing *or unparseable* value: fail-OPEN. So the "targeted restore of just
// the pad blob" it was built to catch cost exactly one extra `removeItem`. The
// pentest reproduced the full break — restore an old blob, delete the
// watermark, and two messages encrypt at offset 0, giving
// `C1 XOR C2 === P1 XOR P2` and a recovered plaintext. A two-time pad from one
// deleted key.
//
// It also only ever tracked `sendOffset` (M-7), so a restore that left the send
// side alone — the state after a stretch of receiving only — rewound
// `recvHighWater` to zero and every previously-received frame re-authenticated
// as fresh.
//
// Now: the watermark is an AEAD record under the pad's own at-rest key, it
// covers BOTH offsets, it is mirrored inside the pad blob (max of the two
// wins), and a pad blob that has one but cannot produce a valid watermark FAILS
// CLOSED. Forging one needs the pad passphrase; deleting one is not a bypass
// but a refusal to unlock.
//
// STILL RESIDUAL (documented, unchanged): an attacker who snapshots the pad
// blob AND its watermark and restores BOTH rewinds undetected. That is the
// whole-storage rollback README.md already calls out; it needs OS-level trusted
// monotonic storage, not another localStorage key.
const hwKey = (id) => `sc.otp.hw.v1.${id}`;        // legacy plaintext watermark
const wmKey = (id) => `sc.otp.wm.v1.${id}`;        // authenticated {send,recv}
const usedKey = (id) => `sc.otp.used.v1.${id}`;    // "this pad ran here" marker
const EPOCH_KEY = "sc.otp.epoch.v1";               // "post-fix OTP ran on this device"
const WM_DOMAIN = "secure-chat/otp-watermark/v1";

// --- the native monotonic floor (pentest 2026-07-28 F-1) --------------------
//
// Everything above lives in localStorage, where each key is independently
// deletable by whoever holds the JS context. For a v3 blob the floor is mirrored
// inside the pad's own AEAD, so deleting `wmKey` is caught. For a v2-SHAPED blob
// there is no mirror, and the whole defence collapsed to `usedKey` — one
// plaintext string. Restore a v2 snapshot, delete three keys, and the pad
// unlocks at offset 0: a full two-time pad.
//
// That is not fixable inside localStorage. Telling "genuinely old" from
// "restored old" needs state the attacker cannot edit, and there is none here.
// So on Android the floor also lives behind a native bridge, in app-private
// storage under an AndroidKeyStore HMAC: monotone (no lowering call exists),
// unforgeable without the non-exportable key, and its ABSENCE next to a pad that
// exists is itself evidence. See android/.../PadFloor.kt.
//
// In a plain browser there is no such primitive, so `nativeFloor` is null and the
// residual stands — documented in README. This is why OTP's guarantee is
// strongest in the app, where pads actually live (they are exchanged in person,
// device to device).
const NATIVE_ABSENT = -1;
const NATIVE_TAMPERED = -2;
// ROUND-3 F-4. A BUMP-ONLY signal from the native floor: the in-memory map moved
// but `SharedPreferences.commit()` returned false, so nothing reached disk (see
// PadFloor.bump). It is deliberately distinct from NATIVE_TAMPERED so `num()` does
// not fold it away — a commit failure is not a forged record, and the two are
// handled differently (a failed save vs. a hard refusal). `read()` never returns
// it, because a read-back cannot observe a failed commit; only the bump's own
// return can, which is exactly why the discarded boolean was the whole hole.
const NATIVE_COMMIT_FAILED = -3;

// Pentest 2026-08-07 F-ATREST-001 / F-ATREST-002. The native floor covered the
// SEND offset only — F-ATREST-009 counted it as 1 of ~5 rollback-sensitive
// counters — so on Android, the one platform where a floor exists at all:
//
//   * rolling back `recvHighWater` was undetected, and every OTP frame the peer
//     had already sent re-authenticated as fresh (anti-replay gone);
//   * rolling back the `exported` flag silently re-armed export, and a second
//     export of the same pad is a two-time pad, which is the one failure OTP
//     cannot survive.
//
// Both now get their own floor. `PadFloor.bump/read` key on an opaque string and
// MAC the key together with the value (`…/v1\0<padId>\0<value>`), so a derived
// id is a distinct, separately-authenticated slot — no Kotlin change needed, and
// a floor still cannot be lifted from one slot to another.
const floorKeySend = (padId) => padId;
const floorKeyRecv = (padId) => padId + "#recv";
const floorKeyExported = (padId) => padId + "#exported";

// Pentest 2026-07-29 H-1. Feature-detecting the bridge alone was a silent
// downgrade: `SecureChatPadFloor` is an ordinary writable global, so
// `delete window.SecureChatPadFloor` at document-start made the code below
// return null, the floor went away, and NOTHING said so — on the platform whose
// whole point is that the floor is unreachable from JS.
//
// The app's document-start script now also defines `__SECURE_CHAT_NATIVE_FLOOR__`
// as a non-writable, NON-CONFIGURABLE property. That is the load-bearing part:
// a JS attacker can still delete the bridge, but `delete` on a non-configurable
// property does not remove it, so they cannot also erase the statement that a
// floor was supposed to be here. Marker present + bridge missing or unusable is
// therefore not "plain browser" — it is evidence of tampering, and it fails
// CLOSED on every pad rather than quietly dropping the control.
//
// A plain browser sets neither, so it still gets `null` and the documented
// residual (see README) — unchanged.
// Fix review 2026-07-30 (H-A). Hardening the marker alone was not enough: this
// code used to look the bridge up by the ordinary global `SecureChatPadFloor`
// and accept anything with `read`/`bump` functions. An attacker never needed to
// DELETE it — installing a lookalike that answers "no floor", or overwriting
// just the two methods on the real object, satisfied every check while the real
// Keystore-backed floor was never consulted. Two assignments, and F-1 was void.
//
// The app now captures the bridge at document-start, before any page script can
// run, and republishes it FROZEN under `__SECURE_CHAT_PAD_FLOOR__` as a
// non-configurable property, with the methods bound so a later
// `SecureChatPadFloor.read = fake` cannot reach them. That name is the only one
// read here. `__SECURE_CHAT_NATIVE_FLOOR__` is the separate, also
// non-configurable statement that a floor is SUPPOSED to exist, so
// "expected but not securable" is a distinguishable, fail-closed state rather
// than something that reads as a plain browser.
const nativeFloorMarker = globalThis.__SECURE_CHAT_NATIVE_FLOOR__;
const nativeFloorExpected = nativeFloorMarker === true || nativeFloorMarker === "unavailable";

const nativeFloor = (() => {
  const b = globalThis.__SECURE_CHAT_PAD_FLOOR__;
  if (!b || typeof b.read !== "function" || typeof b.bump !== "function") {
    if (!nativeFloorExpected) return null;   // genuine browser: no floor exists
    // Marker without a usable protected bridge. Refuse everything rather than
    // degrade — this is either the app failing to secure the interface, or
    // someone having set the marker to brick OTP (loud, and fail-closed).
    return { read: () => NATIVE_TAMPERED, bump: () => NATIVE_TAMPERED, broken: true };
  }
  // Fix review round 2 (H-1): validate WITHOUT poisonable globals.
  //
  // This used to be `parseInt(v, 10)` guarded by `Number.isFinite`. Freezing the
  // bridge stopped an attacker replacing the function that produces the answer,
  // but both of those are ordinary writable globals, so one assignment —
  // `globalThis.parseInt = () => 0` — made every floor read as 0 while the
  // frozen bridge, the non-configurable marker and verifyRelayConfig's probe
  // all stayed intact. The hardened part was bypassed by poisoning the step
  // AFTER it. Note that capturing primordials at module top would not help
  // either: a document-start attacker runs first.
  //
  // So: the bridge now returns a NUMBER (see PadFloorBridge), and the checks
  // below use only `typeof` and bitwise ops, which are language constructs with
  // no interceptable global behind them. `(n | 0) === n` is an integer test
  // that cannot be redefined, and pad offsets are far below 2^31.
  const num = (v) => {
    // An unreadable answer from the bridge is TAMPERED, never "no floor" — a
    // broken bridge must not read as a clean slate.
    if (typeof v !== "number") return NATIVE_TAMPERED;
    if ((v | 0) !== v) return NATIVE_TAMPERED;      // NaN, Infinity, fractions
    return v;
  };
  return {
    read: (id) => { try { return num(b.read(id)); } catch { return NATIVE_TAMPERED; } },
    bump: (id, v) => { try { return num(b.bump(id, v | 0)); } catch { return NATIVE_TAMPERED; } },
  };
})();

// F-ATREST-008. The identity blob's write counter (identity-store.js) is mirrored
// into the same native floor, under its own slot. The bridge is captured ONCE, at
// this module's load, precisely so no later page script can substitute it (see
// above) — so rather than have a second module repeat that capture (and give an
// attacker a second copy of the same ceremony to defeat), the one captured bridge
// is reached through here. `null` in a plain browser; a `broken` object when the
// marker says a floor should exist but none is usable — callers must treat that
// as evidence, never as "no floor".
//
// Pentest of this change (2026-09-16, F-2): the first cut returned `nativeFloor`
// ITSELF — a plain, unfrozen object literal that this module also calls through.
// One assignment on the returned object (`otp.deviceFloor().read = () => -1`)
// then rewrote what `padWasUsed` and `unlockPad` saw, and the H-1/H-A ceremony
// (frozen bridge, non-configurable globals) was bypassed one hop downstream, the
// same shape as the `parseInt` poisoning it had already been fixed for once. So
// this returns a fresh facade per call, closing over the private object: a
// caller may mutate what it was handed and reach nothing this module or any
// other holder uses. (`Object.freeze` would not do: it is a writable global and
// a document-start attacker runs first — closures are language constructs.)
export function deviceFloor() {
  if (!nativeFloor) return null;
  const f = nativeFloor;
  return {
    read: (id) => f.read(id),
    bump: (id, v) => f.bump(id, v),
    broken: f.broken === true,
  };
}
export { NATIVE_ABSENT, NATIVE_TAMPERED, NATIVE_COMMIT_FAILED };

// Max without `Math.max` (H-1). `Math.max` is writable, and the rollback verdict
// is a single call to it over the four floors — so one assignment overruled the
// native floor, the authenticated watermark, the in-AEAD `hwSend` and the legacy
// watermark simultaneously, silently. Comparison operators cannot be redefined.
function maxOf(...values) {
  let best = 0;
  for (const v of values) {
    const n = typeof v === "number" && (v | 0) === v ? v : 0;
    if (n > best) best = n;
  }
  return best;
}

// In-memory high-water marks for pads unlocked this session, so every re-save
// can take a max without re-deriving the at-rest key.
// Fix review 2026-07-30 (L-A). When the floor is EXPECTED but not usable, the
// pad is fine and the platform is not: every message that came out of this state
// blamed the pad ("damaged or forged", "already been used") and told the user to
// exchange a fresh one, which does not help and burns real pads. Say what is
// actually wrong instead. Still fail-closed — only the wording changes.
function floorUnavailableError() {
  return new Error(
    "this device says it has hardware rollback protection for one-time pads, but the app cannot reach it. " +
    "Your pad is probably fine — do NOT exchange a new one. On Android, reinstall or update the app; " +
    "in a browser, an extension or script has set this flag and OTP is disabled until it is removed.",
  );
}

const wmCache = new Map(); // padId -> {send, recv}

function cachedWm(id) {
  return wmCache.get(id) || { send: 0, recv: 0 };
}

// The legacy (plaintext, send-only) watermark. Read ONLY to migrate a pad that
// predates the authenticated record, and to answer padWasUsed for a pad whose
// blob is gone. Never load-bearing for a rollback decision on its own.
function readLegacyHW(id) {
  // H-1: no parseInt/Number.isFinite — both writable. The VALUE here is
  // attacker-writable anyway (plain localStorage), but poisoning the parse
  // could zero a floor that would otherwise have fired, so it is read the
  // same poison-proof way as the native one.
  const raw = localStorage.getItem(hwKey(id));
  const v = +raw;                       // unary plus: no global to redefine
  return typeof v === "number" && (v | 0) === v && v > 0 ? v : 0;
}

// Decrypt the authenticated watermark for `id` under the pad's at-rest key.
// Returns {send, recv} | null (absent) | "corrupt".
async function readWatermark(id, key) {
  const raw = localStorage.getItem(wmKey(id));
  if (!raw) return null;
  try {
    const rec = JSON.parse(raw);
    const plain = new Uint8Array(await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: unb64(rec.iv) }, key, unb64(rec.ct),
    ));
    const w = JSON.parse(decU.decode(plain));
    plain.fill(0);
    // The padId is INSIDE the AEAD, so an old pad's watermark cannot be
    // re-keyed under a fresh id to read as a clean slate (the P-01 lesson).
    if (w.d !== WM_DOMAIN || w.padId !== id ||
        !Number.isInteger(w.send) || !Number.isInteger(w.recv)) {
      return "corrupt";
    }
    return { send: w.send, recv: w.recv };
  } catch {
    return "corrupt";
  }
}

// Read all three native floors back and turn them into the two claims the blob
// makes about itself. Item 13, second pass — see writePadBlob for why the answer
// has to be measured rather than assumed.
//
// Measured by READING THE SLOTS BACK, not by trusting the bump. The JS wrapper
// swallows any bridge exception into NATIVE_TAMPERED, so an EXCEPTIONAL failure
// says nothing useful. A read-back is a statement about a slot that is actually
// evidence — for every failure mode EXCEPT one: a `commit()` that returns false
// leaves the in-memory map (which `read` is backed by) already advanced, so the
// read-back looks healthy while nothing reached disk. `PadFloor.bump` used to
// discard that boolean; since ROUND-3 F-4 it returns NATIVE_COMMIT_FAILED, and
// probeFloors/armFloors inspect the bump RETURN for exactly that case, because a
// read-back structurally cannot see it.
//
// The SEND slot is included because `nativeFloor: !!nativeFloor` has exactly the
// same defect the item 13 fix was written to repair, one level up: the 2026-07-29
// H-1 flag is also a claim made before the bump that backs it, with the bump's
// result discarded. It has always been able to brick a pad the same way. Both
// flags are answers to "does this slot exist?", so both are now measured.
function readFloorClaims(id) {
  const s = nativeFloor.read(floorKeySend(id));
  const r = nativeFloor.read(floorKeyRecv(id));
  const e = nativeFloor.read(floorKeyExported(id));
  // Item 13, THIRD pass. `read` has three classes of answer, not two, and the
  // first cut of this function collapsed two of them with `>= 0`.
  //
  // ABSENT (-1) is benign: nothing was ever written here, which is the
  // non-adversarial failure the trade-off below is written for. TAMPERED (-2) is
  // the opposite: something IS here and its Keystore MAC did not verify. Folding
  // them together answered "no floor, write the blob unguarded" to BOTH — so
  // CORRUPTING a prefs entry, which costs an attacker exactly what deleting one
  // costs (a single file edit), silently disarmed the very guard that deleting
  // it trips. That turned a fail-CLOSED path into a fail-OPEN one: the pentest
  // rewound `recvHighWater` by 4000 bytes with the guard off, replaying
  // already-delivered frames (M-7), where the previous cut had refused outright.
  //
  // Tampering is evidence, so it is a hard refusal — never a quiet `false`.
  // NATIVE_COMMIT_FAILED is folded in defensively: `read` does not return it today
  // (only bump does — see NATIVE_COMMIT_FAILED), but if a future bridge change ever
  // surfaced it through `read`, "the slot's durable write failed" must fail CLOSED
  // like a forged record, never slip past `s >= 0` below and read as "not armed".
  if (s === NATIVE_TAMPERED || r === NATIVE_TAMPERED || e === NATIVE_TAMPERED
    || s === NATIVE_COMMIT_FAILED || r === NATIVE_COMMIT_FAILED || e === NATIVE_COMMIT_FAILED) {
    throw new Error(
      "this pad's device-protected rollback record is damaged or forged — refusing to use the pad; exchange a fresh one",
    );
  }
  // Note what these two claims say, because the guards in unlockPad test exactly
  // this and nothing more: "a slot for this pad EXISTED when the blob was
  // written", so a later ABSENT is evidence of deletion. They deliberately say
  // nothing about the slot's VALUE — the value is covered by the max() in
  // unlockPad, and tying the claim to a value is what made F-A1 possible.
  return { send: s >= 0, derived: r >= 0 && e >= 0 };
}

// Ensure the three slots EXIST, without advancing any of them, and report what
// is genuinely in place. Called before the blob is serialised so its claims can
// be decided by measurement.
//
// `bump(_, 0)` is the whole trick. Against an ABSENT slot it really does write
// it (PadFloor.ABSENT is -1, so `next` is 0 and differs from `current`), which is
// what lets a pad's FIRST save claim a floor honestly; against any existing slot
// it is a no-op, because `bump` is monotone. So this creates what is missing and
// can never move a floor AHEAD of the blob that is about to be written — which
// is the ordering property F-A1 is about (see writePadBlob).
//
// TRADE-OFF, stated because it is a security choice and not an obvious one: when
// a slot cannot be created the pad is not REFUSED outright. A permanent brick
// carrying the wording of the tamper alarm is the worse outcome: it destroys an
// in-person key exchange, it cannot be undone by any user action, and it teaches
// the user to disbelieve the alarm. The failure this protects against is
// non-adversarial (a transient Keystore error, a full disk, a kill between two
// JNI calls); an attacker who can actually suppress bumps is inside the native
// floor's threat model and is caught by `broken`/NATIVE_TAMPERED, which still
// refuse outright.
//
// What it does instead (A4/F-A3, fixed 2026-08-20): the blob records
// CLAIM_UNCONFIRMED — NOT the `false` a plain browser writes — and unlockPad
// routes it through the adoption consent gate. Two earlier sentences here were
// wrong and are worth naming, because they described a safety that did not exist:
//   * "the pad opens UNGUARDED for that slot — the pre-fix behaviour" — the code
//     this replaced REFUSED; unguarded was never the status quo it restored.
//   * "the claim re-arms on the next save that succeeds" — true of the LIVE pad
//     only. A blob written during the degraded window is sealed, and no later
//     save can reach back into an AEAD that has already been snapshotted, so a
//     copy taken then keeps the weaker claim forever. That permanence is exactly
//     why a silent `false` was unacceptable and why the third value exists.
// The three claim values, and why "arming failed" may not collapse into "never
// armed" (A4/F-A3). `nativeFloor: false` is what a plain browser legitimately
// writes on every save; if a bridge IS present but its prefs write silently does
// not take (unwritable file, full disk), the old code recorded that same `false`.
// Both unlock guards are keyed on the claim being `true`, so they could never fire
// for that blob — and because the claim is AEAD-sealed, a later save that succeeds
// cannot repair a snapshot taken during the degraded window. It stayed exploitable
// forever, into keystream reuse. UNCONFIRMED keeps the two cases apart, and routes
// such a blob through the existing adoption consent gate instead of opening it
// silently. Since ROUND-3 F-4 the "silently does not take" case is no longer
// silent: `PadFloor.bump` returns NATIVE_COMMIT_FAILED, and probeFloors maps a
// failed CREATE to CLAIM_UNCONFIRMED directly from that return rather than relying
// on a read-back the failed commit leaves looking healthy.
const CLAIM_ARMED = true;          // slot existed and was read back
const CLAIM_NONE = false;          // no bridge on this device (a plain browser)
const CLAIM_UNCONFIRMED = "unconfirmed"; // bridge present, slot could not be created

function probeFloors(id) {
  if (!nativeFloor) return { send: CLAIM_NONE, derived: CLAIM_NONE };
  const sendBump = nativeFloor.bump(floorKeySend(id), 0);
  // F-ATREST-001: the recv high-water mark, which used to be AEAD-mirrored only
  // — and an AEAD record can be restored wholesale from a snapshot.
  const recvBump = nativeFloor.bump(floorKeyRecv(id), 0);
  // F-ATREST-002: monotone one-way latch. Created at 0 on a pad's first save, so
  // the slot exists from then on and its ABSENCE is unambiguous evidence of
  // deletion rather than of a pad that was simply never exported.
  const exportedBump = nativeFloor.bump(floorKeyExported(id), 0);
  const claims = readFloorClaims(id);
  // ROUND-3 F-4. On a pad's FIRST save the bump that creates a slot is the only
  // thing that can prove the slot is durable. A `commit()` that fails still moves
  // the in-memory map, so `readFloorClaims` (a read-back) reports the slot armed
  // while nothing reached disk — and a false CLAIM_ARMED sealed into the blob
  // becomes a guard that a restart silently erases. So trust the bump's OWN return
  // over the read-back: a NATIVE_COMMIT_FAILED create forces CLAIM_UNCONFIRMED,
  // which routes the pad through unlockPad's adoption consent gate (F-A3) rather
  // than promising a floor that is not durably in force. This is the create-side
  // half; armFloors is the advance-side half that fails the save outright.
  const sendUnconfirmed = sendBump === NATIVE_COMMIT_FAILED;
  const derivedUnconfirmed = recvBump === NATIVE_COMMIT_FAILED || exportedBump === NATIVE_COMMIT_FAILED;
  // A bridge is present, so a slot that is STILL absent after the bump above (or a
  // create whose commit did not take) means the write did not durably land. That
  // is not "this device has no floor" — say so (F-A3), and let unlockPad ask the
  // user rather than sealing a false negative.
  return {
    send: (claims.send && !sendUnconfirmed) ? CLAIM_ARMED : CLAIM_UNCONFIRMED,
    derived: (claims.derived && !derivedUnconfirmed) ? CLAIM_ARMED : CLAIM_UNCONFIRMED,
  };
}

// Raise all three floors to the state the blob on disk now describes.
//
// Pentest 2026-08-10-night F-A1: this MUST run after the blob has been
// persisted, and it is the only place that advances a floor.
//
// The previous cut advanced the floors up front, so that their read-back could
// decide the blob's claims — and thereby put the floor AHEAD of the blob for the
// whole of a `JSON.stringify` plus an `await crypto.subtle.encrypt`. A process
// kill or a QuotaExceededError in that window left a floor above the offsets the
// stored blob carries, which the next unlock reads as a ROLLBACK and refuses
// permanently: `forgetPad` + re-import cannot recover it, because `padWasUsed`
// sees the floor and refuses the import too. That is a brick wearing the tamper
// alarm's own wording — the exact outcome probeFloors' trade-off note calls the
// worse one — and it was a REGRESSION: the code this replaced bumped from
// `writeWatermark`, i.e. after the blob was already on disk, so an interruption
// left the floor BEHIND the blob, which is harmless (the blob's own authenticated
// `hwSend`/`hwRecv` are the higher input to unlockPad's max()).
//
// So the ordering is split by what each half is for: the CLAIM is measured
// before the write (probeFloors, which cannot advance anything), the VALUE is
// raised after it (here). A floor is never above the blob it is meant to protect.
function armFloors(id, wm, exportedNow, armed) {
  if (!nativeFloor) return { send: false, derived: false };
  const wantExported = exportedNow ? 1 : 0;
  const sendBump = nativeFloor.bump(floorKeySend(id), wm.send);
  const recvBump = nativeFloor.bump(floorKeyRecv(id), wm.recv);
  // Bumped with 0 when the pad has not been exported, so an ordinary save keeps
  // the slot alive without lowering the latch (`bump` never lowers).
  const exportedBump = nativeFloor.bump(floorKeyExported(id), wantExported);
  const claims = readFloorClaims(id);   // throws on TAMPERED

  // ROUND-3 F-1 (pentest of the F-A1-R1 fix, 2026-08-21). The claim used to be
  // DISCARDED, and "a slot exists" was the only thing anyone checked — so a floor
  // FROZEN at its current value let this function report success while the durable
  // floor did not move at all. The read-back below is the F-1 repair: it catches a
  // floor that a read genuinely reports STALE. It does NOT catch the Android
  // residual (ROUND-3 F-4, handled just after it): a failed `commit()` leaves the
  // in-memory map — which `read` is backed by — already advanced, so the read-back
  // looks healthy. That case needs the bump's own return, not a read.
  //
  // Why that was catastrophic rather than untidy: `app.js` persists BEFORE it
  // transmits (P-04), so "the save succeeded" is precisely the signal that
  // releases keystream onto the wire. The floor stayed at the probe-only 0, and
  // since F-A1-R1 a probe-only triple is deliberately NOT evidence of use — so
  // deleting the (deletable) localStorage markers and re-importing the (always
  // pristine) pad file brought the pad back at sendOffset 0 and spent the same
  // keystream twice. C1 XOR C2 = P1 XOR P2: the one failure a one-time pad cannot
  // survive, and the exact hole H-3 closed.
  //
  // Tightening `padWasUsed` again is not the repair — every input it has left is
  // attacker-deletable, and tightening it is what burned padIds and produced
  // F-A1-R1 in the first place. The repair is to stop the SAVE from succeeding
  // when the floor it depends on did not take.
  //
  // Scoped deliberately to slots the blob CLAIMS are armed. `probeFloors` makes a
  // different trade for a slot it could not create at all — it records
  // CLAIM_UNCONFIRMED and routes the pad through the adoption consent gate rather
  // than refusing, because a permanent brick is the worse outcome there. That
  // decision is untouched: this only fires when a slot exists, i.e. when the blob
  // is about to promise a guard that is not actually in force.
  const readBack = {
    send: nativeFloor.read(floorKeySend(id)),
    recv: nativeFloor.read(floorKeyRecv(id)),
    exported: nativeFloor.read(floorKeyExported(id)),
  };
  const stuck = (claims.send === CLAIM_ARMED && readBack.send < wm.send)
    || (claims.derived === CLAIM_ARMED
      && (readBack.recv < wm.recv || readBack.exported < wantExported));

  // ROUND-3 F-4 (pentest of the F-1 fix, 2026-08-21). The read-back `stuck` check
  // above catches a floor frozen at its OLD value — but NOT the Android residual
  // it was written for. `SharedPreferences.commit()` writes the in-memory map
  // synchronously and does not roll it back on a failed disk write, and
  // `PadFloor.read` is backed by that map, so after a failed commit the read-back
  // reports the NEW value (`readBack.send >= wm.send`, `stuck` false) while the
  // durable floor is still 0. armFloors then returned success, `app.js` transmitted
  // (persist-before-transmit, P-04), and a restart plus a pristine re-import
  // respent the keystream — a two-time pad, the exact hole H-3 closed.
  //
  // The only witness to that failure is the BUMP's return, which `PadFloor.bump`
  // used to discard and now surfaces as NATIVE_COMMIT_FAILED. So inspect it, and
  // fail the save when a slot the blob CLAIMS ARMED did not durably record its
  // advance. `app.js` persists before it transmits, so a throw here means the
  // keystream never goes on the wire — which is the only repair that holds when
  // every read-back on this device lies healthy.
  //
  // Scoped to `armed` (the verdict probeFloors sealed into the blob), NOT to the
  // local `claims` read-back: a slot probeFloors could not even CREATE is recorded
  // CLAIM_UNCONFIRMED and routed through the adoption gate rather than failing the
  // save (a permanent brick of an in-person exchange is the worse outcome there).
  // This throw is for a slot the blob promises is armed while the bump says its
  // durable write just failed — i.e. an ESTABLISHED pad advancing onto a frozen
  // disk, which is the keystream-reuse case and not the first-save one.
  const scope = armed || { send: claims.send, derived: claims.derived };
  const commitFailed =
    (scope.send === CLAIM_ARMED && sendBump === NATIVE_COMMIT_FAILED)
    || (scope.derived === CLAIM_ARMED
      && (recvBump === NATIVE_COMMIT_FAILED || exportedBump === NATIVE_COMMIT_FAILED));

  if (stuck || commitFailed) {
    throw new Error(
      "this device's rollback guard did not record this pad's progress (the protected floor " +
      `did not move: send ${readBack.send}/${wm.send}, recv ${readBack.recv}/${wm.recv}). ` +
      "Nothing was sent. The pad is unchanged on this device — free some storage and try " +
      "again; if it keeps happening, exchange a fresh pad in person rather than continuing.",
    );
  }
  return claims;
}

// Seal the authenticated watermark. PURE: it returns the record to store and
// writes nothing, so writePadBlob can do all of its crypto first and all of its
// storage writes afterwards, back to back — see the note there.
async function sealWatermark(id, key, wm) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const plain = encU.encode(JSON.stringify({
    d: WM_DOMAIN, padId: id, send: wm.send, recv: wm.recv,
  }));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, plain));
  plain.fill(0);
  return JSON.stringify({ iv: b64(iv), ct: b64(ct) });
}

// Pad size presets (total bytes; each direction gets half). XOR-OTP spends one
// pad byte per plaintext byte + 32 per message, so these are honest lifetimes.
export const PAD_SIZES = [
  { label: "64 KiB — ~350 short messages/side", bytes: 64 * 1024 },
  { label: "256 KiB — ~1,400 short messages/side", bytes: 256 * 1024 },
  { label: "1 MiB — ~5,700 short messages/side", bytes: 1024 * 1024 },
];

// ---- randomness ------------------------------------------------------------

// Produce `totalBytes` of pad material. The base is the OS CSPRNG; if the user
// supplied drawn-entropy samples we fold them in by XOR with an AES-CTR
// keystream keyed by their hash. XOR of independent sources is never weaker than
// either: if getRandomValues were ever weak, the drawn entropy still randomizes
// the pad; if the drawing were low-entropy, the CSPRNG still carries it.
// Web Crypto hard-caps a single getRandomValues() call at 65536 bytes and
// throws QuotaExceededError above it (Web Cryptography API §10.1.1). Pentest
// 2026-08-07 F-CRYPTO-012: `randomPad` asked for the whole pad in one call, so
// two of the three sizes PAD_SIZES advertises — 256 KiB and 1 MiB — could never
// be generated at all. Fill in chunks; the CSPRNG is the same one either way.
const CSPRNG_MAX_BYTES = 65536;

function fillRandom(buf) {
  for (let off = 0; off < buf.length; off += CSPRNG_MAX_BYTES) {
    crypto.getRandomValues(buf.subarray(off, Math.min(off + CSPRNG_MAX_BYTES, buf.length)));
  }
  return buf;
}

async function randomPad(totalBytes, fingerBytes) {
  const base = fillRandom(new Uint8Array(totalBytes));
  if (!fingerBytes || fingerBytes.length === 0) return base;
  const seed = await crypto.subtle.digest("SHA-256", fingerBytes);
  const key = await crypto.subtle.importKey("raw", seed, { name: "AES-CTR" }, false, ["encrypt"]);
  const stream = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: "AES-CTR", counter: new Uint8Array(16), length: 64 },
      key,
      new Uint8Array(totalBytes),
    ),
  );
  for (let i = 0; i < totalBytes; i++) base[i] ^= stream[i];
  stream.fill(0);
  return base;
}

function randomId() {
  return Array.from(crypto.getRandomValues(new Uint8Array(16)), (b) => b.toString(16).padStart(2, "0")).join("");
}

// ---- generation ------------------------------------------------------------

// Generate a fresh pristine pad. The generator is always role 0.
export async function generatePad({ label, totalBytes, fingerBytes }) {
  if (!Number.isInteger(totalBytes) || totalBytes < 128 || totalBytes % 2 !== 0) {
    throw new Error("pad size must be an even number of bytes");
  }
  return {
    padId: randomId(),
    label: label || "pad " + new Date().toISOString().slice(0, 16).replace("T", " "),
    regionSize: totalBytes / 2,
    role: 0,
    createdAt: Date.now(),
    bytes: await randomPad(totalBytes, fingerBytes),
    sendOffset: 0,
    recvHighWater: 0,
  };
}

// ---- encrypted export / import --------------------------------------------

// Audit 2026-07-18 L-01: `iters`/`salt` come from pad files and the persisted
// blobs — bound them before WebCrypto runs (huge count = UI stalled for hours;
// tiny count = silently weakened KDF). Same bounds as identity.js.
const KDF_MIN_ITERS = 100000;
const KDF_MAX_ITERS = 5000000;

async function deriveKey(passphrase, salt, iters) {
  if (!Number.isInteger(iters) || iters < KDF_MIN_ITERS || iters > KDF_MAX_ITERS) {
    throw new Error("invalid key-derivation parameters (iteration count)");
  }
  if (!(salt instanceof Uint8Array) || salt.length < 8 || salt.length > 64) {
    throw new Error("invalid key-derivation parameters (salt)");
  }
  const base = await crypto.subtle.importKey("raw", encU.encode(passphrase), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: iters, hash: "SHA-256" },
    base,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

// Serialize a PRISTINE pad into a passphrase-encrypted file string. The importer
// becomes the opposite role, so their send region is the other half.
export async function exportPad(record, passphrase) {
  if (!passphrase) throw new Error("choose a transfer passphrase (agree on it in person)");
  if (record.sendOffset !== 0 || record.recvHighWater !== 0) {
    throw new Error("this pad has already been used — export a freshly generated pad only");
  }
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKey(passphrase, salt, KDF_ITERS);
  const plain = encU.encode(JSON.stringify({
    padId: record.padId,
    label: record.label,
    regionSize: record.regionSize,
    recipientRole: 1 - record.role,
    bytes: b64(record.bytes),
  }));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, plain));
  plain.fill(0);
  return JSON.stringify({
    fmt: "secure-chat-otp-pad",
    v: 1,
    kdf: { salt: b64(salt), iters: KDF_ITERS },
    iv: b64(iv),
    ct: b64(ct),
  });
}

// Decrypt an export file into a fresh local pad record (role = recipient role).
export async function importPad(fileText, passphrase) {
  // Audit 2026-07-18 L-01: cap the file before any parsing/decoding. The
  // largest genuine export (1 MiB pad) is ~1.4 MiB of base64 + envelope;
  // 4 MiB leaves headroom without letting a crafted file drive large
  // JSON/base64 allocations.
  if (typeof fileText !== "string" || fileText.length > 4 * 1024 * 1024) {
    throw new Error("not a valid pad file");
  }
  let file;
  try {
    file = JSON.parse(fileText);
  } catch {
    throw new Error("not a valid pad file");
  }
  if (file.fmt !== "secure-chat-otp-pad" || file.v !== 1) throw new Error("unrecognized pad file format");
  if (!file.kdf || typeof file.kdf !== "object") throw new Error("unrecognized pad file format");
  const key = await deriveKey(passphrase, unb64(file.kdf.salt), file.kdf.iters || KDF_ITERS);
  let plain;
  try {
    plain = new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: unb64(file.iv) }, key, unb64(file.ct)));
  } catch {
    throw new Error("wrong passphrase or corrupted pad file");
  }
  const o = JSON.parse(decU.decode(plain));
  plain.fill(0);
  const bytes = unb64(o.bytes);
  if (bytes.length !== 2 * o.regionSize) throw new Error("pad file is internally inconsistent");
  if (o.recipientRole !== 0 && o.recipientRole !== 1) throw new Error("pad file has an invalid role");
  if (!looksRandom(bytes)) {
    throw new Error("this pad is not random enough to be safe (all-zero or low-entropy) — do not use it");
  }
  // Pentest 2026-07-26 P-05: an export file is always pristine, so re-importing
  // one this device has already consumed would rewind sendOffset to 0 and reuse
  // keystream the peer has already seen. The watermark survives `forgetPad`
  // precisely so this check can fire.
  // F-ATREST-008 fix review round 2 (F-4): the pad id names the pad's native
  // floor slots, and it arrives here from the FILE, unchecked — so a pad-file
  // author chose the slot name. `randomId()` is 32 lowercase hex characters;
  // anything else (e.g. the identity's `sc.identity.v1#gen` slot, whose
  // "cannot collide" argument rests on exactly this check) is not a pad.
  if (typeof o.padId !== "string" || !/^[0-9a-f]{32}$/.test(o.padId)) {
    throw new Error("not a valid pad file (pad id)");
  }
  if (nativeFloor && nativeFloor.broken) throw floorUnavailableError();
  if (padWasUsed(o.padId)) {
    throw new Error(
      "this pad has already been used on this device — importing it again would reuse key material. Generate and exchange a fresh pad in person.",
    );
  }
  return {
    padId: o.padId,
    label: o.label || "imported pad",
    regionSize: o.regionSize,
    role: o.recipientRole,
    createdAt: Date.now(),
    bytes,
    sendOffset: 0,
    recvHighWater: 0,
  };
}

// ---- entropy sanity check --------------------------------------------------

// Reject an obviously non-random pad (all zeros, or grossly low entropy). A
// malicious or corrupted pad — e.g. an all-zero send region — would make the
// importer's outbound ciphertext equal its plaintext (`ct = pt XOR 0`), leaking
// it to the relay. This can't catch a cryptographically-crafted pad the sender
// already knows (they generated it — inherent to OTP), but it stops accidental
// corruption and blatant sabotage. Random bytes score ~8 bits/byte; we require
// a healthy margin.
export function looksRandom(bytes) {
  const n = bytes.length;
  if (n < 64) return true; // too small to judge; region-size checks apply elsewhere
  const hist = new Uint32Array(256);
  // Sample up to 65536 bytes for speed on large pads.
  const step = Math.max(1, Math.floor(n / 65536));
  let count = 0;
  for (let i = 0; i < n; i += step) { hist[bytes[i]]++; count++; }
  let H = 0;
  for (let v = 0; v < 256; v++) {
    if (!hist[v]) continue;
    const p = hist[v] / count;
    H -= p * Math.log2(p);
  }
  return H >= 7.0; // ~8 for uniform random; well below for low-entropy/zeros
}

// ---- persistence (encrypted at rest) ---------------------------------------
// The pad is the long-term secret, so it is stored ENCRYPTED under a per-pad
// passphrase (PBKDF2 -> AES-256-GCM), the same posture as the identity blob —
// never in the clear. The encrypted payload also covers the consumption offsets,
// so a local attacker cannot roll `sendOffset` back to force pad reuse. PBKDF2
// runs once per unlock; the derived key is cached in memory so the frequent
// per-message re-saves are cheap AES-GCM only.

function readIndex() {
  try {
    return JSON.parse(localStorage.getItem(LS_INDEX) || "[]");
  } catch {
    return [];
  }
}
function writeIndexEntry(record, extra = {}) {
  const idx = readIndex().filter((e) => e.padId !== record.padId);
  const prev = readIndex().find((e) => e.padId === record.padId) || {};
  idx.push({
    padId: record.padId,
    label: record.label,
    regionSize: record.regionSize,
    role: record.role,
    createdAt: record.createdAt,
    exported: prev.exported || false,
    ...extra,
  });
  localStorage.setItem(LS_INDEX, JSON.stringify(idx));
}

// List pad metadata (no bytes / no secrets) for the selector, newest first.
export function listPads() {
  return readIndex().slice().sort((a, b) => b.createdAt - a.createdAt);
}
export function padMeta(padId) {
  return readIndex().find((e) => e.padId === padId) || null;
}

// Stored-blob format version. v1 kept padId/label/regionSize/role OUTSIDE the
// AES-GCM ciphertext; v2 puts every security-relevant field inside it (P-01).
// v3 (pentest 2026-07-27) additionally carries the send/recv high-water marks
// and the `exported` flag inside the AEAD — see H-3/M-7 above and L-3 below.
const PAD_BLOB_V = 3;

// Encrypt the WHOLE record under `key` (a cached AES-GCM CryptoKey) with a fresh
// IV and persist, keeping the stored salt/iters so the same key still unlocks it.
//
// Pentest 2026-07-26 P-01: `role`, `padId` and `regionSize` used to sit in the
// outer plaintext JSON and were read straight back by unlockPad. `OtpPad`
// derives the send region as `role * regionSize`, so flipping one stored byte
// (`"role":1` -> `"role":0`) pointed the sender at the PEER's region and
// produced a full two-time pad — with no passphrase and no key material. The
// same outer `padId` also keyed the M-01 rollback watermark, so re-keying an old
// blob under a fresh id walked around that control. Everything now lives inside
// the AEAD; only the KDF parameters and the ciphertext are outside (they cannot
// redirect key material, and the tag covers the rest).
async function writePadBlob(record, key, salt, iters) {
  // H-3/M-7: the watermarks only ever move forward, and they cover BOTH
  // directions. Mirrored inside the blob so a restored blob carries its own
  // floor, and written to the authenticated outer record so a restored blob is
  // measured against the newest state this device ever reached.
  const prev = cachedWm(record.padId);
  const wm = {
    send: maxOf(prev.send, record.sendOffset | 0),
    recv: maxOf(prev.recv, record.recvHighWater | 0),
  };
  // Item 13, second pass — the first cut of this fix could BRICK a pad.
  //
  // It set `derivedFloors: !!nativeFloor` here and left the two derived bumps to
  // `writeWatermark` AFTER the blob had already been written, discarding their
  // return values. So if either derived bump failed or was interrupted during a
  // pad's FIRST save, the blob permanently asserted two slots that were never
  // written and the guard in unlockPad then refused the pad forever — with the
  // wording of the tamper alarm, which teaches the user to disbelieve it. Worse
  // on `importPad`: `padWasUsed` sees the send slot at 0, so the in-person pad
  // file could not be re-imported either, and the padId was burned. Verified as
  // a real regression: the same interruption opens normally on the pre-fix code.
  //
  // So the claim is now MADE ONLY WHERE IT IS TRUE: ensure the slots exist,
  // verify that by reading them back, and let that verdict decide what the blob
  // says. A bridge that fails yields `derivedFloors: false` — the pad still
  // opens, unguarded, exactly as it would have before this fix existed —
  // instead of a permanent brick.
  //
  // Pentest 2026-08-10-night F-A1, third pass: the probe may only CREATE slots,
  // never advance them, or the claim's read-back reintroduces the brick from the
  // other side (floor above the blob for the length of the encrypt below). The
  // advance happens after the blob is on disk — see armFloors.
  const armed = probeFloors(record.padId);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const plain = encU.encode(JSON.stringify({
    padId: record.padId,
    label: record.label,
    regionSize: record.regionSize,
    role: record.role,
    createdAt: record.createdAt,
    bytes: b64(record.bytes),
    sendOffset: record.sendOffset,
    recvHighWater: record.recvHighWater,
    hwSend: wm.send,
    hwRecv: wm.recv,
    // L-3: `exported` decides whether the "you already gave this pad away"
    // warning fires, and that warning is the only thing standing between a
    // user and handing one pristine pad to two importers — a two-time pad by
    // construction. It lived in the plaintext index, where clearing it was a
    // one-line localStorage write. It is authenticated state now; the index
    // keeps a copy purely so the pad list can render without the passphrase.
    exported: !!record.exported,
    // Pentest 2026-07-29 H-1: "a floor was in force when this blob was written."
    //
    // Deleting the native floor record used to be SILENT even though the file
    // header claimed otherwise: with the floor gone, `native` reads ABSENT, so
    // the "floor but no watermark" branch cannot fire and the floor contributes
    // 0 to the max() below — the pad just reopens wherever the blob says.
    //
    // This flag is the missing half. It says a floor EXISTED, it lives inside
    // the AEAD so it cannot be cleared or forged from JS, and its presence next
    // to an ABSENT floor is proof of deletion rather than of a fresh pad. Pads
    // written before the floor shipped simply lack it, so no legitimate pad is
    // caught by it — which is why this is authenticated state and not another
    // localStorage marker.
    nativeFloor: armed.send,
    // Pentest 2026-08-08 item 13: the same statement, for the two DERIVED slots.
    //
    // `nativeFloor` above cannot do this job. It says "a floor was in force",
    // and it is true on blobs written by the 2026-07-29 code — which predates
    // `#recv`/`#exported` entirely and so legitimately has no derived slots.
    // Keying a strict presence check on it would brick every one of those pads.
    // That is why the H-1 guard below was written against the send slot only,
    // and why the omission has to be repaired with a NEW field rather than by
    // tightening the old one: a pad written before this line existed must go on
    // opening, and a pad written after it must not be able to lose a derived
    // slot silently.
    //
    // Present ⇒ this save maintained BOTH derived slots AND read them back to
    // confirm it, so both must still be there on the next unlock. Absent ⇒ say
    // nothing, and fall back to the pre-2026-08-08 behaviour for that blob.
    derivedFloors: armed.derived,
  }));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, plain));
  plain.fill(0);
  const blobJson = JSON.stringify({
    v: PAD_BLOB_V,
    kdf: { salt: b64(salt), iters },
    iv: b64(iv),
    ct: b64(ct),
  });
  // F-A1, the other half. Every remaining step is ordered so that an interruption
  // leaves a state the next unlock accepts ON AN ESTABLISHED PAD, and both crypto
  // operations are finished before the first byte is stored so that no `await`
  // sits between two writes that have to agree:
  //
  // The claim used to need the qualifier "on an established pad", because on a
  // pad's FIRST save — `saveNewPad`, `importPad`, or the v1/v2 migration rewrite
  // — `probeFloors` has just created the send slot, and `padWasUsed` counted that
  // bare slot as use while no blob, watermark or `usedKey` existed yet. Any
  // failure here therefore burned the padId (F-A1-R1). CLOSED 2026-08-20 by the
  // second of the two options that finding named: `padWasUsed` no longer treats
  // the probe-only triple (0,0,0) as evidence — see the note there. The slots are
  // still created early, which is what keeps the claim honest and H-3 refused.
  //
  //   1. the blob FIRST. It carries the new offsets inside its AEAD, so a stored
  //      blob with a stale watermark beside it is fine — unlockPad's max() takes
  //      the blob's own `hwSend`/`hwRecv`. The reverse order is NOT safe: a new
  //      watermark over an old blob reads as `sendOffset < wm.send`, i.e. a
  //      rollback refusal, which is the brick this finding is about.
  //   1b. the index entry, right after the blob (ROUND-2 F-5). It is the only
  //      thing listPads() reads and so the only route to the pad in the UI; a
  //      durable pad that is not indexed is a burned pad. It carries no security
  //      decision, so it is safe this early and unsafe any later.
  //   2. the watermark, `usedKey` and the epoch marker, synchronously and
  //      adjacent, so the only survivable gap on a pad's FIRST save (where
  //      `outerWm === null` plus an existing floor is itself a refusal) is
  //      between two adjacent statements rather than across an encrypt.
  //   3. the floors LAST, once everything they could contradict is durable.
  const wmJson = await sealWatermark(record.padId, key, wm);
  localStorage.setItem(padKey(record.padId), blobJson);
  // The index entry, immediately after the blob (ROUND-2 F-5). `listPads()` reads
  // ONLY the index, and `refreshOtpPads` builds the pad selector — the sole route
  // to `unlockPad` — from `listPads()`. If the index is written LAST (after the
  // watermark/used/epoch), a kill or QuotaExceededError on a pad's FIRST save
  // between the blob and the index leaves the pad durable and (via probeFloors)
  // counted as used, but absent from the selector: no UI route to it and
  // re-import refused, i.e. the padId is burned. The index carries no security
  // decision (unauthenticated render metadata), so nothing about the ordering
  // rationale below requires it to be late; it must be early enough that a
  // durable pad is always reachable.
  writeIndexEntry(record, { exported: !!record.exported });
  localStorage.setItem(wmKey(record.padId), wmJson);
  // Plaintext "this pad has run on this device" marker. It carries no offsets
  // and is not trusted for a rollback decision — it exists so importPad, which
  // holds only the TRANSFER passphrase and so cannot open the record above, can
  // still refuse to resurrect a consumed pad from its (always pristine) file.
  localStorage.setItem(usedKey(record.padId), "1");
  // "Post-fix OTP has run on this device." Deletable like everything else here,
  // so it may only ESCALATE a warning, never authorise anything — see the
  // legacy-adoption gate in unlockPad.
  localStorage.setItem(EPOCH_KEY, "1");
  // F-1: mirror the floors into the native store, where they cannot be deleted
  // from the JS context and cannot be lowered at all. `armed` is passed so the
  // ROUND-3 F-4 commit-failure throw fires only for a slot this blob CLAIMS ARMED
  // — never for one probeFloors recorded CLAIM_UNCONFIRMED, which the adoption
  // gate already covers without failing the save.
  armFloors(record.padId, wm, !!record.exported, armed);
  wmCache.set(record.padId, { send: wm.send, recv: wm.recv });
}

// First save of a freshly generated/imported pad: derive a NEW at-rest key from
// the passphrase (PBKDF2 once) and encrypt. Returns the cached key for the
// session's cheap re-saves.
export async function saveNewPad(record, passphrase) {
  if (!passphrase) throw new Error("choose a pad passphrase to protect it on this device");
  // Pentest 2026-07-29 H-3, second half. This used to seed the cache at zero
  // unconditionally, so the very next writePadBlob overwrote the authenticated
  // watermark WITH ZEROS — the step that turned "delete three markers and
  // re-import" into a legitimate-looking v3 pad at offset 0 rather than
  // something unlockPad could refuse.
  //
  // A "new" pad must genuinely be new. The check is here as well as in
  // importPad because this is the function that destroys the record: any future
  // caller that reaches it with a used padId would rebuild the same hole, and
  // an argument about why the callers are safe is not a control.
  if (nativeFloor && nativeFloor.broken) throw floorUnavailableError();
  if (padWasUsed(record.padId)) {
    throw new Error(
      "this pad has already been used on this device — saving it as new would erase its usage record and reuse key material. Generate and exchange a fresh pad in person.",
    );
  }
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const key = await deriveKey(passphrase, salt, KDF_ITERS);
  // Belt and braces: seed from whatever floors DID survive rather than from
  // zero, so even a bypass of the refusal above cannot lower the watermark.
  // For a genuinely new pad every source is absent and this is {0,0}.
  const survivingNative = nativeFloor ? nativeFloor.read(record.padId) : NATIVE_ABSENT;
  wmCache.set(record.padId, {
    send: maxOf(readLegacyHW(record.padId), survivingNative > NATIVE_ABSENT ? survivingNative : 0),
    recv: 0,
  });
  await writePadBlob(record, key, salt, KDF_ITERS);
  return { key, salt, iters: KDF_ITERS };
}

// Re-save consumption progress during a session using the already-derived key
// (no PBKDF2). `atRest` = { key, salt, iters } from unlock/saveNewPad.
export async function savePadProgress(record, atRest) {
  // Item 13, third pass: `unlockPad`, `saveNewPad` and `importPad` all gate on a
  // broken bridge, but this did not — and `app.js` caches {record, atRest} per
  // pad for the whole session, so after one successful unlock every per-message
  // save reached `writePadBlob` with no native-floor check at all. A bridge that
  // broke mid-session was therefore invisible to the writer.
  if (nativeFloor && nativeFloor.broken) throw floorUnavailableError();
  await writePadBlob(record, atRest.key, atRest.salt, atRest.iters);
}

// Decrypt a stored pad with its passphrase -> { record (bytes+offsets), atRest }.
// `opts.adoptLegacy` — the caller has shown the user the F-1 warning and they
// chose to adopt a pad whose consumption cannot be verified. Never default it to
// true: silent adoption IS the vulnerability.
export async function unlockPad(padId, passphrase, opts = {}) {
  const raw = localStorage.getItem(padKey(padId));
  if (!raw) throw new Error("no such pad on this device");
  const o = JSON.parse(raw);
  const salt = unb64(o.kdf.salt);
  const iters = o.kdf.iters || KDF_ITERS;
  const key = await deriveKey(passphrase, salt, iters);
  let plain;
  try {
    plain = new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: unb64(o.iv) }, key, unb64(o.ct)));
  } catch {
    throw new Error("wrong pad passphrase (or the stored pad is corrupted)");
  }
  const inner = JSON.parse(decU.decode(plain));
  plain.fill(0);
  const sendOffset = inner.sendOffset | 0;
  const recvHighWater = inner.recvHighWater | 0;

  // P-01: take every security-relevant field from INSIDE the AEAD. A v1 blob
  // kept them outside; it is migrated to v2 on first unlock (below), which binds
  // them from here on.
  //
  // The legacy discriminator MUST come from the authenticated plaintext, never
  // from the outer JSON. A first cut of this fix tested `(o.v || 1) < PAD_BLOB_V`
  // — an outer, unauthenticated byte — so simply DELETING `"v"` from a stored v2
  // blob (leaving kdf/iv/ct untouched, so it still decrypts under the victim's
  // real passphrase) downgraded it back onto the legacy path, handing `role`
  // back to the attacker and skipping the padId binding check: a full two-time
  // pad, exactly what this fix removes. A genuine v1 plaintext has no `padId`
  // inside the ciphertext, and forging that would require breaking AES-GCM, so
  // the inner shape is a discriminator an attacker cannot influence.
  const legacy = inner.padId === undefined;
  const src = legacy ? o : inner;
  if (!legacy && inner.padId !== padId) {
    throw new Error("stored pad does not match its storage key — refusing to use it");
  }

  // M-01 / H-3 / M-7: refuse a pad whose consumption has been rolled back below
  // the highest offset we ever recorded — that reuses already-spent keystream
  // (send side) or re-accepts already-delivered frames (receive side). Runs
  // AFTER the identity check above, so the more specific "this blob is not the
  // pad you asked for" verdict wins over "its rollback record is missing".
  //
  // P-01: everything here is keyed on the REQUESTED id (the storage key the
  // caller asked for), never on an id read out of the blob being validated —
  // and the record binds the padId inside its own AEAD for the same reason, so
  // re-keying an old watermark under a fresh id cannot read as a clean slate.
  const outerWm = await readWatermark(padId, key);
  if (outerWm === "corrupt") {
    throw new Error(
      "the rollback record for this pad is damaged or forged — refusing to use the pad; exchange a fresh one",
    );
  }

  // F-1: the native floor, where available, is the one input to this decision an
  // attacker holding the JS context cannot touch. Read it BEFORE the localStorage
  // evidence so a forged bridge answer cannot be masked by a clean-looking store.
  if (nativeFloor && nativeFloor.broken) throw floorUnavailableError();
  const native = nativeFloor ? nativeFloor.read(padId) : NATIVE_ABSENT;
  if (native === NATIVE_TAMPERED) {
    throw new Error(
      "this pad's device-protected rollback record is damaged or forged — refusing to use the pad; exchange a fresh one",
    );
  }
  // A floor recorded natively but no authenticated record beside it means the
  // record was deleted: the H-3 PoC, and the v2-shaped variant it used to escape
  // through. Unlike `usedKey`, this evidence is not deletable from JS.
  if (native > NATIVE_ABSENT && outerWm === null) {
    throw new Error(
      "the rollback record for this pad is missing — refusing to use the pad, because pad reuse could no longer be detected; exchange a fresh pad",
    );
  }
  // F-ATREST-001/002: the two floors the send floor never covered. Read them in
  // the same breath as the send floor and for the same reason — they are the one
  // input here an attacker holding the JS context cannot touch.
  const nativeRecv = nativeFloor ? nativeFloor.read(floorKeyRecv(padId)) : NATIVE_ABSENT;
  const nativeExported = nativeFloor ? nativeFloor.read(floorKeyExported(padId)) : NATIVE_ABSENT;
  if (nativeRecv === NATIVE_TAMPERED || nativeExported === NATIVE_TAMPERED) {
    throw new Error(
      "this pad's device-protected rollback record is damaged or forged — refusing to use the pad; exchange a fresh one",
    );
  }
  // F-ATREST-002. `exported` is a one-way latch: exporting a pad twice hands the
  // same keystream to two devices, which is a two-time pad — the one failure OTP
  // cannot survive. The flag lived only inside the blob, so restoring a
  // pre-export snapshot silently re-armed export. The native latch never lowers,
  // so it outlives any restore of the blob.
  if (nativeExported >= 1 && !inner.exported) {
    throw new Error(
      "this pad was already exported once, but its stored copy says otherwise — refusing to use it, because exporting the same pad twice would reuse key material; exchange a fresh pad",
    );
  }
  // …and the converse (2026-07-29 H-1): a blob written WHILE a floor was in
  // force, with the floor now gone. Removing `clear()` from the bridge closed
  // the JS route to this state, but file-level access can still delete the
  // prefs entry, and that used to be completely silent — ABSENT reads as "no
  // floor", so neither the branch above nor the max() below notices. `inner.nativeFloor`
  // is inside the AEAD, so it cannot be stripped to hide the deletion.
  if (inner.nativeFloor === true && native === NATIVE_ABSENT) {
    throw new Error(
      "this pad's device-protected rollback record has been deleted — refusing to use the pad, because pad reuse could no longer be detected; exchange a fresh pad",
    );
  }
  // Pentest 2026-08-08 item 13, and the same bug one level down: the guard above
  // covers the SEND slot ONLY, because `native` is the send slot. Each derived id
  // is its own SharedPreferences entry, so deleting one is one file edit — and
  // both derived slots then read as ABSENT, which every consumer below treats as
  // "no floor":
  //
  //   * `#exported` ABSENT ⇒ the F-ATREST-002 latch check reads "never exported".
  //     With a pre-export snapshot restored beside it, that is a SECOND export of
  //     a pristine pad — two devices, one keystream, a two-time pad. The one
  //     failure OTP cannot survive.
  //   * `#recv` ABSENT ⇒ it contributes 0 to the recv max() below, reopening the
  //     M-7 replay window the slot was added to close.
  //
  // Deletion is destruction, and destruction must fail closed — the same rule
  // PadFloor.kt's own header states, applied to the slots that fix added. The
  // F-ATREST-002 comment above ("the native latch never lowers, so it outlives
  // any restore of the blob") was true only of LOWERING; it did not hold against
  // removal, and does now because of this check.
  //
  // Gated on `derivedFloors` — see writePadBlob for why it cannot be gated on
  // `nativeFloor`. One residual, stated plainly: a blob written by this branch
  // BETWEEN the F-ATREST-001/002 fix and this one has the derived slots but not
  // the marker, so it keeps the old behaviour until its next save rewrites it.
  // The branch has never been merged or deployed, so that window is this working
  // tree only.
  if (inner.derivedFloors === true &&
      (nativeRecv === NATIVE_ABSENT || nativeExported === NATIVE_ABSENT)) {
    throw new Error(
      "this pad's device-protected rollback record has been deleted — refusing to use the pad, because pad reuse could no longer be detected; exchange a fresh pad",
    );
  }
  // Evidence that this pad has run here UNDER THE POST-FIX CODE, i.e. that a
  // watermark record must once have existed. Both sources are written only by
  // this version: `hwSend`/`hwRecv` live inside the AEAD and only a v3 blob
  // carries them, and `usedKey` is stamped by unlockPad below.
  //
  // The legacy plaintext watermark is deliberately NOT evidence here. It is
  // written only by PRE-fix code, so it is present on exactly the pads that
  // legitimately have no record yet — including it refused every used pre-fix
  // pad outright (found on-device 2026-07-28: a v2 blob at sendOffset 1234 with
  // `sc.otp.hw.v1` = 1234 was rejected as "rollback record missing", while a
  // pristine one migrated fine). It stays load-bearing where it belongs: as a
  // floor in the max() below. That is also all it can bear — it is
  // attacker-writable plaintext, per readLegacyHW's own note.
  //
  // Do NOT be tempted to key this on the outer `v` byte instead: it is outside
  // the AEAD, and deleting it is the downgrade trap documented at the top of
  // unlockPad. `inner.hwSend` is the authenticated way to ask the same question.
  const knownUsedHere = Number.isInteger(inner.hwSend) || Number.isInteger(inner.hwRecv) ||
    localStorage.getItem(usedKey(padId)) !== null;
  if (outerWm === null && knownUsedHere) {
    // H-3: this is the reported PoC — restore an old blob, delete the watermark.
    // A pad that has demonstrably run on this device but can no longer produce
    // its watermark FAILS CLOSED. (No record AND no evidence = a pad written
    // before this fix, adopted below.)
    throw new Error(
      "the rollback record for this pad is missing — refusing to use the pad, because pad reuse could no longer be detected; exchange a fresh pad",
    );
  }
  // max(outer, inner, legacy, native): each is a floor this device is known to
  // have passed, so the highest of them is the truth.
  const wm = {
    send: maxOf(
      outerWm ? outerWm.send : 0,
      inner.hwSend | 0,
      readLegacyHW(padId),
      native > NATIVE_ABSENT ? native : 0,
    ),
    // F-ATREST-001: the native recv floor joins the same max(). Without it a
    // recv rollback was undetected even on Android — the AEAD record and its
    // mirror can both be restored from one snapshot, and then every OTP frame
    // the peer already sent authenticates again as fresh.
    recv: maxOf(
      outerWm ? outerWm.recv : 0,
      inner.hwRecv | 0,
      nativeRecv > NATIVE_ABSENT ? nativeRecv : 0,
    ),
  };
  if (sendOffset < wm.send) {
    throw new Error("pad state was rolled back (consumed key material) — refusing to use it; exchange a fresh pad");
  }
  if (recvHighWater < wm.recv) {
    // M-7: no keystream is reused, but every OTP frame the peer already sent
    // would authenticate again as fresh — the anti-replay guarantee, gone.
    throw new Error("pad receive state was rolled back (already-delivered messages could replay) — refusing to use it; exchange a fresh pad");
  }

  // F-1: adopting a v2/v1 blob means accepting consumption state NOTHING can
  // verify — there is no authenticated floor for it, by definition. Doing that
  // SILENTLY was the vulnerability: an attacker restores a v2 snapshot, deletes
  // the deletable markers, and the pad quietly reopens at offset 0.
  //
  // So it is no longer automatic. The caller must ask for it explicitly, which
  // means the user sees it and can recognise "this pad has no usage record" as
  // wrong for a pad they have been using. The native floor above already refuses
  // the attack outright on Android; this gate is what protects the browser,
  // where no such floor exists, and it is the honest control there: user
  // attention, because there is no cryptographic one to reach for.
  //
  // DELIBERATELY AFTER the two rollback checks. Adoption is consent to accept
  // state that cannot be VERIFIED — never permission to override a rollback that
  // has actually been DETECTED. A pad whose legacy watermark or native floor
  // already proves it ran further than this blob claims is refused outright, and
  // no `adoptLegacy` can reopen it.
  //
  // `EPOCH_KEY` and `usedKey` only ESCALATE the wording. They are deletable, so
  // depending on them would rebuild the hole this closes; their absence must
  // never turn the gate off.
  // A4/F-A3: a blob sealed while the native floor could not be armed carries a
  // claim nothing can check. That is exactly the "consumption state nothing can
  // verify" the gate below exists for, so it takes the same route rather than
  // opening silently on a claim that both unlock guards are structurally unable
  // to test. Unlike the legacy case this does not require `outerWm === null`: the
  // watermark is deletable, so requiring its absence would let one `removeItem`
  // turn the gate off.
  const floorUnconfirmed = inner.nativeFloor === CLAIM_UNCONFIRMED ||
    inner.derivedFloors === CLAIM_UNCONFIRMED;
  const needsAdoption = floorUnconfirmed ||
    ((legacy || (o.v || 1) < PAD_BLOB_V) && outerWm === null);
  if (needsAdoption && !opts.adoptLegacy) {
    const err = new Error(floorUnconfirmed
      ? "this pad was saved while this device could not write its tamper-proof usage record, so nothing here can prove whether the pad has been rewound. If it has ever sent a message, it is NOT safe to use — exchange a fresh one."
      : "this pad has no usage record on this device. If it has ever sent a message, that record has been deleted and the pad is NOT safe to use — exchange a fresh one.",
    );
    err.code = "LEGACY_PAD_ADOPTION";
    err.padId = padId;
    // Which of the two unverifiable states this is, so the UI can escalate with a
    // sentence that is TRUE of it (F-A3). "No usage record at all" and "the record
    // could not be written when this pad was last saved" are different facts, and
    // the warning that should stop the user differs accordingly.
    err.reason = floorUnconfirmed ? "unarmable-floor" : "legacy";
    // True = this device has demonstrably run OTP under the current code, so a
    // pad with no record is a much stronger signal of tampering than it would be
    // on a device that just upgraded.
    err.suspicious = localStorage.getItem(EPOCH_KEY) !== null ||
      localStorage.getItem(usedKey(padId)) !== null;
    throw err;
  }
  wmCache.set(padId, wm);
  const regionSize = src.regionSize;
  const role = src.role;
  if (role !== 0 && role !== 1) throw new Error("stored pad has an invalid role");
  if (!Number.isInteger(regionSize) || regionSize <= 0) {
    throw new Error("stored pad has an invalid region size");
  }
  const bytes = unb64(inner.bytes);
  if (bytes.length !== 2 * regionSize) {
    throw new Error("stored pad is internally inconsistent — refusing to use it");
  }
  const record = {
    padId,
    label: src.label,
    regionSize,
    role,
    createdAt: src.createdAt,
    bytes,
    sendOffset,
    recvHighWater,
    // L-3: authenticated in v3; a v1/v2 blob falls back to the plaintext index
    // ONCE, on the unlock that upgrades it, after which the flag is covered.
    //
    // F-2 (review of bf6bcd2): that fallback took the plaintext index value
    // outright, so flipping the index to `false` BEFORE the migrating unlock
    // baked `false` into the AEAD permanently and disarmed the double-export
    // warning for good — one pristine pad to two importers, a two-time pad by
    // construction.
    //
    // OR-ing the two sources does NOT fix it: a v1/v2 blob has no `exported`
    // inside the AEAD at all, so the flipped index is the only source and the
    // answer is still `false`. There is nothing to recover here — the flag was
    // never authenticated on these blobs — so the only honest move is the same
    // one the F-1 gate makes about consumption state: when it cannot be
    // verified, assume the WORST. An adopted legacy pad is treated as possibly
    // already exported, which costs a confirm on re-export and closes the
    // laundering path. The user adopting it has just been told, in as many
    // words, that this pad's history cannot be verified.
    exported: inner.exported !== undefined
      ? !!inner.exported
      : true,
  };
  const atRest = { key, salt, iters };
  // Rewrite a genuine legacy blob in the v2 (fully authenticated) format
  // immediately, so the window in which its metadata is unauthenticated is one
  // unlock long and it can never be downgraded again.
  //
  // HONEST RESIDUAL, limited to blobs written before this fix: a v1 blob's
  // role/regionSize genuinely live outside the AEAD, so tampering done while it
  // was still v1 cannot be detected retroactively — no change here can recover
  // information that was never authenticated. What IS now guaranteed: a v2 blob
  // cannot be downgraded to obtain that weakness, and every blob becomes v2 on
  // its first unlock.
  //
  // A v2 blob is rewritten for the same reason one version later: it carries no
  // authenticated watermark and no authenticated `exported` flag, and the sooner
  // it does the sooner H-3/M-7/L-3 apply to it.
  if (legacy || (o.v || 1) < PAD_BLOB_V) await writePadBlob(record, key, salt, iters);
  return { record, atRest };
}

// Record that a pad has been exported (shared). Used to warn on re-export, which
// risks distributing one pad to more than one importer (-> key reuse).
//
// L-3: this used to write the plaintext index and nothing else, so clearing one
// unauthenticated field removed the only warning standing between a user and
// exporting one pristine pad to two importers — a two-time pad by construction.
// The flag now lives inside the pad's AEAD, which is why this needs the
// unlocked record and its at-rest key. The index copy is kept in step purely as
// a render cache for the pad list (which has no passphrase to hand).
export async function markExported(record, atRest) {
  // Same gate as savePadProgress (item 13, third pass). This one matters more:
  // it is the write that latches the one-way `exported` flag.
  if (nativeFloor && nativeFloor.broken) throw floorUnavailableError();
  record.exported = true;
  await writePadBlob(record, atRest.key, atRest.salt, atRest.iters);
}

// Forget a pad locally. Pentest 2026-07-26 P-05: the rollback watermark is
// deliberately KEPT. It used to be deleted here, which made "Forget pad" the
// easiest route to a two-time pad: an export file is always pristine
// (`exportPad` refuses a used pad), and the duplicate-import guard is an index
// lookup this function clears — so *Forget → re-import the same file* resurrected
// the pad at sendOffset 0 with a clean tripwire and every later message reused
// keystream the peer had already seen. That path is reachable by accident ("it
// wasn't working, let me re-import"), not just by an attacker. The watermark is
// a few bytes; keeping it lets `importPad`/`unlockPad` refuse the resurrection.
export function forgetPad(padId) {
  localStorage.removeItem(padKey(padId));
  localStorage.setItem(LS_INDEX, JSON.stringify(readIndex().filter((e) => e.padId !== padId)));
}

// True if this device has ever recorded consumption for `padId` — i.e. the pad
// was used here before, so re-importing the pristine file would rewind it.
//
// This is the ONE watermark reader that cannot authenticate what it reads:
// importPad holds the pad file's TRANSFER passphrase, not the at-rest passphrase
// that opens the authenticated record, and after `forgetPad` there is no blob to
// derive a key from anyway. It therefore answers from evidence-of-presence,
// which is the fail-CLOSED direction: extra evidence can only cause a refusal,
// never an acceptance. Rollback decisions that CAN be authenticated are made in
// unlockPad, against the AEAD record.
//
// Pentest 2026-07-29 H-3: the three localStorage markers below are ALL
// deletable, and this function was the only guard on the import path — so
// `removeItem` x3, then re-import the (always pristine) pad file, rebuilt a
// LEGITIMATE v3 pad at offset 0. No adoption prompt was possible, because the
// result is a genuine v3 blob with a matching fresh watermark rather than a
// legacy one. In the browser that is a permanent two-time pad.
//
// The native floor is the one input here an attacker holding the JS context
// cannot delete, so it is consulted FIRST and it is decisive. It is also the
// only one that survives the deletions, which is precisely why the PoC worked.
export function padWasUsed(padId) {
  if (nativeFloor && nativeFloor.broken) return true;   // fail closed
  if (nativeFloor) {
    const send = nativeFloor.read(floorKeySend(padId));
    const recv = nativeFloor.read(floorKeyRecv(padId));
    const exported = nativeFloor.read(floorKeyExported(padId));
    // TAMPERED (a forged record, or a marker with no working bridge) counts as
    // used: an import must never be the way to escape a damaged floor.
    // NATIVE_COMMIT_FAILED is folded in for the same reason and defensively:
    // `read` does not return it today (only bump does), but a floor whose durable
    // write failed must never become the crack an import escapes through — fail
    // CLOSED, exactly like TAMPERED.
    if (send === NATIVE_TAMPERED || recv === NATIVE_TAMPERED || exported === NATIVE_TAMPERED
      || send === NATIVE_COMMIT_FAILED || recv === NATIVE_COMMIT_FAILED || exported === NATIVE_COMMIT_FAILED) return true;
    // F-A1-R1 (pentest of the F-A1 fix): "a slot exists" is NOT "the pad ran".
    // `probeFloors` creates all three slots at exactly 0 BEFORE the blob is
    // written, so a first save interrupted before the blob lands — a failed
    // write, a kill between the JNI probe and the setItem — used to answer true
    // here and BURN the padId, for a pad that spent no keystream at all. The two
    // people then have to exchange a pad in person again.
    //
    // So the probe-only triple (0, 0, 0) is not by itself evidence: it falls
    // through to the localStorage markers below, exactly like a device with no
    // native floor. Anything ABOVE 0 in any slot IS evidence and is decisive —
    // real send/recv consumption or an export latch — and that is the state H-3
    // is about (delete the deletable markers, re-import a consumed pad), so that
    // refusal is unchanged: those floors are undeletable and never lowered.
    if (send > 0 || recv > 0 || exported > 0) return true;
  }
  return localStorage.getItem(usedKey(padId)) !== null ||
    localStorage.getItem(wmKey(padId)) !== null ||
    readLegacyHW(padId) > 0;
}
