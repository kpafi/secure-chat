// The identity blob AT REST: writing it, opening it, and deciding whether the
// copy on disk is the one this device last wrote.
//
// Pentest 2026-08-07 F-ATREST-008 — "the identity blob has no anti-rollback
// control" — fixed 2026-09-16. Why it mattered more than its original "low":
// the F-ATREST-003/004 fix moved the contact store's anti-deletion anchor into
// the identity's AEAD (identity.js `deviceFlags`), on the argument that an
// attacker cannot forge or strip it without the passphrase. True — but they
// never needed to. They ROLL THE BLOB BACK: a saved older `sc.identity.v1`
// opens on the same passphrase with the same keys, fingerprint and safety
// number, carries no `flags`, and every anchor reads "not established", so the
// contact store's deletion check takes its "genuine first run" path and hands
// out an empty, pin-less store. And every blob written before the flags
// existed IS such a copy, so on every device the archived artifact was already
// in hand. Cost to the attacker: one setItem plus the two removeItem calls
// they already had.
//
// The shape of the fix is the one this project already uses twice (the OTP
// watermark, the contact-store generation witness): a monotone counter INSIDE
// the AEAD, and a copy of it somewhere the JS context cannot lower. On Android
// that somewhere is the Keystore-MACed native floor (PadFloor.kt), which keys
// slots by an opaque string and has no lowering or deleting operation — so the
// identity gets a slot of its own with no Kotlin change. In a plain browser
// there is nothing the page cannot delete, and the residual stands, exactly as
// it does for OTP (README, "OTP's guarantee is materially stronger in the app").
//
// What a bad verdict DOES is the part worth reading. It does NOT refuse to
// unlock. The identity's keys are the same in every version of the blob; what
// a rollback buys is the anchor flags reading false, and only that. So on any
// verdict short of "ok" — rollback, floor deleted, floor tampered, floor
// expected but unusable — every anchor is read as ESTABLISHED (fail closed):
// a store that is genuinely there opens as before, and a store that has been
// deleted trips the alarm F-ATREST-003 exists to raise. Refusing the unlock
// instead would turn a non-adversarial failure (below) into a permanent
// lock-out from the user's own keys, which is the brick-with-the-alarm's-
// wording outcome otp.js's probeFloors note already rules out.
//
// The non-adversarial failure, named so nobody "fixes" it into a refusal:
// WebView localStorage is flushed to disk asynchronously, SharedPreferences
// `commit()` is synchronous, and the floor is bumped only AFTER `setItem`
// returns. A process kill in the seconds after a write can therefore leave the
// floor one ahead of the blob that actually reached disk. That reads as a
// rollback here, the anchors fail closed (correct in practice — a store that
// was there is still there), the user sees one warning, and the very next
// write re-converges the counter. Nothing is lost. The opposite kill window —
// blob written, floor not yet bumped — leaves the floor BEHIND the blob, which
// is benign and is never reported.
//
// THE FLOOR IS CAPTURED AT LOAD, AND THERE IS NO SETTER. The first cut of this
// module took the floor through an exported `setIdentityFloor()` plus a
// `_resetForTests()`, which the pentest of the change (2026-09-16, F-9) pointed
// out ship in the APK and put `judge()` permanently in the "plain browser"
// branch with one same-realm call. otp.js already solved this for pads: the
// bridge is read from a non-configurable global once, at module load, and
// nothing can be injected later because there is nothing to inject into. So
// this module does the same, through otp.js's `deviceFloor()` (a fresh facade
// over the one captured bridge — see the F-2 note there). Tests that need a
// different floor start a fresh process; see identity-store.test.mjs.
//
// RESIDUALS, stated (pentest of this change, F-4 / F-8):
//  * The deletion alarm relies on the BLOB's claim that a floor was in force.
//    An attacker with app-data access (root) who deletes the slot AND restores
//    a blob that claims nothing — every pre-fix blob is one — gets a clean
//    verdict, because ABSENT-and-nothing-claimed is exactly what a first run
//    looks like. This is weaker than the OTP analogue, where a pad blob is
//    always written on a device that had a floor and so always claims one.
//    Closing it needs a second durable witness that root cannot delete, which
//    the platform does not offer; it is the same power that can uninstall the
//    app. What root cannot do is rewind: once a device has recorded a
//    generation, every OLDER blob is caught, whatever it claims.
//  * A forced anchor is LATCHED: `anchorEstablished` sets the flag under a bad
//    verdict, and the heal write seals it. When no store exists — the
//    attacker's deletion, or the same unflushed first write that lost the blob
//    in the crash window above — that leaves the contact store refusing to
//    open on every later unlock, verdict clean or not. The two cases are the
//    SAME state on disk, so no policy here can tell them apart (fix review
//    round 2, F-2). The recovery is not "forget the identity": contacts.js and
//    chats.js take `startFresh`, a consent gate app.js offers only behind the
//    deletion alarm and a confirm() — the OTP adoption gate's trade, again.
//  * The anchor FLAGS are last-writer-wins across tabs. The generation
//    converges (a stale tab writes past the floor), but a stale tab that never
//    saw a flag set by another tab writes a blob without it, and this module
//    then certifies that blob as current. Pre-existing at HEAD; the fix would
//    be to mirror the one-shot flags into floor slots of their own, which is
//    deferred and tracked in PROGRESS.md.
//
// Node-testable by construction: no DOM, no module-scope storage access; the
// `localStorage` global is read at call time.

import { deviceFloor } from "./otp.js";

export const LS_IDENTITY = "sc.identity.v1";

// The floor slot. A pad id is 32 hex characters (otp.js randomId), so a name
// containing "." and "#" cannot collide with one; the `#` mirrors otp.js's
// derived-slot convention. PadFloor MACs the slot name together with the
// value, so this floor cannot be lifted from a pad's slot or vice versa.
export const FLOOR_SLOT = "sc.identity.v1#gen";

// Sentinels, mirroring otp.js / PadFloor.kt. Duplicated as literals rather
// than imported so the only thing taken from otp.js is the bridge itself.
const NATIVE_ABSENT = -1;
const NATIVE_TAMPERED = -2;
const NATIVE_COMMIT_FAILED = -3;

// Same three claim values as otp.js (A4/F-A3), for the same reasons.
const CLAIM_ARMED = true;
const CLAIM_NONE = false;
const CLAIM_UNCONFIRMED = "unconfirmed";

// Counters go through `bump(id, v | 0)` on the JS side of the bridge, so they
// must stay well inside int32. A device would need two billion identity writes
// to get here; refusing loudly is still better than wrapping negative, which
// PadFloor would then refuse to record and the floor would silently stop.
// (Anyone in the page realm can call the frozen bridge's `bump` directly and
// park a slot at this ceiling — that is the documented "can destroy, cannot
// rewind" power, the same one that can brick any pad, and not new here.)
const MAX_GENERATION = 0x7fffffff - 1;
// Only language constructs — `Number.isInteger` is a writable global (H-1).
const isGen = (v) => typeof v === "number" && (v | 0) === v && v >= 0;

// Captured once, at load. `null` in a plain browser; `broken` when the app's
// marker says a floor should exist and none is usable.
const floor = deviceFloor();
const usable = floor !== null && floor.broken !== true;

let verdict = { ok: true }; // for the identity currently open (see openIdentity)

function readFloor() {
  return floor.read(FLOOR_SLOT);
}

// Write `identity` to localStorage under a FRESH generation, then raise the
// floor to it. Every write of the identity blob goes through here — app.js is
// pinned to that by identity-store.test.mjs, because one `setItem(LS_IDENTITY,
// …)` elsewhere would write a blob whose counter the floor never learns of.
//
// Ordering, and why: claim measured before the write (probe cannot advance
// anything), blob written, THEN the floor raised — so the floor is never above
// a blob that exists on disk, except through the async-flush window described
// at the top, which is reported but never fatal. This is armFloors' ordering
// argument from otp.js (F-A1), applied here.
//
// Returns { generation, armed, warning } — `warning` is a string the caller
// should show when the floor could not durably record the new generation, and
// null otherwise. Throws only when localStorage refuses the write or the
// counter would leave int32. A TAMPERED slot does NOT throw (pentest of this
// change, F-6): it used to, and that made a device with one forged prefs entry
// unable to CREATE an identity at all — a regression against plain setItem.
// The blob is written claiming an UNCONFIRMED floor instead, the caller is
// warned, and every later open reports "tampered" with the anchors failing
// closed. Tampering is still never healed into a valid record (PadFloor's rule:
// bump on TAMPERED writes nothing).
export async function persistIdentity(identity, passphrase) {
  let current = NATIVE_ABSENT;
  let warning = null;
  // Pentest of this change, F-3: a claim is NEVER LOWERED. The first cut reset
  // it to CLAIM_NONE whenever the floor was not usable, so one session under a
  // broken bridge (or one write from a plain browser) turned a blob that
  // correctly claimed an armed floor into one that claims none — and the
  // deletion alarm could never fire for that identity again. A claim the
  // device cannot re-measure is carried forward if it was ARMED; otherwise a
  // plain browser keeps whatever it had (there is no floor to be unconfirmed
  // ABOUT), and a broken bridge records UNCONFIRMED, which claims nothing but
  // is not the `false` a plain browser writes (A4/F-A3).
  let claim = identity.floorClaim === CLAIM_ARMED
    ? CLAIM_ARMED
    : (floor === null ? identity.floorClaim : CLAIM_UNCONFIRMED);
  if (floor !== null && !usable) {
    // Marker says a floor should exist; none is usable. otp.js refuses every
    // pad in this state. The identity is the user's own keys, so it is
    // written anyway, and openIdentity reports the state as "unavailable"
    // with the anchors failing closed.
    warning = "this device's protected storage is not usable, so this identity's rollback guard could not be armed";
  }
  let measured = false;
  if (usable) {
    // `bump(_, 0)` creates an ABSENT slot at 0 and is a no-op on any existing
    // one (bump never lowers) — the probeFloors trick. Its own return is the
    // only witness to a failed commit (ROUND-3 F-4): the read-back after a
    // failed commit looks healthy, because PadFloor.read is backed by the
    // in-memory map that commit() already mutated.
    const probe = floor.bump(FLOOR_SLOT, 0);
    current = readFloor();
    // Any negative answer other than "the durable write failed" is evidence —
    // the same fold judge() uses (fix review round 3, F-4: this used to test
    // the two sentinels by name and let an unknown negative read as healthy).
    const forged = (v) => !(v >= 0) && v !== NATIVE_COMMIT_FAILED;
    if (forged(current) || forged(probe)) {
      current = NATIVE_ABSENT;
      claim = identity.floorClaim === CLAIM_ARMED ? CLAIM_ARMED : CLAIM_UNCONFIRMED;
      warning = "this device's protected record for your identity is damaged or forged — the identity was saved, " +
        "but its rollback guard cannot be relied on here. Forget the identity and restore it from a backup " +
        "if you have one";
    } else if (probe === NATIVE_COMMIT_FAILED || current < 0) {
      claim = identity.floorClaim === CLAIM_ARMED ? CLAIM_ARMED : CLAIM_UNCONFIRMED;
      warning = "this device could not durably record this identity's rollback guard (storage full or unwritable?)";
    } else {
      claim = CLAIM_ARMED;
      measured = true;
    }
  }
  // Next generation: past BOTH what this process last wrote and what the device
  // has durably recorded. The second term is what makes two tabs converge
  // instead of alarming each other — a tab that unlocked at generation N and
  // writes after another tab reached N+2 must write N+3, not N+1.
  let base = current > identity.generation ? current : identity.generation;
  if (!isGen(base)) { // language constructs only, like the verdict (H-1)
    throw new Error("identity write counter is malformed — refusing to write the identity");
  }
  let generation = base + 1;
  if (generation > MAX_GENERATION) {
    // Fix review round 2 (F-3): the frozen bridge's `bump` is callable from the
    // page, so a script can park the slot at the ceiling with one call. This
    // used to THROW, which made every later write — including CREATING an
    // identity — impossible until app data was cleared: the F-6 brick shape
    // through another door. Treat it like TAMPERED instead: write the blob at
    // its own counter with an unconfirmed claim and warn; `judge` then reports
    // the parked slot as a rollback on every open, so the anchors stay closed
    // (a DoS the attacker already has, never a bypass) while the identity
    // itself remains usable.
    // Fix review round 3 (F-1): the first cut of this branch fell back to the
    // blob's own counter and then re-applied the same ceiling test to it — so
    // a slot parked one BELOW the ceiling let one honest write stamp the
    // ceiling value into the blob, after which every write threw (the brick,
    // one value along, and with a CLEAN verdict so no banner said why). The
    // rule now: the blob is ALWAYS writable. At the ceiling it is written at
    // its own current counter, never advanced, never refused.
    generation = isGen(identity.generation)
      ? (identity.generation > MAX_GENERATION ? MAX_GENERATION : identity.generation)
      : 0;
    measured = false;
    claim = identity.floorClaim === CLAIM_ARMED ? CLAIM_ARMED : CLAIM_UNCONFIRMED;
    warning = "this device's protected record for your identity is at its ceiling — the rollback guard cannot " +
      "advance. Clearing the app's data and restoring the identity from a backup is the only repair";
  }
  identity.generation = generation;
  identity.floorClaim = claim;
  const blob = await identity.export(passphrase);
  localStorage.setItem(LS_IDENTITY, blob); // a QuotaExceededError propagates
  let armed = false;
  if (measured) {
    const r = floor.bump(FLOOR_SLOT, generation);
    if (r === NATIVE_COMMIT_FAILED) {
      // The blob is on disk; only the floor's durable copy lagged. The next
      // write bumps again. Report it — a rollback to exactly this blob would
      // go unnoticed while the floor lags — but there is nothing to undo.
      warning = "this device could not durably record this identity's rollback guard (storage full or unwritable?)";
    } else if (!(r >= generation)) {
      // TAMPERED, or any answer that does not cover what was just written.
      warning = "this device's protected record for your identity is damaged or forged";
    } else {
      armed = true;
    }
  }
  // A successful write makes the blob on disk the newest one, so any earlier
  // verdict about an OLDER copy is settled. app.js only calls this after a bad
  // verdict once every anchor has been read (and thereby forced established),
  // so the healed blob carries the fail-closed flags — see anchorEstablished.
  verdict = { ok: true };
  return { generation, armed, warning };
}

// Compare a just-opened identity against the device's durable record of it.
// Returns the verdict, plus `arm`: true when the verdict is clean but this
// device has not yet recorded this identity (no slot, or the blob does not
// claim an armed one) and a write would arm it.
//
// `arm` exists because of the pentest of this change (F-1, High): the first cut
// wrote only on a bad verdict or a pre-v3 upgrade, so on every EXISTING install
// — a v3 blob with both anchor flags already set — no write ever happened, the
// slot was never created, and the guard never armed. The finding was reopened
// unchanged on precisely the population it was written for. Adopting on read
// is the write that was missing: one PBKDF2 on the first unlock after the
// update, and from then on every older blob is caught.
export function judge(identity) {
  if (floor === null) return { ok: true, arm: false }; // plain browser: no floor, documented residual
  if (!usable) {
    return {
      ok: false,
      arm: false,
      reason: "unavailable",
      message: "this device says it has protected storage for your identity's rollback guard, but none is usable — " +
        "treating every saved store as present, so a deleted contact store will be reported rather than replaced",
    };
  }
  const f = readFloor();
  // Every negative answer except ABSENT is evidence, including ones no bridge
  // returns today (fix review round 2, F-5): an unrecognised negative used to
  // fall through every branch below to a CLEAN verdict — the fail-open shape
  // otp.js's padWasUsed folds in defensively for exactly this reason.
  if (f !== NATIVE_ABSENT && !(f >= 0)) {
    return {
      ok: false,
      arm: false,
      reason: "tampered",
      message: "this device's protected record for your identity is damaged or forged — " +
        "treating every saved store as present rather than trusting the identity file on its own",
    };
  }
  if (f >= MAX_GENERATION) {
    // Second review of store-floor.js (H-1), applied here too: a slot the
    // blob can never overtake is a permanent bad verdict, whatever put it
    // there — otherwise the blob freezes EQUAL to it and later states cannot
    // be told apart. Fail closed (anchors established), say so every unlock.
    return {
      ok: false,
      arm: false,
      reason: "exhausted",
      message: "this device's protected record for your identity is exhausted (its counter can no longer advance), " +
        "so a rollback could no longer be told from a save — treating every saved store as present",
    };
  }
  if (f === NATIVE_ABSENT) {
    if (identity.floorClaim === CLAIM_ARMED) {
      return {
        ok: false,
        arm: false,
        reason: "deleted",
        message: "this device's protected record for your identity has been DELETED — the identity file says one " +
          "was in force when it was last saved. Treating every saved store as present",
      };
    }
    // First write on this device, a pre-fix blob, or an unconfirmed slot:
    // nothing to compare against yet, so record one now.
    return { ok: true, arm: true };
  }
  // Review of 4b9d2c6..a88baa4 (Info-2): normalise ONCE, as store-floor.js
  // does, so a malformed counter cannot skip the exhaustion rule and then win
  // a JS-coerced `f > generation` (`f > Infinity` is false). Not reachable
  // today — import clamps, persist only ever stores an int — but the verdict
  // path must not depend on that.
  const gen = isGen(identity.generation) ? identity.generation : 0;
  if (gen >= MAX_GENERATION) {
    // The symmetric half of the exhaustion rule (see store-floor.js): a blob
    // whose own counter can no longer advance is as unfalsifiable as a slot it
    // can never overtake, and when the counter is PAST the ceiling the bump is
    // refused too, so `f > generation` never fires again.
    return {
      ok: false,
      arm: false,
      reason: "exhausted",
      message: "this device's record of your identity can no longer advance (its counter is exhausted), " +
        "so a rollback could no longer be told from a save — treating every saved store as present",
    };
  }
  if (f > gen) {
    return {
      ok: false,
      arm: false,
      reason: "rollback",
      message: `the identity file on this device is OLDER than this device's record of it (generation ` +
        `${gen}, device recorded ${f}) — it has been restored from an earlier copy, or a save ` +
        "did not reach disk. Treating every saved store as present, so a deleted contact store is reported " +
        "rather than replaced; if you have a newer backup, restore it",
    };
  }
  // A slot exists and the blob is not behind it, but the blob itself does not
  // yet say so (a pre-fix blob after the probe created the slot at 0, or a
  // write whose create-bump did not commit): arm, so the deletion alarm has
  // a claim to stand on.
  return { ok: true, arm: identity.floorClaim !== CLAIM_ARMED };
}

// Open the identity stored on this device. `importer` is Identity.import,
// passed in so this module does not pull identity.js (and its post-quantum
// dependency) into every test that only wants the storage logic. Throws
// exactly what the importer throws (wrong passphrase, malformed blob); a bad
// at-rest verdict is NOT an error, it is returned.
export async function openIdentity(passphrase, importer) {
  const blob = localStorage.getItem(LS_IDENTITY);
  if (!blob) throw new Error("no identity on this device");
  const identity = await importer(blob, passphrase);
  verdict = judge(identity);
  return { identity, verdict };
}

// The anchor read app.js installs into contacts.js / chats.js. Under a clean
// verdict it is the flag itself. Under any other verdict it is TRUE — and the
// flag is SET, deliberately, from inside a read: the next persistIdentity
// (which app.js triggers right after installing the anchors on a bad verdict)
// must carry the conservative answer into the healed blob, or a rolled-back
// blob would be re-labelled as current with its flags still absent and the
// attacker would simply need two unlocks instead of one. This holds for EVERY
// non-ok verdict, not only "rollback" — the test pins all four.
export function anchorEstablished(identity, flag) {
  if (!verdict.ok) {
    identity.deviceFlags[flag] = true;
    return true;
  }
  return identity.deviceFlags[flag] === true;
}
