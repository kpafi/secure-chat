// A native-floor mirror for the two encrypted stores' generation counters.
//
// Phase-7 pentest 2026-09-16, F-P7-6 (the last runtime Medium of that report,
// PROGRESS item 7b). contacts.js and chats.js each keep a monotone generation
// inside their AEAD and a witness beside the store — but both live in
// localStorage, so a device-local attacker who snapshots and restores BOTH
// keys rewinds the store undetected. With a healthy Android floor, an
// established anchor and a clean identity verdict, restoring
// `sc.contacts.v1` + `sc.contacts.gen.v1` from before an in-person
// re-verification brought back the SUPERSEDED pin with no alarm, and
// `sameBundle(pin, bundle) -> unlockMessaging()` walked in — the
// post-compromise-revocation failure F-ATREST-007 exists to close. The
// 2026-08-07 report's remediation #1 named "the contact-store generation
// witness" explicitly; the branch built the primitive for the identity blob
// (identity-store.js) and left these two behind.
//
// Same shape as identity-store.js, shared by both stores: the store's
// generation is bumped into a Keystore-MACed slot after every write
// (PadFloor.kt keys slots by an opaque string and MACs key with value — zero
// Kotlin), and the store's plaintext carries a CLAIM about the floor so a
// later ABSENT slot is evidence of deletion rather than a first run. Ordering
// is armFloors' (F-A1): claim measured BEFORE the write (a probe cannot
// advance anything), value raised AFTER it, so the floor is never above a
// store that exists on disk — except through the WebView's asynchronous
// localStorage flush, which is reported and never fatal.
//
// WHAT A BAD VERDICT DOES — deliberately NOT a refusal, and (after the review
// of the first cut) deliberately NOT destruction either. The identity blob
// fails its anchors closed and stays usable; the stores fail their TRUST
// closed and stay open: contacts.js marks every pin SUSPECT — the pin stays,
// but app.js's renderVerify refuses to auto-unlock on a suspect pin and shows
// the loud "re-verify" prompt instead, until an in-person check writes a
// fresh pin — and marks every contact "verify again"; chats.js keeps every
// negotiated mode and secret (a stale secret fails loudly on the wire, and
// the secret exists nowhere else) and names what a rollback can have undone.
// The first cut DROPPED every pin and every secret, which turned the crash
// window below into fifty re-verifications and a lost shared passphrase from
// one process kill, and — with no tombstone filed — rendered the next
// arrival as a benign first contact (the M-2 alarm inversion). Refusing to
// open would be worse still: a permanent lock-out with "start over" as the
// only exit.
//
// Captured at load from otp.js's one bridge; there is no setter (F-9 of the
// F-ATREST-008 reviews). In a plain browser `floor` is null and every function
// here is a no-op that reports "no floor": the documented residual stands.

import { deviceFloor } from "./otp.js";

const NATIVE_ABSENT = -1;
const NATIVE_COMMIT_FAILED = -3;

const CLAIM_ARMED = true;
const CLAIM_NONE = false;
const CLAIM_UNCONFIRMED = "unconfirmed";

const MAX_GENERATION = 0x7fffffff - 1;

// Review of the first cut (F-2): `Number.isInteger` is a writable global, and
// routing the verdict through it was the H-1 poisoning shape otp.js was fixed
// for twice — here it failed OPEN (a lie made the slot never leave 0). Only
// language constructs: `typeof` and the int32 truncation test.
const isGen = (v) => typeof v === "number" && (v | 0) === v && v >= 0;

const floor = deviceFloor();
const usable = floor !== null && floor.broken !== true;

// Measure the slot before a write. Creates an ABSENT slot at 0 (a no-op on
// any existing one — bump never lowers) and returns the claim the store may
// seal: ARMED only when the slot exists and its create committed.
export function probeStoreFloor(slot, previousClaim) {
  if (floor === null) return { claim: previousClaim === CLAIM_ARMED ? CLAIM_ARMED : previousClaim || CLAIM_NONE, current: NATIVE_ABSENT, warning: null };
  if (!usable) {
    return {
      claim: previousClaim === CLAIM_ARMED ? CLAIM_ARMED : CLAIM_UNCONFIRMED,
      current: NATIVE_ABSENT,
      warning: "this device's protected storage is not usable, so this store's rollback guard could not be armed",
    };
  }
  const probe = floor.bump(slot, 0);
  const current = floor.read(slot);
  const forged = (v) => !(v >= 0) && v !== NATIVE_COMMIT_FAILED;
  if (forged(current) || forged(probe)) {
    return {
      claim: previousClaim === CLAIM_ARMED ? CLAIM_ARMED : CLAIM_UNCONFIRMED,
      current: NATIVE_ABSENT,
      warning: "this device's protected record for this store is damaged or forged — its rollback guard cannot be relied on",
    };
  }
  if (probe === NATIVE_COMMIT_FAILED || current < 0) {
    return {
      claim: previousClaim === CLAIM_ARMED ? CLAIM_ARMED : CLAIM_UNCONFIRMED,
      current: NATIVE_ABSENT,
      warning: "this device could not durably record this store's rollback guard (storage full or unwritable?)",
    };
  }
  if (current >= MAX_GENERATION) {
    // Review of the first cut (F-1): a slot parked at the ceiling from the
    // page realm (one `bump` on the frozen bridge) let the catch-up carry the
    // store's generation past the ceiling, after which armStoreFloor returned
    // null forever — no bump, no warning, and every verdict clean: the whole
    // control silently off. The store never advances to the ceiling; the
    // parked slot therefore reads as a rollback on EVERY open (identity-store
    // does the same), i.e. a loud, permanent "verify again" — never silence.
    return {
      claim: previousClaim === CLAIM_ARMED ? CLAIM_ARMED : CLAIM_UNCONFIRMED,
      current: MAX_GENERATION - 1,
      ceiling: true, // the store's generation must stop HERE, one below the slot, forever
      warning: "this device's protected record for this store is at its ceiling — the rollback guard cannot advance, " +
        "and every pin will keep asking to be verified again. Clearing the app's data is the only repair",
    };
  }
  return { claim: CLAIM_ARMED, current, warning: null };
}

// Raise the slot to the generation just written. Only when the probe measured
// an armed slot; the return is a warning string or null.
export function armStoreFloor(slot, generation, claim) {
  if (!usable || claim !== CLAIM_ARMED) return null;
  if (!isGen(generation) || generation > MAX_GENERATION) {
    // Never silent (review of the first cut): an unarmable write is a warning.
    return "this store's generation could not be recorded in the rollback guard (out of range)";
  }
  const r = floor.bump(slot, generation);
  if (r === NATIVE_COMMIT_FAILED) return "this device could not durably record this store's rollback guard (storage full or unwritable?)";
  if (!(r >= generation)) return "this device's protected record for this store is damaged or forged";
  return null;
}

// Compare a just-opened store against the device's durable record of it.
// `ok: true` with `arm: true` means the device has no record yet and a write
// should create one (an existing install's first unlock after the update).
export function judgeStoreFloor(slot, generation, claim) {
  if (floor === null) return { ok: true, arm: false };
  if (!usable) return { ok: false, arm: false, reason: "unavailable" };
  const f = floor.read(slot);
  if (f !== NATIVE_ABSENT && !(f >= 0)) return { ok: false, arm: false, reason: "tampered" };
  if (f === NATIVE_ABSENT) {
    if (claim === CLAIM_ARMED) return { ok: false, arm: false, reason: "deleted" };
    return { ok: true, arm: true };
  }
  const gen = isGen(generation) ? generation : 0;
  if (f > gen) return { ok: false, arm: false, reason: "rollback", floor: f, generation: gen };
  return { ok: true, arm: claim !== CLAIM_ARMED };
}

// The plaintext field's reading rules, mirrored from identity.js: anything but
// a literal true/false claims nothing (and can never raise a false deletion
// alarm), and cannot read as "armed".
export function readClaim(v) {
  return (v === true || v === false) ? v : CLAIM_UNCONFIRMED;
}
