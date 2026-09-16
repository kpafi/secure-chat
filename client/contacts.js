// Encrypted on-device contact store ("Users" view).
//
// A contact is (username, lookup token, public identity bundle, trust state).
// That is social-graph + trust-anchor data, so it is stored with the same
// posture as the identity's private keys and the OTP pads: PBKDF2-600k →
// AES-256-GCM under the IDENTITY passphrase. The derived key lives only in
// memory while the identity is unlocked; the blob in localStorage is opaque.
// GCM also gives tamper protection: an attacker who edits the blob (say, to
// flip `verified` onto a swapped key) just breaks decryption.
//
// Trust state per contact (the "safety marks", computed client-side ONLY):
//   verified: true  → 🟢 you compared the fingerprint/safety number in person
//   (P2 will add: vouches[] → 🟡 someone YOU verified vouches for them)
//   otherwise       → ⚪ unverified
//
// The store is keyed by username (unique in the directory). The lookup token
// is kept so the contact can be re-fetched / vouch-checked later.

import { probeStoreFloor, armStoreFloor, judgeStoreFloor, readClaim } from "./store-floor.js";

const LS_CONTACTS = "sc.contacts.v1";
// Phase-7 F-P7-6: the generation is mirrored into the native floor under this
// slot (see store-floor.js). A pad id is 32 hex characters, so no collision.
const FLOOR_SLOT = "sc.contacts.v1#gen";
// Pentest 2026-07-27 L-1: an authenticated, monotonic generation counter kept
// BESIDE the store. See assertNotRolledBack() for what it buys and what it does
// not. Encrypted under the same data key, so only the passphrase holder can
// write one — and its mere PRESENCE proves a store is supposed to exist.
const LS_GEN = "sc.contacts.gen.v1";
const GEN_DOMAIN = "secure-chat/contacts-generation/v1";
// Pentest 2026-07-29 H-2. The witness above and the store below were encrypted
// under the SAME dataKey and recorded the SAME salt, and only the witness
// carried a domain tag. So the witness blob decrypted perfectly as a store:
// `sc.contacts.v1 := sc.contacts.gen.v1` — one setItem, no passphrase, no
// deletion — yielded an empty, PIN-LESS store at the witness's own generation.
// assertNotRolledBack passed (same gen), hasStore() and pinsReadable() stayed
// true so the loud P-02 path never ran, and every peer then rendered as a
// benign first contact instead of "identity key CHANGED". The alarm inverted,
// which is exactly what L-1 and the 2026-07-27 H-2 were written to prevent. A
// sweep of all 30 blob-swap combinations found this was the ONLY one that
// opened; the store plaintext was simply missing the tag its witness had.
const STORE_DOMAIN = "secure-chat/contacts-store/v4";
const KDF_ITERS = 600000; // same OWASP-2023 work factor as identity.js

const enc = new TextEncoder();
const dec = new TextDecoder();

function b64(u8) {
  let bin = "";
  for (let i = 0; i < u8.length; i++) bin += String.fromCharCode(u8[i]);
  return btoa(bin);
}
function unb64(s) {
  const bin = atob(s);
  const u = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i);
  return u;
}

// Audit 2026-07-18 L-01: `iters`/`salt` come from the persisted blob — bound
// them before WebCrypto runs (huge count = UI stalled for hours; tiny count =
// silently weakened KDF). Same bounds as identity.js.
const KDF_MIN_ITERS = 100000;
const KDF_MAX_ITERS = 5000000;

async function deriveKey(passphrase, salt, iters) {
  if (!Number.isInteger(iters) || iters < KDF_MIN_ITERS || iters > KDF_MAX_ITERS) {
    throw new Error("invalid key-derivation parameters (iteration count)");
  }
  if (!(salt instanceof Uint8Array) || salt.length < 8 || salt.length > 64) {
    throw new Error("invalid key-derivation parameters (salt)");
  }
  const base = await crypto.subtle.importKey("raw", enc.encode(passphrase), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: iters, hash: "SHA-256" },
    base,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

// Session state: the derived key and the decrypted contact list. `null` key
// means locked. The salt is kept so re-saves don't re-run PBKDF2.
let dataKey = null;
let salt = null;
let contacts = null; // array of contact records while unlocked
let pins = null;     // { "<key>": {ed, mldsa} } — TOFU identity pins (M-02)
// F-A2-R1: { "<pin key>": {at} } — tombstones for pins deleted as collateral of
// SOMEONE ELSE's revocation. Keyed by the pin key, which is in hand at deletion
// time, so it needs no guess about who holds those keys now. See dropPinsFor.
let swept = null;
let generation = 0;  // monotonic store generation (L-1); bumped on every persist
let floorClaim = false; // F-P7-6: what the store's AEAD says about the native floor
let floorWarning = null; // F-P7-6: the last probe/arm warning, for app.js to show

// ---- the anti-deletion anchor (pentest 2026-08-07 F-ATREST-003/004) --------
// Both findings are the same shape: every piece of evidence that a store OUGHT
// to exist lived in localStorage, where deleting it needs no passphrase. The
// witness raised the price of a silent wipe from one `removeItem` to two.
//
// The anchor moves that fact out of the two deletable keys and into the
// identity's own AEAD (identity.js `deviceFlags`), where forging it needs the
// passphrase.
//
// HONEST LIMIT (fix review 2026-08-07, F4). An earlier version of this comment
// said "clearing it means deleting the identity blob, which locks the user out
// — loud, not silent". That is FALSE and the claim is withdrawn: an attacker
// rolls the identity blob BACK rather than deleting it. The restored blob opens
// on the same passphrase with the same keys and safety number, carries no
// `flags`, and this check then reads false and fails open exactly as before.
// See the HONEST LIMIT note in identity.js and finding F-ATREST-008 (the
// identity blob has no anti-rollback control of its own). What this fix
// genuinely buys is the SHAPE tightening below plus a higher price for the
// silent wipe; it is not the complete answer to F-ATREST-003/004 that the
// first version of these comments claimed.
//
// F-ATREST-008 is closed as of 2026-09-16 (identity-store.js): the identity
// blob carries a monotone generation mirrored into the Android native floor,
// and under any at-rest verdict short of clean — rolled back, floor deleted,
// tampered, or expected-but-unusable — the anchor app.js installs here answers
// `established: true`. So on Android the rollback route now lands in the same
// fail-closed branch as the deletion it was covering for. In a plain browser
// there is no floor, and the paragraph above still describes the residual.
//
// Injected rather than imported so this module keeps knowing nothing about
// identity storage; app.js owns the Identity object and wires it in before
// unlocking. When no anchor is installed (an identity-less flow) every check
// below degrades to exactly the pre-fix behaviour, so nothing new can fire a
// false alarm on a path that never had an identity to anchor to.
let anchor = null;

export function setStoreAnchor(a) {
  anchor = a;
}

// True when this device has recorded that a contact store exists. `false` also
// covers "we cannot know" (no anchor installed), which is why every caller
// treats it as evidence FOR failing closed and never as permission to proceed.
export function storeExpected() {
  return anchor !== null && anchor.established === true;
}

async function noteStoreEstablished() {
  if (anchor === null || anchor.established === true) return;
  await anchor.markEstablished();
  anchor.established = true;
}

export function isUnlocked() {
  return dataKey !== null;
}

export function lock() {
  dataKey = null;
  salt = null;
  contacts = null;
  pins = null;
  swept = null;
  generation = 0;
  floorClaim = false;
  floorWarning = null;
}

// F-P7-6: a warning from the last floor probe/arm (storage full, forged slot,
// bridge unusable), or null. Read by app.js after unlock.
export function lastFloorWarning() {
  return floorWarning;
}

// F-P7-6, the fail-closed-on-TRUST response to a bad floor verdict. Every pin
// is marked SUSPECT — it stays, but app.js's renderVerify refuses to unlock
// messaging on a suspect pin and shows the loud re-verify prompt instead; a
// fresh in-person check (savePin) replaces the pin and clears the mark —
// and every contact must be verified again in person. The first cut DROPPED
// the pins (review: fifty re-verifications and a benign first-contact prompt
// from one process kill); a kept-but-suspect pin is strictly safer than a
// missing one, because the peer's next arrival is then "your saved contacts
// were rolled back", never "first contact".
function resetTrust(verdict) {
  for (const [key, pin] of Object.entries(pins)) {
    if (pin) pins[key] = { ...pin, suspect: true };
  }
  for (const c of contacts) {
    c.verified = false;
    c.verifiedAt = null;
    c.reverify = true;
    delete c.vouchedBy;
  }
  const why = {
    rollback: `your saved contacts are OLDER than this device's protected record of them (generation ${verdict.generation}, device recorded ${verdict.floor}) — an earlier copy has been restored, or a save did not reach disk`,
    deleted: "this device's protected record for your saved contacts has been DELETED",
    tampered: "this device's protected record for your saved contacts is damaged or forged",
    unavailable: "this device says it has protected storage for your saved contacts' rollback guard, but none is usable",
  }[verdict.reason] || "the rollback guard for your saved contacts could not be checked";
  return why + ". Every saved identity pin is now marked SUSPECT and every contact must be verified again in person before their messages unlock";
}

// Unlock (or create) the store with the identity passphrase. Throws if a blob
// exists but does not decrypt with this passphrase (foreign/tampered blob —
// the caller decides whether to offer `wipe()`).
export async function unlock(passphrase, { startFresh = false } = {}) {
  if (!passphrase) throw new Error("passphrase required to unlock the contact store");
  const raw = localStorage.getItem(LS_CONTACTS);
  if (!raw) {
    // No store. Before creating a fresh (empty, pin-less) one, make sure this
    // really IS a first run and not a store somebody deleted — see L-1. The
    // witness carries its OWN salt precisely so it stays readable when the
    // store that would otherwise hold the salt has been removed.
    // F-ATREST-008 fix review (F-2): `startFresh` is the consent gate. "No store,
    // but this device says one was established" is, by construction, the same
    // state for an attacker who deleted the store as for a device that lost an
    // unflushed first write in a crash — the floor cannot tell them apart, so
    // no policy can both refuse the attacker and spare the crash without a
    // human in the loop. Same trade as otp.js's adoption gate: the alarm is
    // shown with its full wording, and only an explicit, separately confirmed
    // action (app.js, behind `confirm()`) passes `startFresh`. It skips ONLY
    // this check; a store that exists is never discarded by it.
    if (!startFresh) await assertStoreNotDeleted(passphrase);
    salt = crypto.getRandomValues(new Uint8Array(16));
    dataKey = await deriveKey(passphrase, salt, KDF_ITERS);
    contacts = [];
    pins = {};
    swept = {};
    generation = 0;
    dropLegacyPins();
    await persist();
    await noteStoreEstablished();
    return null;
  }
  const blob = JSON.parse(raw);
  salt = unb64(blob.salt);
  dataKey = await deriveKey(passphrase, salt, blob.iters || KDF_ITERS);
  let plain;
  try {
    plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: unb64(blob.iv) }, dataKey, unb64(blob.ct));
  } catch {
    lock();
    throw new Error("contact store does not decrypt with this passphrase (different identity, or tampered)");
  }
  const data = JSON.parse(dec.decode(plain));

  // H-2: this plaintext must be a contact STORE and not some other record that
  // happens to decrypt under the same key. Only two shapes are acceptable:
  //
  //   d === STORE_DOMAIN  -> a v4+ store, tagged. Normal path.
  //   d absent            -> a pre-v4 store, written before the tag existed.
  //                          Adopted, then re-persisted WITH the tag below.
  //
  // Anything else — in practice the generation witness, whose own `d` is
  // GEN_DOMAIN — is refused. Note the discriminator is the tag INSIDE the
  // AEAD, deliberately not the outer `v` byte: `v` is attacker-writable, and
  // the witness blob has no `v` at all, so `(blob.v || 1) < 4` would read the
  // witness as a legacy store and adopt it — reopening the exact hole. This is
  // the same downgrade trap the outer `v` byte set for OTP (P-01).
  const tagged = Object.prototype.hasOwnProperty.call(data, "d");
  const notAStore = () => {
    lock();
    return new Error(
      "the contact store on this device is not a contact store — refusing to open it, because " +
      "continuing would silently discard your saved identity pins",
    );
  };
  if (tagged && data.d !== STORE_DOMAIN) throw notAStore();
  // Defence in depth for the untagged path: a genuine pre-v4 store is either
  // the bare v1 array or an object carrying contacts/pins.
  //
  // Pentest 2026-08-07 F-ATREST-004: this used to accept any object with an own
  // property NAMED `contacts` or `pins`, whatever its value. The chat store
  // (chats.js) is keyed by contact local label under the same passphrase and
  // wrapper, so a chat literally named "pins" made the chat blob a valid
  // "contact store" — `sc.contacts.v1 := sc.chats.v1` plus one `removeItem`
  // yielded an empty pin-less store. Require the SHAPE, not the key name.
  const isPlainObject = (o) => o !== null && typeof o === "object" && !Array.isArray(o);
  // A pin map is keyed by `user:<name>` / `room:<id>` and its values are pin
  // records. The chat store's plaintext is keyed by contact LOCAL LABEL and its
  // values are chat records, so this is the property that actually separates
  // the two — the key name `pins` alone never did.
  const isPinMap = (o) => isPlainObject(o) && Object.keys(o).every(
    (k) => /^(user|room):/.test(k) && isPlainObject(o[k]) && typeof o[k].ed === "string",
  );
  const hasOwn = (o, k) => Object.prototype.hasOwnProperty.call(o, k);
  const looksLikeStore = Array.isArray(data) || (
    isPlainObject(data) &&
    (hasOwn(data, "contacts") || hasOwn(data, "pins")) &&
    (!hasOwn(data, "contacts") || Array.isArray(data.contacts)) &&
    (!hasOwn(data, "pins") || isPinMap(data.pins))
  );
  if (!tagged && !looksLikeStore) throw notAStore();
  // F-ATREST-004, the durable half. The legacy exemptions below (untagged
  // plaintext, and plaintext with no generation counter) are keyed on the
  // SHAPE of the decrypted record, so they never burn out: an attacker holding
  // one archived pre-L-1 blob could replay the downgrade indefinitely, even
  // after many legitimate v4 generations, resurrecting pins the user had
  // already replaced and auto-unlocking messaging with no prompt. Once this
  // device has recorded a store, the legacy shapes are simply not acceptable
  // any more — the migration they exist for provably already happened.
  if (storeExpected() && (!tagged || !Number.isInteger(data.gen))) {
    lock();
    throw new Error(
      "your saved contacts have been replaced with an older-format copy that carries no rollback " +
      "record — refusing to open it, because adopting it would restore identity pins you have " +
      "since changed and turn off key-change warnings",
    );
  }

  // v1 blobs stored the bare contacts array; v2 wraps {contacts, pins}.
  if (Array.isArray(data)) {
    contacts = data;
    pins = {};
    swept = {};
  } else {
    contacts = data.contacts || [];
    pins = data.pins || {};
    // F-A2-R1: tombstones for pins swept by someone else's revocation, keyed by
    // the PIN KEY. Absent in pre-2026-08-20 stores, which is simply "no sweep has
    // happened here yet".
    swept = (data.swept && typeof data.swept === "object") ? data.swept : {};
  }
  generation = Number.isInteger(data.gen) ? data.gen : 0;
  await assertNotRolledBack(data.gen);
  // F-P7-6: the witness above is a localStorage key an attacker can restore
  // together with the store; the native floor is not. A store behind the
  // floor, a floor that is gone while the store claims one, a forged slot or
  // an unusable bridge all fail TRUST closed (see resetTrust) and are healed
  // by the write below; a device with no record yet is armed by that write.
  floorClaim = readClaim(data.floor);
  const floorVerdict = judgeStoreFloor(FLOOR_SLOT, generation, floorClaim);
  let warning = null;
  let dirty = dropLegacyPins();
  if (!floorVerdict.ok) {
    warning = resetTrust(floorVerdict);
    dirty = true;
  } else if (floorVerdict.arm) {
    dirty = true;
  }
  if ((blob.v || 1) < 3 && migrateH01Verification()) dirty = true;
  // An adopted pre-v4 store is rewritten tagged, so it only ever happens once.
  if (!tagged) dirty = true;
  // A pre-L-1 store carries no generation and no witness: adopt it at its
  // current state (there is nothing to roll back TO yet) and start counting.
  if (!Number.isInteger(data.gen)) dirty = true;
  if (dirty) await persist();
  // Record that this device has a store, so a later deletion cannot pass as a
  // first run and a later legacy-shaped blob cannot pass as a migration.
  await noteStoreEstablished();
  return warning;
}

// Pentest 2026-07-27 H-2: this used to be migrateLegacyPins(), which COPIED any
// entry from the plaintext `sc.pins.v1` into the authenticated pin map — and it
// ran on EVERY unlock, not once. A device-local attacker with nothing but a
// localStorage write could therefore plant a pin for a MITM bundle, have this
// function launder it into the encrypted store, and watch the plaintext
// evidence delete itself. The next session auto-accepted the attacker's keys
// with no prompt while the REAL contact tripped "identity key CHANGED" — the
// alarm inverted, and the M-02 fix ("a forged pin can no longer be planted
// there to auto-unlock") undone.
//
// The migration shipped 2026-07-18 and every live store is v3, so there is
// nothing left to migrate. What remains is the cleanup: delete the plaintext
// key if it is still lying around, and NEVER read a pin out of it.
function dropLegacyPins() {
  if (localStorage.getItem("sc.pins.v1") === null) return false;
  localStorage.removeItem("sc.pins.v1");
  return false; // nothing was imported, so nothing to persist on its account
}

// ---- rollback / deletion detection (pentest 2026-07-27 L-1) ----------------
// The contact store holds the TOFU pins, so removing or rewinding it removes
// key-change detection: app.js treats "no store" as a clean first contact and
// shows the reassuring prompt instead of the loud one. Both moves are available
// to a device-local attacker, who needs no passphrase to delete a file.
//
// The witness is a tiny AEAD record under the same data key carrying the store
// generation. It cannot be forged (that needs the passphrase) and it cannot be
// silently un-written: its presence alone says a store must exist.
//
//   store older than witness  -> rollback           -> fail closed
//   witness present, no store -> store was deleted  -> fail closed
//   store present, no witness -> witness was deleted -> fail closed (v4+ only)
//   neither present           -> genuine first run   -> proceed
//
// HONEST LIMIT: an attacker who saves BOTH values and restores BOTH still
// rewinds undetected. That is the whole-storage rollback README.md already
// documents as residual; the point here is that it now takes a coordinated
// snapshot rather than one `removeItem`.

// `key` is optional: when the store blob is gone we have no salt to re-derive
// from, so the caller passes the passphrase and we use the salt the witness
// carries itself.
async function readWitness(passphrase = null) {
  const raw = localStorage.getItem(LS_GEN);
  if (!raw) return null;
  let rec;
  try {
    rec = JSON.parse(raw);
  } catch {
    return { corrupt: true };
  }
  try {
    const key = passphrase === null
      ? dataKey
      : await deriveKey(passphrase, unb64(rec.salt), rec.iters || KDF_ITERS);
    const plain = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: unb64(rec.iv) }, key, unb64(rec.ct),
    );
    const w = JSON.parse(dec.decode(plain));
    if (w.d !== GEN_DOMAIN || !Number.isInteger(w.gen)) return { corrupt: true };
    return w;
  } catch {
    // Written under a DIFFERENT passphrase, or edited. Either way it is not
    // ours to interpret and it is not evidence we can act on safely.
    return { corrupt: true };
  }
}

async function writeWitness() {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const plain = enc.encode(JSON.stringify({ d: GEN_DOMAIN, gen: generation }));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, dataKey, plain));
  localStorage.setItem(LS_GEN, JSON.stringify({
    salt: b64(salt), iters: KDF_ITERS, iv: b64(iv), ct: b64(ct),
  }));
}

// F-ATREST-008 fix review (2026-09-16, F-2): every "the store is gone" refusal
// carries a code, so app.js can offer the ONE recovery that does not destroy
// the identity — starting over with an empty store, behind an explicit consent
// gate (see unlock's `startFresh`). The message stays the user-facing text.
function storeDeleted(message) {
  const e = new Error(message);
  e.code = "STORE_DELETED";
  return e;
}

async function assertStoreNotDeleted(passphrase) {
  const w = await readWitness(passphrase);
  if (w === null) {
    // Pentest 2026-08-07 F-ATREST-003 (confirmed). "No store and no witness"
    // used to mean "genuine first run" unconditionally — but the witness is an
    // ordinary localStorage key and deleting it needs no passphrase, so an
    // attacker who removed BOTH landed here and got a fresh, empty, pin-less
    // store with no warning anywhere. The anchor is the half they cannot
    // remove without locking the user out of their identity.
    if (storeExpected()) {
      lock();
      throw storeDeleted(
        "your saved contacts and their generation record have BOTH been deleted from this device — " +
        "refusing to start over with an empty store, because that would silently turn off " +
        "key-change warnings for every contact you have verified",
      );
    }
    return; // genuine first run
  }
  lock();
  if (w.corrupt) {
    throw storeDeleted(
      "a contact store was expected on this device but is missing, and its generation record does not " +
      "decrypt — refusing to start over with an empty (unpinned) store",
    );
  }
  throw storeDeleted(
    `your saved contacts (generation ${w.gen}) have been DELETED from this device — refusing to start ` +
    "over with an empty store, because that would silently turn off key-change warnings",
  );
}

async function assertNotRolledBack(storeGen) {
  const w = await readWitness();
  if (w === null) {
    // No witness. Fine only for a pre-L-1 store, which has no generation
    // either; a store that HAS one lost its witness, which is tampering.
    if (Number.isInteger(storeGen)) {
      lock();
      throw new Error(
        "the generation record for your saved contacts is missing — refusing to open the store, " +
        "because a rollback could no longer be detected",
      );
    }
    return;
  }
  if (w.corrupt) {
    lock();
    throw new Error("the generation record for your saved contacts is damaged or forged");
  }
  const gen = Number.isInteger(storeGen) ? storeGen : 0;
  if (gen < w.gen) {
    lock();
    throw new Error(
      `your saved contacts are OLDER than this device recorded (generation ${gen}, expected ${w.gen}) — ` +
      "an earlier copy has been restored, which would silently undo recent verifications and pins",
    );
  }
}

// One-time v2→v3 migration (audit 2026-07-18 H-01): earlier builds displayed a
// contact fingerprint over the SIGNING keys only, so a 🟢 set from the Users
// view never covered the ecdh/mlkem keys that seal async messages. Those marks
// are therefore "not sufficiently verified" — drop them so the user re-compares
// the (now four-key) fingerprint in person. Contacts without encryption keys
// keep their mark: it still covers everything the record can be used for, and
// upsert() drops it the moment encryption keys first appear.
function migrateH01Verification() {
  let changed = false;
  for (const c of contacts) {
    if (c.verified && (c.ecdh || c.mlkem)) {
      c.verified = false;
      c.verifiedAt = null;
      c.reverify = true; // UI hint: verification predates enc-key coverage
      delete c.vouchedBy;
      changed = true;
    }
  }
  return changed;
}

async function persist() {
  if (!dataKey) throw new Error("contact store is locked");
  // Pentest 2026-07-29 L-3: refuse a LOST UPDATE instead of causing one.
  //
  // Two tabs both unlock at generation N and both write N+1; the second
  // overwrites the first, and because it also rewrites the witness to N+1 the
  // rollback check agrees and nothing ever notices. Whatever the first tab
  // saved — including a pin — is simply gone, silently. OTP has a cross-tab
  // lock for the same class of problem; contacts had nothing.
  //
  // A compare-and-swap is enough here and needs no lock: the witness already
  // records the newest generation any tab has committed, so a witness ahead of
  // our in-memory copy means somebody else wrote while we were holding stale
  // state. That is not something to merge behind the user's back — the two
  // versions may disagree about a PIN — so it is a loud refusal and a reload.
  //
  // Not a security boundary against a device-local attacker (they can write the
  // witness too); it is protection against the user's own second tab, which is
  // what actually happens.
  const witness = await readWitness();
  if (witness && !witness.corrupt && witness.gen > generation) {
    lock();
    throw new Error(
      "your contacts were changed in another tab (or another window) — this page is out of date. " +
      "Reload before making further changes, so the other tab's changes are not lost.",
    );
  }
  // F-P7-6: measure the floor slot before the write (a probe cannot advance
  // it), and never write a generation the floor is already past — that is how
  // a fresh store after a wipe catches up with the slot instead of reading as
  // a rollback on every unlock until it does.
  const probe = probeStoreFloor(FLOOR_SLOT, floorClaim);
  floorClaim = probe.claim;
  floorWarning = probe.warning;
  if (probe.current > generation) generation = probe.current;
  generation += 1; // L-1: every write moves the store forward, monotonically
  // A parked slot (review F-1): the generation stops one below it, so the slot
  // reads as a rollback on every open — loud forever, never silently past it.
  if (probe.ceiling) generation = probe.current;
  const iv = crypto.getRandomValues(new Uint8Array(12));
  // `d` is the H-2 domain tag: it makes this plaintext unmistakably a STORE, so
  // no other record encrypted under the same key can be substituted for it.
  const plain = enc.encode(JSON.stringify({ d: STORE_DOMAIN, contacts, pins, swept, gen: generation, floor: floorClaim }));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, dataKey, plain));
  localStorage.setItem(
    LS_CONTACTS,
    JSON.stringify({ v: 4, iters: KDF_ITERS, salt: b64(salt), iv: b64(iv), ct: b64(ct) }),
  );
  // Witness LAST. Interrupted between the two writes we end up with a store
  // one generation ahead of its witness, which reads as "newer than recorded"
  // — not a rollback, so an ordinary crash never locks the user out.
  await writeWitness();
  // F-P7-6: the floor is raised only now, after both localStorage writes.
  floorWarning = armStoreFloor(FLOOR_SLOT, generation, floorClaim) || floorWarning;
}

// ---- identity pins (TOFU, now inside the authenticated store) -------------

export function getPin(key) {
  if (!pins) throw new Error("contact store is locked");
  return pins[key] || null;
}

// Pins store ALL FOUR public keys (audit 2026-07-18 H-01): a pin that only
// covered ed/mldsa would let a swapped ecdh/mlkem pair ride under an existing
// 🟢 pin. Pins without enc keys (pre-fix) are treated by the caller as not
// sufficiently verified once the peer presents encryption keys.
export async function savePin(key, bundle) {
  if (!pins) throw new Error("contact store is locked");
  pins[key] = {
    ed: bundle.ed, mldsa: bundle.mldsa,
    ecdh: bundle.ecdh ?? null, mlkem: bundle.mlkem ?? null,
  };
  // F-A2: saving a pin IS the in-person safety-number confirmation, so it clears
  // the "your pin was cleared by someone else's revocation" tombstone for this
  // key. Without this the marker would outlive the re-verification it asks for on
  // the room-pin path, where `onVerifyOk` has no handle to upsert against.
  //
  // Keyed on the pin key AND on the identity (ROUND-5). Saving a pin is an
  // in-person check of a PERSON, so it may only clear the tombstone raised for
  // that same person. Clearing on the key alone let a LATER, unrelated
  // verification under the same key — a recycled `room:<id>` with somebody else —
  // delete the victim's tombstone. That is worse than losing one alarm: since
  // ROUND-3 F-3 made `pinWasSwept` fall through to an identity scan across
  // tombstones, deleting the wrong one silences that peer's alarm in EVERY room,
  // which is M-2's inverted alarm restored through a side door.
  //
  // Still per-key, so re-verifying one key does NOT silence the alarm for a
  // different key swept in the same revocation.
  const tomb = swept ? swept[key] : null;
  if (tomb && tomb.ed === bundle.ed && tomb.mldsa === bundle.mldsa) delete swept[key];
  await persist();
}

// Remove the blob entirely (identity forgotten, or unrecoverable foreign blob).
// The generation witness goes with it: this is the ONE deletion the user asked
// for, so leaving the witness behind would make the next unlock refuse to open.
export function wipe() {
  localStorage.removeItem(LS_CONTACTS);
  localStorage.removeItem(LS_GEN);
  lock();
}

// True when a contact store is EXPECTED on this device — which includes the
// case where the blob is gone but its generation witness is not (L-1). app.js
// reads this through pinsReadable(), so a deleted store now takes the loud
// "key changes cannot be detected" path instead of rendering every contact as a
// benign first contact.
export function hasStore() {
  return localStorage.getItem(LS_CONTACTS) !== null || localStorage.getItem(LS_GEN) !== null;
}

// ---- contact records ------------------------------------------------------
// { username, token, ed, mldsa, ecdh?, mlkem?, verified, verifiedAt, addedAt }
// ecdh/mlkem are the contact's public ENCRYPTION keys (bundle v2, needed to
// seal async messages to them). All four keys are trust anchors: fingerprints
// and safety numbers cover them, and ANY of them changing (including a key
// appearing for the first time) resets `verified` (audit 2026-07-18 H-01).

export function list() {
  if (!contacts) throw new Error("contact store is locked");
  // defensive copy so callers can't mutate the store behind persist()'s back
  return contacts.map((c) => ({ ...c }));
}

export function get(username) {
  if (!contacts) throw new Error("contact store is locked");
  const c = contacts.find((c) => c.username === username);
  return c ? { ...c } : null;
}

// Insert or update a contact. On update the PUBLIC KEYS ARE NOT silently
// replaced: a changed bundle for a known username resets `verified` to false
// (key change must be re-verified). H-01: this covers the ENCRYPTION keys
// (ecdh/mlkem) too — a relay that swaps only those, keeping the signing
// identity, would otherwise silently redirect sealed async messages while the
// contact still shows 🟢. Any of the four keys changing drops verification.
export async function upsert({
  username, token, ed, mldsa, ecdh = null, mlkem = null, verified = false,
  // Pentest 2026-07-25 F-01: `username` is the LOCAL label and is chosen by us
  // (or by the user), never by a remote party. `addrUsername` is the directory
  // name used to address mail and look the contact up; `claimedName` is the
  // sender's self-asserted handle, kept only so the UI can show it as an
  // explicitly unverified claim. `auto` marks a record created from inbound
  // mail rather than by the user, which is what the F-05 cap counts.
  addrUsername = null, claimedName = null, auto = false,
}) {
  if (!contacts) throw new Error("contact store is locked");
  const now = Date.now();
  const cur = contacts.find((c) => c.username === username);
  if (!cur) {
    contacts.push({
      username, token: token || null, ed, mldsa, ecdh, mlkem,
      addrUsername: addrUsername || null,
      claimedName: claimedName || null,
      auto: !!auto,
      verified, verifiedAt: verified ? now : null, addedAt: now,
    });
  } else {
    // Audit 2026-07-18 H-01: missing→present IS a key change. A verified
    // contact saved before encryption keys existed must NOT stay 🟢 when keys
    // first appear — they were never part of what was compared in person.
    // (present→absent keeps the stored keys below, so nothing the record
    // trusts actually changed in that direction.)
    const keyChanged =
      cur.ed !== ed || cur.mldsa !== mldsa ||
      (ecdh != null && (cur.ecdh ?? null) !== ecdh) ||
      (mlkem != null && (cur.mlkem ?? null) !== mlkem);
    // Item 17: capture the outgoing signing keys BEFORE they are overwritten, so
    // a later Remove/Unverify can still find pins filed under them. Only when
    // the signing keys themselves move — an ecdh/mlkem-only change leaves the
    // identity that pins are matched on untouched.
    if (keyChanged && (cur.ed !== ed || cur.mldsa !== mldsa)) rememberSupersededKeys(cur);
    cur.ed = ed;
    cur.mldsa = mldsa;
    if (ecdh) cur.ecdh = ecdh;
    if (mlkem) cur.mlkem = mlkem;
    if (token) cur.token = token;
    if (addrUsername) cur.addrUsername = addrUsername;
    if (claimedName) cur.claimedName = claimedName;
    if (keyChanged) {
      cur.verified = false; // key change invalidates earlier in-person trust
      cur.verifiedAt = null;
      cur.keyChangedAt = now;
      delete cur.vouchedBy; // stale vouches were for the old keys
    }
    if (verified) {
      cur.verified = true;
      cur.verifiedAt = now;
      delete cur.reverify; // fresh in-person check supersedes the H-01 reset
    }
  }
  await persist();
  return get(username);
}

export async function setVerified(username, on) {
  if (!contacts) throw new Error("contact store is locked");
  const cur = contacts.find((c) => c.username === username);
  if (!cur) throw new Error("unknown contact");
  cur.verified = !!on;
  cur.verifiedAt = on ? Date.now() : null;
  if (on) delete cur.reverify; // fresh in-person check supersedes the H-01 reset
  // Pentest 2026-08-07 F-ATREST-007: the pin used to outlive "Unverify". The
  // pin is what makes the next session auto-unlock messaging with NO prompt
  // (app.js sameBundle(pin, bundle) -> unlockMessaging()), so a contact whose
  // verification the user had explicitly REVOKED still walked straight in —
  // the one outcome the button exists to prevent. Un-verifying is the user
  // saying "I no longer trust this key"; drop the pin so the next session is
  // treated as a first contact and the safety number must be compared again.
  if (!on) dropPinsFor(cur);
  await persist();
  return get(username);
}

// Every pin that names this contact's keys, whatever it is keyed under.
//
// Fix review 2026-08-07 (F5): the first cut deleted only `pins["user:" + name]`.
// But app.js pins under `room:<id>` whenever no directory handle was typed
// (app.js `currentPinKey = expectedPeerName ? "user:"+name : "room:"+room`),
// which is the DEFAULT for Live-room use — so for a peer verified in a live
// room, the revocation deleted a key that was never written and left the pin
// that actually gates auto-unlock. Revocation has to be about the KEYS, not
// about the label they happen to be filed under, so sweep by bundle.
// Pentest 2026-08-08 item 17: sweeping by the contact's CURRENT keys is not
// enough, and the residual is the worst possible one.
//
// `upsert()` overwrites `cur.ed`/`cur.mldsa` on a key change without touching
// `pins`. So after a rotation the record names K2 while the `room:<id>` pin
// still names K1, the comparison below matches nothing, and Remove/Unverify
// leave that pin in place. The key left behind is the SUPERSEDED one — exactly
// the key a user revoking after a suspected compromise is trying to kill — and
// anyone presenting K1 still matches a stored pin and still auto-unlocks
// messaging with no prompt.
//
// Fixed by remembering superseded signing keys on the record (see
// `rememberSupersededKeys`) and sweeping by the union: current bundle ∪ history.
//
// It does NOT over-sweep, which was checked in the other direction: a collateral
// match needs both `ed` AND `mldsa` to equal this contact's, i.e. the same
// identity filed under another label, and deleting that pin is correct.
//
// Honest limit: the history can only contain keys this store actually SAW being
// replaced. A pin written under `room:<id>` at K1 by a device that never held a
// contact record at K1 — pin first, contact added later already at K2 — is still
// missed. Nothing in the record can recover a key it never stored; closing that
// needs the pin to carry its owner, which is only knowable when a handle was
// typed (`user:<name>` pins already carry it in the key).
const MAX_PIN_KEY_HISTORY = 8;

// Record the bundle a contact is moving AWAY from. Must be called BEFORE the new
// keys are written over the record.
function rememberSupersededKeys(cur) {
  if (!cur || typeof cur.ed !== "string" || typeof cur.mldsa !== "string") return;
  const history = Array.isArray(cur.pinKeys) ? cur.pinKeys : [];
  if (history.some((k) => k.ed === cur.ed && k.mldsa === cur.mldsa)) return;
  history.push({ ed: cur.ed, mldsa: cur.mldsa });
  // Pentest 2026-08-10 (M-1): the first cut was `history.slice(-MAX)`, which
  // drops the OLDEST superseded key — and the oldest is exactly the one whose
  // pin has had the longest time to be written and forgotten. Nine rotations
  // therefore evicted K1 while `room:<id>` still pinned K1, restoring verbatim
  // the residual item 17 exists to close. Reproduced.
  //
  // The justification for capping at all was also simply wrong, and is corrected
  // here rather than left as folklore: it claimed `upsert` is reachable from
  // inbound mail. It is not, for this purpose — the inbound-mail path keys new
  // records on `neutralName(senderBundle.ed)`, so a different key makes a
  // different RECORD and never pushes onto an existing contact's history. Only a
  // user action (re-adding a handle, or a live session with a rotated peer) can
  // grow this list.
  //
  // So the bound never evicts a key that still has a pin naming it — those are
  // the entries with work left to do. The cap only trims history that has become
  // inert, which keeps the list bounded by the pins that actually exist.
  const stillPinned = (k) =>
    Object.values(pins).some((p) => p && p.ed === k.ed && p.mldsa === k.mldsa);
  const keepFrom = Math.max(0, history.length - MAX_PIN_KEY_HISTORY);
  cur.pinKeys = history.filter((k, i) => i >= keepFrom || stillPinned(k));
}

function dropPinsFor(contact) {
  if (!contact) return;
  delete pins["user:" + contact.username];
  // Current keys ∪ every superseded pair we recorded for this contact.
  const owned = [{ ed: contact.ed, mldsa: contact.mldsa }];
  if (Array.isArray(contact.pinKeys)) {
    for (const k of contact.pinKeys) {
      if (!k || typeof k.ed !== "string" || typeof k.mldsa !== "string") continue;
      owned.push(k);
    }
  }
  // Pentest 2026-08-10 (M-2) and its repair's own defect (2026-08-10-night F-A2).
  //
  // M-2 first. `pinKeys` is fed from whatever `upsert` was called with, which
  // includes an UNSIGNED directory answer (see item 14 — the directory binds
  // nothing). So a relay that answers one lookup for "mallory" with alice's real
  // bundle gets K_alice written into mallory's history; the record self-corrects
  // on the next honest answer, but the history keeps the lie, and removing
  // mallory weeks later deleted alice's pin. Alice's next session then rendered
  // as a benign FIRST CONTACT — the alarm inverted, which is the shape this
  // project has been bitten by before.
  //
  // The first repair was to SKIP a historical key that is some other contact's
  // current identity. That inverted the failure instead of removing it: the
  // attacker chooses whether such a record exists. One directory lookup answered
  // with the superseded bundle (app.js upserts it), or one sealed envelope, which
  // auto-creates a contact with no user action at all, is enough to manufacture
  // the claimant — and the retained pin then reaches `unlockMessaging()` with no
  // prompt and no safety-number check. Post-compromise revocation, defeated by
  // the thing that was supposed to protect a bystander.
  //
  // Both failures come from trying to settle a key COLLISION by choosing which
  // contact keeps the pin. There is no safe answer to that: retention is
  // fail-open, deletion is a silent downgrade. So neither is used. The pin is
  // ALWAYS deleted — revocation must be absolute, and the user asked for it —
  // and the collision is recorded on the other contact instead, so their next
  // session cannot be rendered as a benign first contact.
  //
  // The marker is a TOMBSTONE ON THE PIN KEY (F-A2-R1, closed 2026-08-20).
  //
  // It used to be a `reverify` flag on a contact whose CURRENT keys were the
  // swept ones. That was measured to miss two reachable shapes: a `room:<id>` pin
  // whose owner has no contact record at all (the DEFAULT for Live-room use —
  // app.js only mirrors a record when a handle was typed), and a bystander who
  // has since rotated, whose stale pin names keys the record no longer has. In
  // both, the pin was swept and NO marker was set, so that peer's next session
  // still rendered as a benign first contact — the alarm inversion this whole
  // item is about, just narrower.
  //
  // The pin KEY is in hand right here, at the moment of deletion, and it is
  // exactly what `renderVerify` looks the pin up by. So the tombstone is filed
  // under it and needs no guess about who holds those keys now. Every swept pin
  // gets one, so the coverage is the swept set itself rather than a subset of it.
  //
  // Deliberately NOT conditioned on any other record being `verified` or
  // user-created: an attacker-made record is exactly the case that must not be
  // able to change what revocation deletes, or what it announces.
  for (const [key, pin] of Object.entries(pins)) {
    if (!pin) continue;
    // Signing keys alone are enough to identify the contact: they ARE the
    // identity (the fingerprint and safety number cover only them), and a pin
    // whose ed/mldsa match is a pin for this peer whatever else it carries.
    const hit = owned.find((k) => pin.ed === k.ed && pin.mldsa === k.mldsa);
    if (!hit) continue;
    delete pins[key];
    // The tombstone records the keys the swept pin named, so the next session on
    // that key can be told apart from a genuine first contact even if the peer's
    // record is gone, was never there, or has since rotated.
    swept[key] = { ed: pin.ed, mldsa: pin.mldsa };
  }
}

// Was the pin under this key deleted as collateral of someone else's revocation?
// Read by app.js's no-pin path so that arrival renders as "re-verify", never as a
// benign first contact (F-A2 / F-A2-R1).
export function pinWasSwept(key, bundle = null) {
  if (!pins) throw new Error("contact store is locked");
  if (!swept) return false;
  if (swept[key]) return true;

  // ROUND-3 F-3 (pentest of this fix). Keyed on the pin key ALONE, the alarm
  // followed the label rather than the peer — and `room:<id>` keys are per chat
  // code, so the same person in a different room came back as a benign FIRST
  // CONTACT. That is M-2's inverted alarm returning through a side door, and it
  // is the DEFAULT shape for Live-room use. The tombstone already recorded the
  // swept pin's ed/mldsa; nothing read them.
  //
  // Signing keys only, as everywhere else here: they are the identity (the
  // fingerprint and safety number cover only them).
  if (!bundle || !bundle.ed || !bundle.mldsa) return false;
  const sameId = (x) => Boolean(x) && x.ed === bundle.ed && x.mldsa === bundle.mldsa;
  if (!Object.values(swept).some(sameId)) return false;

  // ...but a pin SAVED for this identity since the sweep is the in-person
  // safety-number check the alarm exists to demand, and that check authenticates
  // the PERSON, not the room it happened to be done in. So it settles the whole
  // identity. Without this the alarm would be unclearable for every other room —
  // and an alarm that cannot be cleared is one users are trained to click past,
  // which costs more than it buys.
  //
  // Note this deliberately does NOT clear sibling TOMBSTONES (see the per-key
  // test): a key that was swept keeps its own marker, so re-verifying in one room
  // cannot silence the specific room whose pin is still missing.
  return !Object.values(pins).some(sameId);
}

// Cache the locally VERIFIED voucher names for a contact (the 🟡 mark). Only
// ever store names the caller has checked signatures for — this is a render
// cache, not a trust source.
// `expected` is the bundle the caller VERIFIED the vouch signatures against.
//
// Pentest 2026-08-07 F-PROTO-005 (TOCTOU). The caller computes the 🟡 mark from
// a SNAPSHOT of the contact taken before an awaited `/vouches` fetch, then wrote
// it back with a live lookup by username. A directory that simply stalls that
// fetch — no forgery needed — while the user re-adds the same handle buys the
// window: the re-add replaces the stored bundle, the stalled response lands, and
// "vouched by <someone you verified in person>" gets attached to keys that
// voucher never signed. The room-admission prompt then renders that mark with no
// key-changed warning beside it, which is precisely the trust the 🟡 is claiming
// to convey.
//
// So the write is conditional on the bundle still being the one the signatures
// were checked against. Same-process and same-tick as the read below, so there
// is no second window here.
export async function setVouches(username, names, expected = null) {
  if (!contacts) throw new Error("contact store is locked");
  const cur = contacts.find((c) => c.username === username);
  if (!cur) return false;
  if (expected) {
    const same = cur.ed === expected.ed && cur.mldsa === expected.mldsa &&
      (cur.ecdh ?? null) === (expected.ecdh ?? null) &&
      (cur.mlkem ?? null) === (expected.mlkem ?? null);
    if (!same) return false; // re-added / key-changed under us: the mark is stale
  }
  cur.vouchedBy = names;
  cur.vouchCheckedAt = Date.now();
  await persist();
  return true;
}

export async function remove(username) {
  if (!contacts) throw new Error("contact store is locked");
  // F-ATREST-007: same argument as setVerified(false), more so. "Remove" is the
  // strongest revocation the UI offers, and it used to leave the pin behind —
  // so a removed contact still auto-unlocked messaging with no prompt, and the
  // Users list showed nothing at all to explain why. Read the record BEFORE
  // dropping it, so the sweep knows which keys to look for.
  const cur = contacts.find((c) => c.username === username);
  contacts = contacts.filter((c) => c.username !== username);
  dropPinsFor(cur);
  delete pins["user:" + username]; // also covers a pin with no contact record
  await persist();
}
