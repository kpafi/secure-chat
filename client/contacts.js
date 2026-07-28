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

const LS_CONTACTS = "sc.contacts.v1";
// Pentest 2026-07-27 L-1: an authenticated, monotonic generation counter kept
// BESIDE the store. See assertNotRolledBack() for what it buys and what it does
// not. Encrypted under the same data key, so only the passphrase holder can
// write one — and its mere PRESENCE proves a store is supposed to exist.
const LS_GEN = "sc.contacts.gen.v1";
const GEN_DOMAIN = "secure-chat/contacts-generation/v1";
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
let generation = 0;  // monotonic store generation (L-1); bumped on every persist

export function isUnlocked() {
  return dataKey !== null;
}

export function lock() {
  dataKey = null;
  salt = null;
  contacts = null;
  pins = null;
  generation = 0;
}

// Unlock (or create) the store with the identity passphrase. Throws if a blob
// exists but does not decrypt with this passphrase (foreign/tampered blob —
// the caller decides whether to offer `wipe()`).
export async function unlock(passphrase) {
  if (!passphrase) throw new Error("passphrase required to unlock the contact store");
  const raw = localStorage.getItem(LS_CONTACTS);
  if (!raw) {
    // No store. Before creating a fresh (empty, pin-less) one, make sure this
    // really IS a first run and not a store somebody deleted — see L-1. The
    // witness carries its OWN salt precisely so it stays readable when the
    // store that would otherwise hold the salt has been removed.
    await assertStoreNotDeleted(passphrase);
    salt = crypto.getRandomValues(new Uint8Array(16));
    dataKey = await deriveKey(passphrase, salt, KDF_ITERS);
    contacts = [];
    pins = {};
    generation = 0;
    dropLegacyPins();
    await persist();
    return;
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
  // v1 blobs stored the bare contacts array; v2 wraps {contacts, pins}.
  if (Array.isArray(data)) {
    contacts = data;
    pins = {};
  } else {
    contacts = data.contacts || [];
    pins = data.pins || {};
  }
  generation = Number.isInteger(data.gen) ? data.gen : 0;
  await assertNotRolledBack(data.gen);
  let dirty = dropLegacyPins();
  if ((blob.v || 1) < 3 && migrateH01Verification()) dirty = true;
  // A pre-L-1 store carries no generation and no witness: adopt it at its
  // current state (there is nothing to roll back TO yet) and start counting.
  if (!Number.isInteger(data.gen)) dirty = true;
  if (dirty) await persist();
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

async function assertStoreNotDeleted(passphrase) {
  const w = await readWitness(passphrase);
  if (w === null) return; // no witness either: genuine first run
  lock();
  if (w.corrupt) {
    throw new Error(
      "a contact store was expected on this device but is missing, and its generation record does not " +
      "decrypt — refusing to start over with an empty (unpinned) store",
    );
  }
  throw new Error(
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
  generation += 1; // L-1: every write moves the store forward, monotonically
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const plain = enc.encode(JSON.stringify({ contacts, pins, gen: generation }));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, dataKey, plain));
  localStorage.setItem(
    LS_CONTACTS,
    JSON.stringify({ v: 4, iters: KDF_ITERS, salt: b64(salt), iv: b64(iv), ct: b64(ct) }),
  );
  // Witness LAST. Interrupted between the two writes we end up with a store
  // one generation ahead of its witness, which reads as "newer than recorded"
  // — not a rollback, so an ordinary crash never locks the user out.
  await writeWitness();
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
  await persist();
  return get(username);
}

// Cache the locally VERIFIED voucher names for a contact (the 🟡 mark). Only
// ever store names the caller has checked signatures for — this is a render
// cache, not a trust source.
export async function setVouches(username, names) {
  if (!contacts) throw new Error("contact store is locked");
  const cur = contacts.find((c) => c.username === username);
  if (!cur) return;
  cur.vouchedBy = names;
  cur.vouchCheckedAt = Date.now();
  await persist();
}

export async function remove(username) {
  if (!contacts) throw new Error("contact store is locked");
  contacts = contacts.filter((c) => c.username !== username);
  await persist();
}
