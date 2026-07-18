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

async function deriveKey(passphrase, salt, iters) {
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

export function isUnlocked() {
  return dataKey !== null;
}

export function lock() {
  dataKey = null;
  salt = null;
  contacts = null;
  pins = null;
}

// Unlock (or create) the store with the identity passphrase. Throws if a blob
// exists but does not decrypt with this passphrase (foreign/tampered blob —
// the caller decides whether to offer `wipe()`).
export async function unlock(passphrase) {
  if (!passphrase) throw new Error("passphrase required to unlock the contact store");
  const raw = localStorage.getItem(LS_CONTACTS);
  if (!raw) {
    salt = crypto.getRandomValues(new Uint8Array(16));
    dataKey = await deriveKey(passphrase, salt, KDF_ITERS);
    contacts = [];
    pins = {};
    migrateLegacyPins();
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
  if (migrateLegacyPins()) await persist();
}

// One-time migration of the old PLAINTEXT localStorage pins (sc.pins.v1) into
// this authenticated encrypted store (M-02). After migration the plaintext key
// is removed so a forged pin can no longer be planted there to auto-unlock.
function migrateLegacyPins() {
  const legacy = localStorage.getItem("sc.pins.v1");
  if (!legacy) return false;
  try {
    const old = JSON.parse(legacy);
    for (const [k, v] of Object.entries(old)) {
      if (!pins[k] && v && v.ed && v.mldsa) pins[k] = { ed: v.ed, mldsa: v.mldsa };
    }
  } catch { /* corrupt legacy pins: drop them */ }
  localStorage.removeItem("sc.pins.v1");
  return true;
}

async function persist() {
  if (!dataKey) throw new Error("contact store is locked");
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const plain = enc.encode(JSON.stringify({ contacts, pins }));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, dataKey, plain));
  localStorage.setItem(
    LS_CONTACTS,
    JSON.stringify({ v: 2, iters: KDF_ITERS, salt: b64(salt), iv: b64(iv), ct: b64(ct) }),
  );
}

// ---- identity pins (TOFU, now inside the authenticated store) -------------

export function getPin(key) {
  if (!pins) throw new Error("contact store is locked");
  return pins[key] || null;
}

export async function savePin(key, bundle) {
  if (!pins) throw new Error("contact store is locked");
  pins[key] = { ed: bundle.ed, mldsa: bundle.mldsa };
  await persist();
}

// Remove the blob entirely (identity forgotten, or unrecoverable foreign blob).
export function wipe() {
  localStorage.removeItem(LS_CONTACTS);
  lock();
}

export function hasStore() {
  return localStorage.getItem(LS_CONTACTS) !== null;
}

// ---- contact records ------------------------------------------------------
// { username, token, ed, mldsa, ecdh?, mlkem?, verified, verifiedAt, addedAt }
// ecdh/mlkem are the contact's public ENCRYPTION keys (bundle v2, needed to
// seal async messages to them). They are bound to the identity by the
// directory registration signature; the TRUST anchors remain ed/mldsa — an
// encryption-key update alone does not reset `verified`.

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
export async function upsert({ username, token, ed, mldsa, ecdh = null, mlkem = null, verified = false }) {
  if (!contacts) throw new Error("contact store is locked");
  const now = Date.now();
  const cur = contacts.find((c) => c.username === username);
  if (!cur) {
    contacts.push({
      username, token: token || null, ed, mldsa, ecdh, mlkem,
      verified, verifiedAt: verified ? now : null, addedAt: now,
    });
  } else {
    const keyChanged =
      cur.ed !== ed || cur.mldsa !== mldsa ||
      (ecdh && cur.ecdh && cur.ecdh !== ecdh) ||
      (mlkem && cur.mlkem && cur.mlkem !== mlkem);
    cur.ed = ed;
    cur.mldsa = mldsa;
    if (ecdh) cur.ecdh = ecdh;
    if (mlkem) cur.mlkem = mlkem;
    if (token) cur.token = token;
    if (keyChanged) {
      cur.verified = false; // key change invalidates earlier in-person trust
      cur.verifiedAt = null;
      cur.keyChangedAt = now;
      delete cur.vouchedBy; // stale vouches were for the old keys
    }
    if (verified) {
      cur.verified = true;
      cur.verifiedAt = now;
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
