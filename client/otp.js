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
const hwKey = (id) => `sc.otp.hw.v1.${id}`;
function readHW(id) {
  const v = parseInt(localStorage.getItem(hwKey(id)) || "0", 10);
  return Number.isFinite(v) ? v : 0;
}
function bumpHW(id, sendOffset) {
  const cur = readHW(id);
  if (sendOffset > cur) localStorage.setItem(hwKey(id), String(sendOffset));
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
async function randomPad(totalBytes, fingerBytes) {
  const base = crypto.getRandomValues(new Uint8Array(totalBytes));
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

async function deriveKey(passphrase, salt, iters) {
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
  let file;
  try {
    file = JSON.parse(fileText);
  } catch {
    throw new Error("not a valid pad file");
  }
  if (file.fmt !== "secure-chat-otp-pad" || file.v !== 1) throw new Error("unrecognized pad file format");
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

// Encrypt {bytes, offsets} under `key` (a cached AES-GCM CryptoKey) with a fresh
// IV and persist, keeping the stored salt/iters so the same key still unlocks it.
async function writePadBlob(record, key, salt, iters) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const plain = encU.encode(JSON.stringify({
    bytes: b64(record.bytes),
    sendOffset: record.sendOffset,
    recvHighWater: record.recvHighWater,
  }));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, plain));
  plain.fill(0);
  localStorage.setItem(padKey(record.padId), JSON.stringify({
    padId: record.padId,
    label: record.label,
    regionSize: record.regionSize,
    role: record.role,
    createdAt: record.createdAt,
    kdf: { salt: b64(salt), iters },
    iv: b64(iv),
    ct: b64(ct),
  }));
  writeIndexEntry(record);
  bumpHW(record.padId, record.sendOffset); // advance the rollback tripwire (M-01)
}

// First save of a freshly generated/imported pad: derive a NEW at-rest key from
// the passphrase (PBKDF2 once) and encrypt. Returns the cached key for the
// session's cheap re-saves.
export async function saveNewPad(record, passphrase) {
  if (!passphrase) throw new Error("choose a pad passphrase to protect it on this device");
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const key = await deriveKey(passphrase, salt, KDF_ITERS);
  await writePadBlob(record, key, salt, KDF_ITERS);
  return { key, salt, iters: KDF_ITERS };
}

// Re-save consumption progress during a session using the already-derived key
// (no PBKDF2). `atRest` = { key, salt, iters } from unlock/saveNewPad.
export async function savePadProgress(record, atRest) {
  await writePadBlob(record, atRest.key, atRest.salt, atRest.iters);
}

// Decrypt a stored pad with its passphrase -> { record (bytes+offsets), atRest }.
export async function unlockPad(padId, passphrase) {
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
  // M-01: refuse a pad whose consumption has been rolled back below the highest
  // offset we ever recorded — that would reuse already-spent keystream.
  if (sendOffset < readHW(o.padId)) {
    throw new Error("pad state was rolled back (consumed key material) — refusing to use it; exchange a fresh pad");
  }
  const record = {
    padId: o.padId,
    label: o.label,
    regionSize: o.regionSize,
    role: o.role,
    createdAt: o.createdAt,
    bytes: unb64(inner.bytes),
    sendOffset,
    recvHighWater: inner.recvHighWater | 0,
  };
  return { record, atRest: { key, salt, iters } };
}

// Record that a pad has been exported (shared). Used to warn on re-export, which
// risks distributing one pad to more than one importer (-> key reuse).
export function markExported(padId) {
  const meta = padMeta(padId);
  if (meta) writeIndexEntry(meta, { exported: true });
}

export function forgetPad(padId) {
  localStorage.removeItem(padKey(padId));
  localStorage.removeItem(hwKey(padId)); // clear the rollback tripwire too (M-01)
  localStorage.setItem(LS_INDEX, JSON.stringify(readIndex().filter((e) => e.padId !== padId)));
}
