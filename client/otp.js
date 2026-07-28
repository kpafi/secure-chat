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
const WM_DOMAIN = "secure-chat/otp-watermark/v1";

// In-memory high-water marks for pads unlocked this session, so every re-save
// can take a max without re-deriving the at-rest key.
const wmCache = new Map(); // padId -> {send, recv}

function cachedWm(id) {
  return wmCache.get(id) || { send: 0, recv: 0 };
}

// The legacy (plaintext, send-only) watermark. Read ONLY to migrate a pad that
// predates the authenticated record, and to answer padWasUsed for a pad whose
// blob is gone. Never load-bearing for a rollback decision on its own.
function readLegacyHW(id) {
  const v = parseInt(localStorage.getItem(hwKey(id)) || "0", 10);
  return Number.isFinite(v) && v > 0 ? v : 0;
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

async function writeWatermark(id, key, wm) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const plain = encU.encode(JSON.stringify({
    d: WM_DOMAIN, padId: id, send: wm.send, recv: wm.recv,
  }));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, plain));
  localStorage.setItem(wmKey(id), JSON.stringify({ iv: b64(iv), ct: b64(ct) }));
  // Plaintext "this pad has run on this device" marker. It carries no offsets
  // and is not trusted for a rollback decision — it exists so importPad, which
  // holds only the TRANSFER passphrase and so cannot open the record above, can
  // still refuse to resurrect a consumed pad from its (always pristine) file.
  localStorage.setItem(usedKey(id), "1");
  wmCache.set(id, { send: wm.send, recv: wm.recv });
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
    send: Math.max(prev.send, record.sendOffset | 0),
    recv: Math.max(prev.recv, record.recvHighWater | 0),
  };
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
  }));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, plain));
  plain.fill(0);
  localStorage.setItem(padKey(record.padId), JSON.stringify({
    v: PAD_BLOB_V,
    kdf: { salt: b64(salt), iters },
    iv: b64(iv),
    ct: b64(ct),
  }));
  writeIndexEntry(record, { exported: !!record.exported });
  await writeWatermark(record.padId, key, wm);
}

// First save of a freshly generated/imported pad: derive a NEW at-rest key from
// the passphrase (PBKDF2 once) and encrypt. Returns the cached key for the
// session's cheap re-saves.
export async function saveNewPad(record, passphrase) {
  if (!passphrase) throw new Error("choose a pad passphrase to protect it on this device");
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const key = await deriveKey(passphrase, salt, KDF_ITERS);
  wmCache.set(record.padId, { send: 0, recv: 0 }); // a new pad starts at zero
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
  // max(outer, inner, legacy): each is a floor this device is known to have
  // passed, so the highest of them is the truth.
  const wm = {
    send: Math.max(outerWm ? outerWm.send : 0, inner.hwSend | 0, readLegacyHW(padId)),
    recv: Math.max(outerWm ? outerWm.recv : 0, inner.hwRecv | 0),
  };
  if (sendOffset < wm.send) {
    throw new Error("pad state was rolled back (consumed key material) — refusing to use it; exchange a fresh pad");
  }
  if (recvHighWater < wm.recv) {
    // M-7: no keystream is reused, but every OTP frame the peer already sent
    // would authenticate again as fresh — the anti-replay guarantee, gone.
    throw new Error("pad receive state was rolled back (already-delivered messages could replay) — refusing to use it; exchange a fresh pad");
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
    exported: inner.exported !== undefined
      ? !!inner.exported
      : !!(padMeta(padId) || {}).exported,
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
// derive a key from anyway. It therefore answers from evidence-of-presence — any
// of the three markers — which is the fail-CLOSED direction: extra markers can
// only cause a refusal, never an acceptance. Rollback decisions that CAN be
// authenticated are made in unlockPad, against the AEAD record.
export function padWasUsed(padId) {
  return localStorage.getItem(usedKey(padId)) !== null ||
    localStorage.getItem(wmKey(padId)) !== null ||
    readLegacyHW(padId) > 0;
}
