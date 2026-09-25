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
// Pentest 2026-08-07: the floor capture (F-1, H-1, H-A, round-2 H-1) moved to
// nativefloor.js so the contact and chat stores share it. Nothing about how
// the bridge is found, validated or refused changed; see that file.
import {
  captureNativeFloor, NATIVE_ABSENT, NATIVE_TAMPERED, maxOf, floorUnavailableError, bumpFloor,
} from "./nativefloor.js";
const nativeFloor = captureNativeFloor();
import * as durable from "./durable.js";

// --- the durable progress record (package 3b) --------------------------------
//
// Everything above is localStorage, and localStorage is not durable: Chromium
// commits it in rate-limited batches, so a pad saved seconds before a crash
// reopened at the offset the last message had already used — a two-time pad
// with no attacker at all (see durable.js). Owner decision 2026-09-25: HEAL
// FORWARD. Every progress save now also writes, to IndexedDB with strict
// durability, a record of how far the pad has been consumed:
//
//   sc.otp.dur.v1.<padId> = { used: 0|1, iv, ct }
//     ct = AES-GCM under the pad's at-rest key of
//          { d: DUR_DOMAIN, padId, send, recv, exported }
//
// Sealed like the watermark, with its own domain tag (so neither the watermark
// nor the pad blob, which live under the same key, can stand in for it) and
// the pad id inside, so a JS-context attacker can neither raise nor lower it
// undetected. A pad blob found BEHIND its durable record (or behind its
// authenticated watermark) is opened at the higher offsets: skipping pad bytes
// is harmless, reusing them is the only danger. The native floor never heals:
// it only ever refuses, and a floor ahead of every data source — the durable
// record included — is still rollback evidence.
//
// `used` sits outside the AEAD on purpose: importPad holds only the TRANSFER
// passphrase and after a crash may have no blob to derive the at-rest key
// from, yet it must refuse to recreate a pad this device already consumed. It
// is evidence-of-presence like `usedKey` (extra evidence only refuses), and it
// survives the crash that took the localStorage markers with it.
//
// Write order on every save: native slots armed → blob + watermark to
// localStorage → AWAIT the durable write → native floors advanced. So the
// floor can never get ahead of durable data (the Android brick), and app.js's
// "persist before transmit / display / download" now waits for the disk.
// A deleted durable record falls back to the rules below (the next save
// re-creates it). Without IndexedDB, OTP is refused, like without Web Locks.
const durKey = (id) => `sc.otp.dur.v1.${id}`;
const DUR_DOMAIN = "secure-chat/otp-durable/v1";
// Per-pad high-water of what has been handed to the durable store, and a
// per-pad queue: two saves in flight (a send and a receive overlapping) must
// reach the disk in order, and the record written last must never be the
// smaller one.
const durHigh = new Map(); // padId -> {send, recv, exported}
const durQueue = new Map(); // padId -> Promise
function requireDurable() {
  if (!durable.available()) throw durable.unavailableError("One-time pads");
}

async function sealDurable(id, key, v) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const plain = encU.encode(JSON.stringify({
    d: DUR_DOMAIN, padId: id, send: v.send, recv: v.recv, exported: !!v.exported,
    // Review round 1: the pad's geometry, so a blob whose role / region size
    // disagree (an archived v1 blob kept them outside its AEAD) is refused
    // rather than healed onto the wrong half of the pad.
    role: v.role, regionSize: v.regionSize,
  }));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, plain));
  return JSON.stringify({
    used: v.send > 0 || v.recv > 0 || v.exported ? 1 : 0, iv: b64(iv), ct: b64(ct),
  });
}

function writeDurable(id, key, v) {
  const job = async () => {
    const prev = durHigh.get(id) || { send: 0, recv: 0, exported: false };
    const next = {
      send: maxOf(prev.send, v.send), recv: maxOf(prev.recv, v.recv), exported: !!(prev.exported || v.exported),
    };
    await durable.put(durKey(id), await sealDurable(id, key, { ...next, role: v.role, regionSize: v.regionSize }));
    durHigh.set(id, next);
  };
  const run = (durQueue.get(id) || Promise.resolve()).then(job, job);
  durQueue.set(id, run.catch(() => {}));
  return run.catch((e) => {
    const err = new Error(
      "could not write this pad's progress to durable storage (" + (e && e.message ? e.message : "unknown error") +
      "), so it was NOT saved safely. Free some storage and try again.",
    );
    err.code = "DURABLE_WRITE_FAILED";
    throw err;
  });
}

// {send, recv, exported} | null (absent) | "corrupt".
async function readDurable(id, key) {
  let raw;
  try {
    raw = await durable.get(durKey(id));
  } catch {
    const err = new Error("could not read this pad's durable progress record — refusing to use the pad now; reload and try again");
    err.code = "DURABLE_READ_FAILED";
    throw err;
  }
  if (raw === null || raw === undefined) return null;
  try {
    const rec = JSON.parse(raw);
    const plain = new Uint8Array(await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: unb64(rec.iv) }, key, unb64(rec.ct),
    ));
    const w = JSON.parse(decU.decode(plain));
    plain.fill(0);
    if (w.d !== DUR_DOMAIN || w.padId !== id || !isInt(w.send) || !isInt(w.recv) ||
        w.send < 0 || w.recv < 0 || typeof w.exported !== "boolean" ||
        (w.role !== 0 && w.role !== 1) || !isInt(w.regionSize) || w.regionSize <= 0) {
      return "corrupt";
    }
    return { send: w.send, recv: w.recv, exported: w.exported, role: w.role, regionSize: w.regionSize };
  } catch {
    return "corrupt";
  }
}

// True only when a durable record exists and its plaintext hint is exactly
// `used: 0` (review round 2, I-6). Anything unreadable is NOT "unused".
async function durableSaysUnused(id) {
  try {
    const raw = await durable.get(durKey(id));
    return raw !== null && raw !== undefined && JSON.parse(raw).used === 0;
  } catch {
    return false;
  }
}

// The plaintext `used` hint of the durable record (see above). Fail-closed:
// an unreadable record counts as used.
async function durablePadUsed(id) {
  let raw;
  try {
    raw = await durable.get(durKey(id));
  } catch {
    return true;
  }
  if (raw === null || raw === undefined) return false;
  try {
    return JSON.parse(raw).used !== 0;
  } catch {
    return true;
  }
}

// Floor ids for the per-pad state beside the send offset (which uses the bare
// padId). F-ATREST-001: the receive high-water mark had no native floor, so a
// snapshot of the blob AND its watermark, restored after a stretch of
// receiving, re-accepted every OTP frame the peer had already sent — the M-7
// shape, but with the watermark restored too, which only a floor can catch.
// F-ATREST-002: `exported` had none either, so restoring the pre-export blob
// silently re-armed a second export of the same pristine pad (two importers,
// a two-time pad). Both are keyed under prefixes a pad id cannot contain.
const recvFloorId = (id) => "recv:" + id;
const exportedFloorId = (id) => "exported:" + id;
// What randomId() produces, and the only shape a pad id may have: 32 hex
// characters. Enforced on the two paths that take an id from OUTSIDE (a pad
// file, and the storage key the caller asks for), so a crafted file with
// padId "recv:<victim>" cannot reach the victim's floors through the bridge.
const PAD_ID_RE = /^[0-9a-f]{32}$/;

// Package 3 (F-P7-A3 residual): "is this an integer?" for the fields that
// decide whether a pad has run here (`inner.hwSend` / `inner.hwRecv`), asked
// WITHOUT `Number.isInteger`. That is a writable global: a page-realm script
// that made it answer false for the restored blob's values (and nothing else,
// so the KDF and region checks still pass) turned knownUsedHere off, and with
// the watermark and used-marker deleted a restored v3 blob reopened at its old
// offset in a browser — a two-time pad. `typeof` and `|` are language
// operators with nothing behind them to redefine (the maxOf rule). Offsets are
// far below 2^31, so the int32 range loses nothing.
const isInt = (v) => typeof v === "number" && (v | 0) === v;

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
  // The native floors (F-1 send, F-ATREST-001 recv, F-ATREST-002 exported) used
  // to be bumped here, with their answers discarded. Package 3 moved them into
  // writePadBlob, which arms them BEFORE the blob claims them and checks every
  // advance after it — see armPadFloors / advancePadFloors.
  // "Post-fix OTP has run on this device." Deletable like everything else here,
  // so it may only ESCALATE a warning, never authorise anything — see the
  // legacy-adoption gate in unlockPad.
  localStorage.setItem(EPOCH_KEY, "1");
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
// Package 3, F-CRYPTO-012: getRandomValues fills at most 65 536 bytes per call
// (it throws QuotaExceededError above that, in browsers and Node alike), and
// this used to be ONE call over the whole pad — so two of the three sizes
// PAD_SIZES offers, 256 KiB and 1 MiB, failed with an error on every attempt.
// Filled in 64 KiB chunks now; each chunk is an independent CSPRNG draw, so
// the result is the same distribution as one large draw would be.
const RNG_CHUNK = 65536;
async function randomPad(totalBytes, fingerBytes) {
  const base = new Uint8Array(totalBytes);
  for (let off = 0; off < totalBytes; off += RNG_CHUNK) {
    crypto.getRandomValues(base.subarray(off, Math.min(off + RNG_CHUNK, totalBytes)));
  }
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

// "The rollback record for this pad is missing" — and what the user can do.
//
// Fix round 2 (review L): the re-import advice is only true where the import
// can actually tell whether the pad was used, i.e. where a native floor exists
// (padWasUsed consults it first, and nothing in the JS context can delete it).
// In a plain browser padWasUsed sees only the three deletable localStorage
// markers — the very keys whose absence produced this refusal — so following
// the advice after an attack reopened a used pad at offset 0: a two-time pad.
function missingRecordError() {
  const lead = "the rollback record for this pad is missing — refusing to use the pad, because pad reuse could no longer be detected. ";
  return new Error(nativeFloor
    ? lead + "If this pad has never sent or received a message here (e.g. the app was closed while it was first being saved), " +
      "Forget it and import the same file again — the import checks this device's protected record of whether it was used; " +
      "otherwise exchange a fresh pad."
    : lead + "In a browser a re-import cannot verify whether this pad was already used, so do not re-import it: " +
      "exchange a fresh pad in person.");
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
  // The id becomes a storage key AND a native-floor key; only randomId()'s
  // shape is acceptable (see PAD_ID_RE).
  if (typeof o.padId !== "string" || !PAD_ID_RE.test(o.padId)) throw new Error("pad file has an invalid pad id");
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
  if (nativeFloor && nativeFloor.broken) throw floorUnavailableError();
  requireDurable();
  // Package 3b: the durable record's `used` hint as well — after a crash it
  // may be the only trace left that this pad ran here (the localStorage
  // markers lost with the rest of an uncommitted batch).
  if (padWasUsed(o.padId) || await durablePadUsed(o.padId)) {
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
  // Package 3: every native slot this blob is about to claim must EXIST before
  // the claim is sealed (armPadFloors throws FLOOR_WRITE_FAILED otherwise, and
  // nothing has been written yet).
  if (nativeFloor) armPadFloors(record.padId);
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
    // Fix round 2 (Info): "exported" was INFERRED (unverifiable history),
    // not recorded by an export on this device — kept so the re-export
    // warning can say so honestly after the next save latches the flag.
    exportedInferred: !!record.exportedInferred,
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
    nativeFloor: !!nativeFloor,
    // Package 3, 2026-08-08 item 13: the same statement for the two DERIVED
    // slots, `recv:<id>` and `exported:<id>`. Without it their deletion was
    // silent: unlockPad only asked "is the SEND slot present?", an ABSENT recv
    // slot contributed 0 to the max(), and an ABSENT exported slot read as
    // "never exported" — so deleting one prefs entry (file access) rewound the
    // receive side (replay of every delivered frame) or re-armed a second
    // export of the same pad (two importers, a two-time pad). `exported` was
    // also only ever written BY an export, so its absence was ambiguous by
    // construction; it is now armed (0) on every save, which is what makes
    // ABSENT mean "deleted" once this flag is set. Written only after
    // armPadFloors has proven both slots exist.
    derivedFloors: !!nativeFloor,
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
  // Package 3b: the durable record, and only once it is ON DISK the native
  // floors. Every caller awaits this function before it transmits, displays or
  // hands out a file, so those now wait for the disk too.
  await writeDurable(record.padId, key, {
    send: wm.send, recv: wm.recv, exported: !!record.exported, role: record.role, regionSize: record.regionSize,
  });
  // AFTER the blob, never before: a floor ahead of the blob it protects reads
  // as a rollback on the next unlock (the A4 F-A1 brick). Behind is harmless —
  // the blob's own hwSend/hwRecv are the higher input to unlockPad's max().
  if (nativeFloor) advancePadFloors(record.padId, wm, record.exported ? 1 : 0);
}

// Package 3 (ROUND-3 F-1 / F-4, A4 F-A1-R1). The three per-pad slots, created
// if missing and otherwise left alone: `bump(slot, 0)` writes an ABSENT slot
// (-1 -> 0) and is a no-op on any existing one, so it can never move a floor
// ahead of a blob. Each answer is checked (bumpFloor), so a slot that did not
// durably land stops the save BEFORE the blob claims it — which is what used
// to burn fresh pads: the claim was sealed first, the bump's failure was
// discarded, and the next unlock called the missing slot a deletion. The send
// slot goes last because it is the one padWasUsed consults first.
const PAD_FLOOR_WHAT = "this one-time pad";
function armPadFloors(id) {
  bumpFloor(nativeFloor, recvFloorId(id), 0, PAD_FLOOR_WHAT);
  bumpFloor(nativeFloor, exportedFloorId(id), 0, PAD_FLOOR_WHAT);
  bumpFloor(nativeFloor, id, 0, PAD_FLOOR_WHAT);
}
// Raise the three slots to what the blob on disk now says, and prove each
// moved. A save whose floor did not advance is a FAILED save: app.js persists
// before it transmits (P-04), so throwing here keeps the ciphertext off the
// wire — the only repair that holds when a failed commit leaves every
// read-back looking healthy (see bumpFloor).
function advancePadFloors(id, wm, exportedNow) {
  bumpFloor(nativeFloor, id, wm.send, PAD_FLOOR_WHAT);
  bumpFloor(nativeFloor, recvFloorId(id), wm.recv, PAD_FLOOR_WHAT);
  bumpFloor(nativeFloor, exportedFloorId(id), exportedNow, PAD_FLOOR_WHAT);
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
  requireDurable();
  if (padWasUsed(record.padId) || await durablePadUsed(record.padId)) {
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
  const survivingRecv = nativeFloor ? nativeFloor.read(recvFloorId(record.padId)) : NATIVE_ABSENT;
  wmCache.set(record.padId, {
    send: maxOf(readLegacyHW(record.padId), survivingNative > NATIVE_ABSENT ? survivingNative : 0),
    recv: maxOf(survivingRecv > NATIVE_ABSENT ? survivingRecv : 0),
  });
  durHigh.delete(record.padId); // a new at-rest key: the old record is not ours to max against
  await writePadBlob(record, key, salt, KDF_ITERS);
  return { key, salt, iters: KDF_ITERS };
}

// Re-save consumption progress during a session using the already-derived key
// (no PBKDF2). `atRest` = { key, salt, iters } from unlock/saveNewPad.
export async function savePadProgress(record, atRest) {
  await writePadBlob(record, atRest.key, atRest.salt, atRest.iters);
}

// Decrypt a stored pad with its passphrase -> { record (bytes+offsets), atRest }.
// `opts.adoptLegacy` — the caller has shown the user the F-1 warning and they
// chose to adopt a pad whose consumption cannot be verified. Never default it to
// true: silent adoption IS the vulnerability.
export async function unlockPad(padId, passphrase, opts = {}) {
  if (typeof padId !== "string" || !PAD_ID_RE.test(padId)) throw new Error("no such pad on this device");
  requireDurable();
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
  // Package 3b: the durable progress record (IndexedDB). Same verdicts as the
  // watermark: damaged = refuse; absent = the rules below as before (a pad
  // saved before 3b, or a deleted record); present = a record, and the one a
  // crash cannot lose.
  let dur = await readDurable(padId, key);
  // Review round 2 (I-6): a re-import under a NEW pad passphrase (saveNewPad:
  // new salt, new key) that crashed between writing its blob and its durable
  // record leaves the previous record, sealed under the OLD key, beside a new
  // blob — which then read as "damaged or forged" and burned a pad that never
  // sent a byte. saveNewPad only runs when that old record says `used: 0`, so
  // exactly that case is recognised and the record replaced (dur === null
  // re-creates it below): the old record's own plaintext says never used AND
  // the blob — authenticated under the new key — is pristine (both offsets,
  // both in-AEAD mirrors, not exported) AND the watermark, if any, is at 0.
  // Anything that says "used" is still refused. Replacing it is no weaker than
  // the record being deleted, which falls back to the pre-3b rules anyway.
  if (dur === "corrupt" && await durableSaysUnused(padId) &&
      sendOffset === 0 && recvHighWater === 0 && (inner.hwSend | 0) === 0 && (inner.hwRecv | 0) === 0 &&
      inner.exported !== true && (outerWm === null || (outerWm.send === 0 && outerWm.recv === 0))) {
    dur = null;
  }
  if (dur === "corrupt") {
    throw new Error(
      "the durable progress record for this pad is damaged or forged — refusing to use the pad; exchange a fresh one",
    );
  }
  const hasRecord = outerWm !== null || dur !== null;

  // F-1: the native floor, where available, is the one input to this decision an
  // attacker holding the JS context cannot touch. Read it BEFORE the localStorage
  // evidence so a forged bridge answer cannot be masked by a clean-looking store.
  if (nativeFloor && nativeFloor.broken) throw floorUnavailableError();
  const native = nativeFloor ? nativeFloor.read(padId) : NATIVE_ABSENT;
  // F-ATREST-001/002: the receive and exported floors, read the same way. A
  // pad written before they existed simply has none (ABSENT contributes 0 /
  // "unknown"), so no legitimate pad is caught; the first post-fix save
  // creates them. Package 3 (item 13): a blob that says it was written with
  // both slots in force (`derivedFloors`) is refused when either is ABSENT —
  // see the deletion checks below.
  const nativeRecv = nativeFloor ? nativeFloor.read(recvFloorId(padId)) : NATIVE_ABSENT;
  const nativeExported = nativeFloor ? nativeFloor.read(exportedFloorId(padId)) : NATIVE_ABSENT;
  if (native === NATIVE_TAMPERED || nativeRecv === NATIVE_TAMPERED || nativeExported === NATIVE_TAMPERED) {
    throw new Error(
      "this pad's device-protected rollback record is damaged or forged — refusing to use the pad; exchange a fresh one",
    );
  }
  // A floor recorded natively but no authenticated record beside it means the
  // record was deleted: the H-3 PoC, and the v2-shaped variant it used to escape
  // through. Unlike `usedKey`, this evidence is not deletable from JS.
  // (Package 3b: "no authenticated record" now means neither the watermark
  // nor the durable record — after a crash the durable one may be all there is.)
  if (native > NATIVE_ABSENT && !hasRecord) {
    throw missingRecordError();
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
  // Package 3, 2026-08-08 item 13: the same converse for the DERIVED slots. The
  // check above covered the send slot only, so deleting `recv:<id>` rewound the
  // receive side past the max() below (ABSENT contributes 0) and deleting
  // `exported:<id>` read as "never exported" — a replay of every delivered
  // frame, or a second export of one pad. `derivedFloors` is inside the AEAD
  // and is only sealed after both slots were armed (writePadBlob), so ABSENT
  // next to it is deletion, not a pad from before the slots existed.
  if (inner.derivedFloors === true && (nativeRecv === NATIVE_ABSENT || nativeExported === NATIVE_ABSENT)) {
    throw new Error(
      "part of this pad's device-protected rollback record has been deleted — refusing to use the pad, because replayed messages or a second export could no longer be detected; exchange a fresh pad",
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
  // Package 3 (F-P7-A3 residual): `isInt`, not `Number.isInteger` — see isInt.
  const knownUsedHere = isInt(inner.hwSend) || isInt(inner.hwRecv) ||
    localStorage.getItem(usedKey(padId)) !== null;
  if (!hasRecord && knownUsedHere) {
    // H-3: this is the reported PoC — restore an old blob, delete the watermark.
    // A pad that has demonstrably run on this device but can no longer produce
    // its watermark FAILS CLOSED. (No record AND no evidence = a pad written
    // before this fix, adopted below.)
    throw missingRecordError();
  }
  // Package 3b, owner decision 2026-09-25: HEAL FORWARD.
  //
  // This used to be max(outer, inner, legacy, native) with a REFUSAL whenever
  // the blob's own offsets were below it. After a crash that is the ordinary
  // state, not an attack: the blob's last localStorage write never reached
  // disk while the durable record (or the watermark, written in a later task
  // and so possibly in a later commit batch) did — and on Android the native
  // floor with them. Refusing burned the pad; opening at the blob's offset
  // (the pre-package-3 behaviour) reused key material. Now the pad opens at
  // the highest offset any AUTHENTICATED record of it reached: the blob, its
  // in-AEAD mirror, the watermark and the durable record — every one sealed
  // under the pad's key, so none can be raised by a JS-context attacker, and
  // the only effect of a higher one is that pad bytes are skipped.
  //
  // Two inputs never heal, they only refuse, as before:
  //   * the legacy plaintext watermark (attacker-writable; written only by
  //     pre-fix code, never by a crash);
  //   * the native floor. A floor ahead of EVERY data record — the durable one
  //     included — cannot come from a crash any more (the floor is advanced
  //     only after the durable write completed), so it is what it always was:
  //     evidence that the pad's state was rolled back (or its data lost), and
  //     the pad is refused.
  const data = {
    send: maxOf(sendOffset, inner.hwSend | 0, outerWm ? outerWm.send : 0, dur ? dur.send : 0),
    recv: maxOf(recvHighWater, inner.hwRecv | 0, outerWm ? outerWm.recv : 0, dur ? dur.recv : 0),
  };
  // Review round 1 (HIGH, pentest-new-code): never heal a v1 blob. Its
  // `role` / `regionSize` sit OUTSIDE the AEAD and the upgrade re-seals under
  // the same key, so an archived v1 copy decrypts beside the current records;
  // healing it opened the pad with the attacker's outer role — sending from
  // the peer's half, a two-time pad. Pre-3b this state was refused ("blob
  // below its records"), and for v1 it still is. (The durable record's sealed
  // geometry, checked below, binds every other blob shape.)
  if (legacy && (sendOffset < data.send || recvHighWater < data.recv)) {
    throw new Error("pad state was rolled back (consumed key material) — refusing to use it; exchange a fresh pad");
  }
  if (data.send < maxOf(readLegacyHW(padId), native > NATIVE_ABSENT ? native : 0)) {
    throw new Error("pad state was rolled back (consumed key material) — refusing to use it; exchange a fresh pad");
  }
  const wm = { send: data.send, recv: data.recv };
  if (data.recv < (nativeRecv > NATIVE_ABSENT ? nativeRecv : 0)) {
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
  //
  // Package 3, F-P7-5: and "pre-v3" is decided by the blob's AUTHENTICATED
  // shape, never by the outer `v` byte. This line used to read
  // `(o.v || 1) < PAD_BLOB_V` — the very downgrade trap the top of unlockPad
  // warns about, one version later: an archived v2 blob restored with its outer
  // `"v"` rewritten to 3 (no key needed — it is plaintext), plus the deletable
  // markers removed, skipped this gate and opened SILENTLY at its old offset in
  // a browser, where no native floor stands behind it. A two-time pad. Only a
  // blob written by v3 code carries `hwSend` inside the AEAD, and forging it
  // needs the pad passphrase.
  const preV3 = legacy || !isInt(inner.hwSend);
  const needsAdoption = preV3 && !hasRecord;
  if (needsAdoption && !opts.adoptLegacy) {
    const err = new Error(
      "this pad has no usage record on this device. If it has ever sent a message, that record has been deleted and the pad is NOT safe to use — exchange a fresh one.",
    );
    err.code = "LEGACY_PAD_ADOPTION";
    err.padId = padId;
    // True = this device has demonstrably run OTP under the current code, so a
    // pad with no record is a much stronger signal of tampering than it would be
    // on a device that just upgraded.
    err.suspicious = localStorage.getItem(EPOCH_KEY) !== null ||
      localStorage.getItem(usedKey(padId)) !== null;
    throw err;
  }
  // Package 3 fix round 1 (pentest M, item-13 residual, receive half). The
  // `derivedFloors` check above only binds blobs written by this build, and a
  // file-level attacker simply restores an OLDER blob (one without the flag)
  // together with its watermark and deletes `recv:<id>`: the pad then opened
  // at the old receive offset and replayed every frame delivered since. The
  // flag cannot be made retroactive, but the SEND slot can stand in for it:
  // every build that wrote the send slot since 22318a1 (v0.1.0) also wrote
  // `recv:` on the same save, and this build arms `recv:` before the send slot.
  // So "send slot present, recv slot absent" is a deletion — or a pad last
  // saved by a pre-v0.1.0 build, which cannot be told apart. That is exactly
  // the adoption gate's job: refuse by default, open only on the user's
  // explicit consent (the next save arms `recv:` and the question never comes
  // back for this pad).
  if (native > NATIVE_ABSENT && nativeRecv === NATIVE_ABSENT && !opts.adoptLegacy) {
    const err = new Error(
      "this pad's device-protected receive record is missing. If you have received messages with this pad on this device, that record has been deleted and old messages could be replayed as new — exchange a fresh pad.",
    );
    err.code = "LEGACY_PAD_ADOPTION";
    err.padId = padId;
    err.suspicious = true; // a floor exists: this device has run floor-era code with this pad
    err.recvRecord = true; // app.js words the consent for the receive side
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
  // Review round 1: the blob's geometry must be the one the durable record
  // sealed. A mismatch is not a crash artefact (role and size never change),
  // it is a substituted or tampered blob.
  if (dur && (dur.role !== role || dur.regionSize !== regionSize)) {
    throw new Error("stored pad does not match its durable progress record (role or size) — refusing to use it; exchange a fresh pad");
  }
  if (wm.send > regionSize || wm.recv > regionSize) {
    throw new Error("this pad's progress records point past its end — refusing to use it; exchange a fresh pad");
  }
  // Package 3b: the heal. The bytes between the blob's offsets and the healed
  // ones were consumed in the session whose last save did not reach disk, so
  // they are zeroed here exactly as the cipher would have zeroed them (forward
  // secrecy; the next save writes them out as zero).
  const healed = wm.send > sendOffset || wm.recv > recvHighWater;
  if (wm.send > sendOffset) bytes.fill(0, role * regionSize + sendOffset, role * regionSize + wm.send);
  if (wm.recv > recvHighWater) bytes.fill(0, (1 - role) * regionSize + recvHighWater, (1 - role) * regionSize + wm.recv);
  if (dur) {
    const prev = durHigh.get(padId);
    durHigh.set(padId, {
      send: maxOf(dur.send, prev ? prev.send : 0), recv: maxOf(dur.recv, prev ? prev.recv : 0),
      exported: !!(dur.exported || (prev && prev.exported)),
    });
  }
  const record = {
    padId,
    label: src.label,
    regionSize,
    role,
    createdAt: src.createdAt,
    bytes,
    sendOffset: wm.send,
    recvHighWater: wm.recv,
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
    //
    // F-ATREST-002: the native `exported:` floor can only turn the flag ON.
    // A restored pre-export blob carries `exported: false` inside a perfectly
    // valid AEAD, and its send floor is 0 because exportPad only ever exports
    // a pristine pad — so the floor is the one record of the export that a
    // snapshot restore cannot rewind. TAMPERED was refused above.
    //
    // Package 3 fix round 1 (pentest M, export half): and when the send slot
    // exists but `exported:` does not, the flag is UNKNOWN, so it is TRUE.
    // Before this build `exported:` was written only BY an export, so its
    // absence could not be told from its deletion: restore a pre-export blob
    // (no `derivedFloors`), delete the slot, and a pad already exported under
    // v0.3.x offered a silent second export — a two-time pad. Unlike the
    // receive side this needs no prompt: assuming "exported" only costs a
    // confirm on re-export (exportPad refuses a used pad anyway), and the next
    // save latches it (writePadBlob advances `exported:` to 1).
    // Package 3b: and the durable record's flag — an export latched just
    // before a crash whose blob write was lost is still an export.
    exported: nativeExported >= 1 || (dur !== null && dur.exported) ||
      (native > NATIVE_ABSENT && nativeExported === NATIVE_ABSENT) ||
      (inner.exported !== undefined ? !!inner.exported : true),
    // Fix round 2 (Info): true when that TRUE comes only from missing
    // evidence (the slot or the in-AEAD flag absent), not from an export
    // recorded on this device. Only the wording of the re-export warning
    // depends on it; the confirm stays.
    exportedInferred: inner.exportedInferred === true ||
      (nativeExported < 1 && inner.exported !== true && !(dur !== null && dur.exported) &&
        (inner.exported === undefined || (native > NATIVE_ABSENT && nativeExported === NATIVE_ABSENT))),
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
  // (Package 3, F-P7-5: keyed on the inner shape for the same reason as the
  // adoption gate — an outer `v` of 3 on a v2 blob used to skip this upgrade
  // too, leaving the pad without its authenticated watermark mirror.)
  //
  // Package 3b: also rewritten when it was HEALED (so localStorage catches up
  // and the skipped bytes are zeroed on disk), and when it has no durable
  // record yet — the one-time adoption of every pad saved before 3b: its
  // record starts at the offsets just verified.
  if (preV3 || healed || dur === null) await writePadBlob(record, key, salt, iters);
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
  record.exportedInferred = false; // a real export on this device, from here on
  // F-ATREST-002: recorded natively FIRST, so a crash between the two writes
  // leaves the stronger record in place, not the weaker one. Package 3: and
  // CHECKED — this latch is the only record of the export a snapshot restore
  // cannot rewind, and app.js hands out the file only after this returns (F).
  if (nativeFloor) bumpFloor(nativeFloor, exportedFloorId(record.padId), 1, PAD_FLOOR_WHAT);
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
    const native = nativeFloor.read(padId);
    const recv = nativeFloor.read(recvFloorId(padId));
    const exported = nativeFloor.read(exportedFloorId(padId));
    // TAMPERED (a forged record, or a marker with no working bridge) counts as
    // used: an import must never be the way to escape a damaged floor.
    if (native === NATIVE_TAMPERED || recv === NATIVE_TAMPERED || exported === NATIVE_TAMPERED) return true;
    // Package 3 (A4 F-A1-R1): a slot's EXISTENCE is no longer evidence of use,
    // only its VALUE. This used to be `native !== NATIVE_ABSENT`, and the send
    // slot was created at 0 by the pad's first save — so a first save that
    // failed after the slot landed (the blob write hit the storage quota, a
    // later bump did not commit) burned a freshly imported pad for good: every
    // re-import said "already been used", and the in-person exchange was lost.
    // Since Package 3 writePadBlob ARMS all three slots at 0 before the blob is
    // written, which makes that the ordinary failure mode, not a corner case.
    //
    // Why a floor of 0 can safely be ignored: every advance is now checked
    // (advancePadFloors), and a save whose advance did not land FAILS — and
    // app.js persists before it transmits (P-04). So "send 0, recv 0, exported
    // 0" is exactly "no ciphertext ever left this device from this pad, nothing
    // was received on it, it was never exported": re-importing the pristine
    // file recreates that same state and reuses nothing. Any value above 0 is
    // use, and still refuses. (With every slot at 0 the deletable markers below
    // still answer — they are what stops an ordinary re-import of a saved pad.)
    if (native > 0 || recv > 0 || exported > 0) return true;
  }
  return localStorage.getItem(usedKey(padId)) !== null ||
    localStorage.getItem(wmKey(padId)) !== null ||
    readLegacyHW(padId) > 0;
}
