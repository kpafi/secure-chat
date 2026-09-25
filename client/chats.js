// Encrypted on-device chat store (the "Chats" view).
//
// Same at-rest posture as contacts.js: PBKDF2-600k → AES-256-GCM under the
// IDENTITY passphrase, key in memory only while unlocked. Message HISTORY is
// sensitive plaintext, so it must never touch localStorage unencrypted.
//
// Model: one chat per contact username. Each chat:
//   { username, mode, secret?, pending?, messages:[…], updatedAt }
// `mode` is the chat's LOCKED encryption mode. All async traffic rides the
// sealed envelope (that is the transport security); the mode adds an optional
// INNER layer on top:
//   * "SEALED" — no inner layer (hybrid PQ transport only).
//   * "AES256" — inner AES-256-GCM under a per-chat passphrase agreed out of
//     band, so even a break of the recipient's long-term transport keys does
//     not reveal chat text. `secret` holds that passphrase (protected at rest
//     by the identity-keyed store, like everything here).
// A mode change is NEGOTIATED: one side proposes, the other must accept before
// either switches (`pending` = {mode, dir, salt?}). `id` is the envelope id
// for inbound dedup (a retried fetch after a lost response could deliver
// twice).

const LS_CHATS = "sc.chats.v1";
// Pentest 2026-08-07 F-ATREST-005: the chat store had no domain tag, no
// generation and no witness — one `removeItem` emptied the envelope-replay
// ring (`seenIds`, P-13) and every negotiated AES256 mode, and restoring an
// older blob rewound the ring so every envelope since the snapshot replayed.
// It now carries the contact store's mechanism: a tagged plaintext with a
// generation, an AEAD witness beside it (own salt, own domain tag so neither
// witness can be swapped for the other — the H-2 lesson), and on Android the
// per-identity native floor. Two deliberate departures from contacts.js:
//   * no compare-and-swap refusal on persist — this store is written on every
//     inbound envelope, and two tabs of one account polling the mailbox is a
//     real scenario (the M-C self-DoS); a stale tab's write is accepted and
//     numbered past the witness instead, so the store is never BEHIND it;
//   * an untagged pre-v2 blob is NEVER adopted silently — an explicit choice
//     (every deployed chat store is untagged, so every user sees the prompt
//     exactly once on upgrade), and with a floor present it is refused
//     outright. The first cut adopted silently when the plaintext epoch
//     marker was absent; the fix review (2026-09-21) showed one extra
//     removeItem of that marker restored the entire finding in a browser.
//     A deletable marker may escalate a warning, never authorise anything.
const LS_CHATS_GEN = "sc.chats.gen.v1";
const CHATS_DOMAIN = "secure-chat/chats-store/v2";
const CHATS_GEN_DOMAIN = "secure-chat/chats-generation/v1";
const EPOCH_KEY = "sc.chats.epoch.v1";
import {
  captureNativeFloor, NATIVE_ABSENT, NATIVE_TAMPERED, floorUnavailableError, bumpFloor, FLOOR_MAX,
} from "./nativefloor.js";
const nativeFloor = captureNativeFloor();
// Package 3b (owner decision 2026-09-25): store + witness in IndexedDB, strict
// durability, one-time migration from localStorage — see durable.js storeSlot
// and the matching notes in contacts.js.
import { storeSlot } from "./durable.js";
const slot = storeSlot({ blobKey: LS_CHATS, genKey: LS_CHATS_GEN, marker: "sc.chats.idb.v1" });
export const ready = slot.ready;
const KDF_ITERS = 600000;
const MAX_MESSAGES_PER_CHAT = 500; // keep the newest; bound the blob size

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

let dataKey = null;
let salt = null;
let chats = null; // { username: chat } while unlocked
let generation = 0;
let floorKey = null;
let expectedStore = false;

function readFloor() {
  if (!nativeFloor || !floorKey) return NATIVE_ABSENT;
  if (nativeFloor.broken) throw floorUnavailableError("your chat history");
  return nativeFloor.read(floorKey);
}

function adoptionError(message, code) {
  lock();
  const err = new Error(message);
  err.code = code;
  err.suspicious = localStorage.getItem(EPOCH_KEY) !== null;
  return err;
}

// The witness: {d: CHATS_GEN_DOMAIN, gen} under the data key with its OWN salt,
// so it stays readable when the store that would hold the salt is gone.
// `raw`: the witness read together with the store; left out, read fresh (3b).
async function readWitness(passphrase = null, raw = undefined) {
  if (raw === undefined) raw = await slot.readWitness();
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
    const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: unb64(rec.iv) }, key, unb64(rec.ct));
    const w = JSON.parse(dec.decode(plain));
    if (w.d !== CHATS_GEN_DOMAIN || !Number.isInteger(w.gen)) return { corrupt: true };
    return w;
  } catch {
    return { corrupt: true };
  }
}

// Sealed and RETURNED: persist() writes it with the store in one transaction.
async function sealWitness(gen, key, saltBytes) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const plain = enc.encode(JSON.stringify({ d: CHATS_GEN_DOMAIN, gen }));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, plain));
  return JSON.stringify({
    salt: b64(saltBytes), iters: KDF_ITERS, iv: b64(iv), ct: b64(ct),
  });
}

// Pentest 2026-07-26 P-20: the store is keyed by a directory username, and the
// server's charset (^[a-z0-9_.-]+$, 3-32) makes `__proto__` and `constructor`
// registerable handles. On a normal object `chats["constructor"]` returns an
// INHERITED value, so ensure()/append()/get() treated a non-existent chat as
// existing and then threw a TypeError that escaped through the Chats view. A
// null-prototype object has nothing to inherit, so every key is either an own
// property or undefined.
function newStore(from = null) {
  const store = Object.create(null);
  if (from && typeof from === "object") {
    for (const k of Object.keys(from)) store[k] = from[k];
  }
  return store;
}

export function isUnlocked() {
  return dataKey !== null;
}

export function lock() {
  dataKey = null;
  salt = null;
  chats = null;
  generation = 0;
  floorKey = null;
}

// True when a chat store is expected on this device (blob, witness, or a
// native floor seen by the last unlock), like contacts.hasStore().
// Package 3b: over the slot's preloaded state; TRUE until the preload settled.
export function hasStore() {
  return expectedStore || slot.known();
}

// Same options as contacts.unlock: `floorId`, `adoptLegacy`, `adoptDeleted`.
// Review round 3 (F2): see the conflict note in unlock(). Never throws.
async function conflictIsNewerCopy(passphrase, conflict, idbBlob, idbWitness) {
  try {
    const wl = conflict.witness ? await readWitness(passphrase, conflict.witness) : null;
    const wi = idbWitness ? await readWitness(passphrase, idbWitness) : null;
    if (!wl || wl.corrupt || !wi || wi.corrupt || !(wl.gen > wi.gen)) return false;
    const cb = JSON.parse(conflict.blob);
    const ib = JSON.parse(idbBlob);
    if (!cb || !ib || typeof cb.salt !== "string" || cb.salt !== ib.salt) return false;
    const key = await deriveKey(passphrase, unb64(cb.salt), cb.iters || KDF_ITERS);
    const plain = JSON.parse(dec.decode(await crypto.subtle.decrypt({ name: "AES-GCM", iv: unb64(cb.iv) }, key, unb64(cb.ct))));
    return !!plain && typeof plain === "object" && plain.d === CHATS_DOMAIN && plain.gen === wl.gen;
  } catch {
    return false;
  }
}

export async function unlock(passphrase, opts = {}) {
  if (!passphrase) throw new Error("passphrase required to unlock the chat store");
  floorKey = opts.floorId ? "chats:" + opts.floorId : null;
  const floor = readFloor();
  if (floor === NATIVE_TAMPERED) {
    lock();
    throw new Error("the device-protected record for your chat history is damaged or forged — refusing to open it");
  }
  let raw, rawWitness, lost = false, conflict = null;
  try {
    ({ blob: raw, witness: rawWitness, lost = false, conflict = null } = await slot.read());
  } catch (e) {
    lock();
    throw e;
  }
  // Review round 2 (L-2), hardened in round 3 (F2): a blob in localStorage
  // beside the IndexedDB store — normally what a tab still running the previous
  // version wrote after the migration. It is adopted ONLY when it is provably
  // the newer state of THIS store: its witness decrypts under this passphrase
  // at a higher generation than IndexedDB's, the blob itself decrypts, carries
  // the store's domain tag and exactly that generation, and has the same salt
  // as the IndexedDB store (a genuine old-tab save re-uses it; a Forget +
  // re-create, i.e. an earlier incarnation, has another). Adoption used to be
  // decided on the witnesses alone and wrote the blob into IndexedDB before
  // anything authenticated it: two setItem calls brought back an earlier
  // incarnation's pins (alarm inverted), a garbage blob overwrote the good
  // store. Anything else is DROPPED (reported), and IndexedDB is not touched.
  let conflictDropped = false;
  let conflictAdopted = false;
  if (conflict) {
    const adopt = await conflictIsNewerCopy(passphrase, conflict, raw, rawWitness);
    await slot.resolve(conflict, adopt);
    if (adopt) {
      raw = conflict.blob; rawWitness = conflict.witness; conflictAdopted = true;
    } else {
      conflictDropped = true;
    }
  }
  if (!raw) {
    const w = await readWitness(passphrase, rawWitness);
    // Package 3: `floor > 0` — a floor of 0 is a slot persist() armed for a
    // first save that never completed; it is not evidence of a store (see
    // contacts.js, same branch).
    if (w !== null || floor > 0 || lost) { // `lost`: see contacts.js (review round 1)
      // A store existed here (witness, or on Android the floor) and is gone:
      // the replay ring and negotiated modes with it. Explicit choice, never a
      // silent fresh start — the same rule as the contact store.
      expectedStore = true;
      if (!opts.adoptDeleted) {
        const gen = w && !w.corrupt ? w.gen : floor;
        throw adoptionError(
          `your chat history${gen > 0 ? ` (generation ${gen})` : ""} has been DELETED from this device — refusing to start over ` +
          "silently, because already-delivered messages could then be replayed and per-chat encryption " +
          "settings are gone. If you did not Forget this identity yourself, treat this device as tampered.",
          "DELETED_CHATS_ADOPTION",
        );
      }
    }
    // Review round 4 (L-1): see contacts.js — drop a stray localStorage copy
    // before starting over, or the fresh store could never save.
    const strayDropped = lost && opts.adoptDeleted ? slot.dropStray() : false;
    salt = crypto.getRandomValues(new Uint8Array(16));
    dataKey = await deriveKey(passphrase, salt, KDF_ITERS);
    chats = newStore();
    generation = floor > NATIVE_ABSENT ? floor : 0;
    await persist();
    expectedStore = false;
    return strayDropped ? { created: true, conflictDropped: true } : { created: true };
  }
  expectedStore = true;
  // Second fix round (re-review of 9a38d97, I-1): a SyntaxError echoes ~20
  // characters of what is in localStorage — a planted value with a newline or
  // U+202E — into the locked panel and the transcript. A fixed sentence.
  let blob;
  try {
    blob = JSON.parse(raw);
  } catch {
    throw new Error("the chat store on this device is not readable (damaged or replaced)");
  }
  salt = unb64(blob.salt);
  dataKey = await deriveKey(passphrase, salt, blob.iters || KDF_ITERS);
  let plain;
  try {
    plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: unb64(blob.iv) }, dataKey, unb64(blob.ct));
  } catch {
    lock();
    throw new Error("chat store does not decrypt with this passphrase (different identity, or tampered)");
  }
  const data = JSON.parse(dec.decode(plain));
  if (!data || typeof data !== "object" || Array.isArray(data)) {
    lock();
    throw new Error("the chat store on this device is not a chat store — refusing to open it");
  }
  // The discriminator is the tag INSIDE the AEAD, never the outer `v` byte
  // (H-2 / P-01). Untagged = the pre-v2 shape: a bare {username: chat} map.
  const tagged = Object.prototype.hasOwnProperty.call(data, "d");
  if (tagged && data.d !== CHATS_DOMAIN) {
    lock();
    throw new Error("the chat store on this device is not a chat store — refusing to open it");
  }
  const map = tagged ? data.chats : data;
  if (!map || typeof map !== "object" || Array.isArray(map) ||
      Object.values(map).some((c) => !c || typeof c !== "object" || !Array.isArray(c.messages))) {
    lock();
    throw new Error("the chat store on this device is not a chat store — refusing to open it");
  }
  generation = tagged && Number.isInteger(data.gen) ? data.gen : 0;

  // Rollback / deletion detection, in the contact store's order: witness
  // verdicts first (specific wording), then the floor, then adoption.
  const w = await readWitness(null, rawWitness);
  if (w === null) {
    if (tagged) {
      lock();
      throw new Error("the generation record for your chat history is missing — refusing to open it, because a rollback could no longer be detected");
    }
  } else if (w.corrupt) {
    lock();
    throw new Error("the generation record for your chat history is damaged or forged");
  } else if (generation < w.gen) {
    // Review round 2 (I-4): message first, then lock() (which resets it).
    const err = new Error(
      `your chat history is OLDER than this device recorded (generation ${generation}, expected ${w.gen}) — ` +
      "an earlier copy has been restored, which would let already-delivered messages replay",
    );
    lock();
    throw err;
  }
  if (floor > NATIVE_ABSENT && generation < floor) {
    const err = new Error(
      `your chat history is OLDER than this device recorded (generation ${generation}, device record ${floor}) — ` +
      "an earlier copy has been restored, which would let already-delivered messages replay",
    );
    lock();
    throw err;
  }
  if (data.nativeFloor === true && floorKey && floor === NATIVE_ABSENT) {
    lock();
    throw new Error("the device-protected record for your chat history has been deleted — refusing to open it, because a rollback could no longer be detected");
  }
  if (!tagged) {
    // Pre-v2 blob (no witness, or it would have been refused above). On a
    // device that has run this code before, that is a restore; adoption is
    // the user's call. On a fresh upgrade it is simply the old format.
    // (`> 0`: an armed-but-never-saved slot proves nothing — Package 3.)
    if (floor > 0) {
      lock();
      throw new Error("your chat history has no rollback record but this device says it had one — an earlier copy has been restored; refusing to open it");
    }
    if (!opts.adoptLegacy) {
      throw adoptionError(
        "your chat history has no rollback record on this device. If you have used this device with " +
        "these chats before, an older copy may have been restored, which would let already-delivered " +
        "messages replay; if you just upgraded, this is expected once.",
        "LEGACY_CHATS_ADOPTION",
      );
    }
  }
  // P-20: JSON.parse yields a normal object (with a prototype); re-key it into a
  // null-prototype store before anything indexes it by a username.
  chats = newStore(map);
  let dirty = sanitizeModes();
  if (!tagged) dirty = true; // upgraded in place so adoption happens once
  if (floorKey && nativeFloor && slot.durable() && data.nativeFloor !== true) dirty = true;
  if (dirty) await persist();
  if (conflictAdopted) return { created: false, conflictAdopted: true };
  return conflictDropped ? { created: false, conflictDropped: true } : { created: false };
}

// Repair a store written before the F-02 allow-list existed: a chat whose mode
// (or pending proposal) holds an unrecognised string was never actually using
// an inner layer, so SEALED is both the safe and the accurate value. Without
// this an already-poisoned chat would keep rendering the attacker's string.
function sanitizeModes() {
  let changed = false;
  for (const c of Object.values(chats || {})) {
    if (!isValidMode(c.mode)) {
      c.mode = "SEALED";
      delete c.secret;
      delete c.salt;
      changed = true;
    }
    if (c.pending && !isValidMode(c.pending.mode)) {
      delete c.pending;
      changed = true;
    }
  }
  return changed;
}

// Review round 2 (L-1): saves are SERIALIZED per store. They used to overlap:
// save 1 armed the floor at N, took N+1, and awaited its encryption and its
// strict IndexedDB write; save 2, started meanwhile (mail arriving while the
// user sends, an inbound upsert racing an edit), armed the floor at N+1 —
// the generation save 1 had not yet committed. On Android a kill in that
// window left the floor AHEAD of the data: "OLDER than this device recorded",
// no override. And when the two encryptions finished out of order the older
// snapshot committed LAST under a witness sealed from the live counter — a
// regressed store even without a crash. Now each save runs alone, reads the
// state when it runs, seals the generation it is writing, and the counter —
// and with it every arm/advance of the floor — moves only once that
// generation's durable write has completed.
let persistChain = Promise.resolve();
function persist() {
  const run = persistChain.then(persistNow, persistNow);
  persistChain = run.then(() => {}, () => {});
  return run;
}

async function persistNow() {
  if (!dataKey) throw new Error("chat store is locked");
  // Review round 4 (info): what this save belongs to, fixed when it starts —
  // the wipe epoch (a Forget in between makes write() refuse) and the salt
  // (so nothing below depends on lock() having nulled it meanwhile).
  const epochAtStart = slot.epoch();
  const saltAtStart = salt;
  // Review round 3 (F1): see contacts.js — an older-version tab wrote the store
  // to localStorage since we read it; refuse rather than race it.
  if (slot.foreignCopy()) {
    lock();
    const err = new Error(
      "your chat history was changed by an older version of the app in another tab — this page is out of date. " +
      "Close the other tab, then reload.",
    );
    err.code = "STALE";
    throw err;
  }
  // Number past whatever the witness holds (another tab may have written): the
  // store must never end up BEHIND its own witness, or the next unlock reads
  // an honest concurrent write as a rollback. Deliberately not a refusal — see
  // the note at the top of the file.
  const w = await readWitness();
  if (w && !w.corrupt && w.gen > generation) generation = w.gen;
  // Package 3 (ROUND-3 F-1 / F-4, A4 F-A1-R1, 7b): the same arm-check-claim
  // order as contacts.js persist() — the slot must provably exist before the
  // blob claims it, the advance below is checked, a failed floor write locks
  // the store, and the int32 ceiling is a loud refusal rather than a freeze.
  // Package 3b: the floor only where the store is durable (IndexedDB) — see
  // contacts.js persist for why the localStorage fallback must not advance it.
  const floored = !!(nativeFloor && floorKey) && slot.durable();
  if (floored) {
    if (generation >= FLOOR_MAX) {
      lock();
      const err = new Error(
        "your chat history has reached the highest generation this device's rollback record can hold — " +
        "refusing to save further changes, because they could no longer be protected against rollback",
      );
      err.code = "FLOOR_WRITE_FAILED";
      throw err;
    }
    armOrLock(generation);
  }
  const next = generation + 1; // committed to `generation` only after the write (review round 2)
  const key = dataKey;
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const plain = enc.encode(JSON.stringify({
    d: CHATS_DOMAIN, chats, gen: next, nativeFloor: floored,
  }));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, plain));
  const blobStr = JSON.stringify({ v: 2, iters: KDF_ITERS, salt: b64(saltAtStart), iv: b64(iv), ct: b64(ct) });
  // Package 3b: one strict transaction for store + witness, completed before
  // this returns; the native floor only after it (never ahead of the data).
  if (!(await slot.write(blobStr, await sealWitness(next, key, saltAtStart), epochAtStart))) return; // wiped (Forget) since this save began
  if (dataKey !== key) return; // locked meanwhile
  generation = next;
  if (floored) armOrLock(generation);
  localStorage.setItem(EPOCH_KEY, "1");
}

// bumpFloor, plus: a floor write that failed locks the store (see contacts.js
// armOrLock for why — the in-memory state is ahead of what is protected).
function armOrLock(value) {
  try {
    bumpFloor(nativeFloor, floorKey, value, "your chat history");
  } catch (e) {
    lock();
    throw e;
  }
}

// Package 3b: returns the promise of the IndexedDB deletion (app.js awaits it).
export function wipe() {
  const done = slot.wipe();
  lock();
  expectedStore = false;
  return done;
}

// ---- AES256 inner layer ---------------------------------------------------
// Extra AES-256-GCM under the per-chat passphrase, applied to the plaintext
// BEFORE it is sealed (and after it is opened). PBKDF2 salt is fixed per chat
// (agreed at negotiation) so both sides derive the same key.

// The inner salt arrives inside a PEER's `mode-propose` control message.
// Pentest 2026-07-26 P-06: it used to be stored verbatim and fed straight into
// PBKDF2 with no validation — while this very file bounds salt length and
// iteration count for its OWN at-rest KDF a few lines above. A peer could send
// an empty salt, one fixed constant reused across all their victims (removing
// the per-chat separation that makes 600k iterations worth running, and enabling
// precomputation against the shared passphrase), or a multi-megabyte string.
// Enforce exactly the 16 random bytes `newInnerSalt` produces.
const INNER_SALT_BYTES = 16;

export function isValidInnerSalt(saltB64) {
  if (typeof saltB64 !== "string" || saltB64.length > 64) return false;
  let raw;
  try {
    raw = unb64(saltB64);
  } catch {
    return false;
  }
  return raw.length === INNER_SALT_BYTES;
}

async function innerKey(secret, saltB64) {
  if (!isValidInnerSalt(saltB64)) {
    throw new Error("invalid chat salt (expected 16 random bytes) — refusing to derive a key");
  }
  const base = await crypto.subtle.importKey("raw", enc.encode(secret), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: unb64(saltB64), iterations: KDF_ITERS, hash: "SHA-256" },
    base,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

export function newInnerSalt() {
  return b64(crypto.getRandomValues(new Uint8Array(INNER_SALT_BYTES)));
}

export async function innerEncrypt(secret, saltB64, text) {
  const key = await innerKey(secret, saltB64);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, enc.encode(text)));
  return b64(iv) + "." + b64(ct);
}

export async function innerDecrypt(secret, saltB64, blob) {
  const [ivB64, ctB64] = blob.split(".");
  const key = await innerKey(secret, saltB64);
  const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: unb64(ivB64) }, key, unb64(ctB64));
  return dec.decode(pt);
}

// ---- chats ----------------------------------------------------------------

// The ONLY modes a chat may ever be in. Pentest 2026-07-25 F-02: the mode
// arrives inside a peer's control message. It is authenticated (they signed it)
// but it is not trusted — an unrecognised string used to be stored verbatim and
// rendered into the padlocked mode indicator, while every behavioural check is
// an exact `mode === "AES256"` compare. The result was a chat whose header
// claimed "🔒 AES256 + <attacker text>" while no inner layer was applied and no
// passphrase was ever requested. Reject anything off this list before it can be
// stored, so an unknown mode can never reach the UI or the send path.
export const MODES = Object.freeze(["SEALED", "AES256"]);

export function isValidMode(mode) {
  return MODES.includes(mode);
}

function requireValidMode(mode) {
  if (!isValidMode(mode)) throw new Error(`unsupported chat mode: ${String(mode).slice(0, 40)}`);
}

export function list() {
  if (!chats) throw new Error("chat store is locked");
  return Object.values(chats)
    .map((c) => ({ ...c, messages: c.messages.slice() }))
    .sort((a, b) => b.updatedAt - a.updatedAt);
}

export function get(username) {
  if (!chats) throw new Error("chat store is locked");
  const c = chats[username];
  return c ? { ...c, messages: c.messages.slice() } : null;
}

export async function ensure(username, mode = "SEALED") {
  if (!chats) throw new Error("chat store is locked");
  requireValidMode(mode);
  if (!chats[username]) {
    chats[username] = { username, mode, messages: [], seenIds: [], updatedAt: Date.now() };
    await persist();
  }
  return get(username);
}

// Pentest 2026-07-26 P-13: envelope de-duplication used to be a scan of
// `c.messages`, which MAX_MESSAGES_PER_CHAT trims — so once a conversation
// passed 500 messages a hostile mailbox could re-deliver an old envelope and it
// would be appended at the END (render order is array order), making an old
// "yes, go ahead" look like the newest message. Worse, CONTROL envelopes never
// reached that check at all, so a mailbox could replay mode-propose/decline
// frames indefinitely. The seen-id ring is kept independently of the display
// history and covers every envelope kind.
const MAX_SEEN_IDS = 2000;

// The envelope id is chosen by the SENDER, so it is peer-controlled data that we
// are about to write to disk. `newEnvelopeId` mints 16 random bytes as base64
// (24 chars); anything longer is either a bug or an attempt to inflate the store
// (and the ring holds MAX_SEEN_IDS of them). Cap it rather than trusting it —
// the same reasoning that validates the peer-supplied PBKDF2 salt above.
const MAX_ENVELOPE_ID_CHARS = 64;

function isStorableId(id) {
  return typeof id === "string" && id.length > 0 && id.length <= MAX_ENVELOPE_ID_CHARS;
}

// Record `id` as seen for this chat. Returns false if it was already seen (i.e.
// the caller should DROP the envelope as a replay/duplicate).
export async function markSeen(username, id) {
  if (!chats) throw new Error("chat store is locked");
  if (!id) return true;              // no id to dedup on: caller decides
  if (!isStorableId(id)) return false; // implausible id: drop, and store nothing
  if (!chats[username]) await ensure(username);
  const c = chats[username];
  if (!Array.isArray(c.seenIds)) c.seenIds = [];
  if (c.seenIds.includes(id)) return false;
  c.seenIds.push(id);
  if (c.seenIds.length > MAX_SEEN_IDS) c.seenIds = c.seenIds.slice(-MAX_SEEN_IDS);
  await persist();
  return true;
}

// Append a message. Inbound messages carry the envelope id — a duplicate id is
// silently dropped (mailbox refetch after a lost response). Returns true when
// the message was new.
export async function append(username, { dir, text, ts, id = null }) {
  if (!chats) throw new Error("chat store is locked");
  if (!chats[username]) await ensure(username);
  const c = chats[username];
  if (id && c.messages.some((m) => m.id === id)) return false;
  c.messages.push({ dir, text, ts, id });
  if (c.messages.length > MAX_MESSAGES_PER_CHAT) {
    c.messages = c.messages.slice(-MAX_MESSAGES_PER_CHAT);
  }
  c.updatedAt = Date.now();
  await persist();
  return true;
}

// Lock the chat to a mode. For AES256 pass {secret, salt} (both sides must
// share them). Clears any pending proposal.
export async function setMode(username, mode, { secret = null, salt = null } = {}) {
  if (!chats) throw new Error("chat store is locked");
  requireValidMode(mode);
  if (!chats[username]) await ensure(username);
  const c = chats[username];
  c.mode = mode;
  if (mode === "AES256") {
    if (secret !== null) c.secret = secret;
    if (salt !== null) c.salt = salt;
  } else {
    delete c.secret;
    delete c.salt;
  }
  delete c.pending;
  c.updatedAt = Date.now();
  await persist();
  return get(username);
}

// Record a pending mode proposal (either direction). dir "out" = we proposed
// and await their accept; "in" = they proposed and we must accept/decline.
export async function setPending(username, pending) {
  if (!chats) throw new Error("chat store is locked");
  requireValidMode(pending && pending.mode);
  if (!chats[username]) await ensure(username);
  chats[username].pending = pending;
  await persist();
  return get(username);
}

export async function clearPending(username) {
  if (!chats) throw new Error("chat store is locked");
  if (chats[username]) {
    delete chats[username].pending;
    await persist();
  }
}

export async function remove(username) {
  if (!chats) throw new Error("chat store is locked");
  delete chats[username];
  await persist();
}
