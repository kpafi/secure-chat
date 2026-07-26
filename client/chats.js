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
}

export async function unlock(passphrase) {
  if (!passphrase) throw new Error("passphrase required to unlock the chat store");
  const raw = localStorage.getItem(LS_CHATS);
  if (!raw) {
    salt = crypto.getRandomValues(new Uint8Array(16));
    dataKey = await deriveKey(passphrase, salt, KDF_ITERS);
    chats = newStore();
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
    throw new Error("chat store does not decrypt with this passphrase (different identity, or tampered)");
  }
  // P-20: JSON.parse yields a normal object (with a prototype); re-key it into a
  // null-prototype store before anything indexes it by a username.
  chats = newStore(JSON.parse(dec.decode(plain)));
  if (sanitizeModes()) await persist();
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

async function persist() {
  if (!dataKey) throw new Error("chat store is locked");
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const plain = enc.encode(JSON.stringify(chats));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, dataKey, plain));
  localStorage.setItem(
    LS_CHATS,
    JSON.stringify({ v: 1, iters: KDF_ITERS, salt: b64(salt), iv: b64(iv), ct: b64(ct) }),
  );
}

export function wipe() {
  localStorage.removeItem(LS_CHATS);
  lock();
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
