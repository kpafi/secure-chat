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
    chats = {};
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
  chats = JSON.parse(dec.decode(plain));
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

async function innerKey(secret, saltB64) {
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
  return b64(crypto.getRandomValues(new Uint8Array(16)));
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
  if (!chats[username]) {
    chats[username] = { username, mode, messages: [], updatedAt: Date.now() };
    await persist();
  }
  return get(username);
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
