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
// Pentest 2026-08-07 F-ATREST-005 / F-CRYPTO-006. The chat store had no
// generation counter, no witness and no domain tag — the only one of the four
// at-rest stores with no rollback control at all. One `removeItem` silently
// reset the P-13 envelope-replay ring (so every envelope the relay still holds
// replays as new) and the negotiated AES256 mode (so a chat the user upgraded
// falls back to SEALED with no notice). And because the wrapper was
// byte-compatible with the contact store's and shared its passphrase, the chat
// plaintext could be presented AS a contact store (F-ATREST-004(b)).
//
// Same three controls contacts.js carries, for the same reasons: a tag inside
// the AEAD so no other module's plaintext can be adopted here (and this one
// cannot be adopted elsewhere), a monotone generation, and a witness beside the
// blob whose mere presence proves a store is supposed to exist — anchored, like
// the contact store, to the identity AEAD so deleting both keys is not enough.
const LS_CHATS_GEN = "sc.chats.gen.v1";
const CHATS_DOMAIN = "secure-chat/chats-store/v2";
const CHATS_GEN_DOMAIN = "secure-chat/chats-generation/v1";
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
let generation = 0; // monotone store generation (F-ATREST-005); bumped on persist

// The anti-deletion anchor, injected by app.js — see contacts.js for the full
// argument. `null` means "no identity to anchor to", which reads as "cannot
// know" everywhere below and so never fires an alarm on its own.
let anchor = null;

export function setStoreAnchor(a) {
  anchor = a;
}

export function storeExpected() {
  return anchor !== null && anchor.established === true;
}

async function noteStoreEstablished() {
  if (anchor === null || anchor.established === true) return;
  await anchor.markEstablished();
  anchor.established = true;
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
}

export async function unlock(passphrase) {
  if (!passphrase) throw new Error("passphrase required to unlock the chat store");
  const raw = localStorage.getItem(LS_CHATS);
  if (!raw) {
    // F-ATREST-005: "no store" is a first run only if this device never had
    // one. Otherwise it is a deletion, and adopting a fresh empty store would
    // silently reset the envelope-replay ring and every negotiated chat mode.
    await assertStoreNotDeleted(passphrase);
    salt = crypto.getRandomValues(new Uint8Array(16));
    dataKey = await deriveKey(passphrase, salt, KDF_ITERS);
    chats = newStore();
    generation = 0;
    await persist();
    await noteStoreEstablished();
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
  const data = JSON.parse(dec.decode(plain));

  // F-CRYPTO-006: the plaintext must be a chat STORE and not another record
  // that happens to decrypt under the same key. Two acceptable shapes, exactly
  // as contacts.js: tagged (normal), or the untagged pre-v2 bare map, which is
  // adopted once and rewritten tagged. The discriminator is the tag INSIDE the
  // AEAD, never the attacker-writable outer `v` byte.
  const tagged = data !== null && typeof data === "object" && !Array.isArray(data) &&
    Object.prototype.hasOwnProperty.call(data, "d");
  const notAChatStore = () => {
    lock();
    return new Error(
      "the chat history on this device is not a chat store — refusing to open it, because " +
      "continuing would silently discard your message history and negotiated chat modes",
    );
  };
  if (tagged && data.d !== CHATS_DOMAIN) throw notAChatStore();
  if (!tagged) {
    // A pre-v2 store is a plain map of username -> chat record. Require that
    // shape rather than accepting any object, so no other module's plaintext
    // can be laundered in here.
    const isChatRecord = (c) => c !== null && typeof c === "object" && !Array.isArray(c) &&
      (Array.isArray(c.messages) || typeof c.mode === "string");
    const looksLikeChats = data !== null && typeof data === "object" && !Array.isArray(data) &&
      Object.values(data).every(isChatRecord);
    if (!looksLikeChats) throw notAChatStore();
    // ...and once this device has recorded a real store, the legacy shape is a
    // downgrade, not a migration: the migration provably already happened.
    if (storeExpected()) {
      lock();
      throw new Error(
        "your chat history has been replaced with an older-format copy that carries no rollback " +
        "record — refusing to open it, because that would silently reset message-replay protection " +
        "and any encryption mode you negotiated",
      );
    }
  }

  // P-20: JSON.parse yields a normal object (with a prototype); re-key it into a
  // null-prototype store before anything indexes it by a username.
  chats = newStore(tagged ? data.chats : data);
  generation = Number.isInteger(data.gen) ? data.gen : 0;
  await assertNotRolledBack(Number.isInteger(data.gen) ? data.gen : null);
  let dirty = sanitizeModes();
  if (!tagged) dirty = true; // rewrite tagged, so adoption happens exactly once
  if (dirty) await persist();
  await noteStoreEstablished();
}

// ---- rollback / deletion detection (F-ATREST-005) --------------------------
// Mirrors contacts.js. The witness carries its OWN salt so it stays readable
// when the store that would otherwise hold the salt has been removed.
async function readWitness(passphrase = null) {
  const raw = localStorage.getItem(LS_CHATS_GEN);
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
    const w = JSON.parse(dec.decode(await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: unb64(rec.iv) }, key, unb64(rec.ct),
    )));
    if (w.d !== CHATS_GEN_DOMAIN || !Number.isInteger(w.gen)) return { corrupt: true };
    return w;
  } catch {
    return { corrupt: true };
  }
}

async function writeWitness() {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const plain = enc.encode(JSON.stringify({ d: CHATS_GEN_DOMAIN, gen: generation }));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, dataKey, plain));
  localStorage.setItem(LS_CHATS_GEN, JSON.stringify({
    salt: b64(salt), iters: KDF_ITERS, iv: b64(iv), ct: b64(ct),
  }));
}

async function assertStoreNotDeleted(passphrase) {
  const w = await readWitness(passphrase);
  if (w === null) {
    if (storeExpected()) {
      lock();
      throw new Error(
        "your chat history and its generation record have BOTH been deleted from this device — " +
        "refusing to start over with an empty store, because that would silently turn message-replay " +
        "protection off and reset every negotiated chat mode",
      );
    }
    return; // genuine first run
  }
  lock();
  if (w.corrupt) {
    throw new Error(
      "a chat history was expected on this device but is missing, and its generation record does not " +
      "decrypt — refusing to start over with an empty store",
    );
  }
  throw new Error(
    `your chat history (generation ${w.gen}) has been DELETED from this device — refusing to start ` +
    "over with an empty store, because that would silently reset message-replay protection",
  );
}

async function assertNotRolledBack(storeGen) {
  const w = await readWitness();
  if (w === null) {
    // No witness. Fine only for a pre-v2 store, which has no generation either;
    // a store that HAS one lost its witness, which is tampering.
    if (Number.isInteger(storeGen)) {
      lock();
      throw new Error(
        "the generation record for your chat history is missing — refusing to open the store, " +
        "because a rollback could no longer be detected",
      );
    }
    return;
  }
  if (w.corrupt) {
    lock();
    throw new Error("the generation record for your chat history is damaged or forged");
  }
  const gen = Number.isInteger(storeGen) ? storeGen : 0;
  if (gen < w.gen) {
    lock();
    throw new Error(
      `your chat history is OLDER than this device recorded (generation ${gen}, expected ${w.gen}) — ` +
      "an earlier copy has been restored, which would replay old messages and undo negotiated modes",
    );
  }
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

// ---- write serialisation (pentest 2026-08-08 item 16) ----------------------
//
// The CAS below is a compare-and-swap with a gap between the compare and the
// swap: `readWitness` (one await), the check, then TWO more awaits (the encrypt
// and `writeWitness`) before the store is written. Two tabs that both read the
// witness BEFORE either writes therefore both see generation N, both pass the
// check, and both write N+1 — the exact lost update the CAS was added to stop.
// Reproduced in-process with two real module instances over one storage: both
// `markSeen` calls returned true and `env-A1` vanished from the P-13 replay
// ring, which means the relay can replay that envelope and it is accepted as
// new. The CAS is a faithful port of `contacts.js:441-448`; the difference is
// that chats persists on EVERY operation, so the residual that is rare there is
// ordinary here.
//
// So the read-modify-write is serialised instead of merely checked. Two layers,
// because they cover different races:
//
//   * `writeChain` serialises writes WITHIN this tab. `persist()` has awaits in
//     it, so two overlapping operations in one tab (a `markSeen` and an
//     `append`, say) can already interleave without any second tab involved.
//   * `navigator.locks` serialises ACROSS tabs, which is what the finding is
//     about. The lock is per-origin, so it also subsumes the first layer where
//     it exists.
//
// With the lock held across compare AND swap, the losing tab now reads the
// winner's witness and refuses loudly ("changed in another tab — reload")
// instead of silently discarding its history. The permanent-lockout half goes
// with it: store and witness are written as one critical section, so the store
// can no longer end up older than the witness.
//
// The other fix shape considered — folding store and witness into ONE
// localStorage value so there is a single atomic write — was REJECTED, and this
// is worth recording because it looks tidier. The witness has to be separately
// readable when the store is gone; that is the whole of F-ATREST-005's
// deletion detection (`assertStoreNotDeleted` reads the witness precisely when
// `LS_CHATS` is missing), and it carries its own salt for that reason. Merging
// them makes one `removeItem` delete the evidence along with the data.
//
// Fallback posture, stated plainly rather than assumed: with no `navigator.locks`
// the cross-tab layer is absent and the residual is exactly today's behaviour —
// no worse, not fixed. This deliberately does NOT copy F-CRYPTO-014's
// "no Web Locks, no OTP" stance, because the hazards are not comparable: there
// the failure is keystream reuse and the feature can simply be withheld, here it
// is a lost update in a replay ring and withholding it means the user cannot
// open their own chat history at all. The engines involved are Chrome/WebView
// < 69, Firefox < 96 and Safari 15.0-15.3.
const WRITE_LOCK = "sc.chats.write.v1";
// Generous: a legitimate persist is a PBKDF2-free encrypt plus two localStorage
// writes (single-digit ms), and the queue can hold a few of those. Anything past
// this is a holder that is not coming back, not a slow disk.
const WRITE_LOCK_TIMEOUT_MS = 10_000;
let writeChain = Promise.resolve();

function withWriteLock(fn) {
  // `navigator` is guarded, not just `navigator.locks`: this module is imported
  // by the Node test suite, and Node only grew a global `navigator` in 21.0.0.
  // Without the guard `chats.unlock()` throws a TypeError on Node 20 — which the
  // repo's own brief still targets — and it reads as a bug in the store rather
  // than a missing global. Pentest 2026-08-10 (L-2).
  const hasWebLocks = typeof navigator !== "undefined" &&
    navigator.locks && typeof navigator.locks.request === "function";
  // `navigator.locks` is a poisonable global, and this is the one place that
  // decides whether cross-tab ordering happens at all. Marked explicitly so its
  // absence is a stated fallback rather than an invisible one: everywhere else in
  // this project a missing primitive fails closed, but here it cannot — the
  // browsers listed above genuinely lack it, and refusing would lock those users
  // out of their own history. The intra-tab `writeChain` below still orders
  // writes, so what is lost with no Web Locks is ONLY cross-tab ordering, which is
  // exactly what the compare-and-swap in persistLocked is there to catch.
  //
  // A same-origin script that deletes `navigator.locks` therefore downgrades this
  // to the documented no-Web-Locks path; it cannot silently disable the CAS.
  // Two-argument form deliberately: exclusive-and-wait is the Web Locks default,
  // so passing an options object would add nothing but a shape for a shim or a
  // polyfill to get wrong.
  const run = () => (hasWebLocks ? navigator.locks.request(WRITE_LOCK, fn) : fn());
  // Chain on settle, not on success: one failed write must not wedge the queue.
  //
  // TIMEOUT (item 11): a same-origin script — or a tab wedged inside its own
  // callback — holding WRITE_LOCK used to hang every subsequent write forever,
  // silently, because there is no user-visible signal that a persist never
  // returned. Losing history quietly is the failure this store is built to avoid,
  // so a stuck lock now surfaces as an error the caller can report instead.
  const guarded = () => Promise.race([
    run(),
    new Promise((_, reject) => setTimeout(
      () => reject(new Error("the chat store's write lock did not become available — another tab or script is holding it; your last change was NOT saved")),
      WRITE_LOCK_TIMEOUT_MS,
    )),
  ]);
  const next = writeChain.then(guarded, guarded);
  writeChain = next.then(() => {}, () => {});
  return next;
}

async function persist() {
  if (!dataKey) throw new Error("chat store is locked");
  return withWriteLock(persistLocked);
}

async function persistLocked() {
  // Re-checked inside the lock: `lock()` can have run while we were queued.
  //
  // `chats` is checked as well as `dataKey`. `unlock()` sets `dataKey` before it
  // finishes populating `chats`, so a queued write landing in that window would
  // otherwise serialise `chats: null` and write an AGREEING witness beside it —
  // silent, total history loss that the rollback check would then call healthy.
  // Modelled by the 2026-08-10 pentest rather than executed; the guard is free.
  if (!dataKey || !chats) throw new Error("chat store is locked");
  // Pentest 2026-08-07 fix review (F3): the same L-3 compare-and-swap
  // contacts.js has carried since 2026-07-29, which the first cut of this
  // function omitted while copying everything around it.
  //
  // Two tabs both unlock at generation N and both write N+1; the second
  // overwrites the first AND rewrites the witness, so the rollback check agrees
  // and nothing notices. Here that silently discards exactly what the
  // generation counter was added to protect: the P-13 `seenIds` envelope-replay
  // ring and any negotiated AES256 mode. Unlike contacts, EVERY chat operation
  // persists (ensure/append/markSeen/setMode), so concurrent writes are the
  // ordinary case rather than an exotic one.
  //
  // Worse without the CAS: if a stale tab's whole persist lands between another
  // tab's store and witness writes, the store ends up OLDER than the witness
  // and `assertNotRolledBack` then refuses forever — an unrecoverable lockout
  // caused by the user's own second tab.
  //
  // Not a security boundary against a device-local attacker (they can write the
  // witness too); it is protection against the user's own second tab.
  const witness = await readWitness();
  if (witness && !witness.corrupt && witness.gen > generation) {
    lock();
    throw new Error(
      "your chat history was changed in another tab (or another window) — this page is out of date. " +
      "Reload before sending or reading more, so the other tab's messages are not lost.",
    );
  }
  generation += 1;
  const iv = crypto.getRandomValues(new Uint8Array(12));
  // F-CRYPTO-006 / F-ATREST-005: the domain tag and the generation live INSIDE
  // the AEAD, so neither can be stripped or rewritten without the passphrase.
  const plain = enc.encode(JSON.stringify({ d: CHATS_DOMAIN, gen: generation, chats }));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, dataKey, plain));
  localStorage.setItem(
    LS_CHATS,
    JSON.stringify({ v: 2, iters: KDF_ITERS, salt: b64(salt), iv: b64(iv), ct: b64(ct) }),
  );
  // Witness last: if this throws, the store is newer than the witness, which
  // reads as "fine" rather than as a rollback. The other order would lock the
  // user out of their own history on a quota error.
  await writeWitness();
}

export function wipe() {
  localStorage.removeItem(LS_CHATS);
  localStorage.removeItem(LS_CHATS_GEN);
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
