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

// Pentest 2026-08-07 F-ATREST-003/004: the device-native floor, where the app
// runs. The witness above lives in localStorage beside the store, so deleting
// BOTH (two removeItem calls) yielded a fresh, empty, pin-less store with no
// warning anywhere — key-change detection simply off (F-ATREST-003, confirmed).
// And a store with no generation inside its AEAD (any pre-L-1 blob, decrypting
// under the same passphrase because the outer salt travels with it) was
// adopted whenever the witness was gone, so an archived blob + one removeItem
// resurrected revoked pins and auto-unlocked messaging (F-ATREST-004,
// confirmed). Both are the "coordinated snapshot" the L-1 note above calls
// residual; on Android it no longer is. The floor id is per IDENTITY (app.js
// passes a hash of the identity's public signing key), bumped with the store
// generation on every persist, and consulted BEFORE any localStorage evidence.
// See nativefloor.js for the namespace and how the bridge is trusted.
import {
  captureNativeFloor, NATIVE_ABSENT, NATIVE_TAMPERED, floorUnavailableError, bumpFloor, FLOOR_MAX,
} from "./nativefloor.js";
const nativeFloor = captureNativeFloor();
// Package 3b (owner decision 2026-09-25): the store and its witness live in
// IndexedDB, written with strict durability, migrated once from localStorage.
// See durable.js storeSlot for the migration, the marker and the fallback.
import { storeSlot } from "./durable.js";
const slot = storeSlot({ blobKey: LS_CONTACTS, genKey: LS_GEN, marker: "sc.contacts.idb.v1" });
// Resolves once the preload (and any migration) has settled; unlock() waits
// for it itself, so callers need not.
export const ready = slot.ready;
// "Post-fix contacts have run on this device." Deletable like everything in
// localStorage, so it may only ESCALATE a warning, never authorise anything.
const EPOCH_KEY = "sc.contacts.epoch.v1";

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

// The native floor key for the identity this store belongs to, set per unlock.
let floorKey = null;
// True once an unlock has seen evidence (witness or native floor) that a store
// is supposed to exist here, even if the blob itself is gone. hasStore() folds
// it in so app.js takes the loud "pins unreadable" path rather than the benign
// first-contact one while the store is refused (F-ATREST-003).
let expectedStore = false;

export function lock() {
  dataKey = null;
  salt = null;
  contacts = null;
  pins = null;
  generation = 0;
  floorKey = null;
}

function readFloor() {
  if (!nativeFloor || !floorKey) return NATIVE_ABSENT;
  if (nativeFloor.broken) throw floorUnavailableError("your saved contacts");
  return nativeFloor.read(floorKey);
}

function adoptionError(message, code) {
  lock();
  const err = new Error(message);
  err.code = code;
  err.suspicious = localStorage.getItem(EPOCH_KEY) !== null;
  return err;
}

// Unlock (or create) the store with the identity passphrase. Throws if a blob
// exists but does not decrypt with this passphrase (foreign/tampered blob —
// the caller decides whether to offer `wipe()`).
//
// `opts.floorId`      — hash of the identity this store belongs to; enables the
//                       native floor where the app provides one.
// `opts.adoptLegacy`  — the user has seen the F-ATREST-004 warning and chooses
//                       to open a store whose history cannot be verified.
// `opts.adoptDeleted` — the user has seen the F-ATREST-003 warning ("a store
//                       existed here and is gone") and chooses to start over.
// Never default either to true: silent adoption IS the vulnerability. Returns
// `{ created }` so the caller can tell a first run from an existing store.
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
    return !!plain && typeof plain === "object" && plain.d === STORE_DOMAIN && plain.gen === wl.gen;
  } catch {
    return false;
  }
}

export async function unlock(passphrase, opts = {}) {
  if (!passphrase) throw new Error("passphrase required to unlock the contact store");
  floorKey = opts.floorId ? "contacts:" + opts.floorId : null;
  // The floor is the one input a JS-context attacker cannot delete or lower,
  // so it is read FIRST, before any localStorage evidence can shape the verdict.
  const floor = readFloor();
  if (floor === NATIVE_TAMPERED) {
    lock();
    throw new Error("the device-protected record for your saved contacts is damaged or forged — refusing to open the store");
  }
  // Package 3b: the store and its witness live in IndexedDB (durable.js
  // storeSlot), read together — and migrated there from localStorage on the
  // first read after the upgrade.
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
    // No store. Before creating a fresh (empty, pin-less) one, make sure this
    // really IS a first run and not a store somebody deleted — see L-1. The
    // witness carries its OWN salt precisely so it stays readable when the
    // store that would otherwise hold the salt has been removed.
    await assertStoreNotDeleted(passphrase, rawWitness);
    // F-ATREST-003: on Android the floor outlives both blobs. "Floor says
    // generation N, nothing in storage" is either an attacker's two
    // removeItem calls or the user's own Forget-then-restore of the same
    // identity; the two are indistinguishable, so it is a loud, explicit
    // choice — never a silent fresh start. The floor can never be lowered, so
    // the recreated store simply continues its numbering from it.
    //
    // Package 3: `> 0`, not `> NATIVE_ABSENT`. persist() now ARMS the slot at
    // the current generation before it writes, so a floor of exactly 0 means
    // "armed by a first save that never completed" (the blob write threw, the
    // app died) — every completed save leaves generation >= 1 on the floor.
    // Reading 0 as "a store was deleted" turned a failed first save into a
    // false DELETED alarm, and into a no-override refusal on the legacy path.
    // Review round 1 (Low): or the marker says the store had moved to
    // IndexedDB and IndexedDB is now empty (evicted or deleted).
    if (floor > 0 || lost) {
      expectedStore = true;
      if (!opts.adoptDeleted) {
        throw adoptionError(
          `your saved contacts${floor > 0 ? ` (generation ${floor})` : ""} have been DELETED from this device — refusing to ` +
          "start over with an empty store, because that would silently turn off key-change warnings. " +
          "If you did not Forget this identity yourself, treat every contact as unverified.",
          "DELETED_CONTACTS_ADOPTION",
        );
      }
    }
    salt = crypto.getRandomValues(new Uint8Array(16));
    dataKey = await deriveKey(passphrase, salt, KDF_ITERS);
    contacts = [];
    pins = {};
    generation = floor > NATIVE_ABSENT ? floor : 0;
    dropLegacyPins();
    await persist(); // a failed floor write locks the store and throws (Package 3)
    expectedStore = false;
    return { created: true };
  }
  expectedStore = true;
  // Second fix round (re-review of 9a38d97, I-1): a SyntaxError echoes ~20
  // characters of what is in localStorage — a planted value with a newline or
  // U+202E — into the locked panel and the transcript. A fixed sentence.
  let blob;
  try {
    blob = JSON.parse(raw);
  } catch {
    throw new Error("the contact store on this device is not readable (damaged or replaced)");
  }
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
  // the bare v1 array or an object carrying a contacts ARRAY and a pins OBJECT.
  // A record with neither is not a store, whatever it claims. (F-ATREST-004
  // tightened this from "has a contacts or pins property": a chat-store blob
  // holding a chat literally named "pins" or "contacts" used to pass.)
  const looksLikeStore = Array.isArray(data) ||
    (Array.isArray(data.contacts) && typeof data.pins === "object" && data.pins !== null && !Array.isArray(data.pins));
  if (!tagged && !looksLikeStore) throw notAStore();

  // v1 blobs stored the bare contacts array; v2 wraps {contacts, pins}.
  if (Array.isArray(data)) {
    contacts = data;
    pins = {};
  } else {
    contacts = data.contacts || [];
    pins = data.pins || {};
  }
  generation = Number.isInteger(data.gen) ? data.gen : 0;
  await assertNotRolledBack(data.gen, rawWitness);
  // F-ATREST-003/004, the floor half. Runs AFTER the witness checks so the
  // more specific localStorage verdicts keep their wording, but it is the
  // decision the witness could not make: a witness restored together with the
  // store agrees with it, the floor does not.
  if (floor > NATIVE_ABSENT && generation < floor) {
    // Review round 2 (I-4): the message is built BEFORE lock(), which resets
    // `generation` — it used to say "generation 0" every time.
    const err = new Error(
      `your saved contacts are OLDER than this device recorded (generation ${generation}, device record ${floor}) — ` +
      "an earlier copy has been restored, which would silently undo recent verifications and pins",
    );
    lock();
    throw err;
  }
  // ...and the converse (the OTP H-1 flag, ported): a store written while a
  // floor was in force, with the floor now gone. Only file-level access can
  // produce this on Android, and it used to be silent because ABSENT reads as
  // "no floor". `nativeFloor` is inside the AEAD, so it cannot be stripped.
  if (data.nativeFloor === true && floorKey && floor === NATIVE_ABSENT) {
    lock();
    throw new Error(
      "the device-protected record for your saved contacts has been deleted — refusing to open the store, " +
      "because a rollback could no longer be detected",
    );
  }
  const legacyShape = !tagged || !Number.isInteger(data.gen);
  if (legacyShape) {
    // F-ATREST-004: a store with no generation inside its AEAD has no history
    // anything here can verify. That used to be adopted on sight whenever the
    // witness was gone — one removeItem — which is precisely how an archived
    // pre-L-1 blob (identical passphrase, identical salt) resurrected revoked
    // pins. On Android a floor for this identity proves a post-fix store
    // existed, so a gen-less blob is a restore by definition: refused, no
    // adoption possible (adoption is consent to accept state that cannot be
    // VERIFIED, never permission to override a rollback that has been
    // DETECTED — the OTP F-1 rule). Elsewhere it is an explicit user choice.
    // (`> 0`: a floor of 0 is an armed slot whose first save never completed
    // — see the deleted-store branch above. It proves no post-fix store.)
    if (floor > 0) {
      lock();
      throw new Error(
        "your saved contacts have no rollback record but this device says they had one (generation " +
        `${floor}) — an earlier copy has been restored; refusing to open it`,
      );
    }
    if (!opts.adoptLegacy) {
      throw adoptionError(
        "your saved contacts have no rollback record on this device. If you have used this device with " +
        "these contacts before, an older copy has been restored and your saved pins may be stale — " +
        "treat every contact as unverified.",
        "LEGACY_CONTACTS_ADOPTION",
      );
    }
  }
  let dirty = dropLegacyPins();
  // Package 3, F-ATREST-006: the H-01 migration is keyed on the AUTHENTICATED
  // shape, not the outer `v` byte. `(blob.v || 1) < 3` was attacker-writable
  // plaintext in both directions: rewrite an archived pre-v3 blob's `v` to 3
  // and its signing-only 🟢 marks (which never covered the encryption keys)
  // survived the upgrade; rewrite a current blob's `v` to 2 and every genuine
  // four-key verification was silently dropped. Every store this code writes is
  // tagged (`d`, v4), so "untagged" is the one inside-the-AEAD statement that a
  // blob predates the tag — and it cannot be forged without the passphrase.
  // It over-approximates on purpose: a genuine untagged v3 store (which the
  // outer byte could not tell from v2 anyway) also has its enc-key-covering
  // marks re-checked. An untagged store is only ever opened after the explicit
  // LEGACY_CONTACTS_ADOPTION consent, whose message already says to treat
  // every contact as unverified, so asking for re-verification is the honest
  // outcome rather than a regression.
  if (!tagged && migrateH01Verification()) dirty = true;
  // An adopted pre-v4 store is rewritten tagged, so it only ever happens once.
  if (!tagged) dirty = true;
  // A pre-L-1 store carries no generation and no witness: adopt it at its
  // current state (there is nothing to roll back TO yet) and start counting.
  if (!Number.isInteger(data.gen)) dirty = true;
  // A store from before the floor existed is re-persisted so it gains one.
  // (Package 3b: only where the floor is actually advanced — see persist.)
  if (floorKey && nativeFloor && slot.durable() && data.nativeFloor !== true) dirty = true;
  if (dirty) await persist();
  if (conflictAdopted) return { created: false, conflictAdopted: true };
  return conflictDropped ? { created: false, conflictDropped: true } : { created: false };
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
// Package 3b: `raw` is the witness string read together with the store (so the
// two verdicts are about one snapshot); left out, it is read fresh.
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

// Seals the witness and RETURNS it: persist() writes it together with the store
// in one durable transaction (package 3b).
async function sealWitness(gen, key) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const plain = enc.encode(JSON.stringify({ d: GEN_DOMAIN, gen }));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, plain));
  return JSON.stringify({
    salt: b64(salt), iters: KDF_ITERS, iv: b64(iv), ct: b64(ct),
  });
}

async function assertStoreNotDeleted(passphrase, rawWitness) {
  const w = await readWitness(passphrase, rawWitness);
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

async function assertNotRolledBack(storeGen, rawWitness) {
  const w = await readWitness(null, rawWitness);
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
  if (!dataKey) throw new Error("contact store is locked");
  // Review round 3 (F1): a tab still running the previous version has written
  // the store to localStorage since we read it. Committing now would put our
  // generation beside its — and the next unlock would adopt whichever is
  // higher, silently discarding the other side's edits (a Remove included).
  // Refuse, like any other-tab write; the next unlock settles it.
  if (slot.foreignCopy()) {
    lock();
    const err = new Error(
      "your contacts were changed by an older version of the app in another tab — this page is out of date. " +
      "Close the other tab, then reload before making further changes.",
    );
    err.code = "STALE";
    throw err;
  }
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
    const err = new Error(
      "your contacts were changed in another tab (or another window) — this page is out of date. " +
      "Reload before making further changes, so the other tab's changes are not lost.",
    );
    err.code = "STALE"; // app.js tells this benign case apart from a real store error
    throw err;
  }
  // Package 3b: the floor is used only where the store itself is durable
  // (IndexedDB). In the localStorage fallback a write may sit in memory for a
  // minute, and a floor advanced past it is exactly the Android brick: after a
  // kill the floor is ahead of the data and the store refuses with no override.
  // So without IndexedDB the floor is neither armed nor advanced (still READ on
  // unlock — an existing floor keeps refusing a genuine rollback), and the blob
  // says so (`nativeFloor: false`).
  const floored = !!(nativeFloor && floorKey) && slot.durable();
  // Package 3 (ROUND-3 F-1 / F-4, A4 F-A1-R1): the blob below CLAIMS a floor
  // (`nativeFloor: true`), and that claim used to be made before anything had
  // checked that the floor exists — the bump came last and its answer was
  // discarded. A first save whose bump did not commit therefore sealed a claim
  // for a slot that a restart shows ABSENT, and the next unlock refused
  // ("record has been deleted") with no override. So the slot is ARMED first,
  // at the generation already on disk: that creates a missing slot and is a
  // no-op on an existing one, and it can never put the floor ahead of any blob
  // (the F-A1 brick). Only once it provably landed is the claim sealed.
  if (floored) {
    // The 7b ceiling: a floor cannot hold a generation past FLOOR_MAX. Refuse
    // to advance, loudly, instead of the old silent freeze (see nativefloor.js).
    if (generation >= FLOOR_MAX) {
      lock();
      const err = new Error(
        "your saved contacts have reached the highest generation this device's rollback record can hold — " +
        "refusing to save further changes, because they could no longer be protected against rollback",
      );
      err.code = "FLOOR_WRITE_FAILED";
      throw err;
    }
    armOrLock(generation);
  }
  // L-1: every write moves the store forward, monotonically. (Review round 2:
  // the counter itself moves only after the write below completed.)
  const next = generation + 1;
  const key = dataKey;
  const iv = crypto.getRandomValues(new Uint8Array(12));
  // `d` is the H-2 domain tag: it makes this plaintext unmistakably a STORE, so
  // no other record encrypted under the same key can be substituted for it.
  // `nativeFloor` (F-ATREST-003): "a floor was in force when this was written",
  // inside the AEAD so it cannot be cleared to hide a later floor deletion.
  const plain = enc.encode(JSON.stringify({
    d: STORE_DOMAIN, contacts, pins, gen: next, nativeFloor: floored,
  }));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, plain));
  const blobStr = JSON.stringify({ v: 4, iters: KDF_ITERS, salt: b64(salt), iv: b64(iv), ct: b64(ct) });
  // Package 3b: store and witness go to IndexedDB in ONE strict transaction,
  // and this line returns only once it has COMPLETED. (Under localStorage the
  // witness was written last so that a crash between the two left the store
  // ahead of it; one atomic transaction makes that split impossible.) A failed
  // write rejects this save exactly as a failed setItem did (quota): the
  // caller reports it, and the floor below is not touched.
  await slot.write(blobStr, await sealWitness(next, key));
  if (dataKey !== key) return; // locked (or re-unlocked) meanwhile: nothing here is ours any more
  generation = next;
  // Native floor only AFTER the durable write completed — the ordering that
  // makes "floor ahead of the data" impossible short of tampering: a crash
  // before this line leaves the store one ahead of the floor, never behind it.
  // Package 3: and its answer is CHECKED. A floor that did not move leaves this
  // generation unprotected against a restore of the previous one, so the save
  // is reported as failed (and the store locked, like a STALE write).
  if (floored) armOrLock(generation);
  localStorage.setItem(EPOCH_KEY, "1");
}

// bumpFloor, plus: a floor write that failed locks the store. The in-memory
// state may be AHEAD of what is durably protected (or, if the arm failed,
// ahead of disk altogether), and carrying on would keep presenting it as saved.
// Locking is the same recovery a STALE write takes: app.js shows the reason on
// the locked panel and the user unlocks again from what is actually on disk.
function armOrLock(value) {
  try {
    bumpFloor(nativeFloor, floorKey, value, "your saved contacts");
  } catch (e) {
    lock();
    throw e;
  }
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
  // Fix round 2 (review L, poc7): a user: pin replaced by a DIFFERENT signing
  // identity (Bob's new phone, verified in person) supersedes the old one, and
  // so do the room: pins made under it. They used to stay live: revocation
  // later only ever saw the new keys (record and user: pin both hold K2), so
  // after Remove the old device's K1 was still auto-accepted in that room.
  // Revoked here, at the moment the old identity is superseded — the simpler
  // of the two options (no per-contact key history to keep): a revoked pin
  // only means "ask again in person", never a lockout.
  const prev = key.startsWith("user:") ? pins[key] : null;
  if (prev && prev.ed && prev.mldsa &&
      !(sameKeyBytes(prev.ed, bundle.ed) && sameKeyBytes(prev.mldsa, bundle.mldsa))) {
    revokeRoomPins([prev]);
  }
  pins[key] = {
    ed: bundle.ed, mldsa: bundle.mldsa,
    ecdh: bundle.ecdh ?? null, mlkem: bundle.mlkem ?? null,
  };
  await persist();
}

// Remove the blob entirely (identity forgotten, or unrecoverable foreign blob).
// The generation witness goes with it: this is the ONE deletion the user asked
// for, so leaving the witness behind would make the next unlock refuse to open.
//
// Package 3b: the records are in IndexedDB, so this returns the promise of that
// deletion (app.js awaits it); the in-memory state is gone synchronously.
export function wipe() {
  const done = slot.wipe();
  lock();
  expectedStore = false;
  // The native floor (Android) deliberately stays: it cannot be lowered, and
  // the next unlock of the SAME identity on this device is a loud, explicit
  // "start over" (DELETED_CONTACTS_ADOPTION) rather than a silent clean slate —
  // because an attacker's two removeItem calls look exactly like this.
  return done;
}

// True when a contact store is EXPECTED on this device — which includes the
// case where the blob is gone but its generation witness is not (L-1). app.js
// reads this through pinsReadable(), so a deleted store now takes the loud
// "key changes cannot be detected" path instead of rendering every contact as a
// benign first contact.
//
// Package 3b: synchronous over the store slot's preloaded state (read from
// IndexedDB at module load). Until that preload has settled this answers TRUE —
// "unknown" must take the loud path, never the benign first-contact one.
export function hasStore() {
  return expectedStore || slot.known();
}

// The pin key for a contact's live sessions. Lived in app.js as an inline
// `"user:" + name`; here so setVerified/remove can find the pin they revoke.
export function pinKeyFor(username) {
  return "user:" + username;
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
  if (!on) revokePin(username, cur);
  await persist();
  return get(username);
}

// Pentest 2026-08-07 F-ATREST-007: "Unverify" and "Remove" flipped the record
// and left the PIN untouched, so the next live session with that user still
// auto-unlocked messaging on "matches your saved pin" — the explicit
// revocation was not honoured anywhere it mattered (the thief of a contact's
// phone walks straight in). The pin is NOT deleted: a removed contact re-added
// later with a different key is exactly the MITM shape the CHANGED alarm
// exists for, and deleting the pin would downgrade that to the benign
// first-contact prompt. It is marked, and app.js refuses to auto-accept a
// revoked pin; a fresh in-person verification (savePin) clears the mark.
//
// Package 3, F-ATREST-007 / 2026-08-08 item 17: …and the pin was not the only
// one. A session started from a room code (no contact name in play) pins the
// peer under `room:<id>` (app.js enterVerification), and those pins were never
// touched — so a revoked peer who re-entered a remembered room was greeted
// with "contact identity matches your saved pin" and messaging unlocked, the
// revocation honoured everywhere except where it was reachable. Every
// `room:*` pin whose SIGNING identity is the contact's is revoked with it.
// Signing keys, not the whole bundle: a room pin made before the encryption
// keys were pinned, or under the same identity with rotated encryption keys,
// is still this person. `keys` is the contact record as it was BEFORE the
// change (remove() deletes it). Compared as decoded bytes, like app.js
// sameSigning, so a respelled key cannot slip past.
//
// Fix round 1 (pentest L): "the contact's identity" is TWO key sets, not one.
// The record's keys can move without the user re-verifying (a directory
// refresh or re-add stores new keys and drops `verified`), while the user:
// pin still holds the keys they actually compared — and the room: pins made
// in the same period hold those too. Sweeping by the record alone left the
// room pin for the old, verified keys live after Remove. So both sets count.
// Decision, stated: user: pins under OTHER labels are NOT touched. Such a pin
// belongs to a separate contact entry the user verified separately (its
// record still shows 🟢); withdrawing one entry does not withdraw the other,
// and doing it silently would leave that entry claiming a trust its pin no
// longer honours.
function revokePin(username, keys = null) {
  const pin = pins && pins[pinKeyFor(username)];
  const sets = [keys, pin].filter((s) => s && s.ed && s.mldsa);
  if (pin) pin.revoked = true;
  revokeRoomPins(sets);
}

// Mark every room: pin whose signing keys match one of `sets` as revoked.
function revokeRoomPins(sets) {
  if (!pins || sets.length === 0) return;
  for (const k of Object.keys(pins)) {
    if (!k.startsWith("room:")) continue;
    const p = pins[k];
    if (p && sets.some((s) => sameKeyBytes(p.ed, s.ed) && sameKeyBytes(p.mldsa, s.mldsa))) p.revoked = true;
  }
}

function sameKeyBytes(x, y) {
  if (typeof x !== "string" || typeof y !== "string") return false;
  let a, b;
  try { a = unb64(x); b = unb64(y); } catch { return false; }
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

// Cache the locally VERIFIED voucher names for a contact (the 🟡 mark). Only
// ever store names the caller has checked signatures for — this is a render
// cache, not a trust source.
//
// Pentest 2026-08-07 F-PROTO-005: `forKeys` is the bundle the caller VERIFIED
// the vouches against. The fetch that produced `names` is a network round trip
// the directory controls the length of, and the record can be re-added or
// re-looked-up (with different keys, which clears `vouchedBy` and stamps
// `keyChangedAt`) while it is in flight. Writing by username alone then
// re-attached "vouched by <friend>" to keys the friend never signed — shown in
// the admission prompt with no key-changed warning. So the write is
// conditional on the keys still being the ones the vouch covers; a stale
// result is discarded (returns false) and the next refresh redoes it against
// the current keys. The check and the mutation are synchronous, so there is
// no second window between them.
//
// Package 2, item 11 (F-PROTO-005, the rest): `forKeys` used to default to
// null, and null skipped the check — the unbound write F-PROTO-005 is about,
// one forgotten argument away. It is required now: a call without the keys the
// vouches were verified against is a programming error and throws.
export async function setVouches(username, names, forKeys) {
  if (!contacts) throw new Error("contact store is locked");
  if (!forKeys || typeof forKeys !== "object" || !forKeys.ed || !forKeys.mldsa) {
    throw new Error("setVouches needs the keys the vouches were verified against");
  }
  const cur = contacts.find((c) => c.username === username);
  if (!cur) return false;
  if ((
    cur.ed !== forKeys.ed || cur.mldsa !== forKeys.mldsa ||
    (cur.ecdh ?? null) !== (forKeys.ecdh ?? null) ||
    (cur.mlkem ?? null) !== (forKeys.mlkem ?? null)
  )) {
    return false;
  }
  cur.vouchedBy = names;
  cur.vouchCheckedAt = Date.now();
  await persist();
  return true;
}

export async function remove(username) {
  if (!contacts) throw new Error("contact store is locked");
  const cur = contacts.find((c) => c.username === username) || null;
  contacts = contacts.filter((c) => c.username !== username);
  revokePin(username, cur); // F-ATREST-007 (+ its room: pins, Package 3)
  await persist();
}
