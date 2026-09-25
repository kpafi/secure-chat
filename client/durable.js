// Durable on-device storage: one IndexedDB object store, written with
// `durability: "strict"`. Package 3b (the package-3 pentest's durability HIGH).
//
// THE FINDING. `localStorage.setItem` returning is NOT "on disk". Chromium keeps
// localStorage changes in the browser process and commits them to its LevelDB
// in rate-limited batches; measured on Chromium 150, a write made ~12 s after
// the previous one was still lost when the process was killed 45 s later. Every
// "persist before X" rule in this client — persist a pad's consumption before
// the ciphertext leaves, persist a receipt before the text is shown, latch
// "exported" before the file is handed out — was therefore a rule about the
// renderer's memory, not about the disk. End to end through the real otp.js: a
// kill a few seconds after a send reopened the pad at the offset the message
// had already used, and the next message reused those pad bytes (a two-time
// pad). No attacker is needed: a crash, an OOM kill or a power cut does it.
//
// On Android the order was the other way round and just as bad: the native
// floor (PadFloor.kt, SharedPreferences.commit(), synchronous) reached disk
// while the WebView's localStorage batch did not, so after a kill the floor was
// AHEAD of the data it protects — the pad refused as rolled back, the contact
// or chat store refused as "an earlier copy restored", with no override.
//
// WHAT THIS MODULE GUARANTEES. `write()` resolves only on the transaction's
// `complete` event, and every read-write transaction is opened with
// `{durability: "strict"}`:
//   * Chromium (Chrome, Android WebView): strict makes the backend flush to disk
//     BEFORE `complete` fires (Chrome's own documentation, and the reason 121
//     made "relaxed" the default). IndexedDB lives in the browser/storage
//     process, not the renderer, and has no commit batching of its own.
//   * WebKit (Safari, iOS WKWebView): strict runs a FULL WAL checkpoint of the
//     SQLite database after the commit (WebKit changeset 280415, Safari 15+).
//   * Firefox: strict (its "default") syncs the SQLite commit.
// Where the hint is ignored (an old engine), `complete` still means the
// transaction was committed by the storage backend and handed to the OS: that
// survives the app's process being killed — the failure measured above — and
// only a power cut before the OS writes back can lose it. The ordering rule the
// callers rely on (native floor advanced only after `complete`) does not depend
// on the hint at all.
//
// It is NOT a security boundary against the JS context: whoever runs script in
// the page can delete or rewrite these records like any localStorage key. The
// callers seal what they store and treat a missing record by their existing
// rules. This module is about crashes, not attackers.
//
// TESTS: node has no IndexedDB. fake-idb.test.mjs installs a small in-memory
// `globalThis.indexedDB` with just the API surface used here; every call below
// reads `globalThis.indexedDB` afresh, so a test can swap or remove it.

const DB_NAME = "secure-chat";
const DB_VERSION = 1;
const STORE = "kv";

let cached = null; // { factory, promise<IDBDatabase> }

function factory() {
  const f = globalThis.indexedDB;
  return f && typeof f.open === "function" ? f : null;
}

// True when this engine offers IndexedDB at all. OTP is refused without it
// (otp.js); the contact and chat stores fall back to localStorage without a
// native floor (see storeSlot below).
export function available() {
  return factory() !== null;
}

export function unavailableError(what) {
  const err = new Error(
    `${what} need the browser's durable database (IndexedDB), which is not available here — ` +
    "private browsing, disabled site data or a very old browser. Use the app or a current browser with site data allowed.",
  );
  err.code = "NO_DURABLE_STORAGE";
  return err;
}

function openDb() {
  const f = factory();
  if (!f) return Promise.reject(unavailableError("This feature"));
  if (cached && cached.factory === f) return cached.promise;
  const promise = new Promise((resolve, reject) => {
    let req;
    try {
      req = f.open(DB_NAME, DB_VERSION);
    } catch (e) {
      reject(e);
      return;
    }
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains(STORE)) db.createObjectStore(STORE);
    };
    req.onsuccess = () => {
      const db = req.result;
      // Another tab upgrading the schema (a future version) asks us to let go.
      db.onversionchange = () => { try { db.close(); } catch { /* ignore */ } cached = null; };
      resolve(db);
    };
    req.onerror = () => reject(req.error || new Error("could not open the durable database"));
    req.onblocked = () => reject(new Error("the durable database is blocked by another tab — close other tabs of this app"));
  });
  cached = { factory: f, promise };
  promise.catch(() => { if (cached && cached.promise === promise) cached = null; });
  return promise;
}

// Read several keys in one read-only transaction: { key: value | null }.
export async function getMany(keys) {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const out = {};
    let tx;
    try {
      tx = db.transaction(STORE, "readonly");
    } catch (e) {
      reject(e);
      return;
    }
    const os = tx.objectStore(STORE);
    for (const k of keys) {
      const r = os.get(k);
      r.onsuccess = () => { out[k] = r.result === undefined ? null : r.result; };
    }
    tx.oncomplete = () => resolve(out);
    tx.onerror = () => reject(tx.error || new Error("durable read failed"));
    tx.onabort = () => reject(tx.error || new Error("durable read aborted"));
  });
}

export async function get(key) {
  return (await getMany([key]))[key];
}

// Write several keys ATOMICALLY in one strict read-write transaction. A value
// of null deletes the key. Resolves only once the transaction has COMPLETED —
// never on a request's `success`, which fires before the commit.
export async function write(entries) {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    let tx;
    try {
      tx = db.transaction(STORE, "readwrite", { durability: "strict" });
    } catch (e) {
      reject(e);
      return;
    }
    const os = tx.objectStore(STORE);
    for (const k of Object.keys(entries)) {
      const v = entries[k];
      if (v === null || v === undefined) os.delete(k);
      else os.put(v, k);
    }
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error || new Error("durable write failed"));
    tx.onabort = () => reject(tx.error || new Error("durable write aborted (storage full?)"));
  });
}

// Write `entries` only if NONE of their keys exists yet — checked and written in
// the same strict transaction, so two tabs migrating at once cannot let the
// slower one overwrite what the faster one has already moved AND updated.
// Resolves true when written, false when something was already there.
export async function writeIfAbsent(entries) {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    let tx;
    try {
      tx = db.transaction(STORE, "readwrite", { durability: "strict" });
    } catch (e) {
      reject(e);
      return;
    }
    const os = tx.objectStore(STORE);
    const keys = Object.keys(entries);
    let seen = 0;
    let present = false;
    for (const k of keys) {
      const r = os.get(k);
      r.onsuccess = () => {
        if (r.result !== undefined) present = true;
        if (++seen === keys.length && !present) {
          for (const w of keys) if (entries[w] !== null && entries[w] !== undefined) os.put(entries[w], w);
        }
      };
    }
    tx.oncomplete = () => resolve(!present);
    tx.onerror = () => reject(tx.error || new Error("durable write failed"));
    tx.onabort = () => reject(tx.error || new Error("durable write aborted (storage full?)"));
  });
}

export function put(key, value) {
  return write({ [key]: value });
}

export function del(key) {
  return write({ [key]: null });
}

// ---- the contact / chat store slot -----------------------------------------
//
// Owner decision 2026-09-25: the contact and chat stores MOVE to IndexedDB. A
// store is two records — the sealed blob and its generation witness — and they
// now travel together in ONE strict transaction (under localStorage they were
// two setItem calls and a crash could split them). `blobKey` / `genKey` keep
// their localStorage names, so a record is the same string in either place.
//
// Migration: the first read on a device whose IndexedDB holds neither record
// but whose localStorage does copies both, verbatim (they are opaque sealed
// strings; no passphrase is needed), reads them back, and only then removes the
// localStorage copies — so one source of truth remains, and a crash at any
// point leaves at least one complete copy. `marker` (a localStorage key) then
// records "this store lives in IndexedDB": it makes hasStore() answer
// synchronously across tabs, and if IndexedDB later goes missing it turns
// "no store here" into a loud refusal instead of a silent fresh (pin-less)
// store. An OLDER client does not know the marker and would see no store at
// all — downgrading after the migration is not supported (release notes).
//
// Without IndexedDB (and no marker) the slot keeps using localStorage exactly
// as before; `durable()` is then false and the stores do NOT advance their
// native floor, so a floor can never get ahead of data that may not be on disk.
export function storeSlot({ blobKey, genKey, marker }) {
  let pending = true;
  let mode = null;           // "idb" | "ls"
  let cache = { blob: null, witness: null };
  const ls = () => globalThis.localStorage;
  const lsGet = (k) => ls().getItem(k);

  async function read() {
    if (!available()) {
      if (lsGet(marker) !== null) {
        const err = new Error(
          "this store was moved to the browser's durable database (IndexedDB), which is not available right now — " +
          "refusing to start over with an empty one. Reload, or allow site data for this app.",
        );
        err.code = "NO_DURABLE_STORAGE";
        throw err;
      }
      mode = "ls";
      cache = { blob: lsGet(blobKey), witness: lsGet(genKey) };
      return cache;
    }
    const got = await getMany([blobKey, genKey]);
    mode = "idb";
    if (got[blobKey] === null && got[genKey] === null) {
      const legacy = { blob: lsGet(blobKey), witness: lsGet(genKey) };
      if (legacy.blob !== null || legacy.witness !== null) {
        // Conditional: another tab may have migrated (and even saved) between
        // our read and this write. Then its copy stands and we re-read it.
        const moved = await writeIfAbsent({ [blobKey]: legacy.blob, [genKey]: legacy.witness });
        const back = await getMany([blobKey, genKey]);
        if (moved && (back[blobKey] !== legacy.blob || back[genKey] !== legacy.witness)) {
          throw new Error("moving this store to the durable database did not read back identically — nothing was removed; reload and try again");
        }
        ls().setItem(marker, "1");
        ls().removeItem(blobKey);
        ls().removeItem(genKey);
        cache = { blob: back[blobKey], witness: back[genKey] };
        return cache;
      }
      cache = legacy;
      return cache;
    }
    // IndexedDB holds the store. A localStorage copy can only be what an
    // interrupted migration left behind: IndexedDB wins, the copy goes.
    if (lsGet(blobKey) !== null) ls().removeItem(blobKey);
    if (lsGet(genKey) !== null) ls().removeItem(genKey);
    if (lsGet(marker) === null) ls().setItem(marker, "1");
    cache = { blob: got[blobKey], witness: got[genKey] };
    return cache;
  }

  // Preload at module load, so hasStore() can answer synchronously. Until it
  // settles, known() says TRUE: "unknown" must read as "a store exists" (the
  // loud pins-unreadable path in app.js), never as a clean first run.
  const ready = read().then(() => {}, () => {}).finally(() => { pending = false; });

  return {
    ready,
    read: async () => { await ready; return read(); },
    async readWitness() {
      await ready;
      if (mode === "ls" || !available()) return lsGet(genKey);
      return get(genKey);
    },
    // True when the last read went to IndexedDB (writes are durable there).
    durable: () => mode === "idb",
    async write(blob, witness) {
      await ready;
      if (mode !== "idb") {
        ls().setItem(blobKey, blob);
        ls().setItem(genKey, witness);
      } else {
        await write({ [blobKey]: blob, [genKey]: witness });
        if (lsGet(marker) === null) ls().setItem(marker, "1");
      }
      cache = { blob, witness };
    },
    async wipe() {
      cache = { blob: null, witness: null };
      ls().removeItem(blobKey);
      ls().removeItem(genKey);
      ls().removeItem(marker);
      if (available()) await write({ [blobKey]: null, [genKey]: null });
    },
    known() {
      return pending || cache.blob !== null || cache.witness !== null ||
        lsGet(marker) !== null || lsGet(blobKey) !== null || lsGet(genKey) !== null;
    },
  };
}
