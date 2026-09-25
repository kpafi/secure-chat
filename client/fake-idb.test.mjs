// A small in-memory IndexedDB for node — just the surface durable.js uses —
// with the knobs the package-3b crash tests need. NOT a test file on its own:
// it is imported by the tests (named `*.test.mjs` so every ship list excludes
// it, like dom-stub.test.mjs).
//
// What it models faithfully, because the tests depend on it:
//   * a read-write transaction's writes become visible (`mem`) only when the
//     transaction COMPLETES, and `complete` fires asynchronously after the
//     requests' `success` events — so code that resolves on a request's
//     success instead of the transaction's complete is caught;
//   * transactions run one after another in creation order, as IndexedDB runs
//     overlapping transactions on one store: a read created after a write sees
//     that write (and waits for it, even while commits are held);
//   * the `durability` option each read-write transaction was opened with is
//     recorded (`log`), so "strict" is checked, not assumed;
//   * transactions are atomic: an aborted one writes nothing.
// Knobs:
//   fake.hold()                 — commits wait until fake.release() (lets a test
//                                 observe what the app does while a durable
//                                 write is still in flight)
//   fake.failWrites(pred, msg)  — a read-write transaction touching a key for
//                                 which pred(key) is true aborts (quota, I/O)
//   fake.onCommit = fn          — called synchronously at the commit point, i.e.
//                                 the state a process kill right after the
//                                 durable write would leave behind
//   fake.mem                    — the committed data (a Map)
//   fake.getItem/setItem/removeItem/clear — localStorage-shaped access to
//                                 `mem`, for tests that tamper with a record
//   install() / uninstall()     — set / delete globalThis.indexedDB

export function makeFakeIdb() {
  const mem = new Map();
  const log = [];
  let held = null; // pending commit thunks while held
  let failPred = null;
  let failMsg = null;
  const fake = {
    mem, log,
    onCommit: null,
    beforeTx: null, // (mode) => void, called as a transaction is CREATED (another tab acting first)
    hold() { if (!held) held = []; },
    release() { const q = held || []; held = null; for (const f of q) f(); },
    pendingCommits: () => (held ? held.length : 0),
    failWrites(pred, message = null) { failPred = pred; failMsg = message; },
    getItem: (k) => (mem.has(k) ? mem.get(k) : null),
    setItem: (k, v) => { mem.set(k, String(v)); },
    removeItem: (k) => { mem.delete(k); },
    clear: () => mem.clear(),
    install() { globalThis.indexedDB = factory; },
    uninstall() { delete globalThis.indexedDB; },
  };

  const later = (fn) => setTimeout(fn, 0);

  let chain = Promise.resolve();
  function makeTx(mode, opts) {
    if (fake.beforeTx) fake.beforeTx(mode);
    const reqs = []; // [fn, request]
    const staged = [];
    const tx = {
      oncomplete: null, onerror: null, onabort: null, error: null,
      objectStore() {
        const req = (fn) => {
          const r = { onsuccess: null, onerror: null, result: undefined };
          reqs.push([fn, r]);
          return r;
        };
        const writable = () => { if (mode !== "readwrite") throw new Error("ReadOnlyError"); };
        return {
          get: (k) => req(() => (mem.has(k) ? mem.get(k) : undefined)),
          put: (v, k) => { writable(); staged.push(["put", k, v]); return req(() => k); },
          delete: (k) => { writable(); staged.push(["del", k]); return req(() => undefined); },
        };
      },
    };
    if (mode === "readwrite") log.push({ durability: opts && opts.durability, keys: staged });
    const run = () => new Promise((done) => {
      // One macrotask first, so every request of this transaction is queued.
      later(() => {
        for (const [fn, r] of reqs) {
          r.result = fn();
          if (r.onsuccess) r.onsuccess({ target: r });
        }
        // `complete` strictly after the requests' `success` (another hop).
        later(() => {
          if (mode !== "readwrite") { if (tx.oncomplete) tx.oncomplete(); done(); return; }
          const commit = () => {
            if (failPred && staged.some(([, k]) => failPred(k))) {
              tx.error = new Error(failMsg || "QuotaExceededError (fake IndexedDB)");
              if (tx.onerror) tx.onerror({ target: tx });
              if (tx.onabort) tx.onabort({ target: tx });
              done();
              return;
            }
            for (const [op, k, v] of staged) {
              if (op === "put") mem.set(k, v); else mem.delete(k);
            }
            if (fake.onCommit) fake.onCommit(staged.map(([, k]) => k));
            if (tx.oncomplete) tx.oncomplete();
            done();
          };
          if (held) held.push(commit); else commit();
        });
      });
    });
    chain = chain.then(run);
    return tx;
  }

  const db = {
    objectStoreNames: { contains: () => true },
    createObjectStore() {},
    transaction: (store, mode = "readonly", opts) => makeTx(mode, opts),
    close() {},
  };
  const factory = {
    open() {
      const r = { result: null, onsuccess: null, onerror: null, onupgradeneeded: null };
      later(() => { r.result = db; if (r.onupgradeneeded) r.onupgradeneeded(); if (r.onsuccess) r.onsuccess(); });
      return r;
    },
  };
  return fake;
}

// The common case: one fake, installed before any client module is imported.
export const fakeIdb = makeFakeIdb();
fakeIdb.install();
