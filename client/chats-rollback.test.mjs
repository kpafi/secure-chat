// Pentest 2026-08-07 F-ATREST-005 / F-CRYPTO-006: chat-store rollback control.
//
// The chat store was the only one of the four at-rest stores with no rollback
// control at all — no generation counter, no witness, no domain tag. One
// `removeItem` silently reset the P-13 envelope-replay ring (so every envelope
// the relay still holds replays as new) and every negotiated AES256 mode (so a
// chat the user upgraded quietly falls back to SEALED). The missing tag also
// made the chat plaintext adoptable AS a contact store (F-ATREST-004(b)).
//
// Run: node chats-rollback.test.mjs   (server not required)
import assert from "node:assert";
import * as chats from "./chats.js";

const PASS = "correct horse battery staple";
const LS_CHATS = "sc.chats.v1";
const LS_GEN = "sc.chats.gen.v1";

function fakeLocalStorage() {
  const m = new Map();
  return {
    getItem: (k) => (m.has(k) ? m.get(k) : null),
    setItem: (k, v) => m.set(k, String(v)),
    removeItem: (k) => m.delete(k),
    key: (i) => [...m.keys()][i] ?? null,
    get length() { return m.size; },
  };
}

function anchorFor(flags) {
  return {
    get established() { return flags.chatsEstablished === true; },
    set established(v) { flags.chatsEstablished = v; },
    markEstablished: async () => { flags.chatsEstablished = true; },
  };
}

async function deviceWithHistory() {
  globalThis.localStorage = fakeLocalStorage();
  const flags = {};
  chats.setStoreAnchor(anchorFor(flags));
  chats.lock();
  await chats.unlock(PASS);
  await chats.ensure("alice", "SEALED");
  await chats.append("alice", { dir: "in", text: "hello", ts: Date.now(), id: "env-1" });
  await chats.markSeen("alice", "env-1");
  await chats.setMode("alice", "AES256", { secret: "s3cret", salt: "AAAAAAAAAAAAAAAAAAAAAA==" });
  return flags;
}

async function testDeletingTheStoreFailsClosed() {
  const flags = await deviceWithHistory();
  assert.strictEqual(flags.chatsEstablished, true, "opening a store must record the anchor");

  localStorage.removeItem(LS_CHATS); // witness left in place
  chats.lock();
  await assert.rejects(() => chats.unlock(PASS), /has been DELETED/,
    "deleting the store must not mint an empty one");
  console.log("OK  F-ATREST-005: deleting the chat store fails closed");
}

async function testDeletingStoreAndWitnessFailsClosed() {
  await deviceWithHistory();
  localStorage.removeItem(LS_CHATS);
  localStorage.removeItem(LS_GEN); // the two-removeItem attack
  chats.lock();
  await assert.rejects(() => chats.unlock(PASS), /BOTH been deleted|BOTH have been deleted/,
    "deleting store AND witness must fail closed — this is the whole point of the anchor");
  console.log("OK  F-ATREST-005: deleting store + witness fails closed");
}

async function testRollbackIsRefused() {
  await deviceWithHistory();
  const snapshot = localStorage.getItem(LS_CHATS); // attacker keeps a copy
  await chats.append("alice", { dir: "out", text: "later message", ts: Date.now(), id: "env-2" });
  localStorage.setItem(LS_CHATS, snapshot); // ...and restores it
  chats.lock();
  await assert.rejects(() => chats.unlock(PASS), /OLDER than this device recorded/,
    "an older store blob must be detected as a rollback");
  console.log("OK  F-ATREST-005: restoring an older store is detected as a rollback");
}

async function testMissingWitnessOnATaggedStoreIsRefused() {
  await deviceWithHistory();
  localStorage.removeItem(LS_GEN);
  chats.lock();
  await assert.rejects(() => chats.unlock(PASS), /generation record .* is missing/,
    "a v2 store whose witness vanished must fail closed");
  console.log("OK  F-ATREST-005: a tagged store with no witness fails closed");
}

async function testContactWitnessCannotBeAdoptedAsChatStore() {
  // F-CRYPTO-006: the domain tag is what stops another module's plaintext from
  // opening here. Build a record tagged for the contact store and present it.
  await deviceWithHistory();
  const blob = JSON.parse(localStorage.getItem(LS_CHATS));
  const enc = new TextEncoder();
  const unb64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
  const b64 = (u8) => Buffer.from(u8).toString("base64");
  const base = await crypto.subtle.importKey("raw", enc.encode(PASS), "PBKDF2", false, ["deriveKey"]);
  const key = await crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: unb64(blob.salt), iterations: blob.iters, hash: "SHA-256" },
    base, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"],
  );
  const foreign = { d: "secure-chat/contacts-store/v4", gen: 99, contacts: [], pins: {} };
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt(
    { name: "AES-GCM", iv }, key, enc.encode(JSON.stringify(foreign)),
  ));
  localStorage.setItem(LS_CHATS, JSON.stringify({ ...blob, iv: b64(iv), ct: b64(ct) }));
  chats.lock();
  await assert.rejects(() => chats.unlock(PASS), /not a chat store/,
    "a foreign-tagged plaintext must be refused even though it decrypts");
  console.log("OK  F-CRYPTO-006: a foreign-tagged plaintext is refused by the domain tag");
}

async function testGenuineFirstRunAndLegacyAdoption() {
  // Controls: the fix must not lock out a device that legitimately has no
  // store, nor one still holding the pre-v2 bare-map shape.
  globalThis.localStorage = fakeLocalStorage();
  chats.setStoreAnchor(anchorFor({}));
  chats.lock();
  await chats.unlock(PASS);
  assert.ok(chats.isUnlocked(), "genuine first run must proceed");
  console.log("OK  control: a genuine first run still creates a chat store");

  // Pre-v2 device: bare map, no tag, no gen, no witness.
  const blob = JSON.parse(localStorage.getItem(LS_CHATS));
  const enc = new TextEncoder();
  const unb64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
  const b64 = (u8) => Buffer.from(u8).toString("base64");
  const base = await crypto.subtle.importKey("raw", enc.encode(PASS), "PBKDF2", false, ["deriveKey"]);
  const key = await crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: unb64(blob.salt), iterations: blob.iters, hash: "SHA-256" },
    base, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"],
  );
  const legacy = { bob: { username: "bob", mode: "SEALED", messages: [], seenIds: [], updatedAt: Date.now() } };
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt(
    { name: "AES-GCM", iv }, key, enc.encode(JSON.stringify(legacy)),
  ));
  globalThis.localStorage = fakeLocalStorage();
  chats.setStoreAnchor(anchorFor({}));
  localStorage.setItem(LS_CHATS, JSON.stringify({ ...blob, iv: b64(iv), ct: b64(ct) }));
  chats.lock();
  await chats.unlock(PASS);
  assert.ok(chats.get("bob"), "a genuine pre-v2 store must still be adopted");
  assert.ok(localStorage.getItem(LS_GEN), "adoption must rewrite it tagged, with a witness");
  console.log("OK  control: a pre-v2 bare-map store is still adopted and upgraded");
}

await testDeletingTheStoreFailsClosed();
await testDeletingStoreAndWitnessFailsClosed();
await testRollbackIsRefused();
await testMissingWitnessOnATaggedStoreIsRefused();
await testContactWitnessCannotBeAdoptedAsChatStore();
await testGenuineFirstRunAndLegacyAdoption();
console.log("\nAll chat-store rollback checks passed.");

// --- fix review 2026-08-07 (F3) ---------------------------------------------
// The first cut of this file's generation/witness machinery copied everything
// from contacts.js EXCEPT its L-3 compare-and-swap. Every chat operation
// persists, so two tabs is the ordinary configuration, not an exotic one:
// without the CAS the stale tab silently discarded the seenIds replay ring and
// any negotiated mode, and one write interleaving left the store OLDER than the
// witness — an unrecoverable lockout caused by the user's own second tab.
async function testConcurrentTabWriteIsRefused() {
  await deviceWithHistory();

  // Tab B is a second module instance over the same storage. Import it fresh so
  // it holds its own `generation`, exactly like a second page load would.
  const tabB = await import(`./chats.js?tab=b&t=${Date.now()}`);
  tabB.setStoreAnchor(anchorFor({ chatsEstablished: true }));
  await tabB.unlock(PASS);           // B is now at the same generation as A
  await tabB.ensure("carol", "SEALED");
  await tabB.append("carol", { dir: "in", text: "from the other tab", ts: Date.now(), id: "env-9" });
  await tabB.markSeen("carol", "env-9"); // the replay-ring entry, which is what a lost update destroys

  // Tab A is now holding stale state. Writing must REFUSE, not overwrite.
  await assert.rejects(
    () => chats.append("alice", { dir: "out", text: "from the stale tab", ts: Date.now(), id: "env-3" }),
    /changed in another tab/,
    "a stale tab must refuse to write, not silently discard the other tab's history",
  );

  // ...and the other tab's work must still be there.
  chats.lock();
  chats.setStoreAnchor(anchorFor({ chatsEstablished: true }));
  await chats.unlock(PASS);
  assert.ok(chats.get("carol"), "the other tab's chat must survive");
  assert.ok(chats.get("carol").seenIds.includes("env-9"), "...including its replay-ring entry");
  console.log("OK  F3: a stale second tab is refused instead of causing a lost update");
}

await testConcurrentTabWriteIsRefused();

// --- pentest 2026-08-08, item 16 --------------------------------------------
// The test above only covers the interleaving the CAS DOES catch: tab B
// completes its whole write before tab A starts. The one that still lost data is
// the other one — BOTH tabs read the witness before EITHER writes, so both see
// generation N, both pass the check, and both write N+1.
//
// Node has no `navigator.locks`, so the cross-tab half of the fix is inert here
// unless it is provided. This shim is a faithful minimal Web Locks: exclusive by
// name, FIFO, held for the life of the callback's promise. It lives on
// `globalThis`, so both module instances contend for the same lock exactly as
// two tabs of one origin do.
function installWebLocksShim() {
  const held = new Map();   // name -> promise chain
  const prev = globalThis.navigator;
  const locks = {
    request(name, fn) {
      const tail = held.get(name) || Promise.resolve();
      const run = () => Promise.resolve().then(fn);
      const next = tail.then(run, run);
      held.set(name, next.then(() => {}, () => {}));
      return next;
    },
  };
  // `navigator` exists but is read-only in Node, so redefine the property.
  Object.defineProperty(globalThis, "navigator", {
    value: { ...(prev || {}), locks },
    configurable: true,
    writable: true,
  });
  return () => Object.defineProperty(globalThis, "navigator", {
    value: prev, configurable: true, writable: true,
  });
}

async function testBothReadFirstInterleaving() {
  const restore = installWebLocksShim();
  try {
    await deviceWithHistory();

    const tabB = await import(`./chats.js?item16=b&t=${Date.now()}`);
    tabB.setStoreAnchor(anchorFor({ chatsEstablished: true }));
    await tabB.unlock(PASS);   // both tabs are now at the same generation

    // Fire both writes WITHOUT awaiting the first, which is what puts both
    // reads before both writes. Each adds a distinct entry to the P-13 replay
    // ring — the structure a lost update silently empties.
    const results = await Promise.allSettled([
      chats.markSeen("alice", "env-A1"),
      tabB.markSeen("alice", "env-B1"),
    ]);

    const fulfilled = results.filter((r) => r.status === "fulfilled" && r.value === true);
    const refused = results.filter(
      (r) => r.status === "rejected" && /changed in another tab/.test(String(r.reason)));

    assert.strictEqual(fulfilled.length, 1,
      "exactly one concurrent write may succeed — two successes IS the lost update");
    assert.strictEqual(refused.length, 1,
      "the loser must be told to reload, not silently discard the winner's history");

    // The winner's entry must actually be on disk. Re-read from storage with a
    // third instance so nothing in-memory can mask a lost write.
    const reader = await import(`./chats.js?item16=r&t=${Date.now()}`);
    reader.setStoreAnchor(anchorFor({ chatsEstablished: true }));
    await reader.unlock(PASS);
    const seen = reader.get("alice").seenIds;
    assert.ok(seen.includes("env-A1") || seen.includes("env-B1"),
      "the surviving write's replay-ring entry must be persisted");
    console.log("OK  item 16: two tabs that both read first cannot both write");

    // The lockout half: the store must never end up OLDER than its witness, or
    // `assertNotRolledBack` refuses forever. Re-opening above already proves the
    // pair is consistent — an inverted pair throws there — so assert it directly.
    assert.ok(reader.isUnlocked(), "store and witness must stay consistent (no permanent lockout)");
    console.log("OK  item 16: store and witness stay consistent, so no self-inflicted lockout");
  } finally {
    restore();
  }
}

await testBothReadFirstInterleaving();

// --- item 11: a stuck write lock must SURFACE, not hang silently -------------
// `withWriteLock` had no timeout, so a same-origin script (or a tab wedged inside
// its own callback) holding WRITE_LOCK hung every subsequent write forever with
// nothing shown to the user. Quiet history loss is the exact failure this store
// exists to prevent, so a lock that never frees must produce an error the caller
// can report.
//
// Waiting out the real 10s timeout would put a 10-second stall in the suite, so
// the timer itself is stubbed: `setTimeout` fires immediately for exactly the
// production delay. That keeps the assertion on the REAL code path (the race in
// withWriteLock, the real error) with no test-only hook in chats.js — a knob a
// same-origin script could turn is precisely what this project does not want.
async function testStuckWriteLockSurfaces() {
  const prevNav = globalThis.navigator;
  const realSetTimeout = globalThis.setTimeout;
  let firedForProductionDelay = false;
  Object.defineProperty(globalThis, "navigator", {
    value: {
      ...(prevNav || {}),
      // Never settles: exactly a lock held by somebody who is not coming back.
      locks: { request: () => new Promise(() => {}) },
    },
    configurable: true,
    writable: true,
  });
  globalThis.setTimeout = (fn, ms, ...rest) => {
    if (ms === 10_000) { firedForProductionDelay = true; return realSetTimeout(fn, 0); }
    return realSetTimeout(fn, ms, ...rest);
  };
  try {
    fakeLocalStorage();
    const chats = await import(`./chats.js?stuck=${Date.now()}`);
    // unlock() creates the store before the lock is wedged...
    Object.defineProperty(globalThis, "navigator", { value: prevNav, configurable: true, writable: true });
    await chats.unlock(PASS);
    // ...and now a real write has to acquire a lock nobody will ever release.
    Object.defineProperty(globalThis, "navigator", {
      value: { ...(prevNav || {}), locks: { request: () => new Promise(() => {}) } },
      configurable: true, writable: true,
    });
    await assert.rejects(() => chats.ensure("bob"),
      /taking too long/,
      "item 11: a write lock nobody releases must REJECT, not hang forever — a silently dropped " +
      "write is indistinguishable from a saved one to the user, and quiet history loss is the " +
      "exact failure this store exists to prevent");
    assert.ok(firedForProductionDelay,
      "item 11: the rejection must come from withWriteLock's own 10s timeout, not from something " +
      "else failing — otherwise this test would pass with the timeout deleted");
    console.log("OK  item 11: a write lock nobody releases surfaces instead of hanging");
  } finally {
    globalThis.setTimeout = realSetTimeout;
    Object.defineProperty(globalThis, "navigator", { value: prevNav, configurable: true, writable: true });
  }
}

await testStuckWriteLockSurfaces();

// ---------------------------------------------------------------------------
// ROUND-3 F-6 (pentest of the timeout above): the timeout must REPORT, never
// release. `Promise.race` does not cancel `run()`, so chaining the next write on
// the RACE let a slow write be abandoned rather than cancelled — the next
// persistLocked started while the first was still in flight. The loser then wrote
// store `gen N+1` over the winner's `N+2` while writeWitness() read the
// module-level generation, leaving store older than witness, which
// assertNotRolledBack refuses PERMANENTLY: the unrecoverable lockout the CAS
// exists to prevent, manufactured by the guard meant to prevent a hang.
//
// Two assertions, because each alone is satisfiable by the bug:
//   1. a REPLICA of the shipped chaining logic must never run two callbacks at
//      once, even when one exceeds the timeout;
//   2. a source anchor that the shipped chain is built from the WORK promise
//      rather than from the race — the replica cannot prove that by itself.
async function testTimeoutDoesNotReleaseTheLock() {
  const TIMEOUT = 20;
  let inFlight = 0;
  let overlapped = false;
  let writeChain = Promise.resolve();

  // Replica of chats.js withWriteLock's chaining, deliberately verbatim in shape.
  const withWriteLock = (run) => {
    const started = writeChain.then(run, run);
    writeChain = started.then(() => {}, () => {});
    return Promise.race([
      started,
      new Promise((_, reject) => setTimeout(() => reject(new Error("taking too long")), TIMEOUT)),
    ]);
  };

  const slow = (ms) => async () => {
    inFlight++;
    if (inFlight > 1) overlapped = true;
    await new Promise((r) => setTimeout(r, ms));
    inFlight--;
  };

  const a = withWriteLock(slow(TIMEOUT * 4)).catch(() => "reported");
  const b = withWriteLock(slow(1)).catch(() => "reported");
  assert.strictEqual(await a, "reported",
    "F-6: the caller of a slow write must still be TOLD — visibility is why the timeout exists");
  await b;
  await writeChain;
  assert.strictEqual(overlapped, false,
    "ROUND-3 F-6: two store writes must never be in flight at once. The timeout may report a " +
    "slow write; it may not let the next one start on top of it, because the loser's generation " +
    "then lands after the winner's and assertNotRolledBack locks the store out forever.");
  console.log("OK  F-6: a timed-out write is reported, not released — no concurrent persists");

  const { readFile } = await import("node:fs/promises");
  const { stripComments } = await import("./test-source.mjs");
  const src = stripComments(await readFile(new URL("./chats.js", import.meta.url), "utf8"));
  assert.match(src, /const started = writeChain\.then\(run, run\);/,
    "F-6: the write chain must be built from the WORK promise...");
  assert.match(src, /writeChain = started\.then\(/,
    "...and must advance on that promise, not on the timeout race — chaining on the race is " +
    "exactly what let an abandoned write run concurrently with the next one");
  console.log("OK  F-6: the shipped chain follows the real completion, not the race");
}

await testTimeoutDoesNotReleaseTheLock();

// ---------------------------------------------------------------------------
// TEST-DEBT ITEM 7. Three guards in `withWriteLock`/`persistLocked` were "green
// against deletion": delete them and the suite still passed, so they proved
// nothing. Each is reached here by stubbing the ENVIRONMENT — never by adding a
// hook to chats.js, because a knob a same-origin script could turn is precisely
// what this project does not want (see testStuckWriteLockSurfaces above, which
// stubs `setTimeout` for exactly the same reason).
//
// A CORRECTION FIRST, since it is the reason two of the three were dead. The
// comment at the head of installWebLocksShim says "Node has no navigator.locks".
// That was true when it was written and is not true now: Node 21 grew a global
// `navigator`, and on this runtime `locks` sits on `Navigator.prototype`
// (`Object.keys(navigator.__proto__)` lists it). So `hasWebLocks` has been TRUE
// in every test in this file whether or not the shim was installed, and the
// `: fn()` fallback branch had never once executed. Note also that
// `delete globalThis.navigator.locks` does NOT work for the same reason — the
// property is on the prototype, not on the instance — so the global itself has
// to be replaced or removed.

// --- item 7 (a): the no-Web-Locks fallback still serialises writes -----------
// On Chrome/Android WebView < 69, Firefox < 96 and Safari 15.0-15.3 there is no
// Web Locks API at all, and chats.js deliberately does NOT fail closed there —
// refusing would lock those users out of their own history, which is a worse
// outcome than the cross-tab race it would prevent (the comment in withWriteLock
// argues this at length). What carries the load on those engines is the intra-tab
// `writeChain`, and NOTHING has ever tested it, because the branch was
// unreachable in this suite.
//
// If the chain is dropped, two `persist()` calls on those engines interleave
// read-witness / bump-generation / write, and the loser lands generation N+1 on
// top of the winner's N+2 while the witness says N+2 — store older than witness,
// which `assertNotRolledBack` refuses PERMANENTLY. A browser-version-dependent,
// unrecoverable lockout.
async function testWritesSerialiseWithoutWebLocks() {
  const prevNav = Object.getOwnPropertyDescriptor(globalThis, "navigator");
  const realEncrypt = crypto.subtle.encrypt.bind(crypto.subtle);
  let inFlight = 0;
  let overlapped = false;
  try {
    // An empty object, not `delete`: this pins the fallback specifically (the
    // binding exists, `locks` does not), which is a DIFFERENT guard from the
    // `typeof navigator` one tested below. They die to different mutants, so
    // they are two tests rather than one.
    Object.defineProperty(globalThis, "navigator", { value: {}, configurable: true, writable: true });
    assert.strictEqual(typeof navigator, "object", "fixture: the binding must still exist");
    assert.strictEqual(navigator.locks, undefined,
      "fixture: ...but with no Web Locks — this is the branch PAD_SIZES of browsers actually run");

    globalThis.localStorage = fakeLocalStorage();
    const store = await import(`./chats.js?nolocks=${Date.now()}`);
    store.setStoreAnchor(anchorFor({}));
    await store.unlock(PASS);

    // Detect overlap in the middle of the real persist, where the read-modify-
    // write window actually is. `encrypt` is the awaited call inside
    // persistLocked, so two persists in flight at once show up here.
    crypto.subtle.encrypt = async (...args) => {
      inFlight++;
      if (inFlight > 1) overlapped = true;
      try {
        await new Promise((r) => setTimeout(r, 20));
        return await realEncrypt(...args);
      } finally { inFlight--; }
    };

    // Three writes fired WITHOUT awaiting, which is what an ordinary burst of
    // chat activity looks like (ensure/append/markSeen all persist).
    const results = await Promise.allSettled([
      store.ensure("alice"), store.ensure("bob"), store.ensure("carol"),
    ]);
    crypto.subtle.encrypt = realEncrypt;
    const failed = results.filter((r) => r.status === "rejected");
    assert.deepStrictEqual(failed.map((r) => String(r.reason)), [],
      "control: with no Web Locks the writes must still SUCCEED — chats.js deliberately does not " +
      "fail closed here, because locking a user out of their own history is worse than the race");
    assert.strictEqual(overlapped, false,
      "item 7: with no Web Locks API, `writeChain` is the ONLY thing serialising writes in the " +
      "tab. Two persists overlapping means the loser writes generation N+1 over the winner's " +
      "N+2 while the witness holds N+2 — store older than witness, which assertNotRolledBack " +
      "refuses permanently. That is an unrecoverable lockout on Chrome/WebView<69, FF<96 and " +
      "Safari 15.0-15.3, and this suite never executed that branch at all until now.");

    // ...and all three writes must actually be on disk, so "serialised" does not
    // quietly mean "one of them was dropped".
    for (const who of ["alice", "bob", "carol"]) {
      assert.ok(store.get(who), `every serialised write must survive (${who} is missing)`);
    }
    console.log("OK  item 7: with no Web Locks API, writeChain still serialises every write");
  } finally {
    crypto.subtle.encrypt = realEncrypt;
    if (prevNav) Object.defineProperty(globalThis, "navigator", prevNav);
    else delete globalThis.navigator;
  }
}

await testWritesSerialiseWithoutWebLocks();

// --- item 7 (b): no `navigator` BINDING at all ------------------------------
// The guard is `typeof navigator !== "undefined"`, not merely `navigator.locks`,
// and the difference is not cosmetic: with no binding, a bare `navigator.locks`
// is a ReferenceError, which is thrown out of `unlock()` and every subsequent
// write. Node only grew a global `navigator` in 21.0.0 and the repo's brief still
// targets Node 20; the same holds for any embedding that does not install one.
// The failure mode is the one this project cares about most — it reads as a bug
// in the chat store rather than as a missing global, so it gets debugged in the
// wrong place while history is inaccessible. Pentest 2026-08-10 (L-2).
async function testNoNavigatorBindingAtAll() {
  const prevNav = Object.getOwnPropertyDescriptor(globalThis, "navigator");
  try {
    delete globalThis.navigator;
    assert.strictEqual(typeof navigator, "undefined", "fixture: the binding must be gone");
    assert.throws(() => navigator.locks, ReferenceError,
      "fixture: an UNGUARDED read must be a ReferenceError — that is what this guard exists for, " +
      "and it is why `navigator.locks &&` alone would not have been enough");

    globalThis.localStorage = fakeLocalStorage();
    const store = await import(`./chats.js?nonav=${Date.now()}`);
    store.setStoreAnchor(anchorFor({}));
    await store.unlock(PASS);          // this is what threw on Node 20
    await store.ensure("alice", "SEALED");
    await store.append("alice", { dir: "in", text: "hi", ts: Date.now(), id: "env-1" });
    assert.ok(store.get("alice"), "a runtime with no `navigator` must still be able to write");
    assert.ok(localStorage.getItem(LS_GEN), "...including the rollback witness beside the store");
    console.log("OK  item 7 / L-2: a runtime with no `navigator` binding can still open and write");
  } finally {
    if (prevNav) Object.defineProperty(globalThis, "navigator", prevNav);
    else delete globalThis.navigator;
  }
}

await testNoNavigatorBindingAtAll();

// --- item 7 (c): `persistLocked` re-checks `chats`, not only `dataKey` -------
// `unlock()` sets `dataKey` (line ~148) and only later assigns `chats` (~197),
// with a `crypto.subtle.decrypt` and a `JSON.parse` in between. A write that was
// already queued on the write lock and dispatches inside that window sees
// `dataKey` set and `chats === null`. Without the `!chats` half of the guard it
// serialises `chats: null` AND writes an agreeing witness beside it — so the
// rollback check then calls the empty store healthy. Silent, total history loss,
// certified as fine by the machinery built to detect exactly that.
//
// The window is opened here with three environment stubs and no product change:
// a controlled Web Locks shim whose grant waits on a gate the test holds, so two
// writes can be parked; and a `crypto.subtle.decrypt` stub that opens the gate
// and then stalls, so the parked writes dispatch while `unlock()` is between its
// two assignments. Same move as testStuckWriteLockSurfaces' `setTimeout` stub.
async function testQueuedWriteInsideTheUnlockWindowIsRefused() {
  const prevNav = Object.getOwnPropertyDescriptor(globalThis, "navigator");
  const realDecrypt = crypto.subtle.decrypt.bind(crypto.subtle);
  let openGate = () => {};
  const gate = new Promise((r) => { openGate = r; });
  let gated = false;
  try {
    globalThis.localStorage = fakeLocalStorage();
    // A faithful minimal Web Locks (exclusive by name, FIFO, held for the life of
    // the callback promise) with one addition: while `gated`, a grant waits on
    // the test's gate. That is what parks the writes without touching chats.js.
    const held = new Map();
    Object.defineProperty(globalThis, "navigator", {
      value: {
        locks: {
          request(name, fn) {
            const tail = held.get(name) || Promise.resolve();
            const run = async () => { if (gated) await gate; return fn(); };
            const next = tail.then(run, run);
            held.set(name, next.then(() => {}, () => {}));
            return next;
          },
        },
      },
      configurable: true, writable: true,
    });

    const store = await import(`./chats.js?window=${Date.now()}`);
    store.setStoreAnchor(anchorFor({}));   // genuine first run: nothing to roll back yet
    await store.unlock(PASS);
    await store.ensure("alice", "SEALED");
    await store.append("alice", { dir: "in", text: "keep me", ts: Date.now(), id: "env-1" });
    const onDisk = localStorage.getItem(LS_CHATS);

    // Park two writes behind the gate, then lock. They are now queued against a
    // store that is about to be re-opened.
    gated = true;
    // Settled outcomes captured EAGERLY. A rejection with no handler attached at
    // the moment it happens is an unhandled rejection that tears the process
    // down before any assertion runs — and the whole point is that these two
    // reject, so the handler has to be on them from the start.
    const settle = (p) => p.then(() => "RESOLVED — the write went through", (e) => String(e && e.message));
    const w1 = settle(store.ensure("bob"));
    const w2 = settle(store.ensure("carol"));
    await new Promise((r) => setTimeout(r, 5));   // let both reach the lock
    store.lock();

    // The stub fires INSIDE unlock(), after `dataKey` is assigned and before
    // `chats` is: it releases the parked writes and then stalls long enough for
    // them to dispatch into the window.
    crypto.subtle.decrypt = async (...args) => {
      gated = false;
      openGate();
      await new Promise((r) => setTimeout(r, 120));
      return realDecrypt(...args);
    };
    await store.unlock(PASS);
    crypto.subtle.decrypt = realDecrypt;

    assert.match(await w1, /chat store is locked/,
      "item 7: a write that dispatches between `dataKey = ...` and `chats = ...` must be REFUSED. " +
      "Without the `!chats` half of the guard it serialises a null store and writes an AGREEING " +
      "witness beside it, so assertNotRolledBack reports the empty store as healthy — silent, " +
      "total history loss certified as fine by the check built to catch exactly that.");
    assert.match(await w2, /chat store is locked/,
      "...and every queued write in the window, not merely the first one");

    // The history itself must be intact: proven by re-reading from storage with a
    // fresh module instance, so nothing in memory can mask a null-store write.
    const reader = await import(`./chats.js?windowread=${Date.now()}`);
    reader.setStoreAnchor(anchorFor({ chatsEstablished: true }));
    await reader.unlock(PASS);
    assert.ok(reader.get("alice"), "the pre-existing chat must survive the refused writes");
    assert.ok(reader.get("alice").messages.some((m) => m.id === "env-1"),
      "...with its messages, which is what a serialised null store would have erased");
    assert.strictEqual(localStorage.getItem(LS_CHATS), onDisk,
      "...and the blob must be byte-identical: a refused write may not have persisted anything");
    console.log("OK  item 7: a write queued into the unlock window is refused, not serialised as null");
  } finally {
    crypto.subtle.decrypt = realDecrypt;
    if (prevNav) Object.defineProperty(globalThis, "navigator", prevNav);
    else delete globalThis.navigator;
  }
}

await testQueuedWriteInsideTheUnlockWindowIsRefused();

console.log("All chat-store concurrency checks passed.");
