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
      /write lock did not become available/,
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
console.log("All chat-store concurrency checks passed.");
