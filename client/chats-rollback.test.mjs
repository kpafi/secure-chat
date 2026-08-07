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
console.log("All chat-store concurrency checks passed.");
