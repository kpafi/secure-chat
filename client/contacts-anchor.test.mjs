// Pentest 2026-08-07 F-ATREST-003 / F-ATREST-004 — both CONFIRMED by an
// independent verifier, both device-local, both fail OPEN.
//
// The contact store holds the TOFU identity pins, so wiping or rewinding it
// turns off key-change detection. L-1 added a generation witness beside the
// store, and H-2 gave the store plaintext a domain tag, but the truth table
// still bottomed out in "neither store nor witness present -> genuine first
// run -> proceed" — and both are ordinary localStorage keys that delete with no
// passphrase. So:
//
//   F-ATREST-003: remove BOTH -> silent, empty, PIN-LESS store. `hasStore()` is
//   then false, so app.js's `pinsReadable()` returned TRUE while the store was
//   locked, the loud branch never ran, and every peer rendered as a benign
//   first contact. The alarm was inverted by the exact act it exists to catch.
//
//   F-ATREST-004: any gen-less plaintext was permanently exempt from the
//   rollback check, because the exemption was keyed on the SHAPE of the
//   decrypted record and so never burned out. One archived pre-L-1 blob plus
//   one removeItem resurrected pins the user had already replaced and
//   auto-unlocked messaging with no prompt — replayable indefinitely.
//
// The fix anchors "a store was established here" inside the identity's AEAD,
// where clearing it costs the attacker the user's identity (loud) rather than
// two silent removeItem calls.
//
// Run: node contacts-anchor.test.mjs   (server not required)
import assert from "node:assert";
import * as contacts from "./contacts.js";

const PASS = "correct horse battery staple";
const LS_CONTACTS = "sc.contacts.v1";
const LS_GEN = "sc.contacts.gen.v1";

function fakeLocalStorage() {
  const m = new Map();
  return {
    getItem: (k) => (m.has(k) ? m.get(k) : null),
    setItem: (k, v) => m.set(k, String(v)),
    removeItem: (k) => m.delete(k),
    key: (i) => [...m.keys()][i] ?? null,
    get length() { return m.size; },
    _dump: () => new Map(m),
    _restore: (snap) => { m.clear(); for (const [k, v] of snap) m.set(k, v); },
  };
}

// Stands in for identity.js's `deviceFlags`: the half of the anchor an attacker
// cannot clear without deleting the identity blob itself.
function anchorFor(flags) {
  return {
    get established() { return flags.contactsEstablished === true; },
    set established(v) { flags.contactsEstablished = v; },
    markEstablished: async () => { flags.contactsEstablished = true; },
  };
}

async function freshDevice() {
  globalThis.localStorage = fakeLocalStorage();
  const flags = {};
  contacts.setStoreAnchor(anchorFor(flags));
  contacts.lock();
  await contacts.unlock(PASS);
  return flags;
}

// --- F-ATREST-003 -----------------------------------------------------------
async function testDeleteBothFailsClosed() {
  const flags = await freshDevice();
  await contacts.savePin("user:alice", { ed: "QUxJQ0UtZWQ", mldsa: "QUxJQ0UtbWxkc2E" });
  assert.ok(contacts.getPin("user:alice"), "fixture: pin must be saved");
  assert.strictEqual(flags.contactsEstablished, true, "opening a store must record the anchor");

  // The attack: two removeItem calls, no passphrase.
  localStorage.removeItem(LS_CONTACTS);
  localStorage.removeItem(LS_GEN);
  contacts.lock();

  await assert.rejects(
    () => contacts.unlock(PASS),
    /BOTH have been deleted|BOTH been deleted/,
    "deleting store AND witness must fail closed, not mint an empty pin-less store",
  );
  assert.strictEqual(contacts.isUnlocked(), false, "must not be left unlocked after refusing");

  // The app-layer half: with the store locked and gone, pins must read as
  // UNREADABLE (loud), never as "no pins recorded" (benign).
  assert.strictEqual(contacts.hasStore(), false, "fixture: the store really is gone");
  assert.strictEqual(contacts.storeExpected(), true, "the anchor must still say a store is expected");
  console.log("OK  F-ATREST-003: deleting store + witness fails closed");
}

async function testGenuineFirstRunStillWorks() {
  // The control that matters: a device that never had a store must still open
  // one, or the fix is just a lockout.
  globalThis.localStorage = fakeLocalStorage();
  contacts.setStoreAnchor(anchorFor({}));
  contacts.lock();
  await contacts.unlock(PASS);
  assert.ok(contacts.isUnlocked(), "genuine first run must proceed");
  assert.deepStrictEqual(contacts.list(), []);
  console.log("OK  control: a genuine first run still creates a store");
}

async function testNoAnchorBehavesAsBefore() {
  // An identity-less flow installs no anchor; it must not start failing closed
  // on a path that has nothing to anchor to.
  globalThis.localStorage = fakeLocalStorage();
  contacts.setStoreAnchor(null);
  contacts.lock();
  await contacts.unlock(PASS);
  assert.ok(contacts.isUnlocked());
  assert.strictEqual(contacts.storeExpected(), false, "no anchor must read as 'cannot know'");
  console.log("OK  control: no anchor installed => pre-fix behaviour, no false alarm");
}

// --- F-ATREST-004 -----------------------------------------------------------
// Build the blob the pre-L-1 code wrote: {contacts, pins}, no `d`, no `gen`,
// under the same passphrase and wrapper.
async function legacyBlob(pinKey, pinBundle) {
  const enc = new TextEncoder();
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const base = await crypto.subtle.importKey("raw", enc.encode(PASS), "PBKDF2", false, ["deriveKey"]);
  const key = await crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: 600000, hash: "SHA-256" },
    base, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"],
  );
  const inner = { contacts: [{ username: "alice", ed: pinBundle.ed, mldsa: pinBundle.mldsa, verified: true }], pins: { [pinKey]: pinBundle } };
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, enc.encode(JSON.stringify(inner))));
  const b64 = (u8) => Buffer.from(u8).toString("base64");
  return JSON.stringify({ v: 3, iters: 600000, salt: b64(salt), iv: b64(iv), ct: b64(ct) });
}

async function testArchivedGenlessBlobRefused() {
  await freshDevice();
  const current = { ed: "UkVBTC1lZA", mldsa: "UkVBTC1tbGRzYQ" };
  await contacts.savePin("user:alice", current);
  await contacts.savePin("room:abc-def-ghi", current);

  const stale = { ed: "T0xELWVk", mldsa: "T0xELW1sZHNh" };
  localStorage.setItem(LS_CONTACTS, await legacyBlob("user:alice", stale));
  localStorage.removeItem(LS_GEN);
  contacts.lock();

  await assert.rejects(
    () => contacts.unlock(PASS),
    /older-format copy/,
    "an archived gen-less store must not be adopted once this device has a real one",
  );
  console.log("OK  F-ATREST-004: archived pre-L-1 blob + witness deletion refused");
}

async function testLegacyAdoptionStillWorksOnAVirginDevice() {
  // The exemption exists for a real migration, so it must still fire exactly
  // once — on a device that has never recorded a store.
  globalThis.localStorage = fakeLocalStorage();
  const flags = {};
  contacts.setStoreAnchor(anchorFor(flags));
  contacts.lock();
  const stale = { ed: "T0xELWVk", mldsa: "T0xELW1sZHNh" };
  const archived = await legacyBlob("user:alice", stale); // keep the ORIGINAL
  localStorage.setItem(LS_CONTACTS, archived);
  await contacts.unlock(PASS);
  assert.ok(contacts.isUnlocked(), "a genuine pre-L-1 store must still be adopted");
  assert.deepStrictEqual(contacts.getPin("user:alice"), stale);
  assert.strictEqual(flags.contactsEstablished, true, "adoption must record the anchor");

  // ...and having burned out, it must not fire a second time. This is the
  // property the finding turns on: the exemption was keyed on plaintext SHAPE,
  // so replaying the identical two operations worked indefinitely.
  localStorage.setItem(LS_CONTACTS, archived);
  localStorage.removeItem(LS_GEN);
  contacts.lock();
  await assert.rejects(() => contacts.unlock(PASS), /older-format copy/,
    "the legacy exemption must be one-shot, not shape-keyed and replayable");
  console.log("OK  F-ATREST-004: genuine legacy adoption still works, but only once");
}

async function testChatShapedBlobRefusedOnShapeAlone() {
  // F-ATREST-004(b): the chat store is keyed by contact LOCAL LABEL under the
  // same passphrase, so a chat named "pins" made the chat blob pass the old
  // `hasOwnProperty("pins")` test. Refused on shape now, independently of the
  // anchor — so drive it on a virgin device where the anchor cannot help.
  globalThis.localStorage = fakeLocalStorage();
  contacts.setStoreAnchor(anchorFor({}));
  contacts.lock();

  const enc = new TextEncoder();
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const base = await crypto.subtle.importKey("raw", enc.encode(PASS), "PBKDF2", false, ["deriveKey"]);
  const key = await crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: 600000, hash: "SHA-256" },
    base, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"],
  );
  // Exactly the chats.js plaintext shape, with the one chat named "pins".
  const chatLike = { pins: { username: "pins", mode: "SEALED", messages: [], seenIds: [], updatedAt: Date.now() } };
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, enc.encode(JSON.stringify(chatLike))));
  const b64 = (u8) => Buffer.from(u8).toString("base64");
  localStorage.setItem(LS_CONTACTS, JSON.stringify({ v: 3, iters: 600000, salt: b64(salt), iv: b64(iv), ct: b64(ct) }));

  await assert.rejects(() => contacts.unlock(PASS), /not a contact store/,
    "a chat-shaped plaintext must be refused on shape, not merely by the anchor");
  console.log("OK  F-ATREST-004(b): chat-shaped blob refused on shape alone");
}

await testDeleteBothFailsClosed();
await testGenuineFirstRunStillWorks();
await testNoAnchorBehavesAsBefore();
await testArchivedGenlessBlobRefused();
await testLegacyAdoptionStillWorksOnAVirginDevice();
await testChatShapedBlobRefusedOnShapeAlone();
console.log("\nAll contact-store anchor checks passed.");

// --- F-ATREST-007 -----------------------------------------------------------
// The pin is what makes the next session auto-unlock messaging with no prompt.
// It used to survive both "Unverify" and "Remove", so a contact the user had
// explicitly revoked still walked straight in.
async function testPinsDoNotOutliveRevocation() {
  await freshDevice();
  const bundle = { ed: "QUxJQ0UtZWQ", mldsa: "QUxJQ0UtbWxkc2E" };
  // savePin normalises to all four keys (H-01), so compare that shape.
  const pinned = { ed: bundle.ed, mldsa: bundle.mldsa, ecdh: null, mlkem: null };

  await contacts.upsert({ username: "alice", ed: bundle.ed, mldsa: bundle.mldsa });
  await contacts.savePin("user:alice", bundle);
  await contacts.setVerified("alice", true);
  assert.deepStrictEqual(contacts.getPin("user:alice"), pinned, "fixture: pin recorded");

  await contacts.setVerified("alice", false);
  assert.strictEqual(contacts.getPin("user:alice"), null,
    "Unverify must drop the pin, or the revoked key still auto-unlocks messaging");

  // ...and the same for Remove, the stronger control.
  await contacts.savePin("user:alice", bundle);
  await contacts.setVerified("alice", true);
  assert.deepStrictEqual(contacts.getPin("user:alice"), pinned, "fixture: pin re-recorded");
  await contacts.remove("alice");
  assert.strictEqual(contacts.getPin("user:alice"), null, "Remove must drop the pin too");

  // Fix review 2026-08-07 (F5). This block used to assert the OPPOSITE — that a
  // `room:` pin survives Remove — which would have frozen the residual in place.
  // app.js pins under `room:<id>` whenever no directory handle was typed, which
  // is the DEFAULT for Live-room use, so that pin is usually the ONLY one there
  // is, and it is the one that gates auto-unlock. Revocation is about the keys,
  // not the label they are filed under.
  await contacts.upsert({ username: "bob", ed: bundle.ed, mldsa: bundle.mldsa });
  await contacts.savePin("room:live-room-id", bundle);   // how a Live-room peer is really pinned
  await contacts.remove("bob");
  assert.strictEqual(contacts.getPin("room:live-room-id"), null,
    "a room-keyed pin for a REMOVED contact must go too, or the removed key still auto-unlocks");

  // Control: a pin for a DIFFERENT peer in the same room is untouched.
  const other = { ed: "T1RIRVItZWQ", mldsa: "T1RIRVItbWxkc2E" };
  const otherPinned = { ed: other.ed, mldsa: other.mldsa, ecdh: null, mlkem: null };
  await contacts.upsert({ username: "carol", ed: other.ed, mldsa: other.mldsa });
  await contacts.savePin("room:another-room", other);
  await contacts.upsert({ username: "dave", ed: bundle.ed, mldsa: bundle.mldsa });
  await contacts.remove("dave");
  assert.deepStrictEqual(contacts.getPin("room:another-room"), otherPinned,
    "another peer's pin must not be collateral damage");
  console.log("OK  F-ATREST-007: pins are dropped on Unverify and Remove");
}

await testPinsDoNotOutliveRevocation();
console.log("All F-ATREST-007 checks passed.");

// --- F-PROTO-005 ------------------------------------------------------------
// The 🟡 vouch mark is computed against a SNAPSHOT of the contact taken before
// an awaited /vouches fetch, then written back by username. A directory that
// merely stalls that fetch while the user re-adds the same handle lands the mark
// on a bundle the voucher never signed — rendered in the admission prompt with
// no key-changed warning.
async function testVouchWriteIsBoundToTheVerifiedBundle() {
  await freshDevice();
  const oldBundle = { ed: "T0xELWVk", mldsa: "T0xELW1sZHNh", ecdh: null, mlkem: null };
  await contacts.upsert({ username: "alice", ...oldBundle });

  // The snapshot the caller verified the signatures against.
  const snapshot = { ...oldBundle };

  // ...meanwhile the user re-adds the handle and the directory serves new keys.
  await contacts.upsert({ username: "alice", ed: "TkVXLWVk", mldsa: "TkVXLW1sZHNh" });

  const written = await contacts.setVouches("alice", ["trusted-friend"], snapshot);
  assert.strictEqual(written, false, "a mark verified against the OLD bundle must not be written");
  assert.ok(!(contacts.get("alice").vouchedBy || []).length,
    "the swapped bundle must carry no vouch mark");

  // Control: when the bundle is unchanged, the mark is written as normal.
  const live = contacts.get("alice");
  const ok = await contacts.setVouches("alice", ["trusted-friend"], {
    ed: live.ed, mldsa: live.mldsa, ecdh: live.ecdh ?? null, mlkem: live.mlkem ?? null,
  });
  assert.strictEqual(ok, true, "an unchanged bundle must still get its mark");
  assert.deepStrictEqual(contacts.get("alice").vouchedBy, ["trusted-friend"]);
  console.log("OK  F-PROTO-005: the vouch mark cannot land on a bundle it was not verified against");
}

await testVouchWriteIsBoundToTheVerifiedBundle();
console.log("All F-PROTO-005 checks passed.");
