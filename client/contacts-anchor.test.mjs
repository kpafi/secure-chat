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
import { stripComments, codeLines } from "./test-source.mjs";

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

// --- pentest 2026-08-08, item 17 --------------------------------------------
// The sweep above matches on the contact's CURRENT keys. `upsert()` overwrites
// them on a key change without touching `pins`, so after a rotation the record
// names K2 while the pin still names K1 and the sweep matches nothing. The pin
// left behind names the SUPERSEDED key — precisely the key a user revoking after
// a suspected compromise wants dead.
async function testPinSweepSurvivesKeyChange() {
  await freshDevice();
  // Per-contact key material. An earlier version shared K1/K2 across every
  // contact here, which quietly made them the SAME IDENTITY under different
  // labels — so the test was also asserting that removing one label strips a
  // different, still-trusted contact's pin. That is the M-2 collateral the
  // 2026-08-10 pentest found, and it is not what this test is about.
  const K1 = { ed: "ZXJpbjE", mldsa: "ZXJpbjFN" };
  const K2 = { ed: "ZXJpbjI", mldsa: "ZXJpbjJN" };
  const F1 = { ed: "ZnJhbmsx", mldsa: "ZnJhbmsxTQ" };
  const F2 = { ed: "ZnJhbmsy", mldsa: "ZnJhbmsyTQ" };
  const G1 = { ed: "Z2luYTE", mldsa: "Z2luYTFN" };
  const G2 = { ed: "Z2luYTI", mldsa: "Z2luYTJN" };
  const I1 = { ed: "aXZhbjE", mldsa: "aXZhbjFN" };
  const I2 = { ed: "aXZhbjI", mldsa: "aXZhbjJN" };

  // Live-room shape: pinned under `room:<id>` while the contact was still K1.
  await contacts.upsert({ username: "erin", ed: K1.ed, mldsa: K1.mldsa });
  await contacts.savePin("room:rotating-room", K1);
  await contacts.setVerified("erin", true);
  assert.ok(contacts.getPin("room:rotating-room"), "fixture: the K1 pin exists");

  // The rotation. `verified` resets (H-01), but the pin is untouched by upsert.
  await contacts.upsert({ username: "erin", ed: K2.ed, mldsa: K2.mldsa });
  assert.strictEqual(contacts.get("erin").verified, false, "a key change resets 🟢");
  assert.ok(contacts.getPin("room:rotating-room"), "precondition: the K1 pin still exists");

  await contacts.remove("erin");
  assert.strictEqual(contacts.getPin("room:rotating-room"), null,
    "item 17: Remove must sweep the pin naming the SUPERSEDED key, not just the current one");
  console.log("OK  item 17: a pin written before a key change is swept by Remove");

  // The same through Unverify, the other caller of dropPinsFor.
  await contacts.upsert({ username: "frank", ed: F1.ed, mldsa: F1.mldsa });
  await contacts.savePin("room:frank-room", F1);
  await contacts.setVerified("frank", true);
  await contacts.upsert({ username: "frank", ed: F2.ed, mldsa: F2.mldsa });
  await contacts.setVerified("frank", true);   // re-verified at the new key
  assert.ok(contacts.getPin("room:frank-room"), "precondition: the K1 pin survived the rotation");
  await contacts.setVerified("frank", false);
  assert.strictEqual(contacts.getPin("room:frank-room"), null,
    "item 17: Unverify must sweep the superseded key's pin too");
  console.log("OK  item 17: ...and by Unverify");

  // Two rotations: K1 -> K2 -> K3. Both older pins must go.
  const G3 = { ed: "Z2luYTM", mldsa: "Z2luYTNN" };
  await contacts.upsert({ username: "gina", ed: G1.ed, mldsa: G1.mldsa });
  await contacts.savePin("room:gina-1", G1);
  await contacts.upsert({ username: "gina", ed: G2.ed, mldsa: G2.mldsa });
  await contacts.savePin("room:gina-2", G2);
  await contacts.upsert({ username: "gina", ed: G3.ed, mldsa: G3.mldsa });
  await contacts.remove("gina");
  assert.strictEqual(contacts.getPin("room:gina-1"), null, "the oldest key's pin must go");
  assert.strictEqual(contacts.getPin("room:gina-2"), null, "the intermediate key's pin must go");
  console.log("OK  item 17: every superseded key in the chain is swept");

  // Control, in the direction that matters: history must not become a licence to
  // delete OTHER peers' pins. Only an exact ed+mldsa match may be swept.
  const OTHER = { ed: "T1RIRVItZWQy", mldsa: "T1RIRVItbWxkc2Ey" };
  await contacts.upsert({ username: "heidi", ed: OTHER.ed, mldsa: OTHER.mldsa });
  await contacts.savePin("room:heidi-room", OTHER);
  await contacts.upsert({ username: "ivan", ed: I1.ed, mldsa: I1.mldsa });
  await contacts.upsert({ username: "ivan", ed: I2.ed, mldsa: I2.mldsa });
  await contacts.remove("ivan");
  assert.ok(contacts.getPin("room:heidi-room"),
    "another peer's pin must not be collateral damage of the history sweep");
  console.log("OK  item 17: control — the history sweep does not over-reach");

  // The history is bounded, so a peer that can drive upsert cannot grow the
  // record without limit.
  await contacts.upsert({ username: "judy", ed: K1.ed, mldsa: K1.mldsa });
  for (let i = 0; i < 30; i++) {
    await contacts.upsert({ username: "judy", ed: `Uk9UQVRF${i}`, mldsa: `Uk9UQVRFTUw${i}` });
  }
  const hist = contacts.get("judy").pinKeys || [];
  assert.ok(hist.length <= 8, `the superseded-key history must stay bounded, got ${hist.length}`);
  console.log("OK  item 17: the superseded-key history is bounded");
}

await testPinSweepSurvivesKeyChange();

// --- pentest 2026-08-10, findings against the item 17 fix -------------------
async function testPinHistoryFindings() {
  // M-1: the cap used to evict the OLDEST superseded key — precisely the one
  // whose pin has had longest to be written and forgotten — restoring the exact
  // residual item 17 closes. The bound must never drop a key a pin still names.
  await freshDevice();
  const K = (n) => ({ ed: `SzEt${n}`, mldsa: `SzJt${n}` });
  await contacts.upsert({ username: "bob", ...K(1) });
  await contacts.savePin("room:bobs-room", K(1));
  for (let i = 2; i <= 12; i++) await contacts.upsert({ username: "bob", ...K(i) });
  await contacts.remove("bob");
  assert.strictEqual(contacts.getPin("room:bobs-room"), null,
    "M-1: a pin naming a key evicted by the history cap must STILL be swept");
  console.log("OK  item 17 / M-1: the history bound never evicts a key that still has a pin");

  // ...and the bound still does its job on history that has gone inert.
  await freshDevice();
  await contacts.upsert({ username: "carol", ...K(1) });
  for (let i = 2; i <= 30; i++) await contacts.upsert({ username: "carol", ...K(i) });
  const hist = contacts.get("carol").pinKeys || [];
  assert.ok(hist.length <= 8, `unpinned history must stay bounded, got ${hist.length}`);
  console.log("OK  item 17 / M-1: history with no pins behind it is still bounded");

  // M-2: `pinKeys` is fed from unsigned directory answers, so a hostile relay can
  // plant a THIRD PARTY's key in someone's history; removing that someone then
  // deleted the third party's pin, inverting the key-change alarm.
  //
  // The first repair — skip a historical key that some other contact currently
  // holds — is GONE, because the attacker chooses whether that other record
  // exists (2026-08-10-night F-A2). The pin is deleted either way now; what M-2
  // is owed is that the bystander's next session is not rendered as a benign
  // first contact, and that is the `reverify` marker below.
  await freshDevice();
  const ALICE = { ed: "QUxJQ0U", mldsa: "QUxJQ0VN" };
  await contacts.upsert({ username: "alice", ...ALICE });
  await contacts.savePin("user:alice", ALICE);
  await contacts.upsert({ username: "mallory", ...ALICE });   // the poisoned answer
  await contacts.upsert({ username: "mallory", ed: "TUFM", mldsa: "TUFMTQ" }); // corrects
  await contacts.remove("mallory");
  assert.strictEqual(contacts.getPin("user:alice"), null,
    "F-A2: revocation is absolute — a pin naming a revoked key must not survive " +
    "because some other record also names it");
  assert.ok(contacts.get("alice").reverify,
    "M-2: ...but the bystander whose pin went with it must be flagged, so their next " +
    "session cannot render as a benign FIRST CONTACT (the inverted alarm)");
  console.log("OK  item 17 / M-2+F-A2: collateral is swept AND flagged for re-verification");

  // ...and re-verifying in person clears the flag, so it does not become permanent
  // noise that teaches the user to click past it.
  await contacts.savePin("user:alice", ALICE);
  assert.ok(!contacts.get("alice").reverify,
    "an in-person re-verification (savePin) clears the marker");
  console.log("OK  item 17 / M-2: the re-verification marker is cleared by re-verifying");

  // Control: the sweep must not depend on the OTHER record being trustworthy —
  // that dependency IS F-A2. An `auto` contact, which one sealed envelope creates
  // with no user action at all, must not be able to preserve a revoked pin.
  await freshDevice();
  const BOB = { ed: "Qk9C", mldsa: "Qk9CTQ" };
  await contacts.upsert({ username: "bob", ...BOB });
  await contacts.savePin("room:bob-room", BOB);
  await contacts.setVerified("bob", true);
  await contacts.upsert({ username: "bob", ed: "Qk9CMg", mldsa: "Qk9CMk0" });  // rotates
  await contacts.savePin("room:bob-room", BOB);            // the stale K1 pin lives on
  // The attacker's one move: an auto-created record naming the superseded key.
  await contacts.upsert({ username: "sc-abc123", ...BOB, auto: true });
  await contacts.remove("bob");
  assert.strictEqual(contacts.getPin("room:bob-room"), null,
    "F-A2: an unverified auto-created contact must not be able to retain a pin that " +
    "revocation is meant to kill — the attacker chooses whether that record exists");
  console.log("OK  F-A2: an auto-created record cannot preserve a revoked pin");

  // Control: a superseded key that no other contact claims is still swept.
  await freshDevice();
  await contacts.upsert({ username: "dave", ...K(1) });
  await contacts.savePin("room:dave-room", K(1));
  await contacts.upsert({ username: "dave", ...K(2) });
  await contacts.remove("dave");
  assert.strictEqual(contacts.getPin("room:dave-room"), null,
    "control: an unclaimed superseded key must still be swept");
  console.log("OK  item 17: control — ordinary superseded pins are still swept");
}

await testPinHistoryFindings();

// F-A2's other half lives in app.js, which has no export surface (it touches
// `document` at module scope), so it is pinned at source level — anchored on
// EXECUTABLE statements, never on a comment. That distinction is not pedantry:
// the 2026-08-10-night pentest found the item-14 call-site guard was slicing
// between two comments and therefore asserting nothing at all (H-1).
//
// What must hold: revocation now deletes a bystander's pin unconditionally, so
// `renderVerify` has to recognise the marker that sweep leaves behind BEFORE it
// reaches the benign "Verify your contact — in person" first-contact branch.
// Reversing those two renders M-2's inverted alarm again.
{
  const { readFile } = await import("node:fs/promises");
  const app = await readFile(new URL("./app.js", import.meta.url), "utf8");
  // COMMENTS STRIPPED FIRST, with the shared scanner (test-source.mjs). Running
  // `indexOf` over raw source let a mutant DELETE the whole branch and satisfy
  // this check with a comment containing the string `c.reverify` — the pentest of
  // this fix demonstrated it passing 193/0 with F-A2's user-facing half gone. Same
  // defect as H-1, third file. The earlier prefix-filter was itself bypassable
  // (round 2), so this now uses the real scanner shared with the other anchors.
  const stripped = stripComments(app);
  const code = codeLines(stripped);
  const joined = code.join("\n");
  const pinRead = joined.indexOf("const pin = await getPin(currentPinKey);");
  assert.notStrictEqual(pinRead, -1, "renderVerify must still read the pin for this room/user");
  const tail = joined.slice(pinRead);
  const firstContact = tail.indexOf('els.verifyTitle.textContent = "Verify your contact — in person"');
  assert.notStrictEqual(firstContact, -1, "the first-contact branch must still exist");
  // ROUND-2 F-4 (2026-08-15): confine EVERYTHING to the renderVerify no-pin ladder
  // — `tail` from the pin read up to the first-contact branch. The previous check
  // did `code.find((l) => l.includes("c.reverify"))` over the WHOLE file, which
  // returns app.js's FIRST `c.reverify` — the Users-list renderer
  // (`} else if (c.reverify && !c.verified) {`), an unrelated site — so the shape
  // assertions validated a bystander line and never looked at renderVerify. A
  // mutant adding `&& !pinsReadable()` here (always false: renderVerify returns
  // early when pins are unreadable) made THIS branch dead code while every shape
  // check passed against the other file location. So: region-confined, and the
  // branch condition pinned EXACTLY rather than matched by "contains c.reverify".
  const region = tail.slice(0, firstContact);
  const marker = region.indexOf("c.reverify");
  assert.notStrictEqual(marker, -1,
    "F-A2: renderVerify must consult the `reverify` marker that dropPinsFor leaves on a " +
    "contact whose pin was swept as collateral — without it that contact renders as a " +
    "benign FIRST CONTACT, which is exactly M-2's inverted alarm");

  // The exact branch condition, pinned. It spans two stripped lines today; both
  // are required, consecutively, so a mutant cannot bolt an always-false term
  // (`&& !pinsReadable()`, the F-4 dead-code shape) onto the condition without
  // failing here. If this branch is legitimately reshaped, update BOTH lines and
  // say why — that is the review this pin exists to force.
  const EXPECTED_BRANCH = [
    "} else if (contacts.isUnlocked() &&",
    "contacts.list().some((c) => sameSigning(c, bundle) && c.reverify)) {",
  ];
  const regionLines = region.split("\n");
  const bi = regionLines.findIndex((l) => l === EXPECTED_BRANCH[0]);
  assert.notStrictEqual(bi, -1,
    "F-A2: renderVerify's reverify branch must open exactly `} else if (contacts.isUnlocked() &&` " +
    "on the no-pin path — the unlock short-circuit is required (`list()` throws on a locked store, " +
    "and `pinsReadable()` is also true on a device with no store at all)");
  assert.strictEqual(regionLines[bi + 1], EXPECTED_BRANCH[1],
    "F-A2: the reverify branch condition is pinned exactly; nothing may be added to it. Found:\n" +
    `      ${regionLines[bi]}\n      ${regionLines[bi + 1] ?? "<eof>"}`);

  const after = region.slice(marker, marker + 600);
  assert.ok(/els\.verify\.classList\.add\("changed"\)/.test(after),
    "F-A2: the re-verify branch must render as a WARNING (the `changed` styling), not as the " +
    "neutral first-contact panel — the whole point is that this is not a first contact");
  console.log("OK  F-A2: app.js warns on a pin cleared by revocation instead of rendering first contact");
}

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
