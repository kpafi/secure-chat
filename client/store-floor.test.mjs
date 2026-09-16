// Phase-7 pentest 2026-09-16, F-P7-6 — the contact and chat stores' generation
// witnesses get the native floor the identity blob and every pad already have.
// Run: node store-floor.test.mjs   (server not required)
//
// The attack: with a healthy Android floor, an established anchor and a clean
// identity verdict, restoring `sc.contacts.v1` + `sc.contacts.gen.v1` (both
// plain localStorage keys) from before an in-person re-verification brought
// back the SUPERSEDED pin with no alarm, and app.js's `sameBundle(pin, bundle)
// -> unlockMessaging()` walked in. The property under test, as re-shaped by
// the review of the first cut (which dropped every pin and every secret):
//
//   a store whose generation is BEHIND the device's durable record of it opens
//   with every pin marked SUSPECT (kept, never auto-unlocking, loud in
//   renderVerify) and every contact "verify again", chats keep their modes and
//   secrets and are told what may have been rewound, and both heal; nothing is
//   refused, nothing is destroyed, and a plain browser is unchanged.
//
// The floor is captured at load (store-floor.js -> otp.js), so the fake bridge
// is installed BEFORE the stores are imported; the plain-browser control and
// the poisoned-primordial case run in fresh processes.
import assert from "node:assert";
import { readFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname } from "node:path";
import { stripComments, liftFunction } from "./test-source.mjs";
import { PASS, fakeLocalStorage, fakeFloor } from "./identity-store-helpers.test.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
let current = fakeFloor();
globalThis.localStorage = fakeLocalStorage();
globalThis.__SECURE_CHAT_PAD_FLOOR__ = { read: (id) => current.read(id), bump: (id, v) => current.bump(id, v) };
const contacts = await import("./contacts.js");
const chats = await import("./chats.js");
const CSLOT = "sc.contacts.v1#gen";
const HSLOT = "sc.chats.v1#gen";
const MAX = 0x7fffffff - 1;
const BOB = { ed: "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE=", mldsa: "QkJC", ecdh: null, mlkem: null };
const BOB2 = { ed: "Q0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0M=", mldsa: "RERE", ecdh: null, mlkem: null };

function device(floor = fakeFloor()) {
  globalThis.localStorage = fakeLocalStorage();
  current = floor;
  contacts.lock(); chats.lock();
  const flags = { c: false, h: false }; // a first run; the first unlock establishes both anchors
  contacts.setStoreAnchor({ get established() { return flags.c; }, set established(v) { flags.c = v; }, markEstablished: async () => { flags.c = true; } });
  chats.setStoreAnchor({ get established() { return flags.h; }, set established(v) { flags.h = v; }, markEstablished: async () => { flags.h = true; } });
  return floor;
}
function child(setup, body) {
  return execFileSync(process.execPath, ["--input-type=module", "--eval", `
    import assert from "node:assert";
    import { PASS, fakeLocalStorage, fakeFloor } from "./identity-store-helpers.test.mjs";
    globalThis.localStorage = fakeLocalStorage();
    ${setup}
    const contacts = await import("./contacts.js");
    const chats = await import("./chats.js");
    const anchor = () => { const f = { v: false }; return { get established() { return f.v; }, set established(v) { f.v = v; }, markEstablished: async () => { f.v = true; } }; };
    contacts.setStoreAnchor(anchor()); chats.setStoreAnchor(anchor());
    const BOB = { ed: "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE=", mldsa: "QkJC", ecdh: null, mlkem: null };
    const BOB2 = { ed: "Q0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0M=", mldsa: "RERE", ecdh: null, mlkem: null };
    ${body}
  `], { cwd: HERE, encoding: "utf8", stdio: ["ignore", "pipe", "inherit"] });
}
async function establishBob() {
  await contacts.unlock(PASS);
  await contacts.upsert({ username: "bob", token: "t", ...BOB });
  await contacts.savePin("user:bob", BOB);
  await contacts.setVerified("bob", true);
}

// ---- the finding, end to end --------------------------------------------------
async function testRolledBackContactStoreOpensWithSuspectPins() {
  const floor = device();
  await establishBob();
  await contacts.setVouches("bob", ["alice"]);
  assert.deepStrictEqual(contacts.list().find((c) => c.username === "bob").vouchedBy, ["alice"], "fixture: bob carries a vouch mark");
  const gen1 = floor.slots.get(CSLOT);
  assert.ok(gen1 >= 1, "the floor follows the store's generation");
  const archived = localStorage._dump(); // store + witness, both plain localStorage keys
  // Bob rotates; the user re-verifies him in person.
  await contacts.upsert({ username: "bob", token: "t", ...BOB2 });
  await contacts.savePin("user:bob", BOB2);
  await contacts.setVerified("bob", true);
  const gen2 = floor.slots.get(CSLOT);
  assert.ok(gen2 > gen1, "fixture: the floor moved on with the re-verification");
  // The attack: restore both keys. The witness agrees with the store, so the
  // pre-F-P7-6 check passed and the superseded pin came back verified.
  localStorage._restore(archived);
  contacts.lock();
  const warning = await contacts.unlock(PASS);
  assert.ok(contacts.isUnlocked(), "F-P7-6: a rolled-back store OPENS — this is not a lock-out");
  assert.match(warning, /OLDER than this device's protected record/, "...but says what happened");
  const pin = contacts.getPin("user:bob");
  assert.ok(pin && pin.ed === BOB.ed, "the (superseded) pin is KEPT — this is not a first contact...");
  assert.strictEqual(pin.suspect, true, "...but marked SUSPECT, so renderVerify must not auto-unlock on it");
  const bob = contacts.list().find((c) => c.username === "bob");
  assert.strictEqual(bob.verified, false);
  assert.strictEqual(bob.reverify, true, "...and the contact is marked for an in-person check again");
  assert.strictEqual(bob.vouchedBy, undefined, "...with its vouch mark cleared");
  // The in-person check writes a fresh pin and clears the mark.
  await contacts.savePin("user:bob", BOB2);
  assert.strictEqual(contacts.getPin("user:bob").suspect, undefined, "a fresh in-person pin is not suspect");
  // The heal: the write re-armed the record, so the next unlock is clean.
  assert.ok(floor.slots.get(CSLOT) > gen2, "the heal wrote past the floor");
  contacts.lock();
  assert.strictEqual(await contacts.unlock(PASS), null, "clean after the heal");
  assert.strictEqual(contacts.getPin("user:bob").suspect, undefined);
  console.log("OK  F-P7-6: a rolled-back contact store opens with every pin kept but SUSPECT, never auto-unlocking");
}

async function testDeletedFloorSlotMarksPinsSuspect() {
  const floor = device();
  await establishBob();
  floor.slots.clear(); // root deletes the prefs entry
  contacts.lock();
  const warning = await contacts.unlock(PASS);
  assert.match(warning, /has been DELETED/);
  assert.strictEqual(contacts.getPin("user:bob").suspect, true, "a deleted floor is evidence: pins suspect");
  console.log("OK  F-P7-6: a deleted floor slot marks every pin suspect (the store's own claim is the witness)");
}

async function testTamperedFloorFailsTrustClosedAndStillWrites() {
  device(fakeFloor({ tampered: true }));
  await establishBob(); // fresh store on a tampered slot: written, claim unconfirmed
  assert.match(contacts.lastFloorWarning(), /damaged or forged/);
  contacts.lock();
  const warning = await contacts.unlock(PASS);
  assert.match(warning, /damaged or forged/);
  assert.strictEqual(contacts.getPin("user:bob").suspect, true);
  assert.ok(contacts.isUnlocked(), "never a brick");
  console.log("OK  F-P7-6: a tampered slot fails trust closed on every unlock and never refuses the write");
}

async function testFloorBehindTheStoreIsBenign() {
  const floor = device();
  await establishBob();
  floor.slots.set(CSLOT, 1); // the kill window: store written, bump never ran
  contacts.lock();
  assert.strictEqual(await contacts.unlock(PASS), null, "a floor BEHIND the store is never a finding");
  assert.strictEqual(contacts.getPin("user:bob").suspect, undefined, "...and the pins are untouched");
  console.log("OK  F-P7-6: a lagging floor raises no alarm");
}

// The other crash window: store + witness written, floor bumped, the WebView's
// flush lost — the floor is ONE ahead. The first cut dropped every pin here;
// now nothing is destroyed: pins are kept (suspect), secrets are kept.
async function testCrashWindowIsNonDestructive() {
  const floor = device();
  await establishBob();
  await chats.unlock(PASS);
  await chats.ensure("bob");
  await chats.setMode("bob", "AES256", { secret: "shared-out-of-band", salt: "x" });
  floor.slots.set(CSLOT, floor.slots.get(CSLOT) + 1);
  floor.slots.set(HSLOT, floor.slots.get(HSLOT) + 1);
  contacts.lock(); chats.lock();
  const w1 = await contacts.unlock(PASS);
  const w2 = await chats.unlock(PASS);
  assert.match(w1, /OLDER/); assert.match(w2, /OLDER/);
  assert.ok(contacts.getPin("user:bob") && contacts.getPin("user:bob").suspect === true, "pins kept, suspect");
  assert.strictEqual(chats.get("bob").mode, "AES256", "the negotiated mode is KEPT (a stale one fails loudly on the wire)");
  assert.strictEqual(chats.get("bob").secret, "shared-out-of-band", "the out-of-band secret exists nowhere else and is KEPT");
  assert.match(w2, /arrive again as new/, "...and the user is told what a rollback can have undone");
  console.log("OK  F-P7-6: the flush-lost crash window costs one warning and re-verification, never pins or secrets");
}

async function testFreshStoreAfterWipeCatchesUpWithTheSlot() {
  const floor = device();
  await contacts.unlock(PASS);
  for (let i = 0; i < 3; i++) await contacts.upsert({ username: "u" + i, token: "t", ...BOB });
  assert.ok(floor.slots.get(CSLOT) >= 3);
  contacts.wipe(); // the slot survives a wipe (monotone, no delete)
  await contacts.unlock(PASS, { startFresh: true });
  assert.ok(contacts.isUnlocked());
  contacts.lock();
  assert.strictEqual(await contacts.unlock(PASS), null,
    "a fresh store writes PAST the surviving slot, so it does not read as a rollback on every unlock until it catches up");
  // Same for chats.
  await chats.unlock(PASS);
  for (let i = 0; i < 3; i++) await chats.ensure("u" + i);
  chats.wipe();
  await chats.unlock(PASS, { startFresh: true });
  chats.lock();
  assert.strictEqual(await chats.unlock(PASS), null, "the chat store catches up too");
  console.log("OK  F-P7-6: a fresh store after a wipe starts past the surviving slot (both stores)");
}

async function testExistingStoresArmOnFirstUnlock() {
  // Stores written by a plain browser (no floor, no claim) arrive on an
  // Android-shaped device (the app update): a first run, armed on read; the
  // archived pre-fix copies are caught thereafter. Both stores.
  const out = child("", `
    await contacts.unlock(PASS);
    await contacts.upsert({ username: "bob", token: "t", ...BOB });
    await chats.unlock(PASS);
    await chats.ensure("bob");
    process.stdout.write(JSON.stringify([...localStorage._dump()]));
  `);
  const snap = new Map(JSON.parse(out));
  device();
  localStorage._restore(snap);
  assert.strictEqual(await contacts.unlock(PASS), null, "contacts: no claim + no record = first run, not a finding");
  assert.ok(current.slots.has(CSLOT), "...and the device now has a record (armed on read)");
  assert.strictEqual(await chats.unlock(PASS), null, "chats: same");
  assert.ok(current.slots.has(HSLOT), "...armed on read too (the first cut's identity-store F-1, one store over)");
  contacts.lock(); chats.lock();
  localStorage._restore(snap);
  assert.match(await contacts.unlock(PASS), /OLDER/, "the archived pre-fix contact store is caught once the device has a record");
  assert.match(await chats.unlock(PASS), /OLDER/, "...and the chat store");
  console.log("OK  F-P7-6: existing stores arm on their first unlock, and their old copies are caught thereafter");
}

// ---- chats: the same four verdicts ---------------------------------------------
async function testChatStoreVerdicts() {
  let floor = device();
  await chats.unlock(PASS);
  await chats.ensure("bob");
  await chats.setMode("bob", "AES256", { secret: "s", salt: "x" });
  const archived = localStorage._dump();
  await chats.append("bob", { dir: "out", text: "later" });
  localStorage._restore(archived);
  chats.lock();
  assert.match(await chats.unlock(PASS), /OLDER than this device's protected record/, "rollback");
  assert.strictEqual(chats.get("bob").mode, "AES256", "modes are kept");
  chats.lock();
  assert.strictEqual(await chats.unlock(PASS), null, "clean after the heal");
  floor.slots.delete(HSLOT);
  chats.lock();
  assert.match(await chats.unlock(PASS), /has been DELETED/, "deleted slot");
  floor.slots.set(HSLOT, 1);
  chats.lock();
  assert.strictEqual(await chats.unlock(PASS), null, "lagging floor is benign");
  floor = device(fakeFloor({ tampered: true }));
  await chats.unlock(PASS);
  await chats.ensure("bob");
  chats.lock();
  assert.match(await chats.unlock(PASS), /damaged or forged/, "tampered");
  assert.ok(chats.isUnlocked());
  console.log("OK  F-P7-6: the chat store gets every verdict the contact store gets");
}

// ---- the review's two Highs -----------------------------------------------------
async function testParkedSlotIsLoudForever() {
  // One `bump` on the frozen bridge from the page realm parks the slot at the
  // ceiling. The first cut's catch-up then carried the generation PAST it and
  // armStoreFloor went silent forever — the whole control off. Now the parked
  // slot reads as a rollback on every open: loud, permanent, never silent.
  const floor = device();
  await establishBob();
  floor.slots.set(CSLOT, MAX);
  await contacts.upsert({ username: "carol", token: "t", ...BOB2 }); // an honest write after the park
  assert.match(contacts.lastFloorWarning(), /ceiling/, "the write warns");
  assert.strictEqual(floor.slots.get(CSLOT), MAX, "the store never advances the parked slot");
  const archived = localStorage._dump();
  await contacts.savePin("user:bob", BOB2); // the re-verification
  localStorage._restore(archived); // the rollback
  contacts.lock();
  const warning = await contacts.unlock(PASS);
  assert.match(warning, /OLDER/, "F-1: with the slot parked, every open is a (loud) rollback verdict");
  assert.strictEqual(contacts.getPin("user:bob").suspect, true, "...and the superseded pin cannot auto-unlock");
  assert.ok(contacts.isUnlocked(), "...and the store is still usable");
  console.log("OK  F-P7-6 review F-1: a parked floor slot is a permanent loud alarm, not a silent bypass");
}

function testPoisonedIsIntegerCannotBlindTheFloor() {
  // Review F-2: `Number.isInteger` is writable; routed through it, a lie scoped
  // to store-floor.js made the slot never leave 0 with every verdict clean.
  // The verdict now uses only typeof and the int32 truncation test.
  const out = child(`
    const real = Number.isInteger;
    Number.isInteger = function (v) {
      const st = (new Error().stack || "").split("\\n")[2] || "";
      return st.includes("store-floor.js") ? false : real(v);
    };
    const slots = new Map();
    globalThis.__SECURE_CHAT_PAD_FLOOR__ = {
      read: (id) => (slots.has(id) ? slots.get(id) : -1),
      bump: (id, v) => { const c = slots.has(id) ? slots.get(id) : -1; const n = c === -1 ? v : (v > c ? v : c); slots.set(id, n); return n; },
    };
    globalThis.__slots = slots;
  `, `
    await contacts.unlock(PASS);
    await contacts.upsert({ username: "bob", token: "t", ...BOB });
    await contacts.savePin("user:bob", BOB);
    assert.ok(globalThis.__slots.get("sc.contacts.v1#gen") >= 2, "F-2: the floor moves even with Number.isInteger lying to store-floor.js");
    const archived = localStorage._dump();
    await contacts.savePin("user:bob", BOB2);
    localStorage._restore(archived);
    contacts.lock();
    const w = await contacts.unlock(PASS);
    assert.match(w, /OLDER/, "F-2: ...and the rollback is still caught");
    assert.strictEqual(contacts.getPin("user:bob").suspect, true);
    console.log("OK  F-P7-6 review F-2: a poisoned Number.isInteger cannot blind the floor");
  `);
  assert.match(out, /OK  F-P7-6 review F-2/);
  process.stdout.write(out);
}

// ---- the claim is never lowered; the floor is raised only after the write ----------
async function testClaimNeverLoweredAndFloorRaisedAfterTheWrite() {
  const floor = device();
  await establishBob();
  // A probe that fails (commit failed on create of a NEW slot cannot happen for
  // an existing one; model a tampered read on an ARMED store): the claim must
  // stay ARMED, or the deletion alarm dies for good (identity-store's F-3).
  const armedBefore = contacts.getPin("user:bob"); // fixture only
  assert.ok(armedBefore);
  current = fakeFloor({ tampered: true });
  await contacts.upsert({ username: "dave", token: "t", ...BOB2 });
  current = floor; // the slot is fine again
  floor.slots.clear();
  contacts.lock();
  assert.match(await contacts.unlock(PASS), /has been DELETED/,
    "the claim survived a tampered probe as ARMED, so a later ABSENT slot is still evidence");
  // Ordering: the floor is bumped only AFTER the store and the witness are on
  // disk. Spy on setItem: at the moment the store is written, the slot must
  // still be at its previous value.
  const floor2 = device();
  await establishBob();
  const before = floor2.slots.get(CSLOT);
  let seenAtStoreWrite = null;
  const ls = globalThis.localStorage;
  const realSet = ls.setItem;
  ls.setItem = (k, v) => { if (k === "sc.contacts.v1") seenAtStoreWrite = floor2.slots.get(CSLOT); return realSet(k, v); };
  await contacts.upsert({ username: "erin", token: "t", ...BOB2 });
  ls.setItem = realSet;
  assert.strictEqual(seenAtStoreWrite, before, "the floor is not yet raised when the store is written (armFloors' ordering)");
  assert.ok(floor2.slots.get(CSLOT) > before, "...and is raised afterwards");
  console.log("OK  F-P7-6: a claim is never lowered, and the floor is raised only after both writes");
}

// ---- plain browser: unchanged ---------------------------------------------------
function testPlainBrowserIsUnchanged() {
  const out = child("", `
    assert.strictEqual(await contacts.unlock(PASS), null);
    await contacts.upsert({ username: "bob", token: "t", ...BOB });
    const snap = localStorage._dump();
    await contacts.upsert({ username: "carol", token: "t", ...BOB2 });
    localStorage._restore(snap);
    contacts.lock();
    assert.strictEqual(await contacts.unlock(PASS), null, "no floor: the documented browser residual, no new alarm");
    assert.strictEqual(contacts.lastFloorWarning(), null);
    console.log("OK  plain browser: no floor, no verdict, no change (the documented residual)");
  `);
  assert.match(out, /OK  plain browser/);
  process.stdout.write(out);
}

// ---- app.js: the suspect branch and the warnings ---------------------------------
function testAppJsHonoursSuspectPinsAndSurfacesWarnings() {
  const src = stripComments(readFileSync(new URL("./app.js", import.meta.url), "utf8"));
  const fn = liftFunction(src, "unlockContacts", assert);
  assert.match(fn, /const warning = await contacts\.unlock\(pass, \{ startFresh: freshStoreConsent\.contacts \}\);/);
  assert.match(fn, /for \(const w of \[warning, contacts\.lastFloorWarning\(\)\]\) \{\s*if \(w\) \{ addLine\("sys", "", "\[contacts: " \+ w \+ "\]"\); hint\(w, true\); \}/,
    "F-P7-6: the contact store's verdict and floor warnings reach the transcript and the visible hint");
  assert.match(fn, /for \(const w of \[warning, chats\.lastFloorWarning\(\)\]\) \{\s*if \(w\) \{ addLine\("sys", "", "\[chats: " \+ w \+ "\]"\); hint\(w, true\); \}/);
  // renderVerify: a suspect pin is refused BEFORE the auto-unlock comparison,
  // with the loud "changed" prompt, and nothing else may read `suspect`.
  const rv = liftFunction(src, "enterVerification", assert);
  const suspectAt = rv.indexOf("if (pin && pin.suspect === true) {");
  const sameAt = rv.indexOf("if (sameBundle(pin, bundle)) {");
  assert.ok(suspectAt !== -1 && sameAt !== -1 && suspectAt < sameAt,
    "F-P7-6: enterVerification checks `pin.suspect` BEFORE `sameBundle(pin, bundle) -> unlockMessaging()`");
  const branch = rv.slice(suspectAt, sameAt);
  assert.match(branch, /els\.verify\.classList\.add\("changed"\);/, "...and shows the loud prompt");
  assert.match(branch, /rolled back/, "...naming the rollback");
  assert.match(branch, /return;\s*\}\s*$/, "...and returns without unlocking");
  assert.doesNotMatch(branch, /unlockMessaging\(\)/);
  assert.strictEqual((src.match(/\.suspect\b/g) || []).length, 1, "`suspect` is read in exactly one place in app.js");
  console.log("OK  F-P7-6: app.js refuses to auto-unlock on a suspect pin and shows both stores' warnings");
}

await testRolledBackContactStoreOpensWithSuspectPins();
await testDeletedFloorSlotMarksPinsSuspect();
await testTamperedFloorFailsTrustClosedAndStillWrites();
await testFloorBehindTheStoreIsBenign();
await testCrashWindowIsNonDestructive();
await testFreshStoreAfterWipeCatchesUpWithTheSlot();
await testExistingStoresArmOnFirstUnlock();
await testChatStoreVerdicts();
await testParkedSlotIsLoudForever();
testPoisonedIsIntegerCannotBlindTheFloor();
await testClaimNeverLoweredAndFloorRaisedAfterTheWrite();
testPlainBrowserIsUnchanged();
testAppJsHonoursSuspectPinsAndSurfacesWarnings();
console.log("All store-floor (F-P7-6) checks passed.");
