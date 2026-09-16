// Phase-7 pentest 2026-09-16, F-P7-6 — the contact and chat stores' generation
// witnesses get the native floor the identity blob and every pad already have.
// Run: node store-floor.test.mjs   (server not required)
//
// The attack: with a healthy Android floor, an established anchor and a clean
// identity verdict, restoring `sc.contacts.v1` + `sc.contacts.gen.v1` (both
// plain localStorage keys) from before an in-person re-verification brought
// back the SUPERSEDED pin with no alarm, and app.js's `sameBundle(pin, bundle)
// -> unlockMessaging()` walked in. The property under test:
//
//   a store whose generation is BEHIND the device's durable record of it opens
//   with its TRUST reset — no pins, every contact "verify again", every chat
//   mode default — and heals; it is never refused (the crash window must not
//   be a lock-out), and a plain browser is unchanged.
//
// The floor is captured at load (store-floor.js -> otp.js), so the fake bridge
// is installed BEFORE the stores are imported; the plain-browser control runs
// in a fresh process.
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

// ---- the finding, end to end ----------------------------------------------
async function testRolledBackContactStoreOpensWithTrustReset() {
  const floor = device();
  await contacts.unlock(PASS);
  await contacts.upsert({ username: "bob", token: "t", ...BOB });
  await contacts.savePin("user:bob", BOB);
  await contacts.setVerified("bob", true);
  assert.ok(contacts.getPin("user:bob"), "fixture: bob is pinned");
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
  assert.strictEqual(contacts.getPin("user:bob"), null, "F-P7-6: the superseded pin is GONE — no auto-unlock on a replaced key");
  const bob = contacts.list().find((c) => c.username === "bob");
  assert.ok(bob, "the contact record itself survives (nothing to lose there)");
  assert.strictEqual(bob.verified, false);
  assert.strictEqual(bob.reverify, true, "...marked for an in-person check again");
  // The heal: the write re-armed the record, so the next unlock is clean.
  assert.ok(floor.slots.get(CSLOT) > gen2, "the heal wrote past the floor");
  contacts.lock();
  assert.strictEqual(await contacts.unlock(PASS), null, "clean after the heal");
  console.log("OK  F-P7-6: a rolled-back contact store opens with every pin dropped, not with a superseded pin");
}

async function testDeletedFloorSlotResetsTrust() {
  const floor = device();
  await contacts.unlock(PASS);
  await contacts.upsert({ username: "bob", token: "t", ...BOB });
  await contacts.savePin("user:bob", BOB);
  floor.slots.clear(); // root deletes the prefs entry
  contacts.lock();
  const warning = await contacts.unlock(PASS);
  assert.match(warning, /has been DELETED/);
  assert.strictEqual(contacts.getPin("user:bob"), null, "a deleted floor is evidence: pins dropped");
  console.log("OK  F-P7-6: a deleted floor slot resets trust (the store's own claim is the witness)");
}

async function testTamperedFloorResetsTrustAndStillWrites() {
  device(fakeFloor({ tampered: true }));
  await contacts.unlock(PASS); // fresh store on a tampered slot: written, claim unconfirmed
  await contacts.upsert({ username: "bob", token: "t", ...BOB });
  await contacts.savePin("user:bob", BOB);
  assert.match(contacts.lastFloorWarning(), /damaged or forged/);
  contacts.lock();
  const warning = await contacts.unlock(PASS);
  assert.match(warning, /damaged or forged/);
  assert.strictEqual(contacts.getPin("user:bob"), null);
  assert.ok(contacts.isUnlocked(), "never a brick");
  console.log("OK  F-P7-6: a tampered slot fails trust closed on every unlock and never refuses the write");
}

async function testFloorBehindTheStoreIsBenign() {
  const floor = device();
  await contacts.unlock(PASS);
  await contacts.upsert({ username: "bob", token: "t", ...BOB });
  await contacts.savePin("user:bob", BOB);
  floor.slots.set(CSLOT, 1); // the kill window: store written, bump never ran
  contacts.lock();
  assert.strictEqual(await contacts.unlock(PASS), null, "a floor BEHIND the store is never a finding");
  assert.ok(contacts.getPin("user:bob"), "...and the pins are intact");
  console.log("OK  F-P7-6: a lagging floor raises no alarm");
}

async function testFreshStoreAfterWipeCatchesUpWithTheSlot() {
  const floor = device();
  await contacts.unlock(PASS);
  for (let i = 0; i < 3; i++) await contacts.upsert({ username: "u" + i, token: "t", ...BOB });
  const high = floor.slots.get(CSLOT);
  assert.ok(high >= 3);
  contacts.wipe(); // the slot survives a wipe (monotone, no delete)
  await contacts.unlock(PASS, { startFresh: true });
  assert.ok(contacts.isUnlocked());
  contacts.lock();
  assert.strictEqual(await contacts.unlock(PASS), null,
    "a fresh store writes PAST the surviving slot, so it does not read as a rollback on every unlock until it catches up");
  console.log("OK  F-P7-6: a fresh store after a wipe starts past the surviving slot");
}

async function testExistingStoreArmsOnFirstUnlock() {
  const floor = device();
  // A pre-F-P7-6 store: written with no floor claim (simulate by clearing the
  // slot after the write — the store's AEAD then says nothing the slot must match).
  await contacts.unlock(PASS);
  await contacts.upsert({ username: "bob", token: "t", ...BOB });
  await contacts.savePin("user:bob", BOB);
  // Forge the pre-fix shape: rewrite the store with no `floor` field. We cannot
  // edit the AEAD from here, so model it with the slot absent and the claim
  // unconfirmed by starting from a plain-browser-written store in a child.
  const out = execFileSync(process.execPath, ["--input-type=module", "--eval", `
    import assert from "node:assert";
    import { PASS, fakeLocalStorage } from "./identity-store-helpers.test.mjs";
    globalThis.localStorage = fakeLocalStorage();
    const contacts = await import("./contacts.js");   // plain browser: no floor, no claim
    contacts.setStoreAnchor({ established: false, markEstablished: async () => {} });
    await contacts.unlock(PASS);
    await contacts.upsert({ username: "bob", token: "t", ed: "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE=", mldsa: "QkJC", ecdh: null, mlkem: null });
    process.stdout.write(JSON.stringify([...localStorage._dump()]));
  `], { cwd: HERE, encoding: "utf8" });
  const snap = new Map(JSON.parse(out));
  device(); // a fresh Android-shaped device receives that store (e.g. the app update)
  localStorage._restore(snap);
  assert.strictEqual(await contacts.unlock(PASS), null, "a store with no claim on a device with no record is a first run, not a finding");
  assert.ok(current.slots.has(CSLOT), "...and the device now has a record (armed on read)");
  assert.ok(contacts.list().some((c) => c.username === "bob"), "nothing was dropped");
  // From now on the pre-fix copy IS the archived artifact.
  contacts.lock();
  localStorage._restore(snap);
  const warning = await contacts.unlock(PASS);
  assert.match(warning, /OLDER/, "the archived pre-fix copy is caught once the device has a record");
  console.log("OK  F-P7-6: an existing store arms on its first unlock, and its old copy is caught thereafter");
}

// ---- chats -----------------------------------------------------------------
async function testRolledBackChatStoreResetsModes() {
  const floor = device();
  await chats.unlock(PASS);
  await chats.ensure("bob");
  await chats.setMode("bob", "AES256", { secret: "s", salt: "x" });
  const archived = localStorage._dump();
  await chats.append("bob", { dir: "out", text: "later" });
  assert.ok(floor.slots.get(HSLOT) >= 2);
  localStorage._restore(archived);
  chats.lock();
  const warning = await chats.unlock(PASS);
  assert.ok(chats.isUnlocked(), "F-P7-6: a rolled-back chat store OPENS");
  assert.match(warning, /OLDER than this device's protected record/);
  const bob = chats.get("bob");
  assert.strictEqual(bob.mode, "SEALED", "F-P7-6: a rolled-back negotiated mode goes back to the default");
  assert.strictEqual(bob.secret, undefined);
  chats.lock();
  assert.strictEqual(await chats.unlock(PASS), null, "clean after the heal");
  console.log("OK  F-P7-6: a rolled-back chat store opens with every negotiated mode reset");
}

// ---- plain browser: unchanged ------------------------------------------------
function testPlainBrowserIsUnchanged() {
  const out = execFileSync(process.execPath, ["--input-type=module", "--eval", `
    import assert from "node:assert";
    import { PASS, fakeLocalStorage } from "./identity-store-helpers.test.mjs";
    globalThis.localStorage = fakeLocalStorage();
    const contacts = await import("./contacts.js");
    contacts.setStoreAnchor({ established: false, markEstablished: async () => {} });
    assert.strictEqual(await contacts.unlock(PASS), null);
    await contacts.upsert({ username: "bob", token: "t", ed: "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE=", mldsa: "QkJC", ecdh: null, mlkem: null });
    const snap = localStorage._dump();
    await contacts.upsert({ username: "carol", token: "t", ed: "Q0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0M=", mldsa: "RERE", ecdh: null, mlkem: null });
    localStorage._restore(snap);
    contacts.lock();
    assert.strictEqual(await contacts.unlock(PASS), null, "no floor: the documented browser residual, no new alarm");
    assert.strictEqual(contacts.lastFloorWarning(), null);
    console.log("OK  plain browser: no floor, no verdict, no change (the documented residual)");
  `], { cwd: HERE, encoding: "utf8" });
  assert.match(out, /OK  plain browser/);
  process.stdout.write(out);
}

// ---- app.js surfaces the warnings ----------------------------------------------
function testAppJsSurfacesTheWarnings() {
  const src = stripComments(readFileSync(new URL("./app.js", import.meta.url), "utf8"));
  const fn = liftFunction(src, "unlockContacts", assert);
  assert.match(fn, /const warning = await contacts\.unlock\(pass, \{ startFresh: freshStoreConsent\.contacts \}\);/);
  assert.match(fn, /for \(const w of \[warning, contacts\.lastFloorWarning\(\)\]\) \{\s*if \(w\) \{ addLine\("sys", "", "\[contacts: " \+ w \+ "\]"\); hint\(w, true\); \}/,
    "F-P7-6: the contact store's verdict and floor warnings reach the transcript and the visible hint");
  assert.match(fn, /for \(const w of \[warning, chats\.lastFloorWarning\(\)\]\) \{\s*if \(w\) \{ addLine\("sys", "", "\[chats: " \+ w \+ "\]"\); hint\(w, true\); \}/);
  console.log("OK  F-P7-6: app.js shows both stores' at-rest warnings");
}

await testRolledBackContactStoreOpensWithTrustReset();
await testDeletedFloorSlotResetsTrust();
await testTamperedFloorResetsTrustAndStillWrites();
await testFloorBehindTheStoreIsBenign();
await testFreshStoreAfterWipeCatchesUpWithTheSlot();
await testExistingStoreArmsOnFirstUnlock();
await testRolledBackChatStoreResetsModes();
testPlainBrowserIsUnchanged();
testAppJsSurfacesTheWarnings();
console.log("All store-floor (F-P7-6) checks passed.");
