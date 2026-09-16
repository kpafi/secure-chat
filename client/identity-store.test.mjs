// Pentest 2026-08-07 F-ATREST-008 — the identity blob has no anti-rollback
// control — fixed 2026-09-16.
//
// The F-ATREST-003/004 fix put the contact store's "a store was established
// here" bit inside the identity's AEAD, and its fix review (F4) immediately
// withdrew the claim that this made the bit undeletable: an attacker restores an
// OLDER copy of `sc.identity.v1`, which opens on the same passphrase, carries
// the same keys and no `flags`, and every anchor reads false — the contact
// store's deletion check then hands out an empty, pin-less store, key-change
// detection silently off. Every pre-fix blob is such a copy.
//
// identity-store.js closes it the way the OTP watermark and the contact-store
// witness are closed: a monotone generation inside the AEAD, mirrored into the
// Keystore-MACed native floor on Android. The property under test:
//
//   a blob whose generation is BEHIND the device's durable record of it makes
//   every anchor read ESTABLISHED, and the healed blob keeps that answer.
//
// HOW THE FLOOR IS FAKED. identity-store.js captures the floor at module load
// from otp.js, which captures the bridge at ITS load from a global — there is
// no setter on either (pentest of the change, F-9), so the fake must be in
// place before the first import. This process installs ONE delegating bridge
// whose behaviour is switched per case with device(); the two states that
// can only be decided at load (no bridge at all = plain browser; marker but no
// bridge = broken) run in fresh child processes.
//
// Run: node identity-store.test.mjs   (server not required)
import assert from "node:assert";
import { readFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname } from "node:path";
import { Identity } from "./identity.js";
import { stripComments, liftFunction, referencesOf } from "./test-source.mjs";
import { PASS, fakeLocalStorage, fakeFloor, fakeIdentity, fakeImport, preFixBlob } from "./identity-store-helpers.test.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));

// The one bridge otp.js will capture. `current` is what it delegates to.
let current = fakeFloor();
globalThis.localStorage = fakeLocalStorage();
globalThis.__SECURE_CHAT_PAD_FLOOR__ = {
  read: (id) => current.read(id),
  bump: (id, v) => current.bump(id, v),
};
const idstore = await import("./identity-store.js");
const otp = await import("./otp.js");
// F-P7-6: contacts.js and chats.js now import otp.js too (via store-floor.js),
// so they must load AFTER the bridge above is installed, like identity-store.
const contacts = await import("./contacts.js");
const chats = await import("./chats.js");
const { LS_IDENTITY, FLOOR_SLOT } = idstore;

function device(floor = fakeFloor()) {
  globalThis.localStorage = fakeLocalStorage();
  current = floor;
  return floor;
}

// Run `body` (module source) in a fresh node process with `setup` evaluated
// first, before identity-store.js is imported. Returns stdout.
function inFreshProcess(setup, body) {
  const code = `
    import assert from "node:assert";
    import { PASS, fakeLocalStorage, fakeFloor, fakeIdentity, fakeImport, preFixBlob } from "./identity-store-helpers.test.mjs";
    globalThis.localStorage = fakeLocalStorage();
    ${setup}
    const idstore = await import("./identity-store.js");
    const { LS_IDENTITY, FLOOR_SLOT } = idstore;
    ${body}
  `;
  return execFileSync(process.execPath, ["--input-type=module", "--eval", code], {
    cwd: HERE, encoding: "utf8", stdio: ["ignore", "pipe", "inherit"],
  });
}

// ---- the finding --------------------------------------------------------------

async function testRollbackFailsClosedAndTheHealKeepsIt() {
  const floor = device();
  // Day 1: the identity is written, the contact store is established (flag set).
  const id = fakeIdentity();
  const first = await idstore.persistIdentity(id, PASS);
  assert.strictEqual(first.generation, 1);
  assert.strictEqual(first.armed, true, "the floor recorded generation 1");
  assert.strictEqual(floor.slots.get(FLOOR_SLOT), 1);
  const archived = localStorage._dump(); // the attacker's saved copy: no flags
  id.deviceFlags.contactsEstablished = true;
  id.deviceFlags.chatsEstablished = true;
  const second = await idstore.persistIdentity(id, PASS);
  assert.strictEqual(second.generation, 2);
  assert.strictEqual(floor.slots.get(FLOOR_SLOT), 2, "the floor follows the newest write");

  // The attack: one setItem (restore the old blob) — plus, in the real thing,
  // the two removeItem calls on the contact store and its witness.
  localStorage._restore(archived);
  const { identity: rolled, verdict } = await idstore.openIdentity(PASS, fakeImport);
  assert.deepStrictEqual(rolled.deviceFlags, {},
    "fixture: the restored blob genuinely carries no flags — this is what the attacker is after");
  assert.strictEqual(verdict.ok, false);
  assert.strictEqual(verdict.reason, "rollback", "generation 1 on disk, 2 recorded: a rollback");
  assert.match(verdict.message, /OLDER/);
  assert.strictEqual(idstore.anchorEstablished(rolled, "contactsEstablished"), true,
    "F-ATREST-008: under a rollback verdict the anchor reads ESTABLISHED (fail closed)");
  assert.strictEqual(idstore.anchorEstablished(rolled, "chatsEstablished"), true, "...for every anchor");
  assert.strictEqual(rolled.deviceFlags.contactsEstablished, true,
    "...and the conservative answer is committed into the in-memory flags");

  // The heal, as app.js performs it right after installing the anchors: the
  // re-write must carry the fail-closed flags, or an attacker needs two unlocks
  // instead of one (the second opens a 'current' blob with no flags).
  const healed = await idstore.persistIdentity(rolled, PASS);
  assert.strictEqual(healed.generation, 3, "past the floor's 2, not the blob's 1");
  const again = await idstore.openIdentity(PASS, fakeImport);
  assert.strictEqual(again.verdict.ok, true, "the healed blob is the newest: clean verdict");
  assert.strictEqual(again.verdict.arm, false, "...and already armed");
  assert.strictEqual(again.identity.deviceFlags.contactsEstablished, true,
    "the healed blob carries the flag — the rollback bought the attacker nothing on the second unlock either");
  assert.strictEqual(idstore.anchorEstablished(again.identity, "contactsEstablished"), true);
  console.log("OK  F-ATREST-008: a rolled-back identity blob fails closed, and stays closed after the heal");
}

// Pentest of the change, F-1 (High): the first cut only wrote on a bad verdict
// or a pre-v3 upgrade, so an EXISTING install (v3 blob, both flags set) never
// created its slot and the guard never armed — the finding reopened unchanged
// on exactly the deployed population. `arm` is the write that was missing.
async function testExistingInstallArmsOnFirstUnlock() {
  const floor = device();
  localStorage.setItem(LS_IDENTITY, preFixBlob({ contactsEstablished: true, chatsEstablished: true }));
  const archivedPreFix = preFixBlob(); // the flagless copy in the attacker's hand since before the update
  const first = await idstore.openIdentity(PASS, fakeImport);
  assert.strictEqual(first.verdict.ok, true, "nothing recorded yet: not a finding");
  assert.strictEqual(first.verdict.arm, true, "...but the device must record this identity NOW");
  assert.strictEqual(first.identity.upgraded, false, "fixture: this is a v3 blob, no upgrade write would happen");
  assert.strictEqual(idstore.anchorEstablished(first.identity, "contactsEstablished"), true, "fixture: flags already set");
  // What app.js does on `arm`.
  await idstore.persistIdentity(first.identity, PASS);
  assert.strictEqual(floor.slots.get(FLOOR_SLOT), 1, "the slot exists after the first unlock post-update");
  const second = await idstore.openIdentity(PASS, fakeImport);
  assert.strictEqual(second.verdict.ok, true);
  assert.strictEqual(second.verdict.arm, false, "armed: no further write on ordinary unlocks");
  // The original attack, against the armed install.
  localStorage.setItem(LS_IDENTITY, archivedPreFix);
  const { identity: rolled, verdict } = await idstore.openIdentity(PASS, fakeImport);
  assert.strictEqual(verdict.reason, "rollback", "F-1: the pre-fix flagless copy is caught on an existing install");
  assert.strictEqual(idstore.anchorEstablished(rolled, "contactsEstablished"), true);
  console.log("OK  F-1: an existing install arms on its first unlock, so the original attack is caught there too");
}

async function testPreFixBlobIsTheArchivedArtifact() {
  const floor = device();
  localStorage.setItem(LS_IDENTITY, preFixBlob());
  // First unlock after the update: adopted quietly (no floor yet, nothing claimed).
  const adopted = await idstore.openIdentity(PASS, fakeImport);
  assert.strictEqual(adopted.verdict.ok, true, "a pre-fix blob on a device with no record is a first run");
  assert.strictEqual(adopted.verdict.arm, true);
  assert.strictEqual(adopted.identity.generation, 0, "absent counter reads as 0 — the oldest value");
  assert.strictEqual(adopted.identity.floorClaim, "unconfirmed", "absent claim claims nothing");
  const saved = await idstore.persistIdentity(adopted.identity, PASS);
  assert.strictEqual(saved.generation, 1);
  assert.strictEqual(floor.slots.get(FLOOR_SLOT), 1, "the device now has a record");
  // The archived artifact, restored.
  localStorage.setItem(LS_IDENTITY, preFixBlob());
  const { verdict } = await idstore.openIdentity(PASS, fakeImport);
  assert.strictEqual(verdict.ok, false);
  assert.strictEqual(verdict.reason, "rollback",
    "once the device has recorded ANY generation, the pre-fix blob (gen 0) is a rollback");
  console.log("OK  F-ATREST-008: the pre-fix blob is caught the moment the device has recorded a newer one");
}

async function testFloorDeletionIsEvidence() {
  const floor = device();
  await idstore.persistIdentity(fakeIdentity(), PASS);
  floor.slots.clear(); // root deletes the prefs entry
  const { identity, verdict } = await idstore.openIdentity(PASS, fakeImport);
  assert.strictEqual(identity.floorClaim, true, "fixture: the blob claims a floor was in force");
  assert.strictEqual(verdict.reason, "deleted", "claimed floor + ABSENT = deletion, not a first run");
  assert.strictEqual(idstore.anchorEstablished(identity, "contactsEstablished"), true, "fails closed");
  assert.strictEqual(identity.deviceFlags.contactsEstablished, true,
    "pentest mutant A: the flag is COMMITTED under 'deleted' too, not only under 'rollback'");
  console.log("OK  a deleted floor slot fails closed (the blob's own claim is the witness)");
}

async function testTamperedFloorFailsClosedButStillWrites() {
  device(fakeFloor({ tampered: true }));
  localStorage.setItem(LS_IDENTITY, await fakeIdentity().export(PASS));
  const { identity, verdict } = await idstore.openIdentity(PASS, fakeImport);
  assert.strictEqual(verdict.reason, "tampered");
  assert.strictEqual(idstore.anchorEstablished(identity, "contactsEstablished"), true, "fails closed");
  assert.strictEqual(identity.deviceFlags.contactsEstablished, true, "mutant A: committed under 'tampered' too");
  // Pentest of the change, F-6: this used to THROW, which made a device with one
  // forged prefs entry unable to create an identity at all (a regression on
  // plain setItem). The write goes through; the guard is honestly unconfirmed.
  const saved = await idstore.persistIdentity(identity, PASS);
  assert.match(saved.warning, /damaged or forged/);
  assert.strictEqual(saved.armed, false);
  assert.strictEqual(identity.floorClaim, "unconfirmed", "never promise a guard that is not in force");
  assert.ok(localStorage.getItem(LS_IDENTITY), "the blob is written");
  // ...and a blob that already claimed ARMED keeps claiming it (F-3).
  const armedBefore = fakeIdentity();
  armedBefore.floorClaim = true;
  await idstore.persistIdentity(armedBefore, PASS);
  assert.strictEqual(armedBefore.floorClaim, true, "F-3: a claim is never lowered");
  console.log("OK  a tampered floor slot fails closed, and is a warning on write rather than a brick");
}

async function testFloorBehindTheBlobIsBenign() {
  const floor = device();
  const id = fakeIdentity();
  await idstore.persistIdentity(id, PASS);
  await idstore.persistIdentity(id, PASS); // gen 2, floor 2
  floor.slots.set(FLOOR_SLOT, 1);          // the kill window: blob written, bump never ran
  const { verdict } = await idstore.openIdentity(PASS, fakeImport);
  assert.strictEqual(verdict.ok, true, "a floor BEHIND the blob is never a finding (armFloors' ordering argument)");
  assert.strictEqual(verdict.arm, false);
  console.log("OK  a lagging floor raises no alarm");
}

async function testFailedCreateClaimsNothing() {
  // The slot's create-bump fails to commit: the blob must not claim a floor it
  // does not durably have, or a restart (slot ABSENT again) reads as deletion.
  const floor = device(fakeFloor({ commitFails: (id, next) => next === 0 }));
  const id = fakeIdentity();
  const saved = await idstore.persistIdentity(id, PASS);
  assert.strictEqual(id.floorClaim, "unconfirmed", "A4/F-A3: 'could not arm' is not 'never had one'");
  assert.match(saved.warning, /could not durably record/);
  // The in-memory map still shows the slot (PadFloor semantics): the verdict is
  // clean and asks to arm again, so a later healthy write can claim honestly.
  const same = await idstore.openIdentity(PASS, fakeImport);
  assert.strictEqual(same.verdict.ok, true);
  assert.strictEqual(same.verdict.arm, true, "unconfirmed + slot present: try to arm again");
  floor.slots.clear(); // the restart: nothing reached disk
  const opened = await idstore.openIdentity(PASS, fakeImport);
  assert.strictEqual(opened.verdict.ok, true, "an unconfirmed claim cannot raise a deletion alarm");
  // ...but it still gets the rollback comparison.
  floor.slots.set(FLOOR_SLOT, 5);
  const later = await idstore.openIdentity(PASS, fakeImport);
  assert.strictEqual(later.verdict.reason, "rollback");
  console.log("OK  a slot that could not be created claims nothing, and is still compared");
}

async function testFailedAdvanceIsReportedNotFatal() {
  device(fakeFloor({ commitFails: (id, next) => next > 0 }));
  const id = fakeIdentity();
  const saved = await idstore.persistIdentity(id, PASS);
  assert.strictEqual(id.floorClaim, true, "the slot exists (create committed)");
  assert.strictEqual(saved.armed, false, "...but the advance did not land");
  assert.match(saved.warning, /could not durably record/);
  assert.ok(localStorage.getItem(LS_IDENTITY), "the blob itself is written");
  console.log("OK  a failed floor advance is a warning, not a lost identity");
}

async function testTwoTabsConverge() {
  const floor = device();
  const tabA = fakeIdentity();
  await idstore.persistIdentity(tabA, PASS); // gen 1
  const tabB = await fakeImport(localStorage.getItem(LS_IDENTITY), PASS); // unlocked at 1
  await idstore.persistIdentity(tabA, PASS);
  await idstore.persistIdentity(tabA, PASS); // floor 3
  const b = await idstore.persistIdentity(tabB, PASS);
  assert.strictEqual(b.generation, 4, "past the FLOOR (3), not the stale tab's own counter (1) + 1");
  assert.strictEqual(floor.slots.get(FLOOR_SLOT), 4);
  const { verdict } = await idstore.openIdentity(PASS, fakeImport);
  assert.strictEqual(verdict.ok, true, "two honest tabs never alarm each other");
  console.log("OK  a stale tab writes past the floor, so honest tabs converge");
}

async function testCounterOutOfRangeRefuses() {
  const floor = device();
  const id = fakeIdentity();
  id.generation = 0x7fffffff; // a blob whose OWN counter is past the int32 bridge
  const saved = await idstore.persistIdentity(id, PASS);
  assert.strictEqual(saved.generation, 0x7fffffff - 1, "clamped to the ceiling, never wrapped, never refused (round 3)");
  assert.match(saved.warning, /ceiling/);
  assert.ok(!floor.slots.has(FLOOR_SLOT) || floor.slots.get(FLOOR_SLOT) >= 0, "nothing negative ever reaches the bridge");
  id.generation = "not a number";
  await assert.rejects(idstore.persistIdentity(id, PASS), /malformed/, "a non-integer counter is the one refusal left");
  console.log("OK  the counter cannot wrap through the int32 bridge, and the blob stays writable");
}

// ---- the two load-time states, in fresh processes ------------------------------

function testPlainBrowserInFreshProcess() {
  const out = inFreshProcess("", `
    const id = fakeIdentity();
    const gens = [];
    for (let i = 0; i < 3; i++) gens.push((await idstore.persistIdentity(id, PASS)).generation);
    assert.deepStrictEqual(gens, [1, 2, 3], "the counter advances on every write, floor or not");
    const { identity, verdict } = await idstore.openIdentity(PASS, fakeImport);
    assert.strictEqual(verdict.ok, true);
    assert.strictEqual(verdict.arm, false, "nothing to arm without a floor");
    assert.strictEqual(identity.generation, 3, "the counter is inside the blob");
    assert.strictEqual(identity.floorClaim, false, "a plain browser claims NO floor, never 'unconfirmed'");
    assert.strictEqual(idstore.anchorEstablished(identity, "contactsEstablished"), false,
      "no floor: the flag is read as it is (the documented browser residual)");
    // F-3: a blob that came from the app (claims an armed floor) keeps that
    // claim through a browser write — a later open on the app must still be
    // able to notice a deleted slot.
    const fromApp = fakeIdentity();
    fromApp.floorClaim = true;
    await idstore.persistIdentity(fromApp, PASS);
    assert.strictEqual(fromApp.floorClaim, true, "F-3: a claim is never lowered, even where it cannot be measured");
    console.log("OK  plain browser: the counter is carried, no floor means no verdict, claims are kept");
  `);
  assert.match(out, /OK  plain browser/);
  process.stdout.write(out);
}

function testBrokenFloorInFreshProcess() {
  // The app's marker says a floor exists; no bridge is usable (otp.js `broken`).
  const out = inFreshProcess(`globalThis.__SECURE_CHAT_NATIVE_FLOOR__ = true;`, `
    const id = fakeIdentity();
    const saved = await idstore.persistIdentity(id, PASS);
    assert.strictEqual(id.floorClaim, "unconfirmed",
      "written claiming an UNCONFIRMED floor — not the false a plain browser writes, and never a promise");
    assert.match(saved.warning, /not usable/);
    const { identity, verdict } = await idstore.openIdentity(PASS, fakeImport);
    assert.strictEqual(verdict.reason, "unavailable", "expected-but-unusable is evidence, not a plain browser");
    assert.strictEqual(idstore.anchorEstablished(identity, "contactsEstablished"), true, "fails closed");
    assert.strictEqual(identity.deviceFlags.contactsEstablished, true, "mutant A: committed under 'unavailable' too");
    // F-3: one session under a broken bridge must not disarm the deletion alarm
    // for a blob that correctly claimed an armed floor.
    const armed = fakeIdentity();
    armed.floorClaim = true;
    await idstore.persistIdentity(armed, PASS);
    assert.strictEqual(armed.floorClaim, true, "F-3: a claim is never lowered by a broken session");
    console.log("OK  a marker without a usable bridge fails closed rather than reading as 'no floor'");
  `);
  assert.match(out, /OK  a marker without a usable bridge/);
  process.stdout.write(out);
}


// ---- round-2 F-2: the latched anchor and the consent gate ------------------------

// The crash window identity-store.js names: markEstablished's floor bump landed
// (synchronous prefs commit) but the WebView never flushed the blob OR the
// just-created store. On disk: blob gen 1 with no flags, no store, floor 2.
// That is byte-for-byte the state an attacker leaves behind, so the verdict is
// "rollback", the anchors fail closed, the heal LATCHES the flags, and every
// later unlock refuses the (absent) store — permanently, with "forget the
// identity" as the only way out. Round 2 called that a regression against HEAD,
// where the same crash gave a silent fresh store. The repair is a consent gate,
// not a policy: `startFresh` skips exactly the deletion check, only when the
// human said so.
async function testCrashWindowIsRecoverableOnlyByConsent() {
  const floor = device();
  const id = fakeIdentity();
  await idstore.persistIdentity(id, PASS);
  const unflushed = localStorage._dump();         // what reached disk: gen 1, no flags, no store
  id.deviceFlags.contactsEstablished = true;      // markEstablished ran...
  await idstore.persistIdentity(id, PASS);        // ...and its floor bump landed (floor 2)
  localStorage._restore(unflushed);               // ...but the WebView flush never happened
  assert.strictEqual(floor.slots.get(FLOOR_SLOT), 2);

  // Unlock #1, exactly as app.js does it: open, anchors, heal, then the store.
  const first = await idstore.openIdentity(PASS, fakeImport);
  assert.strictEqual(first.verdict.reason, "rollback");
  const anchorFor = (identity, flag) => ({
    established: idstore.anchorEstablished(identity, flag),
    markEstablished: async () => { identity.deviceFlags[flag] = true; await idstore.persistIdentity(identity, PASS); },
  });
  contacts.lock(); chats.lock();
  contacts.setStoreAnchor(anchorFor(first.identity, "contactsEstablished"));
  chats.setStoreAnchor(anchorFor(first.identity, "chatsEstablished"));
  await idstore.persistIdentity(first.identity, PASS); // the heal write, flags latched
  await assert.rejects(contacts.unlock(PASS), (e) => e.code === "STORE_DELETED",
    "unlock #1: the alarm fires — correct, this is also what an attacker's deletion looks like");
  await assert.rejects(chats.unlock(PASS), (e) => e.code === "STORE_DELETED");

  // Unlock #2: the verdict is clean now, but the latched flag keeps refusing.
  const second = await idstore.openIdentity(PASS, fakeImport);
  assert.strictEqual(second.verdict.ok, true, "the heal converged the counter");
  assert.strictEqual(second.identity.deviceFlags.contactsEstablished, true, "...and the flag is sealed in");
  contacts.lock(); chats.lock();
  contacts.setStoreAnchor(anchorFor(second.identity, "contactsEstablished"));
  chats.setStoreAnchor(anchorFor(second.identity, "chatsEstablished"));
  await assert.rejects(contacts.unlock(PASS), (e) => e.code === "STORE_DELETED",
    "unlock #2 without consent still refuses: the two-unlock attack is closed");
  await assert.rejects(contacts.unlock(PASS, { startFresh: false }), (e) => e.code === "STORE_DELETED");

  // The gate: explicit consent, and only that, starts over.
  await contacts.unlock(PASS, { startFresh: true });
  assert.strictEqual(contacts.isUnlocked(), true, "F-2: with consent the store starts over EMPTY — the identity is not lost");
  assert.deepStrictEqual(contacts.list(), []);
  await chats.unlock(PASS, { startFresh: true });
  assert.strictEqual(chats.isUnlocked(), true);
  // ...and a store that EXISTS is never discarded by the gate.
  contacts.lock();
  await contacts.unlock(PASS, { startFresh: true });
  assert.strictEqual(contacts.isUnlocked(), true, "startFresh on an existing store just opens it");
  contacts.lock(); chats.lock();
  console.log("OK  round-2 F-2: the crash window is recoverable by consent, and only by consent");
}

// ---- round-2 F-3: a floor slot parked at the ceiling is a warning, not a brick ----

async function testParkedCeilingDoesNotBrickCreation() {
  const MAX = 0x7fffffff - 1;
  // Round 3 (F-1): the first cut handled 0x7fffffff and threw at MAX — a slot
  // parked one BELOW let one honest write stamp MAX into the blob and every
  // later write threw, with a clean verdict. Every boundary, in every order.
  for (const parked of [0x7fffffff, MAX, MAX - 1, MAX - 2]) {
    const floor = device();
    floor.slots.set(FLOOR_SLOT, parked); // one page-realm bump on the frozen bridge
    const id = fakeIdentity();           // a brand-new identity (createIdentity)
    for (let i = 0; i < 4; i++) {        // create, then markEstablished, then more
      const saved = await idstore.persistIdentity(id, PASS);
      assert.ok(localStorage.getItem(LS_IDENTITY), `parked at ${parked}, write ${i}: the blob is always writable`);
      assert.ok(id.generation <= MAX, "the writer never stamps a value it would refuse");
      if (saved.warning) assert.match(saved.warning, /ceiling/);
      const { identity, verdict } = await idstore.openIdentity(PASS, fakeImport);
      assert.ok(verdict.ok || verdict.reason === "rollback", "clean, or the parked slot reads as a rollback");
      if (!verdict.ok) assert.strictEqual(idstore.anchorEstablished(identity, "contactsEstablished"), true);
    }
  }
  console.log("OK  round-2 F-3 / round-3 F-1: a parked ceiling never costs the ability to write the identity");
}

// ---- round-2 F-4: a pad file cannot name the identity's floor slot ----------------

async function testPadFileCannotNameTheIdentitySlot() {
  device();
  const pad = await otp.generatePad({ label: "x", totalBytes: 4096, fingerBytes: new Uint8Array(0) });
  assert.match(pad.padId, /^[0-9a-f]{32}$/, "fixture: generated ids are 32 hex chars");
  const honest = await otp.exportPad(pad, PASS);
  await otp.importPad(honest, PASS); // an honest file imports
  pad.padId = FLOOR_SLOT;
  const crafted = await otp.exportPad(pad, PASS);
  await assert.rejects(otp.importPad(crafted, PASS), /pad id/,
    "F-4: the pad id names the pad's floor slots and comes from the FILE — it must be validated, not assumed");
  pad.padId = "A".repeat(32);
  await assert.rejects(otp.importPad(await otp.exportPad(pad, PASS), PASS), /pad id/, "...uppercase hex is not a pad id either");
  console.log("OK  round-2 F-4: importPad refuses a pad id that is not 32 lowercase hex characters");
}

// ---- round-2 F-5: an unknown negative floor answer is evidence ------------------------

async function testUnknownNegativeFloorFailsClosed() {
  device({ slots: new Map(), read: () => -5, bump: () => -5 });
  localStorage.setItem(LS_IDENTITY, await fakeIdentity().export(PASS));
  const { identity, verdict } = await idstore.openIdentity(PASS, fakeImport);
  assert.strictEqual(verdict.reason, "tampered", "F-5: -5 is not ABSENT and not a value, so it is evidence");
  assert.strictEqual(idstore.anchorEstablished(identity, "contactsEstablished"), true);
  // Round-3 F-4: the WRITE side folds unknown negatives the same way. A bump
  // that answers -5 with a healthy read-back must not be taken as "armed".
  device({ slots: new Map(), read: () => 0, bump: () => -5 });
  const id = fakeIdentity();
  const saved = await idstore.persistIdentity(id, PASS);
  assert.strictEqual(id.floorClaim, "unconfirmed", "an unrecognised bump answer never yields an ARMED claim");
  assert.strictEqual(saved.armed, false);
  assert.match(saved.warning, /damaged or forged/);
  console.log("OK  round-2 F-5 / round-3 F-4: every negative answer except ABSENT fails closed, on read and on write");
}

// ---- end to end: the alarm F-ATREST-003 exists to raise ------------------------

async function testRolledBackAnchorTripsTheContactStoreAlarm() {
  const floor = device();
  const id = fakeIdentity();
  await idstore.persistIdentity(id, PASS);
  const archived = localStorage._dump();
  id.deviceFlags.contactsEstablished = true;
  await idstore.persistIdentity(id, PASS);
  assert.strictEqual(floor.slots.get(FLOOR_SLOT), 2);

  // The full F-ATREST-003 attack plus the F4 rollback: restore the old identity
  // blob, delete the store and its witness (they were never created in this
  // fixture, which is the same state).
  localStorage._restore(archived);
  const { identity: rolled, verdict } = await idstore.openIdentity(PASS, fakeImport);
  assert.strictEqual(verdict.reason, "rollback");
  // Exactly the anchor app.js's installStoreAnchor builds.
  contacts.lock();
  contacts.setStoreAnchor({
    established: idstore.anchorEstablished(rolled, "contactsEstablished"),
    markEstablished: async () => { rolled.deviceFlags.contactsEstablished = true; },
  });
  await assert.rejects(contacts.unlock(PASS), /BOTH been deleted/,
    "F-ATREST-003's alarm fires: no empty pin-less store is handed out under a rolled-back identity");

  // Control: the SAME blob under a CLEAN verdict — the device's record standing
  // at exactly the blob's generation, i.e. this copy is the newest one written —
  // opens a fresh store, exactly as before. This is what shows the assertion
  // above is the verdict's doing and not the fixture's.
  floor.slots.set(FLOOR_SLOT, rolled.generation);
  const fresh = await idstore.openIdentity(PASS, fakeImport);
  assert.strictEqual(fresh.verdict.ok, true);
  contacts.lock();
  contacts.setStoreAnchor({
    established: idstore.anchorEstablished(fresh.identity, "contactsEstablished"),
    markEstablished: async () => { fresh.identity.deviceFlags.contactsEstablished = true; },
  });
  await contacts.unlock(PASS);
  assert.strictEqual(contacts.isUnlocked(), true, "control: a genuine first run still opens a fresh store");
  contacts.lock();
  console.log("OK  end to end: the rolled-back anchor trips the contact-store deletion alarm");
}

// ---- the real Identity carries the counter inside its AEAD ---------------------

async function testRealIdentityCarriesTheCounter() {
  device();
  const id = await Identity.generate();
  assert.strictEqual(id.generation, 0);
  assert.strictEqual(id.floorClaim, false);
  const saved = await idstore.persistIdentity(id, PASS);
  assert.strictEqual(saved.generation, 1);
  const { identity: back, verdict } = await idstore.openIdentity(PASS, Identity.import);
  assert.strictEqual(verdict.ok, true);
  assert.strictEqual(back.generation, 1, "gen survives the AEAD round trip");
  assert.strictEqual(back.floorClaim, true, "the claim survives the AEAD round trip");
  assert.strictEqual(back.upgraded, false);

  // The reading rules the fake importer mirrors: anything but a non-negative
  // integer is the OLDEST value, anything but true/false claims nothing.
  id.generation = "7";
  id.floorClaim = "armed";
  const odd = await Identity.import(await id.export(PASS), PASS);
  assert.strictEqual(odd.generation, 0, "a malformed counter reads as 0, so it can only look OLDER");
  assert.strictEqual(odd.floorClaim, "unconfirmed", "a malformed claim claims nothing");
  id.generation = -1;
  assert.strictEqual((await Identity.import(await id.export(PASS), PASS)).generation, 0);
  // The pre-fix shape (both fields absent) cannot be produced through the AEAD
  // by deleting them from an export, so pin the parser's defaults instead: a
  // freshly generated identity with the fields blanked IS the absent case.
  const fresh = await Identity.generate();
  fresh.generation = undefined;
  fresh.floorClaim = undefined;
  const parsed = await Identity.import(await fresh.export(PASS), PASS);
  assert.strictEqual(parsed.generation, 0);
  assert.strictEqual(parsed.floorClaim, "unconfirmed");
  console.log("OK  the real Identity carries gen + floor inside the AEAD, with fail-old defaults");
}

// ---- otp.js hands out a FACADE over its one captured bridge ---------------------

async function testOtpFacadeCannotBeTurnedAgainstItsHolders() {
  const floor = device();
  const a = otp.deviceFloor();
  const b = otp.deviceFloor();
  assert.notStrictEqual(a, b, "a fresh object per call — nothing shared to mutate");
  assert.ok(!a.broken);
  // Pentest of the change, F-2: with the object itself returned, this one
  // assignment made every floor read ABSENT for identity-store.js AND for
  // otp.js's own padWasUsed/unlockPad — a two-time pad through the side door.
  a.read = () => -1;
  a.bump = () => -1;
  await idstore.persistIdentity(fakeIdentity(), PASS);
  assert.strictEqual(floor.slots.get(FLOOR_SLOT), 1, "identity-store's floor is untouched by the mutation");
  floor.slots.set(FLOOR_SLOT, 9);
  const { verdict } = await idstore.openIdentity(PASS, fakeImport);
  assert.strictEqual(verdict.reason, "rollback", "F-2: the poisoned facade changes nothing for the verdict");
  assert.strictEqual(b.read(FLOOR_SLOT), 9, "...nor for any other holder");
  // The facade still validates through otp.js's num(): a non-number from the
  // bridge is TAMPERED, never 0.
  current = { read: () => "0", bump: () => "0" };
  assert.strictEqual(otp.deviceFloor().read("x"), otp.NATIVE_TAMPERED);
  assert.strictEqual(otp.deviceFloor().bump("x", 1), otp.NATIVE_TAMPERED);
  console.log("OK  otp.deviceFloor() is a facade: mutating it reaches nothing the pads or the identity use");
}

// ---- no off switch ships (F-9) ---------------------------------------------------

function testExportInventoryIsExact() {
  assert.deepStrictEqual(Object.keys(idstore).sort(), [
    "FLOOR_SLOT", "LS_IDENTITY", "anchorEstablished", "judge", "openIdentity", "persistIdentity",
  ], "the module exports no setter, reset or test seam — the floor is captured at load and there is nothing to inject into");
  console.log("OK  identity-store.js exports exactly its API, and no way to replace the floor");
}

// ---- app.js is wired through the store, and only through it ----------------------

function lineOf(stripped, index) {
  return stripped.slice(0, index).split("\n").length;
}
function lineRangeOf(stripped, name) {
  const body = liftFunction(stripped, name, assert);
  const start = lineOf(stripped, stripped.indexOf(body));
  return [start, start + body.split("\n").length - 1];
}
const within = ([lo, hi]) => (hit) => hit.line >= lo && hit.line <= hi;

function testAppJsWiring() {
  const src = stripComments(readFileSync(new URL("./app.js", import.meta.url), "utf8"));

  // (1) Every write of localStorage in app.js is allow-listed by KEY CONSTANT,
  // and LS_IDENTITY is not among them. Spelled as an allow-list over call
  // sites — a deny-list over literal spellings is what the pentest's mutant K
  // (`const key = idstore.LS_IDENTITY; localStorage.setItem(key, …)`) walked
  // straight past.
  const writes = referencesOf(src, "setItem");
  const ALLOWED_KEYS = new Set(["LS_USERNAME", "LS_LOOKUP_TOKEN"]);
  for (const w of writes) {
    const m = w.text.match(/^localStorage\.setItem\(\s*(LS_[A-Z_]+)\s*,/);
    assert.ok(m, `app.js:${w.line}: every setItem must be \`localStorage.setItem(LS_<CONST>, …)\` — got: ${w.text}`);
    assert.ok(ALLOWED_KEYS.has(m[1]), `app.js:${w.line}: setItem on ${m[1]} is not allow-listed (identity writes go through identity-store.js)`);
  }
  assert.strictEqual(writes.length, 3, "the allow-listed identity-free write sites (update deliberately)");
  // ...and no key constant can be a second spelling of the identity key.
  const consts = [...src.matchAll(/^const (LS_[A-Z_]+) = (.+?);\s*$/gm)];
  assert.ok(consts.length >= 4, "the LS_ constants are declared at module scope");
  for (const [, name, value] of consts) {
    if (name === "LS_IDENTITY") {
      assert.strictEqual(value, "idstore.LS_IDENTITY", "LS_IDENTITY is the store's own key");
    } else {
      assert.match(value, /^"[^"]+"$/, `${name} must be a plain string literal`);
      assert.notStrictEqual(value, '"sc.identity.v1"', `${name} must not alias the identity key`);
    }
  }
  assert.strictEqual((src.match(/["']sc\.identity\.v1["']/g) || []).length, 0, "the key is never spelled in app.js");
  assert.strictEqual((src.match(/localStorage\s*\[/g) || []).length, 0, "no bracket access to storage");
  for (const line of src.split("\n").filter((l) => /\bprototype\b/.test(l))) {
    assert.match(line, /Object\.prototype\.hasOwnProperty\.call\(/,
      `prototype reach-around (pentest mutant K used Identity.prototype.export): ${line.trim()}`);
  }
  assert.strictEqual(referencesOf(src, "export").length, 0, "app.js never serialises an identity itself");
  assert.strictEqual((src.match(/setIdentityFloor|_resetForTests/g) || []).length, 0, "no floor injection exists to call");

  // (2) The store's API is called from exactly the places that may call it.
  const unlockRange = lineRangeOf(src, "unlockWithPassphrase");
  const createRange = lineRangeOf(src, "createIdentity");
  const anchorRange = lineRangeOf(src, "installStoreAnchor");
  const persists = referencesOf(src, "persistIdentity");
  assert.strictEqual(persists.length, 3, "persistIdentity: create, unlock heal, markEstablished — and nowhere else");
  assert.ok(persists.some(within(createRange)) && persists.some(within(unlockRange)) && persists.some(within(anchorRange)));
  const opens = referencesOf(src, "openIdentity");
  assert.strictEqual(opens.length, 1);
  assert.ok(within(unlockRange)(opens[0]), "openIdentity is called from unlockWithPassphrase only");
  assert.match(opens[0].text, /idstore\.openIdentity\(pass,\s*Identity\.import\)/);
  const reads = referencesOf(src, "anchorEstablished");
  assert.strictEqual(reads.length, 1);
  assert.ok(within(anchorRange)(reads[0]), "the verdict-aware anchor read lives in installStoreAnchor only");
  // Pentest mutant B: a SECOND setStoreAnchor call after installStoreAnchor,
  // installing `{established: false}`, reopened the finding while the
  // presence-only regexes stayed green. Allow-list the call sites.
  const anchorInstalls = referencesOf(src, "setStoreAnchor");
  assert.strictEqual(anchorInstalls.length, 2, "contacts + chats, once each");
  for (const h of anchorInstalls) {
    assert.ok(within(anchorRange)(h), `app.js:${h.line}: setStoreAnchor may only be called inside installStoreAnchor`);
    assert.match(h.text, /^(contacts|chats)\.setStoreAnchor\(anchorFor\("(contacts|chats)Established"\)\);$/,
      "each anchor is built by anchorFor and nothing else");
  }

  // (3) The shapes inside the three functions.
  const anchor = liftFunction(src, "installStoreAnchor", assert);
  assert.match(anchor, /established:\s*idstore\.anchorEstablished\(identity,\s*flag\)/);
  assert.doesNotMatch(anchor, /deviceFlags\[flag\]\s*===\s*true/, "no direct read path beside the verdict-aware one");
  assert.match(anchor, /await idstore\.persistIdentity\(identity,\s*pass\)/, "markEstablished writes through the store");
  assert.strictEqual((anchor.match(/const anchorFor = \(flag\) =>/g) || []).length, 1, "anchorFor: one definition");
  assert.strictEqual((anchor.match(/anchorFor\(/g) || []).length, 2, "anchorFor: two uses (contacts, chats)");

  const unlock = liftFunction(src, "unlockWithPassphrase", assert);
  assert.match(unlock, /if\s*\(identity\.upgraded\s*\|\|\s*!verdict\.ok\s*\|\|\s*verdict\.arm\)/,
    "the heal write runs on a bad verdict AND on `arm` (pentest F-1: an existing install must arm)");
  const anchorAt = unlock.indexOf("installStoreAnchor(pass)");
  const healAt = unlock.search(/identity\.upgraded\s*\|\|\s*!verdict\.ok/);
  assert.ok(anchorAt !== -1 && healAt !== -1 && anchorAt < healAt,
    "the anchors are installed (and the flags thereby forced) BEFORE the heal write, or the healed blob loses them");
  // Round-3 mutant M-D: `if (verdict.ok) installStoreAnchor(pass);` kept every
  // rule above green and reopened the finding. The call is its own statement
  // at function-body depth, preceded by a completed statement, called once.
  assert.strictEqual((unlock.match(/installStoreAnchor\(/g) || []).length, 1);
  assert.match(unlock, /[;}]\n  installStoreAnchor\(pass\);\n/, "installStoreAnchor(pass) is unconditional");
  assert.match(unlock, /els\.atRestWarning\.textContent = verdict\.ok \? "" : [^;]*verdict\.message/,
    "the verdict is shown in the every-view banner (pentest F-7)");
  assert.match(unlock, /els\.atRestWarning\.hidden = verdict\.ok;/);
  assert.match(unlock, /setIdentityStatus\([^;]*verdict\.message/, "...and in the Live-room status row");
  assert.doesNotMatch(unlock, /setItem\(/, "no direct write in the unlock path");

  const create = liftFunction(src, "createIdentity", assert);
  assert.match(create, /await idstore\.persistIdentity\(identity,\s*pass\)/, "creation writes through the store");
  assert.doesNotMatch(create, /setItem\(/);

  const html = readFileSync(new URL("./index.html", import.meta.url), "utf8");
  assert.match(html, /<p class="hint err" id="atRestWarning" aria-live="polite" hidden><\/p>/,
    "the banner exists, outside every view section");
  const forget = liftFunction(src, "forgetIdentity", assert);
  assert.match(forget, /els\.atRestWarning\.hidden = true;/, "forgetting the identity clears the banner");

  // (4) Round-2 F-1: the rules above bind SPELLINGS, and round 2 walked past
  // them four ways — `contacts["setStoreAnchor"]`, a renamed destructure, a
  // shadowing `const idstore = {...}` that leaves the anchored line
  // byte-identical, and an early `return` before installStoreAnchor. No regex
  // binds name resolution (the durable answer is a behavioural test that
  // imports app.js against a DOM stub — PROGRESS.md tracks it); what CAN be
  // pinned is that the four module bindings are only ever used as plain
  // member expressions, are never re-declared, re-bound or reflected over, and
  // that the unlock path has exactly the returns it is supposed to have.
  const BOUND = ["contacts", "chats", "idstore", "localStorage", "globalThis", "window", "Reflect"];
  assert.strictEqual((src.match(new RegExp(`\\b(${BOUND.join("|")})\\s*\\[`, "g")) || []).length, 0,
    "no bracket/computed property access on the bound modules or storage (round-2 mutant B')");
  assert.strictEqual((src.match(/\bReflect\b|\beval\b|\bnew Function\b/g) || []).length, 0, "no reflection");
  assert.strictEqual((src.match(/\bObject\.(values|entries|keys|assign|getOwnPropertyNames|getOwnPropertyDescriptors?)\(\s*(contacts|chats|idstore)\b/g) || []).length, 0,
    "the modules are never enumerated");
  assert.strictEqual((src.match(/\.\.\.\s*(contacts|chats|idstore)\b/g) || []).length, 0, "...nor spread");
  assert.strictEqual((src.match(/\b(const|let|var|function|class)\s+(contacts|chats|idstore|Identity|localStorage|confirm|freshStoreConsent)\b/g) || []).length, 1,
    "the module bindings are never re-declared (round-2 mutant M4 shadowed `idstore`; round-3 M-C shadowed `confirm`) — the one hit is the module-scope `const freshStoreConsent` and nothing else");
  assert.match(src, /^const freshStoreConsent = \{ contacts: false, chats: false \};$/m);
  assert.strictEqual((src.match(/\b(const|let|var)\s+identity\b/g) || []).length, 1, "`identity` is declared exactly once (module scope)");
  assert.match(src, /^let identity = null;/m);
  // Every use of the three module namespaces is `name.member` — a destructure
  // (`const { setStoreAnchor: wireC } = contacts`), an alias (`const c =
  // contacts`), an argument (`f(contacts)`) or a parameter all leave a bare
  // token. Strings are stripped first so prose like "contacts can look you up"
  // does not count.
  const noStrings = src
    .replace(/`(?:[^`\\]|\\.)*`/g, "``")
    .replace(/"(?:[^"\\\n]|\\.)*"/g, '""')
    .replace(/'(?:[^'\\\n]|\\.)*'/g, "''");
  for (const name of ["contacts", "chats", "idstore"]) {
    // A token preceded by `.` is somebody else's property (`freshStoreConsent.contacts`),
    // one followed by `:` is an object-literal key; both are not the binding.
    const bare = [...noStrings.matchAll(new RegExp(`(?<![.\\w$])${name}\\b(?!\\s*[.:])`, "g"))]
      .map((m) => noStrings.slice(0, m.index).split("\n").length)
      .filter((line) => !/^import \* as \w+ from/.test(noStrings.split("\n")[line - 1]));
    assert.deepStrictEqual(bare, [], `\`${name}\` may only be used as \`${name}.member\` (bare uses at lines ${bare.join(", ")}: alias, destructure, argument or parameter — round-2 mutant M2)`);
  }
  // Parameters and arrow params named like the bindings would shadow them.
  assert.strictEqual((noStrings.match(/\(([^()]*\b(idstore|contacts|chats|confirm|freshStoreConsent)\b[^()]*)\)\s*=>/g) || []).length, 0,
    "no arrow parameter shadows a module (checked on string-stripped source — round 3 showed the string-intact form tripping on a harmless default string)");
  assert.strictEqual((src.match(/\bidstore\.(?!(persistIdentity|openIdentity|anchorEstablished|LS_IDENTITY)\b)/g) || []).length, 0,
    "idstore is used for exactly its four members");
  // The unlock path: after openIdentity there are exactly two returns — the
  // catch's error string and the final `return null` — so no verdict can be
  // turned into a refusal ahead of the anchors (round-2 mutant M3).
  const afterOpen = unlock.slice(unlock.indexOf("idstore.openIdentity"));
  const returns = afterOpen.match(/\breturn\b[^;]*;/g) || [];
  assert.deepStrictEqual(returns, ['return "Wrong passphrase or corrupted identity.";', "return null;"],
    "unlockWithPassphrase returns exactly twice after opening: the import failure, and null at the end");
  assert.ok(afterOpen.trimEnd().endsWith("return null;\n}"), "...and null is the last statement");
  assert.strictEqual((afterOpen.match(/\bthrow\b/g) || []).length, 0);

  // (5) Round-2 F-2: the consent gate. `startFresh` reaches the stores only
  // from unlockContacts, only from the consent object, and the consent object
  // is written only inside wireStartFresh, after a confirm(), for one attempt.
  const unlockStores = liftFunction(src, "unlockContacts", assert);
  const freshUses = referencesOf(src, "unlock").filter((h) => /\b(contacts|chats)\.unlock\(/.test(h.text));
  assert.strictEqual(freshUses.length, 2, "the two stores are unlocked from exactly one place each");
  const storesRange = lineRangeOf(src, "unlockContacts");
  for (const h of freshUses) {
    assert.ok(within(storesRange)(h), `app.js:${h.line}: store unlocks live in unlockContacts only`);
    assert.match(h.text, /^(?:const warning = )?await (contacts|chats)\.unlock\(pass, \{ startFresh: freshStoreConsent\.\1 \}\);/,
      "each unlock passes ITS OWN consent flag (round-3 M-B cross-wired them) and nothing else");
  }
  // Round-3 M-A / M-H: the consent object may be ASSIGNED only inside the gate,
  // in any spelling — counted as every `=` after the identifier, not as the
  // two literal forms the first cut looked for.
  const consentWrites = [...src.matchAll(/(?<!const )\bfreshStoreConsent\b[^=\n]*=(?!=)/g)];
  assert.strictEqual(consentWrites.length, 2, "consent is written in exactly two places: armed, then disarmed");
  assert.deepStrictEqual(consentWrites.map((m) => m[0].trim()), ["freshStoreConsent[store] =", "freshStoreConsent[store] ="]);
  const gate = liftFunction(src, "wireStartFresh", assert);
  const gateRange = lineRangeOf(src, "wireStartFresh");
  for (const w of consentWrites) {
    const line = lineOf(src, w.index);
    assert.ok(line >= gateRange[0] && line <= gateRange[1], `app.js:${line}: consent may only be written inside wireStartFresh`);
  }
  assert.match(gate, /if \(!confirm\([\s\S]*?\)\) return;[\s\S]*freshStoreConsent\[store\] = true;[\s\S]*await go\(\);[\s\S]*finally \{[\s\S]*freshStoreConsent\[store\] = false;/,
    "the gate confirms first, arms, runs one unlock, and disarms in a finally");
  assert.match(src, /wireStartFresh\(els\.usersStartFresh, "contacts", "contact store",\n  "[^"]+", usersGo\);/, "the Users button arms the CONTACTS consent");
  assert.match(src, /wireStartFresh\(els\.chatsStartFresh, "chats", "chat history",\n  "[^"]+", chatsGo\);/, "the Chats button arms the CHATS consent");
  assert.strictEqual((src.match(/wireStartFresh\(/g) || []).length, 3, "one definition, two wirings");
  // Round-3 F-3: the Chats pane must render its alarm like the Users pane does.
  assert.match(src, /els\.chatsLocked\.querySelector\("p"\)\.textContent = chatsError\n\s+\? "Chat store error: " \+ chatsError \+\n\s+\(chatsErrorCode === "STORE_DELETED"/,
    "the chat store's deletion alarm is rendered in its pane");
  assert.match(src, /els\.usersLocked\.querySelector\("p"\)\.textContent = contactsError\n\s+\? "Contact store error: " \+ contactsError \+\n\s+\(contactsErrorCode === "STORE_DELETED"/);
  assert.match(html, /<button id="usersStartFresh" type="button" class="danger" hidden>/);
  assert.match(html, /<button id="chatsStartFresh" type="button" class="danger" hidden>/);
  assert.match(src, /els\.usersStartFresh\.hidden = contactsErrorCode !== "STORE_DELETED";/, "the button shows only behind the deletion alarm");
  assert.match(src, /els\.chatsStartFresh\.hidden = chatsErrorCode !== "STORE_DELETED";/);
  // ...and in the stores, `startFresh` skips exactly the deletion check.
  for (const file of ["contacts.js", "chats.js"]) {
    const store = stripComments(readFileSync(new URL("./" + file, import.meta.url), "utf8"));
    assert.match(store, /export async function unlock\(passphrase, \{ startFresh = false \} = \{\}\) \{/);
    assert.strictEqual((store.match(/\bstartFresh\b/g) || []).length, 2, `${file}: startFresh appears in the signature and one guard, nowhere else`);
    assert.match(store, /if \(!startFresh\) await assertStoreNotDeleted\(passphrase\);/);
    assert.strictEqual((store.match(/await assertStoreNotDeleted\(passphrase\)/g) || []).length, 1, `${file}: the check has one caller`);
  }
  console.log("OK  app.js writes and opens the identity only through identity-store.js");
}

await testRollbackFailsClosedAndTheHealKeepsIt();
await testExistingInstallArmsOnFirstUnlock();
await testPreFixBlobIsTheArchivedArtifact();
await testFloorDeletionIsEvidence();
await testTamperedFloorFailsClosedButStillWrites();
await testFloorBehindTheBlobIsBenign();
await testFailedCreateClaimsNothing();
await testFailedAdvanceIsReportedNotFatal();
await testTwoTabsConverge();
await testCounterOutOfRangeRefuses();
testPlainBrowserInFreshProcess();
testBrokenFloorInFreshProcess();
await testCrashWindowIsRecoverableOnlyByConsent();
await testParkedCeilingDoesNotBrickCreation();
await testPadFileCannotNameTheIdentitySlot();
await testUnknownNegativeFloorFailsClosed();
await testRolledBackAnchorTripsTheContactStoreAlarm();
await testRealIdentityCarriesTheCounter();
await testOtpFacadeCannotBeTurnedAgainstItsHolders();
testExportInventoryIsExact();
testAppJsWiring();
console.log("All identity at-rest (F-ATREST-008) checks passed.");
