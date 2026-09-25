// Package 3b — durable storage. Run: node durable.test.mjs
//
// The finding (package-3 pentest, pre-existing HIGH): `localStorage.setItem`
// returning is not durability. Chromium commits localStorage in rate-limited
// batches, so a write can stay off disk for a minute; a crash (no attacker)
// then reopened an OTP pad at an offset a sent message had already used — a
// two-time pad — and on Android left the native floor AHEAD of the data, which
// bricked the pad / the contact or chat store.
//
// How a crash is simulated here, faithfully to that mechanism:
//   * "localStorage lost"      — the test snapshots localStorage at the moment
//                                the disk is known to hold it and restores that
//                                snapshot as the "relaunch" (everything written
//                                after it never left the renderer);
//   * IndexedDB                — fake-idb.test.mjs: a write exists only once its
//                                transaction COMPLETED, `hold()` keeps it in
//                                flight, `onCommit` captures the state a kill
//                                right after the durable write leaves;
//   * the native floor         — a Kotlin-faithful monotone map (PadFloor.kt);
//   * a relaunch               — a FRESH module instance (`?query`), so nothing
//                                in memory survives.
import assert from "node:assert";
import { makeFakeIdb } from "./fake-idb.test.mjs";
import { V031_BROWSER, V031_ANDROID } from "./v031-fixture.test.mjs";

const mem = new Map();
globalThis.localStorage = {
  getItem: (k) => (mem.has(k) ? mem.get(k) : null),
  setItem: (k, v) => mem.set(k, String(v)),
  removeItem: (k) => mem.delete(k),
  clear: () => mem.clear(),
};
const lsSnap = () => new Map(mem);
const lsRestore = (s) => { mem.clear(); for (const [k, v] of s) mem.set(k, v); };

let fake = makeFakeIdb();
fake.install();
const freshIdb = () => { fake = makeFakeIdb(); fake.install(); return fake; };

const settle = async (n = 30) => { for (let i = 0; i < n; i++) await new Promise((r) => setTimeout(r, 1)); };
let gen = 0;
const fresh = (mod, tag) => import(`./${mod}?3b=${tag}-${gen++}`);

// Kotlin-faithful floor (PadFloor.kt): monotone, a value exists or not.
const floors = new Map();
function installFloor() {
  globalThis.__SECURE_CHAT_NATIVE_FLOOR__ = true;
  globalThis.__SECURE_CHAT_PAD_FLOOR__ = Object.freeze({
    read: (id) => (floors.has(id) ? floors.get(id) : -1),
    bump: (id, v) => {
      if (typeof v !== "number" || v < 0 || v > 0x7fffffff) return -4;
      const cur = floors.has(id) ? floors.get(id) : -1;
      const n = cur === -1 ? v : (v > cur ? v : cur);
      floors.set(id, n);
      return n;
    },
  });
}
function removeFloor() {
  delete globalThis.__SECURE_CHAT_NATIVE_FLOOR__;
  delete globalThis.__SECURE_CHAT_PAD_FLOOR__;
}
async function withFloor(mod, tag) {
  installFloor();
  try { return await fresh(mod, tag); } finally { removeFloor(); }
}

const durable = await import("./durable.js");
const PASS = "pad passphrase for 3b";
const durKey = (id) => "sc.otp.dur.v1." + id;

// ============================================================================
// A. durable.js itself
// ============================================================================
{
  fake.log.length = 0;
  await durable.write({ a: "1", b: "2" });
  await durable.put("c", "3");
  await durable.del("c");
  assert.ok(fake.log.length === 3 && fake.log.every((t) => t.durability === "strict"),
    "every read-write transaction is opened with durability: \"strict\" — " + JSON.stringify(fake.log.map((t) => t.durability)));

  // Resolves only once the transaction COMPLETED — not on the request's success.
  fake.hold();
  let done = false;
  const p = durable.put("d", "4").then(() => { done = true; });
  await settle();
  assert.strictEqual(done, false, "a durable write does not resolve while its transaction has not committed");
  assert.strictEqual(fake.getItem("d"), null, "…(and indeed nothing is on 'disk' yet)");
  fake.release();
  await p;
  assert.ok(done && fake.getItem("d") === "4", "…and resolves once it has");

  // Atomic, and an abort rejects.
  fake.failWrites((k) => k === "y");
  await assert.rejects(durable.write({ x: "1", y: "2" }), /Quota/, "an aborted transaction rejects");
  fake.failWrites(null);
  assert.strictEqual(fake.getItem("x"), null, "…and writes nothing (one transaction, all or nothing)");
  assert.deepStrictEqual(await durable.getMany(["a", "b", "zz"]), { a: "1", b: "2", zz: null });

  assert.strictEqual(await durable.writeIfAbsent({ a: "X", n: "new" }), false, "writeIfAbsent: an existing key blocks the write");
  assert.ok(fake.getItem("a") === "1" && fake.getItem("n") === null, "…and nothing is written");
  assert.strictEqual(await durable.writeIfAbsent({ n: "new" }), true);
  assert.strictEqual(fake.getItem("n"), "new");

  fake.uninstall();
  assert.strictEqual(durable.available(), false);
  await assert.rejects(durable.get("a"), (e) => e.code === "NO_DURABLE_STORAGE");
  fake.install();
  console.log("OK  durable.js: strict durability on every write, resolves on COMPLETE only, atomic, rejects on abort");
}

// ============================================================================
// B. The bug, in a plain browser: the pad reopened at an offset already used.
// ============================================================================
// The pentest PoC shape: save at 0 (on disk), message 1 spends 0..500 and
// message 2 500..1000, each awaiting its pre-send save; killed seconds later,
// localStorage still holds the offset-0 state. Pre-3b: "OPENED silently at
// sendOffset 0/500" — the next message reuses spent pad bytes.
{
  mem.clear(); freshIdb();
  const A = await fresh("otp.js", "b-run");
  const { makeCipher } = await import("./crypto.js");
  const pad = await A.generatePad({ label: "crash", totalBytes: 8192, fingerBytes: new Uint8Array(0) });
  const at = await A.saveNewPad(pad, PASS);
  const onDisk = lsSnap(); // "wait 70 s": this much reached disk
  const cipher = makeCipher("OTP", "r".repeat(64), { pad });
  const ct1 = await cipher.encrypt("x".repeat(468));
  pad.sendOffset = cipher.sendOffset;
  await A.savePadProgress(pad, at);                  // persist before transmit
  const ct2 = await cipher.encrypt("y".repeat(468));
  pad.sendOffset = cipher.sendOffset;
  await A.savePadProgress(pad, at);
  assert.strictEqual(pad.sendOffset, 1000, "fixture: two messages spent 0..1000");
  // Kill: localStorage never committed after `onDisk`; IndexedDB did.
  lsRestore(onDisk);
  const B = await fresh("otp.js", "b-relaunch");
  const re = await B.unlockPad(pad.padId, PASS);
  assert.strictEqual(re.record.sendOffset, 1000,
    "3b: after a crash that lost localStorage the pad reopens at 1000 (healed forward), never at 0");
  const c2 = makeCipher("OTP", "r".repeat(64), { pad: re.record });
  const next = JSON.parse(Buffer.from(await c2.encrypt("z"), "base64").toString());
  const used = [ct1, ct2].map((c) => JSON.parse(Buffer.from(c, "base64").toString()).o);
  assert.ok(next.o >= 1000 && !used.includes(next.o), `the next message starts past every spent byte (o=${next.o}, spent at ${used})`);
  assert.ok(re.record.bytes.subarray(0, 1000).every((b) => b === 0), "the healed-over span is zeroed");
  console.log("OK  3b: a crash that loses localStorage no longer reopens an OTP pad at a spent offset (browser)");

  // …and the import route: the pad was imported, used once, and the crash took
  // EVERY localStorage trace of it. Re-importing the (always pristine) file
  // recreated it at offset 0. The durable record's `used` hint refuses that.
  mem.clear(); freshIdb();
  const C = await fresh("otp.js", "b-imp");
  const src = await C.generatePad({ label: "imp", totalBytes: 8192, fingerBytes: new Uint8Array(0) });
  const file = await C.exportPad(src, "xfer");
  mem.clear(); // the importing device
  const before = lsSnap();
  const imp = await C.importPad(file, "xfer");
  const iat = await C.saveNewPad(imp, PASS);
  imp.sendOffset = 200;
  await C.savePadProgress(imp, iat);
  lsRestore(before);
  const D = await fresh("otp.js", "b-imp-relaunch");
  await assert.rejects(D.importPad(file, "xfer"), /already been used on this device/,
    "3b: re-importing a pad whose every localStorage trace a crash erased is refused (durable `used`)");
  // Control: a pad that never SENT anything may be re-imported (a failed first
  // save must not burn an in-person exchange — the package-3 rule).
  mem.clear(); freshIdb();
  const E = await fresh("otp.js", "b-imp0");
  const src0 = await E.generatePad({ label: "imp0", totalBytes: 8192, fingerBytes: new Uint8Array(0) });
  const file0 = await E.exportPad(src0, "xfer");
  mem.clear();
  const imp0 = await E.importPad(file0, "xfer");
  await E.saveNewPad(imp0, PASS);
  mem.clear();
  await (await fresh("otp.js", "b-imp0-r")).importPad(file0, "xfer");
  console.log("OK  3b: a pad a crash erased from localStorage cannot be re-imported once used (and can if unused)");
}

// ============================================================================
// C. Android: the native floor is advanced only after the durable write
// ============================================================================
{
  mem.clear(); floors.clear(); freshIdb();
  const A = await withFloor("otp.js", "c-run");
  const pad = await A.generatePad({ label: "and", totalBytes: 8192, fingerBytes: new Uint8Array(0) });
  const at = await A.saveNewPad(pad, PASS);
  pad.sendOffset = 500;
  await A.savePadProgress(pad, at);
  const onDisk = lsSnap();

  // (1) While the durable write is in flight the floor has NOT moved.
  pad.sendOffset = 1000;
  fake.hold();
  let saved = false;
  const p = A.savePadProgress(pad, at).then(() => { saved = true; });
  await settle();
  assert.strictEqual(saved, false, "fixture: the save waits for the durable write");
  assert.strictEqual(floors.get(pad.padId), 500,
    "3b: the send floor is not advanced while the durable write has not completed (never ahead of the data)");
  // (2) A kill right at the commit (durable on disk, floor not yet advanced,
  // localStorage lost) reopens cleanly at the durable offset.
  let atCommit = null;
  fake.onCommit = () => { atCommit = { floors: new Map(floors) }; };
  fake.release();
  await p;
  fake.onCommit = null;
  assert.strictEqual(floors.get(pad.padId), 1000, "…and is advanced once it has");
  assert.strictEqual(atCommit.floors.get(pad.padId), 500, "fixture: at the commit point the floor was still 500");
  const afterRun = new Map(floors);
  floors.clear(); for (const [k, v] of atCommit.floors) floors.set(k, v);
  lsRestore(onDisk);
  const B = await withFloor("otp.js", "c-relaunch");
  assert.strictEqual((await B.unlockPad(pad.padId, PASS)).record.sendOffset, 1000,
    "3b: killed between the durable write and the floor advance, the pad reopens at the durable offset (no brick, no reuse)");
  // (3) The pre-3b Android brick — floor ahead of localStorage — now heals.
  floors.clear(); for (const [k, v] of afterRun) floors.set(k, v);
  lsRestore(onDisk);
  const C = await withFloor("otp.js", "c-brick");
  assert.strictEqual((await C.unlockPad(pad.padId, PASS)).record.sendOffset, 1000,
    "3b: floor on disk, localStorage lost — the pad opens at the durable offset instead of refusing as 'rolled back'");
  // (4) But the floor never HEALS: ahead of every data record (durable one
  // deleted, old blob + watermark restored) it is rollback evidence as before.
  lsRestore(onDisk);
  fake.removeItem(durKey(pad.padId));
  const D = await withFloor("otp.js", "c-rollback");
  await assert.rejects(D.unlockPad(pad.padId, PASS), /rolled back/,
    "3b: a native floor ahead of every data record — the durable one included — is still refused");
  console.log("OK  3b: on Android the floor moves only after the durable write; a kill between them heals, a floor ahead of all data refuses");
}

// (5) A durable write that fails is a failed save: nothing advances, the
// caller (app.js) does not transmit.
{
  mem.clear(); floors.clear(); freshIdb();
  const A = await withFloor("otp.js", "c-fail");
  const pad = await A.generatePad({ label: "fail", totalBytes: 8192, fingerBytes: new Uint8Array(0) });
  const at = await A.saveNewPad(pad, PASS);
  pad.sendOffset = 300;
  fake.failWrites((k) => k.startsWith("sc.otp.dur."));
  await assert.rejects(A.savePadProgress(pad, at), (e) => e.code === "DURABLE_WRITE_FAILED",
    "3b: a durable write that fails fails the save (so app.js keeps the ciphertext off the wire)");
  fake.failWrites(null);
  assert.strictEqual(floors.get(pad.padId), 0, "…and the floor stays where the durable data is");
  console.log("OK  3b: a failed durable write fails the save and leaves the floor alone");
}

// ============================================================================
// D. No IndexedDB: OTP is refused, with a reason
// ============================================================================
{
  mem.clear(); freshIdb();
  const A = await fresh("otp.js", "d");
  const pad = await A.generatePad({ label: "noidb", totalBytes: 8192, fingerBytes: new Uint8Array(0) });
  const file = await A.exportPad(pad, "xfer");
  await A.saveNewPad(pad, PASS);
  fake.uninstall();
  await assert.rejects(A.unlockPad(pad.padId, PASS), (e) => e.code === "NO_DURABLE_STORAGE" && /IndexedDB/.test(e.message),
    "3b: without IndexedDB a pad does not unlock");
  const other = await A.generatePad({ label: "noidb2", totalBytes: 8192, fingerBytes: new Uint8Array(0) });
  await assert.rejects(A.saveNewPad(other, PASS), (e) => e.code === "NO_DURABLE_STORAGE", "…nor is one saved");
  mem.clear();
  await assert.rejects(A.importPad(file, "xfer"), (e) => e.code === "NO_DURABLE_STORAGE", "…nor imported");
  fake.install();
  console.log("OK  3b: without IndexedDB, OTP is refused with a clear reason");
}

// ============================================================================
// E. The durable record is authenticated state
// ============================================================================
{
  mem.clear(); freshIdb();
  const A = await fresh("otp.js", "e");
  const pad = await A.generatePad({ label: "auth", totalBytes: 8192, fingerBytes: new Uint8Array(0) });
  const at = await A.saveNewPad(pad, PASS);
  pad.sendOffset = 100;
  await A.savePadProgress(pad, at);
  const rec = JSON.parse(fake.getItem(durKey(pad.padId)));
  assert.deepStrictEqual(Object.keys(rec).sort(), ["ct", "iv", "used"], "only iv + ct + the plaintext `used` hint");
  assert.strictEqual(rec.used, 1);
  fake.setItem(durKey(pad.padId), JSON.stringify({ used: 1, iv: "AAAAAAAAAAAAAAAA", ct: "AAAAAAAAAAAAAAAAAAAAAAA=" }));
  await assert.rejects(A.unlockPad(pad.padId, PASS), /durable progress record .*damaged or forged/,
    "3b: a forged durable record is refused, never ignored");
  // The pad's own watermark (same key) cannot stand in for it.
  fake.setItem(durKey(pad.padId), mem.get("sc.otp.wm.v1." + pad.padId));
  await assert.rejects(A.unlockPad(pad.padId, PASS), /durable progress record .*damaged or forged/,
    "…nor can the watermark record be copied into its place");
  console.log("OK  3b: the durable record is sealed under the pad key; forged or substituted records are refused");
}

// E2. Review round 1 (HIGH, traced by pentest-new-code): the heal must never
// apply to state that is not authenticated. A pre-P-01 (v1) blob kept `role`
// and `regionSize` OUTSIDE its AEAD and is re-sealed under the same key when
// upgraded, so an archived v1 copy still decrypts next to the pad's current
// watermark and durable record. Pre-3b "blob below record" refused it; the
// first 3b cut healed it — with the attacker's outer `role`, i.e. sending from
// the PEER's region: a two-time pad. Now (a) a v1 blob is never healed, and
// (b) the durable record carries role + regionSize, so ANY blob shape whose
// geometry disagrees with it is refused.
{
  mem.clear(); freshIdb();
  const A = await fresh("otp.js", "e2");
  const pad = await A.generatePad({ label: "v1-role", totalBytes: 8192, fingerBytes: new Uint8Array(0) });
  const pristine = pad.bytes.slice();
  const at = await A.saveNewPad(pad, PASS);
  pad.sendOffset = 500;
  await A.savePadProgress(pad, at);
  // The archived v1 blob: inner = {bytes, sendOffset, recvHighWater} only,
  // everything else outside — and the attacker flips `role`.
  const cur = JSON.parse(mem.get("sc.otp.pad.v1." + pad.padId));
  const b64s = (u) => Buffer.from(u).toString("base64");
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const inner = new TextEncoder().encode(JSON.stringify({ bytes: b64s(pristine), sendOffset: 0, recvHighWater: 0 }));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, at.key, inner));
  const v1 = (role) => JSON.stringify({ kdf: cur.kdf, iv: b64s(iv), ct: b64s(ct), padId: pad.padId, label: "x", regionSize: pad.regionSize, role });
  mem.set("sc.otp.pad.v1." + pad.padId, v1(1));
  const B = await fresh("otp.js", "e2-r");
  await assert.rejects(B.unlockPad(pad.padId, PASS, { adoptLegacy: true }), /rolled back|role|does not match/,
    "review r1: an archived v1 blob with its unauthenticated role flipped is refused, never healed");
  // …and with the role left alone it is still not healed (v1 geometry is not
  // authenticated): the pre-3b refusal.
  mem.set("sc.otp.pad.v1." + pad.padId, v1(0));
  await assert.rejects((await fresh("otp.js", "e2-r0")).unlockPad(pad.padId, PASS, { adoptLegacy: true }), /rolled back/,
    "review r1: a v1 blob below its records is refused as before 3b (no heal on unauthenticated geometry)");
  // (b) The durable record's geometry binds even without the v1 rule: a v3
  // blob re-sealed with a flipped role (needs the key — models any future
  // path to a wrong-geometry blob) is refused.
  const dur = JSON.parse(fake.getItem(durKey(pad.padId)));
  const durPlain = JSON.parse(new TextDecoder().decode(await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: Buffer.from(dur.iv, "base64") }, at.key, Buffer.from(dur.ct, "base64"))));
  assert.deepStrictEqual([durPlain.role, durPlain.regionSize], [0, pad.regionSize],
    "review r1: the durable record seals the pad's role and region size");
  mem.set("sc.otp.pad.v1." + pad.padId, JSON.stringify(cur)); // the real v3 blob back
  const v3 = JSON.parse(new TextDecoder().decode(await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: Buffer.from(cur.iv, "base64") }, at.key, Buffer.from(cur.ct, "base64"))));
  v3.role = 1;
  const iv3 = crypto.getRandomValues(new Uint8Array(12));
  const ct3 = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: iv3 }, at.key,
    new TextEncoder().encode(JSON.stringify(v3))));
  mem.set("sc.otp.pad.v1." + pad.padId, JSON.stringify({ ...cur, iv: b64s(iv3), ct: b64s(ct3) }));
  await assert.rejects((await fresh("otp.js", "e2-v3")).unlockPad(pad.padId, PASS), /does not match its durable progress record/,
    "review r1: a blob whose role disagrees with the durable record is refused");
  console.log("OK  review r1: an archived v1 blob (unauthenticated role) is never healed; the durable record binds the geometry");
}

// ============================================================================
// F. `exported` survives the crash too
// ============================================================================
{
  mem.clear(); freshIdb();
  const A = await fresh("otp.js", "f");
  const pad = await A.generatePad({ label: "exp", totalBytes: 8192, fingerBytes: new Uint8Array(0) });
  const at = await A.saveNewPad(pad, PASS);
  const onDisk = lsSnap();
  await A.markExported(pad, at);              // app.js hands the file out after this
  lsRestore(onDisk);
  const B = await fresh("otp.js", "f-relaunch");
  const re = await B.unlockPad(pad.padId, PASS);
  assert.strictEqual(re.record.exported, true,
    "3b: an export latched just before a crash that lost localStorage is still recorded (no silent second export)");
  assert.strictEqual(re.record.exportedInferred, false, "…as a recorded export, not an inferred one");
  console.log("OK  3b: the export latch reaches durable storage before the file is handed out");
}

// ============================================================================
// G. Migration: a pad saved by v0.3.1 (no durable record)
// ============================================================================
for (const fx of [V031_BROWSER, V031_ANDROID]) {
  mem.clear(); floors.clear(); freshIdb();
  for (const [k, v] of Object.entries(fx.localStorage)) mem.set(k, v);
  for (const [k, v] of Object.entries(fx.floors)) floors.set(k, v);
  const A = fx.mode === "android" ? await withFloor("otp.js", "g-a") : await fresh("otp.js", "g-b");
  const u = await A.unlockPad(fx.padId, fx.PAD_PASS);
  assert.deepStrictEqual([u.record.sendOffset, u.record.recvHighWater], [300, 100], `${fx.mode}: a v0.3.1 pad opens where it was`);
  assert.ok(fake.getItem(durKey(fx.padId)), `${fx.mode}: …and gains its durable record on that first unlock`);
  // From here the crash is covered: send, lose localStorage, relaunch.
  const onDisk = lsSnap();
  u.record.sendOffset = 700;
  await A.savePadProgress(u.record, u.atRest);
  lsRestore(onDisk);
  const B = fx.mode === "android" ? await withFloor("otp.js", "g-a2") : await fresh("otp.js", "g-b2");
  assert.strictEqual((await B.unlockPad(fx.padId, fx.PAD_PASS)).record.sendOffset, 700,
    `${fx.mode}: a migrated v0.3.1 pad heals forward after a crash`);
}
console.log("OK  3b: v0.3.1 pads (browser and Android) gain a durable record on first unlock and are crash-safe from then on");

// ============================================================================
// H. The contact and chat stores in IndexedDB
// ============================================================================
const STORE_KEYS = ["sc.contacts.v1", "sc.contacts.gen.v1", "sc.chats.v1", "sc.chats.gen.v1"];

// H1: one-time migration from a v0.3.1 localStorage.
for (const fx of [V031_BROWSER, V031_ANDROID]) {
  mem.clear(); floors.clear(); freshIdb();
  for (const [k, v] of Object.entries(fx.localStorage)) mem.set(k, v);
  for (const [k, v] of Object.entries(fx.floors)) floors.set(k, v);
  const android = fx.mode === "android";
  const C = android ? await withFloor("contacts.js", "h1") : await fresh("contacts.js", "h1");
  const H = android ? await withFloor("chats.js", "h1") : await fresh("chats.js", "h1");
  await C.ready; await H.ready;
  for (const k of STORE_KEYS) {
    assert.strictEqual(mem.get(k), undefined, `${fx.mode}: ${k} moved out of localStorage`);
    assert.strictEqual(fake.getItem(k), fx.localStorage[k], `${fx.mode}: …into IndexedDB, byte for byte`);
  }
  assert.ok(mem.has("sc.contacts.idb.v1") && mem.has("sc.chats.idb.v1"), `${fx.mode}: the moved-to-IndexedDB markers are set`);
  assert.ok(C.hasStore() && H.hasStore(), `${fx.mode}: hasStore() still says a store exists`);
  await C.unlock(fx.PASS, { floorId: fx.FLOOR_ID });
  assert.strictEqual(C.get("alice").verified, true, `${fx.mode}: the migrated contact is intact`);
  assert.ok(C.getPin("user:alice"), `${fx.mode}: …with its pin`);
  await H.unlock(fx.PASS, { floorId: fx.FLOOR_ID });
  assert.strictEqual(H.get("alice").messages[0].text, "hello from v0.3.1", `${fx.mode}: the migrated chat is intact`);
  assert.strictEqual(await H.markSeen("alice", "env-1"), false, `${fx.mode}: …with its replay ring`);
  await C.setVerified("alice", true);
  if (android) {
    assert.strictEqual(floors.get("contacts:" + fx.FLOOR_ID), 4, "android: the floor keeps counting from the migrated generation");
  }
  assert.ok(STORE_KEYS.every((k) => !mem.has(k)), `${fx.mode}: later writes go to IndexedDB only (one source of truth)`);
  C.lock(); H.lock();
}
console.log("OK  3b: v0.3.1 contact + chat stores migrate to IndexedDB verbatim, open intact, and localStorage is cleared");

// H2: an interrupted migration (copied, not yet removed) resolves to IndexedDB;
// a migration whose write fails keeps localStorage and says so.
{
  const fx = V031_BROWSER;
  mem.clear(); freshIdb();
  for (const [k, v] of Object.entries(fx.localStorage)) mem.set(k, v);
  fake.setItem("sc.contacts.v1", fx.localStorage["sc.contacts.v1"]);
  fake.setItem("sc.contacts.gen.v1", fx.localStorage["sc.contacts.gen.v1"]);
  const C = await fresh("contacts.js", "h2");
  await C.ready;
  assert.ok(!mem.has("sc.contacts.v1") && !mem.has("sc.contacts.gen.v1"), "an interrupted migration's leftover copy is removed");
  await C.unlock(fx.PASS, { floorId: fx.FLOOR_ID });
  assert.ok(C.get("alice"));
  C.lock();

  mem.clear(); freshIdb();
  for (const [k, v] of Object.entries(fx.localStorage)) mem.set(k, v);
  fake.failWrites((k) => k.startsWith("sc.chats"));
  const H = await fresh("chats.js", "h2");
  await assert.rejects(H.unlock(fx.PASS, { floorId: fx.FLOOR_ID }), /Quota/, "a migration that cannot write is a loud failure");
  assert.strictEqual(mem.get("sc.chats.v1"), fx.localStorage["sc.chats.v1"], "…and localStorage keeps the only copy");
  fake.failWrites(null);
  await H.unlock(fx.PASS, { floorId: fx.FLOOR_ID });
  assert.ok(H.get("alice") && !mem.has("sc.chats.v1"), "…and the next attempt migrates");
  H.lock();
  // Two tabs migrating at once: this tab read "IndexedDB empty", and before its
  // copy is written the other tab has migrated AND saved a newer generation.
  // The stale localStorage copy must not overwrite it (a self-inflicted
  // rollback, refused on the next unlock as "an earlier copy restored").
  mem.clear(); freshIdb();
  for (const [k, v] of Object.entries(fx.localStorage)) mem.set(k, v);
  fake.beforeTx = (mode) => {
    if (mode !== "readwrite") return;
    fake.beforeTx = null;
    fake.setItem("sc.contacts.v1", "NEWER-FROM-OTHER-TAB");
    fake.setItem("sc.contacts.gen.v1", "NEWER-WITNESS");
  };
  const C2 = await fresh("contacts.js", "h2-race");
  await C2.ready;
  assert.strictEqual(fake.getItem("sc.contacts.v1"), "NEWER-FROM-OTHER-TAB",
    "3b: a migration racing another tab's never overwrites what that tab already moved and saved");
  assert.ok(!mem.has("sc.contacts.v1"), "…and the stale localStorage copy is dropped");
  console.log("OK  3b: an interrupted migration resolves to IndexedDB; a failed one loses nothing; a racing one never overwrites");
}

// H3: hasStore() is never "no store" before the preload has answered.
{
  mem.clear(); freshIdb();
  fake.hold(); // the preload's read waits behind a held write
  const blocker = durable.put("blocker", "1");
  const C = await fresh("contacts.js", "h3");
  const H = await fresh("chats.js", "h3");
  await settle();
  assert.strictEqual(C.hasStore(), true,
    "3b: until the IndexedDB preload settled, hasStore() says TRUE (the loud path), never 'first contact'");
  assert.strictEqual(H.hasStore(), true, "…for the chat store too");
  fake.release();
  await blocker; await C.ready; await H.ready;
  assert.strictEqual(C.hasStore(), false, "…and FALSE once it has, when there really is no store");
  assert.strictEqual(H.hasStore(), false);
  // Review round 1 (Low): a preload that FAILED is still unknown, not "no store".
  mem.clear(); freshIdb();
  globalThis.indexedDB = { open: () => { throw new Error("IndexedDB broken"); } };
  const Cf = await fresh("contacts.js", "h3-fail");
  await Cf.ready;
  assert.strictEqual(Cf.hasStore(), true,
    "review r1: a FAILED IndexedDB preload leaves hasStore() true (unknown), not 'no store'");
  fake.install();
  console.log("OK  3b: hasStore() cannot answer 'no store' before (or after a failed) IndexedDB preload");
}

// H4: the floor is advanced only after the store's durable write; a kill in
// between is not a brick.
{
  mem.clear(); floors.clear(); freshIdb();
  const ID = "b".repeat(64);
  const C = await withFloor("contacts.js", "h4");
  await C.unlock("id pass", { floorId: ID });
  const g0 = floors.get("contacts:" + ID);
  fake.hold();
  let done = false;
  const p = C.upsert({ username: "bob", ed: "RURC", mldsa: "TUxC" }).then(() => { done = true; });
  await settle();
  assert.strictEqual(done, false, "fixture: the save waits for the durable write");
  assert.strictEqual(floors.get("contacts:" + ID), g0,
    "3b: the contact-store floor is not advanced while its durable write is in flight");
  let atCommit = null;
  fake.onCommit = () => { atCommit = new Map(floors); };
  fake.release();
  await p;
  fake.onCommit = null;
  assert.strictEqual(floors.get("contacts:" + ID), g0 + 1, "…and is advanced once it completed");
  floors.clear(); for (const [k, v] of atCommit) floors.set(k, v);
  C.lock();
  const C2 = await withFloor("contacts.js", "h4-relaunch");
  await C2.unlock("id pass", { floorId: ID });
  assert.ok(C2.get("bob"), "3b: killed between the durable write and the floor advance, the store opens with the write in it");
  C2.lock();

  // Chats: same order.
  const H = await withFloor("chats.js", "h4");
  await H.unlock("id pass", { floorId: ID });
  const h0 = floors.get("chats:" + ID);
  fake.hold();
  const q = H.append("bob", { dir: "in", text: "hi", ts: 1, id: "e1" });
  await settle();
  assert.strictEqual(floors.get("chats:" + ID), h0, "3b: the chat-store floor waits for the durable write too");
  fake.release();
  await q;
  assert.ok(floors.get("chats:" + ID) > h0);
  H.lock();
  console.log("OK  3b: store floors advance only after the durable write; a kill in between opens normally");
}

// H5: no IndexedDB — the stores keep working in localStorage but never advance
// the floor (it could get ahead of data that is not on disk); and a store that
// was moved to IndexedDB is not silently recreated when IndexedDB is missing.
{
  mem.clear(); floors.clear(); freshIdb();
  fake.uninstall();
  const ID = "c".repeat(64);
  const C = await withFloor("contacts.js", "h5");
  await C.unlock("id pass", { floorId: ID });
  await C.upsert({ username: "carol", ed: "RURD", mldsa: "TUxD" });
  assert.ok(mem.has("sc.contacts.v1"), "without IndexedDB the store falls back to localStorage");
  assert.strictEqual(floors.has("contacts:" + ID), false,
    "3b: …and the native floor is neither armed nor advanced (it could otherwise get ahead of the data)");
  C.lock();
  await C.unlock("id pass", { floorId: ID });
  assert.ok(C.get("carol"), "…and it reopens (no brick)");
  C.lock();
  const H = await withFloor("chats.js", "h5");
  await H.unlock("id pass", { floorId: ID });
  await H.append("carol", { dir: "in", text: "hi", ts: 1, id: "e1" });
  assert.ok(mem.has("sc.chats.v1") && !floors.has("chats:" + ID),
    "3b: the chat store likewise falls back to localStorage without touching its floor");
  H.lock();
  // Marker says the store lives in IndexedDB, which is gone: loud, not fresh.
  mem.clear();
  mem.set("sc.contacts.idb.v1", "1");
  const C3 = await fresh("contacts.js", "h5-marker");
  assert.strictEqual(C3.hasStore(), true, "a moved store is still expected");
  await assert.rejects(C3.unlock("id pass"), (e) => e.code === "NO_DURABLE_STORAGE",
    "3b: a store moved to IndexedDB is not silently recreated when IndexedDB is unavailable");
  fake.install();
  console.log("OK  3b: without IndexedDB the stores never advance the floor; a moved store is never silently recreated");
}

// H6: wipe() removes the IndexedDB records and the marker.
{
  mem.clear(); freshIdb();
  const C = await fresh("contacts.js", "h6");
  await C.unlock("id pass");
  assert.ok(fake.getItem("sc.contacts.v1") && mem.has("sc.contacts.idb.v1"));
  await C.wipe();
  assert.ok(!fake.getItem("sc.contacts.v1") && !fake.getItem("sc.contacts.gen.v1") && !mem.has("sc.contacts.idb.v1"),
    "3b: wipe() deletes the store from IndexedDB, with its marker");
  assert.strictEqual(C.hasStore(), false);
  // Review round 1 (Low): IndexedDB emptied (eviction / deletion) while the
  // marker survives — a loud DELETED refusal, not a fresh pin-less store.
  await C.unlock("id pass");
  C.lock();
  fake.clear();
  await assert.rejects(C.unlock("id pass"), (e) => e.code === "DELETED_CONTACTS_ADOPTION",
    "review r1: an emptied IndexedDB beside the moved-marker is a loud DELETED refusal (contacts)");
  const H = await fresh("chats.js", "h6");
  await H.unlock("id pass");
  H.lock();
  fake.clear();
  await assert.rejects(H.unlock("id pass"), (e) => e.code === "DELETED_CHATS_ADOPTION",
    "review r1: …and for the chat store");
  assert.deepStrictEqual(await H.unlock("id pass", { adoptDeleted: true }), { created: true }, "…with the explicit override");
  H.lock();
  console.log("OK  3b: wipe() clears IndexedDB; an emptied IndexedDB with the marker left refuses loudly");
}

console.log("\nAll durable-storage checks passed.");
process.exit(0);
