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
    assert.strictEqual(fake.getItem(k), fx.localStorage[k], `${fx.mode}: ${k} is in IndexedDB, byte for byte`);
  }
  // The blobs leave localStorage; the witnesses stay there as a MIRROR (review
  // round 2, L-3: a downgraded client then refuses loudly instead of starting
  // a fresh, pin-less store).
  for (const k of ["sc.contacts.v1", "sc.chats.v1"]) assert.strictEqual(mem.get(k), undefined, `${fx.mode}: ${k} moved out of localStorage`);
  if (!process.env.R2_ONLY) {
    for (const k of ["sc.contacts.gen.v1", "sc.chats.gen.v1"]) assert.strictEqual(mem.get(k), fx.localStorage[k], `${fx.mode}: ${k} mirrored in localStorage`);
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
  assert.ok(!mem.has("sc.contacts.v1") && !mem.has("sc.chats.v1") &&
    (process.env.R2_ONLY !== undefined || mem.get("sc.contacts.gen.v1") === fake.getItem("sc.contacts.gen.v1")),
    `${fx.mode}: later writes go to IndexedDB (localStorage holds only the witness mirror, kept current)`);
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
  assert.ok(!mem.has("sc.contacts.v1"), "an interrupted migration's leftover (identical) copy is removed");
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

// ============================================================================
// R2. Review round 2 (coordinator's pentest of c0f6cd6)
// ============================================================================
const V031C = (tag) => import(`./v031-contacts.test.mjs?${tag}-${gen++}`);
const V031H = (tag) => import(`./v031-chats.test.mjs?${tag}-${gen++}`);
// R2_ONLY=<id> runs a single round-2 block (to show each one RED on its own).
const r2 = (id) => !process.env.R2_ONLY || process.env.R2_ONLY === id;

// L-1: two overlapping saves on Android. Save 2 used to ARM the floor to the
// generation save 1 was still writing (its strict transaction in flight): a
// kill then left floor N+1 over durable N — "OLDER than this device
// recorded", no override. persist() is now serialized per store and the floor
// is only ever armed/advanced at a generation whose durable write completed.
for (const mod of r2("l1") ? ["chats.js", "contacts.js"] : []) {
  mem.clear(); floors.clear(); freshIdb();
  const ID = "e".repeat(64);
  const H = await withFloor(mod, "r2-l1");
  await H.unlock("id pass", { floorId: ID });
  if (mod === "chats.js") await H.append("bob", { dir: "in", text: "a", ts: 1, id: "e0" });
  else await H.upsert({ username: "bob", ed: "RURC", mldsa: "TUxC" });
  const committed = new Map(fake.mem);
  const key = (mod === "chats.js" ? "chats:" : "contacts:") + ID;
  const onDisk = floors.get(key);
  fake.hold();
  const p1 = mod === "chats.js" ? H.append("bob", { dir: "in", text: "b", ts: 2, id: "e1" }) : H.upsert({ username: "carol", ed: "RURD", mldsa: "TUxD" });
  const p2 = mod === "chats.js" ? H.markSeen("alice", "e2") : H.upsert({ username: "dave", ed: "RURE", mldsa: "TUxE" });
  p1.catch(() => {}); p2.catch(() => {});
  await settle(50);
  assert.strictEqual(floors.get(key), onDisk,
    `review r2 L-1 (${mod}): with a save's durable write in flight, a second save does not move the floor past the data`);
  // Kill now: the held commits never land.
  const snapFloors = new Map(floors);
  freshIdb(); for (const [k, v] of committed) fake.mem.set(k, v);
  floors.clear(); for (const [k, v] of snapFloors) floors.set(k, v);
  const R = await withFloor(mod, "r2-l1-relaunch");
  assert.deepStrictEqual(await R.unlock("id pass", { floorId: ID }), { created: false },
    `review r2 L-1 (${mod}): killed with two saves in flight, the store reopens (no floor-ahead brick)`);
  R.lock();
}
console.log("OK  review r2 L-1: overlapping saves never put the floor ahead of durable data (contacts + chats)");

// L-1 (lead): out-of-order encryption. The older snapshot used to commit LAST
// (and the witness was sealed from the live generation) — IndexedDB regressed
// under an advanced floor, refused even without a crash.
if (r2("reorder")) {
  // Save 1's encryption is held until save 2 has been STARTED (and, unordered,
  // has finished): save 1's snapshot is then the older one. It must not be the
  // one that commits last.
  for (const mod of ["chats.js", "contacts.js"]) {
    mem.clear(); floors.clear(); freshIdb();
    const ID = "f".repeat(64);
    const H = await withFloor(mod, "r2-reorder");
    await H.unlock("id pass", { floorId: ID });
    const change = (i) => (mod === "chats.js"
      ? H.append("bob", { dir: "in", text: "m" + i, ts: i, id: "e" + i })
      : H.upsert({ username: "u" + i, ed: "RUQ" + i, mldsa: "TUw" + i }));
    await change(0);
    const orig = crypto.subtle.encrypt.bind(crypto.subtle);
    let started, release;
    const slowStarted = new Promise((r) => { started = r; });
    const gate = new Promise((r) => { release = r; });
    let first = true;
    crypto.subtle.encrypt = async (...a) => {
      const slow = first; first = false;
      if (slow) { started(); await gate; }
      return orig(...a);
    };
    const p1 = change(1);
    await slowStarted;              // save 1 holds its (older) snapshot…
    const p2 = change(2);            // …while save 2 starts with the newer one
    await settle(40);
    release();
    await Promise.allSettled([p1, p2]);
    crypto.subtle.encrypt = orig;
    H.lock();
    const R = await withFloor(mod, "r2-reorder-r");
    await R.unlock("id pass", { floorId: ID });
    if (mod === "chats.js") {
      assert.deepStrictEqual(R.get("bob").messages.map((m) => m.text), ["m0", "m1", "m2"],
        "review r2 L-1 (chats): overlapping saves commit in order — the newest state is the one on disk");
    } else {
      assert.ok(R.get("u1") && R.get("u2"),
        "review r2 L-1 (contacts): overlapping saves commit in order — the newest state is the one on disk");
    }
    R.lock();
  }
  // A save that FAILED must not move the counter: the next save used to arm
  // the floor at the generation that never reached disk (floor ahead of data).
  for (const mod of ["chats.js", "contacts.js"]) {
    mem.clear(); floors.clear(); freshIdb();
    const ID = "8".repeat(64);
    const key = (mod === "chats.js" ? "chats:" : "contacts:") + ID;
    const H = await withFloor(mod, "r2-fail");
    await H.unlock("id pass", { floorId: ID });
    const change = (i) => (mod === "chats.js"
      ? H.append("bob", { dir: "in", text: "m" + i, ts: i, id: "e" + i })
      : H.upsert({ username: "u" + i, ed: "RUQ" + i, mldsa: "TUw" + i }));
    const onDisk = floors.get(key);
    fake.failWrites((k) => k.startsWith(mod === "chats.js" ? "sc.chats" : "sc.contacts"));
    await assert.rejects(change(1));
    fake.failWrites(null);
    fake.hold();
    const p = change(2); p.catch(() => {});
    await settle(40);
    assert.strictEqual(floors.get(key), onDisk,
      `review r2 L-1 (${mod}): after a failed save the next one does not arm the floor at the generation that never reached disk`);
    fake.release();
    await p.catch(() => {});
    H.lock();
  }
  console.log("OK  review r2 L-1: out-of-order encryption cannot commit an older snapshot last; a failed save moves no counter");
}

// L-2: a v0.3.1 tab left open across the upgrade. The new tab migrated the
// store; the old tab (still unlocked) removed Bob — revoking his pin — in
// localStorage; the next new-version load deleted that write as "the copy
// goes" and Bob came back. Now the old tab's write is either refused (STALE,
// when the new code wrote since) or adopted when it is the newer generation.
if (r2("l2")) {
  const PASSX = "identity passphrase r2";
  const bob = { username: "bob", ed: "RUQx", mldsa: "TUwx", verified: true };
  // (a) the old tab writes after the migration, nothing newer in IndexedDB.
  mem.clear(); freshIdb();
  const oldTab = await V031C("r2-l2a");
  await oldTab.unlock(PASSX);
  await oldTab.upsert(bob);
  const newTab = await fresh("contacts.js", "r2-l2a-new");
  await newTab.ready;
  await oldTab.remove("bob");
  const reload = await fresh("contacts.js", "r2-l2a-reload");
  await reload.unlock(PASSX);
  assert.strictEqual(reload.get("bob"), null,
    "review r2 L-2: an old tab's newer write (Remove = pin revocation) is adopted, not silently deleted");
  reload.lock();
  // (b) the new code wrote since: the old tab's save is refused as STALE.
  mem.clear(); freshIdb();
  const oldB = await V031C("r2-l2b");
  await oldB.unlock(PASSX);
  await oldB.upsert(bob);
  const newB = await fresh("contacts.js", "r2-l2b-new");
  await newB.unlock(PASSX);
  await newB.upsert({ username: "carol", ed: "RUQy", mldsa: "TUwy" });
  await assert.rejects(oldB.remove("bob"), (e) => e.code === "STALE",
    "review r2 L-2: once the new code has written, an old tab's save is refused loudly (STALE)");
  // (c) an OLDER localStorage copy (a replayed snapshot, or an old tab that
  // lost the race) never replaces the newer store — and the drop is reported.
  mem.clear(); freshIdb();
  const n3 = await fresh("contacts.js", "r2-l2c");
  await n3.unlock(PASSX);
  const oldBlob = fake.getItem("sc.contacts.v1");
  const oldWit = fake.getItem("sc.contacts.gen.v1");
  await n3.upsert(bob);
  n3.lock();
  mem.set("sc.contacts.v1", oldBlob); mem.set("sc.contacts.gen.v1", oldWit);
  const n3r = await fresh("contacts.js", "r2-l2c-r");
  assert.deepStrictEqual(await n3r.unlock(PASSX), { created: false, conflictDropped: true },
    "review r2 L-2: an older localStorage copy is dropped, and the unlock says so");
  assert.ok(n3r.get("bob") && !mem.has("sc.contacts.v1"), "…the newer IndexedDB store stands");
  n3r.lock();
  // (d) I-1: marker present, IndexedDB empty, a localStorage copy present —
  // not migrated back in silently: the loud DELETED refusal.
  fake.clear();
  mem.set("sc.contacts.v1", oldBlob);
  await assert.rejects((await fresh("contacts.js", "r2-l2d")).unlock(PASSX), (e) => e.code === "DELETED_CONTACTS_ADOPTION",
    "review r2 I-1: marker + localStorage copy + empty IndexedDB is a loud refusal, not a silent re-migration");
  console.log("OK  review r2 L-2: an old-version tab's writes after the migration are adopted or refused, never silently dropped");
}

// L-3: downgrade after the migration. The v0.3.1 client used to find no store
// in localStorage and silently start a fresh, pin-less one (browser). It now
// finds the generation witness the new code keeps mirrored there and takes its
// own loud "store deleted" branch.
if (r2("l3")) {
  const PASSX = "identity passphrase r2 dg";
  mem.clear(); freshIdb();
  const n = await fresh("contacts.js", "r2-l3");
  await n.unlock(PASSX);
  await n.upsert({ username: "bob", ed: "RUQx", mldsa: "TUwx", verified: true });
  const h = await fresh("chats.js", "r2-l3");
  await h.unlock(PASSX);
  await h.append("bob", { dir: "in", text: "x", ts: 1, id: "e0" });
  const o = await V031C("r2-l3-old");
  assert.strictEqual(o.hasStore(), true, "review r2 L-3: a downgraded client still sees that a contact store exists");
  await assert.rejects(o.unlock(PASSX), /DELETED|refusing/,
    "review r2 L-3: a downgraded client refuses loudly instead of starting a fresh, pin-less contact store");
  const oh = await V031H("r2-l3-old");
  await assert.rejects(oh.unlock(PASSX), /DELETED|refusing/, "…and the same for the chat store");
  console.log("OK  review r2 L-3: a downgrade after the migration fails loudly (no silent pin-less store)");
}

// I-4: the "OLDER than recorded" messages name the real generation (they
// used to lock() first, which reset it, and always said "generation 0").
if (r2("i4")) {
  mem.clear(); floors.clear(); freshIdb();
  const ID = "9".repeat(64);
  const C = await withFloor("contacts.js", "r2-i4");
  await C.unlock("id pass", { floorId: ID });
  await C.upsert({ username: "bob", ed: "RURC", mldsa: "TUxC" });
  C.lock();
  const g0 = floors.get("contacts:" + ID);
  floors.set("contacts:" + ID, g0 + 5);
  const R = await withFloor("contacts.js", "r2-i4-r");
  await assert.rejects(R.unlock("id pass", { floorId: ID }), new RegExp(`generation ${g0}, device record ${g0 + 5}`),
    "review r2 I-4: the refusal names the store's actual generation, not 0");
  console.log("OK  review r2 I-4: rollback refusals name the real generation");
}

// I-6: a crash inside saveNewPad (re-import under a new passphrase) between the
// new-key blob and the durable write stranded the OLD-key durable record → a
// false "damaged or forged". A never-used record (`used: 0`) beside a pristine
// blob is now simply replaced.
if (r2("i6")) {
  mem.clear(); freshIdb();
  const A = await fresh("otp.js", "r2-i6");
  const src = await A.generatePad({ label: "i6", totalBytes: 8192, fingerBytes: new Uint8Array(0) });
  const file = await A.exportPad(src, "xfer");
  mem.clear();
  const imp1 = await A.importPad(file, "xfer");
  await A.saveNewPad(imp1, "first pass");
  mem.clear(); // the crash takes localStorage; the unused durable record survives
  const B = await fresh("otp.js", "r2-i6-b");
  const imp2 = await B.importPad(file, "xfer");
  fake.failWrites((k) => k.startsWith("sc.otp.dur."));
  await assert.rejects(B.saveNewPad(imp2, "second pass"));
  fake.failWrites(null);
  const C = await fresh("otp.js", "r2-i6-c");
  const u = await C.unlockPad(src.padId, "second pass");
  assert.strictEqual(u.record.sendOffset, 0, "review r2 I-6: the pristine pad opens (no false 'damaged or forged')");
  // …but a USED record under another key is still refused.
  fake.setItem(durKey(src.padId), JSON.stringify({ ...JSON.parse(fake.getItem(durKey(src.padId))), used: 1, ct: "AAAAAAAAAAAAAAAAAAAAAAA=" }));
  await assert.rejects((await fresh("otp.js", "r2-i6-d")).unlockPad(src.padId, "second pass"), /damaged or forged/,
    "review r2 I-6: an unreadable record that says USED is still refused");
  console.log("OK  review r2 I-6: an unused durable record stranded under an old key is replaced, a used one refused");
}

// ============================================================================
// R3. Review round 3 (pentest of f9711e7)
// ============================================================================

// F1: the REVERSE two-tab order. The old (v0.3.1) tab writes first — its CAS
// sees the mirrored witness N and puts blob+witness N+1 in localStorage; the
// new tab then saves (Remove bob) against IndexedDB alone and its mirror()
// overwrote the old tab's witness; the old tab wrote again (N+2, no STALE);
// the next unlock ADOPTED the old tab's copy — the Remove (pin revocation)
// silently undone. Now a new-code save next to a localStorage blob is refused
// (STALE) and the conflict is settled at unlock — with a notice on adoption.
if (r2("r3f1")) {
  const PASSX = "identity passphrase r3";
  const bob = { username: "bob", token: "t", ed: "RUQx", mldsa: "TUwx", ecdh: "RUMx", mlkem: "TUsx", verified: true };
  mem.clear(); freshIdb();
  const oldTab = await V031C("r3f1");
  await oldTab.unlock(PASSX);
  await oldTab.upsert(bob);
  await oldTab.savePin("user:bob", bob);
  const newTab = await fresh("contacts.js", "r3f1-new");
  await newTab.unlock(PASSX);
  await oldTab.upsert({ username: "carol", token: "t2", ed: "RUQy", mldsa: "TUwy" }); // old tab first
  await assert.rejects(newTab.remove("bob"), (e) => e.code === "STALE",
    "review r3 F1: a save beside a localStorage blob an old-version tab wrote is refused (STALE), not committed over it");
  const reload = await fresh("contacts.js", "r3f1-reload");
  const r = await reload.unlock(PASSX);
  assert.strictEqual(r.conflictAdopted, true, "review r3 F1: adopting an old tab's copy is reported (conflictAdopted)");
  assert.ok(reload.get("carol"), "…the old tab's newer copy is the store");
  reload.lock();
  // Chats: the same, and the adoption of a newer old-tab chat store is covered
  // (round-3 coverage gap M3b).
  mem.clear(); freshIdb();
  const oldH = await V031H("r3f1c");
  await oldH.unlock(PASSX);
  await oldH.append("bob", { dir: "in", text: "one", ts: 1, id: "e1" });
  const newH = await fresh("chats.js", "r3f1c-new");
  await newH.unlock(PASSX);
  await oldH.append("bob", { dir: "in", text: "two", ts: 2, id: "e2" });
  await assert.rejects(newH.append("bob", { dir: "out", text: "mine", ts: 3, id: null }), (e) => e.code === "STALE",
    "review r3 F1 (chats): a save beside an old tab's localStorage blob is refused (STALE)");
  const rh = await fresh("chats.js", "r3f1c-reload");
  assert.deepStrictEqual(await rh.unlock(PASSX), { created: false, conflictAdopted: true },
    "review r3 (M3b): a newer old-tab chat store is adopted, and that is reported");
  assert.deepStrictEqual(rh.get("bob").messages.map((m) => m.text), ["one", "two"]);
  rh.lock();
  console.log("OK  review r3 F1: new-code saves beside an old tab's copy are refused (STALE); adoption is reported (contacts + chats)");
}

// F2: a localStorage-ONLY plant. Adoption was decided on the two witnesses
// alone and wrote the planted blob into IndexedDB unauthenticated: an earlier
// incarnation's pair (Forget + re-create) brought back bob's OLD pin (alarm
// inverted); a garbage blob overwrote the good store before the refusal (raw
// atob error). Now the blob must decrypt, carry the store's domain tag and the
// witness's generation, and share the IndexedDB store's salt — else it is
// dropped (reported), and IndexedDB is never touched first.
if (r2("r3f2")) {
  const PASSX = "identity passphrase r3 plant";
  mem.clear(); freshIdb();
  const a = await fresh("contacts.js", "r3f2-a");
  await a.unlock(PASSX);
  await a.upsert({ username: "bob", ed: "RUQtT0xE", mldsa: "TUwtT0xE", verified: true });
  await a.savePin("user:bob", { ed: "RUQtT0xE", mldsa: "TUwtT0xE" });
  for (let i = 0; i < 5; i++) await a.upsert({ username: "x" + i, ed: "RUQ" + i, mldsa: "TUw" + i });
  const snapBlob = fake.getItem("sc.contacts.v1"), snapWit = fake.getItem("sc.contacts.gen.v1");
  await a.wipe();
  const b = await fresh("contacts.js", "r3f2-b");
  await b.unlock(PASSX);
  await b.savePin("user:bob", { ed: "RUQtTkVX", mldsa: "TUwtTkVX" });
  b.lock();
  const good = fake.getItem("sc.contacts.v1");
  mem.set("sc.contacts.v1", snapBlob); mem.set("sc.contacts.gen.v1", snapWit);
  const r1 = await fresh("contacts.js", "r3f2-r1");
  const res = await r1.unlock(PASSX);
  assert.strictEqual(r1.getPin("user:bob").ed, "RUQtTkVX",
    "review r3 F2: an earlier incarnation's blob+witness planted in localStorage is NOT adopted (the current pin stands)");
  assert.strictEqual(res.conflictDropped, true, "…it is dropped, and reported");
  assert.strictEqual(fake.getItem("sc.contacts.v1"), good, "…and IndexedDB is untouched");
  r1.lock();
  // Garbage blob + a genuine higher witness: dropped, IndexedDB untouched,
  // no raw decoder error.
  mem.set("sc.contacts.v1", "{\"v\":4,\"garbage\":1}"); mem.set("sc.contacts.gen.v1", snapWit);
  const r2m = await fresh("contacts.js", "r3f2-r2");
  const res2 = await r2m.unlock(PASSX);
  assert.strictEqual(res2.conflictDropped, true, "review r3 F2: a garbage localStorage blob is dropped, not adopted");
  assert.strictEqual(fake.getItem("sc.contacts.v1"), good, "review r3 F2: …and the good IndexedDB store is never overwritten");
  r2m.lock();
  // Same store (same salt), a genuine higher witness, but a blob of ANOTHER
  // generation beside it (a mismatched pair): dropped too.
  mem.clear(); freshIdb();
  const c = await fresh("contacts.js", "r3f2-c");
  await c.unlock(PASSX);
  const b0 = fake.getItem("sc.contacts.v1");                         // gen g
  await c.upsert({ username: "q1", ed: "RUQq", mldsa: "TUwq" });    // g+1
  const sIdb1 = new Map(fake.mem);
  await c.upsert({ username: "q2", ed: "RUQr", mldsa: "TUwr" });    // g+2
  const w2 = fake.getItem("sc.contacts.gen.v1");
  c.lock();
  freshIdb(); for (const [k, v] of sIdb1) fake.mem.set(k, v);       // IndexedDB at g+1
  mem.set("sc.contacts.v1", b0); mem.set("sc.contacts.gen.v1", w2);  // blob g, witness g+2
  const r3m = await fresh("contacts.js", "r3f2-r3");
  assert.strictEqual((await r3m.unlock(PASSX)).conflictDropped, true,
    "review r3 F2: a localStorage blob whose generation is not its witness's is dropped (not adopted on the witness alone)");
  assert.ok(r3m.get("q1"), "…the IndexedDB store stands");
  assert.strictEqual(fake.getItem("sc.contacts.v1"), sIdb1.get("sc.contacts.v1"), "…untouched");
  r3m.lock();
  // The witness record itself planted as the "blob" (same key, same salt, its
  // own gen matches): only the domain tag tells it apart — dropped.
  mem.set("sc.contacts.v1", w2); mem.set("sc.contacts.gen.v1", w2);
  const r4m = await fresh("contacts.js", "r3f2-r4");
  assert.strictEqual((await r4m.unlock(PASSX)).conflictDropped, true,
    "review r3 F2: a record that is not a contact store (the witness, by domain tag) is never adopted as one");
  assert.strictEqual(fake.getItem("sc.contacts.v1"), sIdb1.get("sc.contacts.v1"));
  r4m.lock();
  console.log("OK  review r3 F2: a planted localStorage copy is authenticated (domain, generation, salt) before adoption; IndexedDB untouched otherwise");
}

// Coverage (round 3): an EQUAL-generation localStorage copy is not adopted
// (M3: `>` → `>=`).
if (r2("r3cov")) {
  const PASSX = "identity passphrase r3 cov";
  mem.clear(); freshIdb();
  const c = await fresh("contacts.js", "r3cov");
  await c.unlock(PASSX);
  await c.upsert({ username: "base", ed: "RUQb", mldsa: "TUwb" });
  const sIdb = new Map(fake.mem);
  await c.upsert({ username: "fromB", ed: "RUQc", mldsa: "TUwc" });
  const blobB = fake.getItem("sc.contacts.v1"), witB = fake.getItem("sc.contacts.gen.v1");
  c.lock();
  freshIdb(); for (const [k, v] of sIdb) fake.mem.set(k, v);
  const c2 = await fresh("contacts.js", "r3cov-2");
  await c2.unlock(PASSX);
  await c2.upsert({ username: "fromC", ed: "RUQd", mldsa: "TUwd" });
  c2.lock();
  mem.set("sc.contacts.v1", blobB); mem.set("sc.contacts.gen.v1", witB);
  const r = await fresh("contacts.js", "r3cov-r");
  assert.strictEqual((await r.unlock(PASSX)).conflictDropped, true,
    "review r3 (M3): a localStorage copy at the SAME generation is dropped, not adopted");
  assert.ok(r.get("fromC") && !r.get("fromB"), "…the IndexedDB store stands");
  r.lock();

  // M8: a save still in flight when the store is locked must not touch the
  // floor (floorKey is gone) or revive the counter.
  mem.clear(); floors.clear(); freshIdb();
  const ID = "7".repeat(64);
  const L = await withFloor("contacts.js", "r3cov-lock");
  await L.unlock("id pass", { floorId: ID });
  const before = [...floors.keys()].sort();
  fake.hold();
  const p = L.upsert({ username: "late", ed: "RUQl", mldsa: "TUwl" });
  p.catch(() => {});
  await settle(30);
  L.lock();
  fake.release();
  await p.catch(() => {});
  assert.deepStrictEqual([...floors.keys()].sort(), before,
    "review r3 (M8): a save that completes after lock() does not bump any floor (no floor under a null id)");
  console.log("OK  review r3 coverage: equal-generation copies are dropped; a save finishing after lock() touches no floor");
}

// I-6 coverage (M5b/M5c): the stranded-record replacement also requires a
// zero watermark and an un-exported blob.
if (r2("r3i6")) {
  const enc8 = new TextEncoder();
  const b64s = (u) => Buffer.from(u).toString("base64");
  const u8 = (s) => Uint8Array.from(Buffer.from(s, "base64"));
  const setup = async (tag) => {
    mem.clear(); freshIdb();
    const A = await fresh("otp.js", tag);
    const src = await A.generatePad({ label: "i6b", totalBytes: 8192, fingerBytes: new Uint8Array(0) });
    const file = await A.exportPad(src, "xfer");
    mem.clear();
    await A.saveNewPad(await A.importPad(file, "xfer"), "first pass");
    mem.clear();
    const B = await fresh("otp.js", tag + "-b");
    const imp = await B.importPad(file, "xfer");
    fake.failWrites((k) => k.startsWith("sc.otp.dur."));
    await assert.rejects(B.saveNewPad(imp, "second pass"));
    fake.failWrites(null);
    const outer = JSON.parse(mem.get("sc.otp.pad.v1." + src.padId));
    const base = await crypto.subtle.importKey("raw", enc8.encode("second pass"), "PBKDF2", false, ["deriveKey"]);
    const key = await crypto.subtle.deriveKey({ name: "PBKDF2", salt: u8(outer.kdf.salt), iterations: outer.kdf.iters, hash: "SHA-256" },
      base, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
    return { src, key, outer };
  };
  // (a) a watermark sealed under the new key that says the pad was used.
  {
    const { src, key } = await setup("r3i6a");
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key,
      enc8.encode(JSON.stringify({ d: "secure-chat/otp-watermark/v1", padId: src.padId, send: 0, recv: 64 }))));
    mem.set("sc.otp.wm.v1." + src.padId, JSON.stringify({ iv: b64s(iv), ct: b64s(ct) }));
    await assert.rejects((await fresh("otp.js", "r3i6a-u")).unlockPad(src.padId, "second pass"), /damaged or forged/,
      "review r3 (M5b): a stranded record is not replaced when the watermark says the pad was used");
  }
  // (b) the blob says exported.
  {
    const { src, key, outer } = await setup("r3i6b");
    const inner = JSON.parse(new TextDecoder().decode(await crypto.subtle.decrypt({ name: "AES-GCM", iv: u8(outer.iv) }, key, u8(outer.ct))));
    inner.exported = true;
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, enc8.encode(JSON.stringify(inner))));
    mem.set("sc.otp.pad.v1." + src.padId, JSON.stringify({ ...outer, iv: b64s(iv), ct: b64s(ct) }));
    await assert.rejects((await fresh("otp.js", "r3i6b-u")).unlockPad(src.padId, "second pass"), /damaged or forged/,
      "review r3 (M5c): a stranded record is not replaced when the blob says the pad was exported");
  }
  console.log("OK  review r3 coverage: the I-6 replacement also needs a zero watermark and an un-exported blob");
}

// Infos (round 3): (a) a Forget during an in-flight save must not put the
// marker / witness mirror back after wipe(); (b) a failing mirror write
// (quota) after the IndexedDB commit must not fail the committed save.
if (r2("r3info")) {
  mem.clear(); freshIdb();
  const C = await fresh("contacts.js", "r3info");
  await C.unlock("id pass");
  fake.hold();
  const p = C.upsert({ username: "late", ed: "RUQl", mldsa: "TUwl" });
  p.catch(() => {});
  await settle(30);
  const w = C.wipe();
  fake.release();
  await p.catch(() => {}); await w;
  assert.ok(!mem.has("sc.contacts.idb.v1") && !mem.has("sc.contacts.gen.v1"),
    "review r3 info: a save in flight across wipe() does not put the marker or the witness mirror back");
  assert.strictEqual(C.hasStore(), false, "…so the next unlock is a clean first run, not a false DELETED");

  mem.clear(); freshIdb();
  const D = await fresh("contacts.js", "r3info-q");
  await D.unlock("id pass");
  const realSet = globalThis.localStorage.setItem;
  globalThis.localStorage.setItem = (k, v) => { if (k === "sc.contacts.gen.v1") throw new Error("QuotaExceededError"); return realSet(k, v); };
  try {
    await D.upsert({ username: "q", ed: "RUQq", mldsa: "TUwq" });
  } finally {
    globalThis.localStorage.setItem = realSet;
  }
  await D.upsert({ username: "q2", ed: "RUQr", mldsa: "TUwr" }); // no false STALE
  assert.ok(D.get("q") && D.get("q2"), "review r3 info: a failed mirror write does not fail the committed save or the next one");
  D.lock();
  console.log("OK  review r3 info: wipe() during a save stays wiped; a mirror write failure is not a failed save");
}

console.log("\nAll durable-storage checks passed.");
process.exit(0);
