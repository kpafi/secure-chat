// M-01 regression: a full old encrypted-pad blob restore (rolling sendOffset
// back to reuse consumed keystream) is refused by the separate high-water
// tripwire. Run: node otp-rollback.test.mjs
import assert from "node:assert";
import { readFile } from "node:fs/promises";

const mem = new Map();
globalThis.localStorage = {
  getItem: (k) => (mem.has(k) ? mem.get(k) : null),
  setItem: (k, v) => mem.set(k, String(v)),
  removeItem: (k) => mem.delete(k),
};

const otp = await import("./otp.js");

const PASS = "pad-pass";
const rec = await otp.generatePad({ label: "rollback", totalBytes: 64 * 1024, fingerBytes: new Uint8Array(0) });
const atRest = await otp.saveNewPad(rec, PASS);

// Snapshot the pristine (offset 0) blob — this is what an attacker would keep.
const padK = "sc.otp.pad.v1." + rec.padId;
const oldBlob = localStorage.getItem(padK);

// Consume some pad: advance sendOffset and persist (bumps the high-water).
rec.sendOffset = 500;
await otp.savePadProgress(rec, atRest);
assert.strictEqual(otp.padMeta(rec.padId).padId, rec.padId);
const unlockedOk = await otp.unlockPad(rec.padId, PASS);
assert.strictEqual(unlockedOk.record.sendOffset, 500, "current pad unlocks normally");
console.log("OK  pad unlocks at its true (advanced) offset");

// Attacker restores the OLD blob (offset 0) wholesale — valid GCM ciphertext.
localStorage.setItem(padK, oldBlob);
await assert.rejects(otp.unlockPad(rec.padId, PASS), /rolled back/, "rolled-back blob must be refused");
console.log("OK  M-01: a wholesale old-blob restore (offset rollback) is refused");

// Pentest 2026-07-26 P-05: forgetPad must KEEP the tripwire. It used to delete
// it, which made "Forget pad" the easiest route to a two-time pad: an export
// file is always pristine, and the duplicate-import guard is an index lookup
// that forgetPad clears — so forget + re-import the same file resurrected the
// pad at offset 0 with a clean watermark, and every later message reused
// keystream the peer had already seen.
otp.forgetPad(rec.padId);
assert.ok(
  localStorage.getItem("sc.otp.wm.v1." + rec.padId) !== null,
  "P-05: the authenticated watermark survives forgetPad so a re-import can be refused",
);
assert.ok(otp.padWasUsed(rec.padId), "P-05: pad is still known to have been used here");
console.log("OK  P-05: high-water tripwire SURVIVES forgetPad");

// ...and re-importing that same pad file is refused rather than rewinding it.
const freshPad = await otp.generatePad({ label: "reimport", totalBytes: 1024, fingerBytes: new Uint8Array(0) });
freshPad.padId = rec.padId; // same pad identity as the one already consumed here
const file = await otp.exportPad(freshPad, "transfer-pass");
await assert.rejects(
  otp.importPad(file, "transfer-pass"), /already been used/,
  "P-05: re-importing a pad already consumed on this device is refused",
);
console.log("OK  P-05: re-import of an already-consumed pad is refused");

// P-01 (and its own fix-review follow-up): the stored blob must authenticate its
// own metadata, and must not be downgradable to the legacy format. The first cut
// of the P-01 fix keyed "is this legacy?" on the OUTER `v` byte, so deleting `v`
// handed `role` back to an attacker — a full two-time pad. The discriminator is
// now the presence of `padId` INSIDE the ciphertext, which cannot be forged.
const p = await otp.generatePad({ label: "authmeta", totalBytes: 8192, fingerBytes: new Uint8Array(0) });
p.role = 1;
const pAtRest = await otp.saveNewPad(p, PASS);
p.sendOffset = 4000;
await otp.savePadProgress(p, pAtRest);
const pKey = "sc.otp.pad.v1." + p.padId;

const outer = JSON.parse(localStorage.getItem(pKey));
assert.deepStrictEqual(
  Object.keys(outer).sort(), ["ct", "iv", "kdf", "v"],
  "P-01: only version + KDF params + ciphertext may sit outside the AEAD",
);

// Downgrade attempt: strip "v", re-attach attacker-chosen outer metadata.
delete outer.v;
outer.padId = p.padId; outer.label = "x"; outer.regionSize = p.regionSize; outer.role = 0;
localStorage.setItem(pKey, JSON.stringify(outer));
const afterDowngrade = await otp.unlockPad(p.padId, PASS);
assert.strictEqual(afterDowngrade.record.role, 1, "P-01: outer 'role' must be ignored even with 'v' stripped");
console.log("OK  P-01: a v2 blob cannot be downgraded to the legacy path");

// Re-keying that same blob under a fresh id must still be refused. (The id is
// well-formed on purpose: since F-ATREST-001 a malformed one is refused one
// step earlier, and this test is about the storage-key binding, not the shape.)
const FORGED_ID = "0123456789abcdef0123456789abcdef";
const copy = JSON.parse(localStorage.getItem(pKey));
delete copy.v; copy.padId = FORGED_ID; copy.regionSize = p.regionSize; copy.role = 0;
localStorage.setItem("sc.otp.pad.v1." + FORGED_ID + "", JSON.stringify(copy));
await assert.rejects(
  otp.unlockPad(FORGED_ID, PASS), /does not match its storage key/,
  "P-01: a blob re-keyed under a fresh padId must be refused",
);
console.log("OK  P-01: padId re-key (M-01 watermark bypass) is refused");

// --- Pentest 2026-07-27 H-3: the watermark is authenticated + fails closed ---
// The tripwire used to be one PLAINTEXT decimal string, and its reader returned
// 0 for a missing value. So the "restore just the pad blob" attack M-01 was
// built to catch cost one extra removeItem: two messages then encrypted at the
// same offset and C1 XOR C2 = P1 XOR P2 handed over a plaintext.
{
  const h = await otp.generatePad({ label: "h3", totalBytes: 8192, fingerBytes: new Uint8Array(0) });
  const hAtRest = await otp.saveNewPad(h, PASS);
  const hKey = "sc.otp.pad.v1." + h.padId;
  const pristine = localStorage.getItem(hKey);
  h.sendOffset = 85;
  await otp.savePadProgress(h, hAtRest);

  // The watermark is opaque at rest: no offset readable or editable in the clear.
  //
  // This was `!wmRaw.includes("85")` — a substring search over random base64
  // ciphertext, so it failed ~1.4% of runs whenever "85" turned up by chance
  // (caught 2026-07-28 while re-running the suite; pre-existing, not from the
  // bf6bcd2 work). A flaky assertion on a security property is worse than none:
  // it trains you to re-run until green. The property it was reaching for is
  // structural and deterministic — the record carries ONLY iv+ct, so there is no
  // plaintext field to read or edit, whatever the ciphertext happens to spell.
  const wmRaw = localStorage.getItem("sc.otp.wm.v1." + h.padId);
  assert.ok(wmRaw, "the watermark exists after a save");
  assert.deepStrictEqual(Object.keys(JSON.parse(wmRaw)).sort(), ["ct", "iv"],
    "watermark stores only iv+ct — no plaintext offset field");

  // Restore the pristine blob AND delete the watermark — the reported PoC.
  localStorage.setItem(hKey, pristine);
  localStorage.removeItem("sc.otp.wm.v1." + h.padId);
  await assert.rejects(
    otp.unlockPad(h.padId, PASS), /rollback record for this pad is missing/,
    "H-3: deleting the watermark must FAIL CLOSED, not reset the tripwire to 0",
  );

  // Forging one is not an option either: it is AEAD under the pad's own key.
  localStorage.setItem("sc.otp.wm.v1." + h.padId, JSON.stringify({
    iv: "AAAAAAAAAAAAAAAA", ct: "AAAAAAAAAAAAAAAAAAAAAAA=",
  }));
  await assert.rejects(
    otp.unlockPad(h.padId, PASS), /damaged or forged/,
    "H-3: a forged watermark is refused",
  );
}
console.log("OK  H-3: deleting or forging the OTP watermark fails closed");

// --- Pentest 2026-07-27 M-7: the RECEIVE watermark rolls back too ------------
// bumpHW only ever advanced on sendOffset, and the tripwire only checked
// sendOffset. A restore taken after a stretch of RECEIVING ONLY therefore left
// sendOffset untouched — nothing fired — while recvHighWater fell back to zero
// and every already-delivered frame re-authenticated as fresh.
{
  const m = await otp.generatePad({ label: "m7", totalBytes: 8192, fingerBytes: new Uint8Array(0) });
  const mAtRest = await otp.saveNewPad(m, PASS);
  const mKey = "sc.otp.pad.v1." + m.padId;

  m.sendOffset = 200;            // some sending, then…
  await otp.savePadProgress(m, mAtRest);
  const beforeReceiving = localStorage.getItem(mKey);

  m.recvHighWater = 119;         // …a stretch of receiving only
  await otp.savePadProgress(m, mAtRest);
  assert.strictEqual((await otp.unlockPad(m.padId, PASS)).record.recvHighWater, 119);

  // Restore the copy taken before the receiving: sendOffset is IDENTICAL, so
  // the old send-only tripwire saw nothing wrong.
  localStorage.setItem(mKey, beforeReceiving);
  await assert.rejects(
    otp.unlockPad(m.padId, PASS), /receive state was rolled back/,
    "M-7: a receive-side rollback is refused even when sendOffset is unchanged",
  );
}
console.log("OK  M-7: OTP recvHighWater rollback (replay across a reload) is refused");

// --- Pentest 2026-07-27 L-3: `exported` is authenticated ---------------------
// The double-export gate lived in the plaintext index, so clearing one field
// removed the only warning that stops one pristine pad going to two importers.
{
  const e = await otp.generatePad({ label: "l3", totalBytes: 8192, fingerBytes: new Uint8Array(0) });
  const eAtRest = await otp.saveNewPad(e, PASS);
  const unlocked = await otp.unlockPad(e.padId, PASS);
  assert.strictEqual(unlocked.record.exported, false, "a fresh pad is not exported");

  await otp.markExported(unlocked.record, unlocked.atRest);
  assert.strictEqual((await otp.unlockPad(e.padId, PASS)).record.exported, true,
    "the flag round-trips through the AEAD");

  // Clear the plaintext index copy — the render cache, not the trust source.
  const idx = JSON.parse(localStorage.getItem("sc.otp.index.v1"));
  for (const entry of idx) {
    if (entry.padId === e.padId) entry.exported = false;
  }
  localStorage.setItem("sc.otp.index.v1", JSON.stringify(idx));
  assert.strictEqual(otp.padMeta(e.padId).exported, false, "the index copy really was cleared");
  assert.strictEqual((await otp.unlockPad(e.padId, PASS)).record.exported, true,
    "L-3: clearing the plaintext index does NOT disarm the double-export warning");
}
console.log("OK  L-3: the double-export gate is authenticated, not a plaintext flag");

// --- v2 -> v3 migration of a pad that was ALREADY USED before the fix -------
// Found on-device 2026-07-28: every check above builds its pad with the CURRENT
// generatePad(), so the blob is v3 with an authenticated watermark from birth.
// Nothing here ever saw a genuine pre-fix pad, and the shipped code refused one:
// `knownUsedHere` counted the legacy PLAINTEXT watermark as proof that a v3
// record must exist — but that watermark is written only by pre-fix code, so it
// is present on exactly the pads that legitimately have none yet. Result: a
// pre-fix pad that had sent even one message was permanently unusable.
//
// Reconstructs a real pre-fix pad rather than asserting on the guard directly:
// re-encrypt the inner record WITHOUT the v3-only fields under the same at-rest
// key, stamp `v:2`, drop both post-fix artifacts, and leave the legacy
// plaintext watermark the old code would have written.
const _enc = new TextEncoder();
const _dec = new TextDecoder();
const _b64 = (u8) => Buffer.from(u8).toString("base64");
const _unb64 = (s) => new Uint8Array(Buffer.from(s, "base64"));

// Rewrite a pad's stored blob into the genuine pre-fix (v2) shape: the same
// inner record minus the v3-only fields, re-encrypted under the same at-rest
// key. `mutate` may adjust the inner record first (e.g. to stage a rollback).
// Verified against `git show e86a60b:client/otp.js` — the pre-fix writePadBlob
// emits exactly padId,label,regionSize,role,createdAt,bytes,sendOffset,
// recvHighWater, in that order, which is what stripping the three v3 fields
// from the current inner record produces.
// Re-seal a pad's CURRENT (v3) inner record under the same key after `mutate`,
// keeping the outer shape (and `v`) as it is. For modelling a blob written by
// an earlier v3 build, e.g. one that predates `derivedFloors`.
async function resealInner(padId, key, mutate, outerPatch = {}) {
  const k = "sc.otp.pad.v1." + padId;
  const cur = JSON.parse(localStorage.getItem(k));
  const inner = JSON.parse(_dec.decode(await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: _unb64(cur.iv) }, key, _unb64(cur.ct),
  )));
  mutate(inner);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt(
    { name: "AES-GCM", iv }, key, _enc.encode(JSON.stringify(inner)),
  ));
  localStorage.setItem(k, JSON.stringify({ ...cur, iv: _b64(iv), ct: _b64(ct), ...outerPatch }));
}

// The text of the `Object.defineProperty(window, '<name>', …)` CALL in the app's
// injected script, paren-matched — never "everything after the first mention of
// the name", which a comment can satisfy (Package 3, F-P7-A5).
function definePropertyCall(src, name) {
  const at = src.indexOf(`Object.defineProperty(window, '${name}'`);
  assert.notStrictEqual(at, -1, `the app must publish ${name} with Object.defineProperty`);
  let d = 0;
  for (let i = src.indexOf("(", at); i < src.length; i++) {
    if (src[i] === "(") d++;
    else if (src[i] === ")" && --d === 0) return src.slice(at, i + 1);
  }
  throw new Error("unbalanced defineProperty call for " + name);
}

async function makeV2Blob(padId, key, mutate) {
  const k = "sc.otp.pad.v1." + padId;
  const cur = JSON.parse(localStorage.getItem(k));
  const inner = JSON.parse(_dec.decode(await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: _unb64(cur.iv) }, key, _unb64(cur.ct),
  )));
  delete inner.hwSend;    // v3-only: the authenticated watermark mirror
  delete inner.hwRecv;
  delete inner.exported;  // v3-only: L-3 moved this inside the AEAD
  delete inner.nativeFloor;   // later still (2026-07-29 H-1): no pre-fix blob has it
  delete inner.derivedFloors; // Package 3 (item 13)
  if (mutate) mutate(inner);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt(
    { name: "AES-GCM", iv }, key, _enc.encode(JSON.stringify(inner)),
  ));
  localStorage.setItem(k, JSON.stringify({ v: 2, kdf: cur.kdf, iv: _b64(iv), ct: _b64(ct) }));
}

{
  const enc = _enc;
  const dec = _dec;
  const b64 = _b64;
  const unb64 = _unb64;

  const m = await otp.generatePad({ label: "v2-used", totalBytes: 8192, fingerBytes: new Uint8Array(0) });
  const mAtRest = await otp.saveNewPad(m, PASS);
  const mKey = "sc.otp.pad.v1." + m.padId;

  const USED = 1234;
  m.sendOffset = USED;
  await otp.savePadProgress(m, mAtRest);

  // Roll the stored blob back to the pre-fix shape.
  const cur = JSON.parse(localStorage.getItem(mKey));
  const innerPlain = JSON.parse(dec.decode(await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: unb64(cur.iv) }, mAtRest.key, unb64(cur.ct),
  )));
  delete innerPlain.hwSend;      // v3-only: the authenticated watermark mirror
  delete innerPlain.hwRecv;
  delete innerPlain.exported;    // v3-only: L-3 moved this inside the AEAD
  const iv2 = crypto.getRandomValues(new Uint8Array(12));
  const ct2 = new Uint8Array(await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: iv2 }, mAtRest.key, enc.encode(JSON.stringify(innerPlain)),
  ));
  localStorage.setItem(mKey, JSON.stringify({ v: 2, kdf: cur.kdf, iv: b64(iv2), ct: b64(ct2) }));
  localStorage.removeItem("sc.otp.wm.v1." + m.padId);    // never existed pre-fix
  localStorage.removeItem("sc.otp.used.v1." + m.padId);  // stamped only post-fix
  localStorage.setItem("sc.otp.hw.v1." + m.padId, String(USED)); // what old code wrote

  // F-1: adoption is no longer automatic. A pad with no authenticated floor is
  // refused until the caller has shown the user the warning and they accept it.
  // Silent adoption was the vulnerability, so this refusal is the fix.
  await assert.rejects(
    otp.unlockPad(m.padId, PASS),
    (e) => e.code === "LEGACY_PAD_ADOPTION" && e.suspicious === true,
    "F-1: a pre-fix pad must NOT be adopted silently, and this device has run OTP so it is flagged suspicious",
  );

  const migrated = await otp.unlockPad(m.padId, PASS, { adoptLegacy: true });
  assert.strictEqual(migrated.record.sendOffset, USED,
    "a USED pre-fix pad must migrate, not be refused");
  assert.strictEqual(JSON.parse(localStorage.getItem(mKey)).v, 3,
    "the migrated blob is rewritten as v3");
  assert.ok(localStorage.getItem("sc.otp.wm.v1." + m.padId),
    "migration writes the authenticated watermark");

  // The floor must SURVIVE the migration — adopting a pre-fix pad must not
  // reset its tripwire to zero, or the upgrade itself becomes the rollback.
  const rewound = JSON.parse(localStorage.getItem(mKey));
  const innerNow = JSON.parse(dec.decode(await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: unb64(rewound.iv) }, mAtRest.key, unb64(rewound.ct),
  )));
  // NOTE: this assertion is necessary but NOT discriminating on its own — with
  // USED === sendOffset, writePadBlob's max(prev, record.sendOffset) satisfies it
  // even if readLegacyHW were dropped from the floor entirely. The case that
  // actually pins readLegacyHW is the separate block below.
  assert.strictEqual(innerNow.hwSend, USED, "the legacy watermark became the authenticated floor");

  // And the H-3 guard still bites once the pad IS post-fix: same PoC as above.
  const post = localStorage.getItem(mKey);
  m.sendOffset = USED + 500;
  await otp.savePadProgress(m, mAtRest);
  localStorage.setItem(mKey, post);
  localStorage.removeItem("sc.otp.wm.v1." + m.padId);
  await assert.rejects(
    otp.unlockPad(m.padId, PASS), /rollback record for this pad is missing/,
    "H-3 still fails closed for a v3 blob whose watermark was deleted",
  );
}
console.log("OK  v2→v3: a USED pre-fix pad migrates (and keeps its floor), H-3 still closed");

// --- the legacy watermark stays load-bearing AS A FLOOR ----------------------
// Review of bf6bcd2 (F-3): every existing assertion about the floor was
// satisfied by `record.sendOffset` alone, so deleting readLegacyHW() from the
// max() at otp.js survived the whole suite — while being a real break. The
// discriminating case is a pre-fix blob whose stored offset sits BELOW the
// legacy watermark: a partial restore, or a restore-from-backup that reverted
// the blob but not the plaintext tripwire. Only readLegacyHW() catches it.
//
// This is the one job bf6bcd2's rationale left for the legacy value after
// removing it from `knownUsedHere`, so it is the one that must be pinned.
{
  const f = await otp.generatePad({ label: "v2-floor", totalBytes: 8192, fingerBytes: new Uint8Array(0) });
  const fAtRest = await otp.saveNewPad(f, PASS);
  const REACHED = 1234;
  f.sendOffset = REACHED;
  await otp.savePadProgress(f, fAtRest);

  // Pre-fix shape, blob rewound to 0, legacy tripwire still recording 1234.
  await makeV2Blob(f.padId, fAtRest.key, (inner) => { inner.sendOffset = 0; });
  localStorage.removeItem("sc.otp.wm.v1." + f.padId);
  localStorage.removeItem("sc.otp.used.v1." + f.padId);
  localStorage.setItem("sc.otp.hw.v1." + f.padId, String(REACHED));

  await assert.rejects(
    otp.unlockPad(f.padId, PASS), /rolled back/,
    "the legacy watermark must remain a FLOOR: a v2 blob below it is a rollback",
  );
}
console.log("OK  F-3: the legacy watermark is still load-bearing as a rollback floor");

// --- each knownUsedHere clause must be load-bearing ON ITS OWN ---------------
// Review of bf6bcd2 (F-4): the H-3 checks above delete sc.otp.wm.v1 but leave
// sc.otp.used.v1 on a v3 blob, so BOTH surviving clauses are true and neither is
// isolated — dropping either one survived the suite, and dropping the
// inner.hwSend clause is exploitable. bf6bcd2 deliberately narrowed this
// predicate to two clauses, so both need pinning separately.
{
  // (a) the AUTHENTICATED clause alone: v3 blob, every plaintext marker deleted.
  const a = await otp.generatePad({ label: "clause-inner", totalBytes: 8192, fingerBytes: new Uint8Array(0) });
  const aAtRest = await otp.saveNewPad(a, PASS);
  a.sendOffset = 400;
  await otp.savePadProgress(a, aAtRest);
  localStorage.removeItem("sc.otp.wm.v1." + a.padId);
  localStorage.removeItem("sc.otp.used.v1." + a.padId);
  localStorage.removeItem("sc.otp.hw.v1." + a.padId);
  await assert.rejects(
    otp.unlockPad(a.padId, PASS), /rollback record for this pad is missing/,
    "inner.hwSend alone must trip H-3 once every plaintext marker is gone",
  );

  // (b) the usedKey clause alone: v2-shaped blob (no inner.hwSend), but this
  // device stamped sc.otp.used.v1 — so a missing watermark is DELETION, not a
  // pad that predates the scheme, and it must still fail closed.
  const b = await otp.generatePad({ label: "clause-used", totalBytes: 8192, fingerBytes: new Uint8Array(0) });
  const bAtRest = await otp.saveNewPad(b, PASS);
  b.sendOffset = 300;
  await otp.savePadProgress(b, bAtRest);
  await makeV2Blob(b.padId, bAtRest.key);
  localStorage.removeItem("sc.otp.wm.v1." + b.padId);
  localStorage.removeItem("sc.otp.hw.v1." + b.padId);
  await assert.rejects(
    otp.unlockPad(b.padId, PASS), /rollback record for this pad is missing/,
    "usedKey alone must trip H-3 on a v2-shaped blob",
  );
}
console.log("OK  F-4: each knownUsedHere clause fails closed on its own");

// --- F-1: the reported two-time pad, and the native floor that closes it -----
// Review of bf6bcd2 found H-3 fully bypassable on a v2-shaped blob: with no
// `hwSend` inside the AEAD the whole defence was the plaintext `sc.otp.used.v1`,
// so restoring a v2 snapshot plus three removeItem()s reopened the pad at offset
// 0 and two messages encrypted under the same keystream.
//
// Two layers now stand in the way, and they are tested separately because they
// protect different platforms: the adoption gate (browser — user attention, the
// only control available where all storage is attacker-writable), and the native
// monotonic floor (Android — the pad ran, the floor says so, and no JS-side
// deletion can say otherwise).
{
  // -- browser: no native bridge. The attack must at minimum become LOUD. ----
  const v = await otp.generatePad({ label: "f1-browser", totalBytes: 8192, fingerBytes: new Uint8Array(0) });
  const vAtRest = await otp.saveNewPad(v, PASS);
  v.sendOffset = 900;
  await otp.savePadProgress(v, vAtRest);

  await makeV2Blob(v.padId, vAtRest.key, (inner) => { inner.sendOffset = 0; });
  localStorage.removeItem("sc.otp.wm.v1." + v.padId);
  localStorage.removeItem("sc.otp.used.v1." + v.padId);
  localStorage.removeItem("sc.otp.hw.v1." + v.padId);   // the full 3-key PoC

  await assert.rejects(
    otp.unlockPad(v.padId, PASS),
    (e) => e.code === "LEGACY_PAD_ADOPTION" && e.suspicious === true,
    "F-1: the v2 two-time-pad PoC must not unlock silently",
  );

  // -- android: the native floor refuses it OUTRIGHT, adoption or not. -------
  // Fresh module instance so the bridge is captured at load, exactly as on the
  // device (otp.js reads globalThis.__SECURE_CHAT_PAD_FLOOR__ once, at import).
  const floors = new Map();
  globalThis.__SECURE_CHAT_PAD_FLOOR__ = {
    read: (id) => (floors.has(id) ? floors.get(id) : -1),
    bump: (id, val) => {
      const cur = floors.has(id) ? floors.get(id) : -1;
      const n = val > cur ? val : cur;
      floors.set(id, n);
      return n;
    },
  };
  const otpN = await import("./otp.js?native=1");

  const n = await otpN.generatePad({ label: "f1-native", totalBytes: 8192, fingerBytes: new Uint8Array(0) });
  const nAtRest = await otpN.saveNewPad(n, PASS);
  n.sendOffset = 900;
  await otpN.savePadProgress(n, nAtRest);
  assert.strictEqual(floors.get(n.padId), 900, "the native floor tracks the send offset");

  // Same PoC, plus consent — the strongest form of the attack.
  await makeV2Blob(n.padId, nAtRest.key, (inner) => { inner.sendOffset = 0; });
  localStorage.removeItem("sc.otp.wm.v1." + n.padId);
  localStorage.removeItem("sc.otp.used.v1." + n.padId);
  localStorage.removeItem("sc.otp.hw.v1." + n.padId);

  await assert.rejects(
    otpN.unlockPad(n.padId, PASS, { adoptLegacy: true }),
    /rollback record for this pad is missing/,
    "F-1: the native floor refuses the PoC even when the user adopts",
  );

  // The floor is monotone: a bump downwards must not lower it.
  globalThis.__SECURE_CHAT_PAD_FLOOR__.bump(n.padId, "5");
  assert.strictEqual(floors.get(n.padId), 900, "the native floor never goes down");

  // A bridge that cannot be read fails CLOSED, never as "no floor". Since the
  // H-3 fix this is refused at the FIRST step that touches the floor — creating
  // the pad — rather than at unlock: padWasUsed treats an unreadable floor as
  // "used", because an import/save must never be the way out of a damaged one.
  // Both refusals are the same property; assert the earliest, and that the pad
  // never reaches a usable state.
  globalThis.__SECURE_CHAT_PAD_FLOOR__ = { read: () => "not-a-number", bump: () => "0" };  // strings are now invalid
  const modBroken = await import("./otp.js?native=broken");
  const pBroken = await modBroken.generatePad({ label: "f1-broken", totalBytes: 8192, fingerBytes: new Uint8Array(0) });
  await assert.rejects(
    modBroken.saveNewPad(pBroken, PASS),
    /already been used on this device/,
    "an unreadable native floor must not read as a clean slate",
  );
  assert.strictEqual(modBroken.padMeta(pBroken.padId), null,
    "a pad refused at save must not be left half-created");

  delete globalThis.__SECURE_CHAT_PAD_FLOOR__;
}
console.log("OK  F-1: v2 two-time-pad PoC is loud in the browser, refused outright on device");

// --- H-1 (2026-07-29): the floor must not be removable from the JS context ---
// Two separate downgrades, both silent, both on the platform whose entire claim
// is that the floor is out of the JS context's reach:
//
//   a) PadFloorBridge exposed an unauthenticated `clear(padId)`. Restore a
//      snapshotted blob AND its watermark, call clear() once, and the pad
//      reopens rolled back with no prompt — full keystream reuse.
//   b) The bridge was feature-detected from `globalThis.SecureChatPadFloor`, an
//      ordinary writable global, so `delete` on it read as "plain browser".
//
// The suite's own bridge mock hid both: it never had a `clear`, so (a) could not
// be expressed, and it ended with `delete globalThis.SecureChatPadFloor` as
// cleanup — treating bridge-absence as a clean browser, which IS downgrade (b).
{
  const floors = new Map();
  const bridge = (extra = {}) => ({
    read: (id) => (floors.has(id) ? floors.get(id) : -1),
    bump: (id, val) => {
      const cur = floors.has(id) ? floors.get(id) : -1;
      const n = val > cur ? val : cur;
      floors.set(id, n);
      return n;
    },
    ...extra,
  });

  // (a) The shipped bridge must expose NO lowering or deletion operation. This
  // is the assertion the old mock could never make: it is about the real
  // Kotlin surface, so it reads the source rather than a stand-in.
  const kotlin = await readFile(
    new URL("../android/app/src/main/java/org/securechat/app/PadFloor.kt", import.meta.url),
    "utf8",
  );
  const bridgeBody = kotlin.slice(kotlin.indexOf("class PadFloorBridge"));
  const exposed = [...bridgeBody.matchAll(/@JavascriptInterface\s+fun\s+(\w+)/g)].map((m) => m[1]);
  assert.deepStrictEqual(
    exposed.sort(), ["bump", "read"],
    `H-1: PadFloorBridge must expose exactly read+bump, got ${exposed.join(",")}`,
  );

  // …and the attack that method enabled, modelled end to end: snapshot a pad
  // and its watermark, advance the pad, restore BOTH, then clear the floor.
  // Without a floor to contradict it the restore is undetectable, so this is
  // the case that must stay unreachable.
  globalThis.__SECURE_CHAT_PAD_FLOOR__ = bridge();
  const otpC = await import("./otp.js?native=clear");
  const c = await otpC.generatePad({ label: "h1-clear", totalBytes: 8192, fingerBytes: new Uint8Array(0) });
  const cAtRest = await otpC.saveNewPad(c, PASS);
  const snapBlob = localStorage.getItem("sc.otp.pad.v1." + c.padId);
  const snapWm = localStorage.getItem("sc.otp.wm.v1." + c.padId);
  c.sendOffset = 900;
  await otpC.savePadProgress(c, cAtRest);
  assert.strictEqual(floors.get(c.padId), 900, "precondition: the floor advanced");

  localStorage.setItem("sc.otp.pad.v1." + c.padId, snapBlob);   // rewind the pad
  localStorage.setItem("sc.otp.wm.v1." + c.padId, snapWm);      // and its watermark
  floors.delete(c.padId);                                       // what clear() did
  await assert.rejects(
    otpC.unlockPad(c.padId, PASS, { adoptLegacy: true }),
    /device-protected rollback record has been deleted/,
    "H-1(a): deleting the floor under a restored blob must not reopen the pad",
  );

  // (b) Marker present, bridge gone: `delete window.SecureChatPadFloor` at
  // document-start — the downgrade the old cleanup line quietly performed.
  //
  // Model it the way it actually happens: a device with a REAL pad, created and
  // advanced under a working bridge, whose owner then loads a page with the
  // bridge deleted. Creating the pad under the broken bridge instead would test
  // nothing, because there would be no floor to lose.
  globalThis.__SECURE_CHAT_PAD_FLOOR__ = bridge();
  const otpW = await import("./otp.js?native=marker-pre");
  const w = await otpW.generatePad({ label: "h1-marker", totalBytes: 8192, fingerBytes: new Uint8Array(0) });
  const wAtRest = await otpW.saveNewPad(w, PASS);
  w.sendOffset = 700;
  await otpW.savePadProgress(w, wAtRest);
  assert.strictEqual(floors.get(w.padId), 700, "precondition: the pad has a real floor");

  globalThis.__SECURE_CHAT_NATIVE_FLOOR__ = true;
  delete globalThis.__SECURE_CHAT_PAD_FLOOR__;                 // the whole attack
  const otpM = await import("./otp.js?native=marker-only");
  await assert.rejects(
    otpM.unlockPad(w.padId, PASS, { adoptLegacy: true }),
    // Since the L-A fix this says what is actually wrong instead of blaming
    // the pad — the old wording told the user to exchange a fresh pad, which
    // does not help and burns real pads.
    /cannot reach it/,
    "H-1(b): marker present + bridge deleted must fail closed, not degrade",
  );
  // The floor itself is untouched — this is a JS-side downgrade, not deletion —
  // so restoring the bridge restores normal service. Fail-closed, not bricked.
  globalThis.__SECURE_CHAT_PAD_FLOOR__ = bridge();
  const otpR = await import("./otp.js?native=marker-restored");
  const reopened = await otpR.unlockPad(w.padId, PASS);
  assert.strictEqual(reopened.record.sendOffset, 700, "the pad reopens once the bridge is back");

  // The marker the app injects is non-configurable, so a JS attacker cannot
  // erase the evidence that a floor was expected. Assert the app really does
  // define it that way — the fix depends on it, and it is one word away from
  // being a plain assignment.
  const activity = await readFile(
    new URL("../android/app/src/main/java/org/securechat/app/MainActivity.kt", import.meta.url),
    "utf8",
  );
  // Package 3 (F-P7-A5): this used to be `activity.slice(activity.indexOf(
  // "__SECURE_CHAT_NATIVE_FLOOR__"))` — whose first match is a COMMENT in
  // loadWithRelay, so the regex was satisfied by the pad-floor call further
  // down and a flipped marker descriptor stayed green. The call itself now.
  const markerCall = definePropertyCall(activity, "__SECURE_CHAT_NATIVE_FLOOR__");
  assert.match(markerCall, /configurable:\s*false/,
    "H-1: the marker must be non-configurable or `delete` hides the downgrade");
  assert.match(markerCall, /writable:\s*false/, "H-1: …and non-writable");

  // A genuine browser — NEITHER global — is unaffected: no floor, and the
  // documented residual stands. Without this the fix could be "fail closed
  // everywhere", which would brick every browser pad.
  delete globalThis.__SECURE_CHAT_NATIVE_FLOOR__;
  const otpB = await import("./otp.js?native=none");
  const b2 = await otpB.generatePad({ label: "h1-browser", totalBytes: 8192, fingerBytes: new Uint8Array(0) });
  await otpB.saveNewPad(b2, PASS);
  const opened = await otpB.unlockPad(b2.padId, PASS);
  assert.strictEqual(opened.record.sendOffset, 0, "a plain browser must still open its pads");
}
console.log("OK  H-1: the native floor cannot be cleared or feature-detected away");

// --- H-A (fix review 2026-07-30): a LYING bridge, not a deleted one ----------
// The H-1 fix hardened the marker, on the assumption that the only move
// available was `delete window.SecureChatPadFloor`. It was not. otp.js located
// the bridge by its ordinary global name and accepted anything shaped like it,
// so an attacker could install a lookalike that reports "no floor" — or simply
// overwrite the two METHODS on the real object, which needs no `delete` and no
// `defineProperty` and survives making the global itself non-writable. Every
// new check passed, `verifyRelayConfig`'s probe answered true, and the real
// Keystore floor sat untouched and unconsulted: full keystream reuse.
//
// The bridge is now captured at document-start and republished FROZEN under
// `__SECURE_CHAT_PAD_FLOOR__`, with bound methods, and that is the only name
// otp.js reads. These tests are what the old bridge mock could not express: a
// bridge that lies.
{
  const realFloors = new Map();
  const realBridge = {
    read: (id) => (realFloors.has(id) ? realFloors.get(id) : -1),
    bump: (id, val) => {
      const cur = realFloors.has(id) ? realFloors.get(id) : -1;
      const n = val > cur ? val : cur;
      realFloors.set(id, n);
      return n;
    },
  };

  // What the app's document-start script does, transcribed. `.bind` captures
  // the function VALUES, which is the load-bearing detail.
  const publishProtected = () => {
    delete globalThis.__SECURE_CHAT_PAD_FLOOR__;
    globalThis.__SECURE_CHAT_PAD_FLOOR__ = Object.freeze({
      read: realBridge.read.bind(realBridge),
      bump: realBridge.bump.bind(realBridge),
    });
  };

  globalThis.SecureChatPadFloor = realBridge;   // the raw, writable interface
  publishProtected();
  const otpA = await import("./otp.js?ha=1");

  const p = await otpA.generatePad({ label: "ha", totalBytes: 8192, fingerBytes: new Uint8Array(0) });
  const atRest = await otpA.saveNewPad(p, PASS);
  const XFER = "xfer-pass";
  const file = await otpA.exportPad(p, XFER);
  p.sendOffset = 3000;
  await otpA.savePadProgress(p, atRest);
  assert.strictEqual(realFloors.get(p.padId), 3000, "precondition: the real floor is 3000");

  // ATTACK 1 — overwrite the methods on the raw interface. Two assignments.
  globalThis.SecureChatPadFloor.read = () => -1;
  globalThis.SecureChatPadFloor.bump = () => -1;
  assert.ok(otpA.padWasUsed(p.padId),
    "H-A: overwriting the raw bridge's methods must not make the pad look unused");

  // ATTACK 2 — replace the raw global outright with a lookalike.
  globalThis.SecureChatPadFloor = { read: () => -1, bump: () => 0 };
  assert.ok(otpA.padWasUsed(p.padId),
    "H-A: a substituted raw bridge must not make the pad look unused");

  // …and the consequences that mattered: re-import and unlock both still refuse.
  otpA.forgetPad(p.padId);
  for (const k of ["used", "wm", "hw"]) localStorage.removeItem(`sc.otp.${k}.v1.${p.padId}`);
  await assert.rejects(
    otpA.importPad(file, XFER),
    /already been used on this device/,
    "H-A: the full PoC — lying bridge plus the three deletions — must be refused",
  );
  assert.strictEqual(realFloors.get(p.padId), 3000, "H-A: the real floor is untouched");

  // The protected copy really is immune: freezing means the attacker cannot
  // reach through it, and non-configurability is what the app relies on.
  assert.throws(
    () => { "use strict"; globalThis.__SECURE_CHAT_PAD_FLOOR__.read = () => -1; },
    "H-A: the protected bridge must be frozen",
  );
  assert.strictEqual(globalThis.__SECURE_CHAT_PAD_FLOOR__.read(p.padId), 3000,
    "H-A: the protected bridge still reports the real floor");

  // And the app must actually publish it that way — the fix depends on `.bind`
  // and on configurable:false, both of which are one word from being lost.
  const activity = await readFile(
    new URL("../android/app/src/main/java/org/securechat/app/MainActivity.kt", import.meta.url),
    "utf8",
  );
  const inject = definePropertyCall(activity, "__SECURE_CHAT_PAD_FLOOR__"); // the call, not the first mention
  assert.match(inject, /Object\.freeze/, "H-A: the published bridge must be frozen");
  assert.match(inject, /\.bind\(b\)/,
    "H-A: methods must be BOUND, or a later `b.read = fake` is still obeyed");
  assert.match(inject, /configurable:\s*false/, "H-A: the published name must be non-configurable");
  // otp.js must not read the writable global at all any more.
  const otpSrc = await readFile(new URL("./otp.js", import.meta.url), "utf8");
  const code = otpSrc.split("\n").filter((l) => !l.trim().startsWith("//")).join("\n");
  assert.ok(!/globalThis\.SecureChatPadFloor/.test(code),
    "H-A: otp.js must read only the protected name, never the writable global");

  delete globalThis.SecureChatPadFloor;
  delete globalThis.__SECURE_CHAT_PAD_FLOOR__;
}
console.log("OK  H-A: a bridge that LIES is refused, not just one that is deleted");

// --- H-1 round 2: poisoning the VALUE path, not the bridge -------------------
// The H-A fix froze which function produces the floor. It did not freeze what
// the caller did with the answer: `parseInt`, `Number.isFinite` and `Math.max`
// are all writable globals, and the rollback verdict was a single `Math.max`
// over the four floors. So one assignment — never naming the bridge, needing no
// `delete` — made every floor read as 0 while the frozen bridge, the
// non-configurable marker and verifyRelayConfig's probe all stayed intact.
//
// Note these cannot be defended by capturing primordials at module top: a
// document-start attacker runs first. The bridge returns a NUMBER now, and the
// remaining checks use only `typeof` and bitwise ops, which have no global
// behind them to redefine.
{
  const REAL = { parseInt: globalThis.parseInt, max: Math.max, isFinite: Number.isFinite };
  const floors = new Map();
  globalThis.__SECURE_CHAT_PAD_FLOOR__ = Object.freeze({
    read: (id) => (floors.has(id) ? floors.get(id) : -1),
    bump: (id, v) => {
      const cur = floors.has(id) ? floors.get(id) : -1;
      const n = v > cur ? v : cur;
      floors.set(id, n);
      return n;
    },
  });
  globalThis.__SECURE_CHAT_NATIVE_FLOOR__ = true;
  const otpP = await import("./otp.js?poison=1");

  const p = await otpP.generatePad({ label: "poison", totalBytes: 8192, fingerBytes: new Uint8Array(0) });
  const atRest = await otpP.saveNewPad(p, PASS);
  const pristine = localStorage.getItem("sc.otp.pad.v1." + p.padId);
  const XFER = "xfer-pass";
  const file = await otpP.exportPad(p, XFER);
  p.sendOffset = 3000;
  await otpP.savePadProgress(p, atRest);
  assert.strictEqual(floors.get(p.padId), 3000, "precondition: the real floor is 3000");

  try {
    // ATTACK 1 — parseInt. One assignment, and the bridge is never named.
    globalThis.parseInt = () => 0;
    assert.ok(otpP.padWasUsed(p.padId), "H-1: a poisoned parseInt must not zero the floor");

    // ATTACK 2 — Number.isFinite, the guard that was supposed to catch garbage.
    globalThis.parseInt = REAL.parseInt;
    Number.isFinite = () => false;
    assert.ok(otpP.padWasUsed(p.padId), "H-1: a poisoned Number.isFinite must not zero the floor");

    // ATTACK 3 — Math.max, which WAS the whole rollback verdict: one call over
    // the native floor, the authenticated watermark, inner.hwSend and the
    // legacy watermark. Poisoning it overruled all four at once. This one works
    // in a plain browser too, with no bridge involved.
    Number.isFinite = REAL.isFinite;
    Math.max = (...a) => (a.length === 4 ? 0 : REAL.max(...a));
    localStorage.setItem("sc.otp.pad.v1." + p.padId, pristine);   // rewind the blob
    await assert.rejects(
      otpP.unlockPad(p.padId, PASS, { adoptLegacy: true }),
      /rolled back|rollback record|deleted/,
      "H-1: a poisoned Math.max must not overrule the rollback floors",
    );

    // …and the full PoC: poisoned parseInt plus the three deletions plus a
    // re-import, which is what recovered a plaintext in the review.
    Math.max = REAL.max;
    globalThis.parseInt = () => 0;
    otpP.forgetPad(p.padId);
    for (const k of ["used", "wm", "hw"]) localStorage.removeItem(`sc.otp.${k}.v1.${p.padId}`);
    await assert.rejects(
      otpP.importPad(file, XFER),
      /already been used on this device/,
      "H-1: the full poisoned-parse PoC must be refused",
    );
    assert.strictEqual(floors.get(p.padId), 3000, "H-1: the real floor is untouched");
  } finally {
    globalThis.parseInt = REAL.parseInt;
    Math.max = REAL.max;
    Number.isFinite = REAL.isFinite;
  }

  // The source must not reintroduce a poisonable step on the rollback path.
  const src = await readFile(new URL("./otp.js", import.meta.url), "utf8");
  const code = src.split("\n").filter((l) => !l.trim().startsWith("//")).join("\n");
  const rollback = code.slice(code.indexOf("export async function unlockPad"));
  for (const bad of [/\bMath\.max\(/, /\bparseInt\(/, /\bNumber\.isFinite\(/]) {
    assert.ok(!bad.test(rollback), `H-1: ${bad} is poisonable and must not decide a rollback`);
  }
  // …nor may the shared floor module (pentest 2026-08-07: the capture and the
  // value validation moved to nativefloor.js, and every store's verdict now
  // passes through it).
  const floorSrc = await readFile(new URL("./nativefloor.js", import.meta.url), "utf8");
  const floorCode = floorSrc.split("\n").filter((l) => !l.trim().startsWith("//")).join("\n");
  for (const bad of [/\bMath\.max\(/, /\bparseInt\(/, /\bNumber\.isFinite\(/, /globalThis\.SecureChatPadFloor/]) {
    assert.ok(!bad.test(floorCode), `H-1/H-A: nativefloor.js must not contain ${bad}`);
  }

  delete globalThis.__SECURE_CHAT_PAD_FLOOR__;
  delete globalThis.__SECURE_CHAT_NATIVE_FLOOR__;
}
console.log("OK  H-1: poisoning parseInt/isFinite/Math.max cannot lower a floor");

// --- H-3 (2026-07-29): delete the three markers, then re-import --------------
// importPad's only rollback guard was padWasUsed(), which read three DELETABLE
// plaintext keys and never the native floor. So: use a pad, remove the three
// keys, re-import the (always pristine) export file — and the pad was rebuilt
// as a LEGITIMATE v3 blob at offset 0, with a matching fresh watermark. No
// adoption prompt was possible, because nothing about the result looks legacy.
// Browser: a permanent two-time pad. Android: the floor refused on the NEXT
// unlock, but the whole current session sent from offset 0 over spent keystream.
{
  const floors = new Map();
  globalThis.__SECURE_CHAT_PAD_FLOOR__ = {
    read: (id) => (floors.has(id) ? floors.get(id) : -1),
    bump: (id, val) => {
      const cur = floors.has(id) ? floors.get(id) : -1;
      const n = val > cur ? val : cur;
      floors.set(id, n);
      return n;
    },
  };
  const otpI = await import("./otp.js?h3=import");

  const XFER = "transfer-pass";
  const p = await otpI.generatePad({ label: "h3", totalBytes: 8192, fingerBytes: new Uint8Array(0) });
  const atRestP = await otpI.saveNewPad(p, PASS);
  // The export file an attacker (or a confused user) re-imports later. Taken
  // while pristine, because exportPad refuses a used pad — that is the point.
  const file = await otpI.exportPad(p, XFER);

  p.sendOffset = 640;
  await otpI.savePadProgress(p, atRestP);
  assert.strictEqual(floors.get(p.padId), 640, "precondition: the floor advanced");

  // "It wasn't working, let me re-import" — plus the three deletions.
  otpI.forgetPad(p.padId);
  localStorage.removeItem("sc.otp.used.v1." + p.padId);
  localStorage.removeItem("sc.otp.wm.v1." + p.padId);
  localStorage.removeItem("sc.otp.hw.v1." + p.padId);

  await assert.rejects(
    otpI.importPad(file, XFER),
    /already been used on this device/,
    "H-3: the native floor must be consulted on the import path",
  );

  // And the step that made the result look legitimate: saveNewPad seeded the
  // watermark cache to zero, overwriting the authenticated record. Even reached
  // directly — bypassing importPad entirely, which is what app.js's
  // otpFileChosen effectively did — it must refuse rather than erase.
  const rebuilt = {
    padId: p.padId, label: "h3", regionSize: 4096, role: 0,
    createdAt: Date.now(), bytes: new Uint8Array(8192), sendOffset: 0, recvHighWater: 0,
  };
  await assert.rejects(
    otpI.saveNewPad(rebuilt, PASS),
    /already been used on this device/,
    "H-3: saveNewPad must not lower an existing watermark",
  );
  assert.strictEqual(floors.get(p.padId), 640, "H-3: the floor survived the attempt");

  // In a plain browser there is no floor, so the three deletions DO erase the
  // localStorage evidence and the re-import SUCCEEDS. H-3 is therefore fixed on
  // Android only, and the fix review (H-B) was right that the summary line and
  // PROGRESS.md read as though it were fixed everywhere. Closing it in the
  // browser is not possible with deletable storage — the honest options are
  // trusted monotonic storage (what PadFloor is) or nothing.
  //
  // What is still asserted below is the weaker property that DOES hold in a
  // browser: while any evidence survives, the guard fires. That is P-05, and it
  // is what keeps the guard from being dead code on the platform.
  delete globalThis.__SECURE_CHAT_PAD_FLOOR__;
  const otpBr = await import("./otp.js?h3=browser");
  const q = await otpBr.generatePad({ label: "h3-browser", totalBytes: 8192, fingerBytes: new Uint8Array(0) });
  const atRestQ = await otpBr.saveNewPad(q, PASS);
  const fileQ = await otpBr.exportPad(q, XFER);
  q.sendOffset = 320;
  await otpBr.savePadProgress(q, atRestQ);
  otpBr.forgetPad(q.padId);
  await assert.rejects(
    otpBr.importPad(fileQ, XFER),
    /already been used on this device/,
    "H-3: forget-then-reimport is still refused in the browser (P-05)",
  );
}
console.log("OK  H-3 (Android): delete-the-markers-then-reimport is refused where a floor exists");
console.log("    NOTE: in a plain browser the three markers are still deletable and the");
console.log("    re-import still succeeds — documented residual, not covered by the above.");

// --- F-2: `exported` cannot be laundered through the migrating unlock --------
// The plaintext index used to be taken at face value on the one unlock that
// upgrades a pad, and then baked into the AEAD forever. Flipping it to false
// beforehand disarmed the double-export warning permanently — the warning that
// is all that stands between one pristine pad and two importers.
{
  const x = await otp.generatePad({ label: "f2", totalBytes: 8192, fingerBytes: new Uint8Array(0) });
  const xAtRest = await otp.saveNewPad(x, PASS);
  const unlocked = await otp.unlockPad(x.padId, PASS);
  await otp.markExported(unlocked.record, unlocked.atRest);

  // Pre-fix shape (no authenticated `exported`), and the attacker clears the
  // only remaining source before the upgrading unlock.
  await makeV2Blob(x.padId, xAtRest.key);
  localStorage.removeItem("sc.otp.wm.v1." + x.padId);
  localStorage.removeItem("sc.otp.used.v1." + x.padId);
  localStorage.removeItem("sc.otp.hw.v1." + x.padId);
  const idx = JSON.parse(localStorage.getItem("sc.otp.index.v1"));
  for (const e of idx) if (e.padId === x.padId) e.exported = false;
  localStorage.setItem("sc.otp.index.v1", JSON.stringify(idx));

  const adopted = await otp.unlockPad(x.padId, PASS, { adoptLegacy: true });
  assert.strictEqual(adopted.record.exported, true,
    "F-2: an unverifiable `exported` must resolve to TRUE, not to the attacker's plaintext false");
  assert.strictEqual((await otp.unlockPad(x.padId, PASS)).record.exported, true,
    "and it is authenticated from then on");
}
console.log("OK  F-2: `exported` cannot be cleared through the legacy migration");

// --- F-ATREST-001 (2026-08-07): the RECEIVE side gets a native floor ---------
// M-7 above catches a receive rollback through the authenticated watermark —
// which is one `setItem` away from being restored alongside the blob. On
// Android the send side had a floor the JS context cannot rewind; the receive
// side did not, so a snapshot of blob + watermark taken after sending, restored
// after receiving, passed every check and re-accepted every OTP frame the peer
// had already sent.
{
  const floors = new Map();
  const bridge = () => ({
    read: (id) => (floors.has(id) ? floors.get(id) : -1),
    bump: (id, val) => {
      const cur = floors.has(id) ? floors.get(id) : -1;
      const n = val > cur ? val : cur;
      floors.set(id, n);
      return n;
    },
  });
  globalThis.__SECURE_CHAT_PAD_FLOOR__ = bridge();
  const otpR = await import("./otp.js?atrest=recv");
  const r = await otpR.generatePad({ label: "recv-floor", totalBytes: 8192, fingerBytes: new Uint8Array(0) });
  const rAtRest = await otpR.saveNewPad(r, PASS);
  r.sendOffset = 200;
  await otpR.savePadProgress(r, rAtRest);
  // The attacker's coordinated snapshot: blob AND watermark, both after sending.
  const padSnap = localStorage.getItem("sc.otp.pad.v1." + r.padId);
  const wmSnap = localStorage.getItem("sc.otp.wm.v1." + r.padId);
  // Then a stretch of receiving.
  r.recvHighWater = 119;
  await otpR.savePadProgress(r, rAtRest);
  assert.strictEqual(floors.get("recv:" + r.padId), 119, "the receive high-water mark reaches the native floor");
  assert.strictEqual(floors.get(r.padId), 200, "and the send floor is untouched by it");
  // Restore both. Send floor == blob's sendOffset, watermark says recv 0: pre-fix
  // this unlocked at recv 0 and every already-delivered frame replayed.
  localStorage.setItem("sc.otp.pad.v1." + r.padId, padSnap);
  localStorage.setItem("sc.otp.wm.v1." + r.padId, wmSnap);
  await assert.rejects(otpR.unlockPad(r.padId, PASS), /receive state was rolled back/,
    "F-ATREST-001: a both-restored receive rollback is refused where a floor exists");
  // A forged recv floor is TAMPERED, never "no floor".
  floors.set("recv:" + r.padId, "junk");
  await assert.rejects(otpR.unlockPad(r.padId, PASS), /damaged or forged/,
    "an unreadable recv floor fails closed");
  floors.delete("recv:" + r.padId);
  // Package 3, 2026-08-08 item 13: this block used to assert that the rewound
  // pad OPENS here — with the recv slot deleted it read "ABSENT contributes
  // 0", so deleting one prefs entry turned the refusal above into a silent
  // replay of every delivered frame. The test encoded the bug. A blob written
  // with the derived slots in force (`derivedFloors`, sealed only after both
  // were armed) is now refused when either slot is gone.
  await assert.rejects(otpR.unlockPad(r.padId, PASS), /record has been deleted/,
    "item 13: deleting the recv: slot under a restored blob must not reopen it at the old receive offset");
  // A blob from BEFORE the derived slots were armed (no `derivedFloors` inside
  // its AEAD) is not caught by that rule. The first cut of this block called
  // that a residual "limited to blobs no save since this fix has rewritten" —
  // wrong (fix round 1, pentest M): the attacker picks WHICH blob to restore,
  // so any pre-upgrade copy kept it open forever. The send slot now stands in:
  // every floor-era build wrote `recv:` with it, so "send present, recv absent"
  // goes to the explicit adoption gate, never opens silently.
  await resealInner(r.padId, rAtRest.key, (inner) => { delete inner.derivedFloors; });
  await assert.rejects(otpR.unlockPad(r.padId, PASS),
    (e) => e.code === "LEGACY_PAD_ADOPTION" && e.suspicious === true && /receive record is missing/.test(e.message),
    "fix round 1: a pre-item-13 blob with its recv: slot deleted must not open silently (send slot present)");
  const older = await otpR.unlockPad(r.padId, PASS, { adoptLegacy: true });
  assert.strictEqual(older.record.recvHighWater, 0, "…only the user's explicit adoption opens it");

  // The `:` namespace cannot be reached from a pad file: an id that is not 32
  // hex characters is refused at import and at unlock.
  const XFER = "xfer";
  const bad = { ...r, padId: "recv:" + r.padId, sendOffset: 0, recvHighWater: 0 };
  const badFile = await otpR.exportPad(bad, XFER);
  await assert.rejects(otpR.importPad(badFile, XFER), /invalid pad id/,
    "a pad file cannot carry an id in another floor namespace");
  await assert.rejects(otpR.unlockPad("recv:" + r.padId, PASS), /no such pad/,
    "nor can unlockPad be pointed at one");
  delete globalThis.__SECURE_CHAT_PAD_FLOOR__;

  // Browser twin: no floor, so the both-restored rollback still opens. This is
  // the documented residual, pinned here so the fix cannot quietly become
  // "fail closed everywhere" and break the plain browser.
  const otpB = await import("./otp.js?atrest=recv-browser");
  const b = await otpB.generatePad({ label: "recv-browser", totalBytes: 8192, fingerBytes: new Uint8Array(0) });
  const bAtRest = await otpB.saveNewPad(b, PASS);
  const bPad = localStorage.getItem("sc.otp.pad.v1." + b.padId);
  const bWm = localStorage.getItem("sc.otp.wm.v1." + b.padId);
  b.recvHighWater = 50;
  await otpB.savePadProgress(b, bAtRest);
  localStorage.setItem("sc.otp.pad.v1." + b.padId, bPad);
  localStorage.setItem("sc.otp.wm.v1." + b.padId, bWm);
  assert.strictEqual((await otpB.unlockPad(b.padId, PASS)).record.recvHighWater, 0,
    "browser: both-restored receive rollback is the documented residual");
}
console.log("OK  F-ATREST-001: the receive high-water mark has a native floor on device");

// --- F-ATREST-002 (2026-08-07): `exported` gets a native floor ---------------
// L-3 put the flag inside the AEAD; F-2 stopped the migration laundering it.
// Neither survives restoring the pre-export blob + watermark: both are valid,
// the send floor is 0 because only a pristine pad can be exported, and the
// flag reads false — one pristine pad to two importers with no warning.
{
  const floors = new Map();
  globalThis.__SECURE_CHAT_PAD_FLOOR__ = {
    read: (id) => (floors.has(id) ? floors.get(id) : -1),
    bump: (id, val) => {
      const cur = floors.has(id) ? floors.get(id) : -1;
      const n = val > cur ? val : cur;
      floors.set(id, n);
      return n;
    },
  };
  const otpE = await import("./otp.js?atrest=exported");
  const e = await otpE.generatePad({ label: "exported-floor", totalBytes: 8192, fingerBytes: new Uint8Array(0) });
  await otpE.saveNewPad(e, PASS);
  const padSnap = localStorage.getItem("sc.otp.pad.v1." + e.padId);
  const wmSnap = localStorage.getItem("sc.otp.wm.v1." + e.padId);
  const u = await otpE.unlockPad(e.padId, PASS);
  assert.strictEqual(u.record.exported, false);
  await otpE.markExported(u.record, u.atRest);
  assert.strictEqual(floors.get("exported:" + e.padId), 1, "the export is recorded natively");
  localStorage.setItem("sc.otp.pad.v1." + e.padId, padSnap);
  localStorage.setItem("sc.otp.wm.v1." + e.padId, wmSnap);
  assert.strictEqual((await otpE.unlockPad(e.padId, PASS)).record.exported, true,
    "F-ATREST-002: a restored pre-export blob must not re-arm export where a floor exists");
  delete globalThis.__SECURE_CHAT_PAD_FLOOR__;

  // Browser twin: the same restore reads `false` — documented residual.
  const otpB = await import("./otp.js?atrest=exported-browser");
  const b = await otpB.generatePad({ label: "exported-browser", totalBytes: 8192, fingerBytes: new Uint8Array(0) });
  await otpB.saveNewPad(b, PASS);
  const bPad = localStorage.getItem("sc.otp.pad.v1." + b.padId);
  const bWm = localStorage.getItem("sc.otp.wm.v1." + b.padId);
  const ub = await otpB.unlockPad(b.padId, PASS);
  await otpB.markExported(ub.record, ub.atRest);
  localStorage.setItem("sc.otp.pad.v1." + b.padId, bPad);
  localStorage.setItem("sc.otp.wm.v1." + b.padId, bWm);
  assert.strictEqual((await otpB.unlockPad(b.padId, PASS)).record.exported, false,
    "browser: the pre-export restore re-arms export — documented residual");
}
console.log("OK  F-ATREST-002: `exported` has a native floor on device");

// ============================================================================
// Package 3 (fix/atrest-android)
// ============================================================================

// A bridge modelled on PadFloor.kt AS FIXED: SharedPreferences applies an edit
// to its in-memory map before writing the file and does not undo it when
// commit() returns false; that failure is answered COMMIT_FAILED (-3) and
// latched for the rest of the process; a value outside 0..2^31-1 is INVALID
// (-4). `disk` is what a restart sees. `failCommit(id, value)` decides which
// commits fail.
function kotlinFloor(disk, ctl = {}) {
  const mem = new Map(disk);
  let latched = false;
  return {
    read: (id) => (mem.has(id) ? mem.get(id) : -1),
    bump: (id, v) => {
      if (typeof v !== "number" || v < 0 || v > 0x7fffffff) return -4;
      if (latched) return -3;
      const cur = mem.has(id) ? mem.get(id) : -1;
      // `freeze`: a floor that silently does not move (ROUND-3 F-1's frozen
      // floor — no error, the old value comes back). No latch, so every slot's
      // check is exercised on its own rather than masked by a later one.
      if (ctl.freeze && ctl.freeze(id) && cur !== -1) return cur;
      if (ctl.full && cur === -1) return -5;               // PadFloor.FULL: record cap reached
      const next = cur === -1 ? v : (v > cur ? v : cur);
      if (next === cur) return cur;
      mem.set(id, next);
      if (ctl.failCommit && ctl.failCommit(id, next)) { latched = true; return -3; }
      disk.set(id, next);
      return next;
    },
  };
}

// --- 2026-08-08 item 13: the DERIVED slots are armed and their deletion refused
// Deleting `recv:<id>` rewound the receive side (the F-ATREST-001 block above
// now asserts the refusal); deleting `exported:<id>` read as "never exported",
// and because the slot was only ever written BY an export, its absence was
// ambiguous by construction. It is now armed at 0 on every save, and the blob
// records that both derived slots were in force.
{
  const disk = new Map();
  globalThis.__SECURE_CHAT_PAD_FLOOR__ = kotlinFloor(disk);
  const o = await import("./otp.js?p3=item13");
  const XFER = "xfer-13";

  // (a) Never exported: the slot exists from the first save, at 0.
  const a = await o.generatePad({ label: "i13-a", totalBytes: 8192, fingerBytes: new Uint8Array(0) });
  await o.saveNewPad(a, PASS);
  assert.strictEqual(disk.get("exported:" + a.padId), 0,
    "item 13: the exported: slot is armed (0) by the first save, so ABSENT later means deleted");
  assert.strictEqual(disk.get("recv:" + a.padId), 0, "…and so is recv:");
  disk.delete("exported:" + a.padId);
  globalThis.__SECURE_CHAT_PAD_FLOOR__ = kotlinFloor(disk);            // file-level deletion, then restart
  const o2 = await import("./otp.js?p3=item13-restart");
  await assert.rejects(o2.unlockPad(a.padId, PASS), /record has been deleted/,
    "item 13: a deleted exported: slot is refused, not read as 'never exported'");

  // (b) The second-export attack end to end: export, restore the pre-export
  // blob + watermark, delete the exported: slot. Before: the blob says
  // exported=false, the slot reads ABSENT, and the pad can be exported again
  // with no warning — two importers, a two-time pad.
  const b = await o2.generatePad({ label: "i13-b", totalBytes: 8192, fingerBytes: new Uint8Array(0) });
  await o2.saveNewPad(b, PASS);
  const padSnap = localStorage.getItem("sc.otp.pad.v1." + b.padId);
  const wmSnap = localStorage.getItem("sc.otp.wm.v1." + b.padId);
  const ub = await o2.unlockPad(b.padId, PASS);
  await o2.exportPad(ub.record, XFER);
  await o2.markExported(ub.record, ub.atRest);
  assert.strictEqual(disk.get("exported:" + b.padId), 1);
  localStorage.setItem("sc.otp.pad.v1." + b.padId, padSnap);
  localStorage.setItem("sc.otp.wm.v1." + b.padId, wmSnap);
  disk.delete("exported:" + b.padId);
  globalThis.__SECURE_CHAT_PAD_FLOOR__ = kotlinFloor(disk);
  const o3 = await import("./otp.js?p3=item13-export");
  await assert.rejects(o3.unlockPad(b.padId, PASS), /record has been deleted/,
    "item 13: restore + delete the exported: slot must not re-arm a second export");

  // (c) The send slot rule is unchanged, and an intact pad still opens.
  const c = await o3.generatePad({ label: "i13-c", totalBytes: 8192, fingerBytes: new Uint8Array(0) });
  const cAt = await o3.saveNewPad(c, PASS);
  c.sendOffset = 100; c.recvHighWater = 77;
  await o3.savePadProgress(c, cAt);
  assert.strictEqual((await o3.unlockPad(c.padId, PASS)).record.recvHighWater, 77, "control: an intact pad opens");
  delete globalThis.__SECURE_CHAT_PAD_FLOOR__;
}
console.log("OK  item 13: deleting the recv: or exported: slot is refused on device (derived-floors marker)");

// --- fix round 1 (pentest M): the item-13 residual for OLDER blob copies -----
// `derivedFloors` lives in the blob, and the attacker chooses which blob to
// restore. A copy from before the flag (v0.3.x shape: nativeFloor, no
// derivedFloors) plus a deleted derived slot must not reopen the hole.
{
  const disk = new Map();
  globalThis.__SECURE_CHAT_PAD_FLOOR__ = kotlinFloor(disk);
  const o = await import("./otp.js?p3r1=older");
  const XFER = "xfer-r1";
  const preFlag = (inner) => { delete inner.derivedFloors; };

  // Case A: receive replay. Blob + watermark at recv 300, pad later at 800.
  const a = await o.generatePad({ label: "r1-a", totalBytes: 8192, fingerBytes: new Uint8Array(0) });
  const aAt = await o.saveNewPad(a, PASS);
  a.recvHighWater = 300;
  await o.savePadProgress(a, aAt);
  await resealInner(a.padId, aAt.key, preFlag);
  const aSnap = [localStorage.getItem("sc.otp.pad.v1." + a.padId), localStorage.getItem("sc.otp.wm.v1." + a.padId)];
  a.recvHighWater = 800;
  await o.savePadProgress(a, aAt);
  localStorage.setItem("sc.otp.pad.v1." + a.padId, aSnap[0]);
  localStorage.setItem("sc.otp.wm.v1." + a.padId, aSnap[1]);
  disk.delete("recv:" + a.padId);
  globalThis.__SECURE_CHAT_PAD_FLOOR__ = kotlinFloor(disk);
  const o2 = await import("./otp.js?p3r1=older-a");
  await assert.rejects(o2.unlockPad(a.padId, PASS), (e) => e.code === "LEGACY_PAD_ADOPTION",
    "fix round 1, case A: an older blob + deleted recv: slot must not open at recv 300 (replay of 300..800)");

  // Case B: second export. Exported pad, pre-export pre-flag blob restored,
  // exported: slot deleted.
  const b = await o2.generatePad({ label: "r1-b", totalBytes: 8192, fingerBytes: new Uint8Array(0) });
  const bAt = await o2.saveNewPad(b, PASS);
  await resealInner(b.padId, bAt.key, preFlag);
  const bSnap = [localStorage.getItem("sc.otp.pad.v1." + b.padId), localStorage.getItem("sc.otp.wm.v1." + b.padId)];
  const file = await o2.exportPad(b, XFER);
  await o2.markExported(b, bAt);
  localStorage.setItem("sc.otp.pad.v1." + b.padId, bSnap[0]);
  localStorage.setItem("sc.otp.wm.v1." + b.padId, bSnap[1]);
  disk.delete("exported:" + b.padId);
  globalThis.__SECURE_CHAT_PAD_FLOOR__ = kotlinFloor(disk);
  const o3 = await import("./otp.js?p3r1=older-b");
  assert.strictEqual((await o3.unlockPad(b.padId, PASS)).record.exported, true,
    "fix round 1, case B: an unknown exported: slot (send slot present) reads as EXPORTED, never as a fresh pad to hand out again");

  // Control: the same rule on an honest v0.3.x pad that was never exported —
  // it opens (no prompt), merely treated as exported (a confirm on export).
  const c = await o3.generatePad({ label: "r1-c", totalBytes: 8192, fingerBytes: new Uint8Array(0) });
  const cAt = await o3.saveNewPad(c, PASS);
  await resealInner(c.padId, cAt.key, preFlag);
  disk.delete("exported:" + c.padId);
  globalThis.__SECURE_CHAT_PAD_FLOOR__ = kotlinFloor(disk);
  const o4 = await import("./otp.js?p3r1=older-c");
  const uc = await o4.unlockPad(c.padId, PASS);
  assert.strictEqual(uc.record.exported, true, "control: an unverifiable exported flag is TRUE (conservative)");
  assert.strictEqual(uc.record.exportedInferred, true, "fix round 2: …and marked as INFERRED, for the warning's wording");
  await o4.savePadProgress(uc.record, uc.atRest);          // the save latches exported:1 …
  const uc2 = await o4.unlockPad(c.padId, PASS);
  assert.strictEqual(uc2.record.exportedInferred, true, "fix round 2: …but it stays 'inferred' across saves (sealed in the AEAD)");
  await o4.markExported(uc2.record, uc2.atRest);             // a REAL export here
  assert.strictEqual((await o4.unlockPad(c.padId, PASS)).record.exportedInferred, false,
    "fix round 2: a recorded export is not 'inferred'");
  assert.strictEqual(uc.record.sendOffset, 0, "control: …and the pad opens");

  // J1 gap: `exported > 0` alone is evidence of use in padWasUsed — the file of
  // a pad this device exported must not be importable here (two role-1 holders).
  const d = await o4.generatePad({ label: "r1-d", totalBytes: 8192, fingerBytes: new Uint8Array(0) });
  const dAt = await o4.saveNewPad(d, PASS);
  const dFile = await o4.exportPad(d, XFER);
  await o4.markExported(d, dAt);
  o4.forgetPad(d.padId);
  for (const k of ["used", "wm", "hw"]) localStorage.removeItem(`sc.otp.${k}.v1.${d.padId}`);
  assert.strictEqual(disk.get(d.padId), 0, "precondition: the send floor is 0 (nothing sent)");
  assert.strictEqual(disk.get("recv:" + d.padId), 0, "precondition: recv 0");
  assert.ok(file, "fixture");
  await assert.rejects(o4.importPad(dFile, XFER), /already been used on this device/,
    "an exported pad (exported: 1, send 0, recv 0) is 'used': its own file must not be re-imported here");
  delete globalThis.__SECURE_CHAT_PAD_FLOOR__;
}
console.log("OK  fix round 1: older pre-flag blobs cannot reopen the recv replay or the second export");

// --- ROUND-3 F-1 / F-4 + A4 F-A1-R1: every pad floor write is CHECKED ---------
{
  const XFER = "xfer-p3";
  // The pad file the "device" below imports. Generated in the plain-browser
  // module (no floor), never saved there: only the file leaves.
  const gen = await otp.generatePad({ label: "p3-import", totalBytes: 8192, fingerBytes: new Uint8Array(0) });
  const file = await otp.exportPad(gen, XFER);

  // (1) The first save of a freshly imported pad, and the floor's commit fails.
  // Before: the blob was sealed claiming a floor, the failure was discarded, the
  // save "succeeded" — and after a restart the missing slot was a deletion:
  // "has been deleted", every re-import "already been used". A burned
  // in-person exchange.
  // Each of the three slots in turn is the one whose commit fails, so every
  // slot the blob will claim must be proven BEFORE the claim is sealed.
  const disk = new Map();
  for (const slot of ["recv:", "exported:", ""]) {
    const ctl = { failCommit: (id) => id === slot + gen.padId };
    globalThis.__SECURE_CHAT_PAD_FLOOR__ = kotlinFloor(disk, ctl);
    const d1 = await import("./otp.js?p3=first-fail-" + (slot || "send"));
    const rec = await d1.importPad(file, XFER);
    await assert.rejects(d1.saveNewPad(rec, PASS),
      (e) => e.code === "FLOOR_WRITE_FAILED" && /storage full or not writable/.test(e.message),
      `F-4: a pad floor write (${slot || "send"} slot) that did not commit fails the save, loudly`);
    assert.strictEqual(localStorage.getItem("sc.otp.pad.v1." + gen.padId), null,
      `F-A1-R1: no blob claiming the ${slot || "send"} slot is written before that slot provably exists`);
    assert.strictEqual(d1.padMeta(gen.padId), null, "…and the pad is not half-created");
  }
  globalThis.__SECURE_CHAT_PAD_FLOOR__ = kotlinFloor(disk);            // restart
  const d2 = await import("./otp.js?p3=first-restart");
  const again = await d2.importPad(file, XFER);
  const againAt = await d2.saveNewPad(again, PASS);
  assert.strictEqual((await d2.unlockPad(gen.padId, PASS)).record.sendOffset, 0,
    "F-A1-R1: after a restart the same file imports and opens — the pad is not burned");

  // (2) An established pad, and the ADVANCE does not commit. The save must
  // fail: app.js persists before it transmits (P-04), so this is what keeps a
  // ciphertext the floor never recorded off the wire. Before: the failure was
  // discarded, the frame went out, and after a restart the floor was behind.
  again.sendOffset = 300;
  await d2.savePadProgress(again, againAt);
  assert.strictEqual(disk.get(gen.padId), 300, "precondition: the send floor follows");
  const ctl2 = { failCommit: (id) => id === gen.padId };
  globalThis.__SECURE_CHAT_PAD_FLOOR__ = kotlinFloor(disk, ctl2);      // same device, new session
  const d3 = await import("./otp.js?p3=advance-fail");
  const u3 = await d3.unlockPad(gen.padId, PASS);
  u3.record.sendOffset = 600;
  await assert.rejects(d3.savePadProgress(u3.record, u3.atRest),
    (e) => e.code === "FLOOR_WRITE_FAILED",
    "F-1/F-4: a save whose send floor did not advance is a FAILED save (nothing may be sent)");
  assert.strictEqual(disk.get(gen.padId), 300, "the durable floor did not move — which is why the save failed");
  // The blob did advance (it is written first), so the pad reopens AHEAD of its
  // floor after a restart: wasted keystream, never reused keystream.
  globalThis.__SECURE_CHAT_PAD_FLOOR__ = kotlinFloor(disk);
  const d4 = await import("./otp.js?p3=advance-restart");
  assert.strictEqual((await d4.unlockPad(gen.padId, PASS)).record.sendOffset, 600,
    "a failed advance leaves the blob ahead of the floor (harmless), never behind");

  // (2b) The same for EACH slot on its own, with a floor that is frozen rather
  // than failing (no latch to make a later check catch an earlier omission).
  for (const [slot, set] of [["", (r) => { r.sendOffset += 50; }], ["recv:", (r) => { r.recvHighWater += 40; }]]) {
    globalThis.__SECURE_CHAT_PAD_FLOOR__ = kotlinFloor(disk, { freeze: (id) => id === slot + gen.padId });
    const df = await import("./otp.js?p3=frozen-" + (slot || "send"));
    const uf = await df.unlockPad(gen.padId, PASS);
    set(uf.record);
    await assert.rejects(df.savePadProgress(uf.record, uf.atRest),
      (e) => e.code === "FLOOR_WRITE_FAILED" && /did not move/.test(e.message),
      `ROUND-3 F-1: a FROZEN ${slot || "send"} floor must fail the save, not report success`);
  }
  globalThis.__SECURE_CHAT_PAD_FLOOR__ = kotlinFloor(disk);

  // (3) The markExported latch is checked too — BEFORE the blob is touched.
  const x = await d4.generatePad({ label: "p3-exp", totalBytes: 8192, fingerBytes: new Uint8Array(0) });
  await d4.saveNewPad(x, PASS);
  globalThis.__SECURE_CHAT_PAD_FLOOR__ = kotlinFloor(disk, { freeze: (id) => id === "exported:" + x.padId });
  const d5 = await import("./otp.js?p3=export-fail");
  const ux = await d5.unlockPad(x.padId, PASS);
  const blobBefore = localStorage.getItem("sc.otp.pad.v1." + x.padId);
  await assert.rejects(d5.markExported(ux.record, ux.atRest), (e) => e.code === "FLOOR_WRITE_FAILED",
    "F-1: an export latch that did not land must fail (app.js then hands out no file)");
  assert.strictEqual(localStorage.getItem("sc.otp.pad.v1." + x.padId), blobBefore,
    "F-ATREST-002: the native latch is checked FIRST — a failed latch leaves the stored pad untouched");

  // (4) The quota case: the slots land, the BLOB write fails. Before Package 3
  // the send slot existing at all was "used", so this burned the pad; a slot
  // at 0 is not use (nothing can have been sent: every advance is checked).
  const gen2 = await otp.generatePad({ label: "p3-quota", totalBytes: 8192, fingerBytes: new Uint8Array(0) });
  const file2 = await otp.exportPad(gen2, XFER);
  globalThis.__SECURE_CHAT_PAD_FLOOR__ = kotlinFloor(disk);
  const d6 = await import("./otp.js?p3=quota");
  const r6 = await d6.importPad(file2, XFER);
  const realSet = localStorage.setItem;
  localStorage.setItem = (k, v) => {
    if (k === "sc.otp.pad.v1." + gen2.padId) throw new Error("QuotaExceededError");
    return realSet(k, v);
  };
  try {
    await assert.rejects(d6.saveNewPad(r6, PASS), /QuotaExceededError/);
  } finally {
    localStorage.setItem = realSet;
  }
  assert.strictEqual(disk.get(gen2.padId), 0, "precondition: the send slot was armed at 0 before the blob write");
  const r6b = await d6.importPad(file2, XFER);
  await d6.saveNewPad(r6b, PASS);
  assert.strictEqual((await d6.unlockPad(gen2.padId, PASS)).record.sendOffset, 0,
    "F-A1-R1: a first save that died after arming does not burn the pad");
  // …while a slot ABOVE 0 is still use: the H-3 guard is intact.
  assert.strictEqual(d6.padWasUsed(gen.padId), true, "a pad whose floor moved is still 'used'");
  delete globalThis.__SECURE_CHAT_PAD_FLOOR__;
}
console.log("OK  ROUND-3 F-1/F-4, A4 F-A1-R1: pad floor writes are checked; a failed first save burns nothing");

// --- 7b: the floor wrapper refuses a value it cannot hold ---------------------
{
  const calls = [];
  globalThis.__SECURE_CHAT_PAD_FLOOR__ = {
    read: () => -1,
    bump: (id, v) => { calls.push(v); return v; },
  };
  const { captureNativeFloor, NATIVE_INVALID, NATIVE_TAMPERED, FLOOR_MAX } = await import("./nativefloor.js?p3=7b");
  const nf = captureNativeFloor();
  for (const bad of [2 ** 31, -1, 1.5, NaN, "5", 2 ** 32 + 7]) {
    assert.strictEqual(nf.bump("x", bad), NATIVE_INVALID,
      `7b: bump(${String(bad)}) must be refused, not truncated (\`v | 0\` made 2^31 negative and the floor froze)`);
  }
  assert.deepStrictEqual(calls, [], "7b: …before the bridge is ever called");
  assert.strictEqual(nf.bump("x", FLOOR_MAX), FLOOR_MAX, "the ceiling itself is a valid value");
  // A read answering a negative that is not ABSENT is TAMPERED, never a value
  // that slips past both `=== ABSENT` and `> ABSENT`.
  globalThis.__SECURE_CHAT_PAD_FLOOR__ = { read: () => -3, bump: () => -3 };
  const nf2 = (await import("./nativefloor.js?p3=7b-read")).captureNativeFloor();
  assert.strictEqual(nf2.read("x"), NATIVE_TAMPERED);
  // Fix round 1 (Info): the record cap's answer (-5) fails a save like any other.
  const { bumpFloor } = await import("./nativefloor.js?p3=7b-read");
  assert.throws(() => bumpFloor({ bump: () => -5 }, "x", 1, "test"),
    (e) => e.code === "FLOOR_WRITE_FAILED" && /store is full/.test(e.message));
  delete globalThis.__SECURE_CHAT_PAD_FLOOR__;
}
console.log("OK  7b: out-of-range floor values are refused before the bridge; odd negative reads are TAMPERED");

// --- F-P7-5: the adoption gate is keyed INSIDE the AEAD -----------------------
// (plain browser: no floor, which is where this gate is the only control)
{
  const p = await otp.generatePad({ label: "p7-5", totalBytes: 8192, fingerBytes: new Uint8Array(0) });
  const pAt = await otp.saveNewPad(p, PASS);
  p.sendOffset = 900;
  await otp.savePadProgress(p, pAt);
  // An archived v2 snapshot at offset 0, its outer byte rewritten to 3 (no key
  // needed — plaintext), and the three deletable markers removed.
  await makeV2Blob(p.padId, pAt.key, (inner) => { inner.sendOffset = 0; });
  const outer = JSON.parse(localStorage.getItem("sc.otp.pad.v1." + p.padId));
  outer.v = 3;
  localStorage.setItem("sc.otp.pad.v1." + p.padId, JSON.stringify(outer));
  for (const k of ["wm", "used", "hw"]) localStorage.removeItem(`sc.otp.${k}.v1.${p.padId}`);
  await assert.rejects(otp.unlockPad(p.padId, PASS), (e) => e.code === "LEGACY_PAD_ADOPTION",
    "F-P7-5: a v2 blob claiming `v: 3` outside the AEAD must still hit the adoption gate, not open at offset 0");
  // …and when the user does adopt it, it is really upgraded (the migration is
  // keyed the same way): the next unlock finds the authenticated mirror.
  await otp.unlockPad(p.padId, PASS, { adoptLegacy: true });
  const cur = JSON.parse(localStorage.getItem("sc.otp.pad.v1." + p.padId));
  const inner = JSON.parse(_dec.decode(await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: _unb64(cur.iv) }, pAt.key, _unb64(cur.ct))));
  assert.ok(Number.isInteger(inner.hwSend), "F-P7-5: an adopted pre-v3 blob is rewritten with hwSend inside the AEAD");
}
console.log("OK  F-P7-5: rewriting the outer `v` cannot skip the pad adoption gate or the upgrade");

// --- F-P7-A3 residual: knownUsedHere does not trust Number.isInteger ----------
{
  const p = await otp.generatePad({ label: "a3", totalBytes: 8192, fingerBytes: new Uint8Array(0) });
  const pAt = await otp.saveNewPad(p, PASS);
  const pristine = localStorage.getItem("sc.otp.pad.v1." + p.padId);   // hwSend 0, hwRecv 0
  p.sendOffset = 900;
  await otp.savePadProgress(p, pAt);
  localStorage.setItem("sc.otp.pad.v1." + p.padId, pristine);
  for (const k of ["wm", "used", "hw"]) localStorage.removeItem(`sc.otp.${k}.v1.${p.padId}`);
  const REAL = Number.isInteger;
  // Selective, as an attacker would write it: false only for the restored
  // blob's watermark values, so the KDF and region-size checks still pass.
  Number.isInteger = (v) => (v === 0 ? false : REAL(v));
  try {
    await assert.rejects(otp.unlockPad(p.padId, PASS), /rollback record for this pad is missing/,
      "F-P7-A3: a poisoned Number.isInteger must not turn knownUsedHere off and reopen a restored pad");
  } finally {
    Number.isInteger = REAL;
  }
}
console.log("OK  F-P7-A3: knownUsedHere uses no writable global");

// --- F-CRYPTO-012: every offered pad size can be generated -------------------
{
  for (const { bytes } of otp.PAD_SIZES) {
    for (const finger of [new Uint8Array(0), new Uint8Array([1, 2, 3, 4])]) {
      const p = await otp.generatePad({ label: "size", totalBytes: bytes, fingerBytes: finger });
      assert.strictEqual(p.bytes.length, bytes, `F-CRYPTO-012: a ${bytes}-byte pad is generated`);
      assert.ok(otp.looksRandom(p.bytes), "…and it is random");
      // No chunk is left unfilled (a zero 64 KiB tail would pass looksRandom's sample).
      for (let off = 0; off < bytes; off += 65536) {
        const chunk = p.bytes.subarray(off, off + 65536);
        assert.ok(chunk.some((b) => b !== 0), `F-CRYPTO-012: chunk at ${off} was filled`);
      }
    }
  }
}
console.log("OK  F-CRYPTO-012: 64 KiB, 256 KiB and 1 MiB pads all generate (chunked CSPRNG)");

// --- fix round 2 ----------------------------------------------------------------
// (1) FULL (-5, the PadFloor record cap) fails a first save closed: nothing written.
{
  const disk = new Map();
  globalThis.__SECURE_CHAT_PAD_FLOOR__ = kotlinFloor(disk, { full: true });
  const o = await import("./otp.js?p3r2=full");
  const p = await o.generatePad({ label: "full", totalBytes: 8192, fingerBytes: new Uint8Array(0) });
  await assert.rejects(o.saveNewPad(p, PASS),
    (e) => e.code === "FLOOR_WRITE_FAILED" && /store is full/.test(e.message),
    "fix round 2: a full floor store fails the save with the 'full' reason");
  assert.strictEqual(localStorage.getItem("sc.otp.pad.v1." + p.padId), null, "…and nothing is written");
  assert.strictEqual(o.padMeta(p.padId), null);
  delete globalThis.__SECURE_CHAT_PAD_FLOOR__;
}
// (2) The "rollback record missing" advice. Re-import is only offered where the
// import can really tell prior use (a native floor). In a browser padWasUsed
// sees only the deletable markers the attacker removed (poc6: two-time pad).
{
  const XFER = "xfer-r2";
  const gen = await otp.generatePad({ label: "r2-browser", totalBytes: 8192, fingerBytes: new Uint8Array(0) });
  const file = await otp.exportPad(gen, XFER);
  const imp = await otp.importPad(file, XFER);
  const at = await otp.saveNewPad(imp, PASS);
  imp.sendOffset = 500;
  await otp.savePadProgress(imp, at);
  for (const k of ["wm", "used", "hw"]) localStorage.removeItem(`sc.otp.${k}.v1.${imp.padId}`);
  const e = await otp.unlockPad(imp.padId, PASS).then(() => null, (x) => x);
  assert.ok(e && /rollback record for this pad is missing/.test(e.message), "fixture: refused");
  assert.doesNotMatch(e.message, /import the same file again/,
    "fix round 2: in a browser the refusal must NOT advise re-importing (the import cannot verify use there)");
  assert.match(e.message, /cannot verify whether this pad was already used/, "…it says why, and to exchange a fresh pad");
  // Native: a first save killed between blob and watermark — the advice holds.
  const disk = new Map();
  globalThis.__SECURE_CHAT_PAD_FLOOR__ = kotlinFloor(disk);
  const o = await import("./otp.js?p3r2=advice-native");
  const gen2 = await otp.generatePad({ label: "r2-native", totalBytes: 8192, fingerBytes: new Uint8Array(0) });
  const file2 = await otp.exportPad(gen2, XFER);
  const imp2 = await o.importPad(file2, XFER);
  await o.saveNewPad(imp2, PASS);
  localStorage.removeItem("sc.otp.wm.v1." + imp2.padId);
  const e2 = await o.unlockPad(imp2.padId, PASS).then(() => null, (x) => x);
  assert.ok(e2 && /import the same file again/.test(e2.message), "fix round 2: with a native floor the re-import advice stays");
  o.forgetPad(imp2.padId);
  for (const k of ["used", "hw"]) localStorage.removeItem(`sc.otp.${k}.v1.${imp2.padId}`);
  await o.importPad(file2, XFER); // …and it is true: nothing was used, the floor says 0
  delete globalThis.__SECURE_CHAT_PAD_FLOOR__;
}
console.log("OK  fix round 2: FULL fails closed; re-import advice only where a floor can verify it");

console.log("\nAll OTP rollback checks passed.");
