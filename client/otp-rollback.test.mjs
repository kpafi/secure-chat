// M-01 regression: a full old encrypted-pad blob restore (rolling sendOffset
// back to reuse consumed keystream) is refused by the separate high-water
// tripwire. Run: node otp-rollback.test.mjs
import assert from "node:assert";
import { readFile } from "node:fs/promises";
import { stripComments, codeLines } from "./test-source.mjs";

// ROUND-5 (cold reviewer). The two `Object.defineProperty` injections that
// publish `__SECURE_CHAT_NATIVE_FLOOR__` and `__SECURE_CHAT_PAD_FLOOR__` sit a
// few lines apart in MainActivity.kt, and both anchors below used to slice from
// `indexOf(<name>)` to the END OF THE FILE. Each slice therefore contained the
// OTHER block, so each was satisfied by the other's attribute list and neither
// pinned its own target: flipping one to `configurable: true` — which makes the
// protected name deletable from a document-start script, the exact downgrade H-1
// and H-A exist to stop — left the suite green.
//
// Two things are needed. Bound each block to ITS OWN call by paren matching, and
// strip comments from the injected JS so a comment cannot satisfy it. The
// injection lives inside a Kotlin RAW STRING, which the JS scanner cannot parse
// (see android-source.test.mjs), so pull the raw string out first and strip
// THAT — it is JavaScript, which is exactly what the scanner is for.
function injectedJs(kotlinSrc) {
  const open = kotlinSrc.indexOf('"""');
  if (open === -1) return null;
  const close = kotlinSrc.indexOf('"""', open + 3);
  if (close === -1) return null;
  return stripComments(kotlinSrc.slice(open + 3, close));
}

// The single `Object.defineProperty(...)` call whose arguments name `global`,
// bounded by paren matching so the NEXT call cannot stand in for it.
function definePropertyFor(js, global) {
  const re = /Object\.defineProperty\s*\(/g;
  for (let m = re.exec(js); m; m = re.exec(js)) {
    let i = js.indexOf("(", m.index);
    let depth = 0;
    for (; i < js.length; i++) {
      if (js[i] === "(") depth++;
      else if (js[i] === ")" && --depth === 0) { i++; break; }
    }
    const block = js.slice(m.index, i);
    if (block.includes(global)) return block;
  }
  return null;
}

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

// Re-keying that same blob under a fresh id must still be refused.
const copy = JSON.parse(localStorage.getItem(pKey));
delete copy.v; copy.padId = "forgedid"; copy.regionSize = p.regionSize; copy.role = 0;
localStorage.setItem("sc.otp.pad.v1.forgedid", JSON.stringify(copy));
await assert.rejects(
  otp.unlockPad("forgedid", PASS), /does not match its storage key/,
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
async function makeV2Blob(padId, key, mutate) {
  const k = "sc.otp.pad.v1." + padId;
  const cur = JSON.parse(localStorage.getItem(k));
  const inner = JSON.parse(_dec.decode(await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: _unb64(cur.iv) }, key, _unb64(cur.ct),
  )));
  delete inner.hwSend;    // v3-only: the authenticated watermark mirror
  delete inner.hwRecv;
  delete inner.exported;  // v3-only: L-3 moved this inside the AEAD
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
  assert.match(activity, /__SECURE_CHAT_NATIVE_FLOOR__/, "the app must inject the marker");
  const injected = injectedJs(activity);
  assert.ok(injected, "MainActivity.kt must still carry the injected document-start script");
  const markerDef = definePropertyFor(injected, "__SECURE_CHAT_NATIVE_FLOOR__");
  assert.ok(markerDef,
    "H-1: the marker must be published with Object.defineProperty, not a plain assignment");
  assert.match(markerDef, /configurable:\s*false/,
    "H-1: the marker must be non-configurable or `delete` hides the downgrade. Bounded to its " +
    "OWN defineProperty call (ROUND-5): slicing to end-of-file let the OTHER injection's " +
    `attribute list satisfy this. Found: ${markerDef}`);

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
  const injectedA = injectedJs(activity);
  assert.ok(injectedA, "MainActivity.kt must still carry the injected document-start script");
  const inject = definePropertyFor(injectedA, "__SECURE_CHAT_PAD_FLOOR__");
  assert.ok(inject,
    "H-A: the bridge must be published with Object.defineProperty, not a plain assignment");
  assert.match(inject, /Object\.freeze/, "H-A: the published bridge must be frozen");
  assert.match(inject, /\.bind\(b\)/,
    "H-A: methods must be BOUND, or a later `b.read = fake` is still obeyed");
  assert.match(inject, /configurable:\s*false/,
    "H-A: the published name must be non-configurable. Bounded to its OWN defineProperty call " +
    `(ROUND-5) so the marker's block cannot satisfy it. Found: ${inject}`);
  // otp.js must not read the writable global at all any more.
  const otpSrc = await readFile(new URL("./otp.js", import.meta.url), "utf8");
  const code = stripComments(otpSrc);
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
  const code = stripComments(src);
  const rollback = code.slice(code.indexOf("export async function unlockPad"));
  for (const bad of [/\bMath\.max\(/, /\bparseInt\(/, /\bNumber\.isFinite\(/]) {
    assert.ok(!bad.test(rollback), `H-1: ${bad} is poisonable and must not decide a rollback`);
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

console.log("\nAll OTP rollback checks passed.");

// --- F-ATREST-001 / F-ATREST-002 -------------------------------------------
// The native floor covered the SEND offset only: 1 of ~5 rollback-sensitive
// counters (F-ATREST-009). So on Android — the one platform with a floor at all
// — a recv rollback replayed every frame the peer had already sent, and an
// `exported` rollback re-armed export, and a second export of one pad is a
// two-time pad.
async function testRecvAndExportedFloors() {
  const slots = new Map();
  // Model of PadFloor.kt: monotone per opaque key, never lowers, MACs the key
  // and value together so slots cannot be lifted between each other.
  const floor = {
    read: (k) => (slots.has(k) ? slots.get(k) : -1),
    bump: (k, v) => {
      if (v < 0) return floor.read(k);
      const next = Math.max(floor.read(k), v);
      slots.set(k, next);
      return next;
    },
  };
  Object.defineProperty(globalThis, "__SECURE_CHAT_NATIVE_FLOOR__", { value: true, configurable: true });
  Object.defineProperty(globalThis, "__SECURE_CHAT_PAD_FLOOR__", { value: Object.freeze(floor), configurable: true });

  const otp = await import(`./otp.js?floors=${Date.now()}`);
  const PASS = "pad passphrase";
  const pad = await otp.generatePad({ label: "floors", totalBytes: 64 * 1024 });

  const atRest = await otp.saveNewPad(pad, PASS);
  const pristine = localStorage.getItem(`sc.otp.pad.v1.${pad.padId}`);
  const pristineWm = localStorage.getItem(`sc.otp.wm.v1.${pad.padId}`);

  // Receive some traffic, then persist.
  pad.recvHighWater = 4096;
  await otp.savePadProgress(pad, atRest);
  assert.strictEqual(floor.read(pad.padId + "#recv"), 4096, "the recv floor must be mirrored natively");

  // The whole-storage rollback the send floor already refuses — now for recv.
  localStorage.setItem(`sc.otp.pad.v1.${pad.padId}`, pristine);
  localStorage.setItem(`sc.otp.wm.v1.${pad.padId}`, pristineWm);
  await assert.rejects(() => otp.unlockPad(pad.padId, PASS), /receive state was rolled back/,
    "restoring BOTH blob and watermark must still be caught by the native recv floor");
  console.log("OK  F-ATREST-001: a recv rollback is refused even with blob+watermark restored");

  // F-ATREST-002: export latches natively and outlives a pre-export snapshot.
  //
  // On a pad of its own, so the recv floor above cannot decide this case. The
  // previous version of this test reached for `slots.delete(padId + "#recv")` to
  // isolate the latch — deleting a control to test its neighbour — and that
  // deletion is exactly the 2026-08-08 item 13 attack, which the assertions
  // below now cover deliberately instead.
  const exp = await otp.generatePad({ label: "export-latch", totalBytes: 64 * 1024 });
  const expAtRest = await otp.saveNewPad(exp, PASS);
  const expPristine = localStorage.getItem(`sc.otp.pad.v1.${exp.padId}`);
  const expPristineWm = localStorage.getItem(`sc.otp.wm.v1.${exp.padId}`);
  assert.strictEqual(floor.read(exp.padId + "#exported"), 0,
    "item 13: the export slot must exist from the first save, so its ABSENCE is unambiguous");

  await otp.markExported(exp, expAtRest);
  assert.strictEqual(floor.read(exp.padId + "#exported"), 1, "export must latch natively");

  localStorage.setItem(`sc.otp.pad.v1.${exp.padId}`, expPristine);
  localStorage.setItem(`sc.otp.wm.v1.${exp.padId}`, expPristineWm);
  await assert.rejects(() => otp.unlockPad(exp.padId, PASS), /already exported once/,
    "a pre-export snapshot must not re-arm export — that is a two-time pad");
  console.log("OK  F-ATREST-002: an `exported` rollback is refused by the native latch");

  // --- item 13 -------------------------------------------------------------
  // The 2026-07-29 H-1 deletion guard reads the SEND slot only, so the two
  // derived slots the F-ATREST-001/002 fix added could each be deleted in one
  // file edit and read back as "no floor". Each derived id is its own
  // SharedPreferences entry, so this needs no rollback of the send floor.

  // (a) `#exported` deleted + a pre-export snapshot = a SECOND export of a
  //     pristine pad. This is the two-time pad, and it is the whole point.
  localStorage.setItem(`sc.otp.pad.v1.${exp.padId}`, expPristine);
  localStorage.setItem(`sc.otp.wm.v1.${exp.padId}`, expPristineWm);
  slots.delete(exp.padId + "#exported");
  assert.strictEqual(floor.read(exp.padId + "#exported"), -1, "precondition: the slot is gone");
  await assert.rejects(() => otp.unlockPad(exp.padId, PASS),
    /device-protected rollback record has been deleted/,
    "item 13: deleting the #exported slot must not re-arm export");
  console.log("OK  item 13: a deleted `#exported` slot is refused, not read as 'never exported'");

  // (b) `#recv` deleted — the M-7 replay window. The send floor is untouched and
  //     the send guard therefore does not fire; only the derived check catches it.
  localStorage.setItem(`sc.otp.pad.v1.${pad.padId}`, pristine);
  localStorage.setItem(`sc.otp.wm.v1.${pad.padId}`, pristineWm);
  slots.delete(pad.padId + "#recv");
  assert.notStrictEqual(floor.read(pad.padId), -1, "precondition: the SEND floor is still present");
  await assert.rejects(() => otp.unlockPad(pad.padId, PASS),
    /device-protected rollback record has been deleted/,
    "item 13: deleting the #recv slot must not reopen the replay window");
  console.log("OK  item 13: a deleted `#recv` slot is refused, not read as 'no floor'");

  // (c) The guard must not brick pads that predate the derived slots. A blob
  //     with `nativeFloor: true` and no `derivedFloors` is the 2026-07-29 shape,
  //     and it legitimately has no derived slots at all — this is why the check
  //     is keyed on a new field instead of tightening the old one.
  const old = await otp.generatePad({ label: "pre-derived", totalBytes: 64 * 1024 });
  const oldAtRest = await otp.saveNewPad(old, PASS);
  // Reconstruct the old writer's output: the same v3 blob minus the one field it
  // never wrote, re-encrypted under the same at-rest key. `nativeFloor` stays
  // true, which is what makes this the interesting case — the send guard fires
  // on it, so only the `derivedFloors` gate keeps the derived check off.
  const oldKey = "sc.otp.pad.v1." + old.padId;
  const oldCur = JSON.parse(localStorage.getItem(oldKey));
  const oldInner = JSON.parse(_dec.decode(await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: _unb64(oldCur.iv) }, oldAtRest.key, _unb64(oldCur.ct),
  )));
  assert.strictEqual(oldInner.derivedFloors, true, "precondition: the new writer sets the marker");
  assert.strictEqual(oldInner.nativeFloor, true, "precondition: a floor was in force");
  delete oldInner.derivedFloors;
  const oldIv = crypto.getRandomValues(new Uint8Array(12));
  const oldCt = new Uint8Array(await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: oldIv }, oldAtRest.key, _enc.encode(JSON.stringify(oldInner)),
  ));
  localStorage.setItem(oldKey, JSON.stringify({
    v: oldCur.v, kdf: oldCur.kdf, iv: _b64(oldIv), ct: _b64(oldCt),
  }));
  // The state a 2026-07-29-era pad is actually in: no derived slots ever written.
  slots.delete(old.padId + "#recv");
  slots.delete(old.padId + "#exported");
  const opened = await otp.unlockPad(old.padId, PASS);
  assert.ok(opened.record, "a pre-derived-slot pad must still open with no derived slots present");
  console.log("OK  item 13: pads written before the derived slots existed are not bricked");

  delete globalThis.__SECURE_CHAT_NATIVE_FLOOR__;
  delete globalThis.__SECURE_CHAT_PAD_FLOOR__;
}

await testRecvAndExportedFloors();

// --- item 13, second pass: the fix must not BRICK a pad --------------------
// The first cut wrote `derivedFloors: !!nativeFloor` into the blob BEFORE the
// bumps that back it, and discarded their return values. A derived bump that
// failed or was interrupted during a pad's FIRST save therefore left the blob
// asserting slots that were never written, and the guard above then refused the
// pad forever — using the wording of the tamper alarm, and with `padWasUsed`
// blocking re-import so the padId was burned. Found by pentest, reproduced, and
// confirmed to open normally on the pre-fix code, i.e. a regression the fix
// itself introduced.
//
// Neither layer reports a failed bump: the JS wrapper swallows bridge exceptions
// into NATIVE_TAMPERED and PadFloor.bump ignores commit()'s boolean. So the flags
// are decided by READING THE SLOTS BACK.
async function testFailedBumpDoesNotBrickAPad() {
  for (const failing of ["#recv", "#exported", ""]) {
    const slots = new Map();
    // A floor whose bump silently does nothing for ONE slot — a transient
    // Keystore error, or a commit() that returned false on a full disk.
    const floor = {
      read: (k) => (slots.has(k) ? slots.get(k) : -1),
      bump: (k, v) => {
        if (k.endsWith(failing) && (failing !== "" || !k.includes("#"))) return floor.read(k);
        if (v < 0) return floor.read(k);
        const n = Math.max(floor.read(k), v);
        slots.set(k, n);
        return n;
      },
    };
    Object.defineProperty(globalThis, "__SECURE_CHAT_NATIVE_FLOOR__", { value: true, configurable: true });
    Object.defineProperty(globalThis, "__SECURE_CHAT_PAD_FLOOR__", { value: Object.freeze(floor), configurable: true });
    const fresh = new Map();
    globalThis.localStorage = {
      getItem: (k) => (fresh.has(k) ? fresh.get(k) : null),
      setItem: (k, v) => fresh.set(k, String(v)),
      removeItem: (k) => fresh.delete(k),
    };

    const otp = await import(`./otp.js?brick=${failing}&t=${Date.now()}`);
    const PASS = "pad passphrase";
    const pad = await otp.generatePad({ label: "brick", totalBytes: 64 * 1024 });
    await otp.saveNewPad(pad, PASS);

    const which = failing === "" ? "the SEND slot" : `the ${failing} slot`;
    // A4/F-A3 (2026-08-20) changed what this state looks like on the way out, and
    // the change is the point: an unarmable slot is no longer sealed as the same
    // `false` a plain browser writes, so unlockPad now routes the pad through the
    // adoption consent gate instead of opening it on a claim nothing can check.
    // What must NOT change is that the pad is not BRICKED — the gate is passable,
    // and item 13's whole lesson was that a permanent refusal here destroys an
    // in-person key exchange.
    await assert.rejects(() => otp.unlockPad(pad.padId, PASS),
      (e) => e.code === "LEGACY_PAD_ADOPTION",
      `F-A3: a first save where ${which} failed to take must be GATED — the blob carries a ` +
      "floor claim that nothing on this device can verify");
    const opened = await otp.unlockPad(pad.padId, PASS, { adoptLegacy: true });
    assert.ok(opened.record,
      `item 13: a first save where ${which} failed to take must leave the pad USABLE, ` +
      "not permanently refused — the fix must never brick a pad it was meant to protect");
    assert.strictEqual(opened.record.sendOffset, 0, "...and at its true offset");
    console.log(`OK  item 13: a first save with ${which} unwritable is gated but not bricked`);

    // ...and the guard must ARM as soon as the floor starts working again, so
    // the degraded state is temporary rather than a permanent hole.
    // Deliberately NOT pre-seeded: the point is that `armFloors` writes these
    // slots itself once the floor works. Seeding them here would prove only that
    // the guard fires when slots exist, which is a different (already covered)
    // claim — flagged by the 2026-08-10 pentest.
    const healthy = {
      read: (k) => (slots.has(k) ? slots.get(k) : -1),
      bump: (k, v) => { if (v < 0) return healthy.read(k); const n = Math.max(healthy.read(k), v); slots.set(k, n); return n; },
    };
    Object.defineProperty(globalThis, "__SECURE_CHAT_PAD_FLOOR__", { value: Object.freeze(healthy), configurable: true });
    const otp2 = await import(`./otp.js?heal=${failing}&t=${Date.now()}`);
    // Still adopted explicitly: the blob on disk was sealed during the degraded
    // window and keeps its unverifiable claim until a healthy save rewrites it.
    // That permanence is the F-A3 finding's core point — an AEAD already written
    // cannot be reached back into — so the gate correctly still fires here.
    const r = await otp2.unlockPad(pad.padId, PASS, { adoptLegacy: true });
    r.record.recvHighWater = 4096;
    await otp2.savePadProgress(r.record, r.atRest);   // a save with a working floor
    slots.delete(pad.padId + "#recv");                 // now delete a derived slot
    await assert.rejects(() => otp2.unlockPad(pad.padId, PASS),
      /device-protected rollback record has been deleted/,
      "item 13: once a save succeeds with a working floor, the guard must be armed again");
    console.log(`OK  item 13: ...and the guard re-arms on the next healthy save (${which})`);

    delete globalThis.__SECURE_CHAT_NATIVE_FLOOR__;
    delete globalThis.__SECURE_CHAT_PAD_FLOOR__;
  }
}

await testFailedBumpDoesNotBrickAPad();

// --- ROUND-3 F-4: a bump whose commit() FAILED must fail the save ----------
// The Android residual the F-1 read-back cannot reach. `SharedPreferences.commit()`
// writes the in-memory map synchronously and does NOT roll it back on a failed disk
// write, and `PadFloor.read` is backed by that map — so after a failed commit a
// read-back reports the NEW value while the DURABLE floor is unchanged. The F-1
// stuck-check is a read-back, so it passes; armFloors used to report success,
// app.js transmitted (persist-before-transmit, P-04), and a restart + a pristine
// re-import respent the keystream: a two-time pad, the one failure OTP cannot
// survive.
//
// The ONLY witness is the bump's OWN return, which PadFloor.bump now surfaces as
// NATIVE_COMMIT_FAILED (-3) instead of discarding commit()'s boolean. This mock
// models that faithfully: `mem` is the in-memory SharedPreferences map (read() is
// backed by it and always looks healthy after a bump); `disk` is what a process
// restart would actually read; a failing slot's bump advances `mem` AND returns
// -3, and NEVER writes `disk`. The item-13 mock (which returns the OLD value and
// writes neither) is NOT a valid model here — a real device's read-back is healthy
// — so it is deliberately not reused; that is the whole point of a separate test.
const NATIVE_COMMIT_FAILED = -3;
function makePrefsFloor(failingSlot) {
  const mem = new Map();   // SharedPreferencesImpl's in-memory map — read() reads THIS
  const disk = new Map();  // what survives a process restart
  // failingSlot: null = every slot healthy; "" = the SEND slot (no '#'); "#recv" /
  // "#exported" = that derived slot. Matches the item-13 mock's slot selector.
  const isFailing = (k) => (failingSlot === "" ? !k.includes("#") : k.endsWith(failingSlot));
  const floor = {
    mem, disk,
    read: (k) => (mem.has(k) ? mem.get(k) : -1),
    bump: (k, v) => {
      if (v < 0) return mem.has(k) ? mem.get(k) : -1;
      const cur = mem.has(k) ? mem.get(k) : -1;
      const next = cur === -1 ? v : Math.max(cur, v);
      if (next === cur) return cur;              // monotone no-op: no commit() at all
      mem.set(k, next);                           // commitToMemory ALWAYS runs first
      if (failingSlot !== null && isFailing(k)) return NATIVE_COMMIT_FAILED; // disk failed
      disk.set(k, next);                          // healthy: the durable write lands
      return next;
    },
  };
  return floor;
}

async function testCommitFailureFailsTheSave() {
  for (const failing of ["", "#recv", "#exported"]) {
    const which = failing === "" ? "the SEND slot" : `the ${failing} slot`;
    // Phase 1: ESTABLISH the pad with a fully healthy floor, so all three slots
    // exist and are DURABLE. F-4 is an established pad advancing onto a frozen disk
    // — distinct from a first save whose slot could not be created at all (that is
    // probeFloors' CLAIM_UNCONFIRMED path, covered by testFailedBumpDoesNotBrickAPad).
    const healthy = makePrefsFloor(null);
    const store = new Map();
    globalThis.localStorage = {
      getItem: (k) => (store.has(k) ? store.get(k) : null),
      setItem: (k, v) => store.set(k, String(v)),
      removeItem: (k) => store.delete(k),
    };
    Object.defineProperty(globalThis, "__SECURE_CHAT_NATIVE_FLOOR__", { value: true, configurable: true });
    Object.defineProperty(globalThis, "__SECURE_CHAT_PAD_FLOOR__", { value: Object.freeze(healthy), configurable: true });
    const mod1 = await import(`./otp.js?f4est=${failing}&t=${Date.now()}`);
    const PASS = "pad passphrase";
    const pad = await mod1.generatePad({ label: "f4", totalBytes: 64 * 1024 });
    await mod1.saveNewPad(pad, PASS);           // establishes durable slots at 0

    // Phase 2: swap in a floor that FAILS the target slot's disk commit, carrying
    // the SAME mem+disk state forward (a process that keeps running — the healthy
    // slots stay durable). `nativeFloor` is captured at module load, so re-import.
    const failer = makePrefsFloor(failing);
    for (const [k, v] of healthy.mem) failer.mem.set(k, v);
    for (const [k, v] of healthy.disk) failer.disk.set(k, v);
    Object.defineProperty(globalThis, "__SECURE_CHAT_PAD_FLOOR__", { value: Object.freeze(failer), configurable: true });
    const mod2 = await import(`./otp.js?f4fail=${failing}&t=${Date.now()}`);
    const r = await mod2.unlockPad(pad.padId, PASS);

    // Advance the counter that the target slot backs, then try to persist.
    if (failing === "") r.record.sendOffset = 900;
    else if (failing === "#recv") r.record.recvHighWater = 4096;
    else r.record.exported = true;
    const target = failing === "" ? pad.padId : pad.padId + failing;
    const durableBefore = failer.disk.has(target) ? failer.disk.get(target) : -1;

    // (a) the save REJECTS. armFloors sees the bump's NATIVE_COMMIT_FAILED for a
    // slot the blob CLAIMS ARMED, so it throws before app.js can transmit (P-04).
    await assert.rejects(
      () => mod2.savePadProgress(r.record, r.atRest),
      /did not record this pad's progress|Nothing was sent/,
      `F-4: a save whose commit() failed for ${which} must REJECT — the durable floor did not ` +
      "move, and app.js persists before it transmits, so the keystream must not go on the wire");
    console.log(`OK  F-4: a save whose commit() fails for ${which} is rejected (nothing transmitted)`);

    // (b) H-3 stays closed. The DURABLE floor genuinely did NOT advance (commit
    // failed) — a real restart would read the old value — even though a bare read()
    // looks healthy because the in-memory map moved. Because (a) refused the save,
    // the offset the target slot backs was never released onto the wire, so no
    // keystream was spent; re-importing the pristine pad at offset 0 later would be
    // a FIRST use, not a reuse. The rejection is the ONLY thing standing between
    // here and a two-time pad, which is exactly why the durable floor being frozen
    // must fail the save rather than be papered over by a healthy-looking read-back.
    const durableAfter = failer.disk.has(target) ? failer.disk.get(target) : -1;
    assert.strictEqual(durableAfter, durableBefore,
      `F-4: the durable ${which} floor must be UNCHANGED after a failed commit — a restart would ` +
      "read the old value, so it is the refused save (not the floor) that keeps H-3 closed");
    assert.ok(failer.read(target) > durableAfter,
      `F-4: the in-memory read of ${which} DID advance and looks healthy — proving a read-back ` +
      "cannot see the failure and the bump's return is the only witness the fix can react to");

    delete globalThis.__SECURE_CHAT_NATIVE_FLOOR__;
    delete globalThis.__SECURE_CHAT_PAD_FLOOR__;
  }

  // (c) CONTROL: a healthy commit still saves normally and the durable floor moves.
  const healthy = makePrefsFloor(null);
  const store = new Map();
  globalThis.localStorage = {
    getItem: (k) => (store.has(k) ? store.get(k) : null),
    setItem: (k, v) => store.set(k, String(v)),
    removeItem: (k) => store.delete(k),
  };
  Object.defineProperty(globalThis, "__SECURE_CHAT_NATIVE_FLOOR__", { value: true, configurable: true });
  Object.defineProperty(globalThis, "__SECURE_CHAT_PAD_FLOOR__", { value: Object.freeze(healthy), configurable: true });
  const mod = await import(`./otp.js?f4ok=${Date.now()}`);
  const PASS = "pad passphrase";
  const pad = await mod.generatePad({ label: "f4-ok", totalBytes: 64 * 1024 });
  const at = await mod.saveNewPad(pad, PASS);
  pad.sendOffset = 900;
  await mod.savePadProgress(pad, at);           // must NOT throw
  assert.strictEqual(healthy.disk.get(pad.padId), 900,
    "F-4 control: a healthy commit advances the DURABLE send floor and the save succeeds");
  const reopened = await mod.unlockPad(pad.padId, PASS);
  assert.strictEqual(reopened.record.sendOffset, 900, "F-4 control: the pad reopens at its true offset");
  console.log("OK  F-4 control: a healthy commit still saves normally and the durable floor advances");
  delete globalThis.__SECURE_CHAT_NATIVE_FLOOR__;
  delete globalThis.__SECURE_CHAT_PAD_FLOOR__;
}
await testCommitFailureFailsTheSave();

// Kotlin SOURCE anchor (Kotlin cannot run in this suite). The entire JS-side
// reaction above is worthless unless PadFloor.bump actually SURFACES commit()'s
// boolean as a distinct sentinel instead of discarding it and returning the
// intended value — the F-4 residual in one line. Pin that at the source so a
// revert to `.commit(); return next` cannot slip past this suite unnoticed.
{
  const kt = await readFile(
    new URL("../android/app/src/main/java/org/securechat/app/PadFloor.kt", import.meta.url),
    "utf8",
  );
  assert.match(kt, /const val COMMIT_FAILED = -3L/,
    "F-4: PadFloor must define COMMIT_FAILED = -3L beside ABSENT/TAMPERED");
  const bumpBody = kt.slice(
    kt.indexOf("fun bump("),
    kt.indexOf("// Pentest 2026-07-29 H-1: there is deliberately NO clear"),
  );
  assert.match(bumpBody, /\.commit\(\)/, "F-4: bump must call commit()");
  assert.match(bumpBody, /if\s*\(\s*committed\s*\)\s*next\s+else\s+COMMIT_FAILED/,
    "F-4: bump must return COMMIT_FAILED when commit() returns false, not discard the boolean");
  assert.doesNotMatch(bumpBody, /\.commit\(\)\s*\n\s*return next/,
    "F-4: bump must NOT discard commit()'s boolean and return the intended value unconditionally");
  console.log("OK  F-4 (Kotlin source): PadFloor.bump surfaces commit()'s boolean as COMMIT_FAILED");
}

// A CORRUPTED slot is not the same as an absent one, and must not be handled the
// same way. NATIVE_ABSENT (-1) is benign — nothing was ever written. TAMPERED
// (-2) means something IS there and its Keystore MAC did not verify, which costs
// an attacker exactly one file edit, the same as a deletion. The first repair
// collapsed both with `>= 0`, so corrupting a slot silently disarmed the guard
// that deleting it trips: fail-OPEN, where the code it replaced was fail-CLOSED.
async function testTamperedSlotFailsClosed() {
  for (const slot of ["", "#recv", "#exported"]) {
    const slots = new Map();
    let corrupt = null;
    const floor = {
      read: (k) => (k === corrupt ? -2 : (slots.has(k) ? slots.get(k) : -1)),
      bump: (k, v) => {
        if (k === corrupt) return -2;            // PadFloor never heals a forged record
        if (v < 0) return floor.read(k);
        const n = Math.max(floor.read(k), v);
        slots.set(k, n);
        return n;
      },
    };
    Object.defineProperty(globalThis, "__SECURE_CHAT_NATIVE_FLOOR__", { value: true, configurable: true });
    Object.defineProperty(globalThis, "__SECURE_CHAT_PAD_FLOOR__", { value: Object.freeze(floor), configurable: true });
    const fresh = new Map();
    globalThis.localStorage = {
      getItem: (k) => (fresh.has(k) ? fresh.get(k) : null),
      setItem: (k, v) => fresh.set(k, String(v)),
      removeItem: (k) => fresh.delete(k),
    };
    const otp = await import(`./otp.js?tamper=${slot}&t=${Date.now()}`);
    const PASS = "pad passphrase";
    const pad = await otp.generatePad({ label: "tampered", totalBytes: 64 * 1024 });
    const at = await otp.saveNewPad(pad, PASS);

    corrupt = pad.padId + slot;                  // the attacker's one file edit
    const which = slot === "" ? "the SEND slot" : `the ${slot} slot`;
    await assert.rejects(
      () => otp.savePadProgress(pad, at), /damaged or forged/,
      `item 13: corrupting ${which} must FAIL CLOSED, never quietly write an unguarded blob`);
    console.log(`OK  item 13: a corrupted ${which} is refused, not treated as 'no floor'`);

    delete globalThis.__SECURE_CHAT_NATIVE_FLOOR__;
    delete globalThis.__SECURE_CHAT_PAD_FLOOR__;
  }
}

await testTamperedSlotFailsClosed();

// ---------------------------------------------------------------------------
// Pentest 2026-08-10-night F-A1: a save INTERRUPTED between the floor and the
// blob must not brick the pad.
//
// The regression this pins: `writePadBlob` armed all three floors to the NEW
// offsets, then did a `JSON.stringify` and an `await crypto.subtle.encrypt`, and
// only then stored the blob. Anything that ended the save in that window — a
// process kill, a QuotaExceededError — left the floor ABOVE the offsets the
// stored blob carries. The next unlock reads that as a rollback and refuses, and
// the refusal is PERMANENT: `forgetPad` + re-import cannot recover it either,
// because `padWasUsed` consults the same floor. A brick, wearing the wording of
// the tamper alarm.
//
// No attacker is involved. The interruption is modelled as the storage write
// failing, which is exactly what a full disk does.
//
// This test fails against the pre-fix ordering with "pad state was rolled back",
// on every one of the three save paths below.
async function testInterruptedSaveDoesNotBrickAPad() {
  for (const path of ["savePadProgress", "markExported"]) {
    const slots = new Map();
    const floor = {
      read: (k) => (slots.has(k) ? slots.get(k) : -1),
      bump: (k, v) => {
        if (v < 0) return floor.read(k);
        const n = Math.max(floor.read(k), v);
        slots.set(k, n);
        return n;
      },
    };
    Object.defineProperty(globalThis, "__SECURE_CHAT_NATIVE_FLOOR__", { value: true, configurable: true });
    Object.defineProperty(globalThis, "__SECURE_CHAT_PAD_FLOOR__", { value: Object.freeze(floor), configurable: true });

    const store = new Map();
    let failPadWrite = false;
    globalThis.localStorage = {
      getItem: (k) => (store.has(k) ? store.get(k) : null),
      setItem: (k, v) => {
        // The pad blob is the big write, so it is the one a full disk refuses.
        if (failPadWrite && k.startsWith("sc.otp.pad.v1.")) {
          const e = new Error("QuotaExceededError");
          e.name = "QuotaExceededError";
          throw e;
        }
        store.set(k, String(v));
      },
      removeItem: (k) => store.delete(k),
    };

    const otp = await import(`./otp.js?interrupt=${path}&t=${Date.now()}`);
    const PASS = "pad passphrase";
    const pad = await otp.generatePad({ label: "interrupt", totalBytes: 64 * 1024 });
    const at = await otp.saveNewPad(pad, PASS);

    // A normal, completed save first, so there is real consumed state to lose.
    pad.sendOffset = 500;
    pad.recvHighWater = 700;
    await otp.savePadProgress(pad, at);

    // Now the save that gets interrupted, carrying HIGHER offsets. Whatever the
    // floors are left at, they must not exceed what is actually on disk.
    failPadWrite = true;
    pad.sendOffset = 5000;
    pad.recvHighWater = 6000;
    await assert.rejects(
      () => (path === "markExported"
        ? otp.markExported(pad, at)
        : otp.savePadProgress(pad, at)),
      /QuotaExceededError/,
      `${path}: the interrupted save must surface its failure to the caller`);
    failPadWrite = false;

    // The pad must still open, at the last offsets that were actually stored.
    const opened = await otp.unlockPad(pad.padId, PASS);
    assert.strictEqual(opened.record.sendOffset, 500,
      `F-A1 (${path}): a save interrupted before the blob landed must leave the pad ` +
      "USABLE at its last durable offset — a floor above the stored blob is read as a " +
      "rollback and refuses the pad forever");
    assert.strictEqual(opened.record.recvHighWater, 700, "...and the recv floor likewise");
    console.log(`OK  F-A1: a ${path} interrupted before the blob lands does not brick the pad`);

    // ...and the brick really would have been permanent: prove the recovery route
    // an ordinary user would reach for is closed, so "it opens" is the only
    // acceptable outcome above.
    otp.forgetPad(pad.padId);
    assert.ok(otp.padWasUsed(pad.padId),
      `F-A1 (${path}): forgetPad + re-import cannot undo it — which is why the ` +
      "interrupted save must not have produced a refusal in the first place");
    console.log(`OK  F-A1: ...and forgetPad/re-import is not an escape (${path})`);

    delete globalThis.__SECURE_CHAT_NATIVE_FLOOR__;
    delete globalThis.__SECURE_CHAT_PAD_FLOOR__;
  }
}

await testInterruptedSaveDoesNotBrickAPad();

// ---------------------------------------------------------------------------
// ROUND-2 F-5 (2026-08-15): a pad's FIRST save must not leave it DURABLE-BUT-
// INVISIBLE. `fc566dd` reordered writePadBlob to blob -> wm -> used -> epoch ->
// writeIndexEntry -> floors, i.e. the index entry (the ONLY thing listPads()
// reads, and the ONLY route to unlockPad through refreshOtpPads) is written
// LAST. A kill or QuotaExceededError after the blob but before the index, on a
// pad's first save, leaves the blob on disk and the index empty: the pad is
// durable and — because probeFloors already created the native send slot —
// padWasUsed() is true, so re-import is refused too. The pad is gone and the two
// people must meet in person again. This is strictly worse than the alarm this
// commit was fixing, and it is a genuine regression the commit shipped.
//
// The discriminator: fail the WATERMARK write. In the buggy order the index has
// not been written yet, so listPads() is empty. In the fixed order (index
// immediately after the blob, before the watermark) the pad is already listed.
async function testFirstSaveStaysVisibleIfInterrupted() {
  const slots = new Map();
  const floor = {
    read: (k) => (slots.has(k) ? slots.get(k) : -1),
    bump: (k, v) => {
      if (v < 0) return floor.read(k);
      const n = Math.max(floor.read(k), v);
      slots.set(k, n);
      return n;
    },
  };
  Object.defineProperty(globalThis, "__SECURE_CHAT_NATIVE_FLOOR__", { value: true, configurable: true });
  Object.defineProperty(globalThis, "__SECURE_CHAT_PAD_FLOOR__", { value: Object.freeze(floor), configurable: true });

  const store = new Map();
  let failWmWrite = false;
  globalThis.localStorage = {
    getItem: (k) => (store.has(k) ? store.get(k) : null),
    setItem: (k, v) => {
      // Model a full disk that refuses the watermark write specifically — any
      // write can fail on a nearly-full disk, and this is the one that sits
      // AFTER the index in the correct ordering and BEFORE it in the buggy one.
      if (failWmWrite && k.startsWith("sc.otp.wm.v1.")) {
        const e = new Error("QuotaExceededError");
        e.name = "QuotaExceededError";
        throw e;
      }
      store.set(k, String(v));
    },
    removeItem: (k) => store.delete(k),
  };

  const otp = await import(`./otp.js?f5&t=${Date.now()}`);
  const PASS = "pad passphrase";
  const pad = await otp.generatePad({ label: "first-save", totalBytes: 64 * 1024 });

  // Interrupt the VERY FIRST save (saveNewPad), before any completed save.
  failWmWrite = true;
  await assert.rejects(() => otp.saveNewPad(pad, PASS), /QuotaExceededError/,
    "F-5: the interrupted first save must surface its failure to the caller");
  failWmWrite = false;

  // The blob is durable...
  assert.notStrictEqual(store.get(`sc.otp.pad.v1.${pad.padId}`), undefined,
    "F-5 setup: the blob write landed before the interruption, as intended");
  // ...and with F-A1-R1 fixed the probe-only floors (0,0,0) are no longer read as
  // "used", so the re-import route is open as well. Both halves of the burn are
  // therefore closed: the pad is reachable in the selector AND re-importable.
  // (unlockPad itself still fails closed here — the watermark never landed — which
  // is correct: it cannot tell that state from an attacker deleting a consumed
  // pad's watermark. Re-import is the recovery, and it must exist.)
  assert.strictEqual(otp.padWasUsed(pad.padId), false,
    "F-5/F-A1-R1: a first save interrupted before the watermark spent no keystream, so the " +
    "padId must stay re-importable rather than being burned");
  // THE REGRESSION: the pad must still be reachable in the selector. Under the
  // buggy ordering listPads() is empty here and there is no UI route to the pad.
  const listed = otp.listPads().some((p) => p.padId === pad.padId);
  assert.ok(listed,
    "F-5: a durable, used pad MUST be listed by listPads() — otherwise refreshOtpPads " +
    "cannot offer it and there is no route to unlockPad, so the padId is burned. " +
    "writeIndexEntry must run right after the blob, not after the watermark.");
  assert.notStrictEqual(otp.padMeta(pad.padId), null, "F-5: padMeta must resolve for a durable pad");
  console.log("OK  F-5: a first save interrupted after the blob still lists the pad (not burned)");

  delete globalThis.__SECURE_CHAT_NATIVE_FLOOR__;
  delete globalThis.__SECURE_CHAT_PAD_FLOOR__;
}

await testFirstSaveStaysVisibleIfInterrupted();

// ---------------------------------------------------------------------------
// F-A1-R1 (round 1, still open): a pad's FIRST save must be all-or-nothing in
// the RIGHT direction. `probeFloors` creates the send/recv/exported slots at 0
// before the blob is written, and `padWasUsed` counted any non-ABSENT send slot
// as evidence of use — so an interruption BEFORE the blob lands (a failed blob
// write, a kill between the JNI probe and the setItem) left the three slots at
// (0,0,0) with nothing else on disk, and `padWasUsed` answered true. That burns
// the padId: saveNewPad/importPad both refuse it, and the two people must meet
// again — for a pad that consumed no keystream at all.
//
// The fix: a slot triple that is exactly (0,0,0) — the probe-only state — is NOT
// evidence of use on its own; it defers to the localStorage markers. A slot
// ABOVE 0 (real send/recv consumption or an export) stays decisive and
// undeletable, so H-3 (delete the markers, re-import a CONSUMED pad) is still
// refused.
async function testInterruptedFirstSaveIsReimportable() {
  const slots = new Map();
  const floor = {
    read: (k) => (slots.has(k) ? slots.get(k) : -1),
    bump: (k, v) => {
      if (v < 0) return floor.read(k);
      const n = Math.max(floor.read(k), v);
      slots.set(k, n);
      return n;
    },
  };
  Object.defineProperty(globalThis, "__SECURE_CHAT_NATIVE_FLOOR__", { value: true, configurable: true });
  Object.defineProperty(globalThis, "__SECURE_CHAT_PAD_FLOOR__", { value: Object.freeze(floor), configurable: true });

  const store = new Map();
  let failPadWrite = false;
  globalThis.localStorage = {
    getItem: (k) => (store.has(k) ? store.get(k) : null),
    setItem: (k, v) => {
      if (failPadWrite && k.startsWith("sc.otp.pad.v1.")) {
        const e = new Error("QuotaExceededError");
        e.name = "QuotaExceededError";
        throw e;
      }
      store.set(k, String(v));
    },
    removeItem: (k) => store.delete(k),
  };

  const otp = await import(`./otp.js?far1&t=${Date.now()}`);
  const PASS = "pad passphrase";

  // (1) FIRST save interrupted before the blob lands: probeFloors created the
  // (0,0,0) slots, then the blob write threw. Nothing durable exists.
  const fresh = await otp.generatePad({ label: "fresh", totalBytes: 64 * 1024 });
  failPadWrite = true;
  await assert.rejects(() => otp.saveNewPad(fresh, PASS), /QuotaExceededError/,
    "F-A1-R1 setup: the interrupted first save must surface its failure");
  failPadWrite = false;
  assert.strictEqual(store.get(`sc.otp.pad.v1.${fresh.padId}`), undefined,
    "F-A1-R1 setup: the blob write did NOT land (this is the pre-blob interruption)");
  assert.strictEqual(otp.padWasUsed(fresh.padId), false,
    "F-A1-R1: a first save interrupted before the blob leaves only the probe slots at 0 — " +
    "no keystream was spent, so the padId must be re-importable, not burned");
  // And re-import actually works: saveNewPad no longer refuses it.
  const at = await otp.saveNewPad(fresh, PASS);
  assert.ok(at && at.key, "F-A1-R1: the pad re-imports cleanly after the interrupted first save");
  console.log("OK  F-A1-R1: a first save interrupted before the blob is re-importable, not burned");

  // (2) H-3 still holds: a CONSUMED pad, then all localStorage deleted, is still
  // refused because the native send floor is above 0 and undeletable.
  const used = await otp.generatePad({ label: "used", totalBytes: 64 * 1024 });
  const usedAt = await otp.saveNewPad(used, PASS);
  used.sendOffset = 4096;
  await otp.savePadProgress(used, usedAt);
  for (const k of [...store.keys()]) if (k.includes(used.padId)) store.delete(k);
  assert.strictEqual(otp.padWasUsed(used.padId), true,
    "H-3: a consumed pad whose localStorage markers were deleted is STILL used — the native " +
    "send floor is above 0 and cannot be deleted or lowered from the JS context");
  console.log("OK  H-3 preserved: a consumed pad with markers deleted is still refused");

  delete globalThis.__SECURE_CHAT_NATIVE_FLOOR__;
  delete globalThis.__SECURE_CHAT_PAD_FLOOR__;
}

await testInterruptedFirstSaveIsReimportable();

// ---------------------------------------------------------------------------
// A4/F-A3: a floor that could not be ARMED must not be sealed as "no floor".
//
// `PadFloor.bump` discards `commit()`'s boolean, so a prefs write that silently
// does not take (unwritable file, full disk) left probeFloors reporting the same
// `false` a plain browser legitimately reports. Both unlock guards are keyed on
// that claim being true, so they could never fire for that blob — and the claim
// is AEAD-sealed, so a later save that succeeds cannot repair a snapshot taken
// during the degraded window. It stayed exploitable forever, into keystream
// reuse.
async function testUnarmableFloorIsNotSealedAsAbsent() {
  const slots = new Map();
  let acceptBumps = true;
  const floor = {
    read: (k) => (slots.has(k) ? slots.get(k) : -1),
    bump: (k, v) => {
      // The failure being modelled: bump reports success (it returns a number)
      // but the write does not persist. This is what a discarded commit() looks
      // like from the JS side.
      if (!acceptBumps) return -1;
      if (v < 0) return floor.read(k);
      const n = Math.max(floor.read(k), v);
      slots.set(k, n);
      return n;
    },
  };
  Object.defineProperty(globalThis, "__SECURE_CHAT_NATIVE_FLOOR__", { value: true, configurable: true });
  Object.defineProperty(globalThis, "__SECURE_CHAT_PAD_FLOOR__", { value: Object.freeze(floor), configurable: true });

  const store = new Map();
  globalThis.localStorage = {
    getItem: (k) => (store.has(k) ? store.get(k) : null),
    setItem: (k, v) => store.set(k, String(v)),
    removeItem: (k) => store.delete(k),
  };

  const otp = await import(`./otp.js?fa3&t=${Date.now()}`);
  const PASS = "pad passphrase";

  // Save a pad while the floor cannot be armed.
  acceptBumps = false;
  const pad = await otp.generatePad({ label: "degraded", totalBytes: 64 * 1024 });
  const at = await otp.saveNewPad(pad, PASS);
  pad.sendOffset = 1024;
  await otp.savePadProgress(pad, at);

  // The blob must NOT claim "no floor was in force" — that claim is what a plain
  // browser writes, and it makes both unlock guards structurally unable to fire.
  const blob = JSON.parse(store.get(`sc.otp.pad.v1.${pad.padId}`));
  assert.ok(blob && blob.ct, "F-A3 setup: a pad blob was written");

  // Unlock must not open it silently: an unverifiable claim takes the same
  // consent route as any other unverifiable consumption state.
  await assert.rejects(() => otp.unlockPad(pad.padId, PASS),
    (e) => {
      assert.strictEqual(e.code, "LEGACY_PAD_ADOPTION",
        "F-A3: a pad sealed while the floor could not be armed must route through the adoption " +
        "consent gate, not open silently on a claim nothing can check");
      assert.match(e.message, /could not write its tamper-proof usage record/,
        "F-A3: the prompt must say what is actually wrong — the floor could not be written — " +
        "rather than the legacy wording about a missing usage record");
      return true;
    },
    "F-A3: unlockPad must refuse without explicit adoption");
  console.log("OK  F-A3: a pad saved with an unarmable floor is gated, not silently trusted");

  // With explicit consent it opens (a brick would destroy an in-person exchange),
  // and once the floor works again a fresh save re-arms the claim.
  const opened = await otp.unlockPad(pad.padId, PASS, { adoptLegacy: true });
  assert.strictEqual(opened.record.sendOffset, 1024, "F-A3: adoption opens the pad at its stored offset");
  acceptBumps = true;
  await otp.savePadProgress(opened.record, opened.atRest);
  const healed = await otp.unlockPad(pad.padId, PASS);
  assert.strictEqual(healed.record.sendOffset, 1024,
    "F-A3: once the floor can be written again, a save re-arms the claim and the gate stops firing");
  console.log("OK  F-A3: the claim heals on the next save whose probe succeeds");

  // CONTROL: a plain browser (no bridge at all) must NOT be pushed through the
  // gate — that is the legitimate `false`, and gating it would prompt every
  // browser user on every unlock.
  delete globalThis.__SECURE_CHAT_NATIVE_FLOOR__;
  delete globalThis.__SECURE_CHAT_PAD_FLOOR__;
  const store2 = new Map();
  globalThis.localStorage = {
    getItem: (k) => (store2.has(k) ? store2.get(k) : null),
    setItem: (k, v) => store2.set(k, String(v)),
    removeItem: (k) => store2.delete(k),
  };
  const otp2 = await import(`./otp.js?fa3b&t=${Date.now()}`);
  const pad2 = await otp2.generatePad({ label: "browser", totalBytes: 64 * 1024 });
  const at2 = await otp2.saveNewPad(pad2, PASS);
  pad2.sendOffset = 512;
  await otp2.savePadProgress(pad2, at2);
  const browserOpen = await otp2.unlockPad(pad2.padId, PASS);
  assert.strictEqual(browserOpen.record.sendOffset, 512,
    "F-A3 control: a plain browser has no floor to arm, which is not a degraded state — it must " +
    "open normally, or every browser user is prompted on every unlock");
  console.log("OK  F-A3 control: a plain browser is unaffected by the new claim value");
}

await testUnarmableFloorIsNotSealedAsAbsent();

// The same finding's second half, which lives in app.js and so can only be
// pinned at source level: the export handler must LATCH before it hands the pad
// file to the user.
//
// `markExported` is the only record that a pad has left the device. Downloading
// first and latching second means a failed latch leaves a pristine pad file in
// the user's hands with nothing on the device remembering it — so the re-export
// warning is silent on the SECOND export, and one pad in two importers is a
// two-time pad. Anchored on executable statements, never on a comment (H-1).
{
  const appSrc = await readFile(new URL("./app.js", import.meta.url), "utf8");
  // COMMENTS STRIPPED FIRST. The first cut of this check ran `indexOf` over raw
  // source, so reverting the order and leaving a comment that mentions
  // `await otp.markExported(record, atRest)` above the download satisfied it —
  // the check passed while the code did the opposite. Found by the pentest of
  // this very fix; it is H-1's defect, one file over.
  const code = codeLines(stripComments(appSrc)).join("\n");
  const dl = code.indexOf("downloadText(`secure-chat-pad-");
  const latch = code.indexOf("await otp.markExported(record, atRest)");
  assert.notStrictEqual(dl, -1, "the pad export download call must still exist in app.js");
  assert.notStrictEqual(latch, -1, "the pad export must still call markExported");
  assert.ok(latch < dl,
    "F-A1: app.js must await markExported BEFORE downloadText hands the pad file over — " +
    "the other order can release a pad file that nothing on this device records as exported");
  console.log("OK  F-A1: app.js latches the export before releasing the pad file");

  // ROUND-3 F-2: the RECEIVE path must persist before it displays, mirroring the
  // send path's persist-before-transmit. Shown-but-not-persisted is a frame whose
  // keystream is spent with nothing durable saying so — and on a pad's first
  // received frame the floors are still the probe-only (0,0,0), which since
  // F-A1-R1 is not evidence of use, so a crash there plus H-3's marker deletion
  // rewinds recvHighWater and replays every delivered frame.
  const recvCase = code.indexOf('case "msg": {');
  assert.notStrictEqual(recvCase, -1, "the msg case must still exist in app.js");
  const recvBody = code.slice(recvCase, recvCase + 1400);
  const persistAt = recvBody.indexOf("await persistOtpProgress();");
  const showAt = recvBody.indexOf('addLine("peer", "peer", text);');
  assert.notStrictEqual(persistAt, -1, "the msg case must still persist OTP progress");
  assert.notStrictEqual(showAt, -1, "the msg case must still display the decrypted line");
  assert.ok(persistAt < showAt,
    "ROUND-3 F-2: app.js must await persistOtpProgress BEFORE addLine displays the frame — " +
    "the other order shows the user a message whose keystream nothing on this device records " +
    "as spent");
  console.log("OK  F-2: app.js persists the receive watermark before displaying the frame");
}

// ---------------------------------------------------------------------------
// ROUND-3 F-1 (2026-08-21, pentest of the F-A1-R1 fix): a floor that does not
// actually MOVE must fail the save, loudly, before any keystream is transmitted.
//
// How F-A1-R1 reopened H-3. `armFloors`' return value was discarded, and
// `readFloorClaims` only throws on TAMPERED — a slot still sitting at 0 after
// `bump(k, 4096)` reads back as `s >= 0`, i.e. "armed". So a floor frozen at 0
// (an unwritable prefs file; on Android `SharedPreferences.commit()`'s boolean is
// also dropped) let `writePadBlob` return SUCCESS. app.js persists before it
// transmits (P-04), so success is exactly the signal that releases the keystream
// onto the wire — and the durable floor stayed at the probe-only 0, which after
// F-A1-R1 is no longer evidence of use. Delete the (deletable) localStorage
// markers, re-import the (always pristine) pad file, and the pad comes back at
// sendOffset 0: the SAME keystream is spent twice. C1 XOR C2 = P1 XOR P2, the one
// failure a one-time pad cannot survive.
//
// The fix is not to tighten `padWasUsed` again — every input it has left is
// attacker-deletable, and tightening it is what burned padIds in the first place.
// It is to stop the save from SUCCEEDING when the floor it depends on did not
// take: verify the read-back covers the watermark just sealed, and throw if it
// does not. Then the keystream is never sent, and the state left behind is
// forward-consistent (the blob carries the higher offsets; unlockPad's max()
// takes them).
async function testFrozenFloorFailsTheSaveBeforeSending() {
  const slots = new Map();
  let freeze = false;
  const floor = {
    read: (k) => (slots.has(k) ? slots.get(k) : -1),
    bump: (k, v) => {
      // A frozen store: the value is refused, but the slot that already exists
      // still reads back fine. This is the shape the pentest's PoC used, and it
      // is what an unwritable prefs file does.
      if (freeze) return floor.read(k);
      if (v < 0) return floor.read(k);
      const n = Math.max(floor.read(k), v);
      slots.set(k, n);
      return n;
    },
  };
  Object.defineProperty(globalThis, "__SECURE_CHAT_NATIVE_FLOOR__", { value: true, configurable: true });
  Object.defineProperty(globalThis, "__SECURE_CHAT_PAD_FLOOR__", { value: Object.freeze(floor), configurable: true });

  const store = new Map();
  globalThis.localStorage = {
    getItem: (k) => (store.has(k) ? store.get(k) : null),
    setItem: (k, v) => store.set(k, String(v)),
    removeItem: (k) => store.delete(k),
  };

  const otp = await import(`./otp.js?frozen&t=${Date.now()}`);
  const PASS = "pad passphrase";
  const pad = await otp.generatePad({ label: "frozen", totalBytes: 64 * 1024 });
  const at = await otp.saveNewPad(pad, PASS);

  // Now the prefs file becomes unwritable, and the pad consumes keystream.
  freeze = true;
  pad.sendOffset = 4096;
  await assert.rejects(() => otp.savePadProgress(pad, at), /rollback guard|floor/i,
    "ROUND-3 F-1: a save whose floor did not move must FAIL. app.js persists before it " +
    "transmits, so returning success here is what puts the keystream on the wire while " +
    "nothing durable records that it was spent.");
  console.log("OK  F-1: a frozen native floor fails the save instead of returning success");

  // THE INVARIANT this restores, stated as the property rather than as one of its
  // consequences: **if a save RESOLVES, the durable floor covers the offsets that
  // save recorded.** That is what makes `padWasUsed` sound after F-A1-R1 — a
  // probe-only (0,0,0) can then only mean "no keystream was ever transmitted",
  // because app.js persists before it transmits and a persist that did not reach
  // the floor now rejects.
  //
  // Note what is NOT asserted here, because getting it wrong is how the previous
  // round talked itself into a hole: after the REFUSED save the pad is still
  // re-importable at 0, and that is CORRECT, not a residual. The save threw, so
  // app.js never sent, so bytes 0..4096 are unspent. Re-importing spends them
  // once. The danger was never "the pad came back"; it was "the pad came back
  // AFTER the keystream had already gone out".
  assert.strictEqual(floor.read(pad.padId), 0, "F-1 setup: the floor really is stuck at 0");

  freeze = false;
  const pad2 = await otp.generatePad({ label: "healthy", totalBytes: 64 * 1024 });
  const at2 = await otp.saveNewPad(pad2, PASS);
  pad2.sendOffset = 4096;
  await otp.savePadProgress(pad2, at2);          // resolves...
  assert.ok(floor.read(pad2.padId) >= 4096,      // ...so the floor MUST cover it
    "ROUND-3 F-1: a save that resolves must leave the protected floor covering the offsets " +
    `it recorded — got ${floor.read(pad2.padId)}, expected >= 4096. If this can fail, a pad ` +
    "whose keystream is already on the wire can still look unused, which is H-3.");

  // ...and therefore the H-3 attack fails on it: markers deleted, re-import refused.
  for (const k of [...store.keys()]) store.delete(k);
  assert.strictEqual(otp.padWasUsed(pad2.padId), true,
    "ROUND-3 F-1: H-3 stays closed for a pad that actually transmitted — every deletable " +
    "marker is gone and the undeletable floor still refuses the re-import");
  console.log("OK  F-1: a save that resolves always leaves a floor covering it (H-3 closed)");

  delete globalThis.__SECURE_CHAT_NATIVE_FLOOR__;
  delete globalThis.__SECURE_CHAT_PAD_FLOOR__;
}

await testFrozenFloorFailsTheSaveBeforeSending();

// --- item 13, third pass: the two writers that had no broken-bridge gate -----
// Test-debt item 7. `unlockPad`, `saveNewPad` and `importPad` each refuse when
// the bridge is BROKEN — `__SECURE_CHAT_NATIVE_FLOOR__` says a hardware floor is
// supposed to exist but `__SECURE_CHAT_PAD_FLOOR__` is missing or malformed, so
// every floor read and every bump answers NATIVE_TAMPERED. `savePadProgress` and
// `markExported` did not, and they are the two writers that run WITHOUT a fresh
// unlock: app.js caches {record, atRest} per pad for the whole session. So every
// per-message save, and the write that latches the one-way `exported` flag,
// reached `writePadBlob` with no floor check at all. `markExported` is the worse
// of the two — that flag is the only thing standing between one pristine export
// file and a two-time pad by construction.
//
// HONESTY NOTE, because a test that overstates what it proves is worse than no
// test. This state is NOT producible in production, and PROGRESS.md item 9 (A4)
// already records that: the bridge is republished non-configurable at
// document-start, and `nativeFloor` is captured once in a module-scope IIFE, so
// within one page load it cannot "break mid-session" the way the code comment
// above savePadProgress claims; across a page load, every producer of
// {record, atRest} refuses first. This is therefore a MUTATION-BINDING test for a
// defence-in-depth line, not a regression test for a live hole. It exists so the
// line cannot be deleted as dead weight without something going red, which is
// exactly what the debt entry asked for.
//
// Reaching it needs no hook in otp.js: `nativeFloor` is decided at IMPORT time,
// so the pad is created by one module instance with a working bridge and then
// handed to a SECOND instance imported after the bridge global was removed.
// `record`/`atRest` are plain objects and cross instances freely.
async function testBrokenBridgeBlocksTheCachedWriters() {
  const slots = new Map();
  const floor = {
    read: (k) => (slots.has(k) ? slots.get(k) : -1),
    bump: (k, v) => { if (v < 0) return floor.read(k); const n = Math.max(floor.read(k), v); slots.set(k, n); return n; },
  };
  Object.defineProperty(globalThis, "__SECURE_CHAT_NATIVE_FLOOR__", { value: true, configurable: true });
  Object.defineProperty(globalThis, "__SECURE_CHAT_PAD_FLOOR__", { value: Object.freeze(floor), configurable: true });
  const store = new Map();
  globalThis.localStorage = {
    getItem: (k) => (store.has(k) ? store.get(k) : null),
    setItem: (k, v) => store.set(k, String(v)),
    removeItem: (k) => store.delete(k),
  };

  const PASS = "pad passphrase";
  const healthy = await import(`./otp.js?broken=a&t=${Date.now()}`);
  const record = await healthy.generatePad({ label: "broken bridge", totalBytes: 64 * 1024 });
  const atRest = await healthy.saveNewPad(record, PASS);
  const padKey = "sc.otp.pad.v1." + record.padId;
  const sealed = localStorage.getItem(padKey);
  assert.ok(sealed, "fixture: the pad must be on disk before the bridge is taken away");

  // The marker STAYS (this device claims a hardware floor); only the bridge goes.
  // That is precisely the "expected but not securable" state, and it is what
  // makes a plain browser distinguishable from a device whose floor was removed.
  delete globalThis.__SECURE_CHAT_PAD_FLOOR__;
  const broken = await import(`./otp.js?broken=b&t=${Date.now()}`);

  record.sendOffset = 4096;
  await assert.rejects(() => broken.savePadProgress(record, atRest),
    /hardware rollback protection/,
    "item 13: a per-message save must refuse once the floor cannot be reached — app.js caches " +
    "{record, atRest} for the session, so without this gate every save after the first unlock " +
    "sealed a blob whose floor claim nothing on the device can check");
  assert.strictEqual(localStorage.getItem(padKey), sealed,
    "...and it must refuse BEFORE writing: a rejected save that already rewrote the blob would " +
    "advance the recorded offset with no floor behind it, which is the H-3 shape");

  record.exported = false;
  await assert.rejects(() => broken.markExported(record, atRest),
    /hardware rollback protection/,
    "item 13: latching the one-way `exported` flag must refuse too — that flag is the only " +
    "warning between one pristine export file and the same pad handed to two importers, i.e. a " +
    "two-time pad by construction, so it is the last write that may happen unverifiably");
  assert.strictEqual(localStorage.getItem(padKey), sealed,
    "...and markExported must not have touched the blob either");
  console.log("OK  item 13: savePadProgress and markExported refuse on a broken floor bridge");

  // Control: the SAME calls on the SAME record succeed against a working bridge,
  // so the assertions above are pinned to the broken state and not to something
  // incidental about a re-imported module instance.
  Object.defineProperty(globalThis, "__SECURE_CHAT_PAD_FLOOR__", { value: Object.freeze(floor), configurable: true });
  const again = await import(`./otp.js?broken=c&t=${Date.now()}`);
  await again.savePadProgress(record, atRest);
  await again.markExported(record, atRest);
  assert.notStrictEqual(localStorage.getItem(padKey), sealed,
    "control: with the bridge back, the very same writes must go through — otherwise the test " +
    "above would pass with the gate deleted and something else doing the refusing");
  console.log("OK  item 13: control — the same writes succeed once the bridge is back");

  delete globalThis.__SECURE_CHAT_NATIVE_FLOOR__;
  delete globalThis.__SECURE_CHAT_PAD_FLOOR__;
}

await testBrokenBridgeBlocksTheCachedWriters();

// ---- Phase-7 pentest 2026-09-16, F-P7-A3: three floor-verdict controls that
// were load-bearing at HEAD and pinned by nothing. Each test is the lane's PoC
// turned into an assertion; the corresponding one-line mutant of otp.js kept
// this file green before these existed.
function padFloorLike(opts = {}) {
  // PadFloor.kt semantics: monotone, ABSENT = -1; with `failSlot`, a bump on a
  // matching slot moves the IN-MEMORY map (read() looks healthy) but returns
  // COMMIT_FAILED and writes nothing durable.
  const mem = new Map();
  const disk = new Map();
  const cur = (k) => (mem.has(k) ? mem.get(k) : -1);
  return {
    mem, disk,
    read: (k) => cur(k),
    bump: (k, v) => {
      if (v < 0) return cur(k);
      const c = cur(k);
      const next = c === -1 ? v : (v > c ? v : c);
      if (next === c) return c;
      mem.set(k, next);
      if (opts.failSlot !== undefined && k === opts.failSlot) return -3;
      disk.set(k, next);
      return next;
    },
  };
}
function withFloor(floor, fn) {
  const prevLS = globalThis.localStorage;
  const mem = new Map();
  globalThis.localStorage = {
    getItem: (k) => (mem.has(k) ? mem.get(k) : null),
    setItem: (k, v) => mem.set(k, String(v)),
    removeItem: (k) => mem.delete(k),
    _mem: mem,
  };
  Object.defineProperty(globalThis, "__SECURE_CHAT_NATIVE_FLOOR__", { value: true, configurable: true });
  Object.defineProperty(globalThis, "__SECURE_CHAT_PAD_FLOOR__", { value: Object.freeze({ read: floor.read, bump: floor.bump }), configurable: true });
  return fn(mem).finally(() => {
    delete globalThis.__SECURE_CHAT_NATIVE_FLOOR__;
    delete globalThis.__SECURE_CHAT_PAD_FLOOR__;
    globalThis.localStorage = prevLS;
  });
}

// (a) maxOf() is hand-rolled WITHOUT Math.max because Math.max is a writable
// global and the rollback verdict is one call to it over the four floors.
// Reimplementing maxOf over Math.max (semantics otherwise identical) kept this
// file green. Poison Math.max at "document start" and require the native floor
// to still win.
async function testFloorVerdictSurvivesPoisonedMathMax() {
  const floor = padFloorLike();
  await withFloor(floor, async (mem) => {
    const otpN = await import(`./otp.js?p7=mathmax&t=${Date.now()}`);
    const pad = await otpN.generatePad({ label: "mm", totalBytes: 64 * 1024, fingerBytes: new Uint8Array(0) });
    const atRest = await otpN.saveNewPad(pad, PASS);
    const pristine = new Map(mem);
    pad.sendOffset = 3000;
    pad.recvHighWater = 1200;
    await otpN.savePadProgress(pad, atRest);
    assert.strictEqual(floor.read(pad.padId), 3000, "fixture: the durable native send floor is 3000");
    mem.clear(); for (const [k, v] of pristine) mem.set(k, v); // the attacker restores the pristine blob + watermark
    const realMax = Math.max;
    Math.max = () => 0;
    try {
      await assert.rejects(() => otpN.unlockPad(pad.padId, PASS), /rolled back|consumed/,
        "F-P7-A3: with Math.max poisoned to 0, the native floor must STILL refuse the rollback — " +
        "maxOf() may not depend on any writable global");
    } finally { Math.max = realMax; }
  });
  console.log("OK  F-P7-A3: the floor verdict does not depend on Math.max");
}

// (b) padWasUsed's recv-only and exported-only evidence. Narrowing the clause
// to `send > 0` kept this file green; without the other two, forget + delete
// the markers + re-import the pristine file resurrects a receive-only pad at
// recvHighWater 0 (M-7) or re-imports a pad this device already exported.
async function testPadWasUsedHonoursRecvAndExportedEvidence() {
  for (const shape of ["recv-only", "exported-only"]) {
    const floor = padFloorLike();
    await withFloor(floor, async (mem) => {
      const otpN = await import(`./otp.js?p7=${shape}&t=${Date.now()}`);
      const pad = await otpN.generatePad({ label: shape, totalBytes: 64 * 1024, fingerBytes: new Uint8Array(0) });
      const atRest = await otpN.saveNewPad(pad, PASS);
      const file = await otpN.exportPad(pad, "xfer"); // the pristine file the attacker keeps
      if (shape === "recv-only") { pad.recvHighWater = 4096; await otpN.savePadProgress(pad, atRest); }
      else await otpN.markExported(pad, atRest);
      otpN.forgetPad(pad.padId);
      for (const k of ["sc.otp.wm.v1.", "sc.otp.used.v1.", "sc.otp.hw.v1."]) mem.delete(k + pad.padId);
      assert.strictEqual(floor.read(pad.padId), 0, `fixture (${shape}): the SEND floor is still 0`);
      await assert.rejects(() => otpN.importPad(file, "xfer"), /already been used/,
        `F-P7-A3 (${shape}): re-importing the pristine file must be refused on the ${shape === "recv-only" ? "#recv" : "#exported"} evidence alone`);
    });
  }
  console.log("OK  F-P7-A3: padWasUsed refuses on recv-only and on exported-only floor evidence");
}

// (c) probeFloors' create-side COMMIT_FAILED -> CLAIM_UNCONFIRMED mapping —
// the create half of commit 2eb2ea5. Setting it to false kept this file
// green: the existing tests model a stale read-back or established slots,
// never a FIRST save whose create-bump commits to nothing while the read-back
// looks healthy (exactly what SharedPreferences.commit() does). A blob that
// claimed ARMED over a floor that never reached disk is refused forever after a
// restart, and with the markers gone the pristine re-import is a two-time pad.
async function testFirstSaveWithFailedCreateCommitIsUnconfirmed() {
  const floor = padFloorLike({ failSlot: null }); // filled in below: the SEND slot of the pad
  await withFloor(floor, async () => {
    const otpN = await import(`./otp.js?p7=commitfail&t=${Date.now()}`);
    const pad = await otpN.generatePad({ label: "cf", totalBytes: 4096, fingerBytes: new Uint8Array(0) });
    // The pad id exists only now; make its SEND slot the one whose commit fails.
    const failing = padFloorLike({ failSlot: pad.padId });
    Object.defineProperty(globalThis, "__SECURE_CHAT_PAD_FLOOR__", { value: Object.freeze({ read: failing.read, bump: failing.bump }), configurable: true });
    const otpF = await import(`./otp.js?p7=commitfail2&t=${Date.now()}`);
    await otpF.saveNewPad(pad, PASS);
    assert.ok(!failing.disk.has(pad.padId), "fixture: the send slot's create never reached disk");
    assert.strictEqual(failing.read(pad.padId), 0, "fixture: ...while the in-memory read-back looks healthy");
    await assert.rejects(() => otpF.unlockPad(pad.padId, PASS),
      (e) => e.code === "LEGACY_PAD_ADOPTION" && e.reason === "unarmable-floor",
      "F-P7-A3: a first save whose create-bump did not commit must seal CLAIM_UNCONFIRMED and route the pad " +
      "through the adoption gate — not claim a floor that is not durable");
  });
  console.log("OK  F-P7-A3: a failed create-commit on a first save is sealed as unconfirmed, not armed");
}

// Phase-7 pentest 2026-09-16, F-P7-5: the legacy-adoption gate was keyed on
// the OUTER `v` byte. Plain-browser device, a v2-shaped blob (what the
// 2026-07-26 build wrote), the three deletable markers removed: with "v":2 the
// gate fired; with the one unauthenticated byte edited to "v":3 the same
// ciphertext opened SILENTLY at sendOffset 0 — a browser two-time pad, and
// repeatable because the migration rewrite was suppressed by the same byte.
async function testAdoptionGateIgnoresTheOuterVersionByte() {
  const pad = await otp.generatePad({ label: "vbyte", totalBytes: 8192, fingerBytes: new Uint8Array(0) });
  const atRest = await otp.saveNewPad(pad, PASS);
  pad.sendOffset = 3000;
  await otp.savePadProgress(pad, atRest);
  await makeV2Blob(pad.padId, atRest.key, (inner) => { inner.sendOffset = 0; });
  for (const k of ["sc.otp.wm.v1.", "sc.otp.used.v1.", "sc.otp.hw.v1."]) localStorage.removeItem(k + pad.padId);
  await assert.rejects(() => otp.unlockPad(pad.padId, PASS), (e) => e.code === "LEGACY_PAD_ADOPTION",
    "fixture: with the outer byte honest, the v2 blob is routed to the adoption gate");
  const key = "sc.otp.pad.v1." + pad.padId;
  const raw = JSON.parse(localStorage.getItem(key));
  assert.strictEqual(raw.v, 2, "fixture: the blob says v2 outside the AEAD");
  raw.v = 3; // one byte, no MAC to satisfy, ciphertext untouched
  localStorage.setItem(key, JSON.stringify(raw));
  await assert.rejects(() => otp.unlockPad(pad.padId, PASS), (e) => e.code === "LEGACY_PAD_ADOPTION",
    "F-P7-5: the outer version byte is attacker-writable and must not decide the gate — a pre-v3 plaintext " +
    "(no hwSend inside the AEAD) is routed to the adoption gate whatever the outer byte says");
  // ...and the migration rewrite is decided the same way: adopting it writes a v3 blob.
  const { record } = await otp.unlockPad(pad.padId, PASS, { adoptLegacy: true });
  assert.strictEqual(record.sendOffset, 0);
  const rewritten = JSON.parse(localStorage.getItem(key));
  assert.strictEqual(rewritten.v, 3, "adoption migrates the blob to v3 regardless of what the outer byte claimed");
  console.log("OK  F-P7-5: the OTP adoption gate is keyed on the AEAD, not the outer v byte");
}

await testAdoptionGateIgnoresTheOuterVersionByte();
await testFloorVerdictSurvivesPoisonedMathMax();
await testPadWasUsedHonoursRecvAndExportedEvidence();
await testFirstSaveWithFailedCreateCommitIsUnconfirmed();

console.log("All OTP native-floor scope checks passed.");
