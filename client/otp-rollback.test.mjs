// M-01 regression: a full old encrypted-pad blob restore (rolling sendOffset
// back to reuse consumed keystream) is refused by the separate high-water
// tripwire. Run: node otp-rollback.test.mjs
import assert from "node:assert";

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
  const wmRaw = localStorage.getItem("sc.otp.wm.v1." + h.padId);
  assert.ok(wmRaw && !wmRaw.includes("85"), "watermark is ciphertext, not a plaintext integer");

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

console.log("\nAll OTP rollback checks passed.");
