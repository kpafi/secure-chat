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
assert.strictEqual(
  localStorage.getItem("sc.otp.hw.v1." + rec.padId), "500",
  "P-05: high-water survives forgetPad so a re-import can be refused",
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

console.log("\nAll OTP rollback checks passed.");
