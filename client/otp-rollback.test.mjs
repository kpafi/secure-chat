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

// forgetPad clears the tripwire so a genuinely fresh pad with the same id could
// start over (ids are random, so this is just hygiene).
otp.forgetPad(rec.padId);
assert.strictEqual(localStorage.getItem("sc.otp.hw.v1." + rec.padId), null, "high-water cleared on forget");
console.log("OK  high-water tripwire cleared on forgetPad");

console.log("\nAll OTP rollback checks passed.");
