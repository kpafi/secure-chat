// Offline tests for the web-of-trust vouch binding (H-01, 2026-07-19).
//
// A vouch must attest ALL FOUR public keys, so a 🟡 mark can never be awarded
// for a contact whose ENCRYPTION keys a malicious directory swapped. These
// reproduce the exact award check in app.js refreshVouchMarks (Identity.verify
// over account.vouchMessageBytes of the bundle the client holds).
// Run: node vouch.test.mjs
import assert from "node:assert";
import { Identity } from "./identity.js";
import { vouchMessageBytes } from "./account.js";

// --- v2 message shape: enc keys present -> v2 domain + all four keys ---------
const withEnc = { ed: "AA", mldsa: "BB", ecdh: "CC", mlkem: "DD" };
const dec = new TextDecoder();
const v2 = dec.decode(vouchMessageBytes("carol", withEnc));
assert.ok(v2.startsWith("secure-chat/vouch/v2\n"), "enc-key bundle signs under the v2 domain");
assert.deepStrictEqual(v2.split("\n"), ["secure-chat/vouch/v2", "carol", "AA", "BB", "CC", "DD"]);
const v1 = dec.decode(vouchMessageBytes("carol", { ed: "AA", mldsa: "BB" }));
assert.ok(v1.startsWith("secure-chat/vouch/v1\n"), "signing-only bundle stays v1");
console.log("OK  vouchMessageBytes: v2 covers ecdh+mlkem, v1 for legacy targets");

// --- cast -------------------------------------------------------------------
const bob = await Identity.generate();    // voucher (verified in person by the victim)
const carol = await Identity.generate();  // target
const attacker = await Identity.generate();
const carolPub = carol.publicBundle();
const bobPub = bob.publicBundle();

// Bob publishes a genuine v2 vouch over Carol's REAL bundle.
const sig = await bob.sign(vouchMessageBytes("carol", carolPub));

// award(bundle) = the exact check app.js refreshVouchMarks runs for the
// contact bundle the client currently holds.
async function award(heldCarolBundle) {
  return Identity.verify(
    { ed: bobPub.ed, mldsa: bobPub.mldsa },
    vouchMessageBytes("carol", {
      ed: heldCarolBundle.ed, mldsa: heldCarolBundle.mldsa,
      ecdh: heldCarolBundle.ecdh ?? null, mlkem: heldCarolBundle.mlkem ?? null,
    }),
    { ed: sig.ed, mldsa: sig.mldsa },
  ).catch(() => false);
}

// Honest directory: the client holds Carol's real bundle -> 🟡 awarded.
assert.strictEqual(await award(carolPub), true, "honest bundle earns the vouch");
console.log("OK  honest four-key bundle -> vouch verifies (🟡 awarded)");

// Malicious directory: real signing keys + attacker encryption keys.
const poisoned = {
  ed: carolPub.ed, mldsa: carolPub.mldsa,
  ecdh: attacker.publicBundle().ecdh, mlkem: attacker.publicBundle().mlkem,
};
assert.strictEqual(await award(poisoned), false, "poisoned enc keys must NOT earn the vouch");
console.log("OK  swapped encryption keys -> vouch fails (no 🟡, gap closed)");

// A stale v1 signature (signing-only) must not light 🟡 for a v2 contact that
// now has encryption keys (forces a real v2 re-vouch).
const v1sig = await bob.sign(vouchMessageBytes("carol", { ed: carolPub.ed, mldsa: carolPub.mldsa }));
const v1Award = await Identity.verify(
  { ed: bobPub.ed, mldsa: bobPub.mldsa },
  vouchMessageBytes("carol", carolPub), // v2 message (carol has enc keys)
  { ed: v1sig.ed, mldsa: v1sig.mldsa },
).catch(() => false);
assert.strictEqual(v1Award, false, "a v1 vouch does not satisfy a v2 (enc-key) contact");
console.log("OK  legacy v1 vouch does not cover a contact's encryption keys");

console.log("\nAll vouch binding checks passed.");
