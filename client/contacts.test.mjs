// Offline tests for the encrypted contact store. Run: node contacts.test.mjs
import assert from "node:assert";

// Minimal in-memory localStorage for Node (the browser provides the real one).
const mem = new Map();
globalThis.localStorage = {
  getItem: (k) => (mem.has(k) ? mem.get(k) : null),
  setItem: (k, v) => mem.set(k, String(v)),
  removeItem: (k) => mem.delete(k),
};

const contacts = await import("./contacts.js");

const PASS = "correct horse battery staple";
const alice = { username: "alice", token: "tok-a", ed: "EDA==", mldsa: "MLA==" };
const bob = { username: "bob", token: "tok-b", ed: "EDB==", mldsa: "MLB==" };

// Fresh store: unlock creates an encrypted empty blob.
assert.ok(!contacts.hasStore(), "no store initially");
await contacts.unlock(PASS);
assert.ok(contacts.isUnlocked() && contacts.hasStore());
assert.deepStrictEqual(contacts.list(), []);

// Blob at rest is ciphertext only — no usernames/keys in the clear.
const atRest = localStorage.getItem("sc.contacts.v1");
assert.ok(atRest.includes('"ct"') && !atRest.includes("alice"), "opaque at rest");

// Add + read back.
await contacts.upsert(alice);
await contacts.upsert({ ...bob, verified: true });
assert.strictEqual(contacts.list().length, 2);
assert.strictEqual(contacts.get("alice").verified, false);
assert.strictEqual(contacts.get("bob").verified, true);
console.log("OK  add + verified flag round-trip");

// Persistence across lock/unlock with the right passphrase.
contacts.lock();
assert.throws(() => contacts.list(), /locked/);
await contacts.unlock(PASS);
assert.strictEqual(contacts.get("bob").verified, true, "state survives relock");
console.log("OK  encrypted persistence across lock/unlock");

// Wrong passphrase refused.
contacts.lock();
await assert.rejects(contacts.unlock("wrong-pass"), /does not decrypt/);
assert.ok(!contacts.isUnlocked());
await contacts.unlock(PASS);
console.log("OK  wrong passphrase refused");

// Key change on a verified contact resets trust.
await contacts.upsert({ username: "bob", ed: "EDX==", mldsa: "MLX==" });
assert.strictEqual(contacts.get("bob").verified, false, "key change drops verified");
assert.ok(contacts.get("bob").keyChangedAt, "key change recorded");
console.log("OK  key change invalidates in-person verification");

// Explicit re-verify + unverify.
await contacts.setVerified("bob", true);
assert.strictEqual(contacts.get("bob").verified, true);
await contacts.setVerified("bob", false);
assert.strictEqual(contacts.get("bob").verified, false);

// Tampered blob refused (GCM integrity).
contacts.lock();
const blob = JSON.parse(localStorage.getItem("sc.contacts.v1"));
const ct = Buffer.from(blob.ct, "base64");
ct[5] ^= 0xff;
blob.ct = ct.toString("base64");
localStorage.setItem("sc.contacts.v1", JSON.stringify(blob));
await assert.rejects(contacts.unlock(PASS), /does not decrypt/);
console.log("OK  tampered blob refused");

// Wipe removes everything.
contacts.wipe();
assert.ok(!contacts.hasStore());
await contacts.unlock(PASS);
assert.deepStrictEqual(contacts.list(), [], "fresh after wipe");
console.log("OK  wipe");

// Remove.
await contacts.upsert(alice);
await contacts.remove("alice");
assert.strictEqual(contacts.list().length, 0);
console.log("OK  remove");

// ---- Audit 2026-07-18 H-01 regressions ------------------------------------

// A verified contact saved WITHOUT encryption keys must lose verification the
// moment encryption keys first appear (missing→present is a real key change).
await contacts.upsert({ username: "carol", token: "tok-c", ed: "EDC==", mldsa: "MLC==", verified: true });
assert.strictEqual(contacts.get("carol").verified, true);
await contacts.upsert({ username: "carol", ed: "EDC==", mldsa: "MLC==", ecdh: "ECX==", mlkem: "KMX==" });
assert.strictEqual(contacts.get("carol").verified, false, "new enc keys drop verified");
assert.ok(contacts.get("carol").keyChangedAt, "enc-key appearance recorded as key change");
console.log("OK  H-01: encryption keys appearing drops verification");

// Changing ONLY one encryption key on a fully-keyed verified contact drops it.
await contacts.setVerified("carol", true);
await contacts.upsert({ username: "carol", ed: "EDC==", mldsa: "MLC==", ecdh: "ECY==", mlkem: "KMX==" });
assert.strictEqual(contacts.get("carol").verified, false, "ecdh change drops verified");
await contacts.setVerified("carol", true);
await contacts.upsert({ username: "carol", ed: "EDC==", mldsa: "MLC==", ecdh: "ECY==", mlkem: "KMY==" });
assert.strictEqual(contacts.get("carol").verified, false, "mlkem change drops verified");
console.log("OK  H-01: any single encryption-key change drops verification");

// An update WITHOUT encryption keys keeps the stored ones and the trust mark
// (nothing the record trusts actually changed).
await contacts.setVerified("carol", true);
await contacts.upsert({ username: "carol", ed: "EDC==", mldsa: "MLC==" });
assert.strictEqual(contacts.get("carol").verified, true, "absent enc keys in update keep verified");
assert.strictEqual(contacts.get("carol").ecdh, "ECY==", "stored ecdh kept");
assert.strictEqual(contacts.get("carol").mlkem, "KMY==", "stored mlkem kept");
console.log("OK  H-01: enc-keyless update keeps stored keys and trust");

// Pins store all four public keys.
await contacts.savePin("user:carol", { ed: "EDC==", mldsa: "MLC==", ecdh: "ECY==", mlkem: "KMY==" });
assert.deepStrictEqual(
  contacts.getPin("user:carol"),
  { ed: "EDC==", mldsa: "MLC==", ecdh: "ECY==", mlkem: "KMY==" },
  "pin covers all four keys",
);
console.log("OK  H-01: pins cover all four keys");

// v2→v3 migration: a verified contact WITH encryption keys was verified
// against a signing-only fingerprint — the mark must be dropped on unlock.
// (The version byte lives in the outer plaintext wrapper, so rewriting it
// simulates a pre-fix blob; the encrypted payload is unchanged.)
{
  const outer = JSON.parse(localStorage.getItem("sc.contacts.v1"));
  assert.strictEqual(outer.v, 3, "store persists as v3 now");
  outer.v = 2;
  localStorage.setItem("sc.contacts.v1", JSON.stringify(outer));
  contacts.lock();
  await contacts.unlock(PASS);
  assert.strictEqual(contacts.get("carol").verified, false, "v2 verified+enc-keys downgraded");
  assert.ok(contacts.get("carol").reverify, "downgrade flagged for the UI");
  assert.strictEqual(JSON.parse(localStorage.getItem("sc.contacts.v1")).v, 3, "re-persisted as v3");
  // Re-verifying clears the flag.
  await contacts.setVerified("carol", true);
  assert.ok(!contacts.get("carol").reverify, "fresh verification clears the reverify flag");
}
console.log("OK  H-01: v2→v3 migration downgrades signing-only verifications");

// Audit 2026-07-18 L-01: the iteration count in the (plaintext) outer wrapper
// is bounded before PBKDF2 runs — a planted blob with a huge count must not
// stall the UI, and a tiny count must not silently weaken the KDF.
{
  contacts.lock();
  const outer = JSON.parse(localStorage.getItem("sc.contacts.v1"));
  for (const iters of [2_000_000_000, 1000]) {
    localStorage.setItem("sc.contacts.v1", JSON.stringify({ ...outer, iters }));
    await assert.rejects(contacts.unlock(PASS), /key-derivation/, `iters=${iters} rejected`);
  }
  localStorage.setItem("sc.contacts.v1", JSON.stringify(outer));
  await contacts.unlock(PASS);
}
console.log("OK  L-01: out-of-bounds KDF iteration counts rejected");

console.log("\nAll contact-store checks passed.");
