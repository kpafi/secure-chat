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

console.log("\nAll contact-store checks passed.");
