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
  assert.strictEqual(outer.v, 4, "store persists as v4 now (L-1 generation counter)");
  outer.v = 2;
  localStorage.setItem("sc.contacts.v1", JSON.stringify(outer));
  contacts.lock();
  await contacts.unlock(PASS);
  assert.strictEqual(contacts.get("carol").verified, false, "v2 verified+enc-keys downgraded");
  assert.ok(contacts.get("carol").reverify, "downgrade flagged for the UI");
  assert.strictEqual(JSON.parse(localStorage.getItem("sc.contacts.v1")).v, 4, "re-persisted as v4");
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

// --- Pentest 2026-07-27 H-2: forged pins can no longer be laundered in -------
// migrateLegacyPins() used to COPY entries out of the plaintext `sc.pins.v1`
// into the authenticated pin map, on EVERY unlock. One localStorage write —
// no passphrase — was therefore enough to make the app auto-accept a MITM
// bundle with no prompt, while the real contact tripped "identity key CHANGED".
{
  contacts.lock();
  localStorage.setItem("sc.pins.v1", JSON.stringify({
    "user:dave": { ed: "MITMED==", mldsa: "MITMMLDSA==" },
  }));
  await contacts.unlock(PASS);
  assert.strictEqual(contacts.getPin("user:dave"), null,
    "a planted plaintext pin is NOT imported into the authenticated store");
  assert.strictEqual(localStorage.getItem("sc.pins.v1"), null,
    "the plaintext pin key is still cleaned up");
  // And a pin that was genuinely saved is unaffected by the plant.
  await contacts.savePin("user:dave", { ed: "REALED==", mldsa: "REALML==" });
  localStorage.setItem("sc.pins.v1", JSON.stringify({
    "user:eve": { ed: "MITMED==", mldsa: "MITMMLDSA==" },
  }));
  contacts.lock();
  await contacts.unlock(PASS);
  assert.strictEqual(contacts.getPin("user:eve"), null, "second plant also ignored");
  assert.strictEqual(contacts.getPin("user:dave").ed, "REALED==", "genuine pin intact");
}
console.log("OK  H-2: plaintext pins are never laundered into the authenticated store");

// --- Pentest 2026-07-27 L-1: deletion / rollback of the store fails closed ---
{
  // Rollback: keep an old copy of the blob, make changes, restore the old copy.
  await contacts.savePin("user:frank", { ed: "FED==", mldsa: "FML==" });
  const oldBlob = localStorage.getItem("sc.contacts.v1");
  await contacts.savePin("user:grace", { ed: "GED==", mldsa: "GML==" });
  await contacts.setVerified("carol", true);
  const currentBlob = localStorage.getItem("sc.contacts.v1");
  contacts.lock();
  localStorage.setItem("sc.contacts.v1", oldBlob);
  await assert.rejects(contacts.unlock(PASS), /OLDER than this device recorded/,
    "an older store copy is refused, not silently opened");
  assert.ok(!contacts.isUnlocked(), "a refused rollback leaves the store LOCKED");

  // …and hasStore() still reports a store is expected, so app.js takes the
  // loud "key changes cannot be detected" path rather than "first contact".
  assert.ok(contacts.hasStore(), "a refused store still counts as present");
  localStorage.setItem("sc.contacts.v1", currentBlob);
}
console.log("OK  L-1: a rolled-back contact store is refused");

{
  // Deletion: remove the blob only. The witness proves a store existed.
  const current = localStorage.getItem("sc.contacts.v1");
  localStorage.removeItem("sc.contacts.v1");
  assert.ok(contacts.hasStore(), "witness alone means a store is still expected");
  await assert.rejects(contacts.unlock(PASS), /DELETED from this device/,
    "a deleted store does not silently become a fresh empty one");
  assert.ok(!contacts.isUnlocked(), "no empty store was created");

  // Deleting the WITNESS instead is caught the other way round.
  localStorage.setItem("sc.contacts.v1", current);
  const witness = localStorage.getItem("sc.contacts.gen.v1");
  localStorage.removeItem("sc.contacts.gen.v1");
  await assert.rejects(contacts.unlock(PASS), /generation record .* is missing/,
    "a store whose witness was removed is refused");

  // A forged/foreign witness is refused too (it is AEAD under the data key).
  localStorage.setItem("sc.contacts.gen.v1", JSON.stringify({ iv: "AAAAAAAAAAAAAAAA", ct: "AAAAAAAAAAAAAAAAAAAAAAA=" }));
  await assert.rejects(contacts.unlock(PASS), /damaged or forged/, "forged witness refused");

  // Restored intact: everything opens again, unchanged.
  localStorage.setItem("sc.contacts.gen.v1", witness);
  await contacts.unlock(PASS);
  assert.strictEqual(contacts.getPin("user:grace").ed, "GED==", "the real store still opens");
  assert.strictEqual(contacts.get("carol").verified, true, "recent verification intact");
}
console.log("OK  L-1: a deleted store / missing / forged witness all fail closed");

{
  // wipe() is the user's OWN deletion — it must clear both, so the next unlock
  // is a clean first run rather than a permanent lockout.
  contacts.wipe();
  assert.ok(!contacts.hasStore(), "wipe clears the witness too");
  await contacts.unlock(PASS);
  assert.deepStrictEqual(contacts.list(), [], "a wiped device starts fresh");
}
console.log("OK  L-1: wipe() clears the witness (no lockout after a deliberate reset)");

// A genuine pre-L-1 store carries NEITHER a generation field nor a witness.
// Existing users must not be locked out by the new check, so that combination
// is adopted at face value and starts counting from there. Built by hand with
// the real KDF, since the point is the payload shape the old code wrote.
{
  await contacts.savePin("user:heidi", { ed: "HED==", mldsa: "HML==" });
  const outer = JSON.parse(localStorage.getItem("sc.contacts.v1"));
  contacts.lock();

  const te = new TextEncoder();
  const u8 = (b64s) => Uint8Array.from(Buffer.from(b64s, "base64"));
  const toB64 = (u) => Buffer.from(u).toString("base64");
  const base = await crypto.subtle.importKey("raw", te.encode(PASS), "PBKDF2", false, ["deriveKey"]);
  const key = await crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: u8(outer.salt), iterations: 600000, hash: "SHA-256" },
    base, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"],
  );
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const legacy = te.encode(JSON.stringify({
    contacts: [{ username: "ivan", ed: "IED==", mldsa: "IML==", verified: true }],
    pins: { "user:ivan": { ed: "IED==", mldsa: "IML==" } },
  })); // note: no `gen`
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, legacy));
  localStorage.setItem("sc.contacts.v1", JSON.stringify({
    v: 3, iters: 600000, salt: outer.salt, iv: toB64(iv), ct: toB64(ct),
  }));
  localStorage.removeItem("sc.contacts.gen.v1");

  await contacts.unlock(PASS);
  assert.strictEqual(contacts.get("ivan").verified, true, "a legacy v3 store still opens");
  assert.strictEqual(contacts.getPin("user:ivan").ed, "IED==", "legacy pins survive");
  assert.ok(localStorage.getItem("sc.contacts.gen.v1") !== null,
    "the upgrade writes a witness so the NEXT rollback is caught");
  assert.strictEqual(JSON.parse(localStorage.getItem("sc.contacts.v1")).v, 4, "upgraded to v4");
}
console.log("OK  L-1: a genuine pre-L-1 store is adopted, not locked out");

console.log("\nAll contact-store checks passed.");
