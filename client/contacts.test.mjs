// Offline tests for the encrypted contact store. Run: node contacts.test.mjs
import assert from "node:assert";

// Minimal in-memory localStorage for Node (the browser provides the real one).
const mem = new Map();
globalThis.localStorage = {
  getItem: (k) => (mem.has(k) ? mem.get(k) : null),
  setItem: (k, v) => mem.set(k, String(v)),
  removeItem: (k) => mem.delete(k),
  clear: () => mem.clear(),
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

// --- H-2 (2026-07-29): the witness must not be openable AS the store ---------
// The witness and the store were encrypted under the SAME dataKey with the SAME
// salt, and only the witness carried a domain tag. So copying the witness over
// the store — one setItem, no passphrase, no deletion, nothing removed —
// decrypted cleanly into an empty, PIN-LESS store at the same generation. The
// rollback check passed (same gen), hasStore() and pinsReadable() stayed true so
// the loud "key changes cannot be detected" path never ran, and every peer then
// rendered as a benign FIRST CONTACT instead of "identity key CHANGED": the
// alarm inverted. It then healed itself into a legitimate store on the next
// write, erasing the evidence.
{
  await contacts.unlock(PASS);
  await contacts.savePin("user:judy", { ed: "JED==", mldsa: "JML==" });
  assert.strictEqual(contacts.getPin("user:judy").ed, "JED==", "precondition: pin stored");
  const witness = localStorage.getItem("sc.contacts.gen.v1");
  assert.ok(witness, "precondition: a witness exists to copy");
  contacts.lock();

  // The whole attack.
  localStorage.setItem("sc.contacts.v1", witness);

  await assert.rejects(
    contacts.unlock(PASS),
    /not a contact store/,
    "H-2: the witness must not open as a pin-less store",
  );
  // And it must fail CLOSED — no half-open store left behind for the caller.
  assert.throws(() => contacts.getPin("user:judy"), /locked/,
    "H-2: a refused unlock must leave the store locked, not empty-and-usable");
}
console.log("OK  H-2: the generation witness cannot be substituted for the store");

// The tag must not lock out the users it was added around: a pre-v4 store has
// no `d` at all, and must still open and then be re-persisted WITH the tag.
{
  localStorage.clear();
  await contacts.unlock(PASS);
  await contacts.savePin("user:ken", { ed: "KED==", mldsa: "KML==" });
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
  const write = async (payload, v) => {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = new Uint8Array(await crypto.subtle.encrypt(
      { name: "AES-GCM", iv }, key, te.encode(JSON.stringify(payload)),
    ));
    localStorage.setItem("sc.contacts.v1", JSON.stringify({
      v, iters: 600000, salt: outer.salt, iv: toB64(iv), ct: toB64(ct),
    }));
  };

  // Untagged but genuinely a store — the real pre-v4 shape, which carries no
  // `gen` either. Adopted, and upgraded in place so it is tagged from now on.
  await write({ contacts: [{ username: "lena", ed: "LED==", mldsa: "LML==" }],
                pins: { "user:lena": { ed: "LED==", mldsa: "LML==" } } }, 3);
  localStorage.removeItem("sc.contacts.gen.v1");
  await contacts.unlock(PASS);
  assert.strictEqual(contacts.getPin("user:lena").ed, "LED==", "an untagged store still opens");
  assert.strictEqual(JSON.parse(localStorage.getItem("sc.contacts.v1")).v, 4,
    "the adopted store is re-persisted at v4");
  contacts.lock();
  // …and once upgraded it really does carry the tag, so the adoption path is
  // taken exactly once. Re-opening must not need adopting again.
  await contacts.unlock(PASS);
  assert.strictEqual(contacts.getPin("user:lena").ed, "LED==", "the upgraded store reopens");
  contacts.lock();

  // A wrong tag is refused even though it decrypts and looks store-shaped —
  // the check is on the tag, not on the shape.
  await write({ d: "secure-chat/contacts-store/v99", contacts: [], pins: {}, gen: 9 }, 4);
  await assert.rejects(contacts.unlock(PASS), /not a contact store/,
    "H-2: a foreign domain tag is refused");
}
console.log("OK  H-2: pre-v4 stores are adopted and tagged; a foreign tag is refused");

// --- L-3 (2026-07-29): a second tab must not silently lose a write -----------
// Both tabs unlock at generation N and both persist N+1. The second overwrites
// the first and rewrites the witness to match, so the rollback check agrees and
// the first tab's change — possibly a PIN — is gone with no trace.
{
  localStorage.clear();
  await contacts.unlock(PASS);
  await contacts.savePin("user:mo", { ed: "MED==", mldsa: "MML==" });

  // Snapshot this tab's view, then let "the other tab" advance the store.
  const myStore = localStorage.getItem("sc.contacts.v1");
  const myGenView = localStorage.getItem("sc.contacts.gen.v1");
  await contacts.savePin("user:nina", { ed: "NED==", mldsa: "NML==" });   // other tab writes
  const otherStore = localStorage.getItem("sc.contacts.v1");
  const otherWitness = localStorage.getItem("sc.contacts.gen.v1");
  assert.notStrictEqual(otherWitness, myGenView, "precondition: the other tab moved the generation");

  // Now this tab, still holding its stale in-memory generation, tries to write.
  // Reconstruct that state: our store blob is the OLD one, the witness is NEW.
  localStorage.setItem("sc.contacts.v1", myStore);
  contacts.lock();
  // This half is already covered by the L-1 rollback check — a stale store
  // against a newer witness reads as "an earlier copy has been restored". Kept
  // so the two halves of the tab race are visible together; the NEW part is the
  // write-side refusal at the end of this block.
  await assert.rejects(
    contacts.unlock(PASS),
    /OLDER than this device recorded/,
    "L-3: a stale store against a newer witness must not open silently",
  );

  // The other tab's data is what survives, and it still opens.
  localStorage.setItem("sc.contacts.v1", otherStore);
  localStorage.setItem("sc.contacts.gen.v1", otherWitness);
  await contacts.unlock(PASS);
  assert.strictEqual(contacts.getPin("user:nina").ed, "NED==", "the newer write survived");
  assert.strictEqual(contacts.getPin("user:mo").ed, "MED==", "…and so did the earlier one");

  // The write side, which is the actually-new part. Two tabs are two module
  // instances over one localStorage, so that is exactly how this is built —
  // a second import with a query string gets its own module state.
  const tabB = await import("./contacts.js?tab=b");
  await tabB.unlock(PASS);                                   // both tabs at gen N
  await tabB.savePin("user:otto", { ed: "OED==", mldsa: "OML==" }); // B commits N+1

  // Tab A is still holding N in memory and has no idea. Its next write is the
  // lost update: before the fix it overwrote B's store AND B's witness, so
  // "otto" vanished with nothing to detect it afterwards.
  await assert.rejects(
    contacts.savePin("user:pia", { ed: "PED==", mldsa: "PML==" }),
    /changed in another tab/,
    "L-3: writing over a newer witness must be refused, not silently merged",
  );
  assert.throws(() => contacts.getPin("user:mo"), /locked/,
    "L-3: the refusal leaves the store locked, so nothing half-written is used");

  // B's write survived intact — that is the whole point.
  await tabB.unlock(PASS);
  assert.strictEqual(tabB.getPin("user:otto").ed, "OED==", "the other tab's pin is still there");
}
console.log("OK  L-3: a concurrent second-tab write is refused, not silently lost");

console.log("\nAll contact-store checks passed.");
