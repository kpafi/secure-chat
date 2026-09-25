// Offline tests for the encrypted contact store. Run: node contacts.test.mjs
import assert from "node:assert";
import { fakeIdb } from "./fake-idb.test.mjs"; // package 3b: IndexedDB for node

// Minimal in-memory localStorage for Node (the browser provides the real one).
const mem = new Map();
globalThis.localStorage = {
  getItem: (k) => (mem.has(k) ? mem.get(k) : null),
  setItem: (k, v) => mem.set(k, String(v)),
  removeItem: (k) => mem.delete(k),
  clear: () => mem.clear(),
};

const contacts = await import("./contacts.js");
await contacts.ready; // 3b: hasStore() answers "yes" until the IndexedDB preload settled

const PASS = "correct horse battery staple";
const alice = { username: "alice", token: "tok-a", ed: "EDA==", mldsa: "MLA==" };
const bob = { username: "bob", token: "tok-b", ed: "EDB==", mldsa: "MLB==" };

// Fresh store: unlock creates an encrypted empty blob.
assert.ok(!contacts.hasStore(), "no store initially");
await contacts.unlock(PASS);
assert.ok(contacts.isUnlocked() && contacts.hasStore());
assert.deepStrictEqual(contacts.list(), []);

// Blob at rest is ciphertext only — no usernames/keys in the clear.
const atRest = fakeIdb.getItem("sc.contacts.v1");
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
const blob = JSON.parse(fakeIdb.getItem("sc.contacts.v1"));
const ct = Buffer.from(blob.ct, "base64");
ct[5] ^= 0xff;
blob.ct = ct.toString("base64");
fakeIdb.setItem("sc.contacts.v1", JSON.stringify(blob));
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
//
// Package 3, F-ATREST-006: this test used to SIMULATE a pre-fix blob by
// rewriting the outer `v` byte to 2 — i.e. it asserted the bug: plaintext
// outside the AEAD decided the migration. The migration is now keyed on the
// authenticated shape (an untagged store), so both directions are pinned: a
// current store whose outer byte is rewritten keeps its genuine verifications,
// and a genuinely pre-tag store cannot skip the migration by claiming `v: 3`.
async function sealLegacyStore(inner, outerV) {
  const outer = JSON.parse(fakeIdb.getItem("sc.contacts.v1"));
  const te = new TextEncoder();
  const u8 = (b64s) => Uint8Array.from(Buffer.from(b64s, "base64"));
  const toB64 = (u) => Buffer.from(u).toString("base64");
  const base = await crypto.subtle.importKey("raw", te.encode(PASS), "PBKDF2", false, ["deriveKey"]);
  const key = await crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: u8(outer.salt), iterations: 600000, hash: "SHA-256" },
    base, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"],
  );
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, te.encode(JSON.stringify(inner))));
  fakeIdb.setItem("sc.contacts.v1", JSON.stringify({ v: outerV, iters: 600000, salt: outer.salt, iv: toB64(iv), ct: toB64(ct) }));
}
{
  const outer = JSON.parse(fakeIdb.getItem("sc.contacts.v1"));
  assert.strictEqual(outer.v, 4, "store persists as v4 now (L-1 generation counter)");
  // (1) The outer byte rewritten on a CURRENT store: nothing inside the AEAD
  // says it predates the four-key fingerprint, so carol's verification stands.
  outer.v = 2;
  fakeIdb.setItem("sc.contacts.v1", JSON.stringify(outer));
  contacts.lock();
  await contacts.unlock(PASS);
  assert.strictEqual(contacts.get("carol").verified, true,
    "F-ATREST-006: rewriting the plaintext `v` of a current store must not drop genuine verifications");
  assert.ok(!contacts.get("carol").reverify);

  // (2) A genuinely pre-tag store (no `d`, no `gen` inside the AEAD) whose outer
  // byte CLAIMS v3. Before the fix `(blob.v || 1) < 3` was false, so the
  // signing-only mark survived the upgrade.
  const carol = contacts.get("carol");
  await sealLegacyStore({ contacts: [{ ...carol, verified: true }], pins: {} }, 3);
  fakeIdb.removeItem("sc.contacts.gen.v1");
  contacts.lock();
  await contacts.unlock(PASS, { adoptLegacy: true });
  assert.strictEqual(contacts.get("carol").verified, false,
    "F-ATREST-006: a pre-tag store cannot skip the H-01 migration by writing `v: 3` outside the AEAD");
  assert.ok(contacts.get("carol").reverify, "downgrade flagged for the UI");
  assert.strictEqual(JSON.parse(fakeIdb.getItem("sc.contacts.v1")).v, 4, "re-persisted as v4");
  // Re-verifying clears the flag.
  await contacts.setVerified("carol", true);
  assert.ok(!contacts.get("carol").reverify, "fresh verification clears the reverify flag");
}
console.log("OK  H-01 / F-ATREST-006: the v2→v3 migration is keyed inside the AEAD, not on the outer byte");

// Audit 2026-07-18 L-01: the iteration count in the (plaintext) outer wrapper
// is bounded before PBKDF2 runs — a planted blob with a huge count must not
// stall the UI, and a tiny count must not silently weaken the KDF.
{
  contacts.lock();
  const outer = JSON.parse(fakeIdb.getItem("sc.contacts.v1"));
  for (const iters of [2_000_000_000, 1000]) {
    fakeIdb.setItem("sc.contacts.v1", JSON.stringify({ ...outer, iters }));
    await assert.rejects(contacts.unlock(PASS), /key-derivation/, `iters=${iters} rejected`);
  }
  fakeIdb.setItem("sc.contacts.v1", JSON.stringify(outer));
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
  const oldBlob = fakeIdb.getItem("sc.contacts.v1");
  await contacts.savePin("user:grace", { ed: "GED==", mldsa: "GML==" });
  await contacts.setVerified("carol", true);
  const currentBlob = fakeIdb.getItem("sc.contacts.v1");
  contacts.lock();
  fakeIdb.setItem("sc.contacts.v1", oldBlob);
  await assert.rejects(contacts.unlock(PASS), /OLDER than this device recorded/,
    "an older store copy is refused, not silently opened");
  assert.ok(!contacts.isUnlocked(), "a refused rollback leaves the store LOCKED");

  // …and hasStore() still reports a store is expected, so app.js takes the
  // loud "key changes cannot be detected" path rather than "first contact".
  assert.ok(contacts.hasStore(), "a refused store still counts as present");
  fakeIdb.setItem("sc.contacts.v1", currentBlob);
}
console.log("OK  L-1: a rolled-back contact store is refused");

{
  // Deletion: remove the blob only. The witness proves a store existed.
  const current = fakeIdb.getItem("sc.contacts.v1");
  fakeIdb.removeItem("sc.contacts.v1");
  assert.ok(contacts.hasStore(), "witness alone means a store is still expected");
  await assert.rejects(contacts.unlock(PASS), /DELETED from this device/,
    "a deleted store does not silently become a fresh empty one");
  assert.ok(!contacts.isUnlocked(), "no empty store was created");

  // Deleting the WITNESS instead is caught the other way round.
  fakeIdb.setItem("sc.contacts.v1", current);
  const witness = fakeIdb.getItem("sc.contacts.gen.v1");
  fakeIdb.removeItem("sc.contacts.gen.v1");
  await assert.rejects(contacts.unlock(PASS), /generation record .* is missing/,
    "a store whose witness was removed is refused");

  // A forged/foreign witness is refused too (it is AEAD under the data key).
  fakeIdb.setItem("sc.contacts.gen.v1", JSON.stringify({ iv: "AAAAAAAAAAAAAAAA", ct: "AAAAAAAAAAAAAAAAAAAAAAA=" }));
  await assert.rejects(contacts.unlock(PASS), /damaged or forged/, "forged witness refused");

  // Restored intact: everything opens again, unchanged.
  fakeIdb.setItem("sc.contacts.gen.v1", witness);
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
  const outer = JSON.parse(fakeIdb.getItem("sc.contacts.v1"));
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
  fakeIdb.setItem("sc.contacts.v1", JSON.stringify({
    v: 3, iters: 600000, salt: outer.salt, iv: toB64(iv), ct: toB64(ct),
  }));
  fakeIdb.removeItem("sc.contacts.gen.v1");

  // F-ATREST-004 (2026-08-07): no longer adopted on sight. This exact shape —
  // an archived pre-L-1 blob, decrypting under the same passphrase, witness
  // removed — is also how revoked pins were resurrected, so it is an explicit
  // choice. The epoch marker is present (this device has run post-fix code),
  // which makes the prompt the suspicious flavour.
  await assert.rejects(contacts.unlock(PASS),
    (e) => e.code === "LEGACY_CONTACTS_ADOPTION" && e.suspicious === true,
    "a gen-less store is not adopted silently");
  assert.ok(!contacts.isUnlocked(), "the refusal leaves the store locked");
  assert.ok(contacts.hasStore(), "and app.js sees a store that will not open (loud path), not a first run");
  {
    // A genuinely upgrading device has never run post-fix code: same prompt,
    // not marked suspicious.
    const epoch = localStorage.getItem("sc.contacts.epoch.v1");
    localStorage.removeItem("sc.contacts.epoch.v1");
    await assert.rejects(contacts.unlock(PASS),
      (e) => e.code === "LEGACY_CONTACTS_ADOPTION" && e.suspicious === false);
    localStorage.setItem("sc.contacts.epoch.v1", epoch);
  }

  await contacts.unlock(PASS, { adoptLegacy: true });
  assert.strictEqual(contacts.get("ivan").verified, true, "a legacy v3 store still opens when adopted");
  assert.strictEqual(contacts.getPin("user:ivan").ed, "IED==", "legacy pins survive");
  assert.ok(fakeIdb.getItem("sc.contacts.gen.v1") !== null,
    "the upgrade writes a witness so the NEXT rollback is caught");
  assert.strictEqual(JSON.parse(fakeIdb.getItem("sc.contacts.v1")).v, 4, "upgraded to v4");
}
console.log("OK  L-1 / F-ATREST-004: a genuine pre-L-1 store is adopted on request, never silently");

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
  const witness = fakeIdb.getItem("sc.contacts.gen.v1");
  assert.ok(witness, "precondition: a witness exists to copy");
  contacts.lock();

  // The whole attack.
  fakeIdb.setItem("sc.contacts.v1", witness);

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
  localStorage.clear(); fakeIdb.clear();
  await contacts.unlock(PASS);
  await contacts.savePin("user:ken", { ed: "KED==", mldsa: "KML==" });
  const outer = JSON.parse(fakeIdb.getItem("sc.contacts.v1"));
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
    fakeIdb.setItem("sc.contacts.v1", JSON.stringify({
      v, iters: 600000, salt: outer.salt, iv: toB64(iv), ct: toB64(ct),
    }));
  };

  // Untagged but genuinely a store — the real pre-v4 shape, which carries no
  // `gen` either. Adopted, and upgraded in place so it is tagged from now on.
  await write({ contacts: [{ username: "lena", ed: "LED==", mldsa: "LML==" }],
                pins: { "user:lena": { ed: "LED==", mldsa: "LML==" } } }, 3);
  fakeIdb.removeItem("sc.contacts.gen.v1");
  // (F-ATREST-004: an untagged store has no generation, so it takes the explicit
  // adoption path now — the H-2 property under test is unchanged.)
  await assert.rejects(contacts.unlock(PASS), (e) => e.code === "LEGACY_CONTACTS_ADOPTION");
  await contacts.unlock(PASS, { adoptLegacy: true });
  assert.strictEqual(contacts.getPin("user:lena").ed, "LED==", "an untagged store still opens");
  assert.strictEqual(JSON.parse(fakeIdb.getItem("sc.contacts.v1")).v, 4,
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
  localStorage.clear(); fakeIdb.clear();
  await contacts.unlock(PASS);
  await contacts.savePin("user:mo", { ed: "MED==", mldsa: "MML==" });

  // Snapshot this tab's view, then let "the other tab" advance the store.
  const myStore = fakeIdb.getItem("sc.contacts.v1");
  const myGenView = fakeIdb.getItem("sc.contacts.gen.v1");
  await contacts.savePin("user:nina", { ed: "NED==", mldsa: "NML==" });   // other tab writes
  const otherStore = fakeIdb.getItem("sc.contacts.v1");
  const otherWitness = fakeIdb.getItem("sc.contacts.gen.v1");
  assert.notStrictEqual(otherWitness, myGenView, "precondition: the other tab moved the generation");

  // Now this tab, still holding its stale in-memory generation, tries to write.
  // Reconstruct that state: our store blob is the OLD one, the witness is NEW.
  fakeIdb.setItem("sc.contacts.v1", myStore);
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
  fakeIdb.setItem("sc.contacts.v1", otherStore);
  fakeIdb.setItem("sc.contacts.gen.v1", otherWitness);
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

// ---- Pentest 2026-08-07 F-PROTO-005: a vouch verified for superseded keys ----
// must not be attached to the keys that replaced them.
{
  localStorage.clear(); fakeIdb.clear();
  await contacts.unlock(PASS);
  await contacts.upsert({ username: "carol", token: "t", ed: "E1==", mldsa: "M1==", ecdh: "C1==", mlkem: "K1==" });
  const old = contacts.get("carol");
  // The keys change while a vouch fetched + verified for the OLD keys is still
  // in flight (a stalling directory chooses how long that window is).
  await contacts.upsert({ username: "carol", token: "t", ed: "E2==", mldsa: "M2==", ecdh: "C2==", mlkem: "K2==" });
  const landed = await contacts.setVouches("carol", ["bob"],
    { ed: old.ed, mldsa: old.mldsa, ecdh: old.ecdh ?? null, mlkem: old.mlkem ?? null });
  assert.strictEqual(landed, false, "a stale vouch result must be discarded, not written");
  assert.ok(!(contacts.get("carol").vouchedBy || []).length,
    "a vouch verified for superseded keys must not mark the new keys");
  // An enc-key-only change is a key change too (H-01 says all four keys count).
  await contacts.upsert({ username: "carol", token: "t", ed: "E2==", mldsa: "M2==", ecdh: "C3==", mlkem: "K3==" });
  assert.strictEqual(
    await contacts.setVouches("carol", ["bob"], { ed: "E2==", mldsa: "M2==", ecdh: "C2==", mlkem: "K2==" }),
    false, "an encryption-key change alone must also invalidate the in-flight vouch");
  // The honest case still lands.
  assert.strictEqual(
    await contacts.setVouches("carol", ["bob"], { ed: "E2==", mldsa: "M2==", ecdh: "C3==", mlkem: "K3==" }),
    true);
  assert.deepStrictEqual(contacts.get("carol").vouchedBy, ["bob"]);
  // Package 2, item 11 (F-PROTO-005, the rest): `forKeys` used to default to
  // null, and null SKIPPED the check — the unbound write, one forgotten
  // argument away. Without the keys the vouches were verified against, the
  // write is refused outright, and nothing is written.
  for (const missing of [undefined, null, {}, { ed: "E2==" }]) {
    await assert.rejects(contacts.setVouches("carol", ["mallory"], missing), /verified against/,
      `item 11: setVouches without the verified keys (${JSON.stringify(missing)}) must throw`);
  }
  assert.deepStrictEqual(contacts.get("carol").vouchedBy, ["bob"], "item 11: ...and write nothing");
}
console.log("OK  F-PROTO-005: a vouch result for superseded keys is discarded; the keys are required");

// ---- Pentest 2026-08-07 F-ATREST-007: Unverify / Remove revoke the pin ------
{
  localStorage.clear(); fakeIdb.clear();
  await contacts.unlock(PASS);
  const bob = { ed: "BED==", mldsa: "BML==", ecdh: "BEC==", mlkem: "BKM==" };
  await contacts.upsert({ username: "bob", token: "t", ...bob, verified: true });
  await contacts.savePin(contacts.pinKeyFor("bob"), bob);
  assert.strictEqual(contacts.getPin("user:bob").revoked, undefined);
  await contacts.setVerified("bob", false);
  assert.strictEqual(contacts.getPin("user:bob").revoked, true,
    "Unverify must mark the pin revoked, or the next session auto-unlocks on it");
  assert.strictEqual(contacts.getPin("user:bob").ed, "BED==", "the keys stay for change detection");
  await contacts.savePin(contacts.pinKeyFor("bob"), bob); // fresh in-person verification
  assert.strictEqual(contacts.getPin("user:bob").revoked, undefined, "a new verification clears the mark");
  await contacts.remove("bob");
  assert.ok(contacts.getPin("user:bob"), "Remove keeps the pin (a re-add with new keys must still alarm)");
  assert.strictEqual(contacts.getPin("user:bob").revoked, true, "…but revoked");
  // It survives a lock/unlock: it lives inside the AEAD.
  contacts.lock();
  await contacts.unlock(PASS);
  assert.strictEqual(contacts.getPin("user:bob").revoked, true);
}
console.log("OK  F-ATREST-007: Unverify and Remove revoke the pin (kept for change detection)");

// ---- Package 3, F-ATREST-007 / 2026-08-08 item 17: the room: pins too --------
// A session started from a room code pins the peer under `room:<id>`; those
// pins were never revoked, so a revoked peer re-entering a remembered room
// auto-unlocked on "matches your saved pin". (app-behaviour.test.mjs drives
// that end to end; this pins the store's half.)
{
  localStorage.clear(); fakeIdb.clear();
  await contacts.unlock(PASS);
  const dan = { ed: "REVEDA==", mldsa: "REVMLA==", ecdh: "REVECA==", mlkem: "REVKMA==" };
  const eve = { ed: "OTHEDA==", mldsa: "OTHMLA==" };
  await contacts.upsert({ username: "dan", token: "t", ...dan, verified: true });
  await contacts.savePin("room:" + "1".repeat(64), dan);
  // Same SIGNING identity, pinned before the encryption keys were: still dan.
  await contacts.savePin("room:" + "2".repeat(64), { ed: dan.ed, mldsa: dan.mldsa });
  await contacts.savePin("room:" + "3".repeat(64), eve);           // somebody else
  await contacts.savePin("user:dan", dan);
  await contacts.setVerified("dan", false);
  assert.strictEqual(contacts.getPin("room:" + "1".repeat(64)).revoked, true,
    "item 17: Unverify revokes a room: pin under the contact's identity");
  assert.strictEqual(contacts.getPin("room:" + "2".repeat(64)).revoked, true,
    "item 17: …including one made before the encryption keys were pinned (same signing keys)");
  assert.strictEqual(contacts.getPin("room:" + "3".repeat(64)).revoked, undefined,
    "item 17: another identity's room pin is untouched");
  assert.strictEqual(contacts.getPin("room:" + "1".repeat(64)).ed, dan.ed, "the keys stay for change detection");

  // Remove does the same, from the record as it was before removal.
  await contacts.savePin("room:" + "1".repeat(64), dan);   // re-verified in that room
  await contacts.setVerified("dan", true);
  await contacts.remove("dan");
  assert.strictEqual(contacts.getPin("room:" + "1".repeat(64)).revoked, true, "item 17: Remove revokes room: pins too");
  assert.strictEqual(contacts.getPin("room:" + "3".repeat(64)).revoked, undefined);
  contacts.lock();
  await contacts.unlock(PASS);
  assert.strictEqual(contacts.getPin("room:" + "1".repeat(64)).revoked, true, "…and it is persisted");
}
console.log("OK  item 17: Unverify / Remove revoke every room: pin under the contact's signing identity");

// ---- fix round 1 (pentest L): the keys the user VERIFIED, not only the record's
// poc4: Bob verified with K1 (user:bob + a room: pin), then a directory refresh
// stores K2 in his record. Remove used to sweep room: pins by K2 only, so the
// room pin for the K1 he had verified stayed live and auto-accepted K1.
{
  localStorage.clear(); fakeIdb.clear();
  await contacts.unlock(PASS);
  const K1 = { ed: "RURCMQ==", mldsa: "TUxCMQ==", ecdh: "RUMx", mlkem: "TUsx" };
  const K2 = { ed: "RVZJTA==", mldsa: "TUxFVg==", ecdh: "RUMy", mlkem: "TUsy" };
  const R = "room:" + "4".repeat(64);
  await contacts.upsert({ username: "bob", ...K1, verified: true });
  await contacts.savePin(contacts.pinKeyFor("bob"), K1);
  await contacts.savePin(R, K1);
  await contacts.upsert({ username: "bob", ...K2 });
  await contacts.remove("bob");
  assert.strictEqual(contacts.getPin(R).revoked, true,
    "fix round 1: a room: pin under the keys the user verified (user:bob's pin) is revoked, even after the record's keys moved");

  // J10: the comparison is on decoded BYTES — a respelled key (same bytes,
  // non-canonical base64) is the same identity.
  const Q = { ed: "QQ==", mldsa: "Qg==" };
  const R2 = "room:" + "5".repeat(64);
  await contacts.upsert({ username: "quinn", ...Q, verified: true });
  await contacts.savePin(R2, { ed: "QR==", mldsa: "Qh==" }); // decode to the same bytes as Q
  await contacts.setVerified("quinn", false);
  assert.strictEqual(contacts.getPin(R2).revoked, true,
    "fix round 1: room: pins are matched on decoded key bytes, not on the base64 spelling");

  // …and the RECORD's keys still count on their own: a contact verified only in
  // a room session (no user: pin) is removed — its room pin must go too.
  const E = { ed: "RUVE", mldsa: "RU1M" };
  const R3 = "room:" + "6".repeat(64);
  await contacts.upsert({ username: "erin", ...E, verified: true });
  await contacts.savePin(R3, E);
  await contacts.remove("erin");
  assert.strictEqual(contacts.getPin(R3).revoked, true,
    "Remove revokes room: pins under the removed record's keys even with no user: pin");

  // Decision pinned: another contact ENTRY with the same keys keeps its own pin.
  await contacts.upsert({ username: "quinn2", ...Q, verified: true });
  await contacts.savePin(contacts.pinKeyFor("quinn2"), Q);
  await contacts.setVerified("quinn", false);
  assert.strictEqual(contacts.getPin(contacts.pinKeyFor("quinn2")).revoked, undefined,
    "a separately verified entry's user: pin is not withdrawn by unverifying another entry");
}
console.log("OK  fix round 1: revocation follows the verified keys (user: pin) and decoded bytes");

// ---- fix round 2 (review L, poc7): a re-verification under NEW keys supersedes
// the room: pins of the OLD ones. Bob verified with K1 (user:bob, room:R); his
// phone is replaced (K2) and re-verified in person, which overwrites user:bob;
// a later Remove only ever sees K2 — so room:R (K1) stayed live and the old
// phone's holder was auto-accepted in that room.
{
  localStorage.clear(); fakeIdb.clear();
  await contacts.unlock(PASS);
  const K1 = { ed: "RURCMQ==", mldsa: "TUxCMQ==", ecdh: "RUMx", mlkem: "TUsx" };
  const K2 = { ed: "RVZJTA==", mldsa: "TUxFVg==", ecdh: "RUMy", mlkem: "TUsy" };
  const R = "room:" + "7".repeat(64);
  const R2 = "room:" + "8".repeat(64);
  await contacts.upsert({ username: "bob", ...K1, verified: true });
  await contacts.savePin(contacts.pinKeyFor("bob"), K1);
  await contacts.savePin(R, K1);
  await contacts.savePin(R2, K2);                    // an unrelated room pin already under K2
  await contacts.upsert({ username: "bob", ...K2, verified: true });
  await contacts.savePin(contacts.pinKeyFor("bob"), K2);
  assert.strictEqual(contacts.getPin(R).revoked, true,
    "fix round 2: re-pinning user:bob to a different identity revokes room: pins of the superseded keys");
  assert.strictEqual(contacts.getPin(R2).revoked, undefined, "…not those of the new keys");
  await contacts.remove("bob");
  assert.strictEqual(contacts.getPin(R).revoked, true, "poc7: after Remove the K1 room pin is (still) revoked");
  // Re-saving the SAME identity (enc keys updated) supersedes nothing.
  const R3 = "room:" + "9".repeat(64);
  await contacts.upsert({ username: "cat", ed: "Q0FU", mldsa: "Q01M", verified: true });
  await contacts.savePin(contacts.pinKeyFor("cat"), { ed: "Q0FU", mldsa: "Q01M" });
  await contacts.savePin(R3, { ed: "Q0FU", mldsa: "Q01M" });
  await contacts.savePin(contacts.pinKeyFor("cat"), { ed: "Q0FU", mldsa: "Q01M", ecdh: "RUNE", mlkem: "S0VN" });
  assert.strictEqual(contacts.getPin(R3).revoked, undefined, "same signing identity: its room pins stay");
}
console.log("OK  fix round 2: a re-verification under new keys revokes the old keys' room: pins");

// ---- Pentest 2026-08-07 F-ATREST-003/004: the native floor, where it exists --
// A second module instance captures the bridge at load, exactly as on the
// device (the app injects it at document-start, before any module runs).
{
  localStorage.clear(); fakeIdb.clear();
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
  const cN = await import("./contacts.js?native=1");
  const ID = "a".repeat(64); // sha256 hex of the identity's signing key, as app.js passes it

  assert.deepStrictEqual(await cN.unlock(PASS, { floorId: ID }), { created: true });
  await cN.savePin("user:carl", { ed: "CED==", mldsa: "CML==" });
  assert.strictEqual(floors.get("contacts:" + ID), 2, "every persist bumps the identity's floor");
  const storeSnap = fakeIdb.getItem("sc.contacts.v1");
  const witSnap = fakeIdb.getItem("sc.contacts.gen.v1");
  await cN.savePin("user:dora", { ed: "DED==", mldsa: "DML==" });
  cN.lock();

  // F-ATREST-003, confirmed finding: delete BOTH blobs. Pre-fix: silent empty
  // store, pins gone, no warning. Now: refused, and app.js sees "a store that
  // will not open", not a first run.
  fakeIdb.removeItem("sc.contacts.v1");
  fakeIdb.removeItem("sc.contacts.gen.v1");
  await assert.rejects(cN.unlock(PASS, { floorId: ID }),
    (e) => e.code === "DELETED_CONTACTS_ADOPTION" && /DELETED/.test(e.message),
    "F-ATREST-003: store + witness both deleted fails CLOSED where a floor exists");
  assert.ok(!cN.isUnlocked());
  assert.ok(cN.hasStore(), "pins are 'unreadable', not 'absent', so the loud P-02 path runs");

  // The coordinated snapshot the L-1 note calls residual: restore BOTH. The
  // witness agrees with the store; the floor does not.
  fakeIdb.setItem("sc.contacts.v1", storeSnap);
  fakeIdb.setItem("sc.contacts.gen.v1", witSnap);
  await assert.rejects(cN.unlock(PASS, { floorId: ID }), /OLDER than this device recorded/,
    "a both-restored rollback is caught by the floor");

  // F-ATREST-004 on device: a gen-less blob is a restore BY DEFINITION once a
  // floor exists — refused outright, adoption or not.
  {
    const outer = JSON.parse(storeSnap);
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
      contacts: [], pins: { "user:mallory": { ed: "MED==", mldsa: "MML==" } },
    }));
    const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, legacy));
    fakeIdb.setItem("sc.contacts.v1", JSON.stringify({ v: 3, iters: 600000, salt: outer.salt, iv: toB64(iv), ct: toB64(ct) }));
    fakeIdb.removeItem("sc.contacts.gen.v1");
    await assert.rejects(cN.unlock(PASS, { floorId: ID, adoptLegacy: true }), /earlier copy has been restored/,
      "F-ATREST-004 on device: adoption cannot override a floor");
  }

  // The user's own Forget-then-restore of the same identity is the SAME state
  // as the attack, so it is an explicit choice, and the store then continues
  // the floor's numbering rather than restarting it.
  cN.wipe();
  await assert.rejects(cN.unlock(PASS, { floorId: ID }), (e) => e.code === "DELETED_CONTACTS_ADOPTION");
  assert.deepStrictEqual(await cN.unlock(PASS, { floorId: ID, adoptDeleted: true }), { created: true });
  assert.ok(floors.get("contacts:" + ID) >= 4, "the recreated store continues from the floor");
  cN.lock();

  // A different identity on the same device has its own floor: a clean first run.
  localStorage.clear(); fakeIdb.clear();
  assert.deepStrictEqual(await cN.unlock(PASS, { floorId: "b".repeat(64) }), { created: true });
  cN.lock();

  // A floor that exists but cannot be read is TAMPERED, never "no floor".
  floors.set("contacts:" + "b".repeat(64), "junk");
  await assert.rejects(cN.unlock(PASS, { floorId: "b".repeat(64) }), /damaged or forged/);

  // Marker present, bridge gone (the H-1 shape): fail closed, distinct wording.
  Object.defineProperty(globalThis, "__SECURE_CHAT_NATIVE_FLOOR__", { value: true, configurable: true });
  delete globalThis.__SECURE_CHAT_PAD_FLOOR__;
  const cM = await import("./contacts.js?native=marker-only");
  await assert.rejects(cM.unlock(PASS, { floorId: ID }), /cannot reach it/);
  delete globalThis.__SECURE_CHAT_NATIVE_FLOOR__;

  // Browser residual, pinned so the fix cannot become "fail closed everywhere":
  // with no floor, store + witness deleted is a first run, and an existing
  // identity's fresh store is reported as `created` so app.js can warn.
  localStorage.clear(); fakeIdb.clear();
  const cB = await import("./contacts.js?native=none");
  await cB.unlock(PASS, { floorId: ID });
  await cB.savePin("user:erin", { ed: "EED==", mldsa: "EML==" });
  cB.lock();
  fakeIdb.removeItem("sc.contacts.v1");
  fakeIdb.removeItem("sc.contacts.gen.v1");
  assert.deepStrictEqual(await cB.unlock(PASS, { floorId: ID }), { created: true },
    "browser: both deleted opens as a fresh store (documented residual; app.js warns on `created`)");
}
console.log("OK  F-ATREST-003/004: on device the contact store fails closed; browser residual pinned");

// ---- Package 3 (ROUND-3 F-1 / F-4, A4 F-A1-R1, 7b): floor writes are CHECKED --
// The bridge below models PadFloor.kt as fixed: SharedPreferences updates its
// in-memory map before the file, a failed commit() is answered COMMIT_FAILED
// (-3) and latched for the process, and a value outside 0..2^31-1 is INVALID
// (-4). `disk` is what survives a restart. Before the fix every store threw
// the bump's answer away.
{
  localStorage.clear(); fakeIdb.clear();
  const disk = new Map();
  let failCommit = null; // (id, value) => true: that commit() returns false
  let full = false;      // fix round 2: the record cap answers FULL (-5) for new ids
  const kotlinModel = () => {
    const mem = new Map(disk);
    let latched = false;
    return {
      read: (id) => (mem.has(id) ? mem.get(id) : -1),
      bump: (id, v) => {
        if (v < 0 || v > 0x7fffffff) return -4;
        if (latched) return -3;
        const cur = mem.has(id) ? mem.get(id) : -1;
        if (full && cur === -1) return -5; // PadFloor.FULL (record cap)
        const next = cur === -1 ? v : (v > cur ? v : cur);
        if (next === cur) return cur;
        mem.set(id, next);
        if (failCommit && failCommit(id, next)) { latched = true; return -3; }
        disk.set(id, next);
        return next;
      },
    };
  };
  const ID = "c".repeat(64);

  // (1) A first save whose floor write does not commit. Before: the blob was
  // sealed CLAIMING a floor, the failure was discarded, the unlock "succeeded",
  // and after a restart the missing slot read as a deletion — refused with no
  // override. Now: the save fails, nothing is sealed, the restart is a clean
  // first run.
  failCommit = () => true;
  globalThis.__SECURE_CHAT_PAD_FLOOR__ = kotlinModel();
  const c1 = await import("./contacts.js?p3=arm-fail");
  await assert.rejects(c1.unlock(PASS, { floorId: ID }),
    (e) => e.code === "FLOOR_WRITE_FAILED" && /storage full or not writable/.test(e.message),
    "F-4: a floor write that did not commit fails the save, loudly");
  assert.ok(!c1.isUnlocked(), "…and leaves the store locked, not open over unsaved state");
  assert.strictEqual(fakeIdb.getItem("sc.contacts.v1"), null,
    "F-A1-R1: nothing claiming a floor is sealed before the floor slot provably exists");
  failCommit = null;
  globalThis.__SECURE_CHAT_PAD_FLOOR__ = kotlinModel(); // restart: only `disk` survives
  const c2 = await import("./contacts.js?p3=arm-restart");
  assert.deepStrictEqual(await c2.unlock(PASS, { floorId: ID }), { created: true },
    "F-A1-R1: after a restart it is an ordinary first run — no DELETED alarm, no brick");

  // (1b) The arm lands but the BLOB write fails (storage quota). The slot is
  // now at 0 with nothing stored: "armed, never saved", which must read as a
  // first run — not as "your saved contacts (generation 0) have been DELETED".
  {
    const IDQ = "9".repeat(64);
    localStorage.clear(); fakeIdb.clear();
    const realSet = localStorage.setItem;
    fakeIdb.failWrites((k) => k === "sc.contacts.v1"); // 3b: the store write is the IndexedDB transaction now
    const cq = await import("./contacts.js?p3=quota");
    try {
      await assert.rejects(cq.unlock(PASS, { floorId: IDQ }), /QuotaExceededError/);
    } finally {
      fakeIdb.failWrites(null);
    }
    assert.strictEqual(disk.get("contacts:" + IDQ), 0, "precondition: the slot was armed at 0 before the write");
    assert.deepStrictEqual(await cq.unlock(PASS, { floorId: IDQ }), { created: true },
      "F-A1-R1: an armed-but-never-saved floor (0) is a first run, not a DELETED alarm");
    // …and a genuinely pre-L-1 store next to such a floor gets the adoption
    // prompt (a choice), not the no-override "had one" refusal.
    cq.lock();
    await sealLegacyStore({ contacts: [], pins: {} }, 3);
    fakeIdb.removeItem("sc.contacts.gen.v1");
    disk.set("contacts:" + "8".repeat(64), 0);
    globalThis.__SECURE_CHAT_PAD_FLOOR__ = kotlinModel();
    const cl = await import("./contacts.js?p3=legacy-zero");
    await assert.rejects(cl.unlock(PASS, { floorId: "8".repeat(64) }), (e) => e.code === "LEGACY_CONTACTS_ADOPTION",
      "F-A1-R1: a floor of 0 does not prove a post-fix store existed");
    localStorage.clear(); fakeIdb.clear();
  }

  // (2) An established store whose advance does not commit: the save fails and
  // the store locks (its in-memory state is ahead of what is protected).
  await c2.savePin("user:fay", { ed: "FED==", mldsa: "FML==" });
  assert.strictEqual(disk.get("contacts:" + ID), 2, "precondition: the floor follows the generation");
  failCommit = () => true;
  await assert.rejects(c2.savePin("user:gus", { ed: "GED==", mldsa: "GML==" }),
    (e) => e.code === "FLOOR_WRITE_FAILED",
    "F-1/F-4: a save whose floor did not advance is reported as FAILED, not done");
  assert.ok(!c2.isUnlocked(), "…and the store is locked");
  failCommit = null;

  // (3) 7b: a floor parked at the int32 ceiling (a page-realm bump, or a store
  // that got there) and the user's Forget-then-start-over. The recreated store
  // continues from the floor, so its next generation is 2^31. Before: sealed at
  // 2^31, `bump(id, v | 0)` went NEGATIVE, the bridge ignored it, and the floor
  // froze while the store kept counting — every later rollback undetected, all
  // silently. Now: a loud refusal, and nothing is written.
  localStorage.clear(); fakeIdb.clear();
  const ID2 = "d".repeat(64);
  disk.set("contacts:" + ID2, 0x7fffffff);
  globalThis.__SECURE_CHAT_PAD_FLOOR__ = kotlinModel();
  const c3 = await import("./contacts.js?p3=ceiling");
  await assert.rejects(c3.unlock(PASS, { floorId: ID2 }), (e) => e.code === "DELETED_CONTACTS_ADOPTION");
  await assert.rejects(c3.unlock(PASS, { floorId: ID2, adoptDeleted: true }),
    (e) => e.code === "FLOOR_WRITE_FAILED" && /highest generation/.test(e.message),
    "7b: a store must refuse to advance past the floor's ceiling, loudly");
  assert.strictEqual(fakeIdb.getItem("sc.contacts.v1"), null, "7b: …before anything is written");
  assert.strictEqual(disk.get("contacts:" + ID2), 0x7fffffff);

  // (4) Fix round 2: the record cap (FULL, -5) fails the first save closed,
  // with its own reason, and nothing is sealed.
  localStorage.clear(); fakeIdb.clear();
  full = true;
  globalThis.__SECURE_CHAT_PAD_FLOOR__ = kotlinModel();
  const c4 = await import("./contacts.js?p3r2=full");
  await assert.rejects(c4.unlock(PASS, { floorId: "f".repeat(64) }),
    (e) => e.code === "FLOOR_WRITE_FAILED" && /store is full/.test(e.message),
    "fix round 2: a full floor store fails the contact store's save with the 'full' reason");
  assert.strictEqual(fakeIdb.getItem("sc.contacts.v1"), null, "…and nothing is written");
  assert.ok(!c4.isUnlocked());
  full = false;
  delete globalThis.__SECURE_CHAT_PAD_FLOOR__;
  localStorage.clear(); fakeIdb.clear();
}
console.log("OK  Package 3: contact-store floor writes are checked; first-save failure is not a brick; int32 ceiling is loud");

// ---- second fix round (re-review of 9a38d97, I-1): a planted, unparseable ----
// store is refused with a fixed sentence — never the SyntaxError, which
// echoes ~20 characters of the planted value (a newline, U+202E) into the
// locked panel and the transcript.
{
  const lsKey = "sc.contacts.v1";
  const saved = fakeIdb.getItem(lsKey);
  if (contacts.isUnlocked()) contacts.lock();
  fakeIdb.setItem(lsKey, "x\n[verified by you]\u202e\u2028");
  const err = await contacts.unlock(PASS).catch((e) => e);
  assert.ok(err instanceof Error, "a planted unparseable store is refused");
  assert.match(err.message, /on this device is not readable \(damaged or replaced\)$/, "...with a fixed sentence");
  assert.ok(!/[\n\u202e\u2028]|verified by you/.test(err.message), "...that carries none of the planted text");
  if (saved === null) fakeIdb.removeItem(lsKey); else fakeIdb.setItem(lsKey, saved);
  console.log("OK  I-1: an unparseable store is refused with a fixed sentence (no planted text echoed)");
}

console.log("\nAll contact-store checks passed.");
