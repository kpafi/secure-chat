// Offline tests for the chat store's mode allow-list (pentest 2026-07-25 F-02).
// Run: node chats.test.mjs
//
// The chat mode arrives inside a peer's control message. It is authenticated
// (the sealed envelope proves they signed it) but NOT trusted: an unrecognised
// string used to be stored verbatim and rendered into the padlocked mode
// indicator, while every behavioural check is an exact `=== "AES256"` compare.
// A chat could therefore display "🔒 AES256 + verified by secure-chat" while no
// inner layer was applied and no passphrase had ever been requested.
import assert from "node:assert";
import { fakeIdb } from "./fake-idb.test.mjs"; // package 3b: IndexedDB for node

const mem = new Map();
globalThis.localStorage = {
  getItem: (k) => (mem.has(k) ? mem.get(k) : null),
  setItem: (k, v) => mem.set(k, String(v)),
  removeItem: (k) => mem.delete(k),
};

const chats = await import("./chats.js");
await chats.ready; // 3b: the IndexedDB preload
const PASS = "correct horse battery staple";

await chats.unlock(PASS);

// --- the allow-list itself --------------------------------------------------
assert.deepStrictEqual([...chats.MODES], ["SEALED", "AES256"]);
assert.ok(chats.isValidMode("SEALED") && chats.isValidMode("AES256"));
for (const bad of [
  "AES256 + verified by secure-chat ✅", // the PoC payload
  "aes256", "SEALED ", " SEALED", "PLAINTEXT", "", null, undefined, 0, {}, ["AES256"],
]) {
  assert.ok(!chats.isValidMode(bad), `must reject mode ${JSON.stringify(bad)}`);
}
console.log("OK  allow-list accepts exactly SEALED + AES256");

// --- setMode / setPending / ensure refuse anything off the list -------------
await chats.ensure("mallory");
await assert.rejects(
  () => chats.setMode("mallory", "AES256 + verified by secure-chat"),
  /unsupported chat mode/,
  "setMode must refuse an unknown mode",
);
await assert.rejects(
  () => chats.setPending("mallory", { mode: "AES256 evil", dir: "in" }),
  /unsupported chat mode/,
  "setPending must refuse an unknown proposed mode",
);
await assert.rejects(
  () => chats.ensure("eve", "NOPE"),
  /unsupported chat mode/,
  "ensure must refuse an unknown mode",
);
// The refused writes left the chat untouched.
assert.strictEqual(chats.get("mallory").mode, "SEALED");
assert.ok(!chats.get("mallory").pending, "no pending proposal was stored");
console.log("OK  setMode/setPending/ensure refuse an off-list mode");

// The legitimate transitions still work.
await chats.setMode("mallory", "AES256", { secret: "s3cret", salt: chats.newInnerSalt() });
assert.strictEqual(chats.get("mallory").mode, "AES256");
assert.ok(chats.get("mallory").secret, "AES256 keeps its secret");
await chats.setMode("mallory", "SEALED");
assert.strictEqual(chats.get("mallory").mode, "SEALED");
assert.ok(!chats.get("mallory").secret, "leaving AES256 drops the secret");
console.log("OK  SEALED <-> AES256 transitions still work");

// --- an ALREADY-poisoned store heals on unlock ------------------------------
// Simulate a store written before the fix: forge the encrypted blob by
// unlocking, mutating through the module, and re-persisting is not possible
// (setMode now refuses), so write the plaintext shape directly via a fresh
// store built from a hand-made blob.
const poisoned = {
  mallory: {
    username: "mallory",
    mode: "AES256 + verified by secure-chat ✅",
    secret: "never-really-used",
    salt: "AAAA",
    pending: { mode: "TOTALLY BOGUS", dir: "in" },
    messages: [],
    updatedAt: Date.now(),
  },
};
// Re-encrypt that object under the same passphrase/salt the store uses.
{
  const enc = new TextEncoder();
  const blob = JSON.parse(fakeIdb.getItem("sc.chats.v1"));
  const unb64 = (s) => {
    const bin = atob(s);
    const u = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i);
    return u;
  };
  const b64 = (u8) => {
    let bin = "";
    for (let i = 0; i < u8.length; i++) bin += String.fromCharCode(u8[i]);
    return btoa(bin);
  };
  const base = await crypto.subtle.importKey("raw", enc.encode(PASS), "PBKDF2", false, ["deriveKey"]);
  const key = await crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: unb64(blob.salt), iterations: blob.iters, hash: "SHA-256" },
    base, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"],
  );
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt(
    { name: "AES-GCM", iv }, key, enc.encode(JSON.stringify(poisoned)),
  ));
  fakeIdb.setItem("sc.chats.v1", JSON.stringify({ ...blob, iv: b64(iv), ct: b64(ct) }));
}

chats.lock();
// (F-ATREST-005: the hand-made blob is the untagged pre-v2 shape with no
// witness, on a device that has run this code — an explicit adoption now.)
fakeIdb.removeItem("sc.chats.gen.v1");
await assert.rejects(chats.unlock(PASS), (e) => e.code === "LEGACY_CHATS_ADOPTION");
await chats.unlock(PASS, { adoptLegacy: true });
const healed = chats.get("mallory");
assert.strictEqual(healed.mode, "SEALED", "poisoned mode is reset to SEALED on unlock");
assert.ok(!healed.secret && !healed.salt, "the phantom AES256 secret/salt are dropped");
assert.ok(!healed.pending, "the bogus pending proposal is dropped");
console.log("OK  a store poisoned before the fix heals on unlock");

// ---- Pentest 2026-08-07 F-ATREST-005: the chat store fails closed at rest -----
// One removeItem used to empty the envelope-replay ring and every negotiated
// mode; an older blob rewound the ring. Same mechanism as the contact store.
{
  mem.clear(); fakeIdb.clear();
  await chats.unlock(PASS);
  await chats.ensure("bob");
  assert.strictEqual(await chats.markSeen("bob", "env-1"), true);
  assert.strictEqual(await chats.markSeen("bob", "env-1"), false, "the ring works");
  // The plaintext is tagged and versioned inside the AEAD.
  {
    const enc = new TextEncoder(), dec = new TextDecoder();
    const blob = JSON.parse(fakeIdb.getItem("sc.chats.v1"));
    const unb64 = (x) => Uint8Array.from(Buffer.from(x, "base64"));
    const base = await crypto.subtle.importKey("raw", enc.encode(PASS), "PBKDF2", false, ["deriveKey"]);
    const key = await crypto.subtle.deriveKey(
      { name: "PBKDF2", salt: unb64(blob.salt), iterations: blob.iters, hash: "SHA-256" },
      base, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"],
    );
    const inner = JSON.parse(dec.decode(await crypto.subtle.decrypt({ name: "AES-GCM", iv: unb64(blob.iv) }, key, unb64(blob.ct))));
    assert.strictEqual(inner.d, "secure-chat/chats-store/v2", "domain-tagged inside the AEAD");
    assert.ok(Number.isInteger(inner.gen) && inner.gen >= 1, "carries a generation");
    assert.ok(fakeIdb.getItem("sc.chats.gen.v1"), "and a witness beside it");
  }
  chats.lock();

  // Deletion: the store is gone, the witness says one existed.
  const storeSnap = fakeIdb.getItem("sc.chats.v1");
  const witSnap = fakeIdb.getItem("sc.chats.gen.v1");
  fakeIdb.removeItem("sc.chats.v1");
  await assert.rejects(chats.unlock(PASS), (e) => e.code === "DELETED_CHATS_ADOPTION" && /DELETED/.test(e.message),
    "F-ATREST-005: a deleted chat store is refused, not silently recreated");
  assert.ok(!chats.isUnlocked());
  fakeIdb.setItem("sc.chats.v1", storeSnap);

  // Witness gone, store present: tampering (a tagged store always has one).
  fakeIdb.removeItem("sc.chats.gen.v1");
  await assert.rejects(chats.unlock(PASS), /generation record .* is missing/);
  fakeIdb.setItem("sc.chats.gen.v1", witSnap);

  // Rollback: mark another envelope seen, then restore the older blob.
  await chats.unlock(PASS);
  assert.strictEqual(await chats.markSeen("bob", "env-2"), true);
  chats.lock();
  fakeIdb.setItem("sc.chats.v1", storeSnap);
  await assert.rejects(chats.unlock(PASS), /OLDER than this device recorded/,
    "an older chat store is refused — env-2 would otherwise be accepted again");
  // The whole point, stated as the consequence: post-fix, no unlock path exists
  // in which markSeen("bob", "env-2") returns true a second time.

  // Both restored (the coordinated snapshot): opens in a browser, documented
  // residual — the floor below is what removes it on device.
  fakeIdb.setItem("sc.chats.gen.v1", witSnap);
  await chats.unlock(PASS);
  assert.strictEqual(await chats.markSeen("bob", "env-2"), true, "browser residual: both-restored rewinds the ring");
  chats.lock();

  // A stale second tab: writes must never leave the store BEHIND the witness.
  const tabB = await import("./chats.js?tab=b");
  await chats.unlock(PASS);
  await tabB.unlock(PASS);
  await chats.ensure("carol");   // tab A writes N+1
  await tabB.ensure("dave");     // tab B still holds N in memory, writes anyway
  chats.lock(); tabB.lock();
  await chats.unlock(PASS);      // must not read as a rollback (the M-C shape)
  assert.ok(chats.get("dave"), "the later write wins (accepted lost update, not a lockout)");
  chats.lock();

  // wipe() clears both, so a deliberate reset is a clean first run.
  chats.wipe();
  assert.ok(!chats.hasStore());
  assert.deepStrictEqual(await chats.unlock(PASS), { created: true });
  chats.lock();

  // A genuine pre-v2 blob (every deployed chat store is this shape) with NO
  // epoch marker — the state an attacker can produce with one removeItem, and
  // the state of a device that just upgraded. Both get the prompt: the fix
  // review showed that adopting silently here reopened the whole finding.
  mem.clear(); fakeIdb.clear();
  {
    const enc = new TextEncoder();
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const base = await crypto.subtle.importKey("raw", enc.encode(PASS), "PBKDF2", false, ["deriveKey"]);
    const key = await crypto.subtle.deriveKey(
      { name: "PBKDF2", salt, iterations: 600000, hash: "SHA-256" },
      base, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"],
    );
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const legacy = { erin: { username: "erin", mode: "SEALED", messages: [], seenIds: ["old-1"], updatedAt: 1 } };
    const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, enc.encode(JSON.stringify(legacy))));
    const b64 = (u) => Buffer.from(u).toString("base64");
    fakeIdb.setItem("sc.chats.v1", JSON.stringify({ v: 1, iters: 600000, salt: b64(salt), iv: b64(iv), ct: b64(ct) }));
  }
  await assert.rejects(chats.unlock(PASS),
    (e) => e.code === "LEGACY_CHATS_ADOPTION" && e.suspicious === false,
    "an untagged blob with no epoch marker must still prompt (deletable markers never authorise)");
  assert.deepStrictEqual(await chats.unlock(PASS, { adoptLegacy: true }), { created: false },
    "the upgrade adopts the pre-v2 blob on request");
  assert.strictEqual(await chats.markSeen("erin", "old-1"), false, "its ring survives");
  assert.ok(fakeIdb.getItem("sc.chats.gen.v1"), "and it is witnessed from now on");
  chats.lock();
}
console.log("OK  F-ATREST-005: chat store is tagged, versioned and witnessed; delete/rollback fail closed");

// ---- F-ATREST-005 on device: the native floor ------------------------------
{
  mem.clear(); fakeIdb.clear();
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
  const cN = await import("./chats.js?native=1");
  const ID = "c".repeat(64);
  await cN.unlock(PASS, { floorId: ID });
  await cN.ensure("bob");
  await cN.markSeen("bob", "env-1");
  const storeSnap = fakeIdb.getItem("sc.chats.v1");
  const witSnap = fakeIdb.getItem("sc.chats.gen.v1");
  await cN.markSeen("bob", "env-2");
  assert.ok(floors.get("chats:" + ID) >= 3, "every persist bumps the identity's chat floor");
  cN.lock();
  // The coordinated snapshot: refused on device.
  fakeIdb.setItem("sc.chats.v1", storeSnap);
  fakeIdb.setItem("sc.chats.gen.v1", witSnap);
  await assert.rejects(cN.unlock(PASS, { floorId: ID }), /OLDER than this device recorded/,
    "F-ATREST-005 on device: both-restored is caught by the floor");
  // Both deleted: refused (explicit adoption), then continues the numbering.
  fakeIdb.removeItem("sc.chats.v1");
  fakeIdb.removeItem("sc.chats.gen.v1");
  await assert.rejects(cN.unlock(PASS, { floorId: ID }), (e) => e.code === "DELETED_CHATS_ADOPTION");
  assert.deepStrictEqual(await cN.unlock(PASS, { floorId: ID, adoptDeleted: true }), { created: true });
  cN.lock();
  delete globalThis.__SECURE_CHAT_PAD_FLOOR__;
}
console.log("OK  F-ATREST-005 on device: the chat store has a native floor");

// ---- Package 3 (ROUND-3 F-1 / F-4, A4 F-A1-R1, 7b): chat floor writes checked --
// Same PadFloor.kt model as contacts.test.mjs: memory before file, a failed
// commit() answers -3 and latches, out-of-range is -4; `disk` survives restarts.
{
  mem.clear(); fakeIdb.clear();
  const disk = new Map();
  let failCommit = null;
  const kotlinModel = () => {
    const m = new Map(disk);
    let latched = false;
    return {
      read: (id) => (m.has(id) ? m.get(id) : -1),
      bump: (id, v) => {
        if (v < 0 || v > 0x7fffffff) return -4;
        if (latched) return -3;
        const cur = m.has(id) ? m.get(id) : -1;
        const next = cur === -1 ? v : (v > cur ? v : cur);
        if (next === cur) return cur;
        m.set(id, next);
        if (failCommit && failCommit(id, next)) { latched = true; return -3; }
        disk.set(id, next);
        return next;
      },
    };
  };
  const ID = "e".repeat(64);
  failCommit = () => true;
  globalThis.__SECURE_CHAT_PAD_FLOOR__ = kotlinModel();
  const c1 = await import("./chats.js?p3=arm-fail");
  await assert.rejects(c1.unlock(PASS, { floorId: ID }), (e) => e.code === "FLOOR_WRITE_FAILED",
    "F-4: a chat-store floor write that did not commit fails the save");
  assert.ok(!c1.isUnlocked());
  assert.strictEqual(fakeIdb.getItem("sc.chats.v1"), null,
    "F-A1-R1: no blob claims a floor whose slot never landed");
  failCommit = null;
  globalThis.__SECURE_CHAT_PAD_FLOOR__ = kotlinModel();
  const c2 = await import("./chats.js?p3=arm-restart");
  assert.deepStrictEqual(await c2.unlock(PASS, { floorId: ID }), { created: true },
    "F-A1-R1: the restart is a clean first run, not a DELETED alarm or a brick");
  // Armed at 0 but the blob write failed (quota): a first run, not DELETED.
  {
    const IDQ = "9".repeat(64);
    const realSet = localStorage.setItem;
    const saved = new Map(mem); const savedIdb = new Map(fakeIdb.mem);
    mem.clear(); fakeIdb.clear();
    fakeIdb.failWrites((k) => k === "sc.chats.v1"); // 3b: the store write is the IndexedDB transaction now
    const cq = await import("./chats.js?p3=quota");
    try {
      await assert.rejects(cq.unlock(PASS, { floorId: IDQ }), /QuotaExceededError/);
    } finally {
      fakeIdb.failWrites(null);
    }
    assert.strictEqual(disk.get("chats:" + IDQ), 0, "precondition: armed at 0");
    assert.deepStrictEqual(await cq.unlock(PASS, { floorId: IDQ }), { created: true },
      "F-A1-R1: an armed-but-never-saved chat floor (0) is a first run, not a DELETED alarm");
    cq.lock();
    mem.clear(); fakeIdb.clear();
    for (const [k, v] of saved) mem.set(k, v);
    for (const [k, v] of savedIdb) fakeIdb.mem.set(k, v);
  }
  await c2.ensure("bob");
  failCommit = () => true;
  await assert.rejects(c2.markSeen("bob", "env-p3"), (e) => e.code === "FLOOR_WRITE_FAILED",
    "F-1/F-4: a chat save whose floor did not advance is reported as failed");
  assert.ok(!c2.isUnlocked(), "…and the chat store locks");
  failCommit = null;
  // 7b: the ceiling is a loud refusal before anything is written.
  mem.clear(); fakeIdb.clear();
  const ID2 = "f".repeat(64);
  disk.set("chats:" + ID2, 0x7fffffff);
  globalThis.__SECURE_CHAT_PAD_FLOOR__ = kotlinModel();
  const c3 = await import("./chats.js?p3=ceiling");
  await assert.rejects(c3.unlock(PASS, { floorId: ID2, adoptDeleted: true }),
    (e) => e.code === "FLOOR_WRITE_FAILED" && /highest generation/.test(e.message),
    "7b: the chat store refuses to advance past the ceiling, loudly");
  assert.strictEqual(fakeIdb.getItem("sc.chats.v1"), null);
  delete globalThis.__SECURE_CHAT_PAD_FLOOR__;
  mem.clear(); fakeIdb.clear();
}
console.log("OK  Package 3: chat-store floor writes are checked; first-save failure is not a brick; int32 ceiling is loud");

// ---- second fix round (re-review of 9a38d97, I-1): a planted, unparseable ----
// store is refused with a fixed sentence — never the SyntaxError, which
// echoes ~20 characters of the planted value (a newline, U+202E) into the
// locked panel and the transcript.
{
  const lsKey = "sc.chats.v1";
  const saved = fakeIdb.getItem(lsKey);
  if (chats.isUnlocked()) chats.lock();
  fakeIdb.setItem(lsKey, "x\n[verified by you]\u202e\u2028");
  const err = await chats.unlock(PASS).catch((e) => e);
  assert.ok(err instanceof Error, "a planted unparseable store is refused");
  assert.match(err.message, /on this device is not readable \(damaged or replaced\)$/, "...with a fixed sentence");
  assert.ok(!/[\n\u202e\u2028]|verified by you/.test(err.message), "...that carries none of the planted text");
  if (saved === null) fakeIdb.removeItem(lsKey); else fakeIdb.setItem(lsKey, saved);
  console.log("OK  I-1: an unparseable store is refused with a fixed sentence (no planted text echoed)");
}

console.log("\nAll chat-mode allow-list checks passed.");
