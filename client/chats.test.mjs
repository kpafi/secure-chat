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

const mem = new Map();
globalThis.localStorage = {
  getItem: (k) => (mem.has(k) ? mem.get(k) : null),
  setItem: (k, v) => mem.set(k, String(v)),
  removeItem: (k) => mem.delete(k),
};

const chats = await import("./chats.js");
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
  const blob = JSON.parse(localStorage.getItem("sc.chats.v1"));
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
  localStorage.setItem("sc.chats.v1", JSON.stringify({ ...blob, iv: b64(iv), ct: b64(ct) }));
  // Pentest 2026-08-07 F-ATREST-005: the store now carries a generation and a
  // witness beside it. `poisoned` is the shape an app version PREDATING both
  // wrote, so a device holding it has no witness either — drop it, or this
  // fixture is indistinguishable from a rollback (which the store is now
  // required to refuse, and does; see chats-rollback.test.mjs).
  localStorage.removeItem("sc.chats.gen.v1");
}

chats.lock();
await chats.unlock(PASS);
const healed = chats.get("mallory");
assert.strictEqual(healed.mode, "SEALED", "poisoned mode is reset to SEALED on unlock");
assert.ok(!healed.secret && !healed.salt, "the phantom AES256 secret/salt are dropped");
assert.ok(!healed.pending, "the bogus pending proposal is dropped");
console.log("OK  a store poisoned before the fix heals on unlock");

console.log("\nAll chat-mode allow-list checks passed.");
