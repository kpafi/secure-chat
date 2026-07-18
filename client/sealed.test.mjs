// Offline tests for the sealed async envelope + bundle-v2 identity upgrade.
// Run: node sealed.test.mjs
import assert from "node:assert";
import { Identity } from "./identity.js";
import { seal, open } from "./sealed.js";

const alice = await Identity.generate();
const bob = await Identity.generate();
const eve = await Identity.generate();

// New identities carry encryption keys in the public bundle.
const bobPub = bob.publicBundle();
assert.ok(bobPub.ecdh && bobPub.mlkem, "bundle v2 has encryption keys");

// Round-trip: alice -> bob.
const env = await seal(alice, bobPub, "hello bob, sealed & signed");
const got = await open(bob, env);
assert.strictEqual(got.msg, "hello bob, sealed & signed");
assert.strictEqual(got.kind, "msg", "plain text defaults to kind=msg");
assert.deepStrictEqual(got.from, alice.publicBundle(), "sealed sender = alice");
assert.ok(got.ts > 0 && got.id.length > 0);
console.log("OK  seal -> open round-trip (sender + message intact)");

// Control message (mode negotiation) rides the same signed envelope.
const ctl = await seal(alice, bobPub, { kind: "mode-propose", mode: "AES256", salt: "c2FsdA==" });
const gotCtl = await open(bob, ctl);
assert.strictEqual(gotCtl.kind, "mode-propose");
assert.strictEqual(gotCtl.mode, "AES256");
assert.strictEqual(gotCtl.salt, "c2FsdA==");
console.log("OK  control message (mode-propose) sealed + authenticated");

// The envelope leaks neither plaintext nor sender identity.
assert.ok(!env.includes("hello bob") && !env.includes(alice.publicBundle().ed), "opaque envelope");
console.log("OK  envelope hides plaintext AND sender (sealed sender)");

// Wrong recipient cannot open (eve has different keys).
await assert.rejects(open(eve, env), /does not decrypt/);
console.log("OK  wrong recipient refused");

// Tampered ciphertext refused.
const t = JSON.parse(env);
const ctBytes = Buffer.from(t.ct, "base64");
ctBytes[3] ^= 0xff;
await assert.rejects(open(bob, JSON.stringify({ ...t, ct: ctBytes.toString("base64") })), /does not decrypt/);
console.log("OK  tampered envelope refused");

// Re-targeting: an envelope sealed for bob, re-sent to eve after re-sealing
// the same inner content with eve's keys, MUST fail eve's signature check —
// the dual signature covers the recipient identity key. Simulate by opening
// bob's envelope and checking a forged from-bundle fails too.
const env2 = await seal(alice, bobPub, "second message");
const inner = await open(bob, env2);
assert.notStrictEqual(inner.id, got.id, "fresh id per envelope");

// Forged sender: eve seals a message claiming... she can't — sign() uses her
// own keys, so `from` and the signature stay consistent. What MUST fail is a
// mismatched from-bundle: craft an envelope where the signature is eve's but
// the from-bundle claims alice. (Rebuild manually with eve signing.)
import { ml_kem768 } from "@noble/post-quantum/ml-kem.js";
{
  const encTx = new TextEncoder();
  const b64 = (u8) => Buffer.from(u8).toString("base64");
  const eph = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
  const ephPubRaw = new Uint8Array(await crypto.subtle.exportKey("raw", eph.publicKey));
  const rec = await crypto.subtle.importKey("raw", Buffer.from(bobPub.ecdh, "base64"), { name: "ECDH", namedCurve: "P-256" }, false, []);
  const ss1 = new Uint8Array(await crypto.subtle.deriveBits({ name: "ECDH", public: rec }, eph.privateKey, 256));
  const { cipherText, sharedSecret: ss2 } = ml_kem768.encapsulate(new Uint8Array(Buffer.from(bobPub.mlkem, "base64")));
  const core = JSON.stringify({ from: alice.publicBundle(), msg: "i am totally alice", ts: Date.now(), id: "x" });
  const sig = await eve.sign(encTx.encode(["secure-chat/sealed/v1", bobPub.ed, b64(ephPubRaw), b64(cipherText), core].join("\n")));
  const ikm = await crypto.subtle.importKey("raw", Buffer.concat([ss1, ss2]), "HKDF", false, ["deriveKey"]);
  const key = await crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: encTx.encode("secure-chat/sealed/v1"), info: Buffer.from(bobPub.ed, "base64") },
    ikm, { name: "AES-GCM", length: 256 }, false, ["encrypt"],
  );
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, encTx.encode(JSON.stringify({ core, sig }))));
  const forged = JSON.stringify({ v: 1, eph: b64(ephPubRaw), kem: b64(cipherText), iv: b64(iv), ct: b64(ct) });
  await assert.rejects(open(bob, forged), /signature invalid/);
  console.log("OK  impersonated sender (eve signing as alice) refused");
}

// Pre-v3 blob upgrade: strip the encryption keys, re-import, expect upgrade.
const pass = "test-pass";
const blobV3 = await alice.export(pass);
// Simulate an old blob by exporting an identity built without enc keys.
const legacy = new Identity({
  edPriv: alice._edPriv, edPubRaw: alice.edPubRaw,
  mldsaSecret: alice._mldsaSecret, mldsaPub: alice.mldsaPub,
});
const legacyBlob = await legacy.export(pass);
const reimported = await Identity.import(legacyBlob, pass);
assert.ok(reimported.upgraded, "legacy blob triggers upgrade");
assert.ok(reimported.publicBundle().ecdh, "upgraded identity has encryption keys");
const reimportedV3 = await Identity.import(blobV3, pass);
assert.ok(!reimportedV3.upgraded, "v3 blob imports without upgrade");
assert.strictEqual(reimportedV3.publicBundle().ecdh, alice.publicBundle().ecdh, "enc keys persist");
console.log("OK  legacy identity blob upgrades; v3 blob round-trips enc keys");

console.log("\nAll sealed-envelope checks passed.");
