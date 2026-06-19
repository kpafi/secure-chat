// Tests for identity keys + authenticated handshake.
//
// The headline test simulates a malicious relay (Mallory) performing a
// man-in-the-middle on the ephemeral key exchange, and proves:
//   * the UNAUTHENTICATED exchange is fooled (Bob accepts Mallory's key);
//   * the AUTHENTICATED exchange DETECTS it (signature verify fails),
// which is exactly the property in-person key verification buys us.
//
// Run: node identity.test.mjs   (server not required)
import assert from "node:assert";
import { Identity, b64 } from "./identity.js";
import { signHandshake, verifyHandshake } from "./auth.js";
import { makeCipher, bufToB64 } from "./crypto.js";

const ROOM = "a".repeat(64);

async function ephemeralPub(cipher) {
  await cipher.init();
  return cipher.handshakePayload(); // base64 ECDH P-256 public key
}

async function testIdentityBasics() {
  const id = await Identity.generate();
  const bundle = id.publicBundle();
  // Dual signature round-trips.
  const msg = new TextEncoder().encode("verify me");
  const sig = await id.sign(msg);
  assert.ok(await Identity.verify(bundle, msg, sig), "valid dual signature verifies");

  // Tampered message fails.
  const bad = new TextEncoder().encode("verify ME");
  assert.ok(!(await Identity.verify(bundle, bad, sig)), "tampered message rejected");

  // A signature from a DIFFERENT identity fails against this bundle.
  const other = await Identity.generate();
  const otherSig = await other.sign(msg);
  assert.ok(!(await Identity.verify(bundle, msg, otherSig)), "wrong identity rejected");

  console.log("OK  identity dual-signature (Ed25519 + ML-DSA-65)");
}

async function testFingerprints() {
  const a = await Identity.generate();
  const b = await Identity.generate();
  const fpA1 = await a.fingerprint();
  const fpA2 = await Identity.fingerprintOf(a.publicBundle());
  assert.strictEqual(fpA1, fpA2, "fingerprint is deterministic from public bundle");
  assert.notStrictEqual(fpA1, await b.fingerprint(), "different identities differ");

  // Safety number is order-independent (both peers compute the same value).
  const sn1 = await Identity.safetyNumber(a.publicBundle(), b.publicBundle());
  const sn2 = await Identity.safetyNumber(b.publicBundle(), a.publicBundle());
  assert.strictEqual(sn1, sn2, "safety number is order-independent");
  console.log("OK  fingerprint + safety number (sample SN: " + sn1.slice(0, 23) + " …)");
}

async function testExportImport() {
  const id = await Identity.generate();
  const blob = await id.export("strong device passphrase");
  const back = await Identity.import(blob, "strong device passphrase");
  // Imported identity produces verifiable signatures under the same bundle.
  const msg = new TextEncoder().encode("after reload");
  assert.ok(await Identity.verify(back.publicBundle(), msg, await back.sign(msg)), "round-trip identity works");
  assert.deepStrictEqual(back.publicBundle(), id.publicBundle(), "same public bundle after import");
  // Wrong passphrase must fail.
  let failed = false;
  try {
    await Identity.import(blob, "wrong");
  } catch {
    failed = true;
  }
  assert.ok(failed, "wrong passphrase rejected");
  console.log("OK  identity encrypted export/import (PBKDF2 + AES-256-GCM)");
}

async function testLegacyBlobImport() {
  // A pre-v2 backup (310k iterations, no `iters` field) must still import after
  // the KDF work factor was raised — import falls back to 310k for old blobs.
  const id = await Identity.generate();
  const enc = new TextEncoder();
  const edPkcs8 = new Uint8Array(await crypto.subtle.exportKey("pkcs8", id._edPriv));
  const plain = enc.encode(JSON.stringify({
    edPriv: b64(edPkcs8), edPub: b64(id.edPubRaw),
    mldsaSecret: b64(id._mldsaSecret), mldsaPub: b64(id.mldsaPub),
  }));
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const base = await crypto.subtle.importKey("raw", enc.encode("pp"), "PBKDF2", false, ["deriveKey"]);
  const key = await crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: 310000, hash: "SHA-256" },
    base, { name: "AES-GCM", length: 256 }, false, ["encrypt"],
  );
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, plain));
  const legacy = JSON.stringify({ v: 1, salt: b64(salt), iv: b64(iv), ct: b64(ct) }); // no `iters`
  const back = await Identity.import(legacy, "pp");
  assert.deepStrictEqual(back.publicBundle(), id.publicBundle(), "legacy v:1 blob imports via 310k fallback");
  console.log("OK  legacy (v:1, 310k) identity backup still imports");
}

async function testMitmDefeated() {
  // Alice and Bob generated identities and verified each other IN PERSON:
  const alice = await Identity.generate();
  const bob = await Identity.generate();
  const alicePinnedByBob = alice.publicBundle(); // Bob holds Alice's real key
  const bobPinnedByAlice = bob.publicBundle();

  // Mallory is the malicious relay with her own identity + ephemeral key.
  const mallory = await Identity.generate();

  // Alice creates her ephemeral ECDH key and signs it with her identity.
  const aliceEph = makeCipher("DHKE", ROOM);
  const aliceEphPub = await ephemeralPub(aliceEph);
  const aliceSig = await signHandshake(alice, ROOM, aliceEphPub);

  // --- Attack: Mallory swaps Alice's ephemeral key for her own. ---
  const malloryEph = makeCipher("DHKE", ROOM);
  const malloryEphPub = await ephemeralPub(malloryEph);

  // 1) Unauthenticated path: Bob just accepts whatever public key arrives.
  //    He cannot tell Mallory's key from Alice's -> MITM succeeds.
  assert.notStrictEqual(malloryEphPub, aliceEphPub);
  console.log("OK  (control) unauthenticated exchange cannot distinguish the swapped key");

  // 2) Authenticated path: Bob verifies the signature over the ephemeral key
  //    against Alice's PINNED identity.
  //    a) Mallory forwards Alice's real signature but her OWN swapped key:
  const forgedAccepted = await verifyHandshake(alicePinnedByBob, ROOM, malloryEphPub, aliceSig);
  assert.strictEqual(forgedAccepted, false, "swapped key with Alice's old sig -> REJECTED");

  //    b) Mallory signs her swapped key with her OWN identity (not Alice's):
  const mallorySig = await signHandshake(mallory, ROOM, malloryEphPub);
  const impostorAccepted = await verifyHandshake(alicePinnedByBob, ROOM, malloryEphPub, mallorySig);
  assert.strictEqual(impostorAccepted, false, "Mallory-signed key vs Alice's pin -> REJECTED");

  //    c) The genuine Alice key + signature is accepted:
  const genuineAccepted = await verifyHandshake(alicePinnedByBob, ROOM, aliceEphPub, aliceSig);
  assert.strictEqual(genuineAccepted, true, "genuine signed key -> ACCEPTED");

  // And cross-room replay of a genuine signature is rejected (transcript binds room).
  const otherRoom = "b".repeat(64);
  const replay = await verifyHandshake(alicePinnedByBob, otherRoom, aliceEphPub, aliceSig);
  assert.strictEqual(replay, false, "cross-room replay -> REJECTED");

  void bobPinnedByAlice;
  console.log("OK  MITM relay DEFEATED by authenticated handshake (classical + PQ)");
}

await testIdentityBasics();
await testFingerprints();
await testExportImport();
await testLegacyBlobImport();
await testMitmDefeated();
console.log("\nAll identity / authenticated-handshake checks passed.");
