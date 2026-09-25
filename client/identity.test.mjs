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
import { Identity, b64, concat } from "./identity.js";
import { signHandshake, verifyHandshake, freshNonce, signKnock, verifyKnock } from "./auth.js";
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

  // Audit 2026-07-18 H-01 regression: the fingerprint must change when ANY of
  // the four public keys changes — including the encryption keys that seal
  // async messages, not just the signing identity.
  const base = a.publicBundle();
  const donor = b.publicBundle();
  for (const key of ["ed", "mldsa", "ecdh", "mlkem"]) {
    const swapped = { ...base, [key]: donor[key] };
    assert.notStrictEqual(
      await Identity.fingerprintOf(swapped), fpA1,
      `fingerprint changes when ${key} changes`,
    );
    assert.notStrictEqual(
      await Identity.safetyNumber(swapped, donor), sn1,
      `safety number changes when ${key} changes`,
    );
  }
  console.log("OK  fingerprint/safety number cover all four keys (H-01)");
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

  // Audit 2026-07-18 L-01: KDF parameters from the (external) backup file are
  // bounded BEFORE PBKDF2 runs — a crafted file must not stall the UI (huge
  // count), weaken the KDF (tiny count), or drive large allocations (size).
  const crafted = JSON.parse(blob);
  // (falsy `iters` falls back to the legacy 310k default — safe — so only
  // truthy out-of-bounds values are expected to hit the parameter check)
  for (const iters of [2_000_000_000, 1000, -1, 1.5, "600000"]) {
    await assert.rejects(
      Identity.import(JSON.stringify({ ...crafted, iters }), "strong device passphrase"),
      /key-derivation/,
      `iters=${iters} rejected before PBKDF2`,
    );
  }
  await assert.rejects(
    Identity.import("x".repeat(300 * 1024), "strong device passphrase"),
    /identity backup/,
    "oversized backup file rejected before parsing",
  );
  console.log("OK  L-01: crafted KDF parameters / oversized backup rejected");
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
  // The SIGNING identity must survive unchanged; the import also upgrades the
  // blob with fresh encryption keys (bundle v2), so compare only ed/mldsa.
  assert.strictEqual(back.publicBundle().ed, id.publicBundle().ed, "legacy v:1 blob imports via 310k fallback (ed)");
  assert.strictEqual(back.publicBundle().mldsa, id.publicBundle().mldsa, "legacy v:1 blob imports via 310k fallback (mldsa)");
  assert.ok(back.upgraded && back.publicBundle().ecdh, "legacy blob is upgraded with encryption keys");
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

  // Both peers contributed a fresh per-connection nonce (hello phase).
  const nonces = [freshNonce(), freshNonce()];

  // Alice creates her ephemeral ECDH key and signs it with her identity.
  const aliceEph = makeCipher("DHKE", ROOM);
  const aliceEphPub = await ephemeralPub(aliceEph);
  const aliceSig = await signHandshake(alice, ROOM, nonces, aliceEphPub);

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
  const forgedAccepted = await verifyHandshake(alicePinnedByBob, ROOM, nonces, malloryEphPub, aliceSig);
  assert.strictEqual(forgedAccepted, false, "swapped key with Alice's old sig -> REJECTED");

  //    b) Mallory signs her swapped key with her OWN identity (not Alice's):
  const mallorySig = await signHandshake(mallory, ROOM, nonces, malloryEphPub);
  const impostorAccepted = await verifyHandshake(alicePinnedByBob, ROOM, nonces, malloryEphPub, mallorySig);
  assert.strictEqual(impostorAccepted, false, "Mallory-signed key vs Alice's pin -> REJECTED");

  //    c) The genuine Alice key + signature is accepted:
  const genuineAccepted = await verifyHandshake(alicePinnedByBob, ROOM, nonces, aliceEphPub, aliceSig);
  assert.strictEqual(genuineAccepted, true, "genuine signed key -> ACCEPTED");

  //    d) The nonce fold is order-independent (both peers verify the same
  //       transcript regardless of who contributed which nonce):
  const swapped = await verifyHandshake(alicePinnedByBob, ROOM, [nonces[1], nonces[0]], aliceEphPub, aliceSig);
  assert.strictEqual(swapped, true, "nonce order must not matter");

  // And cross-room replay of a genuine signature is rejected (transcript binds room).
  const otherRoom = "b".repeat(64);
  const replay = await verifyHandshake(alicePinnedByBob, otherRoom, nonces, aliceEphPub, aliceSig);
  assert.strictEqual(replay, false, "cross-room replay -> REJECTED");

  void bobPinnedByAlice;
  console.log("OK  MITM relay DEFEATED by authenticated handshake (classical + PQ)");
}

async function testCrossSessionReplayDefeated() {
  // The 2026-07-02 pentest finding: a relay replays Alice's validly-signed
  // handshake from an OLD session into a NEW session that reuses the room id.
  // Under the v1 transcript (room only) the signature still verified and the
  // two honest peers silently desynced. Under v2 the transcript covers a
  // fresh nonce from EACH connection, so the stale signature must fail.
  const alice = await Identity.generate();
  const alicePinnedByBob = alice.publicBundle();

  // Session 1: genuine handshake, captured by the relay.
  const oldNonces = [freshNonce(), freshNonce()];
  const aliceEphPub = await ephemeralPub(makeCipher("DHKE", ROOM));
  const capturedSig = await signHandshake(alice, ROOM, oldNonces, aliceEphPub);
  assert.ok(await verifyHandshake(alicePinnedByBob, ROOM, oldNonces, aliceEphPub, capturedSig),
    "sanity: captured handshake verified in its own session");

  // Session 2: SAME room, but Bob generated a fresh nonce. The relay delivers
  // the captured (validly-signed!) old handshake — with any nonce story it can
  // tell: Alice's old nonce, or even both old nonces replayed via fake hellos.
  const bobFresh = freshNonce();
  const staleVsFresh = await verifyHandshake(
    alicePinnedByBob, ROOM, [oldNonces[0], bobFresh], aliceEphPub, capturedSig);
  assert.strictEqual(staleVsFresh, false,
    "old signed handshake vs Bob's fresh nonce -> REJECTED");

  // Even if the relay replays BOTH old hellos, Bob verifies against the nonce
  // HE generated this connection (never one fed to him), so the pair can never
  // be the old pair. Verify the exact old pair is the only accepting pair:
  const freshPair = await verifyHandshake(
    alicePinnedByBob, ROOM, [bobFresh, freshNonce()], aliceEphPub, capturedSig);
  assert.strictEqual(freshPair, false, "old handshake vs fully fresh nonces -> REJECTED");

  console.log("OK  cross-session handshake replay (reused room id) DEFEATED by session nonces");
}

// Phase-7 pentest 2026-09-16, F-P7-A1 #1. identity.js's headline claim — "Both
// signatures must verify for any check to pass" — had no test: the only
// dual-signature check above uses a signature from a DIFFERENT identity, which
// fails the classical half too. Deleting the whole ML-DSA half of
// Identity.verify left every test file green. This pins each half alone.
async function testDualSignatureIsMandatory() {
  const id = await Identity.generate();
  const other = await Identity.generate();
  const bundle = id.publicBundle();
  const msg = new TextEncoder().encode("both halves, or nothing");
  const good = await id.sign(msg);
  const alien = await other.sign(msg);
  assert.strictEqual(await Identity.verify(bundle, msg, good), true, "control: the genuine dual signature verifies");
  assert.strictEqual(await Identity.verify(bundle, msg, { ed: good.ed, mldsa: alien.mldsa }), false,
    "a valid Ed25519 signature with a wrong ML-DSA signature must be REFUSED — the post-quantum half is not decorative");
  assert.strictEqual(await Identity.verify(bundle, msg, { ed: alien.ed, mldsa: good.mldsa }), false,
    "a valid ML-DSA signature with a wrong Ed25519 signature must be REFUSED — the classical half is not decorative");
  assert.strictEqual(await Identity.verify(bundle, msg, { ed: good.ed }), false,
    "an ABSENT ML-DSA signature must be refused, not skipped");
  assert.strictEqual(await Identity.verify(bundle, msg, { ed: good.ed, mldsa: "AAAA" }), false,
    "a malformed ML-DSA signature must be refused, not skipped");
  console.log("OK  F-P7-A1: each signature half is independently load-bearing in Identity.verify");
}

// Phase-7 pentest 2026-09-16, F-P7-A1 #2. The 2026-07-26 P-03 fix binds the
// signer's whole bundle (through its 32-byte digest) into the handshake
// transcript, so a relay that swaps or strips the long-term ENCRYPTION keys in
// a `key` frame fails signature verification instead of relying on the user to
// spot a changed safety number. Dropping that digest from auth.js left every
// test green. The same signature must verify against the bundle as presented
// and fail against a swapped or stripped copy.
async function testTranscriptBindsTheSignersBundle() {
  const id = await Identity.generate();
  const other = await Identity.generate();
  const nonces = [freshNonce(), freshNonce()];
  const pub = await ephemeralPub(makeCipher("DHKE", ROOM));
  const sig = await signHandshake(id, ROOM, nonces, pub);
  const b = id.publicBundle();
  assert.strictEqual(await verifyHandshake(b, ROOM, nonces, pub, sig), true, "control: genuine bundle verifies");
  const swappedEcdh = { ...b, ecdh: other.publicBundle().ecdh };
  assert.strictEqual(await verifyHandshake(swappedEcdh, ROOM, nonces, pub, sig), false,
    "P-03: a relay-swapped idb.ecdh must fail the handshake signature");
  const swappedKem = { ...b, mlkem: other.publicBundle().mlkem };
  assert.strictEqual(await verifyHandshake(swappedKem, ROOM, nonces, pub, sig), false,
    "P-03: a relay-swapped idb.mlkem must fail the handshake signature");
  const stripped = { ed: b.ed, mldsa: b.mldsa };
  assert.strictEqual(await verifyHandshake(stripped, ROOM, nonces, pub, sig), false,
    "P-03: stripping the encryption keys from the presented bundle must fail the handshake signature");
  console.log("OK  F-P7-A1: the handshake transcript binds the signer's full bundle (P-03)");
}

// Phase-7 pentest 2026-09-16, F-P7-A1 (also green on its own): the knock
// signature lives in its own domain, so a knock can never be read as a
// handshake signature or the reverse. Making KNOCK_DOMAIN equal the handshake
// domain was green. Pinned by behaviour: a knock-shaped transcript signed under
// the HANDSHAKE domain is refused by verifyKnock, and the same shape under
// "secure-chat/knock/v1" is accepted (the positive control proves the shape is
// the real one, so the refusal is about the domain and nothing else).
async function testKnockDomainIsItsOwn() {
  const id = await Identity.generate();
  const b = id.publicBundle();
  const knockShaped = async (domain) => id.sign(concat(
    new TextEncoder().encode(domain), new TextEncoder().encode(ROOM), await Identity.bundleDigest(b),
  ));
  assert.strictEqual(await verifyKnock(b, ROOM, await knockShaped("secure-chat/knock/v1")), true,
    "control: the knock transcript is DOMAIN || room || bundleDigest");
  assert.strictEqual(await verifyKnock(b, ROOM, await knockShaped("secure-chat/handshake/v3")), false,
    "a knock signed under the HANDSHAKE domain must not verify as a knock — the two transcripts live in disjoint spaces");
  assert.strictEqual(await verifyKnock(b, ROOM, await signKnock(id, ROOM)), true, "control: signKnock/verifyKnock agree");
  console.log("OK  F-P7-A1: the knock signature has its own domain");
}

// Phase-7 pentest 2026-09-16, F-P7-A1 (P-17, green on its own): import proves
// the stored PUBLIC keys belong to the stored PRIVATE keys. Deleting the
// `_assertKeypairsConsistent()` call from import() was green. A backup that
// pairs this identity's private keys with ANOTHER identity's public ML-DSA /
// ECDH / ML-KEM key must be refused at import, not loaded to show contacts a
// safety number for keys it cannot use.
async function testImportRefusesMismatchedKeypairs() {
  const a = await Identity.generate();
  const other = await Identity.generate();
  const fields = {
    edPriv: a._edPriv, edPubRaw: a.edPubRaw, mldsaSecret: a._mldsaSecret, mldsaPub: a.mldsaPub,
    ecdhPriv: a._ecdhPriv, ecdhPubRaw: a.ecdhPubRaw, mlkemSecret: a._mlkemSecret, mlkemPub: a.mlkemPub,
  };
  const pass = "franken";
  const ok = await Identity.import(await new Identity(fields).export(pass), pass);
  assert.strictEqual(ok.publicBundle().ed, a.publicBundle().ed, "control: an untampered backup imports");
  for (const [k, v] of [["mldsaPub", other.mldsaPub], ["ecdhPubRaw", other.ecdhPubRaw], ["mlkemPub", other.mlkemPub]]) {
    const blob = await new Identity({ ...fields, [k]: v }).export(pass);
    await assert.rejects(() => Identity.import(blob, pass), /inconsistent|malformed|do not match|does not match/,
      `P-17: a backup whose ${k} belongs to another identity must be refused at import`);
  }
  console.log("OK  F-P7-A1: import refuses a backup whose public keys do not match its private keys (P-17)");
}

await testIdentityBasics();
await testDualSignatureIsMandatory();
await testTranscriptBindsTheSignersBundle();
await testKnockDomainIsItsOwn();
await testImportRefusesMismatchedKeypairs();
await testFingerprints();
await testExportImport();
await testLegacyBlobImport();
await testMitmDefeated();
await testCrossSessionReplayDefeated();
console.log("\nAll identity / authenticated-handshake checks passed.");
