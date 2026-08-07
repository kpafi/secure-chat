// Pentest 2026-08-07 F-CRYPTO-009: peer RSA public-key assurance.
//
// `Rsa.onPeerKey` used to perform exactly one check on the counterparty's
// transport key — the modulus bit length — and WebCrypto's SPKI import performs
// no public-key assurance beyond DER well-formedness. e = 0, 1, 2, 3 and even
// moduli all import and all report `modulusLength = 2048`, so all of them
// reached `crypto.subtle.encrypt` and got this session's 32-byte root secret
// wrapped to them. With e = 1 that "encryption" is the keyless, fully
// invertible OAEP/MGF1 encoding: anyone holding the handshake frame recovers
// the root, and the root is the sole HKDF IKM for BOTH direction chains.
//
// These tests pin SP 800-56B Rev.2 §6.4.2.2 partial validation. Note what is
// deliberately NOT asserted: a modulus of the form <small factor> x <large
// prime> with e = 65537 still passes, because partial validation cannot certify
// that a modulus is a product of two large primes. That residual is documented
// at `assertRsaPublicKeyUsable` in crypto.js and is a protocol decision
// (contributory root, or not using peer-chosen RSA transport), not a check.
//
// Run: node rsa-keyvalidation.test.mjs   (server not required)
import assert from "node:assert";
import { makeCipher } from "./crypto.js";

const ROOM = "a".repeat(64);
const packMsg = (o) => Buffer.from(JSON.stringify(o)).toString("base64");
const toB64Url = (n) => {
  let hex = n.toString(16);
  if (hex.length % 2) hex = "0" + hex;
  return Buffer.from(hex, "hex").toString("base64url");
};

// WebCrypto does no assurance on import, so a JWK round-trip is enough to mint
// an SPKI for any (n, e) we like — which is precisely the finding.
async function spkiFor(n, e) {
  const k = await crypto.subtle.importKey(
    "jwk",
    { kty: "RSA", n, e, alg: "RSA-OAEP-256", ext: true, key_ops: ["encrypt"] },
    { name: "RSA-OAEP", hash: "SHA-256" }, true, ["encrypt"],
  );
  return Buffer.from(await crypto.subtle.exportKey("spki", k)).toString("base64");
}

async function honestPublicJwk() {
  const kp = await crypto.subtle.generateKey(
    { name: "RSA-OAEP", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
    true, ["encrypt", "decrypt"],
  );
  return crypto.subtle.exportKey("jwk", kp.publicKey);
}

async function refuses(label, spki) {
  const c = await makeCipher("RSA", ROOM);
  await c.init();
  await assert.rejects(
    () => c.onPeerKey(packMsg({ pub: spki })),
    (e) => e instanceof Error,
    `${label} was ACCEPTED — the root secret would be wrapped to it`,
  );
  console.log(`OK  ${label} refused`);
}

const honest = await honestPublicJwk();

async function testDegenerateExponents() {
  // Every exponent that makes OAEP invertible or near-invertible.
  for (const [label, e] of [["e=0", "AA"], ["e=1", "AQ"], ["e=2", "Ag"], ["e=3", "Aw"]]) {
    await refuses(`peer key with ${label}`, await spkiFor(honest.n, e));
  }
}

async function testStructurallyBadModuli() {
  const n = BigInt("0x" + Buffer.from(honest.n, "base64url").toString("hex"));
  await refuses("even modulus", await spkiFor(toB64Url(n + 1n), "AQAB"));

  // n = 3 * odd 2046-bit q: odd, 2048 bits, trivially factorable.
  const q = (1n << 2046n) | 1n;
  await refuses("modulus with a small prime factor", await spkiFor(toB64Url(3n * q), "AQAB"));
}

async function testPerfectPower() {
  // p must be free of small factors, or trial division catches n first and this
  // never reaches the perfect-power branch. Sized so p*p is exactly 2048 bits,
  // so it clears the size gate too.
  const composite = new Uint8Array(1 << 16);
  const primes = [];
  for (let i = 2; i < (1 << 16); i++) {
    if (composite[i]) continue;
    primes.push(BigInt(i));
    for (let j = i * i; j < (1 << 16); j += i) composite[j] = 1;
  }
  let p = (3n << 1022n) | 1n;
  while (primes.some((r) => p % r === 0n)) p += 2n;
  const n = p * p;
  assert.strictEqual(n.toString(2).length, 2048, "test fixture must clear the size gate");
  await refuses("perfect-power modulus (p^2)", await spkiFor(toB64Url(n), "AQAB"));
}

async function testHonestKeyStillWorks() {
  // The controls that matter: validation must not break the honest mode.
  const a = await makeCipher("RSA", ROOM);
  const b = await makeCipher("RSA", ROOM);
  await a.init();
  await b.init();
  await b.onPeerKey(await a.handshakePayload());
  await a.onPeerKey(await b.handshakePayload());
  assert.ok(a.ready && b.ready, "honest RSA handshake did not complete");
  const msg = "the launch code is 0451";
  assert.strictEqual(await b.decrypt(await a.encrypt(msg)), msg);
  assert.strictEqual(await a.decrypt(await b.encrypt(msg)), msg);
  console.log("OK  honest RSA handshake still completes and round-trips both directions");
}

await testDegenerateExponents();
await testStructurallyBadModuli();
await testPerfectPower();
await testHonestKeyStillWorks();
console.log("\nAll RSA peer-key validation checks passed.");
