// Crypto correctness check, runnable in Node (uses the same Web Crypto API as
// the browser). Simulates two peers (A and B) for each algorithm and asserts a
// full round-trip. Run: node client/crypto.test.mjs
import assert from "node:assert";
import { makeCipher, isAscii } from "./crypto.js";

const ROOM = "a".repeat(64);
const MSG = "Hello over the relay! ~ ASCII only 123 #@$";

async function roundtripShared() {
  // AES-256 passphrase: no handshake; both derive the same key.
  const a = makeCipher("AES256", ROOM, { passphrase: "correct horse battery staple" });
  const b = makeCipher("AES256", ROOM, { passphrase: "correct horse battery staple" });
  await a.init();
  await b.init();
  assert.ok(a.ready && b.ready, "AES256 ready");
  const wire = await a.encrypt(MSG);
  assert.strictEqual(await b.decrypt(wire), MSG, "AES256 A->B");
  assert.strictEqual(await a.decrypt(await b.encrypt(MSG)), MSG, "AES256 B->A");
  console.log("OK  AES256 (passphrase) round-trip");
}

async function roundtripHandshake(alg) {
  const a = makeCipher(alg, ROOM);
  const b = makeCipher(alg, ROOM);
  await a.init();
  await b.init();
  assert.ok(a.needsHandshake, `${alg} needs handshake`);
  // Two rounds through the (simulated) relay. For DHKE the second payload is
  // the same idempotent public key; for RSA/PQKEM round 1 is the offer and
  // round 2 the answer (wrapped MAC secret / KEM encapsulation). Exchanging
  // both offers + both answers mirrors the relay's join-order race (both
  // peers' offers delivered), which RSA and PQKEM must converge on.
  const aOffer = await a.handshakePayload();
  const bOffer = await b.handshakePayload();
  await a.onPeerKey(bOffer);
  await b.onPeerKey(aOffer);
  const aAns = await a.handshakePayload();
  const bAns = await b.handshakePayload();
  await a.onPeerKey(bAns);
  await b.onPeerKey(aAns);
  assert.ok(a.ready && b.ready, `${alg} ready after handshake`);
  assert.strictEqual(await b.decrypt(await a.encrypt(MSG)), MSG, `${alg} A->B`);
  assert.strictEqual(await a.decrypt(await b.encrypt(MSG)), MSG, `${alg} B->A`);
  console.log(`OK  ${alg} handshake + round-trip`);
}

async function negativeChecks() {
  // Wrong passphrase must fail to decrypt (GCM auth tag rejects it).
  const a = makeCipher("AES256", ROOM, { passphrase: "right" });
  const b = makeCipher("AES256", ROOM, { passphrase: "wrong" });
  await a.init();
  await b.init();
  let failed = false;
  try {
    await b.decrypt(await a.encrypt(MSG));
  } catch {
    failed = true;
  }
  assert.ok(failed, "wrong passphrase must not decrypt");
  console.log("OK  wrong passphrase rejected (authenticated encryption)");

  assert.ok(isAscii(MSG) && !isAscii("café"), "ascii check");
  console.log("OK  ascii guard");
}

// RSA-specific attacks the per-message HMAC must defeat. Mallory plays the
// relay: she sees every handshake payload (so she learns both public keys)
// but never the OAEP-wrapped MAC secret.
async function rsaAttackChecks() {
  const a = makeCipher("RSA", ROOM);
  const b = makeCipher("RSA", ROOM);
  await a.init();
  await b.init();
  // Staggered handshake: B offers, A answers (the realistic single-secret path).
  const bOffer = await b.handshakePayload();
  await a.onPeerKey(bOffer);
  await b.onPeerKey(await a.handshakePayload());
  assert.ok(a.ready && b.ready, "RSA ready");

  const rejects = async (p, what) => {
    let failed = false;
    try {
      await p();
    } catch {
      failed = true;
    }
    assert.ok(failed, what);
  };

  // FORGERY: Mallory saw B's offer go past, so she holds B's public key and can
  // build ciphertext that OAEP-decrypts cleanly — exactly the old attack. She
  // completes her own handshake against B's offer and injects a message.
  const mallory = makeCipher("RSA", ROOM);
  await mallory.init();
  await mallory.onPeerKey(bOffer);
  assert.ok(mallory.ready, "mallory can always build a well-formed frame");
  await rejects(async () => b.decrypt(await mallory.encrypt("evil message")), "forged message must be rejected");
  console.log("OK  RSA forgery by the relay rejected (MAC)");

  // REFLECTION: A's own frame echoed back must not verify (direction keys).
  await rejects(async () => a.decrypt(await a.encrypt(MSG)), "reflected message must be rejected");
  console.log("OK  RSA reflection rejected (direction-separated MAC keys)");

  // REPLAY: the same genuine frame must not be accepted twice.
  const wire = await a.encrypt(MSG);
  assert.strictEqual(await b.decrypt(wire), MSG, "genuine frame accepted once");
  await rejects(async () => b.decrypt(wire), "replayed frame must be rejected");
  console.log("OK  RSA replay rejected (sequence number)");

  // TAMPER: flipping ciphertext must fail the MAC (checked before decryption).
  const m = JSON.parse(Buffer.from(await a.encrypt(MSG), "base64").toString());
  m.ct = (m.ct[0] === "A" ? "B" : "A") + m.ct.slice(1);
  const tampered = Buffer.from(JSON.stringify(m)).toString("base64");
  await rejects(async () => b.decrypt(tampered), "tampered frame must be rejected");
  console.log("OK  RSA tampering rejected (MAC before decrypt)");
}

// Reflection / replay / tamper the AuthChannel must defeat for the symmetric
// modes (AES256, DHKE, PQKEM), which share one AES-GCM key in both directions.
// A malicious relay never learns that key, but it CAN capture and re-route
// genuine ciphertext — so it can try to echo your own frame back or replay one.
async function symmetricAttackChecks(alg) {
  const a = makeCipher(alg, ROOM, { passphrase: "correct horse battery staple" });
  const b = makeCipher(alg, ROOM, { passphrase: "correct horse battery staple" });
  await a.init();
  await b.init();
  if (a.needsHandshake) {
    // Staggered single-secret path (the realistic order).
    const bOffer = await b.handshakePayload();
    await a.onPeerKey(bOffer);
    await b.onPeerKey(await a.handshakePayload());
  }
  assert.ok(a.ready && b.ready, `${alg} ready`);

  const rejects = async (p, what) => {
    let failed = false;
    try { await p(); } catch { failed = true; }
    assert.ok(failed, what);
  };

  // REFLECTION: A's own frame echoed back to A must not decrypt (sender tag).
  await rejects(async () => a.decrypt(await a.encrypt(MSG)), `${alg} reflection must be rejected`);

  // REPLAY: a genuine frame is accepted exactly once.
  const wire = await a.encrypt(MSG);
  assert.strictEqual(await b.decrypt(wire), MSG, `${alg} genuine frame accepted once`);
  await rejects(async () => b.decrypt(wire), `${alg} replay must be rejected`);

  // TAMPER: flipping ciphertext fails the GCM tag.
  const m = JSON.parse(Buffer.from(await a.encrypt(MSG), "base64").toString());
  m.ct = (m.ct[0] === "A" ? "B" : "A") + m.ct.slice(1);
  const tampered = Buffer.from(JSON.stringify(m)).toString("base64");
  await rejects(async () => b.decrypt(tampered), `${alg} tampered frame must be rejected`);
  console.log(`OK  ${alg} reflection + replay + tamper rejected (authenticated framing)`);
}

// A replayed handshake frame must NOT rotate an established key (relay DoS).
async function pqkemReplayDoesNotDesync() {
  const a = makeCipher("PQKEM", ROOM);
  const b = makeCipher("PQKEM", ROOM);
  await a.init();
  await b.init();
  const bOffer = await b.handshakePayload();
  await a.onPeerKey(bOffer);
  await b.onPeerKey(await a.handshakePayload());
  assert.strictEqual(await b.decrypt(await a.encrypt(MSG)), MSG, "PQKEM baseline works");
  // Relay replays B's original (validly-signed) offer to A after establishment.
  await a.onPeerKey(bOffer);
  assert.strictEqual(await b.decrypt(await a.encrypt("still here")), "still here",
    "PQKEM session survives a replayed offer (no key desync)");
  console.log("OK  PQKEM replayed handshake offer does not desync the key");
}

await roundtripShared();
await roundtripHandshake("DHKE");
await roundtripHandshake("RSA");
await roundtripHandshake("PQKEM");
await negativeChecks();
await rsaAttackChecks();
await symmetricAttackChecks("AES256");
await symmetricAttackChecks("DHKE");
await symmetricAttackChecks("PQKEM");
await pqkemReplayDoesNotDesync();
console.log("\nAll crypto checks passed.");
