// Crypto correctness check, runnable in Node (uses the same Web Crypto API as
// the browser). Simulates two peers (A and B) for each algorithm and asserts a
// full round-trip. Run: node client/crypto.test.mjs
import assert from "node:assert";
import { makeCipher, isAscii } from "./crypto.js";

const ROOM = "a".repeat(64);
const MSG = "Hello over the relay! ~ ASCII only 123 #@$";

// Fresh session nonces, as app.js's plaintext hello exchange would produce.
function nonce() {
  return Buffer.from(crypto.getRandomValues(new Uint8Array(32))).toString("base64");
}
async function exchangeNonces(a, b) {
  const [nA, nB] = [nonce(), nonce()];
  await a.setNonces(nA, nB);
  await b.setNonces(nB, nA);
}

async function roundtripShared() {
  // AES-256 passphrase: no key material on the wire; both derive the same
  // chains from the passphrase + the exchanged pair of session nonces.
  const a = makeCipher("AES256", ROOM, { passphrase: "correct horse battery staple" });
  const b = makeCipher("AES256", ROOM, { passphrase: "correct horse battery staple" });
  await a.init();
  await b.init();
  assert.ok(!a.ready && !b.ready, "AES256 not ready before the nonce exchange");
  await exchangeNonces(a, b);
  assert.ok(a.ready && b.ready, "AES256 ready");
  const wire = await a.encrypt(MSG);
  assert.strictEqual(await b.decrypt(wire), MSG, "AES256 A->B");
  assert.strictEqual(await a.decrypt(await b.encrypt(MSG)), MSG, "AES256 B->A");
  console.log("OK  AES256 (passphrase + session nonces) round-trip");
}

async function roundtripHandshake(alg) {
  const a = makeCipher(alg, ROOM);
  const b = makeCipher(alg, ROOM);
  await a.init();
  await b.init();
  assert.ok(a.needsHandshake, `${alg} needs handshake`);
  // Two rounds through the (simulated) relay. For DHKE the second payload is
  // the same idempotent public key; for RSA/PQKEM round 1 is the offer and
  // round 2 the answer (wrapped root secret / KEM encapsulation). Exchanging
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
  await exchangeNonces(a, b);
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

// RSA-specific attacks the ratcheted framing must defeat. Mallory plays the
// relay: she sees every handshake payload (so she learns both public keys)
// but never the OAEP-wrapped root secret.
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

  // FORGERY: Mallory saw B's offer go past, so she holds B's public key and
  // can complete her own well-formed handshake against it — the classic
  // encrypting-to-a-public-key-proves-nothing attack. Her chains descend from
  // HER root secret, which B never processed, so her frames fail the AEAD.
  const mallory = makeCipher("RSA", ROOM);
  await mallory.init();
  await mallory.onPeerKey(bOffer);
  assert.ok(mallory.ready, "mallory can always build a well-formed frame");
  await rejects(async () => b.decrypt(await mallory.encrypt("evil message")), "forged message must be rejected");
  console.log("OK  RSA forgery by the relay rejected (relay never learns the root)");

  // REFLECTION: A's own frame echoed back must not decrypt (direction chains).
  await rejects(async () => a.decrypt(await a.encrypt(MSG)), "reflected message must be rejected");
  console.log("OK  RSA reflection rejected (direction-separated chains)");

  // REPLAY: the same genuine frame must not be accepted twice (and its
  // one-time key is already deleted).
  const wire = await a.encrypt(MSG);
  assert.strictEqual(await b.decrypt(wire), MSG, "genuine frame accepted once");
  await rejects(async () => b.decrypt(wire), "replayed frame must be rejected");
  console.log("OK  RSA replay rejected (sequence + one-time keys)");

  // TAMPER: flipping ciphertext must fail GCM authentication — and must NOT
  // burn the receive chain (the step is committed only on success).
  const m = JSON.parse(Buffer.from(await a.encrypt(MSG), "base64").toString());
  m.ct = (m.ct[0] === "A" ? "B" : "A") + m.ct.slice(1);
  const tampered = Buffer.from(JSON.stringify(m)).toString("base64");
  await rejects(async () => b.decrypt(tampered), "tampered frame must be rejected");
  assert.strictEqual(await b.decrypt(await a.encrypt("still alive")), "still alive",
    "channel must survive a rejected frame");
  console.log("OK  RSA tampering rejected (channel intact afterwards)");
}

// Forward-secrecy mechanics of the RSA ratchet. These are white-box checks:
// they reach into the cipher to prove the sensitive material is actually gone.
async function rsaForwardSecrecyChecks() {
  const a = makeCipher("RSA", ROOM);
  const b = makeCipher("RSA", ROOM);
  await a.init();
  await b.init();
  const bOffer = await b.handshakePayload();
  await a.onPeerKey(bOffer);
  await b.onPeerKey(await a.handshakePayload());

  const rejects = async (p, what) => {
    let failed = false;
    try {
      await p();
    } catch {
      failed = true;
    }
    assert.ok(failed, what);
  };

  // SEAL: the first real message erases the RSA private key and root secret —
  // the two things that, with a recorded transcript, would undo the ratchet.
  assert.ok(a.kp !== null && a.secrets.size > 0, "handshake material held until traffic starts");
  const w1 = await a.encrypt("one");
  assert.ok(a.sealed && a.kp === null && a.secrets.size === 0 && a.peerPub === null,
    "sender sealed on first encrypt");
  assert.strictEqual(await b.decrypt(w1), "one");
  assert.ok(b.sealed && b.kp === null && b.secrets.size === 0,
    "receiver sealed on first decrypt");
  console.log("OK  RSA seal: root secret + RSA private key erased once traffic starts");

  // ONE-WAY CHAIN: deliver frame 3 with frame 2 lost in flight — the chain
  // fast-forwards, and the skipped frame's one-time key is gone for good.
  const w2 = await a.encrypt("two (lost in flight)");
  const w3 = await a.encrypt("three");
  assert.strictEqual(await b.decrypt(w3), "three", "gap tolerated");
  await rejects(async () => b.decrypt(w2), "skipped frame's key must be unrecoverable");
  console.log("OK  RSA skipped frame unrecoverable (keys deleted as the chain steps)");

  // POST-SEAL HANDSHAKE: a replayed (validly-signed) offer after establishment
  // must be ignored — no key desync, no resurrection of handshake state.
  await a.onPeerKey(bOffer);
  assert.ok(a.kp === null && a.secrets.size === 0, "sealed state untouched by late handshake frame");
  assert.strictEqual(await b.decrypt(await a.encrypt("still here")), "still here",
    "session survives a replayed offer");
  console.log("OK  RSA post-seal handshake frames ignored (no desync)");

  // SKIP BOUND: a far-future sequence number is rejected before any chain work.
  const far = JSON.parse(Buffer.from(await a.encrypt("x"), "base64").toString());
  far.n += 100000;
  await rejects(
    async () => b.decrypt(Buffer.from(JSON.stringify(far)).toString("base64")),
    "far-future sequence must be rejected",
  );
  console.log("OK  RSA chain-stepping bounded (hostile skip rejected)");
}

// Reflection / replay / tamper checks for the symmetric modes (AES256, DHKE,
// PQKEM). A malicious relay never learns the key material, but it CAN capture
// and re-route genuine ciphertext — so it can try to echo your own frame back
// or replay one.
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
  } else if (a.usesNonces) {
    await exchangeNonces(a, b);
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

// AES256 ratchet mechanics. The headline check is CROSS-SESSION REPLAY: it was
// a documented accepted residual of the static passphrase-derived key (a frame
// captured under the same room + passphrase decrypted again in a later
// session). The chains now bind both peers' fresh session nonces, so an old
// frame can never authenticate in a new session.
async function aesRatchetChecks() {
  const mk = () => makeCipher("AES256", ROOM, { passphrase: "correct horse battery staple" });

  const rejects = async (p, what) => {
    let failed = false;
    try {
      await p();
    } catch {
      failed = true;
    }
    assert.ok(failed, what);
  };

  // Session 1: capture a genuine frame off the wire.
  const a1 = mk();
  const b1 = mk();
  await a1.init();
  await b1.init();
  await exchangeNonces(a1, b1);
  const captured = await a1.encrypt(MSG);
  assert.strictEqual(await b1.decrypt(captured), MSG, "session-1 baseline works");

  // Session 2: same room, same passphrase, fresh nonces — the exact replay
  // scenario that used to succeed. The victim's own fresh nonce guarantees
  // fresh chains, so the captured frame must fail authentication.
  const a2 = mk();
  const b2 = mk();
  await a2.init();
  await b2.init();
  await exchangeNonces(a2, b2);
  assert.strictEqual(await b2.decrypt(await a2.encrypt(MSG)), MSG, "session-2 baseline works");
  await rejects(async () => b2.decrypt(captured), "cross-session replay must be rejected");
  // Pristine receiver too: no sequence-number history to hide behind — the
  // rejection must come from the nonce-bound key, not the replay counter.
  const a3 = mk();
  const b3 = mk();
  await a3.init();
  await b3.init();
  await exchangeNonces(a3, b3);
  await rejects(async () => b3.decrypt(captured), "cross-session replay must be rejected (fresh receiver)");
  console.log("OK  AES256 cross-session replay rejected (nonce-bound session chains)");

  // ERASURE: the passphrase copy and the derived base are gone once chains exist.
  assert.ok(a2.passphrase === null && a2.base === null, "passphrase + base erased after derivation");
  console.log("OK  AES256 passphrase copy + derived base erased (ratchet state only)");

  // ONE-WAY CHAIN: a skipped frame's one-time key is unrecoverable.
  const w1 = await a2.encrypt("one (lost in flight)");
  const w2 = await a2.encrypt("two");
  assert.strictEqual(await b2.decrypt(w2), "two", "gap tolerated");
  await rejects(async () => b2.decrypt(w1), "skipped frame's key must be unrecoverable");
  console.log("OK  AES256 skipped frame unrecoverable (keys deleted as the chain steps)");
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
await rsaForwardSecrecyChecks();
await aesRatchetChecks();
await symmetricAttackChecks("AES256");
await symmetricAttackChecks("DHKE");
await symmetricAttackChecks("PQKEM");
await pqkemReplayDoesNotDesync();
console.log("\nAll crypto checks passed.");
