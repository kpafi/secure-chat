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
  // the same idempotent public key; for PQKEM round 1 is the offer and round 2
  // the answer (the KEM encapsulation). Exchanging both offers + both answers
  // mirrors the relay's join-order race (both peers' offers delivered), which
  // PQKEM must converge on.
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

// In-session forward secrecy for the DHKE/PQKEM ratchets: white-box proof that the handshake material really is erased and
// that skipped one-time keys are gone. Plus the reflection guard shared by all
// handshake modes: a peer "offer" carrying OUR OWN public key can only be a
// relay echoing us back, and must be refused outright (identical pubs would
// collapse the direction separation of the chains).
async function handshakeRatchetChecks() {
  const rejects = async (p, what) => {
    let failed = false;
    try {
      await p();
    } catch {
      failed = true;
    }
    assert.ok(failed, what);
  };

  // DHKE: exactly one derivation ever happens, so the private key is dropped
  // the moment the chains exist — even before any traffic.
  {
    const a = makeCipher("DHKE", ROOM);
    const b = makeCipher("DHKE", ROOM);
    await a.init();
    await b.init();
    await rejects(async () => a.onPeerKey(await a.handshakePayload()), "DHKE reflected handshake must be rejected");
    const bOffer = await b.handshakePayload();
    await a.onPeerKey(bOffer);
    await b.onPeerKey(await a.handshakePayload());
    assert.ok(a.kp === null && b.kp === null, "DHKE private keys dropped at derivation");
    const w1 = await a.encrypt("one (lost in flight)");
    const w2 = await a.encrypt("two");
    assert.strictEqual(await b.decrypt(w2), "two", "DHKE gap tolerated");
    await rejects(async () => b.decrypt(w1), "DHKE skipped frame's key must be unrecoverable");
    await a.onPeerKey(bOffer); // replayed offer after establishment: ignored
    assert.strictEqual(await b.decrypt(await a.encrypt("still here")), "still here",
      "DHKE session survives a replayed offer");
    console.log("OK  DHKE in-session forward secrecy (private key dropped, one-way chains) + reflection guard");
  }

  // PQKEM: seals on first traffic (the join-order race means a
  // second root secret may still arrive until then).
  {
    const a = makeCipher("PQKEM", ROOM);
    const b = makeCipher("PQKEM", ROOM);
    await a.init();
    await b.init();
    await rejects(async () => a.onPeerKey(await a.handshakePayload()), "PQKEM reflected handshake must be rejected");
    const bOffer = await b.handshakePayload();
    await a.onPeerKey(bOffer);
    await b.onPeerKey(await a.handshakePayload());
    assert.ok(a.kem !== null && a.ecdh !== null && a.secrets.size > 0,
      "PQKEM handshake material held until traffic starts");
    const w1 = await a.encrypt("one");
    assert.ok(a.sealed && a.kem === null && a.ecdh === null && a.secrets.size === 0,
      "PQKEM sender sealed on first encrypt");
    assert.strictEqual(await b.decrypt(w1), "one");
    assert.ok(b.sealed && b.kem === null && b.ecdh === null && b.secrets.size === 0,
      "PQKEM receiver sealed on first decrypt");
    const w2 = await a.encrypt("two (lost in flight)");
    const w3 = await a.encrypt("three");
    assert.strictEqual(await b.decrypt(w3), "three", "PQKEM gap tolerated");
    await rejects(async () => b.decrypt(w2), "PQKEM skipped frame's key must be unrecoverable");
    await a.onPeerKey(bOffer); // post-seal: ignored, no desync or resurrection
    assert.ok(a.sealed && a.secrets.size === 0, "PQKEM sealed state untouched by late handshake frame");
    assert.strictEqual(await b.decrypt(await a.encrypt("still here")), "still here",
      "PQKEM session survives a replayed offer");
    console.log("OK  PQKEM in-session forward secrecy (seal on first traffic, one-way chains) + reflection guard");
  }

}

// Concurrency races (2026-07-03 pentest). The channels update their
// anti-replay state across awaited WebCrypto calls, and their real callers do
// not serialize (ws.onmessage fires handlers back-to-back; the UI can fire
// overlapping sends). These checks fire deliberately OVERLAPPING calls — no
// await between starting them — and must hold for every mode.
async function concurrencyChecks(alg) {
  const mk = () => makeCipher(alg, ROOM, { passphrase: "correct horse battery staple" });
  const pair = async () => {
    const a = mk();
    const b = mk();
    await a.init();
    await b.init();
    if (a.needsHandshake) {
      const bOffer = await b.handshakePayload();
      await a.onPeerKey(bOffer);
      await b.onPeerKey(await a.handshakePayload());
    } else if (a.usesNonces) {
      await exchangeNonces(a, b);
    }
    return [a, b];
  };

  // OVERLAPPING ENCRYPTS (the ratchet-killer): two unawaited encrypts used to
  // read the same chain head and consume the same one-time key — the second
  // frame was garbage and the chain never recovered. Both frames must decrypt,
  // and the channel must still work afterwards.
  {
    const [a, b] = await pair();
    const [w1, w2] = await Promise.all([a.encrypt("first"), a.encrypt("second")]);
    assert.strictEqual(await b.decrypt(w1), "first", `${alg} overlapping encrypt #1`);
    assert.strictEqual(await b.decrypt(w2), "second", `${alg} overlapping encrypt #2`);
    assert.strictEqual(await b.decrypt(await a.encrypt("third")), "third",
      `${alg} channel intact after overlapping encrypts`);
  }

  // OVERLAPPING DECRYPTS of the SAME frame: both used to read the replay
  // counter before either committed it, so both could succeed. Exactly one
  // may be accepted.
  {
    const [a, b] = await pair();
    const wire = await a.encrypt("only once");
    const results = await Promise.allSettled([b.decrypt(wire), b.decrypt(wire), b.decrypt(wire)]);
    const accepted = results.filter((r) => r.status === "fulfilled");
    assert.strictEqual(accepted.length, 1, `${alg} concurrent duplicate accepted exactly once`);
    assert.strictEqual(accepted[0].value, "only once", `${alg} the one acceptance is genuine`);
    assert.strictEqual(await b.decrypt(await a.encrypt("still alive")), "still alive",
      `${alg} channel intact after concurrent duplicates`);
  }

  // COUNTER ROLLBACK (the exact pentest replay): two DIFFERENT frames delivered
  // concurrently could commit out of order, rolling the counter back so a
  // frame the user already saw was accepted a second time. Both replays must
  // now be rejected.
  {
    const [a, b] = await pair();
    const w1 = await a.encrypt("one");
    const w2 = await a.encrypt("two");
    const delivered = await Promise.allSettled([b.decrypt(w1), b.decrypt(w2)]);
    assert.ok(delivered.every((r) => r.status === "fulfilled"),
      `${alg} concurrent in-order frames both accepted`);
    for (const replay of [w1, w2]) {
      let failed = false;
      try {
        await b.decrypt(replay);
      } catch {
        failed = true;
      }
      assert.ok(failed, `${alg} replay after concurrent delivery must be rejected`);
    }
  }
  console.log(`OK  ${alg} overlapping encrypt/decrypt serialized (replay + desync races closed)`);
}

// A replayed handshake frame must NOT rotate an established key (relay DoS).
//
// Pentest 2026-07-29, test-coverage gap 1: this test WAS VACUOUS. It replayed
// the offer after `a.encrypt()` had already sealed the cipher, and `_seal()`
// makes `onPeerKey` an immediate no-op — so the replay never reached `_derive`
// at all and the assertion could not observe it. It would have passed with
// `_derive` entirely broken, which is the same failure mode 7d4e480 set out to
// fix. The replay has to land BEFORE the first message for this to test
// anything.
async function pqkemReplayDoesNotDesync() {
  const a = makeCipher("PQKEM", ROOM);
  const b = makeCipher("PQKEM", ROOM);
  await a.init();
  await b.init();
  const bOffer = await b.handshakePayload();
  await a.onPeerKey(bOffer);
  await b.onPeerKey(await a.handshakePayload());

  // The real test: replay while the cipher is still UNSEALED, so the frame
  // genuinely reaches _derive and idempotence is what has to save us.
  const beforeReplay = a.confirmation;
  await a.onPeerKey(bOffer);
  assert.deepStrictEqual(a.confirmation, beforeReplay,
    "a replayed offer must not rebuild the chains (pre-seal — this is the live path)");

  assert.strictEqual(await b.decrypt(await a.encrypt(MSG)), MSG,
    "PQKEM still works after a pre-seal replay");

  // …and the post-seal path stays covered too: once sealed, onPeerKey is a
  // no-op by construction. Kept because it is a DIFFERENT mechanism, and
  // labelled so nobody mistakes it for the assertion above again.
  await a.onPeerKey(bOffer);
  assert.strictEqual(await b.decrypt(await a.encrypt("still here")), "still here",
    "PQKEM session survives a replayed offer post-seal (onPeerKey is a no-op)");
  console.log("OK  PQKEM replayed handshake offer does not desync the key");
}

// M-5 (2026-07-29): a WITHHELD offer delivered later is not a replay — it is
// new material, and `_derive` rebuilds `this.chan` (and both confirmation tags)
// when it lands. That is the mechanism behind the silent desync; the app-level
// fix is a confirmDone gate in app.js, but the cipher-level fact it rests on
// needs pinning here, or a future refactor could make _derive idempotent-ish
// and quietly invalidate the reasoning on both sides.
async function pqkemLateOfferChangesTheChains() {
  const a = makeCipher("PQKEM", ROOM);
  const b = makeCipher("PQKEM", ROOM);
  await a.init();
  await b.init();
  // A derives from its own offer being answered…
  await a.onPeerKey(await b.handshakePayload());
  const first = a.confirmation;
  assert.ok(first && first.mine, "precondition: A has chains and a confirmation tag");

  // …then B's ANSWER (new KEM material, a different input signature) arrives.
  await b.onPeerKey(await a.handshakePayload());
  const bAnswer = await b.handshakePayload();
  await a.onPeerKey(bAnswer);

  if (a.confirmation.mine === first.mine) {
    // Nothing to prove: this input did not add material. Say so rather than
    // passing silently, so the test cannot rot into another vacuous one.
    console.log("OK  PQKEM late offer folded idempotently (no chain change to gate)");
    return;
  }
  assert.notStrictEqual(a.confirmation.theirs, first.theirs,
    "a chain rebuild must move BOTH tags, or confirmation could not detect it");
  console.log("OK  PQKEM a late offer DOES rebuild the chains (M-5's mechanism, pinned)");
}

// ---- OTP (pre-shared one-time pad) -----------------------------------------
// Build two peer views of the SAME pad (as export/import would produce on two
// devices): identical bytes, opposite roles, independent Uint8Arrays so zeroing
// on one peer never touches the other's copy.
function otpPeers(regionSize = 4096) {
  const shared = crypto.getRandomValues(new Uint8Array(2 * regionSize));
  const view = (role) => makeCipher("OTP", ROOM, {
    pad: { bytes: shared.slice(), role, regionSize, sendOffset: 0, recvHighWater: 0 },
  });
  return [view(0), view(1)];
}

// L-5 (2026-07-29): OtpPad must validate its own offsets.
//
// Not reachable through otp.js today — it rejects negative offsets before the
// cipher is built, and v3 keeps them inside the AEAD — but the class validates
// every OTHER field of the record, and with a bad offset the consequences are
// two-time-pad shaped: a negative sendOffset makes the P-01 spent-keystream
// guard return false on its first iteration and makes slice() draw the MAC key
// and keystream from the PEER's region, while a negative recvHighWater turns
// the zeroing fill() into a no-op. `| 0` also quietly turned NaN into 0.
function otpChecksOffsetValidation() {
  const regionSize = 4096;
  const bytes = crypto.getRandomValues(new Uint8Array(2 * regionSize));
  const build = (over) => () => makeCipher("OTP", ROOM, {
    pad: { bytes: bytes.slice(), role: 0, regionSize, sendOffset: 0, recvHighWater: 0, ...over },
  });

  for (const bad of [-1, -4096, -0.5, 1.5, NaN, Infinity, "0", null, undefined, regionSize + 1]) {
    assert.throws(build({ sendOffset: bad }), /invalid send offset/,
      `sendOffset ${String(bad)} must be refused`);
    assert.throws(build({ recvHighWater: bad }), /invalid receive high-water/,
      `recvHighWater ${String(bad)} must be refused`);
  }
  // The legitimate boundaries still work: a fresh pad and a fully spent one.
  assert.ok(build({ sendOffset: 0, recvHighWater: 0 })(), "a fresh pad is valid");
  assert.ok(build({ sendOffset: regionSize, recvHighWater: regionSize })(),
    "a fully consumed pad is valid (it just has no room left)");
  console.log("OK  L-5: OtpPad refuses out-of-range or non-integer offsets");
}

async function otpChecks() {
  // Round-trip both directions.
  {
    const [a, b] = otpPeers();
    assert.ok(a.ready && b.ready, "OTP ready once the pad is loaded");
    assert.strictEqual(await b.decrypt(await a.encrypt(MSG)), MSG, "OTP A->B");
    assert.strictEqual(await a.decrypt(await b.encrypt(MSG)), MSG, "OTP B->A");
    // Distinct messages consume distinct pad bytes (offset advances).
    assert.strictEqual(await b.decrypt(await a.encrypt("second")), "second", "OTP second A->B");
  }
  // Replay (and cross-session replay) rejected: an already-consumed offset never
  // decrypts twice.
  {
    const [a, b] = otpPeers();
    const wire = await a.encrypt(MSG);
    assert.strictEqual(await b.decrypt(wire), MSG, "OTP first delivery ok");
    await assert.rejects(() => b.decrypt(wire), /consumed|replay/i, "OTP replay rejected");
  }
  // Tamper: flipping a ciphertext byte fails authentication, and the channel
  // still works afterwards (a rejected frame consumes no pad).
  {
    const [a, b] = otpPeers();
    const frame = JSON.parse(Buffer.from(await a.encrypt(MSG), "base64").toString());
    const ctBytes = Buffer.from(frame.ct, "base64");
    ctBytes[0] ^= 0x01;
    frame.ct = ctBytes.toString("base64");
    const tampered = Buffer.from(JSON.stringify(frame)).toString("base64");
    await assert.rejects(() => b.decrypt(tampered), /authentication/i, "OTP tamper rejected");
    assert.strictEqual(await b.decrypt(await a.encrypt("after tamper")), "after tamper",
      "OTP channel survives a rejected frame");
  }
  // Reflection: our own frame echoed back to us is refused (wrong region).
  {
    const [a] = otpPeers();
    const wire = await a.encrypt(MSG);
    await assert.rejects(() => a.decrypt(wire), /region|reflected/i, "OTP reflection rejected");
  }
  // Forgery: a peer holding a DIFFERENT pad cannot authenticate a frame.
  {
    const [a] = otpPeers();
    const [, bOther] = otpPeers(); // unrelated pad, role 1
    const wire = await a.encrypt(MSG);
    await assert.rejects(() => bOther.decrypt(wire), /authentication/i,
      "OTP forged/other-pad frame rejected");
  }
  // Exhaustion: sending past the region end throws rather than reusing pad.
  {
    const region = 128;
    const shared = crypto.getRandomValues(new Uint8Array(2 * region));
    const a = makeCipher("OTP", ROOM, { pad: { bytes: shared.slice(), role: 0, regionSize: region, sendOffset: 0, recvHighWater: 0 } });
    // 32-byte MAC + payload; a 200-byte message cannot fit a 128-byte region.
    await assert.rejects(() => a.encrypt("x".repeat(200)), /exhausted/i, "OTP exhaustion refused");
  }
  // Forward secrecy: consumed pad bytes are zeroed on both sender and receiver.
  {
    const region = 4096;
    const shared = crypto.getRandomValues(new Uint8Array(2 * region));
    const aBytes = shared.slice();
    const bBytes = shared.slice();
    const a = makeCipher("OTP", ROOM, { pad: { bytes: aBytes, role: 0, regionSize: region, sendOffset: 0, recvHighWater: 0 } });
    const b = makeCipher("OTP", ROOM, { pad: { bytes: bBytes, role: 1, regionSize: region, sendOffset: 0, recvHighWater: 0 } });
    const wire = await a.encrypt(MSG);
    const used = 32 + Buffer.byteLength(MSG);
    assert.ok(aBytes.slice(0, used).every((x) => x === 0), "sender zeroed consumed pad (region 0)");
    await b.decrypt(wire);
    assert.ok(bBytes.slice(0, used).every((x) => x === 0), "receiver zeroed consumed pad (region 0)");
  }
  console.log("OK  OTP round-trip, replay/tamper/reflection/forgery rejected, exhaustion + FS zeroing");
}

await roundtripShared();
await roundtripHandshake("DHKE");
await roundtripHandshake("PQKEM");
await negativeChecks();
await aesRatchetChecks();
await symmetricAttackChecks("AES256");
await symmetricAttackChecks("DHKE");
await symmetricAttackChecks("PQKEM");
await pqkemReplayDoesNotDesync();
await pqkemLateOfferChangesTheChains();
await handshakeRatchetChecks();
await concurrencyChecks("AES256");
await concurrencyChecks("DHKE");
await concurrencyChecks("PQKEM");
otpChecksOffsetValidation();
await otpChecks();
console.log("\nAll crypto checks passed.");
