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
  // Swap public keys through the (simulated) relay.
  const aPub = await a.handshakePayload();
  const bPub = await b.handshakePayload();
  await a.onPeerKey(bPub);
  await b.onPeerKey(aPub);
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

await roundtripShared();
await roundtripHandshake("DHKE");
await roundtripHandshake("RSA");
await negativeChecks();
console.log("\nAll crypto checks passed.");
