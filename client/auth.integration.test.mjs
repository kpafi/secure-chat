// Full-stack integration test for the AUTHENTICATED handshake — the same
// protocol app.js speaks: each peer signs its ephemeral key with a long-term
// identity, the other verifies the dual signature against the pinned bundle,
// and both independently derive the same shared key and the same safety number.
//
// This complements identity.test.mjs (which proves MITM rejection at the
// protocol layer) by proving the wired protocol actually CONVERGES through the
// real relay for DHKE and RSA.
//
// Requires the server running:  cd backend && ./run.sh
// Run:                          node client/auth.integration.test.mjs
import assert from "node:assert";
import { makeCipher, bufToB64, b64ToBuf } from "./crypto.js";
import { Identity } from "./identity.js";
import { signHandshake, verifyHandshake } from "./auth.js";

const URL = "ws://127.0.0.1:8000/ws";
const enc = new TextEncoder();
const dec = new TextDecoder();

function packKey(obj) {
  return bufToB64(enc.encode(JSON.stringify(obj)));
}
function unpackKey(b64) {
  return JSON.parse(dec.decode(b64ToBuf(b64)));
}

// A peer that mirrors app.js's authenticated handshake for one algorithm.
function makePeer(name, room, alg, identity, peerPinnedBundle, onText) {
  const cipher = makeCipher(alg, room, {});
  const myBundle = identity.publicBundle();
  const ws = new WebSocket(URL);
  let myEph = null;
  const ready = {};
  const readyP = new Promise((r) => (ready.resolve = r));

  async function mine() {
    if (myEph) return myEph;
    const pub = await cipher.handshakePayload();
    const sig = await signHandshake(identity, room, pub);
    myEph = { pub, sig };
    return myEph;
  }

  ws.addEventListener("open", async () => {
    await cipher.init();
    ws.send(JSON.stringify({ type: "join", room }));
  });

  ws.addEventListener("message", async (ev) => {
    const m = JSON.parse(ev.data);
    if (m.type === "joined") {
      const { pub, sig } = await mine();
      ws.send(JSON.stringify({ type: "key", room, alg, payload: packKey({ pub, reply: false, idb: myBundle, sig }) }));
    } else if (m.type === "key") {
      const { pub, reply, idb, sig } = unpackKey(m.payload);
      // Verify against the bundle we pinned in person — not whatever arrives.
      const ok = await verifyHandshake(peerPinnedBundle, room, pub, sig);
      assert.strictEqual(ok, true, `${name}: peer handshake signature must verify against the pin`);
      assert.deepStrictEqual(idb, peerPinnedBundle, `${name}: received bundle must equal the pinned bundle`);
      await cipher.onPeerKey(pub);
      if (!reply) {
        const mk = await mine();
        ws.send(JSON.stringify({ type: "key", room, alg, payload: packKey({ pub: mk.pub, reply: true, idb: myBundle, sig: mk.sig }) }));
      }
      if (cipher.ready) {
        const sn = await Identity.safetyNumber(myBundle, peerPinnedBundle);
        ready.resolve(sn);
      }
    } else if (m.type === "msg") {
      onText(await cipher.decrypt(m.payload));
    } else if (m.type === "error") {
      throw new Error(`${name} got server error: ${m.reason}`);
    }
  });

  return {
    name, ws, readyP,
    async send(text) {
      ws.send(JSON.stringify({ type: "msg", room, payload: await cipher.encrypt(text), alg }));
    },
    close() { ws.close(); },
  };
}

function randomRoom() {
  const b = crypto.getRandomValues(new Uint8Array(32));
  return Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
}

async function testAlg(alg) {
  const room = randomRoom();
  // Alice and Bob verified each other in person => each holds the other's pin.
  const alice = await Identity.generate();
  const bob = await Identity.generate();

  const got = {};
  const aGot = new Promise((r) => (got.a = r));
  const bGot = new Promise((r) => (got.b = r));

  const A = makePeer("A", room, alg, alice, bob.publicBundle(), (t) => got.a(t));
  const B = makePeer("B", room, alg, bob, alice.publicBundle(), (t) => got.b(t));

  const [snA, snB] = await Promise.all([A.readyP, B.readyP]);
  assert.strictEqual(snA, snB, `${alg}: both peers must compute the same safety number`);

  await A.send(`from A via ${alg}`);
  await B.send(`from B via ${alg}`);
  assert.strictEqual(await bGot, `from A via ${alg}`, `${alg}: B should read A`);
  assert.strictEqual(await aGot, `from B via ${alg}`, `${alg}: A should read B`);
  A.close();
  B.close();
  console.log(`OK  ${alg} authenticated handshake end-to-end through relay (safety number matched)`);
}

await testAlg("DHKE");
await testAlg("RSA");
console.log("\nAll authenticated-handshake integration checks passed.");
process.exit(0);
