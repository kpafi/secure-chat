// Full-stack integration test: two real WebSocket clients talk through the
// running relay using the SAME handshake protocol as app.js. Verifies the
// server relays opaque ciphertext and that DHKE/PQKEM handshakes converge.
//
// Requires the server running:  cd backend && ./run.sh
// Run:                          node client/integration.test.mjs
import assert from "node:assert";
import { makeCipher, bufToB64, b64ToBuf } from "./crypto.js";

const URL = "ws://127.0.0.1:8000/ws";
const enc = new TextEncoder();
const dec = new TextDecoder();

function packKey(obj) {
  return bufToB64(enc.encode(JSON.stringify(obj)));
}
function unpackKey(b64) {
  return JSON.parse(dec.decode(b64ToBuf(b64)));
}

// A peer that mirrors app.js logic for one algorithm.
function makePeer(name, room, alg, onText) {
  const cipher = makeCipher(alg, room, { passphrase: "shared-secret" });
  const ws = new WebSocket(URL);
  const ready = { resolve: null };
  const readyP = new Promise((r) => (ready.resolve = r));
  const joined = { resolve: null };
  const joinedP = new Promise((r) => (joined.resolve = r));
  const myNonce = bufToB64(crypto.getRandomValues(new Uint8Array(32)));
  let peerNonce = null;
  let helloAnswered = false;

  ws.addEventListener("open", async () => {
    await cipher.init();
    ws.send(JSON.stringify({ type: "join", room }));
  });

  ws.addEventListener("message", async (ev) => {
    const m = JSON.parse(ev.data);
    // P-08 admission: the second peer waits and introduces itself; the owner
    // admits whoever knocks. These harness peers trust each other by
    // construction — the identity checks live in auth.integration.test.mjs.
    if (m.type === "pending") {
      ws.send(JSON.stringify({ type: "knock", room, payload: packKey({ anon: true }) }));
      return;
    }
    if (m.type === "knock") {
      ws.send(JSON.stringify({ type: "admit", room, jid: m.jid }));
      return;
    }
    if (m.type === "joined") {
      joined.resolve();
      if (cipher.needsHandshake) {
        const pub = await cipher.handshakePayload();
        ws.send(JSON.stringify({ type: "key", room, payload: packKey({ pub, reply: false }), alg }));
      } else if (cipher.usesNonces) {
        // AES256: mirror app.js's plaintext hello (session-nonce) exchange.
        ws.send(JSON.stringify({ type: "key", room, payload: packKey({ hello: true, n: myNonce, reply: false }), alg }));
      }
    } else if (m.type === "key") {
      const p = unpackKey(m.payload);
      if (p.hello) {
        if (peerNonce === null) peerNonce = p.n;
        if (!p.reply && !helloAnswered) {
          helloAnswered = true;
          ws.send(JSON.stringify({ type: "key", room, payload: packKey({ hello: true, n: myNonce, reply: true }), alg }));
        }
        if (cipher.usesNonces && !cipher.ready) {
          await cipher.setNonces(myNonce, peerNonce);
          if (cipher.ready) ready.resolve();
        }
        return;
      }
      await cipher.onPeerKey(p.pub);
      if (!p.reply) {
        const mine = await cipher.handshakePayload();
        ws.send(JSON.stringify({ type: "key", room, payload: packKey({ pub: mine, reply: true }), alg }));
      }
      if (cipher.ready) ready.resolve();
    } else if (m.type === "msg") {
      onText(await cipher.decrypt(m.payload));
    } else if (m.type === "error") {
      throw new Error(`${name} got server error: ${m.reason}`);
    }
  });

  return {
    name, ws, readyP, joinedP,
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
  const got = {};
  const aGot = new Promise((r) => (got.a = r));
  const bGot = new Promise((r) => (got.b = r));

  // Stagger: A fully joins before B connects (the realistic order). This makes
  // B the late joiner / sole offerer, so the handshake takes its deterministic
  // single-secret path rather than the simultaneous-join race.
  const A = makePeer("A", room, alg, (t) => got.a(t));
  await A.joinedP;
  const B = makePeer("B", room, alg, (t) => got.b(t));

  await Promise.all([A.readyP, B.readyP]);
  await A.send(`from A via ${alg}`);
  await B.send(`from B via ${alg}`);

  assert.strictEqual(await bGot, `from A via ${alg}`, `${alg}: B should read A`);
  assert.strictEqual(await aGot, `from B via ${alg}`, `${alg}: A should read B`);
  A.close();
  B.close();
  console.log(`OK  ${alg} end-to-end through relay`);
}

await testAlg("DHKE");
await testAlg("AES256");
await testAlg("PQKEM");
console.log("\nAll integration checks passed.");
process.exit(0);
