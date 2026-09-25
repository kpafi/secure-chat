// Full-stack integration test for the AUTHENTICATED handshake — the same
// protocol app.js speaks: each peer signs its ephemeral key with a long-term
// identity, the other verifies the dual signature against the pinned bundle,
// and both independently derive the same shared key and the same safety number.
//
// This complements identity.test.mjs (which proves MITM rejection at the
// protocol layer) by proving the wired protocol actually CONVERGES through the
// real relay for DHKE and PQKEM.
//
// Requires the server running:  cd backend && ./run.sh
// Run:                          node client/auth.integration.test.mjs
import assert from "node:assert";
import { makeCipher, bufToB64, b64ToBuf } from "./crypto.js";
import { Identity } from "./identity.js";
import {
  signHandshake, verifyHandshake, freshNonce, isValidNonce, signKnock, verifyKnock,
} from "./auth.js";

const URL = "ws://127.0.0.1:8000/ws";
const enc = new TextEncoder();
const dec = new TextDecoder();

function packKey(obj) {
  return bufToB64(enc.encode(JSON.stringify(obj)));
}
function unpackKey(b64) {
  return JSON.parse(dec.decode(b64ToBuf(b64)));
}

// A peer that mirrors app.js's authenticated handshake for one algorithm:
// hello (fresh session nonce) first, then the signed offer/answer whose
// transcript covers BOTH nonces (cross-session replay protection).
function makePeer(name, room, alg, identity, peerPinnedBundle, onText) {
  const cipher = makeCipher(alg, room, {});
  const myBundle = identity.publicBundle();
  const ws = new WebSocket(URL);
  const ready = {};
  const readyP = new Promise((r) => (ready.resolve = r));
  const joined = {};
  const joinedP = new Promise((r) => (joined.resolve = r));

  const myNonce = freshNonce();
  let peerNonce = null;
  let helloAnswered = false;
  let admitted = null; // the identity this peer let into the room (owner side)

  // Computed fresh each call (no caching): PQKEM's offer and answer
  // are different payloads and each needs its own signature.
  async function mine() {
    const pub = await cipher.handshakePayload();
    const sig = await signHandshake(identity, room, [myNonce, peerNonce], pub);
    return { pub, sig };
  }

  async function sendSignedKey(reply) {
    const { pub, sig } = await mine();
    ws.send(JSON.stringify({ type: "key", room, alg, payload: packKey({ pub, reply, idb: myBundle, sig }) }));
  }

  ws.addEventListener("open", async () => {
    await cipher.init();
    ws.send(JSON.stringify({ type: "join", room }));
  });

  ws.addEventListener("message", async (ev) => {
    const m = JSON.parse(ev.data);
    // P-08 admission. The knock carries the SIGNED identity, and the owner
    // admits only the bundle it pinned in person — so this harness also covers
    // the client-side rule that the admitted key must be the expected one.
    if (m.type === "pending") {
      signKnock(identity, room).then((sig) => {
        ws.send(JSON.stringify({ type: "knock", room, payload: packKey({ idb: myBundle, sig }) }));
      });
      return;
    }
    if (m.type === "knock") {
      const p = unpackKey(m.payload);
      const okKnock = await verifyKnock(p.idb, room, p.sig);
      assert.strictEqual(okKnock, true, `${name}: knock signature must verify`);
      assert.deepStrictEqual(p.idb, peerPinnedBundle, `${name}: only the pinned peer is admitted`);
      admitted = p.idb;
      ws.send(JSON.stringify({ type: "admit", room, jid: m.jid }));
      return;
    }
    if (m.type === "denied") {
      throw new Error(`${name}: unexpectedly denied entry`);
    }
    if (m.type === "joined") {
      joined.resolve();
      ws.send(JSON.stringify({ type: "key", room, alg, payload: packKey({ hello: true, n: myNonce, reply: false }) }));
    } else if (m.type === "key") {
      const p = unpackKey(m.payload);
      if (p.hello) {
        assert.ok(isValidNonce(p.n), `${name}: peer hello nonce must be well-formed`);
        if (peerNonce === null) peerNonce = p.n;
        if (!p.reply && !helloAnswered) {
          helloAnswered = true;
          ws.send(JSON.stringify({ type: "key", room, alg, payload: packKey({ hello: true, n: myNonce, reply: true }) }));
          await sendSignedKey(false);
        }
        return;
      }
      const { pub, reply, idb, sig } = p;
      assert.notStrictEqual(peerNonce, null, `${name}: handshake must not arrive before the nonce exchange`);
      // Verify against the bundle we pinned in person — not whatever arrives.
      const ok = await verifyHandshake(peerPinnedBundle, room, [myNonce, peerNonce], pub, sig);
      assert.strictEqual(ok, true, `${name}: peer handshake signature must verify against the pin`);
      assert.deepStrictEqual(idb, peerPinnedBundle, `${name}: received bundle must equal the pinned bundle`);
      // P-08: the peer that completes the handshake must be the identity we let
      // in — the rule that stops "admit Alice, route Mallory".
      if (admitted) {
        assert.deepStrictEqual(idb, admitted, `${name}: handshake peer must be the admitted identity`);
      }
      await cipher.onPeerKey(pub);
      if (!reply) {
        await sendSignedKey(true);
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
  // Alice and Bob verified each other in person => each holds the other's pin.
  const alice = await Identity.generate();
  const bob = await Identity.generate();

  const got = {};
  const aGot = new Promise((r) => (got.a = r));
  const bGot = new Promise((r) => (got.b = r));

  // Stagger so B is the sole late joiner (deterministic single-secret path).
  const A = makePeer("A", room, alg, alice, bob.publicBundle(), (t) => got.a(t));
  await A.joinedP;
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

// Regression for the 2026-07-02 pentest finding: a malicious relay captures a
// peer's validly-signed handshake in session 1 and replays it into a NEW
// session that reuses the same room id. Under the v1 transcript (no freshness)
// the signature still verified and the honest peers silently desynced; under
// v2 the transcript covers a nonce the victim generated THIS connection, so
// the stale handshake must fail signature verification.
async function testCrossSessionReplayLive() {
  const room = randomRoom();
  const alice = await Identity.generate();
  const bob = await Identity.generate();

  // --- Session 1: honest A + B complete a handshake; "the relay" (us, via a
  // tap on A's socket) captures every frame B sent: his hello + signed answer.
  const captured = [];
  const got = {};
  const aGot = new Promise((r) => (got.a = r));
  const A1 = makePeer("A1", room, "DHKE", alice, bob.publicBundle(), (t) => got.a(t));
  A1.ws.addEventListener("message", (ev) => {
    const m = JSON.parse(ev.data);
    if (m.type === "key") captured.push(m.payload);
  });
  await A1.joinedP;
  const B1 = makePeer("B1", room, "DHKE", bob, alice.publicBundle(), () => {});
  await Promise.all([A1.readyP, B1.readyP]);
  await B1.send("session 1 sanity");
  assert.strictEqual(await aGot, "session 1 sanity");
  A1.close();
  B1.close();
  const staleHello = captured.find((p) => unpackKey(p).hello);
  const staleSigned = captured.find((p) => !unpackKey(p).hello);
  assert.ok(staleHello && staleSigned, "captured B's hello and signed handshake");

  // --- Session 2: same room. Honest Alice reconnects with a FRESH nonce;
  // Mallory (the relay, played by a plain room member) replays B's captured,
  // validly-signed session-1 frames. Alice must REJECT the stale handshake.
  const myNonce = freshNonce();
  let peerNonce = null;
  const verdict = {};
  const verdictP = new Promise((r) => (verdict.resolve = r));
  const victim = new WebSocket(URL);
  const victimJoined = new Promise((r) => {
    victim.addEventListener("message", async (ev) => {
      const m = JSON.parse(ev.data);
      if (m.type === "joined") r();
      // Mallory is modelled as a hostile peer the victim DOES let in — the
      // point of the test is that the replayed handshake fails anyway.
      if (m.type === "knock") {
        victim.send(JSON.stringify({ type: "admit", room, jid: m.jid }));
        return;
      }
      if (m.type !== "key") return;
      const p = unpackKey(m.payload);
      if (p.hello) {
        if (peerNonce === null) peerNonce = p.n;
        return; // replayed hello is reply:false, but the victim needn't answer for this test
      }
      // The stale signed handshake arrives: verify exactly like app.js does.
      verdict.resolve(await verifyHandshake(bob.publicBundle(), room, [myNonce, peerNonce], p.pub, p.sig));
    });
  });
  victim.addEventListener("open", () => victim.send(JSON.stringify({ type: "join", room })));
  await victimJoined;

  const mallory = new WebSocket(URL);
  await new Promise((r) => {
    mallory.addEventListener("message", (ev) => {
      const m = JSON.parse(ev.data);
      if (m.type === "pending") {
        mallory.send(JSON.stringify({ type: "knock", room, payload: packKey({ anon: true }) }));
      }
      if (m.type === "joined") r();
    });
    mallory.addEventListener("open", () => mallory.send(JSON.stringify({ type: "join", room })));
  });
  mallory.send(JSON.stringify({ type: "key", room, alg: "DHKE", payload: staleHello }));
  mallory.send(JSON.stringify({ type: "key", room, alg: "DHKE", payload: staleSigned }));

  const accepted = await verdictP;
  assert.strictEqual(accepted, false,
    "replayed session-1 handshake must FAIL verification in session 2 (fresh victim nonce)");
  victim.close();
  mallory.close();
  console.log("OK  cross-session handshake replay through the live relay REJECTED (session nonces)");
}

await testAlg("DHKE");
await testAlg("PQKEM");
await testCrossSessionReplayLive();
console.log("\nAll authenticated-handshake integration checks passed.");
process.exit(0);
