// tamper.mjs — a relay that attacks the CRYPTO layer. Companion to hostile.mjs,
// which lies about roles and the directory but forwards every `key`/`msg`
// frame verbatim; nothing in the tree exercised promise #1 (a hostile relay
// cannot read, forge, replay or undetectably tamper with a conversation) end to
// end until the Phase-7 pentest of 2026-09-16 (F-P7-A8) wrote this one.
//
// Role assignment is HONEST here — owner first, guest via knock/admit — so a
// session genuinely completes under EVIL=none, and every other mode changes
// exactly one thing about the key material or the frames:
//
//   keysub      replace the peer's ephemeral public key with one the relay made
//   idbswap     rewrite ONLY idb.ecdh inside the signed key frame (P-03, live)
//   idbstrip    strip idb.ecdh/idb.mlkem from the signed key frame
//   ctflip      flip one ciphertext bit in every msg frame
//   msgreplay   deliver every msg frame three times
//   confirmpre  inject two bogus key-confirmation tags before the honest one
//   algflood    send ALGFLOOD_N (default 300) frames tagged alg:"RSA" per key frame
//   msgflood    after the first real msg, send MSGFLOOD_N (default 600) junk msg frames
//   confirmpost inject two bogus confirm tags AFTER each handshake key frame (the
//               half F-P7-19 could not fix: an expected, loud, relay-blaming teardown)
//
// crypto-tamper.mjs drives two real browsers through each mode and asserts what
// the shipped client must show. Run it, not this, unless you are debugging.
import { createServer } from "node:http";
import { randomBytes } from "node:crypto";
import { readFile } from "node:fs/promises";
import { extname, normalize, join } from "node:path";
import ws_ from "../node_modules/ws/index.js";
const { WebSocketServer } = ws_;

const ROOT = (process.env.CLIENT_ROOT
  ? process.env.CLIENT_ROOT
  : new URL("../../client/", import.meta.url).pathname).replace(/\/$/, "");
const PORT = Number(process.env.PORT || 8098);
const EVIL = process.env.EVIL || "none";
const ALGFLOOD_N = Number(process.env.ALGFLOOD_N || 300);
const MSGFLOOD_N = Number(process.env.MSGFLOOD_N || 600);
const MODES = new Set(["none", "keysub", "idbswap", "idbstrip", "ctflip", "msgreplay", "confirmpre", "algflood", "msgflood", "confirmpost"]);
if (!MODES.has(EVIL)) {
  console.error(`EVIL must be one of ${[...MODES].join(", ")}; got ${EVIL}`);
  process.exit(2);
}
const TYPES = {
  ".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8",
  ".mjs": "text/javascript; charset=utf-8", ".css": "text/css; charset=utf-8",
  ".json": "application/json", ".svg": "image/svg+xml",
};
const log = (...a) => console.log(new Date().toISOString().slice(11, 23), ...a);

const http = createServer(async (req, res) => {
  const u = new URL(req.url, "http://x");
  let p = normalize(u.pathname);
  if (p === "/") p = "/index.html";
  try {
    const body = await readFile(join(ROOT, p));
    res.writeHead(200, { "content-type": TYPES[extname(p)] || "application/octet-stream" });
    res.end(body);
  } catch {
    res.writeHead(404);
    res.end("no");
  }
});
const wss = new WebSocketServer({ server: http, path: "/ws" });
const rooms = new Map();
let seq = 0;
const b64json = (o) => Buffer.from(JSON.stringify(o)).toString("base64");
const unb64json = (s) => JSON.parse(Buffer.from(s, "base64").toString());
function send(c, o) { if (c.ws.readyState === 1) c.ws.send(JSON.stringify(o)); }

let subst = null; // the relay's own substituted ephemeral key (DHKE raw point shape)
function tamper(m) {
  if (EVIL === "none") return m;
  let p;
  try { p = unb64json(m.payload); } catch { return m; }
  if (m.type === "key" && p.pub) {
    if (EVIL === "keysub") {
      if (!subst) subst = Buffer.concat([Buffer.from([4]), randomBytes(64)]).toString("base64");
      log("  !! substituting the ephemeral public key");
      return { ...m, payload: b64json({ ...p, pub: subst }) };
    }
    if (EVIL === "idbswap" && p.idb) {
      const idb = { ...p.idb, ecdh: Buffer.concat([Buffer.from([4]), randomBytes(64)]).toString("base64") };
      log("  !! rewriting idb.ecdh in the peer's key frame");
      return { ...m, payload: b64json({ ...p, idb }) };
    }
    if (EVIL === "idbstrip" && p.idb) {
      log("  !! stripping idb.ecdh/idb.mlkem");
      return { ...m, payload: b64json({ ...p, idb: { ed: p.idb.ed, mldsa: p.idb.mldsa } }) };
    }
  }
  if (m.type === "msg" && EVIL === "ctflip") {
    const ct = Buffer.from(p.ct, "base64");
    ct[0] ^= 1;
    log("  !! flipping a ciphertext bit");
    return { ...m, payload: b64json({ ...p, ct: ct.toString("base64") }) };
  }
  return m;
}

wss.on("connection", (ws) => {
  const conn = { ws, label: `c${++seq}`, room: null, jid: randomBytes(8).toString("hex"), preDone: false };
  log(`${conn.label} connected`);
  ws.on("message", (raw) => {
    let m;
    try { m = JSON.parse(String(raw)); } catch { return; }
    const entry = () => {
      if (!rooms.has(m.room)) rooms.set(m.room, { sockets: [], owner: null });
      return rooms.get(m.room);
    };
    if (m.type === "join") {
      const e = entry();
      conn.room = m.room;
      e.sockets.push(conn);
      if (e.owner === null) { e.owner = conn; send(conn, { type: "joined", role: "owner" }); }
      else send(conn, { type: "pending" });
      return;
    }
    if (m.type === "knock") {
      const e = entry();
      if (e.owner) send(e.owner, { type: "knock", jid: conn.jid, payload: m.payload });
      return;
    }
    if (m.type === "admit" || m.type === "deny") {
      const e = entry();
      const t = e.sockets.find((c) => c.jid === m.jid);
      if (!t) return;
      if (m.type === "admit") send(t, { type: "joined", role: "guest" });
      else send(t, { type: "denied" });
      return;
    }
    if (m.type === "key" || m.type === "msg") {
      const e = entry();
      const peers = e.sockets.filter((c) => c !== conn);
      let out = m;
      try { out = tamper(m); } catch (err) { log("tamper error", err.message); }
      for (const peer of peers) send(peer, out);
      if (EVIL === "algflood" && m.type === "key") {
        for (const peer of e.sockets) for (let i = 0; i < ALGFLOOD_N; i++) send(peer, { alg: "RSA" });
      }
      if (EVIL === "confirmpre" && m.type === "key" && !conn.preDone) {
        conn.preDone = true;
        for (const peer of e.sockets) {
          for (let i = 0; i < 2; i++) {
            send(peer, { type: "key", room: m.room, alg: m.alg, payload: b64json({ confirm: "BOGUS" + i }) });
          }
        }
      }
      if (EVIL === "msgreplay" && m.type === "msg") {
        for (const peer of peers) { send(peer, out); send(peer, out); }
      }
      if (EVIL === "msgflood" && m.type === "msg" && !conn.flooded) {
        conn.flooded = true;
        for (const peer of e.sockets) {
          for (let i = 0; i < MSGFLOOD_N; i++) {
            send(peer, { type: "msg", room: m.room, alg: m.alg, payload: b64json({ iv: "AAAAAAAAAAAAAAAA", ct: "AAAAAAAAAAAAAAAAAAAAAAAA", n: 100000 + i }) });
          }
        }
      }
      if (EVIL === "confirmpost" && m.type === "key") {
        let p = null;
        try { p = unb64json(m.payload); } catch {}
        if (p && p.pub) { // the handshake frame: the receiver derives chains on it, so tags after it COUNT
          for (const peer of peers) {
            for (let i = 0; i < 2; i++) {
              send(peer, { type: "key", room: m.room, alg: m.alg, payload: b64json({ confirm: "POST" + i }) });
            }
          }
        }
      }
    }
  });
  ws.on("close", () => {
    if (conn.room && rooms.has(conn.room)) {
      const e = rooms.get(conn.room);
      e.sockets = e.sockets.filter((c) => c !== conn);
      if (e.owner === conn) e.owner = null;
    }
  });
});

http.listen(PORT, "127.0.0.1", () => log(`tamper relay EVIL=${EVIL} on http://127.0.0.1:${PORT} serving ${ROOT}`));
