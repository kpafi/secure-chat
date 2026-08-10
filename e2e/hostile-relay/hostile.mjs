// Hostile relay for F-PROTO-001 (secure-chat, pentest 2026-08-07, TODO item A.1).
//
// Serves the real client from ~/secure-chat/client on one origin and speaks the
// relay's websocket protocol at /ws, so the browser runs the SHIPPED app.js
// against a relay that lies. Two policies:
//
//   honest  — faithful reimplementation of backend/main.py's dispatch, used as
//             the POSITIVE CONTROL. If a normal session does not complete here,
//             nothing this harness says about the attack means anything.
//   demote  — the F-PROTO-001 configuration: BOTH parties are told they are
//             guests (pending, then joined:guest), so neither is ever asked to
//             approve anybody. Knocks are swallowed (a demoted client ignores an
//             inbound knock anyway — showNextKnock() returns unless roomRole is
//             "owner"), and key/msg frames are routed between the two sockets
//             UNCONDITIONALLY.
//
// That last point is the whole reason this file exists. A hostile relay has no
// obligation to keep the real relay's `admitted` bookkeeping: if the demote
// policy routes frames only for sockets it privately considers seated, then the
// two victims stall for the ATTACKER'S bookkeeping reasons and the client's
// admission check is never reached — which would look exactly like a fix that
// works. Here, routing is deliberately unconditional.
//
// Every frame is logged in both directions with a timestamp and the socket
// label, so "the client never sent a key frame" and "the relay never delivered
// one" are distinguishable.
import { createServer } from "node:http";
import { randomBytes } from "node:crypto";
import { readFile } from "node:fs/promises";
import { extname, normalize, join } from "node:path";
import ws_ from "../node_modules/ws/index.js";
const { WebSocketServer } = ws_;

const ROOT = new URL("../../client/", import.meta.url).pathname.replace(/\/$/, "");
const PORT = Number(process.env.PORT || 8099);
const POLICY = process.env.POLICY || "demote";
const HS_DELAY_MS = Number(process.env.HS_DELAY_MS || 0);

const TYPES = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".mjs": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".json": "application/json",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".webmanifest": "application/manifest+json",
};

const t0 = Date.now();
const log = (...a) => console.log(`[${String(Date.now() - t0).padStart(6)}ms]`, ...a);

// The attacker's own client, served from the same origin under /evil/.
//
// Any control that depends on the peer behaving is only testable by running a
// peer that does not. This is the smallest such client: it approves whoever
// sends it a handshake without asking its user, which is what an attacker's
// client does. What it CANNOT do is make the victim skip its own prompt —
// that is the property under test.
//
// The attacker client, selected by EVIL_MODE:
//
//   autoapprove — the attacker does not ask its own user anything: it treats
//                 whoever sends it a handshake as approved. This is the
//                 successor to the `forge` mode that defeated the 2026-08-07
//                 admission proof by self-signing one. Under the rebuilt
//                 control there is nothing left to forge, so the only question
//                 is whether an attacker who skips its OWN prompt can suppress
//                 the victim's — it cannot, because approval is read from local
//                 state and nothing crosses the wire.
//   none        — unpatched; serves the shipped client under /evil/ too.
const EVIL_MODE = process.env.EVIL_MODE || "autoapprove";

const EVIL_PATCHES = {
  none: null,
  autoapprove: {
    anchor: "        if (!approvedBundle) {",
    // Sets the approval AND skips the prompt. Skipping alone is not an
    // attacker: the very next check compares the approved bundle to the
    // handshake identity, and `sameBundle(null, x)` is false, so the patched
    // client refused ITSELF and the run proved nothing about the victim.
    replace: "        approvedBundle = idbCanon; /* EVIL: approves itself, silently */\n" +
      "        if (false) {",
  },
};

async function evilAppJs() {
  const src = await readFile(join(ROOT, "app.js"), "utf8");
  if (!(EVIL_MODE in EVIL_PATCHES)) throw new Error(`unknown EVIL_MODE ${EVIL_MODE}`);
  const patch = EVIL_PATCHES[EVIL_MODE];
  if (!patch) return src;
  // Fail loudly rather than silently serving an unpatched client: a harness
  // whose attacker quietly stopped attacking reports a green that means nothing.
  if (!src.includes(patch.anchor)) throw new Error(`evil patch anchor not found for mode ${EVIL_MODE}`);
  return src.replace(patch.anchor, patch.replace);
}

const http = createServer(async (req, res) => {
  const url = new URL(req.url, "http://x");
  let p = decodeURIComponent(url.pathname);
  if (p === "/") p = "/index.html";
  // /evil/* serves the same client tree, with app.js swapped for the patched
  // one. Same origin, so the websocket and secure-context rules are unchanged.
  if (p.startsWith("/evil/") || p === "/evil") {
    p = p.replace(/^\/evil\/?/, "/") || "/index.html";
    if (p === "/" || p === "") p = "/index.html";
    if (p === "/app.js") {
      try {
        res.writeHead(200, { "content-type": TYPES[".js"] });
        res.end(await evilAppJs());
      } catch (e) {
        log("!! evil patch failed:", e.message);
        res.writeHead(500).end(e.message);
      }
      return;
    }
  }
  const file = join(ROOT, normalize(p).replace(/^(\.\.[/\\])+/, ""));
  if (!file.startsWith(ROOT)) { res.writeHead(403).end(); return; }
  try {
    const body = await readFile(file);
    res.writeHead(200, { "content-type": TYPES[extname(file)] || "application/octet-stream" });
    res.end(body);
  } catch {
    res.writeHead(404).end("not found");
  }
});

const wss = new WebSocketServer({ server: http, path: "/ws" });

// room -> { sockets: [conn], owner: conn|null }
const rooms = new Map();
let seq = 0;

function send(conn, obj) {
  const s = JSON.stringify(obj);
  log(`  -> ${conn.label}`, s.slice(0, 240));
  if (conn.ws.readyState === 1) conn.ws.send(s);
}

wss.on("connection", (ws) => {
  // The jid must be 16 lowercase hex chars or app.js's queueKnock drops the
  // knock silently (`/^[0-9a-f]{16}$/`) — which looked exactly like "the owner
  // refused to show the prompt" in the first control run.
  const conn = {
    ws, label: `c${++seq}`, room: null, seated: false,
    jid: randomBytes(8).toString("hex"),
  };
  log(`${conn.label} connected`);

  ws.on("message", (raw) => {
    const text = String(raw);
    let m;
    try { m = JSON.parse(text); } catch { return; }
    log(`  <- ${conn.label}`, text.slice(0, 240));

    const entry = () => {
      if (!rooms.has(m.room)) rooms.set(m.room, { sockets: [], owner: null });
      return rooms.get(m.room);
    };

    if (m.type === "join") {
      const e = entry();
      conn.room = m.room;
      e.sockets.push(conn);
      if (POLICY === "honest") {
        if (e.owner === null) {
          e.owner = conn; conn.seated = true;
          send(conn, { type: "joined", role: "owner" });
        } else {
          send(conn, { type: "pending" });
        }
        return;
      }
      // demote: nobody owns this room. Both are told they queued and were let
      // in, so neither client ever runs an admit prompt.
      send(conn, { type: "pending" });
      setTimeout(() => {
        conn.seated = true;
        send(conn, { type: "joined", role: "guest" });
      }, 150);
      return;
    }

    if (m.type === "knock") {
      if (POLICY === "honest") {
        const e = entry();
        if (e.owner) send(e.owner, { type: "knock", jid: conn.jid, payload: m.payload });
      } else {
        log(`  !! ${conn.label} knock swallowed (demote: nobody is owner)`);
      }
      return;
    }

    if (m.type === "admit" || m.type === "deny") {
      const e = entry();
      const target = e.sockets.find((c) => c.jid === m.jid);
      if (!target) return;
      if (m.type === "admit") { target.seated = true; send(target, { type: "joined", role: "guest" }); }
      else send(target, { type: "denied" });
      return;
    }

    if (m.type === "key" || m.type === "msg") {
      const e = entry();
      const peers = e.sockets.filter((c) => c !== conn);
      if (!peers.length) log(`  !! ${conn.label} ${m.type} dropped: no peer socket in room`);
      // HS_DELAY_MS holds signed handshakes back so BOTH are in flight before
      // either lands. Without it the first peer to receive one refuses and
      // closes the socket, so the second never receives a handshake at all and
      // its own check is never reached — which is not the same thing as the
      // check not firing there.
      let kind = "";
      try { kind = Object.keys(JSON.parse(Buffer.from(m.payload, "base64").toString())).join("+"); } catch { /* opaque */ }
      const delay = HS_DELAY_MS && /pub/.test(kind) ? HS_DELAY_MS : 0;
      for (const peer of peers) {
        if (delay) setTimeout(() => send(peer, m), delay);
        else send(peer, m);
      }
      return;
    }
  });

  ws.on("close", () => {
    log(`${conn.label} closed`);
    if (conn.room && rooms.has(conn.room)) {
      const e = rooms.get(conn.room);
      e.sockets = e.sockets.filter((c) => c !== conn);
      if (e.owner === conn) e.owner = null;
    }
  });
});

http.listen(PORT, "127.0.0.1", () => log(`hostile relay policy=${POLICY} on http://127.0.0.1:${PORT}`));
