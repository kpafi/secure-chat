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

// Which client tree to serve. Overridable so the harness can be pointed at a
// MUTATED copy of the client — which is how you show that a scenario here binds
// (i.e. that reintroducing the bug turns it red) without dirtying the working
// tree. A harness whose scenarios have never been shown to fail is decoration;
// this project has produced three rounds of green-but-vacuous controls already.
const ROOT = (process.env.CLIENT_ROOT
  ? process.env.CLIENT_ROOT
  : new URL("../../client/", import.meta.url).pathname).replace(/\/$/, "");
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
  if (!patch) {
    // Item 8, second half. `EVIL_MODE=none SCENARIO=attacker` used to serve the
    // shipped client under /evil/ with no warning and report a clean 9/9 — a
    // green that proves nothing, because there was no attacker in the run. The
    // combination is almost always a mistyped invocation, so say it in the log
    // AND in the served bytes, where the driver can see it.
    log("!! EVIL_MODE=none: /evil/ is serving the UNPATCHED shipped client.");
    log("!! Nothing is attacking in this run. A pass here is a CONTROL, not a proof.");
    return "globalThis.__HARNESS_EVIL_MODE__ = 'none';\n" + src;
  }
  // Fail loudly rather than silently serving an unpatched client: a harness
  // whose attacker quietly stopped attacking reports a green that means nothing.
  if (!src.includes(patch.anchor)) throw new Error(`evil patch anchor not found for mode ${EVIL_MODE}`);
  return src.replace(patch.anchor, patch.replace);
}

// ---- the directory (pentest 2026-08-08 item 8: close the harness gap) ------
//
// This harness used to serve NO /api/* routes, and proto001 never typed a
// handle — so `expectedPeerBundle` was null in every run and the entire
// directory-driven flow that item 14 is ABOUT was invisible end to end. Item 14
// deleted a route that skipped the approval prompt when the peer matched "the
// directory bundle for the contact you picked", on the grounds that a directory
// answer is unsigned and so is the attacker's to choose. Proving that at the
// unit level is not the same as proving the shipped client refuses.
//
//   honest  — answers with the bundle that identity actually registered.
//   hostile — answers a lookup for ANY handle with a DIFFERENT registered
//             identity's bundle: the "directory names alice and hands you
//             mallory's keys" configuration. The client must still prompt.
//
// The relay legitimately sees these bundles: they arrive in the registration and
// in the knock/hello frames. Nothing here needs a key the attacker could not
// have.
const DIRECTORY = process.env.DIRECTORY || "honest";
const directory = new Map();   // username -> bundle {ed, mldsa, ecdh?, mlkem?}
const LOOKUP_TOKEN = "harnesstoken";

function directoryAnswer(username) {
  const own = directory.get(username);
  if (DIRECTORY !== "hostile") return own || null;
  // Hand back somebody else's keys — the lie item 14 is about. Prefer a
  // genuinely different identity; if only one is registered there is no lie to
  // tell, and answering honestly would silently turn the attack scenario into a
  // control, so say so loudly instead.
  for (const [name, bundle] of directory) {
    if (name !== username) return bundle;
  }
  log(`!! DIRECTORY=hostile has no OTHER identity to answer "${username}" with —`,
    "the lookup is being answered honestly, so this run proves nothing about item 14");
  return own || null;
}

function readBody(req) {
  return new Promise((resolve) => {
    let b = "";
    req.on("data", (c) => { b += c; });
    req.on("end", () => resolve(b));
  });
}

const http = createServer(async (req, res) => {
  const url = new URL(req.url, "http://x");
  let p = decodeURIComponent(url.pathname);

  if (p.startsWith("/api/")) {
    const json = (code, obj) => {
      res.writeHead(code, { "content-type": "application/json" });
      res.end(JSON.stringify(obj));
    };
    if (p === "/api/register" && req.method === "POST") {
      let body;
      try { body = JSON.parse(await readBody(req)); } catch { return json(400, { detail: "bad json" }); }
      // No signature check: this is the attacker's directory. That is the point
      // — the client must not treat any of this as authenticated.
      directory.set(body.username, {
        ed: body.ed, mldsa: body.mldsa, ecdh: body.ecdh, mlkem: body.mlkem,
      });
      log(`api: register "${body.username}" (directory now: ${[...directory.keys()].join(", ")})`);
      return json(200, { status: "registered", username: body.username, lookup_token: LOOKUP_TOKEN });
    }
    const m = p.match(/^\/api\/users\/([^/]+)$/);
    if (m && req.method === "GET") {
      const name = m[1];
      const bundle = directoryAnswer(name);
      if (!bundle) { log(`api: lookup "${name}" -> 404`); return json(404, { detail: "not found" }); }
      const answeredAs = [...directory].find(([, b]) => b === bundle)?.[0];
      log(`api: lookup "${name}" -> ${DIRECTORY === "hostile" && answeredAs !== name
        ? `LIE (${answeredAs}'s keys)` : "honest"}`);
      return json(200, { username: name, ...bundle });
    }
    // The directory session. A hostile relay is free to mint whatever session it
    // likes — it owns this endpoint — so it simply says yes. Modelled at all only
    // because a client that registers a username then tries to log in, and a
    // failing login puts an error in the console that would otherwise be read as
    // a defect in the client under test.
    if (p === "/api/auth/challenge" && req.method === "POST") {
      await readBody(req);
      return json(200, { challenge: randomBytes(32).toString("base64") });
    }
    if (p === "/api/auth/verify" && req.method === "POST") {
      await readBody(req);   // signatures unchecked: this relay is the attacker
      return json(200, { token: "harness-session", ttl: 3600 });
    }
    if (p === "/api/auth/logout" && req.method === "POST") {
      await readBody(req);
      return json(200, { status: "ok" });
    }
    // A logged-in client polls its mailbox. Always empty: sealed async messages
    // are a different surface from the live-room admission this harness tests,
    // and an empty mailbox is a truthful answer a real relay can also give.
    if (p === "/api/mailbox" && req.method === "GET") {
      return json(200, { messages: [] });
    }
    // Anything else the client asks for is a gap in this harness, not a 404 the
    // real relay would produce. Say so rather than letting a silent 404 be read
    // as a tested path.
    log(`!! api: UNIMPLEMENTED ${req.method} ${p} — the harness does not model this route`);
    return json(501, { detail: "not implemented by the hostile harness" });
  }

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
