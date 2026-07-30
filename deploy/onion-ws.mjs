// Relay round trip over the .onion, with no npm dependencies.
//
// Node's built-in WebSocket cannot speak through a SOCKS proxy, and the e2e
// suite's puppeteer-core is not installed, so this drives the relay over a raw
// socket: SOCKS5 CONNECT to the onion, a hand-rolled RFC 6455 handshake, then
// the actual owner-approved admission protocol from backend/main.py.
//
//   node onion-ws.mjs <onion-host>
//
// Asserts: the WS upgrade succeeds through Tor, the onion Origin is on the
// allow-list, a foreign Origin is still refused (the CSWSH guard did not get
// loosened by adding the onion), and two peers relay a payload end to end.
import net from "node:net";
import crypto from "node:crypto";

const ONION = process.argv[2];
if (!ONION) throw new Error("usage: node onion-ws.mjs <onion-host>");
const SOCKS = { host: "127.0.0.1", port: 9050 };
const TIMEOUT = 90_000;

const results = [];
const check = (name, ok, detail = "") => {
  results.push({ name, ok });
  console.log(`  ${ok ? "OK  " : "FAIL"} ${name}${detail ? " — " + detail : ""}`);
};

function socks5Connect(host, port) {
  return new Promise((resolve, reject) => {
    const sock = net.connect(SOCKS.port, SOCKS.host);
    sock.setTimeout(TIMEOUT, () => reject(new Error("socks timeout")));
    sock.on("error", reject);
    sock.once("connect", () => sock.write(Buffer.from([0x05, 0x01, 0x00])));
    sock.once("data", (greeting) => {
      if (greeting[0] !== 0x05 || greeting[1] !== 0x00) {
        return reject(new Error(`socks greeting refused: ${[...greeting]}`));
      }
      const name = Buffer.from(host, "ascii");
      const req = Buffer.concat([
        Buffer.from([0x05, 0x01, 0x00, 0x03, name.length]),
        name,
        Buffer.from([(port >> 8) & 0xff, port & 0xff]),
      ]);
      sock.once("data", (reply) => {
        // 0x00 = succeeded; anything else is a Tor-side failure (0x04 = host
        // unreachable, which is what an unpublished descriptor looks like).
        if (reply[1] !== 0x00) return reject(new Error(`socks connect failed: code ${reply[1]}`));
        resolve(sock);
      });
      sock.write(req);
    });
  });
}

// One WebSocket connection: SOCKS -> HTTP upgrade -> framed JSON.
async function wsConnect(host, { origin }) {
  const sock = await socks5Connect(host, 80);
  const key = crypto.randomBytes(16).toString("base64");
  const headers = [
    "GET /ws HTTP/1.1",
    `Host: ${host}`,
    "Upgrade: websocket",
    "Connection: Upgrade",
    `Sec-WebSocket-Key: ${key}`,
    "Sec-WebSocket-Version: 13",
  ];
  if (origin) headers.push(`Origin: ${origin}`);
  sock.write(headers.join("\r\n") + "\r\n\r\n");

  // Read the HTTP response head, keeping any frame bytes that arrived with it.
  const status = await new Promise((resolve, reject) => {
    let buf = Buffer.alloc(0);
    const onData = (chunk) => {
      buf = Buffer.concat([buf, chunk]);
      const end = buf.indexOf("\r\n\r\n");
      if (end === -1) return;
      sock.off("data", onData);
      const head = buf.subarray(0, end).toString("ascii");
      resolve({ code: parseInt(head.split(" ")[1], 10), rest: buf.subarray(end + 4) });
    };
    sock.on("data", onData);
    sock.on("error", reject);
    // Pentest 2026-07-29 M-3: this used to resolve `{code: 0}` and say nothing
    // more, so a socket that died before the header terminator — a Tor hiccup,
    // a relay restart, the connection cap — was indistinguishable from "the
    // server refused the upgrade". The one security assertion in this file
    // (`!foreign.upgraded`) was satisfied by BOTH, so it passed vacuously; it
    // was proved green at HTTP 0 with the CSWSH guard never exercised. Flag the
    // difference so callers can refuse to draw a conclusion from a dead socket.
    sock.on("close", () => resolve({ code: 0, rest: Buffer.alloc(0), transportFailed: true }));
    setTimeout(() => reject(new Error("upgrade timeout")), TIMEOUT);
  });

  if (status.code !== 101) {
    sock.destroy();
    return { upgraded: false, code: status.code, transportFailed: !!status.transportFailed };
  }

  const inbox = [];
  const waiters = [];
  let buf = status.rest;
  const drain = () => {
    // Server->client frames are never masked; we only ever get small text ones.
    while (buf.length >= 2) {
      const opcode = buf[0] & 0x0f;
      let len = buf[1] & 0x7f;
      let off = 2;
      if (len === 126) { len = buf.readUInt16BE(2); off = 4; }
      else if (len === 127) { len = Number(buf.readBigUInt64BE(2)); off = 10; }
      if (buf.length < off + len) return;
      const payload = buf.subarray(off, off + len);
      buf = buf.subarray(off + len);
      if (opcode === 0x1) {
        const text = payload.toString("utf8");
        if (waiters.length) waiters.shift().resolve(text);
        else inbox.push(text);
      } else if (opcode === 0x8) {
        while (waiters.length) waiters.shift().reject(new Error("closed by peer"));
      }
    }
  };
  sock.on("data", (c) => { buf = Buffer.concat([buf, c]); drain(); });
  sock.on("close", () => { while (waiters.length) waiters.shift().reject(new Error("socket closed")); });
  drain();

  return {
    upgraded: true,
    send(obj) {
      const body = Buffer.from(JSON.stringify(obj), "utf8");
      const mask = crypto.randomBytes(4);
      const masked = Buffer.from(body.map((b, i) => b ^ mask[i % 4]));
      let header;
      if (body.length < 126) header = Buffer.from([0x81, 0x80 | body.length]);
      else {
        header = Buffer.alloc(4);
        header[0] = 0x81; header[1] = 0xfe; header.writeUInt16BE(body.length, 2);
      }
      sock.write(Buffer.concat([header, mask, masked]));
    },
    next() {
      if (inbox.length) return Promise.resolve(inbox.shift());
      return new Promise((resolve, reject) => {
        waiters.push({ resolve, reject });
        setTimeout(() => reject(new Error("timed out waiting for a frame")), TIMEOUT);
      });
    },
    close() { sock.destroy(); },
  };
}

const room = crypto.randomBytes(32).toString("hex");
const onionOrigin = `http://${ONION}`;

console.log(`\nrelay round trip over ${ONION}\n`);

// 1) The onion origin must be accepted (it is in SECURE_CHAT_EXTRA_ORIGINS).
const owner = await wsConnect(ONION, { origin: onionOrigin });
check("WS upgrade through Tor with the onion Origin", owner.upgraded, `HTTP ${owner.code ?? 101}`);
if (!owner.upgraded) process.exit(1);

owner.send({ type: "join", room });
const ownerJoined = JSON.parse(await owner.next());
check("first peer owns the room", ownerJoined.type === "joined" && ownerJoined.role === "owner",
  JSON.stringify(ownerJoined));

// 2) Second peer is queued, not seated (P-08).
const guest = await wsConnect(ONION, { origin: onionOrigin });
guest.send({ type: "join", room });
const guestPending = JSON.parse(await guest.next());
check("second peer is queued, not seated", guestPending.type === "pending", JSON.stringify(guestPending));

// 3) Knock -> owner sees it -> admit.
const intro = Buffer.from("onion-probe-introduction").toString("base64");
guest.send({ type: "knock", room, payload: intro });
const knock = JSON.parse(await owner.next());
check("owner receives the knock verbatim", knock.type === "knock" && knock.payload === intro,
  JSON.stringify(knock).slice(0, 120));

owner.send({ type: "admit", room, jid: knock.jid });
const seated = JSON.parse(await guest.next());
check("admitted peer is seated as guest", seated.type === "joined" && seated.role === "guest",
  JSON.stringify(seated));

// 4) The actual point: an opaque payload relayed between two onion peers.
const ciphertext = crypto.randomBytes(48).toString("base64");
guest.send({ type: "msg", room, payload: ciphertext, alg: "AES256" });
const relayed = JSON.parse(await owner.next());
check("payload relayed guest -> owner unchanged", relayed.type === "msg" && relayed.payload === ciphertext);

const back = crypto.randomBytes(48).toString("base64");
owner.send({ type: "msg", room, payload: back, alg: "AES256" });
const relayedBack = JSON.parse(await guest.next());
check("payload relayed owner -> guest unchanged", relayedBack.type === "msg" && relayedBack.payload === back);

owner.close();
guest.close();

// 5) The CSWSH guard must still be closed: adding the onion must not have
//    turned the allow-list into "anything goes".
//
//    Pentest 2026-07-29 M-3. `!foreign.upgraded` on its own proves nothing —
//    every transport failure satisfies it. Asserting `code === 403` instead is
//    ALSO unsound: main.py closes on a bad origin and on the connection cap
//    before `accept()`, and uvicorn collapses both to 403, so a capped relay
//    would "pass" this check while the guard was never consulted.
//
//    What distinguishes "the guard rejected it" from "the transport is dead" is
//    a POSITIVE CONTROL in the same pass: an allowed Origin must upgrade right
//    now, over the same Tor circuit-building path, or the negative result is
//    not evidence. Run the control immediately AFTER the foreign attempt, so a
//    failure in between cannot make the pair look good.
const foreign = await wsConnect(ONION, { origin: "http://evil.example.com" });
if (foreign.upgraded) foreign.close();
const control = await wsConnect(ONION, { origin: onionOrigin });
if (control.upgraded) control.close();

check(
  "positive control: an allowed Origin upgrades right now",
  control.upgraded,
  control.transportFailed
    ? "transport died — the refusal below proves nothing"
    : `HTTP ${control.code ?? 101}`,
);
check(
  "foreign Origin still refused over the onion",
  // All three, together: the foreign attempt was actually answered by the
  // server (not a dead socket), it was refused, and an allowed Origin got
  // through on the same run.
  !foreign.upgraded && !foreign.transportFailed && foreign.code > 0 && control.upgraded,
  foreign.transportFailed
    ? "INCONCLUSIVE: socket closed before any HTTP status"
    : `HTTP ${foreign.code}`,
);

// A native client sending no Origin at all is allowed by design (documented).
const noOrigin = await wsConnect(ONION, { origin: null });
check("absent Origin still accepted (native clients, by design)", noOrigin.upgraded);
if (noOrigin.upgraded) noOrigin.close();

const failed = results.filter((r) => !r.ok);
console.log(`\n${results.length - failed.length}/${results.length} checks passed\n`);
process.exit(failed.length ? 1 : 0);
