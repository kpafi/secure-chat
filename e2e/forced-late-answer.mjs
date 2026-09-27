// A relay's key exchange before it answered `join`, and its answer handled
// after its own close, in Chromium.
//
//   node e2e/forced-late-answer.mjs            (~40 s; no relay needed)
//
// Served from this process: client/ as static files and a raw WebSocket relay
// on /ws. Each attempt's relay: on `join` it sends a peer hello (and, per
// case, first an honest `pending`, or instead of the hello a handshake signed
// by its own identity); if the page answers the hello it sends that handshake;
// then, after a pause, its answer to `join`, Close and FIN.
//
// Early key (owner decision 2026-09-27, pentest C3-2 r2 "pre-existing lead").
// With no answer to `join` the page used to answer the hello and raise the
// guest approval prompt for the relay's handshake inside the hidden chat
// screen: invisible (0×0), the tab bar inert, the pump parked on it until the
// close — the lever that forced the relay's answer behind its own close (C3-2
// r1 R1-2). Now the first `key` frame ends the attempt at once:
//   owner / pending / roleless   a hello first; then that answer
//   handshake                    a signed handshake first; then joined:owner
//     -> the fixed sentence on the room screen before the relay's answer,
//        nothing of the key exchange sent, no prompt, the tab bar never inert;
//        the answer and close that follow change nothing
//
// Forced late answer (pentest r3 C3-2; C3-2 r1 R1-2), still forceable after
// an honest `pending` — the prompt is then drawn over the chat screen:
//   pguest   pending, hello, handshake, then joined:guest behind the prompt
//     -> the prompt is visible; no false "without approving" refusal; back on
//        the room screen (before the fix 495a12f: the false refusal)
//   psecond  pending, hello, handshake, then a second handshake (another
//            identity) behind the prompt, and the close
//     -> the frame dispatched after the close is dropped: no prompt on the
//        room screen (before e919018: 0×0, the tab bar inert)
import http from "node:http";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import puppeteer from "puppeteer-core";

const DIR = path.resolve(process.env.CLIENT_DIR || path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "client"));
const { Identity } = await import(path.join(DIR, "identity.js"));
const { signHandshake } = await import(path.join(DIR, "auth.js"));
const PORT = Number(process.env.PORT || 8795);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const results = [];
function check(name, ok, detail = "") {
  results.push({ name, ok: !!ok });
  console.log(`  ${ok ? "OK  " : "FAIL"} ${name}${detail ? " — " + detail : ""}`);
}

// ---- the static server and the hostile relay ------------------------------------
const MIME = { ".html": "text/html", ".js": "text/javascript", ".mjs": "text/javascript", ".css": "text/css",
  ".json": "application/json", ".svg": "image/svg+xml", ".png": "image/png", ".webmanifest": "application/manifest+json" };
const frame = (o) => {
  const pl = Buffer.from(JSON.stringify(o));
  const h = pl.length < 126 ? Buffer.from([0x81, pl.length]) : Buffer.from([0x81, 126, pl.length >> 8, pl.length & 255]);
  return Buffer.concat([h, pl]);
};
const CLOSE = Buffer.from([0x88, 0x02, 0x03, 0xe8]); // Close, 1000
const b64 = (o) => Buffer.from(JSON.stringify(o)).toString("base64");
const unb = (s) => JSON.parse(Buffer.from(s, "base64").toString());
const ANSWERS = {
  owner: [{ type: "joined", role: "owner" }],
  pending: [{ type: "pending" }],
  roleless: [{ type: "joined" }],
  handshake: [{ type: "joined", role: "owner" }],
  pguest: [{ type: "joined", role: "guest" }],
  psecond: [], // a second handshake instead (below)
};
const EARLY_KEY =
  "The relay passed on a key exchange before it had let you into the room \u2014 an honest relay " +
  "never does that, so this connection attempt was stopped and nothing was exchanged. " +
  "Press Connect to try again.";
const relayId = await Identity.generate();
const relayId2 = await Identity.generate(); // psecond: another identity, queued behind the prompt
let mode = "owner";
const seen = []; // what the relay received, per attempt
const srv = http.createServer((req, res) => {
  let p = decodeURIComponent(new URL(req.url, "http://x").pathname);
  if (p.startsWith("/api/")) { res.writeHead(404, { "content-type": "application/json" }); return res.end("{}"); }
  if (p === "/") p = "/index.html";
  const f = path.join(DIR, path.normalize(p));
  if (!f.startsWith(DIR) || !fs.existsSync(f) || fs.statSync(f).isDirectory()) { res.writeHead(404); return res.end(); }
  res.writeHead(200, { "content-type": MIME[path.extname(f)] || "application/octet-stream" });
  fs.createReadStream(f).pipe(res);
});
const socks = [];
srv.on("upgrade", (req, sock) => {
  socks.push(sock);
  sock.on("error", () => {});
  const acc = crypto.createHash("sha1").update(req.headers["sec-websocket-key"] + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").digest("base64");
  sock.write("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " + acc + "\r\n\r\n");
  const answer = ANSWERS[mode];
  const queuedFirst = mode === "pguest" || mode === "psecond"; // an honest `pending` before the key exchange
  let buf = Buffer.alloc(0), room = null, nonce = null, done = false;
  // The answer, Close and FIN: after the handshake for pguest (the prompt is
  // up, the pump parked on it), else a fixed pause after the early key frame —
  // long enough that a page that refuses at once has done so well before.
  const answerLater = (ms, extra = []) => setTimeout(() => { relay.answeredAt = Date.now(); sock.end(Buffer.concat([...extra, ...answer.map(frame), CLOSE])); }, ms);
  const handshake = async (peerN, id = relayId) => {
    const pub = crypto.randomBytes(32).toString("base64");
    const sig = await signHandshake(id, room, [peerN, nonce], pub);
    return frame({ type: "key", room, alg: "DHKE", payload: b64({ pub, reply: true, idb: id.publicBundle(), sig }) });
  };
  sock.on("data", async (d) => {
    buf = Buffer.concat([buf, d]);
    for (;;) {
      if (buf.length < 2) return;
      const op = buf[0] & 15;
      let len = buf[1] & 0x7f, off = 2;
      if (len === 126) { if (buf.length < 4) return; len = buf.readUInt16BE(2); off = 4; }
      if (buf.length < off + 4 + len) return;
      const mask = buf.subarray(off, off + 4);
      const pl = Buffer.from(buf.subarray(off + 4, off + 4 + len));
      for (let i = 0; i < pl.length; i++) pl[i] ^= mask[i & 3];
      buf = buf.subarray(off + 4 + len);
      if (op !== 1) continue;
      const f = JSON.parse(pl.toString());
      seen.push(f.type);
      if (f.type === "join") {
        room = f.room;
        nonce = crypto.randomBytes(32).toString("base64");
        if (queuedFirst) sock.write(frame({ type: "pending" }));
        if (mode === "handshake") sock.write(await handshake(crypto.randomBytes(32).toString("base64")));
        else sock.write(frame({ type: "key", room, alg: "DHKE", payload: b64({ hello: true, n: nonce, reply: false }) }));
        if (!queuedFirst) answerLater(2500);
      } else if (f.type === "key" && !done) {
        const p = unb(f.payload);
        if (!(p.hello && p.reply)) continue;
        done = true;
        sock.write(await handshake(p.n)); // the old page raised the prompt for this
        if (mode === "psecond") answerLater(800, [await handshake(p.n, relayId2)]);
        else if (queuedFirst) answerLater(800);
      }
    }
  });
});
const relay = { answeredAt: 0 };
await new Promise((r) => srv.listen(PORT, "127.0.0.1", r));

// ---- the page -------------------------------------------------------------------
const browser = await puppeteer.launch({
  executablePath: process.env.CHROMIUM || "/usr/bin/chromium",
  headless: "new",
  args: ["--no-sandbox", "--disable-dev-shm-usage"],
});
const errors = [];
const page = await (await browser.createBrowserContext()).newPage();
page.on("pageerror", (e) => errors.push(e.message));
await page.evaluateOnNewDocument(() => {
  window.__trail = [];
  const W = window.WebSocket;
  window.WebSocket = class extends W {
    constructor(...a) {
      super(...a);
      window.__ws = this;
      // The log as the close event found it (pentest C3-2 r3, test gap 2): the
      // late answer is handled after this, so a change from here on is its own.
      this.addEventListener("close", () => {
        window.__trail.push("close-event");
        const log = document.querySelector("#log");
        window.__logAtClose = log ? [...log.children].map((e) => e.textContent) : null;
      });
    }
  };
});
await page.goto(`http://127.0.0.1:${PORT}/`, { waitUntil: "networkidle0" });
await page.type("#idPass", "forced late answer — e2e only passphrase");
await page.click("#idCreate");
await page.waitForFunction(() => !document.querySelector("#idExport").hidden, { timeout: 60000 });
await page.evaluate(() => document.querySelector("#toRoom").click());
await page.evaluate(() => {
  document.querySelector("#algDetails").open = true;
  const r = document.querySelector('input[name="alg"][value="DHKE"]');
  r.checked = true;
  r.dispatchEvent(new Event("change", { bubbles: true }));
  const room = document.querySelector("#room");
  room.value = "5d".repeat(32); // typed over: not a code this page minted
  room.dispatchEvent(new Event("input", { bubbles: true }));
  // The prompt going up (with its size on screen) and down, and the tab bar
  // going inert, in order with the close event.
  const ad = document.querySelector("#admit");
  new MutationObserver(() => {
    window.__trail.push("admit.hidden=" + ad.hidden);
    if (!ad.hidden) { const r = ad.getBoundingClientRect(); window.__trail.push("admit.box=" + Math.round(r.width) + "x" + Math.round(r.height)); }
  }).observe(ad, { attributes: true, attributeFilter: ["hidden"] });
  const tb = document.querySelector("#tabbar");
  new MutationObserver(() => window.__trail.push("tabbar.inert=" + tb.inert)).observe(tb, { attributes: true, attributeFilter: ["inert"] });
});
const state = () => page.evaluate(() => ({
  chat: !document.querySelector("#scrChat").hidden,
  status: document.querySelector("#status").textContent,
  connectDisabled: document.querySelector("#connect").disabled,
  rs: window.__ws && window.__ws.readyState,
  roomHint: document.querySelector("#roomHint").textContent,
  log: [...document.querySelectorAll("#log > *")].map((e) => e.textContent),
  trail: window.__trail.splice(0),
  logAtClose: window.__logAtClose,
}));

async function attempt(m) {
  mode = m;
  seen.length = 0;
  relay.answeredAt = 0;
  // A build that failed a previous case may have left a chat screen up: the
  // app bar's #toRoom goes back, so every case starts from Connect.
  await page.evaluate(() => { if (!document.querySelector("#scrChat").hidden) document.querySelector("#toRoom").click(); });
  const logBefore = (await state()).log;
  await page.evaluate(() => { window.__logAtClose = undefined; });
  await page.$eval("#connect", (e) => e.click());
  let early = null;
  if (m !== "pguest" && m !== "psecond") {
    // The refusal, at once: sampled as soon as the sentence is up, before the
    // relay's answer (2.5 s after its key frame).
    await page.waitForFunction((t) => document.querySelector("#roomHint").textContent === t, { timeout: 2400 }, EARLY_KEY).catch(() => {});
    early = { ...(await state()), beforeAnswer: relay.answeredAt === 0 };
  }
  await page.waitForFunction(() => window.__trail.includes("close-event"), { timeout: 15000 }).catch(() => {});
  await sleep(1000);
  const s = await state();
  s.newLog = s.log.slice(logBefore.length);
  // The whole log's text, not just its new lines: addLine folds a repeated
  // line into "(×2)" in place (pentest C3-2 r2 R2-3); compared with the log
  // as the close event found it, so only the late answer's effect counts (r3).
  s.logUnchanged = Array.isArray(s.logAtClose) && JSON.stringify(s.log) === JSON.stringify(s.logAtClose);
  if (early) { s.early = early; s.trail = [...early.trail, ...s.trail]; return s; }
  // Fixture: the relay really parked the pump before its answer — the prompt
  // went up, and came down only at the close event (onclose settles it).
  const up = s.trail.indexOf("admit.hidden=false"), closed = s.trail.indexOf("close-event");
  const downEarly = up >= 0 && closed > up && s.trail.slice(up + 1, closed).includes("admit.hidden=true");
  check(`fixture (${m}): the approval prompt parked the pump until the relay's close, the answer behind it`,
    up >= 0 && closed > up && !downEarly && s.trail.slice(closed).includes("admit.hidden=true") && s.rs === 3 && seen.includes("key"),
    JSON.stringify({ trail: s.trail, rs: s.rs, seen }));
  return s;
}
const onRoom = (s) => !s.chat && s.status === "disconnected" && !s.connectDisabled;
const brief = (s) => JSON.stringify({ chat: s.chat, status: s.status, connectDisabled: s.connectDisabled, roomHint: s.roomHint.slice(0, 70), newLog: (s.newLog || []).map((l) => l.slice(0, 60)) });

console.log(`\n=== key exchange before the relay answered join (http://127.0.0.1:${PORT}) ===\n`);

for (const m of ["owner", "pending", "roleless", "handshake"]) {
  console.log(`${m}: ${m === "handshake" ? "a signed handshake" : "a hello"} before the answer${m === "handshake" ? "" : " (" + JSON.stringify(ANSWERS[m][0]) + ")"}`);
  const s = await attempt(m);
  const e = s.early;
  check(`2026-09-27 (${m}): refused at once — the fixed sentence on the room screen, Connect enabled, before the relay's answer`,
    e.roomHint === EARLY_KEY && onRoom(e) && e.beforeAnswer, brief(e));
  check(`2026-09-27 (${m}): nothing of the key exchange went back (the relay saw only join)`,
    JSON.stringify(seen) === '["join"]', JSON.stringify(seen));
  check(`2026-09-27 (${m}): no approval prompt, and the tab bar never went inert`,
    !s.trail.some((t) => t === "admit.hidden=false" || t === "tabbar.inert=true"), JSON.stringify(s.trail));
  check(`2026-09-27 (${m}): the answer and close that follow change nothing (same sentence, no seat, no "joined room")`,
    s.roomHint === EARLY_KEY && onRoom(s) && !s.log.some((l) => /^joined room/.test(l)), brief(s));
}

console.log(`\n=== the answer to join, handled after the relay's own close ===\n`);
console.log("pguest: an honest pending, then joined:guest behind the prompt");
{
  const s = await attempt("pguest");
  const box = s.trail.find((t) => t.startsWith("admit.box="));
  check("fixture: the honest pending was handled while the socket was open (its knock reached the relay)", seen.includes("knock"), JSON.stringify(seen));
  check("2026-09-27: after `pending` the prompt is drawn on screen (not 0×0)",
    !!box && !/=0x|x0$/.test(box), JSON.stringify(s.trail));
  check("C3-2: no false 'put you in the room without the owner approving you' after an honest pending",
    !/without the owner approving you/.test(s.roomHint) && !s.newLog.some((l) => /without ever asking to be let in/.test(l)), brief(s));
  check("C3-2: back on the room screen, Connect enabled", onRoom(s), brief(s));
  check("2026-09-27: no prompt after the close", !s.trail.slice(s.trail.indexOf("close-event")).includes("admit.hidden=false"), JSON.stringify(s.trail));
}

console.log("\npsecond: a second handshake (another identity) queued behind the prompt, then the close");
{
  const s = await attempt("psecond");
  const after = s.trail.slice(s.trail.indexOf("close-event"));
  check("pentest early-key r1 T1: the handshake dispatched after the close raises no prompt on the room screen, nothing goes inert",
    !after.includes("admit.hidden=false") && !after.includes("tabbar.inert=true") && after.includes("tabbar.inert=false"), JSON.stringify(s.trail));
  check("pentest early-key r1 T1: back on the room screen, Connect enabled, nothing narrated after the close", onRoom(s) && s.logUnchanged, brief(s));
}

await browser.close();
socks.forEach((s) => s.destroy());
srv.close();

console.log("\n=== summary ===");
const failed = results.filter((r) => !r.ok);
for (const e of errors.slice(0, 5)) console.log("  [pageerror]", e);
console.log(`  ${results.length - failed.length}/${results.length} checks passed`);
if (failed.length) {
  console.log("  FAILED: " + failed.map((f) => f.name).join("; "));
  process.exit(1);
}
console.log("  all good\n");
