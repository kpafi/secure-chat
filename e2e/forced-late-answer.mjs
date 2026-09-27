// The relay's answer to `join` handled AFTER the relay's own close, forced in
// Chromium (pentest r3 C3-2, made relay-forceable by C3-2 r1 R1-2; the PoC
// scratchpad e2e/poc-forced-late.mjs of that round).
//
//   node e2e/forced-late-answer.mjs            (~40 s; no relay needed)
//
// Frames of a socket the RELAY closed are still handled (e2e/hostile-relay.mjs
// sections 6 and 8), so a hostile relay can park the page's message pump and
// hang up with its answer queued behind it:
//   1. before answering `join` it sends a peer hello — the page answers with
//      its own hello (its session nonce);
//   2. it sends a handshake signed by its OWN identity over the room and both
//      nonces; it verifies, and with no role yet the page asks the user
//      whether to talk to that key (the guest approval prompt) — the pump is
//      parked on the answer;
//   3. it sends its answer to `join`, then Close and FIN;
//   4. onclose settles the prompt as "no", and the pump resumes on a CLOSED
//      socket, where it meets the answer.
// Served from this process: client/ as static files and a raw WebSocket relay
// on /ws. Before the fix (495a12f): `joined:owner` drew "connected" for the
// dead socket (Disconnect did nothing), `pending` then `joined:guest` accused
// the relay of seating us unqueued, and a late `pending` sat on "waiting for
// approval". Each case:
//   owner     joined:owner  -> the room screen stays, nothing narrated
//   pguest    pending, then joined:guest -> no false "without approving" refusal
//   pending   pending       -> no "waiting for approval" chat for the dead socket
//   roleless  joined (no role) -> its refusal, which reads nothing onclose
//             reset, still reaches the room screen (as L2 wants)
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
  pguest: [{ type: "joined", role: "guest" }],
  pending: [{ type: "pending" }],
  roleless: [{ type: "joined" }],
};
const relayId = await Identity.generate();
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
  const queuedFirst = mode === "pguest"; // an honest `pending` before the prompt
  let buf = Buffer.alloc(0), room = null, nonce = null, done = false;
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
        sock.write(frame({ type: "key", room, alg: "DHKE", payload: b64({ hello: true, n: nonce, reply: false }) }));
      } else if (f.type === "key" && !done) {
        const p = unb(f.payload);
        if (!(p.hello && p.reply)) continue;
        done = true;
        const pub = crypto.randomBytes(32).toString("base64");
        const sig = await signHandshake(relayId, room, [p.n, nonce], pub);
        sock.write(frame({ type: "key", room, alg: "DHKE", payload: b64({ pub, reply: true, idb: relayId.publicBundle(), sig }) }));
        await sleep(800); // the prompt is up; the pump is parked on it
        sock.end(Buffer.concat([...answer.map(frame), CLOSE]));
      }
    }
  });
});
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
      this.addEventListener("close", () => window.__trail.push("close-event"));
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
  // The prompt going up and down, in order with the close event.
  const ad = document.querySelector("#admit");
  new MutationObserver(() => window.__trail.push("admit.hidden=" + ad.hidden)).observe(ad, { attributes: true, attributeFilter: ["hidden"] });
});
const state = () => page.evaluate(() => ({
  chat: !document.querySelector("#scrChat").hidden,
  status: document.querySelector("#status").textContent,
  connectDisabled: document.querySelector("#connect").disabled,
  rs: window.__ws && window.__ws.readyState,
  roomHint: document.querySelector("#roomHint").textContent,
  log: [...document.querySelectorAll("#log > *")].map((e) => e.textContent),
  trail: window.__trail.splice(0),
}));

async function attempt(m) {
  mode = m;
  seen.length = 0;
  // A build that failed a previous case may have left a chat screen up:
  // ‹ Back to room, so every case starts from Connect.
  await page.evaluate(() => { if (!document.querySelector("#scrChat").hidden) document.querySelector("#toRoom").click(); });
  const logBefore = (await state()).log;
  await page.$eval("#connect", (e) => e.click());
  await page.waitForFunction(() => window.__trail.includes("close-event"), { timeout: 15000 }).catch(() => {});
  await sleep(1000);
  const s = await state();
  s.newLog = s.log.slice(logBefore.length);
  // The whole log's text, not just its new lines: addLine folds a repeated
  // line into "(×2)" in place (pentest C3-2 r2 R2-3).
  s.logUnchanged = JSON.stringify(s.log) === JSON.stringify(logBefore);
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
const brief = (s) => JSON.stringify({ chat: s.chat, status: s.status, connectDisabled: s.connectDisabled, roomHint: s.roomHint.slice(0, 70), newLog: s.newLog.map((l) => l.slice(0, 60)) });

console.log(`\n=== the answer to join, handled after the relay's own close (http://127.0.0.1:${PORT}) ===\n`);

console.log("owner: joined:owner behind the prompt");
{
  const s = await attempt("owner");
  check("C3-2: the room screen stays — no 'connected' chat for the dead socket, Connect enabled", onRoom(s), brief(s));
  check("C3-2: the late seat is not narrated (the log is unchanged)", s.logUnchanged, brief(s));
  await page.evaluate(() => { const d = document.querySelector("#disconnect"); if (!document.querySelector("#scrChat").hidden) d.click(); });
  await sleep(300);
  check("C3-2: ...and it is still the room screen (no chat left whose Disconnect does nothing)", onRoom(await state()));
}

console.log("\npguest: an honest pending, then joined:guest behind the prompt");
{
  const s = await attempt("pguest");
  check("fixture: the honest pending was handled while the socket was open (its knock reached the relay)", seen.includes("knock"), JSON.stringify(seen));
  check("C3-2: no false 'put you in the room without the owner approving you' after an honest pending",
    !/without the owner approving you/.test(s.roomHint) && !s.newLog.some((l) => /without ever asking to be let in/.test(l)), brief(s));
  check("C3-2: back on the room screen, Connect enabled", onRoom(s), brief(s));
}

console.log("\npending: pending behind the prompt");
{
  const s = await attempt("pending");
  check("C3-2 r1 R1-1: no 'waiting for approval' chat screen for the dead socket", onRoom(s), brief(s));
  check("C3-2 r1 R1-1: the late pending is not narrated (the log is unchanged, no \"(×2)\" fold either)", s.logUnchanged, brief(s));
}

console.log("\nroleless: an older relay's bare joined behind the prompt");
{
  const s = await attempt("roleless");
  check("C3-2 r1 R1-4: a refusal that reads nothing onclose reset still reaches the room screen",
    /^This relay is running an older protocol without the join-approval step/.test(s.roomHint) && onRoom(s), brief(s));
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
