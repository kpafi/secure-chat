// A relay (and a directory) that never answer: the connect deadlines and the
// room screen's Cancel, in Chromium (pentest r6 R6-1 / r7 R7-3; the geometry of
// the r6 PoC scratchpad/pt6/e2e/poc-r6-hung-relay.mjs).
//
//   SECURE_CHAT_E2E_URL=http://127.0.0.1:8093 node e2e/hung-relay.mjs   (~2 min)
//
// A small proxy in this process forwards HTTP to the relay and accepts every
// WebSocket without ever answering it — a hostile relay, or a half-open
// connection. The page under test is loaded through the proxy. The directory
// lookup is held by request interception.
//
//   [1] Cancel on an unanswered socket: back on the room screen, Connect enabled
//   [2] the join deadline: after 30 s the socket is closed, the fixed sentence
//   [3] the directory lookup: Cancel aborts it (no socket); after 20 s the
//       fixed sentence
//   [4] the real relay (no proxy): an owner seated at once shows no Cancel;
//       a guest waiting in the admission queue is NOT timed out (40 s)
import http from "node:http";
import { WebSocketServer } from "ws";
import puppeteer from "puppeteer-core";
import { readFileSync } from "node:fs";

const cfg = JSON.parse(readFileSync(new URL("./test-users.json", import.meta.url)));
const APP = new URL(process.env.SECURE_CHAT_E2E_URL || cfg.relay);
const UP = { host: APP.hostname, port: Number(APP.port || 80) };
const PASS = "hung relay test passphrase words — e2e only";
const ID_PASS = cfg.users[0].passphrase;
const JOIN_SENTENCE =
  "The relay did not answer within 30 seconds, so this connection attempt was stopped — " +
  "nothing reached your contact. Check your connection and press Connect to try again.";
const LOOKUP_SENTENCE =
  "The directory did not answer within 20 seconds, so the contact lookup was stopped and nothing " +
  "was connected. Press Connect to try again — or leave the contact field blank and compare a " +
  "safety number instead.";
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const results = [];
function check(name, ok, detail = "") {
  results.push({ name, ok: !!ok });
  console.log(`    ${ok ? "OK  " : "FAIL"} ${name}${detail ? " — " + detail : ""}`);
}

// ---- the silent proxy -----------------------------------------------------------
const held = [];
const srv = http.createServer((req, res) => {
  const p = http.request({ ...UP, method: req.method, path: req.url,
    headers: { ...req.headers, host: APP.host, origin: APP.origin } }, (r) => { res.writeHead(r.statusCode, r.headers); r.pipe(res); });
  p.on("error", () => { res.writeHead(502); res.end(); });
  req.pipe(p);
});
const wss = new WebSocketServer({ noServer: true });
srv.on("upgrade", (req, sock, head) => wss.handleUpgrade(req, sock, head, (c) => {
  const h = { c, got: [], closed: false };
  held.push(h);
  c.on("message", (m) => h.got.push(m.toString()));
  c.on("close", () => { h.closed = true; });
}));
await new Promise((r) => srv.listen(0, "127.0.0.1", r));
const PROXY = `http://127.0.0.1:${srv.address().port}/`;

const browser = await puppeteer.launch({ executablePath: process.env.CHROMIUM || "/usr/bin/chromium", headless: "new",
  args: ["--no-sandbox", "--disable-dev-shm-usage"] });
async function mkPage(url) {
  const page = await (await browser.createBrowserContext()).newPage();
  page.on("dialog", async (d) => { await d.accept(); });
  await page.setViewport({ width: 390, height: 844, deviceScaleFactor: 1 });
  await page.goto(url, { waitUntil: "networkidle0", timeout: 60000 });
  await page.click("#toRoom");
  await page.waitForFunction(() => !document.querySelector("#scrRoom").hidden);
  await page.evaluate(() => {
    window.__shown = (el) => !!el && el.getClientRects().length > 0 && getComputedStyle(el).visibility !== "hidden";
    document.querySelector("#algDetails").open = true;
  });
  return page;
}
const setAlg = (page, alg) => page.evaluate((a) => { const r = document.querySelector(`input[name="alg"][value="${a}"]`); r.checked = true; r.dispatchEvent(new Event("change", { bubbles: true })); }, alg);
const setVal = (page, sel, v) => page.evaluate((s, v) => { const e = document.querySelector(s); e.value = v; e.dispatchEvent(new Event("input", { bubbles: true })); }, sel, v);
const tap = async (page, sel) => { await page.$eval(sel, (e) => e.scrollIntoView({ block: "center" })); await page.click(sel); };
const state = (page) => page.evaluate(() => ({
  room: __shown(document.querySelector("#scrRoom")),
  chat: __shown(document.querySelector("#scrChat")),
  cancel: __shown(document.querySelector("#connectCancel")),
  disconnect: __shown(document.querySelector("#disconnect")),
  connectDisabled: document.querySelector("#connect").disabled,
  status: document.querySelector("#status").textContent,
  hint: document.querySelector("#roomHint").textContent,
}));
const until = async (cond, ms = 5000) => { const t0 = Date.now(); while (!(await cond())) { if (Date.now() - t0 > ms) return false; await sleep(100); } return true; };

console.log(`\n=== a relay and a directory that never answer (${APP.origin} via ${PROXY}) ===`);

// ---- [1] Cancel on an unanswered socket ---------------------------------------------
console.log("\n  [1] Cancel while the relay has not answered join");
const page = await mkPage(PROXY);
{
  await setAlg(page, "AES256");
  await setVal(page, "#room", "ab".repeat(32));
  await setVal(page, "#pass", PASS);
  await tap(page, "#connect");
  const joined = await until(() => held.length === 1 && held[0].got.some((m) => /"join"/.test(m)));
  check("the proxy accepted the socket and got the join", joined);
  await sleep(1500);
  const s = await state(page);
  check("the stuck state of R6-1: room screen, Connect disabled, no Disconnect", s.room && !s.chat && s.connectDisabled && !s.disconnect, JSON.stringify(s));
  check("Cancel is shown", s.cancel);
  await tap(page, "#connectCancel");
  const closed = await until(() => held[0].closed);
  const a = await state(page);
  check("Cancel closed the socket", closed);
  check("back on the room screen: Connect enabled, Cancel hidden, disconnected, no sentence",
    a.room && !a.connectDisabled && !a.cancel && a.status === "disconnected" && a.hint === "", JSON.stringify(a));
}

// ---- [2] the join deadline -----------------------------------------------------------------
console.log("\n  [2] the 30 s join deadline");
{
  const t0 = Date.now();
  await tap(page, "#connect");
  await until(() => held.length === 2);
  const early = await until(async () => (await state(page)).hint === JOIN_SENTENCE, 25000);
  check("nothing is timed out before 25 s", !early);
  const done = await until(async () => (await state(page)).hint === JOIN_SENTENCE, 10000);
  const secs = (Date.now() - t0) / 1000;
  const s = await state(page);
  check("the fixed sentence at ~30 s", done && secs >= 29 && secs < 36, `${secs.toFixed(1)} s`);
  check("the socket is closed", await until(() => held[1].closed));
  check("room screen, Connect enabled, Cancel hidden, disconnected",
    s.room && !s.connectDisabled && !s.cancel && s.status === "disconnected", JSON.stringify(s));
}

// ---- [3] the directory lookup -----------------------------------------------------------------
console.log("\n  [3] a directory lookup that never answers");
{
  await page.evaluate(() => document.querySelector("#toIdentity").click());
  await setVal(page, "#idPass", ID_PASS);
  await tap(page, "#idCreate");
  await page.waitForFunction(() => document.querySelector("#idFingerprint").textContent.length > 0, { timeout: 60000 });
  await page.evaluate(() => document.querySelector("#toRoom").click());
  await page.setRequestInterception(true);
  const lookups = [];
  page.on("request", (r) => { if (r.url().includes("/api/users/")) lookups.push(r); else r.continue(); }); // held: never answered
  await setAlg(page, "DHKE");
  await page.evaluate(() => { document.querySelector("#expectRow").open = true; });
  await setVal(page, "#contact", "bob#a1b2c3d4");
  const sockets = held.length;
  await tap(page, "#connect");
  await until(() => lookups.length === 1);
  await sleep(500);
  const s = await state(page);
  check("looking up, Cancel shown", s.status === "looking up contact…" && s.cancel, JSON.stringify(s));
  await tap(page, "#connectCancel");
  const back = await until(async () => !(await state(page)).connectDisabled);
  const a = await state(page);
  check("Cancel ends the lookup: Connect enabled, Cancel hidden, no sentence, disconnected",
    back && !a.cancel && a.hint === "" && a.status === "disconnected", JSON.stringify(a));
  const t0 = Date.now();
  await tap(page, "#connect");
  const done = await until(async () => (await state(page)).hint === LOOKUP_SENTENCE, 30000);
  const secs = (Date.now() - t0) / 1000;
  const b = await state(page);
  check("the fixed sentence at ~20 s", done && secs >= 19 && secs < 26, `${secs.toFixed(1)} s`);
  check("Connect enabled, Cancel hidden", !b.connectDisabled && !b.cancel, JSON.stringify(b));
  await sleep(500);
  check("no socket was opened by either lookup", held.length === sockets, `${held.length - sockets} opened`);
}

// ---- [4] the real relay: answered, and waiting for admission ------------------------------------
console.log("\n  [4] the real relay: an owner seated, a guest waiting in the queue");
{
  const room = "cd".repeat(32);
  const owner = await mkPage(APP.href);
  const guest = await mkPage(APP.href);
  for (const p of [owner, guest]) { await setAlg(p, "AES256"); await setVal(p, "#room", room); await setVal(p, "#pass", PASS); }
  await tap(owner, "#connect");
  await owner.waitForFunction(() => /connected/.test(document.querySelector("#status").textContent) && !document.querySelector("#scrChat").hidden, { timeout: 30000 });
  await owner.evaluate(() => document.querySelector("#toRoom").click());
  const o = await state(owner);
  check("control: an owner the relay seated sees no Cancel on ‹ Back to room", o.room && !o.cancel, JSON.stringify(o));
  await owner.evaluate(() => document.querySelector("#toChat") && document.querySelector("#toChat").click());
  await tap(guest, "#connect");
  await guest.waitForFunction(() => /waiting for approval/.test(document.querySelector("#status").textContent), { timeout: 30000 });
  await sleep(40000);
  const g = await state(guest);
  check("a guest waiting 40 s for admission is still waiting (not timed out)",
    g.chat && /waiting for approval/.test(g.status) && g.disconnect && !g.hint.includes("did not answer"), JSON.stringify(g));
  await guest.evaluate(() => document.querySelector("#disconnect").click());
  await owner.evaluate(() => { const d = document.querySelector("#disconnect"); if (d) d.click(); });
}

await browser.close();
for (const h of held) { try { h.c.terminate(); } catch {} }
srv.close();
const failed = results.filter((r) => !r.ok);
console.log(`\n${results.length - failed.length}/${results.length} checks passed`);
if (failed.length) { console.log("  FAILED: " + failed.map((f) => f.name).join("; ")); process.exit(1); }
