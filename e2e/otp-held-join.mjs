// A relay that holds the owner's `join`: the OTP sheets and the chat screen
// coming up under them (pentest r7, R7-1 and R7-2; the geometry of the PoC
// scratchpad/pt7/e2e/poc-r7-held-join.mjs).
//
//   SECURE_CHAT_E2E_URL=http://127.0.0.1:8093 node e2e/otp-held-join.mjs
//
// A small proxy in this process forwards HTTP and WebSocket traffic to the
// relay, but holds each WebSocket's upstream connection until released — the
// owner's `join` then waits, as on a slow or hostile relay. The owner page is
// loaded through the proxy; the guest talks to the relay directly.
//
//   [1] R7-1: the owner exports a pad (Android stand-in) to "ready" while the
//       join is held; the join is released (the chat comes up under the
//       sheet); a guest knocks; the prompt waits covered. Share → shared →
//       Done, and 150 ms later a tap where "Let them in" is: it must NOT
//       admit (the prompt's 500 ms guard is re-armed when the sheet closes).
//       A deliberate tap afterwards admits (control).
//   [2] R7-2: the owner (a browser) exports while the join is held, the KDF
//       held too; the join is released (chat up), then the KDF: the sheet
//       closes itself after its work, one file is downloaded, and the
//       hand-over line stays visible (chat hint, and the panel after).
import http from "node:http";
import { WebSocketServer, WebSocket } from "ws";
import puppeteer from "puppeteer-core";
import { readFileSync } from "node:fs";

const cfg = JSON.parse(readFileSync(new URL("./test-users.json", import.meta.url)));
const APP = new URL(process.env.SECURE_CHAT_E2E_URL || cfg.relay);
const UP = { host: APP.hostname, port: Number(APP.port || 80) };
const UP_ORIGIN = APP.origin;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const results = [];
function check(name, ok, detail = "") {
  results.push({ name, ok: !!ok });
  console.log(`    ${ok ? "OK  " : "FAIL"} ${name}${detail ? " — " + detail : ""}`);
}

// ---- the holding proxy ------------------------------------------------------
async function holdingProxy() {
  let released = false;
  const pipes = [];
  const srv = http.createServer((req, res) => {
    const p = http.request({ ...UP, method: req.method, path: req.url,
      headers: { ...req.headers, host: APP.host, origin: UP_ORIGIN } }, (r) => { res.writeHead(r.statusCode, r.headers); r.pipe(res); });
    p.on("error", () => { res.writeHead(502); res.end(); });
    req.pipe(p);
  });
  const wss = new WebSocketServer({ noServer: true });
  srv.on("upgrade", (req, sock, head) => wss.handleUpgrade(req, sock, head, (c) => {
    const pipe = { c, up: null, buf: [] };
    pipes.push(pipe);
    c.on("message", (m) => { if (pipe.up && pipe.up.readyState === 1) pipe.up.send(m.toString()); else pipe.buf.push(m.toString()); });
    c.on("close", () => pipe.up && pipe.up.close());
    pipe.connect = () => {
      const up = new WebSocket(`ws://${APP.host}${req.url}`, { origin: UP_ORIGIN });
      pipe.up = up;
      up.on("open", () => { for (const m of pipe.buf.splice(0)) up.send(m); });
      up.on("message", (m) => c.readyState === 1 && c.send(m.toString()));
      up.on("close", () => c.close());
    };
    if (released) pipe.connect();
  }));
  await new Promise((r) => srv.listen(0, "127.0.0.1", r));
  return {
    url: `http://127.0.0.1:${srv.address().port}/`,
    release() { released = true; for (const p of pipes) if (!p.up) p.connect(); },
    close() { for (const p of pipes) { try { p.c.terminate(); } catch {} try { p.up && p.up.terminate(); } catch {} } srv.close(); },
  };
}

const browser = await puppeteer.launch({ executablePath: process.env.CHROMIUM || "/usr/bin/chromium", headless: "new",
  args: ["--no-sandbox", "--disable-dev-shm-usage"] });
async function mkPage(url, android) {
  const ctx = await browser.createBrowserContext();
  const page = await ctx.newPage();
  page.on("dialog", async (d) => { await d.accept(); });
  await page.evaluateOnNewDocument((android) => {
    const orig = SubtleCrypto.prototype.deriveKey;
    SubtleCrypto.prototype.deriveKey = async function (...a) { if (window.__kdfGate) await window.__kdfGate; return orig.apply(this, a); };
    window.__files = [];
    const click = HTMLAnchorElement.prototype.click;
    HTMLAnchorElement.prototype.click = function () { if (this.download) { window.__files.push(this.download); return; } return click.call(this); };
    if (!android) return;
    window.__bridgeLog = [];
    let n = 0;
    const answer = (kind) => { const ret = (++n).toString(16).padStart(16, "0"); window.__bridgeLog.push({ kind, ret }); return ret; };
    const b = Object.freeze({ share: () => answer("share"), save: () => answer("save") });
    Object.defineProperty(window, "__SECURE_CHAT_FILES__", { value: b, writable: false, configurable: false });
  }, android);
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
const PASS = "held join test passphrase words — e2e only";

// A pad made on the owner page, unlocked (New pad, then Later).
async function makePad(owner) {
  await setAlg(owner, "OTP");
  await owner.waitForFunction(() => !document.querySelector("#otpPanel").hidden);
  await tap(owner, "#otpNewOpen");
  await setVal(owner, "#otpNewPass", "a pad passphrase of enough words e2e");
  await owner.evaluate(() => { const s = document.querySelector("#otpSize"); s.value = s.options[0].value; s.dispatchEvent(new Event("change", { bubbles: true })); });
  await sleep(600);
  await tap(owner, "#otpGenerate");
  await owner.waitForFunction(() => document.querySelector("#otpNewSheet").dataset.state === "done", { timeout: 60000 });
  await sleep(600);
  await tap(owner, "#otpNewLater");
  await sleep(300);
}
// Connect in AES256 (the proxy holds the join), then back to the OTP card.
async function connectHeld(owner, room) {
  await setAlg(owner, "AES256");
  await setVal(owner, "#room", room);
  await setVal(owner, "#pass", PASS);
  await tap(owner, "#connect");
  await sleep(1000);
  await setAlg(owner, "OTP");
  await sleep(300);
  await tap(owner, "#otpExportOpen");
  await owner.waitForFunction(() => !document.querySelector("#otpExportSheet").hidden, { timeout: 60000 });
  await setVal(owner, "#otpXferPass", "a transfer passphrase agreed in person e2e");
  await sleep(600);
}

console.log(`\n=== OTP sheets under a held join (${APP.origin}) ===`);

// ---- [1] R7-1 ------------------------------------------------------------------
console.log("\n  [1] a knock revealed by the Export sheet closing");
{
  const proxy = await holdingProxy();
  const ROOM = "ab".repeat(32);
  const owner = await mkPage(proxy.url, true);
  await makePad(owner);
  await connectHeld(owner, ROOM);
  check("fixture: the join is held (still the room screen)", await owner.evaluate(() => !document.querySelector("#scrRoom").hidden));
  await tap(owner, "#otpExport");
  await owner.waitForFunction(() => document.querySelector("#otpExportSheet").dataset.state === "ready", { timeout: 60000 });
  proxy.release();
  await owner.waitForFunction(() => !document.querySelector("#scrChat").hidden, { timeout: 30000 });
  check("the chat comes up under the unshared Android sheet (kept, by design)",
    await owner.evaluate(() => !document.querySelector("#otpExportSheet").hidden && document.querySelector("#viewLive").inert));
  const guest = await mkPage(APP.origin + "/", false);
  await setAlg(guest, "AES256"); await setVal(guest, "#room", ROOM); await setVal(guest, "#pass", PASS);
  await tap(guest, "#connect");
  await owner.waitForFunction(() => !document.querySelector("#admit").hidden, { timeout: 30000 });
  await sleep(1500); // the knock's own guard long gone, while covered
  const hit = await owner.evaluate(() => {
    const ok = document.querySelector("#admitOk").getBoundingClientRect();
    const at = document.elementFromPoint(ok.left + ok.width / 2, ok.top + ok.height / 2);
    return at && at.id;
  });
  check("fixture: the sheet's Share sits exactly on 'Let them in'", hit === "otpShare", hit);
  await tap(owner, "#otpShare");
  await owner.evaluate(() => { const l = window.__bridgeLog.at(-1); window.__SECURE_CHAT_FILES_RESULT__(l.ret, "shared"); });
  await owner.waitForFunction(() => document.querySelector("#otpExportSheet").dataset.state === "done");
  await tap(owner, "#otpExportDone");
  const focusAfterClose = await owner.evaluate(() => document.activeElement && document.activeElement.id);
  check("R7-1: closing the sheet puts focus on Deny (the revealed prompt, re-armed)", focusAfterClose === "admitNo", focusAfterClose);
  await sleep(120);
  const okBox = await owner.$eval("#admitOk", (e) => { const q = e.getBoundingClientRect(); return { x: q.left + q.width / 2, y: q.top + q.height / 2 }; });
  await owner.mouse.click(okBox.x, okBox.y); // the second half of a double tap
  await sleep(1500);
  const after = await owner.evaluate(() => ({ admit: !document.querySelector("#admit").hidden }));
  const guestStatus = await guest.evaluate(() => document.querySelector("#status").textContent.trim());
  check("R7-1: a tap 150 ms after Done does not let the knocker in", after.admit && /waiting for approval/i.test(guestStatus), JSON.stringify({ ...after, guestStatus }));
  await owner.mouse.click(okBox.x, okBox.y); // deliberate, well after the guard
  await guest.waitForFunction(() => !/waiting for approval/i.test(document.querySelector("#status").textContent), { timeout: 30000 }).catch(() => {});
  check("control: a deliberate tap admits", !/waiting for approval/i.test(await guest.evaluate(() => document.querySelector("#status").textContent)));
  await owner.browserContext().close(); await guest.browserContext().close();
  proxy.close();
}

// ---- [2] R7-2 ------------------------------------------------------------------
console.log("\n  [2] a browser Export that finishes after the chat came up");
{
  const proxy = await holdingProxy();
  const ROOM = "cd".repeat(32);
  const owner = await mkPage(proxy.url, false);
  await makePad(owner);
  await connectHeld(owner, ROOM);
  await owner.evaluate(() => { window.__kdfGate = new Promise((r) => { window.__kdfOpen = r; }); });
  await tap(owner, "#otpExport");
  await owner.waitForFunction(() => document.querySelector("#otpExportSheet").dataset.state === "working", { timeout: 60000 });
  proxy.release();
  await owner.waitForFunction(() => !document.querySelector("#scrChat").hidden, { timeout: 30000 });
  check("fixture: the chat is up, the Export still working", await owner.evaluate(() => document.querySelector("#otpExportSheet").dataset.state === "working"));
  await owner.evaluate(() => { window.__kdfGate = null; window.__kdfOpen(); });
  await owner.waitForFunction(() => document.querySelector("#otpExportSheet").hidden, { timeout: 30000 });
  const r = await owner.evaluate(() => ({
    files: window.__files.length,
    hint: window.__shown(document.querySelector("#hint")) ? document.querySelector("#hint").textContent : "(hidden)",
    inert: document.querySelector("#viewLive").inert,
  }));
  check("the sheet closed itself; one file downloaded; the chat is usable", r.files === 1 && !r.inert, JSON.stringify(r));
  check("R7-2: the hand-over advice is shown in the chat",
    /^Pad file downloaded — give it to them in person; once they've imported it, delete the file on both devices\.$/.test(r.hint), r.hint);
  await tap(owner, "#disconnect");
  await owner.waitForFunction(() => !document.querySelector("#scrRoom").hidden, { timeout: 30000 });
  const panel = await owner.evaluate(() => { const s = document.querySelector("#otpStatus"); return [s.textContent, s.className]; });
  check("R7-2: …and stays, visible, in the pad panel after the chat", /delete the file on both devices/.test(panel[0]) && !/\bvh\b/.test(panel[1]), panel.join(" | "));
  await owner.browserContext().close();
  proxy.close();
}

await browser.close();
const failed = results.filter((r) => !r.ok);
console.log(`\n  ${results.length - failed.length}/${results.length} checks passed`);
if (failed.length) { console.log("  FAILED: " + failed.map((f) => f.name).join("; ")); process.exit(1); }
console.log("  otp held join good\n");
