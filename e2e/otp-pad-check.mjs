// The OTP pad check at connect (cold critic r2 MA-2), through two real
// browsers and a real relay.
//
//   SECURE_CHAT_E2E_URL=http://127.0.0.1:8106 node e2e/otp-pad-check.mjs
//
// MA-2's walk: alice and bob BOTH press New pad and call it "Chess", export
// it, and import the other's. Each device then holds "Chess (you generated)"
// and "Chess (from your contact)", and the imported one is selected.
//
//   [1] Both connect on the imported pad — two DIFFERENT pads. Before this
//       fix both saw "Ready" and every message was undecryptable. Now both
//       are refused before Ready, the room screen names the pad and what to
//       check, and Send never unlocks.
//   [2] alice's pad on both sides (alice: generated, bob: from contact) —
//       the pad bob just tried in [1]: Ready with its FULL send budget (so
//       [1] spent none of it), no new refusal, a message each way.
//   [3] bob's pad on both sides — the one alice tried in [1]: the same.
//   [4] alice on One-time pad, bob on AES-256 (pentest r3 R3-F1): alice is
//       refused before Ready with the mode named — not "older version …
//       different pads" — and her pad's send budget is untouched.
import puppeteer from "puppeteer-core";
import { readFileSync, writeFileSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const cfg = JSON.parse(readFileSync(new URL("./test-users.json", import.meta.url)));
const APP = process.env.SECURE_CHAT_E2E_URL || cfg.relay;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const PAD_PASS = "e2e pad at-rest passphrase — pad check only";
const XFER_PASS = "e2e pad transfer passphrase — pad check only";

const results = [];
function check(name, ok, detail = "") {
  results.push({ name, ok: !!ok });
  console.log(`    ${ok ? "OK  " : "FAIL"} ${name}${detail ? " — " + detail : ""}`);
}

const browser = await puppeteer.launch({ executablePath: process.env.CHROMIUM || "/usr/bin/chromium", headless: "new",
  args: ["--no-sandbox", "--disable-dev-shm-usage"], protocolTimeout: 300000 });
const errors = [];
async function agent(label) {
  const ctx = await browser.createBrowserContext();
  const page = await ctx.newPage();
  page.on("pageerror", (e) => errors.push(`${label}: ${e.message}`));
  page.on("dialog", async (d) => { errors.push(`${label}: unexpected dialog`); await d.accept(); });
  // Every frame this page sends, for "no message went out".
  await page.evaluateOnNewDocument(() => {
    window.__sent = [];
    const send = WebSocket.prototype.send;
    WebSocket.prototype.send = function (d) { try { window.__sent.push(JSON.parse(d).type); } catch {} return send.call(this, d); };
    window.__padFile = null;
    const orig = URL.createObjectURL.bind(URL);
    URL.createObjectURL = (blob) => { blob.text().then((t) => { window.__padFile = t; }); return orig(blob); };
  });
  await page.setViewport({ width: 1000, height: 900 });
  await page.goto(APP, { waitUntil: "networkidle0", timeout: 60000 });
  await page.click("#toRoom");
  await page.waitForFunction(() => !document.querySelector("#scrRoom").hidden);
  await page.evaluate(() => {
    document.querySelector("#algDetails").open = true;
    const r = document.querySelector('input[name="alg"][value="OTP"]');
    r.checked = true;
    r.dispatchEvent(new Event("change", { bubbles: true }));
  });
  await page.waitForFunction(() => !document.querySelector("#otpPanel").hidden);
  return { label, page };
}
const setValue = (page, sel, value) => page.evaluate((s, v) => {
  const el = document.querySelector(s);
  el.value = v;
  el.dispatchEvent(new Event("input", { bubbles: true }));
  el.dispatchEvent(new Event("change", { bubbles: true }));
}, sel, value);
const text = (page, sel) => page.evaluate((s) => (document.querySelector(s) || {}).textContent || "", sel);

// New pad "Chess" → Export; returns the file text.
async function makeChess(a) {
  const p = a.page;
  await p.click("#otpNewOpen");
  await p.waitForFunction(() => !document.querySelector("#otpNewSheet").hidden);
  await setValue(p, "#otpNewPass", PAD_PASS);
  await setValue(p, "#otpLabel", "Chess");
  await p.evaluate(() => { const s = document.querySelector("#otpSize"); s.value = s.options[0].value; s.dispatchEvent(new Event("change", { bubbles: true })); });
  await sleep(600);
  await p.click("#otpGenerate");
  await p.waitForFunction(() => document.querySelector("#otpNewSheet").dataset.state === "done", { timeout: 60000 });
  await p.evaluate(() => { window.__padFile = null; });
  await p.click("#otpNewToExport");
  await p.waitForFunction(() => !document.querySelector("#otpExportSheet").hidden);
  await setValue(p, "#otpXferPass", XFER_PASS);
  await sleep(600);
  await p.click("#otpExport");
  await p.waitForFunction(() => window.__padFile !== null, { timeout: 60000 });
  await p.waitForFunction(() => document.querySelector("#otpExportSheet").dataset.state === "done", { timeout: 10000 });
  await p.click("#otpExportDone");
  return p.evaluate(() => window.__padFile);
}
async function importFile(a, json) {
  const p = a.page;
  const path = join(mkdtempSync(join(tmpdir(), "sc-padcheck-")), "secure-chat-pad-e2e.json");
  writeFileSync(path, json);
  await p.click("#otpImportOpen");
  await p.waitForFunction(() => !document.querySelector("#otpImportSheet").hidden);
  await setValue(p, "#otpImportXfer", XFER_PASS);
  await setValue(p, "#otpImportPass", PAD_PASS);
  await (await p.$("#otpFile")).uploadFile(path);
  await p.waitForFunction(() => document.querySelector("#otpImportSheet").dataset.state === "done", { timeout: 60000 });
  await sleep(600);
  await p.click("#otpImportDone");
}
// The pad whose option reads "Chess (<who>, …)".
const padIdFor = (a, who) => a.page.evaluate((w) =>
  [...document.querySelectorAll("#otpSelect option")].find((o) => o.textContent.startsWith(`Chess (${w}`))?.value, who);
async function pick(a, padId) {
  await setValue(a.page, "#otpSelect", padId);
  await setValue(a.page, "#otpPass", PAD_PASS);
}

// alice owns the room, bob knocks, alice lets him in. Resolves when each page
// is either Ready (Send enabled) or back on the room screen.
async function meet(alice, bob) {
  await alice.page.click("#gen");
  const code = await alice.page.evaluate(() => document.querySelector("#room").value.trim());
  await alice.page.evaluate(() => { window.__sent = []; });
  await bob.page.evaluate(() => { window.__sent = []; });
  await sleep(700); // a tap within 500 ms of a sheet closing is ignored (the double-tap guard)
  await alice.page.click("#connect");
  await alice.page.waitForFunction(() => document.querySelector("#chatStatus").textContent.trim().toLowerCase() === "connected", { timeout: 45000 });
  await setValue(bob.page, "#room", code);
  await bob.page.click("#connect");
  await alice.page.waitForFunction(() => !document.querySelector("#admit").hidden, { timeout: 45000 });
  await sleep(600);
  await alice.page.click("#admitOk");
  const settled = (p) => p.waitForFunction(() => !document.querySelector("#text").disabled || !document.querySelector("#scrRoom").hidden, { timeout: 60000 });
  await Promise.all([settled(alice.page), settled(bob.page)]);
  await sleep(500); // a late frame would still change either page
}
const ready = (a) => a.page.evaluate(() => !document.querySelector("#text").disabled && /one-time-pad encrypted/.test(document.querySelector("#hint").textContent));
async function roundTrip(from, to, tag) {
  const msg = `${tag} ${from.label}->${to.label} ${Date.now()}`;
  await from.page.type("#text", msg);
  await from.page.click("#send");
  let log = "";
  for (let i = 0; i < 20 && !log.includes(msg); i++) { await sleep(300); log = await text(to.page, "#log"); }
  return log.includes(msg);
}
async function leave(...as) {
  for (const a of as) {
    if (await a.page.evaluate(() => document.querySelector("#scrRoom").hidden)) {
      await a.page.click("#disconnect");
      await a.page.waitForFunction(() => document.querySelector("#text").disabled, { timeout: 30000 });
      if (await a.page.evaluate(() => document.querySelector("#scrRoom").hidden)) await a.page.click("#toRoom").catch(() => {});
    }
  }
  await sleep(300);
}

console.log(`\n=== OTP pad check at connect (${APP}) ===`);
const alice = await agent("alice");
const bob = await agent("bob");

console.log("\n  both make a pad called \"Chess\" and import the other's");
const aFile = await makeChess(alice);
const bFile = await makeChess(bob);
await importFile(alice, bFile);
await importFile(bob, aFile);
const ids = {
  aMade: await padIdFor(alice, "you generated"), aGot: await padIdFor(alice, "from your contact"),
  bMade: await padIdFor(bob, "you generated"), bGot: await padIdFor(bob, "from your contact"),
};
check("each device holds two pads called Chess", Object.values(ids).every(Boolean) && ids.aMade === ids.bGot && ids.bMade === ids.aGot);

console.log("\n  [1] both on the imported Chess — two different pads");
{
  await pick(alice, ids.aGot);
  await pick(bob, ids.bGot);
  await meet(alice, bob);
  for (const a of [alice, bob]) {
    const room = await text(a.page, "#roomHint");
    check(`${a.label}: not Ready`, !(await ready(a)));
    check(`${a.label}: the room screen says the pads differ and names this device's pad`,
      /You and your contact picked different pads\. This device used "Chess" \(from your contact\)\..*Nothing was sent and no pad was used\./.test(room), room.slice(0, 160));
    check(`${a.label}: Send never unlocked, no message frame went out`,
      await a.page.evaluate(() => document.querySelector("#text").disabled && !window.__sent.includes("msg")));
  }
  await leave(alice, bob);
}

let aMadeBudget = null; // alice's pad after [2]: what [4] must leave unchanged
for (const [n, aId, bId, whose] of [[2, ids.aMade, ids.bGot, "alice's"], [3, ids.aGot, ids.bMade, "bob's"]]) {
  console.log(`\n  [${n}] ${whose} pad on both sides`);
  await pick(alice, aId);
  await pick(bob, bId);
  const refusals = async () => ((await text(alice.page, "#log")) + (await text(bob.page, "#log"))).split(/different pads|same half/).length;
  const r0 = await refusals();
  await meet(alice, bob);
  check(`[${n}] both Ready`, (await ready(alice)) && (await ready(bob)), (await text(alice.page, "#roomHint")).slice(0, 120));
  check(`[${n}] no new refusal line`, (await refusals()) === r0);
  for (const a of [alice, bob]) {
    const st = await text(a.page, "#otpStatus");
    // KiB are rounded; the message estimate (remaining / 92 bytes) moves with
    // every short message — 32768 / 92 → ~356 only on an untouched pad.
    check(`[${n}] ${a.label}: the pad's full send budget is left`, /^Pad "Chess": 32 KiB left to send \(~356 more short messages\)/.test(st), st);
  }
  check(`[${n}] alice -> bob`, await roundTrip(alice, bob, `pad${n}`));
  check(`[${n}] bob -> alice`, await roundTrip(bob, alice, `pad${n}`));
  if (n === 2) aMadeBudget = await text(alice.page, "#otpStatus");
  await leave(alice, bob);
}

console.log("\n  [4] alice on One-time pad, bob on AES-256");
{
  await pick(alice, ids.aMade);
  await bob.page.evaluate(() => {
    const r = document.querySelector('input[name="alg"][value="AES256"]');
    r.checked = true;
    r.dispatchEvent(new Event("change", { bubbles: true }));
  });
  await setValue(bob.page, "#pass", "an aes passphrase for the mode mix-up e2e");
  await alice.page.click("#gen");
  const code = await alice.page.evaluate(() => document.querySelector("#room").value.trim());
  await sleep(700);
  await alice.page.click("#connect");
  await alice.page.waitForFunction(() => document.querySelector("#chatStatus").textContent.trim().toLowerCase() === "connected", { timeout: 45000 });
  await setValue(bob.page, "#room", code);
  await bob.page.click("#connect");
  await alice.page.waitForFunction(() => !document.querySelector("#admit").hidden, { timeout: 45000 });
  await sleep(600);
  await alice.page.click("#admitOk");
  await alice.page.waitForFunction(() => !document.querySelector("#text").disabled || !document.querySelector("#scrRoom").hidden, { timeout: 60000 });
  await sleep(500);
  const room = await text(alice.page, "#roomHint");
  check("[4] alice: not Ready", !(await ready(alice)));
  check("[4] alice: the room screen names bob's mode", /Your contact picked AES-256 under Security options, and you picked One-time pad\..*Nothing was sent and no pad was used\./.test(room), room.slice(0, 140));
  check("[4] alice: no \"older version\" line", !/older version/.test(await text(alice.page, "#log")));
  await leave(alice, bob);
  await bob.page.evaluate(() => {
    const r = document.querySelector('input[name="alg"][value="OTP"]');
    r.checked = true;
    r.dispatchEvent(new Event("change", { bubbles: true }));
  });
  // alice's pad after [4]: the budget [2] left, to the byte (Ready with bob on it).
  await pick(alice, ids.aMade);
  await pick(bob, ids.bGot);
  await meet(alice, bob);
  const st = await text(alice.page, "#otpStatus");
  check("[4] alice's pad: [4] spent nothing (the budget [2] left)", (await ready(alice)) && !!aMadeBudget && st === aMadeBudget, `${st} vs ${aMadeBudget}`);
  await leave(alice, bob);
}

await browser.close();
console.log("\n=== summary ===");
for (const e of errors.slice(0, 8)) console.log("  [page]", e);
const failed = results.filter((r) => !r.ok);
console.log(`  ${results.length - failed.length}/${results.length} checks passed`);
if (failed.length || errors.length) {
  if (failed.length) console.log("  FAILED: " + failed.map((f) => f.name).join("; "));
  process.exit(1);
}
