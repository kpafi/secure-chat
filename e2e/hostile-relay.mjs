// Hostile-relay run of the ROOM-CREATOR invariant (pentest 2026-08-07 F-PROTO-001).
//
//   node e2e/hostile-relay.mjs
//
// Needs the relay running (backend/run.sh) and Chromium ($CHROMIUM).
//
// The finding: the creator's client took its room role from the relay's answer
// to `join`. A relay that answered the creator with `pending` (then swallowed
// the knock and sent `joined:guest`) passed the M-2 guest-half check — which
// only proves we went through the queue, not that an owner existed — so the
// creator was seated as a guest, saw no knock, approved nobody, and whoever the
// relay routed in completed the handshake with no admission binding.
//
// The relay here is the REAL one; the hostility is injected at the page's
// WebSocket (a document-start wrapper, the same place the Android shell injects
// its config), because that is the exact frame sequence a hostile relay would
// send and the relay's own code is what is being distrusted. Two agents get the
// identical treatment:
//
//   1. alice, whose page MINTED the code, must refuse to be demoted and end up
//      disconnected with the prompt never shown;
//   2. bob, who PASTED a code, must still go through the honest pending path —
//      the refusal keys on "we created this code", not on `pending` itself.
import puppeteer from "puppeteer-core";
import { readFileSync } from "node:fs";

const cfg = JSON.parse(readFileSync(new URL("./test-users.json", import.meta.url)));
const APP = process.env.SECURE_CHAT_E2E_URL || cfg.relay;
const PASS = cfg.users[0].passphrase;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const results = [];
function check(name, ok, detail = "") {
  results.push({ name, ok });
  console.log(`  ${ok ? "OK  " : "FAIL"} ${name}${detail ? " — " + detail : ""}`);
}

const browser = await puppeteer.launch({
  executablePath: process.env.CHROMIUM || "/usr/bin/chromium",
  headless: "new",
  args: ["--no-sandbox", "--disable-dev-shm-usage"],
});

// The hostile relay, as seen from the page: the first `joined:owner` becomes
// `pending`; the knock that provokes is swallowed and answered with
// `joined:guest`. Everything else passes verbatim in both directions.
function hostileRelay() {
  const Real = window.WebSocket;
  const synthetic = new WeakSet();
  window.__HOSTILE_RELAY_LOG__ = [];
  window.WebSocket = class extends Real {
    constructor(...args) {
      super(...args);
      let demoted = false;
      const fake = (obj) => {
        const ev = new MessageEvent("message", { data: JSON.stringify(obj) });
        synthetic.add(ev);
        this.dispatchEvent(ev);
      };
      this.addEventListener("message", (ev) => {
        if (synthetic.has(ev)) return;
        let m = null;
        try { m = JSON.parse(ev.data); } catch { return; }
        if (m && m.type === "joined" && m.role === "owner" && !demoted && !window.__HOSTILE_RELAY_OFF__) {
          demoted = true;
          window.__HOSTILE_RELAY_LOG__.push("rewrote joined:owner -> pending");
          ev.stopImmediatePropagation();
          fake({ type: "pending" });
        }
      });
      const send = this.send.bind(this);
      this.send = (data) => {
        let m = null;
        try { m = JSON.parse(data); } catch { /* not ours */ }
        if (demoted && m && m.type === "knock") {
          window.__HOSTILE_RELAY_LOG__.push("swallowed knock, seating as guest");
          setTimeout(() => fake({ type: "joined", role: "guest" }), 50);
          return;
        }
        send(data);
      };
    }
  };
}

const errors = [];
async function agent(label, viewport = { width: 1000, height: 900 }) {
  const ctx = await browser.createBrowserContext();
  const page = await ctx.newPage();
  page.on("pageerror", (e) => errors.push(`${label}: ${e.message}`));
  page.on("console", (m) => {
    const t = m.text();
    if (m.type() === "error" && !/favicon|404/.test(t)) errors.push(`${label}: ${t}`);
  });
  await page.evaluateOnNewDocument(hostileRelay);
  await page.setViewport(viewport);
  await page.goto(APP, { waitUntil: "networkidle0" });
  await page.type("#idPass", PASS);
  await page.click("#idCreate");
  await page.waitForFunction(() => !document.querySelector("#idExport").hidden, { timeout: 60000 });
  await page.click("#toRoom");
  await page.waitForFunction(() => !document.querySelector("#scrRoom").hidden, { timeout: 20000 });
  return { label, ctx, page };
}

const text = (page, sel) => page.evaluate((s) => {
  const el = document.querySelector(s);
  return el ? el.textContent.trim() : "";
}, sel);
const status = async (page) => (await text(page, "#chatStatus")).toLowerCase();
const relayLog = (page) => page.evaluate(() => window.__HOSTILE_RELAY_LOG__.join("; "));

console.log(`\n=== hostile relay demotes the room creator (${APP}) ===\n`);

// --- 1. the creator ----------------------------------------------------------
console.log("1. alice connects with the code HER page minted; the relay says 'pending'");
const alice = await agent("alice");
const code = await alice.page.evaluate(() => document.querySelector("#room").value.trim());
check("a chat code is generated for the creator", /^[0-9a-f]{64}$/.test(code), code.slice(0, 12) + "…");
await alice.page.click("#connect");
// Wait until the demotion has been played and the client has reacted either
// way: pre-fix it lands on "connected" (seated as guest), post-fix on
// "disconnected". Anchored comparisons — "disconnected" contains "connected".
await alice.page.waitForFunction(() => {
  const s = document.querySelector("#chatStatus").textContent.trim().toLowerCase();
  return s === "connected" || s === "disconnected";
}, { timeout: 30000 });
await sleep(300);
const aliceStatus = await status(alice.page);
const aliceLog = await text(alice.page, "#log");
check("the hostile sequence was actually played", /rewrote joined:owner/.test(await relayLog(alice.page)),
  await relayLog(alice.page));
check("the creator refuses to be seated as a guest",
  /we created this chat code/i.test(aliceLog) && /refusing/i.test(aliceLog), JSON.stringify(aliceLog.slice(-120)));
check("the creator is disconnected, not chatting in a room she does not control",
  aliceStatus === "disconnected", aliceStatus);
check("no approval prompt was ever shown to a demoted creator",
  await alice.page.evaluate(() => document.querySelector("#admit").hidden));
check("the creator cannot send", await alice.page.evaluate(() => document.querySelector("#text").disabled));
// The refusal closes the socket, which returns to the room screen — the
// explanation has to survive that transition or the user is left with nothing.
check("the creator is told how to recover, on the screen she lands on",
  /connect first|new code/i.test(await text(alice.page, "#roomHint")),
  JSON.stringify(await text(alice.page, "#roomHint")));

// --- 1b. the same refusal on a phone must be SEEN, not just written ----------
// 2026-09-22 rework pentest (P2): on a 390x844 phone the room screen is taller
// than the viewport and the explanation landed below the fold, or under the
// fixed tab bar. It is written, so the check above passed; it must also be on
// screen and on top: whatever is at its centre is the hint itself.
console.log("\n1b. the same demotion on a phone (390x844, touch): the refusal is on screen");
const phone = await agent("alice-phone", { width: 390, height: 844, deviceScaleFactor: 2, isMobile: true, hasTouch: true });
await phone.page.$eval("#connect", (e) => e.click());
await phone.page.waitForFunction(() => /connect first|new code/i.test(document.querySelector("#roomHint").textContent),
  { timeout: 30000 }).catch(() => {});
await sleep(300);
const hintHit = await phone.page.evaluate(() => {
  const el = document.querySelector("#roomHint");
  const r = el.getBoundingClientRect();
  const x = r.left + r.width / 2, y = r.top + r.height / 2;
  const hit = document.elementFromPoint(x, y);
  return {
    text: el.textContent.trim(),
    box: [Math.round(r.top), Math.round(r.bottom)],
    viewport: innerHeight,
    hit: hit ? (hit.id || hit.closest("[id]")?.id || hit.tagName) : null,
    onTop: !!hit && (hit === el || el.contains(hit)),
  };
});
check("on a phone, the refusal is on screen and nothing covers it",
  /connect first|new code/i.test(hintHit.text) && hintHit.onTop,
  JSON.stringify({ ...hintHit, text: hintHit.text.slice(0, 40) + "…" }));

// --- 2. the control: a pasted code goes through the honest pending path -----
console.log("\n2. bob PASTES a code and gets the same 'pending' — that is the honest path, not a demotion");
const bob = await agent("bob");
await bob.page.evaluate(() => { document.querySelector("#room").value = ""; });
await bob.page.type("#room", code); // input events: this page did not mint it
await bob.page.click("#connect");
await bob.page.waitForFunction(() => {
  const s = document.querySelector("#chatStatus").textContent.trim().toLowerCase();
  return s === "connected" || s === "disconnected";
}, { timeout: 30000 });
const bobLog = await text(bob.page, "#log");
check("a peer who pasted the code accepts 'pending' and knocks",
  /waiting — the person who created this chat/i.test(bobLog) && !/refusing/i.test(bobLog),
  JSON.stringify(bobLog.slice(-120)));
check("the refusal keys on 'we minted this code', not on 'pending' itself",
  (await status(bob.page)) === "connected", await status(bob.page));

// --- 3. the creator's own path is untouched by the change --------------------
// (New code -> Connect against the real relay's `joined:owner` must still seat
// her as the owner. The relay turns honest for this step.)
console.log("\n3. the creator makes a new code and connects again — the honest owner path still works");
await alice.page.evaluate(() => { window.__HOSTILE_RELAY_LOG__.length = 0; window.__HOSTILE_RELAY_OFF__ = true; });
await alice.page.click("#gen");
await alice.page.click("#connect");
await alice.page.waitForFunction(
  () => document.querySelector("#chatStatus").textContent.trim().toLowerCase() === "connected",
  { timeout: 30000 }).catch(() => {});
check("a fresh code connects the creator as the owner",
  (await status(alice.page)) === "connected" && /you decide who is let in/i.test(await text(alice.page, "#log")),
  JSON.stringify((await text(alice.page, "#log")).slice(-90)));

// --- 4. reload, re-paste her own code: the invariant must survive the reload --
// (fix review 2026-09-21: page-instance state alone failed open here — the box
// is empty after a reload, she pastes the code she already sent, and the
// `input` event used to clear the flag.)
console.log("\n4. alice reloads, pastes the code SHE minted in step 1, and the relay tries again");
await alice.page.reload({ waitUntil: "networkidle0" });
await alice.page.type("#idPass", PASS);
await alice.page.click("#idUnlock");
await alice.page.waitForFunction(() => !document.querySelector("#idExport").hidden, { timeout: 60000 });
await alice.page.click("#toRoom");
await alice.page.waitForFunction(() => !document.querySelector("#scrRoom").hidden, { timeout: 20000 });
await alice.page.evaluate(() => { document.querySelector("#room").value = ""; });
await alice.page.type("#room", code);
await alice.page.click("#connect");
await alice.page.waitForFunction(() => {
  const s = document.querySelector("#chatStatus").textContent.trim().toLowerCase();
  return s === "connected" || s === "disconnected";
}, { timeout: 30000 });
check("after a reload, a re-pasted code this device minted is still refused when demoted",
  (await status(alice.page)) === "disconnected" && /we created this chat code/i.test(await text(alice.page, "#log")),
  JSON.stringify((await text(alice.page, "#log")).slice(-100)));

await browser.close();

console.log("\n=== summary ===");
const failed = results.filter((r) => !r.ok);
for (const e of errors.slice(0, 5)) console.log("  [console]", e);
console.log(`  ${results.length - failed.length}/${results.length} checks passed`);
if (failed.length) {
  console.log("  FAILED: " + failed.map((f) => f.name).join("; "));
  process.exit(1);
}
console.log("  all good\n");
