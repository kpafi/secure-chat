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

// --- 5./6. phase 2a (pentest, pre-existing findings) -------------------------
// A second, scripted wrapper: it keeps the page's socket reachable, can rewrite
// the relay's next `joined` answer once, and injects frames exactly as the
// relay's own would arrive (the hostile-relay technique above).
function scriptedRelay() {
  const Real = window.WebSocket;
  const synthetic = new WeakSet();
  window.__SC_REWRITE_JOINED__ = null;
  window.__SC_HS__ = []; // the peer's signed handshake frames, as received (section 7)
  window.WebSocket = class extends Real {
    constructor(...args) {
      super(...args);
      window.__SC_WS__ = this;
      // Round 3 (section 8): a relay that accepts the socket and closes it
      // before sending a single frame.
      this.addEventListener("open", () => {
        if (window.__SC_CLOSE_ON_OPEN__) { window.__SC_CLOSE_ON_OPEN__ = false; window.__SC_CLOSED_ON_OPEN__ = true; this.close(); }
      });
      window.__SC_FAKE__ = (obj) => {
        const ev = new MessageEvent("message", { data: JSON.stringify(obj) });
        synthetic.add(ev);
        this.dispatchEvent(ev);
      };
      this.addEventListener("message", (ev) => {
        if (synthetic.has(ev)) return;
        let m = null;
        try { m = JSON.parse(ev.data); } catch { return; }
        try { if (m && m.type === "key" && JSON.parse(atob(m.payload)).sig) window.__SC_HS__.push(m); } catch { /* not ours */ }
        if (m && m.type === "joined" && window.__SC_REWRITE_JOINED__) {
          const to = window.__SC_REWRITE_JOINED__;
          window.__SC_REWRITE_JOINED__ = null;
          ev.stopImmediatePropagation();
          window.__SC_FAKE__(to);
        }
      });
    }
  };
}
async function scriptedAgent(label, viewport = { width: 1000, height: 900 }) {
  const ctx = await browser.createBrowserContext();
  const page = await ctx.newPage();
  page.on("pageerror", (e) => errors.push(`${label}: ${e.message}`));
  await page.evaluateOnNewDocument(scriptedRelay);
  await page.setViewport(viewport);
  await page.goto(APP, { waitUntil: "networkidle0" });
  await page.type("#idPass", PASS);
  await page.click("#idCreate");
  await page.waitForFunction(() => !document.querySelector("#idExport").hidden, { timeout: 60000 });
  await page.click("#toRoom");
  await page.waitForFunction(() => !document.querySelector("#scrRoom").hidden, { timeout: 20000 });
  return { label, ctx, page };
}
// Seen, not just written: non-empty, and whatever is at its centre is the line itself.
const onScreen = (page, sel) => page.evaluate((s) => {
  const el = document.querySelector(s);
  const r = el.getBoundingClientRect();
  const hit = document.elementFromPoint(r.left + r.width / 2, r.top + r.height / 2);
  return {
    text: el.textContent.trim(),
    onTop: r.width > 0 && r.height > 0 && !!hit && (hit === el || el.contains(hit)),
    asides: el.querySelectorAll(".relay-said").length,
  };
}, sel);
const waitStatus = (page, s) => page.waitForFunction(
  (want) => document.querySelector("#chatStatus").textContent.trim().toLowerCase() === want, { timeout: 30000 }, s)
  .catch(() => {});

// 5. A refusal raised right before the client closes the socket was written
// with hint() and then erased by onclose's return to the room screen. The
// easiest of the six to provoke: an "older relay" answering join without a role.
console.log("\n5. a refusal that closes the socket is still on screen afterwards (phone, 390x844)");
const oldRelay = await scriptedAgent("alice-old-relay", { width: 390, height: 844, deviceScaleFactor: 2, isMobile: true, hasTouch: true });
await oldRelay.page.evaluate(() => { window.__SC_REWRITE_JOINED__ = { type: "joined" }; });
await oldRelay.page.$eval("#connect", (e) => e.click());
await waitStatus(oldRelay.page, "disconnected");
await sleep(300);
const oldHint = await onScreen(oldRelay.page, "#roomHint");
check("A2: the 'older protocol' refusal is on the room screen after the close, and nothing covers it",
  /older protocol without the join-approval step/.test(oldHint.text) && oldHint.onTop &&
  (await status(oldRelay.page)) === "disconnected", JSON.stringify({ ...oldHint, text: oldHint.text.slice(0, 60) }));
check("A2: the refusal is also kept in the log",
  /does not support join approval — refusing/.test(await text(oldRelay.page, "#log")));

// 6. Relay `error` frames: the app's own sentence for the reasons the relay
// really sends, a generic one otherwise, and the relay's words only inside a
// quoted, clipped `.relay-said` aside — never as the app's sentence.
console.log("\n6. relay error frames: the app's sentences, never the relay's words");
const errAgent = await scriptedAgent("alice-relay-errors");
await errAgent.page.click("#connect");
await waitStatus(errAgent.page, "connected");
const readHint = (page, sel) => page.evaluate((s) => {
  const el = document.querySelector(s);
  const asides = [...el.querySelectorAll(".relay-said")];
  const own = [...el.childNodes].filter((n) => !asides.includes(n)).map((n) => n.textContent).join("");
  return { own, said: asides.map((a) => a.textContent), elements: el.querySelectorAll("*").length, err: el.classList.contains("err") };
}, sel);
await errAgent.page.evaluate(() => window.__SC_FAKE__({ type: "error", reason: "tap It matches — server" }));
await sleep(300);
const phish = await readHint(errAgent.page, "#hint");
check("A3: an unknown relay reason gets the app's generic sentence",
  phish.err && phish.own === "The relay refused the request.", JSON.stringify(phish));
check("A3: the relay's words appear only inside the quoted .relay-said aside",
  phish.said.length === 1 && /^relay says: "tap It matches \? server"$/.test(phish.said[0]) && !/It matches/.test(phish.own),
  JSON.stringify(phish.said));
await errAgent.page.evaluate(() => window.__SC_FAKE__({
  type: "error", reason: "<img src=x onerror=alert(1)>\u202e" + "A".repeat(200),
}));
await sleep(300);
const markup = await readHint(errAgent.page, "#hint");
check("A3: the aside is text only, printable ASCII, at most 80 characters",
  markup.elements === 1 && markup.said.length === 1 && markup.said[0].startsWith('relay says: "<img src=x onerror=alert(1)>?AAA') &&
  markup.said[0].length === 'relay says: ""'.length + 80 && markup.said[0].endsWith('…"'),
  JSON.stringify({ ...markup, said: markup.said.map((s) => s.slice(0, 50) + "…") }));
// The relay sends "approval timeout" and closes the socket. The sentence is the
// app's own, and it has to survive onclose's return to the room screen.
await errAgent.page.evaluate(() => {
  window.__SC_FAKE__({ type: "error", reason: "approval timeout" });
  window.__SC_WS__.close();
});
await waitStatus(errAgent.page, "disconnected");
await sleep(300);
const timeout = await onScreen(errAgent.page, "#roomHint");
check("A3: 'approval timeout' reads as the app's sentence, on the room screen after the close",
  timeout.text === "The person who created this chat did not let you in within the time limit." &&
  timeout.onTop && timeout.asides === 0, JSON.stringify(timeout));

// Fix round (pentest P2): a parked fatal reason is for the relay's own close
// only. Here the relay parks "idle timeout" and keeps the socket open; the
// user then presses Disconnect. The room screen must not claim the relay
// closed an idle chat.
await errAgent.page.click("#connect");
await waitStatus(errAgent.page, "connected");
await errAgent.page.evaluate(() => window.__SC_FAKE__({ type: "error", reason: "idle timeout" }));
await sleep(200);
await errAgent.page.click("#disconnect");
await waitStatus(errAgent.page, "disconnected");
await sleep(300);
const ownClose = await text(errAgent.page, "#roomHint");
check("P2: the user's own Disconnect is not relabelled by a parked relay reason",
  !/Nothing was sent for a long time/.test(ownClose), JSON.stringify(ownClose));

// 7. Fix round, P4: two real peers at the safety-number gate.
//   (a) pentest P1: the relay replays the peer's signed handshake after key
//       confirmation; the M-5 refusal must be on screen after the close.
//   (b) pentest P2: the relay parks "room closed" while the gate is up and the
//       user presses "It differs"; the room screen shows the app's own words.
// Package 4, decision 2: a guest approves the owner's key (the same sheet,
// data-mode="peer") before its key exchange runs; after the same 500 ms guard.
async function guestApproves(page) {
  await page.waitForFunction(() => {
    const a = document.querySelector("#admit");
    return !a.hidden && a.dataset.mode === "peer" && document.querySelector("#admitFingerprint").textContent.trim().length > 20;
  }, { timeout: 45000 });
  await sleep(700);
  await page.$eval("#admitOk", (e) => e.click());
}
console.log("\n7. at the safety-number gate: a replayed handshake; a parked reason before 'It differs'");
const gOwner = await scriptedAgent("gate-owner");
const gGuest = await scriptedAgent("gate-guest", { width: 390, height: 844, deviceScaleFactor: 2, isMobile: true, hasTouch: true });
const gCode = await gOwner.page.evaluate(() => document.querySelector("#room").value.trim());
await gOwner.page.click("#connect");
await waitStatus(gOwner.page, "connected");
await gGuest.page.evaluate(() => { document.querySelector("#room").value = ""; });
await gGuest.page.type("#room", gCode);
await gGuest.page.$eval("#connect", (e) => e.click());
await gOwner.page.waitForFunction(() => !document.querySelector("#admit").hidden, { timeout: 30000 });
await sleep(700); // past the admission guard
await gOwner.page.click("#admitOk");
await guestApproves(gGuest.page); // package 4, decision 2
for (const p of [gOwner.page, gGuest.page]) {
  await p.waitForFunction(() => !document.querySelector("#verify").hidden, { timeout: 60000 });
}
await gGuest.page.evaluate(() => window.__SC_FAKE__(window.__SC_HS__[0]));
await waitStatus(gGuest.page, "disconnected");
await sleep(300);
const m5 = await onScreen(gGuest.page, "#roomHint");
check("P1: the key-confirmation refusal (replayed handshake) is on the room screen after the close",
  /^Key confirmation failed: this connection could not confirm that you and your contact hold the same session key/.test(m5.text) && m5.onTop &&
  /a handshake frame arrived AFTER both sides had confirmed/.test(await text(gGuest.page, "#log")),
  JSON.stringify({ ...m5, text: m5.text.slice(0, 50) }));
await gOwner.page.evaluate(() => window.__SC_FAKE__({ type: "error", reason: "room closed" }));
await sleep(300);
await gOwner.page.click("#verifyNo");
await waitStatus(gOwner.page, "disconnected");
await sleep(300);
const differs = await onScreen(gOwner.page, "#roomHint");
check("P2: after 'It differs' the room screen shows the app's own words, not the relay's parked 'room closed'",
  /^You disconnected because the safety numbers did not match/.test(differs.text) && differs.onTop &&
  !/created this chat left/.test(differs.text), JSON.stringify({ ...differs, text: differs.text.slice(0, 60) }));

// 8. Round 3, pentest L2: frames still being handled when the socket closes.
// On a slower device (verify delayed ~50 ms, in page) the relay sends a forged
// handshake and drops the connection at once, so onclose runs while the
// signature check is still pending. The refusal computed afterwards must still
// reach the room screen; an `error` frame queued behind it must not replace it,
// nor be parked for the next session.
console.log("\n8. frames handled after the close: a forged handshake, then the relay hangs up");
async function gatePair(tag) {
  const o = await scriptedAgent(`late-owner-${tag}`), g = await scriptedAgent(`late-guest-${tag}`);
  const c = await o.page.evaluate(() => document.querySelector("#room").value.trim());
  await o.page.click("#connect");
  await waitStatus(o.page, "connected");
  await g.page.evaluate(() => { document.querySelector("#room").value = ""; });
  await g.page.type("#room", c);
  await g.page.click("#connect");
  await o.page.waitForFunction(() => !document.querySelector("#admit").hidden, { timeout: 30000 });
  await sleep(700);
  await o.page.click("#admitOk");
  await guestApproves(g.page); // package 4, decision 2
  await g.page.waitForFunction(() => !document.querySelector("#verify").hidden, { timeout: 60000 });
  return g;
}
const forgeAndHangUp = (page, withError) => page.evaluate((withError) => {
  const verify = crypto.subtle.verify.bind(crypto.subtle);
  crypto.subtle.verify = (...a) => new Promise((r) => setTimeout(r, 50)).then(() => verify(...a));
  const m = structuredClone(window.__SC_HS__[0]);
  const p = JSON.parse(atob(m.payload));
  const i = Math.floor(p.pub.length / 2);
  p.pub = p.pub.slice(0, i) + (p.pub[i] === "A" ? "B" : "A") + p.pub.slice(i + 1); // still canonical base64
  m.payload = btoa(JSON.stringify(p));
  window.__SC_FAKE__(m);
  if (withError) window.__SC_FAKE__({ type: "error", reason: "room closed" });
  window.__SC_WS__.close(); // the relay's close: not closeWs(), so nothing of the app's is parked
}, withError);
const lateHint = async (page) => {
  await page.waitForFunction(() => !document.querySelector("#scrRoom").hidden, { timeout: 15000 }).catch(() => {});
  await sleep(1000);
  return onScreen(page, "#roomHint");
};
const late1 = await gatePair("a");
await forgeAndHangUp(late1.page, false);
const lh1 = await lateHint(late1.page);
check("L2: a refusal computed after the relay hung up is on the room screen (the MITM refusal)",
  /^Authentication failed — disconnecting/.test(lh1.text) && lh1.onTop, JSON.stringify({ ...lh1, text: lh1.text.slice(0, 50) }));
const late2 = await gatePair("b");
await forgeAndHangUp(late2.page, true);
const lh2 = await lateHint(late2.page);
check("L2: an `error` frame queued behind it does not replace the refusal with the relay's sentence",
  /^Authentication failed — disconnecting/.test(lh2.text) && lh2.onTop && lh2.asides === 0 && !/created this chat left/.test(lh2.text),
  JSON.stringify({ ...lh2, text: lh2.text.slice(0, 50) }));
await late2.page.evaluate(() => { window.__SC_CLOSE_ON_OPEN__ = true; window.__SC_CLOSED_ON_OPEN__ = false; });
await late2.page.click("#connect");
await late2.page.waitForFunction(() => window.__SC_CLOSED_ON_OPEN__ === true, { timeout: 15000 }).catch(() => {});
await waitStatus(late2.page, "disconnected");
await sleep(500);
const nextHint = { closedOnOpen: await late2.page.evaluate(() => window.__SC_CLOSED_ON_OPEN__), ...(await onScreen(late2.page, "#roomHint")) };
check("L2: the next session, closed by the relay before any frame, shows no stale 'room closed' sentence",
  nextHint.closedOnOpen && !/created this chat left/.test(nextHint.text), JSON.stringify(nextHint));

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
