// Two-agent live-room run of the JOIN-APPROVAL flow (pentest 2026-07-26 P-08).
//
//   node e2e/room-admission.mjs
//
// Needs the relay running (backend/run.sh) and system Chromium.
//
// The finding: room entry was authorized solely by knowing the room id, so
// anyone who learned a chat code could take one of the two slots and lock the
// invited peer out with "room full". Entry is now owner-approved, and the two
// properties that matter are asserted here against REAL browser peers:
//
//   1. a squatter who knocks FIRST cannot keep the invited peer out, and
//   2. what the owner is shown is the knocker's actual key fingerprint, so the
//      decision is made on identity rather than on being first.
//
// It also drives the ordinary two-person path end to end (approve -> handshake
// -> safety number -> messages both ways), because an approval step that
// breaks the normal case would be a worse bug than the one it fixes.
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

const errors = [];
// Each agent gets its OWN browser context: a live-room peer must have its own
// identity and its own localStorage, or the test would just be one user talking
// to itself.
async function agent(label, viewport = { width: 1000, height: 900 }) {
  const ctx = await browser.createBrowserContext();
  const page = await ctx.newPage();
  page.on("pageerror", (e) => errors.push(`${label}: ${e.message}`));
  page.on("console", (m) => {
    const t = m.text();
    if (m.type() === "error" && !/favicon|404/.test(t)) errors.push(`${label}: ${t}`);
  });
  await page.setViewport(viewport);
  await page.goto(APP, { waitUntil: "networkidle0" });
  // Create an identity (DHKE needs one) and read its fingerprint.
  await page.type("#idPass", PASS);
  await page.click("#idCreate");
  await page.waitForFunction(() => !document.querySelector("#idExport").hidden, { timeout: 60000 });
  // The element carries a "Your fingerprint: " label; compare the value only.
  const fingerprint = await page.evaluate(() =>
    document.querySelector("#idFingerprint").textContent.replace(/^[^:]*:\s*/, "").trim());
  // Step 1 -> step 2: the room screen is where Connect lives.
  await page.click("#toRoom");
  await page.waitForFunction(() => !document.querySelector("#scrRoom").hidden, { timeout: 20000 });
  return { label, ctx, page, fingerprint };
}

const text = (page, sel) => page.evaluate((s) => {
  const el = document.querySelector(s);
  return el ? el.textContent.trim() : "";
}, sel);

const visible = (page, sel) => page.evaluate((s) => {
  const el = document.querySelector(s);
  if (!el || el.hidden) return false;
  const r = el.getBoundingClientRect();
  return r.width > 0 && r.height > 0;
}, sel);

// app.js ignores admit/deny clicks in the first 500 ms after a prompt (or a
// new knock at its head) appears — a tap aimed at what used to be there must
// not decide it (2026-09-22 rework pentest, tap-through). A person reads the
// fingerprint first anyway; the test pauses the same way before it decides.
const DECIDE_PAUSE = 600;

// Put `code` in the room field and press Connect.
async function joinRoom(page, code) {
  await page.evaluate(() => { document.querySelector("#room").value = ""; });
  await page.type("#room", code);
  await page.click("#connect");
}

// What the page looked like the moment the admission sheet was un-hidden, in
// the same task (before any paint, before a test could react): whether its
// entrance animation takes pointer events, what a tap on the centre of "Let
// them in" would hit, which animations run, and when (page clock).
async function watchReveal(page) {
  await page.evaluate(() => {
    window.__reveal = null;
    const admit = document.querySelector("#admit");
    new MutationObserver(() => {
      if (admit.hidden || window.__reveal) return;
      const r = document.querySelector("#admitOk").getBoundingClientRect();
      const hit = document.elementFromPoint(r.left + r.width / 2, r.top + r.height / 2);
      window.__reveal = {
        at: performance.now(),
        pe: getComputedStyle(admit).pointerEvents,
        okCentreHits: hit ? (hit.closest("button")?.id || hit.id || hit.tagName) : "nothing",
        anims: admit.getAnimations().map((a) => a.animationName || "anim"),
      };
    }).observe(admit, { attributes: true, attributeFilter: ["hidden"] });
  });
}
const readReveal = (page) => page.evaluate(() => window.__reveal);
const centreOf = (page, sel) => page.evaluate((s) => {
  const r = document.querySelector(s).getBoundingClientRect();
  return { x: r.left + r.width / 2, y: r.top + r.height / 2 };
}, sel);
// How often the owner has decided so far: "you let someone in" / "you denied
// someone" are its own log lines, one per decision.
const decided = async (page) => {
  const log = await text(page, "#log");
  return { admits: log.split("you let someone in").length - 1, denies: log.split("you denied someone").length - 1 };
};

console.log(`\n=== room admission, two agents (${APP}) ===\n`);

const alice = await agent("alice");   // creates the room -> owner
const bob = await agent("bob");       // the invited peer
const mallory = await agent("mallory"); // knows the code, was not invited

// --- 1. alice opens a room; the code is hers to share ----------------------
console.log("1. alice creates the chat");
const code = await alice.page.evaluate(() => document.querySelector("#room").value.trim());
check("a chat code is generated for the owner", /^[0-9a-f]{64}$/.test(code), code.slice(0, 12) + "…");
await alice.page.click("#connect");
// Anchored, not /connected/i — that also matches "disconnected". This agent is
// fresh so the substring could not bite here, but it is the same latent bug
// that made all-modes.mjs flaky (pentest 2026-07-29 item 13).
await alice.page.waitForFunction(
  () => document.querySelector("#chatStatus").textContent.trim().toLowerCase() === "connected",
  { timeout: 30000 });
const ownerLog = await text(alice.page, "#log");
check("owner is told the room is hers to control", /you decide who is let in/i.test(ownerLog),
  JSON.stringify(ownerLog.slice(-90)));

// --- 2. the squatter knocks FIRST ------------------------------------------
// This is the P-08 scenario: under the old protocol this connection took the
// second slot and the invited peer got "room full".
console.log("\n2. an uninvited peer who knows the code knocks first");
await joinRoom(mallory.page, code);
await mallory.page.waitForFunction(
  () => /waiting for approval/i.test(document.querySelector("#chatStatus").textContent),
  { timeout: 30000 });
check("uninvited peer is left WAITING, not seated", true);
await alice.page.waitForFunction(() => !document.querySelector("#admit").hidden, { timeout: 30000 });
const shownFp = await text(alice.page, "#admitFingerprint");
check("owner is shown the knocker's real key fingerprint",
  shownFp === mallory.fingerprint, `${shownFp.slice(0, 24)}… vs ${mallory.fingerprint.slice(0, 24)}…`);
const shownWho = await text(alice.page, "#admitWho");
check("an unknown key is marked as never verified", /never verified|not in your users list/i.test(shownWho),
  JSON.stringify(shownWho));
// Nothing of the session may have reached it: no safety number, no messaging.
const mallorySees = {
  verify: await visible(mallory.page, "#verify"),
  canSend: await mallory.page.evaluate(() => !document.querySelector("#text").disabled),
};
check("a waiting peer gets no key exchange and cannot send",
  !mallorySees.verify && !mallorySees.canSend, JSON.stringify(mallorySees));

// Phase 2a, B3 (a11y review): the sheet is modal for the keyboard as well.
// Everything behind it is inert, and Tab / Shift+Tab wrap inside it: from
// Leave chat (last) to the "?" beside the hint (first; phase 2b), through the
// fingerprint block, Let them in and Deny, and back.
const inertNow = (page) => page.evaluate(() =>
  ["#tabbar", "#scrChat > .topbar", "#verify", "#chat"].map((s) => document.querySelector(s).inert));
const behindSheet = await inertNow(alice.page);
check("B3: with the sheet up, the tab bar, chat bar, gate and log are inert",
  behindSheet.every((x) => x === true), JSON.stringify(behindSheet));
await alice.page.focus("#admitNo");
const tabWalk = [];
for (const shift of [false, false, true, false, false, false, false]) {
  if (shift) await alice.page.keyboard.down("Shift");
  await alice.page.keyboard.press("Tab");
  if (shift) await alice.page.keyboard.up("Shift");
  // An element without an id (the "?" summary) is named with where it is.
  tabWalk.push(await alice.page.evaluate(() => {
    const a = document.activeElement;
    return a.id || (a.closest("#admit") ? "admit:" : "") + a.tagName;
  }));
}
check("B3: Tab and Shift+Tab stay inside the sheet (Deny -> Leave chat -> the \"?\" -> fingerprint, Shift+Tab back to Leave, on to Deny)",
  JSON.stringify(tabWalk) === JSON.stringify(["admitLeave", "admit:SUMMARY", "admitLeave", "admit:SUMMARY", "admitFingerprint", "admitOk", "admitNo"]),
  JSON.stringify(tabWalk));

// --- 3. the invited peer knocks too, and is let in -------------------------
console.log("\n3. the invited peer knocks; alice denies the squatter and admits bob");
// Phase 2a fix round, C4 (B1): bob is someone alice verified before, so his
// prompt must carry her name for him and the same trust pill the lists draw.
const bobBundle = await bob.page.evaluate(async (pass) => {
  const { Identity } = await import("./identity.js");
  return (await Identity.import(localStorage.getItem("sc.identity.v1"), pass)).publicBundle();
}, PASS);
await alice.page.evaluate(async (b) => {
  const contacts = await import("./contacts.js");
  await contacts.upsert({ username: "bob", token: null, ed: b.ed, mldsa: b.mldsa, ecdh: b.ecdh, mlkem: b.mlkem, verified: true });
}, bobBundle);
await joinRoom(bob.page, code);
await bob.page.waitForFunction(
  () => /waiting for approval/i.test(document.querySelector("#chatStatus").textContent),
  { timeout: 30000 });
// Bob reaching "waiting for approval" only means the RELAY queued him — his
// knock still has to reach alice and be rendered. Reading #admitWarn straight
// after the status flip raced that and reported an empty string as a product
// failure. Poll instead; the assertion itself is unchanged.
let queueNote = "";
for (let i = 0; i < 20 && !/more waiting/i.test(queueNote); i++) {
  await sleep(250);
  queueNote = await text(alice.page, "#admitWarn");
}
check("owner is told more than one peer is waiting", /more waiting/i.test(queueNote),
  JSON.stringify(queueNote));

// Deny the squatter (it is first in the queue), then admit bob.
await sleep(DECIDE_PAUSE);
await alice.page.click("#admitNo");
await sleep(600);
const mallorySawDenial = await text(mallory.page, "#log");
check("the squatter is told it was denied", /did not let you in/i.test(mallorySawDenial),
  JSON.stringify(mallorySawDenial.slice(-80)));

await alice.page.waitForFunction(() => !document.querySelector("#admit").hidden, { timeout: 30000 });
const bobFp = await text(alice.page, "#admitFingerprint");
check("the second prompt shows bob's fingerprint", bobFp === bob.fingerprint,
  `${bobFp.slice(0, 24)}… vs ${bob.fingerprint.slice(0, 24)}…`);
const knownWho = await alice.page.evaluate(() => {
  const w = document.querySelector("#admitWho"), m = w.querySelector(".u-mark"), n = w.querySelector(".u-name");
  return { name: n ? n.textContent : null, mark: m ? m.className : null, words: m ? m.textContent : null };
});
check("B1: a known, verified knocker is shown by name with the green trust pill",
  knownWho.name === "bob" && /\bu-mark\b.*\bok\b/.test(knownWho.mark || "") && knownWho.words === "verified by you",
  JSON.stringify(knownWho));
await sleep(DECIDE_PAUSE);
await alice.page.click("#admitOk");

// --- 4. the squatter did NOT cost the invited peer the room ----------------
console.log("\n4. the real session completes anyway (the finding itself)");
await bob.page.waitForFunction(
  () => !document.querySelector("#verify").hidden, { timeout: 45000 });
await alice.page.waitForFunction(
  () => !document.querySelector("#verify").hidden, { timeout: 45000 });
const [snA, snB] = [await text(alice.page, "#safetyNumber"), await text(bob.page, "#safetyNumber")];
check("both peers reach the safety-number gate after approval", !!snA && snA === snB,
  `${snA.slice(0, 20)}… / ${snB.slice(0, 20)}…`);
const afterDecide = await inertNow(alice.page);
check("B3: once the knocks are decided nothing is inert", afterDecide.every((x) => x === false),
  JSON.stringify(afterDecide));
// Fix round, C1 (a11y review): the admit hid the focused button; focus is on
// the gate's safety number now, on both sides — never dropped to <body>.
const gateFocus = async (page) => {
  await page.waitForFunction(() => document.activeElement.id === "safetyNumber", { timeout: 3000 }).catch(() => {});
  return page.evaluate(() => document.activeElement.id || document.activeElement.tagName);
};
const [gfA, gfB] = [await gateFocus(alice.page), await gateFocus(bob.page)];
check("C1: after Let them in, focus is on the gate (safety number) for owner and guest",
  gfA === "safetyNumber" && gfB === "safetyNumber", JSON.stringify({ owner: gfA, guest: gfB }));

await alice.page.click("#verifyOk");
await bob.page.click("#verifyOk");
await sleep(400);
await bob.page.type("#text", "bob got in despite the squatter");
await bob.page.click("#send");
let aliceLog = "";
for (let i = 0; i < 10 && !/despite the squatter/.test(aliceLog); i++) {
  await sleep(700);
  aliceLog = await text(alice.page, "#log");
}
check("messages flow after approval", /despite the squatter/.test(aliceLog),
  JSON.stringify(aliceLog.slice(-70)));

await alice.page.type("#text", "and back the other way");
await alice.page.click("#send");
let bobLog = "";
for (let i = 0; i < 10 && !/back the other way/.test(bobLog); i++) {
  await sleep(700);
  bobLog = await text(bob.page, "#log");
}
check("and both directions work", /back the other way/.test(bobLog),
  JSON.stringify(bobLog.slice(-70)));

// The denied peer must still be out — not silently re-seated by the relay.
const malloryStillOut = await mallory.page.evaluate(() =>
  document.querySelector("#text").disabled && document.querySelector("#verify").hidden);
check("the denied peer never gains the room", malloryStillOut);

// Phase 2a, B2 (design review): after the in-person check the live-room header
// says so, next to (not instead of) the connection status.
const header = (page) => page.evaluate(() => {
  const v = document.querySelector("#chatVerified"), r = v.getBoundingClientRect();
  return { hidden: v.hidden, shown: !v.hidden && r.width > 0 && r.height > 0, text: v.textContent,
    status: document.querySelector("#chatStatus").textContent };
});
const [hdrA, hdrB] = [await header(alice.page), await header(bob.page)];
check("B2: after the safety-number check both headers show 'verified in person'; the status still reads connected",
  hdrA.shown && hdrB.shown && hdrA.text === "verified in person" && hdrA.status === "connected" && hdrB.status === "connected",
  JSON.stringify({ hdrA, hdrB }));
await alice.page.click("#disconnect");
await alice.page.waitForFunction(
  () => document.querySelector("#chatStatus").textContent.trim() === "disconnected", { timeout: 15000 }).catch(() => {});
const hdrGone = await header(alice.page);
check("B2: after disconnect the verified pill is hidden", hdrGone.hidden && hdrGone.status === "disconnected",
  JSON.stringify(hdrGone));

// --- 5. on a phone, a tap already on its way does not let anyone in --------
// 2026-09-22 rework pentest (tap-through): on a 390px touch screen the
// admission sheet used to dock over the bottom tab bar, clickable while it
// was still fading in, with "Let them in" where the Chats tab had been. A
// tap meant for the tab as the knock arrived admitted the knocker. Now the
// sheet sits above the tab bar (the bar is under the inert scrim) and app.js
// ignores decisions in the prompt's first 500 ms. Both taps below arrive
// inside that window, the way a real mis-tap does; neither may admit.
console.log("\n5. phone (390x844, touch): a tap on its way as the knock arrives admits no one");
const PHONE = { width: 390, height: 844, deviceScaleFactor: 2, isMobile: true, hasTouch: true };
const olga = await agent("olga-phone", PHONE);     // the owner, on a phone
const gus = await agent("gus");                     // the invited peer
const phoneCode = await olga.page.evaluate(() => document.querySelector("#room").value.trim());
await olga.page.$eval("#connect", (e) => e.click());
await olga.page.waitForFunction(
  () => document.querySelector("#chatStatus").textContent.trim().toLowerCase() === "connected",
  { timeout: 30000 });
// Where the thumb goes for the Chats tab, measured BEFORE anyone knocks.
const chatsTab = await olga.page.evaluate(() => {
  const r = document.querySelector('.navitem[data-view="chats"]').getBoundingClientRect();
  return { x: r.left + r.width / 2, y: r.top + r.height / 2 };
});
await watchReveal(olga.page);
await joinRoom(gus.page, phoneCode);
await olga.page.waitForFunction(() => !document.querySelector("#admit").hidden, { timeout: 30000 });
const underThumb = await olga.page.evaluate(({ x, y }) => {
  const el = document.elementFromPoint(x, y);
  return el ? (el.closest("#admit") ? "#admit " + (el.closest("button")?.id || el.id || el.tagName) : "outside the sheet") : "nothing";
}, chatsTab);
await olga.page.touchscreen.tap(chatsTab.x, chatsTab.y);
// ...and a tap straight onto "Let them in" as it appears.
const okBox = await olga.page.evaluate(() => {
  const r = document.querySelector("#admitOk").getBoundingClientRect();
  return { x: r.left + r.width / 2, y: r.top + r.height / 2 };
});
await olga.page.touchscreen.tap(okBox.x, okBox.y);
await sleep(300);
const afterTaps = {
  prompt: await olga.page.evaluate(() => !document.querySelector("#admit").hidden),
  guest: (await text(gus.page, "#chatStatus")).toLowerCase(),
  guestGate: await visible(gus.page, "#verify"),
  ownerLog: await text(olga.page, "#log"),
};
check("phone: the admission sheet does not cover the tab bar", underThumb === "outside the sheet", underThumb);
check("phone: taps landing as the prompt appears admit no one",
  afterTaps.prompt && /waiting for approval/.test(afterTaps.guest) && !afterTaps.guestGate &&
  !/you let someone in/.test(afterTaps.ownerLog), JSON.stringify({ ...afterTaps, ownerLog: afterTaps.ownerLog.slice(-60) }));
// The CSS layer on its own (2026-09-23 re-pentest PT2): the moment the sheet
// is un-hidden its entrance animation takes no pointer events, so a tap there
// reaches nothing in it, whatever app.js does with clicks.
const olgaReveal = await readReveal(olga.page);
check("phone: the sheet takes no pointer events as it appears (CSS layer)",
  !!olgaReveal && olgaReveal.pe === "none" && olgaReveal.okCentreHits !== "admitOk", JSON.stringify(olgaReveal));
// ...and the geometry itself, from rects once the entrance has finished: the
// sheet ends at or above the top of the tab bar, and the tab bar is showing.
await olga.page.waitForFunction(() => document.querySelector("#admit").getAnimations().length === 0, { timeout: 5000 });
const sheetVsTabs = await olga.page.evaluate(() => {
  const a = document.querySelector("#admit").getBoundingClientRect();
  const t = document.querySelector(".tabbar");
  const r = t.getBoundingClientRect();
  return { sheetBottom: a.bottom, tabbarTop: r.top, tabbarShown: getComputedStyle(t).display !== "none" && r.height > 0 };
});
check("phone: the sheet ends above the tab bar (rects, 390x844)",
  sheetVsTabs.tabbarShown && sheetVsTabs.sheetBottom <= sheetVsTabs.tabbarTop + 0.5, JSON.stringify(sheetVsTabs));
// A deliberate decision, after a pause, still works on the phone.
await sleep(DECIDE_PAUSE);
await olga.page.tap("#admitOk");
await gus.page.waitForFunction(() => !document.querySelector("#verify").hidden, { timeout: 45000 }).catch(() => {});
check("phone: after a pause, Let them in admits the knocker", await visible(gus.page, "#verify"),
  JSON.stringify((await text(gus.page, "#chatStatus")).toLowerCase()));

// --- 6. the same with reduced motion: the 500 ms guard on its own ---------
// 2026-09-23 re-pentest (PT1, PT2). With prefers-reduced-motion there is no
// entrance animation, so nothing in CSS keeps a tap off the sheet: app.js is
// the only layer. Three independent passes, each with its own phone owner:
//   a) the tap pass of section 5 again;
//   b) a knock that arrives while the owner is on another view, revealed by
//      switching back to the Live room long after it came in — the guard
//      must start at the reveal, not at the knock;
//   c) keys: Enter on the auto-focused Deny, then Shift+Tab to "Let them in"
//      and Enter, both inside the first 500 ms — neither may decide — and a
//      normal admit with Enter after the pause.
console.log("\n6. phone, reduced motion (no entrance animation): the JS guard alone");
async function reducedOwner(label) {
  const owner = await agent(label, PHONE);
  await owner.page.emulateMediaFeatures([{ name: "prefers-reduced-motion", value: "reduce" }]);
  const roomCode = await owner.page.evaluate(() => document.querySelector("#room").value.trim());
  await owner.page.$eval("#connect", (e) => e.click());
  await owner.page.waitForFunction(
    () => document.querySelector("#chatStatus").textContent.trim().toLowerCase() === "connected",
    { timeout: 30000 });
  return { ...owner, roomCode };
}
// A deliberate tap after the pause — only if there is still a prompt to tap
// (a failed check above may already have let the knocker in).
const tapIfShown = async (page, sel) => { if (await visible(page, sel)) await page.tap(sel); };

// a) taps as the prompt appears
const ra = await reducedOwner("rita-a-phone-reduced"), k1 = await agent("knocker-1");
const raChatsTab = await centreOf(ra.page, '.navitem[data-view="chats"]');
await watchReveal(ra.page);
await joinRoom(k1.page, ra.roomCode);
await ra.page.waitForFunction(() => !document.querySelector("#admit").hidden, { timeout: 30000, polling: "mutation" });
await ra.page.touchscreen.tap(raChatsTab.x, raChatsTab.y);
const raOk = await centreOf(ra.page, "#admitOk");
await ra.page.touchscreen.tap(raOk.x, raOk.y);
await sleep(300);
const raReveal = await readReveal(ra.page);
check("reduced motion: the sheet appears with no animation (only app.js guards it)",
  !!raReveal && raReveal.anims.length === 0 && raReveal.pe !== "none", JSON.stringify(raReveal));
const raTaps = { ...(await decided(ra.page)), guest: (await text(k1.page, "#chatStatus")).toLowerCase() };
check("reduced motion: taps landing as the prompt appears admit no one",
  raTaps.admits === 0 && raTaps.denies === 0 && /waiting for approval/.test(raTaps.guest), JSON.stringify(raTaps));
await sleep(DECIDE_PAUSE);
await tapIfShown(ra.page, "#admitNo");
await k1.page.waitForFunction(() => /did not let you in/.test(document.querySelector("#log").textContent), { timeout: 20000 }).catch(() => {});
check("reduced motion: after a pause, Deny turns the knocker away", /did not let you in/.test(await text(k1.page, "#log")));
// Fix round, C1: that Deny emptied the queue and hid the focused button.
const afterDeny = await ra.page.evaluate(() => {
  const a = document.activeElement, r = a.getBoundingClientRect();
  return { id: a.id || a.tagName, shown: a !== document.body && r.width > 0 && r.height > 0 };
});
check("C1: after the last Deny, focus moves to the chat bar (Copy room id), not <body>",
  afterDeny.id === "copyRoom" && afterDeny.shown, JSON.stringify(afterDeny));

// b) a prompt revealed by a view switch
const rb = await reducedOwner("rita-b-phone-reduced"), k2 = await agent("knocker-2");
const rbUsersTab = await centreOf(rb.page, '.navitem[data-view="users"]');
await rb.page.touchscreen.tap(rbUsersTab.x, rbUsersTab.y);
await rb.page.waitForFunction(() => !document.querySelector("#viewUsers").hidden);
await joinRoom(k2.page, rb.roomCode);
await rb.page.waitForFunction(() => !document.querySelector("#admit").hidden, { timeout: 30000 });
const rbBehindInert = await rb.page.evaluate(() => document.querySelector("#tabbar").inert); // B3, read below
await sleep(900); // the knock is older than the guard by the time the owner looks
const rbLiveTab = await centreOf(rb.page, '.navitem[data-view="live"]');
await rb.page.touchscreen.tap(rbLiveTab.x, rbLiveTab.y);
const focusOnReveal = await rb.page.evaluate(() => document.activeElement.id || document.activeElement.tagName);
const rbOk = await centreOf(rb.page, "#admitOk");
await rb.page.touchscreen.tap(rbOk.x, rbOk.y);
await sleep(300);
const rbSwitch = { ...(await decided(rb.page)), focusOnReveal, guest: (await text(k2.page, "#chatStatus")).toLowerCase() };
check("reduced motion: a prompt revealed by switching back to the Live room ignores a tap at once",
  rbSwitch.admits === 0 && /waiting for approval/.test(rbSwitch.guest), JSON.stringify(rbSwitch));
check("reduced motion: that reveal puts focus on Deny", focusOnReveal === "admitNo", focusOnReveal);
const rbRevealedInert = await rb.page.evaluate(() => document.querySelector("#tabbar").inert);
check("B3: a knock behind another view leaves the tab bar usable; revealing it makes the bar inert",
  rbBehindInert === false && rbRevealedInert === true, JSON.stringify({ rbBehindInert, rbRevealedInert }));

// c) the keyboard inside the first 500 ms, then after it
const rc = await reducedOwner("rita-c-phone-reduced"), k3 = await agent("knocker-3");
await watchReveal(rc.page);
await joinRoom(k3.page, rc.roomCode);
await rc.page.waitForFunction(() => !document.querySelector("#admit").hidden, { timeout: 30000, polling: "mutation" });
const focusOnShow = await rc.page.evaluate(() => document.activeElement.id);
await rc.page.keyboard.press("Enter");
await rc.page.keyboard.down("Shift");
await rc.page.keyboard.press("Tab");
await rc.page.keyboard.up("Shift");
const focusAfterShiftTab = await rc.page.evaluate(() => document.activeElement.id);
await rc.page.keyboard.press("Enter");
const keysAt = await rc.page.evaluate(() => performance.now() - window.__reveal.at);
await sleep(300);
const rcKeys = {
  ...(await decided(rc.page)), focusOnShow, focusAfterShiftTab, keysWithinMs: Math.round(keysAt),
  guest: (await text(k3.page, "#chatStatus")).toLowerCase(),
};
check("keyboard: Enter on the focused Deny inside 500 ms denies no one",
  focusOnShow === "admitNo" && keysAt < 500 && rcKeys.denies === 0 && /waiting for approval/.test(rcKeys.guest),
  JSON.stringify(rcKeys));
check("keyboard: Shift+Tab to Let them in + Enter inside 500 ms admits no one",
  focusAfterShiftTab === "admitOk" && keysAt < 500 && rcKeys.admits === 0 && /waiting for approval/.test(rcKeys.guest),
  JSON.stringify(rcKeys));
await sleep(DECIDE_PAUSE);
await rc.page.keyboard.press("Enter"); // focus is still on "Let them in"
await k3.page.waitForFunction(() => !document.querySelector("#verify").hidden, { timeout: 45000 }).catch(() => {});
check("keyboard: after the pause, Enter on Let them in admits the knocker", await visible(k3.page, "#verify"),
  JSON.stringify((await text(k3.page, "#chatStatus")).toLowerCase()));

// --- 7. back from the background; input stamped before the prompt ---------
// 2026-09-23 final pentest.
//   a) The knock arrives while the owner's page is in the background. The
//      click that brings it forward must not decide the prompt (app.js
//      re-arms the guard when the page is shown or focused again); a click
//      600 ms later does.
//   b) PT4b: the guard times the input by its own timestamp. A tap that
//      happened 100 ms BEFORE the prompt appeared but is delivered 650 ms
//      after it must not admit; the same tap stamped "now" does.
//   c) PT4a: a click while the next knock's prompt is still being drawn (the
//      head withdrew; the screen still shows it) must not decide for the
//      knock the owner has not seen yet.
console.log("\n7. back from the background; input stamped before the prompt; a head swap");
const countOkClicks = (page) => page.evaluate(() => {
  window.__okClicks = 0;
  document.addEventListener("click", (e) => { if (e.target.closest && e.target.closest("#admitOk")) window.__okClicks++; }, true);
});
const okClicks = (page) => page.evaluate(() => window.__okClicks);
async function ownerConnected(owner) {
  const roomCode = await owner.page.evaluate(() => document.querySelector("#room").value.trim());
  await owner.page.$eval("#connect", (e) => e.click());
  await owner.page.waitForFunction(
    () => document.querySelector("#chatStatus").textContent.trim().toLowerCase() === "connected", { timeout: 30000 });
  return roomCode;
}

// a) the owner is looking at another page when the knock arrives
const bgOwner = await agent("owner-background"), k4 = await agent("knocker-4");
const bgCode = await ownerConnected(bgOwner);
const elsewhere = await bgOwner.ctx.newPage();
await elsewhere.goto("about:blank");
await elsewhere.bringToFront();
await joinRoom(k4.page, bgCode);
await bgOwner.page.waitForFunction(() => !document.querySelector("#admit").hidden, { timeout: 30000, polling: 200 });
const shownWhile = await bgOwner.page.evaluate(() => document.visibilityState);
await sleep(1200); // the prompt is far older than the guard when the owner comes back
await bgOwner.page.bringToFront();
await countOkClicks(bgOwner.page);
const bgOk = await centreOf(bgOwner.page, "#admitOk");
await bgOwner.page.mouse.click(bgOk.x, bgOk.y);
await sleep(300);
const bgFirst = { shownWhile, okClicks: await okClicks(bgOwner.page), ...(await decided(bgOwner.page)), guest: (await text(k4.page, "#chatStatus")).toLowerCase() };
check("background: the click on Let them in that brings the page back admits no one",
  shownWhile === "hidden" && bgFirst.okClicks === 1 && bgFirst.admits === 0 && /waiting for approval/.test(bgFirst.guest), JSON.stringify(bgFirst));
await sleep(DECIDE_PAUSE);
await bgOwner.page.mouse.click(bgOk.x, bgOk.y);
await k4.page.waitForFunction(() => !document.querySelector("#verify").hidden, { timeout: 45000 }).catch(() => {});
check("background: a click after the pause admits the knocker", await visible(k4.page, "#verify"),
  JSON.stringify((await text(k4.page, "#chatStatus")).toLowerCase()));
await elsewhere.close();

// b) a tap stamped before the prompt, delivered after the guard
const rd = await reducedOwner("rita-d-phone-reduced"), k5 = await agent("knocker-5");
await watchReveal(rd.page);
await joinRoom(k5.page, rd.roomCode);
await rd.page.waitForFunction(() => !document.querySelector("#admit").hidden, { timeout: 30000, polling: "mutation" });
const shownWallMs = await rd.page.evaluate(() => performance.timeOrigin + window.__reveal.at);
await sleep(650);
await countOkClicks(rd.page);
const rdOk = await centreOf(rd.page, "#admitOk");
const rdCdp = await rd.page.createCDPSession();
const stampedTap = async (sec) => {  // Input.dispatchTouchEvent takes the input's own time, in epoch seconds
  await rdCdp.send("Input.dispatchTouchEvent", { type: "touchStart", touchPoints: [{ x: rdOk.x, y: rdOk.y }], timestamp: sec });
  await rdCdp.send("Input.dispatchTouchEvent", { type: "touchEnd", touchPoints: [], timestamp: sec + 0.02 });
};
await stampedTap((shownWallMs - 100) / 1000);
await sleep(300);
const rdLate = { okClicks: await okClicks(rd.page), ...(await decided(rd.page)), guest: (await text(k5.page, "#chatStatus")).toLowerCase() };
check("PT4b: a tap stamped 100 ms before the prompt, delivered 650 ms after it, admits no one",
  rdLate.okClicks === 1 && rdLate.admits === 0 && /waiting for approval/.test(rdLate.guest), JSON.stringify(rdLate));
await stampedTap(Date.now() / 1000);
await k5.page.waitForFunction(() => !document.querySelector("#verify").hidden, { timeout: 45000 }).catch(() => {});
check("PT4b: the same tap stamped now admits the knocker", await visible(k5.page, "#verify"),
  JSON.stringify((await text(k5.page, "#chatStatus")).toLowerCase()));

// c) the head withdraws; a click lands while the next knock's digest is still being computed
const hs = await agent("owner-headswap");
await hs.page.evaluate(() => { // hostile-relay.mjs's approach, in the page: remember knocks, allow injecting frames
  const Real = window.WebSocket;
  window.__knocks = [];
  window.WebSocket = class extends Real {
    constructor(...a) {
      super(...a);
      window.__ws = this;
      this.addEventListener("message", (ev) => { try { const m = JSON.parse(ev.data); if (m.type === "knock") window.__knocks.push(m.jid); } catch {} });
    }
  };
});
const hsCode = await ownerConnected(hs);
const [k6, k7] = [await agent("knocker-6"), await agent("knocker-7")];
await joinRoom(k6.page, hsCode);
await hs.page.waitForFunction(() => !document.querySelector("#admit").hidden && window.__knocks.length === 1, { timeout: 30000 });
await joinRoom(k7.page, hsCode);
await hs.page.waitForFunction(() => window.__knocks.length === 2 && /more waiting/.test(document.querySelector("#admitWarn").textContent), { timeout: 30000 });
await sleep(900); // the prompt for knocker-6 is well past its guard
const swap = await hs.page.evaluate(async () => {
  const fp = document.querySelector("#admitFingerprint"), warn = document.querySelector("#admitWarn"), shown = fp.textContent;
  window.__ws.dispatchEvent(new MessageEvent("message", { data: JSON.stringify({ type: "withdrawn", jid: window.__knocks[0] }) }));
  // showNextKnock clears the warning line before it awaits the digest: from then on the queue head is knocker-7
  let hops = 0;
  for (; hops < 50 && /more waiting/.test(warn.textContent); hops++) await Promise.resolve();
  const oldStillShown = fp.textContent === shown && !/more waiting/.test(warn.textContent);
  document.querySelector("#admitOk").click();
  return { hops, oldStillShown };
});
await sleep(1500);
const hsOut = { ...swap, ...(await decided(hs.page)), knocker7: (await text(k7.page, "#chatStatus")).toLowerCase() };
check("PT4a: a click while the next knock's prompt is still being drawn admits no one",
  hsOut.oldStillShown && hsOut.admits === 0 && /waiting for approval/.test(hsOut.knocker7), JSON.stringify(hsOut));

// Phase 2a, B3: the connection drops while a knock is still pending (knocker-7's
// prompt is up). The reset path must lift the modal — nothing may stay inert.
const beforeDrop = { prompt: await visible(hs.page, "#admit"), inert: await inertNow(hs.page) };
await hs.page.evaluate(() => window.__ws.close());
await hs.page.waitForFunction(
  () => document.querySelector("#chatStatus").textContent.trim() === "disconnected", { timeout: 15000 }).catch(() => {});
const afterDrop = { prompt: await visible(hs.page, "#admit"), inert: await inertNow(hs.page) };
check("B3: a disconnect with a knock pending leaves nothing inert",
  beforeDrop.prompt && beforeDrop.inert.every((x) => x === true) && !afterDrop.prompt && afterDrop.inert.every((x) => x === false),
  JSON.stringify({ beforeDrop, afterDrop }));

// --- 8. the sheet's own way out (phase 2a fix round, pentest P3) -----------
// Under an endless supply of knocks Deny was the only way off the modal
// sheet. "Leave chat" sits in its Tab cycle, disconnects (after the same
// 500 ms rule as the decisions — round 3, L1: section 9), and leaves nothing
// inert. The waiter is then told by the REAL relay that the room closed.
console.log("\n8. 'Leave chat' inside the admission sheet");
const lv = await agent("owner-leaves"), k8 = await agent("knocker-8");
const lvCode = await ownerConnected(lv);
await joinRoom(k8.page, lvCode);
await lv.page.waitForFunction(() => !document.querySelector("#admit").hidden, { timeout: 30000 });
await lv.page.focus("#admitNo");
await lv.page.keyboard.press("Tab");
const onLeave = await lv.page.evaluate(() => document.activeElement.id);
await sleep(DECIDE_PAUSE);
await lv.page.keyboard.press("Enter");
await lv.page.waitForFunction(
  () => document.querySelector("#chatStatus").textContent.trim() === "disconnected", { timeout: 15000 }).catch(() => {});
const left = {
  onLeave, status: (await text(lv.page, "#chatStatus")).toLowerCase(), prompt: await visible(lv.page, "#admit"),
  inert: await inertNow(lv.page), decisions: await decided(lv.page),
};
check("P3: Tab from Deny reaches Leave chat; Enter leaves — disconnected, sheet gone, nothing inert, no decision",
  left.onLeave === "admitLeave" && left.status === "disconnected" && !left.prompt && left.inert.every((x) => x === false) &&
  left.decisions.admits === 0 && left.decisions.denies === 0, JSON.stringify(left));
await k8.page.waitForFunction(
  () => document.querySelector("#chatStatus").textContent.trim() === "disconnected", { timeout: 15000 }).catch(() => {});
const k8Hint = await text(k8.page, "#roomHint");
check("A3 (real relay): the waiter reads the app's 'room closed' sentence after its socket closed",
  k8Hint === "The person who created this chat left, so the chat was closed.", JSON.stringify(k8Hint));

// --- 9. round 3, pentest L1: "Leave chat" under a tap meant for the composer --
// On a phone the sheet docks over the composer. With reduced motion nothing in
// CSS delays it, so a tap aimed at the composer as the knock arrives lands on
// "Leave chat" — which must ignore it (the same 500 ms rule), then work.
console.log("\n9. phone, reduced motion: a tap meant for the composer as a knock arrives does not leave");
const lt = await reducedOwner("owner-leavetap-phone-reduced"), k9 = await agent("knocker-9");
const composer = await lt.page.evaluate(() => ["#send", "#text"].map((s) => {
  const r = document.querySelector(s).getBoundingClientRect(); return { s, x: r.left + r.width / 2, y: r.top + r.height / 2 };
}));
await joinRoom(k9.page, lt.roomCode);
await lt.page.waitForFunction(() => !document.querySelector("#admit").hidden, { timeout: 30000, polling: "mutation" });
const onLeaveNow = await lt.page.evaluate((pts) => pts.filter((p) => {
  const t = document.elementFromPoint(p.x, p.y); return t && t.closest("#admitLeave");
}), composer);
const aim = onLeaveNow[0] || composer[0];
await lt.page.touchscreen.tap(aim.x, aim.y);
await sleep(300);
const ltEarly = (await text(lt.page, "#chatStatus")).toLowerCase();
await sleep(DECIDE_PAUSE);
await lt.page.touchscreen.tap(aim.x, aim.y);
await lt.page.waitForFunction(
  () => document.querySelector("#chatStatus").textContent.trim() === "disconnected", { timeout: 15000 }).catch(() => {});
const ltLate = (await text(lt.page, "#chatStatus")).toLowerCase();
check("L1: a tap on the composer's spot as the sheet appears lands on Leave chat and is ignored; 600 ms later it leaves",
  !!onLeaveNow.length && ltEarly === "connected" && ltLate === "disconnected",
  JSON.stringify({ aim: aim.s, coveredByLeave: onLeaveNow.map((p) => p.s), ltEarly, ltLate }));

// --- 10. round 3, T1: Enter, Enter on the auto-focused Deny while the gate is up --
// The owner let A in and is at the safety-number gate when B knocks. Enter on
// the focused Deny turns B away and hides the sheet; focus goes to the safety
// number, so a second Enter (a double press, key repeat) must pass nothing.
console.log("\n10. a knock while the gate is up: Enter on Deny, then Enter again");
const df = await agent("owner-denyfocus"), dA = await agent("peer-a"), dB = await agent("knocker-b");
const dfCode = await ownerConnected(df);
await joinRoom(dA.page, dfCode);
await df.page.waitForFunction(() => !document.querySelector("#admit").hidden, { timeout: 30000 });
await sleep(DECIDE_PAUSE);
await df.page.click("#admitOk");
await df.page.waitForFunction(() => !document.querySelector("#verify").hidden, { timeout: 60000 });
await joinRoom(dB.page, dfCode);
await df.page.waitForFunction(() => !document.querySelector("#admit").hidden, { timeout: 30000 });
await sleep(DECIDE_PAUSE);
const dfFocus0 = await df.page.evaluate(() => document.activeElement.id);
await df.page.keyboard.press("Enter");
await sleep(400);
await df.page.keyboard.press("Enter");
await sleep(800);
const dfAfter = await df.page.evaluate(() => ({
  focus: document.activeElement.id || document.activeElement.tagName,
  gate: !document.querySelector("#verify").hidden, sheet: !document.querySelector("#admit").hidden,
  pill: !document.querySelector("#chatVerified").hidden,
}));
const dfDecided = await decided(df.page);
check("T1: Enter on Deny, then Enter again, passes no gate (focus on the safety number, no verified pill)",
  dfFocus0 === "admitNo" && dfDecided.denies === 1 && dfAfter.gate && !dfAfter.sheet && !dfAfter.pill &&
  dfAfter.focus === "safetyNumber", JSON.stringify({ dfFocus0, ...dfAfter, ...dfDecided }));

// --- 11. phase 2b fix round, pentest S1: a warning must not outlive its gate --
// The key-changed variants rewrite #verifyHint; the clean first-contact branch
// used to set only the title, so the NEXT clean session in the same page still
// showed the old warning. Owner "sw" meets peer A under a pin that is not A's
// key (planted through the page's own store, as section 3 does), says "It
// differs", then opens a new chat code with peer B: a clean first contact.
console.log("\n11. a key-changed gate, then a clean first contact in the same page");
const sw = await agent("owner-stalehint"), sA = await agent("peer-stale-a"), sB = await agent("peer-stale-b");
const defaultHint = await text(sw.page, "#verifyHint"); // index.html's sentence, untouched so far
const swCode1 = await sw.page.evaluate(() => document.querySelector("#room").value.trim());
await sw.page.evaluate(async (code, pass) => {
  const { Identity } = await import("./identity.js");
  const contacts = await import("./contacts.js");
  const own = (await Identity.import(localStorage.getItem("sc.identity.v1"), pass)).publicBundle();
  await contacts.savePin("room:" + code, own); // any key but A's
}, swCode1, PASS);
const gateNow = (page) => page.evaluate(() => ({
  changed: document.querySelector("#verify").classList.contains("changed"),
  hint: document.querySelector("#verifyHint").textContent.trim(),
}));
async function admitAtGate(owner, peer, code) {
  await joinRoom(peer.page, code);
  await owner.page.waitForFunction(() => !document.querySelector("#admit").hidden, { timeout: 30000 });
  await sleep(DECIDE_PAUSE);
  await owner.page.click("#admitOk");
  await owner.page.waitForFunction(() => !document.querySelector("#verify").hidden, { timeout: 60000 });
}
await ownerConnected(sw);
await admitAtGate(sw, sA, swCode1);
const gateChanged = await gateNow(sw.page);
await sw.page.click("#verifyNo");
await sw.page.waitForFunction(() => !document.querySelector("#scrRoom").hidden, { timeout: 15000 });
await sw.page.click("#gen");
const swCode2 = await ownerConnected(sw);
await admitAtGate(sw, sB, swCode2);
const gateClean = await gateNow(sw.page);
check("S1: after a key-changed gate, the next clean first contact shows the default sentence, not the old warning",
  gateChanged.changed && gateChanged.hint !== defaultHint && swCode2 !== swCode1 &&
  !gateClean.changed && gateClean.hint === defaultHint && defaultHint.length > 0,
  JSON.stringify({ changed: { ...gateChanged, hint: gateChanged.hint.slice(0, 40) }, clean: gateClean }));

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
