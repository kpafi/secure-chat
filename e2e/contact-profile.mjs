// The contact profile: a saved user's short profile, as a sheet over Users or
// Chats (design/research/reviews/profile-brief.md).
//
//   node e2e/contact-profile.mjs
//
// Needs the relay running (backend/run.sh) and system Chromium, like the other
// runs. Three agents: alice (whose profiles are checked), bob (a saved user
// she chats with) and carol (a stranger whose mail makes an automatic
// contact). It pins:
//   - the three ways in (a Users row, a Chats row's avatar, the conversation's
//     name), by pointer and by keyboard, and that the rest of a Chats row
//     still opens the conversation;
//   - what the sheet shows equals the truth: bob's handle, and the fingerprint
//     bob's OWN device shows for himself;
//   - it is a real modal (focus in, Tab wraps, the rest inert) that closes by
//     ×, Escape and the scrim and gives focus back to what opened it;
//   - Verify from the sheet flips the list mark, waits for the fingerprint,
//     and REFUSES when the keys moved under an open sheet (what the user
//     compared is not what the click would mark);
//   - a key-changed contact says so in the row AND the sheet; an automatic
//     contact's handle is labelled a claim; Remove closes the sheet;
//   - on a phone the sheet docks above the tab bar.
import puppeteer from "puppeteer-core";
import { readFileSync } from "node:fs";

const cfg = JSON.parse(readFileSync(new URL("./test-users.json", import.meta.url)));
const APP = process.env.SECURE_CHAT_E2E_URL || cfg.relay;
const RUN = Date.now().toString(36).slice(-5);
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
async function newTab(label) {
  const ctx = await browser.createBrowserContext();
  const page = await ctx.newPage();
  page.on("pageerror", (e) => errors.push(`${label}: ${e.message}`));
  page.on("console", (m) => {
    const t = m.text();
    if (m.type() === "error" && !/favicon|404/.test(t)) errors.push(`${label}: ${t}`);
  });
  // Every confirm() says yes, unless a check asks for one "no"; each
  // dialog's text is kept, so a check can count the gates it passed.
  page.dialogs = [];
  page.answers = []; // queued answers for the next dialogs (true = OK), then OK
  page.on("dialog", (d) => {
    page.dialogs.push(d.message());
    const yes = page.answers.length ? page.answers.shift() : true;
    if (yes) d.accept(); else d.dismiss();
  });
  await page.setViewport({ width: 1000, height: 900 });
  await page.goto(APP, { waitUntil: "networkidle0" });
  return { ctx, page, label };
}

async function view(page, name) {
  await page.click(`.navitem[data-view="${name}"]`);
  await sleep(400);
}

async function onboard(spec, label) {
  const t = await newTab(label);
  const username = `${spec.usernamePrefix}-${RUN}`;
  await t.page.type("#idPass", spec.passphrase);
  await t.page.click("#idCreate");
  await t.page.waitForFunction(() => !document.querySelector("#idExport").hidden, { timeout: 30000 });
  await t.page.type("#username", username);
  await t.page.click("#register");
  await t.page.waitForFunction(
    () => /registered/i.test(document.querySelector("#accountStatus").textContent),
    { timeout: 30000 },
  );
  await sleep(1500);
  const handle = await t.page.evaluate(() =>
    localStorage.getItem("sc.username.v1") + "#" + localStorage.getItem("sc.lookuptoken.v1"));
  return { ...t, username, handle };
}

async function addUser(page, handle) {
  await view(page, "users");
  await page.type("#addHandle", handle);
  await page.click("#addContact");
  await page.waitForFunction((h) =>
    [...document.querySelectorAll("#userList > li")].some((li) => li.dataset.user === h.split("#")[0]),
  { timeout: 30000 }, handle);
}

// The state of the sheet, in one read.
const sheet = (page) => page.evaluate(() => {
  const s = document.querySelector("#contactSheet");
  const a = document.activeElement;
  const dd = [...document.querySelectorAll("#contactFacts dt")].map((dt) => [dt.textContent, dt.nextElementSibling.textContent]);
  return {
    open: !s.hidden && !document.querySelector("#contactScrim").hidden,
    name: document.querySelector("#contactName").textContent,
    handleLabel: document.querySelector("#contactHandleLabel").textContent,
    handle: document.querySelector("#contactHandle").textContent,
    fp: document.querySelector("#contactFingerprint").textContent,
    mark: document.querySelector("#contactMark").textContent,
    warn: document.querySelector("#contactWarn").textContent,
    facts: Object.fromEntries(dd),
    status: document.querySelector("#contactStatus").textContent,
    message: !document.querySelector("#contactMessage").hidden,
    verify: { text: document.querySelector("#contactVerify").textContent, disabled: document.querySelector("#contactVerify").disabled },
    focusIn: s.contains(a),
    focusId: a.id || a.className || a.tagName,
    inert: { tabbar: document.querySelector("#tabbar").inert, users: document.querySelector("#viewUsers").inert, chats: document.querySelector("#viewChats").inert },
  };
});
// An open waits out the sheet's 500 ms rule too (an activation that early is
// dropped on purpose — check 7 pins that), so the clicks after it are real.
const waitSheet = async (page, open = true) => {
  await page.waitForFunction((o) =>
    document.querySelector("#contactSheet").hidden === !o, { timeout: 5000 }).catch(() => {});
  if (open) await sleep(600);
};
const waitFp = (page) => page.waitForFunction(() =>
  !/^…$/.test(document.querySelector("#contactFingerprint").textContent), { timeout: 10000 }).catch(() => {});
const focusInfo = (page) => page.evaluate(() => {
  const a = document.activeElement;
  return { cls: a.className, id: a.id, user: a.closest("li")?.dataset.user || null };
});
const rowOf = (u) => `#userList > li[data-user="${u}"]`;
const VERIFY_LABEL = "Verified in person\u00a0✓"; // the ✓ never wraps alone

console.log(`\n=== contact profile (${APP}) ===\n`);
const [aliceSpec, bobSpec, carolSpec] = cfg.users.length >= 3 ? cfg.users
  : [cfg.users[0], cfg.users[1], { ...cfg.users[0], usernamePrefix: "e2e-carol" }];
const alice = await onboard(aliceSpec, "alice");
const bob = await onboard(bobSpec, "bob");
console.log(`  alice: ${alice.handle}\n  bob:   ${bob.handle}\n`);
await addUser(alice.page, bob.handle);
await addUser(bob.page, alice.handle);

// What bob's own device says his fingerprint is: the value alice must see.
await view(bob.page, "profile");
await bob.page.waitForFunction(() => /\w{4} \w{4}/.test(document.querySelector("#profileFingerprint").textContent), { timeout: 10000 });
const bobOwnFp = await bob.page.evaluate(() => document.querySelector("#profileFingerprint").textContent);

// --- 1. Users: the row is one button; the profile shows the truth ------------
console.log("1. from a Users row");
await view(alice.page, "users");
const row = await alice.page.evaluate((sel) => {
  const li = document.querySelector(sel);
  return li && { buttons: li.querySelectorAll("button").length, open: !!li.querySelector(":scope > button.u-open"),
    popup: li.querySelector(".u-open")?.getAttribute("aria-haspopup"), fpLine: !!li.querySelector(".u-fp") };
}, rowOf(bob.username));
check("a Users row is ONE button (avatar, name, mark) and carries no fingerprint or actions",
  !!row && row.buttons === 1 && row.open && row.popup === "dialog" && !row.fpLine, JSON.stringify(row));

await alice.page.click(`${rowOf(bob.username)} > .u-open`);
await waitSheet(alice.page);
await waitFp(alice.page);
let s = await sheet(alice.page);
check("a click on the row opens bob's profile, focus on its close button",
  s.open && s.name === bob.username && s.focusIn && s.focusId === "contactClose", JSON.stringify({ open: s.open, name: s.name, focus: s.focusId }));
check("the handle is bob's own username#token", s.handleLabel === "Handle" && s.handle === bob.handle, JSON.stringify([s.handleLabel, s.handle]));
check("the fingerprint equals the one bob's own device shows", s.fp === bobOwnFp, JSON.stringify({ sheet: s.fp, bob: bobOwnFp }));
check("the facts say only what the pill does not: the date saved (no \"not yet\", no vouched-by repeat)",
  !!s.facts.Saved && !("Verified" in s.facts) && !("Vouched by" in s.facts) && !("Sealed mail" in s.facts),
  JSON.stringify(s.facts));
const handleIcon = await alice.page.evaluate(() => getComputedStyle(document.querySelector("#contactHandle"), "::before").content);
check("no check icon beside the contact's handle (17ee937)", handleIcon === "none" || handleIcon === "normal", JSON.stringify(handleIcon));
check("one primary: Message; Verify is secondary and enabled once the fingerprint is on screen",
  s.message && s.verify.text === VERIFY_LABEL && !s.verify.disabled &&
  (await alice.page.evaluate(() => document.querySelectorAll("#contactSheet button.primary:not([hidden])").length)) === 1,
  JSON.stringify(s.verify));
check("the rest of the page is inert while it is up", s.inert.tabbar && s.inert.users && s.inert.chats, JSON.stringify(s.inert));

// Tab wraps inside the sheet (both directions).
await alice.page.keyboard.down("Shift");
await alice.page.keyboard.press("Tab");
await alice.page.keyboard.up("Shift");
const back = await focusInfo(alice.page);
await alice.page.keyboard.press("Tab");
const fwd = await focusInfo(alice.page);
let stayed = true;
for (let i = 0; i < 12; i++) {
  await alice.page.keyboard.press("Tab");
  stayed = stayed && (await alice.page.evaluate(() => document.querySelector("#contactSheet").contains(document.activeElement)));
}
check("Tab wraps inside the sheet: Shift+Tab from × lands on Remove, Tab from Remove on ×, 12 Tabs never leave",
  back.id === "contactRemove" && fwd.id === "contactClose" && stayed, JSON.stringify({ back, fwd, stayed }));

await alice.page.keyboard.press("Escape");
await waitSheet(alice.page, false);
s = await sheet(alice.page);
let f = await focusInfo(alice.page);
check("Escape closes it, un-inerts the page and returns focus to bob's row",
  !s.open && !s.inert.tabbar && !s.inert.users && f.user === bob.username && /u-open/.test(f.cls), JSON.stringify({ open: s.open, inert: s.inert, f }));

// Keyboard open, × close.
await alice.page.focus(`${rowOf(bob.username)} > .u-open`);
await alice.page.keyboard.press("Enter");
await waitSheet(alice.page);
const kbOpen = (await sheet(alice.page)).open;
await alice.page.click("#contactClose");
await waitSheet(alice.page, false);
f = await focusInfo(alice.page);
check("Enter on the row opens it; × closes it and focus returns to the row",
  kbOpen && !(await sheet(alice.page)).open && f.user === bob.username, JSON.stringify({ kbOpen, f }));

// Scrim closes (a point well outside the centred dialog).
await alice.page.click(`${rowOf(bob.username)} > .u-open`);
await waitSheet(alice.page);
await alice.page.mouse.click(8, 8);
await waitSheet(alice.page, false);
f = await focusInfo(alice.page);
check("a click on the scrim closes it and focus returns to the row (cold m1)",
  !(await sheet(alice.page)).open && f.user === bob.username && /u-open/.test(f.cls), JSON.stringify(f));

// Clicking the sheet's text focuses the sheet itself: Escape must still close.
await alice.page.click(`${rowOf(bob.username)} > .u-open`);
await waitSheet(alice.page);
await alice.page.click("#contactFingerprint");
await alice.page.keyboard.press("Escape");
await waitSheet(alice.page, false);
check("Escape closes it also after a click on its text (cold m3)", !(await sheet(alice.page)).open);

// A pointer tap on the row's warning / claim lines opens it too: tested in 4.

// --- 2. Verify from the sheet --------------------------------------------------
console.log("\n2. verify from the sheet");
await alice.page.click(`${rowOf(bob.username)} > .u-open`);
await waitSheet(alice.page);
await waitFp(alice.page);
// Pentest L-1: a double click must verify once, never verify-then-unverify.
await alice.page.click("#contactVerify", { clickCount: 1 }); // both confirm()s accepted
await sleep(60);
await alice.page.click("#contactVerify").catch(() => {});
await alice.page.waitForFunction(() => document.querySelector("#contactVerify").textContent === "Unverify", { timeout: 15000 }).catch(() => {});
await sleep(1500);
s = await sheet(alice.page);
const rowMark = await alice.page.evaluate((sel) => document.querySelector(`${sel} .u-mark`)?.textContent, rowOf(bob.username));
check("Verify (clicked twice) marks bob verified once: the sheet and the row say so, the facts carry the date",
  s.open && s.mark === "verified by you" && rowMark === "verified by you" && s.verify.text === "Unverify" &&
  !!s.facts.Verified, JSON.stringify({ mark: s.mark, rowMark, verify: s.verify, facts: s.facts }));

// Pentest p4 M-1 guard: a stranger's mail makes an automatic contact that
// CLAIMS bob's handle. The vouch refresh then fetches the real bob's vouches —
// ours among them — and must never delete it (an earlier fix did).
{
  const vouchesAboutBob = () => alice.page.evaluate(async (h) =>
    (await (await import("./account.js")).fetchVouches("", h)).map((v) => v.voucher), bob.handle);
  const before = await vouchesAboutBob();
  const deletes = [];
  const onDel = (r) => { if (r.method() === "DELETE" && r.url().includes("/api/vouch")) deletes.push(r.url()); };
  alice.page.on("request", onDel);
  await alice.page.evaluate(async (b) => {
    const { Identity } = await import("./identity.js");
    const contacts = await import("./contacts.js");
    const k = (await Identity.generate()).publicBundle(); // the stranger's own keys
    const [name, token] = b.split("#");
    await contacts.upsert({ username: "unknown-claimsbob01", addrUsername: name, token, claimedName: b, auto: true,
      ed: k.ed, mldsa: k.mldsa, ecdh: k.ecdh, mlkem: k.mlkem });
  }, bob.handle);
  await alice.page.keyboard.press("Escape");
  await waitSheet(alice.page, false);
  await view(alice.page, "chats");
  await view(alice.page, "users"); // renders the list, which runs the vouch refresh
  await sleep(2500);
  alice.page.off("request", onDel);
  const after = await vouchesAboutBob();
  check("a stranger claiming bob's handle cannot make us delete our real vouch for bob",
    before.includes(alice.username) && after.includes(alice.username) && deletes.length === 0,
    JSON.stringify({ before, after, deletes }));
  await alice.page.evaluate(async () => { await (await import("./contacts.js")).remove("unknown-claimsbob01"); });
  // Unverify retracts the real vouch; then verify (and vouch) again for 3.
  await alice.page.click(`${rowOf(bob.username)} > .u-open`);
  await waitSheet(alice.page);
  await alice.page.click("#contactVerify"); // Unverify, accepted
  await alice.page.waitForFunction(() => document.querySelector("#contactVerify").textContent === "Verified in person\u00a0✓", { timeout: 10000 }).catch(() => {});
  await sleep(1200);
  const retracted = await vouchesAboutBob();
  check("Unverify retracts the vouch from the relay", !retracted.includes(alice.username), JSON.stringify(retracted));
  await sleep(600);
  await alice.page.click("#contactVerify"); // verify + vouch again
  await alice.page.waitForFunction(() => document.querySelector("#contactVerify").textContent === "Unverify", { timeout: 15000 }).catch(() => {});
  await sleep(1500);
}

// --- 3. Message → Chats; the conversation's name opens the profile -----------
console.log("\n3. from Chats");
await alice.page.click("#contactMessage");
await alice.page.waitForFunction(() => !document.querySelector("#chatConvo").hidden, { timeout: 10000 }).catch(() => {});
const convo = await alice.page.evaluate(() => ({
  view: !document.querySelector("#viewChats").hidden, convo: !document.querySelector("#chatConvo").hidden,
  peer: document.querySelector("#chatPeer").textContent, sheet: !document.querySelector("#contactSheet").hidden,
  peerBtn: document.querySelector("#chatPeer").tagName, peerDisabled: document.querySelector("#chatPeer").disabled,
}));
check("Message closes the sheet and opens the conversation with bob in Chats",
  convo.view && convo.convo && convo.peer === bob.username && !convo.sheet, JSON.stringify(convo));
await alice.page.type("#chatText", "hello from the profile");
await alice.page.click("#chatSend");
await sleep(800);

await alice.page.click("#chatPeer");
await waitSheet(alice.page);
s = await sheet(alice.page);
check("the conversation's name is a button that opens the profile — without Message there",
  convo.peerBtn === "BUTTON" && !convo.peerDisabled && s.open && s.name === bob.username && !s.message,
  JSON.stringify({ open: s.open, message: s.message }));
// Pentest L-2 / cold M1: Unverify from here — the header's mark follows.
await alice.page.click("#contactVerify"); // Unverify (confirm accepted)
await alice.page.waitForFunction(() => document.querySelector("#contactVerify").textContent === "Verified in person\u00a0✓", { timeout: 10000 }).catch(() => {});
const headerMark = await alice.page.evaluate(() => ({
  mark: document.querySelector("#chatPeerMark").textContent, verify: document.querySelector("#contactVerify").textContent,
}));
check("Unverify from the conversation's profile updates the header's mark and the sheet at once",
  headerMark.mark === "unverified" && headerMark.verify === VERIFY_LABEL, JSON.stringify(headerMark));
await alice.page.keyboard.press("Escape");
await waitSheet(alice.page, false);
f = await focusInfo(alice.page);
check("closing it returns focus to the name", f.id === "chatPeer", JSON.stringify(f));

await alice.page.click("#chatBack");
await sleep(400);
const chatRow = await alice.page.evaluate((u) => {
  const li = [...document.querySelectorAll("#chatList > li")].find((x) => x.dataset.user === u);
  return li && { avatar: li.querySelector(":scope > button.u-avatar")?.getAttribute("aria-label"),
    opener: !!li.querySelector(":scope > button.chatrow-open"), role: li.getAttribute("role") };
}, bob.username);
check("a Chats row: an avatar button named for the profile, an opener button, the row itself no role",
  !!chatRow && chatRow.avatar === "Profile of " + bob.username && chatRow.opener && chatRow.role === null, JSON.stringify(chatRow));
await alice.page.click(`#chatList > li[data-user="${bob.username}"] > .u-avatar`);
await waitSheet(alice.page);
s = await sheet(alice.page);
const convoAfterAvatar = await alice.page.evaluate(() => !document.querySelector("#chatConvo").hidden);
check("the avatar opens the profile (not the conversation), with Message",
  s.open && s.name === bob.username && s.message && !convoAfterAvatar, JSON.stringify({ open: s.open, convoAfterAvatar }));
await alice.page.keyboard.press("Escape");
await waitSheet(alice.page, false);
f = await focusInfo(alice.page);
check("closing it returns focus to that avatar", /u-avatar/.test(f.cls) && f.user === bob.username, JSON.stringify(f));
await alice.page.click(`#chatList > li[data-user="${bob.username}"] > .chatrow-open`);
await alice.page.waitForFunction(() => !document.querySelector("#chatConvo").hidden, { timeout: 5000 }).catch(() => {});
check("the rest of the row still opens the conversation",
  await alice.page.evaluate(() => !document.querySelector("#chatConvo").hidden && document.querySelector("#contactSheet").hidden));
await alice.page.click("#chatBack");
await sleep(300);

// --- 4. keys that move under an open sheet -------------------------------------
console.log("\n4. key change");
await view(alice.page, "users");
// Bob is unverified since 3, so the Verify path (the one with the snapshot
// check) is live.
await alice.page.click(`${rowOf(bob.username)} > .u-open`);
await waitSheet(alice.page);
await waitFp(alice.page);
const fpBefore = (await sheet(alice.page)).fp;
// Re-key bob in alice's store BEHIND the open sheet (what a directory refresh
// or a mail could do), with no re-render: the sheet still shows the old value.
await alice.page.evaluate(async (u) => {
  const { Identity } = await import("./identity.js");
  const contacts = await import("./contacts.js");
  const c = contacts.get(u);
  const k = (await Identity.generate()).publicBundle();
  await contacts.upsert({ username: u, token: c.token, ed: k.ed, mldsa: k.mldsa, ecdh: k.ecdh, mlkem: k.mlkem });
}, bob.username);
const verifyDbg = await alice.page.evaluate(() => ({ action: document.querySelector("#contactVerify").dataset.action,
  disabled: document.querySelector("#contactVerify").disabled, text: document.querySelector("#contactVerify").textContent }));
await alice.page.click("#contactVerify");
await sleep(600);
s = await sheet(alice.page);
const verifiedAfter = await alice.page.evaluate(async (u) => (await import("./contacts.js")).get(u).verified, bob.username);
check("Verify REFUSES when the keys moved under the open sheet, and shows the new fingerprint",
  !verifiedAfter && /keys changed while their profile was open/.test(s.status) && s.fp !== fpBefore,
  JSON.stringify({ verifiedAfter, status: s.status, fpBefore, fpNow: s.fp, verify: s.verify, open: s.open, dbg: verifyDbg }));
const acts = await alice.page.evaluate(() => ({
  mark: document.querySelector("#contactMark").className,
  verifyPrimary: document.querySelector("#contactVerify").classList.contains("primary"),
  messagePrimary: document.querySelector("#contactMessage").classList.contains("primary"),
}));
check("the sheet now carries the key-changed mark and sentence — and Verify is the one primary (hot B1)",
  /\bchanged\b/.test(acts.mark) && acts.verifyPrimary && !acts.messagePrimary &&
  s.warn === "this user's key CHANGED since you saved them — re-verify in person before trusting", JSON.stringify({ acts, warn: s.warn }));
await alice.page.keyboard.press("Escape");
await waitSheet(alice.page, false);
await view(alice.page, "chats");
await view(alice.page, "users"); // a fresh render of the list
const rowWarn = await alice.page.evaluate((sel) => document.querySelector(`${sel} > .hint.err`)?.textContent, rowOf(bob.username));
check("the Users row keeps the key-changed sentence visible without opening anything",
  rowWarn === "this user's key CHANGED since you saved them — re-verify in person before trusting", JSON.stringify(rowWarn));
// Hot M6: a pointer tap on that sentence opens the profile.
await alice.page.click(`${rowOf(bob.username)} > .hint.err`);
await waitSheet(alice.page);
check("a tap on the row's warning sentence opens the profile", (await sheet(alice.page)).open);
await alice.page.keyboard.press("Escape");
await waitSheet(alice.page, false);

// Cold M3: a re-render of the list (what a mail or a vouch refresh does)
// keeps keyboard focus on the same row.
await alice.page.focus(`${rowOf(bob.username)} > .u-open`);
await alice.page.evaluate(() => document.querySelector('.navitem[data-view="users"]').click()); // re-renders the list
await sleep(300);
f = await focusInfo(alice.page);
check("a list re-render keeps focus on the row that had it", f.user === bob.username && /u-open/.test(f.cls), JSON.stringify(f));

// Verify waits for the fingerprint, and a slow fingerprint never lands on
// another contact's sheet. Slow it down for bob's keys only, in the page (the
// same module instance app.js uses), with a helper contact "dave" beside him.
const daveFp = await alice.page.evaluate(async (bobName) => {
  const { Identity } = await import("./identity.js");
  const contacts = await import("./contacts.js");
  const k = (await Identity.generate()).publicBundle();
  await contacts.upsert({ username: "e2e-dave-helper", token: null, ed: k.ed, mldsa: k.mldsa, ecdh: k.ecdh, mlkem: k.mlkem });
  const orig = Identity.fingerprintOf;
  window.__fpOrig = orig;
  const slowEd = contacts.get(bobName).ed;
  Identity.fingerprintOf = async (b) => {
    if (b.ed === slowEd) await new Promise((r) => setTimeout(r, 1500));
    return orig.call(Identity, b);
  };
  return orig.call(Identity, { ed: k.ed, mldsa: k.mldsa, ecdh: k.ecdh, mlkem: k.mlkem });
}, bob.username);
await view(alice.page, "chats");
await view(alice.page, "users"); // dave's row
await alice.page.click(`${rowOf(bob.username)} > .u-open`);
await sleep(300);
const pending = await alice.page.evaluate(() => ({
  fp: document.querySelector("#contactFingerprint").textContent, disabled: document.querySelector("#contactVerify").disabled,
}));
check("Verify is disabled while the fingerprint is still being computed", pending.fp === "…" && pending.disabled, JSON.stringify(pending));
await alice.page.keyboard.press("Escape");
await alice.page.click(`${rowOf("e2e-dave-helper")} > .u-open`);
await sleep(2000); // bob's slow computation finishes while dave's sheet is up
const onDave = await alice.page.evaluate(() => ({
  name: document.querySelector("#contactName").textContent, fp: document.querySelector("#contactFingerprint").textContent,
}));
check("a slow fingerprint for one contact never lands on another's sheet",
  onDave.name === "e2e-dave-helper" && onDave.fp === daveFp, JSON.stringify({ onDave, daveFp }));
await alice.page.keyboard.press("Escape");
await waitSheet(alice.page, false);
await alice.page.evaluate(async () => {
  const { Identity } = await import("./identity.js");
  Identity.fingerprintOf = window.__fpOrig;
  await (await import("./contacts.js")).remove("e2e-dave-helper");
});

// --- 4b. the gates, and what the fix rounds pinned --------------------------------
console.log("\n4b. gates");
const store = (page, fn, ...args) => page.evaluate(fn, ...args);
const isVerified = (u) => store(alice.page, async (n) => (await import("./contacts.js")).get(n)?.verified ?? null, u);
await alice.page.click(`${rowOf(bob.username)} > .u-open`);
await waitSheet(alice.page);
await waitFp(alice.page);
// Key changed: the primary (Verify) is first for Tab too, not only on screen.
await alice.page.focus("#contactClose");
const order = [];
for (let i = 0; i < 8; i++) {
  await alice.page.keyboard.press("Tab");
  order.push(await alice.page.evaluate(() => document.activeElement.id || document.activeElement.tagName));
}
check("key changed: Tab reaches Verify (the primary, shown first) before Message",
  order.indexOf("contactVerify") >= 0 && order.indexOf("contactVerify") < order.indexOf("contactMessage"), JSON.stringify(order));

// Verify (the vouch declined: the test re-keyed bob locally, so the relay
// would rightly refuse a vouch over those keys), then Unverify is
// confirm-gated: "no" keeps it.
alice.page.answers = [true, false];
await alice.page.click("#contactVerify");
await alice.page.waitForFunction(() => document.querySelector("#contactVerify").textContent === "Unverify", { timeout: 15000 }).catch(() => {});
await sleep(600);
const nDialogs = alice.page.dialogs.length;
alice.page.answers = [false];
await alice.page.click("#contactVerify");
await sleep(300);
const unvText = alice.page.dialogs.slice(nDialogs).join(" | ");
check("Unverify asks first, and \"no\" leaves the contact verified",
  /^Unverify "/.test(unvText) && (await isVerified(bob.username)) === true, JSON.stringify({ unvText }));

// data-action: the button acts as it was drawn. Flip the store behind it (a
// second tab would); the click redraws instead of acting on a fresh read.
await store(alice.page, async (u) => { await (await import("./contacts.js")).setVerified(u, false); }, bob.username);
await sleep(600);
const nD2 = alice.page.dialogs.length;
await alice.page.click("#contactVerify"); // still reads "Unverify"
await sleep(300);
const redraw = await alice.page.evaluate(() => document.querySelector("#contactVerify").textContent);
check("a click on a button whose state the store no longer has redraws it and asks nothing",
  alice.page.dialogs.length === nD2 && redraw === VERIFY_LABEL && (await isVerified(bob.username)) === false,
  JSON.stringify({ redraw, dialogs: alice.page.dialogs.length - nD2 }));

// Busy: a vouch the relay never answers. A second click is refused and says
// why; the round trip is bounded, so Verify/Unverify work again afterwards.
await alice.page.setRequestInterception(true);
const held = [];
const onReq = (r) => {
  if (r.method() === "POST" && r.url().endsWith("/api/vouch")) { held.push(r); return; } // never answered
  r.continue();
};
alice.page.on("request", onReq);
await sleep(600);
await alice.page.click("#contactVerify"); // verify + vouch prompt accepted, vouch hangs
await alice.page.waitForFunction(() => /Publishing the vouch/.test(document.querySelector("#contactStatus").textContent), { timeout: 10000 }).catch(() => {});
await sleep(700);
const nD3 = alice.page.dialogs.length;
await alice.page.click("#contactVerify");
await sleep(200);
const busy = await alice.page.evaluate(() => ({
  status: document.querySelector("#contactStatus").textContent, label: document.querySelector("#contactVerify").textContent,
}));
check("while the vouch is in flight the store shows verified at once, and a second click is refused with a reason",
  busy.label === "Unverify" && /Still saving the last change/.test(busy.status) && alice.page.dialogs.length === nD3 &&
  (await isVerified(bob.username)) === true && held.length === 1, JSON.stringify({ busy, held: held.length }));
await alice.page.waitForFunction(() => /No answer from the relay about the vouch/.test(document.querySelector("#contactStatus").textContent),
  { timeout: 25000 }).catch(() => {});
const timedOut = await alice.page.evaluate(() => document.querySelector("#contactStatus").textContent);
alice.page.off("request", onReq);
await alice.page.setRequestInterception(false);
await sleep(600);
await alice.page.click("#contactVerify"); // Unverify, accepted
await sleep(800);
check("a vouch that never returns times out, says it may still be published (and for whom), and Unverify works again",
  timedOut.startsWith(`No answer from the relay about the vouch for "${bob.username}" — it may still have been published.`) &&
  (await isVerified(bob.username)) === false, JSON.stringify(timedOut));
// That Unverify put Verify first again (bob's key once changed): the focused
// button keeps focus through the reorder (cold r3 MAJOR-A, pentest p3 L-3).
const afterReorder = await alice.page.evaluate(() => ({
  focus: document.activeElement.id || document.activeElement.tagName,
  first: document.querySelector(".contact-actions").firstElementChild.id,
}));
check("the reorder of the two actions keeps focus on the button that had it",
  afterReorder.focus === "contactVerify" && afterReorder.first === "contactVerify", JSON.stringify(afterReorder));
// A "?" opened here is shut when a profile opens again.
await alice.page.click("#contactSheet .why-row summary");
await alice.page.keyboard.press("Escape");
await waitSheet(alice.page, false);
await alice.page.click(`${rowOf(bob.username)} > .u-open`);
await waitSheet(alice.page);
check("a \"?\" opened on a profile is shut the next time it opens",
  await alice.page.evaluate(() => !document.querySelector("#contactSheet .why-row details").open));
await alice.page.keyboard.press("Escape");
await waitSheet(alice.page, false);

// Seeded records: an adopted claim (not auto) and malformed stored keys.
await store(alice.page, async () => {
  const { Identity } = await import("./identity.js");
  const contacts = await import("./contacts.js");
  const k = (await Identity.generate()).publicBundle();
  await contacts.upsert({ username: "e2e-adopt", token: "adopttoken0123456789abcd", claimedName: "someone-else#faketoken000000000000",
    ed: k.ed, mldsa: k.mldsa, ecdh: k.ecdh, mlkem: k.mlkem });
  await contacts.upsert({ username: "e2e-broken", token: null, ed: "AAAA", mldsa: "AAAA", ecdh: null, mlkem: null });
});
await view(alice.page, "chats");
await view(alice.page, "users");
await sleep(400);
const broken = await alice.page.evaluate((sel) => document.querySelector(`${sel} > .hint.err`)?.textContent || null, rowOf("e2e-broken"));
check("malformed stored keys are said in the Users row, not only behind the tap",
  broken === "fingerprint unavailable — stored keys are malformed", JSON.stringify(broken));
await alice.page.click(`${rowOf("e2e-adopt")} > .u-open`);
await waitSheet(alice.page);
s = await sheet(alice.page);
check("a contact that carries a claimed name gets \"Handle they claim\" even when not automatic",
  s.handleLabel === "Handle they claim" && s.handle === "e2e-adopt#adopttoken0123456789abcd", JSON.stringify([s.handleLabel, s.handle]));
// Copy's result belongs to one contact: copy here, open bob, it reads "Copy".
await alice.page.click("#contactCopyHandle");
await sleep(150);
const copied = await alice.page.evaluate(() => document.querySelector("#contactCopyHandle").textContent);
await alice.page.keyboard.press("Escape");
await waitSheet(alice.page, false);
await alice.page.click(`${rowOf(bob.username)} > .u-open`);
await waitSheet(alice.page);
const onBob = await alice.page.evaluate(() => document.querySelector("#contactCopyHandle").textContent);
check("a copy result on one contact never shows on the next one's Copy",
  copied !== "Copy" && onBob === "Copy", JSON.stringify({ copied, onBob }));
await alice.page.keyboard.press("Escape");
await waitSheet(alice.page, false);
// ...also when the clipboard is slow: the write finishes while the NEXT
// contact's sheet is up, and must not label it (pentest p2 #3).
await alice.page.evaluate(() => {
  const orig = navigator.clipboard.writeText.bind(navigator.clipboard);
  navigator.clipboard.writeText = async (t) => { await new Promise((r) => setTimeout(r, 1000)); return orig(t).catch(() => {}); };
});
await alice.page.click(`${rowOf("e2e-adopt")} > .u-open`);
await waitSheet(alice.page);
await alice.page.click("#contactCopyHandle");
await alice.page.keyboard.press("Escape");
await waitSheet(alice.page, false);
await alice.page.click(`${rowOf(bob.username)} > .u-open`);
const labels = new Set();
for (let i = 0; i < 16; i++) {
  labels.add(await alice.page.evaluate(() => document.querySelector("#contactCopyHandle").textContent));
  await sleep(100);
}
check("a slow clipboard write never labels the next contact's Copy", labels.size === 1 && labels.has("Copy"), JSON.stringify([...labels]));
await alice.page.keyboard.press("Escape");
await waitSheet(alice.page, false);
// Remove from Users: the sheet closes, the row goes, focus on the add field.
await alice.page.click(`${rowOf("e2e-adopt")} > .u-open`);
await waitSheet(alice.page);
await alice.page.click("#contactRemove");
await waitSheet(alice.page, false);
f = await focusInfo(alice.page);
const adoptGone = await alice.page.evaluate((sel) => !document.querySelector(sel), rowOf("e2e-adopt"));
check("Remove from Users closes the sheet, drops the row, and focus lands on the add field",
  !(await sheet(alice.page)).open && adoptGone && f.id === "addHandle", JSON.stringify({ adoptGone, f }));
await store(alice.page, async () => { await (await import("./contacts.js")).remove("e2e-broken"); });

// --- 5. an automatic contact (a stranger's mail) -------------------------------
console.log("\n5. automatic contact");
const carol = await onboard(carolSpec, "carol");
await addUser(carol.page, alice.handle);
await view(carol.page, "chats");
await carol.page.select("#chatNew", alice.username);
await carol.page.click("#chatStart");
await carol.page.waitForFunction(() => !document.querySelector("#chatConvo").hidden, { timeout: 10000 });
await carol.page.type("#chatText", "hi, a stranger here");
await carol.page.click("#chatSend");
await sleep(1000);
let auto = null;
for (let i = 0; i < 15 && !auto; i++) {
  await view(alice.page, "chats"); // entering the view polls the mailbox
  await sleep(1200);
  auto = await alice.page.evaluate(async () => (await import("./contacts.js")).list().find((c) => c.auto)?.username || null);
}
if (auto) {
  await view(alice.page, "users");
  const rowClaim = await alice.page.evaluate((sel) => document.querySelector(`${sel} > .u-claim`)?.textContent, rowOf(auto));
  await view(alice.page, "chats");
  // From the Chats avatar this time.
  await alice.page.waitForFunction((u) => !!document.querySelector(`#chatList > li[data-user="${u}"] > button.u-avatar`), { timeout: 10000 }, auto).catch(() => {});
  await alice.page.click(`#chatList > li[data-user="${auto}"] > .u-avatar`);
  await waitSheet(alice.page);
  s = await sheet(alice.page);
  const shown = await alice.page.evaluate(() => getComputedStyle(document.querySelector("#contactHandle")).display);
  check("an automatic contact's handle is labelled a claim, printed once: the sheet's claim line points at it (hot M8, M-B)",
    s.handleLabel === "Handle they claim" && s.handle === carol.handle && shown !== "none" &&
    s.warn === "claims the handle below — unverified, they chose this name themselves" &&
    rowClaim === `claims to be "${carol.handle}" — unverified, they chose this name themselves`,
    JSON.stringify({ label: s.handleLabel, handle: s.handle, shown, warn: s.warn, rowClaim }));
  // A contact whose name came from a claim is never vouched for (so no
  // retraction can ever name a claim): Verify asks once, no vouch prompt.
  const vouchesAbout = () => alice.page.evaluate(async (h) => {
    const account = await import("./account.js");
    return (await account.fetchVouches("", h)).map((v) => v.voucher);
  }, carol.handle);
  await waitFp(alice.page);
  const nV = alice.page.dialogs.length;
  await alice.page.click("#contactVerify"); // verify (one confirm)
  await alice.page.waitForFunction(() => document.querySelector("#contactVerify").textContent === "Unverify", { timeout: 15000 }).catch(() => {});
  await sleep(800);
  const asked = alice.page.dialogs.slice(nV);
  const vouchedNow = await vouchesAbout();
  check("verifying a contact whose handle is only claimed offers no vouch and publishes none",
    asked.length === 1 && /^Mark "/.test(asked[0]) && !vouchedNow.includes(alice.username), JSON.stringify({ asked, vouchedNow }));
  await sleep(600);
  await alice.page.click("#contactVerify"); // Unverify, accepted
  await sleep(1000);
  // Remove of a contact that is not verified sends no vouch DELETE: it would
  // tell the relay whom we had saved (pentest p3 I-2 / p4 L-3).
  const deletes = [];
  const onDel = (r) => { if (r.method() === "DELETE" && r.url().includes("/api/vouch")) deletes.push(r.url()); };
  alice.page.on("request", onDel);
  await sleep(600);
  await alice.page.click("#contactRemove");
  await waitSheet(alice.page, false);
  await sleep(800);
  alice.page.off("request", onDel);
  check("Remove of an unverified contact sends no vouch DELETE to the relay", deletes.length === 0, JSON.stringify(deletes));
  f = await focusInfo(alice.page);
  check("Remove from a Chats avatar closes the sheet; focus lands on that row's opener (cold M2)",
    !(await sheet(alice.page)).open && f.user === auto && /chatrow-open/.test(f.cls), JSON.stringify(f));
  await alice.page.click(`#chatList > li[data-user="${auto}"] > .chatrow-open`);
  await alice.page.waitForFunction(() => !document.querySelector("#chatConvo").hidden, { timeout: 5000 }).catch(() => {});
  const peer = await alice.page.evaluate(() => ({
    disabled: document.querySelector("#chatPeer").disabled, popup: document.querySelector("#chatPeer").hasAttribute("aria-haspopup"),
    avatarSpan: document.querySelector("#chatList li .u-avatar")?.tagName,
  }));
  check("for a sender who is no saved user the name is disabled and announces no dialog (cold m4)",
    peer.disabled && !peer.popup, JSON.stringify(peer));
  await alice.page.click("#chatBack");
  await sleep(300);
  await view(alice.page, "users");
  const gone = await alice.page.evaluate((sel) => !document.querySelector(sel), rowOf(auto));
  check("the removed contact's Users row is gone", gone);
} else {
  check("carol's mail made an automatic contact on alice's device", false, "no auto contact after 15 polls");
}

// --- 5b. a store write refused because another tab wrote first ---------------------
console.log("\n5b. store refused");
{
  const STALE = "Your contacts were changed in another tab — enter your passphrase to load that version.";
  // A second tab of the same device unlocks and writes: the store's
  // generation moves past what alice's tab holds.
  const staleWrite = async (verified) => {
    const tab2 = await alice.ctx.newPage();
    tab2.on("dialog", (d) => d.accept());
    await tab2.setViewport({ width: 1000, height: 900 });
    await tab2.goto(APP, { waitUntil: "networkidle0" });
    await tab2.click('.navitem[data-view="users"]');
    await tab2.type("#usersUnlockPass", aliceSpec.passphrase);
    await tab2.click("#usersUnlock");
    await tab2.waitForFunction(() => !document.querySelector("#usersUnlocked").hidden, { timeout: 40000 });
    await tab2.evaluate(async (u, v) => { await (await import("./contacts.js")).setVerified(u, v); }, bob.username, verified);
    await tab2.close();
    await alice.page.bringToFront();
  };
  const lostState = (panel) => alice.page.evaluate((pn) => {
    const p = document.querySelector(`#${pn}Locked p`);
    const r = p.getBoundingClientRect();
    const input = document.querySelector(`#${pn}UnlockPass`);
    const desc = document.getElementById(input.getAttribute("aria-describedby") || "");
    return { sheet: !document.querySelector("#contactSheet").hidden, locked: !document.querySelector(`#${pn}Locked`).hidden,
      text: p.textContent, visible: r.width > 0 && r.height > 0, focus: document.activeElement.id,
      described: desc === p, inert: document.querySelector("#tabbar").inert || document.querySelector(`#view${pn[0].toUpperCase() + pn.slice(1)}`).inert };
  }, panel);
  const relock = async (panel) => {
    await alice.page.type(`#${panel}UnlockPass`, aliceSpec.passphrase);
    await alice.page.click(`#${panel}Unlock`);
    await alice.page.waitForFunction((pn) => !document.querySelector(`#${pn}Unlocked`).hidden, { timeout: 40000 }, panel).catch(() => {});
    await sleep(800);
  };

  // A. Verify from a Users row.
  await staleWrite(true);
  await view(alice.page, "users");
  await alice.page.click(`${rowOf(bob.username)} > .u-open`);
  await waitSheet(alice.page);
  await waitFp(alice.page);
  await alice.page.click("#contactVerify"); // alice's tab still shows bob unverified
  await sleep(1200);
  let lost = await lostState("users");
  check("a Verify the store refuses (another tab wrote first) closes the sheet and says so on the visible locked panel — no Forget advice — focus in the passphrase field, which is described by it",
    !lost.sheet && lost.locked && lost.visible && lost.text === STALE && lost.focus === "usersUnlockPass" && lost.described && !lost.inert,
    JSON.stringify(lost));
  await relock("users");
  check("unlocking again reads the other tab's version", (await isVerified(bob.username)) === true);

  // B. Remove from a Users row.
  await staleWrite(false);
  await alice.page.click(`${rowOf(bob.username)} > .u-open`);
  await waitSheet(alice.page);
  await alice.page.click("#contactRemove");
  await sleep(1200);
  lost = await lostState("users");
  check("a Remove the store refuses is handled the same way (sheet closed, reason shown, focus in the field)",
    !lost.sheet && lost.locked && lost.text === STALE && lost.focus === "usersUnlockPass" && !lost.inert, JSON.stringify(lost));
  await relock("users");
  check("…and the refused Remove removed nothing", (await isVerified(bob.username)) === false);

  // C. Verify from a Chats avatar: the Chats panel says it.
  await staleWrite(true);
  await view(alice.page, "chats");
  await alice.page.click(`#chatList > li[data-user="${bob.username}"] > .u-avatar`);
  await waitSheet(alice.page);
  await waitFp(alice.page);
  await alice.page.click("#contactVerify");
  await sleep(1200);
  lost = await lostState("chats");
  check("a refused Verify from Chats: the Chats panel says so, focus in its passphrase field",
    !lost.sheet && lost.locked && lost.text === STALE && lost.focus === "chatsUnlockPass" && lost.described && !lost.inert,
    JSON.stringify(lost));
  await relock("chats");
  // Back to unverified for the phone checks (the key-changed layout).
  await store(alice.page, async (u) => { await (await import("./contacts.js")).setVerified(u, false); }, bob.username);
  await view(alice.page, "users");
}

// --- 6. phone: docks above the tab bar -------------------------------------------
console.log("\n6. phone");
// Width only: switching isMobile/hasTouch would reload the page (and lock it).
await alice.page.setViewport({ width: 390, height: 844 });
await sleep(400);
await alice.page.click(`${rowOf(bob.username)} > .u-open`);
await waitSheet(alice.page);
await sleep(400); // the entrance animation
const geo = await alice.page.evaluate(() => {
  const r = document.querySelector("#contactSheet").getBoundingClientRect();
  const t = document.querySelector("#tabbar").getBoundingClientRect();
  const btns = [...document.querySelectorAll("#contactSheet button:not([hidden])")].map((b) => b.getBoundingClientRect())
    .filter((b) => b.width > 0);
  return { sheetBottom: Math.round(r.bottom), tabTop: Math.round(t.top), top: Math.round(r.top),
    minTarget: Math.min(...btns.map((b) => Math.min(b.height, b.width))) };
});
check("on a phone the sheet docks above the tab bar, every button ≥44px",
  geo.sheetBottom <= geo.tabTop && geo.top > 0 && geo.minTarget >= 44, JSON.stringify(geo));
// Remove is alone under the decision row: centred in the sheet, never hanging
// off the right edge (owner, on the phone, 0.3.0), and always BELOW the
// decision row's hit area (p4 I-2, hot r4 n5) — measured in both phone arms:
// the static key-changed row here, the sticky Message/Unverify bar below.
// `width < 200` guards the other way to be centred: stretched to the sheet.
const removeGeo = () => alice.page.evaluate(() => {
  const s = document.querySelector("#contactSheet").getBoundingClientRect();
  const r = document.querySelector("#contactRemove").getBoundingClientRect();
  const btns = [...document.querySelectorAll(".contact-actions > button:not([hidden])")].map((b) => b.getBoundingClientRect());
  const hit = document.elementFromPoint(r.x + r.width / 2, r.y + r.height / 2);
  return { sheetMid: Math.round((s.left + s.right) / 2), removeMid: Math.round((r.left + r.right) / 2), width: Math.round(r.width),
    clearance: Math.round(r.top - Math.max(...btns.map((b) => b.bottom))), hit: hit?.id, pos: getComputedStyle(document.querySelector(".contact-actions")).position };
});
const okRemove = (g) => Math.abs(g.sheetMid - g.removeMid) <= 1 && g.width < 200 && g.clearance >= 0 && g.hit === "contactRemove";
const geoStatic = await removeGeo();
check("key changed: Remove is centred under the static row, below its hit area, not right-aligned",
  okRemove(geoStatic) && geoStatic.pos === "static", JSON.stringify(geoStatic));
await alice.page.mouse.click(195, 20);
await waitSheet(alice.page, false);
// The sticky arm: a verified contact, Message primary, Unverify beside it.
await store(alice.page, async (u) => { await (await import("./contacts.js")).setVerified(u, true); }, bob.username);
await alice.page.click(`${rowOf(bob.username)} > .u-open`);
await waitSheet(alice.page);
await sleep(400);
const geoSticky = await removeGeo();
check("verified: Remove is centred under the sticky Message/Unverify bar and below its hit area",
  okRemove(geoSticky) && geoSticky.pos === "sticky", JSON.stringify(geoSticky));
// Opened from a conversation there is no Message: the lone Unverify is
// centred on the same axis as Remove (hot r7 MINOR-2). Hidden the way
// app.js hides it, then restored.
const geoLone = await alice.page.evaluate(() => {
  const m = document.querySelector("#contactMessage"); m.hidden = true;
  const s = document.querySelector("#contactSheet").getBoundingClientRect();
  const v = document.querySelector("#contactVerify").getBoundingClientRect();
  m.hidden = false;
  return { sheetMid: Math.round((s.left + s.right) / 2), verifyMid: Math.round((v.left + v.right) / 2) };
});
check("without Message the lone Unverify is centred on Remove's axis", Math.abs(geoLone.sheetMid - geoLone.verifyMid) <= 1, JSON.stringify(geoLone));
await store(alice.page, async (u) => { await (await import("./contacts.js")).setVerified(u, false); }, bob.username);
await alice.page.mouse.click(195, 20);
await waitSheet(alice.page, false);
check("a tap on the scrim closes it on a phone", !(await sheet(alice.page)).open);

// A changed key on a small phone: the fingerprint is never under the Verify
// bar (pentest p3 L-4) — the row is in the flow after it.
await alice.page.setViewport({ width: 320, height: 568 });
await sleep(300);
const dbgSmall = await alice.page.evaluate((sel) => {
  const el = document.querySelector(sel);
  if (!el) return { row: false };
  el.scrollIntoView({ block: "center" });
  const r = el.getBoundingClientRect();
  const hit = document.elementFromPoint(r.x + r.width / 2, r.y + r.height / 2);
  return { row: true, hit: hit ? hit.id || hit.className : null, inert: document.querySelector("#viewUsers").inert };
}, `${rowOf(bob.username)} > .u-open`);
await alice.page.click(`${rowOf(bob.username)} > .u-open`);
await waitSheet(alice.page);
const small = await alice.page.evaluate(() => {
  const fp = document.querySelector("#contactFingerprint").getBoundingClientRect();
  const bar = document.querySelector(".contact-actions");
  const b = bar.getBoundingClientRect();
  return { open: !document.querySelector("#contactSheet").hidden, fpBottom: Math.round(fp.bottom), barTop: Math.round(b.top),
    pos: getComputedStyle(bar).position, primary: document.querySelector(".contact-actions > .primary")?.id };
});
check("key changed at 320×568: Verify is the primary, its row sits after the fingerprint, never over it",
  small.open && small.fpBottom > 0 && small.primary === "contactVerify" && small.pos === "static" && small.fpBottom <= small.barTop,
  JSON.stringify({ small, dbgSmall }));
const oneRow = await alice.page.evaluate(() => {
  const [a, b] = [...document.querySelectorAll(".contact-actions > button:not([hidden])")].map((x) => x.getBoundingClientRect().top);
  return Math.abs(a - b) < 2;
});
check("at 320px and normal text the two actions share one row", oneRow);
// 200% text (the font tokens doubled, as a user's text size would): no label
// spills out of its button, nothing leaves the sheet.
await alice.page.evaluate(() => {
  const big = new CSSStyleSheet();
  big.replaceSync(":root{--fs-1:24px;--fs-2:26px;--fs-3:30px;--fs-4:34px;--fs-5:40px;--fs-6:48px;--control-fs:32px}");
  document.adoptedStyleSheets = [...document.adoptedStyleSheets, big];
  window.__big = big;
});
await sleep(300);
const fit = await alice.page.evaluate(() => {
  const sheet = document.querySelector("#contactSheet");
  const spills = [...sheet.querySelectorAll("button:not([hidden])")].filter((b) => b.scrollWidth > b.clientWidth + 1).map((b) => b.id);
  return { sheetOverflow: sheet.scrollWidth - sheet.clientWidth, spills };
});
await alice.page.evaluate(() => { document.adoptedStyleSheets = document.adoptedStyleSheets.filter((x) => x !== window.__big); });
check("at 200% text no action label spills out of its button and the sheet does not overflow sideways",
  fit.sheetOverflow <= 0 && fit.spills.length === 0, JSON.stringify(fit));
if (small.open) await alice.page.click("#contactClose");
await waitSheet(alice.page, false);
await alice.page.setViewport({ width: 390, height: 844 });
await sleep(300);

// Pentest L-3 / cold m2: the second half of a double tap lands on the sheet
// (or the scrim) as it appears — reduced motion, so no CSS guard helps. It
// must neither act nor close the sheet.
await alice.page.emulateMediaFeatures([{ name: "prefers-reduced-motion", value: "reduce" }]);
const box = await alice.page.evaluate((sel) => {
  const r = document.querySelector(sel).getBoundingClientRect();
  return { x: r.x + r.width / 2, y: r.y + r.height / 2 };
}, `${rowOf(bob.username)} > .u-open`);
const before = await alice.page.evaluate(async (u) => (await import("./contacts.js")).get(u).verified, bob.username);
await alice.page.mouse.click(box.x, box.y);
const target = await alice.page.evaluate(() => {
  const r = document.querySelector("#contactVerify").getBoundingClientRect();
  return { x: r.x + r.width / 2, y: r.y + r.height / 2 };
});
await sleep(150);
await alice.page.mouse.click(target.x, target.y); // lands on Verify, inside the 500 ms
await alice.page.mouse.click(8, 8);                // and a stray one on the scrim
await sleep(400);
const after = await alice.page.evaluate(async (u) => (await import("./contacts.js")).get(u).verified, bob.username);
s = await sheet(alice.page);
check("a double tap's second half (reduced motion) neither acts nor closes the sheet",
  s.open && before === after, JSON.stringify({ open: s.open, before, after }));
await alice.page.emulateMediaFeatures([]);
await alice.page.click("#contactClose");

check("no page errors", errors.length === 0, errors.slice(0, 3).join(" | "));
await browser.close();

console.log("\n=== summary ===");
const failed = results.filter((r) => !r.ok);
console.log(`  ${results.length - failed.length}/${results.length} checks passed`);
if (failed.length) {
  for (const r of failed) console.log("  FAIL " + r.name);
  process.exit(1);
}
console.log("  all good");
