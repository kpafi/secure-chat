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
  page.on("dialog", (d) => d.accept()); // every confirm() says yes
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
  const dd = [...document.querySelectorAll("#contactFacts > dt")].map((dt) => [dt.textContent, dt.nextElementSibling.textContent]);
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
const waitSheet = (page, open = true) => page.waitForFunction((o) =>
  document.querySelector("#contactSheet").hidden === !o, { timeout: 5000 }).catch(() => {});
const waitFp = (page) => page.waitForFunction(() =>
  !/^…$/.test(document.querySelector("#contactFingerprint").textContent), { timeout: 10000 }).catch(() => {});
const focusInfo = (page) => page.evaluate(() => {
  const a = document.activeElement;
  return { cls: a.className, id: a.id, user: a.closest("li")?.dataset.user || null };
});
const rowOf = (u) => `#userList > li[data-user="${u}"]`;

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
check("the facts: saved today, not verified yet, can receive sealed messages",
  !!s.facts.Saved && s.facts.Verified === "not yet" && s.facts.Messages === "can receive sealed messages" && !("Vouched by" in s.facts),
  JSON.stringify(s.facts));
check("one primary: Message; Verify is secondary and enabled once the fingerprint is on screen",
  s.message && s.verify.text === "Verified in person ✓" && !s.verify.disabled &&
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
check("a click on the scrim closes it", !(await sheet(alice.page)).open);

// --- 2. Verify from the sheet --------------------------------------------------
console.log("\n2. verify from the sheet");
await alice.page.click(`${rowOf(bob.username)} > .u-open`);
await waitSheet(alice.page);
await waitFp(alice.page);
await alice.page.click("#contactVerify"); // both confirm()s accepted
await alice.page.waitForFunction(() => document.querySelector("#contactVerify").textContent === "Unverify", { timeout: 15000 }).catch(() => {});
s = await sheet(alice.page);
const rowMark = await alice.page.evaluate((sel) => document.querySelector(`${sel} .u-mark`)?.textContent, rowOf(bob.username));
check("Verify in the sheet marks bob verified: the sheet and the row say so, the facts carry the date",
  s.open && s.mark === "verified by you" && rowMark === "verified by you" && s.verify.text === "Unverify" &&
  s.facts.Verified !== "not yet", JSON.stringify({ mark: s.mark, rowMark, verify: s.verify, facts: s.facts }));

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
// Unverify first, so the Verify path (the one with the snapshot check) is live.
await alice.page.click(`${rowOf(bob.username)} > .u-open`);
await waitSheet(alice.page);
await alice.page.click("#contactVerify"); // Unverify
await alice.page.waitForFunction(() => document.querySelector("#contactVerify").textContent === "Verified in person ✓", { timeout: 10000 }).catch(() => {});
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
await alice.page.click("#contactVerify");
await sleep(600);
s = await sheet(alice.page);
const verifiedAfter = await alice.page.evaluate(async (u) => (await import("./contacts.js")).get(u).verified, bob.username);
check("Verify REFUSES when the keys moved under the open sheet, and shows the new fingerprint",
  !verifiedAfter && /keys changed while their profile was open/.test(s.status) && s.fp !== fpBefore,
  JSON.stringify({ verifiedAfter, status: s.status, fpBefore, fpNow: s.fp }));
check("the sheet now carries the key-changed mark and sentence",
  /key CHANGED since you last verified/.test(s.mark) &&
  s.warn === "this user's key CHANGED since you saved them — re-verify in person before trusting", JSON.stringify({ mark: s.mark, warn: s.warn }));
await alice.page.keyboard.press("Escape");
await waitSheet(alice.page, false);
await view(alice.page, "chats");
await view(alice.page, "users"); // a fresh render of the list
const rowWarn = await alice.page.evaluate((sel) => document.querySelector(`${sel} > .hint.err`)?.textContent, rowOf(bob.username));
check("the Users row keeps the key-changed sentence visible without opening anything",
  rowWarn === "this user's key CHANGED since you saved them — re-verify in person before trusting", JSON.stringify(rowWarn));

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
await view(alice.page, "users");
if (auto) {
  await alice.page.click(`${rowOf(auto)} > .u-open`);
  await waitSheet(alice.page);
  s = await sheet(alice.page);
  check("an automatic contact's handle is labelled a claim, beside the claim line",
    s.handleLabel === "Handle they claim" && s.handle === carol.handle &&
    s.warn.includes(`claims to be "${carol.handle}"`), JSON.stringify({ label: s.handleLabel, handle: s.handle, warn: s.warn }));
  await alice.page.click("#contactRemove");
  await waitSheet(alice.page, false);
  const gone = await alice.page.evaluate((sel) => !document.querySelector(sel), rowOf(auto));
  f = await focusInfo(alice.page);
  check("Remove closes the sheet, drops the row, and focus lands on the add field",
    !(await sheet(alice.page)).open && gone && f.id === "addHandle", JSON.stringify({ gone, f }));
} else {
  check("carol's mail made an automatic contact on alice's device", false, "no auto contact after 15 polls");
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
await alice.page.mouse.click(195, 20);
await waitSheet(alice.page, false);
check("a tap on the scrim closes it on a phone", !(await sheet(alice.page)).open);

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
