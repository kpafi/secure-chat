// Two-agent end-to-end run of the things a real pair of users actually do.
//
//   node e2e/two-user-flow.mjs
//
// Needs the relay running (backend/run.sh) and system Chromium. Credentials
// live in e2e/test-users.json so a failing step can be re-driven by hand in a
// browser with the same accounts.
//
// It exists because a live test with a real person found two bugs that every
// unit test missed, both about the SECOND user's experience:
//   1. an invite link opens a NEW tab, where the identity is locked and there
//      was no way to unlock without navigating back to the Live room;
//   2. async chat silently delivered nothing unless the recipient had clicked
//      "Log in" — sending worked, receiving did not, with no visible sign.
// Both are asserted below, so they cannot regress quietly.
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
// `ctx` lets a caller open a tab in an EXISTING browser context, which is what
// a real "open link in new tab" does: same origin, same localStorage, but a
// fresh page with no in-memory identity. That distinction is the whole point of
// check 2 — a separate context would have no identity blob at all.
async function newTab(label, ctx = null) {
  ctx = ctx || await browser.createBrowserContext();
  const page = await ctx.newPage();
  page.on("pageerror", (e) => errors.push(`${label}: ${e.message}`));
  page.on("console", (m) => {
    const t = m.text();
    if (m.type() === "error" && !/favicon|404/.test(t)) errors.push(`${label}: ${t}`);
  });
  await page.setViewport({ width: 1000, height: 900 });
  await page.goto(APP, { waitUntil: "networkidle0" });
  return { ctx, page, label };
}

// The four views are tabs that are always on screen (top bar on desktop,
// bottom bar on a phone) — one click, no menu to open first.
async function view(page, name) {
  await page.click(`.navitem[data-view="${name}"]`);
  await sleep(400);
}

// A user as they really onboard: create identity, register. NOTE: deliberately
// NEVER clicks "Log in" — receiving must work without it.
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
  await sleep(1500); // give the automatic directory login a moment
  const handle = await t.page.evaluate(() =>
    localStorage.getItem("sc.username.v1") + "#" + localStorage.getItem("sc.lookuptoken.v1"));
  return { ...t, username, handle, passphrase: spec.passphrase };
}

console.log(`\n=== two-user end-to-end run (${APP}) ===\n`);
const [aliceSpec, bobSpec] = cfg.users;
const alice = await onboard(aliceSpec, "alice");
const bob = await onboard(bobSpec, "bob");
console.log(`  alice: ${alice.handle}`);
console.log(`  bob:   ${bob.handle}\n`);

// --- 1. registering must be enough to RECEIVE (no manual "Log in") ----------
console.log("1. directory session after register (no manual login)");
const aliceLoggedIn = await alice.page.evaluate(() =>
  /logged in/.test(document.querySelector("#profileStatus")?.textContent || "") ||
  /Logged in/.test(document.querySelector("#accountStatus")?.textContent || ""));
await view(alice.page, "profile");
const aliceChips = await alice.page.evaluate(() =>
  [...document.querySelectorAll("#profileStatus .chip")].map((c) => c.textContent));
check("alice holds a directory session automatically",
  aliceChips.includes("logged in"), JSON.stringify(aliceChips));

// --- 2. invite link opens a fresh tab: it must be unlockable in place -------
console.log("\n2. invite link in a new tab (identity locked there)");
const inviteTab = await newTab("invite", alice.ctx);
// Same origin => same localStorage, so the identity blob is present but LOCKED.
await inviteTab.page.evaluate((h) => {
  location.hash = "#add=" + encodeURIComponent(h);
}, bob.handle);
await inviteTab.page.reload({ waitUntil: "networkidle0" });
await view(inviteTab.page, "users");
const lockedState = await inviteTab.page.evaluate(() => ({
  locked: !document.querySelector("#usersLocked").hidden,
  hasUnlock: !!document.querySelector("#usersUnlock"),
}));
check("Users view offers an unlock control while locked",
  lockedState.locked && lockedState.hasUnlock, JSON.stringify(lockedState));

// Unlock right there (this is the flow that was impossible before).
await inviteTab.page.type("#usersUnlockPass", alice.passphrase);
await inviteTab.page.click("#usersUnlock");
await inviteTab.page.waitForFunction(
  () => !document.querySelector("#usersUnlocked").hidden, { timeout: 40000 });
await sleep(800);
const prefilled = await inviteTab.page.evaluate(() => document.querySelector("#addHandle").value);
check("unlocking in place prefills the invited handle", prefilled === bob.handle,
  JSON.stringify(prefilled));
// Phase 2a (pentest, pre-existing): the invite's explanation was written, then
// erased by the list render that followed it.
const statusLine = (page) => page.evaluate(() => {
  const el = document.querySelector("#usersStatus"), r = el.getBoundingClientRect();
  return { text: el.textContent.trim(), shown: r.width > 0 && r.height > 0 };
});
const inviteLine = await statusLine(inviteTab.page);
check("A1: the invite tab says a handle was received (not erased by the render)",
  /^Handle received — review it and press Add\.$/.test(inviteLine.text) && inviteLine.shown, JSON.stringify(inviteLine));

// Add bob from that tab.
await inviteTab.page.click("#addContact");
await inviteTab.page.waitForFunction(
  () => document.querySelectorAll("#userList li:not(.empty)").length > 0, { timeout: 30000 });
check("contact added from the invite tab", true);
const addedLine = await statusLine(inviteTab.page);
check("A1: the add result stays on screen and names the contact",
  addedLine.shown && addedLine.text.includes(`"${bob.username}"`), JSON.stringify(addedLine));
await inviteTab.page.close();

// --- 3. async chat delivers to someone who never added the sender ----------
console.log("\n3. async chat, recipient has NOT added the sender");
await view(alice.page, "users");
await alice.page.reload({ waitUntil: "networkidle0" });
await alice.page.type("#idPass", alice.passphrase);
await alice.page.click("#idUnlock");
await alice.page.waitForFunction(() => !document.querySelector("#idExport").hidden, { timeout: 40000 });
await sleep(1500);
await view(alice.page, "chats");
await alice.page.select("#chatNew", bob.username);
await alice.page.click("#chatStart");
await alice.page.waitForFunction(() => !document.querySelector("#chatConvo").hidden, { timeout: 20000 });
await alice.page.type("#chatText", "hello bob, this is alice");
await alice.page.click("#chatSend");
await sleep(1000);

// Phase 2a, A4: bob is alice's only saved user and now has a chat, so the
// picker must not tell her to add users first.
await alice.page.click("#chatBack");
await sleep(400);
const pickerNote = await alice.page.evaluate(() => document.querySelector("#chatNew option").textContent);
check("A4: the picker says every saved user already has a chat",
  pickerNote === "— every saved user already has a chat —", JSON.stringify(pickerNote));
// Phase 2a, B4 (a11y review): a chat row is a keyboard stop — Tab from the
// Open button reaches it — and Enter opens the conversation.
await alice.page.focus("#chatStart");
await alice.page.keyboard.press("Tab");
const rowFocus = await alice.page.evaluate(() => {
  const a = document.activeElement;
  return { row: a.matches("#chatList > li.chatrow"), role: a.getAttribute("role") };
});
await alice.page.keyboard.press("Enter");
await alice.page.waitForFunction(() => !document.querySelector("#chatConvo").hidden, { timeout: 5000 }).catch(() => {});
const rowOpened = await alice.page.evaluate(() => ({
  convo: !document.querySelector("#chatConvo").hidden, peer: document.querySelector("#chatPeer").textContent,
}));
check("B4: Tab reaches the first chat row and Enter opens the conversation",
  rowFocus.row && rowFocus.role === "button" && rowOpened.convo && rowOpened.peer === bob.username,
  JSON.stringify({ rowFocus, rowOpened }));
// Fix round, C2 (a11y review): opening the row hides it — focus continues in the
// conversation; Back returns focus to the row that was open, not to <body>.
const focusIn = (page) => page.evaluate(() => {
  const a = document.activeElement;
  return { id: a.id || a.tagName, convo: document.querySelector("#chatConvo").contains(a),
    list: document.querySelector("#chatListWrap").contains(a), user: a.dataset ? a.dataset.user || null : null };
});
const afterOpen = await focusIn(alice.page);
await alice.page.keyboard.press("Enter"); // on "Back to chats", where focus now is
await sleep(300);
const afterBack = await focusIn(alice.page);
check("C2: focus moves into the conversation on open, and back to that row on Back",
  afterOpen.convo && afterOpen.id === "chatBack" && afterBack.list && afterBack.user === bob.username,
  JSON.stringify({ afterOpen, afterBack }));

await view(bob.page, "chats");
let bobGot = [];
for (let i = 0; i < 12 && !bobGot.length; i++) {
  await sleep(2500);
  bobGot = await bob.page.evaluate(async () => {
    const chats = await import("./chats.js");
    try { return chats.list().flatMap((c) => c.messages.map((m) => m.text)); } catch { return []; }
  });
}
check("bob receives without ever having added alice",
  bobGot.includes("hello bob, this is alice"), JSON.stringify(bobGot));

const bobsView = await bob.page.evaluate(async () => {
  const contacts = await import("./contacts.js");
  const c = contacts.list()[0];
  return c ? { local: c.username, claimed: c.claimedName, verified: c.verified } : null;
});
check("unknown sender shows as unverified, key-derived name",
  !!bobsView && bobsView.verified === false && bobsView.local.startsWith("unknown-"),
  JSON.stringify(bobsView));

// --- 4. bob adds alice and replies ----------------------------------------
console.log("\n4. bob adds alice, replies both ways");
await view(bob.page, "users");
await bob.page.type("#addHandle", alice.handle);
await bob.page.click("#addContact");
await bob.page.waitForFunction(
  () => document.querySelectorAll("#userList li:not(.empty)").length > 0, { timeout: 30000 });
await view(bob.page, "chats");
await bob.page.evaluate(async () => {
  const row = document.querySelector("#chatList li:not(.empty)");
  if (row) row.click();
  await new Promise((r) => setTimeout(r, 700));
});
await bob.page.type("#chatText", "hi alice, got it");
await bob.page.click("#chatSend");

let aliceGot = [];
for (let i = 0; i < 12 && !aliceGot.includes("hi alice, got it"); i++) {
  await sleep(2500);
  aliceGot = await alice.page.evaluate(async () => {
    const chats = await import("./chats.js");
    try { return chats.list().flatMap((c) => c.messages.map((m) => m.text)); } catch { return []; }
  });
}
check("alice receives bob's reply", aliceGot.includes("hi alice, got it"),
  JSON.stringify(aliceGot));

// --- 5. web of trust: alice verifies bob, publishes a vouch ---------------
console.log("\n5. web of trust");
alice.page.on("dialog", (d) => d.accept());
await view(alice.page, "users");
await sleep(500);
await alice.page.evaluate(() => {
  const b = [...document.querySelectorAll("#userList button")].find((x) => /Verified in person/i.test(x.textContent));
  if (b) b.click();
});
await sleep(2500);
const aliceMarks = await alice.page.evaluate(() =>
  [...document.querySelectorAll("#userList .u-mark")].map((e) => e.textContent));
check("alice can mark bob verified (green)",
  aliceMarks.some((m) => m.includes("verified by you")), JSON.stringify(aliceMarks));

// --- 6. fix round, C4 (B5): a changed key is a caption inside the mark -------
// Bob's record gets new keys in alice's store (what a re-keyed contact looks
// like after a directory refresh). The Chats row's box mark then carries the
// key-changed caption as its own span; the Users row, which says it in a
// sentence of its own, does not.
console.log("\n6. key-changed caption (store-level re-key of bob in alice's page)");
await alice.page.evaluate(async (u) => {
  const { Identity } = await import("./identity.js");
  const contacts = await import("./contacts.js");
  const c = contacts.get(u);
  const k = (await Identity.generate()).publicBundle();
  await contacts.upsert({ username: u, token: c.token, ed: k.ed, mldsa: k.mldsa, ecdh: k.ecdh, mlkem: k.mlkem });
}, bob.username);
await view(alice.page, "chats");
const chatMark = await alice.page.evaluate((u) => {
  const row = document.querySelector(`#chatList li[data-user="${u}"]`);
  const m = row && row.querySelector(".u-mark"), n = m && m.querySelector(".u-mark-note");
  return m ? { cls: m.className, text: m.textContent, note: n ? n.textContent : null } : null;
}, bob.username);
await view(alice.page, "users");
const userNotes = await alice.page.evaluate(() => document.querySelectorAll("#userList .u-mark-note").length);
check("B5: the Chats row's key-changed mark carries the caption span; the Users row does not",
  !!chatMark && /\bchanged\b/.test(chatMark.cls) && /key CHANGED since you last verified/.test(chatMark.note || "") &&
  chatMark.text === "unverified — key CHANGED since you last verified" && userNotes === 0,
  JSON.stringify({ chatMark, userNotes }));

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
