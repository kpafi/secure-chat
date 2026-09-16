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

// F-PROTO-001 (rebuilt 2026-08-08): the peer whose device did NOT run the knock
// prompt is asked to approve the other side's key before the handshake
// completes, unless that key is already trusted — which since 2026-08-08
// item 14 means ONLY a 🟢 key verified in person, never a contact picked by
// name. Every session here is a raw room code between strangers, so the guest
// always gets it. Authenticated modes only — AES256/OTP exchange no
// identity, so there is nothing to approve.
//
// Item 20 (2026-08-10): this waits for the PEER-approval prompt specifically.
// `#admit` is shared with the owner's knock prompt, so "un-hidden" matched
// either one — and this helper would then click "Let them in" on a knock while
// reporting that the guest had approved a key. app.js marks the panel with
// `data-mode`; the button label is checked too, so the marker cannot drift away
// from what the user is shown.
async function approvePeerKey(page, timeout = 45000) {
  await page.waitForFunction(() => {
    const el = document.querySelector("#admit");
    return !!el && !el.hidden && el.dataset.mode === "peer";
  }, { timeout });
  const label = await page.evaluate(() => document.querySelector("#admitOk").textContent.trim());
  if (label !== "Connect") {
    throw new Error(`expected the peer-approval prompt ("Connect"), got ${JSON.stringify(label)}`);
  }
  await page.click("#admitOk");
}

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
async function agent(label) {
  const ctx = await browser.createBrowserContext();
  const page = await ctx.newPage();
  page.on("pageerror", (e) => errors.push(`${label}: ${e.message}`));
  page.on("console", (m) => {
    const t = m.text();
    if (m.type() === "error" && !/favicon|404/.test(t)) errors.push(`${label}: ${t}`);
  });
  await page.setViewport({ width: 1000, height: 900 });
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

// Put `code` in the room field and press Connect.
async function joinRoom(page, code) {
  await page.evaluate(() => { document.querySelector("#room").value = ""; });
  await page.type("#room", code);
  await page.click("#connect");
}

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

// --- 3. the invited peer knocks too, and is let in -------------------------
console.log("\n3. the invited peer knocks; alice denies the squatter and admits bob");
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
await alice.page.click("#admitNo");
await sleep(600);
const mallorySawDenial = await text(mallory.page, "#log");
check("the squatter is told it was denied", /did not let you in/i.test(mallorySawDenial),
  JSON.stringify(mallorySawDenial.slice(-80)));

await alice.page.waitForFunction(() => !document.querySelector("#admit").hidden, { timeout: 30000 });
const bobFp = await text(alice.page, "#admitFingerprint");
check("the second prompt shows bob's fingerprint", bobFp === bob.fingerprint,
  `${bobFp.slice(0, 24)}… vs ${bob.fingerprint.slice(0, 24)}…`);
await alice.page.click("#admitOk");
// The guest approves alice's key in turn (see approvePeerKey).
await approvePeerKey(bob.page);

// --- 4. the squatter did NOT cost the invited peer the room ----------------
console.log("\n4. the real session completes anyway (the finding itself)");
await bob.page.waitForFunction(
  () => !document.querySelector("#verify").hidden, { timeout: 45000 });
await alice.page.waitForFunction(
  () => !document.querySelector("#verify").hidden, { timeout: 45000 });
const [snA, snB] = [await text(alice.page, "#safetyNumber"), await text(bob.page, "#safetyNumber")];
check("both peers reach the safety-number gate after approval", !!snA && snA === snB,
  `${snA.slice(0, 20)}… / ${snB.slice(0, 20)}…`);

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
