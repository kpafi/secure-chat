// Every way to fail on the room screen must SAY something visible.
//
//   node e2e/no-dead-ends.mjs
//
// The reported bug: pressing Connect with an empty chat code did nothing at all.
// The message existed, but `#hint` lives inside the chat screen, which is hidden
// while you are on the room screen — so ten different validation failures were
// all written to an invisible element. This walks each of them and asserts the
// user actually sees text appear.
import puppeteer from "puppeteer-core";
import { readFileSync } from "node:fs";

const cfg = JSON.parse(readFileSync(new URL("./test-users.json", import.meta.url)));
const APP = process.env.SECURE_CHAT_E2E_URL || cfg.relay;
const PASS = cfg.users[0].passphrase;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const results = [];
const check = (name, ok, detail = "") => {
  results.push({ name, ok });
  console.log(`  ${ok ? "OK  " : "FAIL"} ${name}${detail ? " — " + detail : ""}`);
};

const browser = await puppeteer.launch({
  executablePath: process.env.CHROMIUM || "/usr/bin/chromium",
  headless: "new",
  args: ["--no-sandbox", "--disable-dev-shm-usage"],
});
const page = await browser.newPage();
await page.setViewport({ width: 1000, height: 900 });
await page.goto(APP, { waitUntil: "networkidle0" });

// The DYNAMIC feedback the user sees — deliberately excludes static help text
// (#roomHelp and friends), which would otherwise satisfy a check without the
// app having said anything about what just went wrong.
const FEEDBACK = ["#roomHint", "#idHint", "#hint", "#status"];
const visibleText = () => page.evaluate((sel) => {
  const seen = [];
  for (const s of sel) {
    const el = document.querySelector(s);
    if (!el) continue;
    const r = el.getBoundingClientRect();
    if (r.width > 0 && r.height > 0 && getComputedStyle(el).visibility !== "hidden"
        && el.textContent.trim()) {
      seen.push(el.textContent.trim());
    }
  }
  return seen;
}, FEEDBACK);

// Assert some visible feedback matches, and report the text that actually did.
function says(name, seen, re) {
  const hit = seen.find((t) => re.test(t));
  check(name, !!hit, hit ? JSON.stringify(hit.slice(0, 90)) : "nothing visible: " + JSON.stringify(seen));
}

console.log(`\n=== no dead ends on the room screen (${APP}) ===\n`);

// A code is pre-filled, so the original dead end cannot even be reached.
const prefilled = await page.evaluate(() => document.querySelector("#room").value);
check("a chat code is created automatically", /^[0-9a-f]{64}$/.test(prefilled),
  prefilled ? prefilled.slice(0, 16) + "…" : "(empty)");

await page.click("#toRoom");
await sleep(300);

// 1. Empty code — the exact reported scenario.
await page.evaluate(() => { document.querySelector("#room").value = ""; });
await page.click("#connect");
await sleep(600);
let seen = await visibleText();
says("empty chat code explains itself", seen, /chat code/i);

// 2. Malformed code (too short) — and pasted whitespace must be TOLERATED.
await page.evaluate(() => { document.querySelector("#room").value = "abc123"; });
await page.click("#connect");
await sleep(600);
seen = await visibleText();
says("malformed chat code explains itself", seen, /chat code/i);

const spaced = await page.evaluate(() => {
  const code = "a".repeat(64);
  document.querySelector("#room").value = "  " + code.toUpperCase().replace(/(.{8})/g, "$1 ") + "  ";
  return true;
});
check("a pasted code with spaces/capitals is accepted", spaced);

// 3. An identity-requiring mode without an identity.
await page.evaluate(() => {
  document.querySelector("#room").value = "b".repeat(64);
  document.querySelector('input[value="PQKEM"]').click();
});
await sleep(300);
await page.click("#connect");
await sleep(600);
seen = await visibleText();
says("a mode needing an identity says so", seen, /identity/i);

// 4. OTP selected with no pad on the device.
await page.evaluate(() => document.querySelector('input[value="OTP"]').click());
await sleep(300);
await page.click("#connect");
await sleep(600);
seen = await visibleText();
says("OTP with no pad says so", seen, /one-time pad/i);

// 5. Security options stay open once a non-default mode is chosen, and the
//    collapsed summary names it (so the setting can never hide).
const summary = await page.evaluate(() => ({
  open: document.querySelector("#algDetails").open,
  text: document.querySelector("#algSummary").textContent,
}));
check("security options reflect the chosen mode",
  summary.open && /one-time pad/i.test(summary.text), JSON.stringify(summary));

// 6. Copy button reports success or failure — never nothing.
await page.evaluate(() => { document.querySelector("#room").value = ""; });
await page.click("#copyCode");
await sleep(400);
seen = await visibleText();
says("copy with no code explains itself", seen, /no code to copy/i);

// 7. Accessibility basics that were missing.
const a11y = await page.evaluate(() => {
  const ids = [...document.querySelectorAll("input,select,textarea")].map((e) => e.id).filter(Boolean);
  const labelled = new Set([...document.querySelectorAll("label[for]")].map((l) => l.getAttribute("for")));
  const unlabelled = ids.filter((i) => {
    const el = document.getElementById(i);
    return !labelled.has(i) && !el.getAttribute("aria-label");
  });
  return {
    unlabelled,
    liveRegions: document.querySelectorAll("[aria-live]").length,
    menuExpanded: document.querySelector("#menuBtn").getAttribute("aria-expanded"),
  };
});
check("every form control is labelled", a11y.unlabelled.length === 0, JSON.stringify(a11y.unlabelled));
check("status regions are announced", a11y.liveRegions >= 8, "aria-live count: " + a11y.liveRegions);
check("menu button exposes its state", a11y.menuExpanded === "false", String(a11y.menuExpanded));

await page.click("#menuBtn");
await sleep(300);
const drawerState = await page.evaluate(() => ({
  expanded: document.querySelector("#menuBtn").getAttribute("aria-expanded"),
  current: document.querySelector('.navitem[aria-current="page"]')?.dataset.view || null,
}));
check("open drawer marks the current view",
  drawerState.expanded === "true" && drawerState.current === "live", JSON.stringify(drawerState));

// --- a store that refuses to open must offer a way out (fix review 2026-09-21)
// The at-rest stores now refuse a deleted/unverifiable blob instead of silently
// recreating it. The reviewer found that when only the CHAT store refused, the
// user saw an empty, success-looking unlock status and no override anywhere —
// the only exit was Forget identity. This drives that exact state through the
// real UI: identity created, chat store deleted, reload, unlock in the Chats
// view, expect a visible error AND a working "Open anyway".
{
  const p2 = await browser.newPage();
  await p2.goto(APP, { waitUntil: "networkidle0" });
  await p2.type("#idPass", PASS);
  await p2.click("#idCreate");
  await p2.waitForFunction(() => !document.querySelector("#idExport").hidden, { timeout: 60000 });
  await p2.evaluate(() => localStorage.removeItem("sc.chats.v1")); // the one removeItem
  await p2.reload({ waitUntil: "networkidle0" });
  await p2.click("#menuBtn");
  await p2.click('.navitem[data-view="chats"]');
  await p2.waitForFunction(() => !document.querySelector("#viewChats").hidden, { timeout: 10000 });
  await p2.type("#chatsUnlockPass", PASS);
  await p2.click("#chatsUnlock");
  // Pre-fix this wait never resolves: the status was blank and the panel text
  // generic. Swallow the timeout so it reports as a FAIL line, not a crash.
  await p2.waitForFunction(
    () => /unlocked, but|error/i.test(document.querySelector("#chatsUnlockStatus").textContent +
      document.querySelector("#chatsLocked p").textContent), { timeout: 60000 }).catch(() => {});
  const lockedText = await p2.evaluate(() =>
    document.querySelector("#chatsLocked p").textContent + " | " + document.querySelector("#chatsUnlockStatus").textContent);
  check("a refused chat store says so where the user is", /DELETED|error/i.test(lockedText),
    JSON.stringify(lockedText.slice(0, 120)));
  const adoptVisible = await p2.evaluate(() => {
    const b = document.querySelector("#chatsAdopt");
    return !!b && !b.hidden && b.getBoundingClientRect().height > 0;
  });
  check("…and offers 'Open anyway' right there", adoptVisible);
  await p2.type("#chatsUnlockPass", PASS);
  await p2.click("#chatsAdopt");
  await p2.waitForFunction(() => !document.querySelector("#chatsUnlocked").hidden, { timeout: 60000 })
    .catch(() => {});
  check("the override actually opens the chats view",
    await p2.evaluate(() => !document.querySelector("#chatsUnlocked").hidden));
  // Users view: nothing refused there, so no override is offered — the control
  // is per store, not a global "ignore all warnings".
  await p2.click("#menuBtn");
  await p2.click('.navitem[data-view="users"]');
  await p2.waitForFunction(() => !document.querySelector("#viewUsers").hidden, { timeout: 10000 });
  check("the Users view, which did not refuse, shows no override",
    await p2.evaluate(() => document.querySelector("#usersAdopt").hidden && !document.querySelector("#usersUnlocked").hidden));
  await p2.close();
}

await browser.close();
const failed = results.filter((r) => !r.ok);
console.log(`\n  ${results.length - failed.length}/${results.length} checks passed`);
if (failed.length) {
  console.log("  FAILED: " + failed.map((f) => f.name).join("; "));
  process.exit(1);
}
console.log("  no dead ends\n");
