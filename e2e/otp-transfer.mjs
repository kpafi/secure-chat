// One-time pad transfer: the New pad, Export and Import sheets, in a real
// browser (design/research/reviews/otp-transfer-brief.md § 11).
//
//   node e2e/otp-transfer.mjs            (relay from test-users.json, or
//   SECURE_CHAT_E2E_URL=http://127.0.0.1:8093 node e2e/otp-transfer.mjs)
//
// Three agents in their own browser contexts, none with an identity (a pad
// needs none):
//   alice   - the maker, in a desktop browser: New pad → Export (the file is
//             caught at the download), the re-export warning, the must-differ
//             refusal after New pad, Back while working and while idle;
//   bob     - the receiver: Import with a wrong transfer passphrase (the field
//             is marked), Try again without a second pick, the received-pad
//             rules, Lock; then alice and bob Connect on the pad and talk;
//   android - an Android shell stand-in: a FROZEN fake `__SECURE_CHAT_FILES__`
//             injected at document-start, answering like the real one (ids,
//             "busy", "invalid"); the test plays the shell's result callback.
// Every sheet state checked is measured at 390×844: no horizontal overflow,
// the sheet docked above the tab bar, the bottom row inside the sheet and
// hit-testable, one visible primary (none in the re-export confirm), 44px
// targets. The sheet mechanics (inert rest, Tab wrap, Escape / × / scrim and
// focus return) are driven by keyboard and pointer.
import puppeteer from "puppeteer-core";
import { readFileSync, writeFileSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const cfg = JSON.parse(readFileSync(new URL("./test-users.json", import.meta.url)));
const APP = process.env.SECURE_CHAT_E2E_URL || cfg.relay;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const NAME_RE = /^secure-chat-pad-\d{4}-\d{2}-\d{2}-\d{4}\.json$/;
const PHONE = { width: 390, height: 844, deviceScaleFactor: 1 };
const DESKTOP = { width: 1280, height: 800, deviceScaleFactor: 1 };
// Test-only values (throwaway, like test-users.json).
const PAD_A = "alice pad passphrase — e2e only";
const PAD_B = "bob pad passphrase — e2e only";
const XFER = "harbour mint cobalt fern e2e";

const results = [];
function check(name, ok, detail = "") {
  results.push({ name, ok: !!ok });
  console.log(`    ${ok ? "OK  " : "FAIL"} ${name}${detail ? " — " + detail : ""}`);
}

const browser = await puppeteer.launch({
  executablePath: process.env.CHROMIUM || "/usr/bin/chromium",
  headless: "new",
  args: ["--no-sandbox", "--disable-dev-shm-usage"],
  protocolTimeout: 300000,
});
const errors = [];

async function agent(label, { android = false } = {}) {
  const ctx = await browser.createBrowserContext();
  const page = await ctx.newPage();
  page.on("pageerror", (e) => errors.push(`${label}: ${e.message}`));
  page.on("console", (m) => {
    if (m.type() === "error" && !/favicon|404/.test(m.text())) errors.push(`${label}: ${m.text()}`);
  });
  // Dialogs are answered per check (page.answers); an unexpected one fails.
  page.answers = [];
  page.dialogs = [];
  page.on("dialog", async (d) => {
    page.dialogs.push(d.message());
    const a = page.answers.shift();
    if (a === undefined) { errors.push(`${label}: unexpected dialog "${d.message().slice(0, 80)}"`); await d.dismiss(); }
    else if (a) await d.accept(); else await d.dismiss();
  });
  await page.evaluateOnNewDocument((android) => {
    // A KDF that can be HELD (the "working" state, § 11): deriveKey waits
    // while window.__kdfGate is a pending promise.
    const orig = SubtleCrypto.prototype.deriveKey;
    SubtleCrypto.prototype.deriveKey = async function (...a) {
      if (window.__kdfGate) await window.__kdfGate;
      return orig.apply(this, a);
    };
    // The browser download: caught, not written.
    window.__files = [];
    const origURL = URL.createObjectURL.bind(URL);
    URL.createObjectURL = (b) => { const u = origURL(b); window.__blobs = window.__blobs || {}; window.__blobs[u] = b; return u; };
    const click = HTMLAnchorElement.prototype.click;
    HTMLAnchorElement.prototype.click = function () {
      if (this.download && window.__blobs && window.__blobs[this.href]) {
        const name = this.download;
        window.__blobs[this.href].text().then((t) => window.__files.push({ name, text: t }));
        return;
      }
      return click.call(this);
    };
    if (!android) return;
    // The Android shell's bridge, as the shell publishes it (frozen, on a
    // non-writable, non-configurable property). What it was asked is kept
    // on a separate test-only global.
    window.__bridgeLog = [];
    window.__bridgeAnswer = null;
    let n = 0;
    const answer = (kind, name, text) => {
      const ret = window.__bridgeAnswer || (++n).toString(16).padStart(16, "0");
      window.__bridgeLog.push({ kind, name, text, ret });
      return ret;
    };
    const b = Object.freeze({ share: (name, text) => answer("share", name, text), save: (name, text) => answer("save", name, text) });
    Object.defineProperty(window, "__SECURE_CHAT_FILES__", { value: b, writable: false, configurable: false });
  }, android);
  await page.setViewport(PHONE);
  await page.goto(APP, { waitUntil: "networkidle0", timeout: 60000 });
  await page.click("#toRoom"); // "Continue without an identity →": a pad needs none
  await page.waitForFunction(() => !document.querySelector("#scrRoom").hidden, { timeout: 30000 });
  await page.evaluate(() => {
    window.__shown = (el) => !!el && el.getClientRects().length > 0 && getComputedStyle(el).visibility !== "hidden";
    document.querySelector("#algDetails").open = true;
    const r = document.querySelector('input[name="alg"][value="OTP"]');
    r.checked = true;
    r.dispatchEvent(new Event("change", { bubbles: true }));
  });
  await page.waitForFunction(() => !document.querySelector("#otpPanel").hidden, { timeout: 20000 });
  return { label, ctx, page };
}

const text = (page, sel) => page.evaluate((s) => { const e = document.querySelector(s); return e ? e.textContent.trim() : ""; }, sel);
const shown = (page, sel) => page.evaluate((s) => window.__shown(document.querySelector(s)), sel);
const state = (page, sheet) => page.evaluate((s) => document.querySelector(s).dataset.state, sheet);
const waitState = (page, sheet, st, timeout = 60000) =>
  page.waitForFunction((s, v) => document.querySelector(s).dataset.state === v, { timeout }, sheet, st);
const active = (page) => page.evaluate(() => document.activeElement && (document.activeElement.id || document.activeElement.tagName));
const setValue = (page, sel, value) => page.evaluate((s, v) => {
  const el = document.querySelector(s);
  el.value = v;
  el.dispatchEvent(new Event("input", { bubbles: true }));
}, sel, value);
// A real tap: scrolled into view, then the pointer. After a sheet opens the
// app ignores bottom-row taps for 500 ms (the double-tap guard), as a person
// would not notice.
async function tap(page, sel) {
  await page.$eval(sel, (e) => e.scrollIntoView({ block: "center" }));
  await page.click(sel);
}
const guard = () => sleep(600);

// The geometry of an open sheet at the current viewport.
async function geometry(page, sheetSel) {
  await sleep(300); // colour transitions settle (140 ms)
  return page.evaluate((s) => {
    const sh = document.querySelector(s);
    const bar = sh.querySelector(".otp-bar");
    const tab = document.querySelector("#tabbar").getBoundingClientRect();
    const r = sh.getBoundingClientRect(), b = bar.getBoundingClientRect();
    const m = document.querySelector("main").getBoundingClientRect(); // the page column (the scrollbar gutter is outside it)
    const vis = (e) => window.__shown(e);
    const barButtons = [...bar.querySelectorAll("button")].filter(vis);
    const primaries = [...sh.querySelectorAll("button")].filter(vis)
      .filter((e) => getComputedStyle(e).backgroundColor === "rgb(31, 111, 235)");
    // 44px on a phone, 40px wider up (--control-h).
    const min = (innerWidth <= 600 ? 44 : 40) - 0.5;
    const small = [...barButtons, sh.querySelector(".otp-close")].filter(vis)
      .filter((e) => e.getBoundingClientRect().height < min || e.getBoundingClientRect().width < min).map((e) => e.id);
    const hit = barButtons.every((e) => {
      const q = e.getBoundingClientRect();
      const at = document.elementFromPoint(q.left + q.width / 2, q.top + q.height / 2);
      return at === e || e.contains(at);
    });
    const phone = innerWidth <= 600;
    // Desktop (design r3 minor 2): the primary/danger is on the first line of
    // the row, left of any secondary there; ghosts sit on a line below it.
    const pr = barButtons.find((e) => e.classList.contains("primary") || e.classList.contains("danger"));
    const desktopOrder = !pr || barButtons.every((e) => {
      if (e === pr) return true;
      const q = e.getBoundingClientRect(), p = pr.getBoundingClientRect();
      return e.classList.contains("ghost") ? q.top >= p.bottom - 1 : Math.abs(q.top - p.top) < 2 && q.left !== p.left;
    });
    return {
      pageOverflow: document.documentElement.scrollWidth > innerWidth,
      sheetOverflow: sh.scrollWidth > sh.clientWidth + 1,
      primaries: primaries.map((e) => e.id),
      barInside: b.top >= r.top - 1 && b.bottom <= r.bottom + 1 && b.bottom <= innerHeight + 1,
      docked: phone ? Math.abs(r.bottom - tab.top) <= 1
        : Math.abs((r.left + r.right) / 2 - (m.left + m.right) / 2) <= 1 && Math.round(r.width) === 480,
      box: [r.left, r.width, m.left, m.right].map(Math.round).join("/"),
      small, hit, order: barButtons.map((e) => e.id), desktopOrder,
    };
  }, sheetSel);
}
async function checkGeometry(page, sheetSel, what, { primaries = 1 } = {}) {
  const g = await geometry(page, sheetSel);
  check(`${what}: no horizontal overflow (page, sheet)`, !g.pageOverflow && !g.sheetOverflow);
  check(`${what}: ${primaries === 0 ? "no" : "exactly one"} visible primary`, g.primaries.length === primaries, g.primaries.join(",") || "none");
  check(`${what}: the bottom row is inside the sheet and on screen`, g.barInside);
  check(`${what}: every bottom-row button is hit-testable`, g.hit, g.order.join(","));
  check(`${what}: 44px targets (40 wider up; bottom row, ×)`, g.small.length === 0, g.small.join(","));
  check(`${what}: ${(await page.evaluate(() => innerWidth)) <= 600 ? "docked above the tab bar" : "a centred 480px dialog"}`, g.docked, g.box);
  return g;
}
async function panelChecks(page, what) {
  await sleep(300);
  const g = await page.evaluate(() => {
    const p = document.querySelector("#otpPanel");
    const primaries = [...p.querySelectorAll("button"), document.querySelector("#connect")].filter((e) => window.__shown(e))
      .filter((e) => getComputedStyle(e).backgroundColor === "rgb(31, 111, 235)").map((e) => e.id);
    const small = [...p.querySelectorAll("button")].filter((e) => window.__shown(e))
      .filter((e) => e.getBoundingClientRect().height < 43.5).map((e) => e.id || e.textContent.trim());
    const wraps = [...document.querySelectorAll(".otp-actions > button")].filter((e) => window.__shown(e))
      .filter((e) => {
        const r = document.createRange();
        r.selectNodeContents(e);
        const lines = new Set([...r.getClientRects()].filter((q) => q.width > 0).map((q) => Math.round(q.top))).size;
        const box = e.getBoundingClientRect(), text = r.getBoundingClientRect();
        return lines > 1 || e.scrollWidth > e.clientWidth + 1 || text.left < box.left - 0.5 || text.right > box.right + 0.5;
      }).map((e) => e.id);
    const sel = document.querySelector("#otpSelect"), fg = document.querySelector("#otpForget");
    const oneLine = !window.__shown(fg) || Math.abs(sel.getBoundingClientRect().top - fg.getBoundingClientRect().top) < 2;
    return { overflow: document.documentElement.scrollWidth > innerWidth, primaries, small, wraps, oneLine };
  });
  check(`${what}: the pad and Forget share one line (design r3 minor 3)`, g.oneLine);
  check(`${what}: no horizontal overflow`, !g.overflow);
  check(`${what}: 44px targets`, g.small.length === 0, g.small.join(","));
  check(`${what}: entry labels fit on one line`, g.wraps.length === 0, g.wraps.join(","));
  return g;
}

console.log(`\n=== one-time pad transfer sheets ===\n    target: ${APP}\n`);
const alice = await agent("alice");
const bob = await agent("bob");
const droid = await agent("android", { android: true });
const A = alice.page, B = bob.page, D = droid.page;

// ---- 1. the empty panel ----------------------------------------------------
console.log("\n  [1] empty panel (alice, 390×844)");
{
  check("empty: the card is shown, the pad rows are not",
    (await shown(A, "#otpEmpty")) && !(await shown(A, "#otpPadRow")) && !(await shown(A, "#otpPassRow")));
  const g = await panelChecks(A, "empty panel");
  check("empty: nothing is the blue primary (New pad = Import; Connect aria-disabled)", g.primaries.length === 0, g.primaries.join(","));
  check("empty: Connect is aria-disabled", (await A.$eval("#connect", (e) => e.getAttribute("aria-disabled"))) === "true");
  const look = await A.$eval("#connect", (e) => { const c = getComputedStyle(e); return [c.borderTopColor, c.cursor].join(" "); });
  check("empty: …and looks it — a hairline outline, not-allowed (weaker than Import)", look === "rgba(240, 246, 252, 0.08) not-allowed", look);
  await tap(A, "#connect");
  await sleep(300);
  const said = await A.evaluate(() => ["#roomHint", "#idHint", "#hint"].map((s) => document.querySelector(s).textContent).find((t) => t) || "");
  check("empty: a tap on Connect says what to do", said === "Choose a one-time pad first — New pad or Import, under Security options.", said);
}

// ---- 2. sheet mechanics, by keyboard and pointer (Import on alice) --------
console.log("\n  [2] sheet mechanics (keyboard, pointer, Back)");
{
  await A.focus("#otpImportOpen");
  await A.keyboard.press("Enter");
  await A.waitForFunction(() => window.__shown(document.querySelector("#otpImportSheet")), { timeout: 5000 });
  check("keyboard: Enter on Import opens its sheet", true);
  const fine = await A.evaluate(() => matchMedia("(pointer: fine)").matches);
  check(`open: focus goes to ${fine ? "the first field (pointer: fine)" : "the sheet (no fine pointer)"}`,
    (await active(A)) === (fine ? "otpImportXfer" : "otpImportSheet"), await active(A));
  const inert = await A.evaluate(() => [document.querySelector("#tabbar").inert, document.querySelector(".apphead").inert, document.querySelector("#viewLive").inert]);
  check("open: the tab bar, the app bar and the Live room are inert", inert.every(Boolean), JSON.stringify(inert));
  await checkGeometry(A, "#otpImportSheet", "Import form");
  // Tab wraps inside the sheet.
  const stops = await A.evaluate(() => [...document.querySelector("#otpImportSheet").querySelectorAll("button, summary, input, select, [tabindex]")]
    .filter((el) => !el.disabled && el.tabIndex >= 0 && el.offsetParent !== null).map((e) => e.id || e.tagName));
  await A.evaluate(() => { const s = [...document.querySelector("#otpImportSheet").querySelectorAll("button, summary, input, select, [tabindex]")].filter((el) => !el.disabled && el.tabIndex >= 0 && el.offsetParent !== null); s.at(-1).focus(); });
  await A.keyboard.press("Tab");
  const wrapped = await A.evaluate(() => { const s = [...document.querySelector("#otpImportSheet").querySelectorAll("button, summary, input, select, [tabindex]")].filter((el) => !el.disabled && el.tabIndex >= 0 && el.offsetParent !== null); return document.activeElement === s[0]; });
  check("Tab from the last control wraps to the first", wrapped, stops.join(" → "));
  await A.keyboard.down("Shift"); await A.keyboard.press("Tab"); await A.keyboard.up("Shift");
  const back = await A.evaluate(() => { const s = [...document.querySelector("#otpImportSheet").querySelectorAll("button, summary, input, select, [tabindex]")].filter((el) => !el.disabled && el.tabIndex >= 0 && el.offsetParent !== null); return document.activeElement === s.at(-1); });
  check("Shift+Tab from the first control wraps to the last", back);
  await setValue(A, "#otpImportXfer", "typed and then closed");
  await A.keyboard.press("Escape");
  await sleep(200);
  check("Escape closes the sheet", !(await shown(A, "#otpImportSheet")) && !(await shown(A, "#otpScrim")));
  check("…focus returns to Import", (await active(A)) === "otpImportOpen", await active(A));
  check("…and closing cleared what was typed", (await A.$eval("#otpImportXfer", (e) => e.value)) === "");
  check("…the rest of the page is live again", !(await A.evaluate(() => document.querySelector("#viewLive").inert || document.querySelector("#tabbar").inert)));
  // × and the scrim, by pointer.
  await tap(A, "#otpImportOpen");
  await A.waitForFunction(() => window.__shown(document.querySelector("#otpImportSheet")));
  await guard(); // the sheet takes no taps while it slides in
  await A.click("#otpImportClose");
  await sleep(200);
  check("× closes, focus back on Import", !(await shown(A, "#otpImportSheet")) && (await active(A)) === "otpImportOpen", await active(A));
  await tap(A, "#otpImportOpen");
  await A.waitForFunction(() => window.__shown(document.querySelector("#otpImportSheet")));
  await guard();
  await A.mouse.click(195, 20); // the scrim above the sheet
  await sleep(200);
  check("a tap on the scrim closes, focus back on Import", !(await shown(A, "#otpImportSheet")) && (await active(A)) === "otpImportOpen");
  // Back (N-M2).
  await tap(A, "#otpImportOpen");
  await A.waitForFunction(() => window.__shown(document.querySelector("#otpImportSheet")));
  const url0 = A.url();
  await A.goBack();
  await sleep(300);
  check("Back closes an idle sheet", !(await shown(A, "#otpImportSheet")) && A.url() === url0);
  check("…and does not leave the page", await shown(A, "#otpPanel"));
}

// ---- 3. New pad, working, carried passphrase, must-differ, Export ----------
console.log("\n  [3] New pad → Export (alice, browser)");
let padFile, fileName;
{
  await tap(A, "#otpNewOpen");
  await A.waitForFunction(() => window.__shown(document.querySelector("#otpNewSheet")));
  await checkGeometry(A, "#otpNewSheet", "New pad form");
  // A short screen (or an open keyboard): the sheet scrolls, the bottom row stays.
  await A.setViewport({ width: 390, height: 600, deviceScaleFactor: 1 });
  const scrolls = await A.$eval("#otpNewSheet", (e) => e.scrollHeight > e.clientHeight + 1);
  check("390×600: the New pad sheet scrolls", scrolls);
  await checkGeometry(A, "#otpNewSheet", "New pad form at 390×600");
  await A.setViewport(PHONE);
  await A.type("#otpLabel", "Chess club");
  await A.select("#otpSize", await A.$eval("#otpSize", (s) => s.options[0].value));
  check("the size hint follows the size", (await text(A, "#otpSizeHint")) === "~350 short messages each way", await text(A, "#otpSizeHint"));
  const picker = await A.evaluate(() => [document.querySelector('label[for="otpSize"]').textContent, document.querySelector("#otpSize").selectedOptions[0].textContent]);
  check("cold mi-2: the picker says what each side gets (\"Size, each way\": 32 KiB for the 64 KiB pad)", picker.join("|") === "Size, each way|32 KiB", picker.join("|"));
  await A.type("#otpNewPass", "moonlight7");
  check("a weak pad passphrase is warned about live", /^Weak: it is shorter than 12 characters\. Use 12 or more characters, e\.g\. four random words\.$/.test(await text(A, "#otpNewPassWarn")), await text(A, "#otpNewPassWarn"));
  await setValue(A, "#otpNewPass", PAD_A);
  check("…and the line goes for a strong one", !(await shown(A, "#otpNewPassWarn")));
  // Working: the KDF is held.
  await A.evaluate(() => { window.__kdfGate = new Promise((r) => { window.__kdfRelease = () => { window.__kdfGate = null; r(); }; }); });
  await guard();
  await tap(A, "#otpGenerate");
  await waitState(A, "#otpNewSheet", "working", 10000);
  check("working: no ×", !(await shown(A, "#otpNewClose")));
  check("working: no empty bottom bar, the form is inert (design r3 minor 4)",
    await A.evaluate(() => !window.__shown(document.querySelector("#otpNewSheet .otp-bar")) && document.querySelector("#otpNewForm").inert));
  check("working: the progress has focus", (await active(A)) === "otpNewProgress", await active(A));
  await A.keyboard.press("Escape");
  await A.mouse.click(195, 20);
  await A.goBack();
  await sleep(300);
  check("working: Escape, the scrim and Back do not close it", (await shown(A, "#otpNewSheet")) && (await state(A, "#otpNewSheet")) === "working");
  await A.evaluate(() => window.__kdfRelease());
  await waitState(A, "#otpNewSheet", "done");
  check("done: 'Pad created', focus on 'Export to your contact'", (await active(A)) === "otpNewToExport", await active(A));
  await checkGeometry(A, "#otpNewSheet", "New pad done");
  check("the pad passphrase was carried into #otpPass", (await A.$eval("#otpPass", (e) => e.value)) === PAD_A);
  await guard();
  await tap(A, "#otpNewToExport");
  await A.waitForFunction(() => window.__shown(document.querySelector("#otpExportSheet")));
  check("New pad hands over to Export (the scrim stays)", !(await shown(A, "#otpNewSheet")) && (await shown(A, "#otpScrim")));
  await checkGeometry(A, "#otpExportSheet", "Export form");
  await setValue(A, "#otpXferPass", PAD_A);
  await guard();
  await tap(A, "#otpExport");
  await sleep(300);
  check("must-differ: the carried pad passphrase is refused as the transfer passphrase",
    (await text(A, "#otpExportStatus")) === "Use a different passphrase for the file — this one is your pad passphrase.", await text(A, "#otpExportStatus"));
  check("…the field is marked (aria-invalid) and focused", (await A.$eval("#otpXferPass", (e) => e.getAttribute("aria-invalid"))) === "true" && (await active(A)) === "otpXferPass");
  check("…nothing was handed out", (await A.evaluate(() => window.__files.length)) === 0);
  await setValue(A, "#otpXferPass", XFER);
  await tap(A, "#otpExport");
  await waitState(A, "#otpExportSheet", "done");
  await A.waitForFunction(() => window.__files.length === 1, { timeout: 10000 });
  ({ name: fileName, text: padFile } = await A.evaluate(() => window.__files[0]));
  check("the browser downloads the file under the neutral name", NAME_RE.test(fileName), fileName);
  check("…the pad-file envelope", JSON.parse(padFile).fmt === "secure-chat-otp-pad");
  check("done: 'File downloaded', the name on its own line", (await text(A, "#otpExportDoneTitle")) === "File downloaded" && (await text(A, "#otpExportDoneFile")) === fileName);
  check("…in mono (they search Downloads for it)", /mono/i.test(await A.$eval("#otpExportDoneFile", (e) => getComputedStyle(e).fontFamily)));
  check("done: the 'On their device' list says never to send the passphrase", /never send it/.test(await text(A, "#otpExportTheirs")));
  check("done: …and says to delete the file on both devices once imported (cold MA-3)",
    await A.evaluate(() => [...document.querySelectorAll("#otpExportDoneBlock .otp-delete")].some((e) => window.__shown(e) && /delete the file on both devices/.test(e.textContent))));
  check("done: the card says each way", (await text(A, "#otpExportPadMeta")) === "32 KiB each way · you generated · exported", await text(A, "#otpExportPadMeta"));
  await checkGeometry(A, "#otpExportSheet", "Export done (phone)");
  await guard();
  await tap(A, "#otpSendAgain");
  await A.waitForFunction(() => window.__files.length === 2);
  check("'Download the same file again' hands out the same file", (await text(A, "#otpSendAgain")) === "Download the same file again" &&
    (await A.evaluate(() => window.__files[1].text)) === padFile);
  await A.setViewport(DESKTOP);
  const gd = await checkGeometry(A, "#otpExportSheet", "Export done (desktop)");
  check("desktop: the primary leads its row, the quiet link on its own line below (design r3 minor 2)", gd.desktopOrder, gd.order.join(","));
  await A.setViewport(PHONE);
  await tap(A, "#otpExportDone");
  await sleep(200);
  check("Done closes; focus back on New pad (the opener)", !(await shown(A, "#otpExportSheet")) && (await active(A)) === "otpNewOpen", await active(A));
  check("the panel shows the unlocked row", (await shown(A, "#otpUnlocked")) && !(await shown(A, "#otpPass")));
  await panelChecks(A, "panel with a pad");
  await A.setViewport({ width: 360, height: 740, deviceScaleFactor: 1 }); // a common Android width (round 2, minor 9)
  await panelChecks(A, "panel with a pad at 360");
  await A.setViewport({ width: 320, height: 640, deviceScaleFactor: 1 }); // the narrowest the app supports
  await panelChecks(A, "panel with a pad at 320");
  await A.setViewport(PHONE);
}

// ---- 4. the re-export warning --------------------------------------------
console.log("\n  [4] re-export (alice)");
{
  await tap(A, "#otpExportOpen");
  await A.waitForFunction(() => window.__shown(document.querySelector("#otpExportSheet")));
  check("the pad card says '· exported before' at open", await shown(A, "#otpExportPadWarn"));
  await setValue(A, "#otpXferPass", "another transfer passphrase e2e");
  await guard();
  await tap(A, "#otpExport");
  await waitState(A, "#otpExportSheet", "confirm");
  check("confirm: the pinned sentence", /^This pad was already exported\. A pad must be imported on only ONE device/.test(await text(A, "#otpExportStatus")));
  const g = await checkGeometry(A, "#otpExportSheet", "re-export confirm", { primaries: 0 });
  check("confirm: 'Don't export' comes before 'Export again'", g.order.join(",") === "otpExportCancel,otpExport", g.order.join(","));
  check("confirm: no file yet", (await A.evaluate(() => window.__files.length)) === 2);
  await A.setViewport(DESKTOP);
  const gc = await checkGeometry(A, "#otpExportSheet", "re-export confirm (desktop)", { primaries: 0 });
  check("desktop confirm: 'Don't export' then the growing 'Export again', one line", gc.desktopOrder && gc.order.join(",") === "otpExportCancel,otpExport", gc.order.join(","));
  await A.setViewport(PHONE);
  check("design R3-M1: while the sheet is up, the panel does not show its error too",
    await A.$eval("#otpStatus", (e) => e.classList.contains("vh") || !e.textContent));
  await tap(A, "#otpExportCancel");
  await sleep(200);
  check("'Don't export' closes the sheet", !(await shown(A, "#otpExportSheet")));
  check("design R3-M1: …and the panel is left without the sheet's error", (await text(A, "#otpStatus")) === "");
  await tap(A, "#otpExportOpen");
  await A.waitForFunction(() => window.__shown(document.querySelector("#otpExportSheet")));
  await setValue(A, "#otpXferPass", "another transfer passphrase e2e");
  await guard();
  await tap(A, "#otpExport");
  await waitState(A, "#otpExportSheet", "confirm");
  check("closing disarmed the latch: the warning comes again", /already exported/.test(await text(A, "#otpExportStatus")));
  await A.keyboard.press("Escape");
  await sleep(200);
}

// ---- 4b. fix round 1: a busy pad; Back during the Export entry's unlock ----
console.log("\n  [4b] busy pad, Back during the unlock (alice)");
{
  // Another tab of the same browser holds the pad (a chat open on it).
  const id = await A.$eval("#otpSelect", (e) => e.value);
  const other = await alice.ctx.newPage();
  await other.goto(APP, { waitUntil: "networkidle0" });
  await other.evaluate((n) => { window.__held = new Promise((r) => { window.__release = r; }); navigator.locks.request(n, () => window.__held); }, "sc.otp.lock.v1." + id);
  await A.bringToFront();
  await tap(A, "#otpExportOpen");
  await A.waitForFunction(() => window.__shown(document.querySelector("#otpExportSheet")));
  await setValue(A, "#otpXferPass", "a transfer passphrase while busy");
  await guard();
  await tap(A, "#otpExport");
  await waitState(A, "#otpExportSheet", "form", 20000);
  check("hot B1 / R2-1: a busy pad returns the sheet to its form, with the reason and a ×",
    /^This pad is in use/.test(await text(A, "#otpExportStatus")) && (await shown(A, "#otpExportClose")));
  await A.keyboard.press("Escape");
  await sleep(200);
  check("…and it closes: the page is usable", !(await shown(A, "#otpExportSheet")) && !(await A.evaluate(() => document.querySelector("#viewLive").inert)));
  await other.evaluate(() => window.__release());
  await other.close();
  // Back while the Export entry unlocks the pad (hot M1): the app is not left.
  await tap(A, "#otpLock");
  await A.type("#otpPass", PAD_A);
  const url0 = A.url(), len0 = await A.evaluate(() => history.length);
  await tap(A, "#otpExportOpen");
  await A.goBack();
  await sleep(2500); // the unlock's KDF ends
  check("R2-2: Back during the unlock opens no sheet afterwards", !(await shown(A, "#otpExportSheet")) && A.url() === url0);
  await tap(A, "#otpImportOpen");
  await A.waitForFunction(() => window.__shown(document.querySelector("#otpImportSheet")));
  await guard();
  await A.click("#otpImportClose");
  await sleep(500);
  check("R2-2: …and a later × does not navigate out of the app", A.url() === url0 && (await shown(A, "#otpPanel")), A.url());
  void len0;
}

// ---- 5. Import on bob ----------------------------------------------------
console.log("\n  [5] Import (bob)");
{
  const dir = mkdtempSync(join(tmpdir(), "sc-otp-"));
  const path = join(dir, fileName);
  writeFileSync(path, padFile);
  await tap(B, "#otpImportOpen");
  await B.waitForFunction(() => window.__shown(document.querySelector("#otpImportSheet")));
  await setValue(B, "#otpImportXfer", "the same words twice");
  await setValue(B, "#otpImportPass", "the same words twice");
  await guard();
  await tap(B, "#otpImport");
  await sleep(200);
  check("must-differ (Import): refused", (await text(B, "#otpImportStatus")) === "Use a different passphrase on this device — the transfer passphrase is known to your contact.");
  check("…the pad passphrase field is marked", (await B.$eval("#otpImportPass", (e) => e.getAttribute("aria-invalid"))) === "true");
  await setValue(B, "#otpImportXfer", XFER + " but wrong");
  await setValue(B, "#otpImportPass", PAD_B);
  await (await B.$("#otpFile")).uploadFile(path);
  await waitState(B, "#otpImportSheet", "form");
  await B.waitForFunction(() => document.querySelector("#otpImportStatus").textContent !== "", { timeout: 60000 });
  check("a wrong transfer passphrase: the pinned sentence", (await text(B, "#otpImportStatus")) === "Import failed: wrong passphrase or corrupted pad file", await text(B, "#otpImportStatus"));
  const mark = await B.evaluate(() => {
    const i = document.querySelector("#otpImportXfer");
    return { invalid: i.getAttribute("aria-invalid"), line: window.__shown(document.querySelector("#otpImportXferErr")),
      border: getComputedStyle(i).borderTopWidth, desc: i.getAttribute("aria-describedby"),
      icon: getComputedStyle(i.parentElement, "::before").maskImage || getComputedStyle(i.parentElement, "::before").webkitMaskImage };
  });
  check("…the field is marked: aria-invalid, 2px border, its line, described by it",
    mark.invalid === "true" && mark.line && mark.border === "2px" && mark.desc === "otpImportXferErr otpImportStatus", JSON.stringify({ ...mark, icon: undefined }));
  check("…its icon is the alert triangle", /M8 2\.2/.test(mark.icon || ""));
  check("…focus is on it", (await active(B)) === "otpImportXfer");
  check("…the file is named as chosen", (await text(B, "#otpImportStep3Caption")) === fileName + " — chosen");
  const g = await checkGeometry(B, "#otpImportSheet", "Import error");
  check("…'Try again' is the primary, 'Choose another file' follows", g.order.join(",") === "otpImportRetry,otpImport" && g.primaries.join() === "otpImportRetry", g.order.join(","));
  await setValue(B, "#otpImportXfer", XFER);
  check("the marks clear on input", !(await shown(B, "#otpImportXferErr")));
  await tap(B, "#otpImportRetry");
  await waitState(B, "#otpImportSheet", "done");
  check("Try again imports without a second pick", (await text(B, "#otpImportPadLabel")) === "Chess club");
  check("import done: the card says it came from the contact (cold mi-7)", (await text(B, "#otpImportPadMeta")) === "32 KiB each way · from your contact", await text(B, "#otpImportPadMeta"));
  check("import done: 'Delete the pad file now.' (cold MA-3)",
    await B.evaluate(() => [...document.querySelectorAll("#otpImportDoneBlock .otp-delete")].some((e) => window.__shown(e) && e.textContent === "Delete the pad file now.")));
  await checkGeometry(B, "#otpImportSheet", "Import done");
  await tap(B, "#otpImportDone");
  await sleep(200);
  check("received pad: Export is not offered, the note is", !(await shown(B, "#otpExportOpen")) && (await text(B, "#otpExportNote")) === "Received pad — only its maker can export it.");
  check("…unlocked for this session", await shown(B, "#otpUnlocked"));
  await B.evaluate(() => document.querySelector("#otpExportOpen").click()); // a stale index could show it
  await sleep(200);
  check("a forced Export is refused", (await text(B, "#otpStatus")) === "You received this pad — only the person who made it can export it.");
  await panelChecks(B, "received-pad panel");
  await tap(B, "#otpLock");
  await sleep(200);
  check("Lock: the field is back, empty and focused; the unlocked row is gone",
    (await shown(B, "#otpPass")) && !(await shown(B, "#otpUnlocked")) && (await B.$eval("#otpPass", (e) => e.value)) === "" && (await active(B)) === "otpPass");
  await B.type("#otpPass", PAD_B); // Connect below unlocks it again from the field
}

// ---- 6. Connect on the pad, both ways -------------------------------------
console.log("\n  [6] Connect (alice ↔ bob)");
{
  await A.setViewport(DESKTOP);
  await B.setViewport(DESKTOP);
  await A.click("#gen");
  const code = await A.$eval("#room", (e) => e.value.trim());
  await A.click("#connect");
  await A.waitForFunction(() => document.querySelector("#chatStatus").textContent.trim().toLowerCase() === "connected", { timeout: 45000 })
    .catch(async (e) => { console.log("    connect:", await A.evaluate(() => [...document.querySelectorAll("#status, #chatStatus, #roomHint, #idHint, #hint, #otpStatus")].map((x) => x.id + "=" + x.textContent.trim()).join(" | ") + " scrim=" + window.__shown(document.querySelector("#otpScrim")) + " sheets=" + [...document.querySelectorAll(".otp-sheet")].map((x) => x.id + ":" + x.hidden + ":" + x.dataset.state).join(","))); throw e; });
  await setValue(B, "#room", code);
  await B.click("#connect");
  await A.waitForFunction(() => !document.querySelector("#admit").hidden, { timeout: 45000 });
  await sleep(600);
  await A.click("#admitOk");
  await Promise.all([A, B].map((p) => p.waitForFunction(() => !document.querySelector("#text").disabled, { timeout: 60000 })));
  const msg = `otp sheets ${Date.now()}`;
  await A.type("#text", msg);
  await A.click("#send");
  await B.waitForFunction((m) => document.querySelector("#log").textContent.includes(m), { timeout: 20000 }, msg);
  const back = `back ${Date.now()}`;
  await B.type("#text", back);
  await B.click("#send");
  await A.waitForFunction((m) => document.querySelector("#log").textContent.includes(m), { timeout: 20000 }, back);
  check("the transferred pad carries a chat both ways", true);
  for (const p of [A, B]) await p.click("#disconnect");
  // Lock: back on the room screen.
  await B.waitForFunction(() => !document.querySelector("#scrRoom").hidden || !document.querySelector("#scrChat").hidden);
}

// ---- 7. Android: Share / Save over the (fake) bridge -----------------------
console.log("\n  [7] Android export (fake frozen bridge)");
{
  const lastId = () => D.evaluate(() => window.__bridgeLog.at(-1).ret);
  const result = (id, o) => D.evaluate((i, x) => window.__SECURE_CHAT_FILES_RESULT__(i, x), id, o);
  await tap(D, "#otpNewOpen");
  await D.waitForFunction(() => window.__shown(document.querySelector("#otpNewSheet")));
  await D.type("#otpLabel", "Quick share");
  await setValue(D, "#otpNewPass", PAD_A);
  await guard();
  await tap(D, "#otpGenerate");
  await waitState(D, "#otpNewSheet", "done");
  await guard();
  await tap(D, "#otpNewToExport");
  await D.waitForFunction(() => window.__shown(document.querySelector("#otpExportSheet")));
  await setValue(D, "#otpXferPass", XFER);
  await guard();
  await tap(D, "#otpExport");
  await waitState(D, "#otpExportSheet", "ready");
  check("Android: nothing is downloaded", (await D.evaluate(() => window.__files.length)) === 0);
  check("ready: step 3 says Quick Share / Bluetooth / USB stick",
    (await text(D, "#otpExportStep3Caption")) === "Quick Share or Bluetooth, face to face. Or save it and copy it to a USB stick.");
  const g = await checkGeometry(D, "#otpExportSheet", "Android ready");
  check("ready: Share… (primary), then Save to device", g.order.join(",") === "otpShare,otpSave" && g.primaries.join() === "otpShare", g.order.join(","));
  // Back before anything was shared: asks; Cancel keeps it.
  D.answers.push(false);
  await D.goBack();
  await sleep(400);
  check("Back in file-ready asks first (Cancel keeps the sheet)", D.dialogs.at(-1)?.startsWith("The file has not been shared or saved yet.") && (await shown(D, "#otpExportSheet")));
  D.answers.push(false);
  await D.click("#otpExportClose");
  await sleep(200);
  check("× in file-ready asks the same", D.dialogs.length === 2 && (await shown(D, "#otpExportSheet")));
  // Share: cancelled / error / busy / invalid / shared.
  await tap(D, "#otpShare");
  const sent = await D.evaluate(() => window.__bridgeLog.at(-1));
  check("Share hands the bridge the neutral name and exportPad's text, unmodified",
    sent.kind === "share" && NAME_RE.test(sent.name) && /^\{"fmt":"secure-chat-otp-pad","v":1,"kdf":\{"salt":"[^"]+","iters":600000\},"iv":"[^"]+","ct":"[^"]+"\}$/.test(sent.text));
  check("…Share and Save are disabled while it is open", await D.evaluate(() => document.querySelector("#otpShare").disabled && document.querySelector("#otpSave").disabled));
  await result(await lastId(), "cancelled");
  check("cancelled: 'Not shared.', Share / Save available again", (await text(D, "#otpExportStatus")) === "Not shared." && !(await D.$eval("#otpShare", (e) => e.disabled)));
  await tap(D, "#otpSave");
  await result(await lastId(), "error");
  check("error: 'Could not save the file.'", (await text(D, "#otpExportStatus")) === "Could not save the file.");
  await D.evaluate(() => { window.__bridgeAnswer = "busy"; });
  await tap(D, "#otpShare");
  check("busy: said", /^Could not share the file\. Another share or save is still open/.test(await text(D, "#otpExportStatus")));
  await D.evaluate(() => { window.__bridgeAnswer = "invalid"; });
  await tap(D, "#otpSave");
  check("invalid: 'Could not save the file.'", (await text(D, "#otpExportStatus")) === "Could not save the file.");
  await D.evaluate(() => { window.__bridgeAnswer = null; });
  await checkGeometry(D, "#otpExportSheet", "Android ready with an error");
  await tap(D, "#otpSave");
  await result(await lastId(), "saved");
  await waitState(D, "#otpExportSheet", "done");
  check("saved: 'File saved' + the name (UI font) + in person", (await text(D, "#otpExportDoneTitle")) === "File saved" &&
    NAME_RE.test(await text(D, "#otpExportDoneFile")) && !/mono/i.test(await D.$eval("#otpExportDoneFile", (e) => getComputedStyle(e).fontFamily)) &&
    /^Now give it to them in person/.test(await text(D, "#otpHanded")));
  await checkGeometry(D, "#otpExportSheet", "Android saved");
  await tap(D, "#otpSendAgain");
  await waitState(D, "#otpExportSheet", "ready");
  await tap(D, "#otpShare");
  await result(await lastId(), "shared");
  await waitState(D, "#otpExportSheet", "done");
  check("shared: 'File shared' / keep this open", (await text(D, "#otpExportDoneTitle")) === "File shared" && (await text(D, "#otpHanded")) === "Keep this open until it has arrived.");
  const n = D.dialogs.length;
  await D.goBack();
  await sleep(300);
  check("once shared, Back closes without asking", !(await shown(D, "#otpExportSheet")) && D.dialogs.length === n);
}

await browser.close();
console.log("\n=== summary ===");
const failed = results.filter((r) => !r.ok);
for (const e of errors.slice(0, 8)) console.log("  [console]", e);
console.log(`  ${results.length - failed.length}/${results.length} checks passed`);
if (failed.length || errors.length) {
  if (failed.length) console.log("  FAILED: " + failed.map((f) => f.name).join("; "));
  process.exit(1);
}
console.log("  otp transfer sheets good\n");
