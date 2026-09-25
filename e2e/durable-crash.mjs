// Package 3b, in a REAL browser: a hard kill after an OTP send must not reopen
// the pad at a spent offset.
//
//   node e2e/durable-crash.mjs            (relay serving client/, as the other runs)
//
// The finding this pins (package-3 pentest, pre-existing HIGH): Chromium keeps
// localStorage writes in memory and commits them in rate-limited batches, so a
// pad saved seconds before the browser died reopened at the offset the last
// message had already used — the next message reused pad bytes (two-time pad).
// This drives the real otp.js in real Chromium with a persistent profile, in
// the pentest's timing: the pad is saved at offset 0 and left long enough for
// that to reach disk; message 1 spends 0..500, message 2 (10 s later) 500..1000,
// each awaiting its pre-send save (as app.js does); the browser PROCESS is
// SIGKILLed right after the second save returned (DURABLE_KILL_AFTER_MS, default
// 0); a new browser on the same profile unlocks the
// pad. It must open at >= 1000. It also reports whether localStorage actually
// lost the writes on this run (it usually does on Chromium): when it did, the
// pad opening at 1000 is the durable (IndexedDB) record at work.
//
// Takes ~2 minutes (the settle wait is the point). Not part of the six-run set.
import puppeteer from "puppeteer-core";
import { mkdtempSync, rmSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const cfg = JSON.parse(readFileSync(new URL("./test-users.json", import.meta.url)));
const APP = process.env.SECURE_CHAT_E2E_URL || cfg.relay;
const SETTLE_MS = +(process.env.DURABLE_SETTLE_MS || 70000);
const KILL_AFTER_MS = +(process.env.DURABLE_KILL_AFTER_MS || 0);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const profile = mkdtempSync(join(tmpdir(), "sc-durable-"));
const PASS = "durable-crash pad passphrase (test only)";

const launch = () => puppeteer.launch({
  executablePath: process.env.CHROMIUM || "/usr/bin/chromium",
  headless: "new",
  userDataDir: profile,
  args: ["--no-sandbox", "--disable-dev-shm-usage"],
});

async function page(browser) {
  const p = await browser.newPage();
  await p.goto(APP, { waitUntil: "networkidle0" });
  return p;
}

let failed = false;
const check = (name, ok, detail = "") => {
  if (!ok) failed = true;
  console.log(`  ${ok ? "OK  " : "FAIL"} ${name}${detail ? " — " + detail : ""}`);
};

try {
  // ---- run 1: save, settle, send twice, SIGKILL ------------------------------
  let b = await launch();
  let p = await page(b);
  const padId = await p.evaluate(async (PASS) => {
    const otp = await import("./otp.js");
    const pad = await otp.generatePad({ label: "durable-crash", totalBytes: 8192, fingerBytes: new Uint8Array(0) });
    window.__pad = pad;
    window.__at = await otp.saveNewPad(pad, PASS);
    return pad.padId;
  }, PASS);
  console.log(`  pad saved at offset 0; waiting ${SETTLE_MS / 1000} s for it to reach disk…`);
  await sleep(SETTLE_MS);
  const blobNow = () => p.evaluate((id) => localStorage.getItem("sc.otp.pad.v1." + id), padId);
  const seen = { 0: await blobNow() };
  const send = (to) => p.evaluate(async (to) => {
    const otp = await import("./otp.js");
    window.__pad.sendOffset = to;               // the cipher spent pad bytes up to `to`
    await otp.savePadProgress(window.__pad, window.__at); // app.js awaits this, THEN transmits
    return true;
  }, to);
  await send(500);
  seen[500] = await blobNow();
  console.log("  message 1 (0..500) persisted — would be on the wire now");
  await sleep(10000);
  await send(1000);
  seen[1000] = await blobNow();
  console.log(`  message 2 (500..1000) persisted — killing the browser in ${KILL_AFTER_MS / 1000} s`);
  await sleep(KILL_AFTER_MS);
  b.process().kill("SIGKILL");
  await sleep(1500);

  // ---- run 2: same profile, unlock ------------------------------------------
  b = await launch();
  p = await page(b);
  const out = await p.evaluate(async (id, PASS) => {
    const lsNow = localStorage.getItem("sc.otp.pad.v1." + id);
    const otp = await import("./otp.js");
    try {
      const u = await otp.unlockPad(id, PASS);
      return { open: u.record.sendOffset, lsNow };
    } catch (e) {
      return { err: String(e && e.message), lsNow };
    }
  }, padId, PASS);
  // Which save did localStorage keep? (The blob is sealed; compare the strings.)
  const kept = Object.keys(seen).find((k) => seen[k] === out.lsNow);
  delete out.lsNow;
  out.localStorageHeld = kept === undefined ? "unknown" : +kept;
  console.log(`  after the kill: localStorage held the offset-${out.localStorageHeld} blob` +
    (out.localStorageHeld !== 1000 ? " — the later write(s) never reached disk" : ""));
  check("the pad does not reopen at a spent offset after a hard kill", out.open >= 1000, JSON.stringify(out));
  if (out.localStorageHeld !== 1000) {
    check("…and it is the durable record that says so (localStorage alone would have reopened at " + out.localStorageHeld + ")", out.open === 1000);
  }
  await b.close();
} finally {
  rmSync(profile, { recursive: true, force: true });
}
console.log(failed ? "\nFAILED" : "\nDurable-crash run passed.");
process.exit(failed ? 1 : 0);
