// Two-agent live-room run of EVERY encryption mode, over any access point.
//
//   node e2e/all-modes.mjs
//   SECURE_CHAT_E2E_URL=https://138-199-144-35.sslip.io node e2e/all-modes.mjs
//   SECURE_CHAT_E2E_PROXY=socks5://127.0.0.1:9050 \
//     SECURE_CHAT_E2E_URL=http://<addr>.onion node e2e/all-modes.mjs
//
// The other e2e runs each pin one flow (admission, async chat, dead ends) and
// all of them happen to use the default mode. Nothing drove DHKE, AES256, RSA,
// PQKEM and OTP through a real pair of browsers, so a mode could rot without a
// single test noticing. This walks all five: pick the mode, open a room, get
// approved, clear whatever gate that mode raises, and send a message BOTH ways
// asserting the exact text arrives.
//
// Adding SECURE_CHAT_E2E_PROXY is what makes it a Tor run — Chromium resolves
// .onion through the SOCKS5 proxy, so the same script proves the same flows
// over the onion as over clearnet.
import puppeteer from "puppeteer-core";
import { readFileSync, writeFileSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const cfg = JSON.parse(readFileSync(new URL("./test-users.json", import.meta.url)));
const APP = process.env.SECURE_CHAT_E2E_URL || cfg.relay;
const PROXY = process.env.SECURE_CHAT_E2E_PROXY || "";
// Tor adds a second or two to every round trip; give the slow path room.
const SLOW = PROXY ? 3 : 1;
const T = (ms) => ms * SLOW;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const MODES = ["DHKE", "AES256", "RSA", "PQKEM", "OTP"];
const SHARED_PASS = cfg.chatPassphrase;
const PAD_XFER_PASS = "e2e pad transfer passphrase — test only";
const PAD_LOCAL_PASS = "e2e pad at-rest passphrase — test only";

const results = [];
function check(name, ok, detail = "") {
  results.push({ name, ok });
  console.log(`    ${ok ? "OK  " : "FAIL"} ${name}${detail ? " — " + detail : ""}`);
}

const args = ["--no-sandbox", "--disable-dev-shm-usage"];
if (PROXY) args.push(`--proxy-server=${PROXY}`);

const browser = await puppeteer.launch({
  executablePath: process.env.CHROMIUM || "/usr/bin/chromium",
  headless: "new",
  args,
  // Identity creation is heavy local CPU (PBKDF2-600k + ML-DSA-65 + ML-KEM-768
  // keygen, twice). On a loaded machine that outran puppeteer's default 180 s
  // CDP ceiling and surfaced as a bogus "Waiting failed" long before our own
  // timeouts were near. Raise the protocol ceiling above them.
  protocolTimeout: T(300000),
});

const errors = [];
async function agent(label) {
  const ctx = await browser.createBrowserContext();
  const page = await ctx.newPage();
  page.on("pageerror", (e) => errors.push(`${label}: ${e.message}`));
  page.on("console", (m) => {
    const t = m.text();
    if (m.type() === "error" && !/favicon|404/.test(t)) errors.push(`${label}: ${t}`);
  });
  // Nothing in these flows should raise a native dialog; accept anything that
  // does rather than deadlocking the run, and surface it as an error.
  page.on("dialog", async (d) => {
    errors.push(`${label}: unexpected dialog "${d.message().slice(0, 80)}"`);
    await d.accept();
  });
  await page.setViewport({ width: 1000, height: 900 });
  await page.goto(APP, { waitUntil: "networkidle0", timeout: T(60000) });
  await page.type("#idPass", `${cfg.users[0].passphrase} ${label}`);
  await page.click("#idCreate");
  await page.waitForFunction(() => !document.querySelector("#idExport").hidden, { timeout: T(90000) });
  const fingerprint = await page.evaluate(() =>
    document.querySelector("#idFingerprint").textContent.replace(/^[^:]*:\s*/, "").trim());
  await page.click("#toRoom");
  await page.waitForFunction(() => !document.querySelector("#scrRoom").hidden, { timeout: T(30000) });
  return { label, ctx, page, fingerprint };
}

const text = (page, sel) => page.evaluate((s) => {
  const el = document.querySelector(s);
  return el ? el.textContent.trim() : "";
}, sel);

// Select a mode the way the UI models it (radio + change event), and open the
// disclosure so a failure screenshot shows what was chosen.
async function selectMode(page, mode) {
  await page.evaluate((m) => {
    const d = document.querySelector("#algDetails");
    if (d) d.open = true;
    const r = document.querySelector(`input[name="alg"][value="${m}"]`);
    r.checked = true;
    r.dispatchEvent(new Event("change", { bubbles: true }));
  }, mode);
}

const setValue = (page, sel, value) => page.evaluate((s, v) => {
  const el = document.querySelector(s);
  el.value = v;
  el.dispatchEvent(new Event("input", { bubbles: true }));
  el.dispatchEvent(new Event("change", { bubbles: true }));
}, sel, value);

// ---------------------------------------------------------------------------
// OTP needs a pad on BOTH devices before either can connect, and the real
// exchange is a file carried in person. We drive exactly that: generate on
// alice, capture the exported blob, hand the file to bob's file input.
// ---------------------------------------------------------------------------
async function exchangePad(alice, bob) {
  console.log("\n  [OTP] generating a pad on alice and carrying it to bob");
  for (const a of [alice, bob]) {
    await selectMode(a.page, "OTP");
    await a.page.waitForFunction(() => !document.querySelector("#otpPanel").hidden, { timeout: T(20000) });
    await a.page.evaluate(() => { const d = document.querySelector("#otpTools"); if (d) d.open = true; });
    await setValue(a.page, "#otpPass", PAD_LOCAL_PASS);
    await setValue(a.page, "#otpXferPass", PAD_XFER_PASS);
  }

  // Smallest offered pad: this test sends a handful of short messages.
  await alice.page.evaluate(() => {
    const sel = document.querySelector("#otpSize");
    sel.value = sel.options[0].value;
    sel.dispatchEvent(new Event("change", { bubbles: true }));
  });
  await setValue(alice.page, "#otpLabel", "e2e-pad");
  await alice.page.click("#otpGenerate");
  await alice.page.waitForFunction(
    () => document.querySelector("#otpSelect").value !== "", { timeout: T(60000) });
  check("OTP pad generated on alice", true, await text(alice.page, "#otpStatus"));

  // downloadText() hands the file to the browser via a blob URL; intercept it
  // instead of engaging Chromium's download machinery.
  await alice.page.evaluate(() => {
    window.__padFile = null;
    const orig = URL.createObjectURL.bind(URL);
    URL.createObjectURL = (blob) => {
      blob.text().then((t) => { window.__padFile = t; });
      return orig(blob);
    };
  });
  await alice.page.click("#otpExport");
  await alice.page.waitForFunction(() => window.__padFile !== null, { timeout: T(30000) });
  const padJson = await alice.page.evaluate(() => window.__padFile);
  check("pad exported as a transfer file", padJson.length > 100, `${padJson.length} bytes`);

  const dir = mkdtempSync(join(tmpdir(), "sc-pad-"));
  const padPath = join(dir, "secure-chat-pad-e2e.json");
  writeFileSync(padPath, padJson);

  // Upload straight to the hidden input: clicking Import opens a native file
  // chooser, which headless Chromium cannot answer.
  const input = await bob.page.$("#otpFile");
  await input.uploadFile(padPath);
  await bob.page.waitForFunction(
    () => document.querySelector("#otpSelect").value !== "", { timeout: T(60000) });
  check("pad imported on bob", true, await text(bob.page, "#otpStatus"));
}

// ---------------------------------------------------------------------------
// One full conversation in one mode.
// ---------------------------------------------------------------------------
async function runMode(mode, alice, bob) {
  console.log(`\n--- ${mode} ---`);

  for (const a of [alice, bob]) {
    await selectMode(a.page, mode);
    if (mode === "AES256") await setValue(a.page, "#pass", SHARED_PASS);
    if (mode === "OTP") await setValue(a.page, "#otpPass", PAD_LOCAL_PASS);
  }

  // Fresh room per mode: a new room id means a new pin key, so every mode
  // faces its gate from scratch instead of inheriting a previous approval.
  await alice.page.click("#gen");
  const code = await alice.page.evaluate(() => document.querySelector("#room").value.trim());
  check(`${mode}: fresh room code`, /^[0-9a-f]{64}$/.test(code), code.slice(0, 12) + "…");

  await alice.page.click("#connect");
  await alice.page.waitForFunction(
    () => /connected/i.test(document.querySelector("#chatStatus").textContent), { timeout: T(45000) });

  await setValue(bob.page, "#room", code);
  await bob.page.click("#connect");
  await bob.page.waitForFunction(
    () => /waiting for approval/i.test(document.querySelector("#chatStatus").textContent),
    { timeout: T(45000) });

  await alice.page.waitForFunction(() => !document.querySelector("#admit").hidden, { timeout: T(45000) });
  const shownFp = await text(alice.page, "#admitFingerprint");
  check(`${mode}: owner sees the knocker's real fingerprint`, shownFp === bob.fingerprint,
    `${shownFp.slice(0, 20)}…`);
  await alice.page.click("#admitOk");

  // Each mode raises its own gate: the identity-authenticated ones show a
  // safety number, AES256/OTP unlock straight away. Wait for whichever comes.
  const settle = (page) => page.waitForFunction(() => {
    const v = document.querySelector("#verify");
    return (v && !v.hidden) || !document.querySelector("#text").disabled;
  }, { timeout: T(60000) });
  await Promise.all([settle(alice.page), settle(bob.page)]);

  const gated = await alice.page.evaluate(() => !document.querySelector("#verify").hidden);
  const authenticated = ["DHKE", "RSA", "PQKEM"].includes(mode);
  check(`${mode}: ${authenticated ? "raises" : "does not raise"} a safety-number gate`,
    gated === authenticated, gated ? "safety number shown" : "unlocked directly");

  if (gated) {
    const [snA, snB] = [await text(alice.page, "#safetyNumber"), await text(bob.page, "#safetyNumber")];
    check(`${mode}: both peers compute the SAME safety number`, !!snA && snA === snB,
      `${snA.slice(0, 24)}…`);
    await alice.page.click("#verifyOk");
    await bob.page.click("#verifyOk");
  }

  await Promise.all([alice, bob].map((a) => a.page.waitForFunction(
    () => !document.querySelector("#text").disabled, { timeout: T(30000) })));

  // The actual point: real ciphertext through the real relay, both ways.
  const toBob = `${mode} alice->bob ${Date.now()}`;
  await alice.page.type("#text", toBob);
  await alice.page.click("#send");
  let bobLog = "";
  for (let i = 0; i < 25 && !bobLog.includes(toBob); i++) {
    await sleep(T(500));
    bobLog = await text(bob.page, "#log");
  }
  check(`${mode}: alice -> bob delivered verbatim`, bobLog.includes(toBob));

  const toAlice = `${mode} bob->alice ${Date.now()}`;
  await bob.page.type("#text", toAlice);
  await bob.page.click("#send");
  let aliceLog = "";
  for (let i = 0; i < 25 && !aliceLog.includes(toAlice); i++) {
    await sleep(T(500));
    aliceLog = await text(alice.page, "#log");
  }
  check(`${mode}: bob -> alice delivered verbatim`, aliceLog.includes(toAlice));

  for (const a of [alice, bob]) {
    await a.page.click("#disconnect");
    await a.page.waitForFunction(
      () => document.querySelector("#text").disabled, { timeout: T(30000) });
  }
}

console.log(`\n=== all encryption modes, two agents ===`);
console.log(`    target: ${APP}`);
console.log(`    proxy:  ${PROXY || "(none — direct)"}\n`);

const alice = await agent("alice");
const bob = await agent("bob");
check("two independent identities created", alice.fingerprint !== bob.fingerprint);

await exchangePad(alice, bob);
for (const mode of MODES) await runMode(mode, alice, bob);

await browser.close();

console.log("\n=== summary ===");
const failed = results.filter((r) => !r.ok);
for (const e of errors.slice(0, 8)) console.log("  [console]", e);
console.log(`  ${results.length - failed.length}/${results.length} checks passed`);
if (failed.length) {
  console.log("  FAILED: " + failed.map((f) => f.name).join("; "));
  process.exit(1);
}
console.log("  all modes good\n");
