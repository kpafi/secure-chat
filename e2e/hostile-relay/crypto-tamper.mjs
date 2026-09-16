// crypto-tamper.mjs — drives two real browsers through tamper.mjs in every
// EVIL mode and asserts what the SHIPPED client must show. Promise #1 of the
// pentest brief — a hostile relay cannot read, forge, replay or undetectably
// tamper with a conversation — had no end-to-end control until the Phase-7
// pentest (2026-09-16, F-P7-A8): hostile.mjs forwards key/msg verbatim.
//
//   node e2e/hostile-relay/crypto-tamper.mjs             # all modes, ~2 min
//   EVIL=ctflip node e2e/hostile-relay/crypto-tamper.mjs # one mode
//   MODE=PQKEM node e2e/hostile-relay/crypto-tamper.mjs  # a different cipher
//
// Needs system Chromium and puppeteer-core in e2e/ (see e2e/README.md). Exits
// non-zero on the first failed assertion. The relay is spawned per mode on
// PORT (default 8098) so no relay of yours is touched.
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import puppeteer from "puppeteer-core";

const HERE = dirname(fileURLToPath(import.meta.url));
const PORT = Number(process.env.PORT || 8098);
const APP = `http://127.0.0.1:${PORT}`;
const MODE = process.env.MODE || "DHKE";
const ONLY = process.env.EVIL || null;
const CHROMIUM = process.env.CHROMIUM || "/usr/bin/chromium";
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const CANARY = "PING FROM A 4f3c9a";

let checks = 0;
let failed = 0;
function check(cond, what) {
  checks++;
  if (cond) console.log(`  ok   ${what}`);
  else { failed++; console.log(`  FAIL ${what}`); }
}

async function startRelay(evil) {
  const child = spawn(process.execPath, [join(HERE, "tamper.mjs")], {
    env: { ...process.env, EVIL: evil, PORT: String(PORT), ALGFLOOD_N: process.env.ALGFLOOD_N || "300" },
    stdio: ["ignore", "pipe", "inherit"],
  });
  await new Promise((resolve, reject) => {
    child.stdout.on("data", (d) => { if (String(d).includes("tamper relay")) resolve(); });
    child.on("exit", (code) => reject(new Error(`relay exited early (${code})`)));
    setTimeout(() => reject(new Error("relay did not start")), 10000);
  });
  return child;
}

async function setup(page) {
  await page.goto(APP, { waitUntil: "domcontentloaded" });
  await page.evaluate(() => { window.prompt = () => "pw"; window.confirm = () => true; });
  await page.type("#idPass", "e2e tamper passphrase");
  await page.click("#idCreate");
  await page.waitForFunction(() => !document.querySelector("#idExport").hidden, { timeout: 60000 });
  await page.click("#toRoom");
  await page.evaluate((m) => { document.querySelector(`input[name="alg"][value="${m}"]`).click(); }, MODE);
}
const lines = (page) => page.evaluate(() => [...document.querySelectorAll("#log li")].map((l) => l.textContent));
const canSend = (page) => page.evaluate(() => !document.querySelector("#send").disabled);
async function clickIfPrompt(page, mode, timeout) {
  try {
    await page.waitForFunction((md) => {
      const e = document.querySelector("#admit");
      return e && !e.hidden && e.dataset.mode === md;
    }, { timeout }, mode);
    await page.click("#admitOk");
    return true;
  } catch { return false; }
}
async function clickVerify(page) {
  const shown = await page.evaluate(() => { const v = document.querySelector("#verify"); return v && !v.hidden; });
  if (shown) { try { await page.click("#verifyOk"); } catch {} }
}

async function session(evil) {
  const browser = await puppeteer.launch({ executablePath: CHROMIUM, headless: true, args: ["--no-sandbox", "--disable-dev-shm-usage"] });
  try {
    const A = await (await browser.createBrowserContext()).newPage();
    const B = await (await browser.createBrowserContext()).newPage();
    const room = Array.from({ length: 64 }, () => "0123456789abcdef"[Math.floor(Math.random() * 16)]).join("");
    await setup(A); await setup(B);
    for (const p of [A, B]) await p.evaluate((r) => { document.querySelector("#room").value = r; }, room);
    await A.click("#connect"); await sleep(1500);
    await B.click("#connect"); await sleep(2500);
    await clickIfPrompt(A, "knock", 15000); // the owner admits the knock
    await sleep(2500);
    for (const p of [A, B]) await clickIfPrompt(p, "peer", 6000); // first-contact approval, both sides
    await sleep(3000);
    for (const p of [A, B]) await clickVerify(p);
    await sleep(1500);
    const send = { a: await canSend(A), b: await canSend(B) };
    if (send.a) { await A.type("#text", CANARY); await A.click("#send"); await sleep(2500); }
    return { send, logA: await lines(A), logB: await lines(B), liA: (await lines(A)).length, liB: (await lines(B)).length };
  } finally {
    await browser.close();
  }
}

const has = (log, re) => log.some((l) => re.test(l));
const count = (log, re) => log.filter((l) => re.test(l)).length;

const EXPECT = {
  none(r) {
    check(r.send.a && r.send.b, "control: a session completes and both sides can send");
    check(has(r.logB, new RegExp(CANARY)), "control: A's message reaches B");
  },
  keysub(r) {
    check(has(r.logA, /handshake signature INVALID/) || has(r.logB, /handshake signature INVALID/), "keysub: the substituted ephemeral key fails the handshake signature, loudly");
    check(!r.send.a && !r.send.b, "keysub: neither side can send");
  },
  idbswap(r) {
    check(has(r.logA, /handshake signature INVALID/) || has(r.logB, /handshake signature INVALID/), "idbswap (P-03): a rewritten idb.ecdh fails the handshake signature");
    check(!r.send.a && !r.send.b, "idbswap: neither side can send");
  },
  idbstrip(r) {
    check(has(r.logA, /handshake signature INVALID/) || has(r.logB, /handshake signature INVALID/), "idbstrip (P-03): stripped encryption keys fail the handshake signature");
    check(!r.send.a && !r.send.b, "idbstrip: neither side can send");
  },
  ctflip(r) {
    check(r.send.a, "ctflip: the session itself completes (tampering is per frame)");
    check(has(r.logB, /undecryptable/), "ctflip: the flipped frame is refused as undecryptable");
    check(!has(r.logB, new RegExp(CANARY)), "ctflip: the tampered plaintext never renders");
  },
  msgreplay(r) {
    check(count(r.logB, new RegExp(CANARY)) === 1, `msgreplay: the message renders exactly once (got ${count(r.logB, new RegExp(CANARY))})`);
    check(has(r.logB, /undecryptable|replay/), "msgreplay: the replayed copies are refused, visibly");
  },
  confirmpre(r) {
    // F-P7-19: two relay-injected confirm tags before the chains exist must not
    // burn the honest peer's budget — the session completes, and nobody is
    // told the OTHER SIDE sent too many confirmations.
    check(r.send.a && r.send.b, "confirmpre (F-P7-19): injected pre-chain tags do not tear the session down");
    check(!has(r.logA, /more key confirmations/) && !has(r.logB, /more key confirmations/), "confirmpre: the honest peer is not blamed");
  },
  algflood(r) {
    // F-P7-7: the RSA refusal is said once per connection and the log is capped,
    // so a flood of 14-byte frames neither buries the real lines nor wedges the tab.
    check(r.send.a && r.send.b, "algflood (F-P7-7): the session still completes under the flood");
    check(count(r.logA, /the other end is using RSA/) <= 1 && count(r.logB, /the other end is using RSA/) <= 1, "algflood: the deprecated-alg refusal is said at most once per side");
    check(r.liA < 100 && r.liB < 100, `algflood: the transcript stays bounded (A ${r.liA}, B ${r.liB} lines)`);
  },
};

const modes = ONLY ? [ONLY] : Object.keys(EXPECT);
for (const evil of modes) {
  if (!EXPECT[evil]) { console.error(`unknown EVIL=${evil}`); process.exit(2); }
  console.log(`\n=== EVIL=${evil} (${MODE})`);
  const relay = await startRelay(evil);
  try {
    const r = await session(evil);
    EXPECT[evil](r);
    if (process.env.VERBOSE) { console.log("  A:", r.logA); console.log("  B:", r.logB); }
  } catch (e) {
    failed++;
    console.log(`  FAIL ${evil}: ${e.message}`);
  } finally {
    relay.kill();
    await sleep(300);
  }
}
console.log(`\n${checks - failed}/${checks} checks passed${failed ? " — FAILURES ABOVE" : " — tamper relay defeated"}`);
process.exit(failed ? 1 : 0);
