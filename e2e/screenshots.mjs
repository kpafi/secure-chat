// Screenshots of every screen and state, at phone and desktop size, for design
// review.
//
//   CHROMIUM=/opt/pw-browsers/chromium node e2e/screenshots.mjs <outdir>
//
// Needs the relay ALREADY running (backend/run.sh). This script never starts or
// stops it; it only checks GET /healthz before it begins.
//
// Writes NN-<state>-<phone|desktop>.png into <outdir> (phone 390x844 @2x,
// desktop 1280x800 @1x), plus index.html: a contact sheet with every PNG, phone
// and desktop side by side, so a reviewer opens one file.
//
// It is meant to be run twice: once against the current client (the baseline)
// and again after the visual rework, where element ids stay the same but the
// layout does not. So it is keyed ONLY on element ids, on text the app already
// shows, on the `data-view` attribute app.js navigates by, and (to know when
// sealed mail has arrived) on the app's own modules, as two-user-flow.mjs does.
// Never on CSS classes. Navigation uses whatever visible control names the view
// (a tab bar, a rail) and falls back to the #menuBtn drawer. Each state has a
// FIXED number, so the two runs line up file for file even if a state is
// skipped or missed in one of them.
//
// Exit code 0 when every planned state was captured (or skipped for a reason the
// plan allows, e.g. no #menuBtn to open), 1 otherwise with the list of misses.
//
// Agents, all with the throwaway credentials from test-users.json and a per-run
// username suffix:
//   alice - the user whose screens these are (every capture but two)
//   bob   - a contact alice verifies in person; the live-room peer
//   carol - a stranger who writes to alice first, so she is filed as an
//           unverified contact with a claimed name (two-user-flow.mjs, check 3)
import puppeteer from "puppeteer-core";
import { readFileSync, writeFileSync, mkdirSync, existsSync } from "node:fs";
import { join, resolve } from "node:path";

const cfg = JSON.parse(readFileSync(new URL("./test-users.json", import.meta.url)));
const APP = process.env.SECURE_CHAT_E2E_URL || cfg.relay;

const OUT = process.argv[2];
if (!OUT) {
  console.error("usage: CHROMIUM=/path/to/chromium node e2e/screenshots.mjs <outdir>");
  process.exit(2);
}
const outDir = resolve(OUT);
mkdirSync(outDir, { recursive: true });

const RUN = Date.now().toString(36).slice(-5);
const T0 = Date.now();
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const secs = () => ((Date.now() - T0) / 1000).toFixed(1) + "s";
const firstLine = (e) => String((e && e.message) || e).split("\n")[0].slice(0, 300);

const [aliceSpec, bobSpec] = cfg.users;
// test-users.json holds two accounts. The stranger reuses bob's throwaway
// passphrase under its own username prefix (room-admission.mjs likewise gives
// all three of its agents alice's). Every agent has its own browser context, so
// the string is all they share.
const carolSpec = { role: "carol", usernamePrefix: "e2e-carol", passphrase: bobSpec.passphrase };

// Printable ASCII only: both send paths refuse anything else.
const MSG = {
  bob: ["Hi Alice, it's Bob. Got your handle.", "Are we still on for Thursday?"],
  carol: ["Hello Alice, we met at the meetup last week. This is Carol."],
  alice: ["Hi Bob! Yes, Thursday at 6 works.", "I'll bring the printed fingerprints."],
};
const LIVE = {
  bob: ["hi alice - the safety number matched on my side", "sending the draft over now"],
  alice: ["same here, we're good to talk"],
};

// isMobile / hasTouch stay false at BOTH sizes on purpose: puppeteer reloads the
// page whenever either flips, which would drop the in-memory unlocked identity
// and every state built on it. Width, height and pixel ratio switch in place.
const SIZES = [
  { name: "phone", label: "phone 390×844 @2x",
    vp: { width: 390, height: 844, deviceScaleFactor: 2, isMobile: false, hasTouch: false } },
  { name: "desktop", label: "desktop 1280×800 @1x",
    vp: { width: 1280, height: 800, deviceScaleFactor: 1, isMobile: false, hasTouch: false } },
];
// Interactions happen at desktop size; capture() always ends on this size.
const WORK_VP = SIZES[1].vp;

// The plan. Numbers are fixed so a baseline and a rework run line up by name.
const PLAN = [
  ["01", "first-run", "First run: Live room / identity screen, no identity on this device"],
  ["02", "drawer-open", "Navigation drawer open (#menuBtn)", "viewport"],
  ["03", "identity-unlocked", "Identity created + unlocked, username registered: fingerprint and account panel"],
  ["04", "room-setup", "Room setup (#scrRoom)"],
  ["05", "room-security-options", "Room setup, security options open (#algDetails)"],
  ["06", "room-otp-selected", "Room setup, One-time pad card selected (#otpPanel)"],
  ["07", "users-locked", "Users view, locked: a fresh tab on the same device"],
  ["08", "users-unlocked", "Users view unlocked: your handle, a contact verified in person, an unverified stranger with a claimed name"],
  ["09", "chats-list", "Chats view: the chat list"],
  ["10", "chat-conversation", "Chats view: open conversation, messages both ways"],
  ["11", "chat-mode-proposal-sent", "Mode-change proposal, proposing side (bob's screen, waiting for alice)"],
  ["12", "chat-mode-proposal-received", "Mode-change proposal, receiving side: the pending banner with Accept / Decline"],
  ["13", "profile", "Profile view unlocked: avatar, handle, QR, fingerprint, chips"],
  ["14", "live-owner-connected", "Live room: owner connected, nobody else in the room yet"],
  ["15", "live-guest-waiting", "Live room: guest waiting for the owner's approval (bob's screen)"],
  ["16", "live-admission-prompt", "Live room: owner's admission prompt (#admit, #admitFingerprint)"],
  ["17", "live-verify-owner", "Live room: safety-number gate (#verify, #safetyNumber), owner side"],
  ["18", "live-verify-guest", "Live room: safety-number gate, guest side (bob's screen)"],
  ["19", "live-chat-connected", "Live room: connected, messages in #log"],
  ["20", "live-disconnected", "Live room: after Disconnect"],
  ["21", "users-unlock-wrong-passphrase", "Error: wrong passphrase on the Users unlock row (#usersUnlockStatus)"],
  ["22", "contact-profile", "Contact profile (#contactSheet) over Users: bob, verified in person", "viewport"],
  ["23", "contact-profile-stranger", "Contact profile over Users: the stranger, handle labelled a claim", "viewport"],
  ["24", "contact-profile-convo", "Contact profile opened from the conversation's name (no Message button)", "viewport"],
].map(([n, id, what, mode]) => ({ n, id, what, fullPage: mode !== "viewport", state: "pending", note: "", files: [] }));
const byId = Object.fromEntries(PLAN.map((p) => [p.id, p]));

// ---------------------------------------------------------------------------
// relay health (never started or stopped here)

let relayVersion = "?";
try {
  const r = await fetch(new URL("/healthz", APP), { signal: AbortSignal.timeout(5000) });
  const j = await r.json();
  if (!r.ok || j.status !== "ok") throw new Error(`HTTP ${r.status} ${JSON.stringify(j)}`);
  relayVersion = j.version || "?";
} catch (e) {
  console.error(`relay at ${APP} is not healthy (${firstLine(e)}).`);
  console.error("Start it first (cd backend && ./run.sh); this script never starts or stops it.");
  process.exit(1);
}

console.log(`\n=== secure-chat screenshots (${APP}, relay ${relayVersion}, run ${RUN}) ===`);
console.log(`    -> ${outDir}`);

const browser = await puppeteer.launch({
  executablePath: process.env.CHROMIUM || "/usr/bin/chromium",
  headless: "new",
  args: ["--no-sandbox", "--disable-dev-shm-usage"],
  // Identity creation is heavy local CPU (see all-modes.mjs); keep the CDP
  // ceiling above our own longest wait (90 s), but low enough that a stuck
  // call cannot eat the whole run.
  protocolTimeout: 120000,
});

// ---------------------------------------------------------------------------
// bookkeeping

let finished = false;
function mark(id, state, note = "") {
  const st = byId[id];
  st.state = state;
  if (note) st.note = note;
}
function skip(id, why) {
  if (byId[id].state !== "pending") return;
  mark(id, "skipped", why);
  console.log(`  SKIPPED ${byId[id].n}-${id}: ${why}`);
}

// Setup work that captures depend on. A failure is recorded, and every state
// that needs it is reported as missed with the reason, instead of crashing.
const setup = {};
function req(...names) {
  for (const n of names) {
    if (setup[n] !== true) throw new Error(`needs setup "${n}", which ${setup[n] ? "failed: " + setup[n] : "was not reached"}`);
  }
}
async function runSetup(name, fn) {
  console.log(`\n[setup] ${name}`);
  try {
    await fn();
    setup[name] = true;
    console.log(`  ok (${secs()})`);
  } catch (e) {
    setup[name] = firstLine(e);
    console.log(`  FAILED: ${setup[name]}`);
  }
}

async function step(id, fn) {
  const st = byId[id];
  if (finished || st.state !== "pending") return;
  console.log(`\n${st.n} ${st.id} — ${st.what}`);
  try {
    await fn();
    if (st.state === "pending") throw new Error("step ended without a capture");
  } catch (e) {
    mark(id, "missed", firstLine(e));
    console.log(`  MISSED ${st.n}-${st.id}: ${st.note}`);
  }
}

// ---------------------------------------------------------------------------
// page helpers — ids, visible text and data-view only

const errors = [];

// `ctx` opens the tab in an EXISTING browser context: same origin storage (so
// the identity blob is there) but no in-memory unlocked identity, exactly like
// a real second tab (two-user-flow.mjs newTab()).
async function openTab(label, ctx = null) {
  ctx = ctx || await browser.createBrowserContext();
  const page = await ctx.newPage();
  // Poll on an interval, not puppeteer's default requestAnimationFrame: a tab
  // that is not in front (the second tab in alice's context puts her first one
  // behind it) gets no animation frames, and a rAF-polled wait there stalls
  // until the protocol timeout.
  const waitForFunction = page.waitForFunction.bind(page);
  page.waitForFunction = (fn, opts = {}, ...args) => waitForFunction(fn, { polling: 100, ...opts }, ...args);
  page.on("pageerror", (e) => errors.push(`${label}: ${e.message}`));
  page.on("console", (m) => {
    const t = m.text();
    if (m.type() === "error" && !/favicon|404/.test(t)) errors.push(`${label}: ${t}`);
  });
  // confirm() (verify in person, publish vouch) is accepted; prompt() is only
  // the shared passphrase of the AES-256 mode proposal.
  page.on("dialog", async (d) => {
    try {
      if (d.type() === "prompt") await d.accept(cfg.chatPassphrase);
      else await d.accept();
    } catch { /* already handled */ }
  });
  // One visibility test for every wait: what is RENDERED (the element and its
  // ancestors displayed, not visibility:hidden) and has a box. Not the `hidden`
  // attribute itself: a restyled client may render or hide things by CSS alone.
  await page.evaluateOnNewDocument(() => {
    window.__shown = (el) => {
      if (!el || !el.isConnected) return false;
      if (typeof el.checkVisibility === "function") {
        if (!el.checkVisibility({ visibilityProperty: true })) return false;
      } else if (el.closest("[hidden]") || getComputedStyle(el).visibility === "hidden") {
        return false;
      }
      const r = el.getBoundingClientRect();
      return r.width > 0 && r.height > 0;
    };
  });
  await page.setViewport(WORK_VP);
  await page.goto(APP, { waitUntil: "networkidle0", timeout: 60000 });
  return { ctx, page, label };
}

const shown = (page, sel) => page.evaluate((s) => window.__shown(document.querySelector(s)), sel);
const text = (page, sel) => page.evaluate((s) => (document.querySelector(s)?.textContent || "").trim(), sel);

async function waitShown(page, sel, timeout = 30000) {
  await page.waitForFunction((s) => window.__shown(document.querySelector(s)), { timeout }, sel)
    .catch(() => { throw new Error(`${sel} never became visible (${timeout / 1000}s)`); });
}
const shownWithin = (page, sel, timeout) => waitShown(page, sel, timeout).then(() => true, () => false);

async function waitText(page, sel, re, timeout = 30000) {
  await page.waitForFunction((s, src, fl) => {
    const el = document.querySelector(s);
    return !!el && new RegExp(src, fl).test(el.textContent);
  }, { timeout }, sel, re.source, re.flags)
    .catch(async () => {
      throw new Error(`${sel} never matched ${re} (${timeout / 1000}s); it says ${JSON.stringify((await text(page, sel)).slice(0, 120))}`);
    });
}

async function waitIncludes(page, sel, needle, timeout = 30000) {
  await page.waitForFunction((s, n) => (document.querySelector(s)?.textContent || "").includes(n),
    { timeout }, sel, needle)
    .catch(() => { throw new Error(`${sel} never showed ${JSON.stringify(needle.slice(0, 60))} (${timeout / 1000}s)`); });
}

// Poll a node-side predicate. Short sleeps only (existing runs poll at 2.5 s).
async function pollUntil(fn, timeout, what) {
  const end = Date.now() + timeout;
  for (;;) {
    if (await fn()) return;
    if (Date.now() > end) throw new Error(`${what} (${timeout / 1000}s)`);
    await sleep(500);
  }
}

async function click(page, sel) {
  await waitShown(page, sel, 15000);
  try {
    await page.click(sel);
  } catch {
    await page.evaluate((s) => document.querySelector(s).click(), sel);
  }
}

async function typeInto(page, sel, value) {
  await waitShown(page, sel, 15000);
  await page.evaluate((s) => { document.querySelector(s).value = ""; }, sel);
  await page.type(sel, value);
}

// Two frames for layout/paint, capped in case the tab gets no frames at all.
async function settle(page, ms = 250) {
  await page.evaluate(() => Promise.race([
    new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(r))),
    new Promise((r) => setTimeout(r, 300)),
  ]));
  await sleep(ms);
}

// Horizontal overflow at the current size, with the ids of the innermost
// visible elements that stick out past the viewport. The full-page shot then
// comes out WIDER than the viewport, which is itself worth a reviewer's eye.
const overflowAt = (page) => page.evaluate(() => {
  const vw = document.documentElement.clientWidth;
  const sw = document.documentElement.scrollWidth;
  if (sw <= vw + 1) return null;
  const sticks = (el) => window.__shown(el) && el.getBoundingClientRect().right > vw + 1;
  const ids = [];
  for (const el of document.querySelectorAll("body *")) {
    if (!sticks(el) || [...el.children].some(sticks)) continue;
    const owner = el.closest("[id]");
    const tag = owner ? "#" + owner.id : el.tagName.toLowerCase();
    if (!ids.includes(tag)) ids.push(tag);
  }
  return { vw, sw, ids: ids.slice(0, 4) };
});

// Visible position:fixed elements (not full-screen overlays) on a page that
// scrolls. A full-page shot keeps them where the FIRST viewport had them, so a
// bottom tab bar or sheet would float mid-image; such a size is shot at
// viewport size instead. (The current client has none outside the drawer.)
const fixedBars = (page) => page.evaluate(() => {
  const vw = window.innerWidth, vh = window.innerHeight;
  if (document.documentElement.scrollHeight <= vh + 1) return [];
  const out = [];
  for (const el of document.querySelectorAll("body *")) {
    if (!window.__shown(el) || getComputedStyle(el).position !== "fixed") continue;
    const r = el.getBoundingClientRect();
    if (r.width * r.height >= 0.9 * vw * vh) continue;
    const owner = el.closest("[id]");
    const tag = owner ? "#" + owner.id : el.tagName.toLowerCase();
    if (!out.includes(tag)) out.push(tag);
  }
  return out.slice(0, 4);
});

// Both sizes, same page, same in-memory state.
async function capture(page, id, note = "") {
  const st = byId[id];
  st.files = [];
  st.modes = {};
  const notes = note ? [note] : [];
  await page.bringToFront();
  try {
    for (const s of SIZES) {
      await page.setViewport(s.vp);
      await page.evaluate(() => window.scrollTo(0, 0));
      // Park the pointer in the top-left corner, or whatever the last real
      // click landed on keeps its :hover style in the shot.
      await page.mouse.move(0, 0);
      await settle(page);
      const file = `${st.n}-${st.id}-${s.name}.png`;
      let fullPage = st.fullPage;
      const bars = fullPage ? await fixedBars(page).catch(() => []) : [];
      if (bars.length) {
        fullPage = false;
        notes.push(`${s.name}: viewport only, the page scrolls under fixed ${bars.join(", ")}`);
      }
      await page.screenshot({ path: join(outDir, file), fullPage });
      st.files.push(file);
      st.modes[s.name] = fullPage ? "full page" : "viewport";
      const ov = await overflowAt(page).catch(() => null);
      if (ov) {
        notes.push(`${s.name}: content is ${ov.sw}px wide in a ${ov.vw}px viewport (horizontal overflow` +
          (ov.ids.length ? `: ${ov.ids.join(", ")}` : "") + ")");
      }
      console.log(`  [${secs()}] captured ${file}${ov ? `  (overflows to ${ov.sw}px)` : ""}`);
    }
  } finally {
    await page.setViewport(WORK_VP).catch(() => {});
  }
  mark(id, "captured", notes.join("; "));
  for (const n of notes) console.log(`  note: ${n}`);
}

// ---- navigation ------------------------------------------------------------

const VIEW_ID = { live: "#viewLive", users: "#viewUsers", chats: "#viewChats", profile: "#viewProfile" };
const VIEW_LABEL = { live: "^live( room)?$", users: "^users$", chats: "^chats$", profile: "^profile$" };

// Click a VISIBLE control for the view: data-view first (what app.js wires),
// then any button/link/tab whose text is the view's name.
const clickNav = (page, name) => page.evaluate((name, label) => {
  const re = new RegExp(label, "i");
  const cands = [...document.querySelectorAll(`[data-view="${name}"]`)];
  for (const el of document.querySelectorAll("button, a, [role=tab], [role=link], [role=menuitem]")) {
    if (re.test(el.textContent.trim())) cands.push(el);
  }
  const el = cands.find((c) => window.__shown(c));
  if (!el) return false;
  el.click();
  return true;
}, name, VIEW_LABEL[name]);

// Always clicks (never "already there"), because entering a view is what
// re-renders it (refreshUsers / refreshChats / renderProfile).
async function view(page, name) {
  await page.bringToFront();
  let ok = await clickNav(page, name);
  if (!ok && await page.$("#menuBtn") && await shown(page, "#menuBtn")) {
    await page.click("#menuBtn");
    await page.waitForFunction((name, label) => {
      const re = new RegExp(label, "i");
      return [...document.querySelectorAll(`[data-view="${name}"], button, a`)]
        .some((el) => window.__shown(el) && (el.dataset.view === name || re.test(el.textContent.trim())));
    }, { timeout: 5000 }, name, VIEW_LABEL[name]).catch(() => {});
    ok = await clickNav(page, name);
  }
  if (!ok) throw new Error(`no visible navigation control for the "${name}" view`);
  await waitShown(page, VIEW_ID[name], 10000);
  // Any overlay the drawer left behind must be gone before a screenshot.
  await page.waitForFunction(() => !window.__shown(document.querySelector("#scrim")), { timeout: 5000 }).catch(() => {});
  await settle(page, 150);
}

async function closeDrawer(page) {
  await page.evaluate(() => {
    const scrim = document.querySelector("#scrim");
    const menu = document.querySelector("#menuBtn");
    if (window.__shown(scrim)) scrim.click();
    else if (window.__shown(document.querySelector("#drawer")) && window.__shown(menu)) menu.click();
  });
  await page.waitForFunction(() => !window.__shown(document.querySelector("#scrim")), { timeout: 5000 }).catch(() => {});
}

// The identity controls (#idPass/#idCreate), wherever this version shows them.
async function ensureIdentityScreen(page) {
  if (await shownWithin(page, "#idPass", 8000)) return;
  await view(page, "live");
  if (await shownWithin(page, "#idPass", 3000)) return;
  if (await shown(page, "#toIdentity")) await click(page, "#toIdentity");
  await waitShown(page, "#idPass", 15000);
}

async function gotoRoomScreen(page) {
  if (await shown(page, "#scrRoom")) return;
  if (!(await shown(page, "#toRoom"))) await view(page, "live");
  if (await shown(page, "#scrRoom")) return;
  await click(page, "#toRoom");
  await waitShown(page, "#scrRoom", 20000);
}

// ---- identity + directory ---------------------------------------------------

async function createIdentity(page, pass) {
  await typeInto(page, "#idPass", pass);
  await click(page, "#idCreate");
  await page.waitForFunction(() => {
    const fp = document.querySelector("#idFingerprint");
    return window.__shown(fp) && fp.textContent.trim().length > 20;
  }, { timeout: 90000 }).catch(async () => {
    throw new Error(`identity was not created: ${JSON.stringify(await text(page, "#idStatus"))}`);
  });
}

async function registerUsername(page, username) {
  await waitShown(page, "#username", 15000); // the account panel appears once an identity exists
  await typeInto(page, "#username", username);
  await click(page, "#register");
  const res = await page.waitForFunction(() => {
    const t = document.querySelector("#accountStatus")?.textContent || "";
    if (/\bregistered\b/i.test(t) && !/not registered/i.test(t)) return "ok";
    if (/taken|failed/i.test(t)) return "err:" + t;
    return false;
  }, { timeout: 30000 }).then((h) => h.jsonValue())
    .catch(() => { throw new Error("registration never confirmed in #accountStatus"); });
  if (res.startsWith("err:")) throw new Error("registration: " + res.slice(4));
}

// Registering logs in to the directory automatically; receiving sealed mail
// depends on it. The Profile chips are rendered even while that view is hidden.
const waitLoggedIn = (page, timeout = 20000) => page.waitForFunction(() =>
  [...(document.querySelector("#profileStatus")?.children || [])]
    .some((c) => c.textContent.trim().toLowerCase() === "logged in"),
{ timeout }).then(() => true, () => false);

const handleOf = (page) => page.evaluate(() =>
  localStorage.getItem("sc.username.v1") + "#" + localStorage.getItem("sc.lookuptoken.v1"));

async function onboard(spec, label) {
  const t = await openTab(label);
  await ensureIdentityScreen(t.page);
  await createIdentity(t.page, spec.passphrase);
  const username = `${spec.usernamePrefix}-${RUN}`;
  await registerUsername(t.page, username);
  const loggedIn = await waitLoggedIn(t.page);
  const handle = await handleOf(t.page);
  console.log(`  [${secs()}] ${label} ready: ${handle}${loggedIn ? "" : " (directory login not confirmed)"}`);
  return { ...t, username, handle };
}

// ---- users + chats ----------------------------------------------------------

async function addContact(page, handle, username) {
  await view(page, "users");
  await waitShown(page, "#addHandle", 20000);
  await typeInto(page, "#addHandle", handle);
  await click(page, "#addContact");
  await waitIncludes(page, "#userList", username, 30000).catch(async () => {
    throw new Error(`adding ${username} failed: ${JSON.stringify(await text(page, "#usersStatus"))}`);
  });
}

async function markVerified(page, username) {
  // The Verify action lives in the contact's profile: open the row, wait for
  // the fingerprint (Verify is disabled until it is on screen), click, close.
  const opened = await page.evaluate((u) => {
    const list = document.querySelector("#userList");
    const row = list && [...list.children].find((li) => li.textContent.includes(u));
    const open = row && row.querySelector(".u-open");
    if (!open) return false;
    open.click();
    return true;
  }, username);
  if (!opened) throw new Error(`no row for ${username} in #userList`);
  await page.waitForFunction(() => {
    const b = document.querySelector("#contactVerify");
    return b && !b.disabled && !document.querySelector("#contactSheet").hidden;
  }, { timeout: 10000 }).catch(() => {});
  const clicked = await page.evaluate(() => {
    const btn = document.querySelector("#contactVerify");
    if (!btn || btn.disabled || !/verif/i.test(btn.textContent) || /unverif/i.test(btn.textContent)) return false;
    btn.click(); // confirm() dialogs are accepted by the tab's dialog handler
    return true;
  });
  if (!clicked) throw new Error(`no "Verified in person" control in ${username}'s profile`);
  await pollUntil(() => page.evaluate(async (u) => {
    try {
      const c = await import("./contacts.js");
      return !!(c.get(u) && c.get(u).verified);
    } catch {
      const list = document.querySelector("#userList");
      const row = list && [...list.children].find((li) => li.textContent.includes(u));
      return !!row && /unverify|verified by you/i.test(row.textContent);
    }
  }, username), 20000, `${username} never showed as verified`);
  await page.evaluate(() => { if (!document.querySelector("#contactSheet").hidden) document.querySelector("#contactClose").click(); });
}

// Click the row of `container` that names `needle` (a real row, whatever its tag).
async function clickRow(page, container, needle) {
  return page.evaluate((c, n) => {
    const list = document.querySelector(c);
    const row = list && [...list.children].find((el) => el.textContent.includes(n));
    if (!row) return false;
    (row.querySelector(".chatrow-open") || row).click(); // a chat row's opener, not its avatar
    return true;
  }, container, needle);
}

async function openChatWith(page, username) {
  await view(page, "chats");
  if (await shown(page, "#chatConvo") && (await text(page, "#chatPeer")).includes(username)) return;
  if (await shown(page, "#chatConvo") && await shown(page, "#chatBack")) await click(page, "#chatBack");
  await waitShown(page, "#chatNew", 20000);
  const picked = await page.select("#chatNew", username);
  if (picked.includes(username)) {
    await click(page, "#chatStart");
  } else if (!(await clickRow(page, "#chatList", username))) {
    throw new Error(`cannot open a chat with ${username}: not offered in #chatNew and no row in #chatList`);
  }
  await waitShown(page, "#chatConvo", 20000);
}

async function sendChat(page, msg) {
  await typeInto(page, "#chatText", msg);
  await click(page, "#chatSend");
  await waitIncludes(page, "#chatLog", msg, 30000).catch(async () => {
    throw new Error(`send failed: ${JSON.stringify(await text(page, "#chatHint"))}`);
  });
}

// What alice has received, by chat. The app's own store (as two-user-flow.mjs
// reads it); if that module is ever gone, fall back to the visible chat list.
const chatsOf = (page) => page.evaluate(async () => {
  try {
    const chats = await import("./chats.js");
    return chats.list().map((c) => ({ u: c.username, texts: c.messages.map((m) => m.text) }));
  } catch {
    return null;
  }
});

// ---- live room ----------------------------------------------------------------

async function pickMode(page, value, labelRe) {
  const ok = await page.evaluate((value, src, fl) => {
    const scope = document.querySelector("#algCards") || document.querySelector("#algDetails") || document;
    const re = new RegExp(src, fl);
    const input = scope.querySelector(`input[name="alg"][value="${value}"]`);
    // The card the user clicks: the label carrying this mode, found by its input or its name.
    const card = (input && input.closest("label")) ||
      [...scope.querySelectorAll("label")].find((l) => re.test(l.textContent));
    const target = card && window.__shown(card) ? card : input;
    if (!target) return false;
    target.click();
    return true;
  }, value, labelRe.source, labelRe.flags);
  if (!ok) throw new Error(`no control for the ${value} mode`);
  await page.waitForFunction((v) => {
    const i = document.querySelector(`input[name="alg"][value="${v}"]`);
    return !i || i.checked;
  }, { timeout: 5000 }, value).catch(() => { throw new Error(`${value} did not become the selected mode`); });
}

async function setOptionsOpen(page, open) {
  await page.evaluate((open) => {
    const d = document.querySelector("#algDetails");
    if (!d) return;
    const isOpen = d.tagName === "DETAILS" ? d.open : window.__shown(document.querySelector("#algCards"));
    if (isOpen === open) return;
    const s = document.querySelector("#algSummary") || d.querySelector("summary");
    if (s) s.click();
    else if (d.tagName === "DETAILS") d.open = open;
  }, open);
  await settle(page, 100);
}

const liveStatusIs = (page, want, timeout) => page.waitForFunction((w) =>
  ["#chatStatus", "#status"].some((s) => (document.querySelector(s)?.textContent || "").trim().toLowerCase() === w),
{ timeout }, want);

async function waitGate(page) {
  await waitShown(page, "#verify", 45000);
  await page.waitForFunction(() => (document.querySelector("#safetyNumber")?.textContent || "").trim().length > 10,
    { timeout: 15000 }).catch(() => { throw new Error("#safetyNumber stayed empty"); });
}

async function liveSend(from, msg, to) {
  await typeInto(from, "#text", msg);
  await click(from, "#send");
  await waitIncludes(to, "#log", msg, 20000);
}

// ---------------------------------------------------------------------------
// contact sheet + summary

// Width/height from the PNG header, so the sheet shows each shot at its CSS
// size (a 2x phone PNG at half its pixels) and an overflowing phone shot keeps
// its true, wider scale instead of being squeezed into 390px.
function pngSize(path) {
  const b = readFileSync(path);
  return { w: b.readUInt32BE(16), h: b.readUInt32BE(20) };
}

function writeContactSheet() {
  const esc = (s) => String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
  const count = (s) => PLAN.filter((p) => p.state === s).length;
  const toc = PLAN.map((p) =>
    `<li class="${p.state}"><a href="#s${p.n}">${p.n}-${esc(p.id)}</a> <span class="st">${p.state}</span></li>`).join("\n");
  const sections = PLAN.map((p) => {
    const figs = SIZES.map((s) => {
      const file = `${p.n}-${p.id}-${s.name}.png`;
      if (!existsSync(join(outDir, file))) {
        return `<figure class="${s.name} none"><div class="ph">not captured</div><figcaption>${esc(file)}</figcaption></figure>`;
      }
      const { w, h } = pngSize(join(outDir, file));
      const dpr = s.vp.deviceScaleFactor;
      const cssW = Math.round(w / dpr), cssH = Math.round(h / dpr);
      return `<figure class="${s.name}" style="--w:${cssW}px"><a href="${esc(file)}"><img src="${esc(file)}" width="${cssW}" height="${cssH}" alt="${esc(p.what)} — ${s.name}" loading="lazy"></a>` +
        `<figcaption>${esc(file)} · ${esc(s.label)} · ${esc((p.modes && p.modes[s.name]) || (p.fullPage ? "full page" : "viewport"))}</figcaption></figure>`;
    }).join("\n");
    return `<section id="s${p.n}" class="${p.state}">
<h2><span class="n">${p.n}</span> ${esc(p.id)} <span class="st">${p.state}</span></h2>
<p class="what">${esc(p.what)}</p>
${p.note ? `<p class="note">${esc(p.note)}</p>` : ""}
<div class="pair">
${figs}
</div>
</section>`;
  }).join("\n");
  const html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>secure-chat screenshots</title>
<style>
  :root { --bg: #f3f4f6; --card: #ffffff; --fg: #111827; --muted: #4b5563; --line: #d1d5db;
          --ok: #166534; --skip: #92400e; --miss: #b91c1c; }
  * { box-sizing: border-box; }
  body { margin: 0; padding: 24px 16px 64px; background: var(--bg); color: var(--fg);
         font: 15px/1.5 system-ui, -apple-system, "Segoe UI", sans-serif; }
  header, section { max-width: 1760px; margin: 0 auto 24px; }
  h1 { font-size: 1.4rem; margin: 0 0 4px; }
  .meta { color: var(--muted); margin: 0 0 12px; }
  ol.toc { columns: 3 16rem; margin: 0; padding-left: 1.4rem; }
  ol.toc a { color: inherit; }
  .st { font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.04em; font-weight: 600; }
  .captured .st { color: var(--ok); } .skipped .st { color: var(--skip); } .missed .st { color: var(--miss); }
  section { background: var(--card); border: 1px solid var(--line); border-radius: 10px; padding: 16px; }
  h2 { font-size: 1.05rem; margin: 0 0 2px; font-family: ui-monospace, Menlo, Consolas, monospace; }
  h2 .n { color: var(--muted); }
  .what { margin: 0 0 4px; color: var(--muted); }
  .note { margin: 0 0 8px; padding: 6px 10px; border-left: 3px solid var(--skip); background: #fffbeb; }
  .missed .note { border-color: var(--miss); background: #fef2f2; }
  .pair { display: flex; gap: 16px; align-items: flex-start; flex-wrap: wrap; margin-top: 12px; }
  figure { margin: 0; }
  figure.phone { flex: 0 0 var(--w, 390px); max-width: 100%; }
  figure.desktop { flex: 1 1 640px; min-width: 0; max-width: var(--w, 1280px); }
  figure.none { flex-basis: 390px; }
  figure img { display: block; width: 100%; height: auto; border: 1px solid var(--line); border-radius: 6px; background: #0d1117; }
  figcaption { font-size: 0.8rem; color: var(--muted); margin-top: 4px; font-family: ui-monospace, Menlo, Consolas, monospace; overflow-wrap: anywhere; }
  .ph { display: grid; place-items: center; min-height: 160px; border: 1px dashed var(--line); border-radius: 6px; color: var(--muted); }
</style>
</head>
<body>
<header>
<h1>secure-chat — every screen, phone and desktop</h1>
<p class="meta">Run ${esc(RUN)} · ${esc(new Date().toISOString())} · app ${esc(APP)} · relay ${esc(relayVersion)} ·
${count("captured")} captured, ${count("skipped")} skipped, ${count("missed")} missed of ${PLAN.length} states.
Phone 390×844 at 2×, desktop 1280×800 at 1×, both shown at CSS size; full-page shots unless the caption says viewport,
so a phone shot wider than 390 px means the page overflows horizontally. Click an image for full size.</p>
<ol class="toc">
${toc}
</ol>
</header>
${sections}
</body>
</html>
`;
  writeFileSync(join(outDir, "index.html"), html);
}

async function finish(reason = "") {
  if (finished) return;
  finished = true;
  for (const p of PLAN) {
    if (p.state === "pending") mark(p.id, "missed", reason || "not reached");
  }
  try { writeContactSheet(); } catch (e) { console.log("  could not write index.html: " + firstLine(e)); }
  await Promise.race([browser.close().catch(() => {}), sleep(5000)]);

  const missedList = PLAN.filter((p) => p.state === "missed");
  const skippedList = PLAN.filter((p) => p.state === "skipped");
  const pngs = PLAN.reduce((n, p) => n + p.files.length, 0);
  console.log("\n=== summary ===");
  for (const e of errors.slice(0, 5)) console.log("  [console]", e.slice(0, 200));
  console.log(`  ${PLAN.length - missedList.length - skippedList.length}/${PLAN.length} states captured, ${pngs} PNGs, ${secs()}`);
  for (const p of skippedList) console.log(`  skipped ${p.n}-${p.id}: ${p.note}`);
  for (const p of missedList) console.log(`  MISSED  ${p.n}-${p.id}: ${p.note}`);
  console.log(`  contact sheet: ${join(outDir, "index.html")}\n`);
  process.exit(missedList.length ? 1 : 0);
}

// A safety net only: every wait above has its own timeout, so a normal run
// finishes long before this.
const HARD_LIMIT_MS = 6 * 60 * 1000;
setTimeout(() => {
  console.log(`\n  hard time limit (${HARD_LIMIT_MS / 60000} min) reached — stopping`);
  finish("not reached before the hard time limit");
}, HARD_LIMIT_MS).unref();

// ===========================================================================
// the run

let alice, others = null;
try {
  alice = await openTab("alice");
} catch (e) {
  console.log("  cannot open the app: " + firstLine(e));
  await finish("the app did not load: " + firstLine(e));
}
alice.username = `${aliceSpec.usernamePrefix}-${RUN}`;

// Bob and carol are pure setup: onboard them while alice's first screens are
// captured.
const othersP = Promise.all([onboard(bobSpec, "bob"), onboard(carolSpec, "carol")]);
othersP.catch(() => {}); // awaited (and reported) in the "agents" setup below

// ---- 01-03: identity screen ---------------------------------------------------

await step("first-run", async () => {
  const p = alice.page;
  await ensureIdentityScreen(p);
  // The app replaces its "Checking for an identity…" placeholder on first render.
  await p.waitForFunction(() => !/checking/i.test(document.querySelector("#idStatus")?.textContent || ""),
    { timeout: 10000 }).catch(() => {});
  await waitShown(p, "#idCreate", 10000);
  await capture(p, "first-run");
});

await step("drawer-open", async () => {
  const p = alice.page;
  if (!(await p.$("#menuBtn")) || !(await shown(p, "#menuBtn"))) {
    skip("drawer-open", "#menuBtn is missing or hidden in this version — there is no drawer to open");
    return;
  }
  await click(p, "#menuBtn");
  await p.waitForFunction(() => window.__shown(document.querySelector("#drawer")) ||
    [...document.querySelectorAll("[data-view]")].some((el) => window.__shown(el)), { timeout: 10000 })
    .catch(() => { throw new Error("#menuBtn opened nothing visible"); });
  await capture(p, "drawer-open");
  await closeDrawer(p);
});

await step("identity-unlocked", async () => {
  const p = alice.page;
  await ensureIdentityScreen(p);
  await createIdentity(p, aliceSpec.passphrase);
  await registerUsername(p, alice.username);
  alice.handle = await handleOf(p);
  setup.alice = true;
  const loggedIn = await waitLoggedIn(p);
  console.log(`  [${secs()}] alice ready: ${alice.handle}`);
  await waitShown(p, "#idFingerprint", 5000);
  await waitShown(p, "#account", 5000);
  await capture(p, "identity-unlocked", loggedIn ? "" : "the automatic directory login was not confirmed within 20 s");
});
if (setup.alice !== true) setup.alice = byId["identity-unlocked"].note || "identity not created";

// ---- 04-06: room setup ---------------------------------------------------------

await step("room-setup", async () => {
  await gotoRoomScreen(alice.page);
  await capture(alice.page, "room-setup");
});

await step("room-security-options", async () => {
  const p = alice.page;
  await gotoRoomScreen(p);
  await setOptionsOpen(p, true);
  await waitShown(p, "#algCards", 10000);
  await capture(p, "room-security-options");
});

await step("room-otp-selected", async () => {
  const p = alice.page;
  await gotoRoomScreen(p);
  await setOptionsOpen(p, true);
  await pickMode(p, "OTP", /one-time pad/i);
  await waitShown(p, "#otpPanel", 10000);
  await capture(p, "room-otp-selected");
});

// Back to the default mode for the live room at the end.
try {
  if (await shown(alice.page, "#scrRoom")) {
    await setOptionsOpen(alice.page, true);
    await pickMode(alice.page, "DHKE", /^\s*DHKE/i);
    await setOptionsOpen(alice.page, false);
  }
} catch (e) {
  console.log("  (could not reset the mode to DHKE: " + firstLine(e) + ")");
}

// ---- setup: the other agents, contacts and mail ----------------------------------

await runSetup("agents", async () => {
  const [bob, carol] = await othersP;
  others = { bob, carol };
});

await runSetup("contacts", async () => {
  req("alice", "agents");
  const { bob, carol } = others;
  // Alice adds bob BEFORE he writes, so his mail files under his name rather
  // than as an unknown sender. Bob adds alice at the same time.
  await Promise.all([
    addContact(alice.page, bob.handle, bob.username),
    addContact(bob.page, alice.handle, alice.username),
  ]);
  // Carol is the stranger: she adds alice and writes; alice never adds her.
  const carolWrites = (async () => {
    await addContact(carol.page, alice.handle, alice.username);
    await openChatWith(carol.page, alice.username);
    for (const m of MSG.carol) await sendChat(carol.page, m);
  })();
  const bobWrites = (async () => {
    await openChatWith(bob.page, alice.username);
    for (const m of MSG.bob) await sendChat(bob.page, m);
  })();
  // Alice verifies bob in person (two confirm() dialogs, both accepted).
  await markVerified(alice.page, bob.username);
  await Promise.all([bobWrites, carolWrites]);

  // Delivery rides alice's mailbox poll (every 6 s). The Chats view re-renders
  // on arrival, so wait there.
  await view(alice.page, "chats");
  await pollUntil(async () => {
    const list = await chatsOf(alice.page);
    if (list === null) {
      const t = await text(alice.page, "#chatList");
      return t.includes(bob.username) && (await alice.page.evaluate(() =>
        document.querySelector("#chatList")?.children.length || 0)) >= 2;
    }
    const fromBob = list.find((c) => c.u === bob.username);
    const all = list.flatMap((c) => c.texts);
    return !!fromBob && MSG.bob.every((m) => fromBob.texts.includes(m)) && MSG.carol.every((m) => all.includes(m));
  }, 90000, "alice did not receive bob's and carol's messages (is she logged in to the directory?)");
  console.log(`  [${secs()}] alice received mail from bob and from the stranger`);
});

// ---- 07-08: users ---------------------------------------------------------------

let lockedTab = null;
await step("users-locked", async () => {
  req("alice");
  lockedTab = await openTab("alice-2nd-tab", alice.ctx);
  await view(lockedTab.page, "users");
  await waitShown(lockedTab.page, "#usersLocked", 15000);
  await waitShown(lockedTab.page, "#usersUnlockPass", 5000);
  await capture(lockedTab.page, "users-locked");
});
// Close it, as two-user-flow.mjs closes its invite tab: while it is open it is
// the front tab of alice's window and her real tab runs in the background.
if (lockedTab) {
  await lockedTab.page.close().catch(() => {});
  lockedTab = null;
}

await step("users-unlocked", async () => {
  req("contacts");
  const p = alice.page;
  const { bob, carol } = others;
  await view(p, "users");
  await waitShown(p, "#usersUnlocked", 15000);
  await waitIncludes(p, "#myHandleText", alice.username, 10000);
  await waitIncludes(p, "#userList", bob.username, 10000);
  // The stranger is listed under a key-derived name; the handle she sent is
  // shown only as a claim.
  const claimShown = await p.waitForFunction((c) =>
    (document.querySelector("#userList")?.textContent || "").includes(c), { timeout: 10000 }, carol.username)
    .then(() => true, () => false);
  // Row fingerprints are computed asynchronously ("fingerprint: …" first).
  await p.waitForFunction(() => !(document.querySelector("#userList")?.textContent || "").includes("…"),
    { timeout: 5000 }).catch(() => {});
  await capture(p, "users-unlocked", claimShown ? "" : "the stranger's claimed name did not appear in #userList");
});

// ---- 22-23: contact profile over Users ---------------------------------------------

async function openProfile(p, listSel, needle, sel) {
  const ok = await p.evaluate((l, n, s) => {
    const row = [...document.querySelector(l).children].find((el) => el.textContent.includes(n));
    const b = row && row.querySelector(s);
    if (!b) return false;
    b.click();
    return true;
  }, listSel, needle, sel);
  if (!ok) throw new Error(`no ${sel} for ${needle} in ${listSel}`);
  await waitShown(p, "#contactSheet", 5000);
  await p.waitForFunction(() => !/^…$/.test(document.querySelector("#contactFingerprint").textContent),
    { timeout: 10000 }).catch(() => {});
}
const closeProfile = (p) => p.evaluate(() => {
  if (!document.querySelector("#contactSheet").hidden) document.querySelector("#contactClose").click();
});

await step("contact-profile", async () => {
  req("contacts");
  const p = alice.page;
  await view(p, "users");
  await openProfile(p, "#userList", others.bob.username, ".u-open");
  await capture(p, "contact-profile");
  await closeProfile(p);
});

await step("contact-profile-stranger", async () => {
  req("contacts");
  const p = alice.page;
  await openProfile(p, "#userList", others.carol.username, ".u-open");
  const label = await text(p, "#contactHandleLabel");
  await capture(p, "contact-profile-stranger", label === "Handle they claim" ? "" : `handle label reads ${JSON.stringify(label)}`);
  await closeProfile(p);
});

// ---- 09-12: chats ---------------------------------------------------------------

await step("chats-list", async () => {
  req("contacts");
  const p = alice.page;
  await view(p, "chats");
  if (await shown(p, "#chatConvo") && await shown(p, "#chatBack") && !(await shown(p, "#chatList"))) {
    await click(p, "#chatBack");
  }
  await waitShown(p, "#chatList", 15000);
  await waitIncludes(p, "#chatList", others.bob.username, 15000);
  await capture(p, "chats-list");
});

await step("chat-conversation", async () => {
  req("contacts");
  const p = alice.page;
  const bob = others.bob;
  if (!(await clickRow(p, "#chatList", bob.username))) throw new Error(`no row for ${bob.username} in #chatList`);
  if (!(await shownWithin(p, "#chatConvo", 3000))) {
    // A row whose click target is a control inside it rather than the row.
    await p.evaluate((u) => {
      const row = [...document.querySelector("#chatList").children].find((el) => el.textContent.includes(u));
      const inner = row && row.querySelector("button, a, [role=button]");
      if (inner) inner.click();
    }, bob.username);
  }
  await waitShown(p, "#chatConvo", 15000);
  await waitIncludes(p, "#chatLog", MSG.bob[0], 15000);
  for (const m of MSG.alice) await sendChat(p, m);
  await capture(p, "chat-conversation");
});

await step("contact-profile-convo", async () => {
  req("contacts");
  const p = alice.page;
  if (!(await shown(p, "#chatConvo"))) throw new Error("no open conversation");
  await click(p, "#chatPeer");
  await waitShown(p, "#contactSheet", 5000);
  await p.waitForFunction(() => !/^…$/.test(document.querySelector("#contactFingerprint").textContent),
    { timeout: 10000 }).catch(() => {});
  const msg = await shown(p, "#contactMessage");
  await capture(p, "contact-profile-convo", msg ? "#contactMessage is shown" : "");
  await closeProfile(p);
});

let proposalSent = false;
await step("chat-mode-proposal-sent", async () => {
  req("contacts");
  const b = others.bob.page;
  if (!(await shown(b, "#chatConvo"))) await openChatWith(b, alice.username);
  const offered = await b.evaluate(() => {
    const s = document.querySelector("#chatModeSel");
    return !!s && window.__shown(s) && [...s.options].some((o) => o.value === "AES256");
  });
  if (!offered) {
    const why = "#chatModeSel is missing, hidden, or offers no AES256 mode — no proposal to trigger";
    skip("chat-mode-proposal-sent", why);
    skip("chat-mode-proposal-received", why);
    return;
  }
  // Bob proposes; the prompt() for the shared chat passphrase is answered by the
  // dialog handler. Alice is the receiving side (12).
  await b.select("#chatModeSel", "AES256");
  await b.waitForFunction(() => {
    const el = document.querySelector("#chatPending");
    return window.__shown(el) && el.textContent.trim().length > 0;
  }, { timeout: 30000 }).catch(async () => {
    throw new Error(`no pending banner on the proposing side: ${JSON.stringify(await text(b, "#chatHint"))}`);
  });
  proposalSent = true;
  await capture(b, "chat-mode-proposal-sent");
});

await step("chat-mode-proposal-received", async () => {
  if (!proposalSent) throw new Error("the proposal was never sent (see 11)");
  const p = alice.page;
  // Arrives with alice's next mailbox poll (every 6 s).
  await p.waitForFunction(() => {
    const el = document.querySelector("#chatPending");
    return window.__shown(el) && el.textContent.trim().length > 0;
  }, { timeout: 60000 }).catch(() => { throw new Error("the proposal never reached alice (60s)"); });
  await capture(p, "chat-mode-proposal-received");
});

// ---- 13: profile ----------------------------------------------------------------

await step("profile", async () => {
  req("alice");
  const p = alice.page;
  await view(p, "profile");
  await waitShown(p, "#profileUnlocked", 15000);
  await p.waitForFunction(() => (document.querySelector("#profileFingerprint")?.textContent || "").trim().length > 20,
    { timeout: 15000 }).catch(() => { throw new Error("#profileFingerprint never filled in"); });
  await p.waitForFunction(() => (document.querySelector("#profileStatus")?.children.length || 0) > 0,
    { timeout: 5000 }).catch(() => {});
  const qr = await shownWithin(p, "#profileQr", 5000);
  await capture(p, "profile", qr ? "" : "#profileQr is not visible");
});

// ---- 14-20: live room -------------------------------------------------------------

const live = {};
await step("live-owner-connected", async () => {
  req("alice");
  const p = alice.page;
  await view(p, "live");
  await gotoRoomScreen(p);
  await p.evaluate(() => { const c = document.querySelector("#contact"); if (c) c.value = ""; });
  let code = await p.evaluate(() => (document.querySelector("#room")?.value || "").trim());
  if (!/^[0-9a-f]{64}$/.test(code)) {
    await click(p, "#gen");
    code = await p.evaluate(() => (document.querySelector("#room")?.value || "").trim());
  }
  await click(p, "#connect");
  // Anchored: /connected/ would also match "disconnected" (room-admission.mjs).
  await liveStatusIs(p, "connected", 30000)
    .catch(async () => { throw new Error(`owner never connected: ${JSON.stringify(await text(p, "#roomHint"))}`); });
  live.code = code;
  await waitText(p, "#log", /you decide who is let in/i, 5000).catch(() => {});
  await capture(p, "live-owner-connected");
});

await step("live-guest-waiting", async () => {
  if (!live.code) throw new Error("the owner never opened a room (see 14)");
  req("agents");
  const b = others.bob.page;
  await view(b, "live");
  await gotoRoomScreen(b);
  await typeInto(b, "#room", live.code);
  await click(b, "#connect");
  await waitText(b, "#chatStatus", /waiting for approval/i, 30000);
  live.guestWaiting = true;
  await capture(b, "live-guest-waiting");
});

await step("live-admission-prompt", async () => {
  if (!live.guestWaiting) throw new Error("no guest is waiting (see 15)");
  const p = alice.page;
  await waitShown(p, "#admit", 30000);
  await p.waitForFunction(() => (document.querySelector("#admitFingerprint")?.textContent || "").trim().length > 20,
    { timeout: 15000 }).catch(() => { throw new Error("#admitFingerprint stayed empty"); });
  await capture(p, "live-admission-prompt");
});

await step("live-verify-owner", async () => {
  if (!live.guestWaiting) throw new Error("no guest is waiting (see 15)");
  const p = alice.page, b = others.bob.page;
  // app.js ignores admit/deny in the prompt's first 500 ms (tap-through guard).
  await sleep(600);
  await click(p, "#admitOk");
  await Promise.all([waitGate(p), waitGate(b)]);
  live.gates = true;
  await capture(p, "live-verify-owner");
});

await step("live-verify-guest", async () => {
  if (!live.gates) throw new Error("the safety-number gate never appeared (see 17)");
  await capture(others.bob.page, "live-verify-guest");
});

await step("live-chat-connected", async () => {
  if (!live.gates) throw new Error("the safety-number gate never appeared (see 17)");
  const p = alice.page, b = others.bob.page;
  await click(p, "#verifyOk");
  await click(b, "#verifyOk");
  await Promise.all([p, b].map((pg) => pg.waitForFunction(() => {
    const t = document.querySelector("#text");
    return !!t && !t.disabled && window.__shown(t);
  }, { timeout: 20000 }).catch(() => { throw new Error("messaging never unlocked"); })));
  await liveSend(b, LIVE.bob[0], p);
  await liveSend(p, LIVE.alice[0], b);
  await liveSend(b, LIVE.bob[1], p);
  await capture(p, "live-chat-connected");
});

await step("live-disconnected", async () => {
  if (!live.code) throw new Error("the owner never opened a room (see 14)");
  const p = alice.page;
  await click(p, "#disconnect");
  await liveStatusIs(p, "disconnected", 15000).catch(() => { throw new Error("status never read \"disconnected\""); });
  await capture(p, "live-disconnected");
});

// ---- 21: error ------------------------------------------------------------------------

await step("users-unlock-wrong-passphrase", async () => {
  req("alice");
  // A fresh second tab again (locked, same storage); alice's real tab has no
  // more work to do, so it may sit in the background now.
  const q = (await openTab("alice-3rd-tab", alice.ctx)).page;
  await view(q, "users");
  await typeInto(q, "#usersUnlockPass", "definitely not the passphrase");
  await click(q, "#usersUnlock");
  await q.waitForFunction(() => {
    const t = (document.querySelector("#usersUnlockStatus")?.textContent || "").trim();
    return t.length > 0 && !/unlocking/i.test(t);
  }, { timeout: 30000 }).catch(() => { throw new Error("#usersUnlockStatus never reported the failure"); });
  const said = await text(q, "#usersUnlockStatus");
  await capture(q, "users-unlock-wrong-passphrase", /wrong/i.test(said) ? "" : `status reads ${JSON.stringify(said)}`);
});

await finish();
