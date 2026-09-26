// app.js's ONE-TIME-PAD paths, executed — Package 3 (fix/atrest-android).
//
// app-behaviour.test.mjs drives app.js against a hostile relay in the
// handshake modes; nothing drove an OTP session, so the three OTP ordering
// findings of Package 3 had no executable control. This file imports app.js
// into its own DOM stub (a module is evaluated once per process, so it cannot
// share app-behaviour's instance) and plays both the relay and the peer:
//
//   ROUND-3 F-2        a received OTP message is shown only AFTER its receipt
//                      is on disk (persist before display)
//   F-ATREST-002 res.  an exported pad file is handed out only AFTER the
//                      "exported" latch is recorded (latch before download)
//   F-CRYPTO-014       the one-tab-per-pad lock is Web Locks or nothing: no
//                      localStorage lease fallback
//
// Same scope note as app-behaviour: the stub is not a browser. What is proven
// is app.js's DECISIONS and ORDER. Run: node app-otp.test.mjs
import assert from "node:assert";
import { fakeIdb } from "./fake-idb.test.mjs"; // package 3b: IndexedDB for node
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { installDom, El } from "./dom-stub.test.mjs";
import { makeCipher, bufToB64 } from "./crypto.js";
import { freshNonce } from "./auth.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOM = "b".repeat(64);
const PAD_PASS = "pad passphrase for the tests";

const store = new Map();
globalThis.localStorage = {
  getItem: (k) => (store.has(k) ? store.get(k) : null),
  setItem: (k, v) => { store.set(k, String(v)); },
  removeItem: (k) => { store.delete(k); },
  key: (i) => [...store.keys()][i] ?? null,
  get length() { return store.size; },
  clear: () => store.clear(),
};
globalThis.setInterval = () => 0;
globalThis.clearInterval = () => {};
globalThis.fetch = async () => new Response("{}", { status: 404 });

const dom = installDom(join(HERE, "index.html"));
dom.body.appendChild(dom.el("tabbar"));
dom.seedAlgRadios(["DHKE", "AES256", "PQKEM", "OTP"], "DHKE");
dom.seedNavItems(["live", "chats", "users", "profile"]);
dom.seedChild("scrChat", "div", "topbar");
for (const id of ["usersLocked", "chatsLocked"]) dom.seedChild(id, "p", "hint");
// The username field's row (app.js hides it with `closest(".row")`): without it
// showIdentityUnlocked throws, and an identity unlock here would never finish.
{ const row = new El("div"); row.className = "row"; row.appendChild(dom.el("username")); }

// Web Locks, modelled with the one property this file is about: `ifAvailable`
// answers null while the name is held (dom-stub's version always grants).
const held = new Set();
const webLocks = {
  request(name, opts, fn) {
    if (held.has(name) && opts && opts.ifAvailable) return Promise.resolve(fn(null));
    held.add(name);
    return Promise.resolve(fn({ name })).finally(() => held.delete(name));
  },
};
const setLocks = (locks) => { globalThis.navigator = { ...globalThis.navigator, locks }; };
setLocks(webLocks);

// Downloads: app.js hands a file out through an object URL + <a>.click().
let downloads = 0;
const realObjectURL = URL.createObjectURL;
URL.createObjectURL = (b) => { downloads++; return realObjectURL.call(URL, b); };

// A native floor, as in the Android app (fix round 2: the consent and warning
// wordings below exist only where a floor exists). Monotone, and deletable by
// the test the way a file-level attacker deletes a prefs entry.
const floors = new Map();
// Package 4 (F-ATREST-008): identity-floor bumps are recorded with the identity
// blob stored AT THAT MOMENT (the floor must follow the stored blob, never lead
// it), and one can be made to fail the way a failed commit() does.
const identityBumps = [];
let failIdentityBumps = 0;
globalThis.__SECURE_CHAT_PAD_FLOOR__ = Object.freeze({
  read: (id) => (floors.has(id) ? floors.get(id) : -1),
  bump: (id, v) => {
    if (id.startsWith("identity:")) {
      identityBumps.push({ id, v, blob: store.get("sc.identity.v1"), durableBlob: fakeIdb.getItem("sc.identity.v1") });
      if (failIdentityBumps > 0) { failIdentityBumps--; return -3; }
    }
    const cur = floors.has(id) ? floors.get(id) : -1;
    const n = cur === -1 ? v : (v > cur ? v : cur);
    floors.set(id, n);
    return n;
  },
});

await import("./app.js");
const otp = await import("./otp.js"); // the same module instance app.js uses
const otpB = await import("./otp.js?tab=B"); // package 6 round 3: ANOTHER TAB — its own module state (wmCache, durHigh), sharing storage and locks

const tick = () => new Promise((r) => setTimeout(r, 0));
const settle = async (n = 40) => { for (let i = 0; i < n; i++) await new Promise((r) => setTimeout(r, 5)); };
const lines = () => dom.lines();
const said = (re) => lines().some((l) => re.test(l));
const count = (re) => lines().filter((l) => re.test(l)).length;
const anyHint = (re) => ["hint", "roomHint", "idHint"].some((id) => re.test(dom.el(id).textContent));
const pack = (o) => bufToB64(new TextEncoder().encode(JSON.stringify(o)));

// A pad this device generated (role 0), and the peer's copy of the same bytes.
const pad = await otp.generatePad({ label: "live", totalBytes: 8192, fingerBytes: new Uint8Array(0) });
const peerPad = { bytes: pad.bytes.slice(), role: 1, regionSize: pad.regionSize, sendOffset: 0, recvHighWater: 0 };
await otp.saveNewPad(pad, PAD_PASS);
const peer = makeCipher("OTP", ROOM, { pad: peerPad });

let current = null;
async function otpConnect(padId = pad.padId) {
  if (current && current.readyState === 1) await dom.el("disconnect").click();
  const room = dom.el("room");
  room.value = ROOM;
  await room.dispatch("input");
  dom.selectAlg("OTP");
  dom.el("otpSelect").value = padId;
  dom.el("otpPass").value = PAD_PASS;
  const before = dom.socket();
  await dom.el("connect").click();
  const ws = dom.socket();
  if (ws === before) return null; // connect() refused before opening a socket
  ws.open();
  await tick();
  await ws.deliver({ type: "joined", role: "owner" });
  await ws.deliver({ type: "key", room: ROOM, alg: "OTP", payload: pack({ hello: true, n: freshNonce(), reply: false }) });
  await settle(10);
  current = ws;
  return ws;
}

// ---- fixture: a live OTP session receives and records ------------------------
{
  const ws = await otpConnect();
  assert.ok(ws, "fixture: the OTP session opened a socket");
  assert.ok(anyHint(/one-time-pad encrypted/), "fixture: the OTP session is ready: " + dom.el("hint").textContent);
  await ws.deliver({ type: "msg", room: ROOM, alg: "OTP", payload: await peer.encrypt("hello one") });
  await settle(10);
  assert.ok(said(/hello one/), "fixture: a received OTP message is shown");
  const u = await otp.unlockPad(pad.padId, PAD_PASS);
  assert.ok(u.record.recvHighWater > 0, "fixture: …and its receipt is on disk");
  console.log("OK  fixture: an OTP session receives, shows and records a message (executed)");
}

// ---- ROUND-3 F-2: persist BEFORE display --------------------------------------
// The receive path used to show the text and then persist recvHighWater. A
// crash or a failed save in between left the user having read a frame the pad
// still counted as undelivered, so after a reload the same frame
// re-authenticated as new. Here the save fails: the message must NOT appear.
{
  const ws = current;
  const realSet = localStorage.setItem;
  localStorage.setItem = (k, v) => {
    if (k.startsWith("sc.otp.pad.v1.")) throw new Error("QuotaExceededError: disk full");
    return realSet(k, v);
  };
  try {
    await ws.deliver({ type: "msg", room: ROOM, alg: "OTP", payload: await peer.encrypt("hello two") });
    await settle(10);
  } finally {
    localStorage.setItem = realSet;
  }
  assert.ok(!said(/hello two/),
    "ROUND-3 F-2: a message whose receipt could not be saved must not be displayed (persist before display)");
  assert.ok(said(/could not save one-time-pad progress/), "…the session says why it stopped");
  assert.strictEqual(ws.readyState, 3, "…and it is closed");
  console.log("OK  ROUND-3 F-2: an OTP message is displayed only after its receipt is persisted (executed)");
}

// ---- package 6 (2026-07-26 Info): weak pad / transfer passphrases are warned about, never refused ----
{
  const WEAK = /Weak passphrase: .*offline.*A warning only/;
  // Generate with a weak pad passphrase: the pad is made, and the status says why the passphrase is weak.
  const before = otp.listPads().length;
  dom.el("otpNewPass").value = "1234"; // OTP sheets: New pad reads its own field
  dom.el("otpLabel").value = "weakpad";
  dom.el("otpSize").value = "8192";
  await dom.el("otpGenerate").click();
  await settle(10);
  const st = dom.el("otpStatus");
  assert.match(st.textContent, /^Generated \+ encrypted pad "weakpad"/, "a weak pad passphrase does not block generation: " + st.textContent);
  assert.match(st.textContent, /Pad passphrase — Weak passphrase: it is only digits/, "…and the status says the pad passphrase is weak");
  assert.ok(WEAK.test(st.textContent) && /\berr\b/.test(st.className), "…as a warning");
  assert.ok(otp.listPads().some((m) => m.label === "weakpad"), "…and the pad exists " + before + " " + JSON.stringify(otp.listPads().map((m) => m.label)));
  // Export it under a weak TRANSFER passphrase: the file is handed out, with the warning.
  const weakId = otp.listPads().find((m) => m.label === "weakpad").padId;
  dom.el("otpSelect").value = weakId;
  dom.el("otpXferPass").value = "hunter2";
  const d0 = downloads;
  await dom.el("otpExport").click();
  assert.strictEqual(downloads, d0 + 1, "a weak transfer passphrase does not block the export (one file is handed out)");
  assert.match(st.textContent, /^Exported\. .*Transfer passphrase — Weak passphrase: it is shorter than 12 characters/, "…and says so: " + st.textContent);
  // Import a pad under a weak pad passphrase: imported, with the warning.
  const foreign = await otp.generatePad({ label: "imported-weak", totalBytes: 8192, fingerBytes: new Uint8Array(0) });
  const file = await otp.exportPad(foreign, "transfer passphrase");
  dom.el("otpImportXfer").value = "transfer passphrase";
  dom.el("otpImportPass").value = "aaaaaaaaaaaaaaaa";
  dom.el("otpFile").files = [{ text: async () => file }];
  await dom.el("otpFile").dispatch("change");
  await settle(10);
  assert.match(st.textContent, /^Imported \+ encrypted pad "imported-weak".*Pad passphrase — Weak passphrase: it is one character repeated/,
    "a weak pad passphrase on import is accepted and warned about: " + st.textContent);
  // Control: strong passphrases, no warning.
  dom.el("otpNewPass").value = PAD_PASS;
  dom.el("otpLabel").value = "strongpad";
  await dom.el("otpGenerate").click();
  await settle(10);
  assert.match(st.textContent, /^Generated \+ encrypted pad "strongpad"/);
  assert.ok(!/Weak passphrase/.test(st.textContent) && !/\berr\b/.test(st.className), "control: a strong pad passphrase draws no warning");
  console.log("OK  package 6: weak pad and transfer passphrases are accepted with a warning; strong ones draw none (executed)");
}

// ---- package 6 fix round (MEDIUM): one pad is exported ONCE ------------------
// (a) Two clicks, neither awaited (a double click / double tap), and a second
//     click while the first export's KDF runs: exactly one file.
// (b) Another tab exports the pad this page has cached as "not exported":
//     this page's Export must see the stored state, warn, and hand out nothing.
{
  const st = dom.el("otpStatus");
  const fresh = async (label) => {
    const p = await otp.generatePad({ label, totalBytes: 8192, fingerBytes: new Uint8Array(0) });
    await otp.saveNewPad(p, PAD_PASS);
    dom.el("otpSelect").value = p.padId;
    dom.el("otpPass").value = PAD_PASS;
    dom.el("otpXferPass").value = "transfer passphrase";
    return p;
  };
  // (a) same instant
  await fresh("double-a");
  let d0 = downloads;
  const lockNames = [];
  const realRequest = navigator.locks.request;
  navigator.locks.request = function (name, ...rest) { lockNames.push(name); return realRequest.call(this, name, ...rest); };
  let firstDone = false;
  const c1 = dom.el("otpExport").click().then(() => { firstDone = true; });
  assert.strictEqual(dom.el("otpExport").disabled, true, "the Export button is disabled while an export runs");
  const c2 = dom.el("otpExport").click();
  await c2;
  assert.ok(!firstDone && /already running/.test(dom.el("otpStatus").textContent),
    "the second click is refused AT ONCE by the in-flight latch (it does not queue behind the first)");
  await c1;
  navigator.locks.request = realRequest;
  await settle(10);
  assert.strictEqual(downloads, d0 + 1, `package 6 fix round: a double click exports ONE file, not ${downloads - d0}`);
  const padA = dom.el("otpSelect").value;
  assert.deepStrictEqual(lockNames.filter((n) => n.startsWith("sc.otp.export.")), ["sc.otp.export.v1." + padA],
    "the export runs under the pad's own Web Lock (a second tab waits for it)");
  // (a') 30 ms apart — the second click lands during the first export's KDF
  await fresh("double-b");
  d0 = downloads;
  const c3 = dom.el("otpExport").click();
  await new Promise((r) => setTimeout(r, 30));
  const c4 = dom.el("otpExport").click();
  await c3; await c4;
  await settle(10);
  assert.strictEqual(downloads, d0 + 1, `package 6 fix round: a second click during the export adds no file (${downloads - d0})`);
  assert.strictEqual(dom.el("otpExport").disabled, false, "…and the button is usable again afterwards");
  // (b) this page unlocks (and caches) a pad; "another tab" exports it.
  // Generate fills this page's unlock cache with the new pad (exported: false).
  dom.el("otpNewPass").value = PAD_PASS;
  dom.el("otpLabel").value = "two-tabs";
  await dom.el("otpGenerate").click();
  await settle(10);
  const p = otp.listPads().find((m) => m.label === "two-tabs");
  assert.ok(p, "fixture: the pad was generated here");
  dom.el("otpSelect").value = p.padId;
  dom.el("otpXferPass").value = "transfer passphrase";
  const other = await otpB.unlockPad(p.padId, PAD_PASS);      // tab B's own unlock
  const fileB = await otpB.exportPad(other.record, "tab b transfer");
  await otpB.markExported(other.record, other.atRest);        // tab B latches and hands out its file
  void fileB;
  // The cached-key re-read is only for the blob's own salt: a pad saved again
  // under a new salt (re-imported elsewhere) needs the passphrase again.
  await assert.rejects(otpB.unlockPad(p.padId, null, { atRest: { ...other.atRest, salt: new Uint8Array(16) } }),
    /saved again elsewhere/, "a cached key for another salt is refused with its own sentence");
  d0 = downloads;
  await dom.el("otpExport").click();
  assert.strictEqual(downloads, d0, "package 6 fix round: a pad another tab already exported is not handed out again silently");
  assert.match(st.textContent, /already exported/, "…the re-export warning appears: " + st.textContent);
  // (c) no Web Locks: no export (a second tab could not be kept out).
  {
    await fresh("no-locks");
    const realNav = globalThis.navigator;
    Object.defineProperty(globalThis, "navigator", { value: { ...realNav, locks: undefined }, configurable: true, writable: true });
    d0 = downloads;
    try {
      await dom.el("otpExport").click();
    } finally {
      Object.defineProperty(globalThis, "navigator", { value: realNav, configurable: true, writable: true });
    }
    assert.strictEqual(downloads, d0, "without Web Locks no pad file is handed out");
    assert.match(st.textContent, /no Web Locks support/, "…and it says why");
  }
  console.log("OK  package 6 fix round: an OTP pad is exported once — a double click, a click during the export and a second tab's stale cache all hand out no second file (executed)");
}

// ---- package 6 round 2 (MEDIUM, pre-existing): the OTP panel cannot redirect the live pad's saves ----
// Between Connect and the relay's `joined` (which a relay can stall for as long
// as it likes) the OTP panel stays usable. Exporting, generating or importing
// ANOTHER pad there used to overwrite the variables the live session saves
// through: the live pad stopped recording its progress (a two-time pad after a
// reload) and the other pad was saved with the live pad's offsets.
{
  const mkPad = async (label) => {
    const p = await otp.generatePad({ label, totalBytes: 8192, fingerBytes: new Uint8Array(0) });
    await otp.saveNewPad(p, PAD_PASS);
    return p;
  };
  const stored = async (id) => (await otp.unlockPad(id, PAD_PASS)).record;
  const cases = {
    async export(other) {
      dom.el("otpSelect").value = other.padId;
      dom.el("otpXferPass").value = "transfer passphrase";
      await dom.el("otpExport").click();
      return other.padId;
    },
    async generate() {
      dom.el("otpNewPass").value = PAD_PASS;
      dom.el("otpLabel").value = "made-during-connect";
      await dom.el("otpGenerate").click();
      await settle(10);
      return otp.listPads().find((m) => m.label === "made-during-connect").padId;
    },
    async import() {
      const foreign = await otp.generatePad({ label: "imported-during-connect", totalBytes: 8192, fingerBytes: new Uint8Array(0) });
      const file = await otp.exportPad(foreign, "transfer passphrase");
      dom.el("otpImportXfer").value = "transfer passphrase";
      dom.el("otpImportPass").value = PAD_PASS;
      dom.el("otpFile").files = [{ text: async () => file }];
      await dom.el("otpFile").dispatch("change");
      await settle(10);
      return foreign.padId;
    },
  };
  for (const [what, act] of Object.entries(cases)) {
    const live = await mkPad("live-" + what);
    const other = await mkPad("other-" + what);
    if (current && current.readyState === 1) await dom.el("disconnect").click();
    const room = dom.el("room");
    room.value = ROOM;
    await room.dispatch("input");
    dom.selectAlg("OTP");
    dom.el("otpSelect").value = live.padId;
    dom.el("otpPass").value = PAD_PASS;
    await dom.el("connect").click();
    const ws = dom.socket();
    ws.open();
    await tick();
    // … the relay stalls `joined`; meanwhile the user works in the OTP panel.
    const otherId = await act(other);
    await ws.deliver({ type: "joined", role: "owner" });
    await ws.deliver({ type: "key", room: ROOM, alg: "OTP", payload: pack({ hello: true, n: freshNonce(), reply: false }) });
    await settle(10);
    current = ws;
    assert.ok(anyHint(/one-time-pad encrypted/), `fixture (${what}): the live OTP session is ready`);
    for (const t of ["round2 one", "round2 two"]) {
      dom.el("text").value = t;
      await dom.el("sendForm").dispatch("submit");
      await settle(5);
    }
    assert.strictEqual(ws.sent.filter((f) => f.type === "msg").length, 2, `fixture (${what}): two messages sent`);
    const liveRec = await stored(live.padId);
    assert.ok(liveRec.sendOffset > 0,
      `round 2 (${what} during connect): the LIVE pad's progress is saved (send offset ${liveRec.sendOffset}) — else it reopens at spent keystream`);
    const otherRec = await stored(otherId);
    assert.strictEqual(otherRec.sendOffset, 0, `round 2 (${what} during connect): the other pad is untouched (send offset ${otherRec.sendOffset})`);
    await dom.el("disconnect").click();
  }
  console.log("OK  package 6 round 2: exporting, generating or importing another pad while a connection opens does not redirect the live pad's saves (executed)");
}

// ---- package 6 round 2: the session reads its pad fresh, not from the panel's cache ----
// This page generates a pad (the panel caches it at offset 0); "another tab"
// then uses it (offset advanced and saved). Connecting here must start from
// the stored offset, not the cache's 0 — that would reuse spent keystream.
{
  dom.el("otpNewPass").value = PAD_PASS;
  dom.el("otpLabel").value = "used-elsewhere";
  await dom.el("otpGenerate").click();
  await settle(10);
  const id = otp.listPads().find((m) => m.label === "used-elsewhere").padId;
  const b = await otpB.unlockPad(id, PAD_PASS);                 // tab B
  const bc = makeCipher("OTP", ROOM, { pad: b.record });
  await bc.encrypt("sent from the other tab");
  b.record.sendOffset = bc.sendOffset;
  await otpB.savePadProgress(b.record, b.atRest);
  const spent = b.record.sendOffset;
  assert.ok(spent > 0, "fixture: the other tab spent pad bytes");
  const ws = await otpConnect(id);
  assert.ok(ws, "fixture: the session opened");
  dom.el("text").value = "after the other tab";
  await dom.el("sendForm").dispatch("submit");
  await settle(5);
  const frame = JSON.parse(Buffer.from(ws.sent.filter((f) => f.type === "msg").at(-1).payload, "base64").toString());
  assert.ok(frame.o >= spent, `round 2: the session starts at the stored offset (${frame.o} ≥ ${spent}), not the panel cache's 0`);
  await dom.el("disconnect").click();
  console.log("OK  package 6 round 2: a session re-reads its pad from storage under the pad lock (executed)");
}

// ---- package 6 round 2 (F2): the export Web Lock is HELD for the whole export ----
// A lock stub that really serialises per name (and answers query()). "Another
// tab" holds the pad's export lock mid-export; this page's Export must wait
// for it (saying so), then see the other tab's export and hand out nothing.
{
  const queues = new Map();
  const heldNow = new Set();
  const queued = {
    request(name, opts, fn) {
      if (typeof opts === "function") { fn = opts; opts = {}; }
      if (opts && opts.ifAvailable && heldNow.has(name)) return Promise.resolve(fn(null));
      const run = (queues.get(name) || Promise.resolve()).then(async () => {
        heldNow.add(name);
        try { return await fn({ name }); } finally { heldNow.delete(name); }
      });
      queues.set(name, run.catch(() => {}));
      return run;
    },
    query: async () => ({ held: [...heldNow].map((name) => ({ name })) }),
  };
  const saved = globalThis.navigator.locks;
  setLocks(queued);
  try {
    const p = await otp.generatePad({ label: "two-tab-race", totalBytes: 8192, fingerBytes: new Uint8Array(0) });
    await otp.saveNewPad(p, PAD_PASS);
    dom.el("otpSelect").value = p.padId;
    dom.el("otpPass").value = PAD_PASS;
    dom.el("otpXferPass").value = "transfer passphrase";
    let finishB;
    const bMayFinish = new Promise((r) => { finishB = r; });
    let bEntered;
    const bInside = new Promise((r) => { bEntered = r; });
    const tabB = navigator.locks.request("sc.otp.export.v1." + p.padId, { mode: "exclusive" }, async () => {
      const u = await otpB.unlockPad(p.padId, PAD_PASS);
      await otpB.exportPad(u.record, "tab b transfer");
      bEntered();
      await bMayFinish;                       // tab B is mid-export (e.g. sitting in a confirm())
      await otpB.markExported(u.record, u.atRest);
    });
    await bInside;
    const d0 = downloads;
    const mine = dom.el("otpExport").click();
    await settle(20);
    assert.strictEqual(downloads, d0, "F2: while another tab holds the pad's export lock, this page hands out nothing");
    assert.match(dom.el("otpStatus").textContent, /Waiting for this pad's export in another tab/,
      "F3: …and says it is waiting for the other tab (not just a disabled button)");
    finishB();
    await tabB;
    await mine;
    await settle(10);
    assert.strictEqual(downloads, d0, "F2: after the other tab's export, this page sees it and hands out no second file");
    assert.match(dom.el("otpStatus").textContent, /already exported/, "…and shows the re-export warning");

    // The other order: THIS page is mid-export (held inside its first KDF,
    // i.e. inside the lock), and the other tab starts its export. It must wait
    // for this page to finish, then see the export — one file in total. (A lock
    // taken and released at once, before the export, lets the other tab in.)
    const q = await otp.generatePad({ label: "two-tab-race-2", totalBytes: 8192, fingerBytes: new Uint8Array(0) });
    await otp.saveNewPad(q, PAD_PASS);
    dom.el("otpSelect").value = q.padId;
    // Held at its TRANSFER-passphrase KDF — after the page's own re-read, so
    // only the lock can keep the other tab out.
    const subtle = crypto.subtle;
    const realImport = subtle.importKey;
    let pageGate;
    const pageMayGo = new Promise((r) => { pageGate = r; });
    let pageInside = false;
    subtle.importKey = function (fmt, raw, ...rest) {
      if (fmt === "raw" && raw instanceof Uint8Array && new TextDecoder().decode(raw) === "transfer passphrase") {
        subtle.importKey = realImport;
        pageInside = true;
        return pageMayGo.then(() => realImport.call(this, fmt, raw, ...rest));
      }
      return realImport.call(this, fmt, raw, ...rest);
    };
    const d1 = downloads;
    const mine2 = dom.el("otpExport").click();
    for (let i = 0; i < 200 && !pageInside; i++) await new Promise((r) => setTimeout(r, 5));
    assert.ok(pageInside, "fixture: this page's export is running (held in its transfer KDF)");
    let otherFiles = 0;
    const tabB2 = navigator.locks.request("sc.otp.export.v1." + q.padId, { mode: "exclusive" }, async () => {
      const u = await otpB.unlockPad(q.padId, PAD_PASS);
      if (u.record.exported) return;       // tab B's own guard: it sees the export and stops
      await otpB.exportPad(u.record, "tab b transfer");
      await otpB.markExported(u.record, u.atRest);
      otherFiles++;
    });
    await settle(20);
    pageGate();
    await mine2;
    await tabB2;
    await settle(10);
    assert.strictEqual((downloads - d1) + otherFiles, 1,
      `F2: two tabs exporting one pad at once hand out ONE file in total (this page ${downloads - d1}, the other ${otherFiles}) — the lock is held for the whole export`);
  } finally {
    setLocks(saved);
  }
  console.log("OK  package 6 round 2: the export lock is held for the whole export — a concurrent export in another tab yields one file (executed)");
}

// ---- package 6 round 3 (MEDIUM, pre-existing): an export never runs beside a live session ----
// Reviewer's PoC (two-time pad reproduced in Chromium): tab B chats on pad P
// while tab A re-exports P. A's latch wrote its pre-KDF snapshot (offset 0)
// back over B's saved progress; after a reload P reopened at 0. Tab B is a
// SEPARATE otp.js instance here (its own caches), as a real tab is.
{
  const queues = new Map();
  const heldNow = new Set();
  const queued = {
    request(name, opts, fn) {
      if (typeof opts === "function") { fn = opts; opts = {}; }
      if (opts && opts.ifAvailable && heldNow.has(name)) return Promise.resolve(fn(null));
      const run = (queues.get(name) || Promise.resolve()).then(async () => {
        heldNow.add(name);
        try { return await fn({ name }); } finally { heldNow.delete(name); }
      });
      queues.set(name, run.catch(() => {}));
      return run;
    },
    query: async () => ({ held: [...heldNow].map((name) => ({ name })) }),
  };
  const saved = globalThis.navigator.locks;
  setLocks(queued);
  const st = dom.el("otpStatus");
  const holdLock = (name) => new Promise((res) => {
    let release;
    navigator.locks.request(name, { ifAvailable: true }, (l) => {
      if (!l) { res(null); return; }
      res(() => release());
      return new Promise((r) => { release = r; });
    });
  });
  const sendOn = async (u, text) => {           // tab B's session: persist before transmit
    const c = makeCipher("OTP", ROOM, { pad: u.record });
    u.record.sendOffset = u.record.sendOffset; // (the cipher starts at the stored offset)
    const frame = await c.encrypt(text);
    u.record.sendOffset = c.sendOffset; u.record.recvHighWater = c.recvHighWater;
    await otpB.savePadProgress(u.record, u.atRest);
    return { frame, spent: c.sendOffset };
  };
  try {
    // (a) tab B holds the pad's SESSION lock (a live chat): this page's export
    //     is refused, says why, hands out nothing — and B's progress survives.
    const p = await otp.generatePad({ label: "live-elsewhere", totalBytes: 8192, fingerBytes: new Uint8Array(0) });
    await otp.saveNewPad(p, PAD_PASS);
    dom.el("otpSelect").value = p.padId;
    dom.el("otpPass").value = PAD_PASS;
    dom.el("otpXferPass").value = "transfer passphrase";
    const releaseB = await holdLock("sc.otp.lock.v1." + p.padId);
    assert.ok(releaseB, "fixture: tab B holds the pad's session lock");
    const b = await otpB.unlockPad(p.padId, PAD_PASS);
    // Where the PoC struck: tab B sends while this page's export sits in its
    // transfer KDF (held here). A fixed page never gets that far.
    const subtleA = crypto.subtle;
    const realImportA = subtleA.importKey;
    let gateA;
    const mayGoA = new Promise((r) => { gateA = r; });
    let insideA = false;
    subtleA.importKey = function (fmt, raw, ...rest) {
      if (fmt === "raw" && raw instanceof Uint8Array && new TextDecoder().decode(raw) === "transfer passphrase") {
        subtleA.importKey = realImportA;
        insideA = true;
        return mayGoA.then(() => realImportA.call(this, fmt, raw, ...rest));
      }
      return realImportA.call(this, fmt, raw, ...rest);
    };
    const d0 = downloads;
    const exporting = dom.el("otpExport").click();
    for (let i = 0; i < 100 && !insideA; i++) await new Promise((r) => setTimeout(r, 5));
    const { spent } = await sendOn(b, "attack at dawn");
    subtleA.importKey = realImportA;
    gateA();
    await exporting;
    await settle(10);
    assert.strictEqual(downloads, d0, "round 3 F1: no pad file while the pad is live in another tab");
    assert.match(st.textContent, /This pad is in use/, "…and the refusal says why: " + st.textContent);
    releaseB();
    const otpC = await import("./otp.js?tab=C-" + p.padId); // a reload: fresh module state
    const c = await otpC.unlockPad(p.padId, PAD_PASS);
    assert.ok(c.record.sendOffset >= spent,
      `round 3 F1: after a reload the pad opens at ${c.record.sendOffset}, not below what tab B spent (${spent})`);

    // (b) a tab that does NOT hold the pad lock (an older version) spends pad
    //     bytes while this page's export sits in its KDF: the latch re-reads
    //     the pad after the KDF, sees the use, and hands out nothing.
    const q = await otp.generatePad({ label: "used-mid-export", totalBytes: 8192, fingerBytes: new Uint8Array(0) });
    await otp.saveNewPad(q, PAD_PASS);
    dom.el("otpSelect").value = q.padId;
    const subtle = crypto.subtle;
    const realImport = subtle.importKey;
    let gate;
    const mayGo = new Promise((r) => { gate = r; });
    let inside = false;
    subtle.importKey = function (fmt, raw, ...rest) {
      if (fmt === "raw" && raw instanceof Uint8Array && new TextDecoder().decode(raw) === "transfer passphrase") {
        subtle.importKey = realImport;
        inside = true;
        return mayGo.then(() => realImport.call(this, fmt, raw, ...rest));
      }
      return realImport.call(this, fmt, raw, ...rest);
    };
    const d1 = downloads;
    const ex2 = dom.el("otpExport").click();
    for (let i = 0; i < 200 && !inside; i++) await new Promise((r) => setTimeout(r, 5));
    assert.ok(inside, "fixture: this page's export is in its transfer KDF");
    const bq = await otpB.unlockPad(q.padId, PAD_PASS);
    const used = await sendOn(bq, "sent by a tab without the lock");
    gate();
    await ex2;
    await settle(10);
    assert.strictEqual(downloads, d1, "round 3 F1b: a pad used during the export's KDF is not handed out");
    assert.match(st.textContent, /used while it was being exported/, "…and it says so: " + st.textContent);
    const otpD = await import("./otp.js?tab=D-" + q.padId);
    const d = await otpD.unlockPad(q.padId, PAD_PASS);
    assert.ok(d.record.sendOffset >= used.spent, `round 3 F1b: the pad's stored progress is intact (${d.record.sendOffset} ≥ ${used.spent})`);

    // (c) otp.js on its own: a save from a STALE record (this instance's
    //     snapshot) after another instance saved further never lowers what
    //     storage holds — the watermark and the durable record are maxed
    //     against storage, not only this instance's caches.
    const r = await otp.generatePad({ label: "stale-writer", totalBytes: 8192, fingerBytes: new Uint8Array(0) });
    await otp.saveNewPad(r, PAD_PASS);
    const staleA = await otp.unlockPad(r.padId, PAD_PASS);    // this page's snapshot at 0
    const rb = await otpB.unlockPad(r.padId, PAD_PASS);
    const usedR = await sendOn(rb, "tab B moves on");
    await otp.markExported(staleA.record, staleA.atRest);        // a latch from the stale snapshot
    const otpE = await import("./otp.js?tab=E-" + r.padId);
    const e = await otpE.unlockPad(r.padId, PAD_PASS);
    assert.ok(e.record.sendOffset >= usedR.spent,
      `round 3 F1 (belt and braces): a stale save does not rewind storage (${e.record.sendOffset} ≥ ${usedR.spent})`);
    assert.strictEqual(e.record.exported, true, "…and the latch it carried still lands");
  } finally {
    setLocks(saved);
  }
  console.log("OK  package 6 round 3: an export never runs beside a live session; a pad used mid-export is not handed out; a stale save never rewinds storage (executed, separate otp.js instances)");
}

// ---- package 6 round 3 (F2, Low): no copy of the pad keeps spent keystream ----
// The panel cache used to hold a full, never-zeroed copy of the pad while the
// session zeroed its own as it consumed it. Every Uint8Array of the pad's size
// created while the session is opened and used is tracked (WeakRef); after a
// garbage collection, none that is still reachable may hold the spent span.
{
  const v8 = await import("node:v8");
  const vm = await import("node:vm");
  v8.setFlagsFromString("--expose-gc");
  const gc = vm.runInNewContext("gc");
  const PAD_BYTES = 8192;
  const pad = await otp.generatePad({ label: "heap-check", totalBytes: PAD_BYTES, fingerBytes: new Uint8Array(0) });
  await otp.saveNewPad(pad, PAD_PASS);
  const ref = pad.bytes.slice(0, 64);            // our own copy of the first 64 bytes, to recognise copies
  const RealU8 = globalThis.Uint8Array;
  const tracked = [];
  class TrackedU8 extends RealU8 {
    constructor(...a) {
      super(...a);
      if (this.length === PAD_BYTES) tracked.push(new WeakRef(this));
    }
    static [Symbol.hasInstance](x) { return x instanceof RealU8; }
  }
  globalThis.Uint8Array = TrackedU8;
  let spent = 0;
  try {
    // The panel unlocks it first (as Export or Connect does), then a session.
    dom.el("otpSelect").value = pad.padId;
    dom.el("otpPass").value = PAD_PASS;
    const ws = await otpConnect(pad.padId);
    assert.ok(ws, "fixture: the session opened");
    for (const t of ["heap one", "heap two"]) {
      dom.el("text").value = t;
      await dom.el("sendForm").dispatch("submit");
      await settle(5);
    }
    spent = (await otp.unlockPad(pad.padId, PAD_PASS)).record.sendOffset;
    assert.ok(spent > 0, "fixture: pad bytes were spent");
  } finally {
    globalThis.Uint8Array = RealU8;
  }
  for (let i = 0; i < 3; i++) { await new Promise((r) => setTimeout(r, 10)); gc(); }
  const alive = tracked.map((w) => w.deref()).filter(Boolean);
  const copies = alive.filter((a) => a.subarray(32, 64).every((v, i) => v === ref[32 + i]) || a.subarray(0, spent).some((v) => v !== 0));
  const leaking = alive.filter((a) => {
    const role0 = a.subarray(0, Math.min(spent, 64));
    return role0.length > 0 && role0.every((v, i) => v === ref[i]);
  });
  assert.ok(tracked.length > 0, "fixture: pad-sized arrays were created and tracked");
  assert.strictEqual(leaking.length, 0,
    `round 3 F2: ${leaking.length} reachable copy/copies of the pad still hold the spent keystream (of ${alive.length} alive, ${copies.length} pad-like)`);
  await dom.el("disconnect").click();
  console.log("OK  package 6 round 3: after a session spends pad bytes, no reachable copy of the pad still holds them (executed, WeakRef + gc)");
}

// ---- package 6 round 3, infos I1-I3: the pad lock and the send follow the session ----
{
  const lockFree = (id) => new Promise((res) => {
    navigator.locks.request("sc.otp.lock.v1." + id, { ifAvailable: true }, (l) => { res(!!l); });
  });
  // I2: the relay socket cannot even be constructed — the pad lock is released.
  const p = await otp.generatePad({ label: "i2", totalBytes: 8192, fingerBytes: new Uint8Array(0) });
  await otp.saveNewPad(p, PAD_PASS);
  if (current && current.readyState === 1) await dom.el("disconnect").click();
  const RealWS = globalThis.WebSocket;
  globalThis.WebSocket = function () { throw new Error("SecurityError: insecure ws from a secure page"); };
  Object.assign(globalThis.WebSocket, { OPEN: 1, CLOSED: 3, CONNECTING: 0, CLOSING: 2 });
  try {
    const room = dom.el("room");
    room.value = ROOM;
    await room.dispatch("input");
    dom.selectAlg("OTP");
    dom.el("otpSelect").value = p.padId;
    dom.el("otpPass").value = PAD_PASS;
    await dom.el("connect").click();
  } finally {
    globalThis.WebSocket = RealWS;
  }
  assert.ok(anyHint(/Could not open the relay connection/), "fixture (I2): the socket could not be constructed");
  assert.ok(await lockFree(p.padId), "round 3 I2: a connect that failed releases the pad's lock");

  // I3: the socket closes while a save of the pad is still on its way to disk —
  //     the lock is released only once that save has settled.
  const ws = await otpConnect(p.padId);
  assert.ok(ws, "fixture (I3): the session opened");
  fakeIdb.hold();
  dom.el("text").value = "i3 in flight";
  const submitted = dom.el("sendForm").dispatch("submit");
  await settle(10);
  ws.close();                                      // the relay hangs up mid-save
  await settle(5);
  assert.strictEqual(await lockFree(p.padId), false, "round 3 I3: the pad lock is held while its save is in flight");
  fakeIdb.release();
  await submitted;
  await settle(10);
  assert.ok(await lockFree(p.padId), "…and released once the save settled");

  // I1: a reconnect while a send is encrypting — the old frame never goes out
  //     on the NEW socket.
  const w1 = await otpConnect(p.padId);
  const h = crypto.subtle;
  const realSign = h.sign;
  let gate;
  const mayGo = new Promise((r) => { gate = r; });
  let inside = false;
  h.sign = function (...a) { h.sign = realSign; inside = true; return mayGo.then(() => realSign.apply(this, a)); };
  dom.el("text").value = "i1 old session";
  const sending = dom.el("sendForm").dispatch("submit");
  for (let i = 0; i < 100 && !inside; i++) await new Promise((r) => setTimeout(r, 5));
  assert.ok(inside, "fixture (I1): the send is inside its encrypt");
  h.sign = realSign;
  const w2 = await otpConnect(p.padId);
  assert.ok(w2 && w2 !== w1, "fixture (I1): a new connection");
  gate();
  await sending;
  await settle(10);
  assert.strictEqual(w2.sent.filter((f) => f.type === "msg").length, 0,
    "round 3 I1: a frame encrypted for the old session is not sent on the new one");
  await dom.el("disconnect").click();
  console.log("OK  package 6 round 3: I1-I3 — no old frame on a new socket; the pad lock is released on every failed connect and only after an in-flight save (executed)");
}

// ==== package 6 round 4: every writer of a pad runs under its lock, re-checked after the slow step ====
// Tab B is a separate otp.js instance throughout (its own caches), sharing
// localStorage, the fake IndexedDB and Web Locks with this page.
{
  const st = dom.el("otpStatus");
  const holdImportOf = (text) => {       // hold the next importKey of `text` (a PBKDF2 passphrase)
    const subtle = crypto.subtle;
    const real = subtle.importKey;
    let gate;
    const mayGo = new Promise((r) => { gate = r; });
    const h = { entered: false, release: () => gate(), restore: () => { subtle.importKey = real; } };
    subtle.importKey = function (fmt, raw, ...rest) {
      if (fmt === "raw" && raw instanceof Uint8Array && new TextDecoder().decode(raw) === text) {
        subtle.importKey = real;
        h.entered = true;
        return mayGo.then(() => real.call(this, fmt, raw, ...rest));
      }
      return real.call(this, fmt, raw, ...rest);
    };
    return h;
  };
  const waitFor = async (cond) => { for (let i = 0; i < 400 && !cond(); i++) await new Promise((r) => setTimeout(r, 5)); };
  const sendTwo = async (label) => {
    for (const t of [label + " one", label + " two"]) {
      dom.el("text").value = t;
      await dom.el("sendForm").dispatch("submit");
      await settle(5);
    }
  };

  // (1) F1: the same pad FILE imported in two tabs. Tab B's import sits in its
  //     at-rest KDF while this page imports it, connects, sends and saves.
  //     B must then refuse; a reload must open the pad at >= what was spent.
  {
    const foreign = await otp.generatePad({ label: "twice-imported", totalBytes: 8192, fingerBytes: new Uint8Array(0) });
    const file = await otp.exportPad(foreign, "transfer passphrase");
    const recB = await otpB.importPad(file, "transfer passphrase");        // tab B decrypts the file…
    const hB = holdImportOf("tab B pad passphrase");
    const bSaving = otpB.saveNewPad(recB, "tab B pad passphrase").then(() => "saved", (e) => e.message);
    await waitFor(() => hB.entered);                                       // …and sits in its KDF
    assert.ok(hB.entered, "fixture: tab B's import is inside its KDF");
    dom.el("otpImportXfer").value = "transfer passphrase";
    dom.el("otpImportPass").value = PAD_PASS;
    dom.el("otpFile").files = [{ text: async () => file }];
    await dom.el("otpFile").dispatch("change");
    await settle(10);
    assert.match(st.textContent, /^Imported \+ encrypted pad "twice-imported"/, "fixture: this page imported it: " + st.textContent);
    const ws = await otpConnect(foreign.padId);
    assert.ok(ws, "fixture: a session on the imported pad");
    await sendTwo("twice");
    const spent = (await otpB.unlockPad(foreign.padId, PAD_PASS)).record.sendOffset;
    assert.ok(spent > 0, "fixture: pad bytes were spent and saved");
    await dom.el("disconnect").click();
    hB.release();
    const outcome = await bSaving;
    assert.match(String(outcome), /already been used/,
      `round 4 F1: tab B's import, re-checked after its KDF, is refused (got ${outcome})`);
    const otpR = await import("./otp.js?tab=R-" + foreign.padId);
    const r = await otpR.unlockPad(foreign.padId, PAD_PASS);
    assert.ok(r.record.sendOffset >= spent, `round 4 F1: a reload opens the pad at ${r.record.sendOffset} ≥ ${spent}`);
  }

  // (2) F1, the lock: this page imports a pad file while tab B holds the pad's
  //     lock (its own import of the same file): refused, said why.
  {
    const foreign = await otp.generatePad({ label: "import-while-locked", totalBytes: 8192, fingerBytes: new Uint8Array(0) });
    const file = await otp.exportPad(foreign, "transfer passphrase");
    let releaseB;
    const gotB = await new Promise((res) => navigator.locks.request("sc.otp.lock.v1." + foreign.padId, { ifAvailable: true },
      (l) => { res(!!l); return new Promise((r) => { releaseB = r; }); }));
    assert.ok(gotB, "fixture: tab B holds the pad's lock");
    dom.el("otpFile").files = [{ text: async () => file }];
    await dom.el("otpFile").dispatch("change");
    await settle(10);
    releaseB();
    assert.match(st.textContent, /This pad is in use/, "round 4: an import while the pad is locked elsewhere is refused: " + st.textContent);
    assert.strictEqual(otp.padMeta(foreign.padId), null, "…and nothing of it was stored");
  }

  // (3) writePadBlob never silently replaces a record written under another
  //     key: a save under a foreign key is refused and the pad stays readable.
  {
    const p = await otp.generatePad({ label: "foreign-key", totalBytes: 8192, fingerBytes: new Uint8Array(0) });
    const atRest = await otp.saveNewPad(p, PAD_PASS);
    const u = await otpB.unlockPad(p.padId, PAD_PASS);
    const otherKey = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
    await assert.rejects(otpB.savePadProgress(u.record, { ...atRest, key: otherKey }), /written under another key/,
      "round 4: a save under another key does not overwrite this key's records");
    assert.ok(await otp.unlockPad(p.padId, PAD_PASS), "…and the pad still opens with its own passphrase");
  }

  // (4) F2 (Info): a save that would START after a relay close is not made —
  //     the receive is not shown, the send is not sent (no "me" line).
  {
    const p = await otp.generatePad({ label: "after-close", totalBytes: 8192, fingerBytes: new Uint8Array(0) });
    await otp.saveNewPad(p, PAD_PASS);
    const peerPad = { bytes: p.bytes.slice(), role: 1, regionSize: p.regionSize, sendOffset: 0, recvHighWater: 0 };
    const peerC = makeCipher("OTP", ROOM, { pad: peerPad });
    const ws = await otpConnect(p.padId);
    // receive: held inside its HMAC verify, the relay closes, then it completes
    const subtle = crypto.subtle;
    const realVerify = subtle.verify;
    let gate;
    const mayGo = new Promise((r) => { gate = r; });
    let inside = false;
    subtle.verify = function (...a) { subtle.verify = realVerify; inside = true; return mayGo.then(() => realVerify.apply(this, a)); };
    const frame = await peerC.encrypt("after close");
    ws.onmessage({ data: JSON.stringify({ type: "msg", room: ROOM, alg: "OTP", payload: frame }) });
    await waitFor(() => inside);
    ws.close();
    await settle(5);
    gate();
    await settle(20);
    assert.ok(!said(/after close$/), "round 4 F2: a frame whose save would start after the close is not shown");
    assert.ok(said(/arrived as the connection closed — not shown/), "…and that is said");
    assert.strictEqual((await otpB.unlockPad(p.padId, PAD_PASS)).record.recvHighWater, 0, "…and nothing was saved without the lock");
    // send: held inside its encrypt (HMAC sign), the relay closes
    const w2 = await otpConnect(p.padId);
    const realSign = subtle.sign;
    let gate2;
    const mayGo2 = new Promise((r) => { gate2 = r; });
    let inside2 = false;
    subtle.sign = function (...a) { subtle.sign = realSign; inside2 = true; return mayGo2.then(() => realSign.apply(this, a)); };
    dom.el("text").value = "never sent";
    const sending = dom.el("sendForm").dispatch("submit");
    await waitFor(() => inside2);
    w2.close();
    await settle(5);
    gate2();
    await sending;
    await settle(10);
    assert.strictEqual(w2.sent.filter((f) => f.type === "msg").length, 0, "round 4 F2: nothing is sent after the close");
    assert.ok(!said(/^menever sent$/), "…no \"me\" line for it");
    assert.match(dom.el("hint").textContent + dom.el("roomHint").textContent, /was NOT sent/, "…and it says so");
    assert.strictEqual((await otpB.unlockPad(p.padId, PAD_PASS)).record.sendOffset, 0,
      "…and no save was made once the session's lock was released");
    // …and a save that started BEFORE the close completes (it holds the lock),
    // but its frame is not sent on the closed socket, and there is no "me" line.
    const w3 = await otpConnect(p.padId);
    fakeIdb.hold();
    dom.el("text").value = "saved but not sent";
    const s3 = dom.el("sendForm").dispatch("submit");
    await settle(10);
    w3.close();
    await settle(5);
    fakeIdb.release();
    await s3;
    await settle(10);
    assert.strictEqual(w3.sent.filter((f) => f.type === "msg").length, 0, "round 4 F2: a frame saved during the close is not sent");
    assert.ok(!said(/^mesaved but not sent$/), "…and gets no \"me\" line");
  }

  // (5) F2: ALL saves in flight hold the lock, not only the latest one. Save A
  //     (a send) is held at its blob encryption; save B (a receive) at the
  //     durable write. The relay closes. B settles first: the lock is still
  //     held until A settles too.
  {
    const lockFree = (id) => new Promise((res) => {
      navigator.locks.request("sc.otp.lock.v1." + id, { ifAvailable: true }, (l) => { res(!!l); });
    });
    const p = await otp.generatePad({ label: "two-saves", totalBytes: 8192, fingerBytes: new Uint8Array(0) });
    await otp.saveNewPad(p, PAD_PASS);
    const peerC = makeCipher("OTP", ROOM, { pad: { bytes: p.bytes.slice(), role: 1, regionSize: p.regionSize, sendOffset: 0, recvHighWater: 0 } });
    const ws = await otpConnect(p.padId);
    const subtle = crypto.subtle;
    const realEnc = subtle.encrypt;
    let gateA;
    const mayGoA = new Promise((r) => { gateA = r; });
    let insideA = false;
    subtle.encrypt = function (...a) { subtle.encrypt = realEnc; insideA = true; return mayGoA.then(() => realEnc.apply(this, a)); };
    dom.el("text").value = "save A";
    const sendingA = dom.el("sendForm").dispatch("submit");
    await waitFor(() => insideA);
    assert.ok(insideA, "fixture: save A is held");
    fakeIdb.hold();
    ws.onmessage({ data: JSON.stringify({ type: "msg", room: ROOM, alg: "OTP", payload: await peerC.encrypt("save B") }) });
    await settle(20);
    ws.close();
    await settle(5);
    fakeIdb.release();                     // B settles
    await settle(20);
    assert.strictEqual(await lockFree(p.padId), false, "round 4 F2: with save A still in flight the pad lock is still held");
    gateA();
    await sendingA;
    await settle(20);
    assert.ok(await lockFree(p.padId), "…and released once every save settled");
  }

  // (5b) Forget is a writer too: refused while the pad is locked elsewhere.
  {
    const p = await otp.generatePad({ label: "forget-locked", totalBytes: 8192, fingerBytes: new Uint8Array(0) });
    await otp.saveNewPad(p, PAD_PASS);
    let releaseB;
    await new Promise((res) => navigator.locks.request("sc.otp.lock.v1." + p.padId, { ifAvailable: true },
      (l) => { res(!!l); return new Promise((r) => { releaseB = r; }); }));
    dom.el("otpSelect").value = p.padId;
    await dom.el("otpForget").click();
    await settle(5);
    releaseB();
    assert.ok(otp.padMeta(p.padId), "round 4: Forget does not delete a pad that is in use elsewhere");
    assert.match(dom.el("otpStatus").textContent, /This pad is in use/, "…and says why");
  }

  // (6) F3: a reconnect while the previous session's save is still settling
  //     waits for it (no "open in another tab" refusal).
  {
    const p = await otp.generatePad({ label: "reconnect-wait", totalBytes: 8192, fingerBytes: new Uint8Array(0) });
    await otp.saveNewPad(p, PAD_PASS);
    const ws = await otpConnect(p.padId);
    fakeIdb.hold();
    dom.el("text").value = "slow save";
    const sending = dom.el("sendForm").dispatch("submit");
    await settle(10);
    ws.close();
    await settle(5);
    const again = otpConnect(p.padId);
    await settle(10);
    assert.match(dom.el("status") ? dom.el("status").textContent : "", /finishing the previous session's save/,
      "round 4 F3: the reconnect says it is waiting for the previous save");
    fakeIdb.release();
    await sending;
    const w2 = await again;
    assert.ok(w2, "round 4 F3: …and then connects (not refused as 'open in another tab')");
    assert.ok(!anyHint(/open in another tab/), "…no other-tab wording");
    await dom.el("disconnect").click();
  }

  // (7) F3: a cached key the pad no longer matches (it was saved again under a
  //     new key elsewhere) is dropped, and the passphrase unlocks it again.
  {
    dom.el("otpNewPass").value = PAD_PASS;
    dom.el("otpLabel").value = "rekeyed";
    await dom.el("otpGenerate").click();
    await settle(10);
    const id = otp.listPads().find((m) => m.label === "rekeyed").padId;
    // Elsewhere: the pristine pad is forgotten and saved again under a new key.
    const u = await otpB.unlockPad(id, PAD_PASS);
    otpB.forgetPad(id);
    for (const k of ["sc.otp.wm.v1.", "sc.otp.used.v1.", "sc.otp.hw.v1."]) localStorage.removeItem(k + id);
    fakeIdb.removeItem("sc.otp.dur.v1." + id);
    await otpB.saveNewPad(u.record, PAD_PASS);
    const ws = await otpConnect(id);
    assert.ok(ws && anyHint(/one-time-pad encrypted/), "round 4 F3: the stale cached key is dropped and the passphrase opens the pad");
    assert.ok(!anyHint(/saved again elsewhere/), "…without the 'saved again elsewhere' dead end");
    await dom.el("disconnect").click();
  }
  console.log("OK  package 6 round 4: a pad file imported in two tabs is refused after the KDF; imports/forgets hold the pad lock; no save under a foreign key; no save starts after a close and all in-flight saves hold the lock; reconnect waits; a stale cached key is dropped (executed, separate otp.js instances)");
}

// ==== package 6 final round ====================================================
{
  const st = dom.el("otpStatus");
  const waitFor = async (cond, n = 400) => { for (let i = 0; i < n && !cond(); i++) await new Promise((r) => setTimeout(r, 5)); };

  // (1) Low: the shared index is a render cache. Tab B's pad lands in the
  //     index; tab A's next index write works from a view taken BEFORE that
  //     (cross-tab localStorage is only eventually consistent) and drops it.
  //     The pad must still be listed and usable.
  {
    const IDX = "sc.otp.index.v1";
    const before = localStorage.getItem(IDX);
    const y = await otpB.generatePad({ label: "tab-B-pad", totalBytes: 8192, fingerBytes: new Uint8Array(0) });
    await otpB.saveNewPad(y, PAD_PASS);                                    // tab B: pad Y, index has Y
    const realGet = globalThis.localStorage.getItem;
    globalThis.localStorage.getItem = (k) => (k === IDX ? before : realGet(k)); // tab A's stale view
    let x;
    try {
      x = await otp.generatePad({ label: "tab-A-pad", totalBytes: 8192, fingerBytes: new Uint8Array(0) });
      await otp.saveNewPad(x, PAD_PASS);                                   // tab A writes the index without Y
    } finally {
      globalThis.localStorage.getItem = realGet;
    }
    assert.ok(!JSON.parse(localStorage.getItem(IDX)).some((e) => e.padId === y.padId), "fixture: the index lost tab B's entry");
    const listed = otp.listPads().map((m) => m.padId);
    assert.ok(listed.includes(y.padId) && listed.includes(x.padId), "final round: both pads are still listed (the blob is the source of truth)");
    assert.ok(otp.padMeta(y.padId), "…and the lost one has metadata (for the import duplicate check and the selector)");
    assert.ok((await otp.unlockPad(y.padId, PAD_PASS)).record, "…and it is usable");
    // Forget removes the blob; the listing follows, whatever the index says.
    otp.forgetPad(x.padId);
    assert.ok(!otp.listPads().some((m) => m.padId === x.padId), "a forgotten pad is not listed");
    // …even when another tab's stale index write puts its entry back.
    const idx = JSON.parse(localStorage.getItem(IDX));
    idx.push({ padId: x.padId, label: "tab-A-pad", regionSize: 4096, role: 0, createdAt: Date.now(), exported: false });
    localStorage.setItem(IDX, JSON.stringify(idx));
    assert.ok(!otp.listPads().some((m) => m.padId === x.padId) && otp.padMeta(x.padId) === null,
      "final round: an index entry without a stored pad is not listed (the blob decides)");
  }

  // (2) Mf: the "you already have this pad" check inside the import lock.
  //     Normally importPad's used-check refuses first; the lock-held check is
  //     what stands when the deletable used-markers are gone but the pad's blob
  //     is still here — it keeps a second import from replacing that blob.
  {
    const src = await otp.generatePad({ label: "twice-here", totalBytes: 8192, fingerBytes: new Uint8Array(0) });
    const file = await otp.exportPad(src, "transfer passphrase");
    dom.el("otpImportXfer").value = "transfer passphrase";
    dom.el("otpImportPass").value = PAD_PASS;
    dom.el("otpFile").files = [{ text: async () => file }];
    await dom.el("otpFile").dispatch("change");
    await settle(10);
    assert.match(st.textContent, /^Imported/, "fixture: first import");
    const blob = localStorage.getItem("sc.otp.pad.v1." + src.padId);
    for (const k of ["sc.otp.wm.v1.", "sc.otp.used.v1."]) localStorage.removeItem(k + src.padId);
    dom.el("otpFile").files = [{ text: async () => file }];
    await dom.el("otpFile").dispatch("change");
    await settle(10);
    assert.match(st.textContent, /You already have this pad on this device/,
      "final round (Mf): with the used-markers gone, a second import is still refused as a duplicate: " + st.textContent);
    assert.strictEqual(localStorage.getItem("sc.otp.pad.v1." + src.padId), blob, "…and the stored pad is not replaced");
  }

  // (3) Mb: FOREIGN_RECORD also guards the durable record alone.
  {
    const p = await otp.generatePad({ label: "dur-foreign", totalBytes: 8192, fingerBytes: new Uint8Array(0) });
    const atRest = await otp.saveNewPad(p, PAD_PASS);
    const u = await otpB.unlockPad(p.padId, PAD_PASS);
    const k = "sc.otp.dur.v1." + p.padId;
    fakeIdb.setItem(k, JSON.stringify({ ...JSON.parse(fakeIdb.getItem(k)), ct: "AAAAAAAAAAAAAAAAAAAAAAA=" }));
    await assert.rejects(otpB.savePadProgress(u.record, u.atRest), /written under another key/,
      "final round (Mb): a durable record unreadable under this key is not overwritten (watermark readable)");
    void atRest;
  }

  // (4) Ma: a save that would START during the close window (the lock is
  //     closing because an earlier save still holds it) is not made. A send
  //     is held in its save; a receive is held inside its HMAC verify (it
  //     passed the gate before the close); the relay closes; the receive then
  //     completes — its save must not start on the closing lock.
  {
    const p = await otp.generatePad({ label: "closing-window", totalBytes: 8192, fingerBytes: new Uint8Array(0) });
    await otp.saveNewPad(p, PAD_PASS);
    const peerC = makeCipher("OTP", ROOM, { pad: { bytes: p.bytes.slice(), role: 1, regionSize: p.regionSize, sendOffset: 0, recvHighWater: 0 } });
    const ws = await otpConnect(p.padId);
    fakeIdb.hold();
    dom.el("text").value = "first save";
    const sending = dom.el("sendForm").dispatch("submit");
    await settle(10);
    const subtle = crypto.subtle;
    const realVerify = subtle.verify;
    let gate;
    const mayGo = new Promise((r) => { gate = r; });
    let inside = false;
    subtle.verify = function (...a) { subtle.verify = realVerify; inside = true; return mayGo.then(() => realVerify.apply(this, a)); };
    ws.onmessage({ data: JSON.stringify({ type: "msg", room: ROOM, alg: "OTP", payload: await peerC.encrypt("during close") }) });
    await waitFor(() => inside);
    assert.ok(inside, "fixture: the receive is inside its verify");
    ws.close();                                   // lock closing: the send's save still holds it
    await settle(5);
    gate();                                       // the receive completes during the close window
    await settle(20);
    fakeIdb.release();
    await sending;
    await settle(20);
    assert.ok(!said(/during close$/), "final round (Ma): a frame whose save would start while the lock is closing is not shown");
    assert.strictEqual((await otpB.unlockPad(p.padId, PAD_PASS)).record.recvHighWater, 0,
      "…and its save was never started (only the send's save, begun before the close, is recorded)");
  }

  // (5) Info: the user's own Disconnect while a receipt is being saved.
  {
    const p = await otp.generatePad({ label: "disconnect-mid-save", totalBytes: 8192, fingerBytes: new Uint8Array(0) });
    await otp.saveNewPad(p, PAD_PASS);
    const peerC = makeCipher("OTP", ROOM, { pad: { bytes: p.bytes.slice(), role: 1, regionSize: p.regionSize, sendOffset: 0, recvHighWater: 0 } });
    await otpConnect(p.padId);
    // (a narration: an identical line folds, "(×n)", so the fold count is what moves)
    const tally = () => lines().filter((l) => /arrived as the connection closed — not shown/.test(l))
      .reduce((n, l) => n + (+(/\(×(\d+)\)$/.exec(l) || [0, 1])[1]), 0);
    const n0 = tally();
    fakeIdb.hold();
    const delivered = current.deliver({ type: "msg", room: ROOM, alg: "OTP", payload: await peerC.encrypt("mid save") });
    await settle(10);
    await dom.el("disconnect").click();
    fakeIdb.release();
    await delivered;
    await settle(20);
    assert.ok(!said(/mid save$/), "fixture: not shown");
    assert.strictEqual(tally(), n0 + 1,
      "final round (Info): a receipt saved as the user disconnected is said, not silently dropped");
  }

  // (6) Low: a save that never settles does not block Connect for the tab.
  {
    const p = await otp.generatePad({ label: "hung-save", totalBytes: 8192, fingerBytes: new Uint8Array(0) });
    await otp.saveNewPad(p, PAD_PASS);
    const ws = await otpConnect(p.padId);
    fakeIdb.hold();                               // the save hangs
    dom.el("text").value = "hangs";
    const sending = dom.el("sendForm").dispatch("submit");
    await settle(10);
    ws.close();
    await settle(5);
    // an AES256 connect meanwhile is not blocked
    const otpWaiting = (async () => {
      const room = dom.el("room"); room.value = ROOM; await room.dispatch("input");
      dom.selectAlg("OTP"); dom.el("otpSelect").value = p.padId; dom.el("otpPass").value = PAD_PASS;
      return dom.el("connect").click();
    })();
    await settle(10);
    const before = dom.socket();
    dom.el("pass").value = "an AES256 passphrase";
    dom.selectAlg("AES256");
    await dom.el("connect").click();
    assert.ok(dom.socket() && dom.socket() !== before, "final round: an AES256 connect is not blocked by a pending OTP save");
    dom.socket().open();
    await tick();
    await dom.el("disconnect").click();
    await otpWaiting;                             // (a later connect ran: this one stands down)
    // the same pad again, alone: refused after the time limit, with what to do
    dom.selectAlg("OTP"); dom.el("otpSelect").value = p.padId;
    const t0 = Date.now();
    const s0 = dom.socket();
    await dom.el("connect").click();
    assert.ok(Date.now() - t0 >= 9000, "…the same-pad connect waited for the save (up to the limit)");
    assert.strictEqual(dom.socket(), s0, "final round: after the limit the same-pad connect is refused (no socket)");
    assert.ok(anyHint(/still saving its progress/), "…and says what to do");
    fakeIdb.release();
    await sending;
    await settle(20);
  }
  console.log("OK  package 6 final round: the pad index is a render cache; duplicate import worded; foreign durable record guarded; no save during the close window; disconnect mid-save said; a hung save blocks no Connect (executed)");
}

// ---- F-ATREST-002 residual: latch BEFORE download -----------------------------
{
  const p2 = await otp.generatePad({ label: "to-export", totalBytes: 8192, fingerBytes: new Uint8Array(0) });
  await otp.saveNewPad(p2, PAD_PASS);
  dom.el("otpSelect").value = p2.padId;
  dom.el("otpPass").value = PAD_PASS;
  dom.el("otpXferPass").value = "transfer passphrase";
  const realSet = localStorage.setItem;
  localStorage.setItem = (k, v) => {
    if (k === "sc.otp.pad.v1." + p2.padId) throw new Error("QuotaExceededError: disk full");
    return realSet(k, v);
  };
  const d0 = downloads;
  try {
    await dom.el("otpExport").click();
  } finally {
    localStorage.setItem = realSet;
  }
  assert.strictEqual(downloads, d0,
    "F-ATREST-002: when the export cannot be recorded, NO file may be handed out (a second importer would get the same pad)");
  assert.match(dom.el("otpStatus").textContent, /^Export failed: /, "…and the user is told the export failed");
  // Control: with storage working, the export records and hands out one file.
  // (The failed attempt left `exported` set in memory — the conservative side
  // — so the re-export warning needs its confirming second click.)
  await dom.el("otpExport").click();
  await dom.el("otpExport").click();
  assert.strictEqual(downloads, d0 + 1, "control: a recorded export hands out exactly one file");
  assert.strictEqual(otp.padMeta(p2.padId).exported, true, "control: …and the latch is recorded");
  console.log("OK  F-ATREST-002 residual: the export latch is recorded before the pad file is handed out (executed)");
}

// ---- F-CRYPTO-014: Web Locks, or no OTP -----------------------------------------
{
  // (a) No navigator.locks: the old code fell back to a localStorage "lease",
  // which is check-then-write and so not mutual exclusion. Now: refused, and
  // the user is told why.
  setLocks(undefined);
  const before = dom.socket();
  const ws = await otpConnect();
  assert.strictEqual(ws, null, "F-CRYPTO-014: without Web Locks no OTP session may open");
  assert.strictEqual(dom.socket(), before, "…no socket is created");
  assert.ok(anyHint(/One-time pads are disabled in this browser/), "…and the refusal says why: " + dom.el("roomHint").textContent);
  assert.ok(![...store.keys()].some((k) => k.startsWith("sc.otp.lock.v1.")), "…and no localStorage lease is written");

  // (b) With Web Locks, the one-tab-per-pad guarantee: another tab holds it.
  setLocks(webLocks);
  let releaseOther;
  webLocks.request("sc.otp.lock.v1." + pad.padId, {}, () => new Promise((r) => { releaseOther = r; }));
  const ws2 = await otpConnect();
  assert.strictEqual(ws2, null, "control: a pad held by another tab is refused");
  assert.ok(anyHint(/open in another tab or window/), "control: …with the other-tab wording");
  releaseOther();
  await settle(2);
  const ws3 = await otpConnect();
  assert.ok(ws3 && ws3.readyState === 1, "control: once released, the pad opens here");
  console.log("OK  F-CRYPTO-014: the pad lock is Web Locks only — no lease fallback, refused with a reason (executed)");
}

// ---- fix round 2: the consent and warning wordings -----------------------------
// Re-seal a pad's inner record (the test knows the pad passphrase) — to model a
// blob written by an older build.
async function resealPad(padId, mutate) {
  const k = "sc.otp.pad.v1." + padId;
  const o = JSON.parse(localStorage.getItem(k));
  const u8 = (s) => Uint8Array.from(Buffer.from(s, "base64"));
  const b64s = (u) => Buffer.from(u).toString("base64");
  const base = await crypto.subtle.importKey("raw", new TextEncoder().encode(PAD_PASS), "PBKDF2", false, ["deriveKey"]);
  const key = await crypto.subtle.deriveKey({ name: "PBKDF2", salt: u8(o.kdf.salt), iterations: o.kdf.iters, hash: "SHA-256" },
    base, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
  const inner = JSON.parse(new TextDecoder().decode(await crypto.subtle.decrypt({ name: "AES-GCM", iv: u8(o.iv) }, key, u8(o.ct))));
  mutate(inner);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, new TextEncoder().encode(JSON.stringify(inner))));
  localStorage.setItem(k, JSON.stringify({ ...o, iv: b64s(iv), ct: b64s(ct) }));
}
{
  // (a) The receive-record consent: the pad's send slot exists, its recv: slot
  // is gone. The prompt must say THAT, and that the answer is almost always no.
  const r = await otp.generatePad({ label: "recv-gone", totalBytes: 8192, fingerBytes: new Uint8Array(0) });
  await otp.saveNewPad(r, PAD_PASS);
  await resealPad(r.padId, (inner) => { delete inner.derivedFloors; }); // an older blob copy
  floors.delete("recv:" + r.padId);
  const asked = [];
  const realConfirm = globalThis.confirm;
  globalThis.confirm = (m) => { asked.push(String(m)); return false; };
  try {
    const ws = await otpConnect(r.padId);
    assert.strictEqual(ws, null, "declining the consent opens nothing");
  } finally {
    globalThis.confirm = realConfirm;
  }
  assert.strictEqual(asked.length, 1, "fixture: the adoption consent was asked");
  assert.match(asked[0], /^WARNING: this pad's receive record is missing/,
    "fix round 2: the receive-side prompt names what is missing (not 'no usage record')");
  assert.match(asked[0], /do NOT adopt/, "…and says the right answer is almost always no");
  assert.match(asked[0], /never\s+received a message on this device/,
    "…and asks about RECEIVING, not about sending (e.recvRecord drives the wording)");
  assert.ok(anyHint(/Pad not adopted/), "…and declining is reported");
  console.log("OK  fix round 2: the receive-record consent says what is missing and not to adopt (executed)");
}
{
  // (b) "exported" only INFERRED (an older pad, exported: slot missing): the
  // re-export warning says the history can't be verified — still one confirm.
  const x = await otp.generatePad({ label: "inferred", totalBytes: 8192, fingerBytes: new Uint8Array(0) });
  await otp.saveNewPad(x, PAD_PASS);
  await resealPad(x.padId, (inner) => { delete inner.derivedFloors; });
  floors.delete("exported:" + x.padId);
  dom.el("otpSelect").value = x.padId;
  dom.el("otpPass").value = PAD_PASS;
  dom.el("otpXferPass").value = "transfer passphrase";
  const d0 = downloads;
  await dom.el("otpExport").click();
  assert.match(dom.el("otpStatus").textContent, /export history can't be verified/,
    "fix round 2: an INFERRED export is worded as unverifiable history, not 'already exported'");
  assert.doesNotMatch(dom.el("otpStatus").textContent, /catastrophic/);
  assert.strictEqual(downloads, d0, "…and the first click still hands out nothing (the confirm stays)");
  await dom.el("otpExport").click();
  assert.strictEqual(downloads, d0 + 1, "the confirming click exports");
  console.log("OK  fix round 2: an inferred export gets the 'history can't be verified' warning (executed)");
}

// ---- package 3b: transmit / display / download wait for the DURABLE write ------
// The three orderings above were proven against localStorage.setItem, which
// returns long before the data is on disk (Chromium batches it). They now have
// to hold against the IndexedDB write that actually reaches the disk: with the
// durable commit held in flight, nothing may leave, be shown or be handed out.
{
  const ws = await otpConnect();
  assert.ok(ws && ws.readyState === 1, "fixture: a fresh OTP session");
  // (a) receive: not displayed while the durable write is in flight.
  fakeIdb.hold();
  const delivered = ws.deliver({ type: "msg", room: ROOM, alg: "OTP", payload: await peer.encrypt("durable three") });
  await settle(10);
  assert.ok(!said(/durable three/),
    "3b: a received OTP message is not displayed while its receipt's durable write has not completed");
  fakeIdb.release();
  await delivered;
  await settle(10);
  assert.ok(said(/durable three/), "…and is displayed once it has");

  // (b) send: nothing on the wire while the durable write is in flight.
  const sentMsgs = () => ws.sent.filter((f) => f.type === "msg").length;
  const m0 = sentMsgs();
  fakeIdb.hold();
  dom.el("text").value = "durable four";
  const submitted = dom.el("sendForm").dispatch("submit");
  await settle(10);
  assert.strictEqual(sentMsgs(), m0,
    "3b: an OTP ciphertext is not transmitted while the pad's durable write has not completed");
  fakeIdb.release();
  await submitted;
  await settle(10);
  assert.strictEqual(sentMsgs(), m0 + 1, "…and is transmitted once it has");

  // (c) export: no file while the durable write of the latch is in flight.
  const p3 = await otp.generatePad({ label: "durable-export", totalBytes: 8192, fingerBytes: new Uint8Array(0) });
  await otp.saveNewPad(p3, PAD_PASS);
  dom.el("otpSelect").value = p3.padId;
  dom.el("otpPass").value = PAD_PASS;
  dom.el("otpXferPass").value = "transfer passphrase";
  const d0 = downloads;
  fakeIdb.hold();
  const clicked = dom.el("otpExport").click();
  await settle(40);
  assert.strictEqual(downloads, d0, "3b: the pad file is not handed out while the export latch's durable write has not completed");
  fakeIdb.release();
  await clicked;
  await settle(10);
  assert.strictEqual(downloads, d0 + 1, "…and is handed out once it has");
  console.log("OK  3b: OTP transmit, display and export wait for the durable (IndexedDB) write (executed)");
}

// Package 6 fix round: a SECOND import of app.js (the page-reload tests at the
// end of the block below) wires every listener again on the same DOM, so from
// then on one click runs each handler twice — or three times after the second
// reload. That is how a double export first showed up here, as a harness
// artefact. Such tests therefore run LAST, and reloadApp makes that explicit:
// after it, any click or event on the stub DOM throws.
async function reloadApp(query) {
  await import("./app.js?" + query);
  El.prototype.dispatch = function () {
    throw new Error("app.js was imported again: every listener now exists more than once — " +
      "nothing may be clicked after a reload test (put the block before it, or in another file)");
  };
}

// ==== package 4 (F-ATREST-008): the identity blob is never silently re-keyed =====
// …and on a device with a native floor, an older copy is refused. Before: a
// blob without encryption keys was given NEW ones on unlock and app.js stored
// them — a restored older copy (one setItem) silently re-keyed the identity.
{
  const { Identity, identityFloorId, b64 } = await import("./identity.js");
  const PASS = "identity passphrase for the tests";
  const stored = () => store.get("sc.identity.v1");
  const ED = async () => (await Identity.import(stored(), PASS)).edPubRaw;
  const unlock = async () => {
    dom.el("idPass").value = PASS;
    await dom.el("idUnlock").click();
    await settle(20);
  };
  // A keyless copy of an identity: `legacy` = the pre-v3 envelope (v:1).
  const keylessBlob = async (id, legacy, gen = 0) => {
    const k = new Identity({ edPriv: id._edPriv, edPubRaw: id.edPubRaw, mldsaSecret: id._mldsaSecret, mldsaPub: id.mldsaPub });
    k.gen = gen;
    const blob = JSON.parse(await k.export(PASS));
    if (legacy) blob.v = 1;
    return JSON.stringify(blob);
  };
  let asked = [];
  let answer = false;
  globalThis.confirm = (q) => { asked.push(q); return answer; };

  // (1) create: the floor follows the stored blob (generation 1).
  dom.el("idPass").value = PASS;
  await dom.el("idCreate").click();
  await settle(40);
  const keyA = await identityFloorId(await ED());
  assert.strictEqual(floors.get(keyA), 1, "F-ATREST-008: a new identity raises its floor to generation 1");
  const bumpA = identityBumps.find((b) => b.id === keyA);
  assert.ok(bumpA && bumpA.blob && JSON.parse(bumpA.blob).v === 3, "...AFTER the blob was stored (never a floor ahead of the only copy)");
  assert.strictEqual(bumpA.durableBlob, stored(), "fix round L-1: ...and AFTER its DURABLE copy was written (localStorage alone is not on disk)");
  const blobA = stored();
  // An attacker (or a restored snapshot) that puts an old copy back puts it in
  // both places; a lost write loses only the localStorage one (6, 7 below).
  const plant = (blob) => { store.set("sc.identity.v1", blob); fakeIdb.setItem("sc.identity.v1", blob); };
  const idA = await Identity.import(blobA, PASS);

  // (2) Android: an older KEYLESS copy of this identity is put back. Refused
  //     before anyone is asked; nothing re-keyed, nothing stored.
  for (const legacy of [true, false]) {
    const planted = await keylessBlob(idA, legacy);
    plant(planted);
    asked = [];
    await unlock();
    assert.strictEqual(asked.length, 0, `F-ATREST-008 (${legacy ? "legacy" : "v3"} envelope): a device that used this identity WITH keys does not even ask`);
    assert.match(dom.el("idStatus").textContent, /Not unlocked: .*old copy has been put back/, "...it refuses, saying why");
    assert.strictEqual(stored(), planted, "...and the stored copy was NOT upgraded with new keys");
  }
  // an older WITH-keys generation below the floor is refused too
  floors.set(keyA, 3);
  plant(blobA); // generation 1 < floor 3
  await unlock();
  assert.match(dom.el("idStatus").textContent, /Not unlocked: .*OLDER than one this device has already used/, "F-ATREST-008: a generation below the floor is refused");
  floors.set(keyA, 1);

  // (3) a keyless blob of an identity this device never saw (the browser case,
  //     or a genuine first upgrade): the user is ASKED; Cancel changes nothing.
  const idB = await Identity.generate();
  const legacyB = await keylessBlob(idB, true);
  const keyB = await identityFloorId(idB.edPubRaw);
  store.set("sc.identity.v1", legacyB);
  asked = []; answer = false;
  await unlock();
  assert.strictEqual(asked.length, 1, "F-ATREST-008: a keyless blob is never re-keyed without asking");
  assert.match(asked[0], /old version of the app.*ALREADY used this identity with a newer version.*Cancel/s, "...the legacy question warns about a restored copy");
  assert.strictEqual(stored(), legacyB, "...Cancel stores nothing");
  assert.ok(!floors.has(keyB), "...and raises no floor");
  assert.match(dom.el("idStatus").textContent, /Not unlocked/, "...and says it did not unlock");
  // a v3 envelope without keys asks the LOUD question
  store.set("sc.identity.v1", await keylessBlob(idB, false));
  asked = [];
  await unlock();
  assert.match(asked[0] || "", /WARNING: your saved identity has NO encryption keys/, "F-ATREST-008: a v3 blob without keys gets the loud question");
  // (4) confirmed: keys added once, stored, generation +1, floor raised after.
  store.set("sc.identity.v1", legacyB);
  asked = []; answer = true;
  const bumps0 = identityBumps.length;
  await unlock();
  const up = await Identity.import(stored(), PASS);
  assert.ok(up.publicBundle().ecdh && up.gen === 1 && !up.upgraded, "F-ATREST-008: confirmed — the new keys are stored once, as generation 1");
  assert.ok(lines().some((l) => /new encryption keys were created for your identity — you confirmed it/.test(l)), "...and the transcript says so");
  const bumpB = identityBumps.slice(bumps0).find((b) => b.id === keyB);
  assert.ok(bumpB && bumpB.v === 1 && bumpB.blob === stored(), "...the floor was raised to 1 AFTER the upgraded blob was stored");
  assert.strictEqual(bumpB.durableBlob, stored(), "fix round L-1: ...and after its DURABLE copy was written");
  // (5) a crash/failed write between storing and raising: the blob is safe,
  //     the next unlock catches the floor up (no brick).
  const idC = await Identity.generate();
  store.set("sc.identity.v1", await idC.export(PASS));
  const keyC = await identityFloorId(idC.edPubRaw);
  failIdentityBumps = 1;
  await unlock();
  assert.ok(!floors.has(keyC) && lines().some((l) => /rollback record for your identity could not be updated/.test(l)),
    "F-ATREST-008: a failed floor write is said, and the identity still unlocks");
  await unlock();
  assert.strictEqual(floors.get(keyC), 1, "...and the next unlock raises the floor");

  // ---- fix round (pentest of package 4), L-1: a lost localStorage write + kill --
  // localStorage.setItem is not on disk (durable.js); PadFloor's commit() is.
  // Modelled here: the upgrade's setItem is LOST (the pre-upgrade copy is what
  // the disk still has), the floor and IndexedDB (strict, awaited) keep what
  // they got. Before the fix: keyless gen-0 blob + floor 1 = IDENTITY_ROLLBACK
  // forever, no override.
  // (6) the one-time upgrade of an existing (pre-fix: localStorage-only) install
  const idD = await Identity.generate();
  const legacyD = await keylessBlob(idD, true);
  const keyD = await identityFloorId(idD.edPubRaw);
  store.set("sc.identity.v1", legacyD);
  fakeIdb.removeItem("sc.identity.v1");
  asked = []; answer = true;
  await unlock();
  const upD = await Identity.import(stored(), PASS);
  assert.ok(upD.publicBundle().ecdh && floors.get(keyD) === 1, "fixture: the upgrade ran and the floor is at 1");
  store.set("sc.identity.v1", legacyD); // the kill: the upgraded blob never reached the disk
  asked = [];
  await unlock();
  assert.strictEqual(asked.length, 0, "fix round L-1: after a lost write + kill the next unlock is not asked about new keys");
  assert.doesNotMatch(dom.el("idStatus").textContent, /Not unlocked|Wrong passphrase/, `fix round L-1: ...and it UNLOCKS (not a permanent rollback): ${dom.el("idStatus").textContent}`);
  const againD = await Identity.import(stored(), PASS);
  assert.strictEqual(againD.publicBundle().ecdh, upD.publicBundle().ecdh, "...with the keys the upgrade made (not new ones), put back from the durable copy");
  assert.ok(lines().some((l) => /taken from the device's durable copy/.test(l)), "...and says so");
  // (7) create, then the kill loses the localStorage write entirely
  store.delete("sc.identity.v1");
  fakeIdb.removeItem("sc.identity.v1");
  dom.el("idPass").value = PASS;
  await dom.el("idCreate").click();
  await settle(40);
  const created = stored();
  const keyE = await identityFloorId((await Identity.import(created, PASS)).edPubRaw);
  assert.strictEqual(floors.get(keyE), 1, "fixture: create raised the floor");
  store.delete("sc.identity.v1"); // the kill
  await unlock();
  assert.doesNotMatch(dom.el("idStatus").textContent, /Not unlocked|Wrong passphrase|Nothing to unlock/, `fix round L-1: a created identity whose localStorage write was lost still unlocks: ${dom.el("idStatus").textContent}`);
  assert.strictEqual(stored(), created, "...from the durable copy, which is put back");

  // ---- final round (review of a5ac006) ------------------------------------------
  const durableNow = () => fakeIdb.getItem("sc.identity.v1");
  // (8) M1: the durable write FAILS -> the floor does not move, and it is said.
  const idF = await Identity.generate();
  const blobF = await idF.export(PASS);
  const keyF = await identityFloorId(idF.edPubRaw);
  store.set("sc.identity.v1", blobF);
  fakeIdb.removeItem("sc.identity.v1");
  fakeIdb.failWrites((k) => k === "sc.identity.v1", "QuotaExceeded");
  try {
    await unlock();
  } finally {
    fakeIdb.failWrites(null);
  }
  assert.ok(!floors.has(keyF), "final round M1: a failed durable write leaves the identity floor where it was");
  assert.ok(lines().some((l) => /could not be saved to the device's durable storage — its rollback record was not advanced/.test(l)), "...and says so");
  await unlock();
  assert.strictEqual(floors.get(keyF), 1, "...and the next unlock (durable write OK) raises it");

  // (9) M4: Create refuses while a durable copy exists (the localStorage one lost).
  store.delete("sc.identity.v1");
  assert.strictEqual(durableNow(), blobF, "fixture: only the durable copy is left");
  dom.el("idPass").value = PASS;
  await dom.el("idCreate").click();
  await settle(10);
  assert.match(dom.el("idStatus").textContent, /An identity already exists here/, "final round M4: Create refuses while a durable copy exists");
  assert.strictEqual(durableNow(), blobF, "...and does not replace it");
  // (10) Info-2: only the durable copy, and a WRONG passphrase: say so.
  dom.el("idPass").value = "not the passphrase";
  await dom.el("idUnlock").click();
  await settle(20);
  assert.strictEqual(dom.el("idStatus").textContent, "Wrong passphrase or corrupted identity.",
    "final round Info-2: a wrong passphrase against the durable copy is a wrong passphrase, not 'nothing to unlock'");
  // (11) Info-3: a DAMAGED localStorage copy does not hide a durable copy that opens.
  store.set("sc.identity.v1", "{not an identity");
  await unlock();
  assert.doesNotMatch(dom.el("idStatus").textContent, /Wrong passphrase|Not unlocked|Nothing/, `final round Info-3: the durable copy opens: ${dom.el("idStatus").textContent}`);
  assert.strictEqual(stored(), blobF, "...and replaces the damaged one");

  // (12) Info-1: Forget while an unlock is in flight — the unlock must not put
  //      the durable copy back afterwards (it would resurrect on reload).
  {
    const subtle = crypto.subtle, orig = subtle.deriveKey;
    let release, entered = false;
    const gate = new Promise((r) => { release = r; });
    subtle.deriveKey = function (alg, ...rest) {
      if (!entered && alg && alg.name === "PBKDF2") { entered = true; subtle.deriveKey = orig; return gate.then(() => orig.call(this, alg, ...rest)); }
      return orig.call(this, alg, ...rest);
    };
    try {
      dom.el("idPass").value = PASS;
      const unlocking = dom.el("idUnlock").click();
      const t0 = Date.now();
      while (!entered && Date.now() - t0 < 5000) await new Promise((r) => setTimeout(r, 5));
      assert.ok(entered, "fixture: the unlock is deriving its key");
      globalThis.confirm = () => true;
      await dom.el("idForget").click(); // (the handler does not return forgetIdentity's promise)
      await settle(40);
      assert.ok(stored() === undefined && durableNow() === null, "fixture: Forget removed both copies");
      release();
      await unlocking;
      await settle(20);
      assert.strictEqual(durableNow(), null, "final round Info-1: an unlock racing Forget does not put the durable copy back");
      assert.strictEqual(stored(), undefined, "...nor the localStorage one");
    } finally {
      subtle.deriveKey = orig;
      if (release) release();
    }
  }

  // (13) M3: Forget removes BOTH copies, and nothing comes back on a reload
  //      (a fresh instance of app.js runs the page-load restore again).
  store.set("sc.identity.v1", blobF);
  fakeIdb.setItem("sc.identity.v1", blobF);
  await unlock();
  globalThis.confirm = () => true;
  await dom.el("idForget").click();
  await settle(40);
  assert.strictEqual(stored(), undefined, "final round M3: Forget removes the localStorage copy");
  assert.strictEqual(durableNow(), null, "final round M3: ...AND the durable copy");
  await reloadApp("reload=1");
  await settle(20);
  assert.strictEqual(stored(), undefined, "final round M3: ...and nothing comes back on a reload");
  // (14) M5: the page-load restore of a durable-only copy (a create whose
  //      localStorage write was lost) — a reload puts it back.
  fakeIdb.setItem("sc.identity.v1", blobF);
  await reloadApp("reload=2");
  await settle(20);
  assert.strictEqual(stored(), blobF, "final round M5: a reload puts a durable-only identity back into localStorage");
  globalThis.confirm = () => true;
  void b64;
  console.log("OK  F-ATREST-008: a keyless identity blob is never silently re-keyed; an older copy is refused on a floored device; the floor follows the stored blob (executed)");
}

console.log("\nAll app.js OTP-path checks passed.");
process.exit(0);
