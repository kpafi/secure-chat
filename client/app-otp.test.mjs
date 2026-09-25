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
import { installDom } from "./dom-stub.test.mjs";
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
dom.seedAlgRadios(["DHKE", "AES256", "RSA", "PQKEM", "OTP"], "DHKE");
dom.seedNavItems(["live", "chats", "users", "profile"]);
dom.seedChild("scrChat", "div", "topbar");
for (const id of ["usersLocked", "chatsLocked"]) dom.seedChild(id, "p", "hint");

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
globalThis.__SECURE_CHAT_PAD_FLOOR__ = Object.freeze({
  read: (id) => (floors.has(id) ? floors.get(id) : -1),
  bump: (id, v) => {
    const cur = floors.has(id) ? floors.get(id) : -1;
    const n = cur === -1 ? v : (v > cur ? v : cur);
    floors.set(id, n);
    return n;
  },
});

await import("./app.js");
const otp = await import("./otp.js"); // the same module instance app.js uses

const tick = () => new Promise((r) => setTimeout(r, 0));
const settle = async (n = 40) => { for (let i = 0; i < n; i++) await new Promise((r) => setTimeout(r, 5)); };
const lines = () => dom.lines();
const said = (re) => lines().some((l) => re.test(l));
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

console.log("\nAll app.js OTP-path checks passed.");
process.exit(0);
