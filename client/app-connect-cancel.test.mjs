// app.js's connect deadlines and the room screen's Cancel, executed — pentest
// r6 R6-1 / r7 R7-3 of the OTP transfer-sheets work (the gap predates it).
//
// A relay that accepts the socket and never answers `join`, and a directory
// lookup that never answers, used to leave the user on the room screen with
// Connect disabled, no Disconnect (it lives on the chat screen) and, for an OTP
// connect, the pad locked — until a reload. Bound here:
//
//   J   the join deadline: 30 s from the socket's construction to the relay's
//       answer (`pending` or `joined`), then a close with a fixed sentence;
//       never for a guest waiting in the admission queue, never after a close
//   L   the lookup deadline: 20 s, then a fixed sentence and no socket
//   C   Cancel: shown exactly while a Connect is in flight and unanswered;
//       before the socket it stops the attempt at its next step and releases
//       a pad lock it took; with the socket it is Disconnect (closeWs)
//
// Timers of 20 s and more are captured, not scheduled, and fired by the test.
// Same scope note as app-behaviour: the stub is not a browser (e2e/hung-relay.mjs
// runs the same paths in Chromium). Run: node app-connect-cancel.test.mjs
import assert from "node:assert";
import { fakeIdb } from "./fake-idb.test.mjs"; // IndexedDB for node
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { readFileSync } from "node:fs";
import { installDom, El } from "./dom-stub.test.mjs";
import { Identity } from "./identity.js";

void fakeIdb;
const HERE = dirname(fileURLToPath(import.meta.url));
const ROOM = "c".repeat(64);
const PASS = "correct horse battery staple";
const PAD_PASS = "pad passphrase for the tests";
const JOIN_SENTENCE =
  "The relay did not answer within 30 seconds, so this connection attempt was stopped — " +
  "nothing reached your contact. Check your connection and press Connect to try again.";
const EARLY_KEY_SENTENCE =
  "The relay passed on a key exchange before it had let you into the room \u2014 an honest relay " +
  "never does that, so this connection attempt was stopped and nothing was exchanged. " +
  "Press Connect to try again.";
const LOOKUP_SENTENCE =
  "The directory did not answer within 20 seconds, so the contact lookup was stopped and nothing " +
  "was connected. Press Connect to try again — or leave the contact field blank and compare a " +
  "safety number instead.";

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

// Long timers (the two deadlines) are recorded and fired by hand.
const realSetTimeout = globalThis.setTimeout;
const realClearTimeout = globalThis.clearTimeout;
const mine = new WeakSet();
const longTimers = [];
globalThis.setTimeout = (fn, ms, ...a) => {
  if (ms >= 20000) {
    const t = { fn, ms, cleared: false, fired: false };
    mine.add(t);
    longTimers.push(t);
    return t;
  }
  return realSetTimeout(fn, ms, ...a);
};
globalThis.clearTimeout = (t) => { if (mine.has(t)) t.cleared = true; else realClearTimeout(t); };
const lastTimer = (ms) => longTimers.filter((t) => t.ms === ms).at(-1);
const fire = async (t) => { assert.ok(t && !t.fired, "a deadline to fire"); t.fired = true; t.fn(); await settle(); };

// The directory, played per block: `users` answers /api/users/<name>.
let users = null;
globalThis.fetch = async (url, opts = {}) => {
  if (String(url).includes("/api/users/") && users) return users(String(url), opts);
  return new Response("{}", { status: 404 });
};
// A lookup that answers only by failing when it is aborted — as a real fetch does.
const hangUntilAborted = (_u, opts) => new Promise((_, reject) => {
  if (opts.signal) opts.signal.addEventListener("abort", () => reject(opts.signal.reason));
});

const dom = installDom(join(HERE, "index.html"));
dom.body.appendChild(dom.el("tabbar"));
dom.seedAlgRadios(["DHKE", "AES256", "PQKEM", "OTP"], "AES256");
dom.seedNavItems(["live", "chats", "users", "profile"]);
dom.seedChild("scrChat", "div", "topbar");
for (const id of ["usersLocked", "chatsLocked"]) dom.seedChild(id, "p", "hint");
{ const row = new El("div"); row.className = "row"; row.appendChild(dom.el("username")); }

// Web Locks with `ifAvailable` (as in app-otp.test.mjs), plus a gate that can
// hold the NEXT request's grant — a Cancel pressed while the pad lock is asked for.
const held = new Set();
let lockGate = null;
globalThis.navigator = {
  ...globalThis.navigator,
  locks: {
    async request(name, opts, fn) {
      if (lockGate) { const g = lockGate; lockGate = null; await g; }
      if (held.has(name) && opts && opts.ifAvailable) return fn(null);
      held.add(name);
      try { return await fn({ name }); } finally { held.delete(name); }
    },
  },
};

// Hold the next call of a crypto.subtle method until the test releases it.
// `fail(err)` releases it with a rejection instead.
function gateNext(method) {
  const real = crypto.subtle[method];
  let release;
  const gate = new Promise((r) => { release = r; });
  let entered = false;
  crypto.subtle[method] = async function (...a) {
    crypto.subtle[method] = real;
    entered = true;
    const err = await gate;
    if (err) throw err;
    return real.apply(this, a);
  };
  return { release: () => release(null), fail: (err) => release(err), entered: () => entered };
}
// A peer that never answers the Close frame (a hostile relay, a half-open
// connection): close() leaves the socket CLOSING and runs no onclose — in a
// browser that wait is its closing-handshake timeout (60 s in Chromium).
function stallClose(ws) {
  ws.close = function () { if (this.readyState < 2) this.readyState = 2; };
}

await import("./app.js");
const otp = await import("./otp.js");

const settle = async (n = 20) => { for (let i = 0; i < n; i++) await new Promise((r) => realSetTimeout(r, 2)); };
const until = async (cond, what, ms = 20000) => {
  const t0 = Date.now();
  while (!cond()) {
    if (Date.now() - t0 > ms) throw new Error("timed out waiting for " + what +
      " / status=" + dom.el("status").textContent + " / roomHint=" + dom.el("roomHint").textContent);
    await new Promise((r) => realSetTimeout(r, 5));
  }
};
const el = (id) => dom.el(id);
const cancelShown = () => el("connectCancel").hidden === false;
const onRoomScreen = () => el("scrRoom").hidden === false && el("scrChat").hidden === true;

function prepare(alg, { contact = "", padId = "" } = {}) {
  el("room").value = ROOM;
  el("pass").value = PASS;
  el("contact").value = contact;
  dom.selectAlg(alg);
  if (alg === "OTP") { el("otpSelect").value = padId; el("otpPass").value = PAD_PASS; }
}
// Connect and wait until the socket exists (the stub never opens it by itself).
async function connectToSocket(alg = "AES256", o = {}) {
  prepare(alg, o);
  const before = dom.socket();
  el("connect").click();
  await until(() => dom.socket() !== before, "connect() to open a socket");
  return dom.socket();
}
// The room screen after a close: what every way out must leave behind.
function assertBackOnRoom(what) {
  assert.ok(onRoomScreen(), what + ": the room screen is shown");
  assert.strictEqual(el("connect").disabled, false, what + ": Connect is enabled again");
  assert.strictEqual(el("connectCancel").hidden, true, what + ": Cancel is hidden again");
  assert.strictEqual(el("status").textContent, "disconnected", what + ": the status says disconnected");
}

el("toRoom").click(); // the tests start on the room screen (no identity needed for AES256/OTP)
el("room").value = ROOM;
await el("room").dispatch("input"); // typed over: not a code this page minted
// The stub does not read `hidden` from the markup: check it there, then mirror it.
assert.match(readFileSync(join(HERE, "index.html"), "utf8"), /<button id="connectCancel"[^>]*\shidden>Cancel<\/button>/,
  "C: the page starts with Cancel hidden (index.html)");
el("connectCancel").hidden = true;

// ---- J: the join deadline ------------------------------------------------------
{
  const ws = await connectToSocket();
  assert.ok(cancelShown(), "C: Cancel is offered while the socket is opening");
  assert.strictEqual(el("connect").disabled, true, "fixture: Connect is disabled while it is in flight");
  const t = lastTimer(30000);
  assert.ok(t && !t.cleared, "J: a 30 s deadline is armed when the socket is built (before it opens)");
  ws.open();
  await settle();
  assert.deepStrictEqual(ws.sent[0], { type: "join", room: ROOM }, "fixture: join was sent");
  assert.ok(cancelShown(), "C: ...and while the relay has not answered join");
  document.activeElement = el("room"); // the user is typing elsewhere
  el("connect")._focused = false;
  await fire(t); // the relay never answers
  assert.strictEqual(el("connect")._focused, false, "C (N1): a Cancel going away does not take the focus from elsewhere");
  document.activeElement = null;
  assert.match(el("roomHint").className, /\berr\b/, "J: the sentence is shown as an error (N2)");
  assert.strictEqual(ws.readyState, 3, "J: an unanswered join is closed at the deadline");
  assertBackOnRoom("J");
  assert.strictEqual(el("roomHint").textContent, JOIN_SENTENCE, "J: ...with the fixed sentence, byte for byte");
  console.log("OK  J: a relay that never answers join is closed after 30 s with a fixed sentence; Connect is back (executed)");
}
{
  // The deadline also covers a socket that never opens (a TCP / TLS hang).
  const ws = await connectToSocket();
  await fire(lastTimer(30000));
  assert.strictEqual(ws.readyState, 3, "J: a socket still CONNECTING at the deadline is closed too");
  assertBackOnRoom("J (connecting)");
  assert.strictEqual(el("roomHint").textContent, JOIN_SENTENCE, "J (connecting): the same sentence");
  console.log("OK  J: the deadline runs from the socket's construction, so a socket that never opens ends too (executed)");
}
{
  // A guest the relay put in the admission queue is waiting legitimately.
  const ws = await connectToSocket();
  const t = lastTimer(30000);
  ws.open();
  await ws.deliver({ type: "pending" });
  await settle();
  assert.strictEqual(el("scrChat").hidden, false, "fixture: pending moves to the chat screen (Disconnect is there)");
  assert.strictEqual(el("connectCancel").hidden, true, "C: Cancel is withdrawn once the relay answered (pending)");
  if (!t.cleared) await fire(t);
  assert.notStrictEqual(ws.readyState, 3, "J: a guest waiting for admission is NOT timed out");
  assert.strictEqual(el("scrChat").hidden, false, "J: ...and stays on the chat screen, waiting");
  el("disconnect").click();
  await settle();
  assertBackOnRoom("fixture (Disconnect)");
  assert.notStrictEqual(el("roomHint").textContent, JOIN_SENTENCE, "J: no timeout sentence after a waiting guest's Disconnect");
  console.log("OK  J: a guest waiting in the admission queue (`pending`) is never timed out (executed)");
}
{
  // The owner: `joined` answers too. ‹ Back to room then shows no Cancel for a running session.
  const ws = await connectToSocket();
  const t = lastTimer(30000);
  ws.open();
  await ws.deliver({ type: "joined", role: "owner" });
  await settle();
  assert.strictEqual(el("scrChat").hidden, false, "fixture: joined moves to the chat screen");
  el("toRoom").click();
  assert.ok(onRoomScreen(), "fixture: ‹ Back to room shows the room screen over a live session");
  assert.strictEqual(el("connectCancel").hidden, true, "C: no Cancel on the room screen of a session the relay answered");
  el("connectCancel").click(); // even if it were reached somehow, it does not end an answered session
  await settle();
  assert.notStrictEqual(ws.readyState, 3, "C: Cancel never closes a session the relay has answered");
  if (!t.cleared) await fire(t);
  assert.notStrictEqual(ws.readyState, 3, "J: an owner the relay seated is not timed out");
  el("disconnect").click();
  await settle();
  assertBackOnRoom("fixture (owner Disconnect)");
  console.log("OK  J/C: `joined` ends the deadline and the Cancel; ‹ Back to room shows none for a running session (executed)");
}
{
  // The relay says why and hangs up before answering: its reason stays on screen.
  const ws = await connectToSocket();
  const t = lastTimer(30000);
  ws.open();
  await ws.deliver({ type: "error", reason: "join timeout" }); // the relay's own (fatal, parked for the room screen)
  ws.close(); // the relay's close (the stub runs onclose at once)
  await settle();
  const said = el("roomHint").textContent;
  assert.strictEqual(said, "Joining took too long, so the relay closed the connection. Connect again.",
    "fixture: the relay's reason is on the room screen");
  if (!t.cleared) await fire(t); // a deadline the close left armed would fire now
  assert.strictEqual(el("roomHint").textContent, said, "J: a deadline never fires after the socket closed (the relay's reason stays)");
  console.log("OK  J: a socket the relay closed is not 'timed out' later over its reason (executed)");
}

{
  // A new connect starts a new deadline and ends the old one. (Connect is
  // disabled while a socket lives; the stub's click ignores that, as a future
  // path that reconnects without the button would.)
  const a = await connectToSocket();
  a.open();
  const ta = lastTimer(30000);
  const b = await connectToSocket();
  b.open();
  await settle();
  if (!ta.cleared) await fire(ta);
  assert.notStrictEqual(a.readyState, 3, "J: the previous socket's deadline does not fire after a new connect");
  assert.notStrictEqual(el("roomHint").textContent, JOIN_SENTENCE, "J: ...and says nothing");
  assert.ok(el("status").textContent === "connecting…" && el("connect").disabled && cancelShown(),
    "J: ...and the new attempt is untouched (still in flight, Cancel offered)");
  await fire(lastTimer(30000));
  assert.strictEqual(b.readyState, 3, "control: the new socket's own deadline fires");
  a.close();
  await settle();
  console.log("OK  J: a new connect ends the previous socket's deadline (executed)");
}

// ---- C: Cancel with the socket up ---------------------------------------------
{
  const ws = await connectToSocket();
  ws.open();
  await settle();
  assert.ok(cancelShown(), "fixture: Cancel shown");
  el("connectCancel").click();
  await settle();
  assert.strictEqual(ws.readyState, 3, "C: Cancel closes an unanswered socket");
  assertBackOnRoom("C (socket)");
  assert.strictEqual(el("roomHint").textContent, "", "C: a Cancel the user pressed needs no sentence");
  assert.strictEqual(lastTimer(30000).cleared, true, "C: ...and its deadline is gone with it");
  console.log("OK  C: Cancel on an unanswered socket is Disconnect: closed, room screen, Connect back (executed)");
}

// ---- C: an OTP connect's pad lock goes with the Cancel --------------------------
const pad = await otp.generatePad({ label: "live", totalBytes: 8192, fingerBytes: new Uint8Array(0) });
await otp.saveNewPad(pad, PAD_PASS);
const LOCK = "sc.otp.lock.v1." + pad.padId;
{
  const ws = await connectToSocket("OTP", { padId: pad.padId });
  assert.ok(held.has(LOCK), "fixture: the OTP connect holds its pad's lock");
  ws.open();
  await settle();
  el("connectCancel").click();
  await until(() => !held.has(LOCK), "the pad lock to be released after Cancel");
  assertBackOnRoom("C (OTP)");
  const again = await connectToSocket("OTP", { padId: pad.padId });
  assert.ok(held.has(LOCK), "C: the same pad connects again at once (no reload)");
  again.open();
  await fire(lastTimer(30000));
  await until(() => !held.has(LOCK), "the pad lock to be released after the deadline");
  assertBackOnRoom("J (OTP)");
  assert.strictEqual(el("roomHint").textContent, JOIN_SENTENCE, "J (OTP): the fixed sentence");
  console.log("OK  C/J: an OTP connect's pad lock is released by Cancel and by the deadline; the pad reconnects (executed)");
}
{
  // Cancel while the pad lock is being granted: the lock, once granted, is let go.
  let release;
  lockGate = new Promise((r) => { release = r; });
  prepare("OTP", { padId: pad.padId });
  const before = dom.socket();
  el("connect").click();
  await settle();
  assert.ok(cancelShown(), "C: Cancel is offered while the pad lock is asked for");
  el("connectCancel").click();
  release();
  await until(() => el("connect").disabled === false, "the cancelled connect to end");
  await settle();
  assert.strictEqual(dom.socket(), before, "C: a Cancel before the socket opens no socket");
  assert.ok(!held.has(LOCK), "C: ...and the pad lock granted after the Cancel is released");
  assertBackOnRoom("C (lock)");
  console.log("OK  C: Cancel while the pad lock is being granted: no socket, lock released (executed)");
}
{
  // ...and a lock that turns out to be held elsewhere is not reported after the Cancel.
  held.add(LOCK); // another tab has the pad
  prepare("OTP", { padId: pad.padId });
  el("connect").click();
  await until(() => el("connect").disabled === false, "the refused connect to end");
  assert.match(el("roomHint").textContent, /open in another tab or window/, "fixture: a pad held elsewhere is refused");
  let release;
  lockGate = new Promise((r) => { release = r; });
  el("connect").click();
  await settle();
  el("connectCancel").click();
  release();
  await until(() => el("connect").disabled === false, "the cancelled connect to end");
  assert.strictEqual(el("roomHint").textContent, "", "C: after a Cancel, the lock's answer is not narrated");
  held.delete(LOCK);
  console.log("OK  C: a Cancel while the pad lock is asked for ends the attempt at the lock's answer (executed)");
}
{
  // Cancel while the stored pad is read under its lock.
  const g = gateNext("decrypt");
  prepare("OTP", { padId: pad.padId });
  const before = dom.socket();
  el("connect").click();
  await until(g.entered, "the pad read to start");
  assert.ok(held.has(LOCK), "fixture: the lock is held during the read");
  el("connectCancel").click();
  g.release();
  await until(() => el("connect").disabled === false, "the cancelled connect to end");
  await settle();
  assert.strictEqual(dom.socket(), before, "C: a Cancel during the pad read opens no socket");
  assert.ok(!held.has(LOCK), "C: ...and releases the pad lock");
  assertBackOnRoom("C (pad read)");
  console.log("OK  C: Cancel while the pad is read: no socket, lock released (executed)");
}
{
  // ...and what the read found is not acted on: a used-up pad is not reported after the Cancel.
  const spent = await otp.generatePad({ label: "spent", totalBytes: 8192, fingerBytes: new Uint8Array(0) });
  spent.sendOffset = spent.regionSize - 10;
  await otp.saveNewPad(spent, PAD_PASS);
  prepare("OTP", { padId: spent.padId });
  el("connect").click();
  await until(() => el("connect").disabled === false, "the refused connect to end");
  assert.match(el("roomHint").textContent, /used up/, "fixture: the used-up pad is refused");
  const g = gateNext("decrypt");
  el("connect").click();
  await until(g.entered, "the pad read to start");
  el("connectCancel").click();
  g.release();
  await until(() => el("connect").disabled === false, "the cancelled connect to end");
  assert.strictEqual(el("roomHint").textContent, "", "C: after a Cancel, what the pad read found is not narrated");
  assert.ok(!held.has("sc.otp.lock.v1." + spent.padId), "C: ...and its lock is released");
  console.log("OK  C: a Cancel during the pad read ends the attempt at the read's answer (executed)");
}
{
  // Cancel during the key setup (AES256's passphrase KDF).
  const g = gateNext("deriveBits");
  prepare("AES256");
  const before = dom.socket();
  el("connect").click();
  await until(g.entered, "the key setup to start");
  el("connectCancel").click();
  g.release();
  await until(() => el("connect").disabled === false, "the cancelled connect to end");
  await settle();
  assert.strictEqual(dom.socket(), before, "C: a Cancel during the key setup opens no socket");
  assertBackOnRoom("C (key setup)");
  console.log("OK  C: Cancel during the key setup opens no socket (executed)");
}
{
  // Fix round 1, C1-3: a key setup that FAILS after the Cancel is not narrated...
  const g = gateNext("deriveBits");
  prepare("AES256");
  el("connect").click();
  await until(g.entered, "the key setup to start");
  el("connectCancel").click();
  g.fail(new Error("the KDF broke"));
  await until(() => el("connect").disabled === false, "the cancelled connect to end");
  assert.strictEqual(el("roomHint").textContent, "", "C1-3: a key setup failing after the Cancel is not narrated");
  assertBackOnRoom("C1-3 (key setup)");
  // ...but a pad READ that fails after it still is: it may be the stored pad's
  // tamper or damage warning, and a Cancel must not silence that.
  const r = gateNext("decrypt");
  prepare("OTP", { padId: pad.padId });
  el("connect").click();
  await until(r.entered, "the pad read to start");
  el("connectCancel").click();
  r.fail(new Error("the stored pad does not decrypt"));
  await until(() => el("connect").disabled === false, "the cancelled connect to end");
  assert.notStrictEqual(el("roomHint").textContent, "", "C1-3: a pad read failing after the Cancel is still narrated");
  assert.ok(!held.has(LOCK), "C1-3: ...and the pad lock is released");
  console.log("OK  C1-3: after a Cancel a failed key setup is silent, a failed pad read is still said (executed)");
}

// ---- fix round 1, C1-1 / C1-2: a peer that never answers the Close frame --------
{
  // Cancel: back on the room screen at once, not when the browser gives up.
  const ws = await connectToSocket();
  ws.open();
  stallClose(ws);
  el("connectCancel").click();
  await settle();
  assert.strictEqual(ws.readyState, 2, "fixture: the socket is still CLOSING (the peer never answers)");
  assertBackOnRoom("C1-2 (Cancel)");
  assert.strictEqual(el("roomHint").textContent, "", "C1-2: ...with no sentence");
  // The next attempt runs; the old socket's late events must not touch it.
  const late = { close: ws.onclose, error: ws.onerror };
  const next = await connectToSocket();
  next.open();
  await settle();
  ws.readyState = 3;
  if (late.error) late.error({});
  if (late.close) late.close({});
  await settle();
  assert.strictEqual(el("status").textContent, "connecting…", "C1-2: the old socket's late error / close do not reach the next attempt");
  assert.ok(cancelShown() && el("connect").disabled, "C1-2: ...which is still in flight");
  el("connectCancel").click();
  await settle();
  assertBackOnRoom("fixture (next)");
  console.log("OK  C1-2: Cancel against a peer that never answers the Close ends the attempt at once; its late events are inert (executed)");
}
{
  // The deadline: the same, with its sentence.
  const ws = await connectToSocket();
  ws.open();
  stallClose(ws);
  await fire(lastTimer(30000));
  assert.strictEqual(ws.readyState, 2, "fixture: still CLOSING");
  assertBackOnRoom("C1-2 (deadline)");
  assert.strictEqual(el("roomHint").textContent, JOIN_SENTENCE, "C1-2: the deadline's sentence at once");
  console.log("OK  C1-2: the deadline against a peer that never answers the Close ends the attempt at 30 s (executed)");
}
{
  // OTP: the pad lock comes back at once too.
  const ws = await connectToSocket("OTP", { padId: pad.padId });
  ws.open();
  stallClose(ws);
  el("connectCancel").click();
  await until(() => !held.has(LOCK), "the pad lock to be released while the socket is still closing");
  assert.strictEqual(ws.readyState, 2, "fixture: still CLOSING");
  assertBackOnRoom("C1-2 (OTP)");
  console.log("OK  C1-2: an OTP connect's pad lock is released at the Cancel, not at the browser's close (executed)");
}
{
  // C1-1: a client refusal on a socket that stays CLOSING keeps its own words,
  // whether the deadline or a Cancel comes next. The fixture was the
  // removed-mode refusal of a `key` frame before the relay answered `join` — a
  // closeWs, so the attempt waited for its close. Since 2026-09-27 (block E)
  // any `key` frame before an answer is refused through endUnanswered, at once:
  // the same frame now binds that the early-key refusal ends the attempt
  // although the close stalls, and that nothing after it relabels it. (The
  // refusal clears the deadline and hides Cancel, so neither really runs
  // here; C1-1's own scenario has no relay trigger left and its guard is
  // bound directly in block E.)
  for (const next of ["deadline", "cancel"]) {
    const ws = await connectToSocket();
    const t = lastTimer(30000);
    ws.open();
    stallClose(ws);
    await ws.deliver({ type: "key", room: ROOM, alg: "RSA", payload: "AAAA" });
    await settle();
    assert.strictEqual(ws.readyState, 2, "fixture: the refusal's close is stalled");
    assertBackOnRoom("C1-1 / E (" + next + ", at once)");
    assert.strictEqual(el("roomHint").textContent, EARLY_KEY_SENTENCE,
      "E: a key frame before any answer is the early-key refusal, not the removed-mode one (" + next + ")");
    if (next === "deadline") { if (!t.cleared) await fire(t); }
    else { el("connectCancel").click(); await settle(); }
    assertBackOnRoom("C1-1 (" + next + ")");
    assert.strictEqual(el("roomHint").textContent, EARLY_KEY_SENTENCE, `C1-1: after the ${next}, the room screen keeps the refusal, not the timeout sentence`);
  }
  console.log("OK  C1-1 / E: the early-key refusal ends the attempt at once although its close stalls; nothing after it relabels it (executed)");
}
{
  // Fix round 2, C2-1: a refusal of the relay's ANSWER to join comes before the
  // chat screen (no Disconnect), some after roomRole is set (no Cancel, no
  // deadline): it ends at once, with its sentence, whatever the close does.
  const cases = [
    { what: "pending to the creator", mint: true, frame: { type: "pending" }, said: /^You created this code, so you should be the one approving people\. Connect first/ },
    { what: "joined without a role", mint: false, frame: { type: "joined" }, said: /^This relay is running an older protocol/ },
    { what: "the creator seated as a guest", mint: true, frame: { type: "joined", role: "guest" }, said: /^You created this code, so you should be the one approving people\. The relay tried to seat you/ },
    { what: "a guest seated without queueing", mint: false, frame: { type: "joined", role: "guest" }, said: /^This relay put you in the room without the owner approving you\./ },
  ];
  for (const c of cases) {
    if (c.mint) await el("gen").click(); // New code: this page is the room's creator (F-PROTO-001)
    else { el("room").value = ROOM; await el("room").dispatch("input"); }
    el("pass").value = PASS;
    dom.selectAlg("AES256");
    const before = dom.socket();
    el("connect").click();
    await until(() => dom.socket() !== before, "the socket (" + c.what + ")");
    const ws = dom.socket();
    const t = lastTimer(30000);
    ws.open();
    stallClose(ws);
    await ws.deliver(c.frame);
    await settle();
    assert.strictEqual(ws.readyState, 2, "fixture: the close stalls (" + c.what + ")");
    assertBackOnRoom("C2-1 (" + c.what + ")");
    assert.match(el("roomHint").textContent, c.said, "C2-1: " + c.what + " is refused at once, with its sentence");
    if (!t.cleared) await fire(t);
    assert.match(el("roomHint").textContent, c.said, "C2-1: ...and the deadline does not relabel it (" + c.what + ")");
  }
  el("room").value = ROOM;
  await el("room").dispatch("input");
  console.log("OK  C2-1: the four refusals of the relay's answer end at once although the close stalls (executed)");
}
// ---- C3-2: the relay's answer handled after the relay's own close ---------------
// Frames of a socket the RELAY closed are still handled (its last words, see
// the gate at the top of handleMessage). A `joined` still queued on msgChain
// when the close event ran finds onclose's reset state. The stub forces that
// order: the frame is queued (onmessage only chains it) and the relay's close
// runs onclose in the same task, before the chain gets to it. A hostile relay
// forced the same order in Chromium by parking the pump on the guest approval
// prompt first (C3-2 r1 R1-2). Since 2026-09-27 (block E) that works only
// after a `pending` — before any answer the key exchange is refused — so the
// `joined:guest` case is still forced there (e2e/forced-late-answer.mjs). Which checks still
// run after the close is deliberate: those whose inputs survive onclose.
const logLines = () => dom.el("log").children;
const disconnectedLines = () => logLines().filter((c) => /^disconnected\b/.test(c.textContent)).length;
// The whole log's text: addLine folds a repeated line into "(×2)" in place or
// moves it, so counting new lines is not enough (pentest C3-2 r2 R2-3, r3 R3-1).
const logText = () => JSON.stringify(logLines().map((c) => c.textContent));
function answerThenRelayClose(ws, frame) {
  ws.onmessage({ data: JSON.stringify(frame) });
  ws.close(); // the relay's close, not closeWs(): the stub runs onclose now
}
{
  // An owner's seat handled after the close.
  const ws = await connectToSocket();
  ws.open();
  const lines0 = logLines().length;
  answerThenRelayClose(ws, { type: "joined", role: "owner" });
  await settle();
  assert.strictEqual(ws.readyState, 3, "fixture: the relay closed the socket");
  assertBackOnRoom("C3-2 (owner seated after the close)");
  assert.ok(!logLines().slice(lines0).some((c) => /joined room|you created this chat/.test(c.textContent)),
    "C3-2: a seat handled after the close is not narrated as a session start");
  assert.ok(!ws.sent.some((f) => f.type === "key"), "C3-2: ...and no hello is sent into the dead socket");
  // Positive control: the next session is seated as always, and Disconnect ends it.
  const ws2 = await connectToSocket();
  ws2.open();
  await ws2.deliver({ type: "joined", role: "owner" });
  await settle();
  assert.strictEqual(el("scrChat").hidden, false, "control: an answer handled while the socket is open seats us");
  assert.strictEqual(el("status").textContent, "connected", "control: ...connected");
  el("disconnect").click();
  await settle();
  assertBackOnRoom("control (Disconnect after the late seat)");
  console.log("OK  C3-2: an owner's seat handled after the relay's close draws no chat for the dead socket (executed)");
}
{
  // A guest's seat handled after the close — after an honest `pending`, and
  // without one. Neither is refused on state onclose already wiped, and
  // neither leaves the seat behind: the next session's `denied` is said.
  for (const c of [{ what: "after pending", queued: true }, { what: "without pending", queued: false }]) {
    const ws = await connectToSocket();
    ws.open();
    if (c.queued) {
      await ws.deliver({ type: "pending" });
      await settle();
      assert.strictEqual(el("scrChat").hidden, false, "fixture: pending moves to the chat screen (" + c.what + ")");
    }
    answerThenRelayClose(ws, { type: "joined", role: "guest" });
    await settle();
    assertBackOnRoom("C3-2 (guest seated after the close, " + c.what + ")");
    const lateHint = el("roomHint").textContent; // asserted after the next session: each check fails on its own
    const ws2 = await connectToSocket();
    ws2.open();
    await ws2.deliver({ type: "pending" });
    const lines0 = logLines().length;
    await ws2.deliver({ type: "denied" });
    await settle();
    assert.ok(logLines().slice(lines0).some((l) => /the other person did not let you in/.test(l.textContent)),
      "C3-2: the next session's `denied` is said (" + c.what + ")");
    ws2.close(); // the relay closes after denied
    await settle();
    assertBackOnRoom("fixture (declined, " + c.what + ")");
    assert.doesNotMatch(lateHint, /put you in the room without the owner approving/,
      "C3-2: a guest seat handled after the close is not judged on the wiped queue state (" + c.what + ")");
  }
  console.log("OK  C3-2: a guest's seat handled after the close is not refused on wiped state, and leaves no seat behind (executed)");
}
{
  // Round 1 (R1-1): `pending` handled after the relay's close is not acted on
  // either — no "waiting for approval" chat for the dead socket, no knock.
  const ws = await connectToSocket();
  ws.open();
  const lines0 = logLines().length;
  answerThenRelayClose(ws, { type: "pending" });
  await settle();
  assertBackOnRoom("R1-1 (pending after the close)");
  assert.ok(!logLines().slice(lines0).some((c) => /waiting — the person who created/.test(c.textContent)),
    "R1-1: a pending handled after the close is not narrated");
  assert.ok(!ws.sent.some((f) => f.type === "knock"), "R1-1: ...and no knock is sent into the dead socket");
  console.log("OK  C3-2 r1 R1-1: a pending handled after the relay's close draws no waiting chat, sends no knock (executed)");
}
{
  // Round 1 (R1-4): after the relay's close, a refusal that reads only what
  // onclose leaves (the frame itself, whether this page minted the code) is
  // still said on the room screen, as the L2 "last words" design wants.
  const cases = [
    { what: "joined without a role", mint: false, frame: { type: "joined" }, said: /^This relay is running an older protocol/ },
    { what: "the creator seated as a guest", mint: true, frame: { type: "joined", role: "guest" }, said: /^You created this code, so you should be the one approving people\. The relay tried to seat you/ },
    { what: "pending to the creator", mint: true, frame: { type: "pending" }, said: /^You created this code, so you should be the one approving people\. Connect first/ },
  ];
  for (const c of cases) {
    if (c.mint) await el("gen").click();
    else { el("room").value = ROOM; await el("room").dispatch("input"); }
    el("pass").value = PASS;
    dom.selectAlg("AES256");
    const before = dom.socket();
    el("connect").click();
    await until(() => dom.socket() !== before, "the socket (" + c.what + ")");
    const ws = dom.socket();
    ws.open();
    answerThenRelayClose(ws, c.frame);
    await settle();
    assertBackOnRoom("R1-4 (" + c.what + " after the close)");
    assert.match(el("roomHint").textContent, c.said, "R1-4: " + c.what + " after the relay's close is still refused, with its sentence");
  }
  el("room").value = ROOM;
  await el("room").dispatch("input");
  console.log("OK  C3-2 r1 R1-4: refusals that read nothing onclose reset are still said after the relay's close (executed)");
}
{
  // CLOSING: the relay's Close arrived, the close event has not. The refusals
  // still read live state and are said at once; a seat is not drawn, and the
  // relay HAS answered, so the join deadline ends (R1-3) — Cancel stays usable.
  for (const frame of [{ type: "joined", role: "owner" }, { type: "pending" }]) {
    const what = JSON.stringify(frame);
    const ws = await connectToSocket();
    const t = lastTimer(30000);
    ws.open();
    stallClose(ws);
    ws.readyState = 2; // the relay's Close frame came in; the browser waits for the TCP close
    const log0 = logText();
    await ws.deliver(frame);
    await settle();
    assert.strictEqual(el("scrChat").hidden, true, "C3-2: " + what + " on a CLOSING socket draws no chat screen");
    assert.strictEqual(logText(), log0, "C3-2 r3 R3-1: ...and narrates nothing — no session start, no waiting line (" + what + ")");
    assert.ok(!/^(connected|waiting for approval)$/.test(el("status").textContent), "C3-2: ...and says neither 'connected' nor 'waiting' (" + what + ")");
    assert.ok(!ws.sent.some((f) => f.type === "key" || f.type === "knock"), "C3-2: ...and sends no hello or knock (" + what + ")");
    assert.ok(cancelShown(), "C3-2: Cancel stays offered on the CLOSING socket (" + what + ")");
    await ws.deliver({ type: "error", reason: "room closed" }); // the relay's reason, parked for the close
    if (!t.cleared) await fire(t); // a deadline left armed fires before the close event comes
    const before = disconnectedLines();
    ws.readyState = 3;
    if (ws.onclose) ws.onclose({}); // the close event (a deadline that fired has run it already)
    await settle();
    assertBackOnRoom("C3-2 (" + what + " on a CLOSING socket, then its close)");
    assert.strictEqual(el("roomHint").textContent, "The person who created this chat left, so the chat was closed.",
      "R1-3: the relay's own reason is on the room screen, not the join timeout (" + what + ")");
    assert.strictEqual(disconnectedLines(), before, "C3-2: a seat withheld on CLOSING is not narrated as a session end (" + what + ")");
  }
  for (const frame of [{ type: "joined", role: "owner" }, { type: "pending" }]) {
    // Cancel on a CLOSING socket whose answer was withheld: back at once, the
    // socket still closing (pentest C3-2 r2 R2-2: shown AND working).
    const what = JSON.stringify(frame);
    const ws = await connectToSocket();
    ws.open();
    stallClose(ws);
    ws.readyState = 2;
    const log0 = logText();
    await ws.deliver(frame);
    await settle();
    assert.strictEqual(logText(), log0, "C3-2 r3 R3-1: a withheld " + what + " narrates nothing before the Cancel");
    el("connectCancel").click();
    await settle();
    assert.strictEqual(ws.readyState, 2, "fixture: the socket is still closing (" + what + ")");
    assertBackOnRoom("C3-2 (Cancel on a CLOSING socket after " + what + ")");
  }

  const ws2 = await connectToSocket();
  ws2.open();
  stallClose(ws2);
  ws2.readyState = 2;
  await ws2.deliver({ type: "joined", role: "guest" });
  await settle();
  assertBackOnRoom("C3-2 (unqueued guest on a CLOSING socket)");
  assert.match(el("roomHint").textContent, /^This relay put you in the room without the owner approving you\./,
    "C3-2: a refusal on a CLOSING socket (its onclose has not run) is still said at once");
  {
    // Pentest C3-2 r2 R2-1, decided: a `pending` withheld on CLOSING sends no
    // knock, so a `joined:guest` behind it is a seat no owner could have
    // approved — the unqueued-guest refusal, at once, over a reason parked later.
    const ws = await connectToSocket();
    ws.open();
    stallClose(ws);
    ws.readyState = 2;
    await ws.deliver({ type: "pending" });
    await ws.deliver({ type: "joined", role: "guest" });
    await ws.deliver({ type: "error", reason: "room closed" }); // behind the refusal: dropped
    await settle();
    assert.ok(!ws.sent.some((f) => f.type === "knock"), "fixture: the withheld pending sent no knock");
    assertBackOnRoom("R2-1 (pending, joined:guest on a CLOSING socket)");
    assert.match(el("roomHint").textContent, /^This relay put you in the room without the owner approving you\./,
      "R2-1: a guest seat after a pending withheld on CLOSING is refused as unqueued (no knock was sent)");
  }
  console.log("OK  C3-2: on a CLOSING socket no seat is drawn, the deadline ends, Cancel works, a refusal is still said (executed)");
}
{
  // The role-change refusal (rewritten by C3-2; r1 test gap 1): a guest the
  // owner let in, re-cast as the owner, is refused — no second session start.
  const ws = await connectToSocket();
  ws.open();
  await ws.deliver({ type: "pending" });
  await ws.deliver({ type: "joined", role: "guest" });
  await settle();
  assert.strictEqual(el("status").textContent, "connected", "fixture: pending, then joined:guest seats the guest");
  const hellos = () => ws.sent.filter((f) => f.type === "key").length;
  assert.strictEqual(hellos(), 1, "fixture: one hello");
  await ws.deliver({ type: "joined", role: "owner" });
  await settle();
  assertBackOnRoom("role change");
  assert.strictEqual(el("roomHint").textContent, "The relay tried to change your role in this room. Disconnected.",
    "role change: a seated guest re-cast as the owner is refused, with its sentence");
  assert.strictEqual(hellos(), 1, "role change: ...and no second hello is sent");
  // Before any seat (pentest C3-2 r2 R2-5): `pending` made us a guest, so a
  // `joined:owner` is the relay re-casting us, refused — not a guest seat.
  const ws2 = await connectToSocket();
  ws2.open();
  await ws2.deliver({ type: "pending" });
  await ws2.deliver({ type: "joined", role: "owner" });
  await settle();
  assertBackOnRoom("role change before the seat");
  assert.strictEqual(el("roomHint").textContent, "The relay tried to change your role in this room. Disconnected.",
    "role change: a queued guest told it is the owner is refused, with its sentence");
  assert.ok(!ws2.sent.some((f) => f.type === "key"), "role change: ...and no hello is sent");
  console.log("OK  C3-2 r1/r2: a role the relay changes, before or after the seat, is refused (executed)");
}
{
  // The refusals of the answer take no seat: `joined` is written after them,
  // so onclose does not narrate a session end ("disconnected") that never began.
  for (const frame of [{ type: "joined" }, { type: "joined", role: "guest" }]) {
    const ws = await connectToSocket();
    ws.open();
    const before = disconnectedLines();
    await ws.deliver(frame);
    await settle();
    assertBackOnRoom("C3-2 (refused " + JSON.stringify(frame) + ")");
    assert.strictEqual(disconnectedLines(), before,
      "C3-2: a refused answer (" + JSON.stringify(frame) + ") is not narrated as a session that ended");
  }
  // Control: a session that was seated IS narrated when it ends.
  const ws = await connectToSocket();
  ws.open();
  await ws.deliver({ type: "joined", role: "owner" });
  const before = disconnectedLines();
  ws.close();
  await settle();
  assert.strictEqual(disconnectedLines(), before + 1, "control: a seated session's end is narrated");
  console.log("OK  C3-2: a refused answer takes no seat; a seated session's end is still narrated (executed)");
}

// ---- E: key exchange before any answer to join (owner decision 2026-09-27) ------
// Pentest C3-2 r2, pre-existing lead: a relay-signed handshake with no role
// raised the guest approval prompt inside the hidden chat screen — invisible,
// the tab bar inert, the pump parked on it (and the lever of C3-2 r1 R1-2).
// An honest relay forwards nothing before it answers `join`, so any `key`
// frame then is refused at once with a fixed sentence; nothing of ours (nonce,
// signed key) goes back and no prompt is raised. On a socket that is no longer
// OPEN it is dropped instead: its close says what ended it.
const b64json = (o) => Buffer.from(JSON.stringify(o)).toString("base64");
const promptShown = () => el("admit").hidden === false;
const frames0 = () => ({ hello: true, n: Buffer.alloc(32, 9).toString("base64"), reply: false }); // a peer hello
{
  const frames = {
    "a peer hello": { hello: true, n: Buffer.alloc(32, 7).toString("base64"), reply: false },
    "a handshake": { pub: "AAAA", reply: false, idb: { ed: "AAAA" }, sig: { ed: "AAAA" } },
    "a confirmation tag": { confirm: "AAAA" },
  };
  for (const [what, payload] of [...Object.entries(frames), ["an unreadable payload", null]]) {
    const ws = await connectToSocket();
    const t = lastTimer(30000);
    ws.open();
    await settle();
    const log0 = logText();
    await ws.deliver({ type: "key", room: ROOM, alg: "AES256", payload: payload ? b64json(payload) : "%%" });
    await settle();
    assert.strictEqual(ws.readyState, 3, "E: " + what + " before any answer to join closes the socket");
    assertBackOnRoom("E (" + what + ")");
    assert.strictEqual(el("roomHint").textContent, EARLY_KEY_SENTENCE, "E: ...with the fixed sentence, byte for byte (" + what + ")");
    assert.match(el("roomHint").className, /\berr\b/, "E: ...shown as an error (" + what + ")");
    assert.ok(!ws.sent.some((f) => f.type === "key"), "E: nothing of the key exchange went back (" + what + ")");
    assert.ok(!promptShown() && el("tabbar").inert !== true, "E: no approval prompt, the tab bar is not inert (" + what + ")");
    assert.ok(t.cleared, "E: the join deadline ended with the attempt (" + what + ")");
    // (addLine folds a repeat into "(×2)" in place: the log changed, and its
    // last line is this one.)
    assert.ok(logText() !== log0 && logLines().at(-1).textContent.startsWith("[the relay passed on a key exchange before letting us into the room — refusing]"),
      "E: the transcript says why (" + what + ")");
  }
  console.log("OK  E: any key frame before the relay answered join is refused at once with a fixed sentence; nothing sent, no prompt (executed)");
}
{
  // Frames queued behind the refusal belong to a retired socket: the answer the
  // relay sends after its early key does not seat us.
  const ws = await connectToSocket();
  ws.open();
  ws.onmessage({ data: JSON.stringify({ type: "key", room: ROOM, alg: "AES256", payload: b64json(frames0()) }) });
  ws.onmessage({ data: JSON.stringify({ type: "joined", role: "owner" }) });
  await settle();
  assertBackOnRoom("E (answer behind)");
  assert.strictEqual(el("roomHint").textContent, EARLY_KEY_SENTENCE, "E: the answer queued behind the refusal changes nothing");
  assert.ok(!ws.sent.some((f) => f.type === "key"), "E: ...and sends no hello");
  console.log("OK  E: an answer to join queued behind an early key frame is dropped with its socket (executed)");
}
{
  // Not OPEN. CLOSING: the relay's Close came, its close event has not. Nothing
  // is sent and nothing is said; the attempt waits for its close, which says
  // what ended it (here the relay's own reason, parked by the `error` it sent
  // after the key frame).
  const ws = await connectToSocket();
  const t = lastTimer(30000);
  ws.open();
  ws.readyState = 2;
  const hint0 = el("roomHint").textContent;
  const log0 = logText();
  await ws.deliver({ type: "key", room: ROOM, alg: "AES256", payload: b64json(frames0()) });
  await settle();
  assert.ok(!ws.sent.some((f) => f.type === "key"), "E (CLOSING): nothing is sent into a closing socket");
  assert.strictEqual(logText(), log0, "E (CLOSING): nothing is narrated (the whole log, folds included)");
  assert.strictEqual(el("roomHint").textContent, hint0, "E (CLOSING): no sentence — the close says what ended it");
  assert.ok(el("connect").disabled && !t.cleared, "E (CLOSING): the attempt waits for its close (the deadline still runs)");
  await ws.deliver({ type: "error", reason: "join timeout" }); // its last words (A3 drops a reason a later frame follows)
  ws.close();
  await settle();
  assertBackOnRoom("E (CLOSING)");
  assert.strictEqual(el("roomHint").textContent, "Joining took too long, so the relay closed the connection. Connect again.",
    "E (CLOSING): the relay's own reason, not the early-key sentence");
  // CLOSED: the frame is handled after onclose ran (the stub runs it inside
  // close(), before the chain gets to the frame) — roomRole is onclose's reset.
  const ws2 = await connectToSocket();
  ws2.open();
  await ws2.deliver({ type: "error", reason: "join timeout" });
  ws2.onmessage({ data: JSON.stringify({ type: "key", room: ROOM, alg: "AES256", payload: b64json(frames0()) }) });
  ws2.close();
  const log2 = logText(); // onclose ran inside close(); the frame is still queued
  await settle();
  assert.strictEqual(logText(), log2, "E (CLOSED): nothing is narrated after the close (the whole log)");
  assertBackOnRoom("E (CLOSED)");
  assert.strictEqual(el("roomHint").textContent, "Joining took too long, so the relay closed the connection. Connect again.",
    "E (CLOSED): a key frame handled after the close does not write over the relay's reason");
  assert.ok(!ws2.sent.some((f) => f.type === "key"), "E (CLOSED): ...and sends nothing");
  console.log("OK  E: on a CLOSING or CLOSED socket an early key frame is dropped: nothing sent, the close's own words stay (executed)");
}
{
  // Pentest early-key r1 T1: CLOSED means onclose's reset role whatever the
  // session had got to — a seated owner past the hello exchange included
  // (peerNonce set, our hello answered). A key frame the relay queued before
  // its close and that is dispatched after it is dropped: no "Key exchange
  // failed" over the close's own words, nothing narrated, nothing sent.
  // (app-behaviour binds the same for DHKE, where the old handling raised the
  // approval prompt on the room screen.)
  const ws = await connectToSocket();
  ws.open();
  await ws.deliver({ type: "joined", role: "owner" });
  await ws.deliver({ type: "key", room: ROOM, alg: "AES256", payload: b64json(frames0()) });
  await settle();
  const sent0 = ws.sent.length;
  assert.ok(ws.sent.filter((f) => f.type === "key").length >= 2, "fixture: the hello exchange ran (ours, and the answer to theirs)");
  for (const payload of [{ pub: "AAAA", reply: true, idb: { ed: "AAAA" }, sig: { ed: "AAAA" } }, { confirm: "AAAA" }]) {
    ws.onmessage({ data: JSON.stringify({ type: "key", room: ROOM, alg: "AES256", payload: b64json(payload) }) });
  }
  ws.close(); // the relay's close: onclose runs now, the two frames after it
  const hint1 = el("roomHint").textContent, log1 = logText();
  await settle();
  assertBackOnRoom("E (CLOSED, seated)");
  assert.strictEqual(el("roomHint").textContent, hint1, "E (CLOSED, seated): a key frame after the close writes nothing over the room screen");
  assert.strictEqual(logText(), log1, "E (CLOSED, seated): ...narrates nothing");
  assert.strictEqual(ws.sent.length, sent0, "E (CLOSED, seated): ...and sends nothing");
  console.log("OK  E: a seated session's key frames dispatched after the relay's close are dropped too (executed)");
}
{
  // Pentest early-key r1 T2: C1-1's guard in endUnanswered (a socket this app
  // already decided to close keeps its own reason; no second closeWs) has no
  // relay-driven trigger left before an answer. Bound directly: a closeWs on
  // an unanswered socket whose close stalls — here Disconnect's, clicked
  // through the stub (it lives on the hidden chat screen) — then the deadline.
  const ws = await connectToSocket();
  const t = lastTimer(30000);
  ws.open();
  stallClose(ws);
  el("disconnect").click();
  await settle();
  assert.ok(ws.readyState === 2 && el("connect").disabled, "fixture: the app's own close is stalled, the attempt still in flight");
  await fire(t);
  assertBackOnRoom("C1-1 (direct)");
  assert.notStrictEqual(el("roomHint").textContent, JOIN_SENTENCE,
    "C1-1 (direct): the deadline ends a socket the app already closed without relabelling it as unanswered");
  console.log("OK  C1-1: endUnanswered does not close again what the app already closed (direct; no relay trigger left) (executed)");
}
{
  // Controls: `pending` is an answer. A key frame in the admission queue (which
  // an honest relay does not send either) is judged by the key arm as before —
  // the chat screen and its Disconnect are up, so a prompt there is visible.
  // And a seated owner's hello exchange runs.
  const ws = await connectToSocket();
  ws.open();
  await ws.deliver({ type: "pending" });
  await ws.deliver({ type: "key", room: ROOM, alg: "AES256", payload: b64json(frames0()) });
  await settle();
  assert.notStrictEqual(el("roomHint").textContent, EARLY_KEY_SENTENCE, "E control: after `pending` a key frame is not the early-key refusal");
  assert.ok(ws.sent.some((f) => f.type === "key"), "E control: ...it is handled (the hello is answered)");
  el("disconnect").click();
  await settle();
  const ws2 = await connectToSocket();
  ws2.open();
  await ws2.deliver({ type: "joined", role: "owner" });
  await ws2.deliver({ type: "key", room: ROOM, alg: "AES256", payload: b64json(frames0()) });
  await settle();
  assert.strictEqual(ws2.readyState, 1, "E control: a seated owner's hello exchange runs");
  assert.ok(ws2.sent.filter((f) => f.type === "key").length >= 2, "E control: ...our hello and the answer to theirs");
  el("disconnect").click();
  await settle();
  assertBackOnRoom("E control");
  console.log("OK  E: controls — after `pending` or `joined` key frames are handled as before (executed)");
}

// ---- L: the directory lookup ----------------------------------------------------
el("toIdentity").click();
el("idPass").value = PASS;
await el("idCreate").click();
await until(() => el("idFingerprint").textContent.length > 0, "the identity to be created");
el("toRoom").click();
const bob = await Identity.generate();
const bb = bob.publicBundle();
const bobAnswer = () => new Response(JSON.stringify({ username: "bob", ed: bb.ed, mldsa: bb.mldsa, ecdh: bb.ecdh, mlkem: bb.mlkem }),
  { status: 200, headers: { "content-type": "application/json" } });
{
  users = hangUntilAborted;
  prepare("DHKE", { contact: "bob#tok" });
  const before = dom.socket();
  el("connect").click();
  await until(() => el("status").textContent === "looking up contact…", "the lookup to start");
  assert.ok(cancelShown(), "C: Cancel is offered during the directory lookup");
  const t = lastTimer(20000);
  assert.ok(t && !t.cleared, "L: a 20 s lookup deadline is armed");
  await fire(t);
  await until(() => el("connect").disabled === false, "the timed-out connect to end");
  assert.strictEqual(dom.socket(), before, "L: a lookup that timed out opens no socket");
  assertBackOnRoom("L");
  assert.strictEqual(el("roomHint").textContent, LOOKUP_SENTENCE, "L: ...and says so with the fixed sentence, byte for byte");
  assert.match(el("roomHint").className, /\berr\b/, "L (N2): ...shown as an error");
  console.log("OK  L: a directory lookup that never answers ends after 20 s with a fixed sentence and no socket (executed)");
}
{
  users = hangUntilAborted;
  prepare("DHKE", { contact: "bob#tok" });
  const before = dom.socket();
  el("connect").click();
  await until(() => el("status").textContent === "looking up contact…", "the lookup to start");
  document.activeElement = el("connectCancel"); // pressed from the keyboard
  el("connect")._focused = false;
  el("connectCancel").click();
  await until(() => el("connect").disabled === false, "the cancelled lookup to end");
  assert.strictEqual(el("connect")._focused, true, "C: the focus goes from the vanishing Cancel to Connect");
  document.activeElement = null;
  assert.strictEqual(dom.socket(), before, "C: a Cancel during the lookup opens no socket");
  assertBackOnRoom("C (lookup)");
  assert.strictEqual(el("roomHint").textContent, "", "C: a cancelled lookup is not reported as a failure");
  assert.strictEqual(lastTimer(20000).cleared, true, "L: the lookup deadline is cleared with it");
  console.log("OK  C: Cancel during the directory lookup aborts it: no socket, no failure sentence (executed)");
}
{
  // A lookup that answers anyway after the Cancel (a fetch that ignores the abort).
  let answer;
  users = () => new Promise((r) => { answer = () => r(bobAnswer()); });
  prepare("DHKE", { contact: "bob#tok" });
  const before = dom.socket();
  el("connect").click();
  await until(() => typeof answer === "function", "the lookup to start");
  el("connectCancel").click();
  answer();
  await until(() => el("connect").disabled === false, "the cancelled connect to end");
  await settle();
  assert.strictEqual(dom.socket(), before, "C: an answer that arrives after the Cancel opens no socket");
  assertBackOnRoom("C (late answer)");
  // A late "no such user" is not narrated either.
  answer = null;
  users = () => new Promise((r) => { answer = () => r(new Response("{}", { status: 404 })); });
  el("connect").click();
  await until(() => typeof answer === "function", "the lookup to start");
  el("connectCancel").click();
  answer();
  await until(() => el("connect").disabled === false, "the cancelled connect to end");
  await settle();
  assert.strictEqual(el("roomHint").textContent, "", "C: a lookup's late answer after the Cancel is not narrated");
  console.log("OK  C: a lookup answer that arrives after the Cancel is not acted on (executed)");
}
{
  // Positive control, and Cancel is withdrawn after a refusal that needs no socket.
  users = () => Promise.resolve(new Response("{}", { status: 404 }));
  prepare("DHKE", { contact: "bob#tok" });
  el("connect").click();
  await until(() => el("connect").disabled === false, "the refused connect to end");
  assert.match(el("roomHint").textContent, /No one found for the handle/, "fixture: an unknown handle is refused");
  assert.strictEqual(el("connectCancel").hidden, true, "C: Cancel is withdrawn when a connect ends before its socket");
  users = () => Promise.resolve(bobAnswer());
  const ws = await connectToSocket("DHKE", { contact: "bob#tok" });
  assert.ok(ws, "control: a lookup that answers still connects");
  ws.open();
  await ws.deliver({ type: "joined", role: "owner" });
  await settle();
  assert.strictEqual(el("scrChat").hidden, false, "control: ...and the relay's answer seats us");
  console.log("OK  L/C: a lookup that answers still connects; a refusal withdraws the Cancel (positive controls)");
}

console.log("\nAll connect deadline and Cancel checks passed.");
process.exit(0);
