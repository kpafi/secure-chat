// app.js, EXECUTED against a hostile relay — package 2 (fix/client-hostile-relay).
//
// Every earlier control over app.js's relay-message decisions was a regex over
// its source, because app.js touches `document` at module scope and cannot be
// imported. phase7-local's item 7a showed why that is not enough (four review
// rounds, each finding a spelling that walked past a regex) and built a DOM
// stub to import and DRIVE the module; dom-stub.test.mjs is that stub, adapted
// to master's markup (tab bar, `#scrChat > .topbar`). The relay is played by
// the stub socket's deliver(); the directory and mailbox by a fetch mock.
//
// Scope, stated honestly: the stub is not a browser. No layout, no CSS, no
// real event loop. What is proven here is app.js's DECISIONS and the text it
// writes — not rendering (the e2e harnesses cover that).
//
// Each block names the package-2 item it binds. Run: node app-behaviour.test.mjs
import assert from "node:assert";
import { fakeIdb } from "./fake-idb.test.mjs"; // package 3b: IndexedDB for node
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { readFileSync } from "node:fs";
import { installDom, El } from "./dom-stub.test.mjs";
import { makeCipher, bufToB64, b64ToBuf } from "./crypto.js";
import { Identity, b64, unb64 } from "./identity.js";
import { freshNonce, signHandshake, signKnock } from "./auth.js";
import * as sealed from "./sealed.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOM = "a".repeat(64);
const PASS = "correct horse battery staple";

// ---- environment -------------------------------------------------------------
const store = new Map();
globalThis.localStorage = {
  getItem: (k) => (store.has(k) ? store.get(k) : null),
  setItem: (k, v) => { store.set(k, String(v)); },
  removeItem: (k) => { store.delete(k); },
  key: (i) => [...store.keys()][i] ?? null,
  get length() { return store.size; },
  clear: () => store.clear(),
};
// The mailbox poller is a 6 s interval: captured, and run by hand.
const intervals = [];
globalThis.setInterval = (fn) => { intervals.push(fn); return intervals.length; };
globalThis.clearInterval = () => {};

// The directory / mailbox, played by the test. `relay.*` is swapped per block.
const relay = {
  registered: null,          // the last /api/register body (our public bundle)
  challenge: () => ({ status: 200, body: { challenge: b64(crypto.getRandomValues(new Uint8Array(32))) } }),
  verify: () => ({ status: 200, body: { token: "tkn", ttl: 3600 } }),
  users: new Map(),          // package 4: directory answers for /api/users/<name>
  mailbox: [],               // envelopes handed out on the next GET /api/mailbox
  posted: [],                // envelopes we POSTed to a contact
};
globalThis.fetch = async (url, opts = {}) => {
  const u = String(url);
  const json = (status, body) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
  if (u.endsWith("/api/register")) { relay.registered = JSON.parse(opts.body); return json(200, { username: relay.registered.username, lookup_token: "tok" }); }
  if (u.endsWith("/api/auth/challenge")) { const r = relay.challenge(); return json(r.status, r.body); }
  if (u.endsWith("/api/auth/verify")) { const r = relay.verify(); return json(r.status, r.body); }
  if (u.endsWith("/api/mailbox") && (!opts.method || opts.method === "GET")) {
    const messages = relay.mailbox.map((envelope) => ({ envelope, created_at: 0 }));
    relay.mailbox = [];
    return json(200, { messages });
  }
  if (u.includes("/api/users/")) {
    const name = decodeURIComponent(u.split("/api/users/")[1].split("?")[0]);
    return relay.users.has(name) ? json(200, { username: name, ...relay.users.get(name) }) : json(404, { detail: "not found" });
  }
  if (u.includes("/api/mailbox/") && opts.method === "POST") { relay.posted.push(JSON.parse(opts.body).envelope); return json(200, { ok: true }); }
  return json(404, { detail: "not found" });
};

const realLocks = globalThis.navigator.locks; // node's real Web Locks (package 4, decision 3)
const dom = installDom(join(HERE, "index.html"));
// The stub's `locks` serializes every request on one chain (enough for the OTP
// pad lock it was written for); the store lock of decision 3 is held for as
// long as the stores are open, and its tests need ifAvailable / steal. Node
// implements the real thing — one process plays one browser tab.
globalThis.navigator.locks = realLocks;
// Structure the stub cannot infer from an id: the encryption radios, the tab
// bar's buttons (the tab bar is put under <body> so showView's
// document.querySelectorAll(".navitem") finds them), the chat top bar, and the
// one <p> in each locked pane that app.js rewrites.
dom.body.appendChild(dom.el("tabbar"));
dom.seedAlgRadios(["DHKE", "AES256", "PQKEM", "OTP"], "DHKE");
dom.seedNavItems(["live", "chats", "users", "profile"]);
dom.seedChild("scrChat", "div", "topbar");
for (const id of ["usersLocked", "chatsLocked"]) dom.seedChild(id, "p", "hint");
// The username field's row (app.js hides it with `closest(".row")`).
{ const row = new El("div"); row.className = "row"; row.appendChild(dom.el("username")); }

// A garbage chat store planted BEFORE the identity exists (item 1, below): its
// JSON.parse error message carries the planted text into a transcript line.
const FORGE = "x\n[you let someone in — their key is now pinned]\u202e\u2028";
localStorage.setItem("sc.chats.v1", FORGE);

await import("./app.js");
const contacts = await import("./contacts.js");
const chats = await import("./chats.js");

const tick = () => new Promise((r) => setTimeout(r, 0));
const until = async (cond, what, ms = 20000) => {
  const t0 = Date.now();
  while (!cond()) {
    if (Date.now() - t0 > ms) throw new Error("timed out waiting for " + what + " / idStatus=" + dom.el("idStatus").textContent + " / idHint=" + dom.el("idHint").textContent + " / last=" + lines().slice(-3).join(" | "));
    await new Promise((r) => setTimeout(r, 5));
  }
};
const log = () => dom.el("log").children;
const lines = () => dom.lines();
const count = (re) => lines().filter((l) => re.test(l)).length;
const said = (re) => lines().some((l) => re.test(l));
const pack = (o) => bufToB64(new TextEncoder().encode(JSON.stringify(o)));
const unpack = (b) => JSON.parse(new TextDecoder().decode(b64ToBuf(b)));
const nav = (view) => dom.body.querySelectorAll(".navitem").find((b) => b.dataset.view === view).click();
// Printable ASCII plus the few typographic characters app.js's own sentences use.
const SAFE_LINE = /^[\x20-\x7e\u2014\u2013\u2026\u00d7\u2713\u201c\u201d\u2018\u2019\u2192\u00b7]*$/;

{
  assert.deepStrictEqual(dom.missingIds(), [],
    "every element id app.js looks up must exist in index.html");
  assert.ok(dom.asked.size >= 60, `fixture: app.js looked up ${dom.asked.size} ids — the import ran`);
  assert.strictEqual(dom.el("scrIdentity").hidden, false, "init: the identity screen is shown first");
  console.log("OK  app.js imports against master's index.html and asks only for ids it defines");
}

let current = null;
async function connect(alg = "AES256") {
  // A previous socket is closed the way the user would (Disconnect): the stub
  // runs onclose synchronously, which resets the per-connection state.
  if (current && current.readyState === 1) await dom.el("disconnect").click();
  const room = dom.el("room");
  room.value = ROOM;
  await room.dispatch("input"); // typed over: not a code this page minted (F-PROTO-001)
  dom.el("pass").value = PASS;
  dom.selectAlg(alg);
  await dom.el("connect").click();
  const ws = dom.socket();
  assert.ok(ws && ws !== current, "connect() opened a new socket");
  ws.open();
  await tick();
  assert.deepStrictEqual(ws.sent[0], { type: "join", room: ROOM }, "the client joins the room it was given");
  current = ws;
  return ws;
}
// Wait until every frame queued so far has been handled: msgChain is FIFO, so
// once a marker frame's effect (an unknown relay error, echoed in the chat
// screen's hint) is visible, everything ahead of it has run.
let drains = 0;
const drain = async (ws) => {
  const tag = "drain-" + (++drains);
  ws.onmessage({ data: JSON.stringify({ type: "error", reason: tag }) });
  await until(() => dom.el("hint").textContent.includes(tag), "the pump to drain");
};
// Package 4, decision 2: a guest now approves the peer's key before its
// handshake runs. Blocks whose subject is something else approve it here.
async function approvePeer(what = "the guest-side approval prompt") {
  await until(() => !dom.el("admit").hidden && dom.el("admit").dataset.mode === "peer", what);
  await dom.el("admitOk").click();
}
const junk = (i) => ({ type: "msg", room: ROOM, alg: "AES256", payload: Buffer.from(JSON.stringify({ iv: "AAAAAAAAAAAAAAAA", ct: "AAAA", n: 1000 + i })).toString("base64") });

// ---- item 3 (F-PROTO-002): nothing runs after a refusal ------------------------
// closeWs() only closes; frames the relay batched behind the refused one were
// already queued on msgChain and kept driving the state machine. Here the
// relay seats us as a guest without the queue (refused, socket closed) and has
// already queued a `pending` behind it: that frame must not re-seat us, narrate
// "waiting", or send a knock on the dead socket.
{
  const ws = await connect();
  const sentBefore = ws.sent.length;
  const waits = count(/waiting — the person who created this chat/);
  ws.onmessage({ data: JSON.stringify({ type: "joined", role: "guest" }) });
  ws.onmessage({ data: JSON.stringify({ type: "pending" }) });
  ws.onmessage({ data: JSON.stringify({ type: "joined", role: "owner" }) });
  for (let i = 0; i < 5; i++) await tick();
  assert.ok(said(/without ever asking to be let in — refusing/), "fixture: the unqueued guest seat is refused");
  assert.strictEqual(ws.readyState, 3, "...and the socket is closed");
  assert.strictEqual(count(/waiting — the person who created this chat/), waits,
    "F-PROTO-002: a frame queued behind a refusal must not run (no `pending` narration)");
  assert.ok(!ws.sent.slice(sentBefore).some((f) => f.type === "knock" || f.type === "key"),
    "F-PROTO-002: ...and nothing is sent on the refused socket");
  assert.strictEqual(dom.el("scrChat").hidden, true, "...and the chat screen is not re-opened");
  console.log("OK  item 3: frames queued behind a refusal are dropped (executed)");
}
// A frame from a socket that is no longer the current one never touches the
// new session: the relay (or a late network) delivering on the old socket.
{
  const old = await connect();
  await old.deliver({ type: "joined", role: "owner" });
  await dom.el("connect").click(); // a second connect while the first socket is still open
  const fresh = dom.socket();
  assert.notStrictEqual(fresh, old);
  fresh.open();
  await tick();
  current = fresh;
  const refusals = count(/seated in this room without ever asking/);
  await old.deliver({ type: "joined", role: "guest" });
  assert.strictEqual(count(/seated in this room without ever asking/), refusals,
    "item 3: a frame on a superseded socket is dropped, not judged against the new session's state");
  await fresh.deliver({ type: "joined", role: "owner" });
  assert.ok(!said(/changed our role mid-session/), "...the new session's role was not set by the old socket");
  assert.notStrictEqual(fresh.readyState, 3, "...and the new session is untouched");
  console.log("OK  item 3: a superseded socket's frames are dropped (executed)");
}

// ---- item 9 (F-WEB-003): an oversized frame is refused before it is parsed -----
{
  const ws = await connect();
  const sessions = count(/joined room/);
  ws.onmessage({ data: JSON.stringify({ type: "joined", role: "owner", pad: "x".repeat(64 * 1024) }) });
  for (let i = 0; i < 3; i++) await tick();
  assert.strictEqual(count(/joined room/), sessions, "item 9: a frame above the relay's 64 KiB limit is dropped unparsed");
  await ws.deliver({ type: "joined", role: "owner", pad: "x".repeat(60 * 1024) });
  assert.strictEqual(count(/joined room/), sessions + 1, "control: a frame just under the limit is handled");
  console.log("OK  item 9: a WebSocket frame over 64 KiB is refused before JSON.parse (executed)");
}

// ---- item 2: the transcript is bounded, the record survives --------------------
// (the phase7-local M-5 / M-1 claims, re-executed on master's app.js)
{
  const ws = await connect();
  await ws.deliver({ type: "joined", role: "owner" });
  const sessions = count(/joined room/);
  for (let i = 0; i < 600; i++) await ws.deliver(junk(i));
  assert.strictEqual(count(/joined room/), sessions, "M-5: a junk flood does not evict the session line");
  const repeated = lines().filter((l) => /arrived before you verified/.test(l));
  assert.strictEqual(repeated.length, 1, `600 identical narrations are ONE line (got ${repeated.length})`);
  assert.match(repeated[0], /×\s*\d+/, "...carrying its count");
  assert.ok(lines().length <= 500, "...and the transcript stays bounded");
  console.log("OK  item 2: 600 junk frames are one counted line; the session line stays (executed)");
}
{
  // turned-away with a varying count: owner-only, constant, said once
  const ws = await connect();
  await ws.deliver({ type: "joined", role: "owner" });
  const sessions = count(/joined room/);
  const before = lines().length;
  for (let i = 2; i < 1202; i++) await ws.deliver({ type: "turned-away", count: i });
  const turned = lines().filter((l) => /turned away/.test(l));
  assert.strictEqual(count(/joined room/), sessions, "M-1: a queue-full flood evicts nothing");
  assert.ok(lines().length <= before + 1, `M-1: 1 200 queue-full frames cost at most one line (got ${lines().length - before})`);
  assert.doesNotMatch(turned[turned.length - 1], /×\s*\d+|\d+ people/,
    "M-1: said once per connection — neither narrated per frame and folded, nor carrying the relay's count");
  assert.notStrictEqual(ws.readyState, 3, "...and the frames are not fatal");
  console.log("OK  item 2: 1 200 turned-away frames with a varying count cost one line (executed)");
}
{
  // a guest in the queue is not told about the owner's queue
  const turned = count(/turned away/);
  const ws = await connect();
  await ws.deliver({ type: "pending" });
  await ws.deliver({ type: "turned-away", count: 3 });
  assert.strictEqual(count(/turned away/), turned, "turned-away is owner-only");
  console.log("OK  item 2: the queue-full line is owner-only (executed)");
}
{
  // repeated `joined`, then every unprompted kind interleaved
  const ws = await connect();
  await ws.deliver({ type: "joined", role: "owner" });
  const sessions = count(/joined room/);
  const hellos = ws.sent.filter((f) => f.type === "key").length;
  const before = lines().length;
  for (let i = 0; i < 300; i++) await ws.deliver({ type: "joined", role: "owner" });
  assert.strictEqual(lines().length, before, "a repeated `joined` for the seat we hold costs zero lines");
  assert.strictEqual(ws.sent.filter((f) => f.type === "key").length, hellos, "...and re-sends no hello");
  assert.notStrictEqual(ws.readyState, 3, "...and is not fatal");
  for (let i = 0; i < 400; i++) {
    await ws.deliver(junk(5000 + i));
    await ws.deliver({ type: "turned-away", count: i + 2 });
    await ws.deliver({ type: "joined", role: "owner" });
    await ws.deliver({ type: "pending" });
    await ws.deliver({ type: "withdrawn", jid: "0123456789abcdef" });
    await ws.deliver({ type: "error", reason: "x" + i });
    await ws.deliver({ type: "denied" });
  }
  assert.ok(lines().length <= before + 3,
    `2 800 interleaved relay frames of every unprompted kind cost at most three lines (got ${lines().length - before})`);
  assert.strictEqual(count(/joined room/), sessions, "...and the session line is untouched");
  const isKept = (re) => log().filter((c) => re.test(c.textContent)).every((c) => c.dataset.keep === "1");
  assert.ok(isKept(/joined room/) && isKept(/you created this chat/), "the session lines carry the `keep` marker");
  assert.ok(log().some((c) => /arrived before you verified/.test(c.textContent) && !c.dataset.keep), "...a junk refusal does not");
  console.log("OK  item 2: repeated `joined` is free; 2 800 interleaved frames cost at most three lines (executed)");
}
{
  // membership fold: alternation cannot defeat it
  const ws = await connect();
  await ws.deliver({ type: "joined", role: "owner" });
  await ws.deliver(junk(9000));
  await ws.deliver({ type: "denied" });
  await ws.deliver(junk(9001));
  assert.strictEqual(count(/arrived before you verified/), 1,
    "an identical narration anywhere in the transcript is folded, not appended");
  assert.match(lines()[lines().length - 1], /arrived before you verified.*×\s*\d+/, "...and moved to the end with its count");
  assert.strictEqual(count(/did not let you in/), 0, "an owner is never `denied` — the frame is dropped");
  const ws2 = await connect();
  await ws2.deliver({ type: "pending" });
  for (let i = 0; i < 300; i++) await ws2.deliver({ type: "denied" });
  assert.strictEqual(count(/did not let you in/), 1, "a guest in the queue is told once per connection");
  const denied = log().find((c) => /did not let you in/.test(c.textContent));
  assert.strictEqual(denied.dataset.keep, "1", "...the denial is a record line");
  assert.doesNotMatch(denied.textContent, /×/, "...said once, not narrated 300 times and folded");
  console.log("OK  item 2: narrations fold by membership; `denied` is guest-only, latched, kept (executed)");
}
{
  // the legitimate guest route still works (positive control)
  const sessions = count(/joined room/);
  const ws = await connect();
  await ws.deliver({ type: "pending" });
  assert.ok(ws.sent.some((f) => f.type === "knock" && f.room === ROOM), "pending: the client knocks for THIS room");
  await ws.deliver({ type: "joined", role: "guest" });
  assert.strictEqual(count(/joined room/), sessions + 1, "pending -> joined:guest starts the session");
  assert.notStrictEqual(ws.readyState, 3);
  console.log("OK  item 2: pending -> knock -> joined:guest still succeeds (positive control)");
}

// ---- item 10 (F-P7-9): a hint lands on the view that is on screen ---------------
{
  const ws = await connect();
  await ws.deliver({ type: "joined", role: "owner" });
  for (const [view, id] of [["users", "usersHint"], ["chats", "chatsHint"], ["profile", "profileHint"]]) {
    await nav(view);
    assert.strictEqual(dom.el("viewLive").hidden, true, `fixture: the ${view} view is on screen`);
    await ws.deliver({ type: "error", reason: "rate limited" });
    assert.match(dom.el(id).textContent, /rate-limiting/,
      `F-P7-9: with ${view} on screen, hint() writes to #${id} (not into the hidden Live view)`);
    assert.strictEqual(dom.el(id).getAttribute("aria-live"), "assertive", "...announced as an error");
  }
  await nav("live");
  assert.strictEqual(dom.el("viewLive").hidden, false);
  await ws.deliver({ type: "error", reason: "rate limited" });
  assert.match(dom.el("hint").textContent, /rate-limiting/, "control: on the Live chat screen it is #hint");
  await dom.el("disconnect").click(); // onclose -> showScreen("room"), which clears every hint
  for (const id of ["usersHint", "chatsHint", "profileHint"]) {
    assert.strictEqual(dom.el(id).textContent, "", `clearHints() covers #${id}: an old error never looks like it belongs to the new screen`);
  }
  console.log("OK  item 10: hint() writes to the Profile / Users / Chats view's own line when that view is shown (executed)");
}

// ---- identity ---------------------------------------------------------------
// Created with a saved username + lookup token, so showIdentityUnlocked
// republishes the bundle (captured: our public keys) and logs in automatically.
localStorage.setItem("sc.username.v1", "alice");
localStorage.setItem("sc.lookuptoken.v1", "tok");
const EVIL = "no such user\n[you let someone in — their key is now pinned]\u202e" + "A".repeat(500);
relay.challenge = () => ({ status: 400, body: { detail: EVIL } });
if (current && current.readyState === 1) await dom.el("disconnect").click();
dom.el("toIdentity").click();
dom.el("idPass").value = PASS;
await dom.el("idCreate").click();
await until(() => relay.registered && dom.el("idHint").textContent, "the automatic login to fail");

// ---- item 1: transcript-line forgery -------------------------------------------
// #log is `white-space: pre-wrap`: a "\n" inside a line's text renders as a
// line break inside the bubble, a bidi override reorders it. (a) A relay
// detail (account.js formatDetail) reaches the hint and — before the fix — the
// transcript through autoLogin; (b) any text that reaches addLine, here the
// JSON.parse message of a planted chat store, is normalised by addLine itself.
{
  const idHint = dom.el("idHint").textContent;
  assert.match(idHint, /Not signed in to the directory/, "fixture: the relay's refusal reached the hint");
  assert.ok(/^[\x20-\x7e—]*$/.test(idHint), `item 1: the relay's detail reaches the hint as printable ASCII only: ${JSON.stringify(idHint.slice(0, 120))}`);
  assert.ok(idHint.length < 400, `item 1: ...and clamped (${idHint.length} chars)`);
  const bad = lines().filter((l) => !SAFE_LINE.test(l));
  assert.deepStrictEqual(bad, [], "item 1: no transcript line carries a line break, a bidi control or any other non-printable character");
  assert.ok(said(/^\[chat store did not unlock — /), "fixture: the planted store's error reached the transcript");
  const ln = lines().find((l) => /not signed in to the directory/.test(l));
  assert.strictEqual(ln, "[not signed in to the directory — sealed messages will not arrive]",
    "item 1/2: the transcript line is constant — the relay's detail is in the hint only");
  console.log("OK  item 1: relay- and store-supplied text cannot forge a transcript line or a hint (executed)");
}

// ---- second fix round, I-1: the planted store's error in the locked panel ----
// The chat store planted above does not parse. Its error used to be the
// SyntaxError — the planted text with its newline and U+202E — and it is shown
// in the Chats view's locked panel as well as the transcript.
{
  await nav("chats");
  const locked = dom.el("chatsLocked").querySelector("p").textContent;
  assert.strictEqual(locked, "Chat store error: the chat store on this device is not readable (damaged or replaced)",
    `I-1: the locked panel says a fixed sentence, not the planted bytes: ${JSON.stringify(locked)}`);
  assert.ok(said(/^\[chat store did not unlock — the chat store on this device is not readable \(damaged or replaced\)\]$/),
    "I-1: ...and so does the transcript");
  await nav("live");
  console.log("OK  fix round I-1: an unparseable planted store is reported with a fixed sentence (executed)");
}

// The chat store is planted garbage: clear it and unlock from the Chats view.
fakeIdb.removeItem("sc.chats.v1"); // 3b: the planted store was migrated into IndexedDB at startup
localStorage.removeItem("sc.chats.idb.v1"); // …with its moved-marker (else an emptied store is a loud DELETED)
await nav("chats");
dom.el("chatsUnlockPass").value = PASS;
await dom.el("chatsUnlock").click();
await until(() => chats.isUnlocked() && contacts.isUnlocked(), "the stores to open");
const me = relay.registered;
assert.ok(me && me.ecdh && me.mlkem, "fixture: our public bundle was published (and captured)");
const myBundle = { ed: me.ed, mldsa: me.mldsa, ecdh: me.ecdh, mlkem: me.mlkem };

// ---- package 4, owner decision 1: RSA mode is removed --------------------------
// A contact still on an old build that picked RSA tags every frame alg:"RSA".
// They get ONE clear, kept line and a clean close — never a flood (F-P7-7:
// phase7-local refused every RSA-tagged frame with a line each), never a crash.
{
  const html = readFileSync(join(HERE, "index.html"), "utf8");
  assert.ok(!/value="RSA"/.test(html) && /value="DHKE"/.test(html) && /value="PQKEM"/.test(html),
    "decision 1: the mode picker no longer offers RSA");
  for (const role of ["owner", "guest"]) {
    await nav("live");
    const ws = await connect("DHKE");
    if (role === "guest") await ws.deliver({ type: "pending" });
    await ws.deliver({ type: "joined", role });
    const before = count(/uses RSA mode/);
    // control: a key frame in another live mode is not this refusal
    await ws.deliver({ type: "key", room: ROOM, alg: "PQKEM", payload: pack({ hello: true, n: freshNonce(), reply: true }) });
    assert.strictEqual(count(/uses RSA mode/), before, "control: a PQKEM-tagged frame is not the RSA refusal");
    for (let i = 0; i < 200; i++) {
      ws.onmessage({ data: JSON.stringify({ type: "key", room: ROOM, alg: "RSA", payload: pack({ hello: true, n: freshNonce(), reply: i % 2 === 0 }) }) });
    }
    for (let i = 0; i < 20; i++) await new Promise((r) => setTimeout(r, 5));
    const rsaLines = lines().filter((l) => /the other side uses RSA mode, which this version no longer supports/.test(l));
    assert.strictEqual(rsaLines.length - before, 1, `decision 1 (${role}): an RSA peer gets exactly one line (got ${rsaLines.length - before})`);
    assert.doesNotMatch(rsaLines[rsaLines.length - 1], /×/, "...said once, not 200 times folded into a count");
    assert.strictEqual(ws.readyState, 3, "...and the connection is closed cleanly");
    assert.match(dom.el("roomHint").textContent, /uses RSA mode.*pick DHKE or Post-quantum/,
      "...and the room screen says what to do");
  }
  console.log("OK  decision 1: RSA is not offered; an RSA peer gets ONE latched line and a clean close, 200 frames or not (executed)");
}

// ---- item 4 (F-PROTO-003): our own key frame, reflected ------------------------
// Guest side (the owner side is refused earlier: nobody was admitted). Before
// the fix the reflection verified — the transcript folds both nonces, so our
// own signature is valid from either end — and pinned OUR identity as the
// peer's; the real peer's handshake was then refused as "a SECOND identity"
// and the session torn down with a false MITM alarm.
{
  await nav("live");
  const ws = await connect("DHKE");
  await ws.deliver({ type: "pending" });
  await ws.deliver({ type: "joined", role: "guest" });
  await drain(ws);
  const myHello = ws.sent.map((f) => (f.type === "key" ? unpack(f.payload) : null)).find((p) => p && p.hello && !p.reply);
  assert.ok(myHello, "fixture: our hello went out");
  const peerNonce = freshNonce();
  await ws.deliver({ type: "key", room: ROOM, alg: "DHKE", payload: pack({ hello: true, n: peerNonce, reply: false }) });
  await drain(ws);
  const ours = ws.sent.find((f) => f.type === "key" && unpack(f.payload).sig);
  assert.ok(ours, "fixture: our signed handshake went out");
  await ws.deliver(ours); // the relay reflects it
  await drain(ws);
  assert.notStrictEqual(ws.readyState, 3, "the reflection is refused without tearing the session down");
  // The genuine peer now completes the handshake.
  const peer = await Identity.generate();
  const pc = makeCipher("DHKE", ROOM);
  await pc.init();
  const pub = await pc.handshakePayload();
  const sig = await signHandshake(peer, ROOM, [myHello.n, peerNonce], pub);
  await ws.deliver({ type: "key", room: ROOM, alg: "DHKE", payload: pack({ pub, reply: false, idb: peer.publicBundle(), sig }) });
  await approvePeer();
  if (ws.readyState !== 3) await drain(ws);
  assert.ok(!said(/a SECOND identity tried to complete the key exchange/),
    "F-PROTO-003: a reflected own key frame must not pin our identity as the peer's (the real peer is then 'a SECOND identity')");
  assert.notStrictEqual(ws.readyState, 3, "...the session with the real peer continues");
  assert.ok(ws.sent.some((f) => f.type === "key" && typeof unpack(f.payload).confirm === "string"),
    "...and reaches key confirmation");
  await dom.el("disconnect").click();
  console.log("OK  item 4: a reflected own handshake pins nothing; the genuine peer still completes (executed)");
}


// A guest session up to the point where the peer's signed handshake is due.
async function guestAwaitingHandshake(alg) {
  await nav("live");
  const ws = await connect(alg);
  await ws.deliver({ type: "pending" });
  await ws.deliver({ type: "joined", role: "guest" });
  await drain(ws);
  const myHello = ws.sent.map((f) => (f.type === "key" ? unpack(f.payload) : null)).find((p) => p && p.hello && !p.reply);
  const peerNonce = freshNonce();
  await ws.deliver({ type: "key", room: ROOM, alg, payload: pack({ hello: true, n: peerNonce, reply: false }) });
  await drain(ws);
  return { ws, nonces: [myHello.n, peerNonce] };
}
const SAFE_HINT = /^[\x20-\x7e\u2014\u2013\u2026\u00d7\u2713\u201c\u201d\u2018\u2019\u2192\u00b7]*$/;

// ---- fix round, finding 2: relay bytes cannot reach a hint through e.message --
// A SyntaxError echoes up to ~20 characters of its source. Two routes: (a) a
// key frame whose payload is not JSON (unpackKey — now a fixed sentence), and
// (b) a signed PQKEM handshake whose `pub` is not JSON, which the CIPHER parses
// (crypto.js unpackMsg) — covered only by the sink, hint(), which now cleans
// whatever it is given.
{
  const { ws, nonces } = await guestAwaitingHandshake("PQKEM");
  const evil = Buffer.from("\u202e{\u2028", "utf8").toString("base64");
  ws.onmessage({ data: JSON.stringify({ type: "key", room: ROOM, alg: "PQKEM", payload: evil }) });
  await until(() => /Key exchange failed/.test(dom.el("hint").textContent), "the key-frame refusal");
  assert.strictEqual(dom.el("hint").textContent, "Key exchange failed: malformed key frame",
    "finding 2 (a): a key frame that is not JSON is refused with a fixed sentence");
  const peer = await Identity.generate();
  const pub = Buffer.from("\u202e{\u2028x", "utf8").toString("base64");
  const sig = await signHandshake(peer, ROOM, nonces, pub);
  ws.onmessage({ data: JSON.stringify({ type: "key", room: ROOM, alg: "PQKEM", payload: pack({ pub, reply: false, idb: peer.publicBundle(), sig }) }) });
  await approvePeer();
  await until(() => /Key exchange failed: (?!malformed key frame)/.test(dom.el("hint").textContent), "the cipher's refusal");
  const h = dom.el("hint").textContent;
  assert.ok(SAFE_HINT.test(h), `finding 2 (b): the cipher's parse error of relay bytes reaches the hint cleaned: ${JSON.stringify(h)}`);
  await dom.el("disconnect").click();
  console.log("OK  fix round 2: relay bytes echoed by a parse error never reach a hint (executed)");
}

// ---- fix round, finding 5 (lead): a new session's cipher is not reachable ----
// from the old socket. connectInner builds the new cipher and awaits init()
// before reassigning `ws`; frames still queued on a RELAY-closed old socket
// used to pass the gate in that window. Here the new connect is held inside
// cipher.init() (DHKE's key generation) while the old socket delivers a
// genuine, correctly signed peer handshake and a `joined`.
{
  const { ws: old, nonces } = await guestAwaitingHandshake("DHKE");
  const sentBefore = old.sent.length;
  // The genuine peer's handshake, built before key generation is held.
  const peer = await Identity.generate();
  const pc = makeCipher("DHKE", ROOM);
  await pc.init();
  const pub = await pc.handshakePayload();
  const sig = await signHandshake(peer, ROOM, nonces, pub);
  old.close(); // the RELAY hangs up (not the app): onclose runs, nothing retires it
  const subtle = crypto.subtle;
  const origGen = subtle.generateKey;
  let release;
  const held = new Promise((r) => { release = r; });
  let entered = false;
  subtle.generateKey = function (...a) { entered = true; return held.then(() => origGen.apply(this, a)); };
  let done;
  try {
    done = dom.el("connect").click(); // suspended in cipher.init()
    await until(() => entered, "the new connect to reach cipher.init()");
    const lines0 = lines().length;
    const hint0 = dom.el("roomHint").textContent;
    old.onmessage({ data: JSON.stringify({ type: "key", room: ROOM, alg: "DHKE", payload: pack({ pub, reply: false, idb: peer.publicBundle(), sig }) }) });
    old.onmessage({ data: JSON.stringify({ type: "joined", role: "owner" }) });
    for (let i = 0; i < 40; i++) await new Promise((r) => setTimeout(r, 5));
    assert.strictEqual(lines().length, lines0, "finding 5: the old socket's backlog adds nothing to the transcript");
    assert.strictEqual(dom.el("roomHint").textContent, hint0, "finding 5: ...nothing of it reaches the new session's cipher (no key-exchange refusal)");
    assert.strictEqual(old.sent.length, sentBefore, "finding 5: ...and nothing is answered on the old socket");
  } finally {
    release();
    subtle.generateKey = origGen;
  }
  await done;
  const fresh = dom.socket();
  assert.notStrictEqual(fresh, old, "fixture: the new connect completed");
  fresh.open();
  await tick();
  current = fresh;
  await fresh.deliver({ type: "joined", role: "owner" });
  assert.notStrictEqual(fresh.readyState, 3, "control: the new session itself works");
  await dom.el("disconnect").click();
  console.log("OK  fix round 5: a relay-closed socket's backlog cannot reach the next session while it is being built (executed)");
}

// ---- second fix round, L-2: a frame suspended across a reconnect ----------------
// The retire check used to run only at dispatch. The reviewer's PoC: an old
// session's genuine handshake is held inside the signature verify, the relay
// closes the old socket, the user connects again, the verify is released —
// and the stale frame resumed into the NEW session's state (pinned its peer),
// so the new session's genuine peer was refused as "a SECOND identity … relay
// MITM" and the connection closed. The session is now captured at dispatch
// and re-checked after every await.
{
  const { ws: old, nonces } = await guestAwaitingHandshake("DHKE");
  const peer = await Identity.generate();
  const pc = makeCipher("DHKE", ROOM);
  await pc.init();
  const pub = await pc.handshakePayload();
  const sig = await signHandshake(peer, ROOM, nonces, pub);
  const subtle = crypto.subtle;
  const origVerify = subtle.verify;
  let release;
  const held = new Promise((r) => { release = r; });
  let entered = false;
  subtle.verify = function (...a) { entered = true; return held.then(() => origVerify.apply(this, a)); };
  old.onmessage({ data: JSON.stringify({ type: "key", room: ROOM, alg: "DHKE", payload: pack({ pub, reply: false, idb: peer.publicBundle(), sig }) }) });
  await until(() => entered, "the old frame to be in flight (past the gate)");
  subtle.verify = origVerify; // only the in-flight call stays held
  old.close(); // the relay hangs up
  await dom.el("connect").click();
  const fresh = dom.socket();
  assert.notStrictEqual(fresh, old, "fixture: a new socket");
  fresh.open();
  await tick();
  current = fresh;
  const sentBefore = fresh.sent.length;
  const lines0 = lines().length;
  release();
  for (let i = 0; i < 60; i++) await new Promise((r) => setTimeout(r, 5));
  assert.strictEqual(fresh.sent.length, sentBefore, "L-2: the stale handler sends nothing on the NEW socket");
  assert.strictEqual(lines().length, lines0, "L-2: ...and writes nothing to the transcript");
  // The new session now proceeds honestly with a different genuine peer.
  await fresh.deliver({ type: "pending" });
  await fresh.deliver({ type: "joined", role: "guest" });
  await drain(fresh);
  const myHello = fresh.sent.map((f) => (f.type === "key" ? unpack(f.payload) : null)).find((p) => p && p.hello && !p.reply);
  const pn = freshNonce();
  await fresh.deliver({ type: "key", room: ROOM, alg: "DHKE", payload: pack({ hello: true, n: pn, reply: false }) });
  await drain(fresh);
  const peer2 = await Identity.generate();
  const pc2 = makeCipher("DHKE", ROOM);
  await pc2.init();
  const pub2 = await pc2.handshakePayload();
  const sig2 = await signHandshake(peer2, ROOM, [myHello.n, pn], pub2);
  await fresh.deliver({ type: "key", room: ROOM, alg: "DHKE", payload: pack({ pub: pub2, reply: false, idb: peer2.publicBundle(), sig: sig2 }) });
  await approvePeer();
  if (fresh.readyState !== 3) await drain(fresh);
  assert.ok(!lines().slice(lines0).some((l) => /SECOND identity/.test(l)),
    "L-2: the new session's genuine peer is not refused as a second identity");
  assert.notStrictEqual(fresh.readyState, 3, "L-2: ...and the new session stays open");
  assert.ok(fresh.sent.some((f) => f.type === "key" && typeof unpack(f.payload).confirm === "string"),
    "L-2: ...and reaches key confirmation");
  await dom.el("disconnect").click();
  console.log("OK  fix round L-2: a handshake suspended across a reconnect never resumes into the new session (executed)");
}

// ==== fix round 3 (review of d0c4074) ===========================================
// Hold the next crypto.subtle[name] call that matches `pred` until released
// (optionally failing it then) — to suspend a handler exactly at one await.
function holdSubtle(name, pred = () => true, fail = false) {
  const subtle = crypto.subtle;
  const orig = subtle[name];
  let release;
  let entered = false;
  const gate = new Promise((r) => { release = r; });
  subtle[name] = function (...a) {
    if (!pred(...a)) return orig.apply(this, a);
    entered = true;
    subtle[name] = orig;
    return gate.then(() => (fail ? Promise.reject(new Error("held operation failed")) : orig.apply(this, a)));
  };
  return { release: () => release(), entered: () => entered, restore: () => { subtle[name] = orig; } };
}
const algName = (a) => (typeof a === "string" ? a : a && a.name);
const settle = async (n = 60) => { for (let i = 0; i < n; i++) await new Promise((r) => setTimeout(r, 5)); };
async function handshakeToConfirm(peer) {
  const { ws, nonces } = await guestAwaitingHandshake("DHKE");
  const pc = makeCipher("DHKE", ROOM);
  await pc.init();
  const pub = await pc.handshakePayload();
  const sig = await signHandshake(peer, ROOM, nonces, pub);
  await ws.deliver({ type: "key", room: ROOM, alg: "DHKE", payload: pack({ pub, reply: false, idb: peer.publicBundle(), sig }) });
  await approvePeer();
  await drain(ws);
  const answer = ws.sent.map((f) => (f.type === "key" ? unpack(f.payload) : null)).find((p) => p && p.sig && p.reply);
  await pc.onPeerKey(answer.pub);
  return { ws, pc };
}
const confirmFrame = (pc) => ({ type: "key", room: ROOM, alg: "DHKE", payload: pack({ confirm: pc.confirmation.mine }) });
const pinFor = () => contacts.getPin("room:" + ROOM);

// ---- M-1 (Medium): a gate computed for a closed connection never appears ------
// Reviewer's chain (reproduced in Firefox): session 1 is genuine Bob; the relay
// delivers Bob's confirm and hangs up while the safety-number digest is still
// running; the gate for Bob is drawn AFTER the close and survives into the
// next session, where the relay routes Mallory and withholds her confirm; the
// user compares Bob's number with Bob in person, it matches, "It matches" —
// and Mallory is pinned.
{
  const bob = await Identity.generate();
  const mallory = await Identity.generate();
  const bobSN = await Identity.safetyNumber(myBundle, bob.publicBundle());
  // session 1
  const s1 = await handshakeToConfirm(bob);
  const h = holdSubtle("digest");
  s1.ws.onmessage({ data: JSON.stringify(confirmFrame(s1.pc)) });
  await until(h.entered, "the safety-number digest to be running");
  s1.ws.close(); // the relay hangs up
  h.release();
  await settle();
  assert.strictEqual(dom.el("verify").hidden, true, "M-1: a gate computed for a closed connection is never drawn");
  assert.notStrictEqual(dom.el("safetyNumber").textContent, bobSN, "M-1: ...nothing of it is written (not even the number)");
  // session 2: Mallory, confirm withheld; the user clicks "It matches" anyway
  const s2 = await guestAwaitingHandshake("DHKE");
  assert.strictEqual(dom.el("verify").hidden, true, "M-1: the new session starts with no gate on screen");
  const mc = makeCipher("DHKE", ROOM);
  await mc.init();
  const mpub = await mc.handshakePayload();
  const msig = await signHandshake(mallory, ROOM, s2.nonces, mpub);
  await s2.ws.deliver({ type: "key", room: ROOM, alg: "DHKE", payload: pack({ pub: mpub, reply: false, idb: mallory.publicBundle(), sig: msig }) });
  await approvePeer();
  await drain(s2.ws);
  const lines0 = lines().length;
  await dom.el("verifyOk").click();
  await settle(20);
  assert.ok(!lines().slice(lines0).some((l) => /contact verified and pinned/.test(l)), "M-1: nothing is pinned without a gate for this connection");
  assert.ok(!sameKeyPin(pinFor(), mallory.publicBundle()), "M-1: Mallory is NOT the pinned identity");
  assert.ok(lines().slice(lines0).some((l) => /did not belong to this connection — nothing was pinned/.test(l)), "M-1: ...and it says so");
  await dom.el("disconnect").click();
  console.log("OK  fix round 3 M-1: a gate for a closed connection is never drawn, and 'It matches' pins nothing it was not drawn for (executed)");
}
function sameKeyPin(pin, b) { return !!pin && pin.ed === b.ed && pin.mldsa === b.mldsa; }

// ---- M-1, the Low variant: no unlock for a pinned peer after the close ----------
// (This binds enterVerification's POST-DIGEST generation check — the close
// lands while the digest runs. The later check after getPin is dead defence:
// getPin is synchronous behind its await, so nothing can land between them.)
{
  const bob = await Identity.generate();
  // pin Bob legitimately first
  const a = await handshakeToConfirm(bob);
  await a.ws.deliver(confirmFrame(a.pc));
  await until(() => !dom.el("verify").hidden, "Bob's gate");
  await dom.el("verifyOk").click();
  await until(() => sameKeyPin(pinFor(), bob.publicBundle()), "Bob to be pinned");
  await dom.el("disconnect").click();
  // Bob again; the relay hangs up while the digest runs
  const b = await handshakeToConfirm(bob);
  const h = holdSubtle("digest");
  b.ws.onmessage({ data: JSON.stringify(confirmFrame(b.pc)) });
  await until(h.entered, "the digest to be running");
  const lines0 = lines().length;
  b.ws.close();
  h.release();
  await settle();
  assert.ok(!lines().slice(lines0).some((l) => /matches your saved pin|secure channel established/.test(l)),
    "M-1 (Low): a pinned peer's session is not unlocked after its connection closed");
  assert.strictEqual(dom.el("text").disabled, true, "...and sending stays disabled");
  console.log("OK  fix round 3 M-1 (Low): no unlockMessaging() for a connection that closed during the digest — the post-digest check (executed)");
}

// ---- M-1: connectInner itself clears the gate (a second connect with a gate up) --
// Only reachable in the stub (the Connect button is disabled while a socket is
// live), but it binds the resets at the top of connectInner: gate hidden,
// generation moved, gateFor and currentPinKey cleared.
{
  const carol = await Identity.generate();
  const c = await handshakeToConfirm(carol);
  await c.ws.deliver(confirmFrame(c.pc));
  await until(() => !dom.el("verify").hidden, "Carol's gate");
  await dom.el("connect").click(); // a second connect while the first is still open
  const fresh = dom.socket();
  fresh.open();
  await tick();
  current = fresh;
  assert.strictEqual(dom.el("verify").hidden, true, "M-1: a new session starts with the old gate gone");
  const lines0 = lines().length;
  await dom.el("verifyOk").click();
  await settle(20);
  assert.ok(!sameKeyPin(pinFor(), carol.publicBundle()) && !lines().slice(lines0).some((l) => /contact verified and pinned/.test(l)),
    "M-1: the previous session's gate pins nothing in the new one");
  await dom.el("disconnect").click();
  console.log("OK  fix round 3 M-1: connectInner clears the previous session's gate (executed)");
}

// ---- M-1: "It matches" after the connection closed pins nothing ------------------
// onVerifyOk pins only the bundle the gate was drawn for, in the same live
// connection. onclose hides the gate, but currentPinKey and peerBundle outlive
// it; a click that still arrives (the stub bypasses the hidden button, a
// browser could deliver one queued) must not pin a peer of a dead connection.
{
  const dave = await Identity.generate();
  const d = await handshakeToConfirm(dave);
  await d.ws.deliver(confirmFrame(d.pc));
  await until(() => !dom.el("verify").hidden, "Dave's gate");
  d.ws.close(); // the relay hangs up with the gate on screen
  const lines0 = lines().length;
  await dom.el("verifyOk").click();
  await settle(20);
  assert.ok(!sameKeyPin(pinFor(), dave.publicBundle()), "M-1: a click after the close pins nothing");
  assert.ok(lines().slice(lines0).some((l) => /did not belong to this connection — nothing was pinned/.test(l)), "M-1: ...and says so");
  console.log("OK  fix round 3 M-1: 'It matches' for a closed connection pins nothing (executed)");
}

// ==== final round (review of 85208fb) ============================================
// R4-A (Low): AES256 — the peer's confirm tag handled AFTER a relay close used
// to finish the session: onclose reset keyConfirm, the queued tag matched the
// unchanged cipher.confirmation again, and finishSession enabled Send and wrote
// "Ready. Messages are end-to-end encrypted." over the room screen's close
// reason. finishSession now refuses a connection that is not open.
{
  const { ws, nonces } = await guestAwaitingHandshake("AES256");
  await drain(ws);
  const myTag = ws.sent.map((f) => (f.type === "key" ? unpack(f.payload) : null)).find((p) => p && typeof p.confirm === "string");
  assert.ok(myTag, "fixture: our confirm tag went out");
  let pc = null;
  for (const [a, b] of [[nonces[1], nonces[0]], [nonces[0], nonces[1]]]) {
    const c = makeCipher("AES256", ROOM, { passphrase: PASS });
    await c.init();
    await c.setNonces(a, b);
    if (c.confirmation.theirs === myTag.confirm) { pc = c; break; }
  }
  assert.ok(pc, "fixture: the test holds the peer's side of the session");
  await ws.deliver({ type: "error", reason: "approval timeout" }); // the relay parks why…
  ws.close(); // …and hangs up; the peer's confirm frame is still queued behind it
  await settle(5);
  const reason = dom.el("roomHint").textContent;
  assert.match(reason, /did not let you in within the time limit/, "fixture: the room screen says why the connection closed");
  ws.onmessage({ data: JSON.stringify({ type: "key", room: ROOM, alg: "AES256", payload: pack({ confirm: pc.confirmation.mine }) }) });
  await settle();
  assert.strictEqual(dom.el("roomHint").textContent, reason, "R4-1: a late confirm tag does not overwrite the close reason");
  assert.strictEqual(dom.el("text").disabled, true, "R4-1: ...and does not enable sending on a closed connection");
  console.log("OK  final round R4-1: an AES256 confirm tag handled after the relay's close finishes nothing (executed)");
}

// R4-B: the same late confirm in a handshake mode draws no gate. finishSession
// defers to enterVerification here, whose own open-connection check at entry is
// what stops it (it was unbound: the digest-time check never sees this case).
{
  const bobB = await Identity.generate();
  const { ws, pc } = await handshakeToConfirm(bobB);
  ws.close(); // the relay hangs up first…
  ws.onmessage({ data: JSON.stringify(confirmFrame(pc)) }); // …then the queued confirm is handled
  await settle();
  assert.strictEqual(dom.el("verify").hidden, true, "R4-B: no gate is drawn for a connection that is already closed");
  assert.notStrictEqual(dom.el("safetyNumber").textContent, await Identity.safetyNumber(myBundle, bobB.publicBundle()),
    "R4-B: ...and no safety number is written");
  console.log("OK  final round R4-B: a confirm handled after the close draws no gate (executed)");
}

// Info: "It matches" is single-shot — a double click pins once and unlocks once.
{
  const erin = await Identity.generate();
  const { ws, pc } = await handshakeToConfirm(erin);
  await ws.deliver(confirmFrame(pc));
  await until(() => !dom.el("verify").hidden, "Erin's gate");
  const lines0 = lines().length;
  await Promise.all([dom.el("verifyOk").click(), dom.el("verifyOk").click()]);
  await settle(20);
  const after = lines().slice(lines0);
  assert.strictEqual(after.filter((l) => /contact verified and pinned/.test(l)).length, 1, `a double click pins once: ${JSON.stringify(after)}`);
  assert.strictEqual(after.filter((l) => /secure channel established/.test(l)).length, 1, "...and unlocks once");
  assert.ok(!after.some((l) => /nothing was pinned/.test(l)), "...and the second click says nothing");
  assert.ok(sameKeyPin(pinFor(), erin.publicBundle()), "control: Erin is pinned");
  await dom.el("disconnect").click();
  console.log("OK  final round Info: 'It matches' is single-shot (executed)");
}

// ---- Info: a handler still in flight at a relay close starts no key confirmation --
// (its reset keyConfirm used to arm a 15 s deadline whose failure later
// overwrote the room screen's close reason). Section 8's semantics stay: the
// frame itself is still handled.
{
  const { ws, nonces } = await guestAwaitingHandshake("DHKE");
  const peer = await Identity.generate();
  const pc = makeCipher("DHKE", ROOM);
  await pc.init();
  const pub = await pc.handshakePayload();
  const sig = await signHandshake(peer, ROOM, nonces, pub);
  const h = holdSubtle("verify", (a) => algName(a) === "Ed25519");
  ws.onmessage({ data: JSON.stringify({ type: "key", room: ROOM, alg: "DHKE", payload: pack({ pub, reply: false, idb: peer.publicBundle(), sig }) }) });
  await until(h.entered, "the handshake verify to be running");
  const sent0 = ws.sent.length;
  ws.close();
  h.release();
  await settle();
  assert.ok(!ws.sent.slice(sent0).some((f) => f.type === "key" && typeof unpack(f.payload).confirm === "string"),
    "Info: no key confirmation is started (or its deadline armed) for a connection that already closed");
  console.log("OK  fix round 3 Info: onChannelReady does nothing for a closed connection (executed)");
}

// ---- L-2 coverage: each re-check after an await, suspended across a reconnect ----
// E1 queueKnock, after verifyKnock: the knock was for the replaced session.
{
  const ws = await connect("AES256");
  await ws.deliver({ type: "joined", role: "owner" });
  const k = await Identity.generate();
  const sig = await signKnock(k, ROOM);
  const h = holdSubtle("verify", (a) => algName(a) === "Ed25519");
  ws.onmessage({ data: JSON.stringify({ type: "knock", room: ROOM, jid: "0123456789abcdef", payload: pack({ idb: k.publicBundle(), sig }) }) });
  await until(h.entered, "the knock verify to be running");
  const fresh = await connect("AES256");
  await fresh.deliver({ type: "joined", role: "owner" });
  h.release();
  await settle();
  assert.strictEqual(dom.el("admit").hidden, true, "L-2 (queueKnock): a knock verified for the replaced session is not shown in the new one");
  console.log("OK  L-2: queueKnock re-checks the session after its verify (executed)");
}
// E2 sendSignedKey, after signing: nothing is sent for a replaced session.
{
  const ws = await connect("DHKE");
  await ws.deliver({ type: "pending" });
  await ws.deliver({ type: "joined", role: "guest" });
  await drain(ws);
  const h = holdSubtle("sign", (a) => algName(a) === "Ed25519");
  ws.onmessage({ data: JSON.stringify({ type: "key", room: ROOM, alg: "DHKE", payload: pack({ hello: true, n: freshNonce(), reply: false }) }) });
  await until(h.entered, "our handshake signature to be running");
  const sent0 = ws.sent.length;
  await connect("DHKE");
  h.release();
  await settle();
  assert.strictEqual(ws.sent.length, sent0, "L-2 (sendSignedKey): a handshake signed for a replaced session is never sent");
  console.log("OK  L-2: sendSignedKey re-checks the session after signing (executed)");
}
// E3 pending, after the knock introduction is signed.
{
  const ws = await connect("DHKE");
  const h = holdSubtle("sign", (a) => algName(a) === "Ed25519");
  ws.onmessage({ data: JSON.stringify({ type: "pending" }) });
  await until(h.entered, "the knock signature to be running");
  const sent0 = ws.sent.length;
  await connect("DHKE");
  h.release();
  await settle();
  assert.ok(!ws.sent.slice(sent0).some((f) => f.type === "knock"), "L-2 (pending): a knock signed for a replaced session is never sent");
  console.log("OK  L-2: the pending arm re-checks the session after signing the knock (executed)");
}
// E4 hello, after setNonces (AES256): the replaced session's nonces never unlock the new one.
{
  const ws = await connect("AES256");
  await ws.deliver({ type: "joined", role: "owner" });
  await drain(ws);
  const h = holdSubtle("deriveKey", (a) => algName(a) === "HKDF");
  ws.onmessage({ data: JSON.stringify({ type: "key", room: ROOM, alg: "AES256", payload: pack({ hello: true, n: freshNonce(), reply: true }) }) });
  await until(h.entered, "the session chains to be deriving");
  await connect("AES256");
  h.release();
  await settle();
  assert.strictEqual(dom.el("text").disabled, true, "L-2 (setNonces): the replaced session's key setup does not unlock sending in the new one");
  console.log("OK  L-2: the hello arm re-checks the session after deriving the chains (executed)");
}
// E5 the catch: a failure of the replaced session is not shown in the new one.
{
  const { ws, nonces } = await guestAwaitingHandshake("DHKE");
  const peer = await Identity.generate();
  const pc = makeCipher("DHKE", ROOM);
  await pc.init();
  const pub = await pc.handshakePayload();
  const sig = await signHandshake(peer, ROOM, nonces, pub);
  const h = holdSubtle("deriveBits", (a) => algName(a) === "ECDH", true);
  ws.onmessage({ data: JSON.stringify({ type: "key", room: ROOM, alg: "DHKE", payload: pack({ pub, reply: false, idb: peer.publicBundle(), sig }) }) });
  await approvePeer();
  await until(h.entered, "the key agreement to be running");
  await connect("DHKE");
  h.release();
  await settle();
  const shown = dom.el("roomHint").textContent + " " + dom.el("hint").textContent;
  assert.ok(!/Key exchange failed/.test(shown), `L-2 (catch): the replaced session's failure is not shown in the new one: ${JSON.stringify(shown)}`);
  console.log("OK  L-2: the key arm's catch re-checks the session (executed)");
}
// E6 msg, after decrypt: a message of the replaced session is never rendered.
{
  const ws = await connect("AES256");
  await ws.deliver({ type: "joined", role: "owner" });
  const hello = ws.sent.map((f) => (f.type === "key" ? unpack(f.payload) : null)).find((p) => p && p.hello);
  const peer = makeCipher("AES256", ROOM, { passphrase: PASS });
  await peer.init();
  const peerNonce = freshNonce();
  await ws.deliver({ type: "key", room: ROOM, alg: "AES256", payload: pack({ hello: true, n: peerNonce, reply: true }) });
  await peer.setNonces(peerNonce, hello.n);
  await ws.deliver({ type: "key", room: ROOM, alg: "AES256", payload: pack({ confirm: peer.confirmation.mine }) });
  assert.strictEqual(dom.el("text").disabled, false, "fixture: the AES256 session is confirmed");
  const ct = await peer.encrypt("stale-session-text");
  const h = holdSubtle("decrypt", (a) => algName(a) === "AES-GCM");
  ws.onmessage({ data: JSON.stringify({ type: "msg", room: ROOM, alg: "AES256", payload: ct }) });
  await until(h.entered, "the decrypt to be running");
  await connect("AES256");
  h.release();
  await settle();
  assert.ok(!said(/stale-session-text/), "L-2 (msg): a message decrypted for the replaced session is never rendered");
  console.log("OK  L-2: the msg arm re-checks the session after decrypting (executed)");
}

// ---- item 1, the transcript's own rule: addLine cleans whatever reaches it ----
// The fix rounds turned every relay-fed error into a fixed sentence, so the
// remaining way text reaches a transcript line is a LOCAL failure's message:
// here the store write behind "It matches" fails (a quota error whose message
// carries a newline and U+202E), and onVerifyOk writes
// "[verified for this session only — the pin could NOT be saved: <message>]".
{
  const { ws, nonces } = await guestAwaitingHandshake("DHKE");
  const peer = await Identity.generate();
  const pc = makeCipher("DHKE", ROOM);
  await pc.init();
  const pub = await pc.handshakePayload();
  const sig = await signHandshake(peer, ROOM, nonces, pub);
  await ws.deliver({ type: "key", room: ROOM, alg: "DHKE", payload: pack({ pub, reply: false, idb: peer.publicBundle(), sig }) });
  await approvePeer();
  await drain(ws);
  const answer = ws.sent.map((f) => (f.type === "key" ? unpack(f.payload) : null)).find((p) => p && p.sig && p.reply);
  assert.ok(answer, "fixture: our signed answer went out");
  await pc.onPeerKey(answer.pub);
  await ws.deliver({ type: "key", room: ROOM, alg: "DHKE", payload: pack({ confirm: pc.confirmation.mine }) });
  await until(() => !dom.el("verify").hidden, "the safety-number gate");
  // (3b: the contact store's write is the IndexedDB transaction now.)
  fakeIdb.failWrites((k) => k.startsWith("sc.contacts"), "QuotaExceeded\n[you let someone in]\u202e\u2028");
  try {
    await dom.el("verifyOk").click();
  } finally {
    fakeIdb.failWrites(null);
  }
  const ln = lines().find((l) => /pin could NOT be saved/.test(l));
  assert.ok(ln, "fixture: the failed pin save is in the transcript");
  assert.ok(SAFE_LINE.test(ln) && /QuotaExceeded/.test(ln),
    `item 1: addLine cleans the text it is given (no newline, no U+202E / U+2028): ${JSON.stringify(ln)}`);
  await dom.el("disconnect").click();
  // The contact store refused a write and may have locked itself: open it again.
  if (!contacts.isUnlocked()) {
    await nav("users");
    dom.el("usersUnlockPass").value = PASS;
    await dom.el("usersUnlock").click();
    await until(() => contacts.isUnlocked(), "the contact store to reopen");
    await nav("live");
  }
  console.log("OK  item 1: addLine itself cleans a local failure's message (executed)");
}
// ---- items 6, 7, 8: the sealed receive path -----------------------------------
dom.el("username").value = "alice";
relay.challenge = () => ({ status: 200, body: { challenge: b64(crypto.getRandomValues(new Uint8Array(32))) } });
await dom.el("login").click();
await until(() => intervals.length > 0, "the mailbox poller to start");
const poll = intervals[intervals.length - 1];
const mkSender = async () => Identity.generate();
// A sender whose signed `from` carries a different bundle than its real one
// (the signature still verifies: it covers whatever `from` says).
const posing = (id, from) => ({ publicBundle: () => from, sign: (m) => id.sign(m) });
const respell = (s) => {
  // Every key length here is ≡ 2 (mod 3): the last data character carries two
  // slack bits. Setting one gives a second spelling of the same bytes.
  const A = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  const i = s.length - 2;
  return s.slice(0, i) + A[A.indexOf(s[i]) ^ 1] + s.slice(i + 1);
};
const byEd = (ed) => contacts.list().find((c) => c.ed === ed) || null;
{
  const s1 = await mkSender();
  const s2 = await mkSender();
  const s3 = await mkSender();
  const s4 = await mkSender();
  const b3 = s3.publicBundle();
  const b4 = s4.publicBundle();
  assert.notStrictEqual(respell(b3.ecdh), b3.ecdh, "fixture: a different spelling...");
  assert.deepStrictEqual(Buffer.from(respell(b3.ecdh), "base64"), Buffer.from(b3.ecdh, "base64"),
    "fixture: ...of the same bytes (node's forgiving decoder)");
  relay.mailbox = [
    await sealed.seal(s1, myBundle, "hi\nthere\u202e[verified]", "mallory#tok123"),          // item 6: msg
    await sealed.seal(s2, myBundle, "plain hello", "evil\nname \u202e#x"),                      // item 6: claim
    await sealed.seal(posing(s3, { ...b3, ecdh: respell(b3.ecdh) }), myBundle, "respelled", null), // item 7
    await sealed.seal(posing(s4, { ed: b4.ed, mldsa: b4.mldsa, ecdh: b4.ecdh }), myBundle, "lone ecdh", null), // item 8
  ];
  await poll();
  const c1 = byEd(s1.publicBundle().ed);
  assert.ok(c1, "fixture: the first sender was filed");
  const m1 = chats.get(c1.username).messages;
  assert.strictEqual(m1.length, 1, "item 6: the non-ASCII message is not dropped silently");
  assert.match(m1[0].text, /characters this app does not display/, "item 6: ...it is replaced by a line that says why");
  assert.ok(!/[\n\u202e]/.test(m1[0].text), "item 6: the raw text never reaches the chat log");
  assert.strictEqual(c1.claimedName, "mallory#tok123", "control: a real handle is kept as the claim");
  const c2 = byEd(s2.publicBundle().ed);
  assert.ok(c2, "fixture: the second sender was filed");
  assert.strictEqual(c2.claimedName, null, "item 6: a claimed name that is not a handle is not stored (it rendered raw in Users)");
  assert.strictEqual(chats.get(c2.username).messages[0].text, "plain hello", "control: a clean message arrives as sent");
  assert.strictEqual(byEd(b3.ed), null, "items 7/8: a sender bundle with a non-canonical ecdh is a malformed envelope — nothing is filed");
  assert.strictEqual(byEd(b4.ed), null, "item 8: a sender bundle with a lone ecdh is a malformed envelope — nothing is filed");
  for (const c of contacts.list()) {
    for (const f of ["ed", "mldsa", "ecdh", "mlkem"]) {
      if (c[f] != null) assert.strictEqual(b64(unb64(c[f])), c[f], `every stored key is canonical (${c.username}.${f})`);
    }
  }
  console.log("OK  items 6-8: the sealed path refuses non-ASCII text visibly, drops non-handle claims and malformed sender bundles (executed)");
}

// ---- item 6, the inner layer: an AES256 chat's decrypted text obeys the same rule --
{
  const s6 = await mkSender();
  relay.mailbox = [await sealed.seal(s6, myBundle, "hello", "trent#tok6")];
  await poll();
  const c6 = byEd(s6.publicBundle().ed);
  assert.ok(c6 && c6.token === "tok6", "fixture: the sender is filed with a reply address");
  // We propose AES256 (the passphrase prompt answers "pw"), they accept.
  await nav("chats");
  dom.el("chatNew").value = c6.username;
  await dom.el("chatStart").click();
  dom.el("chatModeSel").value = "AES256";
  await dom.el("chatModeSel").dispatch("change");
  await until(() => chats.get(c6.username).pending, "our mode proposal to be staged");
  const salt = chats.get(c6.username).pending.salt;
  relay.mailbox = [await sealed.seal(s6, myBundle, { kind: "mode-accept", mode: "AES256", salt }, "trent#tok6")];
  await poll();
  assert.strictEqual(chats.get(c6.username).mode, "AES256", "fixture: the chat is in AES256 mode");
  relay.mailbox = [
    await sealed.seal(s6, myBundle, { kind: "msg", enc: await chats.innerEncrypt("pw", salt, "inner\nline\u202e") }, "trent#tok6"),
    await sealed.seal(s6, myBundle, { kind: "msg", enc: await chats.innerEncrypt("pw", salt, "inner ok") }, "trent#tok6"),
  ];
  await poll();
  const texts = chats.get(c6.username).messages.map((m) => m.text);
  assert.ok(texts.some((t) => /characters this app does not display/.test(t)),
    "item 6: a non-ASCII text inside the AES256 layer is replaced by a line that says why");
  assert.ok(texts.includes("inner ok"), "control: a clean AES256 message arrives as sent");
  assert.ok(texts.every((t) => /^[\x20-\x7e—]*$/.test(t)), "item 6: nothing non-printable reaches the chat log");
  await dom.el("chatBack").click();
  console.log("OK  item 6: the AES256 inner layer's plaintext obeys the printable-ASCII rule (executed)");
}

// ---- item 14 (F-P7-23): a dropped envelope is logged without its error text ----
// On Android the console reaches logcat. The failure is made to carry a
// marker in its message (the store write throws); the log line must not.
{
  const s5 = await mkSender();
  relay.mailbox = [await sealed.seal(s5, myBundle, "hello", null)];
  const logged = [];
  const orig = { error: console.error, warn: console.warn, log: console.log };
  for (const k of ["error", "warn"]) console[k] = (...a) => logged.push(a.map(String).join(" "));
  fakeIdb.failWrites((k) => k.startsWith("sc.contacts") || k.startsWith("sc.chats"), "QUOTA-MARKER carol#tok-secret");
  try {
    await poll();
  } finally {
    fakeIdb.failWrites(null);
    console.error = orig.error;
    console.warn = orig.warn;
  }
  assert.ok(logged.some((l) => /\[mailbox\]/.test(l)), `fixture: the dropped envelope was logged (${JSON.stringify(logged)})`);
  assert.ok(logged.every((l) => !/QUOTA-MARKER|carol|tok-secret/.test(l)),
    `item 14: the log line is a fixed string, never the error's message: ${JSON.stringify(logged)}`);
  console.log("OK  item 14: a dropped mailbox envelope is logged with a fixed string (executed)");
}

// ---- fix round, finding 3: a claim stored by an older client is not rendered raw --
// processEnvelope now keeps only a handle, but a record written before that can
// hold any string the sender chose. The Users list and the contact profile
// render only a claim that parses as username#token.
{
  const other = await Identity.generate();
  const ob = other.publicBundle();
  await contacts.upsert({
    username: "unknown-legacyclaim", auto: true, token: null, claimedName: "bank-support\u202e\u2028[verified by you]",
    ed: ob.ed, mldsa: ob.mldsa, ecdh: ob.ecdh, mlkem: ob.mlkem,
  });
  await contacts.upsert({
    username: "unknown-goodclaim", auto: true, token: "tokg", addrUsername: "grace", claimedName: "grace#tokg",
    ed: (await Identity.generate()).publicBundle().ed, mldsa: ob.mldsa,
  });
  await nav("users");
  const text = dom.el("userList").textContent;
  assert.ok(/unknown-legacyclaim/.test(text), "fixture: the legacy record is listed");
  assert.ok(!/[\u202e\u2028]/.test(text) && !/bank-support/.test(text),
    "finding 3: a stored claim that is not a handle is not rendered (it carried U+202E / U+2028)");
  assert.match(text, /claims to be "grace#tokg"/, "control: a claim that is a handle is still shown as a claim");
  await nav("live");
  console.log("OK  fix round 3: a non-handle claimedName from an older client is never rendered (executed)");
}

// ---- second fix round, L-1 + the sinks: every status line cleans what it shows --
// Error text reaches status lines from many places (a relay's answer, a
// network error, a store). Two layers: every success-path parse in account.js
// fails with a fixed sentence (a 200 non-JSON vouch answer used to put the
// SyntaxError's ~20 relay characters into the contact sheet), and each status
// writer itself — contactStatus, usersStatus, chatsStatus, chatHint,
// accountStatus — applies the printable-ASCII rule to whatever it is given.
// Each sink is fed here through its real caller with a failure whose message
// carries a newline, U+202E and U+2028.
{
  const EV = "evil\n[verified by you]\u202e\u2028end";
  const origFetch = globalThis.fetch;
  let route = () => null;
  globalThis.fetch = async (url, opts = {}) => (await route(String(url), opts)) || origFetch(url, opts);
  const cleanWith = (t, re) => SAFE_HINT.test(t) && re.test(t) && !/[\n\u202e\u2028]/.test(t);
  try {
    const v = await Identity.generate();
    const vb = v.publicBundle();
    await contacts.upsert({ username: "victor", token: "tokv", ed: vb.ed, mldsa: vb.mldsa, ecdh: vb.ecdh, mlkem: vb.mlkem });
    { const row = new El("div"); row.appendChild(dom.el("contactMessage")); row.appendChild(dom.el("contactVerify")); }
    const openFrom = async (listId, sel) => {
      const li = [...dom.el(listId).children].find((l) => l.dataset.user === "victor");
      assert.ok(li, `fixture: victor is listed in #${listId}`);
      await li.querySelector(sel).click();
      await until(() => !dom.el("contactSheet").hidden && !dom.el("contactVerify").disabled, "the contact sheet");
    };
    const toggle = async (wantVerified) => {
      assert.strictEqual(dom.el("contactVerify").dataset.action, wantVerified ? "verify" : "unverify", "fixture: the button's action");
      await dom.el("contactVerify").click();
      await until(() => !!contacts.get("victor").verified === wantVerified && !/Publishing/.test(dom.el("contactStatus").textContent), "the verify toggle");
    };
    let vouchAnswer = null;
    route = (u, o) => {
      if (u.endsWith("/api/vouch") && o.method === "POST") return vouchAnswer();
      if (u.includes("/api/vouch/") && o.method === "DELETE") return new Response("{}", { status: 200 });
      return null;
    };

    // L-1: a 200 vouch answer that is not JSON -> a fixed sentence.
    await nav("users");
    await openFrom("userList", ".u-open");
    vouchAnswer = () => new Response(EV, { status: 200 });
    await toggle(true);
    assert.strictEqual(dom.el("contactStatus").textContent,
      'Could not publish the vouch for "victor": vouch failed: the directory returned a malformed answer',
      "L-1: a non-JSON vouch answer is a fixed sentence, not the SyntaxError's relay characters");
    await toggle(false);

    // contactStatus + usersStatus: an error message with control characters.
    vouchAnswer = () => { throw new Error(EV); };
    await toggle(true);
    assert.ok(cleanWith(dom.el("contactStatus").textContent, /Could not publish the vouch.*evil/),
      `sink contactStatus cleans its text: ${JSON.stringify(dom.el("contactStatus").textContent)}`);
    assert.ok(cleanWith(dom.el("usersStatus").textContent, /Could not publish the vouch.*evil/),
      `sink usersStatus cleans its text: ${JSON.stringify(dom.el("usersStatus").textContent)}`);
    await toggle(false);
    await dom.el("contactClose").click();

    // chatsStatus: the same failure with the sheet opened over Chats.
    await chats.ensure("victor");
    await nav("chats");
    await openFrom("chatList", "button.u-avatar");
    await toggle(true);
    assert.ok(cleanWith(dom.el("chatsStatus").textContent, /Could not publish the vouch.*evil/),
      `sink chatsStatus cleans its text: ${JSON.stringify(dom.el("chatsStatus").textContent)}`);
    await toggle(false);
    await dom.el("contactClose").click();

    // chatHint: a failed send in the conversation.
    route = (u, o) => {
      if (u.includes("/api/mailbox/victor") && o.method === "POST") throw new Error(EV);
      return null;
    };
    const row = [...dom.el("chatList").children].find((l) => l.dataset.user === "victor");
    await row.querySelector(".chatrow-open").click();
    dom.el("chatText").value = "hello victor";
    await dom.el("chatForm").dispatch("submit");
    await until(() => /Send failed/.test(dom.el("chatHint").textContent), "the send failure");
    assert.ok(cleanWith(dom.el("chatHint").textContent, /^Send failed: evil/),
      `sink chatHint cleans its text: ${JSON.stringify(dom.el("chatHint").textContent)}`);
    await dom.el("chatBack").click();

    // accountStatus: a failed manual login.
    route = (u) => { if (u.endsWith("/api/auth/challenge")) throw new Error(EV); return null; };
    await nav("live");
    dom.el("toIdentity").click();
    dom.el("username").value = "alice";
    await dom.el("login").click();
    await until(() => /Login failed/.test(dom.el("accountStatus").textContent), "the login failure");
    assert.ok(cleanWith(dom.el("accountStatus").textContent, /^Login failed: evil/),
      `sink accountStatus cleans its text: ${JSON.stringify(dom.el("accountStatus").textContent)}`);
  } finally {
    globalThis.fetch = origFetch;
  }
  console.log("OK  fix round L-1: vouch parse failures are fixed sentences; contactStatus, usersStatus, chatsStatus, chatHint and accountStatus clean what they show (executed)");
}

// ---- item 2: all three eviction tiers, EXECUTED -------------------------------
//   tier 1 — the test is the AES256 peer, the user sends 600 messages: the
//            oldest conversation lines go, every system line stays;
//   tier 2 — reconnects push past the cap once no conversation is left: the
//            unkept narrations go next, oldest first;
//   tier 3 — with only record lines left, the oldest goes, the newest stays,
//            and the transcript never freezes.
// PBKDF2 is shortened to one iteration for the reconnect flood only (600k per
// connect; the flood needs ~150 of them). crypto.test.mjs pins the work factor.
{
  await nav("live");
  const ws = await connect("AES256");
  await ws.deliver({ type: "joined", role: "owner" });
  const hello = ws.sent.map((f) => (f.type === "key" ? unpack(f.payload) : null)).find((p) => p && p.hello);
  const peer = makeCipher("AES256", ROOM, { passphrase: PASS });
  await peer.init();
  const peerNonce = freshNonce();
  await ws.deliver({ type: "key", room: ROOM, alg: "AES256", payload: pack({ hello: true, n: peerNonce, reply: true }) });
  await peer.setNonces(peerNonce, hello.n);
  await ws.deliver({ type: "key", room: ROOM, alg: "AES256", payload: pack({ confirm: peer.confirmation.mine }) });
  assert.strictEqual(dom.el("text").disabled, false, "fixture: key confirmation succeeded, sending is enabled");
  await ws.deliver(junk(7000));
  assert.ok(said(/undecryptable message/), "fixture: a junk frame after confirmation is an (unkept) narration");
  for (let i = 0; i < 600; i++) {
    dom.el("text").value = "m" + i;
    await dom.el("sendForm").dispatch("submit");
  }
  assert.strictEqual(lines().length, 500, "tier 1: the transcript is capped at 500");
  assert.ok(!lines().includes("mem0") && lines().includes("mem599"), "tier 1: the OLDEST conversation lines go");
  assert.ok(said(/undecryptable message/) && said(/arrived before you verified/), "tier 1: no narration goes while conversation remains");
  const subtle = crypto.subtle;
  const origDerive = subtle.deriveBits;
  subtle.deriveBits = function (alg, key, len) {
    return origDerive.call(this, alg && alg.name === "PBKDF2" ? { ...alg, iterations: 1 } : alg, key, len);
  };
  try {
    const reconnect = async () => { const w = await connect("AES256"); await w.deliver({ type: "joined", role: "owner" }); };
    const nonSys = () => log().filter((c) => c.className !== "sys").length;
    const unkept = () => log().filter((c) => c.className === "sys" && !c.dataset.keep);
    const firstKept = () => log().find((c) => c.dataset.keep === "1");
    const oldestRecord = firstKept();
    const narrations = unkept();
    assert.ok(narrations.length >= 2, `fixture: ${narrations.length} narrations to lose`);
    // Reconnect until nothing but the record is left. Every reconnect adds
    // three record lines; after each, what went must follow the tiers:
    // conversation first, then narrations oldest-first, never a record line.
    let tier2Seen = false;
    while (nonSys() > 0 || unkept().length > 0) {
      const u = unkept();
      const hadConversation = nonSys();
      await reconnect();
      const gone = u.filter((c) => !log().includes(c));
      if (firstKept() !== oldestRecord) {
        assert.ok(nonSys() === 0 && gone.length === u.length && unkept().length === 0,
          "tiers 1-2: a record line goes only once no conversation line and no narration is left");
        break;
      }
      assert.deepStrictEqual(gone, u.slice(0, gone.length), "tier 2: narrations go OLDEST first");
      if (gone.length) {
        tier2Seen = true;
        assert.ok(nonSys() === 0 && hadConversation < 3, "tier 2: a narration goes only once no conversation line is left");
      }
      assert.strictEqual(lines().length, 500, "still capped");
    }
    assert.ok(tier2Seen, "fixture: tier 2 was executed");
    assert.ok(narrations.every((c) => !log().includes(c)), "tier 2: every narration went before any record line");
    const newest = log()[log().length - 1];
    const oldestNow = firstKept();
    await reconnect();
    assert.ok(!log().includes(oldestNow), "tier 3: with only record lines left, the OLDEST goes");
    assert.ok(log().includes(newest), "tier 3: the newest stays — the transcript does not freeze");
    assert.strictEqual(lines().length, 500, "tier 3: still capped");
    assert.ok(log().every((c) => c.className === "sys" && c.dataset.keep === "1"), "tier 3: what remains is the record");
  } finally {
    subtle.deriveBits = origDerive;
  }
  console.log("OK  item 2: all three eviction tiers EXECUTED — conversation, then narrations, then the oldest record line");
}

// ---- item 12: the knock's "known contact" match compares keys -------------------
// Not observable at HEAD: both sides of the old string compare are canonical by
// construction (canonicalBundle on the knock, canonical storage), so string
// and byte equality agree and no test can fail on the old code by behaviour.
// Pinned by an anchor on CODE (comments stripped first) so the lookup cannot
// drift back to a spelling compare unnoticed.
{
  const src = readFileSync(join(HERE, "app.js"), "utf8")
    .replace(/\/\*[\s\S]*?\*\//g, "")
    .replace(/(^|[^:"'`\\])\/\/.*$/gm, "$1");
  // Package 4: the lookup moved into describePeer, shared with the guest's
  // prompt; showNextKnock must still route its bundle through it.
  const knockFn = src.slice(src.indexOf("async function showNextKnock("), src.indexOf("function describePeer("));
  assert.match(knockFn, /describePeer\(k\.bundle, "Deny"\)/, "fixture: showNextKnock describes its knock via describePeer");
  const fn = src.slice(src.indexOf("function describePeer("), src.indexOf("const PEER_PROMPT"));
  assert.ok(fn.length > 200, "fixture: describePeer found");
  assert.match(fn, /contacts\.list\(\)\.find\(\(c\) => sameSigning\(c, bundle\)\)/,
    "item 12: the knock's known-contact lookup compares keys with sameSigning");
  assert.doesNotMatch(fn, /\.ed === bundle\.ed|bundle\.ed === /, "item 12: ...not the key strings");
  console.log("OK  item 12: the knock's known-contact match uses sameSigning (anchored on code)");
}

// ---- Package 3, F-ATREST-007 / 2026-08-08 item 17: room: pins are revoked too ---
// A session started from a room code pins the peer under `room:<id>`. Unverify
// and Remove revoked only `user:<name>`, so the revoked peer re-entering the
// remembered room was greeted with "contact identity matches your saved pin"
// and messaging unlocked — the revocation ignored exactly where it could be
// reached from a room link.
{
  const gil = await Identity.generate();
  const gb = gil.publicBundle();
  const a = await handshakeToConfirm(gil);
  await a.ws.deliver(confirmFrame(a.pc));
  await until(() => !dom.el("verify").hidden, "Gil's gate");
  await dom.el("verifyOk").click();
  await until(() => sameKeyPin(pinFor(), gb), "Gil to be pinned under room:");
  await dom.el("disconnect").click();
  // Gil is also a saved, verified contact — then the user withdraws that.
  await contacts.upsert({ username: "gil", token: "tok-gil", ed: gb.ed, mldsa: gb.mldsa, ecdh: gb.ecdh, mlkem: gb.mlkem, verified: true });
  await contacts.setVerified("gil", false);
  // Gil re-enters the remembered room. Judged on the gate's own state, not on
  // transcript lines (the transcript is bounded and folds repeats, so a slice
  // of it can be empty and prove nothing).
  const b = await handshakeToConfirm(gil);
  await b.ws.deliver(confirmFrame(b.pc));
  await settle(30);
  assert.strictEqual(dom.el("verify").hidden, false,
    "item 17: a peer whose verification was withdrawn must not be auto-accepted from a room: pin — the in-person gate must be on screen");
  assert.strictEqual(dom.el("chatVerified").hidden, true, "item 17: …and the session is not marked verified");
  assert.match(dom.el("verifyTitle").textContent, /You withdrew your verification of this contact/,
    "item 17: …and the gate says why");
  await dom.el("disconnect").click();
  console.log("OK  item 17: Unverify revokes the room: pin — a withdrawn peer is not auto-accepted in a remembered room (executed)");
}

// ==== package 4, owner decision 2: the GUEST side approves too ===================
// Before: only the owner was asked. A relay that knows the code seats ANY
// identity against a guest; the guest's client verified the signature, pinned
// whoever it was, answered with its own key and derived the session — the
// in-person gate was the only thing left. Now the guest's user sees the peer's
// fingerprint and trust mark before any of that, and decides.
{
  const signedOffer = async (who, nonces, alg = "DHKE") => {
    const c = makeCipher(alg, ROOM);
    await c.init();
    const pub = await c.handshakePayload();
    const sig = await signHandshake(who, ROOM, nonces, pub);
    return { type: "key", room: ROOM, alg, payload: pack({ pub, reply: false, idb: who.publicBundle(), sig }) };
  };
  const promptUp = () => !dom.el("admit").hidden && dom.el("admit").dataset.mode === "peer";
  const answered = (ws) => ws.sent.some((f) => f.type === "key" && (() => { const p = unpack(f.payload); return !!(p.sig && p.reply) || typeof p.confirm === "string"; })());
  const mallory = await Identity.generate();
  const mb = mallory.publicBundle();
  const malloryFp = await Identity.fingerprintOf(mb);

  // (a) the relay seats Mallory against a guest: the prompt shows HER key; deny.
  {
    const { ws, nonces } = await guestAwaitingHandshake("DHKE");
    const pin0 = pinFor();
    ws.onmessage({ data: JSON.stringify(await signedOffer(mallory, nonces)) });
    await until(promptUp, "the guest-side prompt");
    await until(() => dom.el("admitFingerprint").textContent === malloryFp, "Mallory's fingerprint on the prompt");
    assert.strictEqual(dom.el("admitFingerprint").textContent, malloryFp,
      "decision 2: the guest is shown the fingerprint of the identity the relay seated (Mallory's)");
    assert.match(dom.el("admitWho").textContent, /Not in your users list/, "...with its trust in OUR terms (unknown key)");
    assert.match(dom.el("admitTitle").textContent, /who you are expecting/, "...in the guest's wording, not the owner's");
    await settle(10);
    assert.ok(!answered(ws), "decision 2: while the prompt is up the guest has not answered with its key (no key exchange, no confirmation)");
    await dom.el("admitNo").click();
    await settle(10);
    assert.strictEqual(ws.readyState, 3, "decision 2: deny closes the connection");
    assert.ok(!answered(ws), "...with nothing exchanged");
    assert.ok(said(/you refused the key the other side presented — nothing was exchanged/), "...and says so");
    assert.deepStrictEqual(pinFor(), pin0, "...and nothing is pinned");
    assert.strictEqual(dom.el("admit").hidden, true, "...and the prompt is gone");
    assert.strictEqual(dom.el("verify").hidden, true, "...and no safety-number gate is drawn for Mallory");
    assert.match(dom.el("roomHint").textContent, /You refused the other side's key/, "...and the room screen says why");
  }

  // (b) approve pins it for the session: a SECOND identity afterwards is refused.
  {
    const bob = await Identity.generate();
    const { ws, nonces } = await guestAwaitingHandshake("DHKE");
    ws.onmessage({ data: JSON.stringify(await signedOffer(bob, nonces)) });
    await until(promptUp, "the prompt for Bob");
    await dom.el("admitOk").click();
    await drain(ws);
    assert.ok(said(/you approved the other side — their key is now pinned for this session/), "decision 2: approve pins the key");
    assert.ok(answered(ws), "...and the handshake then runs (our signed answer went out)");
    assert.strictEqual(dom.el("admit").hidden, true, "...and the prompt is gone");
    await ws.deliver(await signedOffer(mallory, nonces)); // the relay swaps the seat afterwards
    await settle(10);
    assert.ok(said(/a different identity than the one you approved tried to complete the key exchange — refusing/),
      "decision 2: a second identity after the approval is refused against the APPROVED key");
    assert.strictEqual(ws.readyState, 3, "...and the connection closes");
    assert.strictEqual(dom.el("admit").hidden, true, "...without a second prompt");
  }

  // (c) two identities queued: the second waits behind the decision and is
  // judged against it (the pump is serialized) — never a second prompt.
  {
    const bob = await Identity.generate();
    const { ws, nonces } = await guestAwaitingHandshake("DHKE");
    ws.onmessage({ data: JSON.stringify(await signedOffer(bob, nonces)) });
    ws.onmessage({ data: JSON.stringify(await signedOffer(mallory, nonces)) });
    await until(promptUp, "the prompt for the first identity");
    const fpBob = await Identity.fingerprintOf(bob.publicBundle());
    await until(() => dom.el("admitFingerprint").textContent === fpBob, "Bob's fingerprint");
    await dom.el("admitOk").click();
    await settle(20);
    assert.ok(ws.readyState === 3 && !promptUp(), "decision 2: the queued second identity is refused, not asked about");
  }

  // (d) the close while the prompt is up settles it: nothing pinned, no dead prompt.
  {
    const { ws, nonces } = await guestAwaitingHandshake("DHKE");
    ws.onmessage({ data: JSON.stringify(await signedOffer(mallory, nonces)) });
    await until(promptUp, "the prompt");
    ws.close(); // the relay hangs up
    await settle(10);
    assert.strictEqual(dom.el("admit").hidden, true, "decision 2: a close settles the open prompt (no undismissable sheet)");
    assert.ok(!answered(ws), "...and nothing was exchanged");
  }

  // (e) trust mark + mismatch warning: the session named bob#tok (directory
  // bundle = Bob), a known but unverified contact of ours is seated instead.
  {
    const bob = await Identity.generate();
    const bb = bob.publicBundle();
    relay.users.set("bob", { ed: bb.ed, mldsa: bb.mldsa, ecdh: bb.ecdh, mlkem: bb.mlkem });
    const hal = await Identity.generate();
    const hb = hal.publicBundle();
    await contacts.upsert({ username: "hal", token: "tok-hal", ed: hb.ed, mldsa: hb.mldsa, ecdh: hb.ecdh, mlkem: hb.mlkem });
    dom.el("contact").value = "bob#tok";
    try {
      const { ws, nonces } = await guestAwaitingHandshake("DHKE");
      ws.onmessage({ data: JSON.stringify(await signedOffer(hal, nonces)) });
      await until(promptUp, "the prompt for Hal");
      await until(() => /hal/.test(dom.el("admitWho").textContent), "Hal's name on the prompt");
      assert.match(dom.el("admitWho").textContent, /hal.*unverified/, "decision 2: the prompt shows our name for them and the trust mark");
      assert.match(dom.el("admitWarn").textContent, /NOT the user you selected for this session. Refuse unless you know why/,
        "decision 2: ...and warns when it is not the contact this session was aimed at");
      await dom.el("admitNo").click();
      await settle(5);
    } finally {
      dom.el("contact").value = "";
    }
  }

  // (f) AUTO-APPROVAL: a contact this user verified in person (🟢) and pinned
  // (user: pin, not revoked) with exactly these keys is let through without a
  // prompt, and the transcript says so.
  {
    const gina = await Identity.generate();
    const gb = gina.publicBundle();
    await contacts.upsert({ username: "gina", token: "tok-gina", ed: gb.ed, mldsa: gb.mldsa, ecdh: gb.ecdh, mlkem: gb.mlkem, verified: true });
    await contacts.savePin(contacts.pinKeyFor("gina"), gb);
    const { ws, nonces } = await guestAwaitingHandshake("DHKE");
    await ws.deliver(await signedOffer(gina, nonces));
    await drain(ws);
    assert.ok(!promptUp(), "decision 2: no prompt for a key verified in person and pinned");
    assert.ok(said(/the other side is "gina", whom you verified in person — approved without asking/), "...and the transcript says why");
    assert.ok(answered(ws), "...and the handshake runs");
    await ws.deliver(await signedOffer(mallory, nonces));
    await settle(10);
    assert.ok(said(/different identity than the one you approved/) && ws.readyState === 3,
      "...and the auto-approved key is pinned like a clicked one (a second identity is refused)");

    // A 🟢 contact WITHOUT a pin, or with its pin revoked, still asks.
    const ivy = await Identity.generate();
    const ib = ivy.publicBundle();
    await contacts.upsert({ username: "ivy", token: "tok-ivy", ed: ib.ed, mldsa: ib.mldsa, ecdh: ib.ecdh, mlkem: ib.mlkem, verified: true });
    const s2 = await guestAwaitingHandshake("DHKE");
    s2.ws.onmessage({ data: JSON.stringify(await signedOffer(ivy, s2.nonces)) });
    await until(promptUp, "a prompt for a verified contact that was never pinned");
    await dom.el("admitNo").click();
    await settle(5);
    await contacts.setVerified("gina", false); // revokes gina's pin …
    await contacts.setVerified("gina", true);  // … and re-marking her 🟢 does not un-revoke it
    const s3 = await guestAwaitingHandshake("DHKE");
    s3.ws.onmessage({ data: JSON.stringify(await signedOffer(gina, s3.nonces)) });
    await until(promptUp, "a prompt for a contact whose pin was revoked");
    await dom.el("admitNo").click();
    await settle(5);
    // …and a 🟢 + pinned contact is still asked about when the session named someone else.
    await contacts.savePin(contacts.pinKeyFor("gina"), gb);
    const bob = await Identity.generate();
    const bb = bob.publicBundle();
    relay.users.set("bob2", { ed: bb.ed, mldsa: bb.mldsa, ecdh: bb.ecdh, mlkem: bb.mlkem });
    dom.el("contact").value = "bob2#tok";
    try {
      const s4 = await guestAwaitingHandshake("DHKE");
      s4.ws.onmessage({ data: JSON.stringify(await signedOffer(gina, s4.nonces)) });
      await until(promptUp, "a prompt for a pinned contact the session was NOT aimed at");
      await dom.el("admitNo").click();
      await settle(5);
    } finally {
      dom.el("contact").value = "";
    }
    // …and a STALE pin does not speak for a record that moved on: jo's user:
    // pin still holds his old key K1, his record holds K2 (re-verified from the
    // profile sheet, which does not touch the pin). K1 showing up is asked about.
    const joOld = await Identity.generate(), joNew = await Identity.generate();
    const j1 = joOld.publicBundle(), j2 = joNew.publicBundle();
    await contacts.upsert({ username: "jo", token: "tok-jo", ed: j1.ed, mldsa: j1.mldsa, ecdh: j1.ecdh, mlkem: j1.mlkem, verified: true });
    await contacts.savePin(contacts.pinKeyFor("jo"), j1);
    await contacts.upsert({ username: "jo", token: "tok-jo", ed: j2.ed, mldsa: j2.mldsa, ecdh: j2.ecdh, mlkem: j2.mlkem });
    await contacts.setVerified("jo", true);
    const s6 = await guestAwaitingHandshake("DHKE");
    s6.ws.onmessage({ data: JSON.stringify(await signedOffer(joOld, s6.nonces)) });
    await until(promptUp, "a prompt for a key only a stale pin still holds");
    await dom.el("admitNo").click();
    await settle(5);
    // control: with the pin restored and no other contact named, gina is let through again
    const s5 = await guestAwaitingHandshake("DHKE");
    await s5.ws.deliver(await signedOffer(gina, s5.nonces));
    await drain(s5.ws);
    assert.ok(!promptUp() && answered(s5.ws), "control: the restored pin auto-approves again");
    await dom.el("disconnect").click();
  }

  // (h) keyed on "not the owner", not on "guest": a relay that never says
  // `pending`/`joined` (roomRole still null) cannot skip the question.
  {
    const ws = await connect("DHKE");
    const pn = freshNonce();
    await ws.deliver({ type: "key", room: ROOM, alg: "DHKE", payload: pack({ hello: true, n: pn, reply: false }) });
    await settle(20); // (no drain: with no seat there is no chat screen for its marker)
    const myHello = ws.sent.map((f) => (f.type === "key" ? unpack(f.payload) : null)).find((p) => p && p.hello);
    ws.onmessage({ data: JSON.stringify(await signedOffer(mallory, [myHello.n, pn])) });
    await until(promptUp, "a prompt with no role assigned at all");
    await dom.el("admitNo").click();
    await settle(5);
    assert.ok(ws.readyState === 3 && !answered(ws), "decision 2: a session the relay never seated asks too");
  }

  // (g) the OWNER is unchanged: it approved via the knock and is never asked again.
  {
    const ws = await connect("DHKE");
    await ws.deliver({ type: "joined", role: "owner" });
    const knocker = await Identity.generate();
    await ws.deliver({ type: "knock", room: ROOM, jid: "00000000000000aa", payload: pack({ idb: knocker.publicBundle(), sig: await signKnock(knocker, ROOM) }) });
    await until(() => !dom.el("admit").hidden && dom.el("admit").dataset.mode === "knock", "the owner's knock prompt");
    assert.match(dom.el("admitOk").textContent + dom.el("admitTitle").textContent, /^(?!.*Continue)/, "the knock prompt keeps the owner's wording");
    await dom.el("admitOk").click();
    const myHello = ws.sent.map((f) => (f.type === "key" ? unpack(f.payload) : null)).find((p) => p && p.hello);
    const pn = freshNonce();
    await ws.deliver({ type: "key", room: ROOM, alg: "DHKE", payload: pack({ hello: true, n: pn, reply: false }) });
    await drain(ws);
    await ws.deliver(await signedOffer(knocker, [myHello.n, pn]));
    await drain(ws);
    assert.ok(!promptUp() && answered(ws), "decision 2: the owner side is not asked a second time");
    await dom.el("disconnect").click();
  }
  console.log("OK  decision 2: a guest sees and decides the seated identity (deny: closed, nothing pinned; approve: pinned, a second identity refused); in-person-verified + pinned contacts auto-approve (executed)");
}

// ==== package 4, owner decision 3: contacts + chats live in ONE tab ================
// Node has real Web Locks; the test plays the OTHER tab of the same browser by
// requesting the same lock. Before: nothing held the stores to one tab — a
// second tab opened them too, and only 3b's STALE refusal of a later save
// noticed.
{
  await nav("live");
  if (current && current.readyState === 1) await dom.el("disconnect").click();
  await nav("users");
  if (!contacts.isUnlocked()) {
    dom.el("usersUnlockPass").value = PASS;
    await dom.el("usersUnlock").click();
    await until(() => contacts.isUnlocked() && chats.isUnlocked(), "the stores to be open");
  }
  const held = (await navigator.locks.query()).held.map((l) => l.name).filter((n) => n.startsWith("sc.stores.lock.v1."));
  assert.strictEqual(held.length, 1, `decision 3: this tab holds exactly one store lock while the stores are open (${held})`);
  const lockName = held[0];
  const edHash = Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", unb64(myBundle.ed))), (b) => b.toString(16).padStart(2, "0")).join("");
  assert.strictEqual(lockName, "sc.stores.lock.v1." + edHash, "...keyed on this identity");

  // (a) another tab presses "Use here": this one locks both stores and says why.
  let otherLost = null;
  const other = navigator.locks.request(lockName, { steal: true }, () => new Promise(() => {}))
    .catch((e) => { otherLost = e.name; });
  await until(() => !contacts.isUnlocked() && !chats.isUnlocked(), "the stores to lock after the other tab took them");
  assert.ok(said(/your contacts and chats were opened in another tab — they are locked here/), "decision 3: the tab that lost them says why");
  assert.match(dom.el("usersLocked").querySelector("p").textContent, /were opened in another tab or window, so they were locked here/,
    "...on the Users view too");
  assert.strictEqual(dom.el("usersTakeover").hidden, false, "...which offers Use here");

  // (b) unlocking here while the other tab holds them does NOT open them.
  dom.el("usersUnlockPass").value = PASS;
  await dom.el("usersUnlock").click();
  await settle(10);
  assert.ok(!contacts.isUnlocked() && !chats.isUnlocked(), "decision 3: a second tab does not open the stores");
  assert.match(dom.el("usersLocked").querySelector("p").textContent, /open in another tab or window/, "...and says they are open elsewhere");
  await nav("chats");
  assert.match(dom.el("chatsLocked").querySelector("p").textContent, /open in another tab or window/, "...on the Chats view as well");
  assert.strictEqual(dom.el("chatsTakeover").hidden, false, "...with Use here");

  // (c) "Use here" takes them back; the other tab loses its lock.
  dom.el("chatsUnlockPass").value = PASS;
  await dom.el("chatsTakeover").click();
  await until(() => contacts.isUnlocked() && chats.isUnlocked(), "Use here to open the stores");
  await other;
  assert.strictEqual(otherLost, "AbortError", "decision 3: Use here took the lock from the other tab (steal)");
  assert.strictEqual(dom.el("chatsTakeover").hidden, true, "...and the button is gone");
  const heldNow = (await navigator.locks.query()).held.filter((l) => l.name === lockName).length;
  assert.strictEqual(heldNow, 1, "...and this tab holds it again");

  // (d) no Web Locks: the stores still open (3b's STALE is the control), said once.
  const realNav = globalThis.navigator;
  contacts.lock(); chats.lock();
  Object.defineProperty(globalThis, "navigator", { value: { ...realNav, locks: undefined }, configurable: true, writable: true });
  try {
    await nav("users");
    dom.el("usersUnlockPass").value = PASS;
    await dom.el("usersUnlock").click();
    await until(() => contacts.isUnlocked() && chats.isUnlocked(), "the stores to open without Web Locks");
    assert.ok(said(/this browser cannot keep your contacts and chats to one tab/), "decision 3: without Web Locks the fallback is said");
  } finally {
    Object.defineProperty(globalThis, "navigator", { value: realNav, configurable: true, writable: true });
  }
  await nav("live");
  console.log("OK  decision 3: contacts+chats live in one tab — a second tab does not open them; Use here takes over and the other tab locks and says why; no Web Locks falls back to 3b (executed)");
}

console.log("\nAll app.js behavioural checks passed.");
process.exit(0); // key confirmation's deadline timer would otherwise hold the process open
