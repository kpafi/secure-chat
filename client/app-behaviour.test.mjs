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
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { readFileSync } from "node:fs";
import { installDom, El } from "./dom-stub.test.mjs";
import { makeCipher, bufToB64, b64ToBuf } from "./crypto.js";
import { Identity, b64, unb64 } from "./identity.js";
import { freshNonce, signHandshake } from "./auth.js";
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
  if (u.includes("/api/mailbox/") && opts.method === "POST") { relay.posted.push(JSON.parse(opts.body).envelope); return json(200, { ok: true }); }
  return json(404, { detail: "not found" });
};

const dom = installDom(join(HERE, "index.html"));
// Structure the stub cannot infer from an id: the encryption radios, the tab
// bar's buttons (the tab bar is put under <body> so showView's
// document.querySelectorAll(".navitem") finds them), the chat top bar, and the
// one <p> in each locked pane that app.js rewrites.
dom.body.appendChild(dom.el("tabbar"));
dom.seedAlgRadios(["DHKE", "AES256", "RSA", "PQKEM", "OTP"], "DHKE");
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
localStorage.removeItem("sc.chats.v1");
await nav("chats");
dom.el("chatsUnlockPass").value = PASS;
await dom.el("chatsUnlock").click();
await until(() => chats.isUnlocked() && contacts.isUnlocked(), "the stores to open");
const me = relay.registered;
assert.ok(me && me.ecdh && me.mlkem, "fixture: our public bundle was published (and captured)");
const myBundle = { ed: me.ed, mldsa: me.mldsa, ecdh: me.ecdh, mlkem: me.mlkem };

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
// (b) a signed RSA handshake whose `pub` is not JSON, which the CIPHER parses
// (crypto.js unpackMsg) — covered only by the sink, hint(), which now cleans
// whatever it is given.
{
  const { ws, nonces } = await guestAwaitingHandshake("RSA");
  const evil = Buffer.from("\u202e{\u2028", "utf8").toString("base64");
  ws.onmessage({ data: JSON.stringify({ type: "key", room: ROOM, alg: "RSA", payload: evil }) });
  await until(() => /Key exchange failed/.test(dom.el("hint").textContent), "the key-frame refusal");
  assert.strictEqual(dom.el("hint").textContent, "Key exchange failed: malformed key frame",
    "finding 2 (a): a key frame that is not JSON is refused with a fixed sentence");
  const peer = await Identity.generate();
  const pub = Buffer.from("\u202e{\u2028x", "utf8").toString("base64");
  const sig = await signHandshake(peer, ROOM, nonces, pub);
  ws.onmessage({ data: JSON.stringify({ type: "key", room: ROOM, alg: "RSA", payload: pack({ pub, reply: false, idb: peer.publicBundle(), sig }) }) });
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
  if (fresh.readyState !== 3) await drain(fresh);
  assert.ok(!lines().slice(lines0).some((l) => /SECOND identity/.test(l)),
    "L-2: the new session's genuine peer is not refused as a second identity");
  assert.notStrictEqual(fresh.readyState, 3, "L-2: ...and the new session stays open");
  assert.ok(fresh.sent.some((f) => f.type === "key" && typeof unpack(f.payload).confirm === "string"),
    "L-2: ...and reaches key confirmation");
  await dom.el("disconnect").click();
  console.log("OK  fix round L-2: a handshake suspended across a reconnect never resumes into the new session (executed)");
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
  await drain(ws);
  const answer = ws.sent.map((f) => (f.type === "key" ? unpack(f.payload) : null)).find((p) => p && p.sig && p.reply);
  assert.ok(answer, "fixture: our signed answer went out");
  await pc.onPeerKey(answer.pub);
  await ws.deliver({ type: "key", room: ROOM, alg: "DHKE", payload: pack({ confirm: pc.confirmation.mine }) });
  await until(() => !dom.el("verify").hidden, "the safety-number gate");
  const origSet = localStorage.setItem;
  localStorage.setItem = (k, v) => {
    if (k.startsWith("sc.contacts")) throw new Error("QuotaExceeded\n[you let someone in]\u202e\u2028");
    return origSet(k, v);
  };
  try {
    await dom.el("verifyOk").click();
  } finally {
    localStorage.setItem = origSet;
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
  const orig = { error: console.error, warn: console.warn, log: console.log, set: localStorage.setItem };
  for (const k of ["error", "warn"]) console[k] = (...a) => logged.push(a.map(String).join(" "));
  localStorage.setItem = (k, v) => {
    if (k.startsWith("sc.contacts") || k.startsWith("sc.chats")) throw new Error("QUOTA-MARKER carol#tok-secret");
    return orig.set(k, v);
  };
  try {
    await poll();
  } finally {
    localStorage.setItem = orig.set;
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
  const fn = src.slice(src.indexOf("async function showNextKnock("), src.indexOf("function hideAdmitPrompt("));
  assert.ok(fn.length > 200, "fixture: showNextKnock found");
  assert.match(fn, /contacts\.list\(\)\.find\(\(c\) => sameSigning\(c, k\.bundle\)\)/,
    "item 12: the knock's known-contact lookup compares keys with sameSigning");
  assert.doesNotMatch(fn, /\.ed === k\.bundle\.ed|k\.bundle\.ed === /, "item 12: ...not the key strings");
  console.log("OK  item 12: the knock's known-contact match uses sameSigning (anchored on code)");
}

console.log("\nAll app.js behavioural checks passed.");
process.exit(0); // key confirmation's deadline timer would otherwise hold the process open
