// app.js, EXECUTED — PROGRESS item 7a.
//
// Every control over app.js's relay-message decisions is a regex over its
// source, because app.js touches `document` at module scope and so cannot be
// imported. Four consecutive pentest rounds each found a spelling that walked
// past one of those regexes while the suite stayed green:
//
//   round 1  `/**/ statement;` satisfied the "comment" filter and executed
//   round 2  a decoy copy of the function inside a comment won `indexOf`
//   round 3  `wasPending ||= true;` was not an assignment to the allow-list
//   round 4  `els.admitOk.click()` evaded the deny-list; later
//            `resolvePeerApproval?.(true)` evaded the callee allow-list, and a
//            `getPin` wrapper stripped the flag before the checked code saw it
//
// A regex cannot bind name resolution. This file imports app.js against a DOM
// stub (dom-stub.test.mjs) and drives the real module through a stub relay
// socket, so the assertions below are about what the shipped code DOES.
//
// Scope, stated honestly: the stub is not a browser. No layout, no CSS, no
// real event loop. What is proven here is decisions and transcript output —
// not rendering. The source anchors in peer-approval.test.mjs and friends stay
// where they are: they are cheap and they catch deletion; this catches what
// they structurally cannot.
//
// Run: node app-behaviour.test.mjs   (server not required)
import assert from "node:assert";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { installDom } from "./dom-stub.test.mjs";
import { fakeLocalStorage } from "./identity-store-helpers.test.mjs";
import { makeCipher, bufToB64, b64ToBuf } from "./crypto.js";
import { freshNonce } from "./auth.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOM = "a".repeat(64);

globalThis.localStorage = fakeLocalStorage();
const dom = installDom(join(HERE, "index.html"));

// The encryption picker is read with `querySelector('input[name="alg"]:checked')`
// and the drawer with `.navitem` — neither carries an id, so the stub is seeded
// with them from the real markup's shape. Everything else app.js touches is
// id-addressed and comes from index.html directly.
dom.seedAlgRadios(["DHKE", "AES256", "PQKEM", "OTP"], "DHKE");
dom.seedNavItems(["profile", "live", "users", "chats"]);
// The three locked panes each hold one <p> that app.js rewrites by
// `querySelector("p")`.
for (const id of ["usersLocked", "chatsLocked"]) dom.seedChild(id, "p", "hint");

// ---- init -------------------------------------------------------------------
// Importing app.js runs its whole module-scope setup: 60+ element lookups, the
// event wiring, populateOtpSizes(), setupEntropyCanvas(), refreshOtpPads(),
// showScreen(), showView(), syncAlgUI(), refreshIdentityUI() and the invite-link
// handler. Nothing in the tree exercises that today — a typo'd id or a markup
// rename is a blank half-built page in the browser and a silent pass here.
await import("./app.js");

{
  assert.deepStrictEqual(dom.missingIds(), [],
    "7a: every element id app.js looks up must exist in index.html — a missing one reads as `null` in " +
    "the browser and surfaces as a TypeError deep inside a handler, or as a half-built page");
  assert.ok(dom.asked.size >= 50, `fixture: app.js looked up ${dom.asked.size} ids — the import clearly ran`);
  const room = dom.el("room");
  assert.match(room.value, /^[0-9a-f]{64}$/, "init: a fresh room code is generated and offered");
  assert.strictEqual(dom.el("scrIdentity").hidden, false, "init: the identity screen is shown first");
  assert.strictEqual(dom.el("scrChat").hidden, true);
  console.log("OK  7a: app.js imports, initialises, and asks only for ids index.html defines");
}

// ---- a live socket ----------------------------------------------------------
// AES256 needs a passphrase but no identity, so a session reaches the `joined`
// arm — where every gate below lives — without 600k PBKDF2 per test.
async function connect() {
  dom.el("room").value = ROOM;
  dom.el("pass").value = "correct horse battery staple";
  dom.selectAlg("AES256");
  await dom.el("connect").click();
  const ws = dom.socket();
  assert.ok(ws, "connect() opened a socket");
  ws.open();
  await new Promise((r) => setTimeout(r, 0));
  assert.deepStrictEqual(ws.sent[0], { type: "join", room: ROOM }, "the client joins the room it was given");
  return ws;
}
const lines = () => dom.lines();
const said = (re) => lines().some((l) => re.test(l));
// Lines matching `re`, counting a collapsed "(×n)" line as n — identical
// consecutive system lines fold, and the transcript is never cleared between
// the connections below, so a plain line count can miss a repeat.
const tally = (re) => lines().filter((l) => re.test(l)).reduce((n, l) => n + (Number((/×\s*(\d+)/.exec(l) || [])[1]) || 1), 0);

// ---- F-PROTO-001, guest side: a seat nobody asked for ------------------------
// The only legitimate route to a guest seat is pending -> knock -> joined:guest.
// A relay that seats us directly means no owner approved anybody. Pinned today
// by an EXACT 56-statement source window; here it is executed.
{
  const ws = await connect();
  await ws.deliver({ type: "joined", role: "guest" });
  assert.ok(said(/without ever asking to be let in/),
    "F-PROTO-001: a guest seat that never passed through the approval queue must be refused, loudly");
  assert.strictEqual(ws.readyState, 3, "...and the socket is closed");
  assert.ok(!said(/joined room/), "...and the session never starts");
  console.log("OK  7a/F-PROTO-001: a guest seated without the approval queue is refused (executed)");
}

// ---- the relay may not re-cast our role mid-session --------------------------
{
  const ws = await connect();
  await ws.deliver({ type: "joined", role: "owner" });
  assert.ok(said(/joined room/), "fixture: the owner seat is accepted");
  await ws.deliver({ type: "joined", role: "guest" });
  assert.ok(said(/changed our role mid-session/),
    "M-2: `roomRole` is write-once — a second, different role is a refusal, not an update");
  assert.strictEqual(ws.readyState, 3);
  console.log("OK  7a: a mid-session role change from the relay is refused (executed)");
}

// ---- an unknown role is an old/hostile relay --------------------------------
{
  const ws = await connect();
  await ws.deliver({ type: "joined", role: "admin" });
  assert.ok(said(/older protocol without the join-approval step|does not support join approval/),
    "a role outside {owner, guest} means no approval step exists — refuse rather than guess");
  assert.strictEqual(ws.readyState, 3);
  console.log("OK  7a: an unrecognised room role is refused (executed)");
}

// ---- F-P7-7: the deprecated-alg refusal is said ONCE -------------------------
// `{"alg":"RSA"}` is 14 bytes, needs no room state, and is handled BEFORE the
// type dispatch. Unlatched it was one DOM write plus a synchronous layout per
// frame — 10 000 of them wedged the renderer for minutes. The latch is pinned
// by a source anchor in rsa-deprecation.test.mjs; this executes it.
{
  const ws = await connect();
  await ws.deliver({ type: "joined", role: "owner" });
  const before = lines().length;
  for (let i = 0; i < 200; i++) await ws.deliver({ alg: "RSA" });
  const refusals = lines().filter((l) => /the other end is using RSA/.test(l));
  assert.strictEqual(refusals.length, 1,
    `F-P7-7: the deprecated-alg refusal occupies one transcript line (got ${refusals.length})`);
  // The line count alone does NOT bind the latch: addLine collapses identical
  // consecutive system lines, so an unlatched refusal would also be ONE line —
  // carrying "(×200)". The repeat counter is what tells "said once" from
  // "narrated 200 times and folded", i.e. from 200 DOM writes and 200
  // synchronous layouts, which is the cost F-P7-7 is about.
  assert.doesNotMatch(refusals[0], /×\s*\d+/,
    `F-P7-7: the refusal must be SAID once per connection, not narrated per frame and collapsed: ${refusals[0]}`);
  assert.ok(lines().length <= before + 1, "...so 200 frames cost at most one transcript line");
  assert.notStrictEqual(ws.readyState, 3, "...and the frames are dropped, not fatal");
  console.log("OK  7a/F-P7-7: 200 alg:\"RSA\" frames cost exactly one line (executed)");
}

// ---- M-5: a junk flood may not evict the security lines ----------------------
// Two rules protect the transcript: identical consecutive system lines collapse
// onto one counted line, and eviction past LOG_MAX_LINES takes the oldest
// NON-system line first. Without them, 600 junk `msg` frames pushed "joined
// room" and the approval lines out of the transcript entirely.
//
// Worth stating, because it is what this test can and cannot prove. The
// collapse rule folds IDENTICAL consecutive system lines, so a flood of the
// constant strings a relay can make us narrate unprompted ("[message arrived
// before you verified…]", "[undecryptable message…]") is one counted line.
// The first cut of this comment claimed that therefore "a hostile relay can no
// longer reach the cap at all". The review of 4b9d2c6..a88baa4 (M-1) showed
// that was false: the queue-full line interpolated the relay's `count`, so
// consecutive frames differed, nothing collapsed, and 1 200 thirty-byte
// frames evicted "joined room" — because once only system lines remained,
// the fallback took the OLDEST. That line is constant and latched now (the
// second block below floods it), and the fallback takes the NEWEST line.
// What this file still cannot do is reach the cap with distinct lines: every
// remaining path to one needs the peer's cooperation or the user's own
// actions, so the eviction ORDER itself stays pinned by the source anchor in
// rsa-deprecation.test.mjs. `lines().length <= 500` below is therefore a
// sanity bound, not the control — the counted line and the surviving session
// line are.
{
  const ws = await connect();
  await ws.deliver({ type: "joined", role: "owner" });
  assert.ok(said(/joined room/), "fixture: the session line is there to lose");
  for (let i = 0; i < 600; i++) {
    await ws.deliver({ type: "msg", room: ROOM, alg: "AES256", payload: Buffer.from(JSON.stringify({ iv: "AAAAAAAAAAAAAAAA", ct: "AAAA", n: 1000 + i })).toString("base64") });
  }
  assert.ok(said(/joined room/),
    "M-5: a junk flood must not evict the security lines — eviction takes the oldest NON-system line first");
  // Unverified, each junk frame narrates the same refusal — the relay-driven
  // repeated system line the collapse rule exists for.
  const repeated = lines().filter((l) => /arrived before you verified/.test(l));
  assert.ok(repeated.length <= 2,
    `M-5: identical system lines collapse onto one counted line (got ${repeated.length} separate ones)`);
  assert.ok(repeated.some((l) => /×\s*\d+/.test(l)) || repeated.length === 1,
    "...and the collapsed line carries its repeat count");
  assert.ok(lines().length <= 500, "...and the transcript stays bounded");
  console.log("OK  7a/M-5: 600 junk frames leave the security lines in place (executed)");
}

// ---- M-1: the queue-full line cannot be varied, and is said once ------------
// Review of 4b9d2c6..a88baa4. `{type:"turned-away", count:i}` with a fresh
// `count` per frame was the one unprompted system line a relay could make
// DISTINCT. Against the old code this test fails: after 1 200 frames "joined
// room" and "you created this chat" were gone and the socket was still open.
{
  // The transcript is never cleared between connections, so count the
  // session lines rather than asking whether ANY is present.
  const count = (re) => lines().filter((l) => re.test(l)).length;
  const ws = await connect();
  await ws.deliver({ type: "joined", role: "owner" });
  const sessionLines = count(/joined room/);
  assert.ok(sessionLines >= 1, "fixture: the session line is there to lose");
  const before = lines().length;
  for (let i = 2; i < 1202; i++) await ws.deliver({ type: "turned-away", count: i });
  assert.strictEqual(count(/joined room/), sessionLines,
    "M-1: a queue-full flood with a varying count must not evict the session's security lines");
  const turned = lines().filter((l) => /turned away/.test(l));
  assert.strictEqual(turned.length, 1, `M-1: the queue-full line is ONE transcript line (got ${turned.length})`);
  assert.doesNotMatch(turned[0], /×\s*\d+|\d+ people/,
    `M-1: the line is said once per connection — neither narrated per frame and folded, nor carrying the relay's count: ${turned[0]}`);
  assert.ok(lines().length <= before + 1, "...so 1 200 frames cost at most one transcript line");
  assert.notStrictEqual(ws.readyState, 3, "...and the frames are dropped, not fatal");
  console.log("OK  7a/M-1: 1 200 queue-full frames with a varying count cost exactly one line (executed)");
}

// ---- second review of the M-1 fix: the alternations a relay CAN drive --------
// The collapse rule folds only CONSECUTIVE identical lines, so two alternating
// lines defeat it. `joined` used to re-narrate the session start on every
// repeat — two distinct lines per 32-byte frame — and 300 of them reached the
// cap with no peer and no user; then the first M-1 fix's "evict the newest"
// fallback froze the transcript, so every later line was destroyed on
// arrival. Now: a repeated `joined` for the seat we hold is dropped, and the
// eviction tiers keep the record lines. Against the old code the first
// assertion fails (300 frames -> 500 lines, "joined room" gone).
{
  const count = (re) => lines().filter((l) => re.test(l)).length;
  const ws = await connect();
  await ws.deliver({ type: "joined", role: "owner" });
  const sessionLines = count(/joined room/);
  const before = lines().length;
  for (let i = 0; i < 300; i++) await ws.deliver({ type: "joined", role: "owner" });
  assert.strictEqual(count(/joined room/), sessionLines, "a repeated `joined` narrates nothing — and evicts nothing");
  assert.strictEqual(lines().length, before, "...zero lines for 300 frames");
  assert.notStrictEqual(ws.readyState, 3, "...and it is not fatal (a changed role still is, above)");
  // Every unprompted line the relay can force, interleaved so nothing is
  // consecutive: still far from the cap, and the record lines are still there.
  const junk = (i) => ({ type: "msg", room: ROOM, alg: "AES256", payload: Buffer.from(JSON.stringify({ iv: "AAAAAAAAAAAAAAAA", ct: "AAAA", n: 5000 + i })).toString("base64") });
  for (let i = 0; i < 400; i++) {
    await ws.deliver(junk(i));
    await ws.deliver({ type: "turned-away", count: i + 2 });
    await ws.deliver({ type: "joined", role: "owner" });
    await ws.deliver({ type: "pending" });
    await ws.deliver({ type: "withdrawn", jid: "0123456789abcdef" });
    await ws.deliver({ type: "error", reason: "x" + i });
    await ws.deliver({ type: "denied" }); // third review: this one was missing, and unguarded
  }
  assert.ok(lines().length <= before + 3,
    `M-1: 2 800 interleaved relay frames of every unprompted kind cost at most three lines (got ${lines().length - before})`);
  assert.strictEqual(count(/joined room/), sessionLines, "...and the session line is untouched");
  // The record marker is on the element the eviction tiers read, on the
  // lines the M-5 flood loses first.
  const log = dom.el("log");
  const isKept = (re) => log.children.filter((c) => re.test(c.textContent)).every((c) => c.dataset.keep === "1");
  assert.ok(isKept(/joined room/) && isKept(/you created this chat/), "the session lines carry the `keep` marker");
  assert.ok(log.children.some((c) => /arrived before you verified/.test(c.textContent) && !c.dataset.keep), "...and a junk refusal does not");
  console.log("OK  7a/M-1: the alternations a relay can drive alone stay far below the cap, the record is marked (executed)");
}

// ---- third review: the membership rule, `denied`, and the tiers EXECUTED ------
// The consecutive-collapse rule folds only neighbours, so `denied` alternated
// with a junk `msg` (two constant lines, never adjacent) reached the cap in
// 800 frames — the third arm found in three rounds. Two things changed:
// `denied` is owner-guarded and latched, and a NARRATION (an unkept system
// line) is folded by membership: if the transcript already holds that exact
// line, it is counted onto and moved to the end, wherever it was. So the
// narration lines are bounded by the number of distinct narration strings,
// whatever a relay interleaves.
{
  const count = (re) => lines().filter((l) => re.test(l)).length;
  const junk = (i) => ({ type: "msg", room: ROOM, alg: "AES256", payload: Buffer.from(JSON.stringify({ iv: "AAAAAAAAAAAAAAAA", ct: "AAAA", n: 9000 + i })).toString("base64") });
  const ws = await connect();
  await ws.deliver({ type: "joined", role: "owner" });
  await ws.deliver(junk(0));
  await ws.deliver({ alg: "RSA" });   // a different narration in between (latched, so once)
  await ws.deliver(junk(1));
  await ws.deliver({ type: "denied" });
  await ws.deliver(junk(2));
  assert.strictEqual(count(/arrived before you verified/), 1,
    "M-1 (third review): an identical narration anywhere in the transcript is folded, not appended — alternation cannot defeat it");
  assert.match(lines()[lines().length - 1], /arrived before you verified.*×\s*\d+/, "...the folded line moves to the end and carries its count");
  assert.strictEqual(count(/did not let you in/), 0, "an owner is never denied — the frame is dropped");
  // A guest IS told, once, and it is part of the record.
  const ws2 = await connect();
  await ws2.deliver({ type: "pending" });
  const denials = count(/did not let you in/);
  for (let i = 0; i < 300; i++) await ws2.deliver({ type: "denied" });
  assert.strictEqual(count(/did not let you in/), denials + 1, "a guest is told once per connection");
  const deniedNode = dom.el("log").children.find((c) => /did not let you in/.test(c.textContent));
  assert.strictEqual(deniedNode.dataset.keep, "1", "...and the denial is a record line");
  assert.doesNotMatch(deniedNode.textContent, /×/, "...said once, not narrated 300 times and folded");
  console.log("OK  7a/M-1: narrations fold by membership; `denied` is owner-guarded, latched, kept (executed)");
}

// The eviction loop was executed ZERO times by the suite through two rounds
// of "tiers" — every tier was pinned by the source anchor only. Here it runs
// for real, all three tiers, through app.js's own paths:
//   tier 1 — the test becomes the AES256 peer (it knows the passphrase),
//            completes the hello + key-confirmation exchange, and the user
//            sends 600 messages: the oldest "me" lines go, every system line
//            stays;
//   tier 2 — reconnects (each adds two record lines) push past the cap once
//            no conversation is left: the unkept narrations go next, oldest
//            first, and the oldest record line is untouched;
//   tier 3 — with no narration left, the oldest record line goes, the newest
//            stays, and the transcript never freezes.
// PBKDF2 is shortened to one iteration for the reconnect flood only (600k
// per connect is 85 ms; the flood needs ~500 connects). Nothing under test
// depends on the work factor; crypto.test.mjs pins it.
{
  const count = (re) => lines().filter((l) => re.test(l)).length;
  const log = () => dom.el("log").children;
  const pack = (o) => bufToB64(new TextEncoder().encode(JSON.stringify(o)));
  const unpack = (b) => JSON.parse(new TextDecoder().decode(b64ToBuf(b)));
  const junk = (i) => ({ type: "msg", room: ROOM, alg: "AES256", payload: Buffer.from(JSON.stringify({ iv: "AAAAAAAAAAAAAAAA", ct: "AAAA", n: 7000 + i })).toString("base64") });

  // -- tier 1: a real AES256 session, then the user talks past the cap --
  const ws = await connect();
  await ws.deliver({ type: "joined", role: "owner" });
  const sessionLines = count(/joined room/);
  const hello = ws.sent.map((f) => (f.type === "key" ? unpack(f.payload) : null)).find((p) => p && p.hello);
  assert.ok(hello && hello.n, "fixture: app.js announced its session nonce");
  const peer = makeCipher("AES256", ROOM, { passphrase: "correct horse battery staple" });
  await peer.init();
  const peerNonce = freshNonce();
  await ws.deliver({ type: "key", room: ROOM, alg: "AES256", payload: pack({ hello: true, n: peerNonce, reply: true }) });
  await peer.setNonces(peerNonce, hello.n);
  await ws.deliver({ type: "key", room: ROOM, alg: "AES256", payload: pack({ confirm: peer.confirmation.mine }) });
  assert.strictEqual(dom.el("text").disabled, false, "fixture: key confirmation succeeded and sending is enabled");
  await ws.deliver(junk(0));
  assert.ok(said(/undecryptable message/), "fixture: a junk frame after confirmation is an (unkept) narration");
  const before1 = lines().length;
  for (let i = 0; i < 600; i++) {
    dom.el("text").value = "m" + i;
    await dom.el("sendForm").dispatch("submit");
  }
  assert.ok(ws.sent.filter((f) => f.type === "msg").length >= 600, "fixture: 600 messages were encrypted and sent");
  assert.strictEqual(lines().length, 500, `tier 1: the transcript is capped at 500 (was ${before1} before the messages)`);
  assert.ok(!lines().includes("mem0") && lines().includes("mem599"), "tier 1: the OLDEST conversation lines are the ones evicted");
  assert.strictEqual(count(/joined room/), sessionLines, "tier 1: no record line is evicted while conversation lines exist");
  assert.ok(said(/undecryptable message/) && said(/arrived before you verified/), "tier 1: no narration is evicted while conversation lines exist either");

  // -- tiers 2 and 3: reconnect past the cap --
  const subtle = crypto.subtle;
  const origDerive = subtle.deriveBits;
  subtle.deriveBits = function (alg, key, len) {
    return origDerive.call(this, alg && alg.name === "PBKDF2" ? { ...alg, iterations: 1 } : alg, key, len);
  };
  try {
    const reconnect = async () => { const w = await connect(); await w.deliver({ type: "joined", role: "owner" }); };
    const nonSys = () => log().filter((c) => c.className !== "sys").length;
    const unkept = () => log().filter((c) => c.className === "sys" && !c.dataset.keep);
    const oldest = () => log()[0];
    const first = oldest();
    assert.strictEqual(first.dataset.keep, "1", "fixture: the oldest line in the transcript is a record line");
    // tier 1 again, from the other side: reconnects evict conversation first
    while (nonSys() > 0) { await reconnect(); assert.strictEqual(oldest(), first, "tier 1: the oldest record line is untouched while conversation remains"); }
    assert.strictEqual(lines().length, 500, "still capped");
    // tier 2: the unkept narrations go next, oldest first, the record untouched
    const narrations = unkept();
    assert.ok(narrations.length >= 2, `fixture: ${narrations.length} narrations to lose`);
    const u0 = narrations[0];
    while (unkept().includes(u0)) { await reconnect(); assert.strictEqual(oldest(), first, "tier 2: a narration goes before the oldest record line"); }
    assert.ok(unkept().length < narrations.length && !unkept().includes(u0), "tier 2: the OLDEST narration went first");
    while (unkept().length > 0) { await reconnect(); assert.strictEqual(oldest(), first, "tier 2: every narration goes before any record line"); }
    // tier 3: only record lines remain — the oldest goes, the newest stays
    const newestBefore = log()[log().length - 1];
    await reconnect();
    assert.notStrictEqual(oldest(), first, "tier 3: with only record lines left, the OLDEST goes");
    assert.ok(log().includes(newestBefore), "tier 3: the newest line stays — the transcript does not freeze");
    assert.strictEqual(lines().length, 500, "tier 3: still capped");
    assert.ok(log().every((c) => c.className === "sys" && c.dataset.keep === "1"), "tier 3: what remains is the record");
  } finally {
    subtle.deriveBits = origDerive;
  }
  console.log("OK  7a/M-1: all three eviction tiers EXECUTED — conversation, then narrations, then the oldest record line (never frozen)");
}

// ---- a guest is not told about the owner's queue ------------------------------
// Info-2 (second review): the arm's comment said "only the owner is told" and
// the code did not check. The nudge to "agree a NEW chat code" delivered to
// the guest in the queue is a lever to abandon a working code.
{
  const count = (re) => lines().filter((l) => re.test(l)).length;
  const turned = count(/turned away/);
  const ws = await connect();
  await ws.deliver({ type: "pending" });
  await ws.deliver({ type: "turned-away", count: 3 });
  assert.strictEqual(count(/turned away/), turned, "a guest in the queue is not told the queue is full");
  console.log("OK  7a/Info-2: the queue-full line is owner-only (executed)");
}

// ---- the legitimate guest path, executed --------------------------------------
// Everything above drives REFUSALS. The positive half — pending -> knock ->
// joined:guest succeeds — was guarded only by the source allow-list, the layer
// round 3 walked past with `wasPending ||= true`. Without an identity the
// knock is anonymous (`{anon:true}`), which keeps this free of PBKDF2.
{
  const count = (re) => lines().filter((l) => re.test(l)).length;
  const sessions = count(/joined room/);
  const refusals = count(/without ever asking to be let in/);
  const waits = tally(/waiting — the person who created this chat has to let you in/);
  const ws = await connect();
  await ws.deliver({ type: "pending" });
  assert.strictEqual(tally(/waiting — the person who created this chat has to let you in/), waits + 1,
    "pending: the guest is told they are in the approval queue");
  const knock = ws.sent.find((f) => f.type === "knock");
  assert.ok(knock && knock.room === ROOM, "pending: the client knocks for THIS room");
  await ws.deliver({ type: "joined", role: "guest" });
  assert.strictEqual(count(/joined room/), sessions + 1,
    "joined:guest after pending is the legitimate route and starts the session");
  assert.strictEqual(count(/without ever asking to be let in/), refusals, "...with no refusal");
  assert.notStrictEqual(ws.readyState, 3, "...and the socket stays open");
  console.log("OK  7a: pending -> knock -> joined:guest succeeds (executed positive control)");
}

console.log("All app.js behavioural checks passed.");
