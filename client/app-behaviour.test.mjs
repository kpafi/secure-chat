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
// Worth stating, because it is what this test can and cannot prove: with the
// collapse rule in place a HOSTILE RELAY can no longer reach the cap at all —
// every line it can make us narrate unprompted ("[message arrived before you
// verified…]", "[undecryptable message…]") is a constant string, so a flood of
// them is one line however long it runs. Distinct lines need the peer's
// cooperation. Eviction is therefore the second line of defence, and its
// ORDER is pinned by the source anchor in rsa-deprecation.test.mjs rather than
// here — nothing a relay can send reaches it once the collapse holds.
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

console.log("All app.js behavioural checks passed.");
