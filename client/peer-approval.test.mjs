// Pentest 2026-08-08, items 14 and 21 — regression tests for the guest-side
// approval gate. Run: node peer-approval.test.mjs
//
// WHY IT IS WRITTEN THIS WAY. `app.js` is a browser controller with no export
// surface: it touches `document` at module scope, so it cannot be imported here,
// and `peerAlreadyTrusted` — the whole of the F-PROTO-001 skip decision — was
// therefore covered by nothing at all (pentest item 27). Refactoring the largest
// and most load-bearing file in the tree purely to hang a test on it is the more
// dangerous change, so instead this lifts the FUNCTION'S REAL SOURCE out of
// app.js and runs it against stubs. If the shipped body changes, this test
// changes with it; if the function disappears or is renamed, this test fails
// loudly rather than passing vacuously.
import assert from "node:assert";
import { readFile } from "node:fs/promises";

const src = await readFile(new URL("./app.js", import.meta.url), "utf8");

// Lift `function peerAlreadyTrusted(...) { ... }` by brace matching.
function lift(name) {
  const start = src.indexOf(`function ${name}(`);
  assert.notStrictEqual(start, -1, `${name} must exist in app.js`);
  let depth = 0;
  let i = src.indexOf("{", start);
  const open = i;
  for (; i < src.length; i++) {
    if (src[i] === "{") depth++;
    else if (src[i] === "}" && --depth === 0) return src.slice(start, i + 1);
  }
  throw new Error(`unbalanced braces in ${name}`);
  void open;
}

const body = lift("peerAlreadyTrusted");

// Executable lines only, trimmed. EVERY source-level anchor in this project must
// go through this: a plain `indexOf`/regex over raw source also matches inside
// comments, so a reverted change can carry a comment that mentions the anchor
// string and satisfy the check while doing the opposite. That is H-1's exact
// defect, and it was found a second time in two other files.
function codeOnly(text) {
  return text.split("\n").map((l) => l.trim())
    .filter((l) => l && !l.startsWith("//") && !l.startsWith("*") && !l.startsWith("/*"));
}

// Byte-wise key equality, standing in for app.js's sameKey/sameBundle/
// sameSigning. Deliberately compares DECODED bytes, so a test that passes here
// is not passing because both sides happen to be the same base64 spelling.
const dec = (s) => (s == null ? null : Buffer.from(s, "base64"));
const eqKey = (x, y) => {
  if (x == null || y == null) return x == null && y == null;
  const a = dec(x), b = dec(y);
  return a.length === b.length && a.every((v, i) => v === b[i]);
};
const sameBundle = (a, b) => !!a && !!b && eqKey(a.ed, b.ed) && eqKey(a.mldsa, b.mldsa) &&
  eqKey(a.ecdh ?? null, b.ecdh ?? null) && eqKey(a.mlkem ?? null, b.mlkem ?? null);
const sameSigning = (a, b) => !!a && !!b && eqKey(a.ed, b.ed) && eqKey(a.mldsa, b.mldsa);

const K = (n) => Buffer.alloc(32, n).toString("base64");
const ALICE = { ed: K(1), mldsa: K(2), ecdh: K(3), mlkem: K(4) };
const MALLORY = { ed: K(9), mldsa: K(8), ecdh: K(7), mlkem: K(6) };
const CAROL = { ed: K(5), mldsa: K(5), ecdh: K(5), mlkem: K(5) };

// Build a callable `peerAlreadyTrusted` over injected module-scope bindings.
function build({ expectedPeerBundle = null, expectedPeerName = "alice", contactList = [], unlocked = true }) {
  const contacts = { isUnlocked: () => unlocked, list: () => contactList };
  const dirName = (c) => c.username;
  const fn = new Function(
    "expectedPeerBundle", "expectedPeerName", "contacts", "dirName", "sameBundle", "sameSigning",
    `${body}; return peerAlreadyTrusted;`,
  );
  return fn(expectedPeerBundle, expectedPeerName, contacts, dirName, sameBundle, sameSigning);
}

let n = 0;
const ok = (name) => { n++; console.log("OK  " + name); };

// --- item 14 ---------------------------------------------------------------
// `expectedPeerBundle` is set from account.fetchBundle, which verifies NO
// signature — nothing binds a handle to its key material. It must therefore
// never be a reason to SKIP the human. A hostile directory answering with the
// attacker's own bundle used to satisfy route (a) exactly.
{
  // The attack: the directory named "alice" but answered with Mallory's keys,
  // and Mallory is who shows up. Pre-fix this returned a trust string and the
  // client printed "peer key matches the directory key for alice".
  const f = build({ expectedPeerBundle: MALLORY, expectedPeerName: "alice" });
  assert.strictEqual(f(MALLORY), null,
    "item 14: a directory answer must never authorise skipping the approval prompt");
  ok("item 14: a hostile directory answer does not skip the prompt");

  // The honest case is refused too, and that is the intended cost: the
  // directory is not a trust source, so a match with it proves nothing.
  const g = build({ expectedPeerBundle: ALICE, expectedPeerName: "alice" });
  assert.strictEqual(g(ALICE), null,
    "item 14: even a MATCHING directory bundle is not grounds to skip — it is unsigned");
  ok("item 14: a matching-but-unsigned directory bundle also costs one click");
}

// --- item 21 ---------------------------------------------------------------
// Route (b) used to fire even when `expectedPeerBundle` was set and did NOT
// match, so a 🟢 contact who is not the contact you selected skipped the prompt.
{
  const carolVerified = [{ username: "carol", ...CAROL, verified: true }];
  const f = build({ expectedPeerBundle: ALICE, expectedPeerName: "alice", contactList: carolVerified });
  assert.strictEqual(f(CAROL), null,
    "item 21: a verified contact who is not the one you picked must still prompt");
  ok("item 21: a 🟢 contact who is not the selected contact does not skip");
}

// --- the route that must SURVIVE -------------------------------------------
// A key verified in person, with no specific contact selected, is a genuinely
// local fact behind the at-rest passphrase. If this stops working the fix has
// over-corrected into "every handshake prompts", which is a usability
// regression the user did not ask for.
{
  const carolVerified = [{ username: "carol", ...CAROL, verified: true }];
  const f = build({ expectedPeerBundle: null, contactList: carolVerified });
  assert.match(String(f(CAROL)), /verified in person/,
    "a 🟢 verified key must still skip the prompt");
  ok("control: a 🟢 key verified in person still skips the prompt");

  // …and the same contact when it IS the one selected.
  const g = build({ expectedPeerBundle: CAROL, expectedPeerName: "carol", contactList: carolVerified });
  assert.match(String(g(CAROL)), /verified in person/,
    "the selected contact, verified in person, still skips");
  ok("control: the selected contact, verified in person, still skips");
}

// --- fail-closed edges ------------------------------------------------------
{
  // Unverified (⚪) contacts are not a skip route — only 🟢.
  const unverified = [{ username: "carol", ...CAROL, verified: false }];
  assert.strictEqual(build({ contactList: unverified })(CAROL), null,
    "an unverified contact must not skip the prompt");
  ok("control: an unverified (⚪) contact does not skip");

  // A locked store cannot answer, and must fail closed rather than skip.
  const locked = [{ username: "carol", ...CAROL, verified: true }];
  assert.strictEqual(build({ contactList: locked, unlocked: false })(CAROL), null,
    "a locked contacts store must fail closed");
  ok("control: a locked contacts store fails closed");

  // Nobody known at all.
  assert.strictEqual(build({})(MALLORY), null, "an unknown peer must prompt");
  ok("control: an unknown peer prompts");
}

// --- source-level: the deleted route must not come back ---------------------
// Items 14/21 are one-line changes, which makes them one-line reversions too.
// This is the belt to the braces above: no positive return may be reachable
// from an `expectedPeerBundle` match.
{
  assert.ok(/if\s*\(expectedPeerBundle\s*&&\s*!sameBundle/.test(body),
    "item 21: the mismatch guard must return null before the contacts route");
  assert.ok(!/if\s*\(expectedPeerBundle\s*&&\s*sameBundle[^)]*\)\s*\{\s*return\s*`/.test(body),
    "item 14: a positive trust route keyed on the directory bundle must not be reintroduced");
  assert.ok(!/directory key/.test(body),
    "item 14: the 'matches the directory key' reassurance must not be reintroduced");
  ok("source: neither deleted route has been reintroduced");
}


// --- pentest 2026-08-10 (M-2): the CALL SITE, not just the function ---------
// This file tests `peerAlreadyTrusted` in isolation, and the hostile-relay
// harness never sets `expectedPeerBundle` (it serves no /api routes and nothing
// types a handle), so the directory-driven skip route — the whole of item 14 —
// is invisible to both. A mutant that restored route (a) AT THE CALL SITE passed
// 9/9 here and 9/9 in the harness while skipping the prompt against a hostile
// directory. So the call site is pinned too: nothing may stand between the
// `approvedBundle` gate and the trust check inside it.
//
// 2026-08-10-night H-1 — THIS GUARD WAS ITSELF DECORATIVE, and the way it failed
// is worth stating because it is easy to repeat. It sliced `site` from a COMMENT
// string ("// F-PROTO-001, rebuilt 2026-08-08"), and the gate is the very next
// statement after that comment — so `between` was the 13 comment lines in
// between and contained NO EXECUTABLE CODE AT ALL. The assertion below it was
// checking that a comment does not mention `expectedPeerBundle`. Two mutants of
// exactly the shape it claimed to catch — one inserted above the comment, one
// moved into `requestPeerApproval` — each skipped the prompt against a hostile
// directory and passed the whole suite.
//
// Two changes: anchor on an EXECUTABLE statement, and assert that the region
// under test actually contains executable code, so this specific failure cannot
// recur silently.
{
  const anchor = src.indexOf("const idbCanon = canonicalBundle(idb);");
  assert.notStrictEqual(anchor, -1, "the handshake branch must still canonicalise the peer bundle");
  const site = src.slice(anchor);
  const gate = site.indexOf("if (!approvedBundle) {");
  assert.notStrictEqual(gate, -1, "the approval gate must still exist at the handshake call site");

  const between = site.slice(0, gate);

  // The H-1 meta-check: prove this region is code before trusting what it says
  // about the code. A comment-anchored slice fails here immediately.
  const codeLines = codeOnly(between);
  assert.ok(codeLines.length >= 5,
    `H-1: the region between the peer bundle and the approval gate holds only ` +
    `${codeLines.length} executable lines — this assertion is testing comments, not code, ` +
    "which is exactly how the previous version of this check passed against live mutants");

  // H-1, SECOND pass (pentest of the H-1 fix itself). Naming the forbidden
  // identifier is not enough, because the decision does not need that identifier.
  // `describeIdentity` (app.js) re-exports the very same directory comparison as
  // `.mismatch`, a decision-grade boolean on a plain object — so
  //
  //     const d = describeIdentity(idbCanon);
  //     if (expectedPeerName && !d.mismatch) approvedBundle = canonicalBundle(idb);
  //
  // is item 14's deleted route, reconstituted, with the string
  // "expectedPeerBundle" appearing nowhere. It passed the whole suite. The
  // `approvedBundle = idbCanon` regex missed it too, because `canonicalBundle(idb)`
  // is the same value spelled differently.
  //
  // A deny-list cannot win this: the attacker picks the spelling. So this is an
  // ALLOW-LIST of every executable line in the window. Nothing may be added here
  // at all, whatever it is made of.
  const EXPECTED_WINDOW = [
    "const idbCanon = canonicalBundle(idb);",
    "const ok = await verifyHandshake(idbCanon, room, [myNonce, peerNonce], pub, sig);",
    "if (!ok) {",
    'addLine("sys", "", "[handshake signature INVALID — refusing to connect; a relay may be tampering with the key exchange]");',
    'hint("Authentication failed — disconnecting. This is what a MITM attempt looks like.", true);',
    "if (ws) ws.close();",
    "return;",
    "}",
    "if (admittedBundle && !sameBundle(admittedBundle, idbCanon)) {",
    'addLine("sys", "", "[the peer that connected is NOT the one you let in — refusing]");',
    'hint("The identity that completed the key exchange differs from the one you approved. Disconnecting.", true);',
    "if (ws) ws.close();",
    "return;",
    "}",
    "if (admittedAnon) {",
    'addLine("sys", "", "[the peer you let in had no identity but now sends one — refusing]");',
    'hint("This peer introduced itself without an identity and then produced one. Disconnecting.", true);',
    "if (ws) ws.close();",
    "return;",
    "}",
    'if (roomRole === "owner" && !admittedSomeone()) {',
    'addLine("sys", "", "[the relay seated someone in your room without asking you — refusing]");',
    'hint("You own this chat and approved nobody, yet someone completed the key exchange. The relay is not behaving. Disconnecting.", true);',
    "if (ws) ws.close();",
    "return;",
    "}",
  ];
  assert.deepStrictEqual(codeLines, EXPECTED_WINDOW,
    "item 14 / H-1: the statements between the peer bundle and the approval gate are pinned " +
    "EXACTLY. Every line here must be a refusal — nothing may compute, cache or consult a " +
    "trust verdict before the human is asked. If you are adding a legitimate refusal, add it " +
    "to EXPECTED_WINDOW in this test and say why in the commit.");

  const body = site.slice(gate, gate + 400);
  assert.ok(/peerAlreadyTrusted\(idbCanon\)/.test(body),
    "the gate must decide via peerAlreadyTrusted, so this file's checks actually bind");
  ok(`item 14: the ${codeLines.length} statements before the approval gate are exactly the pinned refusals`);
}

// --- H-1 second pass: the prompt itself, which no window can reach -----------
// The window check above stops at the gate, so it is blind to a route added
// INSIDE the prompt machinery — and a mutant that made `requestPeerApproval`
// return `Promise.resolve(true)` on a directory match passed the entire suite.
// Those two functions decide whether a human is asked at all, so they are pinned
// by exact body.
{
  const REQUEST_BODY = [
    "function requestPeerApproval(bundle) {",
    "const decided = new Promise((resolve) => { approvalPending = { bundle, resolve }; });",
    "renderPeerApproval(bundle);",
    "return decided;",
    "}",
  ];
  assert.deepStrictEqual(codeOnly(lift("requestPeerApproval")), REQUEST_BODY,
    "item 14 / H-1: `requestPeerApproval` is pinned exactly. It must do nothing but park a " +
    "promise, render, and return it — any other statement is a route that can settle the " +
    "approval without a human, which is the whole of F-PROTO-001");

  // `renderPeerApproval` may READ the directory verdict (it draws the ⚠ line),
  // so it cannot be pinned by exact body without pinning the UI copy. What it
  // must never do is SETTLE the promise: only `resolvePeerApproval`, driven by
  // the two buttons, may call `resolve`.
  const render = codeOnly(lift("renderPeerApproval"));
  for (const l of render) {
    assert.ok(!/\bresolve\b|approvalPending\s*=/.test(l),
      "item 14 / H-1: `renderPeerApproval` may not settle or clear the pending approval — " +
      `only the user's click may do that. Offending line:\n      ${l}`);
  }
  ok("item 14: the approval prompt cannot be settled without a human");
}

// --- H-1 second pass: close the laundering channel at its source -------------
// `describeIdentity().mismatch` IS the directory comparison. As long as any
// decision path can call it, the allow-list on `expectedPeerBundle` is
// decorative. It has exactly two callers, both of which only draw a prompt.
{
  const callers = [];
  const lines = src.split("\n");
  for (let i = 0; i < lines.length; i++) {
    if (!/\bdescribeIdentity\s*\(/.test(lines[i])) continue;
    const l = lines[i].trim();
    if (l.startsWith("//") || l.startsWith("*") || l.startsWith("/*")) continue;
    if (/^function describeIdentity\(/.test(l)) continue; // the definition itself
    // Walk back to the enclosing `function <name>(`.
    let owner = "?";
    for (let j = i; j >= 0; j--) {
      const m = lines[j].match(/^(?:async\s+)?function\s+(\w+)\s*\(/);
      if (m) { owner = m[1]; break; }
    }
    callers.push(owner);
  }
  assert.deepStrictEqual(callers.sort(), ["renderPeerApproval", "showNextKnock"],
    "item 14 / H-1: `describeIdentity` returns `.mismatch`, which is the unsigned directory " +
    "comparison item 14 deleted as a trust route. It may only be called by the two functions " +
    "that DRAW a prompt. A new caller is how that route comes back without ever naming " +
    `expectedPeerBundle. Callers found: ${callers.join(", ")}`);
  ok("item 14: the directory verdict is reachable only from the two prompt renderers");
}

// --- H-1, the other half: an exact allow-list over the WHOLE file -----------
// The check above pins one window. It cannot see a route reintroduced inside
// `requestPeerApproval` or `renderPeerApproval`, which is where the second
// proven mutant lived — those run after the gate is entered, so no window-based
// assertion reaches them.
//
// `expectedPeerBundle` is an unsigned directory answer (item 14), so every use
// of it in app.js is security-relevant and there are few enough to enumerate.
// This is the enumeration: exact trimmed source lines with exact
// multiplicities. Any NEW mention anywhere in app.js fails here, whatever
// function it is in, and any listed one that disappears fails too — so the list
// cannot rot into vacuity the way a regex can.
{
  const ALLOWED = new Map([
    // The declaration, and the fetch path that fills it.
    ["let expectedPeerBundle = null; // bundle fetched from the directory (or null)", 1],
    ["expectedPeerBundle = null;", 1],
    ["expectedPeerBundle = await account.fetchBundle(API_BASE, contact);", 1],
    ["if (!expectedPeerBundle) {", 1],
    // DISPLAY only: describeIdentity computes the ⚠ mismatch line for the prompt.
    ["mismatch: !!(expectedPeerBundle && !sameBundle(expectedPeerBundle, bundle)),", 1],
    // REFUSALS only. Each of these can add a prompt or a warning; none of them
    // can skip one. That asymmetry is the whole of item 14 — a directory answer
    // may accuse, never vouch.
    ["if (expectedPeerBundle && !sameBundle(expectedPeerBundle, bundle)) return null;", 1],
    ["if (expectedPeerBundle && !sameBundle(expectedPeerBundle, bundle)) {", 1],
    // The one remaining positive mention: a "still verify in person" line printed
    // in the first-contact branch, which grants nothing.
    ["if (expectedPeerBundle) {", 1],
  ]);

  const seen = new Map();
  for (const raw of src.split("\n")) {
    const l = raw.trim();
    if (!l.includes("expectedPeerBundle")) continue;
    if (l.startsWith("//") || l.startsWith("*") || l.startsWith("/*")) continue; // prose
    seen.set(l, (seen.get(l) || 0) + 1);
  }

  for (const [l, n] of seen) {
    assert.ok(ALLOWED.has(l),
      "item 14: NEW use of the unsigned directory bundle in app.js:\n" +
      `      ${l}\n` +
      "    Every use must be a refusal or a display string. If this is deliberate, it needs " +
      "review against item 14 first — a directory answer may accuse, never vouch.");
    assert.strictEqual(n, ALLOWED.get(l),
      `item 14: "${l}" appears ${n}x, expected ${ALLOWED.get(l)}x — a duplicated ` +
      "decision line is how this route came back last time");
  }
  for (const [l, n] of ALLOWED) {
    assert.strictEqual(seen.get(l), n,
      `item 14: a pinned expectedPeerBundle site is gone, so something moved: "${l}"`);
  }
  ok(`item 14: all ${seen.size} expectedPeerBundle sites in app.js are on the allow-list`);
}

console.log(`\nAll ${n} peer-approval checks passed.`);
