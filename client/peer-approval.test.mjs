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
import { stripComments, codeLines, liftFunction, referencesOf } from "./test-source.mjs";

const rawSrc = await readFile(new URL("./app.js", import.meta.url), "utf8");

// EVERY source-level anchor in this project runs over COMMENT-STRIPPED source.
// A plain indexOf/regex over raw source also matches inside comments, so a
// reverted change can carry a comment that mentions the anchor string and
// satisfy the check while doing the opposite (H-1's defect, found in three
// files). The previous fix was a prefix filter — drop a line whose trim starts
// with `//`/`*`/`/*` — which round 2 walked past three ways (`/**/ stmt;`,
// a block-comment decoy for the lift, a `/* code */ realCode` one-liner). The
// stripper in test-source.mjs is a real scanner that knows strings and template
// literals. `src` below is the stripped text; nothing here reads `rawSrc`.
const src = stripComments(rawSrc);
const codeOnly = (text) => codeLines(text);

const body = liftFunction(src, "peerAlreadyTrusted", assert);

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
  // ROUND-2 F-3 (2026-08-15): the window used to start AT `const idbCanon =
  // canonicalBundle(idb);`. Everything earlier in the key-frame branch was
  // unconstrained — a mutant writing `approvedBundle = idbCanon` right after the
  // payload is destructured makes the `if (!approvedBundle)` gate never run, and
  // no line in the old window is even reached. So the window now starts at the
  // TOP of the key-frame branch (`if (!cipher.needsHandshake) {`), i.e. the first
  // statement executed once a handshake frame is in hand, and runs to the gate.
  // Nothing may assign, cache, or consult a trust verdict anywhere in here.
  const anchor = src.indexOf("if (!cipher.needsHandshake) {");
  assert.notStrictEqual(anchor, -1, "the key-frame branch must still guard on cipher.needsHandshake");
  const site = src.slice(anchor);
  const gateOpen = site.indexOf("if (!approvedBundle) {");
  assert.notStrictEqual(gateOpen, -1, "the approval gate must still exist at the handshake call site");

  // ROUND-3 F-1 (2026-08-15, pentest of the F-3 fix): the window used to END at
  // the gate line, so the gate's BODY — where `requestPeerApproval` is actually
  // called and where `approvedBundle` is actually set — was pinned by nothing. A
  // mutant could drop `approvedBundle = idbCanon;` straight into the `else` branch
  // (a blanket skip), or reconstitute item 14 there via `expectedPeerName` +
  // `account.fetchBundle` (never naming `expectedPeerBundle`), and pass the whole
  // suite. So the window now runs THROUGH the gate block: the decision body is
  // pinned exactly, and the only path that sets `approvedBundle` without a human
  // is the `peerAlreadyTrusted` (🟢-verified-in-person) branch.
  let depth = 0;
  let gateEnd = -1;
  for (let k = site.indexOf("{", gateOpen); k < site.length; k++) {
    if (site[k] === "{") depth++;
    else if (site[k] === "}" && --depth === 0) { gateEnd = k + 1; break; }
  }
  assert.notStrictEqual(gateEnd, -1, "the approval gate block must be brace-balanced");
  const between = site.slice(0, gateEnd);

  // The H-1 meta-check: prove this region is code before trusting what it says
  // about the code. A comment-anchored slice fails here immediately.
  const codeLines = codeOnly(between);
  assert.ok(codeLines.length >= 5,
    `H-1: the region between the key-frame branch and the approval gate holds only ` +
    `${codeLines.length} executable lines — this assertion is testing comments, not code, ` +
    "which is exactly how the previous version of this check passed against live mutants");

  // H-1, SECOND pass (pentest of the H-1 fix itself). Naming the forbidden
  // identifier is not enough, because the decision does not need that identifier.
  // `describeIdentity` used to RETURN the same directory comparison as
  // `.mismatch`, a decision-grade boolean on a plain object — so
  //
  //     const d = describeIdentity(idbCanon);
  //     if (expectedPeerName && !d.mismatch) approvedBundle = canonicalBundle(idb);
  //
  // was item 14's deleted route, reconstituted, with the string
  // "expectedPeerBundle" appearing nowhere. It passed the whole suite. (That
  // boolean is now gone — describeIdentity writes the DOM and returns nothing —
  // but the window is what makes any such route unreachable regardless.)
  //
  // A deny-list cannot win this: the attacker picks the spelling. So this is an
  // ALLOW-LIST of every executable line in the window. Nothing may be added here
  // at all, whatever it is made of.
  // 2026-09-20 (second review of the M-1 fix): the record lines in this window
  // and in the joined-arm window below carry addLine's `keep` marker, so the
  // transcript's eviction tiers evict them last. Nothing else changed.
  const EXPECTED_WINDOW = [
    "if (!cipher.needsHandshake) {",
    'throw new Error("unexpected key-exchange message for this mode");',
    "}",
    "const { pub, reply, idb, sig } = p;",
    "if (peerNonce === null) {",
    'throw new Error("peer sent a handshake before the nonce exchange");',
    "}",
    "if (!idb || !sig) {",
    'throw new Error("peer sent an unauthenticated handshake");',
    "}",
    "const idbCanon = canonicalBundle(idb);",
    "const ok = await verifyHandshake(idbCanon, room, [myNonce, peerNonce], pub, sig);",
    "if (!ok) {",
    'addLine("sys", "", "[handshake signature INVALID — refusing to connect; a relay may be tampering with the key exchange]", true);',
    'hint("Authentication failed — disconnecting. This is what a MITM attempt looks like.", true);',
    "if (ws) ws.close();",
    "return;",
    "}",
    "if (admittedBundle && !sameBundle(admittedBundle, idbCanon)) {",
    'addLine("sys", "", "[the peer that connected is NOT the one you let in — refusing]", true);',
    'hint("The identity that completed the key exchange differs from the one you approved. Disconnecting.", true);',
    "if (ws) ws.close();",
    "return;",
    "}",
    "if (admittedAnon) {",
    'addLine("sys", "", "[the peer you let in had no identity but now sends one — refusing]", true);',
    'hint("This peer introduced itself without an identity and then produced one. Disconnecting.", true);',
    "if (ws) ws.close();",
    "return;",
    "}",
    'if (roomRole === "owner" && !admittedSomeone()) {',
    'addLine("sys", "", "[the relay seated someone in your room without asking you — refusing]", true);',
    'hint("You own this chat and approved nobody, yet someone completed the key exchange. The relay is not behaving. Disconnecting.", true);',
    "if (ws) ws.close();",
    "return;",
    "}",
    // The approval gate BODY, pinned exactly (ROUND-3 F-1). `approvedBundle` may
    // be set in exactly two places here: the `peerAlreadyTrusted` branch (a 🟢 key
    // verified in person — the one non-prompt route item 14 left standing) and
    // after `allowed` comes back true from `requestPeerApproval` (the human said
    // yes). Any other statement in this block — a blanket `approvedBundle =
    // idbCanon`, or an `else if` consulting a directory answer — fails here.
    "if (!approvedBundle) {",
    "const trusted = peerAlreadyTrusted(idbCanon);",
    "if (trusted) {",
    "approvedBundle = idbCanon;",
    'addLine("sys", "", `peer key ${trusted} — no approval needed`, true);',
    "} else {",
    'addLine("sys", "", "[nobody has approved this connection — asking you before any keys are exchanged]", true);',
    "const allowed = await requestPeerApproval(idbCanon);",
    "if (!ws || ws.readyState !== WebSocket.OPEN) return;",
    "if (!allowed) {",
    'addLine("sys", "", "[you refused this peer — disconnecting]", true);',
    'hint("You refused the key that was offered. Nothing was exchanged.", true);',
    "ws.close();",
    "return;",
    "}",
    "approvedBundle = idbCanon;",
    'addLine("sys", "", "you approved this peer — their key is now pinned for this session", true);',
    "await showNextKnock();",
    "}",
    "}",
  ];
  assert.deepStrictEqual(codeLines, EXPECTED_WINDOW,
    "item 14 / H-1 / ROUND-3 F-1: the key-frame branch THROUGH the approval-gate body is pinned " +
    "EXACTLY. Before the gate, every line must be a refusal; inside the gate, `approvedBundle` may " +
    "be set only by the peerAlreadyTrusted (🟢) branch or after the user's `allowed`. If you are " +
    "changing this decision path deliberately, update EXPECTED_WINDOW and say why in the commit.");

  ok(`item 14: the ${codeLines.length} statements from the key-frame branch through the approval gate are pinned exactly`);
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
  assert.deepStrictEqual(codeOnly(liftFunction(src, "requestPeerApproval", assert)), REQUEST_BODY,
    "item 14 / H-1: `requestPeerApproval` is pinned exactly. It must do nothing but park a " +
    "promise, render, and return it — any other statement is a route that can settle the " +
    "approval without a human, which is the whole of F-PROTO-001");

  // `renderPeerApproval` may READ the directory verdict (it draws the ⚠ line),
  // so it cannot be pinned by exact body without pinning the UI copy. What it
  // must never do is SETTLE the promise: only `resolvePeerApproval`, driven by
  // the two buttons, may call `resolve`.
  // Review of the F-P7-A2 fix (M-6): `resolvePeerApproval?.(true)` slipped
  // both the deny-list (`\bresolve\b` stops at the longer name) and the callee
  // scan (`?.` sits between the name and the paren). Normalise optional calls
  // to plain calls before either check, and match any `resolve…` prefix.
  const render = codeOnly(liftFunction(src, "renderPeerApproval", assert)).map((l) => l.replace(/\?\.\s*\(/g, "("));
  for (const l of render) {
    assert.ok(!/\bresolve\w*\b|approvalPending\s*=/.test(l),
      "item 14 / H-1: `renderPeerApproval` may not settle or clear the pending approval — " +
      `only the user's click may do that. Offending line:\n      ${l}`);
  }
  // Phase-7 pentest 2026-09-16, F-P7-A2: the deny-list above is evaded by
  // `els.admitOk.click()`, `decideKnock(true)` and even `resolvePeerApproval(true)`
  // (`\bresolve\b` does not match the longer name). A deny-list cannot win —
  // the contributor picks the spelling — so pin the CALLEES instead: the
  // renderer may call exactly the helpers that draw, and nothing else.
  const callees = new Set();
  for (const l of render) for (const m of l.matchAll(/\b([A-Za-z_$][\w$]*)\s*\(/g)) callees.add(m[1]);
  callees.delete("renderPeerApproval"); // its own definition line
  assert.deepStrictEqual([...callees].sort(), ["describeIdentity", "fingerprintOf", "if"].sort(),
    "item 14 / F-P7-A2: `renderPeerApproval` may call only Identity.fingerprintOf and " +
    "describeIdentity (both draw; neither decides). Any other call — a click(), a dispatchEvent, " +
    `decideKnock, resolvePeerApproval, a timer — is a route past the human. Found: ${[...callees].join(", ")}`);
  ok("item 14: the approval prompt cannot be settled without a human");
}

// --- H-1 second pass: close the laundering channel at its source -------------
// `describeIdentity` computes the unsigned directory comparison. It used to
// RETURN it as `.mismatch` — a decision-grade boolean any path could read — and
// that has been removed: it now writes the prompt DOM and returns nothing, so
// there is no verdict to launder (ROUND-2 F-3). This check is the belt to that
// braces: every textual reference to `describeIdentity(` must be one of the
// three known-good ones (its definition and the two prompt renderers). A NEW
// reference — an arrow alias `const v = (b) => describeIdentity(b)`, a method,
// an indented declaration — is exactly how a return value would be reintroduced
// and read, and it shows up here whatever function encloses it. The previous
// version walked back to a column-0 `function <name>(`, which could not see
// arrow functions or methods and mis-attributed them to the nearest declaration.
{
  const refs = referencesOf(src, "describeIdentity");
  const ALLOWED_DESCRIBE = [
    "function describeIdentity(bundle, whoEl, warnEl, mismatchMsg) {",
    "describeIdentity(k.bundle, els.admitWho, els.admitWarn,",
    "describeIdentity(bundle, els.admitWho, els.admitWarn,",
  ];
  const seen = refs.map((r) => r.text).sort();
  assert.deepStrictEqual(seen, [...ALLOWED_DESCRIBE].sort(),
    "item 14 / H-1: `describeIdentity` may be referenced ONLY by its definition and the two " +
    "prompt renderers (showNextKnock, renderPeerApproval). A new reference is how a directory " +
    "verdict comes back as a value a decision path can read. References found:\n      " +
    refs.map((r) => `app.js:${r.line}  ${r.text}`).join("\n      "));

  // ROUND-3 F-3: `referencesOf` matches `name(` — an immediate call. A VALUE
  // reference (`const alias = describeIdentity;` then `alias(...)`,
  // `foo(describeIdentity)`, `[describeIdentity]`) would escape it. That laundering
  // is defanged today because describeIdentity returns nothing, but do not rely on
  // one control: assert that EVERY occurrence of the bare identifier in the
  // (comment-stripped) source is immediately followed by `(`, so it can only ever
  // be a call, never be captured as a value.
  const bare = new RegExp("\\bdescribeIdentity\\b(.?)", "g");
  for (let m; (m = bare.exec(src)); ) {
    assert.strictEqual(m[1], "(",
      "item 14 / H-1: `describeIdentity` must only ever be CALLED, never taken as a value — a " +
      "value can be aliased and called from a decision path where this allow-list cannot see it. " +
      `Found the identifier followed by ${JSON.stringify(m[1])} at index ${m.index}.`);
  }
  ok("item 14: describeIdentity is only ever called (never aliased) and only from the two renderers");
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
    // The declaration, and the fetch path that fills it. (The trailing comment on
    // the declaration line is stripped away before we get here.)
    ["let expectedPeerBundle = null;", 1],
    ["expectedPeerBundle = null;", 1],
    ["expectedPeerBundle = await account.fetchBundle(API_BASE, contact);", 1],
    ["if (!expectedPeerBundle) {", 1],
    // REFUSALS or DISPLAY only. Each of these can add a prompt or a warning; none
    // of them can skip one. That asymmetry is the whole of item 14 — a directory
    // answer may accuse, never vouch. The `{`-form appears twice: describeIdentity
    // (draws the ⚠ mismatch line — display) and renderVerify's early return
    // (refuses to auto-accept a directory-mismatched key). Both are non-granting.
    ["if (expectedPeerBundle && !sameBundle(expectedPeerBundle, bundle)) return null;", 1],
    ["if (expectedPeerBundle && !sameBundle(expectedPeerBundle, bundle)) {", 2],
    // The one remaining positive mention: a "still verify in person" line printed
    // in the first-contact branch, which grants nothing.
    ["if (expectedPeerBundle) {", 1],
  ]);

  const seen = new Map();
  for (const raw of src.split("\n")) {
    const l = raw.trim();
    if (!l.includes("expectedPeerBundle")) continue;
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

// ===========================================================================
// §C9 — the guest-side half of F-PROTO-001, which nothing anchored.
//
// The debt entry said "no regression test at all for F-PROTO-001". That is not
// quite right and the correction matters: the OWNER side is covered three times
// over — `peerAlreadyTrusted` runs for real above, the key-frame window pins
// `roomRole === "owner" && !admittedSomeone()`, and e2e/hostile-relay/proto001.mjs
// drives POLICY=demote against a live hostile relay. What has NO anchor anywhere
// is the GUEST side, and it is the half the finding is actually about: a relay
// answering `join` with `pending` demotes the creator to guest, so nobody is
// asked to approve and an unapproved identity completes the handshake.
//
// Two gates carry that, both in the `joined` arm of handleMessage:
//
//   * role WRITE-ONCE. A guest told mid-session that it is the owner would start
//     approving people into a room it does not control; an owner told it is a
//     guest stops being asked at all. The relay picks. Neither is recoverable
//     from, so a role that CHANGES is a refusal.
//
//   * `roomRole === "guest" && !wasPending`. The only legitimate route to a guest
//     seat is pending -> knock -> joined:guest, so a seat handed over without
//     ever passing through the queue means no owner approved it. This is what
//     stops the relay telling BOTH parties they are guests — the state in which
//     the owner-side gate above is never reached by anybody.
//
// `app.js` cannot be imported (it touches `document` at module scope) and
// `handleMessage` closes over ~20 module-scope bindings, so this is a source
// anchor: an exact allow-list of the executable lines from the top of the arm
// through the end of the second gate. Everything in that window must be a
// refusal or the write-once assignment; nothing may be added, in any spelling.
{
  const body = liftFunction(src, "handleMessage", assert);
  const armAt = body.indexOf('case "joined": {');
  assert.notStrictEqual(armAt, -1, "F-PROTO-001: handleMessage must still have a `joined` arm");
  // Brace-match to the end of the guest-seat gate, so the window covers the whole
  // of both gates' BODIES (the ROUND-3 F-1 lesson: a window that stops at a gate
  // line leaves the branch it guards pinned by nothing).
  const gateAt = body.indexOf('if (roomRole === "guest" && !wasPending) {', armAt);
  assert.notStrictEqual(gateAt, -1,
    "F-PROTO-001: the guest half of M-2 must still exist — without it the relay can seat us " +
    "without anybody approving us, and the owner-side gate never runs at all");
  let depth = 0, gateEnd = -1;
  for (let k = body.indexOf("{", gateAt); k < body.length; k++) {
    if (body[k] === "{") depth++;
    else if (body[k] === "}" && --depth === 0) { gateEnd = k + 1; break; }
  }
  assert.notStrictEqual(gateEnd, -1, "the guest-seat gate must be brace-balanced");
  const window = codeOnly(body.slice(armAt, gateEnd));

  // The H-1 meta-check: prove the slice is CODE before trusting what it says
  // about the code. A comment-anchored slice collapses here.
  assert.ok(window.length >= 15,
    `H-1: the joined-arm window holds only ${window.length} executable lines — that is a slice ` +
    "over comments, not over code, which is exactly how a previous anchor in this file passed " +
    "while the branch it named was deleted");

  assert.deepStrictEqual(window, [
    'case "joined": {',
    // 2026-09-20 (second review of the M-1 fix): a REPEATED `joined` for the
    // seat we already hold is dropped before anything is narrated — it used to
    // re-narrate the session start, two distinct lines per frame, the one
    // alternation a relay could drive to the transcript cap alone. It runs
    // before the gates because it decides nothing: a changed role still
    // reaches the refusal below, and a first `joined` passes straight through.
    "if (joined && m.role === roomRole) break;",
    "joined = true;",
    // An older relay's bare {"joined"} is refused rather than silently running
    // the first-come-first-served protocol this fix removed.
    'if (m.role !== "owner" && m.role !== "guest") {',
    'addLine("sys", "", "[this relay does not support join approval — refusing]", true);',
    'hint("This relay is running an older protocol without the join-approval step. Update the relay (or your app) before using it.", true);',
    "if (ws) ws.close();",
    "return;",
    "}",
    // Write-once. `roomRole` may be ASSIGNED here only when it is still null;
    // any other value from the relay is a re-cast and a refusal.
    "if (roomRole === null) {",
    "roomRole = m.role;",
    "} else if (roomRole !== m.role) {",
    'addLine("sys", "", "[the relay changed our role mid-session — refusing]", true);',
    'hint("The relay tried to change your role in this room. Disconnecting.", true);',
    "if (ws) ws.close();",
    "return;",
    "}",
    // A seat that never went through the queue.
    'if (roomRole === "guest" && !wasPending) {',
    'addLine("sys", "", "[we were seated in this room without ever asking to be let in — refusing]", true);',
    'hint("This relay put you in the room without the owner approving you. Disconnecting.", true);',
    "if (ws) ws.close();",
    "return;",
    "}",
  ],
    "F-PROTO-001 (guest side): the joined arm through both role gates is pinned EXACTLY. Nothing " +
    "may run before them, and `roomRole` may be written only on the null->role transition. If " +
    "you are changing this deliberately, update this list and say why in the commit.");
  ok("F-PROTO-001: the guest-side role gates in the `joined` arm are pinned exactly");

  // `wasPending` is the whole evidence base for the second gate, so pin its
  // producer too: it may become true in exactly ONE place, the `pending` arm.
  // A second writer — or one moved into the `joined` arm — would make the gate
  // self-satisfying, i.e. decorative, while every line above still matched.
  // ROUND-5 (pentest): this regex was `/\bwasPending\s*=/`, which does not match
  // the COMPOUND assignments `||=`, `&&=`, `??=`. `wasPending ||= true;` inserted
  // at the top of handleMessage manufactures exactly the evidence the guest-side
  // gate consults, and the allow-list never saw it. Match any assignment form,
  // and exclude comparisons (`==`, `===`, `!=`, `>=` …) rather than only `=`.
  const setters = codeOnly(src).filter((l) =>
    /\bwasPending\s*(?:\|\||&&|\?\?)?=(?!=)/.test(l) || /\bwasPending\s*[-+*/%]=/.test(l));
  assert.deepStrictEqual(setters.sort(),
    ["let wasPending = false;", "wasPending = false;", "wasPending = false;", "wasPending = true;"],
    "F-PROTO-001: `wasPending` may be set true exactly once (in the `pending` arm, which is the " +
    "proof we sat in the approval queue) and otherwise only reset to false on connect/disconnect. " +
    "A second `= true` anywhere lets the relay manufacture the evidence the guest gate checks.");

  // ROUND-5 (pentest): the block above claims "`roomRole` may be written only on
  // the null->role transition", but that was asserted ONLY inside the joined-arm
  // window slice — so an assignment placed anywhere else in app.js (e.g.
  // `if (m && m.hint === "promote") roomRole = "owner";` at the top of
  // handleMessage) satisfied the whole test while granting the relay the role it
  // wants. A claim about "only" needs a writer allow-list over the WHOLE file,
  // exactly as `wasPending` has.
  const roleSetters = codeOnly(src).filter((l) =>
    /\broomRole\s*(?:\|\||&&|\?\?)?=(?!=)/.test(l) || /\broomRole\s*[-+*/%]=/.test(l));
  assert.deepStrictEqual(
    roleSetters,
    ["let roomRole = null;", "roomRole = null;", "roomRole = null;",
      'roomRole = "guest";', "roomRole = m.role;"],
    "item 20 / F-PROTO-001: `roomRole` is the relay's word about who owns the room, and the " +
    "guest-side approval gate reads it. Every assignment in app.js must be one of: the " +
    "declaration, the per-connection reset, and the single null->role transition inside the " +
    "`joined` arm. A new writer anywhere else lets the relay re-assert a role mid-session, " +
    `which is M-2's shape. Found: ${roleSetters.join(" | ")}`);
  // Phase-7 pentest 2026-09-16, F-P7-A2: `approvedBundle` is "the whole
  // admission control: it is written only by a click" (app.js:230-232), and
  // its two siblings above had exact writer allow-lists while it had none — it
  // was pinned only INSIDE the key-frame window. A one-line reintroduction of
  // the deleted item-14 route (`if (dirPeer) approvedBundle = dirPeer;`) placed
  // in the `joined` arm after the guest-seat gate passed the entire suite; only
  // the manually-run browser harness caught it. Same rule as the two above: an
  // allow-list over the WHOLE file, every assignment form.
  const approvedSetters = codeOnly(src).filter((l) =>
    /\bapprovedBundle\s*(?:\|\||&&|\?\?)?=(?!=)/.test(l) || /\bapprovedBundle\s*[-+*/%]=/.test(l));
  assert.deepStrictEqual(
    approvedSetters.sort(),
    ["approvedBundle = idbCanon;", "approvedBundle = idbCanon;", "approvedBundle = k.bundle;",
      "approvedBundle = null;", "approvedBundle = null;", "let approvedBundle = null;"].sort(),
    "item 14 / F-P7-A2: `approvedBundle` may be written by exactly six statements — the " +
    "declaration, the two per-connection resets, the owner's click (`k.bundle` in decideKnock) " +
    "and the two guest-side assignments inside the approval gate. Any other writer is a route " +
    `that approves a peer without a human. Found: ${approvedSetters.join(" | ")}`);
  ok("item 14 / F-P7-A2: `approvedBundle` has an exact file-wide writer allow-list");

  // Both role-setting arms are write-once GUARDED; the allow-list above pins who
  // may write, this pins that neither can be re-driven mid-session by a relay
  // that simply repeats the frame.
  const pendingArmSlice = src.slice(src.indexOf('case "pending": {'));
  assert.match(pendingArmSlice.slice(0, 400), /if \(roomRole !== null\) break;[\s\S]{0,80}roomRole = "guest";/,
    "item 20: the `pending` arm must refuse to re-cast a role that is already set — a relay " +
    "that re-sends `pending` to an OWNER would otherwise stop that owner being asked to " +
    "approve anyone, which is M-2's shape");
  ok("item 20: `roomRole` has exactly five writers file-wide, and both setters are write-once");
  const pendingArm = src.indexOf('case "pending": {');
  const trueAt = src.indexOf("wasPending = true", pendingArm);
  const joinedArm = src.indexOf('case "joined": {');
  assert.ok(pendingArm !== -1 && trueAt !== -1 && trueAt < joinedArm,
    "F-PROTO-001: the single `wasPending = true` must live in the `pending` arm — setting it " +
    "anywhere reachable from `joined` would make the gate approve the thing it is checking");
  ok("F-PROTO-001: `wasPending` is written true only where we actually queued");
}

// ===========================================================================
// §C9 — F-PROTO-002: the readyState gate must be the FIRST statement.
//
// Every authentication refusal in app.js ends in a bare `ws.close()`, which
// stops nothing already in flight: `msgChain` is a FIFO promise chain, so frames
// the relay batched with the refused one stayed queued and kept driving the state
// machine after the decision to refuse. Demonstrated end state, after the client
// had printed "[a SECOND identity tried to complete the key exchange — refusing]":
// the channel was still derived, the receive gate still opened, relayed
// ciphertext was still rendered as trusted peer content, and the user was left
// reading "Verified. Messages are end-to-end encrypted."
//
// The property is POSITIONAL, which is why `includes` would not do: `close()`
// moves readyState to CLOSING synchronously, so anything ABOVE this line still
// runs on a socket that is going away. Note there is a SECOND, different
// occurrence of the same line (the re-check after `await requestPeerApproval`,
// pinned in EXPECTED_WINDOW above), so this anchors on position within the
// lifted body rather than on the string appearing somewhere.
//
// Recorded honestly: PROGRESS.md notes the original burst could not be
// reproduced in Chromium, whose own readyState handling already drops it. This
// is defence in depth against a runtime that does not, and against the same
// class arriving through a non-WebSocket transport later.
{
  const body = liftFunction(src, "handleMessage", assert);
  const lines = codeOnly(body);
  assert.ok(/^async function handleMessage\(|^function handleMessage\(/.test(lines[0]),
    "the lift must start at the signature");
  assert.strictEqual(lines[1], "if (!ws || ws.readyState !== WebSocket.OPEN) return;",
    "F-PROTO-002: the readyState gate must be the FIRST statement in handleMessage. A refusal " +
    "ends in ws.close(), which moves readyState to CLOSING synchronously but cancels nothing " +
    "already queued on msgChain — so every line placed above this one runs on a socket that is " +
    "going away, on frames the relay batched with the one we just refused.");
  ok("F-PROTO-002: the readyState gate is the first statement of handleMessage");
}

// ===========================================================================
// §C9 — F-CRYPTO-014: no Web Locks, no OTP.
//
// OTP's entire information-theoretic claim rests on no pad byte ever encrypting
// twice, and ACROSS tabs the pad lock is the only thing enforcing that. The
// fallback used to be a hand-rolled localStorage lease, which is not an exclusion
// primitive: getItem/setItem have no cross-tab atomicity, so two tabs that both
// read "free" both acquired, and a backgrounded tab whose heartbeat was throttled
// lost its lease and kept sending anyway — the same decrypted pad at the same
// sendOffset in two tabs, i.e. a genuine two-time pad plus a reused one-time MAC
// key, recoverable by crib-dragging. The lease is gone; the stance is fail-closed.
//
// `acquirePadLock` closes over exactly two things — the `navigator` global and
// the module constant PAD_LOCK_UNSUPPORTED — so unlike handleMessage it lifts and
// RUNS. The distinction under test is not "it refused" but WHICH refusal: a
// `null` return renders as "this pad is open in another tab", which is a
// different (and wrong) sentence and reopens exactly the ambiguity the sentinel
// was introduced to remove.
{
  const fnSrc = liftFunction(src, "acquirePadLock", assert);
  const make = (PAD_LOCK_UNSUPPORTED) => new Function(
    "PAD_LOCK_UNSUPPORTED", `${fnSrc}; return acquirePadLock;`,
  )(PAD_LOCK_UNSUPPORTED);
  const SENTINEL = "unsupported";
  const prevNav = Object.getOwnPropertyDescriptor(globalThis, "navigator");
  const setNav = (v) => Object.defineProperty(globalThis, "navigator", {
    value: v, configurable: true, writable: true,
  });
  try {
    // (1) An engine with no Web Locks API — Chrome / Android System WebView < 69,
    // Firefox < 96, Safari 15.0-15.3. Must be the SENTINEL.
    setNav({});
    const got = await make(SENTINEL)("pad-1");
    assert.strictEqual(got, SENTINEL,
      "F-CRYPTO-014: with no Web Locks API, acquirePadLock must return the UNSUPPORTED sentinel. " +
      "Returning a release function would be a fabricated lease (the removed localStorage lock, " +
      "which is what let two tabs hold one pad at one offset); returning null would be correct " +
      "in effect but tells the user 'the pad is open in another tab', which is not what happened " +
      "and sends them looking for a tab that does not exist.");
    assert.notStrictEqual(got, null, "...distinct from null, which means 'held elsewhere'");
    assert.notStrictEqual(typeof got, "function", "...and emphatically not a usable lock");

    // (2) With a real-enough Web Locks (`ifAvailable` honoured, exclusive by
    // name, held for the life of the callback promise): the first caller gets a
    // release function, a second caller for the SAME pad gets null.
    const held = new Set();
    setNav({
      locks: {
        request(name, opts, fn) {
          if (opts && opts.ifAvailable && held.has(name)) return Promise.resolve(fn(null));
          held.add(name);
          return Promise.resolve(fn({ name })).then(() => { held.delete(name); });
        },
      },
    });
    const lock = make(SENTINEL);
    const first = await lock("pad-2");
    assert.strictEqual(typeof first, "function",
      "control: the supported path must hand back a release function, or OTP is unusable on " +
      "every current browser and the fail-closed stance becomes a total outage");
    const second = await lock("pad-2");
    assert.strictEqual(second, null,
      "F-CRYPTO-014: a pad already held must come back as null — 'open in another tab', the one " +
      "case where that sentence is the right one");
    const other = await lock("pad-3");
    assert.strictEqual(typeof other, "function", "...and a DIFFERENT pad is unaffected");
    ok("F-CRYPTO-014: acquirePadLock fails closed with a distinct sentinel when Web Locks is absent");
  } finally {
    if (prevNav) Object.defineProperty(globalThis, "navigator", prevNav);
    else delete globalThis.navigator;
  }

  // The call site is the other half: a sentinel nobody acts on is decoration.
  // Pinned as an exact window so the `return` cannot be dropped (which would let
  // OTP proceed with `otpLockRelease` set to the string "unsupported") and so the
  // sentinel branch cannot be reordered below the `!padLock` branch, where the
  // truthy string would fall straight through to a session with no lock at all.
  const site = src.indexOf("const padLock = await acquirePadLock(padId);");
  assert.notStrictEqual(site, -1, "F-CRYPTO-014: the pad lock must still be acquired before a session");
  const after = codeOnly(src.slice(site)).slice(0, 12);
  assert.deepStrictEqual(after.slice(0, 8), [
    "const padLock = await acquirePadLock(padId);",
    "if (padLock === PAD_LOCK_UNSUPPORTED) {",
    'hint("This browser is too old to guarantee a one-time pad is open only once (it has no Web Locks API), and using a pad twice would destroy its security. Use a current browser for one-time-pad mode, or pick another encryption mode.", true);',
    "return;",
    "}",
    "if (!padLock) {",
    // Spelled with the source's own — escape: this is an EXACT line match
    // against app.js, not a rendering of it.
    'hint("This one-time pad is open in another tab or window. Close it there first \\u2014 using a pad twice at once would break its security.", true);',
    "return;",
    ],
    "F-CRYPTO-014: the UNSUPPORTED branch must come FIRST and must RETURN. The sentinel is a " +
    "truthy string, so if the `!padLock` test were reached first — or if this branch merely " +
    "warned and fell through — the session would continue with no pad lock at all and " +
    "`otpLockRelease` set to a string, which is the two-time pad this finding is about.");
  ok("F-CRYPTO-014: the call site refuses on the UNSUPPORTED sentinel before anything else");
}

console.log(`\nAll ${n} peer-approval checks passed.`);
