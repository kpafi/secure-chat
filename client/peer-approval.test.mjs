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
{
  const site = src.slice(src.indexOf("// F-PROTO-001, rebuilt 2026-08-08"));
  const gate = site.indexOf("if (!approvedBundle) {");
  assert.notStrictEqual(gate, -1, "the approval gate must still exist at the handshake call site");

  const between = site.slice(0, gate);
  assert.ok(!/expectedPeerBundle/.test(between),
    "item 14: nothing may consult expectedPeerBundle BEFORE the approval gate — " +
    "that is the call-site shape a partial revert takes, and it skips the prompt");

  const body = site.slice(gate, gate + 400);
  assert.ok(/peerAlreadyTrusted\(idbCanon\)/.test(body),
    "the gate must decide via peerAlreadyTrusted, so this file's checks actually bind");
  assert.ok(!/approvedBundle\s*=\s*idbCanon/.test(between),
    "item 14: approvedBundle must not be assigned before the gate is reached");
  ok("item 14: the call site consults nothing but peerAlreadyTrusted");
}

console.log(`\nAll ${n} peer-approval checks passed.`);
