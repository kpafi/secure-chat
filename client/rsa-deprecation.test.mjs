// Pentest 2026-08-07 F-CRYPTO-009 — peer-chosen RSA key transport is REMOVED.
//
// The finding is a RESIDUAL that validation cannot close: a counterparty
// offering e = 65537 with n = <small factor> x <large prime> hands the whole
// session to a passive observer, partial public-key validation cannot detect
// it, and raising the trial-division bound does not help. The repo owner's
// decision (2026-08-21) was to drop the mode rather than grow the handshake
// with a third frame. This file replaces rsa-keyvalidation.test.mjs, which
// tested the validator that could not close the finding and has been deleted
// with it.
//
// What is asserted here, and why each half alone would be decorative:
//   1. ENGINE   — makeCipher refuses "RSA" by name, with the reason. Without
//                 this, hiding the radio would be the only thing standing
//                 between a user and the residual (one devtools click away).
//   2. UI       — index.html offers no RSA option, and the mode inventory is
//                 asserted EXACTLY, so neither RSA's return nor an untested new
//                 mode can appear unnoticed.
//   3. PLUMBING — no RSA implementation and no RSA branch survives in crypto.js
//                 or app.js. This project treats dead security code as a hazard:
//                 a leftover `case "RSA":` next to a working class is exactly
//                 the "load-bearing half deleted, decorative half kept" shape
//                 that a prior round flagged.
//   4. WIRE     — an inbound frame tagged alg:"RSA" is refused VISIBLY (a system
//                 line plus a red hint) before the type dispatch, and only the
//                 frame is dropped — never the pump, never a mode switch.
//
// Run: node rsa-deprecation.test.mjs
import assert from "node:assert";
import { readFileSync } from "node:fs";
import { makeCipher, DEPRECATED_ALGS } from "./crypto.js";
import { stripComments, codeLines, liftFunction } from "./test-source.mjs";

const ROOM = "a".repeat(64);
let n = 0;
const ok = (m) => { n++; console.log("OK ", m); };

const read = (f) => readFileSync(new URL(f, import.meta.url), "utf8");
const cryptoSrc = stripComments(read("./crypto.js"));
const appSrc = stripComments(read("./app.js"));
const html = read("./index.html");

// --- 1. ENGINE: makeCipher refuses RSA, with the actual reason ---------------
{
  let err = null;
  try {
    makeCipher("RSA", ROOM);
  } catch (e) {
    err = e;
  }
  assert.ok(err, "makeCipher must REFUSE RSA, not build a cipher");
  const msg = err.message;
  assert.match(msg, /RSA/, "the refusal must name the mode it refused");
  assert.match(msg, /no longer supported/i, "the refusal must say the mode is gone");
  assert.match(msg, /deprecated/i, "the refusal must state the deprecation");
  assert.match(msg, /F-CRYPTO-009/, "the refusal must cite the finding");
  assert.match(msg, /passive observer/i, "the refusal must state the actual risk");
  assert.match(msg, /DHKE/, "the refusal must name a replacement");
  assert.match(msg, /PQKEM/, "the refusal must name the other replacement");
  // The generic default is NOT good enough: a user told only "unsupported"
  // learns nothing, and the same message would appear for a typo.
  assert.doesNotMatch(msg, /^unsupported or unavailable algorithm/,
    "RSA must not fall through to the generic default — the user deserves the reason");
  ok("makeCipher refuses RSA with the deprecation reason, not the generic message");

  // A silent downgrade would be a finding in its own right: nothing may come
  // back from that call.
  assert.strictEqual(typeof err, "object", "the refusal is a throw, never a substituted cipher");
  ok("the refusal is a throw — no fallback cipher is returned");
}

// --- the refusal table is genuinely consumed (it replaced the dead UNAVAILABLE)
{
  assert.ok(Object.isFrozen(DEPRECATED_ALGS), "DEPRECATED_ALGS must be frozen");
  assert.deepStrictEqual(Object.keys(DEPRECATED_ALGS), ["RSA"],
    "RSA is the only deprecated mode today");
  // liftFunction brace-matches from the first `{`, which for makeCipher is the
  // `opts = {}` default parameter — so slice the body explicitly instead.
  const mcAt = cryptoSrc.indexOf("function makeCipher");
  assert.ok(mcAt !== -1, "makeCipher must exist in crypto.js");
  assert.strictEqual(cryptoSrc.indexOf("function makeCipher", mcAt + 1), -1,
    "exactly one makeCipher definition (a second one would redirect this anchor)");
  const body = cryptoSrc.slice(mcAt, cryptoSrc.indexOf("\n}\n", mcAt));
  assert.match(body, /DEPRECATED_ALGS/,
    "makeCipher must READ the table — a refusal table nothing consumes is the dead " +
    "`UNAVAILABLE` hazard all over again");
  assert.doesNotMatch(cryptoSrc, /\bUNAVAILABLE\b/,
    "the dead UNAVAILABLE export (nothing in the tree ever read it, while its comment " +
    "claimed a UI-disable mechanism that did not exist) must be gone");
  // The check must precede the switch, so re-adding a case cannot outrank it.
  assert.ok(body.indexOf("DEPRECATED_ALGS") < body.indexOf("switch"),
    "the deprecation check must run BEFORE the mode switch");
  ok("DEPRECATED_ALGS is live: makeCipher refuses on it, before the switch; UNAVAILABLE is gone");
}

// --- 3. PLUMBING: no RSA implementation, no RSA branch -----------------------
{
  for (const dead of [
    "class Rsa", "new Rsa(", "assertRsaPublicKeyUsable", "RSA_MIN_MODULUS_BITS",
    "RSA_REQUIRED_EXPONENT", "RSA_TRIAL_DIVISION_LIMIT", "RSA_CHAIN_INFO",
    "smallPrimes", "integerNthRoot", "b64UrlToBigInt",
  ]) {
    assert.ok(!cryptoSrc.includes(dead),
      `crypto.js still contains \`${dead}\` — unreachable RSA machinery is the hazard, ` +
      "not the fix (a future contributor is one line from re-enabling the residual)");
  }
  assert.doesNotMatch(cryptoSrc, /case\s+"RSA"/, 'makeCipher must have no `case "RSA":`');

  // ROUND-4 (pentest of this test): everything above is a DENY-LIST, and a
  // deny-list cannot win — the contributor picks the spelling, so a class renamed
  // `RsaTransport` with `case "RSA_v2":` evaded every literal above. This project
  // already learned that on item 14 and answered it the same way: pin the
  // ALLOW-LIST instead. These are the modes makeCipher may construct, exactly; any
  // new case, whatever it is called, fails here and has to be justified.
  const makeCipherSrc = liftFunction(cryptoSrc, "makeCipher", assert);
  const cases = [...makeCipherSrc.matchAll(/case\s+"([^"]*)"/g)].map((m) => m[1]).sort();
  assert.deepStrictEqual(cases, ["AES256", "DHKE", "OTP", "PQKEM"],
    "makeCipher constructs a mode set this test does not know about. Every mode here must be " +
    "exercised by crypto.test.mjs and e2e/all-modes.mjs, and peer-chosen key transport must " +
    `not return by any spelling. Found: ${cases.join(", ")}`);
  ok("crypto.js: the Rsa class, its validator, its constants and its sieve are all gone");
  ok("makeCipher's constructible mode set is pinned by allow-list, not by spelling");

  // app.js mode plumbing must not name RSA anywhere in CODE (comments explaining
  // the removal are fine, and are why this runs over stripped source).
  const appCode = codeLines(appSrc).filter((l) => /RSA/.test(l));
  assert.deepStrictEqual(appCode, [],
    "app.js code still mentions RSA (algNeedsIdentity / ALG_LABELS / syncAlgUI): " +
    appCode.join(" | "));
  ok("app.js mode plumbing lists no RSA (algNeedsIdentity, ALG_LABELS, syncAlgUI)");

  // A missing `:checked` must be a named error, not a TypeError on null: the
  // RSA card's removal is exactly the kind of markup edit that could break it.
  const algValue = liftFunction(appSrc, "algValue", assert);
  assert.match(algValue, /no encryption mode is selected/,
    "algValue must name the failure when nothing is checked");
  ok("algValue fails loudly (named error) rather than throwing TypeError on null");

  // ROUND-4: and the loudness must be WIRED, not merely claimed. `algValue()` is
  // called on connectInner's first line — OUTSIDE its own try — the click handler
  // discards the promise, and the client installs no unhandledrejection handler,
  // so without a catch in connect() the named error reaches the console only and
  // the user sees a dead button. A refusal the user cannot see is not a refusal.
  const connectFn = liftFunction(appSrc, "connect", assert);
  assert.match(connectFn, /catch \(e\)/,
    "connect() must CATCH — connectInner can throw before reaching its own try");
  assert.match(connectFn, /hint\(e\.message, true\)/,
    "...and must surface the message as a red hint, or the refusal is console-only");
  // syncAlgUI runs at module scope; an uncaught throw there aborts the rest of
  // init (identity UI, default room code, invite links) leaving a half-built page.
  const syncFn = liftFunction(appSrc, "syncAlgUI", assert);
  assert.match(syncFn, /try \{[\s\S]*algValue\(\)[\s\S]*catch/,
    "syncAlgUI must not let an algValue throw abort module-scope init silently");
  ok("the refusal is wired: connect() catches and hints; syncAlgUI cannot abort init");
}

// --- 2. UI: index.html offers no RSA, and the inventory is exact -------------
{
  // ROUND-4 (pentest of this test): the character class was [A-Z0-9]+, so a mode
  // whose value contained a hyphen, underscore or lowercase letter was INVISIBLE
  // to the scan and never entered the asserted set — a restored peer-key-transport
  // mode spelled `RSA_v2` or `rsa` passed this "deliberately exact" inventory
  // green. Match ANY value, so an unexpected mode fails the deepStrictEqual rather
  // than slipping through the regex.
  const values = [...html.matchAll(/<input[^>]*name="alg"[^>]*value="([^"]*)"/g)]
    .map((m) => m[1]);
  const valuesAlt = [...html.matchAll(/<input[^>]*value="([^"]*)"[^>]*name="alg"/g)]
    .map((m) => m[1]);
  const all = [...new Set([...values, ...valuesAlt])].sort();
  assert.ok(!all.includes("RSA"), "index.html must offer no selectable RSA option");
  assert.deepStrictEqual(all, ["AES256", "DHKE", "OTP", "PQKEM"],
    "the offered mode set changed — every mode here must be exercised by " +
    "crypto.test.mjs and e2e/all-modes.mjs, so this list is deliberately exact");
  // Whatever remains, exactly one default must stay checked (algValue's invariant).
  const checked = [...html.matchAll(/<input[^>]*name="alg"[^>]*checked/g)];
  assert.strictEqual(checked.length, 1, "exactly one mode card must remain checked by default");
  ok("index.html: no RSA radio, the mode inventory is exactly the four live modes, one default");
}

// --- 4. WIRE: an inbound alg:"RSA" tag is refused visibly --------------------
{
  const body = liftFunction(appSrc, "handleMessage", assert);
  const at = body.indexOf("DEPRECATED_ALGS");
  assert.ok(at !== -1,
    "handleMessage must check the inbound `alg` tag against DEPRECATED_ALGS");
  assert.ok(at < body.indexOf("switch (m.type)"),
    "the deprecated-alg refusal must run before the type dispatch, so no case can act on the frame");
  const window_ = body.slice(at, body.indexOf("switch (m.type)"));
  assert.match(window_, /addLine\("sys"/,
    "the refusal must be VISIBLE in the transcript, never a silent drop");
  assert.match(window_, /hint\([^;]*true\)/s,
    "the refusal must also raise the red hint (a silent downgrade is itself a finding)");
  assert.match(window_, /\breturn\b/,
    "only the frame is dropped — the pump must keep running");
  assert.doesNotMatch(window_, /sessionAlg\s*=/,
    "the peer's claimed mode must never be adopted");
  ok("handleMessage refuses an inbound alg:\"RSA\" frame visibly, before dispatch, without switching modes");
}

console.log(`\nAll RSA deprecation checks passed (${n}).`);


// Phase-7 pentest 2026-09-16, F-P7-7. The refusal above runs BEFORE the type
// dispatch, so `{"alg":"RSA"}` (14 bytes, no room state) reached addLine +
// hint on every frame: 10 000 of them (~140 KB of relay traffic) wedged the
// renderer for minutes and scrolled every genuine warning out of reach. The
// refusal is now said once per connection, and the transcript is bounded.
{
  const appSrc = stripComments(readFileSync(new URL("./app.js", import.meta.url), "utf8"));
  const handle = liftFunction(appSrc, "handleMessage", assert);
  assert.match(handle, /if \(!saidDeprecatedAlg\) \{\s*saidDeprecatedAlg = true;\s*addLine\("sys", "", `\[frame refused — the other end is using \$\{m\.alg\}/,
    "F-P7-7: the deprecated-alg refusal is latched — addLine/hint run only the first time per connection");
  const latchWrites = appSrc.split("\n").map((l) => l.trim()).filter((l) => /^saidDeprecatedAlg = /.test(l)).sort();
  assert.deepStrictEqual(latchWrites, ["saidDeprecatedAlg = false;", "saidDeprecatedAlg = false;", "saidDeprecatedAlg = true;"],
    "F-P7-7: the latch is reset exactly where wasPending is (the two per-connection resets) and set in exactly one place");
  const resets = appSrc.split("\n").map((l) => l.trim());
  for (let i = 0; i < resets.length; i++) {
    if (resets[i] === "wasPending = false;") {
      assert.strictEqual(resets[i + 1], "saidDeprecatedAlg = false;", "the latch reset sits next to each wasPending reset");
    }
  }
  const addLine = liftFunction(appSrc, "addLine", assert);
  assert.match(appSrc, /^const LOG_MAX_LINES = 500;\s*$/m, "F-P7-7: the transcript bound is the literal 500");
  assert.match(addLine, /while \(els\.log\.childElementCount > LOG_MAX_LINES\) \{\s*let victim = null;\s*for \(const c of els\.log\.children\) \{ if \(c\.className !== "sys"\) \{ victim = c; break; \} \}\s*if \(!victim\) for \(const c of els\.log\.children\) \{ if \(!c\.dataset\.keep\) \{ victim = c; break; \} \}\s*if \(!victim\) victim = els\.log\.firstElementChild;\s*els\.log\.removeChild\(victim\);/,
    "F-P7-7 / M-5: eviction takes the oldest NON-system line, then the oldest unkept system line, then the oldest record line — the session's record survives a flood and the transcript never freezes");
  assert.match(addLine, /^function addLine\(kind, who, text, keep = false\)/m, "addLine takes the `keep` marker");
  assert.match(addLine, /if \(keep\) li\.dataset\.keep = "1";/, "...and stamps it on the element the eviction tiers read");
  // The record lines are marked where they are written. Pin the count and the
  // two the behavioural test loses first, so a marker cannot quietly vanish.
  const kept = (appSrc.match(/addLine\("sys", "", [^\n]*, true\);/g) || []);
  assert.ok(kept.some((l) => /joined room — encryption/.test(l)), "the session line is a record line");
  assert.ok(kept.some((l) => /you created this chat/.test(l)), "the owner line is a record line");
  // Third review (L-1): a COUNT binds nothing — a marker moved from a record
  // line onto a relay-repeatable narration kept the count. Bind the SET from
  // the other side: every system line is a record line EXCEPT exactly these
  // four narrations, each of which a relay (or a directory) can repeat, and
  // each of which is either latched or folded by the membership rule.
  const sysCalls = appSrc.split("\n").filter((l) => /addLine\("sys", "", /.test(l));
  const unmarked = sysCalls.filter((l) => !/addLine\("sys", "", .*, true\)/.test(l) && !/(k\.bundle|expectedPeerName)\s*$/.test(l)).map((l) => l.trim()).sort();
  assert.deepStrictEqual(unmarked, [
    'addLine("sys", "", "[message arrived before you verified the safety number — dropped]");',
    'addLine("sys", "", "[the directory is rate-limiting mail fetches — sealed messages are delayed]");',
    'addLine("sys", "", "[undecryptable message — wrong key or tampered]");',
    'addLine("sys", "", `[frame refused — the other end is using ${m.alg}, which this version has removed]`);',
  ], "exactly these four system lines are narrations (unkept); every other system line is part of the record — change this list deliberately");
  assert.strictEqual(sysCalls.length, kept.length + unmarked.length + 2, "fixture: every system addLine is classified (the +2 are the two multi-line ternary calls, both kept)");
  assert.match(appSrc, /addLine\("sys", "", k\.bundle\s*\?[^\n]*\n[^\n]*, true\);/, "the owner-route admission line is a record line");
  assert.match(appSrc, /addLine\("sys", "", expectedPeerName\s*\n[^\n]*\n[^\n]*, true\);/, "the saved-pin match line is a record line");
  // Third review (L-2): the bound is only as good as addLine being the ONLY
  // way onto the transcript. Every DOM write into #log lives in addLine.
  const code = stripComments(appSrc);
  const logWrites = (code.match(/els\.log\.(appendChild|insertBefore|prepend|append|replaceChildren|innerHTML|insertAdjacent\w*)\b/g) || []).length;
  const inAddLine = (stripComments(addLine).match(/els\.log\.(appendChild|insertBefore|prepend|append|replaceChildren|innerHTML|insertAdjacent\w*)\b/g) || []).length;
  assert.ok(inAddLine >= 2 && logWrites === inAddLine, `every write into #log is inside addLine (${logWrites} in app.js, ${inAddLine} in addLine)`);
  // Third review (M-1): the consecutive rule folds only neighbours, so two
  // alternating narrations reached the cap. A narration is folded by
  // MEMBERSHIP: an identical unkept line anywhere in the transcript is counted
  // onto and moved to the end.
  assert.match(addLine, /if \(kind === "sys" && !who && !keep\) \{\s*for \(const c of els\.log\.children\) \{\s*if \(c\.className === "sys" && !c\.dataset\.keep && c\.dataset\.text === text\) \{[\s\S]*?els\.log\.appendChild\(c\);[\s\S]*?return;/,
    "M-1 (third review): an unkept system line already in the transcript is counted onto and moved, never appended again");
  // M-1 (review of 4b9d2c6..a88baa4): the queue-full line was the one unprompted
  // system line a relay could vary (`${n} people were turned away`), which the
  // collapse rule cannot fold. It is a constant string now, latched, and owner-only.
  const turnedAwayArm = handle.slice(handle.indexOf('case "turned-away": {'), handle.indexOf('case "denied": {'));
  assert.ok(turnedAwayArm.length > 0, "fixture: the turned-away arm was found");
  assert.match(turnedAwayArm, /if \(roomRole !== "owner"\) break;/, "M-1/Info-2: only the owner is told");
  assert.match(turnedAwayArm, /if \(!saidTurnedAway\) \{\s*saidTurnedAway = true;\s*addLine\("sys", "", "\[someone was turned away — the waiting queue is full\]", true\);\s*hint\(/,
    "M-1: the queue-full narration is a constant string, said once per connection, and hint() sits INSIDE the latch");
  assert.strictEqual((turnedAwayArm.match(/addLine\(/g) || []).length, 1, "M-1: one addLine in the arm");
  assert.strictEqual((turnedAwayArm.match(/hint\(/g) || []).length, 1, "M-1 (second review L-2): one hint() in the arm, and it is the latched one");
  assert.doesNotMatch(turnedAwayArm, /\$\{/, "M-1: nothing relay-controlled is interpolated into the queue-full line");
  const turnedAwayWrites = appSrc.split("\n").map((l) => l.trim()).filter((l) => /^saidTurnedAway (=|\|\|=|&&=|\?\?=)/.test(l)).sort();
  assert.deepStrictEqual(turnedAwayWrites, ["saidTurnedAway = false;", "saidTurnedAway = false;", "saidTurnedAway = true;"],
    "M-1: the queue-full latch is reset in the two per-connection resets and set in exactly one place");
  // Third review: `denied` was the next unguarded arm (owner never denied;
  // the honest relay closes right after it). Owner-only, latched, kept.
  const deniedArm = handle.slice(handle.indexOf('case "denied": {'), handle.indexOf('case "knock": {'));
  assert.ok(deniedArm.length > 0, "fixture: the denied arm was found");
  assert.match(deniedArm, /if \(roomRole === "owner"\) break;/, "M-1 (third review): an owner is never denied — the frame is dropped");
  assert.match(deniedArm, /if \(!saidDenied\) \{\s*saidDenied = true;\s*addLine\("sys", "", "\[the other person did not let you in\]", true\);\s*hint\(/,
    "M-1 (third review): the denial is said once per connection, is a record line, and hint() sits inside the latch");
  assert.strictEqual((deniedArm.match(/addLine\(/g) || []).length, 1, "one addLine in the denied arm");
  assert.strictEqual((deniedArm.match(/hint\(/g) || []).length, 1, "one hint() in the denied arm");
  const deniedWrites = appSrc.split("\n").map((l) => l.trim()).filter((l) => /^saidDenied (=|\|\|=|&&=|\?\?=)/.test(l)).sort();
  assert.deepStrictEqual(deniedWrites, ["saidDenied = false;", "saidDenied = false;", "saidDenied = true;"],
    "the denial latch is reset in the two per-connection resets and set in exactly one place");
  // Second review of the M-1 fix: a repeated `joined` re-narrated the session
  // start (two distinct lines per frame), the one alternation a relay could
  // drive to the cap alone. The seat is write-once; a repeat is dropped.
  assert.match(handle, /case "joined": \{[\s\S]*?if \(joined && m\.role === roomRole\) break;\s*joined = true;/,
    "a repeated `joined` for the seat we already hold is dropped before anything is narrated");
  assert.match(addLine, /last\.className === "sys" && last\.dataset\.text === text/,
    "M-5: a system line identical to the previous one is counted onto it, not appended");
  assert.ok(addLine.indexOf("LOG_MAX_LINES") < addLine.lastIndexOf("scrollTop"), "...eviction happens before the layout-forcing scroll");
  console.log("OK  F-P7-7: the deprecated-alg refusal is said once per connection and the transcript is bounded");
}
