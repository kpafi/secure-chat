// Pentest 2026-08-07 F-ANDROID-003 — FLAG_SECURE, pinned at SOURCE level.
// Run: node android-source.test.mjs   (server not required)
//
// WHY A SOURCE TEST, AND WHAT IT DOES NOT CLAIM. §C9 recorded F-ANDROID-003 as
// having no regression test at all. It is Kotlin, there is no JVM or Android
// toolchain in this repo's test path, and the property that ultimately matters —
// that the OS really does blank the recents snapshot and refuse MediaProjection —
// is only observable on a device. That belongs to the on-device verification
// phase, not here.
//
// What IS worth having, and is what §C9 actually asked for, is a control that
// catches DELETION and REORDERING. Both flags are one line each in a large file,
// both are invisible in normal use (nothing on screen changes), and a refactor
// that drops or moves them produces no symptom whatsoever until someone takes a
// screenshot of a passphrase. That is precisely the shape a cheap source anchor
// covers well, so:
//
//   1. the Activity sets FLAG_SECURE BEFORE setContentView — it has to be set
//      before the first frame is drawn, so `onResume` is too late;
//   2. the JS-prompt AlertDialog sets FLAG_SECURE on ITS OWN window (commit
//      5c8dbcf). A Dialog gets a separate Window and FLAG_SECURE marks a
//      SURFACE, not a task, so the Activity's flag does not cover it: a capture
//      taken while the dialog is open blacks out the activity behind it and
//      renders the dialog — passphrase field and all — perfectly legibly. The
//      one window in the app guaranteed to hold a secret was the one window not
//      covered;
//   3. that dialog flag sits inside the `if (secret)` block, matching the
//      masking decision one-for-one: whenever we decide an input must be masked,
//      we also decide it must not be capturable.
//
// COMMENTS ARE STRIPPED FIRST, with the shared scanner. H-1 cost this project
// three rounds because `indexOf` over raw source is satisfied by a comment that
// merely MENTIONS the anchor string — and this file is unusually rich in
// comments about FLAG_SECURE, so a prefix filter here would be green the moment
// the code went away.
import assert from "node:assert";
import { readFile } from "node:fs/promises";
import { stripComments, codeLines } from "./test-source.mjs";

const KT_PATH = new URL("../android/app/src/main/java/org/securechat/app/MainActivity.kt", import.meta.url);
const raw = await readFile(KT_PATH, "utf8");

// `stripComments` is a JAVASCRIPT scanner. Kotlin's line and block comments are
// identical to JavaScript's, so it is correct over ordinary Kotlin — but Kotlin
// RAW STRINGS (`"""..."""`) are not JavaScript, and this file contains one: the
// document-start script injected into the WebView. The scanner reads `"""` as an
// empty string followed by an unterminated one, and everything after that is
// scanned in the wrong state.
//
// Today all three anchors sit above that raw string, so it happens not to matter
// — but "happens not to matter" is exactly the assumption H-1 was built on. So
// the file is SLICED at the raw string, and the slice is asserted to still
// contain every anchor. If the raw string ever moves above them, this fails
// loudly instead of silently scanning garbage.
const rawStringAt = raw.indexOf('"""');
assert.notStrictEqual(rawStringAt, -1,
  "expected MainActivity.kt to still contain the injected document-start script as a Kotlin raw " +
  "string — if it is gone, drop this slice rather than leaving a stale premise in place");
const scannable = raw.slice(0, rawStringAt);
const src = stripComments(scannable);
const lines = codeLines(src);
// Phase-7 (F-P7-A5): the Kotlin AFTER the raw string closes (csp(), the
// WebChromeClient's later handlers) is ordinary Kotlin again and is scanned as a
// second slice; whole-file rules below run over BOTH so a mutant cannot hide
// behind the raw string.
const rawStringEnd = raw.indexOf('"""', rawStringAt + 3);
assert.notStrictEqual(rawStringEnd, -1, "the raw string must close");
const linesAfter = codeLines(stripComments(raw.slice(rawStringEnd + 3)));
const allLines = lines.concat(linesAfter);

// Prove the strip actually removed something and did not remove everything: a
// scanner that returned whitespace for the whole file would make every
// "must appear" assertion below fail loudly (good), but a scanner that returned
// the input unchanged would make them all pass vacuously (bad).
assert.ok(lines.length > 50, `the stripped Kotlin slice holds only ${lines.length} code lines`);
assert.ok(!lines.some((l) => l.startsWith("//")),
  "the comment stripper must actually have run over this file — every anchor below is only as " +
  "sound as that, and a comment mentioning FLAG_SECURE satisfying an anchor is literally the " +
  "H-1 defect this project has already paid for three times");
assert.ok(scannable.includes("// Pentest 2026-08-07 F-ANDROID-003"),
  "control: the raw text DOES contain FLAG_SECURE commentary — which is what makes stripping " +
  "load-bearing rather than decorative");

let n = 0;
const ok = (m) => { n++; console.log("OK  " + m); };

// ROUND-5 (found by BOTH reviewers, independently): every anchor below used to
// search the WHOLE file, so the control was satisfied by an identical line in a
// DIFFERENT function. Both reviewers built the same mutant — delete the real
// `window.setFlags(FLAG_SECURE, FLAG_SECURE)` from onCreate, put a copy in a
// `private fun neverCalledAnywhere()` declared above it — and the suite stayed
// green while the app no longer set the flag at all. That is the same defect as
// the app.js anchor that matched `showIdentityUnlocked` instead of
// `registerAccount`, one language over.
//
// So anchors are SCOPED to the function that must contain them. Kotlin bodies
// are brace-matched over the stripped code lines; a second definition of the
// same signature fails loudly rather than resolving to the first.
function kotlinFun(sigRe, what, from = lines) {
  const start = from.findIndex((l) => sigRe.test(l));
  assert.notStrictEqual(start, -1, `${what}: not found in MainActivity.kt`);
  assert.strictEqual(allLines.filter((l) => sigRe.test(l)).length, 1,
    `${what}: more than one definition — an anchor pointed at it would be ambiguous`);
  let depth = 0;
  let opened = false;
  for (let i = start; i < from.length; i++) {
    depth += (from[i].match(/\{/g) || []).length;
    depth -= (from[i].match(/\}/g) || []).length;
    if (depth > 0) opened = true;
    if (opened && depth <= 0) return from.slice(start, i + 1);
  }
  throw new Error(`${what}: body is not brace-balanced`);
}

// --- 1. the Activity window, before the first frame -------------------------
{
  // Scoped to onCreate's body: a copy in a never-called helper must NOT satisfy
  // this (ROUND-5). `lines` is deliberately NOT consulted here.
  const onCreate = kotlinFun(/^override fun onCreate\(/, "onCreate");
  const flagAt = onCreate.findIndex((l) =>
    /^window\.setFlags\(/.test(l) && l.includes("FLAG_SECURE"));
  assert.notStrictEqual(flagAt, -1,
    "F-ANDROID-003: onCreate must set FLAG_SECURE on its own window (a copy in an uncalled " +
    "helper does not count). Without it the OS " +
    "captures a screenshot of this window every time the app is backgrounded and keeps it for " +
    "the recents switcher — on disk, outside the WebView's storage, untouched by anything the " +
    "web client does at rest. Whatever was on screen (decrypted chat, safety numbers, the " +
    "contact list) is then readable by any component with screen-capture capability, or by " +
    "anyone with brief physical access to an unlocked device.");

  const contentAt = onCreate.findIndex((l) => l.startsWith("setContentView("));
  assert.notStrictEqual(contentAt, -1, "onCreate must still call setContentView");
  assert.ok(flagAt < contentAt,
    `F-ANDROID-003: FLAG_SECURE must be set BEFORE setContentView (found at code line ${flagAt} ` +
    `vs ${contentAt}). The flag governs the surface and has to be in place before the first ` +
    "frame is drawn; setting it afterwards — or in onResume, which is the tempting place — " +
    "leaves a window of frames the OS may capture, and that window includes the very first " +
    "render of the chat.");

  // It must set the flag, not merely mention it: both arguments are FLAG_SECURE
  // (the value and the mask). `setFlags(0, FLAG_SECURE)` CLEARS it and would
  // satisfy a check that only looked for the identifier.
  const flagLine = onCreate[flagAt];
  assert.strictEqual(
    (flagLine.match(/FLAG_SECURE/g) || []).length, 2,
    "F-ANDROID-003: setFlags takes (flags, mask) and both must be FLAG_SECURE — `setFlags(0, " +
    "FLAG_SECURE)` CLEARS the flag while still naming it, so counting the identifier once is " +
    `not enough. Got: ${flagLine}`);
  ok("F-ANDROID-003: the Activity sets FLAG_SECURE before setContentView");

  // Phase-7 pentest 2026-09-16, F-P7-A5. Eight one-line Kotlin mutants kept
  // this file green: the flag wrapped in `if (BuildConfig.DEBUG) { … }` on its
  // own line (release builds then have NO FLAG_SECURE), `clearFlags(FLAG_SECURE)`
  // added after setContentView, and so on. The statement must be UNCONDITIONAL
  // — at the function body's own brace depth, not inside any block — and
  // nothing in the file may clear the flag.
  let depth = 0;
  for (let i = 0; i < flagAt; i++) {
    depth += (onCreate[i].match(/\{/g) || []).length;
    depth -= (onCreate[i].match(/\}/g) || []).length;
  }
  assert.strictEqual(depth, 1,
    "F-P7-A5: window.setFlags(FLAG_SECURE, …) must sit directly in onCreate's body (brace depth 1), " +
    `not inside an if/when/try — found at depth ${depth}. \`if (BuildConfig.DEBUG) { … }\` around it ` +
    "ships release builds with no FLAG_SECURE at all, and nothing on screen changes.");
  assert.ok(!/^(if|when|try|else)\b/.test(onCreate[flagAt - 1] || ""),
    "F-P7-A5: the line before the flag must not be a bare `if (…)` header (a single-statement if body needs no braces)");
  assert.strictEqual(allLines.filter((l) => /clearFlags\(/.test(l) && l.includes("FLAG_SECURE")).length, 0,
    "F-P7-A5: nothing in MainActivity.kt may clear FLAG_SECURE");
  ok("F-P7-A5: the Activity flag is unconditional and never cleared");
}

// --- 2 & 3. the JS-prompt dialog's own window (commit 5c8dbcf) --------------
{
  // Scoped to onJsPrompt (ROUND-5): the reviewers' mutant deleted the real block
  // and left an identical copy in an unused `deadDialogHelper`, which every
  // whole-file check here accepted.
  const onJsPrompt = kotlinFun(/^override fun onJsPrompt\($/, "onJsPrompt");
  const dialogFlagLines = onJsPrompt
    .map((l, i) => [l, i])
    .filter(([l]) => /^dialog\.window\?\.setFlags\(/.test(l));
  assert.strictEqual(dialogFlagLines.length, 1,
    "F-ANDROID-003 (§C10): the JS prompt's AlertDialog must set FLAG_SECURE on its OWN window, " +
    "exactly once. A Dialog has its own Window and FLAG_SECURE marks a SURFACE rather than a " +
    "task, so the Activity's flag does not reach it — a screen capture taken while the prompt " +
    "is open blacks out the activity behind it and renders the dialog, passphrase field " +
    "included, perfectly legibly. The one window guaranteed to hold a secret was the one window " +
    "not covered.");
  const [, dialogFlagAt] = dialogFlagLines[0];

  // The argument pair spans several lines here, so read the call, not the line.
  const callWindow = onJsPrompt.slice(dialogFlagAt, dialogFlagAt + 4).join(" ");
  assert.strictEqual((callWindow.match(/FLAG_SECURE/g) || []).length, 2,
    "F-ANDROID-003: the dialog's setFlags must pass FLAG_SECURE as BOTH the flag and the mask — " +
    `clearing it would otherwise pass an identifier check. Got: ${callWindow}`);

  // Located independently of the flag, so "the flag is after show()" fails with
  // the ORDERING message rather than with a confusing "show() not found".
  const showAt = onJsPrompt.findIndex((l) => l.startsWith("dialog.show("));
  assert.notStrictEqual(showAt, -1, "the prompt dialog must still be shown");
  assert.ok(dialogFlagAt < showAt,
    "F-ANDROID-003: the flag must be set BEFORE dialog.show(). Once the dialog's window is " +
    "added to the window manager its surface exists, and a flag applied after that has already " +
    "lost the race with a capture taken at the moment the prompt appears — which is exactly " +
    "when a passphrase prompt is worth capturing.");

  // The `if (secret)` gate: the flag must track the masking decision, and it
  // must be INSIDE that block rather than merely near it. Bounded by brace
  // depth so a mutant cannot satisfy this by putting an `if (secret)` line
  // anywhere above.
  const secretAt = onJsPrompt.findIndex((l, i) => i < dialogFlagAt && /^if \(secret\) \{$/.test(l));
  assert.notStrictEqual(secretAt, -1,
    "F-ANDROID-003: the dialog flag must be gated on `secret`, matching the masking decision " +
    "immediately above it (including its fail-SECURE fallback): whenever we decide an input " +
    "must be masked, we also decide it must not be capturable");
  let depth = 0;
  let blockEnd = -1;
  for (let i = secretAt; i < onJsPrompt.length; i++) {
    depth += (onJsPrompt[i].match(/\{/g) || []).length;
    depth -= (onJsPrompt[i].match(/\}/g) || []).length;
    if (depth <= 0) { blockEnd = i; break; }
  }
  assert.notStrictEqual(blockEnd, -1, "the `if (secret)` block must be brace-balanced");
  assert.ok(dialogFlagAt > secretAt && dialogFlagAt < blockEnd,
    `F-ANDROID-003: the dialog's setFlags must sit INSIDE the nearest preceding \`if (secret)\` ` +
    `block (flag at ${dialogFlagAt}, block ${secretAt}..${blockEnd}) — a gate that the guarded ` +
    "statement has drifted out of is decoration, and it is the drift, not the deletion, that a " +
    "reviewer will not notice");
  ok("F-ANDROID-003: the JS-prompt dialog sets FLAG_SECURE on its own window, gated on `secret`, before show()");

  // F-P7-A5: `secret` is the gate for BOTH the masking and the dialog flag, so
  // its definition is load-bearing — `val secret = false` turned both off with
  // this file green. Pin the exact fail-SECURE definition: the marker OR the
  // substring fallback, never a constant and never a narrower condition.
  const secretDef = onJsPrompt.find((l) => /^val secret = /.test(l));
  assert.strictEqual(secretDef,
    'val secret = marked || message?.contains("passphrase", ignoreCase = true) == true',
    "F-P7-A5: `secret` must be exactly the marker OR the fail-SECURE substring fallback");
  assert.strictEqual(allLines.filter((l) => /clearFlags\(/.test(l)).length, 0, "no dialog may clear its flags either");
  ok("F-P7-A5: the masking/flag gate `secret` is pinned to its fail-SECURE definition");
}

// --- 4. Phase-7 pentest 2026-09-16, F-P7-A5: the WebView surface --------------
// Green mutants: `allowFileAccess = true`, a second addJavascriptInterface
// exposing the Activity, `connect-src *` in csp(), the marker's defineProperty
// flipped to writable/configurable. These are the settings the whole
// "bundled, audited client" argument rests on; pin each.
{
  const configure = kotlinFun(/^private fun configureWebView\(/, "configureWebView");
  for (const must of ["allowFileAccess = false", "allowContentAccess = false",
    "cacheMode = android.webkit.WebSettings.LOAD_NO_CACHE", "javaScriptEnabled = true", "domStorageEnabled = true"]) {
    assert.ok(configure.includes(must), `F-P7-A5: configureWebView must set \`${must}\``);
  }
  const bridges = allLines.filter((l) => /addJavascriptInterface\(/.test(l));
  assert.deepStrictEqual(bridges, ['wv.addJavascriptInterface(PadFloorBridge(this), "SecureChatPadFloor")'],
    "F-P7-A5: exactly ONE JavaScript bridge, the pad floor, under its one name — a second " +
    `interface is a new attack surface on the whole app. Found: ${bridges.join(" | ")}`);
  const debug = allLines.filter((l) => /setWebContentsDebuggingEnabled\(/.test(l));
  assert.deepStrictEqual(debug, ["if (BuildConfig.DEBUG) WebView.setWebContentsDebuggingEnabled(true)"],
    "F-P7-A5: remote debugging (which exposes localStorage over the devtools socket) only in debug builds");
  const csp = kotlinFun(/^private fun csp\(/, "csp", linesAfter);
  assert.ok(csp.some((l) => l.includes(`"connect-src 'self' $connect; " +`)),
    "F-P7-A5: connect-src is pinned to 'self' plus the configured relay origins, nothing wider");
  assert.ok(!csp.some((l) => /\*/.test(l) && !/^\/\//.test(l)),
    "F-P7-A5: no wildcard source anywhere in the CSP");
  assert.ok(csp.some((l) => l.includes("\"default-src 'none'; \"")), "F-P7-A5: default-src 'none'");
  ok("F-P7-A5: the WebView settings, the single bridge, debug-only devtools and the CSP are pinned");
}

// --- 4b. Review of the F-P7-A5 fix (L-7): the raw string's OWN body ---------
// Kotlin raw strings interpolate `$name` and `${ … }`, so Kotlin can hide
// inside the injected script (`${ run { addJavascriptInterface(...); "" } }`)
// where neither slice above looks. Pin the interpolation surface: no `${`
// blocks at all, and the only simple interpolation is the relay config.
{
  const rawBody = raw.slice(rawStringAt + 3, rawStringEnd);
  assert.ok(!/\$\{/.test(rawBody), "F-P7-A5: the injected script may contain no `${ … }` Kotlin interpolation");
  const names = [...new Set([...rawBody.matchAll(/\$([A-Za-z_]\w*)/g)].map((m) => m[1]))];
  assert.deepStrictEqual(names, ["config"],
    `F-P7-A5: the only Kotlin value interpolated into the injected script is $config — found ${names.join(", ")}`);
  ok("F-P7-A5: the raw string interpolates exactly $config and no Kotlin code");
}

// --- 5. F-P7-A5: both document-start defineProperty descriptors -------------
// The injected script lives in the Kotlin RAW STRING the slice above excludes.
// otp-rollback.test.mjs pins the MARKER's `configurable: false`; nothing pinned
// the BRIDGE's descriptor or either `writable: false`. Extract each
// defineProperty call by paren-matching over the raw string and check both.
{
  const injected = raw.slice(rawStringAt);
  const calls = [];
  const re = /Object\.defineProperty\s*\(/g;
  for (let m = re.exec(injected); m; m = re.exec(injected)) {
    let i = injected.indexOf("(", m.index);
    let d = 0;
    for (; i < injected.length; i++) {
      if (injected[i] === "(") d++;
      else if (injected[i] === ")" && --d === 0) { i++; break; }
    }
    calls.push(injected.slice(m.index, i));
  }
  const want = ["__SECURE_CHAT_PAD_FLOOR__", "__SECURE_CHAT_NATIVE_FLOOR__"];
  for (const name of want) {
    const call = calls.find((c) => c.includes(`'${name}'`));
    assert.ok(call, `F-P7-A5: the document-start script must publish ${name} with Object.defineProperty`);
    assert.match(call, /writable:\s*false/, `${name}: must be non-writable`);
    assert.match(call, /configurable:\s*false/, `${name}: must be non-configurable (or \`delete\` hides the downgrade, 2026-07-29 H-1)`);
    assert.match(call, /enumerable:\s*false/, `${name}: must be non-enumerable`);
  }
  assert.strictEqual(calls.length, 2, `exactly two defineProperty calls in the injected script, found ${calls.length}`);
  ok("F-P7-A5: both injected globals are published non-writable, non-configurable, non-enumerable");
}

// What this file deliberately does NOT assert, stated so nobody mistakes green
// here for a verified device: that Android actually blanks the recents snapshot
// and blocks MediaProjection. That is observable only on hardware and belongs to
// the on-device verification phase. This control catches deletion, reordering
// and drift of the two lines — nothing more, and it should never be cited for
// more than that.
console.log(`\nAll ${n} Android source checks passed.`);
