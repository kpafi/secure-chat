// The Android shell's security settings, pinned at SOURCE level — Package 3,
// F-P7-A5 (ported from phase7-local 1d240d0 + 6604d9e, adapted to master's
// MainActivity.kt / PadFloor.kt / AndroidManifest.xml). Run: node android-source.test.mjs
//
// WHY A SOURCE TEST, AND WHAT IT DOES NOT CLAIM. The properties below are Kotlin
// and XML; the one that ultimately matters for most of them (the OS really does
// blank a secure window, logcat really stays empty) is only observable on a
// device. What a source test catches is DELETION and DRIFT: each control is one
// line in a large file, invisible in normal use, and a refactor that drops,
// weakens or moves it produces no symptom at all. phase7-local measured it: eight
// one-line Kotlin mutants (flag inside `if (BuildConfig.DEBUG)`, `clearFlags`,
// `allowFileAccess = true`, a second bridge, a flipped descriptor, `connect-src *`)
// left its suite green before this file existed. Master had no such test at all.
//
// Two lessons from that line are built in:
//   * COMMENTS ARE STRIPPED FIRST, by a scanner that understands Kotlin's strings
//     (including `"""raw"""` strings and `${…}` templates) and NESTED block
//     comments. A regex over raw source is satisfied by a comment that merely
//     mentions the anchor — which is exactly how master's own marker anchor in
//     otp-rollback.test.mjs stayed green with the descriptor flipped (its first
//     match was a comment).
//   * Anchors are SCOPED to the function that must contain them (a copy in a
//     never-called helper must not count), and the injected document-start
//     script — Kotlin raw string, JavaScript inside — is checked as its own text.
import assert from "node:assert";
import { readFile } from "node:fs/promises";
import { NATIVE_COMMIT_FAILED, NATIVE_INVALID, NATIVE_FULL, FLOOR_MAX } from "./nativefloor.js";

const SRC = new URL("../android/app/src/main/java/org/securechat/app/", import.meta.url);
const activityRaw = await readFile(new URL("MainActivity.kt", SRC), "utf8");
const floorRaw = await readFile(new URL("PadFloor.kt", SRC), "utf8");
const manifest = await readFile(new URL("../android/app/src/main/AndroidManifest.xml", import.meta.url), "utf8");
const padFilesRaw = await readFile(new URL("PadFiles.kt", SRC), "utf8");
const sharePaths = await readFile(new URL("../android/app/src/main/res/xml/pad_share_paths.xml", import.meta.url), "utf8");

// Replace every Kotlin comment with whitespace (newlines kept, so line structure
// survives). Strings — "…" with escapes and ${ } templates, """…""" raw strings,
// 'c' char literals — are copied verbatim, so a `//` inside a string is not a
// comment and a comment cannot be opened from inside one. Kotlin block comments
// NEST (`/* /* */ */`), unlike JavaScript's.
function stripKotlinComments(src) {
  let out = "";
  let i = 0;
  const n = src.length;
  const blank = (s) => s.replace(/[^\n]/g, " ");
  const skipTemplate = (j) => {             // j at the `{` of `${`; returns index after the matching `}`
    let depth = 0;
    for (; j < n; j++) {
      const c = src[j];
      if (c === "{") depth++;
      else if (c === "}") { if (--depth === 0) return j + 1; }
      else if (c === '"') { j = skipString(j) - 1; }
    }
    return n;
  };
  const skipString = (j) => {               // j at the opening quote(s); returns index after the close
    if (src.startsWith('"""', j)) {
      const end = src.indexOf('"""', j + 3);
      if (end < 0) return n;
      let k = end + 3;
      while (src[k] === '"') k++;           // `""""` closes with extra quotes inside the string
      return k;
    }
    for (let k = j + 1; k < n; k++) {
      const c = src[k];
      if (c === "\\") { k++; continue; }
      if (c === "$" && src[k + 1] === "{") { k = skipTemplate(k + 1) - 1; continue; }
      if (c === '"') return k + 1;
      if (c === "\n") return k;             // unterminated: bail
    }
    return n;
  };
  while (i < n) {
    const c = src[i];
    const d = src[i + 1];
    if (c === "/" && d === "/") {
      const end = src.indexOf("\n", i);
      const stop = end < 0 ? n : end;
      out += blank(src.slice(i, stop));
      i = stop;
      continue;
    }
    if (c === "/" && d === "*") {
      let depth = 0;
      let j = i;
      for (; j < n; j++) {
        if (src[j] === "/" && src[j + 1] === "*") { depth++; j++; continue; }
        if (src[j] === "*" && src[j + 1] === "/") { depth--; j++; if (depth === 0) { j++; break; } }
      }
      out += blank(src.slice(i, j));
      i = j;
      continue;
    }
    if (c === '"') {
      const end = skipString(i);
      out += src.slice(i, end);
      i = end;
      continue;
    }
    if (c === "'") {                          // char literal: 'x', '\n', '\u0000'
      const m = /^'(?:\\u[0-9a-fA-F]{4}|\\.|[^'\\])'/.exec(src.slice(i, i + 9));
      if (m) { out += m[0]; i += m[0].length; continue; }
    }
    out += c;
    i++;
  }
  return out;
}
const codeLines = (s) => s.split("\n").map((l) => l.trim()).filter(Boolean);

const activity = stripKotlinComments(activityRaw);
const lines = codeLines(activity);
const floorLines = codeLines(stripKotlinComments(floorRaw));

// The stripper must have run, and must not have eaten code.
assert.ok(lines.length > 150, `the stripped MainActivity.kt holds only ${lines.length} code lines`);
assert.strictEqual(activity.length, activityRaw.length, "the stripper preserves offsets (comments become spaces)");
{
  // Outside the injected script (a Kotlin raw string whose JavaScript comments
  // are string CONTENT and stay), no comment may survive.
  const s = activityRaw.indexOf('val js = """');
  const e = activityRaw.indexOf('"""', s + 12) + 3;
  const outside = codeLines(activity.slice(0, s) + activity.slice(e));
  assert.ok(!outside.some((l) => l.startsWith("//") || l.startsWith("/*") || l.startsWith("*")),
    "every Kotlin comment must be gone — an anchor satisfied by a comment is the H-1 defect");
}
assert.ok(/F-ANDROID-003/.test(activityRaw) && !/F-ANDROID-003/.test(activity),
  "control: the raw file DOES discuss FLAG_SECURE in comments, so stripping is load-bearing");
assert.ok(activity.includes("__SECURE_CHAT_PAD_FLOOR__"), "control: the raw-string script survives stripping (it is code)");

let n = 0;
const ok = (m) => { n++; console.log("OK  " + m); };

// A function body, brace-matched over the stripped lines, from its signature.
// A second definition of the same signature fails (an anchor on an ambiguous
// name could point at a decoy).
function kotlinFun(sigRe, what, from = lines) {
  const hits = from.map((l, i) => (sigRe.test(l) ? i : -1)).filter((i) => i >= 0);
  assert.strictEqual(hits.length, 1, `${what}: expected exactly one definition, found ${hits.length}`);
  let depth = 0;
  let opened = false;
  for (let i = hits[0]; i < from.length; i++) {
    depth += (from[i].match(/\{/g) || []).length;
    depth -= (from[i].match(/\}/g) || []).length;
    if (depth > 0) opened = true;
    if (opened && depth <= 0) return from.slice(hits[0], i + 1);
    // single-expression function (`fun f(): T =` continued on the next line)
    if (!opened && /=\s*$/.test(from[i]) && i > hits[0]) return from.slice(hits[0], i + 2);
  }
  throw new Error(`${what}: body is not brace-balanced`);
}
// The text of a call starting at line `at`, paren-matched (arguments may span lines).
function callAt(body, at, name = "setFlags(") {
  const text = body.slice(at).join("\n");
  const open = text.indexOf(name) + name.length - 1;
  let d = 0;
  for (let i = open; i < text.length; i++) {
    if (text[i] === "(") d++;
    else if (text[i] === ")" && --d === 0) return text.slice(0, i + 1);
  }
  throw new Error("unbalanced call at " + body[at]);
}
// Brace depth of line `at` inside `body` (1 = directly in the function body).
function depthAt(body, at) {
  let depth = 0;
  for (let i = 0; i < at; i++) {
    depth += (body[i].match(/\{/g) || []).length;
    depth -= (body[i].match(/\}/g) || []).length;
  }
  return depth;
}
const secureFlags = (call) => (call.match(/WindowManager\.LayoutParams\.FLAG_SECURE/g) || []).length === 2;

// --- 1. the Activity window, before the first frame (F-ANDROID-003) ------------
{
  const onCreate = kotlinFun(/^override fun onCreate\(/, "onCreate");
  const flagAt = onCreate.findIndex((l) => /^window\.setFlags\($/.test(l));
  assert.notStrictEqual(flagAt, -1, "F-ANDROID-003: onCreate must call window.setFlags(…) itself");
  assert.ok(secureFlags(callAt(onCreate, flagAt)),
    "F-ANDROID-003: setFlags(flags, mask) with FLAG_SECURE as BOTH — setFlags(0, FLAG_SECURE) clears it while naming it");
  const contentAt = onCreate.findIndex((l) => l.startsWith("setContentView("));
  assert.ok(contentAt > flagAt, "F-ANDROID-003: FLAG_SECURE must be set BEFORE setContentView (before the first frame)");
  assert.strictEqual(depthAt(onCreate, flagAt), 1,
    "F-P7-A5: the flag must be unconditional — directly in onCreate's body, not inside if/when/try");
  assert.ok(!/^(if|when|try|else)\b/.test(onCreate[flagAt - 1] || ""), "F-P7-A5: …and not under a brace-less `if (…)`");
  assert.ok(!lines.some((l) => /clearFlags\(/.test(l)), "F-P7-A5: nothing in MainActivity.kt may clear window flags");
  // Fix round 1 (coverage): clearFlags is not the only way to drop the flag.
  // `setFlags(0, FLAG_SECURE)` anywhere (e.g. in loadWithRelay, or on a dialog
  // after show()) clears it, and so does rewriting the window attributes. So:
  // every setFlags call in the file passes FLAG_SECURE as BOTH arguments, there
  // are exactly two (onCreate, secureShow), and nothing touches `attributes`.
  const setFlagCalls = lines.map((l, i) => (/\bsetFlags\(/.test(l) ? i : -1)).filter((i) => i >= 0);
  assert.strictEqual(setFlagCalls.length, 2, `exactly two setFlags calls (onCreate, secureShow), found ${setFlagCalls.length}`);
  for (const i of setFlagCalls) {
    assert.ok(secureFlags(callAt(lines, i)), `every setFlags passes FLAG_SECURE as flags AND mask: ${lines[i]}`);
  }
  assert.ok(!lines.some((l) => /\battributes\b|setAttributes\(|\.flags\s*=/.test(l)),
    "nothing may rewrite window attributes / flags directly (that can clear FLAG_SECURE too)");
  ok("F-ANDROID-003: the Activity sets FLAG_SECURE unconditionally, before setContentView, and never clears it");
}

// --- 2. every dialog window (Package 3: F-ANDROID-003 remainder, F-P7-17) ------
{
  const secureShow = kotlinFun(/^private fun secureShow\(dialog: AlertDialog\) \{$/, "secureShow");
  const flagAt = secureShow.findIndex((l) => /\.setFlags\($/.test(l));
  assert.notStrictEqual(flagAt, -1, "secureShow must set flags on the dialog's window");
  assert.match(secureShow[flagAt], /dialog\.window/, "…on the DIALOG's window (the activity's does not cover it)");
  assert.ok(secureFlags(callAt(secureShow, flagAt)), "secureShow: FLAG_SECURE as both flags and mask");
  assert.strictEqual(depthAt(secureShow, flagAt), 1, "secureShow: the flag is unconditional");
  const showAt = secureShow.findIndex((l) => l === "dialog.show()");
  assert.ok(showAt > flagAt, "secureShow: the flag is set BEFORE show(), so no frame of the dialog is unflagged");
  // The ONLY show() in the file is that one (plus the Toast, which is not a
  // dialog window we control and carries no secret). A dialog shown any other
  // way — AlertDialog.Builder(…).show(), dialog.show() elsewhere — is unflagged.
  const shows = lines.filter((l) => /\.show\(\)/.test(l));
  assert.deepStrictEqual(shows.filter((l) => !/^Toast\.makeText\(.*\)\.show\(\)$/.test(l)), ["dialog.show()"],
    `F-P7-17: every dialog must be shown through secureShow — found: ${JSON.stringify(shows)}`);
  const builders = (activity.match(/AlertDialog\.Builder\(/g) || []).length;
  const secured = (activity.match(/\bsecureShow\(/g) || []).length - 1; // minus its definition
  for (const [sig, what] of [
    [/^override fun onJsAlert\($/, "onJsAlert (alert)"],
    [/^override fun onJsConfirm\($/, "onJsConfirm (confirm: contact names, consent text)"],
    [/^override fun onJsPrompt\($/, "onJsPrompt (passphrases)"],
    [/^private fun refuseToRun\(\) \{$/, "refuseToRun"],
    [/^private fun promptForRelay\(initial: Boolean\) \{$/, "promptForRelay"],
  ]) {
    const body = kotlinFun(sig, what);
    assert.ok(body.some((l) => /^secureShow\(/.test(l)), `F-P7-17: ${what} must show its dialog through secureShow`);
  }
  assert.strictEqual(secured, builders, `every AlertDialog.Builder (${builders}) must reach secureShow (${secured} calls)`);
  // The prompt's masking decision is still the fail-SECURE one (marker OR the
  // substring fallback) — it gates the input type.
  const prompt = kotlinFun(/^override fun onJsPrompt\($/, "onJsPrompt");
  assert.ok(prompt.includes('val secret = marked || message?.contains("passphrase", ignoreCase = true) == true'),
    "F-P7-A5: `secret` keeps its fail-SECURE definition");
  ok("F-P7-17 / F-ANDROID-003: every dialog (alert, confirm, prompt, relay, refusal) sets FLAG_SECURE on its own window before show()");
}

// --- 3. console output does not reach logcat in release (F-P7-23) --------------
{
  const fn = kotlinFun(/^override fun onConsoleMessage\(consoleMessage: ConsoleMessage\?\): Boolean =$/, "onConsoleMessage");
  assert.strictEqual(fn[1], "!BuildConfig.DEBUG || super.onConsoleMessage(consoleMessage)",
    "F-P7-23: onConsoleMessage must return true (handled, not logged) whenever the build is not DEBUG");
  // It must be an override on the WebChromeClient the WebView actually uses.
  const configure = kotlinFun(/^private fun configureWebView\(\) \{$/, "configureWebView");
  assert.ok(configure.some((l) => /^override fun onConsoleMessage\(/.test(l)),
    "F-P7-23: …inside the WebChromeClient installed in configureWebView");
  ok("F-P7-23: web console output is swallowed in release builds");
}

// --- 4. the WebView surface (F-P7-A5) ------------------------------------------
{
  const configure = kotlinFun(/^private fun configureWebView\(\) \{$/, "configureWebView");
  for (const must of ["allowFileAccess = false", "allowContentAccess = false",
    "cacheMode = android.webkit.WebSettings.LOAD_NO_CACHE"]) {
    assert.ok(configure.includes(must), `F-P7-A5: configureWebView must set \`${must}\``);
  }
  assert.ok(!lines.some((l) => /allow(File|Content|UniversalAccessFromFile|FileAccessFromFile)\w* = true/.test(l)),
    "F-P7-A5: no file/content access setting may be switched on anywhere");
  // OTP transfer sheets: a second bridge, the pad-file one (section 9). Still
  // an exact list — a third bridge, or either one under another name, is red.
  const bridges = lines.filter((l) => /addJavascriptInterface\(/.test(l));
  assert.deepStrictEqual(bridges, [
    'wv.addJavascriptInterface(PadFloorBridge(this), "SecureChatPadFloor")',
    'wv.addJavascriptInterface(padFiles, "SecureChatFiles")',
  ], `F-P7-A5: exactly TWO JavaScript bridges, the pad floor and the pad files — found ${JSON.stringify(bridges)}`);
  assert.deepStrictEqual(lines.filter((l) => /setWebContentsDebuggingEnabled\(/.test(l)),
    ["if (BuildConfig.DEBUG) WebView.setWebContentsDebuggingEnabled(true)"],
    "F-P7-A5: remote debugging (localStorage over the devtools socket) only in debug builds");
  const csp = kotlinFun(/^private fun csp\(relay: RelayUrls\?\): String \{$/, "csp");
  assert.deepStrictEqual(csp.slice(1, -1), [
    'val connect = if (relay != null) "${relay.httpOrigin} ${relay.wsOrigin}" else ""',
    'return "default-src \'none\'; " +',
    '"script-src \'self\' \'$importMapHash\'; " +',
    '"style-src \'self\'; " +',
    '"connect-src \'self\' $connect; " +',
    '"img-src \'self\' data:; " +',
    '"worker-src \'none\'; " +',
    '"frame-src \'none\'; " +',
    '"child-src \'none\'; " +',
    '"base-uri \'none\'; " +',
    '"form-action \'none\'; " +',
    '"frame-ancestors \'none\'"',
  ], "F-P7-A5: the CSP body is pinned line for line (connect-src = 'self' + the configured relay only)");
  // Package 6, F-ANDROID-002: the one bridge is exposed to EVERY frame of the
  // WebView — so no frame may load. Explicit, not only via default-src.
  assert.ok(csp.includes('"frame-src \'none\'; " +') && csp.includes('"child-src \'none\'; " +'),
    "F-ANDROID-002: the app CSP must say frame-src 'none' and child-src 'none' explicitly");
  assert.ok(csp.includes('"worker-src \'none\'; " +'), "package 6 fix round: no workers either, as on the web and iOS");
  ok("F-P7-A5: file/content access off, two bridges (floor, pad files), debug-only devtools, CSP pinned");
}

// --- 5. the injected document-start script (H-1 / H-A descriptors) -------------
{
  const start = activityRaw.indexOf('val js = """');
  assert.notStrictEqual(start, -1, "the document-start script is the `val js = \"\"\"…\"\"\"` raw string");
  const bodyStart = start + 'val js = """'.length;
  const bodyEnd = activityRaw.indexOf('"""', bodyStart);
  const script = activityRaw.slice(bodyStart, bodyEnd);
  // Kotlin interpolates `$name` and `${…}` inside a raw string: code could hide
  // there where no Kotlin anchor looks (phase7 review L-7).
  assert.ok(!/\$\{/.test(script), "F-P7-A5: the injected script contains no `${…}` Kotlin interpolation");
  assert.deepStrictEqual([...new Set([...script.matchAll(/\$([A-Za-z_]\w*)/g)].map((m) => m[1]))], ["config"],
    "F-P7-A5: the only Kotlin value interpolated into the script is $config");
  // Each defineProperty CALL, paren-matched — in the script, which is code.
  const calls = [];
  for (const m of script.matchAll(/Object\.defineProperty\s*\(/g)) {
    let d = 0;
    let i = m.index + m[0].length - 1;
    for (; i < script.length; i++) {
      if (script[i] === "(") d++;
      else if (script[i] === ")" && --d === 0) break;
    }
    calls.push(script.slice(m.index, i + 1));
  }
  assert.strictEqual(calls.length, 3, `exactly three defineProperty calls in the injected script, found ${calls.length}`);
  for (const name of ["__SECURE_CHAT_PAD_FLOOR__", "__SECURE_CHAT_NATIVE_FLOOR__", "__SECURE_CHAT_FILES__"]) {
    const call = calls.find((c) => c.includes(`'${name}'`));
    assert.ok(call, `the script must publish ${name} with Object.defineProperty`);
    assert.match(call, /writable:\s*false/, `${name}: non-writable`);
    assert.match(call, /configurable:\s*false/, `${name}: non-configurable (or \`delete\` hides the downgrade, 2026-07-29 H-1)`);
    assert.match(call, /enumerable:\s*false/, `${name}: non-enumerable`);
  }
  const bridgeCall = calls.find((c) => c.includes("'__SECURE_CHAT_PAD_FLOOR__'"));
  assert.match(bridgeCall, /value:\s*Object\.freeze\(\{\s*read:\s*b\.read\.bind\(b\),\s*bump:\s*b\.bump\.bind\(b\)\s*\}\)/,
    "H-A: the published bridge is FROZEN with BOUND methods (a later `b.read = fake` must not be obeyed)");
  // OTP transfer sheets: the pad-file bridge is captured in the SAME
  // document-start script, from the raw bridge global, frozen with BOUND
  // methods — the H-A lesson: a closure calling `f.share(…)` would obey a
  // later `SecureChatFiles.share = fake`.
  const filesCall = calls.find((c) => c.includes("'__SECURE_CHAT_FILES__'"));
  assert.match(filesCall, /value:\s*Object\.freeze\(\{\s*share:\s*f\.share\.bind\(f\),\s*save:\s*f\.save\.bind\(f\)\s*\}\)/,
    "the published pad-file bridge is FROZEN with BOUND share/save");
  assert.match(script, /var f = window\.SecureChatFiles;\s*\n\s*if \(!!f && typeof f\.share === 'function' && typeof f\.save === 'function'\) \{\s*\n\s*Object\.defineProperty\(window, '__SECURE_CHAT_FILES__'/,
    "`f` is the shell's SecureChatFiles, read at document-start, and the capture is guarded on both methods");
  // verifyRelayConfig refuses to run a page where the capture did not land:
  // without it the client falls back to a download the WebView drops AFTER
  // the pad is latched as exported (the bug this bridge fixes).
  const verify = kotlinFun(/^private fun verifyRelayConfig\(\) \{$/, "verifyRelayConfig").join("\n");
  for (const m of ["share", "save"]) {
    assert.ok(verify.includes(`"&& typeof (window.__SECURE_CHAT_FILES__||{}).${m} === 'function'`),
      `verifyRelayConfig must require the frozen __SECURE_CHAT_FILES__.${m}`);
  }
  assert.ok(/relayScript = WebViewCompat\.addDocumentStartJavaScript\(\nbinding\.webview, js, setOf\(appOrigin\),\n\)/
    .test(lines.join("\n")), "the script is injected at document-start for the app origin only");
  ok("H-1/H-A: all three injected globals are non-writable, non-configurable, non-enumerable; both bridges are frozen and bound");
}

// --- 6. PadFloor.kt: every bump answer is honest (Package 3, ROUND-3 F-4, 7b) --
{
  const constOf = (name) => {
    const l = floorLines.find((x) => x.startsWith(`const val ${name} = `));
    assert.ok(l, `PadFloor.kt must define ${name}`);
    return l.slice(`const val ${name} = `.length);
  };
  assert.strictEqual(constOf("COMMIT_FAILED"), `${NATIVE_COMMIT_FAILED}L`, "COMMIT_FAILED matches nativefloor.js");
  assert.strictEqual(constOf("INVALID"), `${NATIVE_INVALID}L`, "INVALID matches nativefloor.js");
  assert.strictEqual(constOf("MAX_VALUE"), "0x" + FLOOR_MAX.toString(16) + "L", "MAX_VALUE matches FLOOR_MAX");
  const bump = kotlinFun(/^fun bump\(ctx: Context, padId: String, value: Long\): Long \{$/, "PadFloor.bump", floorLines);
  assert.deepStrictEqual(bump.slice(1, -1), [
    "if (value < 0 || value > MAX_VALUE) return INVALID",
    "if (padId.isEmpty() || padId.length > MAX_ID_LENGTH) return INVALID",
    "if (commitFailed) return COMMIT_FAILED",
    "val current = read(ctx, padId)",
    "if (current == TAMPERED) return TAMPERED",
    "val next = if (current == ABSENT) value else maxOf(current, value)",
    "if (next == current) return current",
    "if (current == ABSENT && prefs(ctx).all.size >= MAX_RECORDS) return FULL",
    'val committed = prefs(ctx).edit().putString(padId, "$next:${tag(padId, next)}").commit()',
    "if (!committed) {",
    "commitFailed = true",
    "return COMMIT_FAILED",
    "}",
    "return next",
  ], "ROUND-3 F-4 / 7b: PadFloor.bump must refuse out-of-range values, answer COMMIT_FAILED for a commit() that " +
    "returned false (and latch it: the in-memory map is ahead of disk), and return a value only once it is on disk");
  assert.ok(!floorLines.some((l) => /\.apply\(\)/.test(l)), "PadFloor must never use apply() (asynchronous, no result)");
  // Fix round 1 (coverage): pinning bump's body did not pin the latch — a
  // `commitFailed = false` anywhere else (read(), a helper) silently re-arms
  // the false-success path. The latch is declared false once and only ever set true.
  assert.deepStrictEqual(floorLines.filter((l) => /\bcommitFailed\s*=/.test(l)),
    ["private var commitFailed = false", "commitFailed = true"],
    "the COMMIT_FAILED latch is only ever SET (never reset) for the life of the process");
  assert.strictEqual(constOf("FULL"), `${NATIVE_FULL}L`, "FULL matches nativefloor.js");
  assert.strictEqual(constOf("MAX_RECORDS"), "4096", "record cap as on iOS (PadFloor.maxRecords)");
  // Fix round 2 (coverage M6): the id-length bound must admit every id the
  // client uses — `contacts:`/`chats:` + 64 hex (73 chars) is the longest. A
  // smaller value would make every contact/chat save on the device fail.
  const longest = Math.max(("contacts:" + "f".repeat(64)).length, ("identity:" + "f".repeat(64)).length,
    ("exported:" + "f".repeat(32)).length);
  assert.strictEqual(constOf("MAX_ID_LENGTH"), "96", "PadFloor.MAX_ID_LENGTH is pinned");
  assert.ok(96 >= longest, `MAX_ID_LENGTH (96) admits the longest client id (${longest})`);
  ok("ROUND-3 F-4 / 7b: PadFloor.bump reports COMMIT_FAILED (latched) and INVALID; constants match nativefloor.js");
}

// --- 7. the manifest: taskAffinity (F-ANDROID-001) -----------------------------
{
  const noComments = manifest.replace(/<!--[\s\S]*?-->/g, "");
  const activityTag = /<activity\b[^>]*android:name="\.MainActivity"[^>]*>/.exec(noComments);
  assert.ok(activityTag, "the manifest declares MainActivity");
  assert.match(activityTag[0], /android:taskAffinity=""/,
    "F-ANDROID-001: MainActivity must have an empty taskAffinity, so no other app can join its task");
  // Fix round 1 (coverage): allowTaskReparenting="true" (on the activity or the
  // application) lets the activity MOVE into another app's task with a matching
  // affinity — the other half of the task-hijack family.
  assert.doesNotMatch(noComments, /allowTaskReparenting="true"/,
    "F-ANDROID-001: allowTaskReparenting must not be enabled anywhere in the manifest");
  assert.doesNotMatch(activityTag[0], /android:launchMode=/,
    "F-ANDROID-001: launchMode stays the default (a singleTask/singleInstance change needs its own device check)");
  assert.strictEqual((noComments.match(/<activity\b/g) || []).length, 1, "one activity");
  ok("F-ANDROID-001: MainActivity has taskAffinity=\"\" and the default launch mode");
}

// --- 8. the manifest: SafeBrowsing off (package 6, F-P7-24) --------------------
{
  const noComments = manifest.replace(/<!--[\s\S]*?-->/g, "");
  const app = /<application\b[\s\S]*?<\/application>/.exec(noComments);
  assert.ok(app, "the manifest has an <application>");
  // application-level only: a <meta-data> inside <activity> is not the WebView switch
  const appLevel = app[0].replace(/<activity\b[\s\S]*?<\/activity>/g, "");
  const metas = [...appLevel.matchAll(/<meta-data\b[^>]*>/g)].map((m) => m[0]);
  const sb = metas.filter((m) => /android:name="android\.webkit\.WebView\.EnableSafeBrowsing"/.test(m));
  assert.strictEqual(sb.length, 1, `F-P7-24: exactly one EnableSafeBrowsing meta-data inside <application> (found ${sb.length})`);
  assert.match(sb[0], /android:value="false"/, "F-P7-24: SafeBrowsing must be disabled (it sends URL hash prefixes to Google)");
  // The same switch exists at runtime; nothing may turn it back on in code.
  assert.ok(!lines.some((l) => /safeBrowsingEnabled\s*=\s*true|setSafeBrowsingEnabled\(\s*true|startSafeBrowsing\(/.test(l)),
    "F-P7-24: no code path re-enables SafeBrowsing");
  ok("F-P7-24: WebView SafeBrowsing is disabled in the manifest and never re-enabled in code");
}

// --- 9. the pad-file bridge: export (share / save) and import (OTP transfer sheets)
// design/research/reviews/otp-transfer-brief.md 5, 6, 9. The bridge is reachable
// by any script in the page, so what it accepts, what it can write where, and
// what it evaluates back into the page are pinned here; the behaviour is in
// android/app/src/test (PadFilesTest, PadFilesActivityTest).
{
  const pf = stripKotlinComments(padFilesRaw);
  const pfLines = codeLines(pf);
  assert.ok(/ICU/.test(padFilesRaw) && !/ICU/.test(pf), "control: PadFiles.kt comments are stripped");

  // (a) the name: brief 7, exactly; [0-9] (ICU's \d is any Unicode digit), whole-input match.
  assert.ok(pfLines.includes('val NAME = Regex("secure-chat-pad-[0-9]{4}-[0-9]{2}-[0-9]{2}-[0-9]{4}\\\\.json")'),
    "PadFileRules.NAME is exactly secure-chat-pad-YYYY-MM-DD-HHMM.json with ASCII digits");
  assert.ok(pfLines.includes("fun validName(name: String?): Boolean = name != null && NAME.matches(name)"),
    "validName matches the WHOLE name (Regex.matches, not find/containsMatchIn)");
  // (b) the size cap and the text check, in this order (cheap length first).
  assert.ok(pfLines.includes("const val MAX_BYTES = 4 * 1024 * 1024"), "the text cap is 4 MiB, as importPad's");
  assert.deepStrictEqual(kotlinFun(/^fun validText\(text: String\?\): Boolean \{$/, "validText", pfLines).slice(1, -1), [
    "if (text == null || text.length > MAX_BYTES) return false",
    "if (text.toByteArray(Charsets.UTF_8).size > MAX_BYTES) return false",
    "return isEnvelope(text)",
  ], "validText: null / over-length refused, UTF-8 bytes capped, then the WHOLE text must be the envelope");
  // Pentest r1: no regex over the (up to 4 MiB) text — ICU on the device is not
  // the engine the JVM tests run. The only regexes left are on the name and the id.
  assert.deepStrictEqual(pfLines.filter((l) => /\bRegex\(/.test(l)), [
    'val NAME = Regex("secure-chat-pad-[0-9]{4}-[0-9]{2}-[0-9]{2}-[0-9]{4}\\\\.json")',
    'private val ID = Regex("[0-9a-f]{16}")',
  ], "PadFiles.kt: regexes only on the short name and id, never on the file text");
  assert.ok(!/\.toRegex\(|Pattern\.|\.matches\(text\)/.test(pf), "…and no other route to a regex over the text");
  assert.ok(pfLines.includes("fun isEnvelope(text: String): Boolean {"), "the envelope is checked by the linear scanner");
  assert.ok(pfLines.includes("fun valid(name: String?, text: String?): Boolean = validName(name) && validText(text)"),
    "valid() needs both");
  // (c) one request at a time; nothing starts before validation and the slot.
  assert.deepStrictEqual(kotlinFun(/^private fun request\(kind: PadFileRequest\.Kind, name: String\?, text: String\?\): String \{$/,
    "PadFilesBridge.request", pfLines).slice(1, -1), [
    "if (inFlight.get() != null) return BUSY",
    "if (!PadFileRules.valid(name, text)) return INVALID",
    "val id = newId()",
    "if (!inFlight.compareAndSet(null, id)) return BUSY",
    "start(PadFileRequest(kind, id, name!!, text!!))",
    "return id",
  ], "request(): busy / invalid refused before anything starts; the slot is claimed atomically");
  assert.strictEqual(pfLines.filter((l) => l === "@JavascriptInterface").length, 2, "exactly two page-callable methods");
  for (const m of ["share", "save"]) {
    assert.ok(pfLines.includes(`fun ${m}(name: String?, text: String?): String = request(PadFileRequest.Kind.${m.toUpperCase()}, name, text)`),
      `${m}() takes only (name, text) and goes through request()`);
  }
  // (d) the way back into the page: our hex id and a constant outcome, nothing else.
  assert.ok(pfLines.includes('private val ID = Regex("[0-9a-f]{16}")'), "request ids are 16 lowercase hex");
  assert.deepStrictEqual(kotlinFun(/^fun resultScript\(id: String, outcome: String\): String \{$/, "resultScript", pfLines).slice(1, -1), [
    'require(ID.matches(id)) { "request id must be 16 lowercase hex" }',
    'require(outcome in PadFileOutcome.ALL) { "unknown outcome" }',
    'return "window.__SECURE_CHAT_FILES_RESULT__ && " +',
    '"window.__SECURE_CHAT_FILES_RESULT__(\\"$id\\", \\"$outcome\\")"',
  ], "resultScript: a checked id and a checked outcome are the only interpolations");
  assert.ok(pfLines.includes("val ALL = setOf(SHARED, SAVED, CANCELLED, ERROR)"), "four outcomes");
  for (const [k, v] of [["SHARED", "shared"], ["SAVED", "saved"], ["CANCELLED", "cancelled"], ["ERROR", "error"]]) {
    assert.ok(pfLines.includes(`const val ${k} = "${v}"`), `outcome ${k} = "${v}" (the web client's contract)`);
  }
  const evals = lines.filter((l) => /evaluateJavascript\(/.test(l));
  assert.deepStrictEqual(evals, [
    "binding.webview.evaluateJavascript(PadFilesBridge.resultScript(id, outcome), null)",
    "binding.webview.evaluateJavascript(",
  ], `MainActivity evaluates only resultScript and the verifyRelayConfig probe — found ${JSON.stringify(evals)}`);

  // (e) the envelope check and the REAL exportPad() output agree — the two
  // ends are tied through a committed fixture. PadFilesTest (JVM) asserts the
  // native check accepts the fixture; here the real exportPad(), on the
  // largest pad size, must write the same skeleton as the fixture (same
  // literals and key order, same salt/iv lengths, only ct's length differs)
  // and fit the cap. Pentest r1 F7: the iteration count is pinned natively,
  // and it must be otp.js's KDF_ITERS.
  const otpSrc = await readFile(new URL("./otp.js", import.meta.url), "utf8");
  const itersJs = /^const KDF_ITERS = (\d+);$/m.exec(otpSrc);
  assert.ok(itersJs, "otp.js defines `const KDF_ITERS = <n>;`");
  assert.ok(pfLines.includes(`const val KDF_ITERS = ${itersJs[1]}`),
    `PadFileRules.KDF_ITERS must equal otp.js KDF_ITERS (${itersJs[1]})`);
  assert.ok(pfLines.includes('private const val AFTER_SALT = "\\",\\"iters\\":$KDF_ITERS},\\"iv\\":\\""'),
    "the native envelope requires exactly KDF_ITERS");
  const fixture = await readFile(new URL("../android/app/src/test/resources/org/securechat/app/pad-export-fixture.json",
    import.meta.url), "utf8");
  const skeleton = (t) => t.replace(/"(salt|iv|ct)":"([A-Za-z0-9+/]*)(=*)"/g,
    (_, k, b, p) => `"${k}":"<${k === "ct" ? (b.length + p.length) % 4 : b.length}+${p.length}>"`);
  const { exportPad, PAD_SIZES } = await import("./otp.js");
  const biggest = Math.max(...PAD_SIZES.map((p) => p.bytes));
  const bytes = new Uint8Array(biggest);
  for (let o = 0; o < biggest; o += 65536) crypto.getRandomValues(bytes.subarray(o, o + 65536));
  const fileText = await exportPad({ padId: "ab".repeat(16), label: "Chess club \u00e9\u2014\"</script>",
    regionSize: biggest / 2, role: 0, sendOffset: 0, recvHighWater: 0, bytes }, "transfer passphrase");
  assert.strictEqual(skeleton(fileText), skeleton(fixture),
    "the real exportPad() output has the fixture's skeleton (the fixture PadFilesTest accepts natively)");
  assert.strictEqual(skeleton(fixture),
    `{"fmt":"secure-chat-otp-pad","v":1,"kdf":{"salt":"<22+2>","iters":${itersJs[1]}},"iv":"<16+0>","ct":"<0+${/(=*)"}$/.exec(fixture)[1].length}>"}`,
    "control: the skeleton really abstracts only the base64 contents");
  assert.ok(Buffer.byteLength(fileText, "utf8") <= 4 * 1024 * 1024,
    `the largest export (${Buffer.byteLength(fileText)} bytes) fits under MAX_BYTES`);

  // (f) share: fixed type, one extra (our FileProvider URI), a READ grant only,
  // the file in cacheDir/pad-share under the validated name.
  const share = kotlinFun(/^private fun startShare\(req: PadFileRequest\) \{$/, "startShare");
  for (const must of [
    "val root = File(cacheDir, SHARE_DIR)",
    "val dir = File(root, req.id)",
    "val file = File(dir, req.name)",
    'if (file.parentFile != dir || dir.parentFile != root) throw IOException("share file escapes its directory")',
    "val uri = FileProvider.getUriForFile(this, filesAuthority, file)",
    "val send = Intent(Intent.ACTION_SEND).apply {",
    'type = "application/json"',
    "putExtra(Intent.EXTRA_STREAM, uri)",
    "clipData = ClipData.newRawUri(req.name, uri)",
    "addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)",
    "this, 0,",
    "Intent(shareChosenAction).setPackage(packageName).setData(Uri.fromParts(SHARE_SCHEME, req.id, null)),",
    "PendingIntent.FLAG_ONE_SHOT or PendingIntent.FLAG_IMMUTABLE,",
    "shareLauncher.launch(Intent.createChooser(send, getString(R.string.share_pad_title), chosen.intentSender))",
  ]) assert.ok(share.includes(must), `startShare must contain \`${must}\``);
  assert.deepStrictEqual(share.join("\n").match(/putExtra\([^)]*\)/g),
    ["putExtra(Intent.EXTRA_STREAM, uri)"],
    "the share intent carries EXTRA_STREAM only (our request id is the chooser callback's DATA)");
  // Fix round 2 (cold mi-4, pentest R2-7a): a new share ends no earlier share.
  assert.ok(!share.some((l) => /revokeAndDelete|expireShares|listFiles|\.delete\(/.test(l)),
    "startShare must not revoke or delete any earlier share (\"Send it again\" would cut off a send in progress)");
  assert.ok(!lines.some((l) => /FLAG_GRANT_(WRITE|PERSISTABLE|PREFIX)_URI_PERMISSION|takePersistableUriPermission/.test(l)),
    "no write, persistable or prefix URI grant anywhere");
  // Pentest r1 F2 / F5: one immutable, one-shot PendingIntent per share —
  // never the app-wide requestCode-0 / UPDATE_CURRENT one, never mutable.
  assert.ok(!lines.some((l) => /FLAG_MUTABLE|FLAG_UPDATE_CURRENT/.test(l)), "no mutable or updatable PendingIntent");
  // Pentest r2 R2-6: the id is the callback's DATA (part of a PendingIntent's
  // identity), not an extra behind a per-process counter that restarts at 1.
  assert.ok(lines.includes('const val SHARE_SCHEME = "x-secure-chat-share"'), "the chosen-callback data scheme");
  assert.ok(!lines.some((l) => /AtomicInteger|EXTRA_REQUEST/.test(l)), "no requestCode counter, no id extra");
  const receiver = lines.slice(lines.indexOf("private val shareChosenReceiver = object : BroadcastReceiver() {"));
  assert.strictEqual(receiver[3], "if (intent.data?.schemeSpecificPart != p.id) return",
    "the receiver matches the pick by the id in the intent's data");
  // Pentest r1 F1 / F2: the temp files' life. Every share file is revoked
  // before it is deleted, and nothing else deletes one.
  assert.deepStrictEqual(kotlinFun(/^private fun expireShares\(\) \{$/, "expireShares").slice(1, -1), [
    "shareTimer.removeCallbacksAndMessages(null)",
    "val now = System.currentTimeMillis()",
    "val left = File(cacheDir, SHARE_DIR).listFiles()?.filter { entry ->",
    "val expired = now - entry.lastModified() >= SHARE_TTL_MS",
    "if (expired) revokeAndDelete(entry)",
    "!expired",
    "} ?: return",
    "val next = left.minOfOrNull { it.lastModified() } ?: return",
    "val due = (next + SHARE_TTL_MS - now).coerceIn(0, SHARE_TTL_MS)",
    "shareTimer.postDelayed({ expireShares() }, due + 1000)",
  ], "expireShares: only entries SHARE_TTL_MS old go, through revokeAndDelete; the timer re-arms for the next one due");
  assert.deepStrictEqual(lines.filter((l) => /\bexpireShares\(\)|revokeAndDelete\(/.test(l)).sort(), [
    "expireShares()",
    "expireShares()",
    "private fun expireShares() {",
    "if (expired) revokeAndDelete(entry)",
    "shareTimer.postDelayed({ expireShares() }, due + 1000)",
    "private fun revokeAndDelete(entry: File) {",
    "revokeAndDelete(it.dir)",
  ].sort(), "expiry is the only way a chooser's file ends; revokeAndDelete is called by expiry and the \"error\" path only");
  const rad = kotlinFun(/^private fun revokeAndDelete\(entry: File\) \{$/, "revokeAndDelete");
  const revokeAt = rad.findIndex((l) => l.startsWith("revokeUriPermission(FileProvider.getUriForFile(this, filesAuthority, f), Intent.FLAG_GRANT_READ_URI_PERMISSION)"));
  assert.ok(revokeAt > 0 && revokeAt < rad.indexOf("f.delete()"), "revokeAndDelete revokes the file's URI BEFORE deleting it");
  assert.deepStrictEqual(lines.filter((l) => /\.delete\(\)|\.deleteRecursively\(|deleteDocument/.test(l)), ["f.delete()"],
    "the only deletion in MainActivity is revokeAndDelete's (no DocumentsContract.deleteDocument: F3)");
  assert.ok(lines.includes('const val SHARE_DIR = "pad-share"'), "SHARE_DIR is pad-share");
  assert.ok(lines.includes("const val SHARE_TTL_MS = 10 * 60 * 1000L"), "a shared file lives 10 minutes");
  const onCreate = kotlinFun(/^override fun onCreate\(/, "onCreate");
  const clearAt = onCreate.indexOf("expireShares()");
  assert.ok(clearAt > 0 && clearAt < onCreate.indexOf("configureWebView()"),
    "expired pad files are removed at every start, before the page can run — only expired ones (F2), and the rest timed (R2-7b)");
  // Every result is answered at most once, by the bridge's slot (pentest r1 MD).
  const deliver = kotlinFun(/^private fun deliverPadFileResult\(id: String, outcome: String\) \{$/, "deliverPadFileResult");
  assert.strictEqual(deliver[1], "if (!padFiles.finish(id)) return", "deliverPadFileResult answers only the request in flight, once");
  // Fix round 2 (cold mi-4): only "error" (the chooser never ran) ends the
  // file at once; "shared" and "cancelled" both leave it to expiry.
  const errAt = deliver.indexOf("if (outcome == PadFileOutcome.ERROR) {");
  assert.ok(errAt > 0 && deliver[errAt + 1] === "revokeAndDelete(it.dir)" && deliver[errAt + 2] === "} else {" &&
    deliver[errAt + 3] === "expireShares()", "deliverPadFileResult: revoke+delete on \"error\" only, else expiry");
  // Save (pentest r1 F3 / F4).
  const save = kotlinFun(/^private fun onSaveDocument\(uri: Uri\?\) \{$/, "onSaveDocument");
  assert.strictEqual(save[1], "val req = padSave ?: return", "a save result without a request is ignored (nothing deleted)");
  assert.ok(save.includes('val out = contentResolver.openOutputStream(uri, "wt") ?: throw IOException("no output stream")'),
    "the save stream is opened \"wt\" (truncate an overwritten file)");
  const foreignAt = save.indexOf("if (!isForeignDocument(uri)) {");
  assert.ok(foreignAt > 0 && foreignAt < save.findIndex((l) => l.startsWith("thread(")), "the save URI is checked before any write");
  assert.deepStrictEqual(kotlinFun(/^private fun isForeignDocument\(uri: Uri\): Boolean \{$/, "isForeignDocument").slice(1, -1), [
    'if (uri.scheme != "content") return false',
    "val authority = uri.host ?: return false",
    "if (authority == filesAuthority) return false",
    "return packageManager.resolveContentProvider(authority, 0)?.packageName != packageName",
  ], "isForeignDocument: content:// only, never our FileProvider or any provider of ours");
  assert.deepStrictEqual(kotlinFun(/^private fun startPadFileRequest\(req: PadFileRequest\) \{$/, "startPadFileRequest").slice(1, 5), [
    "if (isFinishing || isDestroyed) {",
    "padFiles.finish(req.id)",
    "return",
    "}",
  ], "a request reaching a finishing activity starts nothing and frees the slot (pentest r1 MH)");
  const reg = callAt(onCreate, onCreate.findIndex((l) => l.startsWith("ContextCompat.registerReceiver(")), "registerReceiver(");
  assert.ok(reg.includes("ContextCompat.RECEIVER_NOT_EXPORTED"), "the chooser-callback receiver is NOT exported");
  assert.ok(reg.includes("IntentFilter(shareChosenAction).apply { addDataScheme(SHARE_SCHEME) },"),
    "…and filters on the data scheme the id travels in");
  // Cold critic mi-5: every configuration change this activity can take in
  // place is taken in place; a recreation reloads the page mid-Share/Save.
  const act = /<activity\b[^>]*android:name="\.MainActivity"[^>]*>/.exec(manifest.replace(/<!--[\s\S]*?-->/g, ""));
  assert.deepStrictEqual(/android:configChanges="([^"]*)"/.exec(act[0])[1].split("|").sort(), [
    "orientation", "screenSize", "screenLayout", "smallestScreenSize", "density", "keyboard", "keyboardHidden",
    "navigation", "touchscreen", "uiMode", "locale", "layoutDirection", "fontScale", "colorMode", "mcc", "mnc",
    "grammaticalGender"].sort(), "MainActivity takes every configuration change in place (no page reload mid-Share/Save)");

  // (g) the FileProvider: not exported, one authority, one directory.
  const noComments = manifest.replace(/<!--[\s\S]*?-->/g, "");
  const providers = [...noComments.matchAll(/<provider\b[\s\S]*?<\/provider>/g)].map((m) => m[0]);
  assert.strictEqual(providers.length, 1, "exactly one provider");
  for (const attr of ['android:name="androidx.core.content.FileProvider"', 'android:authorities="${applicationId}.files"',
    'android:exported="false"', 'android:grantUriPermissions="true"', 'android:resource="@xml/pad_share_paths"']) {
    assert.ok(providers[0].includes(attr), `the FileProvider declares ${attr}`);
  }
  const paths = sharePaths.replace(/<!--[\s\S]*?-->/g, "");
  assert.deepStrictEqual([...paths.matchAll(/<([a-z-]+)\b[^>]*\/>/g)].map((m) => m[0]),
    ['<cache-path name="pad-share" path="pad-share/" />'],
    "the FileProvider exposes cacheDir/pad-share/ and NOTHING else (no root-/files-/external-path, no bare cache-path)");
  assert.deepStrictEqual([...noComments.matchAll(/<uses-permission\b[^>]*>/g)].map((m) => m[0]),
    ['<uses-permission android:name="android.permission.INTERNET" />'],
    "no new permission: SAF and a FileProvider grant need none");

  // (h) Import: onShowFileChooser on the WebChromeClient the WebView uses.
  const configure = kotlinFun(/^private fun configureWebView\(\) \{$/, "configureWebView");
  assert.ok(configure.includes("override fun onShowFileChooser(") &&
    configure.includes("): Boolean = showFileChooser(filePathCallback, fileChooserParams)"),
    "the WebChromeClient overrides onShowFileChooser (without it <input type=file> is ignored)");
  const chooser = kotlinFun(/^private fun showFileChooser\($/, "showFileChooser");
  assert.deepStrictEqual(chooser.slice(chooser.indexOf("): Boolean {") + 1, -1), [
    "fileChooserCallback?.onReceiveValue(null)",
    "fileChooserCallback = null",
    "if (params.mode != WebChromeClient.FileChooserParams.MODE_OPEN) {",
    "callback.onReceiveValue(null)",
    "return true",
    "}",
    "fileChooserCallback = callback",
    "try {",
    'openLauncher.launch(arrayOf("*/*"))',
    "} catch (e: ActivityNotFoundException) {",
    "fileChooserCallback = null",
    "callback.onReceiveValue(null)",
    "}",
    "return true",
  ], "showFileChooser: old callback cancelled, open mode only, one document of any type, every path answers");
  assert.deepStrictEqual(kotlinFun(/^private fun onFileChosen\(uri: Uri\?\) \{$/, "onFileChosen").slice(1, -1), [
    "val callback = fileChooserCallback ?: return",
    "fileChooserCallback = null",
    "callback.onReceiveValue(uri?.takeIf { isForeignDocument(it) }?.let { arrayOf(it) })",
  ], "onFileChosen hands the WebView the picked URI (or null) exactly once — only another app's content:// (F4)");
  assert.ok(!lines.some((l) => /EXTRA_ALLOW_MULTIPLE|OpenMultipleDocuments|GetContent|ACTION_GET_CONTENT/.test(l)),
    "one document, through the SAF picker only");

  // (i) both document intents: CATEGORY_OPENABLE and — design critic r2 N-M1 —
  // EXTRA_LOCAL_ONLY, so the save dialog (and the import picker) offer no
  // cloud roots. A hint providers may ignore (README), pinned all the same.
  for (const [launcher, contract] of [
    ["saveLauncher", 'object : ActivityResultContracts.CreateDocument("application/json") {'],
    ["openLauncher", "object : ActivityResultContracts.OpenDocument() {"],
  ]) {
    const at = lines.indexOf(`private val ${launcher} = registerForActivityResult(`);
    assert.ok(at > 0 && lines[at + 1] === contract, `${launcher} uses ${contract}`);
    assert.deepStrictEqual(lines.slice(at + 3, at + 5), [
      "super.createIntent(context, input).addCategory(Intent.CATEGORY_OPENABLE)",
      ".putExtra(Intent.EXTRA_LOCAL_ONLY, true)",
    ], `${launcher}: CATEGORY_OPENABLE and EXTRA_LOCAL_ONLY on the intent it launches`);
  }
  ok("pad files: exact name, 4 MiB, canonical envelope (= real exportPad), one at a time, fixed result script, " +
    "share = read grant on a per-request URI, revoked before delete, 10-minute life; save \"wt\", no deletes; " +
    "document URIs content:// of another app only; save/import local-only + openable; onShowFileChooser answers once");
}

console.log(`\nAll ${n} Android source checks passed.`);
