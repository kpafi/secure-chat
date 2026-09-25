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
  const bridges = lines.filter((l) => /addJavascriptInterface\(/.test(l));
  assert.deepStrictEqual(bridges, ['wv.addJavascriptInterface(PadFloorBridge(this), "SecureChatPadFloor")'],
    `F-P7-A5: exactly ONE JavaScript bridge, the pad floor — found ${JSON.stringify(bridges)}`);
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
    '"base-uri \'none\'; " +',
    '"form-action \'none\'; " +',
    '"frame-ancestors \'none\'"',
  ], "F-P7-A5: the CSP body is pinned line for line (connect-src = 'self' + the configured relay only)");
  ok("F-P7-A5: file/content access off, one bridge, debug-only devtools, CSP pinned");
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
  assert.strictEqual(calls.length, 2, `exactly two defineProperty calls in the injected script, found ${calls.length}`);
  for (const name of ["__SECURE_CHAT_PAD_FLOOR__", "__SECURE_CHAT_NATIVE_FLOOR__"]) {
    const call = calls.find((c) => c.includes(`'${name}'`));
    assert.ok(call, `the script must publish ${name} with Object.defineProperty`);
    assert.match(call, /writable:\s*false/, `${name}: non-writable`);
    assert.match(call, /configurable:\s*false/, `${name}: non-configurable (or \`delete\` hides the downgrade, 2026-07-29 H-1)`);
    assert.match(call, /enumerable:\s*false/, `${name}: non-enumerable`);
  }
  const bridgeCall = calls.find((c) => c.includes("'__SECURE_CHAT_PAD_FLOOR__'"));
  assert.match(bridgeCall, /value:\s*Object\.freeze\(\{\s*read:\s*b\.read\.bind\(b\),\s*bump:\s*b\.bump\.bind\(b\)\s*\}\)/,
    "H-A: the published bridge is FROZEN with BOUND methods (a later `b.read = fake` must not be obeyed)");
  assert.ok(/relayScript = WebViewCompat\.addDocumentStartJavaScript\(\nbinding\.webview, js, setOf\(appOrigin\),\n\)/
    .test(lines.join("\n")), "the script is injected at document-start for the app origin only");
  ok("H-1/H-A: both injected globals are non-writable, non-configurable, non-enumerable; the bridge is frozen and bound");
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
  const longest = Math.max(("contacts:" + "f".repeat(64)).length, ("exported:" + "f".repeat(32)).length);
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

console.log(`\nAll ${n} Android source checks passed.`);
