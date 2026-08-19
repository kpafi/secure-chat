// Shared source-inspection helpers for the source-anchored security tests
// (peer-approval / contacts-anchor / otp-rollback). Not a runtime module — it is
// imported only by *.test.mjs.
//
// WHY THIS EXISTS. Several tests in this project cannot import `app.js` (it
// touches `document` at module scope), so they read it as raw text and assert
// over the source: an allow-list of the exact lines in a security-critical
// window, a lift of a function's real body, a check that a decision-grade symbol
// is only reachable from where it may be. Every one of those assertions is only
// as sound as its notion of "what is code and what is a comment."
//
// The first three rounds of this got that wrong. Each test carried its own copy
// of a *prefix filter* — drop a line if its trim starts with `//`, `*` or `/*`.
// A prefix filter is not a comment stripper, and pentest round 2 walked through
// the gap three different ways:
//   - `/**/ approvedBundle = idbCanon;` — starts with `/*`, so the filter drops
//     it as a comment, yet it is executable JavaScript that runs and assigns.
//   - a `/* ... function peerAlreadyTrusted( ... */` block placed before the real
//     function — `indexOf("function peerAlreadyTrusted(")` over RAW source found
//     the decoy first, so the lift asserted against a comment.
//   - the filter never saw `/* code */ realCode;` on one line: it kept the line
//     but left the comment text in it.
// So this module strips comments *properly*, once, with a scanner that also knows
// about strings and template literals (a `//` inside a string is not a comment,
// and a `/*` inside a string must not open one). Everything downstream —
// liftFunction, the window allow-lists, the caller allow-lists — runs over the
// stripped text. A prefix test must never again be spelled like a comment
// stripper.

// Replace every comment in `src` with equivalent-length whitespace (newlines
// preserved), so byte offsets and line numbers are unchanged and no two tokens
// that were on separate lines get fused. Understands `'...'`, `"..."`,
// `` `...` `` (including `\` escapes), `//` line comments and `/* */` block
// comments. Regex literals are NOT parsed — see the note below; app.js has none
// at the sites these tests inspect, and treating `/` as division-or-comment-only
// is safe for that source.
export function stripComments(src) {
  let out = "";
  let i = 0;
  const n = src.length;
  // states: 0 code, 1 line-comment, 2 block-comment, 3 '..', 4 "..", 5 `..`
  let state = 0;
  while (i < n) {
    const c = src[i];
    const d = i + 1 < n ? src[i + 1] : "";
    if (state === 0) {
      if (c === "/" && d === "/") { state = 1; out += "  "; i += 2; continue; }
      if (c === "/" && d === "*") { state = 2; out += "  "; i += 2; continue; }
      if (c === "'") { state = 3; out += c; i++; continue; }
      if (c === '"') { state = 4; out += c; i++; continue; }
      if (c === "`") { state = 5; out += c; i++; continue; }
      out += c; i++; continue;
    }
    if (state === 1) { // line comment: keep newlines, blank the rest
      if (c === "\n") { state = 0; out += c; i++; continue; }
      out += c === "\t" ? "\t" : " "; i++; continue;
    }
    if (state === 2) { // block comment
      if (c === "*" && d === "/") { state = 0; out += "  "; i += 2; continue; }
      out += c === "\n" ? "\n" : (c === "\t" ? "\t" : " "); i++; continue;
    }
    // string / template states: copy verbatim, honour backslash escapes
    if (c === "\\") { out += c + (d ?? ""); i += 2; continue; }
    if (state === 3 && c === "'") { state = 0; out += c; i++; continue; }
    if (state === 4 && c === '"') { state = 0; out += c; i++; continue; }
    if (state === 5 && c === "`") { state = 0; out += c; i++; continue; }
    out += c; i++;
  }
  return out;
}

// Trimmed, non-empty lines of already-stripped source. Pass the OUTPUT of
// stripComments — never raw source.
export function codeLines(stripped) {
  return stripped.split("\n").map((l) => l.trim()).filter((l) => l.length > 0);
}

// Lift `function <name>(...) { ... }` from stripped source by brace matching,
// asserting there is EXACTLY ONE definition so a decoy copy (in a comment, now
// stripped away, or a real second definition) cannot redirect the anchor.
// `assertFn` is node:assert (passed in so this module has no test-runner dep).
export function liftFunction(stripped, name, assertFn) {
  const needle = `function ${name}(`;
  let from = 0;
  const starts = [];
  for (;;) {
    const at = stripped.indexOf(needle, from);
    if (at === -1) break;
    starts.push(at);
    from = at + needle.length;
  }
  assertFn.strictEqual(starts.length, 1,
    `${name}: expected exactly one \`${needle}\` in app.js source, found ${starts.length}. ` +
    "A second definition (or a decoy) is how a source anchor gets pointed at the wrong body.");
  const start = starts[0];
  let depth = 0;
  let i = stripped.indexOf("{", start);
  for (; i < stripped.length; i++) {
    if (stripped[i] === "{") depth++;
    else if (stripped[i] === "}" && --depth === 0) return stripped.slice(start, i + 1);
  }
  throw new Error(`unbalanced braces in ${name}`);
}

// Every line of stripped source that references `<name>(` as an identifier
// (word-boundary), with 1-based line numbers. Used to allow-list the call sites
// of a decision-grade helper: any NEW reference — an arrow alias, a method, an
// indented declaration — shows up here regardless of how it is spelled, because
// this does not walk back to an enclosing `function` (which round 2 defeated
// with a column-0 regex that could not see arrow functions or methods).
export function referencesOf(stripped, name) {
  const re = new RegExp(`\\b${name}\\s*\\(`);
  const hits = [];
  const lines = stripped.split("\n");
  for (let i = 0; i < lines.length; i++) {
    if (re.test(lines[i])) hits.push({ line: i + 1, text: lines[i].trim() });
  }
  return hits;
}
