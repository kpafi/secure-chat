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
// `` `...` `` templates INCLUDING nested `${ ... }` substitutions (which may
// contain further strings/templates/regex), `//` line comments, `/* */` block
// comments, and REGEX literals — so a `/[/*]/` or `/a\/\//` does not spuriously
// open a comment or line-comment and swallow real code after it. Regex-vs-division
// is decided by the standard "what can precede a regex" heuristic on the previous
// meaningful token; a misjudgement would at worst make an exact-match anchor fail
// LOUD, never silently pass. Strings/templates/regex are copied verbatim so the
// code around them is preserved; only comments become whitespace.
//
// Implemented as a stack of frames so `${...}` inside a template can itself hold a
// template, and so on. Each code frame tracks its own brace depth so the `}` that
// closes a substitution is told apart from the `}` of a nested block.
const REGEX_PRECEDING_KEYWORDS = new Set([
  "return", "typeof", "instanceof", "in", "of", "new", "delete", "void", "do",
  "else", "yield", "await", "case", "throw",
]);
const IDENT_CHAR = /[A-Za-z0-9_$]/;

export function stripComments(src) {
  const out = [];
  const n = src.length;
  // Frame types: "code" (braceDepth used for ${} exit), "tmpl" (template literal).
  const stack = [{ type: "code", brace: 0 }];
  let lastMeaningful = ""; // last non-space code char, for regex/division
  let lastWord = "";       // last identifier run in code, for keyword check
  let word = "";

  const top = () => stack[stack.length - 1];
  const blank = (c) => (c === "\n" ? "\n" : c === "\t" ? "\t" : " ");
  const finishWord = () => { if (word) { lastWord = word; word = ""; } };

  let i = 0;
  while (i < n) {
    const c = src[i];
    const d = i + 1 < n ? src[i + 1] : "";
    const frame = top();

    if (frame.type === "code") {
      if (c === "/" && d === "/") { // line comment
        finishWord();
        let j = i + 2;
        out.push("  ");
        while (j < n && src[j] !== "\n") { out.push(blank(src[j])); j++; }
        i = j; continue;
      }
      if (c === "/" && d === "*") { // block comment
        finishWord();
        let j = i + 2;
        out.push("  ");
        while (j < n && !(src[j] === "*" && src[j + 1] === "/")) { out.push(blank(src[j])); j++; }
        out.push("  "); // the closing */
        i = j + 2; continue;
      }
      if (c === "/") { // regex literal, or division?
        // A `/` starts a regex unless the previous meaningful token ENDS a value:
        // an identifier/number (unless it is a regex-preceding keyword like
        // `return`/`typeof`), or a `)` / `]`. Everything else (operators, `(`,
        // `,`, `;`, `=`, `{`, a block-closing `}`, or start-of-input) precedes a
        // regex. A wrong guess only ever makes an exact-match anchor fail loud.
        let isRegex;
        if (lastMeaningful === "") isRegex = true;
        else if (IDENT_CHAR.test(lastMeaningful)) isRegex = REGEX_PRECEDING_KEYWORDS.has(lastWord);
        else if (lastMeaningful === ")" || lastMeaningful === "]") isRegex = false;
        else isRegex = true;
        if (isRegex) {
          finishWord();
          out.push(c); // copy the regex verbatim
          let j = i + 1;
          let inClass = false;
          for (; j < n; j++) {
            const rc = src[j];
            out.push(rc);
            if (rc === "\\") { if (j + 1 < n) { out.push(src[j + 1]); j++; } continue; }
            if (rc === "[") inClass = true;
            else if (rc === "]") inClass = false;
            else if (rc === "/" && !inClass) { j++; break; }
            else if (rc === "\n") break; // unterminated; bail defensively
          }
          while (j < n && /[a-z]/.test(src[j])) { out.push(src[j]); j++; } // flags
          lastMeaningful = "/"; lastWord = "";
          i = j; continue;
        }
        // division
        out.push(c); lastMeaningful = "/"; finishWord(); i++; continue;
      }
      if (c === "'" || c === '"') { // string
        finishWord();
        out.push(c);
        let j = i + 1;
        for (; j < n; j++) {
          out.push(src[j]);
          if (src[j] === "\\") { if (j + 1 < n) { out.push(src[j + 1]); j++; } continue; }
          if (src[j] === c) { j++; break; }
          if (src[j] === "\n") { j++; break; } // unterminated; bail
        }
        lastMeaningful = c; i = j; continue;
      }
      if (c === "`") { // enter template
        finishWord();
        out.push(c); stack.push({ type: "tmpl" }); lastMeaningful = "`"; i++; continue;
      }
      if (c === "{") { frame.brace++; out.push(c); lastMeaningful = "{"; finishWord(); i++; continue; }
      if (c === "}") {
        finishWord();
        if (frame.brace === 0 && stack.length > 1) { // closes a ${ } substitution
          stack.pop(); out.push(c); lastMeaningful = "}"; i++; continue;
        }
        frame.brace--; out.push(c); lastMeaningful = "}"; i++; continue;
      }
      // ordinary code char
      out.push(c);
      if (!/\s/.test(c)) lastMeaningful = c;
      if (IDENT_CHAR.test(c)) word += c; else finishWord();
      i++; continue;
    }

    // template-literal frame
    if (c === "\\") { out.push(c + (d ?? "")); i += 2; continue; }
    if (c === "`") { stack.pop(); out.push(c); lastMeaningful = "`"; word = ""; i++; continue; }
    if (c === "$" && d === "{") { // enter substitution (a code frame)
      out.push("${"); stack.push({ type: "code", brace: 0 }); lastMeaningful = ""; lastWord = ""; word = ""; i += 2; continue;
    }
    out.push(c); i++;
  }
  return out.join("");
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
  // ROUND-4: find the brace that opens the BODY, not merely the first `{` after
  // the name. `function makeCipher(alg, roomId, opts = {}) {` has a `{` inside its
  // PARAMETER LIST, and taking that one made brace-matching close immediately —
  // the "lifted function" was 42 characters of signature, and every assertion over
  // it passed vacuously (an allow-list over its `case` labels found none at all,
  // which is how this was caught). So walk the parameter list to its matching `)`
  // first, then take the next `{`.
  let p = stripped.indexOf("(", start);
  let paren = 0;
  for (; p < stripped.length; p++) {
    if (stripped[p] === "(") paren++;
    else if (stripped[p] === ")" && --paren === 0) { p++; break; }
  }
  let depth = 0;
  let i = stripped.indexOf("{", p);
  assertFn.notStrictEqual(i, -1, `${name}: no function body found after its parameter list`);
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
