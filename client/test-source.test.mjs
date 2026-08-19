// Self-test for test-source.mjs. Run: node test-source.test.mjs
//
// The source-anchored security tests are only as trustworthy as their notion of
// "what is a comment." Pentest round 2 (2026-08-15) defeated the previous
// prefix-filter three ways; each of those exact shapes is asserted against here,
// so a future regression of the stripper fails loudly instead of silently
// reopening every anchor built on top of it.
import assert from "node:assert";
import { stripComments, codeLines, liftFunction, referencesOf } from "./test-source.mjs";

let n = 0;
const ok = (m) => { n++; console.log("ok", m); };

// --- round-2 shape #1: `/**/ stmt;` is code, not a comment -------------------
{
  const src = "/**/ approvedBundle = idbCanon;";
  const lines = codeLines(stripComments(src));
  assert.deepStrictEqual(lines, ["approvedBundle = idbCanon;"],
    "`/**/ stmt;` must survive stripping as executable code — it was round-2 F-1");
  ok("empty block comment prefix does not hide the statement after it");
}

// --- `/* code */ realCode;` on one line: comment gone, code kept -------------
{
  const src = "a; /* b = 1; */ c = 2;";
  assert.strictEqual(stripComments(src).replace(/\s+/g, " ").trim(), "a; c = 2;",
    "inline block comment must be removed without eating the trailing code");
  ok("inline block comment stripped, surrounding code preserved");
}

// --- `//` and `/*` inside strings are NOT comments ---------------------------
{
  const src = 'x = "http://not-a-comment"; y = "/* also not */"; z = 3;';
  const lines = codeLines(stripComments(src));
  assert.deepStrictEqual(lines, ['x = "http://not-a-comment"; y = "/* also not */"; z = 3;'],
    "comment markers inside string literals must be left intact");
  ok("comment markers inside strings are not treated as comments");
}

// --- template literals with `//` are preserved -------------------------------
{
  const src = "t = `a//b${c}d`; e = 4;";
  const lines = codeLines(stripComments(src));
  assert.deepStrictEqual(lines, ["t = `a//b${c}d`; e = 4;"],
    "// inside a template literal is not a line comment");
  ok("template literal contents preserved");
}

// --- line/block comments are actually removed --------------------------------
{
  const src = [
    "keep1;            // trailing line comment",
    "// whole line comment",
    "/* block",
    "   spanning */ keep2;",
    "keep3;",
  ].join("\n");
  assert.deepStrictEqual(codeLines(stripComments(src)), ["keep1;", "keep2;", "keep3;"],
    "line and block comments must be gone; the code around them kept");
  ok("line and multi-line block comments removed, code retained");
}

// --- newlines/offsets preserved so line numbers do not shift -----------------
{
  const src = "a;\n/* two\n   lines */\nb;";
  const stripped = stripComments(src);
  assert.strictEqual(stripped.split("\n").length, src.split("\n").length,
    "stripping must preserve the line count so referencesOf() line numbers stay true");
  ok("line count preserved across a multi-line block comment");
}

// --- liftFunction: a comment decoy before the real function is ignored -------
{
  const src = [
    "/* function target(a) { return DECOY; } */",
    "function target(x) {",
    "  return REAL;",
    "}",
  ].join("\n");
  const body = liftFunction(stripComments(src), "target", assert);
  assert.match(body, /return REAL;/, "must lift the real body, not the comment decoy");
  assert.doesNotMatch(body, /DECOY/, "the decoy inside a block comment must not be lifted — round-2 F-2");
  ok("liftFunction ignores a block-comment decoy of the same function");
}

// --- liftFunction: two REAL definitions are rejected, not silently first-won -
{
  const src = [
    "function target(x) { return ONE; }",
    "function target(y) { return TWO; }",
  ].join("\n");
  assert.throws(() => liftFunction(stripComments(src), "target", assert), /exactly one/,
    "a second real definition must fail loudly, not be resolved by nearest-match");
  ok("liftFunction rejects a duplicate real definition");
}

// --- referencesOf: an arrow alias is a visible new reference ------------------
{
  const src = [
    "function renderPeerApproval(b) { describeIdentity(b, w, e, m); }",
    "  const dirVerdict = (b) => describeIdentity(b);", // indented, arrow — column-0 walk missed this
    "els.x.onclick = () => describeIdentity(z);",
  ].join("\n");
  const refs = referencesOf(stripComments(src), "describeIdentity");
  assert.strictEqual(refs.length, 3,
    "every textual call site must be reported, including arrow/method/indented ones");
  ok("referencesOf surfaces an arrow-function alias the caller-walk could not see");
}

// --- referencesOf: a reference hidden in a comment is NOT reported ------------
{
  const src = [
    "function renderPeerApproval(b) { describeIdentity(b, w, e, m); }",
    "// describeIdentity(sneaky) — this mention is only a comment",
  ].join("\n");
  const refs = referencesOf(stripComments(src), "describeIdentity");
  assert.strictEqual(refs.length, 1, "a call named only inside a comment must not count as a call site");
  ok("referencesOf ignores a reference that lives only in a comment");
}

console.log(`\nOK test-source (${n} checks)`);
