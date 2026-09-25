// formatDetail / asError: an error response must always become one line of
// text, must never throw, and must never cost the caller `err.status`.
// 2026-09-21 on-device: the old relay's 422 for `mldsa_sig` has an ARRAY in
// `detail`, and `"verify failed: " + detail` rendered "[object Object]".
// Fix review of that fix (same day): L-1 a deeply nested entry made the array
// branch throw inside JSON.stringify, and the throw escaped asError BEFORE
// `err.status` was set — a hostile 401 body then stopped clearing apiToken;
// L-2 an object `msg` / `loc` entry still rendered "[object Object]";
// I-1 `[""]` rendered "" instead of the status.
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { formatDetail, fetchMail, register, fetchBundle, login, vouch, unvouch, sendMail, fetchVouches } from "./account.js";

let n = 0;
const eq = (a, b) => { assert.equal(a, b); n++; };

// the exact body the old relay returned for the new client's login
const fastapi422 = [
  { type: "missing", loc: ["body", "sig"], msg: "Field required", input: {} },
  { type: "extra_forbidden", loc: ["body", "mldsa_sig"], msg: "Extra inputs are not permitted", input: "x" },
];
const out = formatDetail(fastapi422, 422);
eq(out, "Field required (sig); Extra inputs are not permitted (mldsa_sig)");
assert.ok(!out.includes("[object Object]")); n++;

// the relay's own errors are strings and pass through untouched
eq(formatDetail("bad signature", 401), "bad signature");
// an object detail is JSON, not "[object Object]"
eq(formatDetail({ code: "E1", hint: "x" }, 409), '{"code":"E1","hint":"x"}');
// nothing usable ⇒ the status code
eq(formatDetail(null, 502), "502");
eq(formatDetail("", 500), "500");
eq(formatDetail([], 422), "422");
eq(formatDetail([""], 422), "422");           // I-1
eq(formatDetail(["", "  "], 422), "422");     // I-1
eq(formatDetail("   ", 500), "500");
// a malformed array entry does not throw
eq(formatDetail([null, 3, { type: "t" }], 422), "null; 3; t");

// L-2: relay-chosen shapes — every piece is coerced, nothing is "[object Object]"
for (const [d, want] of [
  [[{ msg: { a: 1 }, loc: ["body", "sig"] }], '{"msg":{"a":1},"loc":["body","sig"]} (sig)'],
  [[{ msg: "bad", loc: ["body", { x: 1 }, "sig"] }], "bad (sig)"],
  [[{ msg: ["a", "b"], type: "t" }], "t"],
  [[{ msg: "", type: "" }], '{"msg":"","type":""}'],
]) {
  const got = formatDetail(d, 422);
  eq(got, want);
  assert.ok(!got.includes("[object Object]")); n++;
}

// L-1: a deeply nested entry must not throw (JSON.parse is iterative,
// JSON.stringify is recursive — the relay can hand us one that parses and
// then blows the stack when stringified)
let deep = {}; for (let i = 0; i < 200000; i++) deep = { a: deep };
let got;
assert.doesNotThrow(() => { got = formatDetail([deep], 401); }); n++;
eq(got, "401");
assert.doesNotThrow(() => { got = formatDetail(deep, 401); }); n++;
eq(got, "401");

// end to end: a hostile body must not cost the caller `err.status` — app.js
// clears apiToken only on `e.status === 401`, and offers "already taken"
// only on `e.status === 409`
// (built as text: JSON.stringify would hit the same stack limit the fix guards)
const D = 200000;
const deepBody = '{"detail":[' + '{"a":'.repeat(D) + "{}" + "}".repeat(D) + "]}";
const srv = createServer((req, res) => {
  const status = req.url.startsWith("/api/register") ? 409 : 401;
  res.writeHead(status, { "content-type": "application/json" });
  res.end(deepBody);
});
await new Promise((r) => srv.listen(0, "127.0.0.1", r));
const base = "http://127.0.0.1:" + srv.address().port;
try {
  const e1 = await fetchMail(base, "sometoken").catch((e) => e);
  eq(e1.status, 401);
  eq(e1.message, "mailbox fetch failed: 401");
  const fakeIdentity = { publicBundle: () => ({ ed: "", mldsa: "" }), sign: async () => "" };
  const e2 = await register(base, fakeIdentity, "alice").catch((e) => e);
  eq(e2.status, 409);
  eq(e2.message, "409");
} finally {
  srv.close();
}

// ---- package 2, item 1: the relay's detail cannot forge a line ---------------
// formatDetail's text is the relay's and is shown in the app's own voice (a
// hint, a status line, the room transcript, which is `white-space: pre-wrap`).
// Printable ASCII only — every other run becomes one space — and at most 200
// characters, for every shape of `detail`.
{
  const forge = "bad signature\n[you let someone in — their key is now pinned]\u202e\u2028\r\t\u0000x";
  for (const d of [forge, [{ msg: forge, loc: ["body", "sig"] }], { detail: forge }]) {
    const got = formatDetail(d, 401);
    assert.ok(/^[\x20-\x7e]*$/.test(got), `item 1: printable ASCII only: ${JSON.stringify(got)}`); n++;
    assert.ok(!/\n|\u202e|\u2028/.test(got)); n++;
  }
  eq(formatDetail("a\nb\u202ec", 401), "a b c");
  const long = formatDetail("A".repeat(5000), 401);
  eq(long.length, 200);
  assert.ok(long.endsWith("...")); n++;
  eq(formatDetail("\n\u202e\n", 418), "418"); // nothing printable left: the status, as before
}

// ---- package 2, item 9 (F-WEB-003): the mailbox answer is bounded -------------
// At most 200 envelopes (the relay's MAX_MAILBOX_PER_RECIPIENT), each at most
// 64 KiB (MAX_ENVELOPE_BYTES), and a body no honest relay could produce is
// refused before JSON.parse.
{
  let body = "";
  const mb = createServer((req, res) => { res.writeHead(200, { "content-type": "application/json" }); res.end(body); });
  await new Promise((r) => mb.listen(0, "127.0.0.1", r));
  const mbBase = "http://127.0.0.1:" + mb.address().port;
  try {
    body = JSON.stringify({ messages: Array.from({ length: 250 }, (_, i) => ({ envelope: "e" + i, created_at: 0 })) });
    const got = await fetchMail(mbBase, "t");
    eq(got.length, 200);
    eq(got[199].envelope, "e199");
    body = JSON.stringify({ messages: [{ envelope: "x".repeat(64 * 1024 + 1) }, { envelope: "ok" }, { envelope: 7 }, null] });
    const f = await fetchMail(mbBase, "t");
    eq(f.length, 1);
    eq(f[0].envelope, "ok");
    body = JSON.stringify({ messages: [{ envelope: "x".repeat(64 * 1024) }] });
    eq((await fetchMail(mbBase, "t")).length, 1); // exactly at the limit is fine
    // Fix round (review of e0e8f30, Medium): the GET is delete-on-read, so a
    // bound an HONEST relay can exceed destroys real mail. The relay accepts
    // 65 536 printable-ASCII characters per envelope, `"` and `\` included,
    // which JSON-escape to two each: 200 such envelopes must all come back.
    body = JSON.stringify({ messages: Array.from({ length: 200 }, (_, i) => ({ envelope: (i % 2 ? "\\" : '"').repeat(64 * 1024), created_at: 0 })) });
    assert.ok(body.length > 200 * (64 * 1024 + 1024), "fixture: the honest worst case is past the first bound"); n++;
    const worst = await fetchMail(mbBase, "t");
    eq(worst.length, 200);
    eq(worst[0].envelope, '"'.repeat(64 * 1024));
    // One over-cap entry beside a real one costs only itself.
    body = JSON.stringify({ messages: [{ envelope: '"'.repeat(64 * 1024 + 1), created_at: 0 }, { envelope: "real-sealed-mail", created_at: 0 }] });
    const mixed = await fetchMail(mbBase, "t");
    eq(mixed.length, 1);
    eq(mixed[0].envelope, "real-sealed-mail");
    // Only a body no honest relay can produce is refused before parsing.
    body = '{"messages":["' + "z".repeat(200 * (2 * 64 * 1024 + 1024) + 1) + '"]}';
    const e = await fetchMail(mbBase, "t").catch((x) => x);
    assert.ok(e instanceof Error && /more than any mailbox can hold/.test(e.message),
      "item 9: a body larger than 200 x (2 x 64 KiB + 1 KiB) is refused before it is parsed"); n++;
    body = '{"messages": [not json';
    const e3 = await fetchMail(mbBase, "t").catch((x) => x);
    assert.ok(e3 instanceof Error && e3.message === "mailbox fetch failed: malformed answer",
      "a parse failure is a fixed sentence, never the relay's bytes echoed by the SyntaxError"); n++;
    body = JSON.stringify({ messages: "nope" });
    const e2 = await fetchMail(mbBase, "t").catch((x) => x);
    assert.ok(e2 instanceof Error && /malformed/.test(e2.message)); n++;
  } finally {
    mb.close();
  }
}

// ---- fix rounds: a 200 answer that is not JSON never echoes the relay's bytes --
// A SyntaxError carries ~20 characters of its source (U+202E / U+2028
// included) into whatever sentence the caller builds. Each success-path parse
// fails with a fixed sentence instead.
{
  const junk = "\u202e{\u2028[verified by you]";
  const js = createServer((req, res) => { res.writeHead(200, { "content-type": "application/json" }); res.end(junk); });
  await new Promise((r) => js.listen(0, "127.0.0.1", r));
  const jb = "http://127.0.0.1:" + js.address().port;
  const clean = (e) => e instanceof Error && !/[\u202e\u2028]|verified by you|Unexpected|JSON/.test(e.message);
  try {
    const fakeId = { publicBundle: () => ({ ed: "", mldsa: "" }), sign: async () => ({ ed: "", mldsa: "" }) };
    const e1 = await fetchBundle(jb, "alice#tok").catch((x) => x);
    eq(e1.message, "the directory returned a malformed answer");
    const e2 = await login(jb, fakeId, "alice").catch((x) => x);
    eq(e2.message, "challenge failed: the directory returned a malformed answer");
    const e3 = await vouch(jb, fakeId, "t", "bob", { ed: "", mldsa: "" }).catch((x) => x);
    eq(e3.message, "vouch failed: the directory returned a malformed answer");
    const e4 = await unvouch(jb, "t", "bob").catch((x) => x);
    eq(e4.message, "unvouch failed: the directory returned a malformed answer");
    const e5 = await register(jb, fakeId, "alice").catch((x) => x);
    eq(e5.message, "registration failed: the directory returned a malformed answer");
    const e6 = await sendMail(jb, "bob#tok", "env").catch((x) => x);
    eq(e6.message, "send failed: the directory returned a malformed answer");
    const e7 = await fetchVouches(jb, "bob#tok").catch((x) => x);
    eq(e7.message, "vouch lookup failed: the directory returned a malformed answer");
    for (const e of [e1, e2, e3, e4, e5, e6, e7]) { assert.ok(clean(e), e && e.message); n++; }
  } finally {
    js.close();
  }
  // login's SECOND parse (the verify answer): a real challenge, then junk.
  let step = 0;
  const vs = createServer((req, res) => {
    res.writeHead(200, { "content-type": "application/json" });
    res.end(step++ === 0 ? JSON.stringify({ challenge: Buffer.alloc(32).toString("base64") }) : junk);
  });
  await new Promise((r) => vs.listen(0, "127.0.0.1", r));
  try {
    const fakeId = { publicBundle: () => ({ ed: "", mldsa: "" }), sign: async () => ({ ed: "", mldsa: "" }) };
    const e = await login("http://127.0.0.1:" + vs.address().port, fakeId, "alice").catch((x) => x);
    eq(e.message, "verify failed: the directory returned a malformed answer");
  } finally {
    vs.close();
  }
}
console.log(`account-error: ${n} assertions OK`);
