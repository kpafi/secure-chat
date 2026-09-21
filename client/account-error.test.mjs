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
import { formatDetail, fetchMail, register } from "./account.js";

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
console.log(`account-error: ${n} assertions OK`);
