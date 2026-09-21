// formatDetail: an error response must always become one line of text.
// 2026-09-21 on-device: the old relay's 422 for `mldsa_sig` has an ARRAY in
// `detail`, and `"verify failed: " + detail` rendered "[object Object]".
import assert from "node:assert/strict";
import { formatDetail } from "./account.js";

// the exact body the old relay returned for the new client's login
const fastapi422 = [
  { type: "missing", loc: ["body", "sig"], msg: "Field required", input: {} },
  { type: "extra_forbidden", loc: ["body", "mldsa_sig"], msg: "Extra inputs are not permitted", input: "x" },
];
const out = formatDetail(fastapi422, 422);
assert.equal(out, "Field required (sig); Extra inputs are not permitted (mldsa_sig)");
assert.ok(!out.includes("[object Object]"));

// the relay's own errors are strings and pass through untouched
assert.equal(formatDetail("bad signature", 401), "bad signature");
// an object detail is JSON, not "[object Object]"
assert.equal(formatDetail({ code: "E1", hint: "x" }, 409), '{"code":"E1","hint":"x"}');
// nothing usable ⇒ the status code, as before
assert.equal(formatDetail(null, 502), "502");
assert.equal(formatDetail("", 500), "500");
assert.equal(formatDetail([], 422), "422");
// a malformed array entry does not throw
assert.equal(formatDetail([null, 3, { type: "t" }], 422), "null; 3; t");
console.log("account-error: 8 assertions OK");
