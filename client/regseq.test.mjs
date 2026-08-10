// Pentest 2026-08-08, item 18 — the registration counter must stay bounded.
// Run: node regseq.test.mjs   (server not required; `fetch` is stubbed)
//
// `sc.regseq.v1` is plaintext and was unbounded, so one localStorage write set
// it to `2**53 - 2`; the next registration then signed `2**53 - 1`, EXACTLY the
// server's Pydantic cap, which is accepted and stored. From then on the
// account's published encryption keys are frozen forever — anything higher is a
// 422 from the bound, anything at or below is a 409 as a replay, and the
// one-shot recovery (`Math.max(seq, Date.now())`) is six orders of magnitude
// below the poisoned value and only fires on 409 anyway.
//
// Reproduced end to end against the real endpoint before the fix:
//   seq=1                → 200
//   seq=9007199254740991 → 200 "updated"       <- the poisoning succeeds
//   seq=9007199254740992 → 422 less_than_equal
//   seq=1760000000000    → 409 not newer
//   seq=9007199254740991 → 409 not newer       <- frozen
//
// These tests drive the REAL `register()` with a stubbed `fetch`, so they cover
// the counter that is actually signed and sent, not a reimplementation of it.
import assert from "node:assert";

const LS_REG_SEQ = "sc.regseq.v1";
const SERVER_CAP = 2 ** 53 - 1;   // accounts.py: Field(..., le=2**53 - 1)

function fakeLocalStorage() {
  const m = new Map();
  return {
    getItem: (k) => (m.has(k) ? m.get(k) : null),
    setItem: (k, v) => m.set(k, String(v)),
    removeItem: (k) => m.delete(k),
  };
}
globalThis.localStorage = fakeLocalStorage();

const identity = {
  publicBundle: () => ({ ed: "RUQ", mldsa: "TUw", ecdh: "RUM", mlkem: "S00" }),
  sign: async () => ({ ed: "c2ln", mldsa: "c2lnbWw" }),
};

// Captures every registration body the client sends, and replies with whatever
// the current script says. `sent` is what the server would have received.
let sent = [];
let replies = [];
globalThis.fetch = async (_url, opts) => {
  const body = JSON.parse(opts.body);
  sent.push(body);
  const r = replies.shift() || { ok: true, status: 200, body: { status: "ok" } };
  const res = {
    ok: r.ok,
    status: r.status,
    json: async () => r.body,
    text: async () => JSON.stringify(r.body),
  };
  res.clone = () => res;
  return res;
};

const account = await import("./account.js");

function reset(stored) {
  sent = [];
  replies = [];
  localStorage.removeItem(LS_REG_SEQ);
  if (stored !== undefined) localStorage.setItem(LS_REG_SEQ, String(stored));
}

let n = 0;
const ok = (m) => { n++; console.log("OK  " + m); };

// --- the finding -----------------------------------------------------------
{
  reset(2 ** 53 - 2);   // the poisoning: one plaintext localStorage write
  await account.register("http://x", identity, "victim");

  assert.strictEqual(sent.length, 1, "one registration attempt");
  const seq = sent[0].seq;
  assert.ok(Number.isInteger(seq), "a v3 registration must carry a counter");
  assert.ok(seq <= SERVER_CAP,
    `item 18: the client must never sign above the server's cap (signed ${seq})`);
  assert.ok(seq < SERVER_CAP / 2,
    `item 18: a poisoned counter must be DISCARDED, not used as a floor (signed ${seq})`);
  // It should have healed to wall-clock scale, which is what keeps it usable.
  assert.ok(seq >= 1.6e12 && seq <= 4e12,
    `a discarded counter should fall back to Date.now() scale (got ${seq})`);
  ok("item 18: a poisoned counter cannot walk the account to the server's cap");
}

{
  // Exactly the cap, the value that froze accounts.
  reset(SERVER_CAP);
  await account.register("http://x", identity, "victim");
  assert.ok(sent[0].seq < SERVER_CAP / 2, "a stored value AT the cap must be discarded too");
  ok("item 18: a counter already at the cap is discarded rather than resigned");
}

// --- the counter still has to work -----------------------------------------
{
  reset();   // fresh device, nothing stored
  await account.register("http://x", identity, "alice");
  const first = sent[0].seq;
  assert.ok(Number.isInteger(first) && first > 0, "a fresh device still signs a counter");

  await account.register("http://x", identity, "alice");
  const second = sent[1].seq;
  assert.ok(second > first, `the counter must advance (${first} -> ${second})`);
  assert.strictEqual(Number(localStorage.getItem(LS_REG_SEQ)), second, "and be persisted");
  ok("control: the counter still advances monotonically across registrations");
}

{
  // A device whose counter fell behind (reinstall) must still overtake the
  // server's stored value without a round trip — the Date.now() floor.
  reset(5);
  await account.register("http://x", identity, "alice");
  assert.ok(sent[0].seq >= 1.6e12,
    "a counter far behind must jump to wall-clock scale, not to 6");
  ok("control: a stale counter self-heals to wall-clock scale");
}

// --- the 409 retry path ----------------------------------------------------
{
  reset();
  replies = [
    { ok: false, status: 409, body: { detail: "registration counter is not newer than the stored one" } },
    { ok: true, status: 200, body: { status: "updated" } },
  ];
  await account.register("http://x", identity, "alice");
  assert.strictEqual(sent.length, 2, "a 409 naming the counter retries exactly once");
  assert.ok(sent[1].seq <= SERVER_CAP, "the retry must also stay under the cap");
  assert.ok(sent[1].seq >= sent[0].seq, "the retry must not go backwards");
  ok("control: the 409 retry still fires, and stays clamped");
}

// --- garbage in the slot ---------------------------------------------------
for (const junk of ["", "not-a-number", "-1", "0", "1e999", "NaN", String(2 ** 60)]) {
  reset(junk);
  await account.register("http://x", identity, "alice");
  const seq = sent[0].seq;
  assert.ok(Number.isInteger(seq) && seq > 0 && seq <= SERVER_CAP,
    `a junk counter (${JSON.stringify(junk)}) must yield a valid one, got ${seq}`);
}
ok("control: junk in the counter slot never produces an unusable registration");


// --- pentest 2026-08-10, second pass ---------------------------------------
// The first repair used an ABSOLUTE ceiling (2**43) and was still frozen: the
// acceptance bound was inclusive, so a stored 2**43 was used as a floor, signed
// as 2**43+1, and then discarded by the very next call — leaving the server
// holding a value this device could never reach again. The band the freeze lived
// in was exactly the one no test covered.
{
  const SLACK = 7 * 24 * 60 * 60 * 1000;
  // Every value in and around the old self-discarding band.
  for (const stored of [2 ** 43 - 1, 2 ** 43, 2 ** 43 + 1, 2 ** 44, Date.now() + SLACK * 10]) {
    reset(stored);
    await account.register("http://x", identity, "victim");
    const signed = sent[0].seq;
    const ceiling = Date.now() + SLACK;
    assert.ok(signed <= ceiling,
      `item 18: must never sign beyond now+slack (stored ${stored} -> signed ${signed})`);
    // The real property: whatever we signed must still be acceptable as a floor
    // next time, or we have frozen ourselves exactly as before.
    reset(signed);
    await account.register("http://x", identity, "victim");
    assert.ok(sent[0].seq > signed,
      `item 18: a value we signed (${signed}) must remain usable as a floor — ` +
      `got ${sent[0].seq}, which is the self-freeze the absolute ceiling caused`);
  }
  ok("item 18: no self-discarding band — anything signed stays a usable floor");
}

{
  // M-1: the 409 retry recomputed the value that had just been refused, so it
  // was inert by construction while claiming to be a recovery.
  reset();
  replies = [
    { ok: false, status: 409, body: { detail: "registration counter is not newer than the stored one" } },
    { ok: true, status: 200, body: { status: "updated" } },
  ];
  await account.register("http://x", identity, "alice");
  assert.strictEqual(sent.length, 2, "the retry still fires");
  assert.ok(sent[1].seq > sent[0].seq,
    `M-1: the retry must actually ADVANCE the counter, not resend ${sent[0].seq}`);
  ok("item 18 / M-1: the 409 retry advances instead of resending the refused value");
}

console.log(`\nAll ${n} registration-counter checks passed.`);
