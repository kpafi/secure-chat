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
// Named and reusable (ROUND-4 M-1): later blocks swap in a stateful `serverStub`,
// and the scripted stub has to be REINSTALLED afterwards. It was not, so two
// blocks that set `replies = [...]` were silently talking to the leftover honest
// stub and their scripts were never read at all — the hostile-stored_seq matrix
// and the F-5 test both measured an honest server instead. Use `useScript()` at
// the head of every scripted block rather than assuming what the previous one left.
const scriptedFetch = async (_url, opts) => {
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
const useScript = () => { globalThis.fetch = scriptedFetch; };
globalThis.fetch = scriptedFetch;

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
// The backend now returns a STRUCTURED stale_counter 409 that echoes stored_seq
// (commit ea4afe9). The client resyncs to stored_seq+1 rather than guessing.
{
  reset();
  // A stored value modestly ahead of a fresh device's first attempt, well inside
  // the slack window so it is a legitimate resync target.
  const stored = Date.now() + 60_000;
  replies = [
    { ok: false, status: 409, body: { detail: { error: "stale_counter", stored_seq: stored, message: "counter not newer" } } },
    { ok: true, status: 200, body: { status: "updated" } },
  ];
  await account.register("http://x", identity, "alice");
  assert.strictEqual(sent.length, 2, "a stale_counter 409 retries exactly once");
  assert.ok(sent[1].seq <= SERVER_CAP, "the retry must also stay under the cap");
  assert.strictEqual(sent[1].seq, stored + 1,
    "the retry must resync to the server's echoed stored_seq + 1, not guess");
  ok("control: the 409 retry resyncs to stored_seq+1 and stays clamped");
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
  // was inert by construction while claiming to be a recovery. Reach the state
  // where the local counter is already advanced to wall-clock scale (a prior
  // successful registration) BEFORE the 409 — deliberately NOT via reset() — so
  // that the old `Math.max(seq, Date.now())` recovery would recompute the exact
  // value it just sent. Only a real advance passes.
  reset();
  await account.register("http://x", identity, "alice");   // establishes an advanced, persisted counter
  const settled = sent[0].seq;
  sent = [];
  const stored = settled + 5000;   // server holds a value ahead of what we now sign
  replies = [
    { ok: false, status: 409, body: { detail: { error: "stale_counter", stored_seq: stored, message: "not newer" } } },
    { ok: true, status: 200, body: { status: "updated" } },
  ];
  await account.register("http://x", identity, "alice");
  assert.strictEqual(sent.length, 2, "the retry still fires");
  assert.ok(sent[1].seq > sent[0].seq,
    `M-1: the retry must actually ADVANCE the counter, not resend ${sent[0].seq}`);
  ok("item 18 / M-1: the 409 retry advances instead of resending the refused value");
}

// --- pentest 2026-08-21: the backend now echoes stored_seq (commit ea4afe9) ---
// A server-faithful stub: it accepts only a strictly-greater counter, else 409s
// with the real stored_seq. This lets us assert CONVERGENCE, not just what a
// single stubbed reply happens to be.
function serverStub(initialStored) {
  let stored = initialStored;
  return async (_url, opts) => {
    const body = JSON.parse(opts.body);
    sent.push(body);
    const seq = body.seq;
    let r;
    if (!Number.isInteger(seq)) {
      // A counter-free (v2) registration reaching a v3 server: the real backend
      // treats a missing counter on an account that has one as a replay. Model it
      // as a refusal so any silent downgrade is caught, never accepted.
      r = { ok: false, status: 409, body: { detail: { error: "stale_counter", stored_seq: stored, message: "counter required" } } };
    } else if (seq > stored) {
      stored = seq;
      r = { ok: true, status: 200, body: { status: "updated" } };
    } else {
      r = { ok: false, status: 409, body: { detail: { error: "stale_counter", stored_seq: stored, message: "not newer" } } };
    }
    const res = { ok: r.ok, status: r.status, json: async () => r.body, text: async () => JSON.stringify(r.body) };
    res.clone = () => res;
    return res;
  };
}

// Temporarily replace Date.now so we can model a device whose wall clock is wrong.
async function withClock(fixedNow, fn) {
  const realNow = Date.now;
  Date.now = () => fixedNow;
  try { return await fn(); }
  finally { Date.now = realNow; }
}

{
  // A device whose clock is FROZEN slightly behind a server that already holds a
  // realistic counter. Before the echo, the client jumped to its own ceiling
  // (Date.now()+slack) computed from the lying clock; here the resync to
  // stored_seq+1 converges in exactly one retry and sends the MINIMAL advance.
  reset();
  const realish = 1.75e12;
  const stored = realish + 120_000;   // server ~2 min ahead, inside the slack window
  globalThis.fetch = serverStub(stored);
  await withClock(realish, async () => {
    await account.register("http://x", identity, "bob");
  });
  assert.strictEqual(sent.length, 2, "frozen-clock device converges in ONE retry");
  assert.strictEqual(sent[1].seq, stored + 1,
    "resync sends stored_seq+1 (minimal advance), not a ceiling guess");
  ok("stored_seq echo: a frozen/behind clock resyncs in one retry to stored_seq+1");
}

{
  // Two-device skew: device A (clock a little ahead, inside slack) registers and
  // moves the server forward; device B (correct clock, fresh storage) then
  // overtakes A by exactly one via the echo, in one retry — the skew-lockout the
  // echo was added to cure.
  reset();
  const base = 1.75e12;
  globalThis.fetch = serverStub(0);
  // Device A, ~1h ahead.
  await withClock(base + 3_600_000, async () => {
    await account.register("http://x", identity, "shared");
  });
  const aSeq = sent[sent.length - 1].seq;
  // Device B, correct clock, nothing stored.
  reset();                                   // fresh device B (server keeps aSeq)
  globalThis.fetch = serverStub(aSeq);
  sent = [];
  await withClock(base, async () => {
    await account.register("http://x", identity, "shared");
  });
  assert.strictEqual(sent.length, 2, "device B converges in one retry despite the skew");
  assert.strictEqual(sent[1].seq, aSeq + 1, "device B overtakes A by exactly one");
  ok("stored_seq echo: two-device clock skew no longer locks the second device out");
}

// --- a HOSTILE relay controls the 409 body: stored_seq is untrusted ----------
{
  // Huge, negative, fractional, zero, and MISSING stored_seq must never (a) walk
  // the account toward the server cap, (b) loop, or (c) downgrade to a
  // counter-free v2 registration. The retry seq is ALWAYS a signed positive
  // integer at or below the ceiling.
  const SLACK = 7 * 24 * 60 * 60 * 1000;
  const hostile = [SERVER_CAP, 2 ** 60, -1, 0, 1.5, "123", null, undefined, NaN, Infinity];
  for (const bad of hostile) {
    reset();
    useScript();   // ROUND-4 M-1: the previous block left a stateful serverStub installed
    const detail = { error: "stale_counter", message: "not newer" };
    if (bad !== undefined) detail.stored_seq = bad;   // omit the field entirely for `undefined`
    let threw = null;
    replies = [
      { ok: false, status: 409, body: { detail } },
      { ok: true, status: 200, body: { status: "updated" } },
    ];
    try {
      await account.register("http://x", identity, "victim");
    } catch (e) {
      threw = e;   // failing loudly is an acceptable outcome; a silent downgrade is not
    }
    // The script MUST have been consumed — otherwise this block was talking to a
    // leftover stub and asserting nothing about the hostile value (ROUND-4 M-1).
    assert.ok(replies.length < 2,
      `hostile stored_seq ${JSON.stringify(bad)}: the scripted 409 was never delivered — this ` +
      "block is testing a leftover stub, not the hostile value it names");
    // At most one retry — never a loop.
    assert.ok(sent.length <= 2, `hostile stored_seq ${JSON.stringify(bad)} must not loop (sent ${sent.length})`);
    // Every registration this device sent carried a usable v3 counter. In
    // particular the RETRY (if any) never dropped body.seq — the F-5 downgrade.
    for (const b of sent) {
      assert.ok(Number.isInteger(b.seq) && b.seq > 0 && b.seq <= Date.now() + SLACK,
        `hostile stored_seq ${JSON.stringify(bad)}: every send must carry a clamped positive counter, got ${b.seq}`);
    }
    if (threw) assert.strictEqual(threw.code, "stale_counter", "a loud refusal must carry the code");
  }
  ok("hostile relay: an untrusted stored_seq never downgrades to v2, never loops");
}

// --- the F-5 downgrade: a hooked Date.now must not sign a counter-free retry --
{
  // The dangerous path is the RETRY, not the first attempt: nextRegSeq() already
  // guards its own output, so a statically-fractional clock is caught there. F-5
  // is the case where the first attempt signs a clean integer and only the RETRY
  // hits a fractional clock — the pre-fix retry recomputed regSeqCeiling()
  // UNGUARDED, so a fractional value flowed into attempt(), which dropped body.seq,
  // and registerMessageBytes() emitted the REPLAYABLE v2 message. To reproduce
  // exactly that, hand out an integer clock for the first attempt's Date.now()
  // calls and flip to a fraction only for the retry's regSeqCeiling().
  reset();
  // ROUND-4 M-1: reinstall the scripted stub. Without this the block ran against
  // the leftover stateful serverStub, which supplies an HONEST stored_seq near the
  // real wall clock — so this test reached its `assert.ok(threw)` only because that
  // honest value happened to sit more than REG_SEQ_SLACK_MS beyond the hard-coded
  // stub clock and fell into the ceiling branch BY ACCIDENT. On a machine clocked
  // near the stub's own date it would have gone red. It never tested what it says.
  useScript();
  const realNow = Date.now;
  let calls = 0;
  Date.now = () => (++calls <= 2 ? 1.75e12 : 1.75e12 + 0.5);   // integer first, fractional at retry
  replies = [
    { ok: false, status: 409, body: { detail: { error: "stale_counter", message: "not newer" } } },  // no stored_seq -> ceiling fallback
    { ok: true, status: 200, body: { status: "updated" } },
  ];
  let threw = null;
  try {
    await account.register("http://x", identity, "victim");
  } catch (e) { threw = e; }
  finally { Date.now = realNow; }
  // Every send this device made carried an integer counter — in particular the
  // retry never dropped body.seq for a counter-free v2 downgrade.
  for (const b of sent) {
    assert.ok(Number.isInteger(b.seq),
      `F-5: a fractional clock must never produce a counter-free (v2) send, got seq=${JSON.stringify(b.seq)}`);
  }
  // The scripted 409 must actually have been delivered (ROUND-4 M-1).
  assert.ok(replies.length < 2, "F-5: the scripted 409 was never delivered — leftover stub");
  // With an un-signable (fractional) ceiling and no trustworthy stored_seq, the
  // only safe outcome is a loud refusal — never a silent replayable registration.
  assert.ok(threw, "F-5: the retry refuses rather than signing a counter-free registration");
  ok("F-5: a fractional Date.now() on the RETRY cannot silently downgrade to v2");
}

// Restore the default stub for any later additions.
globalThis.fetch = async (_url, opts) => {
  const body = JSON.parse(opts.body);
  sent.push(body);
  const r = replies.shift() || { ok: true, status: 200, body: { status: "ok" } };
  const res = { ok: r.ok, status: r.status, json: async () => r.body, text: async () => JSON.stringify(r.body) };
  res.clone = () => res;
  return res;
};

// --- ROUND-4: the `retrySeq <= seq` half of the guard is load-bearing ---------
// The pentest showed this half was untested: deleting it left the suite green
// while the client RESENT the exact value the server had just refused — item 18's
// M-1 bug, reintroduced. It is reachable without any hostile input: a device whose
// counter is already pinned AT the ceiling computes a retry equal to the value it
// just sent, because regSeqCeiling() is the most it may ever sign.
{
  reset();
  useScript();
  const fixedNow = 1.75e12;
  const SLACK = 7 * 24 * 60 * 60 * 1000;
  const ceiling = fixedNow + SLACK;
  // Pin the stored counter AT the ceiling: nextRegSeq() then returns the ceiling
  // itself (min(max(cur+1, now), ceiling)), so the retry cannot advance.
  localStorage.setItem("sc.regseq.v1", String(ceiling));
  replies = [
    // No stored_seq the client can use -> ceiling fallback -> equal to `seq`.
    { ok: false, status: 409, body: { detail: { error: "stale_counter", message: "not newer" } } },
    { ok: true, status: 200, body: { status: "updated" } },
  ];
  let threw = null;
  await withClock(fixedNow, async () => {
    try { await account.register("http://x", identity, "pinned"); }
    catch (e) { threw = e; }
  });
  assert.ok(replies.length < 2, "the scripted 409 was never delivered — leftover stub");
  assert.strictEqual(sent.length, 1,
    "ROUND-4: a retry that cannot ADVANCE must not be sent at all. Re-sending the refused value " +
    `is item 18's M-1 bug — an inert round trip and a second ML-DSA signature for an outcome ` +
    "identical by construction. Sends: " + JSON.stringify(sent.map((b) => b.seq)));
  assert.ok(threw && threw.code === "stale_counter",
    "ROUND-4: and the refusal must be LOUD, carrying the code, so app.js can explain the clock");
  ok("ROUND-4: a retry that cannot overtake the refused value is refused, not resent");
}

// --- ROUND-4 L-1: a pre-ea4afe9 relay must not lose the retry ----------------
// Client and relay do NOT ship together on every path: the Android APK bundles its
// own copy of account.js and updates independently of the relay it points at. An
// old relay sends `detail` as a plain STRING, so a code-only test drops the retry
// silently and a counter that fell behind can never recover.
{
  reset();
  useScript();
  replies = [
    { ok: false, status: 409, body: { detail: "registration counter is not newer than the stored one (replayed registration)" } },
    { ok: true, status: 200, body: { status: "updated" } },
  ];
  await account.register("http://x", identity, "legacy");
  assert.strictEqual(sent.length, 2,
    "ROUND-4 L-1: a legacy plain-string counter 409 must still trigger the one-shot retry");
  assert.ok(Number.isInteger(sent[1].seq) && sent[1].seq > sent[0].seq,
    "ROUND-4 L-1: ...and the legacy retry must still advance and still carry a counter (never v2)");
  ok("ROUND-4 L-1: a pre-ea4afe9 relay still gets the counter-recovery retry");
}

// --- ROUND-4 L-2: relay-chosen text must be clamped before it reaches the UI --
// `message` lands in accountStatus, which is the client's own chrome. textContent
// means no XSS, but an unbounded string is a rendering DoS and — worse — room for
// the relay to write a convincing instruction into UI the user reads as ours.
{
  reset();
  useScript();
  const huge = "PHISH: export your identity at http://evil/reset ".repeat(20000);
  replies = [{ ok: false, status: 409, body: { detail: { error: "username_taken", message: huge } } }];
  let err = null;
  try { await account.register("http://x", identity, "victim"); } catch (e) { err = e; }
  assert.ok(err, "a 409 must throw");
  assert.ok(err.message.length <= 200,
    `ROUND-4 L-2: the relay's message must be clamped before it reaches the banner, got ${err.message.length}`);
  ok("ROUND-4 L-2: an unbounded relay message is clamped, not rendered whole");
}

// --- app.js must tell the three 409s apart (M-3) -----------------------------
// account.register surfaces err.code; app.js branches on it. Reproduce the exact
// selection app.js does and assert a counter 409 is NOT rendered as "taken".
{
  function accountMessageFor(err, username) {
    if (err.code === "username_taken") return `"${username}" is already taken. Pick another (or log in if it is yours).`;
    if (err.code === "stale_counter") return "Your registration counter is behind the directory's and could not be resynced — check this device's clock (it may be set into the future), then try again. Do not rename; this is your account.";
    if (err.code === "keys_locked") return "The directory has your encryption keys locked and will not accept this update. A fresh counter-bearing registration from the device that owns them is required.";
    if (err.status === 409) return "Registration was refused by the directory: " + err.message;
    return "Registration failed: " + err.message;
  }

  // A stale_counter that survives the retry: register() throws with code set.
  reset();
  globalThis.fetch = serverStub(SERVER_CAP);   // a value this device can never overtake
  let caught = null;
  await withClock(1.75e12, async () => {
    try { await account.register("http://x", identity, "mine"); }
    catch (e) { caught = e; }
  });
  assert.ok(caught, "an un-overtakeable counter throws");
  assert.strictEqual(caught.code, "stale_counter", "and carries the stale_counter code, not a bare 409");
  const msg = accountMessageFor(caught, "mine");
  assert.ok(!/already taken/.test(msg) && !/Pick another/.test(msg),
    "M-3: a counter 409 must NOT tell the owner to pick another name");
  assert.ok(/Do not rename/.test(msg), "M-3: it must tell them to keep their handle");
  ok("M-3: a counter 409 is not surfaced as 'username taken'");

  // And a real username_taken (object detail) DOES render the taken message and a
  // readable message (not '[object Object]').
  reset();
  replies = [{ ok: false, status: 409, body: { detail: { error: "username_taken", message: "that name is taken" } } }];
  globalThis.fetch = async (_url, opts) => {
    sent.push(JSON.parse(opts.body));
    const r = replies.shift();
    const res = { ok: r.ok, status: r.status, json: async () => r.body, text: async () => JSON.stringify(r.body) };
    res.clone = () => res;
    return res;
  };
  let taken = null;
  try { await account.register("http://x", identity, "dup"); } catch (e) { taken = e; }
  assert.strictEqual(taken.code, "username_taken", "username_taken code surfaced");
  assert.strictEqual(taken.message, "that name is taken",
    "asError must render the object detail's .message, never '[object Object]'");
  assert.ok(/already taken/.test(accountMessageFor(taken, "dup")), "and app.js shows the taken message");
  ok("M-3: username_taken still renders correctly, with a human-readable message");
}

// --- M-3, the anchor: the block above is a REPLICA, so pin the real one ------
// `accountMessageFor` reproduces app.js's branching rather than running it
// (app.js touches `document` at module scope and cannot be imported). A replica
// proves the LOGIC is right and proves nothing about the shipped file — it drifts
// silently the moment someone edits app.js, and "a green control that stopped
// tracking the code" is the exact failure this project has hit three rounds
// running. So anchor the shipped branching too, over comment-stripped source.
{
  const { readFile } = await import("node:fs/promises");
  const { stripComments, codeLines } = await import("./test-source.mjs");
  const app = codeLines(stripComments(await readFile(new URL("./app.js", import.meta.url), "utf8")));

  // ROUND-4 M-2 (pentest of THIS anchor, 2026-08-21). The first cut searched the
  // WHOLE file, and both `stale_counter` and `keys_locked` match FIRST inside
  // `showIdentityUnlocked`'s republish catch — a different function entirely. The
  // pentest then deleted registerAccount's branches, restored "already taken" for
  // every 409 (the exact M-3 harm), and the suite stayed GREEN, this line
  // included. An anchor that names a function must be SLICED to that function.
  const fnAt = app.findIndex((l) => /^async function registerAccount\(/.test(l));
  assert.notStrictEqual(fnAt, -1, "M-3: registerAccount must still exist in app.js");
  const nextFnRel = app.slice(fnAt + 1).findIndex((l) => /^(async )?function \w+\(/.test(l));
  assert.notStrictEqual(nextFnRel, -1, "M-3: could not find the end of registerAccount");
  const fn = app.slice(fnAt, fnAt + 1 + nextFnRel);

  const countIn = (hay, needle) => hay.filter((l) => l.includes(needle)).length;
  assert.strictEqual(countIn(fn, 'e.code === "username_taken"'), 1,
    "M-3: registerAccount must branch on e.code === 'username_taken', exactly once. Branching on " +
    "the 409 STATUS alone is the bug: it tells an existing owner whose counter is stale to pick " +
    "another name, which throws away their handle and every contact's pin");
  for (const code of ["stale_counter", "keys_locked"]) {
    assert.strictEqual(countIn(fn, `e.code === "${code}"`), 1,
      `M-3: registerAccount must handle the ${code} 409 distinctly from a name collision, exactly once`);
  }
  // ...and the bare-status branch must come AFTER the code branches, or it
  // swallows them and the distinction is decorative.
  const takenAt = fn.findIndex((l) => l.includes('e.code === "username_taken"'));
  const statusAt = fn.findIndex((l) => /^\} else if \(e\.status === 409\)/.test(l));
  assert.notStrictEqual(statusAt, -1, "M-3: a conservative fallback for an unrecognised 409 must exist");
  assert.ok(takenAt < statusAt,
    "M-3: the e.code branches must precede the bare `e.status === 409` fallback, otherwise the " +
    "fallback catches every 409 first and the codes are never consulted");
  // The renaming advice must appear ONLY in the username_taken branch. Bounding by
  // "the next branch" rather than a fixed line count, so adding a statement cannot
  // silently move the assertion off its target.
  const staleAt = fn.findIndex((l) => l.includes('e.code === "stale_counter"'));
  const afterStale = fn.slice(staleAt + 1).findIndex((l) => /^\} else/.test(l));
  const staleBody = fn.slice(staleAt, staleAt + 1 + (afterStale === -1 ? 4 : afterStale)).join(" ");
  assert.ok(!/Pick another/i.test(staleBody),
    "M-3: the stale_counter branch must NOT tell the user to pick another name — renaming does " +
    "not fix a counter and loses the account");
  ok("M-3: registerAccount's own 409 branching is anchored (sliced to the function)");

  // The republish catch is the OTHER half of this change and had no anchor of its
  // own — it was only ever matched by this one's whole-file search, i.e. by
  // accident. Pin it separately so neither half can vanish silently.
  const repAt = app.findIndex((l) => /^async function showIdentityUnlocked\(/.test(l));
  assert.notStrictEqual(repAt, -1, "showIdentityUnlocked must still exist");
  const repEndRel = app.slice(repAt + 1).findIndex((l) => /^(async )?function \w+\(/.test(l));
  const rep = app.slice(repAt, repAt + 1 + (repEndRel === -1 ? 60 : repEndRel));
  assert.ok(rep.some((l) => l.includes('e.code === "keys_locked"') && l.includes('e.code === "stale_counter"')),
    "the opportunistic republish must WARN for keys_locked / a stale_counter that survived the " +
    "retry — a silent `.catch(() => {})` there means 'your published keys are frozen and sealed " +
    "mail is going to a superseded key' is never said out loud");
  assert.ok(!rep.some((l) => /\.catch\(\(\) => \{\}\)/.test(l)),
    "the republish must not go back to swallowing every error");
  ok("M-3: the republish warning is anchored in its own function");
}

console.log(`\nAll ${n} registration-counter checks passed.`);
