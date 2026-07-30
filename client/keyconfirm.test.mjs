// Key confirmation state machine — pentest 2026-07-27 M-5, hardened 2026-07-29 M-5.
// Run: node keyconfirm.test.mjs   (no server, no DOM)
//
// The 2026-07-29 finding could only be modelled in a scratch harness, because
// the logic lived inline in app.js and app.js needs a DOM. It lives in
// keyconfirm.js now, so these run against the SHIPPED code.
//
// The two properties, which pull in opposite directions and are why this is
// subtle at all:
//   * a chain rebuild AFTER confirmation must be refused (the attack), and
//   * a chain rebuild BEFORE it must NOT tear down two honest peers (the race).
import assert from "node:assert";
import { makeKeyConfirmation, MAX_PEER_CONFIRMS } from "./keyconfirm.js";

// A driver that records effects instead of performing them, and runs timers by
// hand so the deadline is testable without waiting 15 real seconds.
function driver() {
  const log = { sent: [], failed: [], finished: 0, hints: [] };
  let timers = [];
  let nextId = 1;
  const kc = makeKeyConfirmation({
    send: (tag) => log.sent.push(tag),
    fail: (why) => log.failed.push(why),
    finish: () => { log.finished += 1; },
    hint: (m) => log.hints.push(m),
    setTimer: (fn) => { const id = nextId++; timers.push({ id, fn }); return id; },
    clearTimer: (id) => { timers = timers.filter((t) => t.id !== id); },
  });
  return {
    kc,
    log,
    fireTimers() {
      const due = timers;
      timers = [];
      for (const t of due) t.fn();
    },
    get pending() { return timers.length; },
  };
}

// Two peers' views of the same derivation. `mine` is HMAC(send chain) and
// `theirs` is HMAC(recv chain), so A.mine === B.theirs when they share material.
const chains = (id) => ({ a: { mine: `A${id}`, theirs: `B${id}` }, b: { mine: `B${id}`, theirs: `A${id}` } });

// --- the honest case ---------------------------------------------------------
{
  const A = driver();
  const c = chains(1);
  await A.kc.onChains(c.a);
  assert.deepStrictEqual(A.log.sent, ["A1"], "we send our tag once the chains exist");
  assert.strictEqual(A.log.finished, 0, "not confirmed until the peer answers");
  await A.kc.onPeerTag("B1", c.a);
  assert.strictEqual(A.log.finished, 1, "matching tag confirms the session");
  assert.deepStrictEqual(A.log.failed, []);
  assert.strictEqual(A.pending, 0, "the deadline is cleared on success");
  assert.ok(A.kc.done);
}
console.log("OK  honest handshake: one tag each way, confirmed");

// OTP and friends negotiate nothing; there is nothing to confirm and the
// session must still unlock (and must not double-unlock).
{
  const A = driver();
  assert.strictEqual(await A.kc.onChains(null), true);
  assert.strictEqual(A.log.finished, 1, "a mode with no confirmation still finishes");
  assert.deepStrictEqual(A.log.sent, [], "…and sends nothing");
}
console.log("OK  a mode with nothing to confirm unlocks exactly once");

// --- M-5, the ATTACK: chains rebuilt AFTER confirmation ----------------------
// A relay replays one genuine hello and delays one genuine signed offer until
// after confirmation completed. `_derive` then replaces the channel and both
// tags, and nobody re-confirms: both peers show "secure channel established",
// compare safety numbers, and the chat is silently dead.
{
  const A = driver();
  const c1 = chains(1);
  await A.kc.onChains(c1.a);
  await A.kc.onPeerTag("B1", c1.a);
  assert.strictEqual(A.log.finished, 1, "precondition: confirmed on chains #1");

  // The withheld offer lands: new material, new tags.
  const c2 = chains(2);
  const proceed = await A.kc.onChains(c2.a);
  assert.strictEqual(proceed, false, "a post-confirmation rebuild must not proceed");
  assert.strictEqual(A.log.finished, 1, "and must not unlock the session again");
  assert.strictEqual(A.log.failed.length, 1, "it must be LOUD");
  assert.match(A.log.failed[0], /changed AFTER both sides had confirmed/);
}
console.log("OK  M-5: chains rebuilt after confirmation are refused loudly");

// Re-entering with the SAME chains (an idempotent re-derive, or a replayed
// frame the cipher folded to nothing) is not an attack and must stay quiet.
{
  const A = driver();
  const c = chains(1);
  await A.kc.onChains(c.a);
  await A.kc.onPeerTag("B1", c.a);
  await A.kc.onChains(c.a);
  assert.deepStrictEqual(A.log.failed, [], "an unchanged re-derive is not a failure");
  assert.strictEqual(A.log.finished, 1, "…and does not re-unlock");
  assert.deepStrictEqual(A.log.sent, ["A1"], "…and does not re-send");
}
console.log("OK  M-5: an idempotent re-derive after confirmation is silent");

// A confirm tag arriving after confirmation changes nothing either.
{
  const A = driver();
  const c = chains(1);
  await A.kc.onChains(c.a);
  await A.kc.onPeerTag("B1", c.a);
  assert.strictEqual(await A.kc.onPeerTag("B9", c.a), false);
  assert.deepStrictEqual(A.log.failed, []);
  assert.strictEqual(A.log.finished, 1);
}
console.log("OK  M-5: a late confirm tag cannot re-open a confirmed session");

// --- M-5, the RACE the fix must not break ------------------------------------
// Simultaneous connect: each side derives twice, so the tag each sent after its
// FIRST derivation is stale by the time the peer sees it. Comparing only the
// latest tag made this mismatch every time and disconnected both honest peers.
{
  const A = driver();
  const B = driver();
  const one = chains(1);   // after each side's own offer secret
  const two = chains(2);   // after the answer is folded in

  await A.kc.onChains(one.a);
  await B.kc.onChains(one.b);
  const aStale = A.log.sent.at(-1);   // "A1"
  const bStale = B.log.sent.at(-1);   // "B1"

  // Both re-derive before either stale tag is delivered.
  await A.kc.onChains(two.a);
  await B.kc.onChains(two.b);
  assert.deepStrictEqual(A.log.sent, ["A1", "A2"], "a rebuild re-sends the new tag");

  // Now the wire drains, stale first — the ordering that used to kill them.
  await A.kc.onPeerTag(bStale, two.a);
  assert.deepStrictEqual(A.log.failed, [], "a stale tag must not tear the session down");
  assert.strictEqual(A.log.finished, 0, "…and must not confirm on stale material");
  await A.kc.onPeerTag(B.log.sent.at(-1), two.a);
  assert.strictEqual(A.log.finished, 1, "the current tag confirms");

  await B.kc.onPeerTag(aStale, two.b);
  await B.kc.onPeerTag(A.log.sent.at(-1), two.b);
  assert.strictEqual(B.log.finished, 1, "both honest peers survive the race");
  assert.deepStrictEqual(B.log.failed, []);
}
console.log("OK  M-5: the simultaneous-connect race no longer disconnects both peers");

// --- a genuine desync must still be LOUD -------------------------------------
// The relay drops both answers, so the peers hold different material and no tag
// will ever match. Nothing local can tell this apart from a slow race, so the
// loudness comes from the deadline.
{
  const A = driver();
  const c = chains(1);
  await A.kc.onChains(c.a);
  await A.kc.onPeerTag("B-from-different-material", c.a);
  assert.strictEqual(A.log.finished, 0, "a non-matching tag must not confirm");
  assert.deepStrictEqual(A.log.failed, [], "…but is not fatal on the spot (race)");
  assert.strictEqual(A.pending, 1, "the deadline is armed");
  A.fireTimers();
  assert.strictEqual(A.log.failed.length, 1, "the deadline makes it loud");
  assert.match(A.log.failed[0], /never proved it derived the same key/);
  assert.strictEqual(A.log.finished, 0, "the session never unlocks");
}
console.log("OK  M-5: a real desync fails loudly at the deadline, never silently");

// A relay that simply never delivers the peer's confirm frame is the same
// outcome. The ORIGINAL code hung here forever, which is the silent dead chat
// this whole mechanism exists to prevent.
{
  const A = driver();
  await A.kc.onChains(chains(1).a);
  A.fireTimers();
  assert.match(A.log.failed[0] || "", /never proved/, "a withheld confirm frame must not hang");
}
console.log("OK  M-5: a withheld confirm frame is a timeout, not a hang");

// --- the tag set must not become a guessing oracle ---------------------------
// The confirm frame is NOT signature-covered, so the original code took only
// the first tag. The set that makes the race work must stay hard-capped.
{
  const A = driver();
  const c = chains(1);
  await A.kc.onChains(c.a);
  for (let i = 0; i < MAX_PEER_CONFIRMS; i++) {
    assert.strictEqual(await A.kc.onPeerTag(`guess-${i}`, c.a), false);
    assert.deepStrictEqual(A.log.failed, [], "guesses up to the cap are merely wrong");
  }
  await A.kc.onPeerTag("guess-over-cap", c.a);
  assert.strictEqual(A.log.failed.length, 1, "past the cap it is an attack, and loud");
  assert.match(A.log.failed[0], /more key confirmations than any honest peer/);
  assert.strictEqual(A.log.finished, 0);

  // Repeating the SAME tag is not a new guess and must not count toward the cap
  // (a relay re-delivering one frame is ordinary noise).
  const B = driver();
  const cb = chains(1);
  await B.kc.onChains(cb.a);
  for (let i = 0; i < 10; i++) await B.kc.onPeerTag("same-wrong-tag", cb.a);
  assert.deepStrictEqual(B.log.failed, [], "a repeated tag is not a new guess");
}
console.log("OK  M-5: the peer-tag set is capped, so it is not a guessing oracle");

// --- reset really resets ------------------------------------------------------
// A confirmation surviving into the next connection would BE the M-5 desync.
{
  const A = driver();
  const c = chains(1);
  await A.kc.onChains(c.a);
  await A.kc.onPeerTag("B1", c.a);
  assert.ok(A.kc.done);
  A.kc.reset();
  assert.ok(!A.kc.done, "reset clears the confirmed flag");
  assert.deepStrictEqual(A.kc.state, { sentTag: null, peerTags: [], done: false, confirmedTag: null, armed: false });
  assert.strictEqual(A.pending, 0, "reset clears the deadline");
  // The next connection confirms from scratch, and the OLD peer tag is gone.
  const c2 = chains(2);
  await A.kc.onChains(c2.a);
  await A.kc.onPeerTag("B1", c2.a);
  assert.strictEqual(A.log.finished, 1, "a stale tag from the last connection does not confirm");
  await A.kc.onPeerTag("B2", c2.a);
  assert.strictEqual(A.log.finished, 2, "the new connection confirms on its own material");
}
console.log("OK  M-5: reset clears every field, so nothing leaks between connections");

console.log("\nAll key-confirmation checks passed.");
