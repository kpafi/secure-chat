# secure-chat — progress log

Working file so any session can pick up where the last left off. Newest notes
at the top of each section. Dates are absolute (YYYY-MM-DD).

> **Read the git log before trusting the top entry.** A session in progress can
> land several commits between updates to this file, and this file's top section
> going stale has already cost one session an afternoon of duplicated work
> (2026-08-21: Phase 2 was re-implemented from scratch against a stale entry that
> said it was still open). `git log --oneline -15` is the authority on what has
> landed; this file is the authority on WHY.

## ⮕ RESUME HERE (2026-09-21 — third M-1 round: narrations fold by MEMBERSHIP, `denied` guarded, the record fully marked, and the eviction tiers finally EXECUTED — `3dd23c4`)

**HEAD:** see `git log --oneline -8`. **Not pushed. Not deployed.**

**The review of `cdcafe4` found the claim wrong a third time.** `denied` was
unguarded and unlatched; alternated with junk `msg` (two constant lines,
never adjacent, so the CONSECUTIVE collapse never fired) 800 frames reached
the cap unprompted. The 25 marked lines survived; ~15 unmarked record lines
(owner-route admission, at-rest verdict, "key-change warnings are OFF",
key-confirmation failure, directory mismatch, "verified for this session
only") did not. And the eviction loop had been executed ZERO times by the
suite through two rounds of tiers. `3dd23c4` is structural: a narration (unkept
system line) folds by membership — an identical one anywhere in the
transcript is counted onto and moved to the end — so narration lines are
bounded by the number of distinct narration STRINGS whatever a relay
interleaves; `denied` is owner-only, latched, kept; 47 lines are marked and
the anchor binds the set from the other side (exactly four narrations:
the two junk refusals, the latched RSA refusal, the directory rate-limit
notice); every DOM write into #log is inside addLine (anchored); the stub's
appendChild moves like the DOM. **app-behaviour now executes all three
tiers**: the test becomes the AES256 peer (hello + key confirmation with the
known passphrase), the user sends 600 messages (tier 1: oldest "me" lines
go, every system line stays), reconnects with one-iteration PBKDF2 push
past the cap (tier 2: narrations go next, oldest first; tier 3: the oldest
record line goes, the newest stays, never frozen). 10 mutants RED, each
tier and the membership rule RED behaviourally AND by anchor. Client 310
OK, backend 182, `e2e:scenarios` 4/4. Report §9.4. **`3dd23c4` has had no
review yet.**

The lesson, stated once for the file: three rounds in a row the FIX was
right and the CLAIM around it was wider than the code — "every unprompted
line", "the record is marked", "unreachable from the stub". The reviewer
found each by executing the claim. Write the claim as a test first.

### ⬜ NEXT — in order

1. **⬜ Review `3dd23c4` with `pentest-new-code`** (the third fix round), fix
   what it finds.
2. **⬜ Decide push + Phase 8 deploy.** APK first, then relay + web client
   together (F-P7-8). Nothing here pushes.
3. **⬜ Phase 9 — Android on-device** (unchanged list + F-P7-17).
4. **⬜ F-P7-21** stays an owner decision (changes every displayed safety
   number).

## (2026-09-20, later — the M-1 fix's own review: "evict the newest" FROZE the transcript, a repeated `joined` reached the cap alone; fixed structurally in `cdcafe4`)

**HEAD:** see `git log --oneline -6`. **Not pushed. Not deployed.**

**The review of `d98f220` found a Medium IN THE FIX.** Flipping the eviction
fallback to the newest line froze the transcript (every later line, a
genuine refusal included, was destroyed on arrival), and the test's claim
that reaching the cap "needs the peer or the user" was false: the collapse
rule folds only CONSECUTIVE lines, and `joined` had no already-joined guard
— 300 repeated `joined` frames (two distinct lines each) hit the cap alone.
Lesson recorded for the next reader: a fix chosen on a premise the test
did not exercise is the same bug shape as the one it fixes. `cdcafe4`:
a repeated `joined` for the seat we hold is dropped; the 25 lines that are
the session's record are marked `keep` where written; eviction goes in
three tiers (oldest non-system, oldest unkept system, oldest record —
the last reachable only by the user's reconnects); `turned-away` is
owner-only; the peer-approval EXACT windows updated with the reason.
Also: the grid pin (an oversize record lands on 2× the target — a private
8192 inside export() was GREEN before), test-chain scans recursively and
names the integration files, persistIdentity stays writable for a valid
counter past int32 (isCount; it threw, and the ceiling branch would have
rewound to 0), README says `count` is not shown. 9 mutants RED (tier 2
unreachable from the stub — stated; the anchor holds it). Client 308 OK,
backend 182, `e2e:scenarios` 4/4. Report §9.3. **`cdcafe4` has had no
review yet.**

### ⬜ NEXT — in order

1. **⬜ Review `cdcafe4` with `pentest-new-code`** (the second fix round),
   fix what it finds.
2. **⬜ Decide push + Phase 8 deploy.** APK first, then relay + web client
   together (F-P7-8). Nothing here pushes.
3. **⬜ Phase 9 — Android on-device** (unchanged list + F-P7-17).
4. **⬜ F-P7-21** stays an owner decision (changes every displayed safety
   number).

## (2026-09-20 — the post-`4b9d2c6` delta reviewed: 1 Medium (a false claim, and a live flood), 3 Low, 4 Info — all fixed in `d98f220`)

**HEAD:** see `git log --oneline -4`. **Not pushed. Not deployed.**

**The review of `4b9d2c6..a88baa4` (`d09fe41` 7a + `cb84b7c`) found no
Critical/High.** Its Medium was the 7a test's own claim that "a hostile relay
can no longer reach the transcript cap at all": the `turned-away` arm
interpolated the relay's `count`, so nothing collapsed, and 1 200 thirty-byte
frames evicted "joined room" — the fallback took the OLDEST system line once
only system lines remained. Pre-existing since `dc182d7`; the claim was new.
Fixed in `d98f220`: the line is constant and latched once per connection; the
fallback evicts the NEWEST line; the flood is a behavioural test (RED against
the old code); the positive guest path `pending → knock → joined:guest` is
executed for the first time. Also fixed there: L-1 (`ONLY=nope` passed with
zero scenarios), L-2 (a relay that hung on start was never killed and held
PORT), L-3 (the exact-length pin let `PAD_TARGET` 8192/4096 through and the
overhead was one byte too many — the target is exported and pinned, the test
decrypts and measures), Info-1 (pad measured in UTF-8 bytes), Info-2 (judge()
normalises the counter once; isGen everywhere), Info-3 (the sweep says what
it proves), Info-4 (`test-chain.test.mjs`: every runnable test is in `npm
test`). 9 mutants RED, one stated GREEN (the eviction order is unreachable
from the stub without a peer; the anchor holds it). Client 306 OK, backend
182, `e2e:scenarios` 4/4. Recorded as §9.2 of the Phase-7 report.
**`d98f220` itself has had no review yet** — a fix is new code.

### ⬜ NEXT — in order

1. **⬜ Review `d98f220` with `pentest-new-code`** (the fix delta), fix what
   it finds.
2. **⬜ Decide push + Phase 8 deploy.** APK first, then relay + web client
   together (F-P7-8). Nothing here pushes.
3. **⬜ Phase 9 — Android on-device** (unchanged list + F-P7-17).
4. **⬜ F-P7-21** stays an owner decision (changes every displayed safety
   number).

## (2026-09-19 — the F-P7-20 false alarm corrected; the post-`4b9d2c6` delta goes to review)

**HEAD:** see `git log --oneline -4`. **Not pushed. Not deployed.**

**The uncommitted diff this session inherited was wrong.** It raised the
identity blob's padding target from 16 KiB to 20 KiB on the claim that the
record was "~16.4 KiB" and had "fallen through to a 512-byte grid". Measured:
the record is 13 353 bytes at its largest state; the 16 401 that cut saw was
16 384 of padded plaintext plus AES-GCM's 16-byte tag. `cb84b7c` reverts the
target to 16 KiB, keeps the two real improvements from that cut (an outgrown
record steps to the next MULTIPLE of the target, never a fine grid; the test
pins the EXACT sealed length at the largest reachable state), and records the
false alarm in the comment. 4 mutants RED (target below the record, 512-grid,
no padding, and the 20 KiB cut itself). Client exit 0 (303 OK), backend 182
passed.

### ⬜ NEXT — in order

1. **⬜ Review the delta `4b9d2c6..HEAD` with `pentest-new-code`** — `d09fe41`
   (7a: app.js executed, `e2e:scenarios`, the symmetric exhaustion rule) and
   `cb84b7c`. The two reviews launched at the end of 2026-09-16 left no
   report behind (scratchpads empty), so this delta has had NO agent review.
   Fix what it finds, re-review the fixes.
2. **⬜ Decide push + Phase 8 deploy.** APK first, then relay + web client
   together (F-P7-8). Nothing here pushes.
3. **⬜ Phase 9 — Android on-device** (unchanged list + F-P7-17).
4. **⬜ F-P7-21** stays an owner decision (changes every displayed safety
   number).

## (2026-09-16, night — the delta was reviewed, its 16 findings fixed, and the branch MERGED into master locally)

**HEAD:** `master` == `pentest-2026-08-07-fixes` after a local `--no-ff` merge
(see `git log --oneline -3`). **Not pushed. Not deployed.** Tree clean.

**The review of the delta (item 5 of the previous entry) found the mailbox
commit `018652d` did NOT do what it claimed** — 8 Medium / 6 Low / 2 Info, no
Critical/High. Every one is fixed in the last commit before the merge and
recorded, with resolutions, as §9 of `docs/pentests/secure-chat-pentest-2026-09-16.md`.
The short version: the first F-P7-1 fix's `mailbox_fetches` table was a
last-seen log at rest that nothing read, was bought back with one GET per
throwaway inbox, and deleted real mail on deploy day — it is GONE; the budget
is now bytes-first with a minimum envelope size and evict-oldest instead of a
relay-wide 503; the host ceiling is POST-only; `#log` eviction keeps system
lines and collapses repeats; the callee allow-list normalises `?.(`; the
ship-list test strips comments; the Kotlin raw string is pinned to `$config`
only; each view has its own hint element; `/api` is no longer behind the static
gate (closes F-P7-16 too).

Verification for the merge: client suite exit 0 (279 OK), backend **177
passed** (run with nothing on :8000), `crypto-tamper.mjs` **10 modes** green
(`msgflood` and `confirmpost` are new), `two-user-flow` 8/8, `no-dead-ends`
12/12, `room-admission` 13/13, `all-modes` 29/29 against a scratch relay
running the final backend. 7 review-fix mutants RED (one e2e mutant is GREEN
by construction: with repeats collapsed, a junk flood never reaches the cap,
so the eviction ORDER is pinned by the unit anchor only — noted).

### ⬜ NEXT — in order

1. **⬜ Decide push + Phase 8 deploy.** The order is settled: APK first, then
   relay + web client together (F-P7-8). Nothing here pushes.
2. **⬜ Phase 9 — Android on-device** (unchanged list + F-P7-17).
3. ✅ **7b — floors for the contact and chat witnesses (F-P7-6)** — landed
   after the merge (see `git log -1`): `client/store-floor.js` shared by
   contacts.js and chats.js; claim inside each store's AEAD; probe → store →
   witness → floor; a bad verdict resets TRUST (pins dropped, contacts
   "verify again", chat modes default) and heals rather than refusing; a fresh
   store after a wipe writes past the surviving slot; existing stores arm on
   their first unlock; warnings reach the transcript and the visible hint.
   `store-floor.test.mjs` (new), 10 mutants RED. **Reviewed by pentest-new-code
   after the commit: 2 High, 2 Medium, all fixed in the follow-up commit** —
   a slot parked at the int32 ceiling from the page realm let the catch-up
   carry the generation PAST it, after which the floor was silently never
   bumped again (now: the generation stops one below a parked slot, so it
   reads as a loud rollback on every open, as identity-store does); the
   verdict went through the writable `Number.isInteger` and failed OPEN (now
   `typeof` + int32 truncation only, the otp.js idiom, with a
   poisoned-primordial test); the first cut DROPPED every pin and every AES256
   secret on a bad verdict — fifty re-verifications and a lost shared
   passphrase from one process kill in the flush window, and with no tombstone
   the next arrival rendered as a benign first contact (now: pins are KEPT and
   marked `suspect`, `enterVerification` refuses to auto-unlock on a suspect
   pin and shows the loud "rolled back" prompt until an in-person check writes
   a fresh pin; chats keep modes and secrets and are told what a rollback can
   have undone). Six of the reviewer's mutants were green (floor raised before
   the write, claim lowered, chats catch-up/claim/arm-on-read untested,
   vouchedBy kept) — all RED now, 25 store-floor mutants in total.
   **Second review (of `1ee021b`): 1 High, 2 Medium, 2 Low, all fixed in the
   next commit.** The ceiling test was still one value late (a slot parked at
   MAX−1 let one honest write catch up, the store froze EQUAL to the slot and
   every later rollback among the frozen states read clean). The rule that
   survives any off-by-one: **a slot the store can never overtake is itself a
   permanent bad verdict ("exhausted")**, however it got there — no clamp (a
   clamp is a freeze), and identity-store.js gets the same rule (it had the
   same latent freeze). Chats now carry a durable `rollback` mark inside the
   AEAD (the one-shot warning let a deliberately rotated AES256 passphrase be
   silently reverted to its leaked predecessor); the chat view shows it until
   the next deliberate setMode; the warning names the secret. All store
   warnings are ONE hint (four back-to-back hint() calls kept only the last).
   The Users view names a rollback as a rollback, not as the H-01 migration.
   getPin returns a copy. Test gaps closed: table-driven ceiling over
   {MAX−2, MAX−1, MAX, MAX+1, 0x7fffffff} × both stores; `room:` pins; app.js's
   getPin wrapper + suspect predicate EXECUTED against a real rolled-back store
   (the first behavioural test of an app.js decision); chats' durable mark.
   11 more mutants RED (one equivalent: with the exhaustion verdict in place,
   the probe's own threshold no longer decides loudness).
4a. ✅ **7a — a behavioural test for app.js, and the browser harnesses in a
   runner.** `client/dom-stub.test.mjs` (a DOM stub: id lookups answered only
   for ids index.html really defines, a stub relay socket, seeded alg radios /
   nav items / locked-pane `<p>`s) plus `client/app-behaviour.test.mjs`, which
   IMPORTS app.js and drives it: init + the id control, the guest seat with no
   approval queue, the mid-session role change, an unrecognised role, the
   F-P7-7 latch, and a 600-frame junk flood against the security lines. **7
   mutants RED, including `wasPending ||= true`** — round 3's mutant, which
   beat the source allow-list at the time. Two of my own assertions were wrong
   and the mutants caught them: the transcript's repeat-collapse masks both the
   latch and the eviction rule, so the latch is now bound through the repeat
   COUNTER, and the test states plainly that a hostile relay can no longer
   reach the line cap at all (every line it can force unprompted is a constant
   string) **[FALSE — corrected 2026-09-20, `d98f220`: the `turned-away`
   line carried the relay's `count`; see the RESUME entry]** — eviction is second-line defence, pinned by the source anchor.
   `e2e/hostile-relay/run-scenarios.mjs` + `npm run e2e:scenarios` run all four
   role/directory scenarios unattended and pin the expected check COUNT; shown
   RED by reinstating the deleted item-14 route (exit 1, the harm in the
   client's own words). That closes F-P7-A2's fix (e).
4. **⬜ 7a — a behavioural `app.js` test** against a DOM stub; wire
   `proto001.mjs` + `crypto-tamper.mjs` + `room-admission.mjs` into an
   automated runner (`npm run e2e:tamper` exists; the rest still needs a relay).
5. ✅ **The Lows** (same commit as the second-review fixes): F-P7-10 (the
   relay re-reads admission on the timeout branch; an admitted guest gets the
   idle window), F-P7-11 (one vouch error string), F-P7-12 (413 above
   MAX_API_BODY_BYTES; 422s no longer echo the input), F-P7-13 (a loopback
   trusted proxy is refused at startup unless
   SECURE_CHAT_TRUSTED_PROXIES_ALLOW_LOOPBACK=1), F-P7-15 (h11's per-request
   "Invalid HTTP request" line is filtered), F-P7-20 (the identity blob is
   padded to a FIXED 16 KiB, so its length is the same in every sealed
   state), F-P7-22 (the sealed sender bundle is canonicalised). Each with a
   test and a RED mutant. **F-P7-21 stays open on purpose:** digesting each
   bundle before concatenating changes every displayed safety number — a
   version decision for the owner, not exploitable at HEAD.

## ⮕ (2026-09-16, evening — Phase 7's fix list items 1-4 LANDED; next: review the delta, then merge)

**HEAD:** see `git log --oneline -6` (this file is written before the last
commit of the batch; the four fix commits are `1d240d0` item 1, `6695cf1`
item 2, `018652d` item 3, and item 4 lands with this entry). Tree clean apart
from the untracked session `.claude/launch.json`. Not pushed, not merged, not
deployed.

**What landed today, after the Phase-7 report `32fabaf`:**

1. ✅ **Item 1 — the assurance gaps (F-P7-A1..A6, A8)** `1d240d0`. Every
   unpinned control now has a test shown to bind (21 mutants RED): each
   signature half of `Identity.verify`; the P-03 transcript binding;
   `RATCHET_MAX_SKIP === 64` and enforced at exactly 64; `MAX_PEER_CONFIRMS
   === 2` (the cap test had imported the constant it tested); both OTP
   spent-keystream guards; `maxOf` without `Math.max`; `padWasUsed`'s
   recv/exported evidence; `probeFloors`' create-side COMMIT_FAILED; an exact
   six-writer allow-list for `approvedBundle` and a callee allow-list for
   `renderPeerApproval`; canonical base64 on `ecdh`/`mlkem` in the relay; the
   Kotlin anchors (unconditional flag, no clearFlags, `secret` pinned, WebView
   settings, single bridge, debug-only devtools, CSP, both defineProperty
   descriptors; the Kotlin after the raw string is scanned too). NEW HARNESS:
   `e2e/hostile-relay/tamper.mjs` + `crypto-tamper.mjs` — a relay that attacks
   the key material (keysub, idbswap, idbstrip, ctflip, msgreplay, confirmpre,
   algflood) with two real browsers asserting the shipped client's response.
   All eight modes pass.
2. ✅ **Item 2 — the one-liners (F-P7-5, F-P7-19, F-P7-7)** `6695cf1`. The OTP
   adoption gate and its migration rewrite ask the AEAD (`inner.hwSend`), not
   the outer `v` byte; `onPeerTag` ignores tags that arrive before the chains
   exist and the overflow names the relay; the deprecated-alg refusal is said
   once per connection and `#log` is bounded at 500 lines. 6 mutants RED, three
   of them also in the browser harness.
3. ✅ **Item 3 — directory/mailbox availability (F-P7-1..4)** `018652d`. Fetch
   bucket per authenticated user after auth (+ the client says 429 once);
   global post ceiling charged after the token gate; lookup bucket per TARGET
   after the gate (per voucher for POST /vouch); mailbox budget in BYTES
   (256 MiB / 8 MiB per inbox) with a 24 h TTL for inboxes that have never
   fetched (new `mailbox_fetches` table). Per-host ceilings remain only as
   documented backstops. 8 mutants RED; the two XFF tests now probe the /api
   ceiling.
4. ✅ **Item 4 — before-deploy (F-P7-8, F-P7-9, F-P7-18)** (this commit). The
   skew claim in item 8 below is corrected (APK first, then relay); `hint()`
   routes by VIEW first (`views.test.mjs`, new); `test-source.mjs` and
   `vendor/README.md` are on all three ship lists and
   `test_the_three_ship_lists_agree` pins that they stay in step.

### ⬜ NEXT — in order

5. **⬜ Review the delta `32fabaf..HEAD` with `pentest-new-code`** (a fix is
   new code; four commits of it), fix what it finds, then **merge into master**
   (local merge only — no push, no deploy). The report's own recommendation:
   merging is defensible now.
6. **⬜ Phase 8 — deploy.** See item 8 in the previous entry (corrected) for
   the order: APK first, then relay + web client together.
7. **⬜ Phase 9 — Android on-device** (unchanged list, plus F-P7-17: the
   alert/confirm dialogs still have no FLAG_SECURE of their own — Low, not
   fixed, needs a device to judge).
8. **⬜ 7a/7b** — a behavioural `app.js` test (four rounds of regex anchors
   over `app.js` have each been walked past once); floors for the contact and
   chat witnesses (F-P7-6, the one remaining runtime Medium, deliberately left
   for its own commit).
9. **⬜ Lows not yet fixed from the report:** F-P7-10 (relay timeout snapshot),
   F-P7-11 (vouch error strings), F-P7-12 (body size cap), F-P7-13 (loopback
   trusted-proxy warning), F-P7-15 (h11 log lines), F-P7-16 (static gate on
   /api), F-P7-20 (identity blob length oracle), F-P7-21/22 (Info).

**One more ceiling round (2026-09-16, night).** The review agent for `4b9d2c6`
STALLED mid-run (watchdog, no progress for 600s) and left its sweep harness in
the tree. Running it was worth more than the report would have been: it found
that the exhaustion rule covered only the SLOT side. A store whose OWN counter
is past `MAX_GENERATION` is frozen too — `armStoreFloor` then refuses, the slot
stays below it, `f > gen` is never true, and every rollback among the frozen
states reads CLEAN. Fixed symmetrically in `store-floor.js` AND
`identity-store.js`, and the sweep itself is now a permanent test
(`testNoStateIsFrozenAndClean`, an exhaustive slot × generation table asserting
"frozen ⇒ not clean", with three controls so it cannot pass vacuously).
3 mutants RED. **The delta since `4b9d2c6` has had no agent review yet.**

**Environment trap (2026-09-16, evening):** the backend suite HANGS past 10
minutes when a relay is listening on 127.0.0.1:8000 (`tests/test_static_hardening.py`
and `smoke_client.py` reference it). Stop any dev relay before `pytest -q tests`;
with the port free the suite takes ~25 s.

## ⮕ (2026-09-16, later — Phase 7 DONE: whole-branch pentest reported; next is fixing its list, then merge)

**HEAD: `ea0dcba`** plus two UNCOMMITTED files: `docs/pentests/secure-chat-pentest-2026-09-16.md`
(the Phase 7 report) and this entry + a README table row. Left uncommitted on purpose
(the pentest brief's ROE: leave the tree for the author unless asked). Tree otherwise
clean; all lane mutants were restored byte-identically and the branch code is exactly
`ea0dcba`.

**Phase 7 result, in one line:** no Critical, no High at runtime; the E2EE, admission,
directory-counter, dual-scheme-login and identity-anti-rollback promises all held under
five parallel lanes with real traffic. What did not hold: the test estate (1 High + 4
Medium assurance gaps — deleting the ML-DSA half of `Identity.verify` AND the P-03
transcript binding AND both ratchet caps AND both OTP spent-keystream guards keeps all 16
test files and `all-modes` green), four directory/mailbox availability holes (row-counted
mailbox budget; three host-keyed buckets charged before auth / before the 404), the OTP
adoption gate keyed on the outer `v` byte (browser two-time pad, pre-existing), the
contact/chat witnesses without a floor (7b), the new RSA refusal as a DOM flood, an
inverted skew claim in THIS FILE's earlier entry (an old APK cannot log in to the new
relay, so it never receives sealed mail), and the mail warning rendered into a hidden
node off the Live view. 34 findings, 28 reproduced by the lead. Full detail, code paths,
PoC outputs and the fix list: `docs/pentests/secure-chat-pentest-2026-09-16.md` §3-§4;
priorities §8.

### ⬜ NEXT — in order (from the report's §8)

1. **⬜ Pin the crypto and the floor verdict (F-P7-A1, A3, A2, A4, A5).** Dual-signature
   and transcript tests; literal checks for `RATCHET_MAX_SKIP`/`MAX_PEER_CONFIRMS`; both
   OTP spent-keystream guards; `maxOf` / `padWasUsed` / `probeFloors` create-side;
   `approvedBundle` writer allow-list; `_respell` on `ecdh`/`mlkem`; Kotlin anchors for
   the WebView settings, the bridge surface and the two `defineProperty` descriptors.
   Adopt lane B2's key-tampering relay into `e2e/hostile-relay/`.
2. **⬜ Two one-liners:** OTP adoption gate on `inner.hwSend` not `o.v` (F-P7-5);
   `if (!confirmation) return false;` in `onPeerTag` (F-P7-19). Then latch the RSA
   refusal and cap `#log` (F-P7-7).
3. **⬜ Directory/mailbox availability (F-P7-1..4):** byte budget with per-account
   fairness; per-user fetch bucket after auth; per-user lookup bucket; 404 before the
   global post bucket; surface 429 in `pollMailbox`.
4. **⬜ Before deploy:** correct the skew note (item 8 below was WRONG: the legacy body
   sniff is in the NEW client; an old APK gets 401 on `/auth/verify` forever) and decide
   APK-first order or a sunset flag (F-P7-8); route `hint()` by VIEW (F-P7-9); drop
   `client/test-source.mjs` + `vendor/README.md` from all three ship lists (F-P7-18).
5. **⬜ Then merge** — the report's recommendation: merging is defensible now (nothing
   is worse than master); deploying is not until 2-4 are done.
6. **⬜ Phase 8 deploy, Phase 9 Android on-device** (unchanged; the device list grows by
   the identity floor slot, the dialog FLAG_SECURE gaps F-P7-17, and the crash-window
   premise).
7. **⬜ 7a/7b as before** (behavioural `app.js` test; contact/chat witness floors — now
   also F-P7-6).

## ⮕ (2026-09-16 — F-ATREST-008 closed; plan items 1-6 all landed; next is Phase 7)

**HEAD: `bd696b1`** on `pentest-2026-08-07-fixes`. Tree clean. Not pushed, not
merged, not deployed. Client suite **256 OK / exit 0** (15 of those new this
session), backend **168 passed**. Browser smoke of the real client against a
scratch relay: create identity → reload → unlock, same fingerprint, no console
errors, no at-rest warning. Android `assembleDebug` NOT re-run this session
(the only Kotlin change is a doc comment in `PadFloor.kt`).

**The 2026-08-21 entry below went stale by nine commits** — exactly the trap its
own preamble warns about. Its items 1-5 are all DONE; the record of what landed is
in `git log fc712ad..7e5c3af` and summarised here so nobody re-does them:

* ✅ **Item 1, the owed Phase-2 pentest gate** → ran as ROUND-3. Four fixes:
  `902ed8c` F-1 HIGH (a frozen native floor must fail the SAVE, not the pad —
  armFloors verifies its read-back covers the sealed watermark), `782c755` F-3
  (the swept-pin alarm follows the peer's identity, not the `room:<id>` label),
  `01ffbf1` F-2+F-6 (receive path persists BEFORE display; `withWriteLock`'s
  timeout only reports, never releases), `2eb2ea5` F-4 (Android `commit()`
  false → `COMMIT_FAILED` sentinel → the save fails; F-A3's third claim value is
  finally reachable through the real bridge).
* ✅ **Item 2, `SCENARIO=directory` binds** → `7190aff`: `CLIENT_ROOT` override;
  shipped client 13/13, item-14 mutant 4/13 with the harm in the log.
* ✅ **Item 3, Phase 3 client** → `49f1bf0`: the counter retry resyncs to the
  server's echoed `stored_seq + 1` (never believed on sight), `err.code`
  branching, legacy body sniff kept as fallback, 200-char clamp on the relay's
  message. Its own tests were found NOT RUNNING (an un-restored stub) and fixed.
* ✅ **Item 4, Phase 4** → `630c92f` (was already ✅ in the old entry).
* ✅ **Item 5, Phase 5 test debt** → `7e5c3af`: every "green against deletion"
  gate is mutation-bound; three independent reviewers (hot, cold, pentest); and
  it uncovered a LIVE bug — `savePin` cleared the swept-pin tombstone by key
  alone, ignoring the bundle, which let an unrelated verification under a
  recycled `room:<id>` silence the victim's alarm in every room. Fixed there.
* ✅ **Item 6, F-ATREST-008** → `bd696b1` (this session, below).

### What landed this session — F-ATREST-008, the identity blob's anti-rollback control

The finding: the F-ATREST-003/004 anchor lives inside the identity's AEAD, and
the fix review (F4) had already withdrawn the claim that this made it
undeletable — the attacker restores an OLDER `sc.identity.v1` (one `setItem`),
which opens on the same passphrase, carries no `flags`, and every anchor reads
"not established", so `contacts.unlock()` takes its first-run path and hands out
an empty, pin-less store. Every pre-fix blob is that copy.

The fix, same shape as the OTP watermark and the contacts witness:

* `identity.js` carries `generation` (monotone integer) and `floorClaim`
  (`true` / `false` / `"unconfirmed"`, the A4/F-A3 triple) inside the AEAD.
  Absent or malformed reads as 0 / `"unconfirmed"` — the OLDEST value and a
  claim of nothing, so a bad field can only make a blob look older, never newer.
* New **`client/identity-store.js`** owns every write (`persistIdentity`: probe
  the floor slot with `bump(_, 0)` → `gen = max(memory, floor) + 1` → export →
  `setItem` → bump the floor; floor never ahead of a blob on disk except through
  the async WebView flush, which is reported, never fatal) and every open
  (`openIdentity` → `judge` → verdict `ok | rollback | deleted | tampered |
  unavailable`, plus `arm`). `anchorEstablished(identity, flag)` answers `true`
  under EVERY non-ok verdict AND sets the flag, so the heal write app.js
  triggers right after installing the anchors carries the conservative answer —
  otherwise the attacker needs two unlocks instead of one.
* **The floor is captured at module load from otp.js and there is no setter**
  (round-1 F-9: the first cut's `setIdentityFloor`/`_resetForTests` shipped in
  the APK as an off switch). Tests that need a different load-time state spawn
  a fresh node process. Exports are pinned to an exact inventory.
* **`arm`**: a clean verdict with no slot (or a blob that does not claim an
  armed one) makes app.js write once — this is what arms EXISTING installs on
  their first unlock after the update (round-1 F-1, High: without it a v3 blob
  with both flags set never wrote, never created its slot, and the finding was
  reopened unchanged on exactly the deployed population).
* On Android the floor is the existing Keystore-MACed `PadFloor` via a new
  `otp.deviceFloor()` export — a fresh FACADE per call closing over the private
  bridge (round-1 F-2, High: the first cut returned the object itself, and
  `deviceFloor().read = () => -1` disabled the identity guard AND `padWasUsed`
  — a two-time pad one hop downstream of the frozen bridge). Slot
  `sc.identity.v1#gen`. **No Kotlin change**: slots are opaque strings and the
  MAC covers key+value.
* A claim is NEVER LOWERED (round-1 F-3): ARMED is carried through a session
  that cannot measure the floor; a plain browser keeps what the blob had; a
  broken bridge writes `"unconfirmed"`. A TAMPERED slot is a warning plus an
  unconfirmed claim on write, not a throw (round-1 F-6: throwing made a device
  with one forged prefs entry unable to CREATE an identity — a regression on
  plain `setItem`).
* The verdict is shown in a new every-view banner (`#atRestWarning`, outside the
  view sections) as well as the Live-room status row and the transcript
  (round-1 F-7: the per-view unlock rows hide themselves on success, so an
  unlock from Profile/Users/Chats showed nothing).
* **A bad verdict does NOT refuse the unlock.** The keys are the same in every
  version of the blob; what a rollback buys is the flags reading false, and
  only that. So the anchors fail closed, the user gets one warning in the
  status row and the transcript, and the re-write converges the counter. A
  refusal would turn the non-adversarial case (process kill in the seconds
  between `setItem` and the async localStorage flush, with the synchronous
  prefs `commit()` already landed → floor one ahead of the blob) into a
  permanent lock-out from the user's own keys.
* `app.js` is pinned to ZERO direct `setItem(LS_IDENTITY…)` / `identity.export(`
  calls and to reading the anchor only through `anchorEstablished`; the anchors
  must be installed BEFORE the heal write (source anchors via `liftFunction`).
* Plain browser: no floor, the residual stands, exactly as for OTP. Documented
  in `docs/security-history.md`.

**Binding proofs run by hand — 22 mutants, all RED:** rollback-by-one tolerated;
conservative answer not committed to the flags; `import` ignores `gen`; `export`
drops `gen`; app.js reads the flag directly; no heal write on a bad verdict;
deletion never reported; generation ignores the floor (stale tab alarms); failed
create still claims ARMED; unknown claim reads as armed; broken floor reads as no
floor; tampered floor reads ok; `judge` never asks to arm; heal condition
without `arm`; `deviceFloor` returns the shared object; claim lowered to NONE;
TAMPERED throws again; flag committed only under `rollback` (round-1 mutant A);
a second `setStoreAnchor` after `installStoreAnchor` (mutant B); heal write via
`Identity.prototype.export` + aliased key (mutant K); banner never shown; a
floor setter exported.

**Pentest of this change, ROUND 1** (agent, full context): 2 High (F-1 never
arms on an existing install; F-2 mutable `deviceFloor()`), 4 Medium (F-3 claim
lowered; F-4 root picks the blob — RESIDUAL, documented in identity-store.js and
security-history; F-5 the app.js anchors were presence-only regexes and three
mutants stayed green; F-6 TAMPERED brick on create), 3 Low/Info (F-7 verdict
invisible off the Live room; F-8 flags last-writer-wins across tabs —
pre-existing, DEFERRED: the fix is to mirror the one-shot flags into floor slots
of their own; F-9 exported off switch). All but F-4/F-8 fixed as above; the
app.js anchors are now allow-lists over `referencesOf()` hits bounded to
`liftFunction` line ranges, and every round-1 mutant is RED.

**ROUND 2** (the re-fix is new code): the rollback control itself held against
nine same-realm attacks (namespace reassignment, defineProperty, swapping or
deleting the bridge global after load, mutating a handed-out facade, prototype
pollution of `broken`, poisoning `Number.isInteger` / `Math.max` / `parseInt`).
Findings, all addressed: **F-1 High (assurance)** — the app.js anchors bound
spellings, not bindings: `contacts["setStoreAnchor"]`, a renamed destructure, a
shadowing `const idstore = {…}` that left the anchored line byte-identical, and
an early `return` before the anchors all stayed green (the fourth mutant is the
lock-out the module's own header rules out). Now: no bracket/computed access on
the bound modules or storage, no reflection/enumeration/spread over them, no
re-declaration or parameter shadowing, every use of `contacts`/`chats`/`idstore`
is a plain member expression (strings stripped first), `idstore.` is limited to
its four members, and `unlockWithPassphrase` has exactly two returns after
`openIdentity`. **This is still a regex arms race** — see NEXT item 7a.
**F-2 Medium (regression)** — the forced anchor is LATCHED into the AEAD by the
heal write, and when no store exists (the attacker's deletion, or the same
unflushed first write that lost the blob in the crash window) the contact store
refused to open on every later unlock with "forget the identity" as the only
recovery; HEAD gave a silent fresh store. The two states are identical on disk,
so no policy can separate them: **a consent gate**, as for OTP adoption —
`contacts.unlock(pass, {startFresh})` / `chats.unlock(…)` skip exactly the
deletion check; app.js offers "Start over with an empty … store" only behind
the `STORE_DELETED` alarm, behind a `confirm()` that says an attacker would want
exactly this, armed for one unlock attempt and disarmed in a `finally`. The
deletion throws now carry `code: "STORE_DELETED"`. **F-3 Low** — a page-realm
`bump` on the frozen bridge could park the identity slot at the int32 ceiling
and `persistIdentity` then threw forever (no identity could be CREATED): now a
warning + unconfirmed claim, the parked slot reads as a rollback (fail closed,
identity usable). **F-4 Low** — `importPad` never validated `padId`, so a pad
FILE could name the identity's slot (and vice versa; no fail-open, bump never
lowers): now `/^[0-9a-f]{32}$/`. **F-5 Info** — an unrecognised negative floor
answer fell through to a clean verdict: now every negative except ABSENT is
evidence. Verified sound by round 2: `arm` creates no loop/brick/downgrade;
never-lower-a-claim cannot become a permanent false alarm (app→browser→app,
second device, forget+create all traced); ARMED→unconfirmed downgrade
impossible; both deploy paths exclude the new helper test file.

**Binding proofs after round 2 — 18 more mutants, all RED** (the four round-2
green ones B′/M2/M3/M4 plus alias, enumeration, ceiling throw, padId
unvalidated, unknown negative, `startFresh` ignored in each store, codes
dropped, consent without confirm / never disarmed / written from
`unlockContacts` / always true, button always visible, banner kept on forget),
and the 22 earlier ones re-run RED against the grown test. Client **262 OK /
exit 0**, backend **168 passed**.

**ROUND 3** (the consent gate is new code): no High. The consent gate held —
`freshStoreConsent` is a module-scope const with no export or global handle;
`go()` always settles so the `finally` always disarms; `startFresh` is read
only inside the no-store branch, so it never skips the CAS, `assertNotRolledBack`,
the H-2 domain tag or legacy adoption; and **the surviving-witness case holds**
(a consented fresh start draws a new salt, so the old witness reads `corrupt`,
the CAS skips it, and `writeWitness` overwrites it — traced and PoC'd in both
stores). Findings, all addressed: **F-1 Medium** — the round-2 ceiling fix was
off by one: a slot parked at MAX−1 let one honest write stamp MAX into the blob
and every later write threw, with a CLEAN verdict (no banner). Now the blob is
ALWAYS writable: at the ceiling it is written at its own counter, never
advanced, never refused; boundary tests at 0x7fffffff, MAX, MAX−1, MAX−2 over
four consecutive writes. **F-2 Medium (assurance)** — four more green mutants:
`if (verdict.ok) installStoreAnchor(pass)` (reopens the finding outright),
self-consent via `freshStoreConsent["contacts"] = true` inside `unlockContacts`,
a non-literal consent write in `refreshUsers`, cross-wired consent (two
unbackreferenced alternations), and a shadowed `confirm`. Now: the anchor call
is pinned as an unconditional own statement; consent assignments are counted as
every `=` after the identifier in any spelling; `\1` backreferences; `confirm`
and `freshStoreConsent` in the no-re-declaration and no-parameter lists.
**F-3 Low/Med** — `chatsError` was write-only, so the Chats pane showed a red
"Start over" button under a routine "enter your passphrase" line, and the
confirm named the contacts cost for the chat store: the pane now renders its
alarm like the Users pane and each button carries its own cost sentence.
**F-4 Info** — the write side now folds unknown negatives like `judge`.
Also fixed from its coverage notes: the arrow-parameter rule ran on
string-intact source and tripped on a harmless default-string parameter (now
on string-stripped source, with a GREEN control mutant proving it).

**Binding proofs after round 3 — 11 mutants RED + 1 control GREEN**, client
**262 OK / exit 0**. **Browser end-to-end of the gate**, against the scratch
relay: contact store + witness deleted → unlock → Users pane shows the BOTH-
deleted alarm and the red button → click → confirm text as designed → store
recreated, transcript line "started over EMPTY at your request", pane unlocked.
No console errors. **The round-3 re-fix (ceiling arithmetic, chats pane text,
anchor rules) has had no agent review of its own** — it is covered by the
mutants above and will be covered by Phase 7's whole-branch pentest.

**Environment trap (2026-09-16):** do not run the backend suite while a
pentest agent is running `npm test` on the same box. Under that contention the
suite took 15 min instead of 22 s and `tests/test_ws.py::test_one_knock_per_socket`
failed with `approval timeout` instead of `already knocked` (a timing test);
alone it passes in 0.2 s and `backend/` is untouched by this change.

### ⬜ NEXT — in order

7a. **⬜ A behavioural test for app.js's identity/anchor wiring.** Three rounds
   of source anchors over `app.js` for this one change (and three rounds for
   item 14 before it) each fell to a spelling the previous round did not name.
   The durable control is to import the real `app.js` against a DOM stub
   (`document`, `localStorage`, `confirm`, `navigator`) and drive
   `unlockWithPassphrase` end to end: rolled-back blob → anchors established →
   contact store refuses → consent → fresh store. Until then every regex rule in
   `identity-store.test.mjs` §(4)/(5) is a named-mutant control, not a proof.
7b. **⬜ Mirror the one-shot anchor flags into floor slots of their own**
   (round-1 F-8): the generation converges across tabs but the flags are
   last-writer-wins, and the counter now certifies the losing blob as current.
7. **⬜ Phase 7 — pentest the WHOLE branch (`master..pentest-2026-08-07-fixes`),
   then merge.** Every commit on the branch has had its own review; nothing has
   yet reviewed the branch as a whole for interactions between fixes (e.g. the
   identity heal write vs. the contacts CAS, or `padWasUsed` after ROUND-3).
8. **⬜ Phase 8 — deploy.** Relay + web client ship together (`register/v3`,
   dual-scheme `/auth/verify`, the 409 body all refuse older clients). The
   Android APK bundles the client and updates independently, and **an old APK
   does NOT keep working against the new relay** (F-P7-8 corrected the earlier
   claim here: `account.js`'s legacy body sniff is in the NEW client and handles
   an OLD relay's 409): it registers, but `/auth/verify` is dual-scheme and the
   old client never sends `mldsa_sig`, so it gets 401 forever, never mints a
   session, and never receives sealed mail (queued mail expires after 14 d;
   Live rooms still work). **Order: ship the APK first, then the relay** — or
   accept `mldsa_sig`-less verify for one release behind an explicit sunset
   flag. Measured matrix in the 2026-09-16 report §3.9.
9. **⬜ Phase 9 — Android on-device.** Recents snapshot blank; the password
   prompt not capturable (`5c8dbcf`, UNVERIFIED on hardware); PadFloor proof;
   ROUND-3 F-4's `commit()` semantics; and now the identity floor slot
   (`sc.identity.v1#gen` appears in `secure_chat_pad_floors` after the first
   unlock, and a restored older WebView `sc.identity.v1` produces the "OLDER
   than this device's record" warning with the contact store still opening).
   No device was attached on 2026-09-16 either.

## ⮕ (2026-08-21 — working the approved completion plan; 8 commits landed)

**HEAD: `5c8dbcf`** on `pentest-2026-08-07-fixes`. Tree clean. Not pushed, not
merged, not deployed. Client suite **221 OK / exit 0**, backend **168 passed**,
hostile-relay `SCENARIO=directory` **13/13**.

Working from a user-approved plan (phases 0-9). Three decisions were taken by the
user on 2026-08-21 and are now settled:

* **`/api/register`'s 409 echoes the stored `reg_seq`.** Approved as a wire change.
* **Peer-chosen RSA key transport is to be DEPRECATED** (F-CRYPTO-009), rather
  than adding a third handshake frame.
* **Scope of "finished" = fixes + merge + deploy + an Android on-device pass.**
  Lock-on-background (B5) is explicitly OUT. The anchor/restore design (B6) stays
  deferred until a restore feature exists.

### What landed (newest first)

* `5c8dbcf` **android** — the `window.prompt()` password dialog now sets its OWN
  `FLAG_SECURE`. A Dialog has its own Window and FLAG_SECURE marks a surface, so
  the Activity's flag never covered it: a capture during the passphrase prompt
  blacked out the activity and rendered the dialog legibly. Answers the open
  question in §C10. **Also: the build is not broken** — `assembleDebug` succeeds
  with JDK 21; the recorded breakage was the system default being a JDK 25 EA.
* `ac36381` **Phase 6, item 8** — the hostile relay now serves a DIRECTORY
  (`/api/register`, `/api/users/<name>`, auth/session, empty mailbox) behind
  `DIRECTORY=honest|hostile`, plus `SCENARIO=directory`. Item 14 is visible end to
  end for the first time: the directory names "bob", hands over the keys of the
  peer that actually connects, and the client must still prompt. 13/13.
  `EVIL_MODE=none` + `SCENARIO=attacker` now refuses to run instead of reporting
  a meaningless 9/9.
* `ea4afe9` **Phase 3 (backend)** — the three 409s carry `error` codes
  (`username_taken`, `stale_counter`, `keys_locked`); `stale_counter` echoes
  `stored_seq`. Reachable only after both ownership signatures verified AND the
  stored row's keys matched, i.e. only the owner learns it. 3 tests pin that.
* `7a0f6e3`, `7b1a933`, `c86fb74`, `08a20ef`, `ee13fdc` **Phase 2** — small
  residuals (regseq output guard, `withWriteLock` timeout, stale prose); F-A3
  ("arming failed" told apart from "never armed"); F-A2-R1 (the revocation marker
  is now a TOMBSTONE on the pin key, not a contact record); F-A1-R1 (a probe-only
  floor triple is no longer evidence of use, so an interrupted first save no
  longer burns the padId); F-5 (the pad index is written right after the blob —
  writing it last burned padIds, a regression `fc566dd` had shipped).
* `568d3e3`, `f47c0df` **Phase 1** — the item-14 source controls now BIND. New
  `client/test-source.mjs` replaces three inline prefix-filters with a real
  comment scanner (knows strings, template literals, regex literals, nested
  `${}`), a brace-matching `liftFunction` that asserts exactly one definition, and
  a `referencesOf` allow-list. `describeIdentity` no longer returns a `mismatch`
  boolean — it writes the prompt DOM and returns nothing, deleting the laundering
  channel rather than naming it. `EXPECTED_WINDOW` now runs from the top of the
  key-frame branch THROUGH the approval-gate body.
  **The pentest of `f47c0df` found a High and it is fixed in `568d3e3`:** the
  window ended AT the gate line, so the gate's body was unpinned and both a
  blanket `approvedBundle = idbCanon` and item 14 rebuilt via `expectedPeerName`
  passed 207/207. Both are RED now, as are an alias mutant and a regex-hiding
  mutant.
* `ccd7ffb` **docs** — reports moved to `docs/pentests/`, security history split
  out of the README.

### ⬜ NEXT — in order

1. **⬜ The Phase-2 pentest gate is still OWED.** The agent reviewing
   `568d3e3..7a0f6e3` was interrupted twice (once by a session limit) and has not
   reported. Do not treat those five commits as reviewed. The highest-risk change
   in them is **F-A1-R1, because it LOOSENS `padWasUsed`** — the guard against
   one-time-pad reuse. Anything that makes a genuinely-consumed pad re-importable
   at offset 0 reopens H-3 and is a Critical.
2. **⬜ Prove `SCENARIO=directory` BINDS.** Install the item-14 route as a mutant
   in `app.js` and confirm the scenario goes RED. Until that is shown, 13/13 is
   not evidence — this project has produced three rounds of green-but-vacuous
   controls and the harness is not exempt from the rule.
3. **⬜ Phase 3, client half** — retry on `stored_seq + 1` instead of jumping to
   `now + SLACK`; never re-send a refused value; stop reporting a counter 409 as
   "username already taken" (`app.js:740-742`); replace `app.js:537`'s
   `.catch(() => {})` with a visible warning. Then the `regseq.test.mjs` rework:
   the M-1 test opens with `reset()` so it only ever exercises the fresh state and
   passes while the bug it names is live; add `Date.now` stubs (no test stubs the
   clock today, in the lane whose whole subject is clock skew).
4. **✅ Phase 4 — RSA key transport REMOVED** (2026-08-21, F-CRYPTO-009). Two
   premises of the original plan were wrong and were dropped: `UNAVAILABLE` was
   not a mechanism (dead export, read nowhere, comment claiming a UI-disable that
   did not exist) — it is deleted and replaced by `DEPRECATED_ALGS`, which
   `makeCipher` actually consumes; and there is no inbound live-room "mode
   change" to refuse — the mode is chosen 100% locally and `alg` on the wire is
   advisory, never read to pick a cipher (a visible refusal for a frame TAGGED
   `alg:"RSA"` was added anyway, as a backstop). The `Rsa` class,
   `assertRsaPublicKeyUsable`, the `RSA_*` constants and the prime sieve are
   deleted (with a tombstone recording the finding); the UI card is gone;
   `all-modes.mjs` exercises 4 modes and asserts the deprecation + an exhaustive
   mode inventory; `rsa-keyvalidation.test.mjs` → `rsa-deprecation.test.mjs`.
5. **⬜ Phase 5 — the rest of the test debt** (item 7 and §C9).
6. **⬜ F-ATREST-008** — the identity blob has no anti-rollback control, and the
   contacts anchor is load-bearing on it: the anchor is defeated by ROLLING BACK
   the identity blob rather than deleting it, and every pre-fix blob has no
   `flags` field at all, so today's blob on every device is the archived artifact.
   Needs a monotone generation inside the blob's AEAD mirrored into the native
   floor (that plumbing lives in `otp.js` and would want extracting).
7. **⬜ Phase 7** — pentest the WHOLE branch, then merge.
8. **⬜ Phase 8** — deploy (relay + client ship together; `register/v3`,
   dual-scheme `/auth/verify` and now the 409 body all refuse older clients).
9. **⬜ Phase 9** — Android on-device: recents snapshot blank, the password prompt
   not capturable (the fix in `5c8dbcf` is UNVERIFIED on hardware), PadFloor proof.
   No device was attached on 2026-08-21.

## ⮕ (2026-08-15 — A4's 3 Highs fixed in CODE; the item-14 TEST control still does not bind — 3 new Highs)

**Committed: `fc566dd`.** Working tree CLEAN. Not pushed, not merged, not
deployed. `master` is still 1 commit ahead of `origin/master` from an earlier
session. `backend/accounts.db` untouched.

**Read this before anything else.** `pentest-new-code` was run TWICE this
session, and the second run is the one that matters.

* **Round 1** reviewed the three fixes. It broke the H-1 fix, correctly. I
  reproduced its mutant, re-fixed, and every mutant it named went red.
* **Round 2** reviewed the re-fix — the part written *after* round 1 finished,
  which nothing had reviewed. **It found 3 more Highs and installed 5 mutants
  that restore the item-14 directory skip and pass the suite 195/195.** I
  verified the cheapest two by hand before accepting them; both reproduce
  exactly.

So: **A4 items 1 and 2 are genuinely fixed in the runtime code. Item 3 is NOT.**
Three attempts at pinning it have each produced a green control that does not
bind. The runtime code in `fc566dd` is not itself vulnerable — `peerAlreadyTrusted`
and the call site are correct as committed — but nothing stops a future commit
from reintroducing the route, which is the entire job item 3 exists to do.

**The pattern is now the finding.** Source-anchored tests over `app.js` (which
cannot be imported — it touches `document` at module scope) have failed three
rounds running, each time passing while the property was gone. A fourth, sharper
regex is probably the wrong move. See item 1 below.

### ⬜ NEXT SESSION — do these in order

1. **⬜ ROUND-2/F-1 + F-2 (High, together) — the "comment stripper" is a prefix
   test, and `lift()` never uses it.** Two independent holes that make every new
   source-level check in all three test files bypassable:
   - `codeOnly()` (`peer-approval.test.mjs:40-43`, plus inline copies at
     `contacts-anchor.test.mjs:459-460` and `otp-rollback.test.mjs:1263-1264`)
     drops any line whose trim starts with `/*`. **`/**/ statement;` is
     executable JavaScript that satisfies that test.** Verified by hand:
     `/**/ if (expectedPeerBundle && sameBundle(expectedPeerBundle, idbCanon))
     approvedBundle = idbCanon;` is filtered out as a comment *and* executes and
     assigns. One 4-character prefix defeats `EXPECTED_WINDOW`, the whole-file
     `expectedPeerBundle` allow-list, the `describeIdentity` caller walk, and both
     app.js anchors — including the F-A1 export-order check, where the mutant
     hands the pad file over before the latch.
   - `lift()` (`peer-approval.test.mjs:19-31`) does `src.indexOf("function
     <name>(")` on **raw source**; `codeOnly` is applied only to its *output*, so
     it can never undo a bad anchor. A `/* … */` block containing a decoy copy of
     the function is found first. One mutant made **all 13 peer-approval checks,
     including the 9 behavioural ones, assert against a comment.**
   **Fix:** strip block comments AND line comments from `src` once, at load, and
   run `lift()`/`indexOf`/the allow-lists over the stripped text. Assert `lift()`
   matched exactly one `function <name>(` in the stripped source. A prefix test is
   not a comment stripper and must not be spelled like one.
2. **⬜ ROUND-2/F-3 (High) — the pinned window starts too late, and the
   `describeIdentity` caller allow-list is line-based.** No comment tricks; this
   is the ordinary-looking-commit version, and it is the same mutant shape round 1
   used, one level out.
   - `EXPECTED_WINDOW` begins **at** `const idbCanon = canonicalBundle(idb);`
     (`peer-approval.test.mjs:186`). Everything earlier in the `key`-frame branch
     is unconstrained, and `approvedBundle` assigned there makes the
     `if (!approvedBundle)` gate at `app.js:2699` never run at all.
   - the caller walk (`peer-approval.test.mjs:295-314`) attributes a call to the
     nearest preceding `/^(?:async\s+)?function\s+(\w+)\s*\(/` — anchored at
     **column 0**, so it cannot see arrow functions, class or object methods, or
     an indented declaration. A module-scope
     `const dirVerdict = (b) => describeIdentity(b);` placed after
     `renderPeerApproval` is attributed to `renderPeerApproval`, and the
     allow-list still reads `["renderPeerApproval","showNextKnock"]`. It also
     pushes one owner per matching LINE, not per call.
   **Fix, and this is the one worth doing properly:** stop policing
   `describeIdentity` and remove the thing being laundered. It returns
   `mismatch`, a decision-grade boolean, purely so two renderers can draw a ⚠
   line — **have it return the rendered string (or take the element to write
   into) so there is no boolean for a decision path to read.** That deletes the
   whole attack class instead of naming it. Then start the window where
   `approvedBundle` could first be written for the connection, not at `idbCanon`.
3. **⬜ ROUND-2/F-4 (Medium) — F-A2's shape assertions validate the wrong line.**
   `contacts-anchor.test.mjs:485` does `code.find((l) => l.includes("c.reverify"))`
   over the whole stripped file, so it returns the **first** hit — `app.js:1092`,
   `} else if (c.reverify && !c.verified) {` in the **Users-list renderer**, an
   unrelated site. Verified by hand. So `assert.match(branch, /^\}\s*else if\s*\(/)`
   never looks at `renderVerify` at all, and a mutant adding `&& !pinsReadable()`
   — always false there, because `app.js:2845-2858` returns early when it is false
   — makes F-A2's branch **dead code** while every shape assertion passes. The
   bystander falls through to the benign first-contact panel: M-2's inverted
   alarm, restored. **Fix:** anchor the `find` inside the `renderVerify` region
   (slice from `const pin = await getPin(currentPinKey);` first) and assert the
   SAME line carries both the `else if` shape and the unlock short-circuit.
   `code[i-1]` is off-by-one safe (filtered array, `i===0` guarded) but is a weak
   proxy that the dead branch satisfies.
4. **⬜ ROUND-2/F-5 (Medium — I recorded this as Low and was wrong) —
   `writeIndexEntry` moved late, and it BURNS the pad.** `fc566dd` reordered
   `writePadBlob` to blob → wm → used → epoch → `writeIndexEntry` → `armFloors`.
   A kill or quota error between the watermark and the index on a pad's FIRST save
   leaves this, verified by PoC on the committed tree:
   ```
   keys on disk: [ sc.otp.pad.v1.<id>, sc.otp.wm.v1.<id> ]
   listPads(): 0   padMeta(): null
   pad IS durable and unlockable, sendOffset = 0
   padWasUsed(): true     after forgetPad, padWasUsed(): true
   ```
   `refreshOtpPads` (`app.js:3179-3193`) builds the selector from `listPads()`,
   and the selector is the ONLY route to `unlockPad` — so there is no UI path to
   the pad. `padWasUsed()` then refuses re-import, and `forgetPad` deliberately
   keeps the watermark. **The pad is gone and the two people must meet in person
   again.** On a plain browser this window is strictly WORSE than F-A1-R1's (that
   one leaves no keys and re-import is allowed). Same harm class as the bug
   `fc566dd` was fixing, minus the alarm wording, which makes it harder to
   diagnose. **This is a genuine regression introduced by `fc566dd`.**
   **Fix — one line:** move `writeIndexEntry(record, …)` to immediately after
   `setItem(padKey…)`, before the watermark. Nothing in the ordering rationale at
   `otp.js:764-773` requires it to be late; the index is a render cache and
   carries no security decision.
5. **⬜ ROUND-2/F-6 (Info) — a comment of mine over-claims.** `contacts.js`
   dropPinsFor says the marker "covers exactly the set the old code retained".
   Not exactly: `claimedByAnother` applied only to `contact.pinKeys`, while
   `otherHolderOf` is applied to every element of `owned` **including the
   contact's own current keys** — so the marker set is a strict SUPERSET. Error is
   in the conservative direction, but the sentence is load-bearing prose bounding
   a residual. Reword to "at least the set the old code retained."
6. **⬜ Test debt this round exposed** (distinct from item 12's older list):
   - **F-5 has no test at all.** `testInterruptedSaveDoesNotBrickAPad`
     (`otp-rollback.test.mjs:1170-1247`) only fails the BLOB write and only on an
     ESTABLISHED pad. A one-line change to the fail predicate (`sc.otp.used.v1.`
     on a first save) would fail against `fc566dd` and pass against `cbcedf9` —
     i.e. it would have caught the regression the commit shipped. Write it first.
   - `savePin`'s reverify-clearing has a positive test but no negative one:
     nothing asserts that `savePin` for a DIFFERENT bundle leaves the marker alone.
   - The `describeIdentity` caller allow-list has **no self-test**. Every other new
     check is justified by a named mutant that beat the previous version; this one
     is not, and it is the one that fails silently under aliasing.
7. **⬜ The three A4 findings still open from round 1** — F-A2-R1 and F-A1-R1
   (both Medium, both confirmed **pre-existing residuals, not regressions**:
   the identical PoC gives byte-identical output on HEAD), and the `reverify`
   overloading Info. All three are described in full in the round-1 block below.

**Then** continue with items 8 onward (the old numbering, unchanged): item 6's
`/api/register` 409 contract change **still needs the user's decision**, item 7's
older test debt, item 8's harness gap, and the rest.

**Baselines, measured on the committed tree:** client **195 OK, 0 failures**.
Backend **165 passed**. Round 2 did not run e2e (no `backend/` change in the
commit); round 1 ran `room-admission` 13/13, `two-user-flow` 8/8, `no-dead-ends`
12/12 against a scratch relay. **Note what that green means: five mutants that
skip the approval prompt against a hostile directory also score 195/195.** Do NOT
merge this branch on the strength of a green suite.

**Not attacked in either round:** F-A1 was exercised against a JS stub of
`PadFloor`, never on a real device. `e2e/hostile-relay/` structurally cannot see
any of the directory-driven mutants (it serves no `/api/*` routes — item 8 below
is exactly this). `PadFloorBridge`'s Long↔JS-number marshalling and the Android
side beyond `PadFloor.kt` were not reviewed.

### Round 1 — what `fc566dd` actually fixed, and how it was verified

1. **A4/F-A1 — `otp.js` floor/blob write ordering.** `armFloors` was split into
   `probeFloors(id)` (bumps every slot with **0**, so it can only CREATE a slot,
   never advance one; reads back; throws on TAMPERED) and `armFloors` (advances
   to the real values, now called **only after** `setItem(padKey)`). The claim is
   measured before the write, the value is raised after it, so a floor is never
   above the blob it protects. `writeWatermark` became the pure `sealWatermark`,
   and `writePadBlob` now finishes both crypto operations before the first
   `setItem`, then writes blob → watermark → used → epoch → index → floors with
   no `await` between writes that must agree. `app.js otpExport` now awaits
   `markExported` **before** `downloadText`, so a failed latch cannot release a
   pad file that nothing on the device records as exported.
   *Verified:* the new test fails against `HEAD:client/otp.js` with `"pad state
   was rolled back"`. The pentest's own fault-injection matrix (fail each of 5
   localStorage key classes on 2 save paths) is **10/10 openable** on the new code
   vs. 2 permanent bricks on HEAD.
2. **A4/F-A2 — `contacts.js` revocation.** The `claimedByAnother` **retention**
   rule is gone. A pin naming a revoked key is now **always** swept; the
   collision is recorded as `reverify` on the other contact, and `app.js`
   `enterVerification` reads that marker to render "Re-verify — their saved pin
   was cleared" instead of the benign first-contact panel. Both M-2's alarm
   inversion and F-A2's silent trust are removed without either side having to
   win a key collision. Deliberately **not** conditioned on the other record
   being `verified` or user-created — that dependency IS the bug.
   *Verified:* an `auto`-contact control (one sealed envelope, no user action)
   shows `SURVIVED (fail-open)` on HEAD and `swept` on the new code.
3. **A4/H-1 — the call-site pin, twice.** First cut: anchor on the executable
   `const idbCanon = ...` instead of a comment, plus an exact allow-list of the 8
   `expectedPeerBundle` sites. **The pentest broke it**, and the lesson is worth
   carrying: pinning the *identifier* is useless because the decision does not
   need it. `describeIdentity()` re-exports the same directory comparison as
   `.mismatch`, a decision-grade boolean on a plain object, so
   `if (expectedPeerName && !d.mismatch) approvedBundle = canonicalBundle(idb)`
   is item 14's deleted route with the forbidden string appearing nowhere — and
   `canonicalBundle(idb)` also slipped the `approvedBundle = idbCanon` regex. It
   passed 193/0. **Re-fixed by pinning the decision path, not the vocabulary:**
   an exact allow-list of all **26** executable lines between the peer bundle and
   the gate (nothing may be added there at all, whatever it is made of); an exact
   body for `requestPeerApproval`; an assertion that `renderPeerApproval` cannot
   settle the promise; and a call-site allow-list proving `describeIdentity` is
   reachable **only** from the two prompt renderers.
   **⚠ THE RE-FIX DOES NOT BIND EITHER — see items 1-3 at the top of this file.**
   Round 2 defeated all four of those checks. "Proving" in the sentence above is
   too strong and is left standing only so the next reader can see exactly which
   claim failed and why.

**Also fixed: three source anchors were satisfiable by a comment** — H-1's defect
again, in two more files. `indexOf` over raw source let a mutant revert the
`app.js` export order, and another delete the whole `reverify` branch, while a
comment carrying the anchor string kept the check green (both passed 193/0). All
source anchors now strip `//` lines first via a `codeOnly()` filter, and the
F-A2 anchor gained shape assertions (`else if`, locked-store short-circuit, the
`changed` styling).

**Round 1's four mutants were re-run against the hardened tests and all went
RED** (the `requestPeerApproval` short-circuit, the call-site
`describeIdentity().mismatch` skip, the comment-hidden export reorder, and the
comment-hidden `reverify` deletion). **That result stands but means much less
than it looked like at the time** — round 2 then found five DIFFERENT mutants
that pass, via `/**/`-prefixed code, a block-comment decoy for `lift()`, and an
arrow-function alias. Killing the named mutants is not the same as binding the
property. See items 1-3 at the top.

### Round 1's own findings (still open — none fixed)

Both Mediums were **confirmed as pre-existing residuals, not regressions** — the
pentest ran the identical PoC against HEAD and got byte-identical output. They
are recorded because each one falsifies a justification the fix leans on, and
both code comments have been corrected to say so rather than left as folklore.

* **⬜ F-A2-R1 (Medium) — the `reverify` marker misses two reachable shapes.**
  It is keyed on a contact whose CURRENT keys are the swept ones, so a
  `room:<id>` pin whose owner has no contact record (**the default** for Live-room
  use) and a bystander who has since rotated both get the pin swept with **no
  marker**, and still render as a benign first contact. Fix direction: the marker
  belongs on the **pin key** as a tombstone, not on a contact record — the key is
  in hand at deletion time and needs no guess about who holds those keys now.
* **⬜ F-A1-R1 (Medium) — a pad's FIRST save is still all-or-nothing.**
  `probeFloors` creates the send slot before any blob exists, and `padWasUsed`
  counts a non-ABSENT send slot as used, so a failure during `saveNewPad` /
  `importPad` / the v1-v2 migration rewrite **burns the padId** and the two people
  must exchange a pad in person again. Identical on HEAD across all five write
  classes. Fix direction: do not let `probeFloors` create the send slot before a
  blob exists, or stop counting a bare send slot at exactly 0 (with no blob, no
  watermark and no `usedKey`) as evidence of use.
* **⬜ F-A1-R2 — SUPERSEDED by ROUND-2/F-5 (item 4 at the top). I rated this Low
  and called it "recoverable state"; both were wrong.** Round 2's PoC shows the
  padId is BURNED on both platforms and there is no UI route to the pad. It is a
  Medium and a genuine regression shipped by `fc566dd`. Corrected here rather
  than left to mislead the next reader.
* **⬜ INFO — `reverify` is overloaded.** It already meant "your 🟢 predates
  encryption-key coverage" (`contacts.js:414`). Consequences: a 🟢 contact whose
  pin was just swept shows **nothing** in the Users list (`app.js:1092` renders it
  only `if (c.reverify && !c.verified)`); a contact carrying the *migration*
  marker now gets F-A2's wording, which is simply untrue of them; and
  `setVerified(_, true)` from the one-click Users-list toggle clears the F-A2
  marker **without any safety-number comparison and without restoring the pin**.
  Consider a separate field.

**Not attacked:** F-A1 was exercised against a JS stub of `PadFloor`, never on a
real device. `e2e/hostile-relay/` was not run (item 8 below is why: it serves no
`/api/*` routes, so it structurally cannot see the directory-driven mutants).
`PadFloorBridge`'s Long↔JS-number marshalling and the Android side beyond
`PadFloor.kt` were not reviewed.

(Round 1's "state at hand-off" paragraph is superseded — that work is now
committed as `fc566dd`. See the top of this file for the current state.)

## ⮕ (2026-08-10 night — `40d132e`'s repairs pentested: 3 High, 4 Medium)

**The previous TOP ITEM is DONE.** `pentest-new-code` was run over the repairs
made AFTER the 2026-08-10 lanes reported — the code that had never been reviewed.
It found **3 High and 4 Medium**, and **nothing is fixed yet**: this session
ended at the report. That makes it a **fifth consecutive round in which the
repair was more dangerous than the bug** (2026-07-29, 07-30, 08-08, 08-10, and
now 08-10-night). Full detail in **section A4** below.

Two things this round established that are worth carrying forward before the
findings themselves:

* **The regression tests are now the weakest part of this branch, not the code.**
  Both lanes converged on this independently. Lane A found **8 changes with no
  test that fails against the code they replaced**; lane B found that the test
  written to pin item 14 — last round's High — **passes against the very mutant
  it was written to catch**. The project's own rule ("every fix carries a test
  verified to FAIL against the pre-fix code") was followed in letter and, in
  these places, not in substance. Treat a green suite on this branch as weak
  evidence until item 7 below is done.
* **Item 18's protocol change got more load-bearing.** It was recorded as the
  wrong-clock residual only. Lane B proved the same missing server echo also
  causes an inert retry (A4/M-1) and a **two-device lockout at one hour of
  skew** (A4/M-2) — and two devices on one identity is a supported flow
  (`exportIdentity`, `app.js:673`). See item 6; it still needs the user.

### NEXT SESSION — do these in order (items 1-3 CLOSED 2026-08-15, see the entry above)

1. **✅ FIXED 2026-08-15 — A4/F-A1 (High, REGRESSION, no attacker needed) — `armFloors` arms the
   native floors BEFORE the blob that backs them is written.** `otp.js:649` bumps
   all three slots to the new offsets; the blob is not persisted until `:702`,
   with a `JSON.stringify` and an `await crypto.subtle.encrypt` in between. A
   process kill or a `QuotaExceededError` in that window leaves the floor AHEAD
   of the blob, which the next unlock reads as a rollback and refuses
   **permanently** — `forgetPad` + re-import is blocked by `padWasUsed`. The
   pre-fix code bumped inside `writeWatermark`, i.e. AFTER `setItem(padKey)`, so
   an interruption left the floor BEHIND the blob and was harmless; confirmed as
   a regression by running the PoC against `9eb6fdd`. `markExported`
   (`otp.js:1061`) is worse: `app.js:3287` hands the file to the user BEFORE the
   latch at `:3288`, so a failed export brands the pad "already exported once"
   forever. This is the exact harm the trade-off comment at `otp.js:288` names as
   the worse outcome — a false tamper alarm that teaches the user to disbelieve
   it — and `otpPersistFailed` still advises "Free up storage, then reconnect",
   which now leads to "exchange a fresh pad". **Fix:** decide `armed` from the
   PREVIOUSLY persisted watermark (0 on first save), and advance the slots to the
   new offsets only after `setItem(padKey)` succeeds — old ordering for the
   value, new read-back for the claim.
2. **✅ FIXED 2026-08-15 — A4/F-A2 (High, fail-open) — the `claimedByAnother` skip retains a pin that
   revocation must kill.** `contacts.js:694-699`. Closing M-2 ("removing X must
   not delete a third party's pin") opened its inverse: if ANY other contact
   record names the superseded key, `Remove`/`Unverify` will not sweep the pin
   naming it — and **the attacker chooses whether that record exists**. Two cheap
   routes: a hostile relay answering one directory lookup with the old bundle
   (`app.js:1259` upserts it), or one sealed envelope, which auto-creates a
   contact at `app.js:1645` with no user action and no `verified` requirement —
   `claimedByAnother` checks neither. The surviving pin then reaches
   `unlockMessaging()` at `app.js:2860` with **no prompt and no safety-number
   check**. That defeats post-compromise revocation and restores item 17's
   residual. **Fix:** never let an `auto` or unverified record claim a key; on
   collision prefer deleting the pin plus a `reverify` marker over silent
   retention, so neither M-2's alarm inversion nor this silent trust can happen.
3. **✅ FIXED 2026-08-15 (in two passes — the first fix was bypassed) — A4/H-1 (High) — the item-14 call-site pin does not pin the call site.**
   `peer-approval.test.mjs:161-176` slices `src` from a COMMENT string, so
   `between` is the 13 comment lines at `app.js:2686-2699` and contains **zero
   executable code**: the assertion checks that a comment does not mention
   `expectedPeerBundle`. Two mutants reproducing exactly the M-2 shape — one
   inserted above the anchor comment, one moved into `requestPeerApproval`
   (`app.js:2216`) — each skip the approval prompt against a hostile directory
   and **pass 184/184**. The guard on last round's High is decorative. **Fix:**
   scan from the `idbCanon` assignment (or the start of the handshake branch) to
   the gate rather than from a comment, and assert `expectedPeerBundle` appears
   nowhere in the decision path of `requestPeerApproval`/`renderPeerApproval` —
   ideally as an exact-line allow-list of its 8 known display/mismatch sites.
4. **⬜ A4/F-A3 (Medium) — `nativeFloor: armed.send` can seal a permanently false
   floor claim into the AEAD.** `otp.js:682`/`:698`. If the prefs write silently
   does not take on a pad's FIRST save (unwritable file, full disk — `PadFloor
   .bump` discards `commit()`'s boolean), the blob is sealed claiming no floor
   was in force. Both guards (`otp.js:861`, `:891`) are keyed on that claim, so
   they can never fire for that blob, and because it is AEAD-sealed, healing the
   floor later cannot repair it — a snapshot taken during the degraded window
   stays exploitable forever, into keystream reuse. **Fix:** do not collapse
   "arming failed" and "never armed" into the same `false` a plain browser
   writes; a third value routes that blob through the existing
   `LEGACY_PAD_ADOPTION` consent gate. **Also correct two false statements in the
   trade-off comment at `otp.js:288-298`** while there: "the pad opens UNGUARDED
   for that slot — the pre-fix behaviour" is wrong (the code it replaced
   REFUSED), and "the guard re-arms on the next save that succeeds" is true of
   the live pad but not of a snapshot.
5. **⬜ A4/M-3 (Medium) — a counter 409 is reported to the user as "username
   already taken".** `app.js:740-742` branches on `e.status === 409` alone, so
   item 18's "registration counter is not newer" arrives misdiagnosed, and the
   user is advised to pick another name — the one action that loses their handle
   and every contact's pin. Worse, the path that actually matters, the republish
   of a rotated bundle on unlock (`app.js:537`), is
   `.catch(() => {})` — so "your published encryption keys are frozen and sealed
   mail is going to a superseded key" is either silent or wrongly diagnosed,
   never true. Item 18's own rationale objects that the pre-fix poisoning was bad
   partly because "nothing on the device showed why"; that is still the case.
   Both lines predate the fix, but the fix makes a counter 409 the most likely
   409 an EXISTING user will ever see.
6. **⬜ Decide item 18's protocol change — STILL NEEDS THE USER, now for three
   findings rather than one.** Have `/api/register`'s 409 echo the stored
   `reg_seq` so a client can jump to `stored + 1` instead of guessing. It is a
   wire/contract change, and it leaks an account's counter to anyone who can
   produce a valid signature — which is why it is the user's call. It is the real
   repair for all three of:
   - the **wrong-clock residual** (a badly wrong future clock still freezes an
     account; no client-side ceiling can fix it, since the ceiling is computed
     from the lying clock);
   - **A4/M-1**: the retry is inert in exactly the state its own first firing
     creates — once pinned at the ceiling, `nextRegSeq()` and `regSeqCeiling()`
     return the same number, so it re-sends the refused value. That is the M-1
     shape it claimed to have fixed, reproduced against the real endpoint;
   - **A4/M-2**: because the retry jumps to `now + SLACK` rather than
     `stored + 1`, **any skew between two registrants for one identity ratchets
     the slower one out permanently** — reproduced at ONE HOUR of skew, far
     inside the week of "acceptable slack", and re-locked on every registration
     by the faster device. The comment at `account.js:136-138` claiming the
     client "overtakes it on the next registration rather than being locked out"
     is true for one device and false for two. The slack window is **not** the
     safe-skew budget it is documented as.
   If the user declines the contract change, the fallback is narrower: refuse to
   re-send a value equal to the one just refused, and advance rather than jump.
7. **⬜ Pay down the test debt this round exposed — treat as a finding, not
   chores.** The suite is green against mutants it was written to kill:
   - **F-A1 survives the entire suite** — nothing tests a save interrupted
     mid-`writePadBlob`. Add one that fails the save and asserts the pad still
     opens.
   - **A4/H-1's two mutants pass 184/184** (item 3 above).
   - **The sharpest example, verified at close: `regseq.test.mjs:173-186` is
     named `item 18 / M-1: the 409 retry advances instead of resending the
     refused value` — the exact bug A4/M-1 reports — and it PASSES.** It opens
     with `reset()`, so it only ever exercises the FRESH state, where `cur = 0`
     and the ceiling really is an advance. It never re-registers, so it never
     reaches the pinned-at-ceiling state that the first retry itself creates,
     which is the only state where M-1 bites. A test can carry the finding's own
     name, assert the finding's own property, pass, and still not test it. Fix
     this one first: it is the cheapest possible demonstration for whoever needs
     convincing that the green suite is not evidence.
   - `regseq.test.mjs`: mutating the retry to `seq = regSeqCeiling() * 2` writes a
     floor ~58 years ahead that the next `nextRegSeq()` discards — **pass 2's
     exact bug, relocated into the one place the shipped code writes
     `localStorage` outside `nextRegSeq`** — and it passes 8/8 and 184/184. The
     file is not vacuous overall (a faithful pass-2 reconstruction goes red at
     `regseq.test.mjs:160`), but the retry path has no "stays a usable floor"
     assertion.
   - **No test stubs `Date.now` anywhere.** All 8 regseq checks run against the
     real wall clock, so the entire clock dimension — the named priority of the
     lane, and the fix's own stated risk area — is untested. No backward-clock,
     frozen-clock or skew test.
   - Green against deletion, i.e. testing nothing: the `broken` gates on
     `savePadProgress`/`markExported`, `contacts.js:697`'s `typeof k.ed` guard,
     `chats.js:393`'s `!chats` guard, `chats.js:374-376`'s `writeChain` intra-tab
     layer (the shim always supplies Web Locks, so the no-Web-Locks path is never
     exercised), and `chats.js:371`'s `typeof navigator` guard.
   - Missing shapes: a `claimedByAnother` test where the claiming record is an
     `auto` contact (the current control only covers an UNCLAIMED superseded
     key); an integer assertion on `seq`; and a test that a counter 409 is not
     surfaced as "username already taken".
8. **⬜ Close the harness gap** (was item 3, unchanged). `e2e/hostile-relay/
   hostile.mjs` serves no `/api/*` routes and `proto001.mjs` never types a
   handle, so `expectedPeerBundle` is null in every run — the entire
   directory-driven flow that item 14 is ABOUT is invisible end to end. Add a
   `DIRECTORY=hostile` policy (the relay already sees the bundle in the knock)
   and a scenario that connects by handle. Also make `EVIL_MODE=none` loud: it
   currently returns an unpatched client with no warning, so
   `EVIL_MODE=none SCENARIO=attacker` reports a clean 9/9 that proves nothing.
   **Note the overlap with item 3**: this harness is why H-1 could only be proven
   at the unit level.
9. **⬜ A4's Low/Info.** `nextRegSeq` has no integer guard on its own output, so
   a hooked `Date.now` returning a fraction makes both `registerMessageBytes` and
   `attempt` take their `Number.isInteger` false branches and the client silently
   emits a **v2, counter-free, replayable** registration (backend stays
   fail-closed, so no key rollback follows — the objection is the silent
   downgrade of a control by a device-local attacker). A backward clock discards
   the stored counter and rewrites `sc.regseq.v1` into the past, persisted even
   when both attempts 409 — self-healing, but the backward direction is
   undocumented while the forward one is. `clampRegSeq` (`account.js:157`) is
   **dead code, called nowhere in the tree**. `otp.js`'s new `broken` gates are
   **unreachable** — every producer of `{record, atRest}` already refuses in that
   state; the finding they cite IS closed, but by `armFloors`'s read-back, so the
   comment credits the wrong line and a future reader could delete the
   load-bearing half and keep the decorative one. `importPad` returns `o.padId`
   with no type/charset/length check while slots are derived by string
   concatenation (`otp.js:124-125`), so a pad file with `padId =
   "<victim>#recv"` aliases another pad's derived slot — an arbitrary-pad brick
   primitive, unreachable today only **by accident** (`padWasUsed` finds the
   aliased slot present and refuses the import). `chats.js:371` reads
   `navigator.locks` from a poisonable global with no "a lock was expected here"
   marker, unlike the hardening `otp.js` applies everywhere.
10. **⬜ MOST IMPORTANT STALE COMMENT — fix it whenever `account.js` is next
    touched.** The block at `account.js:93-111` still describes **pass 2's**
    design as current and references `REG_SEQ_SANE_MAX` and `REG_SEQ_MAX`,
    **neither of which exists**. That is exactly how a fix gets reverted by a
    well-meaning reader who trusts the prose over the code.
11. **⬜ The small open residuals** (recorded, none fixed): `chats.js` `unlock()`
    reads store and witness outside the lock so a benign second tab can fire the
    rollback alarm; `withWriteLock` has no timeout, so a same-origin script
    holding it hangs writes silently; `contacts.js` `list()`/`get()` return a
    shallow spread that now shares `pinKeys` by reference, contradicting the
    "defensive copy" comment; `app.js` `describeIdentity` still compares keys as
    strings where the gate compares bytes (no-op today, permissive if `unb64` is
    ever loosened); the peer-approval prompt inherits an attacker-choosable
    display name for auto-contacts; and `app.js:2721`'s comment about a knock
    queuing behind the peer prompt is false — the two prompts are mutually
    exclusive, so that `showNextKnock()` and the `approvalPending` guard are
    unreachable-in-effect.
12. **⬜ Then** A2's remaining Low/Info (22, 23, rest of 24), A3's coverage gaps
    (25-27), and section B's decisions for the user.

**State at hand-off:** branch `pentest-2026-08-07-fixes`, working tree CLEAN.
`40d132e` is the last code commit; **this session added no code — only this
report.** **Not pushed, not merged, not deployed.** `master` is still 1 commit
ahead of `origin/master` from an earlier session. Both lanes reverted every
mutant they installed; `git status` was verified clean after they finished, and
`backend/accounts.db` was not touched.

**Baselines re-run on the clean tree at close, not assumed:** client **184 OK,
0 failures**; backend **165 passed**. e2e and hostile-relay were NOT re-run this
session (neither lane touched them, and no code changed). Both numbers match the
`40d132e` baseline exactly — which is the point of item 7: they matched while
three Highs were open.

**Do NOT merge this branch on the strength of a green suite.** Three Highs are
open, and item 7 is the reason the green is not evidence.

### A4 — the 2026-08-10-night review of `40d132e`'s repairs (2 lanes)

Scope was defined by function name rather than by diff, because `40d132e`
contains both the original fixes and the repairs to them, so they cannot be
separated by commit. Lane A took `otp.js` `armFloors` + the
`savePadProgress`/`markExported` gates, `contacts.js`
`rememberSupersededKeys`/`dropPinsFor`, and `chats.js`'s two new guards. Lane B
took `account.js`'s relative two-sided bound and rewritten 409 retry, with the
clock as its named priority, plus the new call-site assertion in
`peer-approval.test.mjs`. Lane C was not run: the backend was clean last round
and unchanged since. Every finding is itemised as TODO items 1-5, 6 and 9 above.

**What was attacked and HELD** — recorded so the next session does not re-spend
the effort:

* **The TAMPERED-vs-ABSENT refusal is genuinely closed and its test is not
  vacuous** — deleting the `throw` at `otp.js:330` turns `otp-rollback.test.mjs`
  red on "corrupting the SEND slot must FAIL CLOSED". The layer below was checked
  too: `PadFloor.bump` (`PadFloor.kt:124-132`) returns `TAMPERED` and **writes
  nothing** when the stored record does not verify, so bump-then-read cannot
  launder a forged slot into a valid one. The read-back is real evidence.
* **`bump(_, 0)` really does create the `#exported` slot** (`PadFloor.kt:128`:
  `current == ABSENT` → `next = 0`, `0 != -1` → `commit()`), so that slot's
  absence really is unambiguous evidence of deletion. The comment is accurate.
* **The `derivedFloors` gate** is inside the AEAD (unstrippable), correctly keyed
  on a NEW field rather than on `nativeFloor` (2026-07-29-era pads still open),
  and strict `=== true`. Its only weakness is F-A3.
* **A throwing save cannot cause keystream reuse** — `app.js:2977` persists
  BEFORE `ws.send`, and `otpPersistFailed` clears `verified`, disables send and
  closes the socket. Checked specifically because `armFloors`'s new `throw` fires
  on the send path.
* **M-1 (eviction order), M-2 (third-party pin) and item 17's base are closed** —
  the mutants `history.slice(-MAX)`, removing `claimedByAnother`, and removing the
  `rememberSupersededKeys` call site each turn `contacts-anchor.test.mjs` red on
  the right assertion.
* **The chats concurrency test is NOT the known vacuous shape** — it installs a
  real FIFO Web Locks shim and redefines `globalThis.navigator`; dropping the
  lock from `withWriteLock` kills it. (The warning recorded last round still
  applies to any NEW such test.)
* **Pass 2's freeze is genuinely gone.** `sc.regseq.v1` was poisoned with
  `2**53-2`, `2**53-1`, `2**43`, `2**43±1`, `2**44` and `Date.now()+10×SLACK` and
  driven through the real `/api/register`: every one heals on the first
  registration, and three consecutive registrations then succeed. The new
  inclusive bound does not recreate the self-discarding band, even with
  `Date.now()` frozen so no millisecond can elapse.
* **`detail.includes("counter")` cannot misfire on an honest server** — the only
  other `accounts.py` 409 containing that substring is reachable only when
  `req.seq is None`, while the client's branch requires `Number.isInteger(seq)`.
* **Inducing the retry from a hostile relay yields no key rollback.** It does
  harvest a valid dual signature dated ~7 days ahead, and the relay can then lie
  `{"status":"updated"}` so nothing is visible to the user — but the client
  persists the ceiling it signed, so every later registration is strictly above
  it, and clearing `localStorage` routes through a retry that jumps to a LATER
  ceiling. Moot against a hostile relay anyway: `/api/users` answers carry no
  signature and item 14 already forbids trusting them.
* **`Number.parseInt` junk** (`""`, `"NaN"`, `"1e999"`, `"-1"`, `"0"`, `"0x…"`,
  `2**60`, non-safe-integer decimals) is all either discarded or yields a valid
  counter. Intra-call clock skew between `ceiling` and `Date.now()` is absorbed
  in both directions.
* **The backend v2/v1 downgrade path is fail-closed** (`accounts.py:711-718`): a
  no-counter registration may only ADD encryption keys to an account that has
  none.

**Not attacked / open uncertainty:** neither lane ran the Puppeteer e2e or
hostile-relay suites (out of lane, and the tree was being mutated concurrently);
H-1 is proven at source/unit level only, which item 8 is the reason for. F-A1 and
F-A3 are argued from the JS ordering plus the Kotlin source with in-process PoCs,
**not exercised on a real device**. The Android side beyond `PadFloor.kt` was not
reviewed. M-2's severity depends on how real "two registrants for one identity"
is in practice — `exportIdentity` exists, but the import path was not traced end
to end. Baseline held throughout both lanes: client **184**, backend **165**.


`pentest-new-code` was run over this session's own fixes, in three lanes. **It
found 2 High and 3 Medium in the fix code — a fourth consecutive round in which
the repair was more dangerous than the bug.** All are fixed, each with a
regression test verified to fail against the code it replaces. Detail per item in
A2 below; the short version:

* **H (item 13 repair) — `armFloors` collapsed `NATIVE_TAMPERED` (-2) and
  `NATIVE_ABSENT` (-1) with `>= 0`.** Corrupting a prefs entry costs an attacker
  exactly what deleting one costs, so corruption silently disarmed the guard that
  deletion trips: my repair turned a fail-CLOSED path fail-OPEN, and the lane
  rewound `recvHighWater` 4000 bytes through it. Tampering is a hard refusal now.
  Also: `savePadProgress`/`markExported` had NO native-floor gate, and `app.js`
  caches `{record, atRest}` per session — so after one unlock every per-message
  save bypassed every floor check in the file. Both gated.
* **H (item 18) — the fix did not close the freeze.** An ABSOLUTE ceiling can
  only relocate it: the acceptance bound was inclusive, so a stored `2**43` was
  signed as `2**43+1` and then discarded by the next call, leaving the server
  holding a value the device could never reach again. Proved end to end against
  the real endpoint. Rebuilt on a RELATIVE two-sided bound (`now + slack` does
  both jobs), so nothing signed can ever become un-signable. **Residual, needs a
  protocol change: a badly wrong wall clock still freezes an account, and no
  client-side ceiling can fix it because the ceiling is computed from the lying
  clock. The repair is for the server to echo its stored counter on 409** — it
  currently says only "not newer", which is why `Date.now()` had to be guessed
  at. Open item.
* **M (item 13 fix) — the first cut could BRICK a pad** (claim written before the
  bump that backs it), unrecoverable, wearing the tamper alarm's own wording.
* **M (item 17 fix) — the history cap evicted the OLDEST superseded key**, the
  one whose pin has had longest to be forgotten, restoring the exact residual
  item 17 closes. Also: the stated justification for the cap was false, and is
  corrected rather than left as folklore.
* **M (item 17 fix) — `pinKeys` is fed from UNSIGNED directory answers**, so a
  hostile relay could plant a third party's key in someone's history and have
  removing that someone delete the third party's pin — inverting the key-change
  alarm. Absent from pre-fix code: the old sweep was self-limiting.
* **M (item 14 coverage) — the harness could not see a call-site reintroduction.**
  A mutant restoring route (a) at the CALL SITE passed 9/9 in both suites while
  skipping the prompt against a hostile directory. The call site is pinned now.

**Still open, recorded not buried:** `chats.js unlock()` reads store and witness
outside the lock, so a benign second tab can fire the rollback alarm (transient,
pre-existing); `withWriteLock` has no timeout, so a same-origin script holding it
hangs writes; `list()`'s shallow spread shares `pinKeys` by reference against its
own "defensive copy" comment; `describeIdentity` still compares keys as strings
where the gate uses bytes (no-op today, permissive if `unb64` is ever loosened);
the peer-approval prompt inherits an attacker-choosable display name for
auto-contacts; `hostile.mjs` serves no `/api` routes so the directory-driven flow
is untestable end to end, and `EVIL_MODE=none` returns an unpatched client with
no warning. **`pentest-new-code` has NOT been re-run over THIS round of repairs.**

## ⮕ (2026-08-10 midday, ALL of A2 closed)

**Every A2 High and every A2 Medium is closed** — items 13, 14, 15, 16, 17, 18,
20 fixed, item 19 decided/documented/hardened, plus 21 and the two
`forge.mjs`/string-compare parts of 24. **Each fix has a regression test that was
verified to FAIL against the pre-fix code**, and two findings the report had only
modelled (13's second export, 18's account freeze) were REPRODUCED end to end
before being fixed. Everything is still **uncommitted** on
`pentest-2026-08-07-fixes`.

**Next, in order:**

1. **Re-run `pentest-new-code` over the whole branch.** Eight fixes have landed
   since it last ran, and on this project fix code has been the most dangerous
   code in the tree three times running — all three A2 Highs were fixes for
   earlier findings. This is the highest-value thing left before merge.
2. **A2 items 22, 23, the rest of 24** — all Low/Info.
3. **A3's coverage gaps** (25-27), then section B's decisions for the user and
   section C's items 8-11.

**Still needs the user** (section B, unchanged): F-CRYPTO-009's RSA residual,
lock-on-background, the anchor/restore design, and the merge/deploy plan for the
two breaking contract changes (`register/v3` and dual-scheme `/auth/verify` both
refuse older clients).

What was done, one line each — 13/14/15 first (the Highs), then 16/17/18:

* **item 13 — FIXED.** New `derivedFloors` marker inside the v3 AEAD, plus
  `#exported` is now bumped on EVERY save (0 or 1) so the slot exists from the
  pad's first save and its absence is unambiguous. `unlockPad` refuses when the
  marker is set and either derived slot reads ABSENT. **The exploit was
  reproduced first** (pre-export snapshot + one prefs deletion ⇒ `unlockPad`
  succeeded with `exported === false`, i.e. a pristine pad re-armed for a SECOND
  export) and is refused after. Gated on a NEW field, not on `nativeFloor`,
  because 2026-07-29-era pads legitimately have no derived slots — that reasoning
  is now in the code, where the pentest correctly noted it was missing.
* **item 14 — FIXED.** `peerAlreadyTrusted` route (a) is deleted. The only
  remaining skip is a 🟢 key verified in person, which is genuinely local.
  **Item 21 is fixed in the same function** (a set-but-mismatched
  `expectedPeerBundle` now returns null instead of falling through), and the
  key comparison moved from string `===` to decoded bytes (`sameSigning`), the
  last part of item 24's list. Cost, now stated honestly everywhere: first
  contact by handle costs one click.
* **item 15 — FIXED** by serialising `_mldsa65_verify` behind a module lock.
  **`xoflib` is NOT installable in this environment** (`pip install xoflib
  --no-index` → no distribution), so the dependency route could not have been
  tested here and was rejected for that reason; the lock is correct whatever
  backend is installed, which is the property that matters given the failure mode
  being closed off is "deployed without xoflib and nothing says so". This is the
  single `dilithium_py` call site in the process, so it also closes the same
  latent bug in `register`.

* **item 16 — FIXED.** The CAS is now a real critical section: a `writeChain`
  orders writes within a tab, `navigator.locks` orders them across tabs, and the
  losing tab refuses loudly instead of silently dropping the replay ring.
  Folding store and witness into one value was rejected — the witness must stay
  readable when the store is gone, which is F-ATREST-005's whole deletion check.
* **item 17 — FIXED.** Superseded signing keys are recorded on the contact
  record before `upsert` overwrites them, and the pin sweep matches the union of
  current ∪ history, so Remove/Unverify now reach a pin filed under a rotated-away
  key — the key a user revoking after a suspected compromise most wants dead.
* **item 18 — FIXED, after reproducing the freeze end to end.** A stored counter
  above a sane ceiling is discarded rather than used as a floor, and the signed
  value is clamped below the server's cap. Discarding (not throwing) matters: the
  counter is attacker-writable plaintext, so refusing would trade a server-side
  freeze for a local one.
* **item 19 — DECIDED, and hardened for free.** Accepted as a residual, with the
  reasoning written where it was missing. Also `CHALLENGE_RATE_REFILL_PER_SEC`
  0.5 → 2.0: because the global bucket is charged first, attacker reach is
  `global refill / per-username refill`, so LOOSENING this bucket cut the number
  of accounts one visitor can silence at once from **eight to two** at no cost to
  honest users. The service-wide 4 req/s DoS is explicitly NOT closed and cannot
  be by this bucket.
* **item 20 — FIXED.** `#admit` now carries `data-mode` (`knock`/`peer`), and
  every harness assertion checks the marker AND the visible button label, so the
  two prompts can no longer be conflated and the marker cannot drift from what
  the user sees. The README's control recipe was missing `SCENARIO=control`; a
  wrong invocation now prints an explicit "this is not a broken fix" banner, and
  a prompt that never appears FAILS instead of silently removing two checks from
  the run.

**Two numbers in the report that differ on this machine:** a verify is ~15 ms
here, not ~7 ms, so the serialisation ceiling is **~66/s, not ~140/s** (still far
above the relay's own throttles: challenges refill at 0.5/s per username, 4/s per
host). And the unserialised failure rate reproduced at 179/320, against the
report's 178/320.

### Verified 2026-08-10, not assumed

| suite | result |
| --- | --- |
| client (`npm test`, +2 new suites) | **184 OK, 0 failures** (was 143) |
| backend (`pytest -q`, +11 new tests) | **165 passed** (was 154) |
| e2e room-admission / all-modes / two-user-flow / no-dead-ends | **13/13 · 32/32 · 8/8 · 12/12** |
| hostile-relay control / demote / attacker | **5/5 · 9/9 · 9/9** (9, not 8 — item 20 added a check) |

Each new test was run against the pre-fix code and **fails there**:

* 13 — at the slot-presence precondition (pre-fix the `#exported` slot is never
  written until export, so it reads ABSENT).
* 14 — "a directory answer must never authorise skipping the approval prompt",
  checked by reintroducing route (a) by hand, since the pre-fix state is
  uncommitted working-tree state rather than HEAD.
* 15 — 179/320 valid signatures rejected.
* 16 — "exactly one concurrent write may succeed — two successes IS the lost
  update".
* 17 — "Remove must sweep the pin naming the SUPERSEDED key".
* 18 — pre-fix it signs `9007199254740991`, the server's cap exactly.
* 20 — mislabelling the peer prompt as `knock` fails `room-admission.mjs` inside
  `approvePeerKey`; and the README's OLD recipe, which used to report a green on
  the check that matters, now reports 3/9 behind an explicit banner.

Note for whoever writes the next concurrency test: **sign serially.**
`ML_DSA_65.sign` shares the same process-global SHAKE state as the verify, so
signing inside the threads corrupts the test's own signatures and blames the
server. And in Node there is no `navigator.locks`, so a chats concurrency test
that does not install a shim passes vacuously.

**`pentest-new-code` has NOT been re-run over these fixes.** That is the next
thing to do after item 16 — and on this project the fix has been the most
dangerous code in the tree three times running, so it matters more than usual
that these three are themselves fix code.

### The previous entry (2026-08-08), for context

The whole branch went through `pentest-new-code` in three parallel lanes (the new
rewrite, the backend contract changes, at-rest + crypto). It found **3 High and 5
Medium**. All three Highs were in FIX CODE — code added to close an earlier
finding.

---

The rest of this section is what the 2026-08-08 session DID, and still stands
except where A2 contradicts it.

**A.1 — where the attack stops.** At the intended refusal, on the endpoint that
receives the first handshake. The earlier "stalls at hello, no refusal" reading
was the OTHER party — the one that is never sent a handshake to check, because
the peer that refuses closes before replying. Full detail in TODO item 1,
including two harness traps that manufacture false greens.

**1a — the 2026-08-07 admission proof was unsound, and is gone.** It was
verified against the peer's own bundle, with nothing requiring the signer to be
trusted or a human to have been asked, so an attacker signs one for its victim
with a keypair it makes on the spot. Reproduced in two browsers: the victim
reached the safety-number screen with nobody having approved anything, against
an attacker client that was the shipped code plus one assignment.

**The rebuilt control: approval is symmetric.** Each side refuses a handshake
from an identity ITS OWN user never approved — the owner through the queue
prompt it already had, the other side through the same prompt shown when the
peer's signed handshake arrives. Already-trusted keys skip it (the contact you
picked by name, matched against the directory bundle; or a 🟢 key from the
contacts store), so the ordinary named-contact flow gains no click. No relay
frame and no peer assertion is consulted, so nothing on the wire can switch it
off. The `adm` field is deleted, which also un-breaks the wire: the handshake is
`handshake/v3` again with no new field.

Why nothing weaker works: the room id reaches the relay in cleartext (it IS the
`join` frame), so a hostile relay can always present itself as a legitimate
code-knowing participant. Every claim such a peer makes about its own authority
is the attacker's to choose. Local approval is the only input it cannot write.

**Verified:** client **143 checks**, backend **154 passed**, e2e **13/13 +
32/32 + 8/8 + 12/12**, and the new hostile-relay regression **8/8 in both
scenarios** (`e2e/hostile-relay/`, in the repo this time — the previous harness
was lost with its scratchpad).

**Cost, stated plainly:** a guest joining by raw room code with an unknown peer
now sees one approve/deny prompt before the safety-number step. That is the case
where the human most needs to look, and it is the same prompt the owner gets.

**⚠️ Superseded in part by A2 item 14:** the "already-trusted keys skip it" half
of this is broken. One of the two skip routes reads an UNSIGNED directory answer,
so a hostile relay turns the control off for the named-contact flow. The claim
above that "no relay frame and no peer assertion is consulted" was wrong, and the
same wrong claim is written into `client/app.js` and `client/auth.js`. Fix item
14 (delete route (a)) and item 21 (route (b)'s fallthrough) together, then
correct the comments in both files, `README.md`, and this paragraph.

### Tree state at the end of the 2026-08-08 session

**Uncommitted, on branch `pentest-2026-08-07-fixes`** (which is itself unmerged,
and `master` is 1 commit ahead of `origin/master`):

```
 M PROGRESS.md          this file
 M README.md            symmetric-approval description (CORRECTED 2026-08-10)
 M client/app.js        the rewrite; items 14, 21, 24 fixed + comments corrected
 M client/auth.js       admission proof removed; forge.mjs citation corrected
 M e2e/all-modes.mjs    guest approval click (item 20 fixed: waits for peer mode)
 M e2e/room-admission.mjs  same
?? e2e/hostile-relay/   new regression harness (item 20 fixed: README + checks)
```

Added 2026-08-10 by the items 13-18 fixes:

```
 M backend/accounts.py            item 15: the ML-DSA lock + the decoy note
 M client/otp.js                  item 13: derivedFloors marker + the guard
 M client/otp-rollback.test.mjs   item 13 regressions; the false green removed
 M client/chats.js                item 16: writeChain + Web Locks around persist
 M client/chats-rollback.test.mjs item 16 regression (installs a Web Locks shim)
 M client/contacts.js             item 17: superseded-key history + union sweep
 M client/contacts-anchor.test.mjs item 17 regressions
 M client/account.js              item 18: sane-ceiling discard + cap clamp
 M client/app.js                  item 20: #admit data-mode marker
 M client/package.json            registers the two new client suites
 M backend/config.py              item 19: challenge refill 0.5 -> 2.0 + why
 M e2e/hostile-relay/*            item 20: mode-based checks + corrected README
?? backend/tests/test_rate_limit_invariants.py  item 19: relationship invariants
?? backend/tests/test_concurrency.py  item 15 regressions (real threads)
?? client/peer-approval.test.mjs      items 14/21 regressions
?? client/regseq.test.mjs             item 18 regressions
```

Green as of the end of the session, BEFORE any A2 fix: client 143 checks,
backend 154 passed, e2e 13/13 + 32/32 + 8/8 + 12/12, hostile-relay 5/5 control +
8/8 shipped + 8/8 attacker. Note that green does not cover any A2 finding — see
A3 for why (serial tests, no `app.js` unit surface, and the two confirmed
coverage gaps).

Per-finding PoCs from the three lanes were written to session scratchpads and are
NOT preserved; the reproductions are described in enough detail in A2 to rebuild
them. The one durable piece of attack tooling is `e2e/hostile-relay/`.

## ⮕ (2026-08-07, the 2026-08-07 pentest: 15 of 15 fixed, ONE UNVERIFIED)

Branch `pentest-2026-08-07-fixes`, **not merged, not deployed**. Backend
**154 passed**, client **143 checks**, e2e **13/13 + 32/32 + 8/8 + 12/12**
(room-admission, all-modes, two-user-flow, no-dead-ends). 20 files, ~1500 lines.

**Read this first: one fix is NOT verified.** The rebuilt F-PROTO-001 admission
check blocks the hostile-relay attack in both scenarios — but it does not stop
at the new refusal. No refusal line in the victim log, socket still `connected`
(so `ws.close()` never ran), no page errors, and both parties stall at the hello
phase instead. Until that is explained the fix may be holding for an incidental
reason, which is not a property to claim. Harness in the scratchpad `h/`
(`hostile.mjs` on :8099 policy=demote + `proto001.mjs`); note its relay log only
prints join/knock, so the absence of `key` lines there proves nothing.

**What was fixed.** All 14 Medium findings plus three Lows whose severity is
capped only by precondition (`F-CRYPTO-009` RSA parameter validation,
`F-CRYPTO-012` unusable pad sizes, `F-CRYPTO-014` the OTP lease lock). Details
per finding in the TODO section below.

**The fix pass was itself pentested, and it found five things — two of them
regressions this branch introduced.** That gate is why it is worth running:

* **F1 (High)** — the first F-PROTO-001 fix inferred ownership from "we minted
  this room code". Wrong twice: `selfMintedRooms` is empty after a reload and
  never holds a PASTED code, so the attack stayed open in the ordinary
  workflow. Rebuilt around a signed admission (below).
* **F2 (Medium, introduced)** — the same fix fired on an HONEST relay. Room
  ownership goes to whoever JOINS FIRST, not to whoever minted the code, so a
  peer connecting first made the minter a legitimate guest and the client
  disconnected them from their own room — silently, because `ws.onclose` →
  `showScreen("room")` → `clearHints()` wipes the message and the log line is in
  the hidden chat pane. Removed at the source.
* **F3 (Medium, introduced)** — `chats.js persist()` copied the generation,
  witness and write ordering from `contacts.js` but NOT its L-3 compare-and-swap.
  Every chat operation persists, so two tabs is the ordinary case: the stale tab
  silently discarded the `seenIds` replay ring and negotiated modes, and one
  interleaving left store gen < witness gen = **permanent unrecoverable
  lockout**. CAS ported; chats unlock failures now have their own message.
* **F4 (Medium)** — the anchor comments claimed the flag "cannot be deleted
  without deleting the identity". False: you roll the identity blob BACK, not
  delete it, and every pre-fix blob has no `flags` field, so today's blob on
  every device IS the archived artifact. Claim withdrawn in both files; the
  dependency on **F-ATREST-008** (identity blob has no anti-rollback control) is
  now stated where the fix lives.
* **F5 (Low-Med)** — revocation deleted only `pins["user:"+name]`, but live-room
  peers are pinned under `room:<id>` — usually the ONLY pin there is. Worse, the
  new test asserted the residual was correct. Now sweeps by bundle.

**Two contract changes that need saying out loud:**

1. **Directory key rotation now requires a counter.** `register/v3` carries a
   signed monotone `seq` (new `reg_seq` column). A registration WITHOUT one may
   only ADD encryption keys to an account that has none — it can no longer
   change or clear published ones, because a hostile replay is indistinguishable
   from a genuine rotation. `test_same_identity_reregistration_refreshes_keys`
   asserted the old, vulnerable contract and was rewritten.
2. **Directory login is dual-scheme.** `/auth/verify` requires Ed25519 AND
   ML-DSA over the same challenge. Old clients get a clean 401. Both decoy paths
   run the ML-DSA verification anyway so the 401 does not become the timing
   oracle F-RELAY-007 already noted (measured: ML-DSA verify ~7 ms).

Also a wire break worth knowing: the admission proof (`adm` in the key frame,
domain `secure-chat/room-admission-proof/v1`) is a separate signature rather
than a new field in the `handshake/v3` transcript — deliberately, so the
transcript is not silently changed — but a client that does not send it is
refused as unapproved.

**Not done, and deliberately not decided alone:**

* **F-CRYPTO-009 residual.** Partial validation cannot certify a modulus is a
  product of two large primes, so `e=65537` with `n = <small factor> × <large
  prime>` still hands an RSA session to a passive observer. Closing it needs a
  contributory root — which needs a THIRD handshake frame, breaking app.js's
  "answer the initiator exactly once" invariant — or deprecating RSA transport.
* **Lock-on-background (F-ANDROID-003).** `FLAG_SECURE` is set, which closes the
  filed recents-snapshot leak. Lock-on-background is a different threat and would
  re-prompt for the passphrase on every app switch.
* **Anchor vs. identity restore.** There is no restore-from-backup flow today
  (`Identity.import` only ever reads the localStorage blob; export is
  clipboard-only), so this is unreachable — but if one is added, restoring a
  backup carrying `contactsEstablished` onto a store-less device is a lockout.
  Device-scoping the flag does NOT work: a device id in localStorage is
  deletable, which reopens the original hole.
* **Android build is unverified.** `FLAG_SECURE` is correct by inspection but was
  never compiled: `./gradlew compileDebugKotlin` fails on this machine with
  `25.0.3-ea` (JDK 25 vs this Gradle/AGP). Confirmed identical on unmodified
  master, so it is pre-existing and not caused by the change. An open question
  from the review: the JS `prompt` AlertDialog is a separate `Window` and may
  need its own `FLAG_SECURE` on some API levels.

**Run the relay for e2e with the venv, not `./run.sh`** — `run.sh` uses the
system python and dies on `ModuleNotFoundError: dilithium_py`:

```bash
cd backend && SECURE_CHAT_DB=/tmp/e2e.db .venv/bin/python -m uvicorn main:app \
  --host 127.0.0.1 --port 8000 --no-server-header --no-proxy-headers \
  --no-access-log --log-level warning --ws-max-size 66560 &
```

## ⮕ (superseded) 2026-07-28, Tor onion service LIVE

**The last never-started checklist item is done.** The relay is reachable at
`http://626vkwn6znrko2xhorirvv5ttrbzcr3xkdjmk65cks26qkvadplyk5id.onion`
alongside the clearnet site, and a full relay round trip over Tor — including
the P-08 owner-approval flow — is proved from the laptop.

**Shape of it.** Tor 0.4.9.11 on the Debian 13 box publishes one v3 onion
service forwarding to `127.0.0.1:8000` — the *same* uvicorn Caddy proxies to.
Sharing the process is deliberate: rooms, session tokens and login challenges
live in memory, so a second instance would split-brain them (same room id, two
different rooms, one per front end). uvicorn still binds loopback only.

**The decision that mattered: `SECURE_CHAT_TRUSTED_PROXIES` is now UNSET.**
It was `127.0.0.1` so `/api` could rate-limit per client IP behind Caddy. Once
Tor also forwards to that port, loopback stops meaning "came through Caddy" —
the app cannot tell the two apart — so trusting it would let any onion visitor
forge `X-Forwarded-For` and mint a fresh bucket per request. That is **F-03
reopened**, against the anti-enumeration lookup limiter, the challenge limiter
and the mailbox limiter at once. Unset, `client_key()` trusts nobody and
everything keys on one shared bucket: fails closed. Measured on the live onion,
16 parallel lookups, `LOOKUP_RATE_CAPACITY = 10`:

| `X-Forwarded-For` | allowed | 429 |
|---|---|---|
| rotating, 16 distinct values | 10 | 6 |
| fixed, 1 value | 10 | 6 |

Identical, and exactly the bucket capacity — the forged header buys nothing.
Had it been honoured, the rotating run would have scored 16/16, so the probe
distinguishes the two hypotheses on the number alone.

> **🔴 CORRECTION 2026-07-29 — the paragraph above is WRONG and the measurement
> that produced it was inadequate.** `client_key()` does not collapse to one
> bucket; it collapses to **two**, and the client selects which one with a single
> header (`X-Forwarded-For: 127.0.0.1` → `'!untrusted-forwarded'`, anything else
> or absent → `'127.0.0.1'`). Both rows of the table above used `203.0.113.x`,
> which land in the SAME branch, so the probe never separated the hypotheses at
> all — it only ever measured one bucket twice. Every `/api` limiter is 2×, and
> an attacker can starve the bucket honest traffic uses while working the
> uncontended one. See M-1 in `docs/pentests/secure-chat-pentest-2026-07-29.md` and item 1 of
> the TODO. The claim is repeated verbatim in `deploy/README.md` and in commit
> `d338e15`'s message; both need the same correction when it is fixed.
>
> **✅ FIXED 2026-07-30.** `client_key()` is now a pure function of the peer: it
> ignores `X-Forwarded-For` entirely when no trusted proxy is configured, so
> there is exactly ONE bucket per peer whatever the headers say. The forgeable
> `peer in hops` detector is gone — with it went L-9, since that predicate was
> also how a remote attacker burned the H-4 warning. Runtime detection of a real
> rewrite now keys on the PORT (uvicorn synthesises `(host, 0)` from a bare-IP
> hop, and no genuine TCP peer has source port 0), which the client cannot set:
> no false positives, so it cannot be provoked. It is explicitly a diagnostic,
> NOT the control — the control is `--no-proxy-headers`, and all three launch
> paths are now held to it by tests, including `deploy/secure-chat.service`,
> which had none. `deploy/README.md` is corrected in place with the third table
> row that separates the hypotheses. Commit `d338e15`'s message cannot be
> rewritten and stays wrong; this note is the correction of record.

**Accepted cost:** the
clearnet side loses per-IP limiting too and shares that global bucket, so one
clearnet abuser can throttle onboarding for everyone. `config.py` already sizes
`REGISTER_RATE_*` for this exact posture. Keeping per-IP limits would need a
Caddy-injected secret header and a code change to `client_key()` — offered and
**not** taken. Tor's `HiddenServicePoWDefensesEnabled 1` is on partly to blunt
the volume attack the shared bucket invites.

**Hardening applied to the tor daemon:** `SOCKSPort 0` (the Debian default
otherwise opens `127.0.0.1:9050` **and a world-writable unix socket** at
`/run/tor/socks` — neither is needed to publish a service, and both would let
any local process route through Tor); `ORPort 0` / `DirPort 0` / `ExitRelay 0`;
and `SafeLogging 1` + `Log warn syslog` so the onion daemon does not reintroduce
the per-connection metadata trail I2 removes everywhere else. Verified after
restart: no 9050, no unix socket, service keys `0600 debian-tor`.

**Verified from the laptop over Tor** (local `tor` as an unprivileged process,
SOCKS on 9050):
- `/healthz` and `/` → 200 on the first attempt.
- **No HSTS on the onion** (correct — `x-forwarded-proto` is absent there, and
  HSTS is meaningless for `.onion`), no `server` header, CSP intact.
- The served assets are the current ones (`CONFIRM_DOMAIN`,
  `sc.contacts.gen.v1`, `sc.otp.wm.v1`, `adoptLegacy`).
- Dev files 404 including the P-10 spellings (`//package.json`,
  `/vendor/lean-qr/package.json`).
- **9/9 relay checks** via `deploy/onion-ws.mjs`: WS upgrade through Tor, owner
  seats first, second peer is *queued not seated* (P-08), knock relayed
  verbatim, admit seats the guest, payloads relayed unchanged both ways,
  **foreign Origin still refused (403)**, absent Origin still accepted.

`deploy/onion-ws.mjs` exists because Node's built-in WebSocket cannot speak
through a SOCKS proxy and `e2e/`'s `puppeteer-core` is gitignored, so it does
SOCKS5 + raw RFC 6455 by hand with no npm dependency. Worth keeping for the same
reason the CDP pad-injection harness was: it tests the deployed thing.

**`deploy/` is new** and holds the unit, the torrc block, and the Caddyfile
**pulled from the running box**, not written from memory, plus the recipe and
the trade-offs.

**Two honest limits.**
1. **This onion is not location-anonymous.** It is colocated with a public
   clearnet site on the same host, so anyone who knows both correlates them, and
   the clearnet site stays an attack surface into the same box. That needs a
   host with no clearnet service, not a config change.
2. **The onion does not fix H-02.** It still serves the JavaScript, so a
   compromised server can still ship backdoored code on the next load. The
   Android app remains the only answer to that. What the onion *does* buy is a
   self-authenticating address (no CA, no DNS) and no client IP at the relay.

**Not done — the Android half.** The app still points at
`https://138-199-144-35.sslip.io`. Pointing it at the onion needs **Orbot** on
the phone (a WebView cannot resolve `.onion` by itself); `RelayUrls.kt` already
accepts `.onion` hosts and `network_security_config.xml` already scopes
cleartext to loopback + `.onion`, so it is an on-device task, not a code change.
The phone was not connected this session.

**Mistake worth recording:** the first unit rewrite used an unquoted heredoc
with `\$ONION`, which wrote the literal string into
`SECURE_CHAT_EXTRA_ORIGINS`. `config._valid_origins()` did exactly its job and
raised at import — so the relay failed to start and the clearnet site was down
for about a minute until the origin was corrected. That fail-closed validator
turned a silent misconfiguration into an immediate, obvious outage, which is the
behaviour its P-15 comment promises. 29 accounts before and after; backups at
`/root/{secure-chat.service,Caddyfile,torrc,accounts.db}.bak-2026-07-28-tor` and
`/root/secure-chat-predeploy-2026-07-28-tor.tar.gz`.

**Not proved:** the counterfactual run (restore `TRUSTED_PROXIES`, watch the
onion score 16/16, revert) was blocked by the sandbox as a live-box hole and was
not worked around. The measured `10` above already separates the hypotheses, but
nobody has *watched* the bypass happen on this deployment.

## ⮕ (superseded) snapshot as of 2026-07-28, every 2026-07-27 pentest finding fixed

**All 4 High, all 7 Medium, and L-1..L-6 from `docs/pentests/secure-chat-pentest-2026-07-27.md`
are fixed, with regression tests.** **Committed and pushed 2026-07-28**
(`dc182d7` on `pentest-2026-07-27-fixes`, merged `--no-ff` as `97c0754`; both on
`origin`). **DEPLOYED to Hetzner + APK installed on the phone 2026-07-28** —
backend and client rsynced, `chown securechat` + `systemctl restart`
(relay PID 206611, `--no-proxy-headers` intact), then `adb install -r`
immediately after so the two-client break was never live for more than the
restart. Pre-deploy backups on the box: `/root/accounts.db.bak-2026-07-28-p27`
and `/root/secure-chat-predeploy-2026-07-28-p27.tar.gz`; **28 accounts before
and after**. Verified live over loopback: `/` and `/healthz` 200, and the served
assets are the new ones (`CONFIRM_DOMAIN` in `crypto.js`, `sc.contacts.gen.v1`
in `contacts.js`, `sc.otp.wm.v1` in `otp.js`). Verified on the phone: clean
launch (no `AndroidRuntime`), `sc.identity.v1` / `sc.contacts.v1` /
`sc.chats.v1` / `sc.username.v1` / `sc.lookuptoken.v1` all still present in the
WebView leveldb, relay pref still `https://138-199-144-35.sslip.io`, and
`healthz` 200 from the device.

**Contact-store migration v3→v4 CONFIRMED ON-DEVICE 2026-07-28.** The user
unlocked on the phone; the app opened normally and `sc.contacts.gen.v1` now
exists in the WebView leveldb alongside `sc.contacts.v1`. That is the migration
running forward against a genuine pre-fix store on real hardware — the thing the
unit tests could not prove.

### 🔴 OTP pad migration v2→v3 was BROKEN — found on-device 2026-07-28
**FIXED (`bf6bcd2`), regression-tested, DEPLOYED + APK reinstalled 2026-07-28,
and re-proved on the phone against the fixed client.**

**A pre-fix OTP pad that was ever USED is permanently refused after the upgrade.**
Tested by generating a genuine v2 blob with the pre-fix `otp.js` (from `e86a60b`),
injecting it into the phone's real WebView localStorage over CDP, and calling the
DEPLOYED `unlockPad()`. Result:

| pre-fix v2 pad | legacy `sc.otp.hw.v1` | outcome |
|---|---|---|
| used (`sendOffset` 1234) | present, `1234` | **REFUSED** — *"the rollback record for this pad is missing … exchange a fresh pad"* |
| pristine (`sendOffset` 0) | absent | migrates fine → `v:3`, opaque `sc.otp.wm.v1` written |

**Root cause — `client/otp.js:497-499` contradicts `client/otp.js:511`.**
```js
const knownUsedHere = Number.isInteger(inner.hwSend) || Number.isInteger(inner.hwRecv) ||
  readLegacyHW(padId) > 0 || localStorage.getItem(usedKey(padId)) !== null;
if (outerWm === null && knownUsedHere) throw new Error("the rollback record … is missing");
```
Line 511 already treats `readLegacyHW(padId)` as a legitimate migration floor
(`max(outer, inner, legacy)`), but line 498 treats the mere existence of that
same legacy watermark as proof a v3 record *should* exist, and throws before
reaching it. A pre-fix pad has no `sc.otp.wm.v1` by definition — it predates the
scheme — so every used one hits `outerWm === null && knownUsedHere`.

**Proposed fix: drop `readLegacyHW(padId) > 0` from `knownUsedHere`.** The other
two clauses are the ones that actually catch H-3, and neither false-positives on
a genuine pre-fix pad: `inner.hwSend/hwRecv` live inside the AEAD and exist only
in v3 blobs, and `sc.otp.used.v1.*` is written only by post-fix code. Nothing is
lost — the legacy value still applies as a floor at line 511, and `otp.js:93-95`
already states it is "never load-bearing for a rollback decision on its own"
because it is attacker-writable plaintext. **Do NOT gate on the outer `v` byte
instead** — it is outside the AEAD and `otp.js:466-468` documents that exact
downgrade trap.

**Why the tests missed it:** every pad in `otp-rollback.test.mjs` is built by
`otp.generatePad()` from the NEW module, so it is v3 with a `sc.otp.wm.v1` from
birth. No test ever constructs a v2 blob carrying a legacy `sc.otp.hw.v1`. The
2026-07-28 claim that the migration was "covered by tests" held only for the
pristine case.

**Impact:** fail-CLOSED, so no key material leaks — but anyone holding a pre-fix
pad that has sent even one message is locked out of it and must exchange a fresh
pad in person. **Zero impact on this user right now: the phone has no pads** (the
test pad was removed afterwards; `sc.otp.*` is empty again, verified).

**Fix applied `bf6bcd2`:** the legacy clause is gone from `knownUsedHere`; the
two remaining sources are written only by post-fix code, so neither
false-positives on a genuine pre-fix pad and H-3 still fails closed.
`padWasUsed()` still consults the legacy marker, which is correct — that path is
fail-closed by construction. The regression test reconstructs a real pre-fix pad
and asserts it migrates, that the floor survives as `inner.hwSend`, and that H-3
still bites once the pad is v3; **verified to FAIL before the fix**. Client
suites now 85 checks / 8 suites, backend 129.

**SHIPPED 2026-07-28.** Client-only change, no wire-format or protocol impact, so
this was NOT the two-client break P-08 and key confirmation were. Deployed via
the safe rsync recipe — **exactly one content transfer, `client/otp.js`** —
`chown securechat` + restart; backups `/root/accounts.db.bak-2026-07-28-otpfix`
and `/root/secure-chat-predeploy-2026-07-28-otpfix.tar.gz`; **28 accounts before
and after**; `/` and `/healthz` 200. APK rebuilt (`syncWebClient` picked it up,
`assets/web/otp.js` byte-identical to source and verified BEFORE installing),
`adb install -r` → Success, clean launch.

**Re-proved on real hardware against the FIXED client** by re-injecting the very
pad that had been refused:

| check | result |
|---|---|
| used pre-fix pad (`sendOffset` 1234, legacy hw 1234) | **migrates** → `v:3`, opaque `sc.otp.wm.v1` written |
| offsets preserved through the migration | `sendOffset` 1234, `recvHighWater` 777 |
| re-unlock after migration | still 1234 / 777 |
| delete the watermark post-migration (the H-3 PoC) | **still REFUSED** — the fix did not buy migration at H-3's expense |

**CORRECTION — "H-3 still fails closed" was overstated.** `bf6bcd2`'s commit
message and the row above claim it without qualification; the `pentest-new-code`
review of that diff (2026-07-28) showed it holds **for v3 blobs only**. On a
**v2-shaped** blob there is no `inner.hwSend`, so the whole evidence set is
`sc.otp.used.v1` — one deletable plaintext key — and H-3 is bypassable. See F-1
below. The review confirmed against `bf6bcd2^` that this is **pre-existing and
not a regression**: the old `readLegacyHW` clause was defeated just as cheaply by
deleting `sc.otp.hw.v1`. It also proved the fix **never lowers a floor** in any
attacker-reachable state. So the fix is sound; the claim around it was too broad.

Test residue removed afterwards; `sc.otp.*` is empty again and the phone is back
to exactly its six real keys, verified. Repro tooling kept in the session
scratchpad (`make-v2-pad.mjs`, `migrate-on-phone.mjs`, `h3-still-closed.mjs`,
`cleanup-phone.mjs` — pre-fix `otp.js` from `e86a60b`, CDP over `adb forward` to
`webview_devtools_remote_*`). **That injection harness is the thing worth
keeping**: it is what caught a bug six suites of unit tests could not, because
every unit test builds its pad with the CURRENT code.

**BREAKING protocol change again** (third one, after handshake v3 and P-08): a
key-confirmation frame now gates the verification step, so relay and client are
fine but two CLIENTS must both be new — an old client never sends `confirm`, so
a new peer waits at "Confirming that both sides derived the same key…" forever.
Deploy the client and rebuild the APK together, exactly as for P-08.

Storage formats bumped: contact store **v3 → v4** (adds an authenticated
generation counter + a `sc.contacts.gen.v1` witness), OTP pad blob **v2 → v3**
(watermarks and `exported` move inside the AEAD, new `sc.otp.wm.v1.<id>` record).
Both migrate forward on first unlock and both are covered by tests; a genuine
pre-fix store is adopted, not rejected.

What was done, by finding:
- **H-4** `main.py`'s `uvicorn.run()` now passes `proxy_headers=False` +
  `forwarded_allow_ips=[]` (it did not), and `accounts.client_key` additionally
  DETECTS a rewrite (peer address appearing among the client-supplied hops) and
  falls back to one shared bucket, so no launcher can reopen it.
  **CORRECTION (2026-07-28): this never affected Hetzner, and the earlier note
  here claiming "the live relay is still running the old launcher — restart it"
  was wrong.** It was written from the finding's wording without checking the
  box. Verified on `138.199.144.35`: the systemd `ExecStart` is
  `/opt/secure-chat/venv/bin/python -m uvicorn main:app … --no-proxy-headers …`
  with `Environment=SECURE_CHAT_TRUSTED_PROXIES=127.0.0.1`, and the running
  process (PID 192873, started 2026-07-27 19:35) carries both. Production has
  never used the `python main.py` launcher, so `main.py`'s `uvicorn.run()` args
  are dead code there — a restart could not have applied this fix, and no
  restart was performed. The F-03 defense has been live since 2026-07-25 (see
  the systemd-unit edit at the 2026-07-25 entry, incl. the through-Caddy test
  that a rotating spoofed `X-Forwarded-For` still gets 429 after 10).
  The finding itself was real but scoped to the **local** dev relay: the pentest
  report's own rules-of-engagement note identifies it as the pre-existing
  `python3 main.py` (PID 15001) that held local :8000, and its executive summary
  states production was never contacted. §H-4 called that instance "live", and
  its remediation step hedged accordingly ("or is actually run via `run.sh`").
  The `client_key` half IS genuinely undeployed and ships with the next normal
  deploy — it is defense-in-depth against a future misconfigured launcher, not
  protection against anything running today.
- **H-1 + M-4** `unb64`/`b64ToBuf` are canonical-only (decode → re-encode →
  require equality), so the byte-domain/string-domain split is gone. Bundles
  compare on decoded bytes, received bundles are canonicalized at the handshake
  and knock boundaries, the DHKE reflection guard compares the POINT, and
  `_b64decode_fixed` closes the same hole server-side at registration.
- **H-2 + L-1** `migrateLegacyPins()` is gone (it laundered plaintext pins into
  the authenticated store on every unlock); the plaintext key is now only
  deleted, never read. Contact store gained a monotonic generation + AEAD
  witness: rollback, deletion, and witness removal all fail closed, and
  `hasStore()` reports "expected" so app.js takes the loud P-02 path.
- **H-3 + M-7 + L-3** OTP watermark is an AEAD record under the pad's at-rest
  key, covers send AND recv, is mirrored inside the blob (max wins), and a pad
  that has demonstrably run here but cannot produce a watermark fails closed.
  `exported` moved inside the AEAD. One plaintext marker remains, deliberately:
  `importPad` holds only the transfer passphrase and cannot open the record —
  documented in `padWasUsed`.
- **M-2** owner refuses a handshake when it admitted nobody; guest refuses a seat
  it never queued for (`wasPending`), which closes the "tell both sides they are
  guests" variant.
- **M-3** binary frames and deeply-nested JSON are answered politely; client-input
  errors never reach `log.exception`.
- **M-5** explicit key confirmation (HMAC of the initial chain heads under a
  domain-separated context) before verification unlocks. Note the finding's
  route (a) fell out of the H-1 fix, and a local-invariant fix for route (b) is
  IMPOSSIBLE — the honest staggered PQKEM order is indistinguishable from the
  attack from inside one endpoint (see the comment in `_derive`).
- **M-6** `RATCHET_MAX_SKIP` 1024 → 64. The suggested skipped-key cache was
  deliberately NOT taken: it trades a real forward-secrecy property
  (`crypto.test.mjs` asserts a skipped frame stays undecryptable) for speed
  against an adversary the smaller window already handles.
- **M-1** the relay now tells the owner when joins are turned away (batched by
  `TURNAWAY_NOTICE_SEC` so the warning cannot itself be flooded). A per-source
  sub-quota was rejected: behind Tor every peer is loopback, so it would cap the
  whole queue.
- **L-2** an AES256 chat that receives a message with no inner layer now says so.
  **L-4** handle + lookup token are wiped by "Forget identity". **L-5** the OTP
  receive path gained the send path's spent-keystream check. **L-6**
  `dataExtractionRules` disables device-to-device transfer (it copied the pad
  blobs and watermarks to a new phone).

Green: backend **129 passed** (was 121; +8 new), `client` `npm test` 84 checks
across 8 suites incl. the new `canonical-b64.test.mjs`, and all three e2e
harnesses against a scratch relay — **13/13, 8/8, 12/12**. Note for whoever runs
e2e next: point it at a scratch DB *and* set `SECURE_CHAT_EXTRA_ORIGINS` to the
test origin, or the WS allow-list rejects every connection and it looks like a
code bug.

The APK was **built** (not installed) to prove the L-6 manifest change compiles:
`aapt2 dump xmltree` confirms `dataExtractionRules` resolves to the new resource
with the `<device-transfer>` exclusions, and `assets/web/` carries the fixed
client (gradle `syncWebClient` picked it up). Installing is still to do.

One bug was found and fixed in this session's OWN work while re-reading it:
`Room.turnaway_notified_at` defaulted to `0.0`, and `time.monotonic()` counts
from process/boot start — so the very first M-1 notice would have been swallowed
during the relay's first `TURNAWAY_NOTICE_SEC`. Now `-inf`, with a test.

A reusable `pentest-new-code` agent now lives in `.claude/agents/` (and
`~/.claude/agents/`) — it audits the changed diff rather than the whole system.

## (2026-07-27, P-08 fixed: room entry is now owner-approved)
**User-designed fix for the last accepted-risk finding.** Their proposal: a peer
who joins a chat code it did not create does not get in — the creator gets a
prompt showing that peer's public key and web-of-trust rating and decides.
Implemented, pentested by a separate agent, and driven by two real browser peers.

**BREAKING protocol change** (like handshake v3): relay and client must be
updated together. A new client refuses an old relay's bare `{"joined"}` — no
`role` means no admission control, and silently running the protocol this fix
removes would be the worse failure. Committed and pushed 2026-07-27
(`c753535` + `4a75769` on `master`), and **deployed to Hetzner** (see below).

**PHONE UPDATED 2026-07-27** — it had to be, in the same session: the APK
bundles its own copy of `client/` (gradle copies `../client` into assets), so
between the deploy and the reinstall the installed app was a pre-P-08 client
against a post-P-08 relay — a `join` into an occupied room is answered
`{"type":"pending"}`, which the old client does not understand, so it would
wait forever and never chat. Rebuilt and installed over the top:
`cd ~/secure-chat/android && ANDROID_HOME=$HOME/android-sdk ./gradlew
assembleDebug -Dorg.gradle.java.home=$HOME/jdk-21.0.4+7 && adb install -r
app/build/outputs/apk/debug/app-debug.apk` (`assembleDebug` — a release-signed
APK is rejected as a signature mismatch and forces an uninstall, destroying the
on-device identity). Verified: the APK's `assets/web/app.js` carries
`admittedBundle` BEFORE installing, `adb install -r` → Success, app launches
clean (no `AndroidRuntime` exception), **`sc.identity.v1` / `sc.contacts.v1` /
`sc.chats.v1` all still present** in the WebView leveldb (`adb shell run-as
org.securechat.app`, path is `app_webview/Default/Local Storage/leveldb` — the
`Default/` segment is new vs. what older notes imply), Step 1 renders with the
stored identity LOCKED, and the phone reaches the deployed relay
(`secure_chat_prefs.xml` → `https://138-199-144-35.sslip.io`, `healthz` 200
from the device shell). NOT driven through a full chat on-device — that needs
the identity passphrase, which is the user's.

Incidentally, the 2026-07-25 UI nit below (Unlock should be the primary on a
locked Step 1, not "Continue without an identity") is FIXED — the on-device
screenshot shows Unlock as the blue primary.

**DEPLOYED to Hetzner 2026-07-27** (backend + client via the safe rsync recipe
below, `chown securechat` + `systemctl restart`). Pre-deploy backups on the box:
`/root/accounts.db.bak-2026-07-27-p08` and
`/root/secure-chat-predeploy-2026-07-27-p08.tar.gz`; **28 accounts before and
after**, journal clean, `/` and `/healthz` 200. Verified live against
`wss://138-199-144-35.sslip.io/ws` with a three-step smoke check: owner join →
`{"type":"joined","role":"owner"}`, second join → `{"type":"pending"}` (no
`role`, no member slot), the knock reaching the owner with a 16-hex `jid`, a
waiting socket's `msg` refused `not in room`, and `deny` → `{"type":"denied"}`
+ close. The served assets are the new ones (`admittedBundle` in `app.js`,
`#admitOk` in `index.html`). Backend suite re-run before deploying: **121
passed** (needs a venv from `backend/requirements.lock` — the old one was in a
deleted scratchpad, same trap as `e2e/node_modules`).

**What actually fixes P-08: waiting costs the room nothing.** Membership was
first-come-first-served, so anyone with the room id could take one of the two
slots and lock the invited peer out with `room full`. Now the first joiner OWNS
the room; every later joiner is QUEUED (`{"pending"}`) and consumes no member
slot. `MAX_ROOM_MEMBERS` is enforced at ADMISSION, not at join — that separation
is the fix, not the prompt. Wire: `join` → `{"joined","role":"owner"}` or
`{"pending"}`; the waiter sends `knock` (its opaque self-introduction, forwarded
verbatim with a server-issued 64-bit `jid`); the owner answers `admit`/`deny`.
Relay-side state is a `Conn` object, not the read loop's locals, because a guest
is admitted by the OWNER's coroutine.

**The prompt is not the security boundary — the pin is.** `admittedBundle`
records the identity the owner approved, and the handshake REFUSES any other
identity (`app.js`). Without that, a relay could show the owner a knock from a
trusted contact and then hand the seat to someone else. The knock signature
(`secure-chat/knock/v1`, its own domain so it can never be read as a handshake)
has **no freshness and cannot get any**: the only party who could issue a
challenge is the relay, i.e. the party being constrained. So a hostile relay CAN
replay a genuine knock and make the owner see a real fingerprint — it just
cannot complete that identity's handshake afterwards. The comments say so.

**Three agent-found bugs in my own fix, all real, all fixed** (two rounds — the
agent re-attacked the fixes and found that the first fix had itself introduced a
new primitive):
- **The queue became the new lockout.** A socket that joins and never knocks is
  invisible to the owner — no prompt, no jid, nothing to deny — so 4 silent
  sockets reproduced the exact `room full` lockout for the full 120 s approval
  window. Reproduced by hand before fixing (`INVITED -> room full`). Fixed: a
  queue place is only HELD by an introduction. Un-knocked waiters get
  `KNOCK_TIMEOUT_SEC = 10`, and when the queue is full a newcomer DISPLACES the
  oldest un-knocked waiter; only if every waiter has knocked is a join refused.
  Re-verified: the same PoC now ends `INVITED -> pending`.
- **`decideKnock` moved the pin on every click.** A chat holds two people, so a
  second admit is refused by the relay — but the client had already re-pinned to
  the second knocker, and the peer already in the room then failed the identity
  check and was disconnected *by its own owner*. Fixed: one admit per session
  (`admittedSomeone()` guard + `#admitOk` disabled once someone is in, with the
  reason on screen). The agent flagged this without reproducing it end-to-end and
  said so — it was right on the code.
- **The eviction fix became a weapon of its own (found in round two).** Every
  honest peer is un-knocked for one round trip too — between being told
  `pending` and its knock landing — so an attacker holding the rest of the queue
  could time a join to evict the INVITED peer inside exactly that window,
  before it could introduce itself. ~1 ms on loopback, hundreds of ms over the
  .onion this is meant to run on. Fixed with `KNOCK_GRACE_SEC = 2.0`: nothing is
  displaced before it has had a fair chance to knock, and if that leaves nothing
  displaceable the NEWCOMER is refused rather than an innocent waiter dropped.
  Verified dead by hand: `attacker -> room full`, `invited survived`, and the
  invited peer still completes (`joined, role: guest`).

**One more of my own, found while reading the diff:** the handshake identity
check was gated on `roomRole === "owner"`, and the role comes from the RELAY —
so re-sending `joined` with `role:"guest"` would have switched the check off.
It now keys on `admittedBundle` alone (only ever set by our own click), and the
role is write-once: a role that CHANGES mid-session disconnects.

**Known limits, deliberate (documented, not silently accepted):**
- whoever joins an EMPTY room first owns it, so an attacker who learns a code
  and wins the race owns the room and can refuse everyone;
- four sockets that each knock once still fill the queue and the invited peer
  gets `room full`. The improvement is that this is now VISIBLE and deniable
  (the owner sees four knocks) and costs real connections, where before it was a
  silent 120 s hold — but an automated attacker refills faster than a human
  clicks, so it is mitigation, not closure;
- the owner cannot admit a REPLACEMENT after its peer leaves (one admit per
  session) — the relay sends no "peer left" signal, so the client cannot know
  the slot is free. The UI says to disconnect and start a new chat. Safe, and
  stated rather than silently broken.

All availability-only, all needing the cryptographic room-entry proof P-08 said
it would take. Confidentiality and integrity never depended on any of this.

**What the agent attacked and could NOT break:** waiting-socket isolation (a
knocker receives no `key`/`msg` and cannot send), non-owner and self admit,
forged/cross-room/unknown jids, the envelope rules (`jid` anywhere else is a bad
envelope), knock flooding, the admitted-identity binding ("admit A, route B"
fails closed), client injection via the attacker-controlled knock payload
(every sink is `textContent`, and a bundle is only rendered if `verifyKnock`
passes), protocol skew (old relay refused), I2 (no room ids/payloads/jids
logged), and the eviction path under a 20-socket churn storm (no
use-after-free, no double-close, no admit-vs-evict race — eviction only ever
targets un-knocked sockets, and an admit only ever names a knocked one).

**Green:** backend **121 passed** (was 103; +18 admission tests incl. the
squatter scenario, silent-waiter eviction, the grace that stops eviction being
aimed, non-owner admit, cross-room jid, waiting-peer isolation), client
`npm test` green, both live integration suites
green through the new dance, **`e2e/room-admission.mjs` 13/13** (new: three real
browser peers — owner, invited peer, squatter-who-knocks-first — asserting the
owner sees the knocker's true fingerprint, a waiter gets no key exchange and
cannot send, the squatter is denied, and the invited peer still completes),
two-user-flow 8/8, no-dead-ends 12/12.

**Gotchas for next time.** (1) `e2e/node_modules` was a symlink into a DELETED
session scratchpad — reinstall with `cd e2e && npm install --no-save
puppeteer-core` (it is gitignored). (2) The read loop must re-read `conn` state
AFTER `await receive_text()`: the pre-await snapshot left a just-admitted guest
unable to send, which `test_only_the_owner_may_admit` caught. (3) `#idFingerprint`
carries a `"Your fingerprint: "` label — strip it before comparing in tests.

## (2026-07-27, Android L-10 fixed — installed on the phone)
**The last open code item from the 2026-07-26 pentest is fixed.** `MainActivity`
used to call `addDocumentStartJavaScript` only `if` the WebView supports
`DOCUMENT_START_SCRIPT`, with **no `else`** — on an older WebView the relay
config was never injected, `RELAY` stayed null, and the client loaded anyway:
every fetch/WS went to the app's own unresolvable virtual origin
(`secure-chat.internal`) with an opaque error, and `promptSecret()` stopped
adding `SECRET_PROMPT_MARK`, so **passphrase masking silently degraded to the
substring heuristic F-08 retired**. Two silent failures, one of them security-
relevant.

**Now it refuses to run.** The feature check moved to `onCreate` (before the
relay prompt — it is a device capability, not a relay question) and is re-checked
in `loadWithRelay`, since "Relay settings" re-enters that path. `refuseToRun()`
blanks the WebView to `about:blank` so no half-configured client is left usable
behind the dialog, then shows a non-cancelable dialog naming the cause ("update
Android System WebView") whose only button finishes the activity.

**Plus a belt-and-braces check the finding did not ask for:** `onPageFinished`
evaluates `!!window.__SECURE_CHAT_RELAY__` and refuses if it is not `true`. The
feature check covers the known cause; this covers *any* reason the script did not
run (origin-allow-list mismatch, a WebView that advertises the feature and drops
it) by asking the loaded page itself. `evaluateJavascript` is a shell-level
injection, so the page CSP does not block it. It is scoped to `url == indexUrl`
and latched by `refusedToRun`, so the `about:blank` load cannot re-enter it and
stack dialogs; `refuseToRun` also bails on `isFinishing/isDestroyed` because that
callback is asynchronous.

**NEW test: `UnsupportedWebViewTest`** (Robolectric — its WebView provider
advertises no androidx.webkit features, so simply starting the activity
exercises the unsupported path). Asserts the dialog is shown, that it is OUR
dialog (compares the rendered `android.R.id.message` text — an earlier version
could have passed on the relay-address prompt), and that the WebView loaded
`about:blank` rather than the client. **Verified as a real regression guard:
reverting the fix makes it fail, restoring it makes it pass** (12 tests, 0
failures; the negative control ran both ways).

**Two gotchas worth keeping.** (1) Robolectric could not inflate the activity at
all until `testOptions { unitTests.isIncludeAndroidResources = true }` was added
to `app/build.gradle.kts` — without merged resources it runs in legacy mode and
AppCompat's own drawables are missing (`Resources$NotFoundException` deep inside
`checkVectorDrawableSetup`); `@Config(sdk = [34])` alone did not help. (2) The
dialog is an **androidx** `AlertDialog`, which `ShadowAlertDialog` does not
track — `ShadowDialog.getLatestDialog()` is the one that sees it.

**INSTALLED ON THE PHONE 2026-07-27** (`adb install -r` of the debug APK —
Success), committed on branch `android-l10-fail-loud` (`2ebb0f0`), **not merged
to master and not pushed**. Nothing here touches the backend or the web client,
so **no Hetzner deploy is needed** — this is Android-shell-only. Verified
on-device: the app starts normally on the phone's current WebView (step 1 of 3,
no refusal dialog) and the existing identity survived the update ("Your identity
is locked" — `sc.identity.v1` intact), which is the point of installing
debug-signed; a release-signed APK is rejected as a signature mismatch and would
force an uninstall, destroying the on-device identity.

**What on-device testing did NOT prove.** This phone's WebView supports
`DOCUMENT_START_SCRIPT`, so the refusal path never fired — it is covered only by
`UnsupportedWebViewTest`. And a normal-looking start is equally consistent with
"`verifyRelayConfig` ran and passed" and "it never ran" (e.g. if the
`url == indexUrl` match were ever wrong), because both look identical from
outside. Proving the belt-and-braces check actually fires needs a deliberately
broken build installed temporarily — not done, since it would leave the phone
running a broken app for the duration.

## (2026-07-26, first full pentest of the final product — ALL FIXED)
**Full pentest + remediation in one session.** Report:
`docs/pentests/secure-chat-pentest-2026-07-26.md` (findings in §4-6, remediation table in §9).
Method: the two test agents (`e2e/two-user-flow.mjs`) plus a new PQKEM live-room
canary harness drove two real browser peers while **tshark** captured loopback;
four specialist agents then attacked in parallel (packet exploitation + live
relay, whole-codebase review, backend pentest, client-crypto pentest). Every
High/Medium was re-verified by hand — agents were wrong in places (e.g. two
claimed static-path bypass vectors actually 404'd).

**Packet capture result: E2EE was NOT broken.** Zero canary plaintext, keys or
secrets recoverable; wire carries only public keys, dual signatures, random
nonces and unique-IV AES-GCM ciphertext. Active attacks (room hijack, replay,
handshake forgery/downgrade, CSWSH, oversized/malformed frames) all failed
closed. What leaks is **metadata** (room id, usernames, tokens, `alg`, sizes,
timing) — visible here only because loopback is un-TLS'd; in prod (wss/.onion) a
network observer sees none of it, but **the relay operator inherently does**.

**Counts: 0 Critical, 1 High, 6 Medium, 13 Low, 12 Info — all fixed** except
**P-08** (room-slot squatting, availability-only, accepted: a cryptographic
room-entry proof is a protocol change, and a hostile relay can DoS anyway) and
the two Android Lows (need an on-device cycle).

**The High (P-01) is worth remembering:** OTP pad `role`/`padId`/`regionSize`
sat OUTSIDE the AES-GCM tag, so a one-byte localStorage edit (`"role":1`→`0`)
pointed the sender at the peer's pad region — a full two-time pad, no passphrase
needed — and re-keying a blob under a fresh `padId` walked around the M-01
watermark. Stored blobs are now **v2**: everything security-relevant is inside
the AEAD, `unlockPad` asserts `inner.padId === requestedId`, the watermark is
keyed by the REQUESTED id, and v1 blobs migrate on first unlock. **Honest
residual: migration cannot retroactively detect tampering done while a blob was
still v1.**

**Other notable fixes.** Handshake transcript → **v3**, now binding the signer's
own bundle via a fixed-length `Identity.bundleDigest()` (a digest, not the raw
`_bundleBytes`, whose length varies 1984↔3233 and would have reintroduced the
F-07 splice ambiguity) — a relay swapping a peer's `ecdh`/`mlkem` now fails the
signature instead of relying on the human safety-number check. OTP consumption is
**write-ahead + fail-closed**. `forgetPad` KEEPS the watermark (forget+re-import
was the easiest route to a two-time pad, reachable by accident). Contact-store
unlock failure no longer silently disables key-change warnings.

**Gotcha found while fixing:** `backend/tests/` had no `conftest.py`, so the
module-global rate limiters leaked state between tests. The new conftest resets
them **and** must set `SECURE_CHAT_DB` *before* anything imports `config` —
otherwise a module-level import there resolves `DB_PATH` to the REAL
`backend/accounts.db` and the suite reads/writes production data (this happened
once; the 24 test accounts + 2 vouches inserted were identified by timestamp and
removed, leaving the 109 genuine accounts intact).

**An independent agent then reviewed the fix diff and caught a HIGH regression in
the P-01 fix itself** (report §9.1). The migration decided "is this legacy?" from
the OUTER, unauthenticated `v` byte — so deleting `"v"` from a v2 blob downgraded
it back to the vulnerable path and handed `role` to the attacker again (PoC:
`baseline role: 1 → ATTACK role: 0`). **Lesson worth keeping: a version/format
discriminator is a security-relevant input; outside the AEAD it silently
re-enabled the exact weakness the change removed.** Now discriminated on the
AUTHENTICATED plaintext (a real v1 payload has no inner `padId`), with a
regression test in `otp-rollback.test.mjs`. The review also produced 2 Medium +
5 Low fixes: the same dict race still live in `KeyedRateLimiter._prune`
(`relay.py` — every /api request hits it); unvalidated peer-chosen `seenIds`;
origin validation crashing the relay at import on a trailing-slash typo (startup
DoS); `otpPersistFailed`'s stop undone by `sendText`'s `finally`; 3 leftover
in-session `algValue()` reads; mailbox polling starving the shared /api bucket
behind Tor (now its own bucket); and P-17's self-test now proving all four keys
(KEM round-trip + ECDH point re-derivation), not just the signing pair.

**SHIPPED 2026-07-26.** Committed on branch `pentest-2026-07-26-fixes`
(`6fb2861`, NOT yet merged to master), APK rebuilt + installed on the phone, and
**deployed to Hetzner** (backend + client, service restarted, 28 accounts intact
before and after; pre-deploy backup `/root/accounts.db.bak-2026-07-26-0212` plus
a full tree snapshot `/root/secure-chat-predeploy-2026-07-26-0212.tar.gz`).
Verified live: `handshake/v3` served, all six dev-file paths 404 while the real
assets 200, a two-peer PQKEM session + the 8/8 two-user flow both green against
`https://138-199-144-35.sslip.io`, and the phone reaching the relay (`healthz
200`, `phoneHandshake: v3`). The two e2e accounts that run created in the LIVE
directory were removed afterwards (back to exactly 28).

**⚠️ The handshake v3 bump is a BREAKING protocol change** — a v3 client cannot
complete a handshake with a v2 one (the transcripts differ, so verification
fails and it surfaces as the "this is what a MITM attempt looks like" error).
Phone and website were therefore updated together, deliberately. Anyone still
running an older bundled APK must update before they can chat.

**Deploy gotchas confirmed this round:** the safe rsync recipe below is correct
and still necessary (a dry-run showed only the 11 changed files transferring, no
`accounts.db`). The APK must be built with `assembleDebug` — the installed app is
debug-signed, so a release-signed APK is rejected as a signature mismatch and
would force an uninstall, **destroying the on-device identity**; data was
verified intact after the update (`sc.identity.v1`, `sc.contacts.v1`,
`sc.chats.v1` all still present). The systemd unit already had both required env
vars (`SECURE_CHAT_TRUSTED_PROXIES=127.0.0.1`, `SECURE_CHAT_EXTRA_ORIGINS=…`);
the new P-15 origin validation was checked against those exact values BEFORE
restarting, since a malformed one would now abort startup.

**Green after fixes (both rounds):** backend 103 passed, client `npm test` green,
two-user-flow 8/8, no-dead-ends 12/12, live PQKEM canary harness green, all
four modes (DHKE/RSA/AES256/PQKEM) verified delivering in a real browser, and the
P-01-downgrade + P-03-bundle-swap PoCs both failing as they should.

## (2026-07-25, Android: duplicate title bar removed)
The app showed TWO stacked "secure-chat" bars — the native ActionBar plus the
web client's own header. **Fixed by dropping the native TITLE, not the bar:**
`supportActionBar?.setDisplayShowTitleEnabled(false)`.

**Why the bar stays.** Both menu items are `showAsAction="never"`, i.e.
overflow-only, and **"Relay settings" is the sole way to fix a wrong relay
address when the page cannot load at all** — hiding the bar would strand the
recovery path. What remains is a background-matched strip with just the ⋮.
Theme now paints the ActionBar / status bar / nav bar in the client's own `bg`
(`#0D1117`, new `app_bg`/`app_fg` colours) with 0dp elevation, so the native
chrome and the page read as one surface instead of two.
Verified on-device: overflow still opens with Reload + Relay settings.
**Gotcha:** `--` is illegal inside an XML comment; referencing the CSS custom
property names in `colors.xml` broke the resource merger.

## ⮕ (2026-07-25) UX pass: comprehension + accessibility
**Feedback from a real user: "hard to understand at first, very technical", and
"joining a live room without generating a code fails with no error message".**

**The missing error was a bug CLASS, not a missing string.** `#hint` lives
inside screen 3 (chat), which is `hidden` while you are on screen 2 — so all TEN
validation failures in `connect()` (empty code, bad code, missing identity, bad
contact handle, directory miss, no OTP pad, pad locked elsewhere, pad exhausted,
setup failure) wrote their message into an invisible element. Only 3 also called
`setStatus()`. **Fix:** `activeHintEl()` routes feedback to whichever screen is
visible (`#idHint` / `#roomHint` / `#hint`), so every call site is fixed at once;
`clearHints()` on screen change stops stale errors following you.

**Scope chosen by the user: reword + progressive disclosure, same screens/flow**
(not a full intent-first redesign — the safety-number gate and pentest fixes stay
exactly where they are).
- **The empty-code dead end is removed, not just explained**: a chat code is
  generated on arrival. `roomCode()` also normalises pasted whitespace/capitals,
  because a code that travels between two people arrives messy.
- **"Room id (64 hex chars)" → "Your chat code — share it with the one person
  you want to talk to"**, with Copy + New code buttons. The user called it a
  "seed", which was the tell that the old term did not land.
- **Encryption picker collapsed behind `<details>` "Security options — currently:
  X"**. Default DHKE. Choosing a non-default mode force-opens the panel and the
  summary names it, so a changed setting can never hide.
- Plain-language labels/errors throughout; "Skip — no identity (AES-256 / OTP
  only)" → "Continue without an identity", and the primary button moved to
  Create/Unlock (it was emphasising the escape hatch).
- **Accessibility:** 7 unlabelled inputs fixed — including `#text`/`#chatText`
  (the two message fields) and the three unlock inputs I shipped unlabelled last
  session. `aria-live` on all 10 status regions (only `#log` had it, so the
  safety number was silent to screen readers). Drawer: `aria-label`,
  `aria-expanded`, `aria-current`, focus into the drawer on open. Focus moves to
  the step heading on navigation — but NOT on first paint (that just drew an
  unrequested focus ring). Base text bumped (hints 0.78→0.84rem).
  **Contrast was already fine** — every token pair passes WCAG AA (4.58:1 to
  12.76:1), so the palette was left alone.

**NEW: `e2e/no-dead-ends.mjs`** — walks every failure path on the room screen and
asserts visible text appears, plus the a11y basics. 12/12. It deliberately reads
ONLY the dynamic feedback elements: an earlier version passed by matching static
help text, which proved nothing.

## ⮕ (2026-07-25) live two-person test: 2 UX/delivery bugs fixed
**A real test run with a second person found two bugs that every unit test and
single-user harness had missed — both about the SECOND user's experience.** Both
are fixed, and a reusable two-agent run now asserts them so they cannot regress.

- **Async chat delivered NOTHING unless the recipient had clicked "Log in".**
  `pollMailbox` needs a directory session (`apiToken`), and that was only ever
  obtained from the explicit Log-in button — registering did not do it. Sending
  worked, receiving did not, with no visible sign. **Fix:** `autoLogin()` runs
  after registration AND after unlocking an already-registered identity, and
  `pollMailbox` re-authenticates on a 401 (sessions last TOKEN_TTL_SEC = 1 h, so
  mail used to stop arriving silently once it expired). `account.fetchMail` now
  surfaces `err.status` so that is detectable.
- **An invite link was unusable in the tab it opens.** A new tab shares
  localStorage but NOT the in-memory unlocked identity, so it always started
  locked — and the only unlock control lived on the Live-room screen. **Fix:**
  Profile / Users / Chats each have an in-place unlock row (passphrase + Unlock,
  Enter submits), sharing a new `unlockWithPassphrase()`; on success the pending
  invite is applied so the handle is prefilled ready to Add.

**NEW: `e2e/` — reusable two-agent end-to-end run** (`node e2e/two-user-flow.mjs`,
relay must be running). Fixed passphrases in `e2e/test-users.json` (throwaway
test values, committed deliberately) so a failing step can be re-driven by hand
in a browser with the same accounts. Asserts: register-is-enough-to-receive,
invite-link-unlockable-in-place, mail from a stranger delivered as ⚪ under a
key-derived name, replies both ways, and 🟢 verification. **8/8 passing.**
Gotcha for whoever extends it: an invite tab must be opened in the SAME
puppeteer browser context (`newTab(label, alice.ctx)`) — a fresh context has no
localStorage and so no identity blob at all, which tests nothing.

## ⮕ (2026-07-25) pentest: ALL 8 findings fixed
**The remaining six findings (F-01, F-03, F-05, F-06, F-07, F-08) are now fixed,
tested and verified against their own PoCs.** See the updated
`docs/pentests/secure-chat-pentest-2026-07-25.md`. Backend **103 passed**, client `npm test`
green, Android unit tests green, all browser harnesses green.

- **F-01 (Medium) — contact injection.** The local contact label is now always
  derived from the sender's KEY (`neutralName()` → `unknown-<key>`); the
  self-claimed handle is kept as `claimedName` and rendered as an explicit
  warning row. **Because the local label no longer matches the directory name,
  addressing had to be split out** — contacts carry `addrUsername`, and every
  mail/vouch/lookup site goes through `dirName()`/`mailHandle()`. The PoC now
  yields `unknown-…` contacts; `regress-reply.mjs` proves replies to an
  auto-created contact still reach the right account (otherwise unsolicited
  chats would silently become one-way — the trap in this fix).
- **F-03 (Medium) — rate-limit keying.** No longer relies on uvicorn defaults:
  `run.sh` passes `--no-proxy-headers` and `accounts.client_key()` honours
  `X-Forwarded-For` only from a peer listed in the new
  `SECURE_CHAT_TRUSTED_PROXIES`, taking the RIGHTMOST hop. Default trusts
  nobody → a direct/.onion deploy fails CLOSED (one shared bucket) instead of
  open. **DEPLOY REQUIREMENT: the systemd unit must set
  `SECURE_CHAT_TRUSTED_PROXIES=127.0.0.1` for the Caddy box; leave it UNSET for
  .onion.** New `tests/test_proxy_headers.py`.
- **F-05 (Low)** — auto-created contacts marked `auto:true`, capped at
  `MAX_AUTO_CONTACTS = 50`; past the cap unknown senders are refused and the
  Chats view says why. `regress-cap.mjs`.
- **F-06 (Low)** — each envelope is filed by `processEnvelope()` in its own
  try/catch so one failure cannot discard the rest of an already-deleted batch.
  Defensive: the window was never demonstrated.
- **F-07 (Info)** — `_bundleBytes` asserts all four key lengths
  (32/1952/65/1184); the Users view shows "fingerprint unavailable" instead of
  hanging on "…".
- **F-08 (Info)** — secret prompts now carry an explicit `SECRET_PROMPT_MARK`
  that the Android shell strips and masks on, instead of guessing from the word
  "passphrase" (old check kept as a fail-SECURE fallback). Marker added only
  in-app, so browser dialogs are unchanged.

**SHIPPED 2026-07-25:** pushed (`88225d2`), deployed, APK rebuilt + installed.
**The systemd unit was edited on the box** (backup at
`/root/secure-chat.service.bak-2026-07-25-1617`): added
`Environment=SECURE_CHAT_TRUSTED_PROXIES=127.0.0.1` and `--no-proxy-headers` to
ExecStart — without BOTH, F-03's fix would silently degrade production to a
single global rate-limit bucket. **Any future re-provision of that unit must
carry these two changes.** Verified on the live box THROUGH Caddy (the real
attacker path): rotating a spoofed `X-Forwarded-For` now gets 429 after 10 —
no extra budget — while honest per-IP limiting still works. F-04 still 404s,
DB byte-identical, site 200.

**STILL OPEN (operational, not a code fix):** the phone runs the **DEBUG** APK,
so WebView debugging is live. Switching to the release build needs an uninstall
(different signing key) which **destroys the on-device identity blob and contact
store** — only do it with an exported backup or a fresh identity.

## ⮕ (superseded) snapshot as of 2026-07-25, in-depth pentest: 2 of 8 fixed
**Full-stack pentest run against `4b9f270`; report in
`docs/pentests/secure-chat-pentest-2026-07-25.md`. The crypto core held — nothing broke in
the handshake, ratchet, OTP, sealed envelope or web-of-trust. Every finding is
in the layer ABOVE the crypto: the async mailbox treats AUTHENTICATED data (the
sender really signed it) as TRUSTED (they are who they claim, and their values
are well-formed).** Deps clean (`npm audit` 0, `pip-audit` 0); starlette 1.3.1 /
fastapi 0.139.2 / cryptography 49.0.0 close the 2026-07-18 M-01/M-02/L-03.

**SHIPPED 2026-07-25:** pushed (`91dbdf7`), deployed to Hetzner (backend
changed → full chown+restart recipe; DB excluded and confirmed byte-identical
afterwards, pre-deploy backup at `/root/accounts.db.bak-2026-07-25-1603`), and
installed on the phone — F-02 is a CLIENT fix, so the APK rebuild is required,
not optional. Verified live: all three F-04 endpoints return 404 with no
traceback in the journal, and `isValidMode` is present in the deployed and
bundled `chats.js`/`app.js`.

**FIXED + committed this session (both re-verified against their own PoCs):**
- **F-02 (Medium) — chat mode string was unvalidated.** A peer could propose an
  arbitrary `mode`; on accept the header rendered `🔒 AES256 + verified by
  secure-chat` while `hasSecret:false` and NO inner layer was applied (every
  check is an exact `=== "AES256"`). Fix: `chats.MODES`/`isValidMode`
  allow-list, enforced in `setMode`/`setPending`/`ensure` AND dropped at the
  boundary in `app.js handleControl`; `chats.unlock()` sanitises an
  already-poisoned store (bogus mode → SEALED, phantom secret/salt dropped) so
  a victim heals on next unlock. New `client/chats.test.mjs`.
- **F-04 (Low) — `?t=ü` → HTTP 500 + traceback** on `/api/users/{u}`,
  `/api/users/{u}/vouches` and `/api/mailbox/{u}`: `hmac.compare_digest` raises
  TypeError on non-ASCII `str`. Not an existence oracle (both branches raised
  identically), but it broke fail-closed on the token gate and let anyone write
  tracebacks to the journal on demand (vs. I2). Fix: `accounts.token_matches()`
  compares UTF-8 **bytes** — constant-time preserved, decoy preserved. New
  `backend/tests/test_token_gate.py` (22 parametrised cases).

**STILL OPEN (highest first):**
- **F-01 (Medium) — contact injection.** `app.js:1142` derives a new contact's
  USERNAME from the attacker-chosen sealed `name`. PoC put contacts called
  `bank-support` and `alice` (attacker's keys) into the victim's Users+Chats
  lists, needing only the victim's public handle and no registered account. ⚪
  is shown correctly and is the real mitigation. Fix: use the neutral
  key-derived `fallback` name and show the claimed handle as an explicitly
  untrusted "claims to be …" field.
- **F-03 (Medium, deployment-gated) — rate-limit bypass off the proxy.**
  Rotating `X-Forwarded-For` gives a fresh bucket per request (16/16 allowed vs
  10-then-429). **Production is safe** (Caddy appends the real IP; uvicorn 0.51
  resolves rightmost-untrusted). The exposure is the planned `.onion` deploy,
  which forwards onion→127.0.0.1:8000 with no Caddy. Fix BEFORE that ships:
  `--forwarded-allow-ips=` when not behind a trusted proxy.
- **F-05/F-06 (Low)** — uncapped auto-created contacts (~5.9 KB each, ~880 to
  5 MB) and delete-on-read mail vs. unguarded batch processing. NOTE: I tried
  and **failed** to demonstrate the terminal failure for both — treat as
  resilience hardening, not confirmed defects.
- **F-07/F-08 (Info)** — `_bundleBytes` lacks per-field length checks (safe
  today because sizes are fixed); the phone runs the DEBUG APK so WebView
  debugging is live, and the Android passphrase masking is a `contains
  ("passphrase")` string match.

**Verified after the fixes:** backend **99 passed** (was 77; +22 new), client
`npm test` all green incl. the new chats suite, F-02 PoC no longer produces a
proposal, F-04 endpoints return 404 with no traceback, and the LEGITIMATE
AES256 negotiation (propose → accept → inner-layer round trip between two
honest peers) still works. Live-room + async-chat browser harnesses green.

## ⮕ RESUME HERE (snapshot as of 2026-07-25, redesign stage 2: hierarchy pass)
**User asked to continue the redesign; chose "go deeper on the visual design"
over shipping first. Stage 2 is BUILT and VERIFIED locally — deploy + APK
rebuild still PENDING (same rsync as every snapshot below; one rsync covers
all of them).** Presentation-only again: no crypto, no protocol, no new deps,
importmap untouched (`test_csp_hash.py` green).

Where stage 1 (2026-07-19) refreshed *tokens* — colors, radii, shadows — this
pass fixes *hierarchy*, which is what still read as cheap:

- **Dual type stack (the big one).** `--font-ui` (system-ui — NOT a web font,
  so `font-src` stays untouched and the CSP is unchanged) now carries labels,
  prose, buttons and nav; `--font-mono` is reserved for material read or
  compared character-by-character: fingerprints, safety numbers, room ids,
  handles, usernames, cipher specs (`.alg-desc`, `.badge.pq`), `.kv dd`.
  **User explicitly approved this** even though the stage-1 spec said "keep
  monospace" — it's the single biggest reason the UI looked like a terminal
  dump. Opt-in via a `.mono` selector list at the top of `style.css`.
- **Button tiers.** The DEFAULT `button` is now the quiet secondary; a screen
  earns at most ONE `.primary` (gradient blue) — Continue / Connect / Send /
  Add / Open / "It matches — unlock messaging" / Generate pad / Accept. Before,
  every "Copy handle" shouted as loud as "Connect". `.ghost` is now truly
  fill-less; `.danger` is a tinted red OUTLINE instead of a solid red block
  (every danger button is already confirm-gated in app.js). This DELETED the
  per-id overrides (`button#gen`, `#idCreate`, `#idUnlock`, `#otpImport/Export`)
  that existed only to undo the old loud default.
- **Profile view restructured** — `.idhead` (initial avatar + name + handle)
  replaces the flat "Name" row; Keys is a `<dl class="kv">` label/value grid;
  Status is a row of `.chip`s (on/off) instead of a `·`-joined sentence.
- **Drawer** gained a `.drawer-head` (wordmark) and a pinned `.drawer-foot`
  ("Keys never leave this device. The relay sees ciphertext only.").
- **Empty states**: new `emptyRow()` renders a dashed "No users yet" /
  "No chats yet" block in the list well (Users no longer just sets a hint).
- **Trust legend** is a 3-item `.legend` row, not a run-on paragraph.
- **Latent bug fixed:** added a global `[hidden] { display: none !important }`.
  `display:flex/grid` beats the `hidden` attribute's UA `display:none`, so any
  flex container toggled via `.hidden` stayed visible — the drawer had a
  one-off patch for this; the Profile copy-handle actions hit it the moment
  they became `.inline`. Now enforced once, globally.
- `renderHandleInto` switched from `className =` to `classList.toggle("ok")`
  so both call sites keep their own base classes.

**Verified** (harnesses in `scratchpad/verify/`, system Chromium via
puppeteer-core — `shots.mjs`, `flow.mjs`, `live.mjs`):
- Backend **77 passed** (unchanged), client offline `npm test` all green.
- `flow.mjs`: two real peers register + log in against the local relay, add
  each other by handle, verify (🟢), open an async SEALED chat — **bob received
  alice's message**; screenshots of the populated user rows / chat list /
  conversation, desktop + 390×844.
- `live.mjs`: two contexts join one room on AES-256, **both directions
  delivered**, disconnect clean. NOTE: the safety-number gate does NOT appear
  for two fresh unpinned identities (it needs a pinned contact) — that's
  by design; the harness treats it as optional.
- **Zero horizontal overflow** in every view at both widths; no pageerrors.
  Only console error is the known `/favicon.ico` 404.

**DEPLOYED + SHIPPED 2026-07-25.** Pushed to GitHub (`3e20702`), deployed to
Hetzner, and installed on the user's physical phone (Nothing A063 over USB;
`org.securechat.app`, launches clean, screenshot confirms the new type stack
and button tiers on-device). This ALSO finally made the long-pending
**vouch-v2 + mailbox-race backend fix (`a548f56`, pending since 2026-07-19)
live** — verified `vouch/v2` present in the deployed `accounts.py` and
`account.js`. The box had been serving Jul-18 code until now.

### ⚠️ THE OLD DEPLOY RECIPE WAS DESTRUCTIVE — DO NOT USE IT
Every earlier snapshot in this file records this rsync:
`rsync -az --exclude node_modules --exclude 'package*.json' --exclude
'*.test.mjs' --exclude __pycache__ backend client root@…:/opt/secure-chat/`
A `--dry-run` on 2026-07-25 showed it transfers **`backend/accounts.db`**
(plus `.venv/` and `.pytest_cache/`) — i.e. it **overwrites the live account
database with the local dev one**. Local was 327 KB (full of throwaway test
accounts); live was 176 KB. Always `--dry-run --itemize-changes` first.
**Use this instead:**
```
cd ~/secure-chat && rsync -az --itemize-changes \
  --exclude node_modules --exclude 'package*.json' --exclude '*.test.mjs' \
  --exclude __pycache__ --exclude '.venv' --exclude '.pytest_cache' \
  --exclude 'accounts.db*' --exclude '*.db' --exclude '*.db-shm' --exclude '*.db-wal' \
  --exclude 'tests' \
  backend client root@138.199.144.35:/opt/secure-chat/ \
&& ssh root@138.199.144.35 'chown -R securechat:securechat /opt/secure-chat/backend \
   && systemctl restart secure-chat'
```
A pre-deploy backup now exists at `/root/accounts.db.bak-2026-07-25-1333` on
the box. NOTE: `curl` to `https://138.199.144.35` fails from some networks
(direct-IP TLS); SSH works fine — verify over loopback on the box instead
(`ssh … 'curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:8000/'`).

**APK rebuild (worked as documented):**
`cd ~/secure-chat/android && ANDROID_HOME=$HOME/android-sdk ./gradlew
assembleDebug -Dorg.gradle.java.home=$HOME/jdk-21.0.4+7 && adb install -r
app/build/outputs/apk/debug/app-debug.apk`

**Open UI nit found on-device (not yet fixed):** on the Step-1 screen with a
LOCKED stored identity, `#toRoom` ("Skip — no identity (AES-256 / OTP only)")
is the `.primary` while **Unlock** is a quiet secondary — backwards, since
Unlock is what the user wants there. The primary should move to `#idUnlock`
when a locked identity exists. Separately, the Android shell shows a native
ActionBar titled "secure-chat" ABOVE the web header's own wordmark — a
duplicated title bar; consider hiding the native one (pre-existing, not from
the redesign).

## ⮕ RESUME HERE (snapshot as of 2026-07-23, Android polish: icon + release signing)
**Deploy is STILL PENDING** (blocked again this session by the Claude Code
auto-mode permission classifier on SSH/rsync to the Hetzner box — same class of
block noted in earlier sessions, not a new problem). The 2026-07-19 vouch-v2 +
mailbox-race fix (commit `a548f56`, see snapshot below) is confirmed **still
not live** — diffed the deployed `app.js` against local and it's missing the
`ecdh`/`mlkem` binding in the vouch call sites. Run by hand:
`cd ~/secure-chat && rsync -az --exclude node_modules --exclude 'package*.json'
--exclude '*.test.mjs' --exclude __pycache__ backend client
root@138.199.144.35:/opt/secure-chat/ && ssh root@138.199.144.35 'chown -R
securechat:securechat /opt/secure-chat/backend && systemctl restart
secure-chat'`. Then rebuild/reinstall the APK (client changed).

**Android polish, two of three items done this session:**
- **App icon — DONE.** Adaptive icon (API 26+; no legacy PNG mipmaps needed
  since `minSdk = 26` is the same level adaptive icons were introduced at): a
  monochrome padlock reusing the same path language as the drawer's "Live
  room" nav SVG icon, `--bg` dark background (`#0D1117`) with `--accent` blue
  foreground (`#2F81F7`), plus a `<monochrome>` variant for Android 13+ themed
  icons. New files: `android/app/src/main/res/mipmap-anydpi-v26/ic_launcher.xml`
  (+ `_round`), `res/drawable/ic_launcher_{foreground,monochrome}.xml`,
  `res/values/colors.xml`. Manifest wired (`android:icon`/`android:roundIcon`).
- **Release signing config — DONE.** `signingConfigs { release { ... } }` in
  `app/build.gradle.kts` reads `android/keystore.properties` (gitignored) if
  present; falls back to an **unsigned** release build if absent (documented
  in new `android/keystore.properties.example`, committed). Generated a real
  local release keystore this session — `android/release.keystore` (PKCS12,
  RSA-4096, 10000-day validity, alias `secure-chat-release`, pseudonymous DN,
  no real name/org in the cert). **Gotcha:** PKCS12 keystores ignore a
  distinct `-keypass` — store and key password must be identical or the build
  breaks; documented in the `.example` file. Verified: `assembleDebug` +
  `assembleRelease` both build clean, and `apksigner verify --print-certs`
  confirms the release APK is actually signed (cert DN + SHA-256 fingerprint
  printed). **Both `release.keystore` and `keystore.properties` are gitignored
  + chmod 600, never committed. Back them up somewhere durable (password
  manager / offline storage) before ever shipping a signed build — losing
  them breaks the ability to publish updates under the same signature.**
- Side-effect fix: `assembleRelease` runs `lintVitalAnalyzeRelease`, which
  pulled lint/kotlin-compiler/groovy jars not covered by the existing
  `gradle/verification-metadata.xml` checksum allowlist (first time anyone
  ran a release build here — only `assembleDebug` had ever been exercised).
  Fixed the TOFU way this project already uses for dependency verification:
  ran once with `--write-verification-metadata sha256`, then confirmed a
  clean rebuild (`rm -rf app/build && assembleRelease`) passes verification
  normally — not a permanent bypass.
- **On-device verification-gate pass (DHKE/RSA/PQKEM) — STARTED, NOT
  FINISHED, session interrupted.** State left behind: emulator `sc_test` was
  running headless with the new-icon debug APK installed and launched
  (confirmed it resolves/launches); next step is attaching CDP per the
  on-device verify recipe and driving each of the three untested modes
  end-to-end (only AES256 has ever been verified on-device). Check
  `adb devices` first — may need reboot via the recipe further down this file
  / `memory/secure-chat-project.md`.

## ⮕ RESUME HERE (snapshot as of 2026-07-19, pentest: vouch enc-key gap fixed)
**A fresh in-depth pentest found ONE real issue (MEDIUM) plus one LOW; BOTH are
now fixed, tested, and committed — deploy PENDING (permission-blocked, commands
below).** The rest of the stack (relay, C-01 handshake binding, ratchet, OTP,
identity/contacts/chats at-rest, anti-enumeration, CSP/headers) was attacked and
held up.

- **MEDIUM — web-of-trust vouch (🟡) did not authenticate encryption keys
  (the H-01 gap, still open in the WoT path).** `vouchMessageBytes` /
  `_vouch_message` signed only the target's SIGNING keys (ed+mldsa), so a
  malicious directory could serve a genuinely-vouched contact's REAL signing
  keys + its OWN ecdh/mlkem and read every sealed message the victim sent, while
  the 🟡 "vouched by X" mark still displayed. Proven with a live module-level
  PoC (`scratchpad/verify-sc/pentest-vouch-enckey.mjs`): attacker decrypted the
  plaintext; real recipient could not. **Fix (v2 vouch, mirrors the H-01
  fingerprint fix):** the vouch now signs all four keys under a new
  `secure-chat/vouch/v2` domain when the target has encryption keys (legacy
  no-enc targets stay v1). Server (`accounts._vouch_message` + the `/api/vouch`
  handler now selects+binds ecdh/mlkem), client (`account.vouchMessageBytes`
  v2), publish path (`app.js` vouches over the full in-person bundle) and the
  🟡 award check (`refreshVouchMarks` verifies over the full bundle it holds —
  so swapped enc keys fail the signature and no 🟡 is given). Old v1 vouches
  stop lighting 🟡 for enc-key contacts until re-published (correct, safe
  migration). **Verified:** new `client/vouch.test.mjs` (in `npm test`) +
  `backend/tests/test_vouches.py::test_vouch_v2_binds_encryption_keys`; the
  fixed-code PoC (`scratchpad/verify-sc/pentest-vouch-fixed.mjs`) shows the
  poisoned bundle now earns NO 🟡 while the honest bundle still does.
- **LOW — mailbox fetch was a SELECT-then-DELETE race.** `fetch_mail` deleted
  the whole inbox (`WHERE recipient = ?`) after selecting, so an envelope that
  arrived between the two statements (two overlapping fetches, or a POST racing
  the GET; sync endpoints run in a threadpool) was silently lost. **Fix:** delete
  only the specific ids that were read (`mailbox.py`).

**Verified:** backend **77 passed** (was 76; +1 vouch-v2 test), client offline
suites all green (+ `vouch.test.mjs`), CSP-hash test still green (importmap
untouched), and a two-context Chromium smoke run (all views + live AES-256
round-trip + disconnect) green — no regression from the app.js edits.
**PENDING (permission-blocked — run by hand):** deploy backend+client and
restart (backend changed, so the full recipe incl. the `chown securechat` step):
`rsync -az --exclude node_modules --exclude 'package*.json' --exclude
'*.test.mjs' --exclude __pycache__ backend client
root@138.199.144.35:/opt/secure-chat/ && ssh root@138.199.144.35
'chown -R securechat:securechat /opt/secure-chat/backend && systemctl restart
secure-chat'`. Then rebuild+install the APK (client changed). NOTE: this is on
top of the still-pending cosmetic-pass deploy below — one rsync covers both.

## ⮕ RESUME HERE (snapshot as of 2026-07-19, cosmetic polish pass)
**The user-requested cosmetic polish pass ("make it look less cheap") is BUILT
and VERIFIED locally — deploy + APK rebuild still PENDING (this session's
permission system blocked the rsync and the gradle build; run them by hand,
commands below).** Presentation-only, zero logic/crypto changes, importmap
untouched (`test_csp_hash.py` green — no CSP-hash churn):

- **Drawer emojis removed** (`client/index.html`): the four `👤🔒👥💬` labels
  are now **monochrome inline SVG icons** (16×16 `stroke="currentColor"`,
  CSP-safe) + plain-text labels in `<span>`s. The `☰` menu button and the
  functional 🟢🟡⚪ trust glyphs are KEPT (documented security UX).
- **Design-token refresh** (`client/style.css`, full-file pass, same var
  names + hue language): new tokens `--panel-2` (raised/hover surface),
  `--inset` (input/log wells), `--accent-soft`, `--ring`, `--warn`,
  `--border-soft`, radii `--r-s/m/l`, spacing `--sp-1..5`, shadows
  `--shadow-1/2`. Refined: soft elevation on `.panel`/drawer, gradient
  primary buttons with hover/active/focus-visible states, input focus rings
  (`box-shadow` ring instead of outline), flex nav items with accent-tinted
  active state, uppercase `.step`, pill badges with tinted backgrounds
  (`color-mix`), gradient chat bubbles, polished `.safety`/`.myhandle`/
  `.profile-qr`, surface-layered `#log`/`.alg-cards`/`.userlist`. Mobile
  `@media (max-width:600px)` behavior preserved verbatim.
- **Verified:** new harness `scratchpad/verify-sc/cosmetic-pass.mjs`
  (system Chromium via puppeteer-core): all 4 views render on desktop AND
  390×844 phone, drawer labels pure-ASCII (no emoji) with SVG icons, trust
  glyphs still present, **zero horizontal overflow** in every view/viewport,
  and a full two-context AES-256 flow (generate room → connect ×2 → unlock →
  message both ways → disconnect) green. Client offline `npm test` green;
  backend `test_csp_hash.py` 2/2 green. Screenshots eyeballed (drawer, room
  cards, live chat, phone views).
- **PENDING (blocked remote/exec permissions — run by hand):**
  1. Deploy (client only, no restart/chown needed):
     `cd ~/secure-chat && rsync -az --exclude node_modules --exclude
     'package*.json' --exclude '*.test.mjs' --exclude __pycache__ client
     root@138.199.144.35:/opt/secure-chat/`
  2. APK: `cd ~/secure-chat/android && ANDROID_HOME=$HOME/android-sdk
     ./gradlew assembleDebug -Dorg.gradle.java.home=$HOME/jdk-21.0.4+7`,
     then `adb install -r app/build/outputs/apk/debug/app-debug.apk`.

## ⮕ RESUME HERE (snapshot as of 2026-07-18, Profile tab shipped)
**The 👤 Profile tab (drawer TODO below) is BUILT, VERIFIED, DEPLOYED, and in
the APK.** New drawer entry (first, before Live room) → a presentation-only
view that reads existing unlocked-identity state: **Name** (registered
username or "not registered yet"), **Handle** with **Copy handle** / **Copy
invite link** (the Users-view helpers were factored into a shared
`renderHandleInto()` + the copy wiring reused), an **invite QR** (new vendored
`lean-qr`, `client/vendor/lean-qr/index.mjs`, added to the importmap — no CDN,
CSP-safe), the four-key **fingerprint** (`identity.fingerprint()`), **key
details** (Ed25519 + ML-DSA-65 / ECDH P-256 + ML-KEM-768), a **status line**
(unlocked · registered? · logged in? · N saved users), and the **Copy backup /
Forget identity** actions surfaced here too. Locked state shows the same
"unlock in Live room first" hint as Users/Chats. All `textContent`, no new
network calls or trust surface.

**Importmap changed → CSP hash regenerated** to
`sha256-6Sm2nhNvoa7gr7uuY2hbAbpdWhIlL15/wXLm4dhO9UQ=` in BOTH `backend/main.py`
and `android/.../MainActivity.kt` (guarded by `test_csp_hash.py`, which passes).

**Verified:** new `scratchpad/verify-sc/profile-flow.mjs` (two-context
Chromium) — locked-before-unlock, pre/post-registration fields, key details,
status line, copy buttons present, and the rendered **invite QR decodes back to
the exact invite link** (jsQR). Green LOCAL and LIVE. Offline suites +
backend 76/76 + H-01 flow still green (no nav regression from adding the tab).
**DEPLOYED to Hetzner** (rsync + the `chown securechat` step + restart;
confirmed live: Profile nav, vendored lean-qr 200, served CSP hash matches,
profile flow green against production). **APK rebuilt** (5.8 MB, bundles the
Profile view + lean-qr; unit tests green) — `adb install -r
android/app/build/outputs/apk/debug/app-debug.apk` when the phone is back.

## ⮕ RESUME HERE (snapshot as of 2026-07-18, Codex-Terra audit fixes)
**A second external audit ("Codex Terra", pushed to GitHub as
`docs/pentests/secure-chat-security-audit-2026-07-18.md`, auditing commit 70bbfcc) found
1 High + 3 Medium + 3 Low. ALL 7 ARE FIXED, TESTED, AND DEPLOYED TO THE
HETZNER BOX** (deploy commands were run by hand because the session's
permission system blocked remote writes; ownership gotcha below).

- **H-01 (async keys not fully bound into verification):** contact-list
  fingerprint now covers all four keys (`app.js` renderUserList);
  `sameBundle` compares all four normalized (`?? null`); pins store all four
  keys (`contacts.savePin`); `contacts.upsert` treats missing→present as a
  real key change; store blob v2→v3 migration downgrades 🟢 contacts that
  have enc keys (verified against the old signing-only fingerprint) to ⚪
  with a `reverify` UI hint; handshake distinguishes "pin predates
  encryption-key coverage" (specific re-verify prompt) from a real key
  change. Regression tests in `contacts.test.mjs` (5 new) +
  `identity.test.mjs` (per-key fingerprint/SN change) — all green. Full
  two-context Chromium flow green (handshake → verify → pin → reconnect
  silently accepted → messaging), harness
  `scratchpad/verify-sc/h01-flow.mjs`.
- **M-01 (Starlette host-header bypass of the dev-file gate):** middleware
  now gates on `request.scope["path"]`; Starlette upgraded (see M-02); new
  `backend/tests/test_static_hardening.py` (malicious-Host 404s, version
  floor, cheap pathological Range) — verified live on a running local server
  with curl.
- **M-02 (Starlette Range CPU DoS, CVE-2025-62727):** FastAPI 0.139.2 +
  Starlette 1.3.1 (also covers M-01's GHSA-86qp-5c8j-p5mr), cryptography
  49.0.0, uvicorn 0.51.0 etc. — exact pins in `requirements.txt`, hashed
  lockfile `requirements.lock` (pip-compile --generate-hashes). Backend
  suite 76/76 green on the new stack, installed `--require-hashes`.
- **M-03 (WS 16 MiB buffered before the 64 KiB app check):** uvicorn now
  runs with `--ws-max-size 66560` (run.sh; MUST also be added to the
  systemd unit ExecStart on deploy). Live-tested: 1 MiB frame → hard close
  1009, no buffering.
- **L-01 (unbounded PBKDF2 iters):** all four `deriveKey`s
  (identity/contacts/chats/otp) enforce integer iters ∈ [100k, 5M] and salt
  8–64 bytes BEFORE WebCrypto; identity backup capped 256 KiB, pad file
  capped 4 MiB before JSON.parse. Tests in identity/contacts suites.
- **L-02 (Android prompt shows passphrases):** `onJsPrompt` masks input
  (TYPE_TEXT_VARIATION_PASSWORD) when the app-local message asks for a
  passphrase. APK rebuilt (5.8 MB, bundles the new client) — `adb install
  -r android/app/build/outputs/apk/debug/app-debug.apk` when the phone is
  back.
- **L-03 (dependency hardening):** Python exact pins + hashed lock (above);
  gradle wrapper pinned via `distributionSha256Sum`; Gradle dependency
  verification enabled (`android/gradle/verification-metadata.xml`, 631
  sha256 entries — builds fail on any unpinned/tampered artifact).

**DEPLOYED + LIVE-VERIFIED (2026-07-18):** rsync of backend+client (now also
excluding `.venv`/`package*.json`/`*.test.mjs`), venv upgraded with
`pip install --require-hashes -r requirements.lock` (starlette 1.3.1 /
fastapi 0.139.2 / cryptography 49.0.0 confirmed on the box), ExecStart now
carries `--ws-max-size 66560`. **Deploy gotcha for next time:** the rsync
runs as root and re-owns `/opt/secure-chat/backend`, which crash-loops the
service (`sqlite3 … readonly database`, 502s) — always finish with
`chown -R securechat:securechat /opt/secure-chat/backend` before the
restart. Live checks all green: app.js on the site carries the H-01 fix;
`package.json`/`*.test.mjs` 404 (a hostile Host header hits Caddy's
catch-all — empty 200, never reaches the backend); HSTS present; 1 MiB WS
frame → hard close 1009; all 3 live integration suites green; full
two-context Chromium H-01 flow (handshake → verify → pin → reconnect
silently accepted) green AGAINST PRODUCTION. The audit-fix backport to
`~/secure-chat-live` is also DONE and pushed (cdc3ba8). Still pending:
`adb install -r` of the rebuilt APK when the phone is reconnected.

## ⮕ RESUME HERE (snapshot as of 2026-07-18, later)
**Repos split + published to GitHub.** The project now has TWO git repos:
this full one (`~/secure-chat` → `github.com/kpafi/secure-chat`) and a
**live-chat-only** split (`~/secure-chat-live` →
`github.com/kpafi/secure-chat-live`) that keeps only the live-room flow (4 modes,
no OTP, no async/contacts layer) plus an encrypted `pins.js` and a consolidated
`PENTEST-FINDINGS.md`. Both pushed on `master` over SSH (key `kpafi@…-deploy`).

**NEW feature (Users view share UX):** the Users view now shows **"Your handle"**
with **Copy handle** + **Copy invite link** buttons, and an inbound invite link
(`<origin>/#add=<url-encoded handle>`) opens the Users view and **pre-fills** the
add field for review. Security note: the link carries the handle in the URL
FRAGMENT (never sent to the server) and only PRE-FILLS — it never auto-adds and
never conveys trust (verification is still the in-person safety-number check), so
it grants nothing a pasted handle wouldn't. Changed files: `client/index.html`
(handle block in `#usersUnlocked`), `client/app.js` (`renderMyHandle`,
`inviteLink`, `applyPendingInvite`, `handleInviteLink`, copy wiring),
`client/style.css` (`.myhandle`). Web-verified in a two-context Chromium run
(`/tmp/verify-sclive/invite-flow.mjs`): handle shown, both buttons pass the
correct strings, invite pre-fills the peer's add field, contact lands ⚪
unverified. **DEPLOYED to Hetzner** (rsync of `client/` to
`/opt/secure-chat/client/`, no restart needed for static files; confirmed the
live `app.js`/`index.html`/`style.css` carry the change via curl). Phone app
inherits it via the gradle `syncWebClient` copy — APK rebuilt (5.8 MB);
`adb install -r android/app/build/outputs/apk/debug/app-debug.apk` when the phone
is reconnected. Committed + pushed to `github.com/kpafi/secure-chat` (643fc7f).
NOTE for future deploys: this is a SEPARATE step from the git push — the live
site serves `/opt/secure-chat/client/` on the box, so a frontend change is only
live after the rsync.

## ⮕ RESUME HERE (snapshot as of 2026-07-18)
**Status:** live on Hetzner `https://138-199-144-35.sslip.io`. **An external
black-box pentest (2026-07-18) found 9 issues incl. a CRITICAL handshake bug
(C-01); ALL are now fixed, tested, and deployed** — see the 2026-07-18 DONE
entry. Highlights: C-01 (session key ↔ identity now atomically bound: identity
pinned on first handshake, serialized message handling, hard-close on a second
identity — regression-tested); H-01 (fingerprint + safety number now cover the
ecdh/mlkem encryption keys; a change resets verified); M-02 (trust pins moved
into the identity-encrypted store, plaintext pins migrated + deleted); M-01
(OTP rollback tripwire); M-03/L-01/L-02 (challenge rate bucket, HSTS, dev-file
404 + removed from server). Backend **71 pytest passed**; client offline suites
green (crypto/identity/contacts/sealed/otp-rollback); C-01 regression + P6
pentest + full UI flow green local AND live; 3 live integration suites still
green. APK rebuilt (phone unplugged — reconnect + `adb install -r
android/app/build/outputs/apk/debug/app-debug.apk`). Verification harness in
`/tmp/verify-sc/`: `c01-regression.mjs`, `pentest-p6.mjs`, `ui-flow.mjs`.

## ⮕ (previous snapshot 2026-07-17, evening)
**Status:** backend relay + web client working locally **and LIVE on a Hetzner
test server: `https://138-199-144-35.sslip.io`** (all 3 live integration suites
green over the public internet — see the first 2026-07-17 DONE entry for the
server layout, hardening, and the rsync deploy recipe); git repo on `master`.
**BIG feature set landed today (P1–P6, all deployed): a left-drawer menu with a
Users view (contacts + 🟢/🟡/⚪ web-of-trust marks, dual-signed vouches) and a
Chats view (WhatsApp-style async 1:1 over a sealed store-and-forward mailbox;
hybrid ECDH P-256 + ML-KEM-768 sealed envelope with sealed sender; per-chat
mode lock SEALED/AES256 with a signed accept/decline mode change). Identity is
now bundle v2 (adds ECDH + ML-KEM encryption keys; pre-today identities
auto-upgrade + re-publish on first unlock). Contacts + chat history are
encrypted at rest under the identity passphrase.** Backend **70 pytest passed**;
client offline suites (crypto/identity/contacts/sealed) green; full puppeteer
flow (identity→room→chat, users, vouches, async chat both ways, mode
negotiation) green; P6 adversarial pentest green local + live. Tests to run
live: sed-swap `127.0.0.1:8000`→`138-199-144-35.sslip.io` in the three
`*.integration.test.mjs`. NEW client modules: `contacts.js`, `chats.js`,
`sealed.js`; NEW backend: `mailbox.py` (+ vouch endpoints in `accounts.py`).
**Phone:** APK rebuilt (5.8 MB) but the last two installs were skipped (phone
unplugged) — reconnect USB + `adb install -r
android/app/build/outputs/apk/debug/app-debug.apk` to update it.
Backend `pytest` = **57 passed**; client offline suite (`npm test`) green; all
3 live integration suites green; real-browser (puppeteer/Chromium) checks green
(v2 handshake, token-gated directory, RSA ratchet, the double-click send
regression, and the new OTP generate→export/import→two-way→persist flow).
**FIVE working encryption modes now: AES256, DHKE, RSA, PQKEM, and OTP (true
one-time pad, in-person pad exchange — added 2026-07-16, see dated entry).**
**OTP was self-pentested the same day; all 4 findings (concurrent-use lock,
encrypt-at-rest, export single-use, import entropy check) are FIXED + verified.**
**All four 2026-06-19-review accepted-risk items (L1, I1, L2, I2) are CLOSED.**
`pip install -r requirements.txt` also pulls `dilithium-py`. Logging is
minimized (no request/connection metadata at rest); `run.sh` must keep
`--no-access-log --log-level warning`.
**2026-07-16 — all four 2026-07-08 Android pentest findings FIXED** (+ the
informational should-fixes): `RelayUrls.parse` now whitelists the host charset
(Critical Finding 1), the injected config is built with `JSONObject`, the
`shouldOverrideUrlLoading` origin check compares parsed scheme+host (Finding 2),
the app serves from a unique `https://secure-chat.internal` origin via
`WebViewAssetLoader.setDomain` (Finding 4, `APP_WEBVIEW_ORIGIN` updated to
match), WebView remote debugging is `BuildConfig.DEBUG`-gated, cleartext is
scoped to loopback/.onion, and `importMapHash` drift is guarded in
`test_csp_hash.py`. New Robolectric `RelayUrlsTest` (11 tests) rejects the live
PoC payloads; debug APK builds clean. See the 2026-07-16 DONE entry. **Remaining
Android work:** on-device re-run against the new origin + the DHKE/RSA/PQKEM
safety-number gate (needs the emulator), app icon, and release-signing.
**2026-07-07 (four entries, newest first):**
0. **Android app (new `android/` module):** thin Kotlin/WebView shell that
   BUNDLES the audited web client in the APK (closes web-only trust gap H1) and
   points at a remote relay. Debug APK builds clean; verified in a real browser
   AND **on-device** (Android 14 emulator — AES256 end-to-end through the relay,
   both directions). Found + fixed a Mixed-Content constraint: the relay must be
   wss/loopback/.onion (a plain-http LAN relay is browser-blocked); app.js now
   reports it clearly. Backend gained a single allow-listed app origin (WS +
   CORS) and `SECURE_CHAT_EXTRA_ORIGINS`. See the two dated entries.
1. **Ratchet unification:** DHKE + PQKEM ported onto `RatchetChannel`
   (in-session forward secrecy for every mode; `AuthChannel` deleted); DHKE
   drops its private key at derivation, PQKEM seals like RSA on first
   traffic; reflected handshake keys + reflected hellos now refused in all
   modes. DHKE/PQKEM `msg` frames are `dhke-msg/v2`/`pqkem-msg/v2`.
2. **Final crypto review** of the whole stack: no High/Medium findings; full
   verification matrix green incl. a 4-mode real-browser end-to-end run.
3. **Both 2026-07-03 pentest concurrency bugs FIXED** (High: racing decrypts
   could roll the replay counter back; Medium: overlapping encrypts consumed
   the same one-time key and killed the ratchet): all channel encrypt/decrypt
   calls are serialized through a per-instance FIFO `CallQueue`, plus a
   Send-in-flight guard in app.js as defense in depth. See dated entries.
**2026-07-03:** TODO item (d) fully closed — ratcheting for RSA **and** AES256.
1. RSA mode is now **forward-secret** — RSA key transport + a one-way HMAC
   ratchet with one-time AES-GCM message keys; root secret and RSA private key
   are erased once traffic starts (see dated entry). RSA `msg` frames are
   `rsa-msg/v2`; handshake format unchanged.
2. AES256 mode now runs the same ratchet (shared `RatchetChannel`), rooted in
   the passphrase **plus both peers' fresh session nonces** (new plaintext
   hello exchange for AES256, reusing the app's existing hello phase) — this
   **CLOSES the AES256 cross-session-replay residual**. AES256 frames are
   `aes-msg/v2`; `AuthChannel` now serves only DHKE/PQKEM. FS for AES256 is
   honestly limited (passphrase = master secret; see dated entry).
Both committed together in a single commit on top of d5e2f68.
**2026-07-02 (second session), in order:**
1. CLOSED Medium finding **cross-session handshake replay in a reused room** —
   handshake transcript bumped to v2, covers a fresh per-connection nonce from
   BOTH peers (plaintext `hello` before the signed offer/answer, folded
   order-independently). Committed as c756cf9.
2. CLOSED accepted-risk **L1** (server-side ML-DSA-65 dual ownership proof at
   registration, via `dilithium-py`) and **I1** (username namespace made
   non-enumerable: token-gated `username#token` lookup + removed the
   challenge/verify existence oracles + dedicated lookup rate limit). See the
   "accepted-risk closeout" dated entry. NEW backend dep: `dilithium-py`.

Both were committed this session (c756cf9 = handshake replay; 1703a19 = L1/I1).

**Done & verified end-to-end (incl. real-browser checks via puppeteer):**
- Dumb-relay backend (strict validation, rate limit, connection cap, join +
  idle timeouts) + passwordless account directory (`/api`, rate-limited + capped).
- Web client: 5 working encryption modes — **AES256, DHKE, RSA, PQKEM, OTP**
  (PQKEM = hybrid ECDH P-256 + ML-KEM-768; OTP = true XOR one-time pad with an
  in-person pad exchange, added 2026-07-16). Identity = Ed25519 + ML-DSA-65,
  passphrase-encrypted at rest (PBKDF2 600k).
- **Authenticated handshake** (dual-sig) + in-person safety-number gate closes
  the relay-MITM gap. Account register/login + fetch-by-username pinning.
- Security review done; M1/M2/L3 fixed, H1 documented (see 2026-06-19 entry).

**Next options (pick one):** (a) on-device smoke test of the new Android app
(build + cross-origin browser verification DONE 2026-07-07; needs a real
device/emulator to exercise the WebView glue); (b) Tor `.onion` deployment
(pairs naturally with the app — set the relay to the `.onion` and add its
origin via `SECURE_CHAT_EXTRA_ORIGINS`); (c) OTP mode. Full open list in TODO
at the bottom.

**Run it:** see "How to run (quick ref)" at the bottom of this file.

## Project goal (from the user)
- Website + server backend for **simple ASCII-only text chat**.
- **Security is the #1 priority** in every design and code decision. Small,
  simple, auditable codebase is itself a security feature.
- User picks the encryption: **RSA, AES-256, DHKE, post-quantum key exchange,
  and OTP** (OTP = pre-shared large random pad exchanged when users meet in
  person; lower priority, harder to implement — defer for now).
- Eventual clients: a **Tor `.onion` website** and a dedicated **Android app**.
  The **website is the priority**; the app comes later.
- Order of work: **backend first, locally, for testing.**

## Key architectural decisions (locked)
1. **Stack:** Python + FastAPI (small, readable, easy to audit; strong crypto
   ecosystem for later client-side / PQ work).
2. **Crypto model:** **End-to-end encryption; the server is a dumb relay.**
   The server never sees keys or plaintext. It validates the envelope, enforces
   limits, and forwards opaque ciphertext. A full server compromise leaks only
   ciphertext. => All algorithm choice and crypto logic lives in the CLIENT.
   The server's `alg` field is an advisory tag only and is never acted upon.

## DONE
### 2026-07-18 — External pentest response: C-01 (critical) + 8 more, all fixed ✅
An independent black-box audit of the live web instance reported 9 findings.
All addressed, tested, deployed. Full write-up in README ("External pentest").

**C-01 — CRITICAL — session key not atomically bound to peer identity.**
Confirmed by reading the code: `handleMessage` set `peerBundle = idb` then
`cipher.onPeerKey(pub)`, and the ciphers are first-key-wins. A relay could send
its OWN validly-signed offer first (cipher locks attacker key) then relay the
peer's real signed offer (peerBundle → real peer, cipher IGNORES the real key),
so the safety number / pin verified against the honest peer while the live
channel used the attacker's key — decoupling exactly what the safety-number
gate protects. **Fix (app.js):** (1) message handling serialized through a FIFO
`msgChain` (closes the TOCTOU where two frames pass verification before either
pins); (2) the peer identity is PINNED to the first accepted handshake —
`peerBundle` is write-once, and a later frame whose `idb` differs hard-closes
the connection with a MITM notice; (3) `enterVerification(room, verifiedBundle)`
takes the pinned bundle explicitly instead of re-reading a mutable global.
**Regression:** `/tmp/verify-sc/c01-regression.mjs` — a mock relay feeds two
validly-signed DHKE offers from DIFFERENT identities with identical nonces; the
first is accepted, the second hard-closes, messaging never unlocks, a MITM line
is logged.

**H-01 — HIGH — relay could swap the async (ecdh/mlkem) encryption keys.**
Fingerprint/safety-number covered only ed+mldsa, and a contacts enc-key change
did NOT reset verified — so a relay could pair the real signing keys with its
own encryption keys and silently redirect sealed messages. **Fix:**
`identity.js` `_bundleBytes` folds ecdh+mlkem into `fingerprintOf` +
`safetyNumber` (pre-v2 bundles hash unchanged); `contacts.upsert` treats ANY of
the four keys changing as a key change (resets verified, drops stale vouches);
the live-room verify gate mirrors the FULL bundle (incl. enc keys) into
contacts; adding a contact by handle no longer auto-verifies from an
ed/mldsa-only pin.

**M-02 — MEDIUM — trust pins were plaintext localStorage.** A forged
`sc.pins.v1` entry could auto-unlock. **Fix:** pins live inside the
identity-encrypted, GCM-authenticated contact store (`contacts.getPin/savePin`),
blob bumped to v2 `{contacts, pins}`; a one-time migration imports the old
plaintext pins then deletes the key.

**M-01 — MEDIUM — OTP rollback.** A wholesale restore of an old encrypted pad
blob rewound `sendOffset` to reuse keystream (GCM stops edits, not rollback).
**Fix (otp.js):** a SEPARATE monotonic high-water key `sc.otp.hw.v1.<id>`;
unlock refuses a pad whose offset regressed below it. `otp-rollback.test.mjs`
proves an old-blob restore is refused. *Residual (documented):* a full-storage
rollback that also reverts the tripwire needs OS-level trusted storage — out of
scope for browser localStorage.

**M-03 / L-01 / L-02.** Dedicated stricter rate bucket on `/api/auth/challenge`
(`CHALLENGE_RATE_CAPACITY=10`, 0.5/s) + test; `Strict-Transport-Security` sent
when `X-Forwarded-Proto: https` (not on loopback/.onion); middleware 404s
`package.json`/`package-lock.json`/`*.test.mjs` and they were removed from the
deployed client dir. **H-02 / L-03 / PQ-assurance:** documented as accepted /
architectural (web client = honest-but-curious; Android app = malicious-relay
answer; SSH key-only on a disposable box; noble-PQ self-audited).

**Verification:** backend **71 passed**; client offline suites green incl. new
`otp-rollback.test.mjs`; `c01-regression.mjs`, `pentest-p6.mjs`, full
`ui-flow.mjs` green LOCAL and the pentest + 3 integration suites green LIVE
against Hetzner. Deployed; HSTS + dev-file-404 confirmed on the live box; APK
rebuilt.

### 2026-07-17 — P6: hardening pass over the contacts/chats surface + live E2E ✅
Adversarial pass following the project method (attack the running code, prove
it with a live PoC): `/tmp/verify-sc/pentest-p6.mjs`, run against BOTH the
local relay and the live Hetzner box. Every attack refused:

- **Vouch forgery:** zero-signature vouch → 400; a vouch signed by a
  non-owner key but submitted under the attacker's session → 400 (server
  checks the sig against the AUTHENTICATED user's keys). **Client 🟡
  forge-resistance:** proved `Identity.verify` rejects a genuine vouch when
  the voucher keys are swapped to the attacker's, and when the target key is
  rotated — so a lying directory cannot manufacture a 🟡 (the award rule
  re-verifies against the client's OWN pinned voucher keys).
- **Mailbox:** wrong-token-for-real-user and unknown-user POST return
  byte-identical 404 (not an existence oracle); fetch without / with a bogus
  bearer token → 401; a logged-in eve never sees bob's queue (per-recipient);
  an envelope captured off the wire won't `open()` without the recipient's
  keys.
- **Chat sender spoofing:** eve seals a message to bob with alice's
  self-claimed handle — `open()` still binds the sender to EVE's real bundle,
  and since chats are keyed by bundle (never the claimed name), she cannot
  inject into bob's alice-chat.
- **Regression:** the 3 live integration suites (relay 4-mode, account
  directory, authenticated handshake) still pass against Hetzner after all the
  backend changes — the dumb relay + directory are untouched in behaviour.
- Docs: README gained a "Contacts, web of trust, and async chats" section
  (trust marks, sealed envelope, mailbox, mode lock, the FS trade-off). APK
  rebuilt (5.8 MB, ready for the next phone connect).
- NOTE: the pentests + browser runs left a handful of `pt-*`/`bob-*` test
  accounts in the LIVE directory (public keys only, harmless) — restart/redeploy
  starts fresh if you want a clean box for real testing.

### 2026-07-17 — P5: per-chat mode lock + negotiated mode change ✅
- **Modes (async):** SEALED (default, transport only) and AES256 (an inner
  AES-256-GCM layer under a per-chat passphrase, applied to the plaintext
  BEFORE sealing — so even a break of the recipient's long-term TRANSPORT keys
  leaks nothing without the chat passphrase). OTP-over-mailbox deliberately NOT
  offered (async pad sync = two-time-pad risk); it stays live-room only.
- **Negotiation:** the sealed envelope core now carries a `kind`
  (msg / mode-propose / mode-accept / mode-decline) — control messages are
  signed and authenticated exactly like text (`sealed.js` generalised from
  `text` to a `content` object; open() returns the whole signed body). One
  side proposes via the chat's mode picker (AES256 → prompts for a shared
  passphrase, mints a PBKDF2 salt sent in the proposal); the peer sees an
  accept/decline banner; the switch happens only after a signed accept, on
  both sides. Decline/lost-response leave the locked mode untouched.
- **Store:** `chats.js` gained `setMode`/`setPending`/`clearPending`, the
  AES256 fields (`secret`,`salt`), and inner-layer `innerEncrypt/innerDecrypt`
  (+ `newInnerSalt`). Mismatch cases render a clear system line rather than
  garbage. All negotiation state is inside the identity-encrypted chat store.
- **Verified:** `sealed.test.mjs` gains a control-message case (kind/mode/salt
  survive sign+seal); browser flow drives alice→propose AES256, bob→accept
  (both prompts auto-answered with the same passphrase), both lock to AES256,
  then a message round-trips through the inner layer. Offline suites + backend
  70 green; deployed to Hetzner. Screenshot eyeballed; tightened the convo
  header to wrap on narrow screens.

### 2026-07-17 — P4: store-and-forward mailbox + Chats view (WhatsApp-style async DMs) ✅
- **Backend `mailbox.py` (new):** rows are (recipient, opaque envelope,
  arrival time) — the sender is sealed INSIDE the envelope, invisible to the
  server. `POST /api/mailbox/{recipient}?t=<lookup token>` (token gate = same
  anti-enumeration boundary as the bundle lookup: wrong token / unknown user
  are an identical 404; printable-ASCII + 64 KiB envelope cap; dedicated
  per-host rate bucket 30 burst / 1 rps; per-inbox cap 200; global cap 100k;
  14-day TTL pruned on access). `GET /api/mailbox` requires the session token
  and DELETES what it returns — no server-side read history. New
  `tests/test_mailbox.py` (roundtrip+delete-on-fetch, token-gate oracle check,
  auth, size/ASCII/inbox-cap, TTL prune) → backend **70 passed**.
- **Client:** `chats.js` — encrypted chat store (same PBKDF2→AES-GCM posture,
  unlocked with the identity, wiped on forget; 500-msg cap per chat; inbound
  dedup by envelope id). `sealed.js` core gained a signed, self-claimed
  sender handle (display/reply-token only — chats are KEYED by the sender's
  signature-verified bundle, never by the claimed name). `account.js`:
  `sendMail`/`fetchMail`. Chats view: start-a-chat picker (saved users),
  chat list with safety marks + last-message preview, bubble conversation
  (textContent-only rendering), mode line "🔒 SEALED …". Sending needs only
  the contact's handle token; RECEIVING needs login (mailbox auth) — 6s
  polling after login + on view entry. Unknown senders are auto-added as ⚪
  contacts (sealed handle preferred, fingerprint-derived name fallback); a
  known bundle without a reply token adopts the sealed handle's token.
- **Verified:** browser suite extended — alice→bob sealed send, bob logs in,
  chat auto-appears filed under alice's handle, bob replies using the sealed
  token, alice's open conversation updates, chat blob at rest is ciphertext
  (no plaintext leak). Screenshots eyeballed (bubble UI). Deployed to the
  Hetzner box; APK rebuilt (phone was unplugged — install pending reconnect).
- **Known limitation (documented):** sealed envelopes have per-envelope
  ephemerals but NO live ratchet — long-term-key compromise exposes captured
  past envelopes. P5 adds the mode lock/negotiation; the hardening pass (P6)
  revisits mailbox abuse surface end-to-end.

### 2026-07-17 — P3: bundle v2 (encryption keys) + sealed async envelope ✅
Foundation for chats-without-a-live-room:

- **Identity (client):** now also holds ENCRYPTION keypairs — ECDH P-256 +
  ML-KEM-768 (`identity.js`). Blob format v3 (v2 blobs auto-upgrade on
  unlock: enc keys generated, blob re-exported once, bundle re-published to
  the directory opportunistically for registered users). Fingerprint / safety
  number / pins still cover ONLY the signing keys (identity continuity); the
  enc keys are bound to the identity by the registration signature.
- **Directory (backend):** registration v2 under `secure-chat/register/v2`
  (dual sig covers ecdh+mlkem; both-or-neither, strict sizes 65/1184 B).
  `accounts` table gained `ecdh_pub`/`mlkem_pub` (empty for v1 rows; those
  can't receive sealed messages until re-registered). **Same-identity
  re-registration is now a bundle refresh** (verifies the dual sig, matches
  stored ed+mldsa exactly, updates enc keys, returns the EXISTING lookup
  token) — foreign identities still get 409. Lookup returns enc keys when
  present; v1 registration still accepted. `tests/test_bundle_v2.py` (5
  tests): roundtrip, sig-must-cover-enc-keys (v1-sig + keys, post-sign key
  swap), both-or-neither + size validation, refresh-vs-409, v1 compat —
  backend **65 passed**.
- **`sealed.js` (client, new):** async E2EE to a contact's public bundle.
  Hybrid: ephemeral ECDH + ML-KEM-768 encaps → HKDF-SHA256(salt=domain,
  info=recipient-ed) → AES-256-GCM. **Sealed sender:** sender bundle + DUAL
  signature live inside the ciphertext; sig covers domain + RECIPIENT identity
  key + eph + KEM ct + core, so envelopes can't be re-targeted and the mailbox
  never learns the sender. FS trade-off documented (per-envelope ephemerals;
  no live ratchet in store-and-forward). `sealed.test.mjs`: roundtrip, opaque
  envelope (no plaintext/sender leak), wrong-recipient, tamper,
  eve-signs-as-alice forgery, legacy-blob upgrade — all green.
- Contacts store now carries contacts' enc keys (updated on add/lookup; an
  enc-key change alone does NOT reset `verified` — trust anchors stay
  ed/mldsa). Client suites + full browser flow green; deployed to Hetzner +
  phone. NOTE: identities created before today must unlock once (auto-upgrade
  + re-publish) before they can RECEIVE sealed messages.

### 2026-07-17 — P2: web-of-trust vouches (🟡 mark) ✅
- **Backend:** `vouches` table (voucher→target, dual sigs, created_at; PK
  dedups re-vouches). `POST /api/vouch` (session-token auth) verifies BOTH
  signatures against the voucher's registered keys over the TARGET's currently
  registered bundle before storing — the table can only hold statements the
  voucher really signed about the real directory entry. `DELETE /api/vouch/
  {target}` revokes. `GET /api/users/{u}/vouches` is gated by the target's
  lookup token (no graph enumeration) + the strict lookup rate bucket, returns
  ≤50 vouches incl. voucher public keys. Bounds in config: 200/voucher, 200k
  total. Domain-separated message: `secure-chat/vouch/v1\ntarget\ned\nmldsa`.
  Self-vouch 422. New `tests/test_vouches.py` (publish/fetch/revoke; wrong-key,
  cross-target, single-scheme-forgery, auth rejections; token-gated 404
  indistinguishability) — backend now **60 passed**.
- **Client:** `account.js` vouch/unvouch/fetchVouches (+ exported
  `vouchMessageBytes`); login now retains the session token in memory.
  Users view: turning a contact 🟢 offers (confirm, opt-in — it reveals the
  social edge publicly) publishing a vouch signed over MY pinned copy of their
  bundle; Unverify retracts. 🟡 computation is strictly local: a vouch counts
  ONLY if the voucher is a contact I verified in person AND the
  server-returned voucher keys equal my pinned copy AND the dual signature
  verifies over MY stored target bundle — a lying directory cannot invent a 🟡.
  Results cached in the encrypted store (10-min recheck TTL).
- **Verified:** full puppeteer flow incl. new WoT scenario (alice registers,
  logs in, re-verifies bob → publishes vouch; carol verifies alice in person,
  adds bob → 🟡 "vouched by alice"), screenshots eyeballed; all offline suites
  green. Deployed to Hetzner (backend restarted) + phone APK. Found+fixed in
  passing: renderUserList() wiped the just-set vouch status line (order swap).

### 2026-07-17 — P1 of the contacts/chats overhaul: drawer menu + encrypted contact store + Users view ✅
First phase of the planned contacts + web-of-trust + async-chats feature set
(full plan in TODO). Shipped:

- **Drawer menu** (☰ top-left): Live room (the untouched 3-step flow) / Users
  (new) / Chats (placeholder until P4). Pure presentation; switching views
  never touches an active connection. CSS gotcha fixed along the way:
  `.drawer { display:flex }` silently overrode the `hidden` attribute
  (author display beats the UA's `display:none`), leaving an invisible
  click-eating overlay — caught by the browser suite, fixed with an explicit
  `.drawer[hidden] { display:none }`.
- **`contacts.js` — encrypted contact store.** Records
  `{username, token, ed, mldsa, verified, verifiedAt, addedAt, keyChangedAt}`;
  at rest PBKDF2-600k → AES-256-GCM under the IDENTITY passphrase (same
  posture as identity + pads; GCM doubles as tamper protection — flipping
  `verified` in the blob just breaks decryption). Unlocked wherever the
  identity is created/unlocked (before the passphrase field is cleared);
  locked state renders a hint; wiped on identity-forget; a changed key for a
  known username RESETS `verified` (same rule as the pin store). Foreign/
  tampered blob → clear error, resettable via identity-forget.
- **Users view:** add contact by `username#token` (directory lookup),
  fingerprint per contact, marks 🟢 "verified by you" / ⚪ unverified (🟡
  vouched comes with P2), confirm-gated "Verified in person ✓" / Unverify /
  Remove, loud key-changed warning. Auto-🟢: adding a handle whose bundle
  matches an existing in-person pin, and the live-room safety-number confirm
  (`onVerifyOk`) mirrors into the store when the contact-handle field named
  the peer.
- **Tests:** new `contacts.test.mjs` (npm test now runs it): encrypted
  round-trip, wrong-passphrase refusal, GCM tamper refusal, key-change trust
  reset, wipe, opaque-at-rest. Browser suite extended: register→handle→add→
  ⚪→verify→🟢→reload-unlock→persisted→blob-is-ciphertext. All green
  (client offline, backend 57/57, full puppeteer flow); deployed to the
  Hetzner box + phone APK reinstalled.

### 2026-07-17 — UI rework: 3-screen flow + disconnect + copy-room-id (deployed live + on phone)
User feedback from live testing: no way to disconnect once connected, and the
single-page UI felt raw. Reworked the client into a guided **3-screen flow** —
UI structure only, **zero crypto/handshake/connection-logic changes** (all
element ids kept, so the test suites run unmodified):

1. **Identity screen** (identity panel + optional username register/login);
   Continue button (labelled "Skip — no identity (AES-256 / OTP only) →" until
   an identity is unlocked).
2. **Room screen** (room id + Generate, encryption picker, passphrase/OTP
   panel, contact handle, Connect) with Back navigation.
3. **Chat screen** with a sticky **top bar**: shortened room id, **Copy room
   id** button (clipboard), mirrored status, and the new **Disconnect** button
   (`ws.close()` → the existing onclose cleanup now returns to the room
   screen). Verify (safety-number) panel lives inside this screen.

Implementation: `index.html` regrouped into `#scrIdentity/#scrRoom/#scrChat`
wrappers + `showScreen()` in app.js; `joined`/`onclose` swap screens instead of
toggling `#setup`/`#chat`; the inline importmap kept **byte-identical** (CSP
hash — `test_csp_hash.py` still green). style.css: step indicator, topbar,
ghost buttons, `#log` height now `min(55vh, 480px)` for phones.
**Verified:** client `npm test` green, backend 57/57 green, and a new
puppeteer/Chromium two-peer UI-flow check (`/tmp/verify-sc/ui-flow.mjs` —
screen navigation, DHKE session, safety-number match, message delivery,
topbar copy → clipboard content asserted, disconnect → room screen). Deployed
to the Hetzner box and reinstalled on the phone (`adb install -r`) same day.
**Follow-up 2 (same day) — mobile polish + encryption picker cards.** The
`<select>` encryption picker is now a **radio-card group** (`#algCards`, one
`<input type="radio" name="alg">` per mode with name/badge/description —
`els.alg.value` reads became the `algValue()` helper; `syncAlgUI` listens on
the container). Phone-sized screens (`@media max-width: 600px`): tighter
padding, 16px inputs (no focus-zoom), bigger touch targets, `#log` sized via
`100dvh`, and the chat top bar becomes a 2×2 grid (room id | copy // status |
disconnect). Verified: npm test + 57/57 pytest green; ui-flow.mjs (extended
with a card-toggling check) green at a 390×844 viewport; screenshots
eyeballed. Deployed to the Hetzner box + phone same day.
**Follow-up (same day):** the browser kept showing the OLD client after the
deploy — StaticFiles sends only ETag/Last-Modified, no `Cache-Control`, so
browsers cache heuristically without revalidating. Fixed: the security-headers
middleware now also sets `Cache-Control: no-cache` (always revalidate; ETag
makes unchanged loads a 304). One manual hard reload (Ctrl+F5) is needed on
clients that cached before this fix; after that, deploys show up on plain
reload. 57/57 backend tests still green; live-verified on the Hetzner box.

### 2026-07-17 — FIRST LIVE DEPLOYMENT: Hetzner test server, all live suites green 🚀
The relay + web client are live on a Hetzner Cloud box (Debian 13, x86_64,
4 GB) for real-network testing:

- **URL: `https://138-199-144-35.sslip.io`** (sslip.io wildcard DNS → the
  server IP `138.199.144.35`; free Let's Encrypt cert via Caddy — swap in a
  real domain or the `.onion` later without touching the backend).
- Layout on the server: `/opt/secure-chat/{backend,client,venv}`, runs as the
  no-login system user `securechat` under systemd (`secure-chat.service`) with
  sandboxing (`ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`,
  `NoNewPrivileges`). Uvicorn binds **loopback only** and keeps the mandatory
  `--no-access-log --log-level warning`; Caddy terminates TLS on 443 and its
  access log is set to `output discard` (metadata-minimization carried over,
  I2). Public origin allow-listed via
  `Environment=SECURE_CHAT_EXTRA_ORIGINS=https://138-199-144-35.sslip.io` in
  the unit (WS origin check + CORS).
- Host hardening: SSH is key-only (password auth disabled via
  `sshd_config.d/90-no-password.conf`), Hetzner cloud firewall allows only
  22/80/443 TCP inbound, unattended security upgrades enabled. Local test
  `accounts.db` was NOT deployed — the live directory starts empty.
- **Verified from the laptop against the live server:** all 3 live integration
  suites green over the public internet — relay (DHKE/AES256/RSA/PQKEM
  end-to-end via `wss://`), account directory (register→lookup→login→me,
  dup-username 409, wrong-key rejected), authenticated handshake
  (DHKE/RSA/PQKEM safety numbers + cross-session replay REJECTED). Run them
  live by sed-swapping `127.0.0.1:8000` → `138-199-144-35.sslip.io` (ws→wss,
  http→https) in the three `*.integration.test.mjs` files.
- Deploy/update recipe: `rsync -az --delete --exclude '.git' --exclude
  '__pycache__' --exclude 'node_modules' --exclude 'accounts.db*'
  backend client root@138.199.144.35:/opt/secure-chat/ && ssh
  root@138.199.144.35 systemctl restart secure-chat`.
- NOTE: test box is disposable (hourly billing); nothing on it is
  irreplaceable — everything above is reproducible from this repo.

### 2026-07-16 — OTP pentest: 2 Medium + 2 Low found (NOT yet fixed) 🔴
Adversarial review of the just-shipped OTP mode (crypto.js `OtpPad`, otp.js, the
app.js wiring), following this project's "attack the running code, prove it with
a live PoC" method. PoCs run against the actual shipping modules
(`/tmp/verify-sc/pentest-otp.mjs`). **The OTP core crypto held up** — replay,
cross-room replay, cross-session replay, ciphertext tamper, offset-relabeling,
reflection, and forward-secrecy zeroing are all correctly rejected/enforced
(re-proven). Four weaknesses found, all in pad *lifecycle/state management*, not
the cipher:

**Finding 1 — MEDIUM — concurrent pad use = two-time pad (catastrophic reuse).**
Nothing locks a pad to one active session. Two OtpPad instances built from the
same persisted record — exactly what two browser TABS get from `loadPad` (they
share localStorage but each holds its own in-memory offset) — both start at the
same offset and reuse the same keystream. **Live-proven:** `C1^C2 == P1^P2`, the
classic two-time-pad break (an eavesdropping relay recovers plaintext
relationships, and any one known/guessable message reveals the other outright).
`MAX_ROOM_MEMBERS=2` blocks the naïve "two tabs + peer in ONE room" variant, but
NOT (a) two concurrent conversations (two rooms) sharing one pad, nor (b) two
tabs alone in a room unlocking each other. Single-tab sequential use is safe
(offset persisted after every message). Fix: a same-origin lock (BroadcastChannel
lease / a localStorage "pad in use" epoch checked before each send) so a pad can
be live in only one session at a time; refuse or hard-warn on concurrent use.

**Finding 2 — MEDIUM — pad stored UNENCRYPTED at rest.** `otp.savePad` writes
`bytes: b64(record.bytes)` straight to localStorage in the clear, unlike the
identity private keys (which are PBKDF2→AES-GCM encrypted at rest). A device /
browser-profile compromise reads the entire REMAINING pad → decrypts all FUTURE
traffic until a new pad is exchanged. Consumed bytes are zeroed, so past traffic
stays protected (the FS property holds), but the long-term secret sitting in
plaintext is inconsistent with the rest of the app's at-rest posture and
undercuts exactly the high-assurance users who pick OTP. Fix: encrypt the pad at
rest under a passphrase (reuse the identity export machinery), unlocked per
session like the identity is.

**Finding 3 — LOW — export file has no single-use / role binding.** `importPad`
always returns `recipientRole` (= 1), so importing the same export file on more
than one device gives EVERY importer role 1 → two role-1 senders reuse region 1
(two-time pad again). Same if the generator forgets its role-0 copy and
re-imports its own file. **Live-proven** (two imports → identical role → keystream
reuse). Only the otp.js header doc ("import on one device per side") prevents it.
Fix direction: bind the pad to the exchanging identities if available, or at
least track "this file already imported / this pad already has a role-1 peer" and
warn hard; there is no fully-robust cross-device enforcement without identities.

**Finding 4 — LOW/informational — a malicious pad generator can downgrade the
importer's outbound confidentiality.** The generator produces ALL pad bytes,
including the importer's send region. A hostile (or corrupted) pad with an
all-zero / low-entropy send region makes the importer's outbound `ct = pt XOR 0
= pt` — plaintext on the wire, readable by the RELAY, not just the generator.
Bounded: the generator is your trusted in-person contact who receives your
plaintext anyway; the only *new* exposure is to third parties. Fix: a cheap
entropy sanity check on import (reject an all-zero / obviously non-random pad),
and/or document that the pad's randomness is only as trustworthy as whoever
generated it.

**Verified negatives (no finding):** the AD binds domain|room|role|offset|len so
moving a frame across rooms/offsets/regions fails the MAC; the one-time HMAC key
is full 32-byte SHA-256 (untruncated); `crypto.subtle.verify` is constant-time;
auth-failed frames consume no pad (a hostile relay can't burn the pad with
forgeries); the entropy mixer (CSPRNG XOR AES-CTR(H(finger))) is never weaker
than the CSPRNG; the export file is GCM-authenticated (wrong passphrase → clean
reject). `offset | 0` would truncate for >2 GiB pads but max pad is 1 MiB
(unreachable, latent-only). The non-OTP stack (relay, accounts, other four
ciphers) was not changed this session and its previously-closed findings remain
closed; a quick re-confirm left backend `pytest` 57 and all live suites green.

**Not yet fixed** — all four are on the TODO list below. **(All four FIXED later
the same day — see the entry above this one.)**

### 2026-07-16 — OTP pentest findings 1–4 FIXED ✅
Fixed all four findings from the OTP pentest (entry below). The OTP cipher core
was already sound; these harden pad lifecycle/state.
- **F1 (MEDIUM) — concurrent-use two-time pad.** New exclusive same-origin lock
  in app.js: `acquirePadLock(padId)` uses the **Web Locks API**
  (`navigator.locks`, auto-released if the tab dies) with a localStorage-
  heartbeat lease fallback. Taken on connect, released on disconnect; a pad live
  in one tab makes connect in any other tab refuse ("already in use"). Single-tab
  sequential use is unaffected.
- **F2 (MEDIUM) — pad unencrypted at rest.** `otp.js` persistence rewritten: the
  pad bytes AND consumption offsets are stored **encrypted** (PBKDF2-600k →
  AES-256-GCM) under a per-pad passphrase, never in the clear — same at-rest
  posture as the identity blob. `saveNewPad` derives the key once (PBKDF2);
  `unlockPad` decrypts on connect; `savePadProgress` re-encrypts each message
  with the cached key (no per-message PBKDF2). Offsets live INSIDE the GCM blob,
  so a local attacker can't roll `sendOffset` back to force pad reuse. A new
  "pad passphrase" field (distinct from the file "transfer passphrase") unlocks
  the pad per session.
- **F3 (LOW) — export single-use.** Re-exporting an already-shared pad warns and
  requires a confirming second click (`markExported` / `padMeta.exported`);
  import dedups by padId and the UI carries a strong "one device per side"
  warning. Cross-device double-import of a manually-copied file is inherent
  without identities (documented).
- **F4 (LOW) — low-entropy imported pad.** `importPad` now runs `looksRandom`
  (Shannon entropy over a byte histogram) and refuses a pad below 7.0 bits/byte
  (all-zero / grossly low-entropy), so a corrupt/sabotaged pad can't silently
  make outbound `ct == pt`.
- **UI:** two OTP passphrases now — a top-level **pad passphrase** (at-rest,
  per-session unlock) and the export/import **transfer passphrase** (`otpXferPass`).
- **Verified.** `node crypto.test.mjs` + `npm test` green (cipher unchanged);
  module-level checks (localStorage shim): at-rest blob carries only kdf/iv/ct
  (no plaintext bytes), unlock round-trips bytes+offsets, wrong passphrase
  rejected, all-zero pad import rejected, `looksRandom` correct. **Real-browser
  E2E (Chromium/puppeteer, two contexts + extra tabs):** generate (encrypted at
  rest) → export → re-export warns → import (encrypted, both passphrases) →
  connect → two-way messaging, zero undecryptable frames; a second tab is refused
  the in-use pad (F1); a wrong pad passphrase refuses unlock (F2). Backend
  `pytest` 57 + all 3 live integration suites still green.

### 2026-07-16 — OTP mode: true one-time pad, in-person pad exchange ✅
Implemented the deferred OTP mode as a genuine XOR one-time pad. Design forks
were decided with the user: true XOR OTP (not a pad-as-keypool shortcut),
file-based in-person pad transport (not Web Bluetooth), and CSPRNG hardened with
optional draw-to-generate entropy.
- **`OtpPad` cipher (`client/crypto.js`).** Confidentiality is a real one-time
  pad: `ct = plaintext XOR keystream`, keystream = fresh pad bytes never reused.
  The pad is split in half by ROLE (generator = role 0, importer = role 1); each
  side sends from its own region and receives from the other, so no byte is ever
  used to encrypt twice. Integrity: each message carries an HMAC-SHA-256 tag
  under a one-time 32-byte key also drawn from the pad, binding
  domain|room|role|offset|len|ct (stops XOR malleability; honest computational
  limit, since an info-theoretic one-time MAC would be hand-rolled crypto we
  forbid). A strictly increasing receive offset rejects replays AND cross-session
  replays (offsets persist per pad, never rewind). Consumed pad bytes are ZEROED
  on both send and receive (forward secrecy: capture at time T can't decrypt
  earlier traffic). Auth-failed frames consume nothing (a hostile relay can't
  burn pad with forgeries). Serialized through the shared `CallQueue`.
  `needsHandshake=false`, `usesNonces=false`; removed from `UNAVAILABLE`.
- **Pad lifecycle (`client/otp.js`, new).** `generatePad` = OS CSPRNG XOR an
  AES-CTR keystream keyed by SHA-256 of the user's drawn-motion samples (never
  weaker than the CSPRNG alone). `exportPad`/`importPad` = a passphrase-encrypted
  file (PBKDF2-600k → AES-256-GCM) carrying padId + region size + recipient role
  + pad bytes; export refuses a already-used pad (would hand the peer zeroed
  regions that XOR back to plaintext). localStorage persistence of bytes +
  offsets + role, pad index/list/forget. Size presets 64 KiB / 256 KiB / 1 MiB
  with honest per-side message estimates.
- **UI (`index.html`, `style.css`, `app.js`).** OTP panel: pad selector,
  generate (with a draw-to-generate entropy canvas), encrypted export (file
  download) / import (file upload), forget, and a live remaining-budget display.
  OTP unlocks messaging on peer PRESENCE (the pad is the out-of-band secret, like
  AES256's passphrase — no identity/safety-number gate). Offsets persisted after
  every send/receive so consumption survives reload (reuse would be
  catastrophic). `syncAlgUI` shows the panel; `connect()` loads the selected pad.
- **Docs.** README encryption-modes table + a new OTP paragraph state the two
  honest caveats plainly (computational MAC; CSPRNG-not-TRNG pad, so "at least as
  strong as the CSPRNG"). Backend needed no change — the `Algorithm` enum already
  allowed `OTP` (advisory tag; relay never acts on it).
- **Tests / verification.** New `otpChecks` in `crypto.test.mjs` (round-trip both
  directions, replay/tamper/reflection/forgery rejected, exhaustion refused, and
  FS zeroing asserted on sender + receiver) — `node crypto.test.mjs` green.
  Offline `npm test` green; all 3 live integration suites green (no regression to
  the other modes). **Real-browser check (Chromium/puppeteer, two isolated
  contexts):** Alice generated a pad with drawn entropy and exported the
  encrypted file; Bob imported it (wrong transfer passphrase rejected); both
  connected to one room, unlocked on presence, exchanged messages BOTH directions
  with zero undecryptable frames; the budget decremented; and localStorage showed
  the offsets persisted AND the consumed pad bytes zeroed at rest.
- **Known limits (documented):** a pad is a shared secret for exactly two
  devices (never import on more than one per side); pad size = total text budget
  (XOR consumes 1 byte/char + 32/msg); no post-compromise recovery beyond the
  zeroing already described. Cross-tab concurrent use of one pad on the same
  device is not locked — the offset is persisted before/after each send, but two
  tabs are a footgun; documented, IndexedDB/BroadcastChannel hardening is a
  future option if larger pads or multi-tab use are wanted.

### 2026-07-16 — Android pentest findings 1–4 (+ informational) FIXED ✅
Closed all four 2026-07-08 Android pentest findings and the informational
should-fix items. Root cause of Findings 1 & 3 was one permissive value flowing
into two sinks; fixed at the source plus defense in depth at each sink.
- **Finding 1 (CRITICAL) — relay-address → JS execution.** `RelayUrls.parse`
  (`RelayUrls.kt`) now rejects any host with a character outside
  `^[A-Za-z0-9.-]+$` (a `SAFE_HOST` regex) and rejects `user:pass@` authorities,
  BEFORE returning — so `android.net.Uri`'s permissive/percent-decoded `.host`
  can no longer smuggle `"`, `;`, `{`, `}`, spaces, or decoded delimiters
  downstream. Defense in depth: `MainActivity.loadWithRelay()` builds the
  injected `window.__SECURE_CHAT_RELAY__` config with `org.json.JSONObject`
  (proper escaping) instead of hand-interpolating a JS string literal.
- **Finding 2 (Medium) — prefix-confusable origin check.**
  `shouldOverrideUrlLoading` now compares the parsed `request.url.scheme`/`host`
  to the app origin (`https` + `appHost`), not `startsWith(appOrigin)`, so
  `https://secure-chat.internal.evil.com/…` is correctly treated as off-origin.
- **Finding 3 (Low) — CSP corruption.** Covered by the Finding 1 host whitelist:
  the value interpolated into `csp()` can no longer contain `;`/quotes/braces.
- **Finding 4 (Low/docs) — non-unique origin.** The asset loader now calls
  `.setDomain("secure-chat.internal")`, so the app serves from
  `https://secure-chat.internal` — an origin unique to this app, not
  androidx.webkit's shared `DEFAULT_DOMAIN`. `appOrigin`/`indexUrl`/`appHost`
  in `MainActivity.kt`, `APP_WEBVIEW_ORIGIN` in `backend/config.py` (WS + CORS
  allow-lists), and the `android/README.md` doc all updated in lockstep; the
  stale config.py comment claiming the default domain uniquely identifies the
  app is corrected.
- **Informational should-fixes.** `WebView.setWebContentsDebuggingEnabled` is now
  `if (BuildConfig.DEBUG)` (added `buildConfig = true` to `build.gradle.kts`);
  `network_security_config.xml` sets `base-config cleartextTrafficPermitted=
  "false"` and scopes cleartext to a `domain-config` of `127.0.0.1`/`localhost`/
  `onion` only; `importMapHash` drift is now guarded by
  `test_android_importmap_hash_matches` in `backend/tests/test_csp_hash.py`
  (recomputes the hash from index.html, asserts the Kotlin constant matches,
  skips when android/ isn't present so the backend stays standalone-testable).
- **Tests / verification:** new `android/app/src/test/.../RelayUrlsTest.kt`
  (Robolectric, so a REAL `android.net.Uri`) — 11 tests: legit https/loopback/
  onion/trailing-slash parse correctly; the exact Finding 1 PoC payloads
  (`http://y"};window.__pwn=1;%2f%2f`, percent-encoded `%2f%2f`/`%22`, and
  literal quote/brace/semicolon/space hosts) are all rejected; plus
  scheme/credentials/path-query-fragment/empty-host rejections.
  `./gradlew testDebugUnitTest` → 11 passed, 0 failures. Debug APK still builds
  clean (`./gradlew assembleDebug` BUILD SUCCESSFUL). Backend `pytest` = **57
  passed** (was 56 + the new drift guard). Web client untouched.
- **Remaining (unchanged):** on-device re-run of the app against the new origin
  + the identity/safety-number gate for DHKE/RSA/PQKEM (needs the emulator);
  app icon + release-signing config; OTP mode; Tor `.onion` deployment.

### 2026-07-08 — Android app pentest: 1 Critical + 3 Medium/Low found (NOT yet fixed) 🔴
Live pentest of the Android app on the same emulator used for on-device
verification, following this project's usual "attack the running system, prove
it with a live PoC" methodology. All four findings below are reproduced against
the actual installed APK; none require jailbreak/root — `run-as` on a **debug**
build stood in for "an attacker gets a value into `Prefs`", which for finding 1
is realistic via the app's own Settings dialog (see reachability note).

**Finding 1 — CRITICAL — relay-address string → arbitrary JS execution,
pre-page-script, CSP-bypassing (full app compromise).**
`RelayUrls.parse()` (`RelayUrls.kt`) validates a user-supplied "relay address"
using only `android.net.Uri.parse(text)` — scheme must be http/https, host must
be non-empty, and path/query/fragment must be absent. **`android.net.Uri` does
NOT validate hostname characters.** Empirically confirmed on-device: `"`, `;`,
`{`, `}`, and space all survive verbatim in `.host`; percent-encoding decodes
into `.host` too (`%22`→`"`, `%3a`→`:`, `%2f`→`/`) *without* tripping the
path/query rejection (the raw `%XX` bytes don't look like the real delimiter
chars to the top-level splitter, so a percent-encoded `%2f%2f` becomes a
literal `//` in the decoded host that the path check never saw coming).
`MainActivity.loadWithRelay()` then string-interpolates the PARSED value,
unescaped, into a JS snippet:
```kotlin
val js = "window.__SECURE_CHAT_RELAY__ = {api:\"${relay.httpOrigin}\", ws:\"${relay.wsOrigin}/ws\"};"
```
injected via `WebViewCompat.addDocumentStartJavaScript` — a mechanism that
(by design, so it can run before any page script) is **not subject to the
page's CSP**. The same unescaped value is also interpolated into the CSP
header itself (`csp()`), but that's a secondary effect (see Finding 3) — the
PRIMARY bypass is that `addDocumentStartJavaScript` doesn't consult CSP at all.
- **PoC 1 (marker):** relay address
  `http://y"};window.__pwn=1;%2f%2f` → after Uri decoding, httpOrigin becomes
  `http://y"};window.__pwn=1;//`. Substituted into the template, `//` becomes
  a JS line-comment eating the rest of the (single-line) injected script:
  `window.__SECURE_CHAT_RELAY__ = {api:"http://y"};window.__pwn=1;//", ws:...`
  parses as three clean statements (assign the object, `;`, `window.__pwn=1;`)
  followed by a comment. **Confirmed live via CDP: `window.__pwn === 1`.**
- **PoC 2 (real impact):** same technique, payload hooks
  `crypto.subtle.importKey` before any page script runs, then the "Create
  identity" / AES256-connect flow was driven for real. **Captured the actual
  first 8 bytes of the user's typed secret**: `[115,117,112,101,114,32,115,101]`
  = ASCII `"super se"` (from the passphrase "super secret victim passphrase"),
  proving the injected code can intercept identity/passphrase key material as
  the app derives it — a full break of the app's core security property
  (client-side key custody) via its one user-configurable value.
- **Reachability:** the ONLY way `Prefs` gets a relay value is the Settings
  dialog's `RelayUrls.parse(input.text.toString())` (confirmed by reading
  `MainActivity.kt` — no other write path exists). The realistic attack is
  social engineering: an attacker hands the victim a "relay address" to paste
  (a natural ask in this app — relays are meant to be shared), and the
  malicious JS executes the moment they hit Save (`loadWithRelay(parsed)`
  fires immediately with the freshly single-pass-parsed value, no restart
  needed). Note: writing the value to `Prefs` via `run-as` (used for the PoCs,
  since driving the native dialog's EditText through `adb shell input text`
  with these characters fights two layers of shell escaping) exactly reproduces
  what a successful dialog Save persists.
- **Fix direction:** `RelayUrls.parse` must reject any host containing
  characters outside a safe hostname charset (`[A-Za-z0-9.-]`, plus `[...]` for
  literal IPv6 — or just reject IPv6 literals too, unneeded here) BEFORE
  accepting it — don't rely on `Uri` alone. Independently, stop string-building
  JSON/JS by hand: `JSONObject` (or a proper JS-string-escape helper) for the
  injected config, and construct the CSP header via a list of validated tokens
  rather than raw interpolation.

**Finding 2 — Medium — `shouldOverrideUrlLoading` origin check is
prefix-confusable (chainable off Finding 1).**
```kotlin
override fun shouldOverrideUrlLoading(view: WebView, request: WebResourceRequest): Boolean =
    request.url.toString().startsWith(appOrigin).not()
```
`"https://appassets.androidplatform.net.evil.com/x".startsWith("https://appassets.androidplatform.net")`
is `true` — `startsWith` doesn't check for a following `/` or end-of-string.
**Live-confirmed:** ran `location.href = "https://appassets.androidplatform.net.evil.com/probe"`
via CDP inside the loaded page; `window.location.href` afterward was
`chrome-error://chromewebdata/` — a real failed-navigation page, proving the
WebView actually attempted to load the attacker-suffixed host (only failing
because that specific fake domain doesn't resolve in DNS; a real
attacker-owned domain would succeed). On its own this needs a script already
running to trigger `location.href` — but Finding 1 supplies exactly that,
so the two chain into "malicious relay string → JS execution → silent
top-level navigation to an attacker page" as a single attack. Fix: compare
`Uri.parse(request.url.toString()).host == "appassets.androidplatform.net"`
(and scheme), not string-prefix matching.

**Finding 3 — Low/robustness — the same unescaped relay value corrupts the CSP
header.** `csp()` also interpolates `relay.httpOrigin`/`wsOrigin` unescaped
into the `Content-Security-Policy` header value. A payload containing `;`
splits it into bogus extra "directives" (confirmed via WebView console:
`"The Content-Security-Policy directive name 'window.__pwn=1' contains one or
more invalid characters"` etc.) — Chromium safely rejects the malformed
directives, so this isn't itself an escape (script-src, set BEFORE
connect-src in the string, is unaffected), but it can silently swallow the
directives that come AFTER connect-src in the source (`img-src`, `base-uri`,
`form-action`, `frame-ancestors`) if enough injected `;` shift the boundary,
and/or break the app's OWN legitimate relay connection (connect-src ends up
with no valid entries but `'self'`). Same fix as Finding 1 covers this too.

**Finding 4 — Low/docs — `https://appassets.androidplatform.net` is
`androidx.webkit`'s shared default domain, not unique to this app.**
Verified directly from the library bytecode (`WebViewAssetLoader.class`):
`public static final String DEFAULT_DOMAIN = "appassets.androidplatform.net"`,
and `MainActivity.kt` never calls `.setDomain(...)`, so it uses this literal
default. **Any other Android app** using `WebViewAssetLoader` with default
settings presents an identical `Origin` header. `backend/config.py`'s comment
on `APP_WEBVIEW_ORIGIN` — *"a single fixed value, not a wildcard, so
allow-listing it does not open the relay to arbitrary web pages"* — is
therefore not accurate: it doesn't uniquely gate "our app". **Impact is
bounded, not ignored:** CORS only restricts browser/WebView-enforced
`fetch()`; any native Android code could already hit `/api` with a raw HTTP
client with no CORS involved at all, and `/api` is designed to expose nothing
sensitive to an unauthenticated caller (token-gated lookup, signature-verified
registration, no existence oracles — see the I1 closeout). So this doesn't
grant a new capability, but the code comment's claim is false and should be
corrected; fix by calling `.setDomain("secure-chat.internal")` (or similar) to
make the origin genuinely unique, which closes the gap outright.

**Verified negative (no finding):** `WebViewAssetLoader`'s `AssetsPathHandler`
correctly rejects path traversal — tried literal `../`, `%2e%2e/`, `..%2f`,
and `....//` variants against `/assets/web/...`; all either hard-failed
("Failed to fetch") or cleanly 404'd, no content outside `assets/web/` leaked,
while the legitimate `index.html` fetch succeeded normally. Also noted but not
separately itemized (pre-existing, informational): `setWebContentsDebuggingEnabled(true)`
is unconditional (not gated to debug builds — should be `if (BuildConfig.DEBUG)`
before a release build ships); `network_security_config.xml`'s
`cleartextTrafficPermitted="true"` is unscoped (any domain, not just
loopback/.onion) though the Mixed-Content browser check is the actual gate in
practice; `importMapHash` in `MainActivity.kt` is a hardcoded duplicate of the
backend's value with no automated drift guard analogous to
`backend/tests/test_csp_hash.py` (fails closed if it drifts — app breaks
loudly rather than a security hole, but worth a guard).

**Not yet fixed** — all four are on the TODO list below. Diagnostic code used
to characterize `Uri.parse` behavior was added temporarily to
`MainActivity.onCreate` during testing and fully reverted (`git diff` clean
afterward); the device's `Prefs` was reset to a benign
`http://127.0.0.1:8000` relay before finishing.

### 2026-07-08 — Android app verified ON-DEVICE + Mixed-Content fix ✅
Installed the emulator (Android 14 `google_apis;x86_64`, KVM-accelerated) and
ran the app on a real WebView. Findings + fixes:
- **Works on-device.** App installs, renders the full UI in the WebView, and the
  relay config is injected before page scripts (`addDocumentStartJavaScript`
  works on WebView 113). Drove the real app via Chrome DevTools Protocol (over
  the adb-forwarded devtools socket) against a host-side AES256 peer through the
  relay: the on-device WebSocket reached the relay, the AES256 nonce exchange
  completed, and messages decrypted BOTH directions on the device.
- **Real bug found: Mixed-Content transport constraint.** The client page is a
  secure origin (https asset loader — required for `crypto.subtle`), so the
  browser blocks opening an INSECURE `ws://` from it. `ws://10.0.2.2:8000` was
  refused with a SecurityError; the relay must be a *potentially-trustworthy*
  origin — **wss://** (TLS), **loopback** (`127.0.0.1`/`localhost`), or a
  **.onion**. This corrected a wrong doc claim (a plain `http://192.168.x.x`
  LAN relay does NOT work). Emulator test uses `adb reverse tcp:8000 tcp:8000`
  + relay `http://127.0.0.1:8000` (loopback is Mixed-Content-exempt).
- **Fix (`client/app.js`):** `new WebSocket()` throws synchronously on the
  Mixed-Content block, which previously left the UI stuck on "connecting…"
  forever. Now wrapped in try/catch → status "connection blocked" + an
  actionable hint (needs wss/loopback/.onion) + Connect re-enabled. Verified
  on-device: pointing at `http://192.168.50.50:8000` shows the clear error
  instead of hanging. (Web client unaffected — it is same-origin, never
  Mixed-Content.)
- **Docs corrected:** relay-settings dialog text, `network_security_config`
  comment, and `android/README.md` now state the trusted-transport requirement.
- **Regression:** offline `npm test`, all 3 live suites, backend `pytest` 56 —
  all green after the app.js change. APK rebuilt + reinstalled; on-device happy
  path re-passed.
- Remaining app polish: icon, release-signing config, and an on-device pass of
  the identity + safety-number gate (only AES256 driven on-device; DHKE/RSA/
  PQKEM handshakes are covered in-browser).

### 2026-07-07 — Android app: WebView shell bundling the audited client ✅
New `android/` Gradle module. Rationale: the web deployment's one honest trust
gap (H1) is that a browser re-fetches the JS from the server each load, so a
compromised server could serve malicious crypto. The app removes that by
shipping the exact reviewed client INSIDE the APK and using the relay only as a
dumb ciphertext carrier.
- **Design (thin shell, one codebase):** `MainActivity` serves bundled
  `assets/web/` to a WebView from the local secure origin
  `https://appassets.androidplatform.net` (WebViewAssetLoader — secure context,
  so `crypto.subtle` works). The relay is remote, so the app supplies what the
  same-origin web build got for free: (1) the relay location, injected as
  `window.__SECURE_CHAT_RELAY__ = {api, ws}` via `addDocumentStartJavaScript`
  BEFORE any page script; (2) the CSP, stamped as a response header on
  index.html with `connect-src` pinned to exactly the configured relay origin.
  The relay address is entered once (menu → Relay settings), stored in
  SharedPreferences, validated to an http(s) origin (`RelayUrls`). Identity/pins
  stay in the WebView localStorage as on the web.
- **Client change (backward-compatible, keeps ONE codebase):** `app.js` reads
  `window.__SECURE_CHAT_RELAY__` for the ws URL + API base if present, else the
  original same-origin behavior (RELAY null path). Web behavior byte-identical;
  verified by re-running the same-origin 4-mode browser matrix + all 3 live
  suites green.
- **Backend change (deliberate, documented):** the app's origin differs from
  the relay's, so `APP_WEBVIEW_ORIGIN` (`https://appassets.androidplatform.net`)
  is added to `ALLOWED_WS_ORIGINS` (else the relay 1008-rejects the WS) and to a
  new `/api` CORS allow-list (`ALLOWED_HTTP_ORIGINS`, methods GET/POST, no
  credentials — endpoints carry no cookies, only explicit Bearer tokens). It is
  one fixed origin, not a wildcard. New `SECURE_CHAT_EXTRA_ORIGINS` env var adds
  more origins (e.g. the prod `.onion`) at deploy time without editing code.
  Backend `pytest` still 56 passed.
- **Bundle = single source of truth:** the `syncWebClient` Gradle task copies
  `../client` into `assets/web` at build time (excludes tests/manifests), so the
  APK can never drift from the reviewed client; the copy is gitignored.
- **Build:** needs a full JDK 21 *with jlink* (the distro's openjdk-21 here was
  JRE-only — used a self-contained Temurin 21) + Android SDK platform-34 /
  build-tools-34. `./gradlew assembleDebug` → 5.7 MB debug APK,
  `org.securechat.app`, minSdk 26 / target 34. Clean build from source verified
  (assets auto-synced, 21 web files packaged).
- **Verified (real browser, Chromium/puppeteer — the WebView IS Chromium):**
  reproduced the app's exact cross-origin setup (bundled client on origin A,
  relay on origin B, relay config injected before scripts, app CSP applied):
  relay config visible to the page; cross-origin `/api` register succeeded
  (CORS); cross-origin WS DHKE handshake with MATCHING safety numbers; two-way
  messages delivered. This exercises the whole app code path except the Kotlin
  glue (asset loader / document-start injection / menu), which compiles +
  packages but is **NOT yet run on a device/emulator** (none in the build env).
  On-device smoke test is the remaining step.

### 2026-07-07 — DHKE/PQKEM in-session FS + reflection guards (ratchet unification) ✅
Closed the main informational finding from the same-day review (below): DHKE
and PQKEM kept one static AES-GCM session key (`AuthChannel`), so state
compromise mid-session decrypted that entire session. Now ALL FOUR modes run
the same forward-secret `RatchetChannel`; `AuthChannel` is DELETED.
- **DHKE (`crypto.js`):** the ECDH secret is HKDF'd into two direction-
  separated chain heads (info binds each chain to its sender's raw pub, salt =
  room id, domain `secure-chat/dhke-fs/v1`); frames are `dhke-msg/v2`. Exactly
  one derivation ever happens (first key wins), so the ECDH private key is
  dropped the moment the chains exist — in-session FS from the first message.
  `myPub` is cached at init so a (replayed-offer) `handshakePayload()` still
  answers after the keypair is gone.
- **PQKEM (`crypto.js`):** same chains rooted in the hybrid ECDH+ML-KEM ikm
  (info binds the sender's ECDH pub, domain `secure-chat/pqkem-fs/v1`); frames
  are `pqkem-msg/v2`. Seals like RSA on first real traffic (`_seal` zeroes the
  KEM secret key + raw shared secrets, drops the ECDH keypair; post-seal
  handshake frames ignored) — the race path may deliver a second root secret
  until then, and messaging sits behind the safety-number gate so the race has
  settled by first traffic. `ecdhBits`/`ikm` intermediates are zeroed right
  after HKDF import (they weren't before; DHKE's too).
- **Reflection guards (all handshake modes + hello):** an offer/answer carrying
  OUR OWN public key (DHKE pub / RSA pub / PQKEM ECDH or KEM pub) is refused
  outright — never legitimate, and identical pubs would collapse the direction
  separation of the chains. Previously only the human safety-number comparison
  caught a relay echoing someone's own identity back. Likewise app.js now
  refuses a hello carrying OUR OWN nonce (a reflected hello used to wedge the
  handshake via first-write-wins; now the slot stays open for the real peer).
- **Wire format:** DHKE/PQKEM `msg` frames changed (`{iv,ct,n}` ratchet frames
  under new domains; the old `secure-chat/msg/v1` AuthChannel framing is gone).
  Handshake payloads unchanged. Both ends always run the same served code, so
  no compatibility shim.
- **Tests:** new `handshakeRatchetChecks` in `crypto.test.mjs` — DHKE keypair
  dropped at derivation; PQKEM material held until traffic then sealed on
  first encrypt AND first decrypt; skipped-frame keys unrecoverable (both);
  replayed offers ignored post-establishment/post-seal; reflected handshakes
  rejected (DHKE/PQKEM/RSA). Existing reflection/replay/tamper + concurrency
  checks now exercise `RatchetChannel` in all 4 modes.
- **Verified:** client offline `npm test` green; backend pytest 56 passed; all
  3 live integration suites green; real-browser matrix (Chromium/puppeteer,
  two isolated contexts per mode) green for ALL 4 MODES — identities, matching
  safety numbers, two-way traffic, zero undecryptable/dropped frames — plus
  the double-click regression; server log still 0 bytes after all traffic.
- Deliberately NOT fixed (still informational): backend token-lookup timing
  (256-bit random tokens), relay per-peer send stall, verify-panel replay
  cosmetics. Post-compromise recovery (DH ratchet) remains out of scope.

### 2026-07-07 — final crypto review + full verification matrix ✅
White-box review of the whole client crypto stack (crypto.js, auth.js,
identity.js, account.js, app.js flow) + backend front door (validation.py,
relay.py, accounts.py, main.py). **No new High/Medium findings.** Verified
green across the board: client offline `npm test` (32 OK), backend `pytest`
56 passed, all 3 live integration suites, real-browser matrix
(Chromium/puppeteer, two isolated contexts per mode): ALL 4 MODES end-to-end —
identity creation, staggered join, matching safety numbers (handshake modes),
4 two-way messages, zero undecryptable/dropped frames — plus the double-click
regression check; server log EMPTY after all traffic (I2 holds).
Informational notes (as found; the first three were FIXED the same day — see
the ratchet-unification entry above):
- **DHKE/PQKEM have no in-session FS** — CLOSED same day (all modes now run
  `RatchetChannel`; `AuthChannel` deleted).
- Key-material hygiene (`ecdhBits`/`ikm` not zeroed) — CLOSED same day.
- A relay reflecting a peer's OWN hello back wedged the handshake until
  reconnect — CLOSED same day (reflected hello + reflected handshake keys now
  refused in all modes).
- A relay replaying a signed offer FROM THE CURRENT session verifies (same
  nonces) and can re-trigger `enterVerification` — ciphers are idempotent so
  no desync; worst case a duplicate sys line / re-shown verify panel (pin
  short-circuits it after first confirm). Cosmetic; left as is.
- Backend nits (left as is): bearer-token dict lookup isn't constant-time
  (256-bit random tokens — negligible); relay fan-out send has no per-peer
  timeout (a stalled peer only stalls its own room's sender).

### 2026-07-07 — cipher-call serialization: both 2026-07-03 pentest races CLOSED ✅
Fixed the two open concurrency findings (High + Medium) in one change; shared
root cause was that `AuthChannel`/`RatchetChannel` update their anti-replay
state (sequence counters, chain heads) across awaited WebCrypto calls while
their callers don't serialize (`ws.onmessage` fires handlers back-to-back; the
UI could fire overlapping sends).
- **Fix (`client/crypto.js`):** new `CallQueue` — a per-channel FIFO promise
  queue; both channel classes now route the public `encrypt()`/`decrypt()`
  through it into the (renamed) `_encrypt`/`_decrypt`. One call runs at a time,
  in arrival order; a rejected call propagates to its caller but never blocks
  the queue. Covers all 4 modes (AES256/RSA via `RatchetChannel`, DHKE/PQKEM
  via `AuthChannel`) with no wire-format or interface change.
  - Kills the **High** (racing decrypts of already-observed frames could
    commit out of order, roll the replay counter back, and re-accept a message
    the user already saw) and the **Medium** (two overlapping encrypts read the
    same chain head, consumed the same one-time key, and permanently desynced
    the ratchet — the peer saw an undecryptable frame and all later messages
    silently vanished).
- **Defense in depth (`client/app.js`):** `sendText` now has a `sending`
  in-flight flag and disables the Send button while an encrypt is pending
  (re-enabled only if the gate still allows messaging), so a double-click /
  Enter-repeat can't even queue a duplicate send. A disabled default submit
  button also blocks implicit (Enter) form submission per spec.
- **Tests (`crypto.test.mjs`, new `concurrencyChecks`, run for all 4 modes):**
  overlapping unawaited encrypts → both frames decrypt + channel intact after;
  3 concurrent decrypts of the SAME frame → accepted exactly once; the exact
  pentest rollback scenario (two different frames delivered concurrently, then
  both replayed) → both replays rejected. Confirmed the suite CATCHES the bug:
  against the pre-fix `crypto.js` (git stash) it fails at the overlapping-
  encrypt check with the ratchet-desync AEAD failure.
- **Verified:** client offline `npm test` green; backend `pytest` 56 passed;
  all 3 live integration suites green; **real-browser regression check**
  (Chromium/puppeteer, two isolated contexts, AES256): Alice double-clicks
  Send in the same tick → message delivered exactly once, zero undecryptable
  frames, ordinary follow-up messages flow both directions afterwards (the
  pre-fix behavior was a corrupted second frame and a permanently dead channel).

### 2026-07-03 — AES256 ratchet: cross-session replay CLOSED + honest FS ✅
Second half of TODO item (d), building directly on the RSA ratchet (below).
- **Refactor first:** RSA's ratchet framing was extracted into a shared
  `RatchetChannel` (`client/crypto.js`): direction-separated one-way
  HMAC-SHA-256 chains, one-time AES-256-GCM message keys, strictly increasing
  `n`, skip-with-discard bounded by `RATCHET_MAX_SKIP=1024`, scratch-head
  stepping committed only after AEAD success. `Rsa` now delegates to it
  (unchanged wire format/behavior, all RSA FS tests still green); `AuthChannel`
  now serves only DHKE/PQKEM.
- **AES256 redesign.** The mode still puts NO key material on the wire, but the
  ratchet chains are no longer derived from the passphrase alone: on join both
  peers exchange fresh random 32-byte session nonces via the app's existing
  plaintext `hello` phase (previously handshake-modes-only; AES256 has no
  identity requirement, so its hello is unauthenticated — tampering only
  desyncs keys, a loud DoS the relay could always cause). Chains =
  HKDF(PBKDF2-600k(passphrase), salt = room|sorted-nonces, info =
  `secure-chat/aes-fs/v1|` + sender's nonce); frames are `aes-msg/v2`.
  **Your own nonce is fresh and never attacker-controlled, so a frame captured
  in an earlier session (same room + passphrase) can never authenticate in a
  new one — the documented AES256 cross-session-replay residual is CLOSED**
  (relay-forced replay of an old peer nonce just desyncs loudly; it cannot make
  the victim re-derive an old key). Erasure: the cipher's passphrase copy is
  dropped at `init()`, the derived HKDF base right after chain derivation.
- **Honest FS limit (documented in README + KNOWN LIMITATIONS):** captured
  ratchet STATE can't decrypt earlier traffic, but the passphrase is a
  long-term secret outside the code and the nonces are public — passphrase
  compromise + recorded ciphertext still re-derives every session. Inherent to
  passphrase-only; real FS = DHKE/PQKEM/RSA.
- **app.js:** the hello phase now runs for every mode (`joined` sends it
  unconditionally); on hello, AES256 (`cipher.usesNonces`) derives via
  `cipher.setNonces(myNonce, peerNonce)` and unlocks (the passphrase is the
  out-of-band verification — no identity gate, as before, but send/receive now
  unlock only after the peer joins). A phase-2 signed-handshake frame arriving
  in AES256 mode is refused (`!cipher.needsHandshake` guard) — it could only be
  relay-injected.
- **Tests:** `crypto.test.mjs` — AES256 paths now exchange nonces; new
  `aesRatchetChecks`: **cross-session replay REJECTED** (fresh-receiver variant
  too, so it's the key, not the counter, doing the rejecting), passphrase/base
  erasure, skipped-frame-unrecoverable. `integration.test.mjs` harness speaks
  the AES256 hello. All offline suites green; all 3 live integration suites
  green; backend pytest 56 passed. **Verified in a real browser**
  (Chromium/puppeteer, two contexts): send locked before the peer joins,
  unlocks after the nonce exchange, 5 messages both directions, zero
  dropped/undecryptable frames; RSA browser check re-run green (regression, since
  the joined/hello path changed for all modes).

### 2026-07-03 — RSA mode: forward secrecy (key transport + one-way ratchet) ✅
Closed TODO item (d) for RSA. Previously every RSA message's AES key was
RSA-OAEP-wrapped to the peer's session-long RSA key, and the HMAC root secret +
RSA private key lived for the whole session — so state compromise at any point
(or later, with a recorded transcript) decrypted the ENTIRE session. That
per-message wrapping was inherently incompatible with forward secrecy and was
removed.
- **New design (`client/crypto.js`, Rsa class).** The handshake is unchanged on
  the wire (offer `{pub}`, answer `{pub, ws}` with the OAEP-wrapped 32-byte
  root secret; race-tolerant sorted-tag folding; first-write-wins). From the
  root, HKDF derives two direction-separated **HMAC-SHA-256 chain keys** (info
  binds the sender's pub, salt = room id, domain `secure-chat/rsa-fs/v1`). Each
  message uses a **one-time AES-256-GCM key**: `msgKey = HMAC(chain, 0x01)`,
  then `chain = HMAC(chain, 0x02)` — one-way, consumed keys erased (raw bytes
  zeroed after import, keys non-extractable). Frames are `{iv, ct, n}` with AD
  `secure-chat/rsa-msg/v2|room|n` (v1 frames are thus invalid). A gap in `n`
  fast-forwards the chain and DISCARDS the skipped keys (bounded by
  `RSA_MAX_SKIP=1024` against hostile-relay CPU burn); the receive step is
  committed only after the AEAD authenticates, so a garbage frame can't wedge
  the channel or burn keys.
- **Sealing.** On the first real message (either direction) `_seal()` erases
  the root secrets AND drops the RSA private key (+ peer wrap key) — the two
  things that could replay the whole key schedule from a recorded transcript.
  Post-seal handshake frames are ignored (a replayed offer can't desync or
  resurrect state). Sealing at first traffic is safe because messaging sits
  behind the safety-number gate, seconds after the handshake settles; a relay
  withholding a race answer past that point could only cause a loud decrypt
  failure (= DoS it could do anyway). Same documented race window as PQKEM.
- **Properties:** forgery still fails (relay never learns the root → no valid
  AEAD); reflection fails (direction chains); replay fails (strictly increasing
  `n` + one-time keys); **in-session forward secrecy** (state at time T can't
  decrypt before T); cross-session FS was already given by per-session RSA keys.
  NOT provided (out of scope): post-compromise/break-in recovery — that needs a
  DH-style ratchet, pointless to fake with RSA.
- **Tests:** `crypto.test.mjs` — `rsaAttackChecks` updated (forgery/reflection/
  replay/tamper still rejected; + channel survives a rejected frame). New
  `rsaForwardSecrecyChecks`: seal erases kp/secrets on first send AND first
  receive; skipped frame's key unrecoverable while later frames decrypt;
  post-seal replayed offer ignored; far-future `n` rejected. All offline suites
  green; all 3 live integration suites green; backend pytest 56 passed.
  **Verified in a real browser** (Chromium/puppeteer, two isolated contexts):
  RSA staggered join, matching safety numbers, 5 messages both directions
  (ratchet advancing), zero dropped/undecryptable frames.
- app.js unchanged except a comment (generic cipher interface held); README
  encryption-modes table + RSA paragraph rewritten.

### 2026-07-02 — L2/I2 closeout: metadata-at-rest disabled + room-id guarantee ✅
Closed the last two accepted-risk items from the 2026-06-19 review.
- **I2 — no request/connection metadata at rest (code fix).** Uvicorn's access
  log wrote every request line (method/path/status/timing) and its error logger
  emitted INFO connection-lifecycle lines ("connection open/closed") — a
  who-connected-when trail if a `.onion` host is seized. `main.py` now disables
  the access logger and lifts `uvicorn.error` to WARNING at import
  (`_minimize_log_metadata`), the `__main__`/`uvicorn.run` path passes
  `access_log=False, log_level="warning"`, and `run.sh` carries
  `--no-access-log --log-level warning`. Verified live: after healthz + `/api`
  + a full WebSocket relay round-trip, the server log is EMPTY. Only genuine
  error tracebacks (never payloads/room ids) are ever logged. Guard test
  `tests/test_logging.py` (access logger disabled, error logger ≥ WARNING,
  run.sh keeps the flags) fails loudly on regression.
- **I2 does NOT change behavior** — purely removes logging; all suites still green.
- **L2 — room-id bearer-capability risk: closed as a documented bounded
  guarantee (no code change).** A room is joined by knowing its 256-bit id; the
  relay is deliberately anonymous (no joiner auth) to keep who-talks-to-whom off
  the server. A mechanism "fix" (relay-side admission control) would require
  binding identities to the relay and recording exactly that metadata — a net
  loss for the primary threat model. The impact of a leaked room id is already
  bounded to **availability + coarse metadata, never confidentiality or
  impersonation**: the relay forwards only opaque ciphertext, and the
  authenticated + safety-number-gated handshake stops a squatter posing as the
  real contact (AES256's unsent passphrase is its gate). Structural mitigations
  already in place: room ids are high-entropy (256-bit) and single-use/rotatable
  — treat one like a one-time secret. Documented precisely in README
  ("Metadata & residual risks") and the relay/threat notes.
- Backend `pytest` = **56 passed** (+3 logging guards).

### 2026-07-02 — accepted-risk closeout: L1 (PQ ownership proof) + I1 (enumeration) ✅
Closed the two accepted-risk items from the 2026-06-19 security review.
- **L1 — server-side ML-DSA-65 ownership proof at registration.** Registration
  now requires a dual signature over the bundle: the server verifies BOTH the
  Ed25519 proof (as before, via `cryptography`) AND an ML-DSA-65 proof (new,
  via `dilithium-py` — a pure-Python verifier, cross-checked against the
  client's `@noble/post-quantum` signer). A registrant can no longer bind a PQ
  public key they don't control. `RegisterReq` gains `mldsa_sig`; `account.js`
  now signs the register message with `identity.sign()` (dual) instead of
  `signEd()`. New dep: `dilithium-py==1.4.*` (verify only; the server is still
  not the authenticity root — the in-person safety number is).
- **I1 — username namespace made non-enumerable (token-gated lookup + oracle
  removal).** Registration mints a random per-account lookup token
  (`config.LOOKUP_TOKEN_BYTES=18`, ~144 bits); the shareable identifier is now
  the HANDLE `username#token`. `GET /api/users/{name}?t=<token>` returns an
  IDENTICAL 404 for a missing user OR a wrong token (constant-time compare
  against a decoy for missing users), so a bare/guessed username reveals
  nothing. `POST /api/auth/challenge` now issues a challenge for ANY well-formed
  username (no existence 404) and `POST /api/auth/verify` returns 401 for
  unknown-user and bad-sig alike — neither is an existence oracle anymore. A
  dedicated stricter per-host rate limit (`_lookup_limiter`) bounds the lookup
  path. Client: `account.parseHandle`, handle-based `fetchBundle`, register
  stores + displays the handle, the contact field takes a handle. Residual
  (documented, inherent): registering a taken name still 409s — but each probe
  costs a full dual-signed proof and is rate-limited, and enumeration of the
  bundle-fetch path is closed.
- **DB:** `accounts` table gains `lookup_token` (with an ALTER-based migration
  for pre-token DBs).
- **Tests:** `test_accounts.py` rewritten to sign with real ML-DSA (dilithium)
  and cover the new behavior: bad-PQ-sig rejection, missing `mldsa_sig`,
  token-gated lookup (no/wrong token → 404), challenge-doesn't-reveal-existence,
  verify-unknown-user-is-401, and a dedicated lookup rate-limit test. Backend
  `pytest` = **53 passed**. `accounts.integration.test.mjs` updated for the
  handle flow (incl. wrong-token → null). Verified in a real browser
  (Chromium/puppeteer): Alice registers → handle shown; Bob's WRONG token fails
  to resolve; Bob's correct handle → directory lookup, matching safety number,
  message delivered. All offline + live suites green.

### 2026-06-19 — backend v0 (local relay)
- Created project at `~/secure-chat`.
- `backend/config.py` — all hard limits in one auditable place (frame size,
  payload size, room id length, max members/rooms, rate-limit params).
- `backend/validation.py` — strict pydantic `Envelope` (extra fields forbidden,
  immutable), printable-ASCII check, base64 payload check, 64-hex room ids,
  enum message types + advisory algorithm enum, payload-presence rules.
- `backend/relay.py` — in-memory `RoomRegistry` (no storage, empty rooms
  deleted) + per-connection `TokenBucket` rate limiter.
- `backend/main.py` — FastAPI app, single `/ws` WebSocket endpoint, `/healthz`,
  security headers, CORS locked shut, docs/openapi disabled, payloads never
  logged, fail-closed validation, size cap before parse, rate limit.
- `backend/tests/test_validation.py` — unit tests for the validation front door.
- `backend/tests/smoke_client.py` — two-client end-to-end relay smoke test.
- `backend/run.sh`, `requirements.txt`, `README.md`, `.gitignore`.

### Security measures already in place (server side)
- Server does no crypto and holds no keys/plaintext (E2EE dumb relay).
- Strict, fail-closed input validation; unknown fields/types rejected.
- ASCII-only enforced on the whole frame.
- Frame size cap (64 KiB) checked before any parsing.
- Payload size cap (~48 KiB) + base64-only payload.
- Per-connection token-bucket rate limiting.
- Global connection cap + per-connection idle read timeout (zombie reaper).
- Global room cap + per-room member cap (DoS/memory bounds).
- Rooms in-memory only; deleted when empty (no data at rest).
- Message payloads never logged; no stack traces leaked to clients. Access log
  + connection-lifecycle logging disabled (I2) — no request/timing metadata at
  rest; only content-free error tracebacks are recorded.
- CORS disabled; security headers (CSP `default-src 'none'`, nosniff, DENY,
  no-referrer); API docs/OpenAPI endpoints disabled; server header stripped.

### 2026-06-19 — verified locally ✅
- venv created, deps installed.
- `pytest tests/test_validation.py` -> **12 passed**.
- Server started; `/healthz` 200 with all security headers present;
  `/docs` -> 404 (disabled); `Server` header **absent** (stripped via
  `server_header=False` / `--no-server-header`).
- `smoke_client.py` -> two clients joined the same room, opaque base64 payload
  relayed **verbatim** and decoded correctly on the peer. Server log shows
  only connection lifecycle, **no payloads**.

### 2026-06-19 — web client + key exchange + server hardening ✅
- `client/crypto.js` — Web Crypto only (no hand-rolled crypto). Implements:
  - **AES256**: shared passphrase → PBKDF2-SHA256 (310k iters, room id as salt)
    → AES-256-GCM. No network handshake.
  - **DHKE**: ephemeral ECDH P-256 → AES-256-GCM, private key non-extractable.
  - **RSA**: RSA-OAEP-2048 public-key swap, hybrid per-message AES-256-GCM.
  - PQKEM + OTP marked unavailable (documented, UI-disabled).
- `client/index.html` + `style.css` + `app.js` — minimal UI: room id (+256-bit
  generator), encryption selector, passphrase field, message log. No inline
  JS/CSS or inline handlers (CSP-clean). Rendering uses textContent only (no
  innerHTML) → no XSS path.
- Handshake protocol over the relay's `key` message: payload = base64(JSON
  {pub, reply}); `reply` flag makes the early joiner answer exactly once, so
  the exchange converges with no infinite ping-pong (verified).
- Server hardening:
  - **WebSocket Origin allow-list (CSWSH protection)** — present-but-disallowed
    origin → 403; missing Origin (native/CLI) allowed.
  - Static web client served **same-origin** via StaticFiles (path traversal
    blocked); explicit /ws + /healthz routes take precedence.
  - CSP tightened to allow only same-origin script/style/connect, no inline.
- Tests:
  - `client/crypto.test.mjs` — round-trips for all 3 algos + wrong-key reject
    + ascii guard. **All pass** (Node Web Crypto).
  - `client/integration.test.mjs` — two real WebSocket clients through the
    running relay, full handshake + message exchange for all 3 algos.
    **All pass.**
  - curl checks: `/`→200, `/app.js`→200, traversal→404, evil Origin→403,
    CSP header present, relay log shows **no payloads**.

## KNOWN LIMITATIONS / THREAT NOTES (read before trusting E2EE)
- **Key-exchange MITM — CLOSED in the live web client (2026-06-19).** DHKE and
  RSA handshakes are now signed by a long-term identity (Ed25519 + ML-DSA-65)
  and verified against the peer's bundle, gated by an in-person safety-number
  check (option (b) from the original plan). A relay swapping the ephemeral key
  fails signature verification; a relay swapping the whole identity yields
  mismatched safety numbers at the two endpoints. AES256-passphrase mode remains
  not-MITM-able (no key material exchanged). Residual trust assumptions:
  - Users MUST actually compare the safety number out of band; clicking through
    "it matches" without checking reduces this to trust-on-first-use.
  - The account directory (`/api`) is only a convenience for *fetching* a bundle;
    it is not a trust root. Authenticity still comes from the in-person check.
- **AES256 forward secrecy is honest-but-limited (2026-07-03).** AES256 now
  ratchets too (one-time message keys; passphrase copy + derived base erased
  after chain derivation), and its session chains bind BOTH peers' fresh
  session nonces — so captured ratchet STATE can't decrypt earlier traffic and
  cross-session replay is closed. But the passphrase itself is a long-term
  secret outside the code (user's head, input field) and the nonces cross the
  relay in the clear: passphrase compromise + recorded ciphertext still
  decrypts every session, past and future. Inherent to a passphrase-only mode;
  real FS = DHKE/PQKEM/RSA — all three ratchet per message AND erase their
  handshake material (RSA/PQKEM seal on first traffic, DHKE drops its private
  key at derivation; since 2026-07-03/2026-07-07), on top of per-session
  ephemeral keys.
- **AES256 passphrase is offline-attackable by the relay.** The room id (which
  the relay routes on, so it always knows it) is the PBKDF2 salt, and the relay
  sees the ciphertext — so a malicious/compromised relay can mount an offline
  dictionary attack on the passphrase. 600k PBKDF2 iterations slow this, but a
  low-entropy passphrase will fall: AES256 security rests entirely on passphrase
  strength. Prefer a generated high-entropy passphrase, or use DHKE/PQKEM.
- **Reflection/replay — CLOSED for all modes, incl. cross-session
  (2026-07-02, completed 2026-07-03; unified 2026-07-07).** ALL FOUR modes now
  use the same `RatchetChannel`: direction-separated one-way chains + one-time
  message keys + strictly increasing sequence numbers. Reflected handshake
  keys and reflected hellos are additionally refused outright (2026-07-07).
  The old AES256 residual — cross-session replay of a frame captured under the
  same passphrase + room id — is CLOSED since 2026-07-03: the session chains
  bind a fresh random nonce from BOTH peers, so an old frame can never
  authenticate in a new session. DHKE/PQKEM are ephemeral per session and
  never had the residual.
- **Metadata:** relay sees room id + timing + ciphertext sizes (padding TBD).

### 2026-06-19 — identity keys + authenticated handshake (MITM gap closed in core) ✅
- Trust model chosen (per user): **simple accounts, each with a long-term
  identity keypair you verify IN PERSON; verified identity keys authenticate
  the per-session key exchange.** Dual keys — classical + post-quantum:
  - **Ed25519** (classical) via Web Crypto (native, 32-byte pub, 64-byte sig).
  - **ML-DSA-65 / Dilithium** (post-quantum) via `@noble/post-quantum`
    (1952-byte pub, 3309-byte sig). Dependency scoped to PQ only.
- `client/identity.js` — `Identity` class: generate, `publicBundle()`,
  `fingerprint()` (per-key, read aloud to verify), `safetyNumber()` (pair,
  order-independent), dual `sign()`, static dual `verify()` (BOTH schemes must
  pass), encrypted `export()/import()` of private keys at rest (PBKDF2 310k →
  AES-256-GCM, passphrase-protected; private keys never leave the device).
- `client/auth.js` — authenticated handshake: signs transcript
  `DOMAIN || roomId || ephemeralPubKey` with the identity; verifier checks the
  dual signature against the PINNED peer identity before trusting the ephemeral
  key. roomId binding prevents cross-room replay.
- `client/identity.test.mjs` — **proves the security property**: simulates a
  malicious relay (Mallory) swapping the ephemeral key; authenticated handshake
  REJECTS (swapped key + old sig, impostor sig, and cross-room replay) and
  ACCEPTS only the genuine signed key. Also covers dual-sig tamper rejection,
  fingerprint determinism, safety-number order-independence, encrypted
  export/import + wrong-passphrase rejection. **All pass.**
- `client/package.json` — `@noble/post-quantum` dep; `npm test` runs crypto +
  identity suites. Installed clean (0 vulnerabilities).
- Library facts (verified in Node 22): Web Crypto Ed25519 = supported;
  `@noble/post-quantum` API is `ml_dsa65.sign(msg, secretKey)` /
  `verify(sig, msg, pubKey)`; ML-KEM-768 available for future PQ key exchange.

### 2026-06-19 — account directory (passwordless, key-based) ✅
- DECIDED with user: **passwordless / key-based login** (server stores only
  public keys; login = sign a server challenge) + **identity key encrypted in
  the browser** (passphrase-unlocked; manual export/import as backup).
- `backend/accounts.py` — SQLite-backed public-key directory + FastAPI router
  under `/api`. Stores only username -> {ed_pub, mldsa_pub}; never secrets.
  Endpoints:
  - `POST /api/register {username, ed, mldsa, sig}` — sig = Ed25519 over
    `secure-chat/register/v1\n<username>\n<ed>\n<mldsa>`; proves control of the
    classical key + binds the bundle (anti-squatting). Strict size checks.
  - `GET /api/users/{username}` — returns the public identity bundle to pin.
  - `POST /api/auth/challenge {username}` — returns a fresh 32-byte nonce (TTL).
  - `POST /api/auth/verify {username, challenge, sig}` — verifies Ed25519 over
    the nonce, one-time-consumes the challenge, issues a bearer token (TTL).
  - `GET /api/me` (Bearer) — resolves token -> username.
- `backend/config.py` — DB path (env `SECURE_CHAT_DB`), username rules, fixed
  key/sig sizes, challenge/token TTLs.
- Server-side crypto: `cryptography==43.*` for Ed25519 verify. (ML-DSA verified
  CLIENT-side in the handshake; server only stores the PQ pubkey — server is
  not the authenticity root, so no native PQ dep needed server-side.)
- `backend/tests/test_accounts.py` — 12 tests: register+lookup, bad sig,
  duplicate, bad username, wrong key size, unknown user, full login flow,
  wrong-sig login, one-time challenge, token required, extra-field rejection.
  **All pass.** Full server suite now **24 passed**.
- Relay `/ws` intentionally stays **anonymous/room-based** (accounts are a key
  directory + auth, not coupled to the relay) to minimize who-talks-to-whom
  metadata. Documented as a deliberate choice.

### 2026-06-19 — browser wiring of identity/auth (live MITM gap CLOSED) ✅
- **Vendored ESM + import map.** Traced the transitive import closure of
  `@noble/post-quantum/ml-dsa.js` (12 files across post-quantum/hashes/curves,
  ~184 KB) and vendored byte-identical copies into `client/vendor/@noble/...`
  (`client/vendor/README.md` records provenance + versions). `index.html` has an
  inline `<script type="importmap">` mapping the three `@noble/` prefixes into
  `vendor/`. Inline import maps are required by spec, so instead of loosening CSP
  it is **pinned by its exact SHA-256 hash** in `script-src` (no `'unsafe-inline'`).
- **Identity UI** (`app.js` + `index.html`): create / unlock / forget / copy-
  backup. Private keys live only inside the passphrase-encrypted blob in
  `localStorage` (`Identity.export/import`); the fingerprint is shown for the
  contact to verify. Identity is **required** for DHKE/RSA, optional for AES256.
- **Authenticated handshake**: the `key` message now carries
  `{pub, reply, idb, sig}`; the receiver runs `verifyHandshake` (dual Ed25519 +
  ML-DSA) against the received bundle before deriving the shared key, and
  refuses + disconnects on failure (visible MITM signal).
- **In-person verification gate**: after the signature verifies, the UI shows
  the safety number and blocks messaging until the user confirms it matches.
  Confirmed bundles are pinned per room id (`sc.pins.v1`); a later session whose
  key differs raises a loud "identity CHANGED" banner and forces re-verification.
- **Tests**: `client/auth.integration.test.mjs` drives two real WebSocket peers
  through the running relay using the exact app.js authenticated protocol and
  asserts both derive the same key + identical safety number (DHKE + RSA). The
  vendored closure was separately proven self-sufficient under import-map-
  equivalent resolution. Existing suites still green (crypto, identity, legacy
  integration; backend pytest **24 passed**); server serves the pinned-hash CSP,
  the import map, and `vendor/@noble/...` same-origin.

### 2026-06-19 — relay WebSocket endpoint tests + deterministic leave-close ✅
- `backend/tests/test_ws.py` — 16 in-process endpoint tests driving the real
  `/ws` loop via Starlette `TestClient`: join→joined, verbatim msg/key relay,
  not-in-room, double-join, wrong-room, room-full (3rd member), leave-closes,
  oversized-frame, non-ascii, bad-envelope (+ connection survives a soft
  reject), extra-field-over-the-wire, rate-limit flood, and the CSWSH origin
  allow-list (disallowed rejected; allowed + missing accepted). Full backend
  suite now **40 passed**.
- `backend/main.py` — on a `leave` message the server now `await ws.close()`s
  explicitly before breaking, instead of relying on the framework's implicit
  close (which left the peer's socket hanging without a close frame). More
  correct relay behaviour and makes leave deterministically observable.

### 2026-06-19 — connection-level abuse / DoS bounds ✅
- `backend/config.py` — `MAX_CONNECTIONS` (global concurrent-socket cap) and
  `IDLE_TIMEOUT_SEC` (per-connection idle read timeout, 15 min default).
- `backend/relay.py` — `ConnectionLimiter` (`try_acquire`/`release`, single-
  event-loop safe) bounding total concurrent connections.
- `backend/main.py` — refuse over-cap connections at the handshake (close 1013)
  before `accept()`; wrap each `receive_text` in `asyncio.wait_for(IDLE_TIMEOUT)`
  to reap half-open/zombie sockets and connect-but-never-join squatters
  (warn + close 1001); release the slot in `finally`.
- Deliberately **did not** add a per-connection lifetime frame cap (the token
  bucket already bounds throughput; a lifetime cap would punish long chats) or
  per-IP limits (behind Tor all traffic appears from loopback, so per-IP is
  meaningless on `.onion`). Both noted inline.
- `backend/tests/test_ws.py` — +2 tests (cap refuses 3rd over a patched cap of
  2; silent socket is idle-timed-out and closed). Full server suite **42 passed**.

### 2026-06-19 — browser account directory integration ✅
- `client/identity.js` — added `signEd()` (classical-only Ed25519 signature) for
  server account proofs; the directory is not the authenticity root, so the PQ
  key isn't needed there.
- `client/account.js` — new module wrapping the `/api` directory protocol:
  `register` (Ed25519 proof binding username→bundle, byte-for-byte matching the
  server's `_register_message`), `fetchBundle` (lookup by username; null on 404),
  `login` (challenge → sign → token), `me`, and a shared username validator.
- `client/app.js` + `index.html` — account panel (claim username / log in) that
  appears once an identity is unlocked and remembers the username locally; an
  optional **Contact username** field in setup (DHKE/RSA only). On connect the
  client fetches that contact's bundle and uses it in the verification gate:
  pins are now keyed `user:<name>` when a username is in play (else `room:<id>`),
  and a live key that disagrees with the directory entry raises a loud mismatch
  banner. The in-person safety number remains the trust anchor.
- `client/accounts.integration.test.mjs` — drives account.js against the live
  server: register→lookup→login→me round-trip, duplicate-username 409, and
  wrong-key login rejection. All pass. (A static check also confirms every
  element id app.js references exists in index.html.)
- No CSP change needed (`connect-src 'self'` already covers the same-origin
  `/api` fetches; account.js/identity.js load under `script-src 'self'`).

### 2026-06-19 — post-quantum key exchange (PQKEM mode) ✅
- Completes the original encryption menu: the **key exchange** is now post-
  quantum too, not just the authentication. (Authentication was already
  one-classical-one-PQ: Ed25519 + ML-DSA-65 dual signatures on the handshake.)
- `client/crypto.js` — new `Pqkem` cipher: **hybrid ECDH P-256 + ML-KEM-768**,
  combined via HKDF-SHA-256 (salt = room id, domain-separated info) into an
  AES-256-GCM key. Secure unless BOTH primitives break ("harvest now, decrypt
  later" resistance) and no weaker than DHKE if ML-KEM were faulted. Vendored
  `@noble/post-quantum/ml-kem.js` (only new file; rest of the closure was shared
  with ml-dsa → 13 vendored files; import map already covers it).
- The exchange is **symmetric and join-order-race tolerant**: each peer offers a
  KEM public key, the other encapsulates, and secrets are folded in keyed by
  `SHA-256(ek)` so both sides combine the same secret(s) in the same order — one
  secret in the normal (staggered-join) case, two in the simultaneous-join race,
  converging either way. The brief two-step settling in the race is covered by
  the manual safety-number gate (no message is sent until the user confirms,
  seconds later, by which point the key is final).
- `client/app.js` + `index.html` — PQKEM enabled in the menu and treated as
  identity-required (authenticated handshake). Removed the per-connection
  handshake-signature cache (`myEph`): PQKEM's offer and answer are distinct
  payloads, each signed fresh; idempotent and harmless for DHKE/RSA.
- Tests: PQKEM added to `crypto.test.mjs` (2-round = the race path, converges),
  `integration.test.mjs`, and `auth.integration.test.mjs` (safety number
  matched). Integration harnesses now **stagger** joins (the realistic order).
  **Verified in a real browser** (Chromium via puppeteer): PQKEM selectable,
  handshake completes, safety numbers match, and messages decrypt **both
  directions** — confirming the vendored ML-KEM loads under CSP + import map.

### 2026-06-19 — security review + hardening (pentest follow-up) ✅
Ran a white-box review + live attack probes. Fixed the actionable findings:
- **M1 — `/api` abuse bounds.** Added a per-client-host token-bucket
  (`KeyedRateLimiter` in relay.py; on Tor it collapses to one global throttle)
  as a router-wide dependency on `/api` → floods now get `429` (confirmed live:
  27/90 blocked; previously 0). Added hard caps: `MAX_ACCOUNTS` (register →
  `503` when full), `MAX_PENDING_CHALLENGES`, `MAX_ACTIVE_TOKENS` (bounds the
  in-memory auth stores so a flood can't exhaust memory even within the TTL).
- **M2 — join deadline.** Split a short `JOIN_TIMEOUT_SEC` (30 s) for pre-join
  sockets from the generous `IDLE_TIMEOUT_SEC` (15 min) for joined peers, so
  "connect but never join" slot-squatters are dropped fast.
- **L3 — KDF work factor.** PBKDF2-SHA256 raised 310k → **600k** (OWASP 2023)
  for AES256 mode and identity-at-rest. Export blob is now `v:2` and stores
  `iters`; import honours it and falls back to 310k for old `v:1` backups
  (regression-tested).
- **H1 — honest trust boundary.** README now scopes "server compromise → only
  ciphertext" to *passive* compromise and documents that the web client trusts
  the server to serve honest code each load (mitigations: Android app, `.onion`,
  reproducible builds). Not a code change — a corrected security claim.
- Tests: +5 backend (`api` rate limit, account/challenge/token caps, join
  timeout) and +1 client (legacy-blob import). Server suite **47 passed**;
  client crypto/identity + all integration suites green.
- **Accepted / deferred (documented, not fixed):** L1 (ML-DSA pubkey ownership
  not proven at registration — needs a native PQ verify; no impersonation
  results since the in-person safety number is the trust root), L2 (room-slot
  squatting if a 256-bit room id leaks), I1/I2 (username enumeration + access-log
  metadata — inherent to a public directory; scrub logs on the `.onion`).
  **UPDATE 2026-07-02 (second session): ALL FOUR now CLOSED** — L1/I1 in the
  "accepted-risk closeout" entry; L2 (documented bounded guarantee) and I2
  (access/connection logging disabled) in the "L2/I2 closeout" entry below.

### 2026-07-02 — RSA mode: per-message HMAC authentication (forgery fix) ✅
- **Finding (code review):** RSA mode had NO message authenticity. Each message
  was a fresh AES key RSA-OAEP-wrapped to the recipient's public key — but that
  key crosses the relay in the (unencrypted, only signed) handshake, so the
  relay could wrap its own AES key and inject messages that decrypted cleanly
  and rendered as "peer". Encrypting to a public key proves nothing about the
  sender. (DHKE/PQKEM/AES256 don't have this: their GCM key is a shared secret
  the relay never learns.)
- **Fix (`client/crypto.js`, Rsa class):** the handshake answer now transports
  a random 32-byte MAC secret, RSA-OAEP-encrypted to the offerer's public key
  (`ws` field — covered by the existing identity signature over the whole
  payload, so the relay can't strip/replace it). Both sides HKDF-SHA-256 the
  secret (salt = room id) into TWO direction-separated HMAC-SHA-256 keys (info
  binds the sender's public key). Every message now carries a strictly
  increasing sequence number `n` and `mac = HMAC(sendKey,
  domain|room|n|ek|iv|ct)`; receivers verify the MAC BEFORE any decryption and
  reject stale `n`. Defeats: forgery (relay never learns the wrapped secret),
  reflection (direction keys), replay (seq + per-session secret). Wrapped
  secrets are folded into HKDF keyed by SHA-256(recipient pub), sorted — same
  race-tolerant convergence pattern as PQKEM — and first-write-wins so a
  replayed handshake frame can't diverge the keys.
- RSA's offer/answer are now distinct payloads (like PQKEM); app.js already
  handled that generically, so only comments changed there. `makeCipher` passes
  the room id to `Rsa`. Shared byte helpers (`concatBytes`, `sha256Hex`) moved
  above the RSA section (used by RSA + PQKEM).
- **Tests:** `crypto.test.mjs` + `rsaAttackChecks()` — Mallory-as-relay
  completes her own handshake from B's observed offer and injects a message
  (the exact old attack): REJECTED; reflection of A's own frame: REJECTED;
  replay of a genuine frame: REJECTED; tampered ciphertext: REJECTED (MAC
  checked before decrypt). All suites green after the change: client offline
  (`npm test`), both live integration suites (integration + auth, all algos),
  backend `pytest` 47 passed.
- **Still open (documented in KNOWN LIMITATIONS):** AES256/DHKE/PQKEM still
  lack reflection/replay protection; porting this MAC construction (or an AD/
  direction-key variant) to them is a natural next step.

### 2026-07-02 — verification gate now covers receiving (pre-verify display fix) ✅
- **Finding (code review):** the safety-number gate only blocked SENDING.
  Inbound `msg` frames were decrypted and rendered as "peer" as soon as
  `cipher.ready`, i.e. before the user confirmed the safety number. In the
  exact threat the gate exists for — a relay swapping the whole identity and
  running a MITM session — the swapped bundle carries a valid signature (the
  relay's own key), so the handshake verifies and the attacker could display
  messages as a trusted peer pre-verification (e.g. social-engineering the
  user into clicking through the gate).
- **Fix (`client/app.js`):** new `verified` flag, set only by
  `unlockMessaging()` (pin match / user confirms) and by the AES256 no-gate
  path (its passphrase IS the out-of-band verification); reset on connect and
  on socket close. The `msg` handler drops frames (never decrypts, shows a
  "[dropped]" sys line) while `verified` is false.
- **Verified in a real browser** (Chromium via puppeteer-core, DHKE): a
  Node-side authenticated peer completed the handshake and sent a message
  while Alice's verify panel was open → dropped, not rendered, send still
  locked; after clicking "it matches" a follow-up message rendered normally.
  All existing suites still green (client offline `npm test`, all 3 live
  integration suites, backend pytest 47 passed).

### 2026-07-02 — reflection/replay closed everywhere + crypto hardening ✅
Follow-up review after the receive-gate fix; fixed the remaining findings.
- **Reflection/replay for AES256/DHKE/PQKEM (`client/crypto.js`).** New shared
  `AuthChannel`: each frame carries a random per-session sender tag + a strictly
  increasing sequence number, both folded into the AES-GCM additional data (so
  a relay can't alter them without the key). Decrypt rejects a frame whose tag
  is our own (reflection) or whose sequence isn't advancing (replay). AES256,
  DHKE and PQKEM all route through it; RSA keeps its own HMAC construction.
  Residual documented: AES256's static key still permits cross-session replay.
- **PQKEM handshake-replay desync (confirmed bug).** A relay replaying a peer's
  validly-signed PQKEM offer made the recipient re-encapsulate a fresh secret
  and rotate the live session key (DoS). Fixed with first-write-wins per
  encapsulation key + idempotent `_derive` (skips when inputs are unchanged, so
  the channel and its replay counters survive a replay). DHKE made idempotent
  too (`if (this.chan) return`).
- **DHKE key derivation.** Was using the raw ECDH X-coordinate directly as the
  AES key; now runs it through HKDF (room-id salt + domain tag), matching PQKEM.
  `Dhke` now takes the room id; `makeCipher` passes it.
- **Login challenge domain separation (`accounts.py` + `account.js`).** The
  login signature now covers `secure-chat/login/v1\n` || nonce instead of a bare
  nonce, so it can't be cross-used as any other protocol signature. Backend +
  client updated in lockstep; `test_accounts.py` adjusted.
- **CSP import-map hash guard.** New `backend/tests/test_csp_hash.py` recomputes
  the SHA-256 of the inline importmap in index.html and asserts the served CSP
  still pins it — so editing the import map without regenerating the hash fails
  loudly instead of silently breaking the page.
- **Tests:** `crypto.test.mjs` gained reflection/replay/tamper checks for
  AES256/DHKE/PQKEM and a PQKEM replay-doesn't-desync regression. Verified in a
  real browser (Chromium/puppeteer): DHKE handshake, receive-gate, and a two-way
  message exchange under the new framing all work. All suites green.

### 2026-07-02 — cross-session handshake replay CLOSED (session nonces, transcript v2) ✅
- **Finding (2026-07-02 pentest, Medium):** the signed handshake transcript
  (`DOMAIN || roomId || ephemeralPayload`) had no per-connection freshness, so
  a relay could replay a peer's validly-signed handshake from an OLD session
  into a NEW session reusing the same room id → silent key desync with a
  misleading "verified" UI (integrity/availability, not confidentiality).
- **Fix (`client/auth.js` + `client/app.js`):** transcript bumped to
  `secure-chat/handshake/v2` and now covers a fresh random 32-byte nonce from
  BOTH peers' current connections. New plaintext `hello` phase inside the `key`
  message (`{hello:true, n, reply}`): each peer announces its nonce on join;
  the receiver of a reply:false hello answers once (reply:true) and then sends
  the signed offer; the signed answer flows as before. Nonces are folded
  order-independently (sort b64, concat bytes) so both sides sign/verify the
  same transcript regardless of direction; peer nonce is first-write-wins.
  Hellos are unauthenticated in flight but authenticated retroactively by the
  signature that covers them — tampering only makes the handshake fail loudly
  (a relay could always DoS). A stale signed handshake can never cover the
  nonce the victim generated THIS connection → signature verification fails
  instead of desyncing. The domain bump alone also invalidates all pre-v2
  captured handshakes. Note the offer direction reversed in the staggered-join
  case (the EARLY joiner now sends the first signed offer, since it learns both
  nonces first); the ciphers' symmetric/race-tolerant design is direction-
  agnostic, and the simultaneous-join race path is unchanged (dual offer +
  dual answer, idempotent onPeerKey).
- **Tests:** `identity.test.mjs` — new cross-session-replay rejection suite
  (stale sig vs fresh nonce REJECTED, fresh-pair REJECTED, genuine ACCEPTED,
  nonce-order independence). `auth.integration.test.mjs` — peers speak the new
  hello+offer/answer protocol, PLUS a live PoC regression: session 1 captured
  through the real relay, its validly-signed handshake replayed by a Mallory
  client into session 2 (same room) → REJECTED. Verified in a real browser
  (Chromium/puppeteer): two isolated contexts, DHKE staggered join, identical
  safety numbers, two-way messages. All suites green: client `npm test`, all 3
  live integration suites, backend `pytest` 48 passed.

## TODO / NEXT (suggested order)

### 🟡 OPEN — the 2026-08-07 pentest (branch `pentest-2026-08-07-fixes`, unmerged)
Committed as `ba4233e`, plus **uncommitted** 2026-08-08 work. All 15 planned
items implemented; backend **154 passed**, client **143 checks**, e2e **13/13 +
32/32 + 8/8 + 12/12**. The branch is **NOT clean to merge** — everything below is
what stands between it and master, in the order I would do it.

**Read A2 before anything else.** The branch was pentested on 2026-08-08 and has
3 High + 5 Medium open against it, none fixed. The green numbers above do not
cover any of them (see A3).

Report: `docs/pentests/secure-chat-pentest-2026-08-07.md`. Per-finding detail and PoCs live
OUTSIDE this repo, in `/home/kpafi/secure-chat-pentest/state/findings/`.

#### A. Blocking — must be resolved before merge

1. **✅ ANSWERED 2026-08-08 — and it turned up a worse problem (new item 1a).**
   The attack stops exactly where the fix intends, on the endpoint that receives
   the first handshake: it logs `[a peer completed the key exchange without ever
   being approved — refusing]` and closes the socket (`readyState 3`).
   Harness now in the repo at `e2e/hostile-relay/` (the old one was lost with the
   scratchpad); `README.md` there has the four run recipes and the result table.

   **Why the earlier run saw nothing.** It was reading the WRONG PARTY. The peer
   that answers the hello sends the first handshake and the peer that refuses it
   closes before ever sending one back — so the refusing side has the log line
   and a closed socket, while the other side sits at "connected" with an open
   socket and its last frame a handshake nobody answered. "Both stall at hello"
   is one endpoint's downstream symptom, not a second stopping point.
   The refusal is also nearly invisible in the UI even on the right party:
   `ws.onclose` → `showScreen("room")` → `clearHints()` wipes the hint, and
   `case "error"` only ever calls `hint()`, so relay errors leave no log trace at
   all. The `#log` line survives; the hint does not.

   **"Both parties refuse" is not what happens, and cannot be.** Only one
   endpoint ever evaluates the check in this configuration — the other is never
   sent a handshake to check. Forcing both handshakes into flight at once
   (`HS_DELAY_MS`) does not change it: the hello INITIATOR only sends a handshake
   in reply to one it accepted. The answering endpoint's branch does fire and was
   verified separately (`EVIL_MODE=nosign`), but the claim in `auth.js` should
   read "the first endpoint to be handed an unaccompanied handshake refuses",
   not "both refuse".

   Two harness traps worth keeping, both of which would have produced a false
   green: `queueKnock` drops any knock whose `jid` is not 16 hex chars (the
   positive control caught this — the owner's prompt simply never appeared), and
   a hostile relay that keeps the real relay's seat bookkeeping never routes the
   `key` frames at all, so both victims stall for the ATTACKER's reasons and the
   client's check is never reached. `demote` routes unconditionally on purpose.

1a. **✅ FIXED 2026-08-08 — the admission proof was self-mintable; approval is
   symmetric now.** Found and reproduced end to end in two real browsers
   (`e2e/hostile-relay/`, `SCENARIO=attacker`).

   **The fix.** `signAdmission`/`verifyAdmission` are deleted, the `adm` wire
   field with them. In their place: a handshake from an identity no human on
   THIS device approved is held at the approval prompt — the same one the owner
   already had — and refused if the user says no. Two ways past without asking,
   both read from local state: the peer matches `expectedPeerBundle` (the
   directory key for the contact the user picked), or it is a 🟢 key in the
   contacts store. Owner and guest routes both write one variable,
   `approvedBundle`, and the handshake is compared against it.

   Kept from before: the admitted-identity binding, the anon-then-signed refusal,
   and M-2's owner half (`roomRole === "owner"` with nobody admitted). That last
   one does consult a relay frame, which is safe in the one direction it runs —
   it can only ADD a refusal, never skip the approval.

   **Verified:** client 143, backend 154, e2e 13/13 + 32/32 + 8/8 + 12/12, and
   the new regression 8/8 in both scenarios. `all-modes.mjs` and
   `room-admission.mjs` gained the guest's approval click; `two-user-flow.mjs`
   and `no-dead-ends.mjs` never complete a live handshake and were untouched.

   **Cost:** one extra prompt for a guest joining a raw room code with an
   unknown peer, immediately before the safety-number step.

   **What it does NOT claim.** A relay that knows the room code can still be a
   participant — that is inherent, the code is the join frame — so this does not
   stop an attacker from getting a prompt shown. It restores the property the
   attack removed: a human sees the peer's fingerprint and trust mark, with the
   "⚠ NOT the user you selected" warning, BEFORE any key material is touched.
   The safety-number comparison remains the last line, as designed.

   The original finding, for the record:

   `verifyAdmission` checks that the signature verifies against `idbCanon` — the
   peer's own bundle. Nothing requires the signer to be an identity the victim
   trusts, or that any human was asked. So an attacker signs an admission naming
   the victim with her own key (a keypair is free), and the victim accepts it:
   in the run, alice reached the safety-number screen with a peer nobody ever
   approved, and the attacker's client is the SHIPPED code plus one assignment
   (`admittedBundle = idbCanon`) — the existing `sendSignedKey` mints the proof.

   So the control holds only against an attacker running an unmodified client,
   which is not a threat model: the party running the hostile relay is exactly
   the party who can patch their client. What still stands between this and a
   readable session is the out-of-band safety-number comparison — the same last
   line as before the fix — and NOT the admission control.

   No binding repairs that shape, which is why the replacement moved the
   decision to local state instead. The claims in `auth.js`, `app.js`, the main
   `README.md` and this file are rewritten to match what the code now does.

2. **✅ DONE 2026-08-08 — `pentest-new-code` ran over the whole branch**, in three
   parallel lanes (the symmetric-approval rewrite; the backend contract changes;
   at-rest + crypto). **It found 3 High and 5 Medium. Every High is in FIX CODE**
   — code added to close an earlier finding. They are items 13-24 in section A2.
   **The three Highs were fixed 2026-08-10; the lanes have NOT been re-run over
   those fixes yet.** Re-run them.
3. **✅ Re-ran the four e2e suites 2026-08-08** after the 1a fix: 13/13 + 32/32 +
   8/8 + 12/12, plus the new hostile-relay regression 8/8 in both scenarios.
   **Re-run after every fix in A2.** Relay must be started with the venv (item 12).

#### A2. The 2026-08-08 pentest of this branch — ALL 8 CLOSED (2026-08-10)

Ordered by severity. Where a claim was modelled rather than executed, it says so.

**Status: every High and every Medium is closed** — 13, 14, 15, 16, 17, 18, 20
fixed; 19 decided, documented and hardened. Plus 21 and the two
`forge.mjs`/string-compare parts of 24. **Open: 22, 23, the rest of 24, and all
of A3.** `pentest-new-code` has NOT been re-run over any of the fixes — that is
now the top item.

**HIGH**

13. **✅ FIXED 2026-08-10 — and the FIX ITSELF had a Medium regression, found by
    the follow-up pentest and repaired the same day. Read this part first.**

    **The regression (pentest lane A).** The first cut wrote
    `derivedFloors: !!nativeFloor` into the blob BEFORE the bumps that back it,
    and discarded the bumps' return values. A derived bump that failed or was
    interrupted during a pad's FIRST save therefore left the blob permanently
    asserting two slots that were never written, and the new guard then refused
    the pad forever — **an unrecoverable brick wearing the exact wording of the
    tamper alarm**, which teaches the user to disbelieve that alarm. Worse via
    `importPad`: `padWasUsed` sees the send slot at 0, so the in-person-exchanged
    pad file could not be re-imported either and the padId was burned. The
    triggers are non-adversarial: a transient Keystore error (the JS wrapper
    swallows it into `NATIVE_TAMPERED`, which the caller discarded), a full disk
    (`PadFloor.bump` ignores `commit()`'s boolean), or a kill between two JNI
    calls. Reproduced, and confirmed to open normally on the pre-fix code — so it
    was genuinely introduced by the fix, not pre-existing.

    **The repair.** New `armFloors(id, wm, exportedNow)` bumps all three slots and
    then **READS EACH BACK**, returning `{send, derived}`; `writePadBlob` calls it
    BEFORE serialising and records `nativeFloor: armed.send` /
    `derivedFloors: armed.derived`. The claim is now made only where it is true.
    **Scope deliberately widened past the finding:** the 2026-07-29 `nativeFloor`
    flag had the identical defect one level up — also a claim written before its
    bump, with the result discarded — and could brick a pad the same way. It is
    measured now too.

    **The trade-off, because it is a security choice and not an obvious one:**
    when arming fails the blob records `false` and the pad opens UNGUARDED for
    that slot (the pre-fix behaviour) rather than being refused. A permanent brick
    is the worse outcome — it destroys an in-person key exchange, no user action
    undoes it, and it trains the user to ignore the alarm. The failure it protects
    against is non-adversarial; an attacker who can actually suppress bumps is
    inside the native floor's threat model and is still caught by
    `broken`/`NATIVE_TAMPERED`, which refuse outright. The guard re-arms on the
    next save that succeeds.

    **Regression test:** `testFailedBumpDoesNotBrickAPad` covers all three slots
    failing independently, asserts the pad stays usable, AND asserts the guard
    re-arms once the floor works again, so the degraded state cannot silently
    become permanent. Non-vacuous: with the read-back reverted it throws the
    brick error.

    The original fix, which still stands: a `derivedFloors: true` marker inside
    the v3 AEAD (`writePadBlob`), `#exported` is bumped on every save with 0/1 rather
    than only on export (so the slot exists from the first save and ABSENT is
    unambiguous — `PadFloor.bump(_, 0)` does write, since ABSENT is `-1`), and
    `unlockPad` refuses when the marker is set while either derived slot reads
    ABSENT. Gated on the new field rather than on `nativeFloor`, because
    2026-07-29-era pads legitimately have no derived slots; that reasoning is now
    written in the code. Exploit reproduced pre-fix (`unlockPad` succeeded with
    `exported === false` after a pre-export snapshot + one prefs deletion — a
    pristine pad re-armed for a second export) and refused post-fix. The false
    green the finding names is gone: `otp-rollback.test.mjs` no longer deletes
    `padId + "#recv"` to isolate the export latch (it uses a second pad), and
    gained three item-13 checks including one that a pre-derived-slot pad is NOT
    bricked. Residual, stated in the code: a blob written by this branch between
    the F-ATREST-001/002 fix and this one has the slots but not the marker, so it
    keeps the old behaviour until its next save — this working tree only, since
    the branch was never merged or deployed.

    The original finding: `client/otp.js:733-756`. The 2026-07-29 H-1 deletion guard reads
    `inner.nativeFloor === true && native === NATIVE_ABSENT`, and `native` is the
    SEND slot only. `NATIVE_ABSENT` is `-1`, so a deleted `#exported` slot reads
    as "never exported" at `:745` and a deleted `#recv` contributes `0` to the
    max at `:804`. Each derived id is its own SharedPreferences entry, so this is
    one file edit. With a pre-export snapshot it yields a SECOND export of a
    pristine pad — a two-time pad, the one failure OTP cannot survive; the recv
    half reopens the M-7 replay window. Reproduced against a faithful PadFloor
    mock. F-ATREST-002's comment ("the native latch never lowers, so it outlives
    any restore of the blob") is false for anyone who can remove the entry.
    **Fix shape:** a `derivedFloors: true` marker (or a floor-schema version)
    inside the v3 AEAD, written whenever the new code bumps a derived slot, and
    refuse when it is set while either derived slot is ABSENT. It cannot simply
    be made strict: pads written before this change legitimately have no derived
    slots — which is presumably why the guard was omitted, and that reasoning
    belongs in the code, where it currently is not.
    Note `otp-rollback.test.mjs` deletes `padId + "#recv"` and then lets
    `unlockPad` SUCCEED with nothing asserted about it.

14. **✅ FIXED 2026-08-10 — route (a) deleted**, exactly as the fix shape said.
    The only remaining skip is route (b), a 🟢 key verified in person behind the
    contacts passphrase. **Item 21 is fixed in the same function** (a set-but-
    mismatched `expectedPeerBundle` returns null instead of falling through) and
    so is the `peerAlreadyTrusted` string-comparison half of item 24 (now
    `sameSigning`, i.e. decoded bytes). The false claims are corrected in
    `client/app.js` (both the `approvedBundle` header and the call site),
    `client/auth.js`, `README.md`, and the two e2e helpers' comments; the
    "gains no click" promise is replaced with the honest cost — a repeat chat
    with an in-person-verified contact is free, everything else including first
    contact by handle costs one prompt. The stale `e2e/hostile-relay/forge.mjs`
    citations in `app.js` and `auth.js` (item 24) now name the command that
    actually reproduces it, `SCENARIO=attacker node e2e/hostile-relay/proto001.mjs`.

    **New regression: `client/peer-approval.test.mjs`, 9 checks.** `app.js` has
    no export surface, so rather than refactor the largest file in the tree to
    hang a test on it, the test lifts the REAL `peerAlreadyTrusted` source out of
    `app.js` by brace matching and runs it against stubs — covering items 14 and
    21, the routes that must survive, the fail-closed edges (⚪ contact, locked
    store), and a source-level assertion that neither deleted route returns.
    Confirmed to fail when route (a) is reintroduced by hand.

    The original finding: `client/app.js:2142` (`peerAlreadyTrusted` route (a)).
    `expectedPeerBundle` is set from `account.fetchBundle` (`client/account.js:152`),
    which canonicalises base64 and length-checks the keys and **verifies no
    signature** — nothing binds the handle to the key material, and the handle's
    token is a random server-issued lookup token. So a hostile directory returns
    its own bundle, the prompt is skipped, and the client prints an
    attacker-chosen reassurance: "peer key matches the directory key for X — no
    approval needed". Reproduced 6/6, victim's peer fingerprint == attacker's.
    This is the flow the rewrite advertised as costing no click, and the comment
    claiming both routes are "facts we hold locally and the relay cannot write"
    is false. Not only same-origin: `RELAY.api` exists so the Android app can
    serve trusted client bytes locally while pointing at a remote directory —
    honest client, attacker-controlled directory, identical single `fetch`.
    **Fix shape:** delete route (a). Route (b) (a 🟢 key in the passphrase-backed
    contacts store) is genuinely local and can stay, so repeat chats with a
    verified contact still skip; first contact by handle costs one click, which
    is what the safety-number step asks for anyway. At minimum stop printing
    "no approval needed".

15. **✅ FIXED 2026-08-10 — serialised behind a module lock** in
    `_mldsa65_verify`, the single `dilithium_py` call site in the process, so it
    covers `/auth/verify` and `register` both (closing the latent `register` bug
    the finding notes predates the branch).

    **The decision, and why:** `xoflib` is not installable in this environment
    (`pip install xoflib --no-index` → "No matching distribution"), so the
    dependency route could not have been tested here — shipping an untestable
    fast path is worse than the ceiling. The lock is correct whatever backend is
    installed, which is the property that matters, since the failure mode being
    closed off is precisely "someone deploys without xoflib and nothing says so".
    Adopting `xoflib` later is a fine change, but it must come with the new
    concurrency test run against the new backend; the comment says so, and says
    not to delete the lock on the strength of a requirements pin alone.

    **Measured, not assumed:** a verify is ~15 ms on this machine, so the ceiling
    is **~66/s process-wide**, not the report's ~140/s. The relay's own throttles
    bind far below that (0.5/s per username, 4/s per host). The always-on decoy
    is kept — dropping it reopens F-RELAY-006's timing oracle — and its
    interaction with the lock is now documented at the decoy: unauthenticated
    garbage can no longer CORRUPT concurrent real logins, only hold the lock for
    one verify each.

    **New regression: `backend/tests/test_concurrency.py`, 4 tests** — the first
    tests in the suite that use real threads, which is what item 26 says the
    whole 154-test suite structurally lacks. Covers the primitive (320 valid
    verifies over 8 threads) and the endpoint (8 concurrent valid logins), each
    with a fail-closed counterpart. Without the lock it reports **179/320 valid
    signatures rejected**. Note for whoever writes the next one: sign SERIALLY in
    the test — `ML_DSA_65.sign` shares the same process-global SHAKE state, so
    signing inside the threads corrupts the test's own signatures and blames the
    server for it. That cost a debugging round here.

    The original finding: `backend/accounts.py:736-752`. No `xoflib`
    in this venv, so `dilithium_py` falls back to a SHAKE wrapper whose
    `shake256`/`shake128` are module-level singletons with mutable buffer state;
    `auth_verify` is a sync `def`, which FastAPI runs in the anyio threadpool (as
    `accounts.py:534`'s own comment says). Independently reproduced twice:
    library level, 8 threads over a VALID signature → 178/320 rejected; tampered
    → 320/320 rejected. End to end, 5 concurrent valid logins → one spurious
    `401 challenge signature invalid`; the same users all pass serially.
    **Fails closed — no auth bypass.** Amplified by the always-on decoy at
    `:745-752`, which runs the ML-DSA verify for legacy clients and nonexistent
    users too, so unauthenticated garbage corrupts real users' logins. Master was
    Ed25519-only (OpenSSL, no shared Python state), so this branch owns it;
    `register` has the same latent bug but that predates the branch.
    **Fix shape (a decision):** add `xoflib` as a dependency, or serialise the
    verify behind a lock (~7 ms each ⇒ ~140/s ceiling), or give each call its own
    XOF. Whichever is chosen, pin it so an `xoflib`-less deploy cannot silently
    reintroduce it.

**MEDIUM**

16. **✅ FIXED 2026-08-10.** The read-modify-write is now serialised instead of
    merely checked, in two layers: a `writeChain` promise queue that orders
    writes WITHIN a tab (`persist()` has awaits, so two overlapping operations in
    one tab could already interleave with no second tab involved), and
    `navigator.locks` across tabs. With the lock held across compare AND swap the
    losing tab reads the winner's witness and refuses loudly instead of silently
    discarding history, and store+witness become one critical section so the
    store can no longer end up older than the witness.

    **The single-value alternative was rejected, deliberately:** the witness has
    to stay readable when the store is gone — that is the whole of F-ATREST-005's
    deletion detection, and it carries its own salt for it — so merging them
    would let one `removeItem` delete the evidence with the data. Written up at
    the fix.

    **Fallback posture, and it is a real difference from OTP:** with no
    `navigator.locks` the cross-tab layer is absent and the residual is exactly
    today's behaviour. This does NOT copy F-CRYPTO-014's "no Web Locks, no OTP"
    stance, because there the failure is keystream reuse and the feature can be
    withheld, whereas here withholding means the user cannot open their own chat
    history. Stated in the code rather than left implicit.

    Regression in `chats-rollback.test.mjs`: two module instances over one
    storage, both writes started without awaiting the first, asserting exactly
    one succeeds and the other is told to reload. Node has no `navigator.locks`,
    so the test installs a faithful FIFO shim on `globalThis` — without it the
    cross-tab half is inert and the test would pass vacuously. Fails pre-fix with
    "exactly one concurrent write may succeed — two successes IS the lost update".

    The original finding: `client/chats.js:337-358`. `persist()` reads the witness, checks
    `witness.gen > generation`, then encrypts (two awaits) before writing store
    and witness. Two tabs that both read the witness BEFORE either writes both
    see gen N and both write N+1. Lost update reproduced in-process with two real
    module instances over one storage: both `markSeen` calls returned `true` and
    `env-A1` was silently dropped from the P-13 replay ring, so the relay can
    replay that envelope and it is accepted as new. The permanent-lockout half
    was reproduced under a **write-ordering model, not two real browser tabs** —
    WebCrypto resolves FIFO in one Node loop — but nothing in the code constrains
    the relative order of the two tabs' four writes. It IS a faithful port of
    `contacts.js:441-448`; the difference is that chats persists on EVERY
    operation, so the residual that is rare there is ordinary here.
    **Fix shape:** wrap read-modify-persist in `navigator.locks.request` (the
    same fail-closed posture F-CRYPTO-014 already adopted for OTP), or make store
    and witness a single localStorage value so there is one atomic write and no
    CAS window at all.

17. **✅ FIXED 2026-08-10** with the `pinKeys` shape (the second option in the fix
    shape). `upsert()` now calls `rememberSupersededKeys(cur)` BEFORE overwriting
    the signing keys, and `dropPinsFor` sweeps by the union of the current bundle
    and that history, so Remove and Unverify reach pins filed under a key the
    contact has since rotated away from. The list is capped at 8 entries, because
    `upsert` is reachable from inbound mail and must not be growable without
    limit by a peer. Only signing-key changes are recorded — an ecdh/mlkem-only
    change leaves the identity that pins are matched on untouched.

    **Honest limit, written at the fix:** the history can only hold keys this
    store SAW being replaced. A pin written under `room:<id>` at K1 by a device
    that never held a contact record at K1 (pin first, contact added later
    already at K2) is still missed. Nothing in the record can recover a key it
    never stored.

    Regression in `contacts-anchor.test.mjs`: Remove and Unverify across a
    rotation, a two-rotation chain (K1→K2→K3, both older pins swept), the
    over-sweep control in the direction that matters (another peer's pin
    untouched), and the history bound. Fails pre-fix on the first one.

    The original finding: `client/contacts.js:610-620`.
    `upsert()` overwrites `cur.ed`/`cur.mldsa` on a key change without touching
    `pins`, so after a rotation the record names K2 while the `room:<id>` pin
    still names K1 and the sweep matches nothing. Reproduced. The residual is the
    SUPERSEDED key — the one a user revoking after a suspected compromise most
    wants dead, and anyone presenting it still matches a stored pin.
    **Checked the other direction:** it does not over-sweep (a collateral match
    requires both `ed` and `mldsa` to equal the contact's, i.e. the same identity
    under another label, which is correct). **Fix shape:** record the owning
    label inside the pin at `savePin` time and sweep by label ∪ bundle, or keep a
    `pinKeys: []` list on the contact record.

18. **✅ FIXED 2026-08-10, and REPRODUCED END TO END first** — the finding was
    "traced against both sides, not executed", so it was executed against the
    real endpoint before fixing: `seq=1` → 200, `seq=2**53-1` → **200 "updated"**
    (the poisoning succeeds), then `2**53` → 422 `less_than_equal`,
    `Date.now()`-scale → 409 not newer, the same value → 409 not newer. Frozen,
    exactly as modelled.

    The fix is two bounds rather than the suggested throw. Any stored value above
    `REG_SEQ_SANE_MAX` (2**43, ~year 2248 in ms — nothing this code writes can
    reach it) is treated as GARBAGE and ignored rather than used as a floor, and
    the result is clamped to `Number.MAX_SAFE_INTEGER` so the client cannot sign
    a value the server will 422. **Discarding rather than refusing is the point:**
    the counter is attacker-writable plaintext, so throwing near the cap would
    just convert a permanent server-side freeze into a permanent local one.
    Falling back to `Date.now()` heals it on the spot. The 409 retry is clamped
    the same way. `Date.now()` is now the floor on the normal path too, which is
    the trick the retry already used — it keeps the counter ahead across a
    reinstall with no round trip.

    New regression: **`client/regseq.test.mjs`, 6 checks**, driving the real
    `register()` with a stubbed `fetch` so it covers the counter actually signed
    and sent. Pre-fix it signs `9007199254740991` — the cap exactly.

    The original finding: `client/account.js`. `sc.regseq.v1` is
    plaintext and unbounded; set it to `2**53-2` and the next registration signs
    `2**53-1`, exactly the server's cap (`backend/accounts.py:510`), so it is
    ACCEPTED and stored. Afterwards every registration is refused forever: `<=`
    stored → 409, higher → 422 from the Pydantic bound. The one-shot recovery
    (`Math.max(seq, Date.now())`) is lower than the poisoned value and only fires
    on 409, not on the 422. **Traced against both sides, not executed end to
    end.** The comment says the counter "does not need to be unforgeable" — true
    for forward forgery, false for exhaustion. **Fix shape:**
    `Math.min(Math.max(cur + 1, Date.now()), 2**53 - 1)` and refuse to sign
    within a margin of the cap.

19. **✅ DECIDED AND HARDENED 2026-08-10 — accepted, with a 4x reduction in the
    attacker's reach taken because it was free.**

    **The tuning.** `CHALLENGE_RATE_REFILL_PER_SEC` 0.5 → **2.0**. The direction
    is counter-intuitive and that is why it is written into `config.py`: every
    challenge is charged to the per-`client_key` GLOBAL bucket BEFORE the
    per-username one, so an attacker's total spend is capped at the global
    ceiling however they aim it, and

        simultaneous victims = global refill / per-username refill

    At 0.5/s that was 4/0.5 = **eight** accounts one unauthenticated visitor
    could hold offline at once; at 2.0/s it is **two**. Making the bucket LOOSER
    shrinks the attack, because the binding constraint on the attacker is the
    global ceiling, not this bucket. Honest cost: nil — a client mints 1-2
    challenges per login, logs in about hourly, and `autoLogin`'s backoff caps
    retries at one per 12 s.

    **Measured, both components:** the per-username bucket refills at exactly its
    configured rate (drained to 0.12 tokens, immediate retry 429, retry after 1 s
    → 200 at refill 2.0), and a globally-throttled request **never creates the
    per-username bucket at all** — so global really is charged first and the
    attacker's budget really is capped at 4/s. Reach is a derived property of
    those two facts, pinned by a test; an end-to-end multi-victim demonstration
    was attempted and abandoned, because the harness has to clear the global
    bucket to pace itself and that is precisely the constraint being measured.
    Not claimed as demonstrated.

    **The comment.** `accounts.py` now states the residual instead of glossing
    it: that for an attacker whose goal is silencing one person, "denies that one
    account" IS the objective; what the victim actually loses (nothing for up to
    the 1 h token TTL, live chat never — a room join touches no account API —
    then async mail with a **visible** hint and ~2 s recovery once the attacker
    stops); the rejected alternative (refund-on-successful-verify does not help,
    since the victim needs a challenge to REACH verify); and plainly that the
    **service-wide DoS is not closed and cannot be by this bucket** — 4 req/s
    still denies logins to everyone, because behind Tor `client_key` carries no
    information. F-RELAY-003 moved that from 0.5 to 4 req/s: an 8x improvement,
    not a fix.

    **New: `backend/tests/test_rate_limit_invariants.py`, 6 tests.** These pin
    RELATIONSHIPS, not values, so tuning stays possible but a change that widens
    attacker reach fails: the reach bound (reverting to 0.5 fails it with "one
    attacker could hold 8 accounts offline at once"), that one username may never
    absorb the whole relay's budget, honest-login headroom, the pending-challenge
    flood bound (which is what the OTHER way of satisfying the invariant —
    lowering the global ceiling — would trade against), bystander isolation, and
    that the 429 stays non-enumerable.

    **Two corrections to the finding**, both lowering severity: delivery does not
    stop "silently" (the client shows "Not signed in to the directory — sealed
    messages will not arrive" on the 1st and 4th failure, routed through `hint()`
    so it lands on whatever screen the user is on), and it is not permanent (it
    recovers ~2 s after the attack stops). Live chat is unaffected throughout.

    The original finding: `backend/accounts.py:687`, capacity 10 / refill
    0.5-per-sec
    (`config.py:170-171`); the global backstop (120 / 4-per-sec) sits far above
    it, so the per-username bucket binds. Attacker drains it and sustains ~1
    request per 1.8 s: victim **denied=23, ok=0**, bystanders unaffected. No
    challenge ⇒ no new session token; when the 1 h TTL lapses the poller's
    re-auth fails permanently and async mail delivery silently stops.
    **This is a conscious tradeoff** (it fixed the service-wide F-RELAY-003 DoS)
    — the item is that the comment treats "draining it denies that one account"
    as acceptable without noting that targeted silencing may be the attacker's
    goal. **Decide and write it down**, or soften (smaller charge + larger burst,
    or exempt a challenge quickly followed by a successful verify).

20. **✅ FIXED 2026-08-10.** Three parts, all of them.

    **The marker.** `app.js` now sets `#admit`'s `data-mode` to `knock` or
    `peer` and clears it on hide (a stale `peer` on a hidden panel is the same
    class of residue). Prose was the only discriminator before, and asserting on
    prose makes every test a hostage to copy-editing — but the marker alone would
    let a bug where the marker says `peer` while the labels say `knock` pass, so
    **every assertion checks the marker AND the visible button label**
    ("Let them in" vs "Connect").

    **The harness.** Victim selection is now `promptMode === "peer"` rather than
    "`#admit` is un-hidden", so the check "the peer that received a handshake ASKS
    its user" can no longer go green against the OWNER's knock prompt. The
    control block waits for the RIGHT prompt per side and asserts which one it
    got (it previously called `check(..., true)` — a literal, asserting nothing).
    The refusal checks no longer sit behind `if (promptShown)`: a missing prompt
    now reports **NOT RUN and fails**, where before the two checks vanished from
    the run and the summary still read as a pass. And a wrong invocation prints
    an explicit banner — "this is an ORDINARY session, the relay is almost
    certainly POLICY=honest, these failures are not evidence the fix is broken"
    — because the finding's real complaint was that the output misleads.

    **The README.** The control recipe is `POLICY=honest` +
    **`SCENARIO=control`**, which was the missing half; it now also says the
    policy is read once at relay startup, records the old recipe's 3/9 as the
    expected wrong-invocation result, and adds the false-green to the catalogue
    it keeps.

    **`approvePeerKey` in `e2e/all-modes.mjs` and `e2e/room-admission.mjs`** waits
    for `data-mode="peer"` and throws unless the button reads "Connect", instead
    of clicking OK on whatever `#admit` was showing.

    **Verified:** control **5/5** (was un-runnable as documented), demote
    **9/9**, attacker **9/9** — 9 rather than 8 because of the new
    marker-matches-label check. The victim is `peer` under demote and `alice`
    under attacker, which is exactly what selecting on mode buys. The old recipe
    now yields 3/9 behind the banner. Non-vacuity checked by mislabelling the
    peer prompt as `knock`: `room-admission.mjs` fails in `approvePeerKey`
    instead of passing. All four e2e suites and the client suite still green.

    The original finding: `e2e/hostile-relay/`. The README's control
    is `POLICY=honest … && node proto001.mjs`, but `SCENARIO` defaults to
    `"shipped"` and the control block is gated on `SCENARIO === "control"`. Run
    verbatim it fails 6/8 with messages that read as *the fix is broken* rather
    than *you invoked it wrong*. Worse, inside that run the check "the peer that
    received a handshake ASKS its user" went GREEN against the OWNER's knock
    prompt: the victim-selection heuristic is "is `#admit` visible", and `#admit`
    is now shared by both prompts. Third instance of the false-green class the
    README itself catalogues. **Fix:** correct the README, and make the check
    assert the panel is in PEER mode (title/button label) rather than un-hidden.
    Same conflation in `approvePeerKey` in `e2e/all-modes.mjs:42` and
    `e2e/room-admission.mjs:34`, which assert only "not hidden" and then click OK.

**LOW / INFO**

21. **✅ FIXED 2026-08-10 with item 14** — a set-but-mismatched
    `expectedPeerBundle` now returns null and prompts, never falls through.
    Covered by `client/peer-approval.test.mjs`. Original finding:
    `peerAlreadyTrusted` route (b) fires even when `expectedPeerBundle` is set and
    does NOT match, so a 🟢 contact who is not the contact you selected skips the
    prompt (`app.js:2140-2150`). `describeIdentity` computes exactly the right
    verdict for this case and the gate never consults it. Reproduced 5/5; the
    backstop held (`enterVerification` fires the directory-mismatch screen and
    messaging never unlocks), which is why it is not High. Fix with item 14: if
    `expectedPeerBundle` is set and does not match, prompt — never fall through.
22. `reg_seq` check-then-update is not atomic (`backend/accounts.py:600-629`): no
    `_store_lock`, no `BEGIN IMMEDIATE`, so two concurrent registrations both read
    the old counter and both pass the gate (reproduced: both 200 in 2/10 rounds).
    A completed rollback was NOT demonstrated — write ordering saved it, not the
    check. Fix: `UPDATE … WHERE username = ? AND reg_seq < ?`, 0 rows = rejection.
23. OTP derived floor ids share the padId namespace and `importPad` never
    validates `padId` (`otp.js:123-125`, `:463`), so a crafted pad file named
    `<padId>#exported` bricks the real pad. **DoS only** — every floor is monotone
    and every consumer compares with `<`, so a collision can only RAISE a floor;
    no collision produces keystream reuse. Fix: validate `^[0-9a-f]{32}$`, or use
    a separator that cannot appear in a padId.
24. Assorted. **Two of these are ✅ FIXED 2026-08-10 with item 14:** the
    `auth.js:110`/`app.js:191` citations of the deleted
    `e2e/hostile-relay/forge.mjs` now name `SCENARIO=attacker node
    e2e/hostile-relay/proto001.mjs`, so the branch's most load-bearing claim is
    reproducible from the tree again and `peer-approval.test.mjs` would catch the
    forgery route's reintroduction; and `peerAlreadyTrusted` now compares decoded
    bytes via `sameSigning` rather than base64 strings. **Still open:**
    `setVouches(…, expected = null)` defaults to the pre-fix unbound
    write (`contacts.js:640`, single caller does pass it — make it required);
    `wipe()` leaves the anchor set with no `markUnestablished()`, unreachable
    today but a trap for a future restore flow (relates to item 6);
    `auth.js:110`/`app.js:191` cite `e2e/hostile-relay/forge.mjs`, which was
    merged into `proto001.mjs` and no longer exists — so the branch's most
    load-bearing claim is unreproducible from the tree and nothing would catch
    the forgery's reintroduction; a dead `showNextKnock()` call whose comment
    asserts a state `roomRole`'s write-once rule makes impossible
    (`app.js:2678`); the `approvalPending` guard sits BEFORE `++knockRenderGen`
    (`app.js:2040`), leaving a latent "approve a fingerprint you were not shown"
    window that is currently unreachable ONLY because of the relay-frame-reading
    check at `app.js:2635` — which is exactly the kind of check this project has
    removed on review before; and `peerAlreadyTrusted` compares two keys with
    string `===` where everything else compares four keys as decoded bytes
    (fails safe, but the log line then asserts something about key material the
    user did not verify).

#### A3. Test-coverage gaps the 2026-08-08 pentest confirmed

25. **Both PROGRESS item 9 suspicions are CONFIRMED, and one fixture has already
    drifted.** `rsa-keyvalidation.test.mjs` asserts only `instanceof Error`, and
    the `e=0` case now fails with `malformed RSA key parameter` from
    `b64UrlToBigInt` (Node normalises the exported JWK `e` to an empty string) —
    it never reaches the exponent check it exists to pin. Assert the message.
    `otp-padgen.test.mjs` never takes the partial-tail branch: all three
    `PAD_SIZES` and the drawn-entropy case are exact multiples of 65536, while
    `generatePad` accepts any even `totalBytes >= 128`. Add e.g. 100000.
26. **All three backend findings are invisible to the 154-test suite**, because
    every test drives `TestClient` serially. Concurrency needs real threads.
27. `chats-rollback.test.mjs`'s concurrency test only covers the interleaving the
    CAS DOES catch (tab B completes before tab A writes), never the both-read-
    first one that still loses data. No test deletes a derived native floor slot
    (item 13). No test covers the pin sweep across a key change (item 17).
    `app.js` has no unit-test surface at all — `approvedBundle` /
    `peerAlreadyTrusted` / `requestPeerApproval` appear in no test file, and
    `peerAlreadyTrusted` is a small pure-ish function that could be exported and
    tested directly (items 14 and 21 are each a one-line unit test against it).
28. **Good news, verified rather than assumed:** the new test files are NOT
    vacuous — `rsa-keyvalidation`, `otp-padgen`, `otp-rollback`, `contacts-anchor`
    and `chats-rollback` were all run against `master`'s sources and all fail
    there, as did the F-ATREST-007 and F-PROTO-005 blocks in isolation.

#### A4. Attacked and held (do not re-litigate without new information)

The full 12-way cross-store blob-swap matrix (0 of 12 opened a wrong or empty
store; every discriminator is the tag INSIDE the AEAD, never the outer `v` byte).
The chats legacy-adoption path cannot launder another module's plaintext.
F-ATREST-004(b) is genuinely dead (`isPinMap` tests shape, not the key name).
`PadFloor`'s "MACs key and value together" framing claim is correct — the last
NUL is an unambiguous separator, so derived ids really are separate authenticated
slots and a floor cannot be lifted from one to another. `assertRsaPublicKeyUsable`
runs BEFORE `this.peerPub` is assigned, and every fixture but `e=0` hits its
intended branch. `fillRandom` chunking is correct (`subarray` is a view).
F-RELAY-005: the counter is inside the signed bytes under its own domain, a v3
cannot be downgraded to the counter-less path, v1/v2 replays against a keyed
account are refused, and the migration boundary is safe. F-RELAY-006 requires
both signatures on every success path with no cross-scheme replay, and the login
existence oracle stays closed (21.3 ms vs 20.5 ms median). F-RELAY-004's mailbox
charge ordering is correct. M-7's vouch oracle was not reopened. And the core of
the 2026-08-08 rewrite: the original F-PROTO-001 attack is refused on BOTH
endpoints (8/8 in both scenarios), `approvedBundle` has exactly five writers and
no relay frame reaches any of them except via items 14/21, no path reaches key
derivation with it null or mismatched, and the parked message pump is sound (the
F-PROTO-002 gate is correctly re-checked after the await, no stale resolve
crosses connections, FIFO order holds, and no path leaves the promise unsettled
while the socket is open).

#### B. Decisions for the user — each changes what gets built

4. **F-CRYPTO-009 residual (RSA).** A counterparty using `e=65537` with
   `n = <small factor> × <large prime>` still hands the session to a passive
   observer; partial validation cannot catch it, and raising the trial-division
   bound does not help. Either make the root contributory (needs a THIRD
   handshake frame, breaking app.js's "answer the initiator exactly once"
   invariant) or deprecate peer-chosen RSA key transport in favour of
   DHKE/PQKEM. Documented at `assertRsaPublicKeyUsable` in crypto.js.
5. **Lock-on-background (F-ANDROID-003).** `FLAG_SECURE` closes the filed
   recents-snapshot leak. Lock-on-background is a different threat (device seized
   while backgrounded and unlocked) and would re-prompt for the passphrase on
   every app switch. Needs a new hook in the web client — the native shell does
   not own lock state.
6. **Anchor vs. a future identity-restore flow.** Unreachable today
   (`Identity.import` only ever reads the localStorage blob; export is
   clipboard-only). If a restore flow is added, a backup carrying
   `contactsEstablished` restored onto a store-less device is a lockout.
   Device-scoping the flag does NOT work — a device id in localStorage is
   deletable, which reopens the original hole. Design it WITH the restore
   feature, not before.
7. **Merge / deploy plan for the two contract changes.** `register/v3` and
   dual-scheme `/auth/verify` both refuse older clients. Decide whether the relay
   and clients ship together (they are served from the same origin, so normally
   yes) and whether existing accounts need a one-time re-registration to adopt
   `reg_seq` — pre-v3 rows start at 0, so one v3 registration adopts the control.

#### C. Work the review identified but this branch did not do

8. **F-ATREST-008 — the identity blob has no anti-rollback control.** Still
   `candidate`/low in the report, but the F-ATREST-003/004 fix is now
   LOAD-BEARING on it: the anchor is defeated by rolling the identity blob back
   rather than deleting it, and every pre-fix blob has no `flags` field, so
   today's blob on every device is the archived artifact. Fixing this is what
   would make the anchor argument actually hold.
9. **Close the test-coverage gaps.** No regression test at all for F-PROTO-001,
   F-PROTO-002, F-CRYPTO-014 or F-ANDROID-003. `otp-padgen.test.mjs` never
   exercises the partial-tail branch (all three `PAD_SIZES` are exact multiples
   of 65536 — add e.g. 100000). `rsa-keyvalidation.test.mjs` asserts only
   `instanceof Error`, so a fixture could drift onto a different branch and still
   pass green; assert the message. A cheap source-level test that `FLAG_SECURE`
   appears before `setContentView` would at least catch deletion.
10. **Verify `FLAG_SECURE` on real hardware, and check the AlertDialog.**
    Never compiled here — `./gradlew compileDebugKotlin` fails with `25.0.3-ea`
    (JDK 25 vs this Gradle/AGP), confirmed identical on unmodified master, so it
    is pre-existing. Open question from the review: the JS `prompt` handler
    builds an `AlertDialog` with a password field, which is a separate `Window`
    and may need its own `FLAG_SECURE` on some API levels.
11. **Get the pentest workspace under version control, or reference it.** The
    committed report cross-references `state/findings/F-*.md` and
    `state/coverage/<lane>.md` with no hint that they live in a sibling directory
    outside the repo. Also `state/verified-sound.md` is an empty stub — the
    cross-lane "attacked and held" digest exists only inside §5 of the report.

#### D. Environment traps that cost time this session

12. **`backend/run.sh` cannot run the relay for e2e.** It uses the system python
    and dies on `ModuleNotFoundError: dilithium_py`. Use the venv:
    ```bash
    cd backend && SECURE_CHAT_DB=/tmp/e2e.db .venv/bin/python -m uvicorn main:app \
      --host 127.0.0.1 --port 8000 --no-server-header --no-proxy-headers \
      --no-access-log --log-level warning --ws-max-size 66560 &
    ```
    Worth fixing `run.sh` itself to prefer `.venv/bin/python`.

#### Fixed on the branch, each with a regression test

- **✅ F-ATREST-003 / F-ATREST-004** (the two CONFIRMED findings) — the "a store
  was established here" bit moved out of two deletable localStorage keys into
  the identity AEAD (`deviceFlags`), `looksLikeStore` now checks pin-map SHAPE
  rather than the key name `pins`, and `pinsReadable()` no longer returns true
  while the store is locked. **Honest limit: see item 8.**
- **✅ F-ATREST-005 / F-CRYPTO-006** — chat store gets the domain tag, generation
  counter, witness and L-3 CAS that contacts.js already had.
- **✅ F-ATREST-001 / F-ATREST-002** — the native floor covered the SEND offset
  only. The recv watermark and the `exported` latch now get their own slots via
  derived ids (`<padId>#recv`, `<padId>#exported`). No Kotlin change: PadFloor
  MACs key and value together, so each derived id is a separate authenticated
  slot.
- **✅ F-ATREST-007** — revocation sweeps every pin whose bundle matches the
  contact, not just `user:<name>` (live-room peers are pinned under `room:<id>`,
  usually the only pin there is).
- **✅ F-PROTO-002** — `handleMessage` drops frames queued behind a refusal.
  NOTE: the review could not reproduce the original finding in Chromium at all —
  the browser's own readyState gate already drops the burst — so this is
  defence-in-depth and the finding's severity rested on shim behaviour.
- **✅ F-PROTO-005** — the vouch mark is bound to the bundle its signatures were
  verified against.
- **✅ F-RELAY-001** — `config.py` no longer recommends
  `TRUSTED_PROXIES=127.0.0.1`; Tor and Caddy share `127.0.0.1:8000`, so trusting
  the IP trusts a raw TCP forward that appends nothing.
- **✅ F-RELAY-003 / F-RELAY-004** — tight buckets keyed on username / recipient
  with a larger per-host backstop; the mailbox charge moved past the token gate.
- **✅ F-RELAY-005** — `register/v3` with a signed monotone counter.
- **✅ F-RELAY-006** — `/auth/verify` requires both signature schemes.
- **✅ F-ANDROID-003** — `FLAG_SECURE` (uncompiled — see item 10).
- **✅ F-CRYPTO-009 / -012 / -014** — RSA peer-key validation (residual: item 4);
  `randomPad` chunked past the 64 KiB `getRandomValues` cap, which had made 2 of
  3 advertised pad sizes ungeneratable; the OTP localStorage lease deleted in
  favour of failing closed when Web Locks is absent.

#### Fixed during the fix review (regressions this branch introduced)

- **F1** — the first F-PROTO-001 fix inferred ownership from "we minted this room
  code": empty after a reload, never true for a pasted code. Rebuilt around a
  signed admission proof.
- **F2** — the same fix fired on an HONEST relay (ownership goes to whoever joins
  first, not whoever minted the code) and the disconnect was silent, because
  `clearHints()` wipes the message and the log line sits in the hidden chat pane.
- **F3** — `chats.js persist()` lacked the L-3 CAS: silent lost update, plus one
  interleaving that left store gen < witness gen = permanent lockout.
- **F4** — the anchor comments claimed a property the code does not have;
  withdrawn rather than papered over.
- **F5** — revocation missed `room:<id>` pins, and the new test asserted the
  residual was correct.

### ✅ CLOSED — the 2026-07-29 pentest, all 13 items (fixed 2026-07-30)
Every finding in `docs/pentests/secure-chat-pentest-2026-07-29.md` is fixed on branch
`pentest-2026-07-29-fixes`. Backend **143 passed**, client **109 checks / 11
suites**, `e2e/all-modes.mjs` **32/32 on 5 consecutive runs** (it used to fail 2
in 5 — root-caused, below). **DEPLOYED 2026-07-30** — see DELIVERY at the end.

Each fix carries a test that FAILS against the pre-fix code — verified by
stashing the fix and re-running, not by assertion. Where that was not possible,
it says so.

1. **✅ M-1 — `client_key()` gives exactly one bucket per peer.** `X-Forwarded-For`
   is ignored outright when no trusted proxy is configured. The forgeable
   `peer in hops` detector is deleted; rewrite detection moved to the PORT
   (uvicorn builds `(host, 0)` from a bare-IP hop; a real TCP peer never has
   source port 0), which the client cannot set — no false positives, so **L-9
   closes with it**. The detector is documented as a diagnostic, not the control.
   Tests: the exact line the report said would have caught it
   (`peer=127.0.0.1, XFF=127.0.0.1`), a one-key-per-peer sweep over 9 header
   shapes, an end-to-end limiter test **through a TestClient bound to
   127.0.0.1** — the module-level client reports `"testclient"`, which is in no
   attacker's header, so the original topology could not reproduce M-1 at all —
   and both directions of the L-9 forgeability property.
2. **✅ H-1 — the native pad floor cannot be cleared or detected away.**
   `PadFloorBridge.clear` is gone (nothing called it), and `PadFloor.kt`'s
   contract no longer claims two things that were false. The app injects
   `__SECURE_CHAT_NATIVE_FLOOR__` at document-start as a **non-configurable**
   property — that is the load-bearing part: `delete window.SecureChatPadFloor`
   still removes the bridge, but `delete` cannot remove the marker, so
   "marker present, bridge missing" is now provable tampering and fails closed
   instead of reading as a plain browser. `verifyRelayConfig` additionally
   refuses to run if the page cannot call the bridge.
   Also closed, and NOT in the report: floor **deletion** was still silent, since
   an absent floor contributes 0 to the rollback comparison. A `nativeFloor`
   flag now lives inside the pad's AEAD, so a blob written while a floor existed
   is refused if the floor is later gone. Tests include the full
   snapshot-restore-then-clear PoC (which silently reopened the pad before, and
   is now refused), and a plain-browser case so the fix cannot become
   "fail closed everywhere".
3. **✅ H-2 — the witness can no longer be opened as the store.** The store
   plaintext carries `d: "secure-chat/contacts-store/v4"` and `unlock()` requires
   it. Pre-v4 blobs have no tag and are adopted, then re-persisted tagged.
   The adoption decision keys on the **tag inside the AEAD, never the outer `v`
   byte** — `v` is attacker-writable and the witness blob has none, so
   `(blob.v || 1) < 4` would have read the witness as legacy and adopted it,
   reopening the hole. That is the same trap the outer `v` byte set for OTP.
4. **⚠️ H-3 — fixed on ANDROID ONLY; the browser residual stands.**
   `padWasUsed()` consults the native floor first and treats TAMPERED as used;
   `saveNewPad` refuses a padId that was ever used here and seeds the watermark
   cache from the surviving floors rather than from zero, so it cannot erase the
   record even if the refusal were bypassed. `app.js`'s `otpFileChosen` still
   skips `unlockPad` **deliberately** — the guard now lives inside the two
   functions it calls, i.e. on the path rather than beside it, for no extra
   600k-iteration KDF.
   **Corrected 2026-07-30 (fix review H-B).** This entry originally read
   "✅ … Reproduced end to end: post-fix it is refused", with no platform
   qualifier. That is false for the WEB CLIENT, which is the primary one: with
   no floor, `nativeFloor` is null and `padWasUsed` still reads only the three
   deletable plaintext keys, so the original PoC — three `removeItem`s, then
   re-import — still rebuilds the pad at offset 0. Re-verified 2026-07-30.
   Closing it in a browser is not possible with deletable storage; the honest
   options are trusted monotonic storage (which is what `PadFloor` is) or
   nothing. **This is exactly the failure mode M-1 was about** — a status line
   claiming a property the measurement did not cover — so it is corrected here
   rather than quietly rewritten, and the test's summary line is now scoped to
   the platform it actually proves.
5. **✅ M-4 — the false premise is corrected where it was written.**
   `network_security_config.xml` no longer claims `.onion` is potentially
   trustworthy; it carries the measured table, the reason
   `cleartextTrafficPermitted` cannot help (it sits below Chromium's
   mixed-content blocker), and an explicit **DO NOT** for the obvious workaround,
   naming why a WebView document origin on the onion is a Critical regression
   twice over. The two workable shapes (loopback Orbot proxy, TLS over the
   onion) are recorded. The `onion` allow-list entry is kept and the comment
   says why it is inert. **No code change is possible here — this finding is a
   plan correction, and the Android-over-Tor work remains unbuilt.**
6. **✅ M-2 — corrected, and the applicable knob is set.** `deploy/README.md`'s
   three wrong claims are corrected in place (it is login for all accounts, not
   onboarding; only `REGISTER_RATE_*` was ever resized; PoW prices introduction,
   not requests). `torrc.secure-chat` gains `HiddenServiceMaxStreams 24` +
   `HiddenServiceMaxStreamsCloseCircuit 1`, validated with `tor --verify-config`.
   Stated plainly in both places: this raises the price, it does not remove the
   DoS, and that remains **accepted**.
7. **✅ M-3 — the harness now has a positive control.** `wsConnect` distinguishes
   "closed before any HTTP status" (`transportFailed`) from a real refusal, and
   the CSWSH check requires all of: the foreign attempt was actually answered,
   it was refused, AND an allowed Origin upgraded in the same run. Verified
   against all five scenarios: it now rejects the Tor-hiccup case that used to
   pass green at `HTTP 0`, and the connection-cap case that a bare
   `code === 403` would also have accepted. **Not re-run over real Tor** — that
   needs the deploy box, so this is verified at the predicate, not end to end.
8. **✅ M-5 — chains are frozen once confirmed, and the race works again.**
   Both halves, which pull in opposite directions:
   the **attack** (a withheld offer delivered after confirmation silently
   rebuilds the chains) is now a loud refusal, gated both in `case "key"` before
   the cipher is touched and in `onChannelReady` after; the **race** (each side
   derives twice in a simultaneous connect, so the first tag is stale) works
   because the peer's tags are kept in a **capped set** — matching any of them
   proves the peer derived our current material, in any arrival order.
   The cap (2, the maximum a legitimate peer can produce) preserves what
   first-write-wins was protecting: the confirm frame is not signature-covered,
   so an uncapped set would be a guessing oracle. A mismatch is no longer
   instantly fatal, so loudness comes from a deadline — which also fixes a case
   the ORIGINAL code hung on forever: a relay that never delivers the confirm
   frame at all.
   The state machine moved to `client/keyconfirm.js` so it can be tested without
   a DOM. That is the point: the report could only model this "line for line" in
   a scratch harness because it lived inline in `app.js`. Ten tests now run
   against the shipped code, and the pre-fix semantics were transcribed and run
   against them to prove they discriminate — the old code fails the attack test
   AND disconnects both honest peers in the race.
9. **✅ M-6 — directory answers go through the canonical gate.**
   `account.fetchBundle` re-spells every key through `b64(unb64(...))`, which
   throws on a non-canonical spelling, so a hostile directory can no longer
   return the same bytes in a different spelling to strip 🟢 and vouches,
   permanently break sealed messaging, or burn the auto-contact budget. Applied
   at the fetch boundary rather than at each consumer.
10. **✅ M-7 — `/api/vouch` is no longer an existence oracle.** The target-existence
    answer is folded into the signature verdict (a random, correctly-sized decoy
    bundle keeps the work and the timing identical), so an absent target and a
    bad signature are byte-identical `400`s. The route also joins
    `lookup_rate_limit`, the same anti-enumeration bucket as `GET /users/{u}`,
    with a test that draining it via `/vouch` throttles `/users` — proving it is
    the same bucket and not merely some limiter. `test_vouches.py:153`, which
    **pinned the oracle in place** with `== 404`, is inverted.
11. **✅ Low/Info.** L-1 knock queue capped at 8, dropping the EXCESS rather than
    the oldest — evicting the oldest would let a flood push a genuine contact's
    knock off the list, turning a nuisance into targeted denial of admission;
    the cap sits before the two signature verifies, so a flood costs a regex.
    L-3 lost updates are now a loud refusal via a compare-and-swap on the witness
    (tested with two real module instances over one localStorage — that is what
    two tabs are). L-4 gains `POST /api/auth/logout` **and** re-login retiring the
    account's previous sessions; logout is deliberately not behind `current_user`,
    or it would be a token-validity oracle needing no signature. L-5 `OtpPad`
    validates its offsets (`| 0` was also turning NaN into 0). L-7 is written
    down in `torrc.secure-chat` as accepted rather than claimed away, with
    `AvoidDiskWrites 1`. L-8 the relay's source is no longer writable
    (`StateDirectory` + `SECURE_CHAT_DB` under `/var/lib`, `ReadWritePaths`
    dropped; **needs the one-off DB move in the unit's comment before restart**).
    L-9 closed by item 1. L-10 the install recipe is idempotent.
    **L-2 is unchanged and remains accepted** — deleting both contact keys still
    yields an empty store; it is the documented whole-storage residual, and the
    honest fix is trusted monotonic storage, not another key.
12. **✅ Test-coverage gaps 1-8, plus the two vacuous tests.**
    `pqkemReplayDoesNotDesync` was vacuous — it replayed AFTER `encrypt()` sealed
    the cipher, so `onPeerKey` returned early and the assertion could never
    observe `_derive`; it now replays pre-seal, where the live path is, and the
    post-seal case is kept and labelled as the different mechanism it is.
    `otp-rollback.test.mjs`'s bridge mock hid both halves of H-1 — no `clear`, so
    the attack could not be expressed, and a final `delete globalThis.SecureChatPadFloor`
    that treated bridge-absence as a clean browser, which IS the downgrade.
    New: `test_service_unit.py` (the production launcher, previously untested),
    `no-fallback.test.mjs` (gap 7 — nothing asserted `crypto.subtle` is required,
    so the best result in the report was one compatibility commit from silently
    inverting), `keyconfirm.test.mjs`, and regression tests for the
    witness→store swap, delete-then-reimport, negative `OtpPad` offsets, and
    the vouch oracle.
    **Not covered, stated plainly:** the L-1 knock flood has no regression test —
    it lives in `app.js`'s relay-message path, which still has no unit tests at
    all (gap 8), and the queue cap is exercised by nothing but review. That is
    the same structural gap that made M-5 untestable until `keyconfirm.js` was
    split out; the admission paths deserve the same treatment.
13. **✅ E2E — the flake is root-caused and fixed, and the harness cannot lie.**
    The cause was a **substring bug in the test, not a race in the app**: the
    harness waited for `/connected/i`, which also matches **"disconnected"** —
    the status left over from the previous mode's teardown. From the second mode
    onward that wait returned instantly, before alice had actually joined, so bob
    could reach the empty room first and become its OWNER; he then never entered
    the approval queue and his "waiting for approval" wait timed out 45 s later.
    That is exactly the reported signature (2 in 5, always bob's approval wait,
    always a later mode). Anchored to an exact match, and the same latent bug
    fixed in `room-admission.mjs`. **5 consecutive runs, 32/32 each.**
    Separately, `SECURE_CHAT_E2E_CHROME_ARGS` now TAINTS the run when it disables
    a security gate: the flags are named up front, the summary never prints a
    bare "all modes good", and the exit code is non-zero unless
    `SECURE_CHAT_E2E_ACK_UNSAFE=1`. A green run in a configuration no user can
    reproduce is worse than a red one, because it gets quoted.

### 🔧 FIX REVIEW of the above (2026-07-30) — 6 findings, all fixed
The `pentest-new-code` agent was run against the fix commit `23bc905`, on the
principle that a fix is new code and the most dangerous kind. It found six
things, **three of them regressions the fixes themselves introduced**. All are
fixed; the review's other verdicts (M-5, H-2, M-6, M-7, L-3, L-5 and the launch
paths) held under independent attack.

- **H-A (High) — the H-1 floor was defeated by SUBSTITUTING the bridge, not
  deleting it.** I hardened the marker and left the lookup alone: `otp.js` found
  the bridge by its ordinary global name and accepted anything with `read`/`bump`
  functions, so an attacker could install a lookalike answering "no floor", or
  just overwrite the two METHODS on the real object — two assignments, no
  `delete`, and it survives making the global itself non-writable. Every new
  check passed, `verifyRelayConfig`'s probe answered true, and the real Keystore
  floor was never consulted: full keystream reuse, F-1 void again. Reproduced.
  **Fixed:** the app captures the interface at document-start, before any page
  script, and republishes it **frozen** under a non-configurable
  `__SECURE_CHAT_PAD_FLOOR__` with `.bind()`-captured methods; `otp.js` reads
  only that name and a test asserts it never touches the writable global. The
  lesson: I keyed the check on SHAPE where it needed to be PROVENANCE.
- **H-B (High, reporting) — my own H-3 claim was false for the web client.**
  Corrected in item 4 above, in the commit trail, and in the test's summary line.
- **M-A (Medium) — my L-1 knock cap made things WORSE than no cap.** Nothing
  pruned the owner's queue when a waiter left (the relay pops `pending` and tells
  nobody), and a knocker whose entry is dropped can never retry, because the
  client knocks exactly once and the relay refuses a second knock per socket. So
  eight cheap connect/knock/disconnect cycles filled the queue with immortal
  ghosts and the invited peer waited forever, unseen — a permanent silent denial
  of admission, and a direct hit on the P-08 property the cap was protecting. My
  own comment claimed a dropped knocker "simply has to knock again"; it cannot.
  **Fixed:** the relay now sends `withdrawn` (join id only — no identity, nothing
  new at rest) and the owner's client prunes; the cap is raised above
  `MAX_ROOM_PENDING` and demoted to a backstop for relays that do not send it.
  Four relay tests, including the flood shape.
- **M-B (Medium) — my M-1 fix deleted H-4's fail-closed collapse.** Removing the
  forgeable detector was right; removing the SAFE COLLAPSE it drove was not,
  because in the H-4 condition `peer` is attacker-chosen, so returning it hands
  out a private bucket per forged header with one log line as the only trace.
  **Fixed:** warn *and* collapse. Port 0 has no remote false positives, which is
  what makes it safe to act on and not merely log — and the suite now asserts
  the BUCKET under a misconfiguration, which it never did.
- **M-C (Medium) — my L-4 fix was a self-inflicted DoS.** One-session-per-account
  plus `pollMailbox`'s 6 s "401 → re-login" made two tabs of the same account
  revoke each other forever: ~0.33 challenges/s against a 0.5/s bucket that,
  since M-1, is GLOBAL to the relay. Two of a user's own tabs ate most of the
  relay's login capacity; three denied login to everyone. Both tabs then sat
  permanently offline for sealed mail with no visible sign — the exact failure
  the 401 handler exists to prevent. **Fixed:** `MAX_SESSIONS_PER_ACCOUNT = 5`
  with oldest-evicted, re-login no longer revokes, failed re-login backs off and
  says so, and revocation is `POST /api/auth/logout` — which is now **wired into
  the profile view** (L-B: it had no caller at all, so the only revocation a user
  could trigger was the one that caused this).
- **L-A (Low) — the fail-closed messages blamed the pad.** "Damaged or forged",
  "already been used", and each recommending a fresh pad exchange, when the real
  cause is the app cannot reach its own floor — so a user burns real pads chasing
  it. Now a distinct message that says so and says *not* to exchange.

(The taint gate and `fetchBundle` length-checking were done in the same commit;
`HiddenServiceMaxStreams 24` remains the value most likely to need revisiting on
the box, and is untestable here without a Tor daemon.)

### 🔧 FIX REVIEW, ROUND 2 (2026-07-30) — 1 High + 5 Low, all fixed
The agent was run again against the fix-review commit `b471cbf`, because those
fixes were themselves written under the assumption that they closed something.
Five of six claims held. One did not, and it is the more instructive failure:

- **H-1 (High) — I hardened the bridge and left every VALUE it produces flowing
  through mutable globals.** `otp.js` parsed the floor with `parseInt` guarded by
  `Number.isFinite`, and the rollback verdict was a single `Math.max` over the
  four floors. So `globalThis.parseInt = () => 0` — one assignment, never naming
  the bridge, no `delete`, no `defineProperty` — made every floor read as zero
  while the frozen bridge, the non-configurable marker and `verifyRelayConfig`'s
  probe all stayed intact. `Math.max = ...` was worse: it overruled the native
  floor, the authenticated watermark, `inner.hwSend` and the legacy watermark in
  one go, **in a plain browser too**. Reproduced: pad reopened at offset 0 with
  the hardware floor still reading 3000.
  **Fixed:** the bridge returns a **number** now (`PadFloorBridge` returns
  `Long`), so there is no parse step to poison; validation uses only `typeof` and
  bitwise ops, which have no global behind them; and every rollback `Math.max` is
  a local `maxOf` built from comparisons. Note capturing primordials at module
  top would NOT have worked — a document-start attacker runs first.
  **The lesson, and it is the same one twice:** in round 1 I keyed the check on
  shape where it needed provenance; here I secured the source of a value and left
  the path it travels. Both times the fix was correct about the PoC and wrong
  about the boundary.
- **M-1 (Medium) — the M-C backoff was dead code.** `pollMailbox` returned at its
  first line when `apiToken` was null, and the 401 branch was the only thing that
  ever called `autoLogin`. So one failed re-login was terminal: no retry, the
  12/24/48/96/120 s ladder unreachable, and the tab permanently offline for
  sealed mail — precisely the state M-C was written to remove, reached by a
  different road. **Fixed:** `pollMailbox` re-authenticates from the top, which
  is what makes the backoff load-bearing rather than decorative.
- **L-1 — `withdrawn` was sent for waiters that never knocked**, which prunes
  nothing (the owner's queue only holds knocked waiters) and is exactly the
  unbatched per-join-attempt frame `note_turned_away` avoids on purpose. Gated on
  `conn.knocked`; the test that asserted the old behaviour is inverted.
- **L-2 — `showNextKnock` is not re-entrant**, and `withdrawn` gave it a second
  concurrent trigger that `msgChain` does not serialise against clicks. Fixed
  with a render generation counter plus a queue-head re-read after the await.
- **L-3 — `forgetIdentity` never revoked the directory session**, leaving a live
  bearer for up to an hour after the control a user reaches for when handing the
  device on. It now calls the `logout` this work introduced.
- **L-4 — the "you are offline" messages went to the chat transcript**, a screen
  the user is usually not on — the same "only if you happen to look" complaint
  M-C was about. Routed to the active screen's hint, and the sign-out message now
  says where to sign back in.

Verified sound across both rounds and not re-broken: M-5/`keyconfirm.js` (byte
identical, re-attacked), H-2/`contacts.js` (byte identical, confirmed the
re-applied version locks before throwing), M-B's port-0 branch (unreachable from
any header), M-C's eviction arithmetic (cannot over-evict; an attacker cannot
force-evict, since the signature is checked before the eviction block), and the
M-A relay path (every way a knocked waiter can leave emits exactly one notice).

**One residual the review could not close and neither could I:** M-B's claim rests
on "a connected TCP socket cannot have source port 0". Neither of us had
`CAP_NET_RAW` to test whether a crafted SYN can surface `sin_port == 0` from
`accept()`. If it can, that branch becomes reachable and is an M-1-shaped second
bucket. The docstring says so rather than claiming "no false positives" flatly.

### 🔧 MERGE REVIEW (2026-07-30) — 1 finding fixed, 1 flagged
Delivery item 1 ("review the diff and merge") read as a real review, not a
formality. The full local gate was re-run first and everything the previous
sessions claimed reproduced: backend **152 passed** (151 before the fix below),
client **112 checks / 10 suites**, the three integration suites green against a
live local relay, and e2e `all-modes` **32/32**, `room-admission` 13/13,
`no-dead-ends` 12/12, `two-user-flow` 8/8.

- **✅ The L-8 fix made the account database world-readable.** Moving the DB out
  of the code tree was right; the mode was never checked. `StateDirectory=` alone
  leaves systemd's **0755 default**, which it re-applies on every start, so
  `/var/lib/secure-chat` would be world-traversable with a 0644 `accounts.db`
  inside it — publishing the directory's lookup TOKENS (the secret half of
  `username#token`, and the entire anti-enumeration control that makes a bare
  username reveal nothing) and the sealed mailbox ciphertext to any local user on
  the box. The unit's own comment asserted "systemd creates it 0700"; it does
  not, and `man systemd.exec` says 0755 in as many words. The migration recipe
  three lines above said 0750, which systemd would have silently overridden — the
  two disagreed and neither was right.
  **Fixed:** `StateDirectoryMode=0700`, the recipe corrected to match, and the
  false claim replaced with why the line is not optional. `test_service_unit.py`
  gains a case that **fails against the pre-fix unit** (verified by reverting the
  file and re-running, not by assertion) and that also holds the comment's recipe
  to the enforced mode, since a divergence there is how this happened.
  Worth noting what class of bug this is: L-8 was verified as "the code tree is
  no longer writable", which was true, and the property that broke was one nobody
  had written down. Same shape as M-1 — a status line the measurement did not
  cover — one layer down.
- **✅ FIXED (in the APK-rebuild step): `PadFloor.kt` was invisible to `git diff`.** It contained
  raw NUL bytes in the HMAC domain separator at line 98
  (`"secure-chat/otp-pad-floor/v1\0$padId\0$value"`, written as literal U+0000 in
  the source rather than `\u0000`), so git classifies it as binary and every diff
  of it renders as `Bin 7111 -> 9149 bytes`. `file` calls it `data`. This is
  **pre-existing on master, not introduced by this branch** — but it means the
  H-1 changes to the one file whose whole job is to be the control the JS context
  cannot reach went to review as an opaque blob. `git diff --text` was used here
  instead and the content is correct.
  **Fixed at the APK rebuild, where a compile could confirm it:** the separator
  is spelled `\u0000` and the file is `UTF-8 text` again, so it diffs normally
  from here on. Byte-identity was not assumed, it was checked in the built
  artifact: `classes3.dex` carries the constant as `secure-chat/otp-pad-floor/v1`
  followed by `c0 80`, which is DEX's MUTF-8 encoding of U+0000. The string the
  HMAC is taken over is therefore unchanged, so every floor already stored on the
  phone still verifies. Worth stating the failure mode had it differed: every
  existing floor would have failed its MAC and read as TAMPERED, which fails
  CLOSED (OTP bricked on the device) rather than open — but that is a reason
  to check, not a reason to assume.

### ✅ DELIVERY — DONE 2026-07-30, all five items, verified not assumed
Merged `--no-ff` as `2918986`, pushed with the branch. Then, in order:

1. **✅ Reviewed + merged.** The review was not a formality — it found the
   world-readable state directory above. Full local gate first: backend **152
   passed**, client **112 checks / 10 suites**, the three integration suites
   green against a live local relay, e2e `all-modes` **32/32**, `room-admission`
   13/13, `no-dead-ends` 12/12, `two-user-flow` 8/8.
2. **✅ Relay + client DEPLOYED**, via `deploy/deploy-2026-07-30.sh` (committed —
   the usual two-line rsync recipe cannot express this release, because the DB
   move is order-dependent and the unit is not covered by the rsync).
   Backup at `/root/accounts.db.bak-2026-07-30-1822`. **The migration worked:
   30 accounts, 2 vouches and 4 mailbox rows survived**, counted through the
   read-only sqlite handle rather than inferred from the file size. `healthz`
   and `/` both 200 over loopback, clearnet 200, no database left in the code
   tree, `SECURE_CHAT_TRUSTED_PROXIES` still absent from the live process
   environment and `--no-proxy-headers` still on its command line.
   **`StateDirectoryMode=0700` was PROVED to be load-bearing, not decorative:**
   `chmod 0755` on the live directory, `systemctl restart`, and systemd put it
   back to `drwx------`. That is the claim the finding was about, so it was
   measured rather than asserted.
3. **✅ APK rebuilt + installed** on device `P21273004544`. Carries the
   `PadFloor.kt` escape fix, compile-verified byte-identical (above).
4. **✅ On-device native-floor proof re-run — 14/14 against the real
   AndroidKeyStore.** The harness is now **committed** at
   `android/native-floor-ondevice.mjs`; the 2026-07-28 one lived in a session
   scratchpad and was gone, which is how a proof of the one control the JS
   context cannot reach stops being re-runnable. It also asserted the OLD
   contract. Proved on hardware: the marker survives `delete` and redefinition;
   the interface is frozen and has **no `clear`**; an unknown pad reads `-1`;
   `bump(500)` → 500 and `bump(5)` → still 500 through the real HMAC; `read()`
   returns a **number**, so there is no parse step to poison; **H-A** —
   replacing `SecureChatPadFloor` wholesale, and overwriting the frozen object's
   own methods, both leave the floor reading 500; **round-2 H-1** — poisoning
   `parseInt` AND `Math.max` together does not move it. Those last two are the
   attacks the Node tests structurally cannot express, because a mock cannot be
   substituted or poisoned.
   *Residual:* the probe left an inert floor at `probe-native-floor-<ts>`. It
   cannot be cleared from JS — by design, no lowering call exists — and no real
   pad can carry that id. The phone still has **0** `sc.otp.*` keys.
5. **✅ `onion-ws.mjs` run over real Tor — 10/10**, against the newly deployed
   relay, through a local unprivileged `tor`. **Including the M-3 positive
   control**, which had only ever been verified at the predicate: an allowed
   Origin upgraded (HTTP 101) in the same run in which a foreign Origin was
   refused (403), so the refusal is now known to be a refusal and not a Tor
   hiccup at `HTTP 0`. Absent Origin still accepted, admission protocol intact
   over the onion (owner seats first, second peer queued not seated, knock
   verbatim, payloads unchanged both ways).

**Still open, deliberately:** the `torrc` change (`HiddenServiceMaxStreams 24`)
is NOT applied. The box's live tor config has never been diffed against the repo
copy, so applying it blind risks clobbering settings that exist only on the box.
The script prints the diff-then-reload recipe. This is a DoS price-raiser on an
accepted DoS, so it is not urgent.

**Previously (superseded by the block above): ⬜ DELIVERY — nothing here is
deployed.** All of the above is committed on a branch and verified locally only.
Still to do, in order:
  1. Review the diff (it touches crypto, at-rest storage, the relay and the
     admission path) and merge.
  2. Deploy the relay + client. **The systemd unit changed**: do the one-off DB
     move in its comment BEFORE the restart, or the relay starts with an empty
     database.
  3. Rebuild + install the APK. **H-1's marker is injected by the app**, so a
     client update WITHOUT an APK update leaves Android on the old feature
     detection — deploy them together, as with the 2026-07-28 release.
  4. Re-run the on-device native-floor proof: H-1 changed `PadFloor.kt` and the
     document-start injection, and the 2026-07-28 hardware proof no longer
     covers the shipped code.
  5. `deploy/onion-ws.mjs`'s new positive control has never run over real Tor.


### ⬜ OPEN from the 2026-07-27 pentest — SHIPPING, not fixing
Every finding in `docs/pentests/secure-chat-pentest-2026-07-27.md` is fixed and now merged to
`master` (see the snapshot at the top). What is left is entirely delivery — and
after item 2 was dropped, none of it protects a running instance:

1. ~~**Review + commit the tree.**~~ **DONE 2026-07-28.** Committed as
   `dc182d7` on branch `pentest-2026-07-27-fixes` (23 files, +2547/−98) and
   merged to `master` with `--no-ff` as `97c0754`; both pushed to `origin`. The
   branch is kept on GitHub so the change stays reachable as one review unit.
   Pre-commit: no DB files or secrets staged, backend 129 passed, client 84
   checks across 8 suites.
2. ~~**Restart the live relay** so H-4 actually applies to it.~~ **DROPPED
   2026-07-28 — this item was based on a wrong reading of H-4; do not re-add
   it.** Hetzner was never exposed: its `ExecStart` runs `-m uvicorn …
   --no-proxy-headers` with `SECURE_CHAT_TRUSTED_PROXIES=127.0.0.1` (live since
   the 2026-07-25 F-03 unit edit), verified against the running process. The
   `main.py` launcher this fix touches is not used in production, so a restart
   would have applied nothing; none was performed. Full detail in the corrected
   H-4 paragraph at the top of this file. **Nothing here protects a live
   instance — every remaining item below is next-release delivery.** The one
   genuinely undeployed piece (`accounts.client_key` rewrite detection) ships
   with item 3's normal deploy.
3. ~~**Deploy client + rebuild the APK TOGETHER.**~~ **DONE 2026-07-28** — see
   the snapshot at the top for backups, verification, and the restart/install
   ordering that kept the breaking two-client window to the restart itself.
4. **PARTLY DONE 2026-07-28.** ~~Contact store v3→v4~~ **CONFIRMED on-device**:
   unlocked on the phone, app opened normally, `sc.contacts.gen.v1` written next
   to a genuine pre-fix `sc.contacts.v1`. **⚠️ OTP pad v2→v3 STILL UNVERIFIED
   and untestable on this phone** — it has no pads at all (`grep sc.otp` over
   the leveldb returns 0), so that path had only run against in-memory
   localStorage. **Now tested on-device 2026-07-28 by injecting a genuine
   pre-fix v2 blob — and it is BROKEN: a USED pre-fix pad is permanently
   refused.** Root cause, proposed one-line fix, and why the unit tests missed
   it are in the 🔴 section of the snapshot at the top. **This is the top open
   item — it is shipped and live.**
5. **⬜ NEW from the `pentest-new-code` review of `bf6bcd2` (2026-07-28).** All
   pre-existing, none introduced by that fix — the review verified the fix never
   lowers a floor and that M-01/M-7/P-01/P-05 and the untrusted outer `v` byte
   all still hold. Tooling: PoCs under the session scratchpad `lab/`.
   - ~~**F-1 (High)**~~ / ~~**F-2 (Medium)**~~ **FIXED 2026-07-28, deployed.**
     Two layers, because they protect different platforms. **Browser:** adopting
     a pad with no verifiable usage record is no longer automatic —
     `unlockPad(..., {adoptLegacy:true})` is required, and `app.js` shows a
     confirm that names the danger ("this pad has no usage record on this
     device…"), escalated when `sc.otp.epoch.v1` or `usedKey` says this device
     has run OTP before. Those markers only ESCALATE; being deletable, they can
     never turn the gate off. The gate sits AFTER the rollback checks on purpose:
     adoption is consent to accept state that cannot be VERIFIED, never
     permission to override a rollback that has been DETECTED. **Android:** the
     send floor also lives in `android/…/PadFloor.kt` — app-private
     SharedPreferences under an AndroidKeyStore HMAC, monotone (no lowering call
     exists), keyed per padId so a floor cannot be replayed under another id, and
     bridged to JS as three integer methods. A floor present with no watermark
     beside it is refused outright; an unreadable bridge fails closed rather than
     reading as "no floor". F-2: an unverifiable `exported` now resolves to
     **true** — OR-ing the sources does NOT fix it, since a v1/v2 blob has no
     authenticated copy at all, so the flipped index would still win. Costs a
     confirm on re-export of an adopted legacy pad; closes the laundering path.
     Tests: `otp-rollback.test.mjs` gained the full v2 two-time-pad PoC (loud in
     the browser, refused outright with a simulated bridge), native-floor
     monotonicity, broken-bridge fail-closed, and the F-2 laundering attempt —
     **89 checks / 8 suites**, 0 flakes in 30 runs. **APK installed and the
     native floor PROVED on real hardware 2026-07-28** against the actual
     AndroidKeyStore path (everything before that was a simulated bridge in
     Node): bridge present; absent floor reads `-1`; `bump(500)` → `500`;
     `bump(5)` → still **`500`** (monotone through the real HMAC); `clear` →
     `-1`; using a pad set its floor to `900` unprompted; and **the full v2
     two-time-pad PoC — rewound blob plus the three deletions — was REFUSED even
     with `adoptLegacy:true`**, i.e. even when the user consents. That is the
     exact attack that recovered a plaintext earlier the same day. Probe pad and
     its native floor removed afterwards; the phone is back to its six real keys
     with no `sc.otp.*` residue and no `AndroidRuntime` exception. Harness:
     `native-floor-ondevice.mjs` in the session scratchpad.
   - **F-1 original finding, for the record — H-3 is bypassable on any v2-shaped blob.** With no
     `inner.hwSend` in the AEAD, `knownUsedHere` collapses to the plaintext
     `sc.otp.used.v1`. Restore a v2 snapshot + 3 `removeItem`s → the pad unlocks
     at offset 0 and two messages encrypt under the same keystream; the review
     recovered a plaintext end-to-end. Two ways to get the snapshot: access while
     the pad was genuinely v2 (used pre-fix pads were STUCK there until
     `bf6bcd2`), or manufacture one — a single save from old client code rewrites
     a v3 blob back to `v:2` and strips `hwSend`, permanently re-exempting it.
     **No localStorage marker can fix this** (any marker is deletable); the
     honest control is to make v2 adoption LOUD — prompt "this pad predates
     rollback protection; its consumption cannot be verified" — and/or time-box
     it behind a migration epoch after which v2 is refused outright. **Needs a
     product decision.** Note `bf6bcd2` shrinks the exposure over time by getting
     used pads onto v3, where the guard is AEAD-anchored.
   - **F-2 (Medium) — the L-3 `exported` flag launders through the migrating
     unlock.** `otp.js` falls back to the plaintext index exactly once, on the
     upgrading unlock, then bakes that value into the AEAD permanently. Flip the
     index first and the double-export warning is disarmed for good → one
     pristine pad to two importers → a two-time pad by construction. **Fix: on
     migration take `exported: true` if EITHER source says true; never downgrade
     to `false` from an unauthenticated read.** Small and self-contained.
   - **F-5 (Low)** — `sc.otp.hw.v1` is an un-clearable local DoS (a large value
     bricks the pad, no UI to clear it). Verified it CANNOT be poisoned into the
     AEAD: the rollback throw precedes the migration write, so deleting the key
     restores the pad. Fail-closed and reversible; noted only because it is
     silent to the user.
6. **Residual, deliberate, unchanged:** whole-storage rollback (an attacker who
   snapshots BOTH the store and its witness, or both the pad and its watermark,
   still rewinds undetected — it needs OS-level trusted monotonic storage);
   whoever joins an empty room first owns it; a visible approval queue can still
   be filled (now at least the owner is told). These need protocol/platform
   changes, not another localStorage key.

### ⬜ OPEN from the 2026-07-26 pentest (everything else in it is fixed + shipped)
Full detail per item in `docs/pentests/secure-chat-pentest-2026-07-26.md` (§4-6 findings,
§9 remediation). These are the deliberate leftovers, not forgotten work.

1. ~~**P-08 (Low) — room-slot squatting.**~~ **FIXED 2026-07-27** with
   owner-approved room entry (user-designed) — see the snapshot at the top.
   Waiting no longer consumes a member slot, so knowing a room id no longer
   takes the room from the invited peer. **Residual, deliberate:** whoever joins
   an empty room FIRST owns it, and a visible queue can still be filled — both
   availability-only, both needing the cryptographic room-entry proof this
   finding always said it would take. **Committed (`c753535`) and deployed
   2026-07-27; the phone still needs an APK rebuild.**

2. ~~**Android L-10 (Low) — relay config fails SILENTLY on an older WebView.**~~
   **FIXED 2026-07-27 — see the snapshot at the top of this file.** (Its sibling
   L-11, the additive `Copy` task shipping stale assets, was already fixed —
   `syncWebClient` is a `Sync`.) **Still needs the on-device install** — the APK
   is built and the unit test passes, but nothing has been run on the phone.

3. **Info-level backlog (no urgency, listed so it is not lost):**
   - `dilithium-py` upstream says *"under no circumstances should this be used
     for cryptographic applications"*. Here it only VERIFIES signatures over
     PUBLIC data (~6.5 ms, constant-time irrelevant), so the residual risk is
     *correctness* of the PQ ownership proof, which nothing else re-checks.
     Document the accepted risk; prefer liboqs bindings if they become viable.
   - No `Cross-Origin-Opener/Resource/Embedder-Policy` (framing is already
     covered by `frame-ancestors 'none'` + XFO) — cheap isolation win.
   - No session revocation/logout: a leaked bearer token stays valid for the
     full `TOKEN_TTL_SEC = 3600`. `/healthz` is unthrottled.
   - `neutralName()` uses a case-folded 12-char (~62-bit) truncation of the
     sender key as the contact store's PRIMARY KEY. Infeasible to grind today,
     but a derived primary key should be a full-width hash.
   - Dead code / naming: `_reimportExtractable()` is a no-op that asserts
     behaviour it does not implement; unused exports `crypto.UNAVAILABLE`,
     `contacts.hasStore` (now used by the P-02 fix), `account.me`; the v2
     register domain is built with `.replace("/v1","/v2")` instead of a constant.
   - `with sqlite3.connect(...)` commits but never `close()`s (refcount-dependent).
   - One `console.error` in `app.js` reaches Android logcat; gate behind a debug flag.
   - No passphrase policy anywhere; at-rest KDF is PBKDF2-SHA256 600k (correct
     and salted, but GPU-friendly — Argon2id/scrypt would be materially better).

### ✅ DONE (2026-07-25): redesign stage 2 — hierarchy pass
**SHIPPED (built + verified; deploy/APK pending) — see the top snapshot.**
Dual type stack, button tiers, restructured Profile, drawer head/foot, empty
states, trust legend, global `[hidden]` fix. Stage 1 fixed tokens; this fixed
hierarchy. If a stage 3 is ever wanted, the remaining candidates are: the
Live-room 3-step flow as a real progress affordance (it's still a text line),
a mobile bottom-nav instead of the drawer, and the OTP panel (still the
densest, least-designed surface in the app).

### ✅ DONE (2026-07-19): cosmetic polish pass ("make it look less cheap")
**SHIPPED — see the 2026-07-19 snapshot at the top** (built + verified;
deploy/APK were run by hand due to session permissions). Original spec below.

### (original spec, 2026-07-18, user-requested): cosmetic polish pass
User wants the web client + app to look **more polished while KEEPING the
existing design language** (dark GitHub-ish palette, monospace, panel cards).
Explicit ask: **remove the emojis from the drawer menu** — they make it look
cheap. This is presentation-only: no crypto, no logic changes, no new runtime
deps.

**Hard constraints (these rule out the usual redesign tools — do NOT fight them):**
- **Strict CSP:** `style-src 'self'` + no `unsafe-inline`, `default-src 'none'`.
  No inline styles, no CDN, no external stylesheets. **Web fonts are blocked**
  (font-src falls back to `'none'`) unless you add `font-src 'self'` to the CSP
  in BOTH `backend/main.py` and `android/.../MainActivity.kt` AND vendor a
  woff2 — treat a custom typeface as a *separate, security-relevant* change, not
  part of this pass. Default to a refined system stack instead.
- **No build step / vanilla JS, security-audited:** do it as a **hand-written
  CSS token refresh in `client/style.css`** (it already uses CSS custom
  properties — `--bg/--panel/--fg/--muted/--accent/--ok/--err/--border`). NO
  framework, NO Tailwind/CDN. Keep JS `textContent`-only.
- **Bundled into the Android WebView** via gradle `syncWebClient` — whatever you
  ship in `client/` must stay self-contained.
- **Do NOT touch the `<script type="importmap">` line in index.html** — its text
  is pinned by the CSP hash (`test_csp_hash.py`); changing it means regenerating
  the hash in two files. A pure style pass shouldn't need to.

**Do:**
1. **Remove drawer emojis** — `client/index.html:18–21` (`👤 Profile / 🔒 Live
   room / 👥 Users / 💬 Chats`). Prefer **subtle monochrome inline SVG icons**
   (inline SVG is CSP-safe; `img-src 'self' data:` also allows data-URIs) for a
   polished look; plain text labels are the safe fallback. **KEEP** the `☰`
   menu button (standard) and the **functional trust-mark glyphs 🟢🟡⚪** in the
   Users/Chats views (they're documented security UX, not decoration).
2. **Token refresh in `style.css`:** introduce a small design-token layer on top
   of the existing vars — a spacing scale, consistent radii, a real type scale
   (sizes/weights/letter-spacing on labels + `.step`), soft elevation/shadow for
   `.panel` and the drawer, and refined **hover/active/focus-visible** states on
   `.navitem`, `button`, `input/select`, `.alg-card`. Tighten the palette
   (subtle surface layering panel-vs-bg, gentler borders) WITHOUT changing the
   hue language. Polish the chat bubbles, `.safety` block, `.myhandle`,
   `.profile-qr`, badges. Keep the mobile `@media (max-width:600px)` behavior.
3. Keep everything responsive + theme-consistent; no horizontal overflow.

**Optional first step:** prototype 1–2 directions in a **Claude Artifact**
(self-contained, already CSP-shaped) so the user can eyeball before porting into
`style.css`.

**Verify + ship:** puppeteer harness in `scratchpad/verify-sc` (reuse
`profile-flow.mjs` / `h01-flow.mjs`) — confirm every view renders, the menu has
NO emoji, nothing overflows, all flows still work; screenshot a couple of views.
Then **deploy: rsync ONLY `client/`** to the box (backend untouched → no
`chown`/restart needed, static files serve immediately; importmap untouched → no
CSP-hash change). Rebuild the APK (`JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64
./gradlew assembleDebug`, `syncWebClient` copies the client) and `adb install
-r`. Backend `test_csp_hash.py` must still pass. Commit + push; update this file.


### ✅ DONE (2026-07-18): Profile tab in the left drawer
**SHIPPED — see the "Profile tab shipped" snapshot at the top.** Built with ALL
the suggested additions (QR, key details, status line, identity actions,
saved-users count). What follows is the original spec, kept for reference.

Add a **👤 Profile** view to the drawer menu (alongside Live room / Users /
Chats — probably first) that shows the user's OWN data in one place. Read-only
display of what's already in memory when the identity is unlocked; no new crypto.

**Must show (user-specified):**
- **Name** — the registered username (`sc.username.v1`), or "not registered yet".
- **Handle** — `username#token` with the **Copy handle** + **Copy invite link**
  buttons (reuse `myHandle()` / `inviteLink()` / the copy wiring already built
  for the Users view — factor them out so both views share one implementation).
- **Fingerprint** — the identity fingerprint (`identity.fingerprint()`), the same
  string contacts verify in person. Show it prominently.

**Suggested additions (my picks — confirm before building):**
- **QR code of the invite link** — the natural in-person exchange (a contact
  scans it to add you). Needs a tiny self-contained QR generator; keep it inline
  (no CDN — CSP forbids external scripts).
- **Key details** — the algorithms (Ed25519 + ML-DSA-65 signing; ECDH P-256 +
  ML-KEM-768 encryption) and maybe the short public-key fingerprints, so a
  curious/technical user can see what's protecting them.
- **Status line** — identity unlocked? registered? logged in (mailbox reachable)?
- **Identity actions** — surface the existing **Copy backup** (export) and
  **Forget identity** here too (currently only on the Live-room identity screen),
  since a "Profile" page is where users will look for them.
- **Counts** — e.g. "N saved users" (from `contacts.list()`), for a quick sense
  of state. Optional.

**Locked/unlocked:** when the identity is locked, show a "unlock in the Live room
first" hint (same pattern as Users/Chats). No data is available before unlock.

**Security note:** this is presentation-only — it displays existing local state,
adds no network calls and no new trust surface. The fingerprint/handle shown are
already public-shareable. Keep everything `textContent` (no innerHTML), matching
the rest of app.js. Do it in `client/` (the single source of truth) so the phone
app inherits it via the gradle `syncWebClient` copy; then deploy to Hetzner
(rsync — separate from git push) and rebuild the APK.

### ⮕ PLAN (2026-07-17): contacts + web-of-trust + async 1:1 chats ("WhatsApp mode")
User-requested feature set: a left drawer menu with two new views next to the
existing live room — a **Users** list (known users + public keys + 3-level
safety marks, securely stored on-device) and a **Chats** list (persistent 1:1
chats, WhatsApp-style, no shared live room needed). Big change incl. backend
(store-and-forward). Locked design decisions:

- **Safety marks (trust levels):** 🟢 *verified by you* (you compared the
  fingerprint/safety number in person — the existing verify gate or an explicit
  action in the Users view); 🟡 *vouched* (a user YOU verified has published a
  signed vouch for them; UI names the voucher); ⚪ *unverified*. Vouches are
  dual-signed (Ed25519 + ML-DSA-65) statements over the target bundle,
  published to / fetched from the directory. The server is never the trust
  root — marks are computed client-side from signatures it can't forge.
- **Contacts & chats at rest:** encrypted client-side under a key derived from
  the identity passphrase (PBKDF2-600k → AES-256-GCM, own salt; key lives only
  in memory while the identity is unlocked) — same posture as the identity
  blob and OTP pads. Never plaintext in localStorage.
- **Async E2EE (chats without a live room)** needs public ENCRYPTION keys in
  the directory → **bundle v2**: identity adds P-256 ECDH + ML-KEM-768 public
  keys, dual-signed at registration. Async chat modes: **SEALED** (default:
  per-message ephemeral hybrid ECDH+ML-KEM → AES-256-GCM; sender identity +
  dual signature INSIDE the ciphertext), **AES256** (shared passphrase),
  **OTP** (pad). DHKE/RSA stay live-room-only (inherently interactive).
- **Mode lock + negotiated change:** each chat is locked to one mode; a mode
  change is an encrypted in-chat control message the peer must accept (both
  directions signed); the chat renders it as system lines.
- **Mailbox backend (store-and-forward):** server stores ONLY
  (recipient, opaque ciphertext, arrival time) — sender is inside the sealed
  envelope, invisible to the server. Hard caps: per-recipient message + byte
  quota, global cap, TTL (~14 d), delete-on-fetch (auth: session token), own
  rate bucket. No content, no sender metadata, no read receipts server-side.

**Phases** (each ends verified: unit + live-browser + deploy; check off here):
- [x] **P1 — client shell + contacts** — DONE 2026-07-17 (see dated entry):
      drawer menu (Live room / Users / Chats placeholder), `contacts.js`
      encrypted store (PBKDF2-600k → AES-GCM under the identity passphrase,
      unlocked alongside the identity, wiped on identity-forget, key-change
      resets `verified`), Users view (add by handle, fingerprint, 🟢/⚪ marks,
      confirm-gated verify/unverify/remove, auto-🟢 from the live-room verify
      gate + from a matching pin on add). Unit + live-browser verified;
      deployed to Hetzner + phone.
- [x] **P2 — web of trust** — DONE 2026-07-17 (see dated entry): vouch
      endpoints (POST/DELETE `/api/vouch`, GET `/api/users/{u}/vouches`
      token-gated), dual-sig verified server-side over the target's registered
      bundle, caps (200/voucher, 200k total, 50/response); client publishes on
      🟢 (opt-in confirm, requires login), retracts on Unverify, and computes
      🟡 STRICTLY locally (voucher must be a contact I verified, server keys
      must equal my pinned copy, dual sig over MY stored target bundle).
      3 new backend tests; browser flow: alice vouches bob → carol (verified
      alice) sees 🟡 "vouched by alice". Deployed to Hetzner + phone.
- [x] **P3 — bundle v2 + sealed envelope** — DONE 2026-07-17 (see dated
      entry): identity carries ECDH P-256 + ML-KEM-768 keypairs (blob v3;
      pre-v3 blobs auto-upgrade on unlock and re-publish), registration v2
      (own domain, dual sig covers enc keys; same-identity re-registration =
      bundle refresh keeping the lookup token), new `sealed.js`
      (hybrid HKDF→AES-GCM envelope, sealed sender + dual sig inside,
      re-target/forgery/tamper refused). 5 new backend tests (65 total),
      new `sealed.test.mjs`. Deployed.
- [x] **P4 — mailbox + Chats view** — DONE 2026-07-17 (see dated entry):
      `mailbox.py` store-and-forward (token-gated POST, login-gated
      delete-on-fetch GET, size/inbox/global caps + 14d TTL + own rate
      bucket; 5 tests, backend 70 passed); `chats.js` encrypted chat store;
      Chats view (start-chat picker, chat list w/ marks + preview,
      bubble conversation, 6s polling incl. auto-add of unknown senders from
      the sealed handle). Browser-verified both directions; deployed.
- [x] **P5 — mode lock + negotiated mode change** — DONE 2026-07-17 (see
      dated entry): each chat is locked to SEALED or AES256; a change is a
      signed control message the peer must accept/decline; AES256 adds an
      inner AES-256-GCM layer under a per-chat passphrase inside the sealed
      envelope. Browser-verified propose→accept→double-encrypted message;
      deployed (APK rebuilt, phone reconnect pending).
- [x] **P6 — hardening pass over the new surface** — DONE 2026-07-17 (see
      dated entry): adversarial `pentest-p6.mjs` (vouch forgery, client 🟡
      forge-resistance, mailbox enumeration/auth/cross-user isolation,
      captured-envelope, chat sender spoofing) — all attacks refused, local
      AND live. 3 live integration suites still green (no relay regression).
      README documents contacts/WoT/chats. APK rebuilt. Live E2E on Hetzner.
- [x] **MEDIUM — OTP concurrent pad use = two-time pad (2026-07-16 OTP pentest,
      Finding 1)** — FIXED 2026-07-16 (see dated entry): a same-origin exclusive
      lock (Web Locks API, localStorage-heartbeat fallback) is taken on connect;
      a pad live in one tab refuses connect in any other. Live-verified (second
      tab refused).
- [x] **MEDIUM — OTP pad stored unencrypted at rest (2026-07-16 OTP pentest,
      Finding 2)** — FIXED 2026-07-16: the pad bytes AND offsets are now stored
      encrypted (PBKDF2-600k → AES-256-GCM) under a per-pad passphrase, unlocked
      per session (PBKDF2 once; cached key for cheap per-message re-saves).
      Offsets inside the GCM blob, so an attacker can't roll `sendOffset` back to
      force reuse. Live-verified (blob has kdf/iv/ct only; wrong passphrase
      refused).
- [x] **LOW — OTP export file has no single-use/role binding (2026-07-16 OTP
      pentest, Finding 3)** — FIXED 2026-07-16: re-export of an already-shared pad
      warns and requires a confirming second click; import still dedups by padId
      and shows a strong one-device-per-side warning. (Cross-device double-import
      of a manually-copied file remains inherent without identities — documented.)
- [x] **LOW/info — malicious/low-entropy imported pad downgrades the importer's
      outbound confidentiality (2026-07-16 OTP pentest, Finding 4)** — FIXED
      2026-07-16: `importPad` rejects a pad whose Shannon entropy is < 7.0
      bits/byte (all-zero / grossly low-entropy). Live-verified.
- [x] **CRITICAL — relay-address JS injection (2026-07-08 Android pentest,
      Finding 1)** — FIXED 2026-07-16 (see dated entry): `RelayUrls.parse` now
      whitelist-validates the host charset (`^[A-Za-z0-9.-]+$`) and rejects
      credentials in the authority, before accepting; `MainActivity` builds the
      injected relay config with `JSONObject` instead of hand-interpolation.
      Regression tests (`RelayUrlsTest`, Robolectric) reject the live PoC
      payloads against the real `android.net.Uri`.
- [x] **Medium — `shouldOverrideUrlLoading` origin check is prefix-confusable
      (2026-07-08 Android pentest, Finding 2)** — FIXED 2026-07-16: the check now
      compares the PARSED `request.url` scheme+host to the app origin instead of
      `startsWith`, so `…internal.evil.com` no longer matches.
- [x] **Low — relay value also corrupts the CSP header (2026-07-08 Android
      pentest, Finding 3)** — FIXED 2026-07-16 by the Finding 1 host whitelist
      (the CSP interpolation can no longer receive `;`/quote/brace characters).
- [x] **Low/docs — CORS/WS-origin allow-list entry for the app isn't unique
      (2026-07-08 Android pentest, Finding 4)** — FIXED 2026-07-16: the app now
      pins a unique virtual origin via `WebViewAssetLoader.setDomain(
      "secure-chat.internal")`; `APP_WEBVIEW_ORIGIN` + `backend/config.py`'s
      comment updated to match (comment no longer claims the shared default
      domain uniquely identifies the app).
- [x] **Should-fix (informational, same pentest)** — FIXED 2026-07-16:
      `setWebContentsDebuggingEnabled` is now gated behind `BuildConfig.DEBUG`
      (enabled `buildConfig` in build.gradle.kts); `network_security_config.xml`
      scopes cleartext to loopback + `.onion` only (base-config now
      `cleartextTrafficPermitted="false"`); `importMapHash` drift is guarded by
      a new assertion in the backend's `test_csp_hash.py`
      (`test_android_importmap_hash_matches`, skips if android/ absent).
- [x] **Initialize git** in `~/secure-chat` and make the first commit — DONE
      (repo initialized on `master`; initial commit covers backend, client, and
      tests; `.venv`/`node_modules`/DBs/logs ignored).
- [x] **Browser account integration** — DONE (see dated entry above): register /
      login / fetch-by-username with directory-aware pinning, plus an integration
      test for the client directory protocol.
- [x] **Abuse/DoS hardening** — DONE (see dated entry above): global connection
      cap + idle read timeout. Per-IP limits and lifetime frame caps were
      intentionally skipped (see rationale in the entry).
- [x] **Reflection/replay protection for AES256/DHKE/PQKEM** — DONE (2026-07-02):
      `AuthChannel` binds a per-session sender tag + sequence number into the GCM
      additional data. AES256 has a documented cross-session-replay residual
      (static key).
- [x] **Forward secrecy for RSA mode** — DONE (2026-07-03, see dated entry):
      RSA key transport + one-way HMAC ratchet with one-time AES-GCM message
      keys; root secret + RSA private key erased once traffic starts.
- [x] **AES256 ratchet** — DONE (2026-07-03, see dated entry): shared
      `RatchetChannel`, chains rooted in passphrase + both peers' fresh session
      nonces (new AES256 hello exchange). Closes the cross-session-replay
      residual; FS honestly limited by the passphrase being a long-term secret.
- [x] **Concurrent decrypt() reopens replay acceptance (High, found 2026-07-03
      pentest, all 4 modes)** — FIXED 2026-07-07 (see dated entry): per-channel
      `CallQueue` serializes all encrypt/decrypt calls, so the replay counter
      can no longer be read before a prior call commits it. Regression tests
      (`concurrencyChecks` in `crypto.test.mjs`, all 4 modes) cover concurrent
      duplicates and the counter-rollback replay scenario.
- [x] **Concurrent encrypt() permanently kills the ratchet channel (Medium,
      found 2026-07-03 pentest, AES256/RSA)** — FIXED 2026-07-07 (see dated
      entry): same `CallQueue` serialization (overlapping encrypts now step the
      chain sequentially), plus app.js disables Send while a send is in flight.
      Verified live in a real browser: double-click Send delivers exactly once
      and the channel keeps working.
- [~] **Android app** — IN PROGRESS (2026-07-07/08, see dated entries; icon +
      signing done 2026-07-23, see top snapshot): `android/` WebView shell
      bundling the audited client; debug APK builds clean; verified in a real
      browser AND ON-DEVICE (Android 14 emulator — AES256 end-to-end through
      the relay, both directions). Surfaced + fixed the Mixed-Content
      transport constraint (relay must be wss/loopback/.onion). Adaptive app
      icon and a real release-signing config (local keystore, gitignored) are
      now in place. REMAINING: an on-device pass of the identity +
      safety-number gate (DHKE/RSA/PQKEM; only AES256 driven on-device so far
      — started 2026-07-23, interrupted mid-session).
- [x] **OTP mode** — DONE (2026-07-16, see dated entry): true XOR one-time pad
      (`OtpPad` in crypto.js) with two-region split (no reuse across senders),
      strictly-increasing offsets (replay + cross-session replay rejected),
      per-message one-time HMAC-SHA-256 authenticator, and forward-secrecy
      zeroing of consumed bytes. Pad lifecycle in `otp.js`: CSPRNG + draw-to-
      generate entropy, passphrase-encrypted export/import file for the in-person
      exchange, localStorage persistence of bytes + offsets. UI + budget display
      in app.js/index.html. Verified end-to-end in a real browser (generate →
      export/import → two-way messaging → offsets persist → consumed bytes zeroed
      at rest).
- [x] **Tor deployment** — DONE 2026-07-28 (see the dated entry at the top):
      v3 onion service live beside the clearnet site, both proxying to the one
      loopback uvicorn; origin added via `SECURE_CHAT_EXTRA_ORIGINS`;
      `SECURE_CHAT_TRUSTED_PROXIES` **unset** (F-03 would otherwise reopen on the
      onion path); config committed under `deploy/`. **Android still points at
      clearnet** — switching it needs Orbot on the phone, which is the remaining
      piece of "pairs with the app".
- [x] **Handshake replay across sessions in a reused room (Medium, found
      2026-07-02 pentest)** — DONE (2026-07-02 second session, see dated
      entry): transcript v2 folds a fresh per-connection nonce from both peers
      (hello phase) into the signed handshake; live relay replay PoC now
      REJECTED (regression test in `auth.integration.test.mjs`).
- [x] **AES256 cross-session replay (Low, re-confirmed 2026-07-02)** — CLOSED
      2026-07-03 by the AES256 ratchet: session chains bind both peers' fresh
      session nonces, so a captured session-1 frame can no longer authenticate
      in session-2 (regression test `aesRatchetChecks` in `crypto.test.mjs`,
      incl. a fresh-receiver variant proving the key — not the replay counter —
      rejects it).

DONE since this list was first written (pruned from the TODOs above): web client
MVP with the WebCrypto encryption menu; the DHKE/RSA/PQ `key`-message handshake
flow (documented + implemented); authenticated key exchange end-to-end in the
browser; the identity model decision (long-term identity keys verified in person,
relay stays anonymous/room-based); and ASGI endpoint tests for the relay.

## Open questions for the user
- Identity model: fully anonymous/ephemeral, or accounts? (Leaning anonymous
  for the privacy goal.)
- How do two people exchange a room id out of band (QR, link, in person)?
- Group chat (>2) ever needed, or strictly 1:1?

## How to run (quick ref)
```bash
cd ~/secure-chat/backend
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
pytest -q                          # full server suite (validation + accounts + ws)
./run.sh                           # terminal 1: relay + web client on 127.0.0.1:8000

# client-side (Node 20+), from ~/secure-chat/client:
npm test                           # crypto + identity/auth unit suites (offline)
node integration.test.mjs          # relay round-trip (server running)
node auth.integration.test.mjs     # authenticated handshake through relay (server running)
```
