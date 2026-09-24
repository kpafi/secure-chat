# Contact profile — fix round 5 (triage of cold r5, pentest pass 5)

Both reviewed HEAD a8e7f2f. Cold: every round-4 minor fixed, no blocker or major, two new minors.
Pentest: every pass-4 PoC fails now (the Medium is gone), four new Lows and three infos — all in the
vouch-retraction and store-refusal code. Pentest's diagnosis is the useful part: each round closed
the specific PoC while the KEY stayed wrong — the unsure mark and the counter were keyed on (local
name, this tab), the relay keys a vouch on (account, directory name).

## Decision
Keep the double retraction (it closes a real case: a vouch the relay took after we stopped
waiting), but key everything the way the relay does, start every retraction from the user's own
action, and never drop a retraction silently. A complete fix — a DELETE that names the exact vouch —
needs a relay change and is out of scope here.

## Vouch path
- p5 L-2a: the unsure set, the POST counter and the pending retractions are keyed by the DIRECTORY
  name; a retraction is skipped while any saved record we still trust has that directory name (an
  automatic contact can claim a real user's name — p5 I-3 is the same rule).
- p5 L-1: a vouch that gets no answer is marked unsure only for the identity that sent it (a Forget
  during the round trip no longer hands the next identity a retraction).
- p5 L-3: a retraction the user asked for is never silently dropped: while logged out it stays
  pending ("Not logged in — any vouch you published for "X" will be retracted once you are."), a
  failed DELETE stays pending, and the mailbox tick (every few seconds while logged in) delivers what
  is pending; a newer vouch for that name cancels it. In memory only: a reload forgets it (stated).
- p5 L-2b (not taken): another TAB re-verifying and re-vouching inside the 20 s window of this tab's
  delayed retraction. This tab cannot see the other tab's write in time; needs the relay change above.
- p5 I-2 (not taken): a 502 from the proxy after the relay committed is reported as "Could not
  publish"; bounded — the contact stays verified, and Unverify/Remove of a verified contact retract.

## Store refusal
- p5 L-4: the most common stale-tab write is the vouch refresh (and mail filing), not the profile.
  Both now show the locked panel with the stale-tab line instead of leaving a dead list. The store's
  stale refusal carries `err.code = "STALE"`, and only that code sets the stale-tab line (p5 I-1).
- cold r5 MINOR-B / p5 I-1: Forget clears the stale flag and the store error; the Chats panel shows
  the stale line only while an identity exists.

## Layout
- cold r5 MINOR-A: the 320px one-row rules are scoped to ≤359px, and the grow-10 rule applies only
  when Verify is the primary. Wider screens and 200% text wrap naturally again (as in 20308f1).

## Tests — contact-profile.mjs 59 → 60 checks
The p4 M-1 guard (cold's audit16, ported): a verified, vouched bob plus an automatic contact
claiming bob's handle, then a vouch refresh — no DELETE, the vouch still on the relay. Verified by
mutation: re-adding the removed self-retraction fails exactly this check (59/60).
