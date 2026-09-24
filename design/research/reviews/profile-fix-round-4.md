# Contact profile — fix round 4 (triage of hot r4, cold r4, pentest pass 4)

All three reviewed HEAD 20308f1. Every pass-3 / round-3 finding closed (original PoCs fail).
New: pentest one Medium and four Lows, all in the vouch-retraction code round 3 added; cold four
minors; hot one major at 320px. All accepted.

## The Medium, and the decision behind the fix
Pentest p4 M-1: round 3's "backstop" in the vouch refresh retracted any vouch of OURS it found in a
list the relay returned for an unverified contact. An automatic contact takes its address from a
stranger's self-claimed name, so one sealed mail claiming `bob#<bob's token>` made us fetch the REAL
bob's vouches, find ours and DELETE it — silently, with an honest relay, re-firing every ten minutes.
The same loop also deleted a vouch published while it was still walking a stale snapshot (p4 L-1),
and let a hostile relay make us send authenticated DELETEs per contact (p4 L-3c).

The loop's self-retraction is **removed**, not patched: a retraction driven by what the relay lists
is attack surface, and the case it backed up (a vouch the relay took after we stopped waiting) is
rare and already covered by the double retraction on Unverify/Remove. Nothing retracts on its own
any more.

## The rest of the vouch path
- p4 L-2 / cold r4 MINOR-1: the delayed second DELETE removed a vouch published again inside its
  window. It now fires only if no vouch was sent for that contact since (a per-contact counter of
  vouch POSTs this session) and the contact is not verified again.
- p4 L-4: only `TimeoutError` counted as "may still be published"; a lost answer (abort, network
  error) said "Could not publish". Every no-response error is now "may still have been published";
  only an HTTP error response means the relay refused.
- p4 L-3a: the "unsure" set outlived Forget identity (a new identity's Remove then sent a DELETE):
  cleared on Forget, with the counter.
- p4 L-3b (not taken, documented): Remove of a VERIFIED contact whose vouch was declined still sends
  one DELETE. The client does not persist whether a vouch was ever published, and the pre-existing
  Unverify has always done the same for verified contacts. The relay learns that the account had
  verified that user — for a contact the user chose to remove. Persisting a "vouched" bit in the
  encrypted store would close it; that is an at-rest format change for a separate round.
- p4 I-3: "Still saving the last change" left on another contact's sheet is cleared when the action
  ends.

## Store refusal
- p4 L-5 / cold r4 MINOR-2: a benign second-tab conflict showed "Contact store error: … (Forget +
  recreate the identity resets it …)" — advice to take the one destructive action that fits no part
  of the case — and "Chat store error" in Chats. Now both panels say "Your contacts were changed in
  another tab — enter your passphrase to load that version." (cleared by the next unlock attempt).
- cold r4 MINOR-3: the passphrase fields of the Users and Chats locked panels are described by the
  panel's line (`aria-describedby`), so the reason is read when focus lands there.

## Layout (hot r4 major, cold r4 MINOR-4)
At 320px the pair wrapped into two rows at normal text size (max-content widths decide wrapping):
the secondary button counts only its longest word toward the break (`flex: 1000 1 min-content`,
never wider than its text), and below 360px so does "Verified in person ✓" when it is the primary.
One row at 320/360/390; at 200% text the pair still wraps and no label spills. The token's own
lines are balanced (no 2-character orphan at 320). In the key-changed state Remove keeps the sheet's
gap under the static row (p4 I-2: 4px overlap with Message's hit area; hot n5).

## Tests — contact-profile.mjs 52 → 59 checks
Store refusal from three entry points (Verify in Users, Remove in Users, Verify from a Chats avatar):
sheet closed, the stale-tab line on the visible panel, focus in the passphrase field that it
describes, nothing inert, re-unlock loads the other version, a refused Remove removed nothing; a
real vouch (carol's own keys) is on the relay and Unverify retracts it; Remove of an unverified
contact sends no vouch DELETE; 320px normal text keeps the pair on one row; 200% text: no label
spills, no sideways overflow. The removed self-retraction needs no test of its own: the code path
that let a claimed handle trigger a DELETE no longer exists.

## Still open, deliberately
- p4 L-3b above; a double click on a Users row opens the profile (cold r3 m2); Android back.
- Hot r4 n4: at 320×568 in the key-changed state nothing hints that Verify is below the fold — the
  point of that layout is reading the fingerprint first; a scroll hint is a follow-up.
