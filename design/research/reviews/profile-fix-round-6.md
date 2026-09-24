# Contact profile — fix round 6 (triage of cold r6, pentest pass 6) — and a simplification

Both reviewed HEAD 6851571. Cold: both r5 minors fixed, the M-1 guard mutation-proven, no blocker or
major, three new minors. Pentest: every pass-5 PoC fails or behaves as documented; nothing
Critical/High/Medium; five new Lows and four infos — again all in the vouch-retraction bookkeeping.

## The decision: stop patching the bookkeeping, remove it
Six passes in a row found new edges in the same place, each one in a rule the previous round added:
the "unsure" set (p4 L-3a, p5 L-1), the delayed second DELETE and its counter (p4 L-2, p5 L-2,
p6 L-4), the skip while a record under the same directory name is trusted (p6 L-1: a verified
contact's later claim switched it on, so Unverify of the real user silently left our vouch up),
and unbounded retries (p6 I-1). The underlying problem is structural — the relay keys a vouch on
(account, directory name), the client can only guess which vouch a DELETE will remove — and the
clean fix is a relay-side DELETE that names the exact vouch. Until then the client does the
simplest thing that is honest:

- **We vouch only for a contact whose directory name the user typed** (added by handle). A
  contact whose name came from a claim (an automatic contact, or an adopted `claimedName`) is
  never offered the vouch prompt — so no DELETE can ever name a claim, and no "trusted under the
  same name" rule is needed. (Pre-existing vouches for such contacts, made before this change,
  are not retracted by Unverify/Remove any more; that combination needed a verified automatic
  contact and was already the case that deleted the wrong vouch.)
- **A retraction starts only from the user's own Unverify or Remove** (never from what the relay
  lists — p4 M-1), and is sent at once.
- **Logged out, or on failure, it waits in memory for this page** and is tried at most three
  times on the mailbox tick; one request per name in flight. The user is told when it waits —
  "Not logged in — your vouch for "X", if you published one, is retracted when you log in on this
  page (closing the page cancels that)." — for Unverify and for Remove (cold r6 MINOR-2/3, p6 L-5),
  and when it gives up ("Could not retract your vouch for "X" — it may still be published.").
- **Removed:** the unsure set, the delayed second DELETE, the POST counter, the trusted-under skip.
  The case they covered — a vouch the relay took after we stopped waiting 15 s, landing AFTER the
  Unverify's DELETE — is left open and stated: the "No answer … it may still have been published"
  line stays; only a relay that is honest but slower than 15 s reaches it.

## Store refusal
- cold r6 MINOR-1: a lock raised in the background (vouch refresh, mail filing) moved focus into
  the passphrase field while the user was typing — the rest of a chat message landed there, masked,
  and Enter submitted it as an unlock attempt. Background locks focus the panel's line instead; only
  the sheet's Verify/Remove (the user's own click) focus the field.
- p6 L-2: a later plain "store is locked" relabelled a stale lock as "Contact store error … Forget +
  recreate" — the stale flag now sticks until the next unlock attempt, and the refresh sets the
  error text only for the STALE code.
- p6 L-3: a Forget with a mailbox fetch or a vouch in flight got the stale line back afterwards —
  the stale flag needs an identity, the Users panel checks it too, and the mailbox tick returns if
  the identity changed while it awaited.

## Tests — contact-profile.mjs 60 → 61 checks
Unverify retracts a real vouch from the relay (bob, real keys); verifying a contact whose handle is
only claimed offers no vouch and publishes none (replaces the round-4 carol vouch check). The M-1
guard stays. Not in e2e (the reviewers' harnesses cover them): the logged-out waiting line and the
flush on login, the background-lock focus, the stale label after Forget.

## Known and accepted (current list)
A vouch landing after the Unverify's DELETE (honest relay slower than 15 s); a pending retraction is
lost on reload (said in the line); Remove/Unverify of a verified contact whose vouch was declined
still sends one DELETE; another tab re-vouching while this tab's retraction waits; a 502 after the
relay committed reads "could not publish"; a stale tab drops the rest of a mailbox batch
(pre-existing, delete-on-read); a double click on a Users row opens the profile; Android back.

## Pass 7 on the simplified code (HEAD 48b0780) — and the follow-up fixes

Pentest pass 7: every pass-6 PoC fixed or an accepted limit; nothing Critical/High/Medium; four
Lows and an info, each a small correction to the new code, all taken:
- p7 L-1: a DELETE failing AFTER its retraction was cancelled (a re-vouch, a Forget) re-created it
  — the client then deleted the vouch it had just reported "published", or sent a DELETE with the
  NEXT identity's token. A failure now counts only for the entry it was sent for, and only while
  the token is unchanged; Forget clears what is in flight.
- p7 L-2: `account.unvouch` had no bound, so a black-holed DELETE silenced that name for good —
  it now has the same 15 s bound as the vouch.
- p7 L-3: a record vouched under its typed name that later adopted a claim (honest mail filling in
  a missing token) could no longer be retracted — the name a vouch was POSTed under is remembered
  for the page and retracted as such.
- p7 L-4: the Verify handler's own late `finally` could still move focus into the passphrase field
  when someone else's write locked the store — it counts as a background lock unless our write was
  the one refused.
- p7 I-1: the give-up line was lost if the user was not on Users/Chats, and the three tries fell
  inside ten seconds — the line waits for the next Users/Chats render, and tries are 20 s apart.
- Stated honestly in the code: a retraction DELETE is not awaited before a quick re-vouch, so a slow
  one can still land after it (added to the accepted list).
