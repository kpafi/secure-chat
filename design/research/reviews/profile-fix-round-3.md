# Contact profile — fix round 3 (triage of hot r3, cold r3, pentest pass 3)

All three reviewed HEAD 120fbf8. Hot: "meets the owner's bar", no blocker or major, three minors.
Cold: two new majors, both regressions from round 2. Pentest: nothing Critical/High/Medium, four
Lows. All accepted except where marked.

## Focus and layout regressions from round 2
- Cold MAJOR-A / pentest L-3 — putting the primary first in the DOM moved the FOCUSED button, and a
  moved node loses focus (Unverify on a contact whose key once changed flips the order back): the
  node that is not focused is the one moved, focus is read before anything moves, and a reorder
  restarts the 500 ms rule (pentest I-3: a tap aimed at one button must not land on the other).
- Cold MAJOR-B — `nowrap` + `min-width: 0` let "Message" spill out of its button at 200% text:
  the row wraps again, and a button is never narrower than its longest word (`min-content`). At
  normal text the pair still fits one line at 320px.
- Pentest L-4 — at 320×568 the sticky bar still covered the fingerprint in the key-changed state,
  where Verify is the primary: in that state the row is not sticky; it follows the fingerprint, so
  reaching Verify means reading past the number first.

## Vouch and store
- Pentest L-1 — an aborted vouch can still be published (the relay acted, the answer was lost or
  late), and the UI said "Could not publish". Now: "No answer from the relay about the vouch for
  "<name>" — it may still have been published. Unverify retracts it." A timed-out vouch marks the
  contact; Unverify/Remove then retract twice (now and once after the bound), and the vouch refresh
  retracts any vouch of OURS it finds for a contact we no longer trust (it already fetches them).
- Pentest I-2 — Remove during or after a vouch left it published: Remove retracts — only for a
  contact that was verified or has an uncertain vouch (a DELETE for anyone else would tell the relay
  whom we had saved). Remove is refused while a Verify/vouch runs.
- Pentest L-2 / cold minor 1 — a refused store write (another tab wrote first) wrote its reason into
  the now-hidden list: the reason goes to the locked panel (`contactsError`, "Contact store error:
  …"), focus to its passphrase field. Cold minor 2: Remove on a refused store is handled the same.
- Pentest I-1 / cold minor 3 — a vouch result landed, unnamed, on another contact's sheet: it is
  shown only on its own contact's sheet, and every vouch line names the contact.
- Pentest I-5 — the busy line said "publishing the vouch" also during an Unverify's write: "Still
  saving the last change — one moment."

## Polish (hot r3)
- n1 — the handle breaks at its "#" first; only the token breaks inside itself, and only when wider
  than the column (was: `text-wrap: balance` + `break-all` cut the token to balance two lines).
- n2 — "Verified in person ✓" carries a no-break space: the ✓ never wraps alone.
- Not taken: n3 (hide the bar's rule when nothing scrolls via `scroll-state` queries) — the rule is
  quiet and the query is not supported in the WebView floor we test; hot's "rem" comment note: the
  10rem does grow with the root size (cold measured 320px at a 32px root), the comment stands.
- Hot m-d (round 2) was the long handle's ragged break; it is n1 here.

## Tests — contact-profile.mjs 46 → 52 checks
Focus survives the reorder after Unverify; the vouch-timeout line names the contact and says it may
be published; a "?" is shut on the next open; a slow clipboard write (1 s stub) never labels the next
contact's Copy (the old check passed without the reset); a store write refused because a second tab
(same context, unlocked with the passphrase) wrote first: sheet closed, reason on the visible locked
panel, focus in the passphrase field, nothing inert, re-unlock reads the other tab's version; at
320×568 in the key-changed state Verify is the primary and its row sits after the fingerprint. The
automatic contact's Users-row claim is read from a fresh Users render (it read a stale hidden list).
Cold's remaining survivors that only change colour or a caption (N24, N25, rings R16/R17) and the
defensive closes (M5, M6) stay untested by e2e; the sticky bar at 390 and scroll-padding are
covered by the reviewers' harnesses, not by the suite.

## Still open, deliberately
- A double click (to select a word) on a Users row still opens the profile — its first click is a
  click. Cold r3 m2 / pentest I-4. Delaying every open to tell a single from a double click would
  cost every user a pause; the drag-select case is handled.
- Android back button closing the sheet (needs a history entry per open) — separate change.
