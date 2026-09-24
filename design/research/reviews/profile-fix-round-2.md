# Contact profile — fix round 2 (triage of hot r2, cold r2, pentest pass 2)

All three reviewed HEAD c322d15. Pentest: L-1…L-4 closed (each original attack re-run past the new
guard and failing); nothing Critical/High/Medium; two new Lows. Cold: no blocker; one major
regression, one major test gap, five minors. Hot: B1 and M1–M8 fixed or partly; three new majors
from the fixes. Everything below is accepted.

Round-1 items the round-1 triage did not list (hot r2 asked): hot m4 (the handle's 2-character
orphans) went with M4 and is finished here with `text-wrap: balance`; hot m7 (the "Messages" label)
was taken — the fact is now "Sealed mail" and appears only when it is the problem.

## The sticky action row (hot M-A, cold MAJOR-1)
On short phones the row that round 1 made sticky grew to two or three lines (Remove never fitted on
the first) and covered the fingerprint Verify asks you to compare, and a focused control could sit
under it (WCAG 2.4.11). Now the sticky row holds only the two decisions, on ONE line (words wrap
inside the buttons at 320px); Remove is under it, last, and scrolls in. The sheet has
`scroll-padding-bottom: 10rem` on phones so focus is always scrolled clear of the bar.

## Trust actions
- Pentest p2 #1: a vouch the relay never answers held `contactBusy` for good — every later
  Verify/Unverify silently ignored. The vouch now has a 15 s bound (`account.vouch(..., signal)`),
  the store change is shown before the round trip starts ("Publishing the vouch…"), and a refused
  click says why ("Still publishing the vouch — one moment."). Busy still spans the round trip, so a
  vouch and an unvouch for the same contact never race at the relay.
- Pentest p2 #2 (pre-existing): `setVerified` throwing (the store refusing a stale write) failed
  silently. Now: "Could not save: …", and a store that locked itself closes the sheet and shows the
  view's locked state.
- Pentest p2 #3: a slow clipboard write could label the next contact's Copy "Copied ✓": each copy
  button has a generation; a write or timer from an older one never relabels it.
- Hot M-C / cold m1: in the key-changed state the primary (Verify) is first in the DOM, not by CSS
  `order`, so Tab and reading order match the screen.
- Hot m-e: Unverify keeps a hairline, so it never reads like Remove.

## Sheet content
- Hot M-B: the claimed handle is shown again; in the sheet the claim line reads "claims the handle
  below — unverified, they chose this name themselves" when the claim IS that handle (the Users row
  keeps the quoted form — it is the only place the claim appears there).
- Hot m-a: each fact's term and value are one unit (`<div>` in the `<dl>`), never split by a wrap.
- Hot m-f: a "?" opened on one profile is shut on the next.
- Cold m4: the Handle label regained its spacing (it became a `<p>`); cold m3: the sheet container
  shows a focus ring when the keyboard lands on it.

## Lists and header
- Hot m-b: a Users row focuses as one (the ring round the whole row, warning lines included).
- Hot m-c: the conversation's name button is as wide as the name (`#chatPeer.peer-open` beats
  `#chatPeer`'s own flex rule; round 1's rule lost on specificity).
- Cold m2: a drag or double click that selects text in a Users row does not open the profile.
- Cold m5: rebuilding the "New chat" picker keeps the user's pick.

## Tests (cold MAJOR-2, pentest gaps) — contact-profile.mjs 37 → 46 checks
Tab order in the key-changed state; Unverify asks first and "no" keeps it (dialogs are now counted
and answered per check); a click on a button whose state the store no longer has redraws and asks
nothing (data-action); a vouch held by the relay: the store shows verified at once, a second click
is refused with its reason, the round trip times out, Unverify works again (contactBusy + bound);
the sheet's Verify label after Unverify from the conversation (N2); malformed stored keys in the
Users row (seeded with `upsert`, which does accept them — the round-1 note saying no path produces
one was wrong); "Handle they claim" for an adopted claim; a copy result never shows on the next
contact; Remove from Users → focus on the add field (restored); the claim line wording in the sheet
and in the row.

## Not taken
- Pentest p2 info #4: `refreshChats()` (now also after a Verify from Chats) clears `#chatsStatus`
  and the conversation hint — the same thing mail arriving already does; and "X declined the mode
  change" is erased by `renderConversation()` right after it is written (pre-existing since
  before b9ff13e). Both belong to the chats status design, not to this change.
