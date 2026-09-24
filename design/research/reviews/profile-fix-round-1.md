# Contact profile — fix round 1 (triage of hot, cold and pentest pass 1)

All three reviewed `git diff b9ff13e` at 17ee937. Pentest: nothing Critical/High/Medium; the Verify
snapshot check and the fingerprint key guard hold (each killed by its own mutant). Cold: no blocker,
three majors. Hot: one blocker, eight majors. Everything below is accepted unless marked otherwise.

## Trust state and actions
- Hot B1 — key changed (or H-01 reset): **Verify becomes the primary and comes first**, Message
  secondary. Signal's pattern: on a changed safety number, verifying is the call to action.
- Hot M1 — Message is primary only when a sealed message can reach them (token + ecdh + mlkem);
  otherwise it is a plain secondary (the conversation says why it cannot send).
- Pentest L-1 — a second click on Verify ran Unverify (fresh read, store already flipped): a running
  action refuses further clicks (`contactBusy`), the button carries the action it was rendered for
  (`data-action`) and a click whose action no longer matches the store is dropped.
- Pentest L-3 / cold m2 — a double tap on a phone reached Unverify (no confirm) or closed the sheet
  through the scrim during its entrance: the admission sheet's rule, 500 ms after open, for Verify /
  Remove / Message / Copy and the scrim (event timestamp, works with reduced motion too). **Unverify
  is now confirm-gated** (new copy; it revokes the pin, so it is as destructive as Remove).
- Pentest L-2 / cold M1 — Chats marks (row and conversation header) went stale after Verify/Unverify
  from the sheet: `contactsChanged()` refreshes Chats when it is on screen; `renderConversation()`
  re-renders the sheet like the two lists.
- Pentest L-4 — "Copied ✓" stuck across contacts: `copyToClipboard` keeps each button's resting
  label once (`data-label`), and opening the sheet resets its Copy button.
- Pentest info — "Handle they claim" keys on `c.auto || c.claimedName` (an adopted claim too).
- Pentest info / cold m5 — the malformed-keys sentence is back in the Users row (the row computes
  the fingerprint again only to raise it), as well as in the sheet's well.

## Layout and hierarchy
- Hot M2 — the fingerprint sits directly above the actions: order head, warnings, handle, facts,
  fingerprint + "?", status, actions — in the markup, so reading and Tab order match.
- Hot M3 — facts shrink to one caption line: "Saved <date>", "Verified <date>" only when verified,
  "Sealed mail: no encryption keys published yet" only when that is the problem. "Vouched by" and
  "not yet" repeated the pill: dropped.
- Hot M4 — handle and Copy on one line (handle 13px; the button reads "Copy", described by the
  "Handle" label); on phones the action row is sticky at the sheet's bottom, so an action is on
  screen the moment the sheet opens at 320×640 and 390×600.
- Hot M5 — red means the changed key: the sheet's mark has no caption (the box under the head says
  it), Remove is a muted word until hover/focus, on the action row, right-aligned (the canvas's
  choice). Hot m1/m2: natural-width buttons, the primary grows.
- Hot M8 — an automatic contact's claimed handle is shown once: when the claim line already quotes
  it, the handle value is hidden (label and Copy stay).
- Hot M6 / cold m7 — a tap anywhere on a Users row (the claim and warning lines too) opens the
  profile; the row hovers as one. Keyboard keeps the one button.
- Hot M7 — the Chats avatar shows hover/press/focus on the disc itself.
- Hot m3 — the conversation's name button is as wide as the name. Hot m6: the sheet's title is 17px
  on phones. Cold m6: action buttons wrap their words at 200% text.

## Focus and semantics
- Cold M2 — focus after Remove from Chats / the conversation: the avatar is a span then and
  `#chatPeer` disabled — fall back to the row's opener, `#chatNew`, `#chatBack`.
- Cold M3 — a re-render of the Users list (mail, vouch refresh) keeps focus on the same row.
- Cold m1 — scrim close returned focus to <body>: the scrim's mousedown no longer blurs the sheet.
- Cold m3 — Escape closes from anywhere while the sheet is up (document listener); Shift+Tab from the
  sheet container wraps to the last stop.
- Cold m4 — `#chatPeer` carries `aria-haspopup` only when it opens something.

## Tests (cold m8, pentest gaps)
contact-profile.mjs gains: Verify disabled while the fingerprint is pending (in-page delayed
`Identity.fingerprintOf`); a slow fingerprint for one contact never lands on another's sheet; a
second click on Verify changes nothing; a phone double tap (reduced motion) neither acts nor closes;
Chats header mark follows Unverify from the sheet; focus after scrim close, after Remove from a
Chats avatar; Escape after a click on the sheet's text; a tap on a row's warning line opens it; Verify
is the primary for a changed key; `#chatPeer` disabled without `aria-haspopup` for a removed contact;
Users-row focus survives a list re-render; the check icon is absent beside the handle (37 checks,
was 27). The malformed-keys row sentence has no e2e check: the store refuses malformed keys at every
entry point, so no UI path produces one.

Found while fixing: disabling the focused Verify button (for L-1) dropped focus to <body>; the busy
state now refuses clicks without disabling, and a render that must disable the focused button moves
focus to the sheet. A second click landing after the button relabelled to "Unverify" is caught by
restarting the 500 ms rule after every Verify/Unverify (and Unverify is confirm-gated now).

Not testable through the UI and left as defensive code: the sheet closing on `showView` / store
unlock / forget (the tab bar and every path to them are inert while it is up).

## Not taken
- Hot m5 (Profile's name in the UI font vs the sheet's mono): the sheet's title is a contact's
  local label, set like every other handle in the lists (`.u-name`, mono). Profile is the user's own
  identity. Left as is.
- Android back button closing the sheet: needs a history entry per open; separate change.
