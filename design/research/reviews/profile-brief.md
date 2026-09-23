# Contact profile — a short profile per saved user (decisions)

Owner's ask (2026-09-23, after testing the 0.2.0 rework): tapping a saved user's avatar or name
in Users or Chats should open a short profile of that user — handle, fingerprint, and the rest of
what the app knows about them. Base: `master` at b9ff13e (release 0.2.0). This is the "contact
detail screen" `design/README.md` listed as a phase-2 behaviour change: it gets its own design
(on the Claude Design canvas), e2e coverage and pentest passes.

Constraints as always (`design/research/direction-contract.md`): CSP, ids, byte-identical import
map, textContent-only rendering, no markup from data, one `.primary` per screen, mono only for key
material, 44px targets and 16px controls on phones, `[hidden]` wins. Refusal, warning and error
texts stay byte-identical where they already exist.

## What the profile is

A modal **sheet** (`#contactSheet`, `role="dialog"`, `aria-modal`, labelled by the name) —
the same component as the admission prompt: a bottom sheet above the tab bar on a phone, a
centred dialog wider up, over the scrim. Unlike the admission prompt it is **dismissible**: a
close button (×, `aria-label="Close"`), Escape, and a tap on the scrim close it; focus goes back
to the control that opened it. While it is up, the tab bar, the view underneath and the app head
are `inert` and Tab wraps inside the sheet.

It is opened only by the user's own tap, from:
1. **Users**: every saved-user row. The row's head (avatar + name + trust mark) is one real
   `<button class="u-open">` — the avatar disc moves onto that button.
2. **Chats list**: the avatar disc of a row is its own `<button class="u-avatar">`
   (`aria-label="Profile of <name>"`); the rest of the row still opens the conversation. The row
   is no longer `role="button"` on the `<li>` (a button inside a button is invalid); the
   conversation opener becomes a real `<button class="chatrow-open">` inside the row, so the
   keyboard reaches both.
3. **Conversation header**: the peer's name `#chatPeer` becomes a button that opens the profile
   (the mark stays beside it). A conversation with a sender who is not a saved user has no
   profile (the name is not a button then).

## What it shows (top to bottom)

- **Head**: 56px avatar disc (initial), the local name (`.u-name`), the same trust pill the lists
  draw (`renderMark`, with the key-changed caption), close button top-right.
- **Warnings, when present, directly under the head** (same sentences as the Users row today,
  byte-identical): the self-claimed name line (F-01), "this user's key CHANGED since you saved
  them — re-verify in person before trusting", the H-01 "verification reset" line, and
  "fingerprint unavailable — stored keys are malformed".
- **Handle**: label "Handle" + the `username#token` handle in mono + Copy (→ "Copied ✓").
  For a contact created from an unknown sender's mail (`auto`) the label is "Handle they
  claim" — it is attacker-chosen, the same F-01 posture as the claim line. No token saved:
  "No handle saved — re-add them by their username#token handle to reply." (no Copy).
- **Fingerprint**: label "Fingerprint" + the full four-key fingerprint in the same `.safety`
  well the verify gate uses + a "?" ("Compare it with them in person, or on a call where you
  recognise their voice. It covers all four of their keys, including the ones that seal
  messages to them."). This is the value the user compares, so it sits directly above the
  verify action.
- **Facts** (one `<dl>`, quiet): "Saved" <date>; "Verified" <date> or "not yet"; "Vouched by"
  <names> only when vouched; "Messages" "can receive sealed messages" or "no encryption keys
  published yet". Dates as the device's short locale date. No timestamps finer than a day.
- **Actions**, one row, the order of a decision:
  - `Message` — **primary**; opens (creates) the chat and switches to Chats. Hidden when the
    sheet was opened from that very conversation's header.
  - `Verified in person ✓` (secondary) or `Unverify` (ghost) — the SAME handler and confirm
    dialogs as the Users row today (confirm-gated, optional vouch publish, unvouch on
    unverify); the status line it produces goes to `#usersStatus` as before, and is also shown
    inside the sheet (`#contactStatus`, `aria-live="polite"`).
  - `Remove` — a quiet danger ghost, last and separated, the same confirm dialog; closes the
    sheet.

## What changes in the lists

- **Users rows get lighter**: avatar + name + mark (the button), then the claim / warning lines
  (these stay visible in the list — a security signal is never behind a tap). The fingerprint
  line and the Verify/Remove buttons **move into the profile**; the row gets a chevron to say it
  opens. e2e checks that clicked "Verified in person" / "Remove" in `#userList` open the profile
  first and click it there (adapted, not weakened; list each).
- **Chats rows**: avatar button + opener button, same look as today.

## Live state

The sheet is rendered from the store every time it opens and re-rendered when the store changes
under it (vouch refresh, verify toggle, a mail that re-keys the contact). It closes itself when
the contact is removed, when the contact store locks or is wiped (sign-out/forget), and on any
`showView`. The admission prompt keeps priority: the inert bookkeeping is one function for both
sheets, so closing one never un-inerts what the other needs.

## Security posture (for the pentest)

- Name = local label only; the self-chosen name only ever appears as the quoted claim.
- The fingerprint is computed from the keys in the store at render time, never cached across
  a key change; a render that finishes after the contact's keys moved must not write the old
  value (generation check, like `showNextKnock`).
- Everything via `textContent` / `createElement`; the handle is copied with the clipboard API only.
- The verify / remove actions keep their confirm gates; the sheet opens only on the user's own
  click, and its buttons sit where no row control used to be (a double-tap on a row must not land
  on Remove or Verify — confirm-gated anyway; the pentest checks the geometry).
- No new storage, no new network calls, no new logging.

## Proof

npm test; pytest once alone; the five e2e runs with an added `e2e/contact-profile.mjs` (open
from each of the three entry points by pointer and by keyboard; Escape / × / scrim close and
return focus; Tab stays inside; inert on the rest; handle + fingerprint equal the peer's own;
verify from the sheet flips the list mark; remove closes the sheet and the row; key-changed
contact shows the warning in the row AND the sheet; auto contact shows "Handle they claim";
sheet closes on lock); `screenshots.mjs` gains the profile states (phone + desktop, clean,
verified, key-changed); then look at every one at both sizes.
