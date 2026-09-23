# Fix round 2 — CSS-only (plus the duplicate-rule cleanup). No app.js, no index.html unless named.

Sources: reviews/hot-critic-round2.md, reviews/cold-critic-round2.md, the re-pentest (appended if it adds
anything). Everything here is accepted; nothing else is in scope.

## Cold critic (verified with real touch/keyboard events — top priority)
- N1 style.css ~1770: DROP the focus-dependent tab-bar hiding (`:has(input:focus)` or similar). Replace
  with: at `max-height: 560px` (keyboard up / landscape) the tab bar becomes a compact 44px icon-only
  bar (labels visually hidden, accessible names kept). Verify with real touch events at 360×400 and
  568×320 that the FIRST tap on Send / Connect / Continue / Unverify lands (the cold critic's script in
  scratchpad/cold/r2/ reproduces it). Inside an open conversation (#chatConvo) the bar stays hidden
  as before (that rule is state-based, not focus-based, and is fine).
- N2 style.css ~1507: while an error hint is showing (`body:has(#roomHint.err:not(:empty))`, same for
  #idHint), raise `scroll-padding-bottom` by ~9rem so a keyboard-focused control (Connect!) is never
  under the sticky hint. Verify at 320×568, 360×640, 390×844, 568×320 with a Tab walk.
- Hygiene: remove the two new duplicate rule blocks the cold critic named (see its round-2 file).

## Hot critic round 2
- M6 (phone live-room bar): SWAP — "Copy room id" becomes the 44px icon-only ghost (its text stays in
  the DOM for the "Copied ✓" feedback and screen readers; show the feedback text visually when it
  changes if cheap, else rely on the icon), "Disconnect" keeps its word. Below 360px both are icons.
  "waiting for approval" must not wrap inside its pill at 360px (nowrap + ellipsis, or a shorter
  visual treatment that keeps the text).
- M9 (desktop widths): lists (Chats list, Users) at the same 832px as the conversation; forms stay
  632px; every screen's content shares the bar's left edge.
- R1: the #room fade only on ≤600px (desktop shows the full code).
- R2: revert "#accountStatus.ok in mono" — only the handle itself may be mono, the sentence is ui.
  If the handle cannot be isolated without markup, the whole line is ui.
- R4 (desktop Users rows): the action column must not push the trust pill to mid-row or wrap the
  fingerprint — put actions on their own row (right-aligned) on desktop too, or reserve the column
  only for the two buttons with the pill staying on the head line.
- R5: verify screen title and paragraph share one alignment on desktop (left).
- Desktop: hide the duplicate "SEALED" #chatMode chip when the select shows the mode (same as phone).
- forced-colors: the active tab needs a visible state (underline/border in Highlight), not only a
  faint pill.

## Deferred to phase 2 (app.js)
- Trust pill inside the admission sheet when the joiner matches; "verified" state in the live-room
  header after the gate; keyboard access for chat rows; focus trap for the sheet.

## Proof (same as round 1): npm test, pytest (once, alone), the five e2e runs, screenshots.mjs into
shots/rework-v3 (20 states, no overflow), the cold critic's touch/keyboard probes at the four sizes,
and a look at every changed screen at both sizes. Then report per item done / done-differently.

## Re-pentest (round 2) — accepted; these are the ONLY app.js changes allowed in this round
- PT1 (Low) guard not re-armed on reveal by view switch: in showView(), when `name === "live"` and
  `!els.admit.hidden`, set `admitShownAt = performance.now()` (or the same arming code path) and
  `els.admitNo.focus()`. Prefer factoring the arming into one small `armAdmitGuard(k)` helper used by
  showNextKnock and showView, so the two places cannot drift.
- PT4a hardening: in both click handlers, `if (knockQueue[0] !== admitShownFor) return;` before
  deciding (the decision must apply to the knock the user is looking at).
- PT4b hardening: compare against the event's `e.timeStamp` instead of `performance.now()` at dispatch
  (`if (e.timeStamp - admitShownAt < 500) return;`). Keep the pentest comment accurate.
- PT2 coverage (e2e/room-admission.mjs, additions only): (a) assert geometry with rects — `#admit`'s
  bottom ≤ `.tabbar`'s top at 390×844 while both are visible; (b) run the tap pass a second time with
  `prefers-reduced-motion: reduce` emulated (tests the JS guard alone); (c) an Enter-within-500 ms
  keyboard check on the focused Deny (must not deny) and Shift+Tab+Enter on Admit (must not admit),
  then a normal admit after the pause. The pentest's mutants m1/m2/m4 (scratchpad/probe/ describes
  them) must each FAIL at least one of these; say which.
- PT3 info: fix the CSS comment on the `#hint` clipping rule (style.css ~1229) so it says what is
  true: non-gate messages (relay `error` frames, key-exchange failures, directory warnings) are
  visually clipped while the gate is up but remain in the aria-live region; do not change behaviour.
