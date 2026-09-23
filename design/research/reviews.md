# Reviews of the design rework — summary

Three independent reviewers looked at the rework before it was committed; the fixer worked from
the orchestrator's triage (`reviews/fix-round-1.md`, `reviews/fix-round-2.md`). The raw reports
are in `reviews/` (screenshot paths in them point at the session's scratchpad and are not in the
repository; `e2e/screenshots.mjs` regenerates the set).

## Design critic ("hot"), three rounds

Round 1: no. Four blockers, eleven majors, fourteen minors — the warning states (key mismatch,
unexpected joiner) still made "proceed" the blue primary; the key-changed trust mark broke the
conversation header; pending-bar buttons under 44px; focused controls under the tab bar; too much
chrome around a phone conversation; the unlocked identity screen kept the first-run pitch; lists
without avatars; three meanings of red on Users; a two-row live-room bar; dead-air waiting states;
copy density; desktop as a centred form; boxes in boxes in the OTP tools. All accepted and fixed,
plus three scoping reversals (static phone wordmark bar, avatar initials, wider desktop chat).
Round 2: no blocker; two majors (swap the icon-only control in the live bar, unify desktop widths)
and four small regressions. Round 3: "meets the owner's bar", no regression. Left for a follow-up:
trust shown as a pill inside the admission sheet and in the live-room header after verification
(one line of app.js each), keyboard access for chat rows.

## Correctness and accessibility critic ("cold"), three rounds

Round 1: CSP, ids, hidden-toggles, app.js scope, e2e edits, WebView support and stylesheet hygiene
pass; fails on pending buttons under 44px, focus under the tab bar, the tab bar over the composer
on short viewports, no focus into the admission sheet, mask icons vanishing in forced-colors, two
12px pairs at 4.4:1. Round 2: two new majors introduced by round 1 — a focus-dependent tab-bar
hide lost the first tap on a button when the keyboard was up (fixed with a compact 44px icon bar
at ≤560px height), and the sticky error hint covered the control a keyboard user tabbed to (fixed
with extra scroll-padding while a hint shows). Round 3: no blocker or major; three minors fixed in
the same commit (a 2px mark on the current tab of the compact bar, 44px compact tabs, focusable
scrolling logs).

## Pentest (`.claude/agents/pentest-new-code.md`), three passes

Pass 1: nothing Critical/High/Medium. Two Low regressions, phone layout only: the admission sheet
docked exactly over the fixed tab bar and was clickable while still transparent, so a tap aimed at
a tab as a knock arrived could admit the knocker (PoC: a `touchscreen.tap` at the Chats tab's
pre-knock centre admitted); and relay refusals on steps 1–2 rendered under the tab bar. Info: mask
icons in forced-colors, the safety number wrapping 4+4+2 at 320px, no focus into the sheet.
Pass 2: both closed. One new Low — the 500 ms guard was not re-armed when the owner revealed the
prompt by switching back to the Live tab (fixed: `armAdmitGuard()` shared by `showNextKnock` and
`showView`); two hardenings (decide only the knock the prompt shows; use the event's own
timestamp); and mutation tests showing the first e2e addition could not tell the CSS layer from the
JS guard (fixed: separate assertions, each killed by its own mutant). Pass 3: one Low — a prompt that arrived while the page was hidden was armed at arrival, so the
window-activating click on return could decide it (fixed: re-armed on `visibilitychange` /
window `focus`, with a background-return e2e check); the PT4a/PT4b hardenings got their own
checks (head swap via an in-page WebSocket wrapper, a back-dated CDP touch). Pass 4: no open
findings; the buttons cannot be left dead by focus churn. Verdict at commit 2bbc64d: "admission
prompt verified against tap-through, pre-prompt taps, view-switch, background-return and
head-swap with PoCs and per-check mutation tests; no open findings."

Pre-existing issues the pentest noticed, NOT changed here:
- `usersStatus("")` at the end of `renderUserList()` wipes `addContactFromHandle`'s messages,
  including "the fetched keys DIFFER…"; the row's red key-changed line still carries the signal.
- Chat-screen refusals raised with `hint()` just before `ws.close()` are erased by `clearHints()`
  when `onclose` returns to the room screen; only `closeHint` messages survive.
- Relay `error` frames reach `#hint` verbatim ("Server: …"): a relay-authored text channel in the
  UI (outside the gate it is shown; inside the gate it is now visually clipped, still announced).
- The `:8000` dev relay has no `SECURE_CHAT_DB`, so every e2e run writes throwaway accounts into
  `backend/accounts.db` (gitignored).
- The "Start a chat with a saved user" picker says "add users in the Users view first" also when
  every saved user already has an open chat.

## Phase 2 (behaviour changes; each needs its own design, e2e coverage and a pentest pass)

- Trust pill in the admission sheet and a verified state in the live-room header (one line of
  app.js each); focus trap for the sheet; keyboard access for chat rows; the key-changed suffix as
  a caption span; hide the empty fingerprint well when a knocker has no identity.
- One global unlock screen and Chats as the home view (see `direction-contract.md` for why not
  now); Start | Join control for the chat code; the encryption picker as a sheet; a 2-line code
  well; a contact detail screen; "re-verify or send anyway" on key change; typed confirmation for
  Forget identity; QR scanning; username on Profile; backup reminder; "Encrypted to <name>"
  placeholder; desktop two-pane chat.
