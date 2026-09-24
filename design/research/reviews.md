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

## Phase 2a — pre-existing bugs and the small app.js items

Scope: the four bugs the pentest had noticed and the six small behaviour items from the critics
(see the commit "client: phase 2a"). Reviewed by the same three reviewers. Design critic: all four
visual items read right, two nits taken (mono name in the sheet, "connected" neutral beside the
"verified" pill). Correctness/a11y critic: one major — focus dropped to body when the sheet
closed — fixed with focus restore and e2e checks; minors taken (focus after opening a row / Back,
`role="none"` on the chat list, e2e checks for the pill and the caption, two duplicate rules).
Pentest, three passes: nothing Critical/High/Medium; four Lows found and fixed with tests — two
more refusals were still erased on close; a relay-parked reason could relabel a close the client
started (closeWs()/clientClosing); "Leave chat" sat over the phone composer without the 500 ms
rule; frames processed after onclose could drop a refusal or carry a relay sentence into the
next session (handling is now tied to the frame's socket). Final verdict: no open findings;
the admission guard is byte-identical to the rework commit. Cosmetic, noted: a handler still
running for a closed socket can add its log line to the next session's log (harden with
`if (sock !== ws) return` after each await in handleMessage).

Still open for a later round: the store-refusal "Open anyway" path loses the invite-link notice
(handle still prefilled); B5's caption is not shown in the Users list because the row carries its
own key-changed sentence.

## Phase 2b — less text, "?" disclosures, one next step per screen

Scope: the owner's feedback after seeing the shipped rework ("still too much text; hide
explanations behind a ? and make the design lead to the right button"). Decisions in
`reviews/phase2b-brief.md`; visible words across the 20 captured states 1274 → 923. Design
critic: no blocker; five majors fixed (a lede that serves the guest too, help panels below the
field, the username row hidden once registered, two empty-state variants for Chats, Profile's
Forget as a quiet word) and the "?" wrap balanced. A11y critic: no blocker; one major fixed
(Forget must stay visible on the locked step 1), 44px "?" targets, a specific name per "?".
Pentest, two passes: every refusal, warning, relay and error text byte-identical; the admission
guard, trap and closeWs byte-identical; every decision point keeps its rule visible without
opening anything; Forget stays confirm-gated; one pre-existing Low fixed (a stale key-changed
sentence in #verifyHint on the next clean session). Final verdict: no findings; the new
username and Expecting toggles hide nothing a user needs.

## Phase 2 (behaviour changes; each needs its own design, e2e coverage and a pentest pass)

- One global unlock screen and Chats as the home view (see `direction-contract.md` for why not
  now); Start | Join control for the chat code; the encryption picker as a sheet; a 2-line code
  well; a contact detail screen; "re-verify or send anyway" on key change; typed confirmation for
  Forget identity; QR scanning; username on Profile; backup reminder; "Encrypted to <name>"
  placeholder; desktop two-pane chat.

## Contact profile (2026-09-23/24) — a saved user's short profile as a sheet

Scope: the owner's ask after testing 0.2.0 — tap a saved user's avatar or name in Users or Chats and
see a short profile (handle, fingerprint, and the rest). Decisions in `reviews/profile-brief.md`;
design on the Claude Design canvas ("Contact profile" row); triage per round in
`reviews/profile-fix-round-1.md` … `profile-fix-round-5.md`. Same three reviewers as the rework.

Design critic ("hot"): round 1 no — Message was the blue primary even when the key had changed
(B1), the fingerprint sat far from Verify, facts repeated the pill, no action on screen on short
phones, three reds. Round 2: B1 fixed, three new majors from the fixes (the sticky bar over the
fingerprint on short phones, a claimed-handle row with a lone Copy, Tab order ≠ screen order).
Round 3: "meets the owner's bar". Round 4 (regression check): one major at 320px (the pair wrapping
into two rows), fixed in round 4/5.

Correctness/a11y critic ("cold"): round 1 three majors (stale Chats trust marks after Verify from
the sheet, focus lost after Remove, a mail re-render dropping focus); round 2 one regression (the
sticky bar covering focus, 2.4.11) and a large mutant gap; round 3 two regressions (moving the
focused button dropped focus; "Message" spilling out of its button at 200% text); rounds 4–5
minors only (stale-tab refusal told the user to Forget their identity; reason not announced; CSS
side effects at 200%), all fixed.

Pentest (`.claude/agents/pentest-new-code.md`): never Critical or High. The trust core held from
pass 1 — Verify can only mark the keys whose fingerprint is on screen (refused when they move under
an open sheet), and a slow fingerprint never lands on another contact's sheet, each pinned by a
mutant. What the passes found was in the edges, and most of it in code the fix rounds themselves
added: a double click that verified then silently unverified (pass 1), a vouch the relay never
answers blocking every later Verify (pass 2), an aborted vouch that could still be published while
the UI said it was not (pass 3), and — the one Medium, pass 4 — round 3's "backstop" that retracted
any vouch of ours the relay listed for an unverified contact, which let a stranger's mail claiming a
friend's handle delete our real vouch for that friend. It was removed, not patched, and pass 5's
diagnosis (the retraction bookkeeping was keyed on our local label, the relay keys a vouch on the
directory name) drove round 5. contact-profile.mjs grew from 27 to 60 checks, each added check
proven against a mutant of the fix it guards.

Known and accepted (see the round files): a double click on a Users row opens the profile; the
Android back button does not close the sheet; Remove of a verified contact whose vouch was declined
still sends one DELETE (no persisted "vouched" bit); another tab re-vouching inside this tab's 20 s
delayed retraction; a 502 after the relay committed reads as "could not publish". A complete fix
for the last three needs a relay change (a DELETE naming the exact vouch).
