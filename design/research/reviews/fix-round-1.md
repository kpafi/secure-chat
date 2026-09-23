# Fix round 1 — orchestrator's triage of the three reviews

Source reviews: reviews/hot-critic.md (design), reviews/cold-critic.md (correctness/a11y), the pentest
report (security). This file is the DECISION: what to fix now, what is deferred, and the guard rails.

## Guard rails (unchanged from direction-contract.md)
- CSP, ids, e2e-pinned strings, byte-identical import map, no inline styles, `[hidden]` wins.
- app.js: ONLY the two additions allowed below. Everything else stays CSS / static markup.
- Every change re-proven: npm test, pytest, the four e2e runs, e2e/screenshots.mjs (20 states, empty
  overflow section). If a change breaks screenshots.mjs navigation at phone width (tab bar hidden
  inside a conversation), fix the SCRIPT (use #chatBack / navigate at desktop width), never the rule.

## Allowed app.js additions (each ≤2 lines, security-neutral)
1. Avatar initials: in renderUserList() and renderChatList(), `li.dataset.initial = username[0]`
   (username is already validated / a local key-derived label; CSS `content: attr(data-initial)`).
2. Nothing else. In particular: no focus management, no new handlers, no DOM restructuring.

## Hot critic — accepted, fix now
- B1 warning states: demote "proceed" (#verifyOk under .gate.changed, #admitOk when #admitWarn.err
  is non-empty) to a secondary; safe action first; no green glow on the status pill during an alarm;
  hide the redundant bottom #hint while the gate is up. CSS only (the `:has` selectors the critic gave).
- B2 key-changed mark: box shape, own full-width row in .u-head and .convo-head, never truncate the
  contact's name (min-width on #chatPeer, the mark spans the row). CSS only — no span in app.js.
- B3 pending buttons ≥44px / 16px on phone; Decline not styled as danger.
- B4 `scroll-padding-top/bottom` on html for both bars.
- M1 phone chat chrome: tab bar hidden while #chatConvo is open (back button exists) and at
  max-height 560px (keyboard); drop the duplicate #chatMode chip on phone (the select IS the chip);
  composer hint one line unless .err. Also apply the same "chrome diet" to the live room #scrChat on
  phone: one-row topbar (see M6).
- M2 unlocked identity: hide the pitch title and the duplicate wordmark tile after unlock; overline
  becomes the title; success line quiet; Forget last as a quiet button; on first run the step line
  comes after the welcome (order).
- M3 admission sheet: warning box directly under the title (err tint, 15px), #admitWho quieter,
  no fake grab handle. CSS only.
- M4 lists: avatar discs via data-initial (allowed app.js change above); #chatStart secondary in
  index.html and visually disabled when the picker has only its placeholder option.
- M5 Users: Remove as a quiet ghost (red only on hover); one alert per key-changed row; desktop rows
  with actions in a right column.
- M6 live topbar: phone one row (Copy room id as a small ghost — keep its TEXT visible, it turns into
  "Copied ✓"; Disconnect as a quiet ghost), desktop status `nowrap`, room chip never double-ellipsized.
- M7 waiting state: centre the last system line in an otherwise empty log; disabled send reads as
  disabled (panel-2, muted), not "pressed".
- M8 copy: second sentences behind a static `<details class="why"><summary>Why?</summary>` (Room ×2,
  Profile QR); Sign-out hint placed after Sign out; "optional" not twice; verify hint left-aligned,
  13px, max 46ch; overlines that wrap → split at the em dash into overline + sentence-case caption
  (words unchanged). Check every touched element against e2e greps first (#roomHelp, #accountStatus).
- M9 desktop: chat windows 880px (forms stay ~640), wordmark 17px in the bar with the lock tile at
  24px before it; drop the hero tile.
- M10 boxes: #otpPanel, #account, .myhandle become hairline-separated sections, not cards; #otpTools
  one level only.
- M11 forward action always on the column's left edge on desktop.
- Minors 1–13: all accepted. Specifically: delete the background grid (keep the glow); `@supports not
  selector(:has(*))` scrim fallback for the sheet; `#idFingerprint` uses .safety; one pill recipe
  (24px, sp-3/sp-2 padding, sp-1 gap; 20px only for inline badges); control heights 44 (40 desktop),
  rows 56; text-wrap: pretty/balance; chips neutral with a green dot; locked card full width; legend
  as grid; handles mono + break-all; hide `.who` labels in the live log; QR centred on phone;
  placeholders in the ui face; `#room` fades instead of cutting glyphs.
- Scoping reversals accepted: phone wordmark bar is `position: static` and hidden inside chat windows.

## Hot critic — deferred to phase 2 (needs app.js behaviour)
- Focus on Deny in the mismatch case; keyboard access for chat rows; the mark suffix as a caption
  span; hiding the empty fingerprint well when there is no key; a 2-line textarea for the code.

## Cold critic — see the appended section (added when the report arrives)

## Pentest — see the appended section (added when the report arrives)

## Pentest — accepted, fix now (these override the "CSS only" rule where stated)
- P1 (Low, top priority) tap-through admission on phones: the sheet docks over the fixed tab bar and
  is clickable while still transparent. Fix all three:
  (a) CSS: `.sheet { inset: auto 0 var(--tabbar-space); }` (never over the bar; the strip above the
      bar is covered by the inert scrim only) and no pointer events on the sheet while its entrance
      animation runs (`.sheet { pointer-events: none } .sheet.ready / after animation { auto }` is NOT
      possible without JS — use the app.js guard below instead, plus `animation-fill-mode` so the
      sheet is not transparent-but-clickable).
  (b) app.js (ALLOWED, security-motivated, keep it to ~6 lines): in showNextKnock(), record
      `admitShownAt = performance.now()` whenever the prompt becomes visible or the knock at the head
      of the queue changes; in the #admitOk / #admitNo click handlers ignore the click when less than
      500 ms have passed (the user can click again). Comment it with the pentest reference
      ("2026-09-22 rework pentest, tap-through under the tab bar").
  (c) e2e/room-admission.mjs: add a 390×844 touch-viewport pass that, right after the knock appears,
      taps the Chats tab's pre-knock centre and asserts the knocker was NOT admitted, then waits ≥600
      ms and admits normally. Existing steps that click #admitOk/#admitNo immediately after the
      prompt appears must wait ≥600 ms first (that is a timing adjustment, not a weakening).
      Also do the same in e2e/screenshots.mjs if it admits right after the prompt.
- P2 (Low) refusal/warning hints under the tab bar or below the fold on phones (`#idHint`,
  `#roomHint` with `.err`): sticky above the bar (`position: sticky; bottom: calc(var(--tabbar-space)
  + var(--sp-2)); background: var(--bg)`), plus `html { scroll-padding-bottom }` (same as hot B4).
  e2e/hostile-relay.mjs: at a 390×844 viewport assert `document.elementFromPoint` at #roomHint's
  centre is #roomHint (or inside it) after the refusal.
- P3 (Info) forced-colors: `@media (forced-colors: active)` → every mask-icon pseudo-element gets
  `forced-color-adjust: none; background: CanvasText`.
- P4 (Info) 320px: the safety number must wrap 5+5 at 320px too (smaller font below 340px) — never
  4+4+2, which looks like a fingerprint.
- P5 (Info) the sheet: static `role="dialog" aria-modal="true" aria-labelledby="admitTitle"` on
  #admit in index.html; in app.js (ALLOWED, 1 line in showNextKnock after the prompt is shown):
  `els.admitNo.focus()` so keyboard users land on the safe action (an Enter already in flight denies,
  never admits; the 500 ms guard applies to keyboard activation too since it goes through the same
  click handler).
- Coverage: e2e/no-dead-ends.mjs's "the tab bar marks the current view" must switch to another view
  and assert aria-current MOVES (index.html hardcodes it on the first tab, so a load-time check
  cannot fail). Remove the hardcoded `aria-current` from index.html (showView sets it on first paint).
- Pre-existing issues the pentest noticed (NOT this round; report to the owner): usersStatus("") at
  the end of renderUserList() wipes addContactFromHandle's messages including "the fetched keys
  DIFFER…"; chat-screen refusals raised with hint() before ws.close() are erased by clearHints() on
  onclose; the :8000 dev relay writes e2e accounts into backend/accounts.db.

## Cold critic — accepted, fix now (overlaps noted)
- C-B1 pending buttons 36px/13px → same as hot B3.
- C-M1 focus under the tab bar → same as hot B4 / pentest P2 (`scroll-padding` both ends).
- C-M2 tab bar covers the composer on short viewports: `min-height: 0` on the log/window rules at
  ≤600px, and hide the tab bar at `max-height: 560px` (hot M1) — covers 360×400 and 568×320 landscape.
  Verify at 360×400 and 568×320 that the composer is fully visible.
- C-M3 focus into the sheet → pentest P5 (focus Deny; role/aria-modal).
- C-M4 forced-colors → pentest P3, plus icon-only buttons (back, send) get `ButtonText` so they are
  not empty in high-contrast mode; any button whose text is visually hidden must keep an accessible
  name (aria-label or visually-hidden text) — check the back and send buttons.
- Contrast minors: `.badge.pq` on a hovered/selected encryption row (4.4:1) and the unverified
  `.u-mark` on a hovered chat row (4.44:1) — lighten the hover tint or the text so both reach 4.5:1;
  re-measure with the cold critic's script (scratchpad/cold/).
- 320px: the long trust pill must not clip (hot B2 makes it a wrapping box).
- 130% system text: "Continue without an identity →" must wrap/shrink instead of leaving the viewport
  (`min-width: 0; white-space: normal` on `.nav` buttons; test with `page.emulateMediaFeatures` or a
  1.3 font-size on html).
- Hygiene: remove the redundant rule the cold critic named; keep `.mono` (documented hook).
- Note: the cold critic's pytest hang in test_ws.py did not reproduce for the implementer, the
  orchestrator or the pentester (162 passed each time, ~23 s) and backend/ is not in the diff; treat
  as an artefact of its parallel relays, but run pytest once more at the end.
