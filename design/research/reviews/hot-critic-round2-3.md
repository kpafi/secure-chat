# secure-chat rework: hot critic, round 2 (after fix round 1)

Screenshots: `rework-v2/*.png` (the official set), `rework-v2-warn/*.png` (the warning states, 320px, forced-colours and short-viewport captures), and `hot/shots2/*.png` (my own round-2 captures against the live client on :8000). I checked every v2 PNG at both sizes against v1 and the baseline, and read the CSS diff for the six deviations. Nothing in the repository was changed; the style experiments ran through `setBypassCSP` in a throwaway page.

## Verdict

**Yes, once the five small items at the end land. No BLOCKER remains.**
- **Phone:** it now reads as one product, not a stack of boxes. The chat screens have no app bar, the sections are flattened, the rows have avatars, and the warning states are the most considered screens in the app.
- **Desktop:** the wider chat window and the wordmark in the bar give it presence.
- **What still keeps it below the bar:** two MAJORs, both small, and three one-line regressions. None of them is structural.

## 1. Round-1 findings: status

| # | Status | Evidence | Note |
|---|---|---|---|
| B1 proceed-as-primary in warnings | **Fixed** | `rework-v2-warn/c-verify-changed-{phone,desktop}.png`, `d-admit-mismatch-{phone,desktop}.png` | Both actions are secondary and the safe one comes first. The "connected" pill goes neutral during the alarm, and the duplicate hint is gone. See R5 for an alignment nit. |
| B2 key-changed mark breaks header/rows | **Fixed** (deviation, accepted) | `h-convo-changed-{320,360,desktop}.png`, `g-chats-long-marks-*.png` | The name is never cut, the mark sits on its own line as a box, and rows are consistent. |
| B3 touch targets < 44px | **Fixed** | `rework-v2/12-chat-mode-proposal-received-phone.png` | Accept and Decline are 44px, and Decline is now neutral. |
| B4 content under the tab bar | **Fixed** | `rework-v2-warn/a-focus-probe-phone.png` | The focused Continue → stays clear of the tab bar (`scroll-padding`, style.css:159). |
| M1 phone chat chrome | **Fixed** (desktop part partly) | `rework-v2/10-*-phone.png`, `j-convo-keyboard-open-phone.png` | The log gets about 215 of 480px with the keyboard up (was 125). Desktop still shows the "SEALED" chip next to "SEALED (default)" (`rework-v2/12-*-desktop.png`). |
| M2 unlocked identity screen | **Fixed** | `rework-v2/03-*-{phone,desktop}.png` | Continue → is in the first phone viewport, and Forget is now a quiet text button. |
| M3 admission hierarchy / trust pill | **Partly** | `d-admit-mismatch-phone.png`, `rework-v2/16-*-phone.png`, `d-admit-noidentity-phone.png` | The hierarchy is fixed. The matched case is still plain text ("e2e-bob-ee5y8 — verified by you", no pill), and the no-identity case still shows an empty well holding "—". Both need the one-line app.js change; phase 2 is acceptable. |
| M4 list anatomy / Chats as form | **Fixed** | `rework-v2/09-*`, `g-chats-long-marks-*` | Avatars are in, and Open looks disabled while the picker is empty. |
| M5 red means three things | **Fixed on phone, regressed on desktop** | `rework-v2/08-users-unlocked-{phone,desktop}.png`, `f-users-changed-phone.png` | See R4. |
| M6 live-room topbar | **Desktop fixed; phone deviated** | `rework-v2/15-*-desktop.png`, `hot/shots2/m6-current-360.png` | Push back; see deviation 1 and R3. |
| M7 waiting states | **Fixed** | `rework-v2/14-*-phone.png`, `15-*-desktop.png` | The waiting message is centred, and the disabled send button is neutral. |
| M8 copy density / overlines | **Fixed** | `rework-v2/04-*`, `13-*`, `08-*`, `17-*` | The Why? disclosures and the overline/caption split work, and the session hint now sits under Sign out. Copy note: the username label lost "(optional)". The hint still says "Optional: …", but list the edit in the changelog. |
| M9 desktop presence / width | **Partly** (deviation) | `rework-v2/09-*-desktop.png` vs `10-*-desktop.png` | See deviation 5 (MAJOR-2). |
| M10 boxes in boxes | **Fixed** | `rework-v2-warn/b-06b-otp-tools-open-desktop-full.png`, `rework-v2/03-*`, `08-*` | |
| M11 primary placement | **Fixed** | `rework-v2/01,03,04-*-desktop.png` | Nit: the "Continue without an identity →" ghost text starts 16px inside the column edge. Fix with `#toRoom:not(.primary) { margin-left: calc(-1 * var(--sp-4)) }`. |
| m1 chat code | **Partly** | `rework-v2/04-*-phone.png` | Good on the phone, regressed on desktop (R1). |
| m2 placeholders | **Partly** | `rework-v2/04-*-phone.png` (fixed); `rework-v2/01-first-run-phone.png` | The passphrase placeholder is still cut at "…only y" with no ellipsis. |
| m3 green chips | **Fixed** | `rework-v2/13-profile-desktop.png` | |
| m4 locked card | **Fixed** | `rework-v2/07-*-desktop.png`, `21-*-phone.png` | |
| m5 legend | **Fixed** | `f-users-changed-phone.png` | |
| m6 handles | **Partly, with a regression** | `rework-v2/03-identity-unlocked-phone.png` | See R2. break-all works. |
| m7 peer/me labels | **Fixed** | `rework-v2/19-*` | |
| m8 orphans | **Fixed** | | |
| m9 QR centring | **Fixed** | `rework-v2/13-profile-phone.png` | Nit: the "Why?" under the centred QR is left-aligned. |
| m10 pill/control heights | **Fixed** | style.css | `--pill-h` and `--row-h` tokens; no 6px gaps left. |
| m11 duplicated recipes | **Fixed** | style.css | `.safety` on `#idFingerprint`, `.title-2`. |
| m12 `:has()` fallback | **Fixed** | style.css:1130 | |
| m13 background grid | **Fixed** | style.css | Removed. |
| m14 chat rows not keyboard-reachable | **Not fixed** | | Phase 2 (app.js). |
| Scoping reversals (phone wordmark bar, avatars, 880px chat) | **Done** | `rework-v2/10,14-*-phone.png`, `09-*`, `10-*-desktop.png` | |

## 2. The six deviations

1. **M6: Disconnect as an icon-only ghost on phones.** **Push back.**
   - The constraint is real: four 16px controls with "Copy room id" as text do not fit. But the wrong control lost its label. The exit from a live session is now a bare "leave" arrow, while the rarely used copy action keeps three words. That arrow is also the universal sign-out glyph, and this app has a separate "Sign out of directory" action, so the icon is ambiguous.
   - The current build has a second problem: at 360px and 320px, "waiting for approval" wraps inside its pill (36px tall; `hot/shots2/m6-current-360.png`). 360px is the most common Android width.
   - **Alternative (tested, `hot/shots2/m6-alt-390.png` and `m6-alt-360.png`):** make **Copy** the 44px icon. It sits right next to the id it copies, and its textContent "Copy room id" stays for e2e and screen readers. **Disconnect** keeps its word as a 16px ghost. At 390px and 360px this is one 56px row: id/status column about 140–170px, copy 44px, Disconnect 115px, and the status pill no longer wraps.
   - There is no `--i-copy` token yet; add one. The two-rect stroke mask I tested is in `hot/r2.mjs`.
   - Only below 360px do both become icons:
     ```css
     @media (max-width: 600px) {
       #copyRoom { width: var(--control-h); padding: 0; font-size: 0; --icon: var(--i-copy); }  /* + ::before mask */
       #disconnect { width: auto; padding: 0 var(--sp-3); font-size: var(--control-fs); }
       #disconnect::before { display: none; }
       #scrChat .topbar .status { white-space: nowrap; }
     }
     @media (max-width: 359px) {
       #disconnect { width: var(--control-h); padding: 0; font-size: 0; }
       #disconnect::before { display: block; }
     }
     ```
2. **M1: the tab bar hides only while a text field has focus.** **Accept.** The rule actually shipped is focus **and** `max-height: 560px`, which is better than mine. A 568×320 landscape phone keeps its tabs. On Android, when Back dismisses the keyboard but focus stays in the field, the viewport grows past 560px again and the tabs come back.
3. **B2: the conversation header wraps.** **Accept.**
   - In a normal chat the header is 2 rows (about 108px): name + pill, then the picker.
   - In a key-changed chat it is 3 rows (about 150px at 360px). That state is rare, and the name stays intact, which was the point.
4. **B1: the redundant #hint is clipped, not `display: none`.** **Accept.** This is correct: `aria-live` still announces it, and the clipped node reserves no height in any capture.
5. **M9: desktop forms (632px) start at the bar's left edge.** **Accept the left edge; push back on the width split.** This is MAJOR-2.
   - Opening a chat jumps the content from 632px (list) to 832px (conversation): `rework-v2/09-*-desktop.png` against `10-*-desktop.png`.
   - The right edges now differ by screen: 849px for forms and lists, 1048px for chat windows, 1036px for the tab row. That leaves a 200px dead band under the tabs on every list screen.
   - **Alternative:** lists are content, like the conversation. Give the Chats and Users lists (and their pickers) the full 832px, and keep the forms at 632px: the Live room steps, Profile and the locked cards.
     ```css
     @media (min-width: 1024px) {
       #viewChats, #viewUsers { max-width: none; }  /* 832 like the window */
       #viewChats .row, #viewUsers .row:not(.panel) { max-width: 632px; }  /* the add/pick rows stay form-width */
     }
     ```
     The exact selectors depend on how `max-width` is applied now. The rule is: the list and the window share both edges.
6. **Minor 1: `#room` keeps 16px, with a fade.** **Accept on phones.** On desktop, where all 64 characters fit, the fade hides the last 2–3 characters (R1).

## 3. Does it meet the owner's bar?

It meets the bar once this list lands. It is about 30 lines of CSS, and none of it is structural:
1. **MAJOR-1:** the live-room bar on phones (deviation 1). Swap the icon to Copy, keep "Disconnect" as a word, and add `white-space: nowrap` on the status pill.
2. **MAJOR-2:** desktop width consistency (deviation 5). The lists and the conversation should share the same 832px edges.
3. **R1:** scope `.code-row:not(:focus-within)::after` to `@media (max-width: 600px)`.
4. **R2:** take `#accountStatus.ok` out of the mono list (style.css:200).
5. **R4:** the Users desktop row layout.

Worth doing, not required for the bar:
- The trust pill in the admission sheet's matched case (M3; one line in app.js).
- Drop the duplicate "SEALED" chip on desktop:
  ```css
  @media (min-width: 601px) { .convo-head #chatMode { display: none; } }
  ```
- **New, not raised in round 1:** after the gate is passed, the live-room header still shows only "connected" (`rework-v2/19-*`). Verification is not visible where the user looks. This needs one line in app.js, `els.scrChat.dataset.verified = ""` in `unlockMessaging()` and removed on disconnect. The status dot can't be keyed off `#text:not(:disabled)`, because passphrase and one-time-pad sessions enable sending without any verification. Then:
  ```css
  #scrChat[data-verified] #chatStatus.ok::before { --icon: var(--i-shield-check); … }  /* swap the dot for a shield-check */
  ```
- **Forced colours:** the active tab is only a faint pill (my capture, `hot/shots2/fc-live.png`). Add:
  ```css
  @media (forced-colors: active) {
    .tabbar .navitem[aria-current="page"] { color: Highlight; outline: 2px solid Highlight; outline-offset: -6px; }
  }
  ```
  The sent bubble's border does render in the current tree. The coordinator's `forced-live-chat-phone.png` shows none, which suggests it was captured before that line.

## 4. Regressions the fixes introduced

- **R1: the chat-code fade on desktop.** The gradient over the end of `#room` is unconditional, so on desktop, where the whole 64-character code fits, it fades out "…3237**d0**" (`rework-v2/04-room-setup-desktop.png`, `b-06b-otp-tools-open-desktop-full.png`). Fix: phone-only media query.
- **R2: prose in mono.** My m6 advice ("set `#accountStatus.ok` in mono") was wrong. The whole status sentence is now 4 lines of monospace on the phone: "Registered. Your contact handle is … — share it (username alone will not resolve)." (`rework-v2/03-identity-unlocked-phone.png`). Revert to sans; only a `<span>` holding the handle should be mono (phase 2).
- **R3: the status pill wraps on phones at ≤360px.** `#scrChat .topbar .status { white-space: normal }` survived into the phone rule, so "waiting for approval" breaks inside its pill (`hot/shots2/m6-current-360.png`). This is the same bug v1 had on desktop. It is fixed by deviation 1's alternative.
- **R4: the Users row on desktop.** The new right-hand actions column stacks "Unverify" over "Remove" and narrows the text column to about 340px. The trust pill now floats mid-row (x≈478–628), and the 8-group fingerprint wraps to two lines on a 632px column (`rework-v2/08-users-unlocked-desktop.png`). Fix: drop the ≥601px two-column rule and keep the phone anatomy, with actions right-aligned on their own line under the fingerprint. Alternatively, put the actions in a row on the head line:
  ```css
  .u-actions { grid-column: 2; grid-row: 1; flex-direction: row; }
  ```
  with the pill after them.
- **R5: gate alignment on desktop.** My "left-align the gate hint" advice produced a centred title over a left-aligned 4-line paragraph (`rework-v2-warn/c-verify-changed-desktop.png`, `rework-v2/17-*-desktop.png`). Keep left alignment on phones, where the paragraph spans the full width. On desktop:
  ```css
  @media (min-width: 601px) { .gate .row > .hint { text-align: center; text-wrap: balance; } }
  ```
- **Nit: the phone live bar sits tight to the top edge.** The room id's cap height starts about 8px from the top, while the side gutter is 16px (`rework-v2/14-*-phone.png`). Use `#scrChat .topbar { padding-top: var(--sp-2) }`.

## Round 3 (final check)

Checked 04, 08, 09, 10, 13 and 14–19 at both sizes in `rework-v3/`, plus the fixer's `fix2/q/` captures (bars at 320, 359, 360, 390 and 1280; the compact bar at 568×320 and 360×400).

**Verdict: yes, it now meets the owner's bar.**

What landed:
- **M6:** as proposed. `fix2/q/bars-phone.png` and `rework-v3/15-*-phone.png` show one 56px row, the pill never wraps, and both controls become icons below 360px.
- **M9:** lists and the conversation share 832px, with one left edge (`rework-v3/09`, `10`, `08-*-desktop.png`).
- **R1, R2 and R4:** fixed (`rework-v3/04-*-desktop.png`, `08-*-desktop.png`).
- **R5:** the desktop gate is one left-aligned 30rem column, and the safety-number band stays centred (`17-*-desktop.png`). Accepted.
- **Compact bar:** the 44px icon-only tab bar at ≤560px height is a good trade (`fix2/q/short-live-568x320.png`).

**Regressions from round 2:** none found.

Small leftovers, not blocking:
- On the phone, the gate still pairs a centred title with a left-aligned paragraph (`rework-v3/17/18-*-phone.png`). Left-align the title too:
  ```css
  @media (max-width: 600px) { .gate .row > label { text-align: left; } }
  ```
- The admission sheet's matched case is still plain text (`rework-v3/16-*-phone.png`).

**What I would change first in a follow-up:** give trust one visual voice in the live room. Two places still state trust in plain text or not at all: the admission sheet ("e2e-bob — verified by you" as text) and the live header after the gate ("connected" only). Both need one line of app.js (the `u-mark` classes on `#admitWho`, and `data-verified` on `#scrChat`), then CSS that reuses the existing pill and shield-check.
