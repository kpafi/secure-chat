# Cold critic: round 2 (re-check after fix round 1)

This review re-checks the same uncommitted working tree, now with fix round 1 applied: 9 files changed, +2216/−692 against HEAD f39751c. Every number below is freshly measured on the current tree. Nothing is re-quoted from round 1.
No repository files were modified. Tools and raw output are in `scratchpad/cold/` (the round-2 outputs are in `scratchpad/cold/r2/`).

- **The harness.** `cold/audit.mjs` was rebuilt from the current `e2e/screenshots.mjs`, which now includes its 600 ms pause before admitting.
  - Usernames are padded to 32 characters, and CSP listeners are attached at document start.
  - The probe library is `cold/audit-lib.mjs`. Two probes are new this round:
    - **`sheetWalk`**: where focus is when the admission prompt appears, and where Tab goes from there.
    - **`fieldFocusProbe`**: runs at 360×400, 568×320 and 390×844 on 10 states. For every visible text field it focuses the field, walks Tab and Shift+Tab out of it, and clicks every visible button at the position that button had while the field was focused. A capture-phase listener records which element the click actually reaches and swallows the event.
  - Output: `cold/r2/audit-out/audit.json` (20 states, 294 s).
- **The server.** The relay on :8000 serves the working tree: the md5 of `/`, `/style.css` and `/app.js` equals the files on disk.
- **Isolation.** Every run below (pytest, e2e, audit) was started with no other browser or test process running.

---

## Checklist

| # | Area | Round 2 |
|---|------|---------|
| 1 | CSP | **PASS** |
| 2 | Structure (ids, `els`, `[hidden]`) | **PASS** |
| 3 | Contrast (new pairs included) | **PASS** |
| 4 | Accessibility | **FAIL**: N2 (the sticky refusal hint hides the focused control); N1 also affects touch |
| 5 | Layout robustness | **FAIL**: N1 (the first tap on Send, Connect and others is lost while a text field has focus on a short viewport) |
| 6 | app.js behaviour | **PASS** |
| 7 | e2e edits and runs | **PASS** (5/5 runs, pytest 162/162, npm test OK) |
| 8 | Android WebView | **PASS** with notes |
| 9 | Stylesheet hygiene | **PASS** with notes |

### 1. CSP: PASS
- **Static checks on `index.html`.** 0 `style=` attributes, 0 `<style>` elements, 0 `on*=` handlers, 0 `http(s)://` URLs.
- **Static checks on `style.css`.** 14 `url(` occurrences, all `data:image/svg+xml` (the new one is `--i-leave`). The only `http` strings are the SVG `xmlns`. No `@import` or `@font-face`. The `app.js` diff adds no `.style`, `innerHTML` or `insertAdjacentHTML`.
- **Import map.** The line is byte-identical to HEAD (`cmp`). Its hash `sha256-6Sm2nhNvoa7gr7uuY2hbAbpdWhIlL15/wXLm4dhO9UQ=` equals `backend/main.py` and the served CSP header.
- **Headless.** 0 `securitypolicyviolation` events across 20 states and 3 agents.
  - The only console or network errors are `404 /favicon.ico` (pre-existing).
  - axe-core ran 40 times (20 states × 390/1280) with 0 violations.

### 2. Structure: PASS
- **Ids** (`cold/ids.py`). HEAD has 145 ids and the working tree has 143, with no duplicates. Missing: only `drawer`, `menuBtn`, `scrim`. Added: `tabbar`.
- **`els` map.** All 136 entries and every `$()`/`getElementById` id in app.js resolve.
- **`aria-current`.** It is no longer hard-coded in `index.html` (0 occurrences). At all 20 states the attribute is on exactly one tab and matches the visible view.
- **`[hidden]`.** The only `display … !important` is `[hidden]` (style.css:152); the other `!important` is `.vh` (:209).
  - The sweep set `hidden` on every element at 8 states (268–322 elements each): 0 kept a display other than `none`.
  - The 21–30 elements already hidden per state: all computed `none`.
- **Pinned strings.** All 14 e2e-pinned strings have the same occurrence counts in HEAD and the working tree.

### 3. Contrast: PASS
Sources: `cold/contrast2.py`, which is round 1's token script plus the new pairs (`cold/r2/contrast.txt`), and a `getComputedStyle` spot check on the live page (`cold/r2/computed.txt`, which matches the tokens).
- **New text pairs, lowest first:**

  | Pair | Ratio |
  |---|---|
  | Pending Accept, white on `#1f6feb` | 4.63 |
  | `#chatStatus` muted during an alarm | 4.84 |
  | `.badge.pq`, untinted, on a selected row | 5.09 (was 4.39) |
  | `.u-mark` unverified, untinted, on a hovered chat row | 5.15 (was 4.44) |
  | Quiet ghost buttons (Remove, `#copyRoom`, `#gen`, Copy invite): `--muted` | 5.58 on panel / 6.15 on bg |
  | "Why?" summary and caption | 6.15 |
  | Muted success line `.hint.ok` | 6.15 on bg / 5.58 on panel |
  | Wrapped key-changed box `.u-mark.changed` | 7.11, or 6.51 on a hovered row |
  | `#admitWarn` error box | 7.67 |
  | Sticky refusal hint | 8.55 |
  | `#idForget` (quiet danger) | 9.40 |
  | Pending Decline (secondary) | 10.95 |
  | Avatar initials | 11.78 (17px and 24px) |
  | Chips (on) text | 14.08 |
  | Chips (off) | 6.15 |

- **New icons:** the green dot on chips 7.45, the success check 6.75–7.45, the Disconnect icon 5.58 (7.86 on hover), and the disabled send arrow 5.15.
- **Report only:**
  - `#chatStart` in its "looks disabled" state (opacity .45): 3.66.
  - Disabled primary: 3.34–3.50. Disabled placeholder: 2.66 (unchanged).
- **Informational non-text:**
  - Outline of the key-changed box: 2.26. Outline of the sticky hint: 1.80.
  - Disabled send disc against the window: 1.08 (its icon is 5.15).
  - In each case the text or icon carries the meaning.

### 4. Accessibility: FAIL
- **Focus visible: PASS.**
  - 45 keyboard walks (15 states × 320/390/1280, real Tab key, read 180–260 ms after each press): 0 stops without a 2px ring, 0 traps, and every walk closes both forwards and backwards.
  - In forced colours, inputs now show a solid 2px outline (round-1 m7, input part fixed).
- **Focus under a bar: PASS for the bars themselves (round-1 M1 fixed).** 0 stops were covered by the tab bar or the top bar in the 45 walks. In round 1 there were 7.
  - The desktop step headings stay visible after scrolled navigation (`cold/r2/layout-scripts.txt`).
- **Focus under the sticky refusal hint: FAIL (N2).**
- **Admission sheet (round-1 M3): partly fixed.**
  - Focus lands on Deny, with a ring. The sheet has `role="dialog"`, `aria-modal="true"` and `aria-labelledby`.
  - Tab from Deny at 390 and 1280: BODY, then the 4 tabs, `#copyRoom`, `#disconnect` (each covered 5 of 5 points by the scrim), then back into the sheet at the fingerprint, Let them in, Deny. Focus is not contained, by decision; see n3.
- **While a text field has focus on a short viewport** (360×400 and 568×320; the tab bar is display:none then):
  - The focused field is never covered (0 of 5 points, 44 field/viewport cases).
  - Hidden tabs are out of the tab order, which is correct.
  - But Shift+Tab from the first field of a screen (`#idPass`, `#room`, `#usersUnlockPass`) goes to BODY and skips the tabs (n2). Tab forwards brings the bar back.
  - At 390×844 the bar never hides.
- **Touch targets ≥44px (round-1 B1): PASS.** 0 controls below 44×44 at 320 and 390. The pending Accept/Decline buttons are now 44px tall at 16px.
- **Font ≥16px on phone.** Every input, select and button is ≥16px except the 12px tab labels (as specified) and the `font-size:0` icon buttons (`#send`, `#chatSend`, `#chatBack`, `#disconnect`), which are named by their text or `aria-label`.
- **`prefers-reduced-motion`: PASS.** Under `reduce`, buttons go to `0s all`; the screen and view `rise` and the sheet `sheet-in` animations become `none`; the chevrons go to `0s`. A sweep found no animated element.
- **Forced colours (round-1 M4): fixed.**
  - Every mask icon now computes CanvasText or ButtonText (black). The back and send buttons show their icon; the disabled send shows GrayText.
  - The trust dots are invisible, as documented. The trust words remain.
  - Still open (pre-existing): the checked algorithm row is not indicated (its radio mark computes `bg transparent, image none`).

### 5. Layout robustness: FAIL
- **No horizontal overflow: PASS.** Measured at 20 states × {320, 360, 390, 600, 601, 640, 768, 1024, 1280} + 640@2x + 568×320, with 32-character usernames.
- **Long text: PASS.** Injected 32-character names, 99-character handles and a two-name "vouched by … key CHANGED" pill fit at 320/360/390/640 in the users, chats, conversation, pending, profile, admission and live states. The trust pill fits at 320 (287 ≤ 303).
- **Long unbreakable handle (round-1 m4): fixed.** In `#accountStatus`, `scrollWidth == clientWidth` at 320, 360 and 390.
- **Enlarged text: PASS at the tested sizes (round-1 m3 fixed).** Scaling the six size tokens and `--control-fs` to 130%, 150% and 200% at 360 and 390 on first-run, identity-unlocked and room-setup puts no control off-screen and causes no overflow.
  - The new residual is n5 (200% text at 640 in the desktop layout).
- **Composer: fully visible (round-1 M2 geometry fixed).**
  - 568×320, no focus: `#sendForm` spans [187..256] and the tab bar top is 256.
  - 360×400, no focus: Send spans [251..295] and the tab bar top is 336.
  - With the field focused (tab bar hidden): `#text` spans [344..388] at 360×400 and [274..318] at 360×330.
  - Chat conversation at 568×320: `#chatForm` spans [230..299] (no tab bar in a conversation).
  - **But the way it switches causes N1.**
- **Long live log** (120 lines, `cold/longlog.mjs`): the page does not scroll, the log scrolls inside the window, and the last line ends above the composer at 320×568, 360×640, 390×844, 601 and 1280.
- **`env(safe-area-inset-bottom)`.** With CDP insets of 34: the tab bar grows 64→98px and `main` padding-bottom 88→122px. The tab button now sits inside the bar (781..844; round-1 m10 fixed).

### 6. app.js: PASS
Every `+` line that is not a string or comment was listed.
- **Beyond round 1 there are exactly the allowed additions:**
  - `li.dataset.initial = …charAt(0)` in `renderUserList` and `renderChatList`.
  - `admitShownAt` / `admitShownFor`.
  - In `showNextKnock`: `fresh` → reset the timer and `els.admitNo.focus()`.
  - The two admit/deny listeners gated on `performance.now() - admitShownAt >= 500`.
- **The 500 ms guard is sound.**
  - The timer resets only when the prompt opens or its head knock changes, not when the queue grows.
  - Keyboard activation goes through the same handler.
  - During the entrance, `pointer-events` computes `none` for 0–201 ms and `auto` from 263 ms (`cold/r2/sheetpe.txt`); hit-testing "Let them in" returns `#scrChat` until then.
- Edge cases: n6.

### 7. e2e: PASS
- **Removed lines.** Only the drawer checks and `#menuBtn` clicks. `agent(label)` and `setViewport(1000×900)` were replaced by a parameter with the same default, so nothing else was weakened.
- **Added checks:**
  - no-dead-ends: "the current-view mark moves with the view".
  - room-admission: 3 phone checks.
  - hostile-relay: the phone hit-test on the hint.
  - The pauses of 600 ms or more before admit/deny in room-admission, all-modes and screenshots are needed because of the guard. A pause before a click cannot make a check pass that would otherwise fail.
- **Runs, sequential and alone** (`cold/r2/e2e-*.log`):

  | Run | Result | Time |
  |---|---|---|
  | two-user-flow | 8/8 | 31 s |
  | room-admission | 16/16 | 17 s |
  | no-dead-ends | 17/17 | 10 s |
  | hostile-relay | 12/12 | 9 s |
  | all-modes | 32/32 | 18 s |

- **`e2e/screenshots.mjs`** (unmodified, `cold/r2/screenshots.log`): 20/21 captured, 1 allowed skip (02-drawer-open), 40 PNGs, no overflow notes, exit 0.
- **pytest, run once in isolation:** 162 passed, 2 warnings, in 23.05 s (23.4 s wall clock). The slowest test is `test_approval_timeout_drops_a_silent_waiter` at 10.02 s. My round-1 hang did not reproduce, so it was an artefact of my own parallel browser runs.
- **Client `npm test`:** 119 OK lines, 0 failures, 47 s.

### 8. Android WebView: PASS with notes
- **`:has()` use has grown from 16 to 43 selectors.**
  - Below Chromium 105 the chrome rules do not match: the tab bar stays inside conversations, the wordmark bar stays in chat windows, and the focus-hide rule is inert.
  - The new `@supports not selector(:has(*))` box-shadow scrim covers the sheet in that case.
- **New features, all progressive:**
  - `field-sizing: content` (Chromium 123): falls back to `width:auto`.
  - `@supports selector()` (Chromium 83).
  - `content: attr() / ""` alt text.
  - `text-wrap: pretty`.
  - Discrete `pointer-events` in `@keyframes`: verified on 141, older WebViews unverified. The app.js guard is the backstop.
- **Unchanged:**
  - Every `mask` is paired with `-webkit-mask`, `backdrop-filter` with its `-webkit-` form plus a solid fallback.
  - `background-attachment` appears only in a comment (:164).
  - `android/` and `backend/` are unchanged against HEAD. `app_bg #0D1117` / `app_fg #D8DFE7` equal `--bg` / `--fg`.

### 9. Stylesheet hygiene: PASS with notes
- **Dead selector:** `.mono` (kept as a documented hook, by decision).
- **Round-1 duplicates are gone.** `.locked::after`, `.wordmark .sub`, and the two identical label blocks (now `.title-2`) are all resolved.
- **New duplicate blocks** in the same context: `.userlist > li > .u-actions` (:826 and :874) and `#viewChats:has(…)` inside `@media (min-width:601px)` (:1848 and :1862).
- **`!important`:** 2 (justified).
- **Font sizes:** all `--fs-1..6`, `--control-fs`, or 0.
- **Colour literals outside `:root`:** 0.
- **Weight:** 73,392 B, gzip 20,257 B, 2,019 lines. Round 1 was 55,251 / 14,875; HEAD was 21,575 / 6,334. Comments are 22,828 B (31%).

---

## Round-1 findings: status

| Round 1 | Status now | Evidence |
|---|---|---|
| B1 pending buttons 36px/13px | **fixed** | 0 targets below 44 at 320/390; 16px |
| M1 focus under the tab bar | **fixed** | 0 of 45 walks had a stop covered by a bar |
| M2 tab bar over the composer on short viewports | **geometry fixed, mechanism regressed** | see N1 |
| M3 sheet focus | **partly** | focus on Deny, dialog semantics; not contained (by decision), n3 |
| M4 forced-colours icons | **fixed** | CanvasText/ButtonText; back and send visible |
| m1 contrast 4.39/4.44 | fixed | 5.09 / 5.15 |
| m2 pill clipped at 320 | fixed | 287 ≤ 303 |
| m3 130% text off-screen | fixed | 130/150/200% clean at 360/390 |
| m4 `#accountStatus` overflow | fixed | sw = vw |
| m5 gate hides the aria-live log | open | style.css:1605 unchanged |
| m6 "keys DIFFER" status without an error cue | open | app.js:1276 (outside the contract) |
| m7 forced colours | partly | input ring fixed; checked radio still not shown |
| m10 hygiene | fixed | two new duplicates (area 9) |
| m11 step-2 back button order | open | :1483, deliberate |

---

## Ranked findings (new this round)

### BLOCKER
None.

### MAJOR

**N1. On a short phone viewport (the soft keyboard is up), the first tap on a button is lost while a text field has focus. That includes the live room's Send button.**
- **Where:** style.css:1770–1775:
  `@media (max-width:600px) and (max-height:560px) { :root:has(:is(input…):focus) { --tabbar-space: env(…) } … .tabbar { display:none } }`.
- **Mechanism:** the layout depends on focus. Pressing a button moves focus off the field at mousedown or touch-down, so the rule stops matching. The tab bar returns, and the live-room window shrinks by 64px.
  - The button moves up under the finger (Send went from y 314–358 to 251–295 at 360×400).
  - The mouseup lands on something else, so `click` is dispatched to their common ancestor, `<body>`.
- **Measured with touch** (`cold/r2/tapsend.mjs`: real `touchscreen.tap`, isMobile/hasTouch, a two-agent verified live room):

  | Viewport | Click events after one tap on Send | Peer received after 1 tap | After a 2nd tap |
  |---|---|---|---|
  | 360×400 | `["BODY"]` | no | yes |
  | 568×320 | `["BODY"]` | no | yes |
  | 390×844 (bar never hides) | `["send"]` | yes | — |

  The typed text stays in the field and the tap does nothing.
- **Measured with a mouse** (`fieldFocusProbe`, `audit.json` `states.*.fieldFocus`). Lost clicks while a field has focus:
  - `#send` (live room; 360×400 and 568×320).
  - `#connect` while `#contact` or `#otpPass` has focus (360×400; 568×320 for OTP).
  - `#toRoom` ("Continue without an identity →") while `#idPass` has focus.
  - `#algSummary` while `#room` has focus (OTP state).
  - The row's "Unverify" and "Remove" while `#addHandle` has focus (568×320).
  - The async chat composer is not affected, because the tab bar is already hidden in conversations.
- **Not verified on a device.** It depends on Chrome's focus-on-mousedown for buttons, which applies to taps too.
- **Minimal fix (verified: the first tap sends, at 360×400 and 568×320):** delete the focus-dependent block (:1770–1775). Replace it with an unconditional compact bar at that size:
  `@media (max-width:600px) and (max-height:560px) { :root { --tab-h: 44px } .tabbar .navlabel { /* .vh clip */ } }`.
  With it, Send sits at 270–314 above a tab bar at 356 (360×400), and at 195–239 above 276 (568×320).

**N2. The sticky refusal hint (new, pentest P2) covers the control that has keyboard focus, including Connect (WCAG 2.2 SC 2.4.11).**
- **Where:** style.css:1507–1518 (`:is(#idHint,#roomHint).err:not(:empty) { position: sticky; bottom: calc(var(--tabbar-space) + 8px) }`) together with html `scroll-padding-bottom` (:160), which reserves only the tab bar.
- **Measured** (`cold/r2/stickyhint.mjs`): the refusal text is written to `#roomHint` exactly as `hint(msg, true)` writes it, then Tab walks step 2. Fully covered (5 of 5 points) under `#roomHint`:
  - 390×844: `#connect`.
  - 320×568: `#connect` and the "Why?" summary; `#copyCode`, `#gen` and `#algSummary` 2 of 5.
  - 360×640: `#contact` and "Why?".
  - 568×320: `#room`, `#contact` and `#algSummary`.
- Connect is the recovery action the hint tells the user to take.
- **Minimal fix (verified: 0 covered stops at all four sizes):** `html:has(:is(#idHint,#roomHint).err:not(:empty)) { scroll-padding-bottom: calc(var(--tabbar-space) + var(--sp-2) + 9rem); }`, or give the hint a max-height to match.

### MINOR
- **n1. (Number not used; n2–n8 are the minor findings.)**
- **n2. Shift+Tab skips the tabs on short viewports.** At 360×400 and 568×320, Shift+Tab from the first text field of a screen goes to BODY (out of the page), because the tabs are `display:none` at that moment. At 390×844 it reaches the Profile tab. Pressing Tab forwards brings the bar back. The unconditional compact tab bar from N1's fix removes this too.
- **n3. Admission sheet focus is not contained** (accepted by decision). Tab from Deny reaches 6 controls behind the scrim before returning.
  - `aria-modal="true"` tells assistive tech that this outside content is inert, but keyboard focus can still reach it.
  - In the warning state the visual order is Deny, then Let them in (`order:-1`, :1224), while the tab order is Let them in, then Deny.
  - `.gate.changed .stacked { flex-direction: column-reverse }` (:1223) has the same visual/DOM mismatch (WCAG 2.4.3).
- **n4. `#chatStart` only looks disabled.** With only the placeholder option it is `opacity:.45; pointer-events:none` (:1630), but it stays in the tab order and Enter still activates it. app.js ignores that without a pick, but the disabled look is not exposed to assistive tech.
- **n5. At 200% text size in the desktop layout (601px up to about 850px), the tab row overflows:** `scrollWidth` 842 in a 640 viewport, at every state. It is reachable by horizontal scroll. Fix: `.tabbar { flex-wrap: wrap }`, or icon-only tabs below about 860px.
- **n6. Deny-focus edge cases.**
  - If a second knock arrives after someone was admitted while the owner is typing in `#text`, focus jumps to Deny. After 500 ms an Enter denies the knocker (admit is disabled then, so this is safe) and the typed keystrokes are lost.
  - If the knock arrives while another view is open, `focus()` on the hidden Deny button does nothing, so focus is not on Deny when the user returns.
- **n7. Open from round 1:** m5, m6, m7 (checked radio in forced colours), m11, and the trust dots (informational).
- **n8. Hygiene.** Two duplicate blocks (area 9). Size is +33% gzip over round 1 and 3.2× HEAD. There are 43 `:has()` selectors, including `:root:has(…:focus)`, which restyles the whole document on every focus change (not measured).

## Reproduce
```
cd /home/user/secure-chat
C=<session scratchpad>/cold
python3 $C/ids.py; python3 $C/contrast2.py; python3 $C/hygiene.py
CHROMIUM=/opt/pw-browsers/chromium node $C/audit.mjs $C/r2/out          # 20 states: CSP, overflow, chrome, targets, keyboard, sheet, field focus + click-through, hidden, long text, zoom, axe, media
cd $C/r2 && node tapsend.mjs && node stickyhint.mjs && node computed.mjs && node sheetpe.mjs
cd $C && node zoomfix.mjs && node longlog.mjs && node stepfocus.mjs && node safearea.mjs
cd /home/user/secure-chat/backend && .venv/bin/python -m pytest -q -p no:cacheprovider --durations=5
```

---

# Round 3: final confirmation (after fix round 2)

## Setup
- **Tree state.** Working tree files have changed since round 2:
  - `style.css` has md5 4d5c197c; `app.js` has md5 a893cffd; `index.html` is unchanged.
  - The `app.js` change was not in the brief. The guard now uses `e.timeStamp` and also ignores clicks while `knockQueue[0] !== admitShownFor`. It is factored into `armAdmitGuard()`, and `showView("live")` re-arms it and moves focus to Deny when a prompt that arrived behind another view is revealed (this addresses round-2 n6). The code was read; no other behaviour changed.
  - room-admission grew from 17 to 27 `check(` calls.
- **Isolation.** Every run was started with no other test or browser process running.
- **Output.** `scratchpad/cold/r3/`.

## Results

| Item | Result | Evidence |
|---|---|---|
| N1 first tap while a field is focused | **PASS** | `r3/tapsend.mjs`, real `touchscreen.tap`, a two-agent verified live room. See N1 below. |
| N2 Tab walk with the refusal showing | **PASS** | `r3/stickyhint.mjs`: `#roomHint` (step 2) and `#idHint` (step 1) at 320×568, 360×640, 390×844, 568×320. `scroll-padding-bottom` computes 216px (196px at 568×320, where the tab bar is compact). **0 focused controls covered** at all 8 combinations. |
| Compact bar and icon-only controls: accessible names | **PASS** | CDP AX tree at 360×400, 568×320, 390×844: button "Live room" / "Chats" / "Users" / "Profile" (labels clipped with `.vh`, still in the tree). axe `button-name`: 0 violations in 60 runs (20 states × 390, 1280, 360×400), which covers `#send`, `#chatSend`, `#chatBack`, `#disconnect`. |
| Compact bar: icon contrast | **PASS** | Inactive icon `--muted` on the bar 6.15:1; active icon `--accent` on its pill 4.45:1. |
| Compact bar: active-tab state | **FAIL (minor)** | See r3-1. |
| Compact bar: touch target | **FAIL (minor)** | See r3-2. |
| ids / `els` | **PASS** | 143 ids: only `drawer`, `menuBtn`, `scrim` gone, `tabbar` added, no duplicates. 136/136 `els` entries resolve. |
| Import map | **PASS** | Byte-identical to HEAD (`cmp`). The hash equals `main.py` and the served header. |
| `[hidden]` | **PASS** | The only `!important` uses are `[hidden]` (:153) and `.vh` (:216). The sweep at 8 states (268–322 elements each) found 0 not `display:none`. |
| CSP | **PASS** | Static: 0 `style=`, `<style>`, `on*=` or `http` in HTML; 15/15 `url(` are `data:image/svg+xml`. Headless: 0 violations across 20 states (`r3/audit-out/audit.json`); only `favicon.ico` 404. |
| Duplicate blocks | **PASS** | 0 selectors declared twice in the same context. |
| e2e (because app.js changed) | **PASS** | two-user-flow 8/8, room-admission 26/26, no-dead-ends 17/17, hostile-relay 12/12, all-modes 32/32. `screenshots.mjs` flow inside the audit: 20/21, 1 allowed skip. |
| Rest of the audit | **PASS** | 0 overflow cases. 45 keyboard walks: 0 traps, 0 stops without a ring, 0 stops under a bar. The mouse click-through probe while a field is focused lost **0** clicks (round 2 lost 9). |

**N1 detail.** The tab bar is now always shown; at ≤560px tall it is 44px (top 356 at 360×400, 276 at 568×320). One tap on Send reaches `#send` and the peer receives the message:

| Viewport | Send at y | Result of one tap |
|---|---|---|
| 360×400 | 270–314 | click reaches `#send`; peer received |
| 568×320 | 195–239 | click reaches `#send`; peer received |
| 360×330 | 207–251 | click reaches `#send`; peer received |
| 390×844 (control) | 694–738 | click reaches `#send`; peer received |

## Remaining findings
No BLOCKER. No MAJOR.
- **r3-1 (minor, WCAG 1.4.1).** On the phone bar, the current tab differs from the others only by hue.
  - The active icon `#2f81f7` against the inactive `#8b949e` is 1.22:1. The active pill against the bar is 1.14:1.
  - In the compact bar the labels are hidden, so nothing else marks it. The 64px bar has the same hue-only label colour, and that has been true since round 1.
  - Impact is low: `aria-current` is set, and each view's title names it.
  - Fix: a shape cue like desktop's, e.g. `.tabbar .navitem[aria-current="page"]::before { content:""; position:absolute; top:0; inset-inline:30%; height:2px; background:var(--accent) }` (accent against the bar is 5.05:1). The active item also needs `position:relative` on phone.
- **r3-2 (minor, 1px under the contract).** In the compact bar each tab is 90×43 at 360 and 142×43 at 568: the 44px bar includes its 1px top border.
  - Fix (verified, 90×44): `--tab-h: calc(var(--control-h) + 1px)` in the ≤560px block.
- **r3-3 (minor, pre-existing).** axe `scrollable-region-focusable` at 360×400 on `#log` and `#chatLog`: a scrolling log with no focusable content.
  - HEAD's logs scrolled the same way, and Chromium 130+ makes such scrollers keyboard-focusable itself (seen in round 2's walk).
  - Fix: `tabindex="0"` on both `<ul>` elements in index.html.
- **Still open from earlier rounds:** round-2 n2 (Shift+Tab skipping the tabs) is fixed by the always-shown bar. Round-2 n3, n4 and n5, and round-1 m5, m6, m7 (checked radio in forced colours) and m11 are still open.
