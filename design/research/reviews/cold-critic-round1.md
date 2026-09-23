# Cold critic: secure-chat design rework (uncommitted diff against HEAD f39751c)

Reviewer role: I checked facts, not taste. I verified every statement below with a script, a headless measurement or a `file:line` reference.
Repository files were not modified. All tooling and raw output is in
`<session scratchpad>/cold/` (shortened to `cold/` below).

Setup: relay on http://127.0.0.1:8000 (serves the working tree: md5 of `/`, `/style.css` and `/app.js` equals the files on disk), Chromium 141.0.7390.37
(`/opt/pw-browsers/chromium`), puppeteer-core from `e2e/`, axe-core 4.x installed in `cold/axe/`.
The main harness is `cold/audit.mjs`. It is a copy of `e2e/screenshots.mjs` with 32-character usernames for alice and bob, a `securitypolicyviolation`
listener injected at document start, and a probe library (`cold/audit-lib.mjs`) that runs at every captured state. It was run three times: `cold/audit-run1.json`,
`audit-run2.json` and `audit-run3.json`. Run 3 includes axe-core.

---

## Checklist

| # | Area | Verdict |
|---|------|---------|
| 1 | CSP compliance | **PASS** |
| 2 | Structure (ids, `els`, `[hidden]`) | **PASS** (one minor note, m5) |
| 3 | Contrast, computed | **FAIL (minor)**: two 12px text pairs at 4.39–4.44:1, both in hover or selected states |
| 4 | Accessibility | **FAIL**: tab bar hides keyboard focus; the admission sheet does not hold focus; 36px/13px pending buttons; empty icon buttons in forced colours |
| 5 | Layout robustness | **FAIL**: composer under the tab bar on short viewports; long trust pill clipped; enlarged text pushes a button off-screen |
| 6 | app.js behaviour | **PASS** (two minor notes, m6) |
| 7 | e2e edits | **PASS** |
| 8 | Android WebView | **PASS** with degradation notes (m9) |
| 9 | Stylesheet hygiene | **PASS** with minor notes (m10, m12) |

### 1. CSP: PASS
- **Static checks.**
  - `index.html`: 0 `style=` attributes, 0 `<style>` elements, 0 `on*=` handlers, 0 `http(s)://` URLs. The only scripts are the import map (line 488) and `app.js` (line 489).
  - `style.css`: 13 `url(` occurrences, all `url("data:image/svg+xml…")`. The only `http` strings are the SVG `xmlns`. No `@import` and no `@font-face`.
  - The `app.js` diff adds no `.style`, `setAttribute("style")` or `innerHTML`.
- **Import map.** The line is byte-identical to HEAD (`cmp` of the `grep 'type="importmap"'` line from `git show HEAD:client/index.html` against the working tree: IDENTICAL). Its sha256 is `6Sm2nhNvoa7gr7uuY2hbAbpdWhIlL15/wXLm4dhO9UQ=`, which matches `backend/main.py:168` and the served header. `backend/tests/test_csp_hash.py` passes (2/2).
- **Headless load.**
  - 0 `securitypolicyviolation` events and 0 CSP console messages across all 20 captured states: identity, room (plus options and OTP), users (locked and unlocked), chats list, conversation, mode proposal on both sides, profile, and live owner/guest/admission/verify/chat/disconnected. Each run covers 3 agents and 3 runs were made.
  - The CSSOM overrides used for my own zoom and forced-colour probes also raised none.
  - The only console error is `404 /favicon.ico`. It is the same at HEAD (`cold/net404.mjs` against both trees), so it is not a regression.

### 2. Structure: PASS
- **Ids** (`cold/ids.py`). HEAD has 145 ids and the working tree has 143, with no duplicates in either. Missing: exactly `drawer`, `menuBtn`, `scrim` (the removals the contract allows). Added: `tabbar`.
- **`els` map.** 136 `$("…")` entries, and every `$()`/`getElementById()` id in app.js exists in index.html. None resolve to null.
- **e2e id references.** The only ones that no longer resolve are the guarded `#menuBtn/#drawer/#scrim` fallbacks in `e2e/screenshots.mjs`.
- **`[hidden]` rule.** `[hidden]{display:none !important}` is at style.css:147. It is the only `display … !important` in the file; the only other `!important` is `.vh{position:absolute !important}` at :215. No other display rule can therefore beat it.
- **Hidden sweep, measured.** At 8 states (first-run, identity-unlocked, otp, users-unlocked, conversation, profile, admission, verify) I set `hidden` on every element in the DOM and read the computed display.
  - 256–310 elements checked per state: 0 kept any display other than `none`.
  - The 21–30 elements already hidden per state: all computed `none`.
  - The app.js-toggled set is unchanged from HEAD: verify, admit, scrIdentity/Room/Chat, the 4 views, and the locked/unlocked/adopt pairs.
- **Hiding that is CSS-only (new, deliberate):**
  - `.facts` once the identity is unlocked (1280).
  - The Chats screen header while a conversation is open (1391).
  - `#log` and `#sendForm` while the verification gate is up (1365). See m5.

### 3. Contrast: FAIL (minor)
Method: `cold/contrast.py` reads the `:root` tokens and composites every alpha, `color-mix()` tint and the top-of-page glow (worst case). Full table: `cold/contrast.txt`, 150 pairs.
Cross-check: axe-core on 20 states × 2 widths (390, 1280) found **0 violations** of any wcag2a/2aa/21aa/22aa rule. Its `color-contrast` rule returned "incomplete" for elements over the `body::before` grid, and the token table covers those.

- **Text below 4.5:1:**
  - `.badge.pq` ("ML-KEM-768", 12px `--muted` on its own 10% tint): 4.44:1 on a hovered algorithm row, 4.39:1 at the top of the selected row's gradient.
  - `.u-mark` (unverified, 12px `--muted` on its 10% tint) on a hovered chat row (`.chatrow:hover` → `--panel-2`): 4.44:1.
- **Pairs that pass, for the record:**
  - White on `#1f6feb`: 4.63.
  - Tab labels: phone inactive `--muted` 12px 6.15, phone active `--accent` 5.05, desktop 6.00 / 13.74.
  - Placeholder (`--muted` on `--inset`): 6.29.
  - Danger label `--err-fg`: 7.85–8.99, and 7.09 at minimum on hover.
  - Pending bar text `--warn-fg` on the warn tint: 7.56.
  - `.hint.err`: 5.12 minimum. Captions `.who`/`li.sys`/`.u-fp`: 5.58–6.29. `.alg-name` selected (`--accent-2`): 4.95.
  - Pills: ok 5.31–6.51, mid 5.35–6.56, changed 6.51–8.03. `.status`: 4.84–5.44.
  - Focus ring `--accent` on every ground: 4.18–5.16. Input border `--field`: 3.03–3.42. Radio ring `--faint`: 3.45–3.73.
- **Disabled controls (report only):**
  - Placeholder in the disabled `#text` (opacity .55): 2.66.
  - Disabled primary (opacity .45): 3.34–3.50.
  - Disabled secondary: 3.66.
- **Non-text below 3:1 (informational; each is either decorative or has its meaning carried by text):**
  - Secondary button outline `--border`: 1.74–1.97. Danger outline: 1.95–1.99.
  - `#chatModeSel` border: 1.24 (its chevron is 5.15).
  - Step progress segments: done 2.07, to-do 1.33 (the step text says it).
  - Trust dots: see m8.

### 4. Accessibility: FAIL
- **Focus visible: PASS.**
  - 45 keyboard walks (15 states × 320/390/1280, real Tab key, read 260ms after each press once transitions settle): every stop matched `:focus-visible` and had a 2px accent outline or the input ring.
  - An earlier 15ms read showed "no ring" on inputs. That was the 140ms `box-shadow` transition, not a missing ring.
  - The alg-card ring works through `:has(input:focus-visible)`.
- **Tab bar semantics: PASS.**
  - `aria-current="page"` is on exactly one tab, and it matches the visible view at all 20 states.
  - `<nav id="tabbar" aria-label="Views">`. Each tab's name is its label (SVG `aria-hidden`); axe `button-name` passes.
- **No keyboard trap: PASS.** Every walk returned to its start going forwards, and again with Shift+Tab.
- **Focus hidden under the fixed tab bar: FAIL (M1).** 7 focus stops were fully covered (5 of 5 sample points under `#tabbar` by `elementFromPoint`):
  - identity-unlocked@320: `#idExport`, `#idForget`, `#toRoom`
  - room-setup@320: `#contact`
  - room-options@320: `#contact`
  - room-options@390: the DHKE radio row
  - users@320: "Verified in person"
  - The sticky top bar covered none: 0 stops, and the step headings focused by `showScreen()` stay visible after scrolled navigation (`cold/stepfocus.mjs`).
- **Admission sheet: FAIL (M3).** Tab order while it is open (390 and 1280): Live room, Chats, Users, Profile, `#copyRoom`, `#disconnect` (all 6 covered by the scrim or the sheet, 5 of 5 points), then `#admitFingerprint`, `#admitOk`, `#admitNo`. Focus is not moved into the sheet.
- **Verification gate: PASS.** No hidden control is reachable: `#log` and `#sendForm` are `display:none` and `#text` is disabled. The sequence is tabs, Copy room id, Disconnect, `#safetyNumber`, verifyOk, verifyNo.
- **Touch targets ≥44px (390 and 320): FAIL (B1).** Everything passes except `#chatPending` Accept (75.8×36) and Decline (74.6×36).
- **Font ≥16px on phone.** Every input and select is 16px: PASS. Buttons:
  - Pending Accept/Decline are 13px (B1).
  - The tab labels are 12px. The contract says buttons ≥16px, but direction.md rule 8 specifies "11px labels", and iOS only zooms on focused inputs. Noted, not failed.
  - Icon-only buttons (`#send`, `#chatSend`, `#chatBack`) are `font-size:0`; they are named by their text or `aria-label`.
- **`prefers-reduced-motion`: PASS.** Under `reduce`:
  - Buttons go to `transition 0s all`; views and screens to `animation none`; the sheet `none`; the summary chevron `0s`.
  - A sweep of every element and its `::before`/`::after` found no transition or animation left.
  - Under `no-preference`: 0.14s, `rise`, `sheet-in`.
- **`forced-colors: active`** (CDP `Emulation.setEmulatedMedia`; screenshots `cold/audit-out2/forced-*.png`):
  - The trust level is still conveyed in words ("verified by you", "unverified", "vouched by …"): PASS.
  - Every mask icon computes `::before` background `rgb(255,255,255)`, which is Canvas, so it is invisible.
  - `#chatBack`, `#send` and `#chatSend` render as empty boxes or circles: FAIL (M4).
  - The trust dots disappear.
  - The checked algorithm card is not indicated. This is pre-existing (m7).
  - Input and select focus: `outline:none` with `box-shadow` forced to `none`, so no ring. Also pre-existing (m7).

### 5. Layout robustness: FAIL
- **No horizontal overflow: PASS.** Measured at 20 states × {320, 360, 390, 600, 601, 640, 768, 1024, 1280} + 640@2x (200% page zoom of a 1280 window) + 568×320, with 32-character usernames (`documentElement.scrollWidth ≤ clientWidth`). The screenshots.mjs overflow section is empty too.
  - One transient 320px overflow (`sw 341`) traced to `#accountStatus`. It is pre-existing (m4) and depends on the random handle token.
- **Tab bar vs composer and last message at portrait sizes: PASS.**
  - At 390×844 the window bottom meets the tab bar top exactly; `--vh` is `100dvh` under `@supports`.
  - `cold/longlog.mjs` injected 120 log lines. The page does not scroll, the log scrolls inside the window, and the last line ends above the composer at 320×568, 360×640, 390×844, 601 and 1280.
- **Short viewports: FAIL (M2).**
  - 568×320: the composer is at [308..377] with the tab bar top at 256.
  - 360×400 (the viewport a resizing WebView has with the soft keyboard up): the live-room composer is at [288..357] with the tab bar top at 336, and the focused `#text` sits under the tab bar.
  - With the pending bar open at 360×400, the centre of `#chatText` is under `#tabbar`.
- **Sticky top bar: PASS.** It never covers the screen header or a focused control (see area 4).
- **Long names and handles** (32-character names in the real flow; injected 32/99-character strings in `.u-name`, `.u-mark`, `.u-claim`, `#myHandleText`, `#profileHandleText`, `#chatPeer`, `#admitWho`, `#roomShort` at 320/360/390/640):
  - No page overflow.
  - A "vouched by <32>, <32> — key CHANGED…" `.u-mark` cannot shrink below 293px, so it is clipped by 25px in list rows at 320. `#chatPeerMark` ends at x=363 in 320 and 360 viewports (clipped by `.window`) (m2).
- **Text-only zoom** (the `--fs-*`/`--control-fs` tokens scaled through the CSSOM): at 130% on a 360px phone, "Continue without an identity →" starts at x=−11 (m3).
- **`env(safe-area-inset-bottom)`: correct.** With CDP `Emulation.setSafeAreaInsetsOverride` bottom=34 (`cold/safearea.mjs`):
  - The tab bar grows 64→98px, the tab button keeps 64px above the inset, and `main` padding-bottom goes 88→122px.
  - The viewport meta has no `viewport-fit=cover`, so real browsers and WebViews report 0 and the rules are inert until the app goes edge-to-edge.

### 6. app.js: PASS (with notes)
All 38 hunks were read and classified by `cold/app.diff` plus a string-diff script.
- **Comment-only hunks.** 9 hunks are comments only, and a tenth (#16) changes only the trailing comment on an unchanged line (`refreshVouchMarks()`). The rewritten comments are accurate: "top-level views (tab bar) … Four views", "verified mark", "vouched mark".
- **Drawer removal.** `els` loses `menuBtn/drawer/scrim` (:72). `setDrawer` and its call in `showView` are deleted (:379–395). Listeners are removed (:3265).
- **Navitem binding** is now `document.querySelectorAll(".navitem")` in both `showView` (:389) and the click wiring (:3266).
- **`.changed` class.**
  - `renderUserList` (:1081): `if (c.keyChangedAt && !c.verified)`, the same condition as the row's err hint.
  - `renderChatList` (:1368) and `renderConversation` (:1395): `c && c.keyChangedAt && !c.verified`.
- **Emoji removed.** Words are unchanged in every string except one: app.js:1276 `"… reset to ⚪."` became `"… reset to unverified."` The emoji was the noun, so this is justified. See m6.
- **Emoji removed outside the three functions the contract names:** the confirm() vouch text, `addContactFromHandle` status messages, admitWho/admitWarn, three verifyTitle strings, `otpExport`, and chatHint. This is consistent with the rule of no emoji anywhere. Warning cues survive through `.hint.err::before` and `.gate.changed::before` everywhere except the one in m6.
- **No emoji remain** in app.js or index.html. The only symbol left is `↔` in a placeholder.
- **Pinned strings.** All e2e-pinned strings have the same occurrence counts in HEAD and the working tree: "Copied ✓", "Copy room id", "Verified in person", "Remove", "registered", "logged in", "identity unlocked", "Open anyway (I understand the risk)", "Let them in", "Deny", "It matches — unlock messaging", "It differs — disconnect", "Continue →", "Continue without an identity →".

### 7. e2e: PASS
- **Only intended changes.**
  - `two-user-flow.mjs`: `view()` now clicks `.navitem[data-view]` directly; `sleep(150)` removed.
  - `no-dead-ends.mjs`: "menu button exposes its state" and "open drawer marks the current view" are replaced by "all four views are reachable from the tab bar" and "the tab bar marks the current view" (it still asserts `current === "live"`). Two `#menuBtn` clicks and a `sleep(300)` are removed.
  - `check(` counts are unchanged: no-dead-ends 12→12, two-user-flow 9→9.
  - `room-admission.mjs` and `hostile-relay.mjs` never used the menu, so nothing needed changing.
- **Runs** (`CHROMIUM=/opt/pw-browsers/chromium node e2e/<run>.mjs`, logs `cold/e2e-*.log`): two-user-flow 8/8, room-admission 13/13, no-dead-ends 16/16, hostile-relay 11/11.
- **`e2e/screenshots.mjs`** (`cold/screenshots.log`, output `cold/shots/`): 20/21 captured, 1 skipped (02-drawer-open, which the plan allows), 40 PNGs, no overflow notes, exit 0.
- **Other suites.** `client npm test`: all suites passed, exit 0 (`cold/npm-test.log`).
- **Backend `pytest`: not completed here.** It hangs in `tests/test_ws.py::test_repeated_join_and_drop_cycles_do_not_accumulate_pending` (in-process TestClient). The 141 tests before it passed, `test_csp_hash.py` passes 2/2, and `git diff HEAD -- backend` is empty, so the hang is not caused by this change.

### 8. Android WebView: PASS with notes
- **No version check.** The app enforces no WebView version, only `WebViewFeature.DOCUMENT_START_SCRIPT` (MainActivity.kt:116). The page itself needs import maps (Chromium 89). The only on-device record is WebView 113 (PROGRESS.md:2178).
- **Feature floors** (Chromium versions per MDN/caniuse, not verifiable offline):
  - `:has()` (105): 16 uses. Already relied on at HEAD for the algorithm card.
  - `color-mix()` (111): 11 uses. Already used at HEAD.
  - `dvh` (108): guarded by `@supports`. HEAD used it unguarded.
  - `mask` (unprefixed 120): always paired with `-webkit-mask`.
  - `backdrop-filter`: `-webkit-` prefix plus an `@supports not` solid fallback.
  - `env()` (69); `text-wrap`, `scrollbar-color` and `scrollbar-gutter` are progressive.
  - `:is`/`:where` (88), `inset` (87), `:focus-visible` (86), flex `gap` (84), `appearance` (84).
  - No container queries.
- **Prefixes.** No missing `-webkit-` prefix: `-webkit-mask`, `-webkit-mask-image`, `-webkit-backdrop-filter`, `-webkit-text-size-adjust` and `::-webkit-details-marker` are all present.
- **`background-attachment`** appears only in a comment (style.css:155).
- **Android colours.** `colors.xml` `app_bg #0D1117` = `--bg` and `app_fg #D8DFE7` = `--fg`.
- **Degradation below 105/111:** see m9.

### 9. Stylesheet hygiene: PASS with notes
Source: `cold/hygiene.py`, output in `cold/hygiene.txt`.
- **Dead selectors.** One: `.mono` (:194). Every other class and id is in index.html or produced by app.js.
- **Duplicates.** No selector appears twice in the same context. There are two redundant or duplicate blocks (m10).
- **`!important`.** Two uses, both justified: `[hidden]` (:147) and `.vh` (:215).
- **Font sizes.** All are `var(--fs-1..6)` (12/13/15/17/20/24) or `var(--control-fs)` (16px on phone, which direction.md sanctions; 15px on desktop), plus `font-size:0` on the two icon buttons.
- **Colour literals.** None outside `:root`. The regex hits on `white` were `white-space`.
- **Weight.** 21,575 B → 55,251 B (+156%). Gzip 6,334 → 14,875 B (+135%). 632 → 1,613 lines. 14,149 B of it is comments and 3,769 B is data-URI icons.

---

## Ranked findings

### BLOCKER

**B1. Pending-banner buttons break two hard constraints: 36px touch target and 13px font on phone.**
- Where: style.css:1454, `.pending > button { min-height: 36px; padding: 0 var(--sp-3); font-size: var(--fs-2); }`.
- Observation (audit state 12, 390×844): `#chatPending` Accept is 75.8×36 at 13px and Decline is 74.6×36 at 13px. The contract's hard constraints require touch targets ≥44px and buttons ≥16px on phone.
- Reproduce: `CHROMIUM=/opt/pw-browsers/chromium node cold/audit.mjs <out>`, then read `states["chat-mode-proposal-received"].targets["390"]`. You can also see it in `cold/shots/12-chat-mode-proposal-received-phone.png`.
- Minimal fix: drop `min-height` and `font-size` from that rule, so the buttons inherit `min-height: var(--control-h)` (44px) and `--control-fs` (16px on phone).

### MAJOR

**M1. Keyboard focus is hidden under the fixed bottom tab bar on phones (WCAG 2.2 SC 2.4.11; direction.md rule 8 says "content never hides under either bar").**
- Where: style.css:149 (`html`), which has no `scroll-padding`.
- Observation: when a control below the fold is tabbed to, Chrome scrolls it to the viewport's bottom edge, under the 64px `#tabbar`. Fully covered stops (5 of 5 sample points):
  - identity-unlocked@320×568: `#idExport`, `#idForget`, `#toRoom`
  - room-setup and options@320: `#contact`
  - room-options@390×844: the DHKE radio row
  - users-unlocked@320: "Verified in person"
- Reproduce: `cold/audit-run3.json`, then `states.*.keyboard.*.seq[].covered == 5`. Or run `node cold/fixcheck.mjs` ("A before: idExport [524..568] under #tabbar; idForget …").
- Minimal fix (verified; `fixcheck.mjs` "A after: no focused control covered"): `html { scroll-padding-top: var(--bar-h); scroll-padding-bottom: var(--tabbar-space); }`.

**M2. The bottom tab bar covers the composer on short phone viewports. This breaks the hard constraint "bottom tab bar never covers the composer" below about 472 CSS px of height.**
- Where: style.css:842 `.window { min-height: 360px }` and :1390 (`#viewChats:has(…) { … min-height: 360px }`). When 48 + 64 + 360 is more than the viewport height, the window grows past the tab bar.
- Observation (audit plus `cold/fixcheck.mjs`):
  - 360×400 (a resizing WebView with the soft keyboard up): composer [288..357] vs tab bar top 336. The focused `#text` is under `#tabbar`.
  - 360×400 in a chat with the pending bar open: the centre of `#chatText` is under `#tabbar`.
  - 568×320: composer [308..377] vs 256.
  - Portrait 320×568, 360×640 and 390×844 pass.
  - The app sets no `windowSoftInputMode` (AndroidManifest.xml:18–21). Whether the WebView resizes under the keyboard was not verified on a device.
- Reproduce: `cold/audit-run2.json` `states["live-chat-connected"].kbdOpen["360x400"]` (`onTop: "#tabbar"`), or `node cold/fixcheck.mjs`.
- Minimal fix (verified at 360×400: the composer ends at 285 against the tab bar top at 336): at ≤600px, `.window, #viewChats:has(…) { min-height: 0 }`. At 568×320 that still leaves 14px covered, so landscape also needs a compact or static tab bar (for example `@media (max-width:600px) and (max-height:480px) { .tabbar { position: static } }`) or acceptance of page scroll there.

**M3. The admission sheet is visually modal but focus is not held in it.**
- Where: style.css:966–998 (`.sheet`, scrim `#scrChat:has(> .sheet…)::before`); app.js `showNextKnock()` (no focus call).
- Observation: while the sheet is open, Tab passes through 6 controls hidden behind the scrim or the sheet (the 4 tabs, `#copyRoom`, `#disconnect`; all 5 of 5 points covered) before `#admitFingerprint`, `#admitOk`, `#admitNo`. Focus stays where it was when the knock arrived. Pressing Enter on a hidden tab leaves the live view, which removes the sheet while the knock is still pending.
- Reproduce: `cold/audit-run2.json`, `states["live-admission-prompt"].keyboard["390"|"1280"].seq`.
- Minimal fix: this cannot be fixed in CSS. It needs two lines in app.js, which is outside what the contract allows: `inert` on `.apphead`, `#scrChat > .topbar` and `#chat` while `#admit` is visible, plus `els.admitOk.focus()`, or a `<dialog>` in phase 2. Escalate to the orchestrator.

**M4. In forced colours (Windows contrast themes), every CSS-mask icon disappears and three controls render empty. This is a regression from HEAD.**
- Where: style.css:232–249 (`background: currentColor` through a mask); `.composer button { font-size:0 }` (:958); `#chatBack { font-size:0 }` (:1422).
- Observation (CDP forced-colors emulation): every icon `::before` computes background `rgb(255,255,255)`, which equals Canvas. `#chatBack` is an empty square and the send buttons are empty circles (`cold/audit-out2/forced-chat-conversation.png`). HEAD showed "‹" and "Send" text. The trust words are still shown.
- Reproduce: `node cold/forcedfix.mjs cold`, output "forced, as shipped".
- Minimal fix (verified; `cold/forced-icons-after.png`):
  - `@media (forced-colors: active) { .u-mark::before, .legend-item::before, .chatmode::before, .facts li::before, .hint.err::before, .u-claim::before, .disclosure > summary::after, .locked::after, .welcome-mark::after, .gate::before { background: CanvasText; } .composer button::before, #chatBack::before { background: ButtonText; } }`
  - Do not apply it to the `.u-mark::after` dots: a solid fill shows 3 dots for every level.

### MINOR

**m1. Two 12px text pairs are below 4.5:1** (contrast table): `.badge.pq` on a hovered or selected algorithm row is 4.44 / 4.39. `.u-mark` (unverified) on `.chatrow:hover` (style.css:1379) is 4.44.
- Fix: no tint on muted pills, `.badge.pq, .u-mark:not(.ok):not(.mid):not(.changed) { background: transparent }`. That gives 5.15 on panel-2 and 5.09 on the selected row.

**m2. A long trust pill cannot shrink.**
- Where: style.css:630 `.u-mark`.
- Observation: "vouched by <32 chars>, <32 chars> — key CHANGED…" has a min-content width of 293px. It is clipped by 19–25px in `.userlist` rows at 320, and `#chatPeerMark` ends at x=363 in 320 and 360 viewports (clipped by `.window`).
- Reproduce: `audit-run1.json` `longText`, or `node cold/zoomfix.mjs` part (2).
- Fix (verified: fits at 320): `.u-mark { overflow-wrap: anywhere; max-width: 100%; }`.

**m3. Enlarged text pushes a button off-screen to the left and widens the page.** Android WebView's text zoom follows the system font scale, and the app does not pin `setTextZoom` (MainActivity.kt:126–133).
- At 130% on a 360px phone, first run: `#toRoom` spans [−11..344]. At 150% it is −60, and at 200% it is −184. The overflow is on the left, so it cannot be scrolled to (style.css:1303–1304 `.nav{justify-content:flex-end}` with `button{white-space:nowrap}` at :448).
- At 200%, the `#idForget` actions row makes the page 401px wide, and the `#status` pill 420px (`.inline` rows without `.wrap`).
- Reproduce: `node cold/zoomfix.mjs` part (1).
- Fix: `.nav > button { min-width: 0; white-space: normal; }` and `.actions, .connect-row { flex-wrap: wrap; }`.

**m4. Pre-existing and not fixed: `#accountStatus` overflows with an unbreakable handle.**
- Observation: "Registered. Your contact handle is <32>#<24>" makes the page 471px wide at 320, 360 and 390. HEAD gives 475px on the same text (`cold/probe-head.mjs`), so this is not a regression.
- Fix: `.hint { overflow-wrap: anywhere; }`.

**m5. The gate hides the `aria-live` log.**
- Where: style.css:1365 `#scrChat:has(> #verify:not([hidden])) :is(#log, #sendForm) { display:none }`.
- Observation: lines written while the gate is up are neither shown nor announced until after the decision. That includes the only positive signal of the handle check, app.js:2737 `key matches the directory entry for "X" — still verify in person`, and :2612 `[message arrived before you verified the safety number — dropped]`. Every warning is duplicated in `#verifyTitle`, so this affects reassurance, not safety.
- Fix: keep the log in the accessibility tree by clipping it with the `.vh` pattern instead of `display:none`, or have app.js mirror line 2737 into `#verifyHint`.

**m6. One status message lost its warning cue.**
- Where: app.js:1273–1277.
- Observation: the "fetched keys DIFFER … reset to unverified" status is written without `isErr`. Its only warning cue was the removed "⚠", so it now reads as a plain muted hint. The row still gets `.changed` and the err hint, because `contacts.upsert` sets `keyChangedAt`.
- This is also the one string whose words changed ("⚪" → "unverified"), which is justified.
- Fix: `usersStatus(msg, true)` in that branch. This is an app.js change outside the contract.

**m7. Pre-existing in HEAD: two things are invisible in forced colours.**
- The checked algorithm card: the native radio is hidden (:1114) and the `:has` gradient and dot are dropped.
- The input and select focus ring: `outline:none` plus `box-shadow` (:510–515).
- Fix: `outline: 2px solid transparent` instead of `outline: none`, and in `@media (forced-colors: active)` un-hide `.alg-card input`.

**m8. Trust dots show a count, not a level out of 3.**
- Unfilled dots are 1.6–1.9:1 against the pill, and filled vs unfilled is 2.99:1 for unverified. The dots vanish in forced colours and below Chromium 111, because `color-mix` inside the background declaration makes it invalid.
- Informational: the words carry the level everywhere.

**m9. WebView degradation below the stylesheet's newest features.** The app gate allows anything with `DOCUMENT_START_SCRIPT`.
- Without `:has` (<105), the rework's new `:has`-based layout degrades:
  - The conversation window loses its fixed height (`#chatConvo{height:auto}`, :1398) and the page scrolls instead.
  - The live window starts 24px lower and needs 48px of page scroll to clear the tab bar.
  - There is no scrim, the facts stay after unlock, and the gate does not hide the log.
- Without `color-mix` (<111), pills and danger buttons lose their tint and the dots vanish.
- Nothing breaks. If the owner wants guarantees, add a minimum-version check next to the feature check.

**m10. Hygiene and cosmetic issues.**
- `.mono` is dead (:194).
- `.locked::after` is redeclared with identical values at :1535, which is redundant with :1168–1175.
- `.wordmark .sub` (:284) re-implements `.vh` (:214).
- `.sheet .row > label` (:999) and `.gate .row > label` (:1034) are identical blocks.
- A 64px `.navitem` (:312) sits in a 64px tab bar with a 1px top border (:299/302), so each tab ends 1px below the viewport (781..845 in 844). Fix: `height: 100%`.

**m11. Step 2's back button is painted above the header (`order:-1`, :1311) but is last in the tab order.** This is deliberate and commented, but it is a visual/DOM order mismatch (WCAG 2.4.3 / 1.3.2 risk).

**m12. Weight and a wording tension.**
- The CSS is 2.6× its previous size (gzip 2.3×). That is acceptable for a single stylesheet. About a quarter of it is comments, which could be stripped in the Android bundle if the size matters.
- The desktop top bar uses `backdrop-filter: blur(12px)`, as direction.md rule 8 asks. The contract bans "glassmorphism". There is a wording tension between the two documents; no action needed.

---

## Reproduce everything
```
cd /home/user/secure-chat
C=<session scratchpad>/cold
python3 $C/ids.py; python3 $C/contrast.py; python3 $C/hygiene.py
CHROMIUM=/opt/pw-browsers/chromium node $C/audit.mjs $C/out     # 20 states: CSP, overflow, chrome, targets, keyboard, hidden, long text, zoom, axe, media
cd $C && node fixcheck.mjs && node forcedfix.mjs $C && node zoomfix.mjs && node longlog.mjs && node stepfocus.mjs && node safearea.mjs
```
