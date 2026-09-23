# secure-chat rework v1: hot critic review

Screenshots: `rework-v1/NN-*.png` and `baseline/NN-*.png` (the official set), `checks/*.png` (extra checks), and `hot/shots/*.png` (my captures). For the warning states the official set never reaches, I rendered them in the live client with the exact strings and classes app.js writes: `.gate.changed`, `#admitWarn.hint.err`, `.u-mark.changed`. Everything was measured at 390×844@2x, 360×740@2x and 1280×800.

## 1. Verdict

**No.** Compared with the baseline this is a real step up. The tokens, tab bar, one-container lists, safety-number band and admission sheet are all better, and Users, Profile (desktop) and the verify gate now look like one product. But the Live room setup, the phone chat chrome and every warning variant still look like a restyled form. **The biggest remaining problem:** the security moments were only designed for the happy path. When a key does not match or an unexpected person joins, the blue primary still says "proceed" and the "connected" pill still glows. The key-changed trust mark also turns into a 4-line blob that truncates the contact's name.

## 2. Findings, ranked

### BLOCKER

**B1. Warning states still make "proceed" the blue primary.**
Shots: `hot/shots/c-verify-changed-{phone,desktop}.png`, `hot/shots/d-admit-mismatch-{phone,desktop}.png`.
- **Key does not match the directory:** "It matches — unlock messaging" is still the filled #1f6feb button, directly under a red "Key does NOT match…" title, and the header pill still says "connected" with its green glow.
- **Unexpected joiner:** when the joiner is "NOT the user you selected", "Let them in" is still the filled primary. The research says the opposite (messenger-patterns §3: "No match: neither button is primary").
- The alarm is repeated a third time as a red hint pinned to the bottom of the window, 200px below the buttons.

Fix:
```css
.gate.changed #verifyOk,
#admit:has(#admitWarn.err:not(:empty)) #admitOk {
  color: var(--fg); background: transparent; border-color: var(--border);
  box-shadow: none; font-weight: 500;
}
.gate.changed .stacked { flex-direction: column-reverse; }   /* the safe action first */
#admit:has(#admitWarn.err:not(:empty)) .pair > #admitNo { order: -1; }
#scrChat:has(> #verify.changed:not([hidden])) #chatStatus { color: var(--muted); }
#scrChat:has(> #verify.changed:not([hidden])) #chatStatus::before { box-shadow: none; }
#scrChat:has(> #verify:not([hidden])) #hint { display: none; }  /* the gate already says it */
```
Setting the initial focus on Deny needs app.js; list it for phase 2.

**B2. The key-changed trust mark breaks the conversation header and list rows.**
Shots: `hot/shots/h-convo-changed-{360,desktop}.png`, `hot/shots/g-chats-long-marks-{360,desktop}.png`.
- `.u-mark` holds a sentence: "vouched by e2e-bob-aykhq — key CHANGED since you last verified".
- At 360px it becomes a 4-line pill, and the header grows to about 170px.
- On desktop the `back name mark` grid gives the pill the width and ellipsizes the contact's name to **"e2e-d…"**. The one state where it matters most who changed is the one state that hides the name.
- In the Chats list, rows alternate between the pill right-aligned and the pill wrapped under the name, so the column is ragged.

Fix:
```css
.u-mark.changed { border-radius: var(--r-s); white-space: normal; align-items: flex-start;
                  padding: var(--sp-1) var(--sp-2); }
.u-head { display: grid; grid-template-columns: minmax(0, 1fr) auto; }
.u-head > .u-mark.changed { grid-column: 1 / -1; justify-self: start; }
.convo-head { grid-template-areas: "back name sel" "back mark mark"; }  /* both widths */
#chatPeer { min-width: 12ch; }
#chatPeerMark { max-width: 100%; }
```
The clean fix is one line in app.js: wrap the " — key CHANGED…" suffix in a `<span class="u-mark-note">` inside the `.u-mark`. textContent does not change, so the e2e checks still pass, and the note can then be styled as a 12px caption.

**B3. Touch targets below 44px on the phone (hard constraint in the contract).**
Shot: `rework-v1/12-chat-mode-proposal-received-phone.png`. Accept and Decline measure 35px because of `.pending > button { min-height: 36px; font-size: 13px }`.

Fix: move that rule into the `@media (min-width: 601px)` block. On a phone they inherit `min-height: var(--control-h)` and 16px.

Decline also uses `.danger` (app.js sets it), but declining a mode switch is not destructive. Override it in CSS: `.pending > .danger { color: var(--fg); background: transparent; border-color: var(--border); }`

**B4. Content hides under the fixed tab bar (hard constraint in the contract).**
Shot: `hot/shots/a-focus-probe-phone.png`.
- Tab to "Continue →": the focused button sits at 799–843px, and the tab bar starts at 780px. The focused primary is invisible.
- The same thing happens whenever the browser scrolls a control into view, including an Android input being focused when the soft keyboard opens. My own scripted click on #toRoom landed on the Users tab for this reason.

Fix:
```css
html { scroll-padding-top: calc(var(--bar-h) + var(--sp-2));
       scroll-padding-bottom: calc(var(--tabbar-space) + var(--sp-2)); }
```

### MAJOR

**M1. On a phone, chat chrome takes the conversation away.**
Shots: `rework-v1/10,11,12-*-phone.png`, `hot/shots/j-convo-keyboard-open-phone.png`, `rework-v1/14–19-*-phone.png`.
- In an async conversation the chrome is 48 (wordmark bar) + 122 (head: name, pill + chip, a full-width select) + 69 (composer) + 51 (hint) + 64 (tab bar) = 354px.
- With the keyboard open (a 480px viewport) the log gets **125px**.
- The mode is shown three times: the "SEALED" chip, the "SEALED (default)" select and the "SEALED — hybrid ECDH…" hint.

Fix:
```css
@media (max-width: 600px) {
  :root:has(#chatConvo:not([hidden])) { --tabbar-space: env(safe-area-inset-bottom, 0px); }
  body:has(#chatConvo:not([hidden])) .tabbar { display: none; }  /* back button exists */
  .convo-head #chatMode { display: none; }                       /* the select IS the chip */
  #chatModeSel { width: auto; }
  #chatHint:not(.err) { font-size: var(--fs-1); white-space: nowrap; overflow: hidden;
                        text-overflow: ellipsis; }
}
@media (max-width: 600px) and (max-height: 560px) {  /* soft keyboard open */
  .tabbar { display: none; } :root { --tabbar-space: 0px; }
}
```
The Live room topbar should also collapse to one 56px row (see M6).

**M2. The unlocked identity screen keeps the first-run pitch, and the primary sits below the fold.**
Shots: `rework-v1/03-identity-unlocked-{phone,desktop}.png`, `checks/p-03-unlocked-bottom.png`.
- After unlock only `.facts` is hidden. The 3-line 24px "Your keys are made on this device. Nobody else holds them." stays, and so does a second "secure-chat" wordmark tile 100px under the one in the app bar.
- The success message is 15px green body text.
- "Forget" (danger, 44px, the same width as Copy backup) sits right under the fingerprint.
- "Continue →" can only be reached by scrolling past the username card.
- On first run, the "STEP 1 OF 3" progress line comes before the welcome, so the flow starts with bookkeeping.

Fix:
```css
.welcome-mark { display: none; }   /* the bar already carries the mark */
.welcome > .step { order: 1; margin-top: var(--sp-3); }  /* after the facts */
#scrIdentity:has(#idExport:not([hidden])) .welcome > .title { display: none; }
#scrIdentity:has(#idExport:not([hidden])) #identity > .row:first-child .overline {
  font-size: var(--fs-6); font-weight: 650; letter-spacing: -0.02em; text-transform: none; color: var(--fg); }
#idStatus { font-size: var(--fs-2); }
.hint.ok { color: var(--muted); }  /* success is quiet; the green dot says it */
#idForget { order: 9; margin-left: auto; flex: none;
            background: transparent; border-color: transparent; }
```

**M3. The admission sheet shows trust as plain text instead of the trust pill, and the hierarchy is upside down.**
Shots: `rework-v1/16-live-admission-prompt-{phone,desktop}.png`, `hot/shots/d-admit-mismatch-phone.png`, `hot/shots/d-admit-noidentity-phone.png`.
- "e2e-bob-aykhq — verified by you" is 15px body text with no shield and no dots. This is the one screen where the pill matters most.
- In the mismatch case the neutral "Not in your users list — you have never verified this key" is 15px `--fg` text, while the red warning under it is 13px.
- With no identity, the sheet shows a 64px empty inset well holding a single "—".
- The grab handle promises drag-to-dismiss, and the sheet does not do that.

Fix:
```css
#admitWho { font-size: var(--fs-2); color: var(--muted); }
#admitWarn.err:not(:empty) { order: -1; font-size: var(--fs-3); color: var(--err-fg);
  padding: var(--sp-3); border-radius: var(--r-s);
  background: color-mix(in srgb, var(--err) 10%, transparent);
  border: 1px solid color-mix(in srgb, var(--err) 40%, transparent); }  /* directly under the title */
.sheet::before { display: none; }
```
Next, in app.js, give `#admitWho` the `u-mark` classes that `contactMark()` already implies (one line), and set `hidden` on the well when there is no key.

**M4. The lists lack the anatomy the direction asked for, and Chats reads as a form.**
Shots: `rework-v1/08-*`, `09-*`, `checks/p-09-chats-empty.png`.
- There are no 40px avatar discs in Users or Chats. The only avatar in the whole app is your own, on Profile.
- The one primary on Chats is the picker's "Open". It stays enabled while the picker holds only "— add users in the Users view first —".

Fix:
- Avatars: one line in app.js, `li.dataset.initial = name[0]`, plus:
  ```css
  .userlist > li { display: grid; grid-template-columns: 40px minmax(0, 1fr); column-gap: var(--sp-3); }
  .userlist > li::before { content: attr(data-initial); … }  /* reuse .avatar at 40px */
  ```
- Change `#chatStart` to a secondary button in index.html, and add:
  ```css
  .inline:has(#chatNew > option:only-child) > #chatStart { opacity: .45; pointer-events: none; }
  ```

**M5. Red means three different things on the Users screen.**
Shots: `rework-v1/08-users-unlocked-{phone,desktop}.png`, `hot/shots/f-users-changed-phone.png`.
- Every row has a 44px tinted-red "Remove".
- A key-changed row adds a red alert pill and a red alert hint with the same icon, which says the same thing twice.
- A phone row is 150–310px tall, so 1.5 rows fit on a screen.

Fix:
```css
.u-actions > .danger { background: transparent; border-color: transparent; color: var(--muted); }
.u-actions > .danger:hover { color: var(--err-fg); }
li:has(> .u-head .u-mark.changed) > .hint.err::before { display: none; }
@media (min-width: 601px) {
  .userlist > li { grid-template-columns: minmax(0, 1fr) auto; }
  .u-actions { grid-column: 2; grid-row: 1 / span 3; align-self: center; }
}
```

**M6. The Live room topbar: two rows on the phone, broken on desktop.**
Shots: `rework-v1/14/15/17/19-*-phone.png`, `rework-v1/15-live-guest-waiting-desktop.png`.
- **Phone:** the topbar is 2 rows (121px). A 44px tinted-red "Disconnect" is the most saturated element on every live screen, including the verify gate, which already has "It differs — disconnect".
- **Desktop:** "waiting for approval" wraps to two lines inside its pill, and the room chip ellipsizes twice ("a27b3471…a61dc8…"). The cause is `#scrChat .topbar .status { white-space: normal }` leaking out of the phone rule.

Fix:
- Desktop:
  ```css
  #scrChat .topbar .status { white-space: nowrap; flex: none; }
  #scrChat .topbar .roomid { flex: none; }
  ```
- Phone, one row:
  ```css
  #copyRoom { width: 44px; padding: 0; font-size: 0; }  /* plus a copy mask icon; text stays */
  #disconnect { background: transparent; border-color: transparent; font-size: var(--fs-2); }
  ```

**M7. The waiting states are dead air.**
Shots: `rework-v1/14-live-owner-connected-*`, `15-live-guest-waiting-*`.
- This is the most common live state, and it shows 500px of empty inset log with two 12px grey lines at the top.
- The only explanation sits in the composer hint.
- The disabled send button is dimmed blue, which reads as "pressed".

Fix:
```css
#log:not(:has(> li.me, > li.peer)) { justify-content: center; }
#log:not(:has(> li.me, > li.peer)) > li.sys:last-child { font-size: var(--fs-3); color: var(--fg); max-width: 32ch; }
.composer button:disabled { background: var(--panel-2); box-shadow: none; color: var(--muted); }
```

**M8. Too much copy, and overlines used as sentences.**
Shots: `rework-v1/04-room-setup-phone.png`, `13-profile-phone.png`, `08-users-unlocked-phone.png`, `17-live-verify-owner-phone.png`, `10-chat-conversation-phone.png`.

Keep these words but move them behind a static `<details class="why"><summary>Why?</summary>`:
- Room: "…Send it however you like — it is useless on its own, because the messages are encrypted end-to-end." Keep only "Both of you must use the same code." visible.
- Room: "If you paste the handle they gave you, we can check the person who joins is really them. Leave it blank and you will compare a safety number instead." (3 lines on the phone). The label says "(optional)", and that is enough.
- Profile: "Scanning only pre-fills your handle on their device — they still verify you by comparing fingerprints in person."

Move or shrink these:
- Profile: "Signing out revokes this device's directory session on the relay, so a copied session token stops working. Your identity and contacts stay on this device." It sits under **Forget identity**, but it explains Sign out. Put it after Sign out, or behind a Why?.
- Username label "Pick a username (optional) — lets people add you by name" plus the hint "Optional: claim a username so contacts can look up this identity.": "optional" twice.
- Verify gate: 5 lines of **centred** 15px grey text. app.js rewrites `#verifyHint`, so do not add markup there. Instead:
  ```css
  .gate .row > .hint { text-align: left; font-size: var(--fs-2); max-width: 46ch; }
  ```
- Composer: "SEALED — hybrid ECDH P-256 + ML-KEM-768, sender sealed inside. Verify this contact in person for the strongest trust." Clamp it to one line on the phone (M1).

Overlines that wrap to two uppercase lines: "INVITE QR — A CONTACT SCANS THIS TO ADD YOU", "FINGERPRINT — WHAT CONTACTS COMPARE WITH YOU IN PERSON", "YOUR HANDLE — SHARE IT SO OTHERS CAN ADD YOU". Split each at the em dash into `.overline` plus a 13px sentence-case caption. The words stay the same; it is a markup change only.

**M9. Desktop reads as a centred form, not an app.**
Shots: all `rework-v1/*-desktop.png`, especially 10–19.
- The column is 632px, below the 720–880 the direction asked for.
- Chat windows are 632×660 cards with more than 300px of nothing on each side.
- The 15px wordmark gives the bar no presence.

Fix:
```css
@media (min-width: 1024px) {
  main:has(.window:not([hidden])) { max-width: 880px; }  /* forms stay at 632 */
  .wordmark { font-size: var(--fs-4); }
}
```
Put the lock tile (today's `.welcome-mark::before`) at 24px in front of the bar wordmark instead of in the hero.

**M10. Boxes in boxes are still there.**
Shots: `rework-v1/06-room-otp-selected-desktop.png`, `hot/shots/b-06b-otp-tools-open-desktop-full.png`, `hot/shots/b-06-otp-phone-full.png`, `rework-v1/03-*`, `08-*`.
- The OTP settings nest four levels: page, `#otpPanel` card, inset `#otpTools` disclosure, `.otp-sub`, dashed canvas.
- `#account` (Live room step 1) and `.myhandle` (Users) are cards wrapped around one field or one line.

Fix:
```css
#otpPanel, #account, .myhandle { background: none; border: 0; box-shadow: none; border-radius: 0;
  padding: var(--sp-5) 0 0; border-top: 1px solid var(--border-soft); }
#otpTools { background: var(--panel); }
```
Also the desktop override `.panel { padding: var(--sp-5) }` must not apply to these.

**M11. The primary button moves around between consecutive screens (desktop).**
Shots: `rework-v1/01-first-run-desktop.png` (Create identity on the left, the ghost "Continue without…" floating right), `03-*-desktop.png` (Continue → on the right), `04-*` (Connect on the left).

Fix: `.nav { justify-content: flex-start; }` on desktop, so every forward action sits on the column's left edge.

### MINOR

1. **The chat code is cut mid-glyph on the phone.** "…39279f99b(": 64 hex characters at 17.6px, and 33 of them fit (`04-room-setup-phone.png`, `checks/p360-04-room.png`). Fix: `#room { font-size: var(--fs-2); letter-spacing: 0 }` and `#room:not(:focus) { -webkit-mask-image: linear-gradient(90deg, #000 85%, transparent); }`. Phase 2: a 2-line `<textarea>` well, which is what the direction meant.
2. **Truncated placeholders.** "…only y", "e.g. alice#a1b2", "username#token (as they sha", and the select "— add users in the Users '". Prose placeholders are set in mono with 0.02em tracking. Fix: `#contact::placeholder, #addHandle::placeholder { font-family: var(--font-ui); letter-spacing: 0 }` and `input { text-overflow: ellipsis }`.
3. **Status chips are all green** ("identity unlocked", "registered", "logged in"; `13-profile-*`). Green should mean verified. Fix: `.chip.on { color: var(--fg); background: transparent; border-color: var(--border-soft) }` and `.chip.on::before { background: var(--ok) }`.
4. **The locked card is narrower than the column.** `.locked { max-width: 560px }` against a 632px column leaves the right edge short (`07/21-*-desktop.png`). It also holds an icon inside a tile inside a card. Fix: remove the max-width, set `.locked::before { display: none }`, and put a 20px inline padlock before the sentence.
5. **The legend wraps with a leading "—"** ("— you compared the fingerprint in person" on its own line; `checks/p-08-users-empty-bottom.png`). Fix: wrap each definition in a `<span>` and use `.legend-item { display: grid; grid-template-columns: auto 1fr; column-gap: var(--sp-2) }`.
6. **Handles are typeset inconsistently.** They are mono in rows and headers, but sans in the Profile name, `#admitWho`, the pending bar and "Registered. Your contact handle is …". They also wrap mid-token ("e2e-alice-" then "aykhq#…"). Fix: `.idhead-sub, #myHandleText { word-break: break-all }`, and set `#accountStatus.ok` in mono.
7. **The live log labels bubbles "peer" and "me"** (`19-live-chat-connected-*`). Async chats have no labels, and in a 1:1 chat the side and colour already say who spoke. Fix: `#log .who { display: none }` and drop the extra `margin-top: var(--sp-5)`. "One message rendering" becomes true.
8. **Orphans.** "…want to talk / to." (04 phone), "you decide who is let / in" (`hot/shots/e-live-chat-360.png`). Fix: `.lede, .hint { text-wrap: pretty }` and `.bubbles > li.sys { text-wrap: balance }`.
9. **The QR is left-aligned on the phone** with an empty right half (`13-profile-phone.png`). Fix: `@media (max-width: 600px) { .qr-row { justify-items: center } .profile-qr { width: 224px } }`.
10. **The pill recipe says "one shape" but has three heights** (20/24/28), three paddings (2/8/10/12px) and `gap: 6px` in three places, which is off the scale. Fix: normalise to `min-height: 24px; padding: 0 var(--sp-3) 0 var(--sp-2); gap: var(--sp-1)`, with 20px only for inline badges. Control heights are also spread across 36/40/44/48/52/56. Keep 44 for controls (40 on desktop) and 56 for rows.
11. **Duplicated recipes.**
    - `#idFingerprint` re-implements `.safety` line for line. Add the class in the markup and delete the 12 lines.
    - `.sheet .row > label`, `.gate .row > label` and `.idhead-name` are three copies of a 20px title. Make it `.title-2`.
    - `.locked::before/::after` and `.welcome-mark::before/::after` are two copies of the icon tile, each centred with `10px` magic offsets. The `.locked::after` offsets are repeated verbatim in the ≥601 block.
    - 49 distinct id selectors carry component styling.
12. **Layout depends on `:has()` in 16 rules.** They include the chat stage, the gate hiding the log, and the sheet scrim. minSdk is 26, so an Android 8/9 device with a stale WebView (<105) gets no scrim. Fix: `@supports not selector(:has(*)) { .sheet:not([hidden]) { box-shadow: 0 0 0 100vmax var(--scrim), var(--shadow-2); } }`.
13. **The background grid and glow do nothing.** The grid alpha is .025, which is 1–2/255 levels (measured). It is not noise, but it is not doing any work either. Delete the 20 lines, or keep only the glow.
14. **Chat rows have a hover state but no keyboard access** (`li` with a click handler). This needs app.js (`tabindex="0"`, `role="button"`); list it for phase 2. The direction also says hover changes the border only, but these rows fill `--panel-2`.

### Scoping decisions I would reverse

- **The wordmark-only sticky top bar on the phone** (direction rule 8) was a mistake. It costs 48px on every screen, does nothing, duplicates every screen title, and appears twice on the welcome screen. On a phone, make it `position: static`, so it scrolls away, and hide it inside chat windows.
- **Avatars were in the direction, but the "app.js only in named places" rule blocked them.** Allow the one-line `data-initial`. Without it, the lists will never look like a messenger.
- **Keep the deferral of two-pane desktop chat, but only if M9 widens the chat window.** A 632px floating card is the weakest desktop screen.

## 3. Three things that are genuinely good; do not "fix" them away

1. **The token system in style.css.** Six sizes and nothing else, the 4/8 spacing scale, the surface ladder with hairlines, no stray colours, and one mask-icon family in `currentColor`. The trust pill (icon + word + 1/2/3 dots) reads without colour. This is the foundation; the fixes above only use its values.
2. **The safety-number band in the verify gate** (`17/18-*`). It runs full-bleed in the inset tone, 5 + 5 groups at 20–24px mono, with stacked equal-width decisions under it. It is the app's terminal snippet and the most considered screen. Keep the band and the grouping exactly as they are.
3. **The encryption disclosure** (`05/06-*-desktop.png`). One row names the current choice and opens into a single hairline-divided list: name, badge, spec in mono, radio on the right. It is the most Kali-like component in the app. The phone tab bar (Material-style pill indicator) and the desktop underline tabs are also right; leave them.

## 4. If only one hour were available, fix these five first

1. **B1: demote "proceed" in the warning states** and stop the "connected" glow during an alarm. About 10 lines of CSS.
2. **B2: the key-changed mark.** Give the mark its own full-width row in `.convo-head` and `.u-head`, give it a box shape, and never let it truncate the name. About 12 lines.
3. **B3 + B4 + the M6 desktop part: the contract and layout bugs.** Pending buttons at 44px on the phone, `scroll-padding` for both bars, a `nowrap` status pill and a non-shrinking room chip. About 6 lines.
4. **M2: the unlocked identity screen.** Hide the pitch and the duplicate wordmark after unlock, promote the overline to the title, quiet the green status, and move Forget to the end as a quiet button. About 10 lines.
5. **M1: phone chat chrome.** Hide the tab bar inside an open conversation and while the keyboard is open, drop the duplicate SEALED chip, and clamp the composer hint to one line. About 15 lines.
