# OTP transfer sheets — design critic, round 3 (the build against the design)

Scope: the implementation on `feat/otp-transfer-sheets` at 448d420, judged against the canvas row
"One-time pad transfer" (version 1790457850-b943, the same version round 2 reviewed) and against
`otp-transfer-brief.md`, including § 9a and § 12, which win where they differ from the canvas.

**Screenshots (real, headless Chromium, scratch relay on :8104):**

- `node e2e/screenshots.mjs` gave 36/37 states and 72 PNGs. 02-drawer-open was skipped because
  there is no drawer. States 25–36 are the OTP sheets, at 390×844 @2x and 1280×800. The contact
  sheet is `index.html` in the same directory.
- `shots/extra/x01–x31` are 34 extra captures with the same fake-bridge and held-KDF injection as
  `e2e/otp-transfer.mjs` (script: `design3/extra.mjs`). They cover the states the harness does not
  reach:
  - the empty panel;
  - New pad, Export and Import while working;
  - the panel after "Later", after "Don't export", locked, and after import errors;
  - file-level import errors;
  - Android cancelled, error and saved;
  - 360×740, and "keyboard up" simulated as 390×460 and 360×400 with a field focused.
- Directory: `/tmp/claude-1000/-home-kpafi-secure-chat/5f8e00c8-7015-466f-9a96-fa9956db20dc/scratchpad/design3/shots/`
  (extras in `extra/`).
- `git diff --stat` was empty right before and right after both capture runs.
- The canvas renders from round 2 were used for the side-by-side comparison.
- The app has no light theme (`style.css` has no `prefers-color-scheme` rule), so dark/light does
  not apply.

## Summary

The build is faithful to the drawing. On the phone the sheets look the same as the artboards,
down to the details:

- head, pad card, 24px discs with the hairline, the two passphrase tokens with their in-field icons;
- the invalid-field mark (triangle, 2px border, label in `--err-fg`, the "Check this one" line);
- the done anatomy, the "On their device" tiles, and the pinned bottom row with its hairline.

§ 12 is implemented as written:

- the empty panel has no primary;
- Export becomes the primary after "Later";
- the received-pad note;
- the entry icons are dropped below 380px so the labels never wrap;
- "128 KiB per side";
- the new Android and iOS copy;
- the desktop "again" link sits at the left.

The one obvious next action is present in every sheet state, and the bottom row stays on screen
with the keyboard up at 390×460 and at 360×400.

What is wrong is mostly at the seams, not in the sheets:

- A sheet's error also lands, visible, in the panel's `#otpStatus` and stays there after the sheet
  closes. That is the one major.
- A step rule mutes steps that are already filled.
- The desktop button order changes from sheet to sheet.
- A pre-existing wrap rule puts Forget on a row of its own.
- The working states leave an empty bottom bar under fields that still look editable.

Counts: **0 blocker, 1 major, 8 minor, 8 nit.**

---

## Major

### R3-M1. A sheet's error is also written, visibly, into the panel, and it outlives the sheet
**Screens:** x14-panel-after-dont-export-390, x15-panel-locked-390,
x17c-panel-after-import-errors-390; also visible behind the scrim in 30-otp-export-again-desktop.

`otpStatusMsg()` (app.js:4822) writes every error to `#otpStatus` with class `hint err`, and
additionally to the open sheet's status. So while a sheet is open the same sentence appears twice:
behind the scrim on desktop, and under the entry row on a phone. After the sheet closes, the panel
copy stays. Two cases seen on screen:

- **After "Don't export":** the panel shows in red, under Export, *"This pad was already exported.
  … Click Export again to confirm you know what you are doing."* There is no "Export again" on the
  panel, and closing disarmed the latch, so the sentence gives an instruction that no longer
  exists. It sits right above the blue Connect and reads as "something failed". It survives Lock
  (x15). It goes away only when some other message replaces it.
- **After a failed import:** "Import failed: unrecognized pad file format" stays in the panel
  under the received-pad note, in red, next to a working pad (x17c).

The spec (§ 3 "Status") puts errors in the sheet ("one per sheet, directly above the bottom row").
The panel line was only meant to keep the pinned text for tests.

**Fix:**
1. `otpStatusMsg`: when `otpUi.sheet` is set, give the panel copy `vh` as well, so the text stays
   byte-identical for the tests and assistive tech but is not shown twice:
   `els.otpStatus.className = "hint" + (isErr ? " err" : "") + (quiet || otpUi.sheet ? " vh" : "");`
2. `closeOtpSheet()`: if the last `#otpStatus` write happened while a sheet was open (keep a flag
   `otpStatusFromSheet`), set `els.otpStatus.textContent = ""` and reset the class to `hint`. The
   dom-stub tests read `#otpStatus` inside the handler, with the sheet open or never opened, so
   clearing it on close does not touch them.

Add to `otp-transfer.mjs`: after Don't export and after an import error plus Escape,
`#otpStatus` is empty or not shown.

---

## Minor

### 1. Filled steps look disabled: every step that is not current gets `--muted`
**Screens:** 31-otp-import (steps 1–2 filled, both grey), 32-otp-import-error and x22 (step 2
filled and step 3 "… — chosen", both grey), x21-import-working (steps 1–2 grey).
**Canvas:** OtpImport and OtpImportError draw filled steps in `--fg`.

`renderOtpImport` marks every step other than the current one as `idle`, and `.otp-step-title` is
`--muted` by default. § 12 says "titles of **upcoming** steps are `--muted`". A step the user has
already filled is not upcoming. The effect is that the phone shows two typed passphrases under grey
titles, as if those steps were switched off, and the file confirmation "pad.json — chosen" is grey
too.

**Fix:**
- JS: an extra state, `otpStep(li, how, filled)`, with
  `li.classList.toggle("is-filled", filled && how === "idle")`. For Import, filled means step 1 has
  `#otpImportXfer.value` (and no `otpImportErr === "pass"`), step 2 has `#otpImportPass.value`,
  and step 3 has `otpImportFile` held.
- CSS: `.otp-step.is-filled .otp-step-title { color: var(--fg); }`.
- Export needs no change: its only non-current, non-done steps really are upcoming.

### 2. The desktop bottom row changes its order from sheet to sheet, and differs from the app's other dialogs
**Screens:** 26-otp-new-done-desktop (primary left, "Later" right), 32-otp-import-error-desktop
(primary left, ghost right), 28-otp-export-done-desktop (ghost left, primary right),
30-otp-export-again-desktop (safe left, danger right). Compare 16-live-admission-prompt-desktop
and 22-contact-profile-desktop.

`.otp-bar` at ≥601px is `justify-content: flex-end` in DOM order, and only `.otp-again` is moved
left. The primary therefore wanders between the left and the right of a right-aligned group. The
app's other two dialogs use a full-width primary on the left, the secondary beside it, and the
ghost centred below.

**Fix (pick one and apply it to every sheet):** either

- **(a) match `#admit` / `#contactSheet`:** at ≥601px keep the phone column, but put the primary
  and one non-ghost side by side: `.otp-bar { flex-direction: row; flex-wrap: wrap; }`,
  `.otp-bar > .primary, .otp-bar > .danger { flex: 1 1 auto; }`,
  `.otp-bar > .ghost { flex-basis: 100%; }` (the ghost on its own centred line); or
- **(b) keep the right-aligned dialog row,** and make every ghost behave like `.otp-again`:
  `.otp-bar > .ghost { order: -1; margin-right: auto; }`, with the primary or danger always last.

(a) is more consistent with the rest of the app. (b) is closer to OtpExportDesktop. Either way,
update § 12 "Desktop bottom row" to state the general rule.

### 3. Forget sits on a row of its own and pushes Connect below the fold
**Screens:** 29-otp-panel-phone, 34-otp-panel-imported-phone, x05, x12, x23.
**Canvas:** OtpPanel shows the select and Forget on one line.

`.inline.wrap > select { flex-basis: 100% }` (style.css:590, pre-existing) forces the wrap on a
phone. Forget is a 44px red button right under the selector, and the row costs about 52px. At
390×844 neither 29 nor 34 shows Connect without scrolling. The canvas's single line keeps Connect
on screen, and there Forget does not dominate.

**Fix:** `#otpPadRow .inline.wrap { flex-wrap: nowrap; }` and
`#otpPadRow .inline.wrap > select { flex: 1 1 0; min-width: 0; }` (the option text already
ellipsizes). At 320px it still fits: the select gets about 200px next to a 90px Forget.

### 4. The working states leave an empty bottom bar under fields that still look live
**Screens:** x03-new-working-390, x09-export-working-390, x21-import-working-360.
**Canvas:** OtpExportWorking has no bottom bar.

- Every button is hidden while working, but `.otp-bar` is still drawn: a hairline and about 56px of
  empty panel at the bottom of the sheet.
- In New pad and Import, all fields stay enabled and look editable during the KDF. Edits do
  nothing, because the values were already read. Export hides its field, so it is fine.

**Fix:**
- `.otp-bar:not(:has(> button:not([hidden]))) { display: none; }`
- In `renderOtpNew` / `renderOtpImport`, add `els.otpNewForm.inert = st === "working"` and the
  same for `#otpImportSteps`, plus CSS
  `.otp-sheet[data-state="working"] :is(.otp-form, .otp-steps) .otp-field { opacity: .6; }`.
  Only the progress keeps focus, as specified.

### 5. Raw browser error text in the Import sheet
**Screen:** from the first extras run (x16/x17, before the path fix). When `file.text()` failed,
the alert read *"Import failed: The requested file could not be read, typically due to permission
problems that have occurred after a reference to a file was acquired."*

This is a real case on Android: a content-URI grant is lost, or Quick Share moves the file.
app.js:5461 prints `e.message` of a DOMException. That is the one sentence in the flow that is not
ours: long, technical, and with no next step.

**Fix:** at 5461, map `e.name === "NotReadableError" || e.name === "NotFoundError"` to
**"Import failed: could not read that file — choose it again."** Fall back to the current text
for anything else. (It is a file-level error, so "Choose another file" is already the primary.)

### 6. "Didn't arrive? Send it again" after *Save*
**Screens:** x30-android-saved-390, x31-android-saved-360.

After `saved` the file is in the user's own Files, and nothing was sent, so "Didn't arrive?"
answers a question the user never had. The link returns to file-ready (Share / Save), which is
right. Only the words are wrong.

**Fix:** app.js:5712: when `otpExportResult === "saved"` → **"Share or save it again"**. Keep
"Didn't arrive? Send it again" for `shared`.

### 7. Keyboard up on a short phone: the tab bar and the app head still eat the space
**Screens:** x19-import-keyboard-up-390x460, x20-import-keyboard-up-360x400,
x25-new-keyboard-up-390x460.

The bottom row does stay visible. That is the § 3 promise, and it holds. But the sheet docks above
the 64px tab bar and under the 48px app head, both inert under the scrim. At 360×400 (a typical
Android height with the keyboard up) this leaves about 250px for the sheet, the bottom row takes
about 120px of that, and step 3 is hidden behind it (x20).

**Fix:** only on short phone viewports, let the open sheet cover the chrome it has already made
inert:

```css
@media (max-width: 600px) and (max-height: 560px) {
  .sheet.otp-sheet { bottom: 0; max-height: 100dvh; z-index: 30 /* above #tabbar */; }
}
```

Use the same rule for `#contactSheet`, so the two stay alike.

### 8. The weak-transfer-passphrase line reads as a fourth item for the receiver
**Screen:** x10-export-done-weak-390.

`#otpExportWeak` is rendered inside `#otpExportTheirs`, after "this file". Under the overline "On
their device: One-time pad → Import" it reads as something the receiver needs.

**Fix:** move `#otpExportWeak` out of `.otp-theirs`, into `.otp-done-text` after `#otpHanded` (the
same place `#otpNewWeak` and `#otpImportWeak` hold relative to their done lines), so it sits above
the pad card.

---

## Nit

1. **"· exported before" wraps as its own line that starts with the dot** (30-otp-export-again-phone,
   x13 at 360). The nowrap works (r2 nit 1), but the new line begins with "·". Move the separator
   outside the nowrap span, so the preceding text ends "you generated ·" and the next line reads
   "exported before".
2. **Connect changes width between states:** narrow when secondary (x05, x01), full-flex when
   primary (x12, x23). `.connect-row > .primary { flex: 1 1 auto }` (style.css:1880) applies only
   to the primary. Use `.connect-row > #connect { flex: 1 1 auto; }` so it stays put when the
   emphasis moves.
3. **"· exported" appears in Android file-ready** (35, x27, x28), before anything has left the
   phone. It is truthful to the latch, but the canvas OtpExportReady does not show it, and it
   pre-empts the done state. Show it only in `done`: in `renderOtpExport`, `st === "done"`.
4. **The invalid field shows two rings when it has focus** (27-otp-export-phone,
   32-otp-import-error): the blue focus halo sits around the red 2px border. Use
   `.otp-field > input[aria-invalid="true"]:focus { box-shadow: 0 0 0 3px color-mix(in srgb, var(--err) 30%, transparent); border-color: var(--err); }`.
5. **At 360 the label row crowds** (x07-export-form-360): the "?" and the "you both know it" pill
   touch, with about 2px between them. Use `.otp-fieldrow { column-gap: var(--sp-2); row-gap: var(--sp-1); }`,
   so the pill wraps under the label when it does not fit rather than touching.
6. **The mono file name breaks inside itself at 360** (x11: "secure-chat-pad-2026-09-27-" /
   "0121.json"). Below 380px, use `.otp-file-name.mono { font-size: 12px; }` so the name that
   people search for in Downloads stays on one line.
7. **At 360 the error alert is half hidden under the sticky bar** (x22). Focus goes to the marked
   field at the top, which is right, but the alert's second line is cut off. After focusing, call
   `els.otpImportStatus.scrollIntoView({ block: "nearest" })` with the field focused
   `{ preventScroll: true }`. Both fit at 360×740.
8. **The empty-state caption leaves an orphan** at 360 (x02: "…the other imports / it."). Add
   `text-wrap: pretty` on `.otp-caption, .otp-lede`. It also fixes the lede break in x07 and x31
   ("Give this file to one person, / for one device.").

---

## Where the build is better than the drawing

- **Desktop "again" link** (28-desktop): at the row's left, with Done at the right. That is cleaner
  than OtpExportDesktop's link under the done line (r2 nit 3, § 12).
- **Invalid mark** (27, 32): the label turns `--err-fg` too, so shape, word and colour agree. The
  canvas coloured only the field.
- **Entry row at 360** (x02, x06): the icons are dropped and the labels stay on one line. The
  canvas wrapped "New pad" at 360.
- **Received-pad panel on desktop** (34-desktop): the two-column entry grid reads as intentional,
  not as a gap where Export was.
- **Copy:** the done list's first row, "the transfer passphrase — tell them, never send it", now
  holds the one warning on every platform, and "On their device: One-time pad → Import" says
  where. Both are better than the drawn text (r2 minors 2 and nit 8).

## Where it is worse

The muted filled steps (minor 1), Forget on its own row (minor 3), the empty working bar (minor 4)
and the double error (R3-M1). The first three are CSS or render-rule deviations from the artboards.
The fourth is not in any artboard, because the canvas never drew the panel and a sheet at the same
time.

## Consistency with the rest of the app

- **Phone:** the sheets match `#contactSheet` (22-contact-profile-phone) in radius, gutter, the
  pinned bottom row with its hairline, and the ghost colour for the quiet action.
- **Status alerts:** the sheet alert box matches `#admitWarn`. The panel's red inline line matches
  the Users unlock error (21), which is one more reason the panel should not show sheet errors
  (R3-M1).
- **Desktop:** only the button order differs from the other dialogs (minor 2).

## One obvious next action per state

Every sheet state has exactly one blue button, or none in re-export confirm, working and the empty
panel, as § 12 intends. The next action is also clear in each of these states:

- Import's file-level error ("Choose another file");
- Android cancelled or error: Share stays the primary, and the status line says what happened;
- the panel after "Later" (Export is the primary);
- after export (Connect is the primary).

The one state where the next action is muddled is the panel after "Don't export" or after an
import error (R3-M1).

## For the harness (not findings)

`screenshots.mjs` does not capture:

- the empty panel;
- any working state;
- Android `saved`, `cancelled` and `error`;
- a file-level import error;
- the panel after a closed sheet;
- 360px.

It also takes the panels (29, 34) as viewport shots that cut off Connect. The extras script
(`design3/extra.mjs`) shows how to reach each of these. Adding them as fixed states 37+ would let
round 4 compare file by file.
