# OTP transfer sheets — design critic, round 1

Scope: the canvas row "One-time pad transfer" (12 `Otp*` artboards, version 1790456558-6d19), rendered at
390×844 and 1280×800 and read in source. Compared against ContactProfile, Admit, RoomOptions and
`otp-transfer-brief.md` § Design decisions, `direction.md` and `direction-contract.md`. Where the brief
specifies a state the canvas does not draw, the brief is judged.

Summary: the skeleton is right. Each sheet has one obvious primary, the steps read top to bottom, and
the working state is honest. What is wrong is mostly at the edges: what the two passphrases are called,
the first-run panel, and the done states claiming more than happened.

Counts: **1 blocker, 9 major, 11 minor, 7 nit.**

---

## Blocker

### B1. "travels with the file" tells the user to send the passphrase with the file
**Artboards:** OtpExport, OtpExportAgain, OtpImport, OtpImportError (and the brief § 0, § 3.1, § 5.1)

The transfer-passphrase tag says **"travels with the file"**. Read literally by a non-expert, it means
"this passphrase goes along with the file". That is exactly the one thing the flow must prevent. Two
lines further down, OtpExportWorking says "never send it with the file". The token meant to make the
two secrets impossible to confuse teaches the dangerous reading of one of them.

The visual difference is also too weak to carry the job on its own. The two fields have the same size,
border, fill and dots. The only things that differ are a 16px glyph inside the field (phone vs file)
and a 12px grey pill. On OtpImport the two fields are stacked 60px apart and look like a
"password / confirm password" pair. A user skimming it will type the same thing twice. The must-differ
rule (M3) then catches the literal case, but not the confusion.

**Fix:** base the distinction on *who knows it*, which is the real difference, not on where it is stored:
- Transfer: tag **"you both know it"** with a two-person icon (reuse the Users tab glyph). Field glyph:
  the same two-person icon, not a file.
- Pad: tag **"only you know it"** with a single-person or phone icon.
- Say the same in the step titles, so the tag is not the only carrier. Export 1 is already fine. Import 1
  "The passphrase you agreed on" is fine. Import 2 / New 3 "Protect it on this device" → **"Your own
  passphrase for this device"**.
- Optionally give the transfer field a visible difference beyond the glyph: a 2px `--border` dashed
  left inset, or the label on the same line as a small "shared" pill in the neutral style. Never tint
  by colour alone.
- Change the same word everywhere the brief says "the same token appears" (panel, New, Export, Import,
  the "On their device" rows).

---

## Major

### M1. The first-run panel (`#otpEmpty`) is not drawn, and as specified its only primary is a dead end
**Artboards:** OtpPanel (the brief § 1.1)

The owner's real first screen is "no pad yet". The canvas draws only the populated panel. In the
empty state as specified, `#otpPadRow`, `#otpPassRow` and Export are hidden, two secondary buttons
remain (New pad, Import), and **Connect stays the one blue primary**. Connect cannot succeed without a
pad, so the eye goes to a refusal. That contradicts "what to tap is obvious from the layout".

**Fix:** draw the empty state. In it, put the two entries *inside* the empty card: "New pad" and
"Import", side by side, with New pad as the card's primary. Hide Connect, or render it disabled with
the hint underneath, until a pad exists. This keeps one primary and makes that primary the right one.
The hint line "One of you makes a pad… the other imports it" can then be cut to "One of you makes it,
the other imports it." The two buttons already say which.

### M2. The panel orders the pad passphrase *after* the Export button that needs it, and shows an empty field for a pad that is already unlocked
**Artboards:** OtpPanel (the brief § 1.3–1.4, § 1 Export entry)

Top to bottom the panel reads: pad → [New pad | Export | Import] → Pad passphrase → Connect. For a pad
made earlier, Export needs `#otpPass`. So the first tap on Export is refused ("Enter this pad's
passphrase…"), and the error appears *below* the field, under the tapped button. Conversely, after New
pad or Import the pad is cached (`otpPanel`, see `ensureUnlocked`). Connect works without typing
anything, yet the panel shows an empty "Pad passphrase" field. The field looks like a required step
that is not needed, and ImportDone's "then Connect" makes the user wonder whether to fill it.

**Fix:**
- Order: pad select → its passphrase row → entry row → status → Connect. The passphrase belongs to the
  selected pad; putting it directly under the pad says so.
- When `otpPanel.padId` equals the selection, replace the input with an "unlocked" row: phone token,
  check icon and the words "Unlocked for this session". Offer a ghost "Lock" button if needed. Draw
  this state; it is the one every user lands on after New pad and Import.

### M3. The "two secrets must differ" rule is bypassed in the main flow (New pad → Export)
**Artboards:** OtpNewDone → OtpExport (the brief § 3 form "new rule", § 2 Clearing, § 4 hand-off)

The export check compares `#otpXferPass` with `#otpPass` (panel) only "if `#otpPass` is non-empty". In
the flow the canvas is built around, the pad passphrase was typed in `#otpNewPass`. That field is
cleared when New pad closes, which the hand-off does. `#otpPass` was never touched, so the rule never
fires. The same holds for Import → (later) Export on the other side.

**Fix:** on a successful generate or import, write the passphrase just used into `#otpPass`. It is the
same secret with the same meaning, and today's panel held it there anyway. This also gives M2's
"unlocked" row a real basis. Alternatively, run the compare in the hand-off before `#otpNewPass` is
cleared. The first option fixes more.

### M4. The done states claim "File handed over" when nothing has been handed over
**Artboards:** OtpExportDone, OtpExportDesktop (the brief § 3 table, done block)

The done block title is "File handed over" after any of these:
- a **browser download**: the file sits in *my* Downloads;
- an **Android "Save to device"**: the file sits on *my* phone;
- an **iOS share sheet merely opened**: the page gets no result at all.

In every one of these cases the real handover (USB, Bluetooth, in person) has not happened yet. The
sheet tells the user they are finished exactly when the step the flow is named after is still ahead.
OtpExportDesktop shows the contradiction directly: "Downloaded secure-chat-pad-…json" and then
"File handed over".

**Fix:** title the done block with what actually happened: "File shared", "File saved to this device"
or "File downloaded". For saved or downloaded, keep step 3 current with one line: "Now give it to them
— USB stick, Bluetooth or AirDrop, in person." Only a `shared` result may mark step 3 done. On iOS,
use "Share sheet opened" and keep "Share again".

### M5. "Share again" / "Save again" are full-weight buttons in the done state: an invitation to the catastrophic act
**Artboards:** OtpExportDone, OtpExportDesktop

The whole point of the pad warnings is "one person, one device". The done state still shows two
bordered 44px buttons, each as large as the Done primary, that send the same file somewhere again.
They are the heaviest thing on screen after Done, and they sit directly above the "On their device"
block. A second share to a second person is the two-time pad the re-export latch exists to stop, and
"again" bypasses that latch by design ("not a new export: no KDF, no latch").

**Fix:** in the done state, collapse them to one ghost text link under step 3: "Didn't arrive? Share
it again". On Android it opens the same two-choice pair only after that tap. Keep the full buttons
only in the "file ready" state and after `cancelled` or `error`.

### M6. The re-export confirm has no safe way out except ×
**Artboards:** OtpExportAgain (the brief § 3 re-export confirm)

The sheet's only button is the red "Export again". The app's own rule ("Warnings demote proceed:
Deny / It differs come first", AdmitWarn, VerifyChanged) puts the safe choice first and visible. Here
the safe choice is the 44px × at the top right, which a first-time user reads as "close", not as
"don't". The five-line alert sits where the primary used to be, so the eye lands on red text plus a
red button and nothing else.

**Fix:** add **"Don't export"** (secondary, closes the sheet) *before* "Export again", stacked
full-width. That is still no `.primary`, so the brief's rule holds. Also mark step 1 done in this state
(the passphrase is set) and hide its field. Otherwise the user wonders whether to retype it.

### M7. "Which passphrase was wrong" is shown by colour alone
**Artboards:** OtpImportError (the brief § 5 error)

The brief says "the layout says *which* passphrase without a new sentence". What carries it is a red
border, a red label and a red-tinted file glyph. The glyph keeps the same shape. The alert text
("wrong passphrase or corrupted pad file") names no field. A user who cannot tell red from grey sees
two identical fields and a generic error. `aria-invalid` covers screen readers only. This breaks the
direction's "not colour-only" rule, which trust marks meet with icon, word and dots.

**Fix:** add a non-colour cue on the field. Swap the field glyph for the triangle-alert shape, and add
a 13px line under the field: **"Check this one — it must match your contact's."** Tie that line in via
`aria-describedby`. The pinned sentence stays unchanged in the alert.

### M8. The weak-passphrase box is the only wall of text in the flow, and it repeats what the user just saw
**Artboards:** OtpNewDone (and `#otpExportWeak`, `#otpImportWeak` per the brief)

The box is five lines: "Pad passphrase — Weak passphrase: it is shorter than 12 characters. Anyone who
copies the encrypted data can try guesses offline, at their own pace — use 12 or more characters… (A
warning only: it was accepted.)". It is the largest text block in the whole row. It comes *after* the
live weak line under the field already said the same thing, and it pushes the hand-off button down.
The artboard also shows it for a 27-character passphrase ("lantern orbit velvet quarry" in OtpNew),
so the pictures contradict each other.

**Fix:** in the done block, one warn line with the icon: "Weak pad passphrase — accepted." plus a "?"
that holds the full pinned sentence (the full sentence stays in `#otpStatus`, which the tests read).
Or drop it from the done block entirely and rely on the live line. Fix the sample data on the canvas.

### M9. Export is offered for an *imported* pad with no warning (missing state)
**Artboards:** OtpPanel, OtpExport (the brief § 1 Export entry, § 3)

The pad card knows "· imported" and the select option says "imported". Nothing in the brief hides
Export, or warns, for a pad this device *received*. As far as I can see in `otp.js` `exportPad()` and
`otpExportFrom()`, only the `exported` flag and "already used" are checked. An imported pad is
pristine and not flagged. An importer who taps Export gives a third device the generator's role, which
is a two-time pad. Someone must confirm this in code; the design has to decide it either way.

**Fix:** for `role === 1` pads, hide Export. If Export stays visible, the sheet should open in a
refusal state: "You received this pad — only the person who made it can export it."

---

## Minor

1. **OtpNew — the "?" is in the wrong place.** It sits on the header hint ("Made on this device, then
   exported…"), but its label and text are about *drawing*. Move it into step 2's title row.
2. **OtpNew — the numbered steps add weight without adding order.** Name/size, an optional scribble
   and a passphrase are a plain form. "Current step follows focus" is extra machinery, and filled
   steps 1–2 are drawn as grey "upcoming", which reads as "not done". Keep the numbers, but drop the
   current/upcoming states in this sheet, or mark a step done when its field is valid. Consider making
   the drawing an unnumbered optional block so the sheet has two real steps.
3. **OtpNew — "Entropy from drawing: 212 motion samples captured."** is jargon under a picture that
   already shows the line. Show a quiet check ("Added") or nothing. If the sentence is pinned, keep it
   visually hidden (`.vh`) and let the drawing be the feedback.
4. **OtpImportError — the retry costs a file re-pick.** After a wrong passphrase the user fixes step 1
   and must tap "Choose pad file…" and find the file again. Either keep the picked file (text, size
   capped, dropped on close) and show a "Try again" primary, or at least relabel the button "Choose
   the file again" so the user knows why the picker reopens.
5. **OtpExportDone — the handover is confirmed twice.** Step 3 says "Handed over ✓ Shared." and a big
   check disc says "File handed over" right below it. Keep one: the disc, and hide step 3's caption,
   or the reverse.
6. **OtpExportDone / Desktop — "On their device" uses the same numbered discs as my own steps.** Two
   1-2-3 lists in one sheet, and the second one reads as more steps for *me*. Draw the contact's list
   with the passphrase tokens instead (the two-person token for "the same passphrase you agreed", the
   single-person token for "their own passphrase", a file glyph for "this file"). That reinforces B1's
   icons and removes the second count. Drop the fragment "Import, then": use the overline "On their
   device: Import" and three rows.
7. **Primary placement differs between sheets.** New pad's concluding action is pinned in the sticky
   bottom row, while Import's ("Choose pad file…"), which also concludes its sheet, sits inside step 3
   and scrolls. With the Android keyboard up after typing step 2, Import's primary is off-screen and
   New pad's is not. Either pin Import's too (it concludes the sheet) or state the rule and apply it
   the same way.
8. **Done states are built differently.** NewDone and ImportDone drop the steps and show disc + card +
   line. ExportDone keeps all three steps and adds the disc block. Choose one anatomy: disc + card +
   next action is the lighter one.
9. **OtpExportWorking — a disabled × at 45% opacity** invites taps that do nothing. Hide it while
   working, since "Keep this open" already explains why, or keep it with a tooltip-free `aria-disabled`.
   Hiding it is simpler.
10. **OtpExport / OtpExportAgain — the re-export warning comes after the in-person agreement.** The user
    agrees a transfer passphrase face to face and only then learns the pad was already given away. The
    index's `exported` flag is non-authoritative but good enough for a *hint*: show "· exported before"
    in the pad card meta when the sheet opens. The authoritative check stays on the first tap.
11. **OtpNew — the name placeholder "e.g. Alice ↔ Bob 2026"** teaches users to put both names in a label
    that becomes the file name in Downloads and share targets (the brief's open question). Until the
    owner decides, use a neutral placeholder ("e.g. Chess club").

## Nit

1. **OtpExportDesktop:** the mono file name wraps mid-name ("secure-chat-pad-" / "Alice_Bob_2026.json")
   to make room for "Download again". Put the name on its own line and the ghost button under it.
2. **Mono for the file name** is outside "mono only for key material". The brief makes this exception
   on purpose. Fine for the browser, where the user searches Downloads for the name. On Android, where
   the user never types or searches it, use the UI font.
3. **The pad icon (2×3 grid)** reads as a table or spreadsheet. A stack of sheets or a perforated strip
   says "pad".
4. **OtpImportError** lost the "?" on the hint line that OtpImport has. Keep the head identical across
   states.
5. **OtpNew — the size option text truncates** at 390 ("…short messages…"), cutting the useful part.
   Move the message count to a caption under the select.
6. **OtpNewDone — "Next: hand it to your contact, in person."** repeats the button under it ("Export to
   your contact"). Cut it.
7. **OtpPanel sample state** shows the long "Exported. …" success sentence in `#otpStatus` under the
   passphrase after the sheet closed. It is a third copy of what the done block said. Clear it on the
   panel's next interaction, or render success sentences in the panel as `.vh` only (tests read
   `textContent`).

## Checked and fine

- One `.primary` per drawn state. The re-export state deliberately has none. The 44px targets hold,
  and the "?" rings grow to 44px on phones via the existing `.why` rule. Nothing overflows horizontally
  at 390.
- The indeterminate bar is honest, with a reduced-motion variant. Working states are not dismissible,
  and the brief explains why.
- The Android "file ready" state (Share… primary, Save secondary, one caption) is the clearest screen in
  the row. It is the model the others should match.
- Sheet chrome (overline, 20px title, ×, sticky bottom row, scrim over an inert tab bar) matches
  ContactProfile and Admit.
