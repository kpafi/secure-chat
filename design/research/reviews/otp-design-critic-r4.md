# OTP transfer sheets — design critic, round 4 (the build after fix round 1)

Scope: `feat/otp-transfer-sheets` at 2e50caa, judged against my round-3 report
(`otp-design-critic-r3.md`), its triage (`otp-fix-round-1.md`) and brief § 13, which wins over
§§ 1–12. The canvas row "One-time pad transfer" is still version 1790457850-b943, the version
rounds 2 and 3 reviewed.

**Screenshots (real, headless Chromium, scratch relay on :8104, killed by PID afterwards):**

- `node e2e/screenshots.mjs`: 37/38 states, 74 PNGs. 02-drawer-open was skipped: there is no
  drawer. 37-otp-panel-empty is new.
- Extras: 53 captures plus 1 re-capture (`design4/extra.mjs` and `design4/measure.mjs`; the
  round-3 script extended). New in the extras:
  - 1280 captures of New pad working, the panel after Later, the Export form, Export done (weak),
    an Import file-level error, the received-pad panel, and Android saved and shared;
  - the Export entry refused with an empty passphrase and with a wrong one;
  - the Export form with the keyboard up;
  - Import done at 360 and 390;
  - Android "shared" after "Share or save the same file again", at 390, 360 and 1280.
- Directory: `/tmp/claude-1000/-home-kpafi-secure-chat/5f8e00c8-7015-466f-9a96-fa9956db20dc/scratchpad/design4/shots/`
  (extras in `extra/`, contact sheet `index.html`).
- `git diff --stat` was empty before and after both runs. The only untracked path was
  `client/node_modules`, a symlink.
- Some shots show a ghost button in its `:hover` look: x04 "Later", x10 "Download the same file
  again", x30. That comes from the capture: the pointer stays where the previous button was.
  It is not a finding.
- iOS done ("Share sheet opened") cannot be reached from a browser (`secure-chat:` protocol).
  I judged it from the code only.

## Summary

Every round-3 finding is fixed as a user sees it, except that the desktop bottom-row fix went
one step too far in the re-export confirm (see minor 2).

The major is gone:

- no sheet sentence reaches the panel, with a sheet open or after it closes (x14, x17c, and
  behind the scrim in 30-desktop);
- the panel's own refusals, which exist only when no sheet is open, read well and move focus to
  the passphrase field (x15b, x15c).

The whole flow still reads layout-first at 390, 360 and 1280. Each new line is short and sits
where it belongs. The added copy did cost some space:

- the browser Export done at 360 now needs a scroll to reach "On their device" (x11);
- one new sentence does not fit every platform it is shown on (minor 1).

Regressions: three small ones, all side effects of the round-3 fixes (minor 2, minor 3, nit 1).

Counts: **0 blocker, 0 major, 4 minor, 6 nit.**

---

## Verification of round 3

| R3 | What I asked | What a user sees now | Screens | Verdict |
| --- | --- | --- | --- | --- |
| M1 | No sheet error in the panel, and nothing left behind | Panel under Export is empty after Don't export (x14), after Lock and after two failed imports (x17c); nothing behind the desktop scrim (30-desktop). Panel refusals now exist only with no sheet open (x15b, x15c) | x14, x15, x17c, 30-d | **Fixed** |
| 1 | Filled steps not muted | Filled Import steps keep `--fg` titles; step 3 "…— chosen" caption stays muted, as a caption should | 31, 32, x21, x22 | **Fixed** |
| 2 | One desktop button order | Primary (or danger) + ghost below, as in #admit: 26, 28, 32, x11d, x31d. **Re-export confirm:** "Don't export" narrow on the left, "Export again" growing on the right — the danger is the widest target in a state that is meant to have no primary; § 13's text says the danger leads on the left | 26-d, 28-d, 30-d, 32-d, 35-d | **Fixed, but see minor 2** |
| 3 | Pad and Forget on one line | One line at 390, 360, 1280. At 390×844 Connect's top half now shows above the tab bar without scrolling (it was fully hidden) | 29, 34, x05, x06, x05d | **Fixed** |
| 4 | No empty bar while working; fields look inert | Bar not drawn; New pad form and Import steps inert; fields at 0.6 (measured). New: the progress card now touches the sheet's bottom edge | x03, x03d, x09, x21 | **Fixed, see minor 3** |
| 5 | No raw DOMException text | Mapped at app.js:5501 ("could not read that file — choose it again."); not reproducible from a harness, trusted to F18 | — | **Fixed (code + unit test)** |
| 6 | No "Didn't arrive?" after Save | "Share or save the same file again" after Save; "Didn't arrive? Send the same file again" after Share | x30, x32, x33 | **Fixed** |
| 7 | Short phone: sheet may cover the inert chrome | At 390×460 and 360×400 the sheet runs from 12px to the bottom; app bar and tab bar are covered; step 3 now reachable under the fields (x19) | x19, x20, x25, y01 | **Fixed** |
| 8 | Weak line out of "On their device" | Under the done line, above the card | x10, x11, x11d | **Fixed, see nit 3** |
| n1 | "·" never starts a line | "you generated ·" / "exported before" | 30, x13, y01 | **Fixed** |
| n2 | Connect keeps its width | Same width as secondary (x05, x06) and as primary (x14, 29) | x05, x14 | **Fixed** |
| n3 | "· exported" only in done | Absent in Android file-ready, present in done | 35, x27, 36 | **Fixed** |
| n4 | One red ring on a focused invalid field | One red ring, no blue halo | 27, 32, x22 | **Fixed** |
| n5 | Label row at 360 not crowded | The pill wraps onto its own line under the label and "?", right-aligned | x07, y01 | **Fixed** |
| n6 | File name on one line at 360 | One line (12px mono) | x11 | **Fixed** |
| n7 | Import error alert fully visible at 360 | Alert and both buttons fully visible; the field keeps focus | x22 | **Fixed** |
| n8 | No orphans in captions and ledes | Captions fixed (x02). **The Export lede got worse at 360**: "…for one / device. ?" — see nit 1 | x02, x07, x11, x13, x27, x33 | **Caption fixed, lede regressed** |

## The new copy

**"Delete the file" lines**

- Import done: "Delete the pad file now." It is short and direct, and it names an action the
  receiver can take, because the file is in their Downloads.
- Export done (browser, Android "saved"): "Once they've imported it, delete the file on both
  devices." Also clear.
- Export done after Android "shared" and after the iOS share sheet: see minor 1. On that path
  the sender has no copy they can see.

**"each way" sizes**

- The cards now read "128 KiB each way · you generated" and "128 KiB each way · from your
  contact". This is clearer than "per side", and the number now means what it says.
- Two leftovers:
  - the picker says "each way" twice within three lines (nit 4);
  - the pad selector still says "(you generated, 128 KiB/side)" and "(imported, …)" (nit 5).

**"from your contact"**

- Better than "imported". It explains why the label is the maker's without adding a line.

**The "again" link**

- At 13px and `--muted` it now reads as a link, not a second button (28, 36, x33).
- "the same file" is the right phrase: it tells the user that no new file is made.
- The longest label, "Didn't arrive? Send the same file again", fits on one line at 360 (x33).

**Text creep**

- Measured against round 3, the done blocks grew by one caption each (Export) or one line
  (Import).
- At 390 every done state still fits without a scroll, with the bottom row pinned (28, 33, 36,
  x30).
- At 360 two states now scroll to reach the end of "On their device":
  - the browser Export done with a weak transfer passphrase (x11 → x11b);
  - the Android "saved" state.
- This is acceptable because the bar is pinned and the list is reference, not action. It is
  also the reason not to add more lines here (see minor 1: fix it by replacing words, not
  adding them).

---

## Minor

### 1. "Delete the file on both devices" tells the Android "shared" and the iOS sender to delete a file they cannot find
**Screens:** 36-otp-export-shared-android, x32, x33 (and iOS "Share sheet opened", read from the code).

- After Share… on Android, the sender's copy is the app's FileProvider file. The user never
  sees it, and it ends on its own by expiry (10 min, per the Android fix round).
- On iOS the share sheet's copy is in the app's temporary folder.
- In both cases "delete the file on both devices" sends a careful user into Files to look for
  a file that is not there. In a one-time-pad app, "where did my pad file go?" is a worrying
  question to leave open.
- For "downloaded" and "saved" the line is exactly right.

**Fix:** word the line per result in `renderOtpExport`, the same way `T` already words the
done line:

- downloaded, saved: "Once they've imported it, delete the file on both devices." (unchanged)
- shared, iOS: **"Once they've imported it, they delete the file."** It is the same length or
  shorter, and it gives no instruction the sender cannot follow. The app removes its own copy.

Update § 13 "Delete the file" to match.

### 2. Desktop re-export confirm: the danger is the widest button in a state with no primary
**Screen:** 30-otp-export-again-desktop.

- `.otp-bar > :is(.primary, .danger) { flex: 1 1 auto }` makes "Export again" grow to about
  70% of the row. "Don't export" keeps its natural width at the left.
- In a confirm that § 12 deliberately leaves without a primary, the risky choice now looks
  like the default.
- The order (safe first) is right, and it matches the phone. § 13's sentence "the primary (or
  the danger) grows on the left" does not describe what was built.
- #admit gives its two choices equal halves (16-desktop).

**Fix:**
- `.otp-bar:has(> .danger:not([hidden])) > button:not([hidden]) { flex: 1 1 0; }`: equal
  halves, safe choice on the left.
- § 13: "…a ghost on its own line below; in the re-export confirm the two choices are equal
  width, the safe one first."

### 3. Working state: the progress card sits flush on the sheet's bottom edge
**Screens:** x03 and x03d (New pad), x21 (Import at 360). Measured: New pad working, progress
bottom = sheet bottom (780 = 780 at 390; 725 vs 726 at 1280). Import is the same, because its
progress is the last thing in step 3.

- The hidden bar used to supply the sheet's bottom padding (`.otp-sheet { padding-bottom: 0 }`).
- With the bar gone, the card's lower border meets the sheet edge on desktop. On a phone it
  meets the tab bar, and it looks cut off.
- Export working does not show this, because step 3 follows its progress.

**Fix:** `.otp-sheet[data-state="working"] { padding-bottom: var(--sp-4); }`, and
`var(--sp-5)` inside the ≥601px block.

### 4. Export done: the weak line splits the two instructions
**Screens:** x10, x11, x11d.

The done text now reads, in order:
1. "Now give it to them in person — USB stick or Bluetooth."
2. ⚠ "Weak transfer passphrase — accepted." (?)
3. "Once they've imported it, delete the file on both devices."

The two instructions (hand over, then delete) are split by a warning about the past. At 360
the warning's "?" also wraps onto a line of its own under the ⚠ (x11).

**Fix:**
- Move `#otpExportWeak` after `.otp-delete` in `index.html`, so the instructions come first
  and the warning last, just above the card.
- At < 380px, `.otp-weak { flex-wrap: nowrap; }` with the text allowed to wrap
  (`.otp-weak > p { min-width: 0; }`), so the "?" stays at the end of its line.

---

## Nit

1. **Regression: the Export lede leaves "device." alone at 360** (x07, x11, x13, x27, x33, y01:
   "Give this file to one person, for one / device. ?").
   - `.otp-lede { text-wrap: pretty }` (style.css:2106) comes later than, and overrides,
     `.qline { text-wrap: balance }` (style.css:1543).
   - `balance` is what gave round 3 its "…one person, / for one device.", and it also keeps
     the "?" from being left alone.
   - Fix: drop `text-wrap: pretty` from `.otp-lede`, or add `.otp-lede.qline { text-wrap: balance; }`.
     Keep `pretty` on `.otp-caption`, where it fixed x02.
2. **Import done: the delete line comes after the "what next" line** (33, x22b):
   - the order is "It is selected. Agree on a chat code…, then Connect." and then "Delete the
     pad file now.";
   - the user's eyes move on to Connect before they reach the one-time chore.
   - Swap the two captions, so the delete comes first and the next step last. There is no
     change in length.
3. **Weak line placement at 1280** (x11d): as in minor 4 it sits between the two instructions.
   Minor 4's fix covers it; I list it here so the desktop check is not forgotten.
4. **"each way" twice in the New pad picker** (25, x26, x03d): the label is "Size, each way" and
   the hint is "~1,400 short messages each way". The canvas had the label "Size" with the same
   hint. Keep the label (it matches the cards) and make the hint "~1,400 short messages".
5. **The pad selector keeps the old words** (x05d: "Chess club (you generated, 128 KiB/side)";
   34 "(imported, …)"). app.js:5154. The cards say "each way" and "from your contact". Use
   `` `${p.label} (${p.role === 0 ? "you generated" : "from your contact"}, ${fmtBytes(p.regionSize)} each way)` ``.
   On a phone the option text ellipsizes before the size anyway, so this matters on desktop.
6. **Share / Save at 1280 are about 60 / 40** (35-desktop): #admit's two choices are equal
   halves. The rule in minor 2 (equal halves when the row holds two non-ghost buttons) would
   give Share / Save the same treatment:
   `.otp-bar:not(:has(> .ghost:not([hidden]))) > button:not([hidden]) { flex: 1 1 0; }`.
   Optional. The primary colour already says which one comes first.

---

## Layout-first check (390 / 360 / 1280)

- **390:**
  - every sheet state keeps head → pad card → steps or done block → pinned bar;
  - no state needs a scroll to reach its action;
  - the panel is one line shorter (Forget), and Connect now peeks above the tab bar.
- **360:**
  - forms still fit (x07, x26);
  - the Import error fits in full (x22);
  - Export done with a weak passphrase, and Android "saved", scroll for the rest of "On their
    device" (acceptable, see "Text creep");
  - the lede orphan (nit 1) is the only visible text flaw at this width.
- **1280:**
  - the dialogs read as dialogs of this app: full-width primary, quiet ghost centred below
    (26, 28, 32, x11d, x17d, x31d, x33d);
  - the confirm row is the one exception (minor 2);
  - working at 1280 shows the flush progress card (minor 3).
- **Keyboard up** (x19, x20, x25, y01): the sheet takes the whole height, and the focused field
  and the bar both stay visible.
  - x08k at 360×400 shows the field under the bar. That is only because the capture resized
    after scrolling. Re-scrolled after the resize (y01), it sits above the bar, which is what a
    real keyboard does.

## One obvious next action per state

- Unchanged from round 3 and still true: one blue button, or none in the empty panel, while
  working, and in the re-export confirm.
- The panel after Don't export and after an import error now points at Connect only (x14,
  x17c). That was the one muddled state in round 3.
- On desktop the confirm now visually suggests "Export again" (minor 2).

---

## Should the canvas row be updated to match the build?

**Yes, once, after the fix for this round lands (so it is not redrawn twice).** § 12 and § 13
bind the build. The canvas is still at the round-2 version and now differs in every artboard.
Much of that difference is copy that was changed on purpose after review, such as the size
wording and the done-list warning. A designer or reviewer who opens the row as the reference
would re-introduce what fix rounds removed. What differs, per artboard (canvas → build):

| Artboard | Differences |
| --- | --- |
| **OtpPanelEmpty** | New pad drawn as `.primary` → both secondary (§ 12); Connect with `--border-soft` outline and `aria-disabled` look |
| **OtpPanel** (unlocked) | Option "(you generated, 256 KiB/side)" → "128 KiB/side" (and after nit 5, "128 KiB each way"); Export is the primary while never exported (§ 12); entry icons drop below 380px; Connect width fixed; `role=status` on the text only (not visible) |
| **OtpPanelImported** | Note "only the person who made it can export it" → "Received pad — only its maker can export it."; option text "(imported, …)" |
| **OtpNew** | Label "Size" → "Size, each way"; option values are per direction (32 / 128 / 512 KiB) |
| **OtpNewDone** | Card meta "256 KiB per side" → "128 KiB each way · you generated" |
| **OtpExport** | Card meta; step 3 caption "Share or save it, face to face." → "Give it to them face to face."; upcoming titles muted, current ring 2px |
| **OtpExportWorking** | Card meta; step 3 caption as above; no bottom bar (the canvas already had none — consistent) |
| **OtpExportReady** (Android) | Card meta without "· exported"; caption "…or save it and send it yourself." → "Quick Share or Bluetooth, face to face. Or save it and copy it to a USB stick." |
| **OtpExportDone** (Android, shared) | Line "Sent to the app you picked." → "Keep this open until it has arrived." + the delete line (after minor 1, the "they delete" wording); overline "On their device: Import" → "On their device: One-time pad → Import"; first row "the transfer passphrase you agreed on" → "the transfer passphrase — tell them, never send it"; link "Didn't arrive? Send it again" → "Didn't arrive? Send the same file again", 13px muted |
| **OtpExportAgain** | Card meta; "exported before" wraps after the "·"; bottom row safe-first on the phone (as drawn) |
| **OtpImport** | Filled steps keep `--fg` titles; pad-passphrase placeholder "a new one — not the one above" |
| **OtpImportError** | Filled steps `--fg`; label in `--err-fg`; single red focus ring |
| **OtpImportDone** | Meta "256 KiB per side · imported" → "128 KiB each way · from your contact"; adds "Delete the pad file now." (before the Connect line, after nit 2) |
| **OtpExportDesktop** (browser, 1280) | "Download it again" moved from under the done line into the bottom row as a centred 13px ghost: "Download the same file again"; Done full width (not a right-aligned small button); the delete line; overline and first row as in OtpExportDone; card meta |

**Worth adding (states that are now binding and easy to get wrong):**
- OtpPanel after "Later", with Export as the primary;
- OtpExportDone for Android "saved": file name in the UI font, "Share or save the same file
  again";
- OtpExportAgainDesktop, the one desktop row with no primary (after minor 2).

The New pad and Import working states can stay undrawn: they are OtpExportWorking with a
different step.

**Not worth doing:** redrawing the round-3 cosmetic fixes (nits 1–8) one by one. They follow
from the tokens once the artboards are touched for the copy.

## For the harness (not findings)

- 37-otp-panel-empty is now a fixed state. The other round-3 gaps are still covered only by
  the extras:
  - working states;
  - Android saved, cancelled and error;
  - a file-level import error;
  - the panel after a closed sheet;
  - 360px;
  - short viewports.
- `design4/extra.mjs` reaches all of them. Its desktop and keyboard additions would be the
  cheapest ones to adopt.
- In any keyboard-up capture, scroll the focused field into view *after* the resize (see y01
  and x08k).
