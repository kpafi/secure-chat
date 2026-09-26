# OTP transfer sheets — design critic, round 2

Scope: the canvas row "One-time pad transfer", version 1790457850-b943, 14 `Otp*` artboards. I
rendered them headless at 390×844 (OtpExportDesktop at 1280×800), plus the panel and the
re-export state at 360×844. I checked them in source (colours, fonts, primaries, overflow,
word counts compared with round 1) and against `otp-transfer-brief.md` § Design decisions,
rewritten for round 2. Triage read: `otp-design-fix-round-1.md`. Owner decisions taken as given:
a neutral file name, transfer == pad passphrase refused, and Android offering Share and Save.

Summary: round 1 was fixed on the canvas as well as in the spec. All 28 findings are addressed,
and I could trace the logic of each fix, not only see it drawn. There is one primary per state
(zero in re-export), nothing overflows horizontally at 390, and words per sheet went down or stayed
flat. The only increases are ImportError (+16, the field line and "Choose another file") and
OtpNew (the sample weak line and the hidden entropy text), and both are warranted. The two
passphrases now read differently on every screen, through icon, word and step title.

What is left is at the platform edges. One Android caption invites a server copy of the pad
file. Android Back is not specified at all. There is also a handful of spec gaps that the
implementer would otherwise fill by guessing.

Counts: **0 blocker, 2 major, 9 minor, 9 nit.**

---

## Major

### N-M1. The Android export path invites a copy of the pad file on someone's server
**Artboards:** OtpExportReady; the Android "saved" done state (spec only, § 5 table; § 9 save)

- The step 3 caption at "file ready" ends with **"— or save it and send it yourself."** It is the
  only line in the whole flow that invites a remote channel (mail, messenger, cloud drive).
  Everything else says in person: the card subtitle, the step 1 title, "Say it to them in
  person", and the saved-state line. A remote channel keeps its copy indefinitely. That copy is
  protected only by the transfer passphrase, which is warn-never-block. If that passphrase is
  weak, anyone holding the copy can guess it offline, and then every message ever sent on that
  pad can be read. The in-person transfer exists to prevent exactly this. A first-time user reads
  "send it yourself" as permission.
- "Save to device" uses `ACTION_CREATE_DOCUMENT`. The system save dialog also lists Google Drive
  and other cloud roots. The implementer's own comment in `MainActivity.onSaveDocument` says "the
  provider may be remote". The done title **"File saved to this device"** is then false, and it
  would bless the cloud copy.

**Fix:** remove the invitation, keep cloud roots out of Save, and stop the title from claiming a
location that native code cannot guarantee.

**Spec change (brief § 5 table, Android row, and § 9):**
- "At file ready" caption → **"Quick Share or Bluetooth, face to face. Or save it and copy it to
  a USB stick."**
- `saved` → title **"File saved"** (drop "to this device"), then the file name on its own line
  (UI font; the user now has to find it in Files), then the line "Now give it to them in person —
  USB stick, Bluetooth or Quick Share." (unchanged). Update the § 7 rationale ("both can read it
  off the sheet"), which today holds only for the browser and for Android's file-ready state.
- § 9 `save`: add "`putExtra(Intent.EXTRA_LOCAL_ONLY, true)` on the `ACTION_CREATE_DOCUMENT`
  intent (DocumentsUI then offers local roots only; some OEM pickers ignore it, hence the title
  without 'this device')". Add a check for it to `android-source.test.mjs` in § 11.

### N-M2. Android Back is not specified: it leaves the app from every sheet state
**Artboards:** all sheets on Android, especially OtpExportWorking and OtpExportReady (brief § 3
"Dismissal", § 5 "Closing on Android")

The single-page app never pushes history, so `MainActivity.onBackPressed()` finds
`canGoBack()` false and calls `super.onBackPressed()`. On Android, Back is the reflex for
dismissing a bottom sheet. Today it:
- skips the rule that a working sheet cannot be dismissed, and skips the Android close confirm
  in file-ready that the spec requires for ×;
- on Android 8–11 (minSdk 26) finishes the activity and destroys the page. A file-ready state
  already has the latch committed, so the file is lost and the pad counts as exported. The user's
  next Export then opens on the red "catastrophic key reuse" confirm for a file that never left
  the phone. On 12+ the task goes to the background. The user loses nothing, but they are thrown
  out of a sheet they only meant to close.

`#contactSheet` has the same gap. There it is harmless, because it holds no state.

**Spec change (brief § 3, "Dismissal", new bullet):**
> **Back** (Android system back, browser back) acts as ×. Opening a sheet from the panel calls
> `history.pushState({ otpSheet: 1 }, "")` (the New pad → Export swap reuses the entry). On
> `popstate` while a sheet is open: working → `pushState` again, nothing else; Android file-ready
> before `shared`/`saved` → `pushState` again, then run the close confirm (5) and close only on
> OK; otherwise close the sheet by the × rules. Closing by × / Escape / scrim / Done / Later /
> Don't export calls `history.back()` once to drop the entry, with a flag so the resulting
> `popstate` is ignored. No native change: `onBackPressed()` already calls `webview.goBack()`
> when it can.

Add to § 11: "`history.back()` closes an idle sheet and returns focus; it is ignored while
working; in Android file-ready it asks first".

---

## Minor

1. **OtpPanelEmpty — the blue "New pad" pulls the *receiver* the wrong way.** This is my own
   round-1 advice, revisited. The empty state is a fork between two roles. A single primary
   tells half the users that they are the maker. A receiver who taps it makes a second pad, then
   gets "Export to your contact", and ends up with two pads to choose from. Nothing is unsafe,
   but the result is confusing. **Fix:** give the two buttons equal weight. Both secondary is
   allowed: the re-export state already has zero primaries. Better, make them two equal tiles
   with a sub-label: "New pad · I'll make it" and "Import · I got a file". The hint line can then
   go.
2. **"Never send it with the file" is invisible when it matters most on iOS and the browser.**
   The line lives in step 1's done caption. On iOS and the browser that caption shows only
   during the few seconds of the working state. On iOS the share sheet opens straight after,
   which is exactly when a user might paste the passphrase into the same message. **Fix:** move
   the warning into the done list, which every platform shows. The first row becomes "the
   transfer passphrase — tell them, never send it" (two-person token).
3. **OtpExportDone — tapping Done before the file has arrived leads to the red re-export
   confirm.** The held file text is dropped on close. If Quick Share failed after the chooser
   returned, the only way back is the red confirm. **Fix:** replace the Android `shared` line
   "Sent to the app you picked." (low value) with **"Keep this open until it has arrived."** The
   iOS line gets the same second sentence (item 4).
4. **iOS done — "Share sheet opened / Pick how to send it — AirDrop, in person."** is shown
   after the share sheet has already closed, because the page gets no result. The instruction
   points at something that is gone. **Fix:** line → **"AirDrop it to them, face to face. Keep
   this open until it has arrived."** Keep "Share it again".
5. **OtpPanel, locked state (not drawn) — the carried passphrase ends up under another pad.**
   New pad B sets `#otpPass` = passB. Switching `#otpSelect` to pad A shows the field for A
   already filled with dots the user never typed there. Connect then fails with "wrong
   passphrase" for A. **Fix (§ 1.3):** "On `change` of `#otpSelect` to a pad other than
   `otpPanel.padId`, set `#otpPass.value = ""`." M3 still holds, because the Export entry makes
   the user type the passphrase for any pad that is locked.
6. **The "Later" path leaves a made-but-never-exported pad with Connect as the primary.** Connect
   cannot succeed until the contact has the pad. This is the same dead end as round-1 M1, one
   step later. **Fix (§ 1.4):** when the selected pad has `role === 0` and the index says it is not
   `exported`, `#otpExportOpen` takes `.primary` and Connect loses it (Connect stays enabled).
   The index is only a hint, which is enough to decide emphasis.
7. **Which errors mark a field is ambiguous (§ 3 "Status").** "An error about a field also marks
   the field (5)" points at § 5, which marks nothing. Only `#otpImportXfer` has an error line, and
   its text ("must match your contact's") would be wrong under any other field. **Fix:** list the
   cases. The wrong-passphrase import error gets the full mark (icon, 2px, `aria-invalid`, line).
   Must-differ refusals mark the field they focus, with icon, 2px border and `aria-invalid`, but
   no line (the status sentence names it). Empty-field refusals only focus.
8. **Step states are inconsistent between Import and Export, and New pad is ambiguous.** On
   Export, the titles of upcoming steps are `--muted`. On Import, the title of the upcoming step 3
   is `--fg`, and OtpImport marks step 2 as current without any rule in the spec for how. The spec
   calls New pad "all idle-styled", and by its own definition that includes muted titles. That
   would bring back round-1 minor 2. **Fix (§ 3 Steps):** "Current = the first step whose input
   is empty, else the last step. Titles of upcoming steps are `--muted` in Export and Import. New
   pad: idle discs, titles always `--fg`."
9. **The entry row overflows at common Android widths.** At 360px (a common Android width;
   rendered), "New pad" wraps to two lines in its 104px cell. At 390px, the spec's
   **"Unlocking…"** label (§ 1, Export entry) needs about 130px of the 114px cell and runs into the
   border. A larger system font makes both worse. **Fix:** `white-space: nowrap` on the three
   labels, and the leading icons hidden below 380px. While unlocking, keep the label "Export"
   and swap only the icon for the spinner (`aria-busy`). Alternatively, put "Unlocking…" in
   `#otpStatus`.

## Nit

1. **OtpExportAgain:** the pad card meta breaks "· exported / before" mid-token at 390 and 360.
   Give that span `white-space: nowrap`. At 360 the head's "?" also floats alone at the end of
   the wrapped hint. Keep it inline with the last word.
2. **OtpExportWorking:** the canvas drops the head's "?" as well as the ×. The spec (§ 3) keeps
   the "?". The spec is right; fix the artboard.
3. **The bottom-row rule versus the desktop link.** § 0 and § 3 say "all actions in one bottom
   row". § 5 puts "Download it again" under the done line in the desktop dialog. State the
   exception in § 3.
4. **Done anatomy:** § 5 says "disc + title + line, pad card". ImportDone (and § 6) put the line
   *after* the card. Either order is fine; make the two sections say the same thing.
5. **OtpExport, form state:** the step 3 caption "Share or save it, face to face." uses Android
   vocabulary on the browser and iOS, where there is no such choice. Change it to **"Give it to
   them face to face."** and keep the Android caption for file-ready.
6. **OtpPanelEmpty:** the disabled Connect differs from the Import secondary only by text colour.
   Use a `--border-soft` outline so it is visibly weaker than a live secondary. Keep it undashed,
   for the same drop-zone reason as B1.
7. **OtpPanelImported:** the note stays on screen on every visit for an action the receiver never
   wants. Shorten it to **"Received pad — only its maker can export it."**
8. **OtpExportDone:** the overline "On their device: Import" does not say where Import is. Change
   it to **"On their device: One-time pad → Import"**.
9. **OtpImport:** the step 2 placeholder "a new one only you know" repeats the tag next to it.
   **"a new one — not the one above"** also teaches the must-differ rule.

---

## Round-1 findings: verified status

| # | Round-1 finding | Status | Evidence / residual |
| --- | --- | --- | --- |
| B1 | "travels with the file" / the two fields look alike | **Fixed** | Two-person vs one-person icon in the field and the tag on all 9 fields drawn; step titles differ ("The passphrase you agreed on" / "Your own passphrase for this device"). The panel and "On their device" rows use the same tokens. |
| M1 | Empty panel not drawn; Connect was the dead-end primary | **Fixed** | OtpPanelEmpty: New pad is the only fill; Connect is `aria-disabled` and muted. Residual: minor 1 (receiver bias), nit 6. |
| M2 | Passphrase below Export; empty field for an unlocked pad | **Fixed** | Order: pad → passphrase → entries → Connect; `#otpUnlocked` row with Lock drawn. |
| M3 | Must-differ never fired in New pad → Export | **Fixed** (spec traced) | Carried into `#otpPass` after generate and import; Lock empties it; Export entry needs it for any locked pad. Residual: minor 5. |
| M4 | "File handed over" when nothing was handed over | **Fixed** | Per-result titles; neutral disc for downloaded, saved and iOS. Residual: N-M1 ("saved to this device" can be false), minor 4 (iOS line). |
| M5 | Full-size "again" buttons in done | **Fixed** | One ghost link, `#otpSendAgain`. |
| M6 | Re-export had no safe way out | **Fixed** | "Don't export" first, "Export again" `.danger`, zero primary; step 1 done, field hidden. |
| M7 | Wrong passphrase shown by colour only | **Fixed** | Triangle icon, 2px border and "Check this one — …" line, tied in by `aria-describedby`. Residual: minor 7 (rule scope). |
| M8 | Weak-passphrase wall of text | **Fixed** | One line + "?"; OtpNew sample data now matches OtpNewDone. |
| M9 | Export offered for a received pad | **Fixed** (design + spec) | OtpPanelImported hides Export and shows the note; otp.js refusals specified (the code is being written — see the aside below). Residual: nit 7. |
| m1 | "?" in the wrong place (New) | Fixed | In the drawing block's title row. |
| m2 | New pad step machinery | Fixed on canvas | Two plain steps + unnumbered optional block. Spec wording could bring back muted titles: minor 8. |
| m3 | Entropy jargon | Fixed | `.vh`. |
| m4 | Retry needed a re-pick | Fixed | Held text; "Try again" primary, "Choose another file" ghost. |
| m5 | Handover confirmed twice | Fixed | Done states drop the steps. |
| m6 | "On their device" reused step discs | Fixed | Token rows. Residual: minor 2 (the passphrase warning belongs there). |
| m7 | Primary placement differed | Fixed | Every sheet's actions sit in the pinned bottom row. The desktop link exception is unstated: nit 3. |
| m8 | Done anatomies differed | Mostly fixed | Line order differs between § 5 and § 6: nit 4. |
| m9 | Disabled × while working | Fixed | × hidden. The artboard also hides the "?": nit 2. |
| m10 | Re-export warning came too late | Fixed | "· exported before" in the card meta at open. Wraps: nit 1. |
| m11 | "Alice ↔ Bob" placeholder | Fixed | "e.g. Chess club" everywhere. |
| n1 | Desktop file name wrapped | Fixed | Own line. |
| n2 | Mono file name on Android | Fixed | Mono only in OtpExportDesktop (verified in source). |
| n3 | Pad icon read as a table | Fixed | Notepad with a perforated top. |
| n4 | ImportError lost the head "?" | Fixed | Head identical. |
| n5 | Size option truncated | Fixed | Size only + `#otpSizeHint`. |
| n6 | "Next: hand it…" repeated the button | Fixed | Cut. |
| n7 | Success sentence repeated in the panel | Fixed (spec) | `quiet` → `hint vh`. |

## The first-time story, phone

**Maker (Android):** Live room → One-time pad card → empty card → **New pad** (blue) → name,
own passphrase → **Create pad** → "Pad created" → **Export to your contact** → agree a
passphrase in person, type it → **Create transfer file** → a few seconds → **Share…** → Quick
Share → "File shared" → **Done** → panel, unlocked, **Connect**. The next action is always the one
blue button, and the reading per screen is one title plus one line. Weak points: the "send it
yourself" caption (N-M1), Back (N-M2), and Done tapped too early (minor 3).

**Receiver (Android):** file arrives in Downloads → Live room → One-time pad card → empty card →
**Import** (secondary; minor 1) → the passphrase you agreed on, your own passphrase → **Choose pad
file…** → system picker → "Pad imported. It is selected. Agree on a chat code…, then Connect." →
panel, unlocked, **Connect**. The receiver needs to be told two things: where Import is (nit 8)
and that the blue button is not theirs (minor 1). With the maker beside them, both are covered.
Without the maker, those two are where a receiver gets stuck.

## Checked and fine

- One `.primary` per drawn state, and zero in re-export (checked by computed background colour).
  44px targets hold. No horizontal overflow at 390 in any artboard.
- Tokens are consistent across the row: pill 20px/12px muted on a 30% outline, warn `#e3b341`,
  err `#ff9c93`, ok disc tint, 40px discs and tiles, 15/600 titles, 13px meta.
- The spec and the canvas agree on ids, labels and state lists, apart from the items above.
  § 8 gives the implementer a complete id map, and § 11 covers every new behaviour except Back.

## Aside (outside design scope)

`client/otp.js:531` in this worktree currently reads `if (false && o.recipientRole !== 1)`,
which disables the new import refusal. It is probably a hand-run mutant in progress. Make sure it
is reverted before the commit.
