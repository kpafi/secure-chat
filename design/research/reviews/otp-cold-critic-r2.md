# OTP transfer sheets — cold critic, round 2

Scope: `git diff 7a606b4..HEAD -- client android e2e` at HEAD `2e50caa` (branch
`feat/otp-transfer-sheets`). This review was done cold: I did not read the brief,
earlier reviews or PROGRESS. I walked the feature in headless Chromium against a
scratch relay on :8102, read the code, and hand-ran 24 mutants in scratch copies.

**Counts: 0 blocker · 4 major · 8 minor · 6 nit.** 2 of the 24 mutants survive every
test, and 2 more survive the behaviour tests and are caught only by string pins.

---

## Blocker

None. I found no way for one pad to reach a third device other than the two
routes the design already accepts: the confirmed "Export again", and copying the
same file (see § "More than two devices").

## Major

### MA-1 — Importing the same file a second time says the pad is burnt and asks for a new one
- **Where:** `client/otp.js` `importPad` (the `padWasUsed(o.padId) || durablePadUsed(...)` refusal) and `client/app.js` `otpRunImport` (the `already` branch).
- **What happens:** I walked this at 360×740. Bob imports the file successfully, opens Import again and picks the same file. He sees a red block: *"Import failed: this pad has already been used on this device — importing it again would reuse key material. Generate and exchange a fresh pad in person."* Alice gets the same sentence when she imports her own export by mistake. Neither pad has been used. `saveNewPad` sets the used-marker when the pad is stored, so `importPad` refuses before the app's own friendlier branch runs. That branch (*"You already have this pad on this device — not importing again"*) can't be reached in this path. The user is told to redo the in-person exchange when nothing is wrong, and the sheet only offers "Choose another file".
- **Fix:** When the decrypted `padId` is already stored on this device (`padMeta(padId)`), `importPad` should throw a coded error (e.g. `code: "PAD_PRESENT"`) before the used-marker check. `otpRunImport` maps that code to "You already have this pad — it is in the list; nothing to do", selects the pad, and offers "Done". Keep the "used" sentence for pads that are gone but whose watermark is still there.

### MA-2 — Mismatched pads look connected and "Ready", then every message fails to decrypt
- **Where:** the connect/chat path (`client/app.js` near the `// OTP: no key material and no nonces` comment and `"[undecryptable message — wrong key or tampered]"`). The code is older than this feature, but the new sheets make the mistake easy.
- **What happens:** I walked the realistic mistake "both of us pressed New pad". Each person makes a pad called "Chess", exports it and imports the other's. Each device now lists "Chess (imported)" and "Chess (you generated)", with the imported one selected. They connect and admit each other, and both screens say *"Ready. Messages are one-time-pad encrypted."* Alice's first message shows up for Bob only as *"[undecryptable message — wrong key or tampered]"*, and each send uses up pad. Nothing tells either person that they are on different pads, and the identical labels make it hard to work out alone. The empty panel's line "One of you makes it, the other imports it." is the only guard.
- **Fix:** When the peer joins, both sides send a short pad tag (e.g. the first 8 bytes of `SHA-256("otp-pad" ‖ padId ‖ roomId)`). On a mismatch, refuse with *"You and your contact picked different pads — check the pad name on both devices."* before any keystream is spent. At minimum, in OTP mode the undecryptable line should say "probably different pads". Also show the pad name in the chat bar.

### MA-3 — "Forget" deletes a pad for good in one tap, with no confirmation
- **Where:** `client/app.js` `otpForgetSelected`. The handler is not new, but the new panel puts the red Forget button on the same line as the pad picker.
- **What happens:** I walked this at 360×740. One tap on Forget deleted the pad at once: no dialog, no undo. The status line said *"Pad forgotten (deleted from this device)."* The pad can't be imported again, because the watermark refuses it by design, so a slip of the thumb next to the dropdown costs a new in-person exchange.
- **Fix:** Ask first, and name the pad: *"Delete 'Chess' from this device? You will need to make and hand over a new pad in person."* Also move Forget away from the dropdown or into an overflow menu.

### MA-4 — A weak transfer passphrase is accepted while the Android primary action is the system share sheet
- **Where:** `otpExport` (a weak transfer passphrase only produces a warning, package 6) together with the Android `ready` state, where "Share…" is the primary button.
- **What happens:** The transfer passphrase is the only thing protecting the file, and the file holds the whole pad. The main Android path is "Share…", and the system share sheet lists messengers and cloud drives next to Quick Share and Bluetooth. A file sent through one of those, under a weak passphrase that was accepted with a warning, can be guessed offline, even at 600k PBKDF2 iterations. That would give away every past and future message on the pad. The pad passphrase is different: it only protects a copy that stays on the device, so a warning is proportionate there.
- **Fix:** This needs an owner decision, because it conflicts with "warn, never block". Pick one of:
  - refuse weak *transfer* passphrases, and keep only the warning for pad passphrases;
  - generate the transfer passphrase (4–5 words shown on both screens to read aloud);
  - make "Save to device" the primary on Android and keep "Share…" secondary.

## Minor

### mi-1 — Mutant M19 survives: nothing tests the write-back that keeps must-differ correct
- **Where:** `ensureUnlocked`, `els.otpPass.value = pass;` inside `if (els.otpSelect.value === padId)`.
- **What happens:** During the Export entry's unlock, `#otpPass` can still be edited (checked in the browser: not inert, not disabled). If the user types something else while the KDF runs, only this write-back puts the real pad passphrase back. With the mutant, `#otpPass` keeps the new text while the pad is unlocked, so the pad passphrase is then accepted as the transfer passphrase. On HEAD this works correctly: I typed the real passphrase into the transfer field and it was refused.
- **Fix:** Add a dom-stub test: hold the KDF → click Export → change `#otpPass` → release → enter the real pad passphrase as the transfer passphrase → expect the must-differ refusal. Also make `#otpPass` `readOnly` while `entryBusy`.

### mi-2 — Mutant M4 survives the unit suite and `e2e/otp-transfer.mjs` (192/192 checks)
- **Where:** `otpHistDrop`, `if (!otpHistOnTop()) return;`.
- **What happens:** The "a later × does not navigate out of the app" check passes without this guard, because `otpOnPopState` already clears `otpHistEntry`. The guard only matters when `otpHistEntry` is stale while our entry is not on top, and I could not reach that by hand. So in practice it is close to an equivalent mutant, but the check the test's name promises is not what the test exercises.
- **Fix:** Add a unit test with a stubbed `history` whose `state` is not `{otpSheet: 1}` and `otpHistEntry === true`, then assert that `back()` is not called.

### mi-3 — Back during "working" re-pushes a history entry without a user gesture (unverified on device)
- **Where:** `otpOnPopState`: `otpHistPush()` in the working branch and in the unshared-file branch.
- **What happens:** The code's own comment on `openOtpSheet` says that Chromium's Back skips entries a page added without a user gesture. Pushing from a popstate handler is exactly the pattern that intervention targets. After a Back while the sheet is working, the next Back may skip the entry: in a browser that leaves the app. In the shell, `WebView.canGoBack()` may return false, and `onBackPressed` then sends the task to the background. An unshared Android file is then left without the close confirm. Puppeteer's `goBack()` does not apply the intervention, so I could not confirm this headless.
- **Fix:** Check on a device. On Android, route system Back to the page through `OnBackPressedDispatcher` → `evaluateJavascript` (close by the × rules) instead of relying on history entries.

### mi-4 — `autocomplete="new-password"` on the three new-passphrase fields
- **Where:** `otpNewPass`, `otpXferPass` and `otpImportPass` (`client/index.html`). Every other passphrase field in the app, including the old `otpXferPass`, uses `"off"`.
- **What happens:** `new-password` invites Chrome's "Suggest strong password" and save prompts, and the same through Android autofill in the WebView. A generated transfer passphrase can't be "agreed in person", and a saved one ends up in a synced password manager, which contradicts "tell them, never send it". I did not verify this, because headless has no password-manager UI.
- **Fix:** Use `autocomplete="off"`, as the rest of the app does.

### mi-5 — The maker's label is the receiver's label
- **Where:** `exportPad` puts the label in the file, and `importPad` uses it as the pad's name.
- **What happens:** Alice names the pad "Bob". Bob's device then lists "Bob (imported, 128 KiB/side)", and Bob can't rename it. When both people make pads, both sides show two pads called "Chess" (this feeds MA-2).
- **Fix:** Let the importer name the pad in the Import sheet, prefilled with the maker's label, or show it as "from <label>".

### mi-6 — The re-export confirm is jargon and gives no guidance
- **Where:** `otpExportFrom`, the `record.exported` warning.
- **What happens:** The sentence *"re-exporting risks catastrophic key reuse. Click Export again to confirm you know what you are doing."* is a red wall at 360 px. It doesn't say when exporting again is fine: the first file was lost, or it was never imported. After the sheet is closed, exporting again is the only way to recover. People either get scared or learn to click through.
- **Fix:** *"You already exported this pad. Export again only if the first file never reached anyone, or they deleted it before importing — otherwise two people could read each other's messages."*

### mi-7 — Two Android guards are caught only by string pins, not by behaviour tests
- **Where:** Mutants A1 (`\d` instead of `[0-9]` in `PadFileRules.NAME`) and A3 (removing `if (authority == filesAuthority) return false`).
- **What happens:** Both mutants pass all 48 JVM tests (`testDebugUnitTest`). Only the text pins in `client/android-source.test.mjs` catch them. A1 can't be caught by a JVM test at all, because OpenJDK's `\d` is ASCII-only and the ICU difference only exists on the device.
- **Fix:** For A3, add a Robolectric test that feeds our own FileProvider URI to `onFileChosen`/`onSaveDocument`. For A1, run an instrumented test on the device with an Arabic-Indic-digit name.

### mi-8 — Error sentences a first-time user can't act on
- **Where:** `importPad` messages.
- **What happens:** Picking a JSON file that isn't a pad gives *"Import failed: unrecognized pad file format"*. That is acceptable, but *"this pad file asks for unsupported encryption settings"* and *"pad file is internally inconsistent"* are developer words. None of the three says what to do next.
- **Fix:** Add a next step to each, e.g. *"This isn't a pad file from secure-chat. Ask your contact to export it again."*

## Nit

- **n-1** Closing New pad with × keeps the Name field ("Chess" was still there when I reopened it), the size and the drawing samples. `resetOtpSheet` only resets `S.inputs`. The header comment says "Everything a sheet collected is dropped".
- **n-2** After Forget, the forgotten pad's passphrase stays in `#otpPass` (confirmed: the value is kept while the row is hidden). If other pads remain, it sits under "— select a pad —". Clear it in `otpForgetSelected`.
- **n-3** The same thing has three names. The Import done block says "chat code". The `#otpStatus` sentence says "use the same **room id**". The chat bar says "Copy room id".
- **n-4** Android "File shared" says *"Keep this open until it has arrived."*, but "Done" is the primary button and the share file lives 10 minutes whatever the UI does. It also says "delete the file on both devices" when the maker has no file on the share path.
- **n-5** On a 360×740 phone, the sheet in the confirm, done and ready states opens scrolled, so the "ONE-TIME PAD" overline and the × are partly clipped at the top edge.
- **n-6** "Download the same file again" produces a second copy, `…(1).json`, in a real browser, while the copy says "delete the file" (singular).

---

## More than two devices (code read)

- **Export of a received pad:** refused in `exportPad` on `record.role`. That value comes from the AEAD-sealed blob and is cross-checked against the durable record's role. It never comes from the plaintext index. `importPad` also refuses `recipientRole: 0`. Both are covered by tests (M9 in `otp-rollback.test.mjs`).
- **Re-export:** the latch is read fresh under the pad's session lock plus the export lock, and a second click is refused while the latch is held. A second file exists only after the in-sheet "Export again" confirm, which is by design.
- **Same file imported twice on one device:** refused (see MA-1 for the wording). **Maker importing its own file:** refused. **Forget then re-import:** refused by the watermark.
- **Android:** a share or save hands out the one encrypted file. "Send the same file again" reuses the held text, with no new export and no new latch. The bridge is one request at a time and answers only with fixed outcomes.
- **Remaining routes:** copying one file to several devices, and the legacy v1 blob with its outer role (older than this feature, and it needs a local attacker plus the adoption confirm). Neither can be closed in software.

**Passphrases.** No passphrase reaches a status line, a file name, the bridge or the index. The pad passphrase deliberately stays in the hidden `#otpPass` for the whole unlocked session (the must-differ rule needs it), and it outlives Forget (n-2). The sheet inputs are cleared on close. The held import file is the encrypted envelope, and it is dropped on done, on a file-level error and on close.

## UX walk notes (headless Chromium, 1280×800 desktop and 360×740 phone, relay :8102)

1. **Landing → "Continue without an identity" → Security options → One-time pad.** The empty card ("No pad on this device yet / One of you makes it, the other imports it.") is clear. Tapping Connect with no pad gives a clear red line that points to New pad and Import.
2. **New pad (desktop).** "Create pad" with an empty passphrase is refused, and the field is focused. The live weak line appears for "sunshine1". A double click on Create made exactly one pad. Pressing Back and Escape during working (KDF held) did not close the sheet, and it finished normally. Done → "Export to your contact" and "Later" both work.
3. **Export (desktop).** Typing the pad passphrase as the transfer passphrase is refused: the field gets a red border and a triangle, with the sentence below. A double tap on "Create transfer file" while the KDF was held produced one file. The done state names the file and lists what the other side needs. The third line, "this file", reads a little oddly. Back from done closes the sheet. Opening Export again shows the orange "· exported before" and then the confirm (see mi-6); "Don't export" closes the sheet cleanly. With the pad locked and the wrong pad passphrase, I got *"Could not unlock this pad: wrong pad passphrase (or the stored pad is corrupted)"* and no sheet opened.
4. **Import (phone).** Tapping "Choose pad file…" with empty fields asks for the transfer passphrase first. A wrong transfer passphrase marks step 1 ("Check this one — it must match your contact's."), keeps the file, and makes "Try again" the primary. After fixing the passphrase, it imported without a second pick. The done state reads "It is selected. Agree on a chat code with your contact, then Connect. / Delete the pad file now." Importing twice gives MA-1. Picking a junk JSON file gives "unrecognized pad file format".
5. **Received pad.** Export is hidden, and the note says "Received pad — only its maker can export it."
6. **Android stand-in (frozen fake bridge, phone).** In the ready state, × and Back each ask *"The file has not been shared or saved yet. Close anyway?…"*, and Cancel keeps the file. Share and Save are disabled while a request is open. "cancelled" shows "Not shared."; "saved" and "shared" each lead to the right done state; "Send the same file again" goes back to ready.
7. **Connect.** I did the maker desktop ↔ importer phone flow twice: admit, then messages both ways worked. With mismatched pads I got MA-2.
8. **Console:** no page errors from the app. There was one favicon 404, plus a harness-only "SubtleCrypto is not defined" from my own injected hook on a blank frame.

## Mutants (hand-run in `scratchpad/cold2/<id>`; full `npm test` for each; JVM `testDebugUnitTest` for the A-mutants; the M4 survivor was also run through `e2e/otp-transfer.mjs`)

| id | guard mutated | result | killed by |
|---|---|---|---|
| M1 | `otpExport`: remove the fail-closed `if (!els.otpPass.value)` | killed | R2-3: unlocked but #otpPass empty → Export refuses |
| M2 | `otpSelectChanged`: keep #otpPass when another pad is chosen | killed | round 2 minor 5 |
| M3 | `ensureUnlocked`: cache/write back regardless of the selected pad | killed | "the unlock of a pad no longer on screen is not cached" |
| **M4** | `otpHistDrop`: drop `if (!otpHistOnTop()) return` | **survives** (unit + e2e 192/192) | — (mi-2) |
| M5 | `otpOnPopState`: drop `entryBack = true` | killed | R2-2 Back during unlock |
| M6 | `otpNativeResult`: drop the id match | killed | "a result for another request id is ignored" |
| M7 | `refreshOtpPanel`: stop clearing the OTP_NO_PAD hint | killed | cold mi-1 |
| M8 | `otpRunImport`: drop the `padMeta` duplicate check | killed | final round (Mf) second import |
| M9 | `otpExportOpenClick`: `ok = true` (ignore a pad switched during the unlock) | killed | cold M2 |
| M10 | `importPad`: `iters !== KDF_ITERS` → `iters > KDF_ITERS` | killed | F7 100k refused |
| M11 | `otpImportFinished`: keep the held file on a file-level error | killed | M5/J16 |
| M12 | `otpOnPopState`: working → don't re-push | killed | "it puts the history entry back" |
| M13 | `closeOtpSheet`: no confirm for an unshared Android file | killed | § 5 Cancel keeps it |
| M14 | `otpTooSoon` → always false (no 500 ms guard) | killed | M6 500 ms |
| M15 | `otpExport`: don't disable the button while running | killed | "Export button is disabled while an export runs" |
| M16 | `otpOnPopState`: unshared file → don't re-push | killed | N-M2 |
| M17 | `renderOtpImport`: don't clear the transfer field's mark | killed | hot m1 |
| M18 | `closeOtpSheet`: keep the sheet's sentence in the panel | killed | design R3-M1 |
| **M19** | `ensureUnlocked`: drop `els.otpPass.value = pass` write-back | **survives** | — (mi-1; reachable in the UI) |
| M20 | `generatePad`: UTC default label | killed | n-1 local time |
| A1 | `PadFileRules.NAME`: `[0-9]{4}` → `\d{4}` | JVM survives; killed by string pin | android-source.test.mjs (mi-7) |
| A2 | `isEnvelope`: drop the base64 padding check | JS suite survives; killed by JVM | PadFilesTest |
| A3 | `isForeignDocument`: drop the own-authority refusal | JVM survives; killed by string pin | android-source.test.mjs (mi-7) |
| A4 | `resultScript`: drop `require(ID.matches(id))` | killed (JVM and string pin) | PadFilesTest / pin |
