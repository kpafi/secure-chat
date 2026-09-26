# OTP transfer sheets — hot critic, round 1

Scope: `git diff 7a606b4..448d420` (13 commits) on `feat/otp-transfer-sheets`, read against
`otp-transfer-brief.md` (§ 9a and § 12 win), design critic r1/r2 + fix round 1, the Android
pentest r1, `direction-contract.md` and the earlier hot-critic / profile-fix-round reports.
I did not modify any tracked file.

- **Unit mutants and e2e:** ran in a scratch copy of the tree
  (`scratchpad/hot/tree`, relay from that copy on **:8101**, killed by PID afterwards), so no
  in-place mutant could reach the reviewers running in parallel on 8102–8104.
- **Stray edit in the worktree:** `client/app.js` has an uncommitted one-line edit (the
  `otpGenerating` guard commented out). It is **not mine**: another reviewer's in-place mutant
  was in flight when I finished. Check `git diff` once all reviewers are done.

## Verdict

**The security core holds; one error path does not.** Every invariant I could bind is bound:
- the export latch order;
- the re-export confirm wordings, byte-identical;
- bytes zeroed;
- must-differ in both sheets, including New pad → Export;
- M9 on both ends and the F7 iteration pin;
- neutral file names;
- native results accepted only by id and kind.

20 of 23 hand-run mutants go red. The weak spots are in the error and edge paths of the sheet
mechanics:
- **BLOCKER:** one refusal leaves the Export sheet stuck in "working" (un-closable, the page
  inert) until a reload.
- **MAJOR:** one Back-button sequence makes a later × navigate out of the app.

Everything else is minor or nit.

**Runs:**
- `cd client && npm test`: green. All 9 Android source checks, the 10 sheet checks, the app-otp
  suite and otp-rollback all pass.
- `e2e/otp-transfer.mjs` on :8101: **167/167**.
- `e2e/all-modes.mjs` on :8101: **28/28**.
- Probes for the findings below: `scratchpad/hot/tree/e2e/probe-hot*.mjs` (real Chromium,
  against :8101).

## BLOCKER

### B1. PAD_BUSY during an export leaves the Export sheet stuck in "working" (un-closable, page inert)

**Where:** `client/app.js:5314-5317` together with `:5352`:
```js
    const got = await acquirePadLock(id);
    if (!got || got === NO_WEB_LOCKS) {
      otpStatusMsg(PAD_BUSY, true);
      return;                       // ← leaves otpExport() entirely
    }
  ...
  otpExportFinished(id, file && file.text ? file : null);   // ← after the try/finally; never reached
```

**What happens:**
- `otpSheetBegin("export")` has already put the sheet in `working`.
- The `return` inside the outer `try` skips the `otpExportFinished` call that sits *after*
  the try/finally. Nothing ever sets the state back.
- **Sheet stuck:** it stays in `data-state="working"`, × is hidden, the `#otpExport` bottom-row
  button is hidden, and Escape, scrim, Back and `showView` all refuse because
  `otpSheetWorking()` is true.
- **Page stuck:** the Live room, tab bar and app bar stay `inert`.
- **Recovery:** the sheet does show the PAD_BUSY sentence under a moving progress bar, but the
  only way out is a reload.

**Compared with the other two handlers:** `otpGenerate` and `otpRunImport` report from inside
their `finally`, so they cannot hit this.

**How a user gets there:** exactly the case PAD_BUSY exists for.
1. Tab 1 is connected (or still waiting for the contact) on pad X.
2. The user opens the Live room in tab 2, sees the pad was never exported (Export is even the
   primary, § 12 "Emphasis after Later"), and taps Export → Create transfer file.
- Also reachable in one tab, right after a Disconnect, while `closingPadLocks` still holds the
  pad lock for a save in flight.

**Reproduced:**
- **Unit stub** (the sheets test plus a held `sc.otp.lock.v1.<id>`): state `working`, × hidden,
  status = PAD_BUSY, and × leaves it open.
- **Real Chromium** (`probe-hot.mjs` P1: a second page in the same context holds the lock):
  `{"hidden":false,"state":"working"}`, `closeHidden: true`. After Escape and a scrim tap:
  still `working`, `#viewLive` still inert.

**Fix:**
- Move `otpExportFinished(...)` into the `finally` of the outer try, the way the other two
  handlers do it. Alternatively, `throw` instead of `return`, so the catch writes the error and
  the call is reached.
- **Test:** add a sheets test that holds `sc.otp.lock.v1.<id>` and asserts `data-state="form"`,
  × shown and the PAD_BUSY sentence in `#otpExportStatus`.
- **Why no test caught it:** the existing 30 s test holds the *export* lock, a different path
  that does throw.

## MAJOR

### M1. Back during the Export entry's unlock orphans the history entry; the later × (or Done) navigates out of the app

**Where:** `client/app.js:6025` (`otpHistPush()` before the unlock's await), `:5995-5997`
(`otpOnPopState` returns when no sheet is open, **without clearing `otpHistEntry`**), `:6036/6041`
(the sheet then opens with `{ pushed: true }`), and `:5989` (`otpHistDrop` → `history.back()`).

**Sequence:**
1. The pad is locked and its passphrase is typed. The user taps Export. The KDF runs (about
   0.5–2 s on a phone) behind a spinner, and the user presses Back.
2. The popstate pops the entry pushed for the unlock. No sheet is open, so it is ignored, and
   `otpHistEntry` stays `true`.
3. The unlock succeeds and the sheet opens on no entry at all.
4. Any close (×, Done, Don't export, Escape, the scrim) calls `history.back()` one entry
   **below** the app's.

**Reproduced** (`probe-hot2.mjs`, real Chromium):
- History is [other page → app]. After Back during the unlock: `[4,'null']`. The sheet then
  opened.
- **After ×:** `url http://127.0.0.1:8101/healthz`, `same doc: false`. The browser left the app,
  dropping the unlocked pad key, the typed transfer passphrase and any in-memory state.
- **On Android** the first entry has nothing below it, so `history.back()` is a no-op there, but
  the bookkeeping is still wrong.
- **Why it matters:** § 12 Back is a spec'd mechanic. This is its one asynchronous gap, and
  "press Back while nothing seems to happen" is the natural reaction to a silent 1–2 s wait.

**Fix:**
- In `otpOnPopState`, when `!otpUi.sheet`, set `otpHistEntry = false`.
- In `otpExportOpenClick`, treat "the entry was popped during the unlock" as a cancel: keep a
  local token, do not open the sheet, and leave the panel unlocked (the unlock itself was
  wanted).
- **Test:** push → popstate → resolve the unlock, then assert that no sheet opened and no
  `back()` was called.

## MINOR

### m1. A field mark outlives its error: after a wrong-transfer-passphrase error, a later file-level error leaves `#otpImportXfer` marked

**Where:** `client/app.js:5728-5736` sets `aria-invalid` and `aria-describedby` when
`otpImportErr === "pass"`, but never removes them. Only `otpClearMark` (on `input`, or on close)
does.

**Sequence:** a wrong passphrase, then "Choose another file", then a junk file, gives
"Import failed: unrecognized pad file format". Measured (`probe-hot3.mjs` Q2):
- `aria-invalid="true"`;
- `aria-describedby="otpImportXferErr otpImportStatus"`, pointing at a now-hidden line;
- 2px red border, label in `--err-fg`, the triangle icon.

**Why it matters:** the sheet blames the passphrase for a bad file, which contradicts § 12
("Which errors mark a field").

**Fix:** in `renderOtpImport`, when `!marked`, call `otpClearMark(els.otpImportXfer)` unless a
must-differ mark is being set, or clear the mark in `otpSheetBegin("import")`.

### m2. Sheet errors are left behind in the panel after the sheet closes

**Where:** `otpStatusMsg` (`app.js:4822`) writes every error to `#otpStatus` (shown, `hint err`)
as well as to the sheet. `closeOtpSheet` / `resetOtpSheet` empty only the sheet's status.

**Measured** (`probe-hot3.mjs` Q3): after a must-differ refusal and then Escape, the panel shows a
red "Use a different passphrase for the file — this one is your pad passphrase." (39px tall)
under the entry row. Nothing it refers to is still on screen.

**Same effect:** "Import failed: wrong passphrase…" and the PAD_BUSY sentence stay behind the
same way.

**Fix:** on close, empty `#otpStatus` when its text is an error the sheet already showed. The
simplest version is to remember which sheet wrote the sentence and clear it with the sheet. This
stays byte-identical for the tests, which read it while the sheet is open or with no sheet at
all.

### m3. Keyboard focus is lost to `<body>` when the Export entry's unlock fails

**Where:** `app.js:6024`. `els.otpExportOpen.disabled = true` on the focused button. Chromium's
focus fix-up moves focus to `<body>`. On failure, `#otpStatus` says "Export failed: wrong
passphrase…", but no focus is placed.

**Measured** (`probe-hot3.mjs` Q1, Enter on the entry): `activeElement = BODY`.

**Why it matters:** § 3 says "error → the field concerned". A keyboard or screen-reader user has
to Tab from the top of the page.

**Fix:**
- Focus `#otpPass` in the catch.
- Or use `aria-disabled` plus an early return instead of `disabled` while busy. That keeps focus
  on the button and still announces `aria-busy`.

### m4. The sheet status live regions are `display:none` while empty, so a screen reader may miss field-error sentences

**Where:** `style.css:2229` `.otp-status:empty { display: none; }` on elements with
`aria-live="polite"`.

**Why it matters:**
- **Missed announcements:** a live region that is out of the accessibility tree until the moment
  its text arrives is frequently not announced (NVDA/JAWS with Chromium, VoiceOver iOS).
- **Errors that focus a field:** here focus goes to the field, not the status. `#otpXferPass` is
  described only by `otpXferWarn`, and `#otpImportPass` only by `otpImportPassWarn`. A
  must-differ refusal is then heard as "Transfer passphrase, invalid entry" with no reason.
  - This covers both must-differ refusals and "Enter a transfer passphrase first".
- **Errors that focus the status** (re-export confirm, PAD_BUSY) are fine: the focus reads them.

**Fix:**
- Keep the region rendered: `:empty { padding: 0; border: 0; min-height: 0 }`, not
  `display:none`.
- And/or add the sheet's status id to `aria-describedby` of a field while `otpMarkField` has
  marked it, as `#otpImportXfer` already does for its own error.

### m5. The must-differ rule silently switches off after a pad round-trip in the selector

**Where:** `app.js:5075` (round 2 minor 5) empties `#otpPass` when another pad is chosen.

**Sequence:**
1. After New pad, pad A is unlocked and its passphrase is carried.
2. The user selects pad B, which empties `#otpPass`, then selects A again. A is still unlocked
   (`otpPanel.padId === A`), so the unlocked row shows, `#otpPass` stays empty and Export opens
   without an unlock.
3. `app.js:5290` `if (els.otpPass.value && xfer === els.otpPass.value)` is now always false, so
   the pad passphrase is accepted as the transfer passphrase.

This matches the letter of § 2 ("only the live input values are compared"), but the owner's
decision was **blocked**, not "blocked when the field happens to be filled".

**Fix:**
- Empty `#otpPass` only when the newly chosen pad is locked, or drop `otpPanel` when the carried
  passphrase is emptied: a pad whose passphrase field was emptied should read as locked.
- The same applies if a KEY_STALE re-prompt happens inside a working export with an empty field.
  It surfaces as "Export failed: Enter this pad's passphrase…" pointing at a field behind the
  modal.

### m6. Two security checks in `FILES_BRIDGE` are unbound (mutants survive `npm test`)

**Where:** `app.js:53-64`.
- Dropping `d.writable || d.configurable` (M11) leaves the whole suite green.
- Dropping `Object.isFrozen(b)` (M12) leaves the whole suite green.
- The sheets test only ever installs a *correct* bridge. `android-source.test.mjs` pins the
  shell's side, not the page's acceptance rule.

**Why it matters:** § 9a makes "accepted only in exactly that shape" a property.

**Fix:** put a small second process (or a `vm` context) around `app.js`. Install:
- a writable bridge, and assert the browser path (a download, no `share` call);
- a configurable bridge, with the same assertion;
- an unfrozen bridge, with the same assertion.

### m7. Closing the sheet disarms the re-export latch, but only e2e proves it

**Mutant M17:** drop `pendingReexportId = null` from `resetOtpSheet`.
- `npm test` stays **green**.
- `e2e/otp-transfer.mjs` goes red, but by a 60 s `waitForFunction` timeout: the second export
  silently went through, the exact two-importer hazard.

**Why it matters:** this is a security invariant (brief § 5, "Closing disarms the latch"), and it
is bound only by the slow suite.

**Fix:** add a unit check. Confirm state, close, click Export again, and the confirm sentence is
back with no file.

### m8. No re-review recorded for the Android fix commit, and PROGRESS.md was not updated

**Android re-review:**
- `a43a9d8` ("pentest r1 fixes: per-request share URIs, revoke before delete, 10-minute life,
  …") is new native code after `otp-pentest-android-r1.md`.
- The workflow rule is that a fix gets pentested too. No r2 is in `reviews/`.
- The web half (held file texts, dismissal, the role fix, `otpNativeResult`) has no pentest
  report on the branch either, as § 11 asks. Some of this may be what the parallel reviewers
  are doing now.

**PROGRESS.md:** the top entry still describes 0.4.0 and has no "RESUME HERE" line for this
branch.

## NIT

- **n1. Hardcoded debug path in a committed test.** `e2e/otp-transfer.mjs:456` screenshots to
  `/tmp/claude-1000/…/scratchpad/web/connect-fail.png`, another session's scratch directory. On
  a failure elsewhere, the catch itself throws ENOENT and hides the real error. Use
  `tmpdir()` + `mkdtemp`, or drop the screenshot.
- **n2. A close and an open in the same task lose the new sheet's history entry.**
  `otpHistDrop`'s `history.back()` is asynchronous, measured at 9 ms to popstate. If another
  sheet opens before that popstate arrives, the pending traversal pops the *new* sheet's entry
  (`probe-hot2.mjs` P3: after ×, then New pad in one task, `history.state` is `null` with the
  sheet open, and the next Back left the app). A human cannot tap that fast. A programmatic
  close→open added later would hit it.
  - **Related case:** if Import is opened during the Export entry's unlock, `app.js:6036` drops
    the Import sheet's entry (the top one), and a dead entry is left behind.
  - **Fix:** clear pending traversals with a "closing" promise, and open only after its popstate.
- **n3. The current step is shown by colour only.** Current vs idle is an accent ring vs a
  border ring, and title `--fg` vs `--muted`. `aria-current="step"` covers assistive tech.
  Sighted colour-blind users get only a ring-colour difference. A 2px ring, or a filled disc,
  for the current step would add a shape cue.
- **n4. Desktop button order in the bottom row.** "Try again" (primary) sits left of "Choose
  another file" (ghost), and "Export to your contact" (primary) left of "Later". The desktop
  convention elsewhere in this sheet (§ 12 nit 3: Done at the right) puts the primary at the
  right. `style.css:2361` handles only `.otp-again`.
- **n5. Leftovers.**
  - `app.js:6363` `void kind;` loop variable: use `Object.values`.
  - `otpSetState` sets `dataset.state` and then `setAttribute("data-state")`: one of them is
    redundant; keep the stub-compatible one.
  - The `force` branch of `closeOtpSheet` (the view switch skips the Android confirm) is
    unreachable today, because the tab bar is inert while a sheet is open. It is fine as a
    guard, but its comment implies a path that does not exist.
- **n6. `#otpUnlocked` is `role="status"` and contains the Lock button.** The announcement reads
  "Unlocked for this session Lock". Put `role="status"` on the text span only.
- **n7. No pad is selected after a reload.** With exactly one pad on the device, the selector
  opens on "— select a pad —", so Export says "Select a pad to export." first. This predates the
  branch, but the new panel makes the extra step more visible. Consider pre-selecting a sole pad.

## Spec conformance: state by state (checked in code, e2e and probes)

**Panel**
- empty ✓ (§ 12: no primary; Connect `aria-disabled` with the hairline look, and a refusal on
  tap);
- unlocked row / Lock ✓;
- received pad (no Export; the note with the § 12 wording; a forced Export refused) ✓;
- Export is the primary while unexported ✓;
- `#otpStatus` initial text empty ✓;
- success sentences are `vh` ✓.

**New pad**
- form ✓: size-only options; the hint "~N short messages each way"; the drawing block, with
  `#otpEntropyStatus` as `vh`.
- working ✓: no ×; Escape, scrim and Back refused.
- done ✓: the carried passphrase, focus on "Export to your contact", the swap keeps the scrim
  and the history entry.

**Export**
- form ✓: step 1 current, step 3 caption per § 12.
- working ✓, **except B1**.
- confirm ✓: no primary, "Don't export" before "Export again" (`.danger`), focus on the status,
  wording byte-identical.
- Android ready ✓: step 3 current, Share (primary) and Save, both disabled while a request is
  open.
- cancelled / error / busy / invalid lines ✓.
- done ✓, per platform: `shared` / `saved` / `downloaded` / `ios` titles, lines, discs; mono only
  for the browser file name; the "On their device" list; the "again" link.
- close-confirm on Android before any delivery (× and Back) ✓.

**Import**
- form ✓: current step = the first empty input; the picker `accept` includes octet-stream.
- working ✓.
- pass error ✓: full mark and "Try again" with the held text, no re-pick. Note **m1**.
- file-level error ✓: held text dropped, "Choose another file" primary.
- PAD_BUSY → "Try again" ✓.
- done ✓: the carried passphrase, the received-pad panel.

**Mechanics**
- the rest of the page inert ✓;
- Tab wraps (and Shift+Tab) ✓;
- Escape, ×, scrim ✓;
- the 500 ms guard ✓;
- focus on open (fine pointer → first field, else the sheet), working → progress,
  done → primary, close → opener ✓;
- clearing on close only ✓;
- history push inside the click ✓, **except M1 and n2**.

**Security invariants**
- **Export:**
  - latch before file (the file is returned only after `markExported` commits; it is handed out
    after the locks are released, which is fine);
  - pad lock, then export lock;
  - in-flight latch;
  - the 30 s bound on the export-lock wait;
  - `record.bytes` zeroed in `finally`;
  - the "used while it was being exported" refusal unchanged ✓.
- **Import:**
  - pad lock around the save;
  - the "already on this device" refusal;
  - `recipientRole === 1` only (bytes zeroed before the throw);
  - `kdf.iters === 600000` only, before any KDF ✓.
- **Passphrases** never appear in a file name, a URL, history state (`{otpSheet:1}`) or DOM
  text. They are read once at the click, and `#otpPass` is never cleared by a sheet ✓.
- **Must-differ** ✓ (but see **m5**).
- **Received pads** cannot export: `otp.exportPad` refuses on the authenticated `role` ✓.
- **Native bridge:** results are accepted by id and by the one outcome each request can have;
  the callback is non-writable and non-configurable ✓. The bridge's own acceptance shape is
  unbound: see **m6**.

**Old paths:** `#otpTools`, `.otp-sub`, "Generate / share", `otpDownloadAgain` and the label in
the file name are gone from the client, CSS, e2e, Kotlin and Swift. There is no duplicate
handler: the dom-stub path (no sheet) still downloads at once and holds nothing (§ 12) ✓.

**Test hygiene:**
- `app-otp.test.mjs` was adapted to the new fields without weakening: the must-differ-relevant
  fixtures set `otpNewPass` / `otpImportPass` explicitly.
- `app-behaviour.test.mjs`'s flood wait is a real race fix and does not weaken the L-1
  assertion that follows.
- `android-source.test.mjs` anchors are exact-line and bind: the Kotlin mutant below goes red.
  Behaviour lives in the Robolectric/JVM tests, which I did not re-run (the pentest ran them).

**Checked, not verifiable here:** whether Chromium's history-manipulation intervention marks the
entry re-pushed from `popstate` (while working) as skippable, so that a *second* Back leaves the
page. Puppeteer's `goBack` uses `navigateToHistoryEntry`, which does not apply the skip rule.
Because the document already has sticky activation, I expect it not to. Add "Back twice during
New pad's KDF" to the on-device checks in `android/README.md` (6).

## Mutants (hand-run, one at a time, scratch copy; restored and `cmp`-verified)

| # | Mutant | Test run | Result |
|---|---|---|---|
| M1 | `otp.exportPad`: role check → `if (!record)` | otp-rollback + app-otp-sheets | **RED**: "Missing expected rejection: M9: exportPad refuses a pad this device received" |
| M2 | `otp.importPad`: `recipientRole !== 1` refusal off | otp-rollback | **RED**: "M9: importPad refuses recipientRole 0" |
| M3 | `otp.importPad`: `kdf.iters !== KDF_ITERS` refusal off | otp-rollback | **RED**: "F7: a file sealed under 100k iterations is refused" (got "wrong passphrase…") |
| M4 | Export must-differ `if (false)` | app-otp-sheets | **RED**: "must-differ: the carried pad passphrase is refused" |
| M5 | Import must-differ `if (false)` | app-otp-sheets | **RED**: "Import must-differ: refused" |
| M6 | Back while working: no re-push | app-otp-sheets | **RED**: "…it puts the history entry back" |
| M7 | Android close-confirm predicate → `false` | app-otp-sheets | **RED**: "§ 5: closing an unshared Android file asks" |
| M8 | 4 MiB import cap off | app-otp-sheets | **RED**: "a file over 4 MiB is refused without being read" |
| M9 | `otpNativeResult`: accept any id | app-otp-sheets | **RED**: "a result for another request id is ignored" |
| M10 | `otpNativeResult`: accept either success for any request | app-otp-sheets | **RED**: "a save request answered 'shared' is not a success" |
| M11 | `FILES_BRIDGE`: accept a writable/configurable global | full `npm test` | **GREEN, survives** → m6 |
| M12 | `FILES_BRIDGE`: accept an unfrozen object | full `npm test` | **GREEN, survives** → m6 |
| M13 | file name carries the label | app-otp-sheets | **RED**: "§ 7: the file name is neutral" |
| M14 | received pad: Export entry shown | app-otp-sheets | **RED**: "received pad: Export hidden, the note shown" |
| M15 | select change keeps `#otpPass` | app-otp-sheets | **RED**: "round 2 minor 5" |
| M16 | no `AbortSignal.timeout` on the export-lock wait | app-otp-sheets | **RED**: "the wait for another tab's export lock ends" |
| M17 | close keeps `pendingReexportId` | full `npm test` | **GREEN, survives** → m7 |
| M17e | same | e2e/otp-transfer.mjs (:8101) | **RED**: timeout waiting for the confirm state (the second export went through) |
| M18 | close does not clear the inputs | app-otp-sheets | **RED**: "the New pad sheet was cleared when it closed" |
| M19 | New pad does not carry the passphrase into `#otpPass` | app-otp-sheets | **RED**: "§ 2: the pad passphrase is carried" |
| M20 | the held import file is dropped on every outcome | app-otp-sheets | **RED**: "'Try again' is the primary…" (binds through the button state, not the re-pick itself) |
| M21 | Connect never `aria-disabled` | app-otp-sheets | **RED**: "empty: Connect is aria-disabled" |
| K1 | `PadFiles.kt` `MAX_BYTES` 4 → 8 MiB | android-source | **RED**: "the text cap is 4 MiB, as importPad's" |

## What to do, in order

1. **B1:** report from `finally` in `otpExport`, plus the PAD_BUSY sheet test.
2. **M1:** clear `otpHistEntry` on an orphan popstate, and do not open the sheet after Back
   during the unlock.
3. **m1–m5:** each is a small edit (clear the stale mark; clear panel errors on close; focus
   after a failed unlock; keep live regions rendered; must-differ vs an emptied field).
4. **m6, m7:** add the bridge-shape and latch-disarm unit checks, and prove each by rerunning
   M11, M12 and M17 red.
5. **m8:** pentest `a43a9d8` and the web half; update PROGRESS.md.
