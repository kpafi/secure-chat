# OTP transfer sheets — hot critic, round 2 (fix round 1 of the build)

Scope: `git diff 8ad39ed..HEAD` (HEAD 2e50caa) on `feat/otp-transfer-sheets`, read against
`otp-fix-round-1.md` (the triage) and `otp-transfer-brief.md` § 13, plus the four round-1
reports: `otp-hot-critic-r1.md`, `otp-cold-critic-r1.md`, `otp-design-critic-r3.md`,
`otp-pentest-r2.md`. I did not modify any tracked file except this report.

**Where things ran:**
- A scratch copy of HEAD (`scratchpad/hot2/tree`) for the mutants.
- A second pristine copy (`scratchpad/hot2/serve`) served by the relay on **:8101**
  (`SECURE_CHAT_EXTRA_ORIGINS=http://127.0.0.1:8101`, killed by PID afterwards). With this, no
  in-place mutant could reach a browser run, and none reached the worktree.
- A third copy (`scratchpad/hot2/probe-client`) for the dom-stub probes.
- Every mutated file was restored and checked with `cmp` against HEAD.

## Verdict

**The fix round does what it says.**

**Verified in a real browser against HEAD, with the round-1 probes:**
- Hot B1 (the Export sheet stuck in "working").
- M1 (Back during the unlock).
- m1 (the stale passphrase mark).
- m2 (sheet errors left in the panel).
- m3 (focus lost after a failed unlock).
- The must-differ bypass.

**Verified by rerunning the reviewers' mutants:** the Android items (R2-5, R2-6, R2-7a/b, mi-4,
mi-5, A5) all go red in Gradle.

**Nothing blocks and nothing is major.** What I found are regressions and gaps at the edges of
the fixes:

- **Import "working" state (new):** it now hides its own progress from assistive tech and cannot
  take focus. The design r3 minor 4 `inert` covers the element that holds the progress.
- **"Unlocked ⇔ its passphrase is in #otpPass" (§ 13):** this is enforced on the dropdown's
  `change` only. The programmatic selection of the "You already have this pad" path breaks it,
  and with it the must-differ comparison. The path is rare.
- **View switch during the Export entry's unlock:** a switch to another tab still opens the
  Export sheet over that view. Back now cancels; a view switch does not.
- **`autocomplete="new-password"` (cold n-6):** now on the pad and transfer passphrase fields.
  It invites password-manager generation and saving for exactly the two secrets this flow keeps
  off every server. Not verified in a signed-in browser.
- **Unbound defences** (a test gap, not a bug today):
  - The failed-unlock variant of M1 is held by two guards, the popstate clear and the on-top
    check. Each survives on its own, and **both removed together still pass every suite** while
    bringing back the Android "swallowed Back".
  - Also unbound: the entry-busy guard, the passphrase write-back, and hot m4's
    `aria-describedby`.

**Counts: 0 blocker, 0 major, 5 minor, 8 nit.**

**Runs (all green at HEAD):**
- `cd client && npm test`: every file, including the new `app-otp-bridge.test.mjs`.
- `./gradlew --offline testDebugUnitTest` (scratch copy): 48/48 (PadFilesActivityTest 26,
  PadFilesTest 10, RelayUrls 11, UnsupportedWebView 1).
- `e2e/otp-transfer.mjs` **192/192**, `e2e/all-modes.mjs` **28/28**, `e2e/no-dead-ends.mjs`
  **17/17**, all on :8101.
- Not run (as instructed): the backend pytest suite and `screenshots.mjs`.

**Probes:**
- Browser: `scratchpad/hot2/tree/e2e/probe-hot.mjs`, `probe-hot2.mjs`, `probe-hot3.mjs` (round
  1, rerun), plus `probe-hot2b.mjs`, `probe-hot2c.mjs` and `probe-hot2d.mjs` (new).
- Stub: `scratchpad/hot2/probe-client/client/probe-hot2.test.mjs` (probe A) and
  `probe-hot2b.test.mjs` (probe B).

## Verification of the round-1 findings

### Hot critic r1

| Finding | Status | Evidence |
| --- | --- | --- |
| B1 PAD_BUSY leaves Export in "working" | **Verified fixed** | `probe-hot.mjs` P1 (a second page holds `sc.otp.lock.v1.<id>`): `{"state":"form"}`, `closeHidden:false`, status = PAD_BUSY; Escape then closes, `#viewLive` not inert. H1 → red (unit); the e2e "hot B1 / R2-1" check is green at HEAD |
| M1 Back during the unlock → × leaves the app | **Verified fixed** (the failed-unlock variant is unbound, see n-mut) | P2: after Back + unlock, no sheet and the URL stays in the app. `probe-hot2b` (c): Back during the unlock → no sheet, pad unlocked, focus on Export, `history.state` null. The next Export opens with its own entry, the must-differ check fires, and × stays in the app (same document). H3 → red in unit **and e2e** (EF: "R2-2: Back during the unlock opens no sheet afterwards") |
| m1 stale transfer-passphrase mark after a file-level error | **Verified fixed** | `probe-hot3` Q2: `aria-invalid` null, `aria-describedby` null, 1px border, muted label, the line hidden. H13 → red |
| m2 sheet errors left in the panel | **Verified fixed** (a residual, nit N1) | Q3: after must-differ + Escape, `#otpStatus` = `["","hint",…,0px]`. H10, H11 → red |
| m3 focus lost after a failed unlock | **Verified fixed** | Q1: `activeElement = otpPass`. H16 → red |
| m4 live regions `display:none` | **Fixed in CSS**; the `aria-describedby` half is **unbound** | `.otp-status:empty` stays rendered at zero height. H15 (the `otpMarkField` describedby line removed) survives unit and e2e (the e2e describedby check is on `#otpImportXfer`, whose mark `renderOtpImport` sets, not `otpMarkField`) |
| m5 must-differ skipped after a pad round trip | **Fixed for the dropdown; partially** | H5, H7, H8 → red. Holds only for a user `change`: see **minor N2** |
| m6 bridge shape unbound | **Verified fixed** | M11 (writable/configurable) and M12 (unfrozen) rerun → red in `app-otp-bridge.test.mjs` |
| m7 latch disarm bound only by e2e | **Verified fixed** | M17 rerun → red in `app-otp-sheets` ("§ 5: closing disarmed the latch…") |
| m8 no pentest of a43a9d8 / web; PROGRESS | **Partially** | Pentest r2 covers both. Still open: PROGRESS.md has no entry for this branch, and **the fix-round code itself (c1cb868, 0141b9f) has had no `pentest-new-code` pass** (workflow rule: a fix is new code) |
| n1 hard-coded /tmp path | **Verified fixed** | no `scratchpad` / `/tmp/claude` in `e2e/*.mjs` |
| n2 close + open in one task | **Mitigated as claimed; better than claimed in Chromium** | `probe-hot2.mjs`: after × + New pad in one task, `history.state = {"otpSheet":1}`, and Back closes the new sheet while staying in the app. The triage's "a Back then leaves the page" does not happen in Chromium 1xx |
| n3 current step by colour only | Fixed | 2px ring (CSS) |
| n4 desktop button order | **Fixed** (the doc wording is off, nit N7) | `probe-hot2b` (b), 1280×800: Done is full-width with the "again" ghost below; in the confirm state, "Don't export" is on the left and the danger grows on the right |
| n5 leftovers | Fixed | `Object.values`, `setAttribute` only (no reader of `dataset.state` exists), `force` removed |
| n6 role=status wraps Lock | Fixed | the role is on the text span |
| n7 preselect a sole pad | **Rejected, and I accept it** | pre-existing; it changes Connect for every OTP user |

### Cold critic r1

| Finding | Status | Evidence |
| --- | --- | --- |
| MA-1 (= hot M1) | Verified fixed | as above |
| MA-2 (= hot m5) | Partially | as above; see N2 |
| MA-3 nobody told to delete the file | **Fixed** (copy nit N6) | both done blocks carry the line; the again-link is 13px muted, "the same file"; H21 → red |
| mi-1 stale "Choose a one-time pad first" | Verified fixed | H12 → red |
| mi-2 256 vs 128 KiB | Fixed | "Size, each way", options per side; e2e picker and card checks |
| mi-3 (cold M2) pad switch during the unlock | Verified fixed | F6 test; H7 → red |
| mi-4 late pick → file deleted | **Verified fixed** | R2a (cancelled deletes again) → red: `shareWithoutAChosenTarget…LivesOutItsTtl`, `aPickReportedAfterCancelled…` |
| mi-5 configChanges | Verified fixed | HA1 (no data scheme on the receiver) turns `aConfigurationChangeKeepsTheActivityAndTheShareInFlight` red too, so the test drives a real share across `configurationChange` |
| mi-6 "Export failed" for an unlock | Fixed | "Could not unlock this pad: …" (Q1 wait matched it) |
| mi-7 maker's label | Partly, as stated | "· from your contact". H22 survives unit, **red in e2e** (191/192, "import done: the card says it came from the contact") |
| n-1 UTC label | Fixed | `localStamp` |
| n-2, n-3, n-4 | Rejected / kept — **I accept the arguments** | n-3 is a pinned `.vh` sentence; n-4 keeps the held file for "the same file again" without a re-export confirm |
| n-5 | Fixed | = hot n1 |
| n-6 `autocomplete` | Fixed as asked — **but challenged**, see **minor N4** | |
| n-7 showView force-close | Fixed | no `force`; the unshared-file confirm applies |
| Cold mutants M1, M2, M4, M5, M6, M10 | Tests added | M17 (= cold M1), M11/M12 (= M4) rerun red; F6/F13/F14/F15 per triage (not rerun by me) |

### Design critic r3

| Finding | Status | Evidence |
| --- | --- | --- |
| R3-M1 sheet error visible in the panel and outliving the sheet | Verified fixed | Q3; H10, H11 → red; e2e EF7 green at HEAD |
| minor 1 filled steps muted | Fixed | `is-filled` + CSS |
| minor 2 desktop order | Fixed | = hot n4 |
| minor 3 Forget on its own row | Fixed | e2e EF2c green |
| minor 4 empty bar / live-looking fields while working | Fixed — **introduced minor N1** (Import progress made inert) | e2e EF3 green; `probe-hot2c` |
| minor 5 raw DOMException | Verified fixed | H14 → red |
| minor 6 "Didn't arrive?" after Save | Verified fixed | H21 → red |
| minor 7 keyboard up on short phones | **Verified** (the harness has no check) | `probe-hot2b` (a), 390×460 with `#otpNewPass` focused: the sheet spans 12→460, `#otpGenerate` at 400–444 is the hit-test target, no horizontal overflow |
| minor 8 weak line in "On their device" | Fixed | markup moved under the done line |
| nits 1–8 | Fixed | markup/CSS read; e2e card check for nit 3 |

### Pentest r2

| Finding | Status | Evidence |
| --- | --- | --- |
| R2-1 PAD_BUSY wedge | Verified fixed | = B1 |
| R2-1 Info: the 30 s bound is dead code | **Removal accepted** | the only taker of `sc.otp.export.v1.*` is `otpExport`, and it always holds the pad lock (`ifAvailable`) first |
| R2-2 | Verified fixed | = M1 |
| R2-3 | Partially | = m5; N2 |
| R2-4 re-deliveries not re-checked | **Rejected (Info) — accepted** | the text is byte-identical and latched; residual (b) (the pad used in another tab since) stands, as documented |
| R2-5 `0@authority` | Verified fixed | R2g (authority again) → red: `pickerResultsThatAreNotAnotherAppsDocumentAreDropped` |
| R2-6 PendingIntent aliasing | Verified fixed | R2f (receiver ignores the id) → red (2); HA1 (filter without the data scheme) → red (6) |
| R2-7a a new share deletes an old one | Verified fixed | HA1 turns `aSecondShareGetsItsOwnUri…` red; R2b per triage |
| R2-7b a restart leaves no timer | Verified fixed | HA2 (always wait a full TTL after a start) → red: `aStartArmsTheTimerForAYoungShare` |
| R2-8 README "canonical" | Fixed (doc) | |
| R2-9 protocol skew | **Rejected as code; accepted — but untracked** | no release-notes file or PROGRESS entry carries it yet (nit N8) |
| Lead: re-push without activation | **Partially** | `android/README.md` item (6) says "does not dismiss a working sheet". It does not say **"press Back twice during a KDF"** or "Back during the Export entry's unlock", which the lead and hot r1 asked for (nit N8) |
| A1 revoke before delete | Source pin only (Robolectric has no URI grants) — accepted | on the phone checklist (5) |
| A5 "wt" | Verified fixed | A5 → red: `saveOverALongerFileTruncatesIt` |

### The "equivalent" and "rejected" arguments

- **J9 (the held export text is not cleared on close): agreed.**
  - H17 survives.
  - Every open runs `resetOtpSheet` first, and nothing reads `otpExportFile` outside the
    ready/done states.
  - What remains is memory lifetime only.
- **J19 (page-side name/size pre-check): agreed.** Native re-checks, and only our own generator
  could trip it.
- **F3 (the on-top check in `otpHistDrop`): "equivalent today" is right, but incomplete.**
  - **H2** (a popstate with no sheet keeps `otpHistEntry`, i.e. the other half of the M1 fix)
    **also survives**.
  - The two guards cover the same hazard, so each masks the other's removal.
  - **H2+H4 together survive `app-otp-sheets`, `app-otp` and `app-behaviour`.** A stub probe
    (probe B: Back during a *failed* Export-entry unlock, at the first history entry, as on
    Android) shows the double mutant is not harmless:
    - app.js calls `back()` once, which does nothing at the first entry;
    - the ignore counter sticks;
    - the next Back on an Import sheet is swallowed (`sheet closed false`).
  - At HEAD, probe B passes.
  - One test with a wrong passphrase plus Back binds the pair.
- **Hot n7, cold n-2/n-3/n-4, R2-4, R2-9: accepted.** R2-9 needs a home (N8).

## New findings

### MINOR

**N1. Import "working": the progress sits inside the `inert` steps, so it is out of the
accessibility tree and cannot take focus.** (A regression from design r3 minor 4.)

- **Where:**
  - `app.js` `renderOtpImport`: `els.otpImportSteps.inert = st === "working"`.
  - But `#otpImportProgress` (`role="status"`, the working sentence and "Keep this open") lives
    **inside** `#otpImportStep3`, inside `#otpImportSteps` (`index.html` ~925).
  - `otpSheetBegin` then calls `progress.focus()` on an inert element.
- **Measured** (`probe-hot2c.mjs`, real Chromium, KDF held):
  - `{"active":"otpImportSheet","progressInInert":true}`.
  - The accessibility snapshot contains neither "Opening the file and encrypting" nor "Keep this
    open".
  - New pad, for comparison (its progress is outside `#otpNewForm`): `active: otpNewProgress`.
- **Effect:** for the two-KDF import (several seconds on a phone), a screen-reader user hears
  nothing and focus is on the dialog. This breaks § 3 "working → the progress".
- **Why the e2e missed it:** e2e and unit check the progress focus for New pad and Export only.
- **Fix:**
  - Make only steps 1–2 and step 3's caption inert (e.g. `otpImportStep1.inert =
    otpImportStep2.inert = …`), or move the progress out of the `<ol>` (as New pad has it).
  - Add "Import working: focus on `#otpImportProgress`" to `app-otp-sheets` or the e2e.

**N2. "Unlocked ⇔ its passphrase is in `#otpPass`" holds only for a dropdown `change`. The
"You already have this pad" path breaks it, and the must-differ comparison with it.**

- **Where:**
  - `otpSelectChanged` enforces the rule (`otpPanel = null`, field emptied).
  - `refreshOtpPads(selectId)` sets `els.otpSelect.value` programmatically and calls only
    `syncOtpSelection()`.
  - The import path (`app.js` ~5550: `if (already) { refreshOtpPads(rec.padId); … }`) selects pad
    X while `otpPanel` stays on pad Y and `#otpPass` keeps Y's passphrase.
  - `otpForgetSelected` → `refreshOtpPads()` has the same gap.
- **Probe A** (`probe-hot2.test.mjs`, dom stub). "made" is unlocked with its passphrase in the
  field. The same file is imported twice, with the used-markers gone in between (the state a
  second tab's concurrent import of the same file leaves, or lost markers; the path
  `app-otp.test` (Mf) exists for). Steps and results:
  1. After "You already have this pad": `selected = other | unlocked row shown: false | #otpPass
     visible: true | holds made's passphrase: true`.
     - That is round 2 minor 5 again: a pad shown locked with another pad's passphrase already in
       its field. Connect would then fail "wrong passphrase".
  2. The user replaces the field's content (the natural move for a locked pad), then picks
     "made" in the dropdown. Result: `unlocked row shown: true | field = other's passphrase:
     true`.
     - The panel says "Unlocked" while the field holds a different pad's passphrase.
  3. Export with made's **pad** passphrase as the transfer passphrase → `state = confirm`
     ("This pad was already exported…").
     - The must-differ refusal did not fire; for a never-exported pad this is a file encrypted
       under the pad passphrase.
- **Severity:** Low × rare path, the same class as R2-3.
- **Fix:** end `refreshOtpPads` with the `otpSelectChanged` rule instead of `syncOtpSelection()`:
  lock when the selection is not `otpPanel.padId`, including `""` after Forget.
  - Generate and Import set `otpPanel` to the new pad before they call it, so they are
    unaffected.
  - Add probe A's first half as a test.

**N3. A view switch during the Export entry's unlock still opens the Export sheet, over the other
view; its × then drops focus to `<body>`.**

- **Where:** `otpExportOpenClick`: `ok = els.otpSelect.value === id` and `!otpUi.entryBack`. The
  tab bar is not inert during the unlock (no sheet is up yet).
- **Measured** (`probe-hot2d.mjs`): tap Export on a locked pad, tap the Chats tab during the KDF.
  After the unlock:
  - `{"exportSheetShown":true,"viewLiveHidden":true,"tabbarInert":true,"histState":{"otpSheet":1}}`;
  - after ×: `focus BODY`, Live still hidden.
- **Why it matters:**
  - Not harmful (the sheet is modal and complete), but a sheet belonging to the Live room pops
    up over Chats.
  - `showView` would have closed it had it been open.
  - The fix round made Back a cancel and missed the other "I went elsewhere" gesture.
  - This predates the fix round, in the function it rewrote.
- **Fix:** `ok = els.otpSelect.value === id && !els.viewLive.hidden`. The `!ok` path then drops
  the entry.

**N4. `autocomplete="new-password"` on `#otpNewPass`, `#otpXferPass` and `#otpImportPass`
(cold n-6) invites password managers to generate and save these secrets.**

- **Why it matters:**
  - `new-password` is the signal for Chrome's "Suggest strong password" and its save-to-Google
    prompt, and on Android for the Autofill framework's save.
  - The pad passphrase is meant to be only the user's own, and the transfer passphrase is
    spoken, never sent. A generated one cannot be spoken, and a saved one lands in a synced
    vault.
  - Every other passphrase field in the app (`idPass`, `pass`, the three unlock fields,
    `#otpPass`, `#otpImportXfer`) keeps `off`.
  - `off` does not stop Chrome's save prompt either (the cold critic's point), but it does not
    *offer* generation.
- **Not verified here:** headless Chromium has no signed-in profile.
- **Fix:** revert to `off` (consistent with the app), or record the decision in § 13. Add it to
  the phone checklist: tap into `#otpXferPass` and see whether Google offers a password.

**N5. The fix round's own defences are partly unbound (the mutants survive).**

- H2+H4: the M1 failed-unlock variant (see "equivalent" above).
- **H9:** `openOtpSheet` without the `entryBusy` guard survives. § 13 says "No other sheet opens
  while that unlock runs"; without the guard, Import opened during the unlock leaves the Export
  entry's history entry orphaned under it (hot r1 n2, "related case").
- **H6:** `ensureUnlocked` without the passphrase write-back survives. The write-back is what
  keeps the field right when the user edits `#otpPass` during a Connect or Export-entry KDF (the
  field is visible then). Without it, the unlocked pad's field holds the edited text, and
  must-differ compares against that.
- **H15:** hot m4's `aria-describedby` addition, as above.
- **Tests:**
  - Back during a failed unlock at the first entry: no `back()`, and the next Back closes a sheet.
  - Import tapped during the unlock: no sheet, and history is unchanged.
  - Edit `#otpPass` during the unlock, then must-differ against the original.
  - A marked `#otpXferPass` has `otpExportStatus` in its describedby.

### NIT

- **N1-nit (panel residue):** a panel error written *before* a sheet opens stays, shown, under
  the sheet and after it.
  - `probe-hot2b` (d): "Could not unlock this pad: …" is still `hint err` behind the Import scrim
    and after Import closes.
  - R3-M1 covered only sentences written while a sheet was open. Clearing `#otpStatus` when a
    sheet opens would finish the job.
- **N6 (delete-the-file copy):** "Once they've imported it, delete the file on both devices."
  also shows after Android "shared" and iOS "Share sheet opened". There the maker has no
  user-visible copy (Android's is app cache, gone in 10 minutes), so "both devices" sends them
  looking for a file. Suggested: "…delete the file on their device, and yours if you saved or
  downloaded it."
- **N7 (§ 13 wording):** § 13 says "the primary (or the danger) grows on the left". In the
  re-export confirm the danger is on the **right**, after "Don't export", which is what § 5
  requires (`probe-hot2b` (b)). Fix the sentence, not the code.
- **N8 (tracking):**
  - R2-9 ("update both phones before exchanging new pads") exists only in the triage. No release
    notes or PROGRESS entry carries it.
  - The on-device list (android/README (6)) lacks "Back twice during a KDF" and "Back during the
    Export entry's unlock".
  - PROGRESS.md has nothing for this branch (hot m8).
- **N9:** the fail-closed "Enter this pad's passphrase to unlock it." inside the Export sheet
  points at a field behind the modal. It is reachable only through N2. "Close this and enter your
  pad passphrase above." would say where.
- **N10:** New pad and Import tapped during the Export entry's unlock do nothing, with no word.
  (Acceptable; the Export button shows the spinner.)
- **N11:** android/README (5) still says "two after 'Send it again'". The link is now "Didn't
  arrive? Send the same file again".
- **N12:** the triage's n2 note ("a Back then leaves the page") is more pessimistic than Chromium
  behaves (see the table). Worth correcting, so nobody "fixes" a non-problem.

## Mutants (hand-run, one at a time, scratch copies; restored and `cmp`-verified)

**Web.** Unit runs use `app-otp` + `app-otp-sheets` + `app-otp-bridge` unless noted. H13–H22 ran
first against `app-otp-sheets` + `app-otp-bridge`; the survivors also ran against `app-otp`.

| # | Mutant | Result |
|---|---|---|
| H1 | B1 reverted: `otpExportFinished` only on the normal path | **RED**: "R2-1: a busy pad leaves 'working' — back to the form" |
| H2 | popstate with no sheet keeps `otpHistEntry` (half of the M1 fix) | **GREEN, survives** (masked by the on-top check) |
| H3 | Back during the unlock still opens the sheet | **RED** unit ("R2-2: …no sheet opens after it") **and e2e** (FAIL "R2-2: Back during the unlock opens no sheet afterwards") |
| H4 | F3: `otpHistDrop` without the on-top check | **GREEN, survives** (as the triage says) |
| H2+H4 | both | **GREEN** in `app-otp-sheets`, `app-otp`, `app-behaviour`; probe B shows the swallowed Back → N5 |
| H5 | select change keeps `otpPanel` | **RED**: "R2-3: back on a pad after choosing another: it is locked again" |
| H6 | `ensureUnlocked` without the passphrase write-back | **GREEN, survives** → N5 |
| H7 | `ensureUnlocked` caches a pad no longer on screen | **RED**: "…the unlock of a pad no longer on screen is not cached" |
| H8 | Export skips the comparison when `#otpPass` is empty (old) | **RED**: "R2-3: … Export refuses instead of skipping the comparison" |
| H9 | `openOtpSheet` without the `entryBusy` guard | **GREEN, survives** → N5 |
| H10 | close keeps a sheet-time sentence in the panel | **RED**: "design R3-M1: …the panel keeps nothing" |
| H11 | the panel copy is shown while a sheet is open | **RED**: "design R3-M1: while the sheet is up…" |
| H12 | no clearing of "Choose a one-time pad first" | **RED**: "cold mi-1" |
| H13 | `renderOtpImport` does not clear the transfer mark | **RED**: "hot m1" |
| H14 | raw DOMException text | **RED**: "design r3 minor 5" |
| H15 | `otpMarkField` without the status in `aria-describedby` (hot m4) | **GREEN, survives** unit; the e2e checks `#otpImportXfer` only → N5 |
| H16 | no focus on `#otpPass` after a failed unlock | **RED**: "(hot m3)" |
| H17 | J9: close keeps `otpExportFile` | **GREEN, survives** (equivalent, agreed) |
| H18 | `entryBusy` never cleared | **RED**: "N-M2: the entry is pushed synchronously…" |
| H19 | popstate never sets `entryBack` | **RED**: "R2-2 …" |
| H20 | `entryBack` not reset per unlock | **RED**: "fixture: the Export sheet is open" |
| H21 | the old "Didn't arrive?" after Save | **RED**: "design r3 minor 6, cold MA-3" |
| H22 | received card says "imported" again | **GREEN** unit; **RED** e2e (191/192, "cold mi-7") |
| M11 | `FILES_BRIDGE` accepts a writable/configurable global (hot r1 survivor) | **RED**: 'bridge shape "writable": app.js took the android path' |
| M12 | `FILES_BRIDGE` accepts an unfrozen object (hot r1 survivor) | **RED**: 'bridge shape "unfrozen"' |
| M17 | close keeps `pendingReexportId` (hot r1 survivor) | **RED**: "§ 5: closing disarmed the latch — the next Create asks again, no file" |

**Android.** `./gradlew --offline testDebugUnitTest`, scratch copy; `MainActivity.kt` restored and
`cmp`-verified after each run.

| # | Mutant | Result |
|---|---|---|
| A5 | `"wt"` → `"w"` | **RED**: `saveOverALongerFileTruncatesIt` |
| R2g | `uri.host` → `uri.authority` | **RED**: `pickerResultsThatAreNotAnotherAppsDocumentAreDropped` |
| R2a | "cancelled" deletes at once again | **RED** (2): `…LivesOutItsTtl`, `aPickReportedAfterCancelled…` |
| R2f | the receiver ignores the id | **RED** (2): `aChosenBroadcastForAnotherRequestIsIgnored`, `aSurvivingPendingIntentFromAnEarlierProcessIsNeverReused` |
| HA1 | receiver filter without `addDataScheme` | **RED** (6), incl. `aConfigurationChangeKeeps…`, `aLateChosenBroadcast…`, `aSecondShareGetsItsOwnUri…` |
| HA2 | the start timer always waits a full TTL (`coerceIn(TTL, TTL)`) | **RED**: `aStartArmsTheTimerForAYoungShare` |

## What to do, in order

1. **N1:** take `#otpImportProgress` out of the inert subtree (or inert steps 1–2 only), and add
   a focus test for Import working.
2. **N2:** apply the `otpSelectChanged` rule at the end of `refreshOtpPads`, and add a test for
   the "already on this device" selection.
3. **N3:** a view switch during the Export entry's unlock cancels it, like Back.
4. **N4:** decide on `autocomplete` (recommended: `off`, as everywhere else), and add it to the
   phone checklist.
5. **N5:** bind H2+H4 (a failed unlock plus Back), H9, H6 and H15, each with one test, and rerun
   them red.
6. **Nits:** N1-nit, N6–N12. Then run `pentest-new-code` on c1cb868 + 0141b9f (the fix is new
   code) and add a PROGRESS entry.
