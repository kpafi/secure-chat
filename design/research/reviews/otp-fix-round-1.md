# OTP transfer sheets — fix round 1 (after hot/cold critic r1, design critic r3, pentest r2)

## Android

Commits 0141b9f (code + tests) and 68f2acd (android/README). Build, `testDebugUnitTest`
(48: PadFilesActivityTest 26, PadFilesTest 10, RelayUrls 11, UnsupportedWebView 1) and
`node client/android-source.test.mjs` (9/9) green. Each row's mutant was hand-run and reverted.

| Finding | Fix | Test | Mutant → result |
| --- | --- | --- | --- |
| Cold mi-4: a late pick after the 1.5 s grace → "cancelled" and the file deleted under a reading target | "cancelled" no longer revokes or deletes; the file lives out `SHARE_TTL_MS` (10 min) like "shared". Only "error" (chooser never ran, no grant possible) removes it at once. A late pick is **not** sent as a correction (the contract answers once); the file survives for the target and "Share…" is still there | `shareWithoutAChosenTarget…LivesOutItsTtl`, `aPickReportedAfterCancelledIsNotACorrectionAndTheFileSurvives` | R2a (delete on everything but "shared") → red (JVM 2, node) |
| Cold mi-4 + pentest R2-7a: a new share ("Send it again", or a 2nd instance) deleted a share still sending | `startShare` touches no earlier file; per-request URIs keep an old grant on the old file; every file ends by expiry (revoke, then delete) | `aSecondShareGetsItsOwnUriAndLeavesTheFirstForItsTarget`, `aShareInASecondInstanceLeavesTheFirstInstancesShare` | R2b (supersede again) → red (JVM 2, node) |
| Pentest R2-7b: a restart within 10 min left the file with no timer | `expireShares()` at every start and after every share; removes what is due, re-arms for the next file. Only process death breaks the bound (next start catches up) — README says so | `aStartArmsTheTimerForAYoungShare`, `aNewInstanceKeepsARecentShareAndPurgesAnExpiredOne`, `aSharedFileIsPurgedAfterItsLifetime` | R2h (no re-arm) → red (3); R2i (start does not expire) → red (2); R2j (expire young files) → red (8) |
| Cold mi-5: configChanges missed uiMode, locale, fontScale, screenLayout, smallestScreenSize, density, keyboard/navigation → page reload mid-Share/Save | `configChanges` now also `screenLayout|smallestScreenSize|density|keyboard|navigation|touchscreen|uiMode|locale|layoutDirection|fontScale|colorMode|mcc|mnc|grammaticalGender` (all safe: no per-config resources, one page theme; the native bar's strings follow a locale switch at next start). Remaining: process death — fresh start, pad latched exported, "export again" confirm next time, possibly an empty saved file (README) | `aConfigurationChangeKeepsTheActivityAndTheShareInFlight` (Robolectric `configurationChange`: same instance, share still pending, then "shared") + manifest pin | R2c (no uiMode) → red; R2d (r1 list) → red |
| Pentest R2-6: per-share requestCode restarts at 1 in a new process → a surviving PendingIntent with an old id | The id is the intent's **data** (`x-secure-chat-share:<id>`, part of PendingIntent identity); requestCode 0; the receiver filters on the scheme and matches `data.schemeSpecificPart` | `aSurvivingPendingIntentFromAnEarlierProcessIsNeverReused` (old-form PIs at requestCodes 0–3), `eachShareHasItsOwnImmutableChosenCallback`, `aChosenBroadcastForAnotherRequestIsIgnored` | R2e (id as extra again) → red (2); R2f (receiver ignores id) → red (2) |
| Pentest R2-5: `content://0@<our authority>` passed `isForeignDocument` | Compare `uri.host` (authority without `userId@`); a user id on a foreign provider (work profile) stays allowed | `pickerResultsThatAreNotAnotherAppsDocumentAreDropped` + `0@….files`, `0@….androidx-startup` | R2g (authority again) → red |
| Pentest A5: "wt" had only a text pin | Behavioural: a documents provider records the open mode; a longer existing file ends up exactly the envelope (unit tests need `--add-opens java.base/java.io`) | `saveOverALongerFileTruncatesIt` | A5 ("w") → red (JVM + node) |
| Pentest A1: revoke-before-delete had only a text pin | **Not observable in Robolectric** (no URI-grant model: `revokeUriPermission` reaches a no-op ActivityManager); kept as a source pin, added to the phone checklist | source pin in `android-source.test.mjs` | A1 (revoke removed) → JVM green, node red |
| Pentest R2-8: README said "ct canonical base64" | README: alphabet, length and padding; tail bits not checked (AES-GCM authenticates the bytes) | — (doc) | — |
| Pentest (earlier survivor) MD | still killed | `aLateChosenBroadcastWithinTheGraceStillCountsAsShared` | MD → red |

## Web client

Commits 075896e (otp.js label), c1cb868 (app.js / index.html / style.css / unit tests),
288fd43 (e2e), and this file + brief § 13. Checked: `npm test` green (incl. the new
`app-otp-bridge.test.mjs`); e2e on a scratch relay: otp-transfer 192/192, all-modes 28/28,
no-dead-ends 17/17, room-admission 49/49, contact-profile 67/67, two-user-flow 15/15,
hostile-relay 24/24; screenshots 37/38 (02 is the old drawer; `git diff` clean before and
after the run, no mutant applied). Every mutant below
was hand-run on its own and reverted (`git diff` clean after each). F-numbers are unit mutants
(`app-otp-sheets` / `app-otp-bridge`), EF-numbers e2e mutants (`e2e/otp-transfer.mjs`).

### Must

| Finding | Verdict | What changed | Bound by (mutant → red check) |
| --- | --- | --- | --- |
| Hot B1 = pentest R2-1: PAD_BUSY leaves Export in "working" | **Fixed** c1cb868 | Every exit of `otpExport` reports from an outer `finally` | F1 → "R2-1: a busy pad leaves 'working'"; EF4 → the e2e waits for the form and times out |
| Pentest R2-1 (Info): the 30 s export-lock bound is dead code | **Removed**, honestly | The wait is entered only inside the pad lock, which every exporter takes first without waiting; no current client holds the export lock then. The old test built that state by hand; it is deleted with the bound. The "Waiting for this pad's export…" line and its app-otp test stay | — (no code left to mutate) |
| Hot M1 = cold MA-1 = pentest R2-2: Back during the Export entry's unlock | **Fixed** c1cb868 | Back during the unlock is a cancel (no sheet; the pad stays unlocked); no other sheet opens meanwhile; every popstate not ignored clears the entry flag; a close calls `history.back()` only while `history.state` is still ours | F2 → "R2-2: … no sheet opens after it"; EF5 → the same in Chromium (`page.goBack()`), and "a later × does not navigate out of the app" |
| Cold MA-2 = pentest R2-3 = hot m5: must-differ skipped after a pad round trip | **Fixed** c1cb868 — chose "lock on switch" + fail closed, not a stored/hashed copy or an extra KDF | A pad switch locks the panel's pad; `ensureUnlocked` caches only the pad on screen and writes back the passphrase that unlocked it; Export with an empty `#otpPass` refuses ("Enter this pad's passphrase to unlock it."). Why: it keeps the owner's rule "only the live values are compared, nothing stored or hashed", costs no extra 600k KDF per export, and fails closed wherever the invariant could break. A pad switch now asks for the passphrase again (rare, and what the unlocked row implies anyway) | F4 → "R2-3: … it is locked again"; F5 (the old `#otpPass && …`) → "R2-3: … refuses instead of skipping"; F7 → "…is not cached"; S1' (comparison removed) → "must-differ: … refused" |
| Design R3-M1 = hot m2 = cold minor: sheet errors in the panel | **Fixed** c1cb868 | `#otpStatus` is `.vh` while a sheet is open; a sentence written then is emptied on close; still byte-identical for the tests | F8, F9 → "design R3-M1: …"; EF7 → the same in Chromium |
| Cold mi-1: stale "Choose a one-time pad first" under Connect | **Fixed** c1cb868 | Removed from the hint lines once a pad exists | F19 → "cold mi-1: …" |
| Cold MA-3: nobody is told to delete the pad file | **Fixed** c1cb868 | Export done: "Once they've imported it, delete the file on both devices." ("devices", not the requested "phones": the maker may be on a computer). Import done: "Delete the pad file now." The again link is 13px/muted and names the same file ("Download the same file again", "Share the same file again", "Didn't arrive? Send the same file again", after Save "Share or save the same file again") | EF6 → "import done: 'Delete the pad file now.'"; F21 → "after a SAVE the link says…" |

### Surviving mutants from the reviews

| Mutant | Verdict | Bound by |
| --- | --- | --- |
| J10 / hot M17 / cold M1: close keeps `pendingReexportId` | **Unit test added** | F10 → "§ 5: closing disarmed the latch — the next Create asks again, no file" |
| M11 / M12 / J18 / cold M4: the bridge shape check | **Test added** (`app-otp-bridge.test.mjs`: six child processes — frozen control, writable, configurable, unfrozen, accessor, plain assignment) | F22 → 'bridge shape "writable": app.js took the android path'; F23 → 'bridge shape "unfrozen": …' |
| Cold M2: pad switch during the Export entry's unlock | **Test added** | F6 → "cold M2: … no Export sheet (for the wrong card)" |
| Cold M5 = J16: held import text kept after a file-level error | **Test added** | F13 → "M5/J16: a file-level error drops the held file" |
| Cold M6: the 500 ms guard | **Test added** (events with `timeStamp`) | F14 → "M6: a tap within 500 ms … is ignored" |
| Cold M10: New pad's re-entry guard | **Test added** | F15 → "M10: two taps on Create pad make ONE pad" |
| J11: `otpNativeReq` not cleared on close | **Test added** | F11 → "J11: a request left open by a closed sheet does not disable Share / Save" |
| J13: `otpSendAgain` state guard | **Test added** | F12 → "J13: … does nothing outside the done state" |
| J20: the ignore counter | **Test added** (a close and an open in one task; the faithful history model) | F16 → red (in the J10 block's fixture: without the counter the close's own popstate closes the next sheet) |
| J9: the held export text not cleared on close | **Equivalent, argued** | Every open runs the same reset before any use (`otpSheetShow` → `resetOtpSheet`), and the held text is read only in the ready/done states, which a new export reaches only by setting a new text. What remains is memory lifetime: the transfer-encrypted envelope stays referenced until the next open. Not observable from the page without a test hook |
| J19: the page-side name/size pre-check before the bridge | **Equivalent, argued** | The name comes only from `otpFileName` (always matches) and the text from `exportPad` (≤ 1.4 MiB for the largest pad); native re-checks both (android-source pins it). The check can only fire on a bug in our own generator |
| F3 (new): the "still on top" check in `otpHistDrop` | **Equivalent today, kept as defence** | With the entry flag cleared on every popstate, no current flow drops with a stale flag; the check guards the case the flag misses (a future caller) |
| Old S15 / S22 | Retired with the code they tested (pad switch now locks; the 30 s bound is gone) | F4, F1 |

### Should (my judgement)

| Finding | Verdict | Note / bound by |
| --- | --- | --- |
| Hot m1: stale passphrase mark after a file-level error | **Fixed** | F17 → "hot m1: …no longer blamed" |
| Hot m3: focus lost after a failed unlock | **Fixed** (focus `#otpPass`) | F20 → "(hot m3)" |
| Hot m4: live regions `display:none` while empty | **Fixed**: empty status kept in the tree (zero height, gap given back); a marked field is described by its sheet status | e2e geometry unchanged; not separately mutated |
| Hot m6, m7 | = M11/M12, J10 above | |
| Hot m8: no pentest of a43a9d8 / web half; PROGRESS | Pentest r2 now covers both. PROGRESS.md **not** updated here (the orchestrator's file) | |
| Hot n1 = cold n-5: hard-coded /tmp path in e2e | **Fixed** 288fd43 | |
| Hot n2: close + open in one task | **Mitigated, not fully fixed**: the counter keeps the new sheet open (J20 test) and the on-top check stops a stray `back()`; the new sheet may sit without an entry of its own (a Back then leaves the page). Not reachable by a person (9 ms) | |
| Hot n3: current step by colour only | **Fixed**: 2px ring | |
| Hot n4 = design minor 2: desktop button order | **Fixed**: as #admit/#contactSheet — primary or danger grows on the left, its secondary beside it, a ghost on its own line | EF1 → "desktop: the primary leads its row…" |
| Hot n5: `void kind`, double data-state, force comment | **Fixed** (`Object.values`; `setAttribute` only; `force` removed — cold n-7) | |
| Hot n6: role=status wraps the Lock button | **Fixed** (on the text span) | |
| Hot n7: preselect a sole pad | **Not done**: pre-existing, changes Connect's behaviour for every OTP user; worth its own decision | |
| Design minor 1: filled steps muted | **Fixed** (`is-filled`) | |
| Design minor 3: Forget on its own row | **Fixed** | EF2c → "the pad and Forget share one line" |
| Design minor 4: empty bar / live-looking fields while working | **Fixed** (bar hidden, form inert, fields 60%) | EF3 → "working: no empty bottom bar…" |
| Design minor 5: raw DOMException text | **Fixed** | F18 → "design r3 minor 5" |
| Design minor 6: "Didn't arrive?" after Save | **Fixed** | F21 |
| Design minor 7: keyboard up on short phones | **Fixed for the OTP sheets only** (≤ 560px tall: the sheet covers the inert tab bar and app bar). Not for #contactSheet / #admit: their docking above the tab bar is a pentest fix (P1, tap-through) | not e2e-mutated (the harness has no ≤ 560px-tall check) |
| Design minor 8: weak line inside "On their device" | **Fixed** (moved under the done line) | |
| Design nits 1–8 | **Fixed**: separator outside the nowrap span; Connect's width fixed; "· exported" only in done; one red focus ring; label-row column gap; 12px mono file name < 380px; the import error scrolled into view; `text-wrap: pretty` | nit 3 in the e2e card check |
| Cold mi-2: 256 KiB vs 128 KiB per side | **Fixed**: "Size, each way", options 32/128/512 KiB, cards "… each way" | e2e picker and card checks |
| Cold mi-3 | = cold M2 above | |
| Cold mi-4, mi-5 | Android — see the Android section | |
| Cold mi-6: "Export failed" for an unlock failure | **Fixed**: "Could not unlock this pad: …" | sheets test "said as an unlock failure" |
| Cold mi-7: the receiver's pad carries the maker's label | **Partly**: the received pad's card says "· from your contact"; renaming is not offered (no rename exists anywhere; file format unchanged) | e2e "import done: the card says it came from the contact" |
| Cold n-1: UTC default label | **Fixed** 075896e | mutant (old `toISOString`) → "n-1: the default label is local time" (binds only when TZ ≠ UTC) |
| Cold n-2: "Security options → One-time pad" | **Not done**: the overline would wrap on a phone; the receiver has the maker beside them | |
| Cold n-3: "room id" in the hidden success sentence | **Not done**: a pinned sentence (§ 1.5 keeps them byte-identical); it is `.vh` | |
| Cold n-4: "Keep this open until it has arrived" | **Kept**: keeping the sheet open keeps the held file for "Send the same file again" without a re-export confirm; the native TTL is about the share copy | |
| Cold n-6: `autocomplete` | **Fixed**: `new-password` on the three "choose" fields | |
| Cold n-7: showView force-close | **Fixed**: no force; an unshared Android file asks | S6' re-anchored |
| Pentest R2-4: re-deliveries not re-checked | **Not done** (Info, by design): the text is byte-identical and latched; the link now says "the same file" and each done block says to delete it. Re-checking would mean unlocking (a writer) under the pad lock per tap | |
| Pentest R2-9: protocol skew (M9 needs both phones on this build) | **Release notes** item, not code | |
| Pentest lead: re-push from popstate without activation | On-device check (android/README list) | |

## Round 2 — Android

Commits 84e6bdf (code + tests) and 35ac56d (android/README). Build, `testDebugUnitTest`
(50: PadFilesActivityTest 28, PadFilesTest 10, RelayUrls 11, UnsupportedWebView 1) and
`node client/android-source.test.mjs` (9/9) green. Each mutant hand-run and reverted.

| Finding | Fix | Test | Mutant → result |
| --- | --- | --- | --- |
| Pentest r3 R3-1: `content://0%40<ours>` passed `isForeignDocument` (host splits on `@` before decoding; the resolver strips the user id from the decoded authority) | `uri.authority?.substringAfterLast('@')` — the resolver's own rule (`getAuthorityWithoutUserId`) | `pickerResultsThatAreNotAnotherAppsDocumentAreDropped` + the PoC's forms (`0%40…files`, `10%40…files`, `0%40…androidx-startup`; plain and `0@` already there); `aSaveResultThatIsNotAnotherAppsDocumentIsNotWritten` + two `%40` forms | R3a (host again) → red; R3b (no user-id strip) → red; R3c (strip on the encoded authority) → red |
| R3-1, the other side: work-profile documents must still pass | a user id on a FOREIGN provider stays allowed | `aWorkProfileDocumentFromAnotherAppStillReachesThePage` (`10@` and `10%40` on externalstorage.documents) | R3d (refuse any user id) → red |
| Pentest r3 R3-2: Bold text (`fontWeightAdjustment`) recreated the activity | added to `configChanges` (compileSdk 34 builds) | `aConfigurationChangeKeepsTheActivityAndTheShareInFlight` sets `fontWeightAdjustment = 300` | R3e (flag removed) → red |
| R3-2 lead: overlay / wallpaper-colour change recreates | **Not fixable in the manifest** (`CONFIG_ASSETS_PATHS` is not declarable). README and the manifest comment now list what still reloads the page: process death, a theme/overlay change (Material You wallpaper colours), an app update or force-stop. Robolectric shows the recreation; on the device it is expected, not yet seen — phone checklist (7) | — | — |
| Cold r2 mi-7 / A1: `\d` for `[0-9]` in the name rule survived the JVM tests (OpenJDK `\d` is ASCII, ICU's is Unicode) | The name is no longer a regex: checked character by character against `secure-chat-pad-####-##-##-####.json`, `#` = `'0'..'9'`, exact length. The same meaning on JVM and device, so a Unicode-digit mistake is visible on the JVM | `refusesEveryOtherName` (Arabic-Indic, extended Arabic-Indic, Devanagari, fullwidth digits; one short, one long) | A1 (`Char.isDigit()`, the JVM equivalent of ICU's `\d`) → red; A1b (length check loosened) → red. The literal `\d` mutant no longer exists (no regex) |
| Cold r2 mi-7 / A3: the own-authority refusal was redundant with the PackageManager check in every test | kept, now load-bearing in a test | `ourFileProviderIsRefusedEvenWhenPackageManagerDoesNotKnowIt` (provider removed from `ShadowPackageManager`; plain, `0@`, `0%40` refused) | A3 → red |
| Hot r2 N8: checklist lacked "Back twice during a KDF" and "Back during the Export entry's unlock" | android/README phone checklist (6), plus (7) Bold text / wallpaper change and (8) a work-profile import | — (device) | — |
| Hot r2 N11: README said "Send it again" | now "Didn't arrive? Send the same file again" | — (doc) | — |

## Round 2 — Web client

Reviews: `otp-hot-critic-r2.md`, `otp-cold-critic-r2.md`, `otp-design-critic-r4.md`,
`otp-pentest-r3.md`. Commits b04d61c (otp.js), 58c3860 (app.js / index.html / style.css / unit
tests), 7723093 (e2e), and this section + brief § 14. Checked: `npm test` green; e2e on a
scratch relay: otp-transfer 196/196, all-modes 28/28, no-dead-ends 17/17, room-admission 49/49;
screenshots 37/38 (02 is the old drawer; `git status` clean before and after, no mutant applied).
G-numbers are unit mutants, EG-numbers e2e mutants; each hand-run on its own and reverted.

### Owner decisions (2026-09-27)

| Finding | Decision | What was done |
| --- | --- | --- |
| Cold r2 MA-2: two people on different pads look "Ready", every message fails | **Deferred by the owner** — a pad-tag check at connect is a separate task (protocol) | nothing in this branch |
| Cold r2 MA-4: a weak transfer passphrase is accepted while Android's primary is the share sheet | **Stays warn-never-block**; the warning must be clearly visible at the field and still visible when the file leaves | The transfer field's live line says what is at stake ("Anyone who gets a copy of the file can try to guess it …") in a warn-tinted box; Android file-ready shows a boxed line beside Share / Save ("…Hand it over face to face — not through a messenger or a cloud drive."). The browser downloads under the field's warning; every done block repeats it. G12, G13 (unit), EG4 (e2e: the box) |

### Must

| Finding | Verdict | Bound by (mutant → red check) |
| --- | --- | --- |
| Cold r2 MA-1: the same file twice / the maker's own file says "already been used … generate a fresh pad" | **Fixed** b04d61c + 58c3860: `importPad` refuses a pad still stored here with `PAD_PRESENT` before the used check; the sheet says the pinned "You already have this pad on this device — not importing again …" and selects the pad. A forgotten pad keeps the "used" refusal | G1 → "MA-1: the same file again → PAD_PRESENT" (otp-rollback) and "cold MA-1: … 'you already have this pad'" (sheets); G2 (app does not map the code) → the same sheets check |
| Cold r2 MA-3: Forget in one tap | **Fixed**: `confirm()` naming the pad and saying it cannot be imported again (Android: through `secureShow`). Forget **stays on the picker's line** — design r3 minor 3 put it there (it had pushed Connect off the first screen); the confirm is the guard against the slip | G4 → "MA-3: Forget asks, naming the pad" |
| Hot r2 N1: Import's progress inside the inert steps | **Fixed**: only steps 1–2 are inert while working | EG1 → "hot r2 N1: Import working — the progress has focus and is not inert" |
| Hot r2 N2: `refreshOtpPads` broke "unlocked ⇔ passphrase in the field" | **Fixed**: it ends with `otpSelectChanged`'s rule (also covers cold r2 n-2, the passphrase left after Forget) | G3 → "hot r2 N2: a selection made by the page locks…"; the Forget test asserts the empty field |
| Hot r2 N3: a view switch during the Export entry's unlock | **Fixed**: no sheet if the Live room or the OTP card is gone meanwhile; the entry is dropped | G5 → "N3: … no Export sheet over it" |
| Hot r2 N4 = cold r2 mi-4: `autocomplete="new-password"` | **Reverted to `off`**, as every other passphrase field in the app (round-1's cold n-6 change was wrong: it invites generated and saved secrets) | EG3 → "hot r2 N4: …autocomplete=off" |
| W1 / M19: the passphrase write-back unbound | **Test added**: `#otpPass` edited during the entry's KDF; the pad passphrase is still refused | G6 → "W1: the field holds the passphrase that unlocked the pad" |
| W3 + W4 (hot H2+H4): Back during a FAILED unlock | **Test added** at the first history entry (Android) | G8 (both guards removed) → "W3+W4: Back took the entry — app.js calls no back()" |
| W6 (hot H9): no other sheet during the unlock | **Test added** | G7 → "W6: Import tapped during the unlock opens nothing" |
| Hot m4 (H15): `aria-describedby` of a marked field | **Test added** | G10 → "hot m4: the refused field is described by the refusal" |
| Cold r2 mi-2 = cold M4: the on-top check alone | **Test added** (a traversal whose popstate never reached the page) — no longer argued equivalent | G9 → "cold M4: a close whose entry is no longer on top calls no back()" |
| Design r4 minor 1 = hot r2 N6: "delete on both devices" after share / iOS | **Fixed**: shared / iOS "Once they've imported it, they delete the file."; downloaded / saved unchanged | G11 → "design r4 minor 1: …"; e2e "shared: … they delete the file" |

### Should

| Finding | Verdict | Note |
| --- | --- | --- |
| Design r4 minor 2 (+ nit 6): the danger widest in the desktop confirm | **Fixed**: two choices with no ghost are equal halves, safe first; § 14 corrects § 13's wording (hot r2 N7) | EG2 → "desktop confirm: … equal halves" (124/298) |
| Design r4 minor 3: working progress flush on the sheet's edge | **Fixed** (bottom padding while working) | CSS; not mutated |
| Design r4 minor 4: weak line between the two instructions | **Fixed** (after the delete line). The `<380px` nowrap part **not done**: with the "?" open its explanation needs the wrap | |
| Design r4 nits 1, 2, 4, 5 | **Fixed** (balanced lede; delete line first on Import done; "~1,400 short messages"; selector "from your contact, … each way") | e2e hint check |
| Design r4 nit 3 | = minor 4 | |
| Hot r2 N1-nit: a panel error from before a sheet opened | **Fixed** (cleared on open) | G14 → "hot r2 N1-nit: …" |
| Hot r2 N5 | = W1, W3+W4, W6, m4 above | |
| Hot r2 N7 | § 14 wording | |
| Hot r2 N8, N11 | Android README — done by the Android agent (35ac56d, 32f75a9). PROGRESS.md: not updated here (orchestrator) | |
| Hot r2 N9: fail-closed sentence points at a field behind the modal | **Not done**: reachable only through N2, now fixed | |
| Hot r2 N10: New pad / Import silent during the entry's unlock | **Kept** (the Export button shows the spinner) | |
| Hot r2 N12: round-1 note on n2 too pessimistic | Accepted: in Chromium Back after the close+open case closes the new sheet and stays in the app | |
| Cold r2 mi-3 / pentest lead: re-push without activation | On-device check (android/README (6), "Back twice during a KDF") | |
| Cold r2 mi-5: the maker's label | Unchanged from round 1 ("· from your contact"; the selector now says it too) | |
| Cold r2 mi-6: re-export sentence | **Not done**: both wordings are pinned by the brief's invariants (byte-identical re-export confirm) | |
| Cold r2 mi-8: developer words in import errors | **Not done**: the sentences are otp.js's, pinned by its tests; the sheet's bottom row gives the next step ("Choose another file") | |
| Cold r2 n-1: New pad keeps name / size / drawing | **Fixed** | G15 → "n-1: a reopened New pad starts clean" |
| Cold r2 n-2 | = N2 | |
| Cold r2 n-3, n-5, n-6 | Not done (pinned sentence; scroll position by focus; one file per download is the browser's) | |
| Cold r2 n-4 | Kept (round 1's reason) | |
| Pentest r3 R3-1, R3-2, A-mutants | Android — see "Round 2 — Android" | |
| Pentest r3 I-1 (entries silent during the unlock), I-4 | Accepted as Info | |
