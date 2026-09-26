# OTP transfer sheets — cold critic, round 1

Reviewer: cold critic (no brief, no prior reviews, no PROGRESS read).
Scope: `git diff 7a606b4..HEAD` (web client sheets, `otp.js` M9 / iteration
checks, Android pad-file bridge), walked in headless Chromium against a
scratch relay on 127.0.0.1:8102 at 390×844 and 1280×800 — two browser
contexts: maker (New pad → Export) and receiver (Import → Connect → admit →
message both ways; it works end to end).
Screenshots and scripts: the reviewer's scratch dir (`cold/m-*.png`,
`cold/d-*.png`, `cold/p-*.png`, `walk.mjs`, `probe.mjs`, `mutants.py`).

Counts: **0 blocker, 3 major, 7 minor, 7 nit.**

---

## Major

### MA-1 Back pressed during the Export unlock: closing the sheet later navigates OUT of the app

*Where:* `client/app.js` `otpExportOpenClick` (pushes the history entry, then
awaits `ensureUnlocked`), `otpOnPopState` (`if (!otpUi.sheet) return;` runs
before `otpHistEntry = false`), `otpHistDrop`.

*What happens (reproduced, `probe.mjs back`, desktop):* pad locked, pad
passphrase typed, tap **Export** — the entry is pushed and the 600k unlock
runs (~1 s, longer on a phone). The user presses Back while the button
spins (a natural reaction to "nothing happened"). `popstate` arrives with no
sheet open, so it returns early and `otpHistEntry` stays `true` although the
entry is gone. The unlock finishes and the sheet opens with `pushed: true`
(no entry). Closing it with × then calls `history.back()` for an entry that
does not exist: the browser leaves the app (in the probe: `about:blank`; in
real life the previous site or the new-tab page — any typed state is lost).
In the Android shell `history.back()` at index 0 is a no-op, but
`otpHistIgnore` stays at 1, so the next real Back on a sheet is swallowed
and the one after that finishes the activity.

*Fix:* in `otpOnPopState` clear `otpHistEntry` (and treat the event as
"entry consumed") before the `!otpUi.sheet` early return; in
`otpExportOpenClick`, after the await, open the sheet with `pushed: true`
only if `otpHistEntry` is still true (otherwise open it without an entry, or
don't open it — Back meant "never mind"). A unit test: push, `popstate()`
during the unlock, then × must not call `history.back()`.

### MA-2 The "transfer passphrase must differ" refusal is bypassed by switching pads

*Where:* `otpSelectChanged` empties `#otpPass` when the selected pad is not
the unlocked one, but keeps `otpPanel`; `otpExport` compares the transfer
passphrase only with the live `#otpPass` value (`els.otpPass.value && …`).

*What happens (reproduced, `probe.mjs bypass`):* two pads made here; unlock
pad *one* (types its passphrase), switch the select to *two* (field emptied),
switch back to *one*: the panel says "Unlocked for this session", `#otpPass`
is `""`. Export → transfer passphrase = pad *one*'s passphrase → the file is
created and downloaded, no refusal. The owner decision ("refused, not
warned") holds only while the field happens to hold the value. Same after
any path that unlocks without leaving the value in the field.

*Fix:* when the selection moves off the unlocked pad, drop the panel cache
too (`otpPanel = null`, i.e. lock), so coming back requires retyping and the
field holds the value again; or refuse to open Export while `#otpPass` is
empty even if unlocked (ask for the passphrase once more). Add the switch-away
/ switch-back case to `app-otp-sheets.test.mjs`.

### MA-3 Nothing ever tells either side to delete the pad file — and "Download it again" makes more copies

*Where:* Export done block (`otpHanded`, "On their device…" list), Import
done block, README OTP section.

*What happens:* the exported file sits in the maker's Downloads (browser) or
wherever it was saved, and in the receiver's Downloads after the transfer.
It is the whole pad (both directions) under the transfer passphrase alone,
which is warn-never-block — "hunter2"-class passphrases are accepted with a
yellow line. Whoever later copies either Downloads folder can brute-force it
offline and read every past and future message of that pad. The design
already fights cloud copies (EXTRA_LOCAL_ONLY, "never send it"), but the
local copy the flow itself creates is never mentioned; the done state even
offers "Download it again" / "Send it again", which a newcomer reads as
harmless. For a mode whose whole promise is "information-theoretic", this is
the weakest link and the UI is silent about it.

*Fix:* one line in both done blocks — maker: "Once they have imported it,
delete the file from this device (and the USB stick)"; receiver: "Imported —
now delete the file you received." Consider making "Download it again" a
ghost link with "only if the first copy never arrived". README: one caveat
line.

---

## Minor

### mi-1 A stale red refusal stays under Connect after the pad exists
`#roomHint` "Choose a one-time pad first — New pad or Import, under Security
options." (from tapping Connect with no pad) survives New pad, Export and
Import; it sits, sticky and red, directly under Connect while the panel says
"Unlocked for this session" (`d-14`, `p-stale.png`; in the 390 full-page shot
it overlaps Connect). The alg-change handler clears it; the pad-appears
paths do not. *Fix:* clear an `.err` `#roomHint` in `refreshOtpPanel` when
the panel stops being empty (or when a sheet opens).

### mi-2 Size picker says "256 KiB", everything after says "128 KiB per side"
New pad's select shows total size; the done card, the select option in the
panel and the Export card all show per-side size. A newcomer who chose
256 KiB sees 128 KiB and wonders what was lost. *Fix:* label the options the
way the rest reads ("128 KiB each way") or say "256 KiB (128 KiB each way)".

### mi-3 A pad switch during the Export unlock is untested (mutant M2 survives)
`ok = els.otpSelect.value === id` has no test: replacing it with `true` keeps
every unit test green. Without it the sheet opens with the card of the pad
that was chosen meanwhile while the unlock was for another. Add the case.

### mi-4 Android: a late "target chosen" broadcast deletes the file the target is about to read
`onShareReturned` answers "cancelled" after `SHARE_GRACE_MS` (1.5 s) and
`deliverPadFileResult` then revokes and deletes the share directory. The code
itself notes Android 14 may hold the broadcast until the app is in front; if
that happens, the user picked Bluetooth / Quick Share, the target holds a
grant to a file that is now gone, and the sheet says "Not shared." Likewise
"Didn't arrive? Send it again" supersedes (revokes + deletes) a share a
Bluetooth service may still be sending. *Fix:* on "cancelled", keep the file
for the TTL like "shared" when `chosen` is unknown (it is only ever deleted
by the timer or by the next share); at least verify on-device.

### mi-5 Android: an activity recreation mid-share/save loses the file after the latch
`configChanges` covers orientation/screenSize/keyboardHidden only; a dark-mode
switch, locale/font change, split-screen or a fold while the share sheet or
save dialog is open recreates the activity and reloads the page. The pad is
latched as exported, the held text is gone, the save dialog may have
created an empty document, and the next export needs the scary "Export
again" confirm. *Fix:* add `uiMode|screenLayout|smallestScreenSize|density|
locale|fontScale` to `configChanges` (the WebView is not layout-inflated per
config), or document the recovery.

### mi-6 "Export failed: wrong pad passphrase…" before any export began
A wrong passphrase at the panel's Export entry (the unlock step) is reported
as "Export failed: …". It is an unlock failure; the user did not export
anything. *Fix:* "Could not unlock this pad: …".

### mi-7 The receiver's pad carries the maker's label
Maker names the pad after the contact ("Bob"); on Bob's device the pad is
also called "Bob" and cannot be renamed. *Fix:* on import, prefill a label
the receiver can change (or show "from <label>").

---

## Nits

- n-1 Default label for an unnamed pad is UTC ("pad 2026-09-26 23:25") while
  the file name is local time ("…-2026-09-27-0120.json") — pick one.
- n-2 Export done "On their device: One-time pad → Import" — the receiver
  must first open *Security options → One-time pad*; say so.
- n-3 Import done says "chat code", the (hidden) status sentence still says
  "room id" — one word.
- n-4 Shared: "Keep this open until it has arrived" — the file's life is the
  native 10-minute TTL, not the sheet; the sentence asks for something that
  does nothing.
- n-5 `e2e/otp-transfer.mjs:456` writes a failure screenshot to another
  session's hard-coded scratchpad path.
- n-6 `type=password autocomplete="off"` is ignored by Chromium's save-password
  prompt; `autocomplete="new-password"` on the three "choose a passphrase"
  fields at least keeps them out of autofill suggestions for the unlock field.
- n-7 (latent) `showView` force-closes a sheet with `force: true`, which skips
  the Android "not shared or saved yet" confirm and discards the only copy of
  a latched export. Today every `showView` caller is a tap on something the
  open sheet makes inert (tab bar, contact sheet) or runs at startup, so it
  is unreachable; a future caller (a notification, a deep link) would hit it.
  Don't force-close an export sheet in state `ready`.

---

## UX walk notes (newcomer, both viewports)

1. Choosing *One-time pad* shows a clear empty card ("No pad on this device
   yet — One of you makes it, the other imports it") with New pad / Import of
   equal weight. Good. Tapping the aria-disabled Connect gives a readable
   refusal (but see mi-1: it never goes away).
2. New pad (390): fits one screen, bottom bar pinned; the empty dashed
   "Draw anything — optional" box is the only puzzling element (the `?`
   explains). Weak passphrase: live yellow line, accepted, repeated in the
   done block. The working state was too quick to see on desktop.
3. "256 KiB" → "128 KiB per side" (mi-2) was my one real moment of doubt.
4. Export: the pad card, three numbered steps and a single primary read
   well. The must-differ refusal is clear and marks the field. Done:
   "File downloaded" + neutral file name + "On their device" checklist —
   the best screen of the flow. Missing: "delete it afterwards" (MA-3).
5. Import: step order (transfer passphrase, own passphrase, file) is right;
   the wrong-passphrase state marks the field, selects its text, keeps the
   file ("pad.json — chosen") and offers "Try again" — no second pick. Very
   good. Placeholder "a new one — not the one above" is clear.
6. After Import the panel says "Received pad — only its maker can export it"
   and Connect is the primary. Connect → maker admits (the admit sheet's
   no-identity text is appropriate) → messages flow.
7. Desktop: sheets are centred dialogs, the rest dimmed; nothing overflowed.
8. Re-export: the confirm state ("Don't export" / red "Export again") is
   unmistakable. The body sentence says "Click Export again" — matches the
   button. Fine.

---

## Tests

`app-otp-sheets.test.mjs` is good at the decisions it names (must-differ in
both sheets, request-id matching, busy/invalid, close-confirm, held file for
Try again, 4 MiB, history push counts), and `e2e/otp-transfer.mjs` covers
geometry and the real-browser flow. Gaps: the history bookkeeping is only
tested on happy paths (MA-1 would be caught by one extra `popstate()`), the
must-differ rule only with the value present (MA-2), and several guards are
only covered by e2e or not at all (table).

### Hand-run mutants (unit suites: app-otp-sheets, app-otp, otp-rollback, android-source)

Baseline: all four unit suites green; `e2e/otp-transfer.mjs` against the
scratch relay: 167/167. Surviving unit mutants were then run against the e2e.

| # | Mutant | Unit suites | e2e/otp-transfer | Verdict |
|---|---|---|---|---|
| M1 | `resetOtpSheet` no longer clears `pendingReexportId` (closing a re-export confirm leaves the next click armed — a pad exported twice without a second warning) | all green | **killed** ("closing disarmed the latch") | covered only by e2e; add it to `app-otp-sheets` |
| M2 | Export entry: `ok = els.otpSelect.value === id` → `ok = true` | all green | green | **survives** (mi-3) |
| M3 | `importPad` accepts `recipientRole: 0` | otp-rollback **killed** | — | good |
| M4 | `FILES_BRIDGE` capture accepts a writable / configurable global | all green | green | **survives** — no negative test that a non-frozen / writable `__SECURE_CHAT_FILES__` means "no bridge" |
| M5 | a file-level import error keeps the held file ("Try again" offered for a file that can never import) | all green | green | **survives** |
| M6 | `OTP_GUARD_MS` 500 → 0 (double-tap guard off) | all green | green | **survives** — the e2e waits 600 ms before every bottom-row tap and never taps early |
| M7 | `showView` no longer closes an open sheet | all green | green | survives (the path is unreachable today, n-7) |
| M8 | `importPad` accepts any iteration count | otp-rollback **killed** | — | good |
| M9 | `exportPad` exports a received pad (role 1) | app-otp-sheets + otp-rollback **killed** | — | good |
| M10 | New pad's `otpGenerating` re-entry guard removed | all green | green | survives (the hidden button is the real guard; belt-and-braces untested) |

The crypto-side refusals (M3, M8, M9) are pinned hard; the sheet state
machine's guards (re-export latch reset, pad switch mid-unlock, double-tap
guard, bridge-shape check) are pinned weakly or only by the e2e.
Android (`PadFilesTest`, `PadFilesActivityTest`) was read, not run (no
Gradle run in this review); its test list covers the bridge slot, envelope,
grace, supersede, TTL and foreign-document rules, but not activity
recreation (mi-5).

All mutants restored (`git checkout --` per file; `git status` clean except
this report).
