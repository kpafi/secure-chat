# One-time pad transfer — Export and Import sheets (brief)

Owner's ask (2026-09-26, after testing 0.4.0 on the Android APK): generating and sharing a
one-time pad is poorly explained. "Export pad" only says a file was generated; "Import" does
nothing at all on the phone. Export and Import should each open their own window (a sheet) that
makes the steps clear — mostly through the layout (what to tap is obvious), not through more
text. Designed on the Claude Design canvas first, then implemented; reviewed by hot and cold
critics, a design critic and the pentest agent, as for the contact profile
(`profile-brief.md`). Base: `master` at 7a606b4 (v0.4.0). Branch `feat/otp-transfer-sheets`.

## What is broken today (facts, checked in the code)

1. **Android, Import does nothing.** `MainActivity.kt`'s `WebChromeClient` has no
   `onShowFileChooser`, so `els.otpFile.click()` (a hidden `<input type="file">`) is ignored by
   the WebView — no picker, no error.
2. **Android, Export hands out nothing.** `downloadText()` (app.js) clicks an `<a download>` on a
   `blob:` URL. The WebView has no `DownloadListener` and cannot fetch `blob:` URLs natively, so
   the file is silently dropped — yet the pad is already LATCHED as exported (latch first, file
   second, deliberately; see `otpExportFrom`) and the status says "Exported." The user has a
   pad marked exported and no file. (iOS already handles blob downloads → share sheet:
   `ios/SecureChat/ShellNavigationDelegate.swift`.)
3. **Browser**: works, but the flow lives in a `<details>` "Generate / share a pad" under the
   OTP panel, with the TRANSFER passphrase field shared by Export and Import, the PAD
   passphrase field at the top of the panel, and results reported in one status line. The two
   passphrases are easy to confuse; nothing shows which step comes next.
4. **Any device can re-export a pad it imported** (found in design round 1, M9, confirmed in
   code): `otp.exportPad()` writes `recipientRole: 1 - record.role`, so a pad imported with role
   1 is exported with `recipientRole: 0` — the generator's role. A third device importing that
   file shares the generator's keystream with the generator: a two-time pad. Fix (implementation):
   `exportPad` refuses any record with `role !== 0`; `importPad` accepts only `recipientRole === 1`.

## Owner decisions

- **Android export (2026-09-26): both** — the export sheet offers "Share…" (Android share sheet:
  Quick Share, Bluetooth, …) AND "Save to device" (system save dialog, e.g. Downloads). iOS
  keeps its share sheet. The browser downloads the file.
- Export and Import each get their own sheet (the app's `.sheet` component: bottom sheet on a
  phone, centred dialog wider up, over the scrim, like `#admit` / `#contactSheet`).
- **File name (2026-09-26): neutral** — no label in the exported file's name (spec 7).
- **Transfer passphrase == pad passphrase (2026-09-26): blocked** — a refusal, not a warning.

## Security invariants the redesign must keep (non-negotiable)

- Export: latch-before-file order, the per-pad session lock + export lock, the in-flight latch,
  the re-export confirm (the two wordings for `exported` vs `exportedInferred`), "used while it
  was being exported" refusal, record bytes zeroed. Import: pad lock around save, "already on
  this device" refusal, importPad's entropy/rollback/native-floor guards, bytes zeroed.
- Pad passphrase (encrypts the pad on THIS device) and transfer passphrase (protects the file,
  agreed in person, must differ) stay two separate secrets; weak-passphrase warnings stay
  warn-never-block. Neither passphrase is ever put in a file name, URL, log or the DOM beyond
  its `<input type="password">`.
- Existing refusal / warning texts stay byte-identical where tests pin them.
- CSP, textContent-only rendering, one `.primary` per screen/sheet, mono only for key material,
  44px targets, `[hidden]` wins, FLAG_SECURE on every native dialog (`secureShow`).
- Any new Android JS bridge is a new attack surface: it must be captured/frozen at document-start
  like `__SECURE_CHAT_PAD_FLOOR__`, accept only what it needs (a file name + text, size-capped),
  and never read files the user did not pick.

## Design decisions

Canvas: row "One-time pad transfer" on https://claude.ai/artifact/NhVZuUXfC2FsJf93NBn5H2
(14 artboards, listed at the end; round 2 after `otp-design-critic-r1.md`, triage in
`otp-design-fix-round-1.md`). This section is the spec; the canvas illustrates it. Where the
two disagree, this text wins. **§ 9a (the Android bridge as implemented), § 13 and § 14 (fix rounds 1 and 2 of the build; triage in `otp-fix-round-1.md`) and § 12 (design critic
round 2 and the implementation) amend the sections before them and win where they differ.**

### 0. The shape in one paragraph

The OTP panel keeps what a *chat* needs — which pad, its passphrase (or "Unlocked for this
session"), Connect — plus the entry buttons **New pad · Export · Import**. With no pad yet, the
panel is one card whose primary is New pad. Each entry opens its own sheet (the `.sheet`
component: bottom sheet above the tab bar on a phone, a 480px centred dialog wider up, over a
scrim, dismissible like `#contactSheet`). Every sheet has the same anatomy: a head (overline "One-time pad",
title, one hint line with a "?", ×), a pad card when a pad is involved, numbered steps, the
sheet's status, and **all actions in one bottom row** — form → working → done
(`data-state` on the sheet). New pad ends by handing straight into Export. The two
passphrases are told apart by **who knows them**: the transfer passphrase carries a two-person
icon and "you both know it"; the pad passphrase a one-person icon and "only you know it". The
same token appears wherever that passphrase appears.

Why Generate is a sheet too: it is a two-input task with a slow step whose result is useless
until it is exported. As a sheet it runs to one clear finish ("Export to your contact"), and the
panel stays short enough that Connect is on screen.

### 1. The OTP panel (`#otpPanel`, Live room step 2, shown when the OTP card is chosen)

Four states, all drawn except "locked" (which is the unlocked state with the field in place of
the row). Top to bottom:

1. **Empty state** (`otp.listPads()` is empty; artboard OtpPanelEmpty): `#otpEmpty` (new) is a
   card (panel ground, hairline, radius 12, padding 16): pad icon tile, "No pad on this device yet"
   (15/600), "One of you makes it, the other imports it." (13 muted), and **inside the card** the
   entry row with two buttons: `#otpNewOpen` "New pad" as **`.primary`** and `#otpImportOpen`
   "Import" secondary. `#otpPadRow`, `#otpPassRow`, `#otpExportOpen` are `hidden`. The entry row
   is one element in every state; in this state it renders inside the card (CSS:
   `#otpEmpty:not([hidden])` wraps it, or the row moves into `#otpEmpty` in markup and back —
   implementer's choice), and app.js toggles `.primary` on `#otpNewOpen` in `refreshOtpPads()`.
   **Connect** gets `aria-disabled="true"` and the neutral disabled look (no fill, `--muted`
   text, `--border` outline, `cursor: not-allowed`; CSS `#connect[aria-disabled="true"]`) — so
   New pad is the only blue thing. It stays clickable: a tap runs `connect()`, which gives its
   refusal "Choose a one-time pad first — New pad or Import, under Security options." (was
   "…→ Generate / share a pad."; no-dead-ends pins only `/one-time pad/i`). `aria-disabled` is
   set and cleared by the same code that toggles the empty state, and only while the OTP card is
   chosen.
2. **`#otpPadRow`** (new wrapper id): label "One-time pad" (`for=otpSelect`), `#otpSelect`
   (option texts unchanged), `#otpForget` (unchanged).
3. **`#otpPassRow`** (new wrapper id), **directly under the pad** — the passphrase belongs to
   the selected pad. Label row: "Pad passphrase" + the pad token (one-person icon, "only you know
   it"). Then one of:
   - **locked**: `#otpPass` (unchanged id, password, one-person icon inside, placeholder
     "unlocks the selected pad"), with the existing "?" and text;
   - **unlocked** (`otpPanel && otpPanel.padId === otpSelect.value`; artboard OtpPanel):
     `#otpUnlocked` (new, `role="status"`), a 44px row in the field's well: a check in `--ok`,
     "Unlocked for this session" (15px), and `#otpLock` (new, ghost) "Lock". `#otpPass` is
     `hidden` in this state but keeps its value (see 4, "the pad passphrase is carried"). Lock sets
     `otpPanel = null`, `#otpPass.value = ""`, and shows the field; it touches only the panel
     cache, never a live session's pad (`otpRecord`/`otpLockRelease`). Re-evaluated on every
     `change` of `#otpSelect`, after New pad / Import / Export-entry unlock, and on Lock.
4. **Entry row** `div.otp-actions` (new): `#otpNewOpen` "New pad" (plus icon), `#otpExportOpen`
   "Export" (tray-out), `#otpImportOpen` "Import" (tray-in); secondary, a 3-column grid, ≥44px.
   Connect is the one primary of step 2 here.
   - **Received pad selected** (`otp.padMeta(id).role === 1`; artboard OtpPanelImported):
     `#otpExportOpen` is `hidden`, the grid has two columns, and `#otpExportNote` (new, 13 muted,
     info icon) under the row says **"Received pad — only the person who made it can export
     it."** The index role is a hint; the authoritative refusal is in `otp.exportPad` (5).
5. **`#otpStatus`** (unchanged id/class): every sentence `otpStatusMsg()` writes still lands
   here byte-identical (tests read its `textContent`). **Success sentences** ("Generated +
   encrypted…", "Imported + encrypted…", "Exported. …", "Pad forgotten…") are written with
   class `hint vh` — present for tests and assistive tech, not shown, because the done block
   already said it and the unlocked row shows the state. Errors and the live budget line are
   shown. Initial text: empty.
6. **Removed**: `#otpTools` and both `.otp-sub` blocks.

**Export entry** (`#otpExportOpen`):
- nothing selected → `otpStatusMsg("Select a pad to export.", true)` (existing), focus `#otpSelect`;
- index says role 1 → `otpStatusMsg("You received this pad — only the person who made it can
  export it.", true)` (new) — only reachable if the button is visible through a stale index;
- not unlocked and `#otpPass` empty → `otpStatusMsg("Enter this pad's passphrase to unlock it.",
  true)` (existing), focus `#otpPass` — which now sits directly above the button;
- not unlocked, `#otpPass` filled → the button shows "Unlocking…" (`aria-busy`, disabled) while
  `ensureUnlocked(id)` runs (the legacy-adoption `confirm()` can appear, unchanged); error →
  `#otpStatus` "Export failed: " + message, no sheet; success → the unlocked row appears and the
  sheet opens.

### 2. The two passphrase tokens

| | Transfer passphrase | Pad passphrase |
| --- | --- | --- |
| Who knows it | you and your contact | only you |
| Icon (field + tag) | two people (the Users tab glyph) | one person (the Profile tab glyph) |
| Tag (neutral pill, 12px) | "you both know it" | "only you know it" |
| Label | "Transfer passphrase" | "Pad passphrase" |
| Step title | Export 1 "Agree on a transfer passphrase — in person"; Import 1 "The passphrase you agreed on" | New 2 / Import 2 "Your own passphrase for this device" |
| Fields | `#otpXferPass`, `#otpImportXfer` | `#otpPass`, `#otpNewPass`, `#otpImportPass` |

The icon sits inside the field at `left: 12px` (input `padding-left: 40px`, CSS mask on the
wrapper's `::before`, `pointer-events: none`). No colour distinguishes them — shape, word and
step title do. The "On their device" list (5) uses the same two icons.

**The two must differ (owner decision: blocked).** Export: `#otpXferPass === #otpPass` (both
non-empty) → **"Use a different passphrase for the file — this one is your pad passphrase."**,
focus `#otpXferPass`. Import: `#otpImportXfer === #otpImportPass` → **"Use a different passphrase
on this device — the transfer passphrase is known to your contact."**, focus `#otpImportPass`.
Only the live input values are compared; nothing is stored or hashed.

**The pad passphrase is carried** (so the rule works in the main flow): after a successful
generate, `#otpPass.value = #otpNewPass.value`; after a successful import,
`#otpPass.value = #otpImportPass.value` — the same secret with the same meaning, in the panel's
password field, which is where it lived before this redesign. The unlocked row then hides it.

### 3. Sheet anatomy (all three)

Markup at `<body>` level after `#contactSheet`, one shared scrim `#otpScrim`. Each:
`<section class="sheet otp-sheet" role="dialog" aria-modal="true" aria-labelledby="…Title"
tabindex="-1" data-state="form" hidden>`.

- **Head** (`div.otp-head`, the `.contact-head` grid): overline "One-time pad", title `h2`
  (20/650), one hint line with its "?" (`details.why`), and × `…Close` (ghost, 44×44,
  `aria-label="Close"`). **Identical in every state** of the sheet, except that × is `hidden`
  while working.
- **Pad card** (`div.otp-padcard`): 40px tile with the pad icon (a notepad with a perforated top
  edge), the label (15/600, UI font), meta 13 muted "256 KiB per side · you generated" /
  "· imported"; on Export, "· exported before" in `--warn-fg` when the index's `exported` is
  set (a hint at open, before the user agrees a passphrase — the authoritative check stays on the
  first tap), and "· exported" in the done state.
- **Steps** (`ol.otp-steps`, `li.otp-step`): 24px disc (number, `aria-hidden`), title 15/600,
  controls or caption indented 36px, a hairline joining the discs; 20px between steps.
  `is-current` (accent ring, `aria-current="step"`), `is-done` (ok tint + check, `.vh` " —
  done"; the title and caption then report the result and the controls are hidden), idle
  (`--border` ring, title in `--muted` when it has not started). Export and Import mark the
  current step; **New pad does not** (a plain form: two numbered steps, all idle-styled).
- **Status** (`…Status`, `aria-live="polite"`, `tabindex="-1"`): one per sheet, **directly above
  the bottom row**, errors and waits only. An error is the `#admitWarn.err` alert box (err tint,
  `--err-fg`, 15px, radius 8, triangle icon). An error about a field also marks the field (5).
- **Bottom row**: every action of the current state, stacked full width on a phone, pinned to
  the sheet's bottom while it scrolls (the `.contact-actions` sticky pattern,
  `scroll-padding-bottom: 10rem`), so the keyboard never hides the action. One `.primary` at most.
- **Progress** (`…Progress`, `role="status"`, `tabindex="-1"`, only while working): inside the
  current step, an inset well with a 4px track and a 32% accent segment sliding (1.2s linear,
  only under `prefers-reduced-motion: no-preference`; reduced: static 100% at 40%), the working
  sentence (15px) and "Keep this open — a few seconds." (13 muted). No percentage.
- **Weak-passphrase line** (`…Warn`, under `#otpNewPass`, `#otpXferPass`, `#otpImportPass`,
  `aria-describedby` from the field): live on `input` while non-empty and weak, warn colour +
  triangle: "Weak: " + reason + ". Use 12 or more characters, e.g. four random words." Built on
  a new `passphraseWeakness(p)` export in `identity.js` (`passphraseWarning()` rebuilt on it,
  byte-identical). Warn, never block.
- **Weak line in a done block** (`…Weak`): one line, warn colour + triangle, "Weak pad
  passphrase — accepted." / "Weak transfer passphrase — accepted." followed by a "?"
  (`details.why`) holding the full pinned sentence. (`#otpStatus` still gets the full suffix.)
- **Dismissal**: ×, Escape, a click on `#otpScrim` close — except **while working** (× hidden,
  Escape and scrim ignored: the KDF cannot be aborted) and the Android export case in 5. The
  contact sheet's 500 ms guard applies to scrim and bottom-row clicks right after open.
- **Modal**: `applyModal()` gains `otpShown` (tab bar, app head and `#viewLive` inert); Tab wraps
  in the open sheet; `showView()` closes a sheet that is not working.
- **Focus**: open → first field on `(pointer: fine)`, else the sheet itself (so a phone keyboard
  does not cover the steps before they are seen); working → the progress; done → the bottom
  row's primary; error → the field concerned, else the status; close → the entry button that
  opened the chain, or `#otpSelect` if that button is now hidden.
- **Clearing — on close only** (never inside the handlers on success: the dom-stub tests click
  `#otpExport`/`#otpGenerate` repeatedly with the sheet hidden, and an emptied field would turn
  the in-flight-latch tests into trivial refusals): the sheet's inputs (`#otpNewPass`,
  `#otpXferPass`, `#otpImportXfer`, `#otpImportPass`) → `""`, status/warn lines emptied,
  `aria-invalid` removed, `data-state="form"`, `<details>` shut, held file texts (5, 6) dropped,
  `pendingReexportId = null`. `#otpPass` is never cleared by a sheet.

### 4. New pad sheet `#otpNewSheet`

Title "New pad". Hint "Made on this device, then exported to your contact." (no "?" on the head:
the only explanation is about drawing and sits there).

1. **"Name and size"**: `#otpLabel` (label "Name", placeholder **"e.g. Chess club"**, maxlength
   60) and `#otpSize` side by side (grid `1fr 112px`). The option text is the size only ("64
   KiB", "256 KiB", "1 MiB" — the part of `PAD_SIZES[i].label` before " — "); `#otpSizeHint`
   (new, 13 muted, right-aligned, `aria-describedby` from the select) shows the rest, reworded
   "~1,400 short messages each way", updated on `change`.
2. **"Your own passphrase for this device"**: the pad token, `#otpNewPass` (placeholder "a
   passphrase only you know"), `#otpNewPassWarn`.
- **Optional block** (unnumbered, after a hairline): "Draw anything — optional" (15/600, "—
  optional" muted) with the "?" (the existing drawing text); `#otpEntropy` full width, 96px tall
  (120px wider up); `#otpEntropyStatus` kept but **visually hidden** (`.vh`, texts unchanged) —
  the drawn line is the feedback.
- Bottom row: `#otpGenerate` **"Create pad"** `.primary`.

States: empty `#otpNewPass` → "Set a pad passphrase first — it encrypts the pad on this device."
(existing), focus it. Working: "Encrypting the pad on this device…", no ×. Errors (`PAD_BUSY`,
no-Web-Locks, "Generation failed: …"): status alert. **Done** (`#otpNewDoneBlock`): check disc +
"Pad created", pad card, `#otpNewWeak` when weak; bottom row `#otpNewToExport` **"Export to
your contact"** `.primary` + `#otpNewLater` ghost "Later". `#otpStatus` gets the existing
"Generated + encrypted pad "…". Now Export it…" (`vh`). `otpGenerate()` reads `#otpNewPass`,
sets `otpPanel`, selects the pad, carries the passphrase into `#otpPass` (2). "Export to your
contact" swaps sheets without dropping the scrim; focus follows 3.

### 5. Export sheet `#otpExportSheet`

Title "Export to your contact". Hint "Give this file to one person, for one device." + "?" (the
existing hand-over text). Pad card `#otpExportPadCard` (`#otpExportPadLabel`, `#otpExportPadMeta`).

Steps: 1 **"Agree on a transfer passphrase — in person"** (the transfer token, `#otpXferPass`,
placeholder "not your pad passphrase", "?" with the existing transfer text, `#otpXferWarn`);
2 **"Create the file"**; 3 **"Hand it over"** (caption "Share or save it, face to face.").

- **form**: step 1 current. Bottom row: `#otpExport` **"Create transfer file"** `.primary`.
  Refusals: empty field → "Enter a transfer passphrase first (agree on it with your contact in
  person)." (existing); equal to `#otpPass` → the must-differ sentence (2); both focus the field.
- **re-export confirm** (the existing two-click latch; artboard OtpExportAgain): step 1 done
  ("Transfer passphrase set", field hidden, value kept), step 2 current. Status: the pinned
  sentence, byte-identical (`exported` or `exportedInferred` wording). Bottom row, in this order:
  **`#otpExportCancel` (new) "Don't export"** secondary — closes the sheet — then `#otpExport`
  relabelled **"Export again"**, `.danger`, not `.primary`. No primary in this state. Focus → the
  status. Closing disarms the latch.
- **working**: step 1 done ("Transfer passphrase set" / "Say it to them in person — never send
  it with the file."), step 2 current with the progress: "Encrypting the file…", or the existing
  "Waiting for this pad's export in another tab or window to finish…". `#otpExport` disabled
  (pinned) and not shown; × hidden.
- **errors** → form, status alert with the exact sentence: `PAD_BUSY`; "Export failed: " +
  message (incl. "this pad was used while it was being exported — no file was handed out" and the
  new otp.js refusal **"you received this pad — only the person who made it can export it"**);
  "An export is already running — wait for it to finish."; no-Web-Locks.
- **file ready** (latch committed, text in `otpExportFile = { name, text }` until close):
  steps 1–2 done — step 2 "File created" with the file name as its caption (UI font). `#otpStatus`
  gets the existing "Exported. Give the file to your contact in person; they Import it with the
  same TRANSFER passphrase." (+ weak suffix), as `vh`.

| Platform | At "file ready" | Done block title (`#otpExportDoneTitle`) + line (`#otpHanded`) | Disc |
| --- | --- | --- | --- |
| **Android** (`__SECURE_CHAT_FILES__` present) | step 3 current, caption "Quick Share or Bluetooth, face to face — or save it and send it yourself."; bottom row `#otpShare` **"Share…"** `.primary` + `#otpSave` **"Save to device"** secondary | `shared` → **"File shared"** / "Sent to the app you picked." · `saved` → **"File saved to this device"** / "Now give it to them in person — USB stick, Bluetooth or Quick Share." | shared: ok check; saved: neutral download glyph |
| **iOS** (`location.protocol === "secure-chat:"`) | `downloadText()` at once; the shell opens the share sheet | **"Share sheet opened"** / "Pick how to send it — AirDrop, in person." | neutral share glyph |
| **Browser** | `downloadText()` at once | **"File downloaded"** + the file name on its own line (mono: they search Downloads for it) / "Now give it to them in person — USB stick or Bluetooth." | neutral download glyph |

  Android `cancelled` → status line (neutral) "Not shared." / "Not saved.", state unchanged;
  `error` → status alert "Could not share the file." / "Could not save the file." (+ detail).
  Share/Save are disabled while a native request is open.
- **done** (`#otpExportDoneBlock`, the same anatomy as New pad/Import done — disc + title +
  line, pad card, then a hairline and the list; the steps are not shown): **"On their device:
  Import"** (overline) and three rows with 28px icon tiles — two-person icon "the transfer
  passphrase you agreed on", one-person icon "a pad passphrase of their own", file icon "this
  file". `#otpExportWeak` when the transfer passphrase was weak. Bottom row: `#otpExportDone`
  **"Done"** `.primary`, then `#otpSendAgain` (new, ghost text link, 15px; on a phone under
  Done in the bottom row, in the desktop dialog under the done line): Android
  **"Didn't arrive? Send it again"** (returns to the file-ready state: Share/Save again),
  browser **"Download it again"**, iOS **"Share it again"** — the same held text, no new
  export. The full-size "again" buttons exist only in the file-ready state and after
  `cancelled`/`error`.
- **Closing on Android before any `shared`/`saved`** asks `confirm("The file has not been shared
  or saved yet. Close anyway? This pad now counts as exported — exporting it again will ask you
  to confirm.")` (native, `secureShow`). Cancel keeps the sheet.

### 6. Import sheet `#otpImportSheet`

Title "Import a pad". Hint "Import it on one device only." + "?" (the existing one-device text).

Steps: 1 **"The passphrase you agreed on"** (transfer token, `#otpImportXfer`, placeholder "the
one you chose together"); 2 **"Your own passphrase for this device"** (pad token,
`#otpImportPass`, placeholder "a new one only you know", `#otpImportPassWarn`); 3 **"Choose the
file"** (caption "Usually in Downloads."; after a pick: the file's name + " — chosen").
`#otpFile` (unchanged) lives in the sheet. Bottom row: `#otpImport` **"Choose pad file…"**
`.primary`. Choosing starts the import (`change` → `otpFileChosen`, as today); a cancelled
picker changes nothing.

- **form** checks on `#otpImport` click: empty `#otpImportXfer` → "Enter the TRANSFER
  passphrase your contact agreed on, then choose their file." (existing); empty `#otpImportPass`
  → "Also set a pad passphrase — it encrypts the imported pad on this device."; equal → the
  must-differ sentence (2). `file.size > 4 MiB` → "Import failed: not a valid pad file", no read.
- **working**: "Opening the file and encrypting it on this device…" (two 600k KDFs); no ×.
- **the picked file is held** (`otpImportFile`, the text, ≤ 4 MiB, dropped on close or on success)
  so a retry needs no second pick.
- **errors** → form, status alert with the exact sentence:
  - **"Import failed: wrong passphrase or corrupted pad file"** (artboard OtpImportError): step 1
    current; `#otpImportXfer` gets `aria-invalid="true"`, a 2px `--err` border, its icon **swaps
    to the triangle-alert shape**, its label turns `--err-fg`, and `#otpImportXferErr` (new, 13px)
    under it says **"Check this one — it must match your contact's."**
    (`aria-describedby="otpImportXferErr otpImportStatus"`). Shape and words carry it, colour
    only reinforces. Bottom row: `#otpImportRetry` (new) **"Try again"** `.primary` (re-runs the
    import with the held text), then `#otpImport` relabelled **"Choose another file"** (ghost).
    Focus + select `#otpImportXfer`. The marks clear on its next `input`.
  - file-level errors ("not a valid pad file", "unrecognized pad file format", "pad file …", "this
    pad is not random enough…", "this pad has already been used on this device — …", and the new
    otp.js refusal for `recipientRole !== 1`: **"this file was exported by someone who received
    the pad, not by its maker — importing it would reuse key material"**): the held text is
    dropped; bottom row `#otpImport` **"Choose another file"** `.primary`; focus it.
  - "You already have this pad on this device — not importing again (a pad must live on exactly
    one device per side)." (pinned): the pad is selected in the panel as today; same as file-level.
  - `PAD_BUSY`, no-Web-Locks: status alert; "Try again" as for the passphrase error.
- **done** (`#otpImportDoneBlock`): check disc + "Pad imported", pad card ("· imported"), "It is
  selected. Agree on a chat code with your contact, then Connect.", `#otpImportWeak` when weak.
  Bottom row `#otpImportDone` "Done" `.primary`. `#otpStatus` gets the existing "Imported +
  encrypted pad "…". Select it, …" (`vh`). The passphrase is carried into `#otpPass` (2); the
  panel shows the received-pad state (1.4).

### 7. The exported file's name (owner: neutral)

**`secure-chat-pad-YYYY-MM-DD-HHMM.json`**, the exporting device's local date and time of the
export, 24h, zero-padded (e.g. `secure-chat-pad-2026-09-26-1432.json`). Why the time: two pads
exported on one day (one for each of two contacts) would otherwise share a name, and a contact
choosing the wrong file is exactly how one pad reaches two importers; the minute tells them apart
and both people can read it off the sheet (step 2 caption / the done block). Why nothing else:
the label is personal (who talks to whom) and the padId is the key of the pad's storage entries
on the exporting device and inside the file, so a filename carrying it would link a file found in
someone's Downloads to that device's pad. The time links to nothing stored. The name contains no
secret and no user text, so native can validate it exactly (8).

### 8. Ids: kept, moved, new, removed

- **Kept**: `otpPanel`, `otpSelect`, `otpForget`, `otpPass`, `otpStatus`, `otpSize`, `otpLabel`,
  `otpEntropy`, `otpEntropyStatus`, `otpGenerate` (New pad bottom row), `otpXferPass` (Export
  step 1), `otpExport` (Export bottom row; "Create transfer file" / "Export again"), `otpImport`
  (Import bottom row; "Choose pad file…" / "Choose another file"), `otpFile`.
- **Handlers do not depend on a sheet being open** (the dom-stub tests drive them as before);
  they update a sheet only when it is open.
- **Read from a new field**: `otpGenerate()` reads `#otpNewPass`; `otpImportClick()` /
  `otpFileChosen()` read `#otpImportXfer` and `#otpImportPass`. Tests to adapt (not weaken):
  `client/app-otp.test.mjs` — `otpPass` set before an `otpGenerate` click → `otpNewPass`;
  `otpXferPass`/`otpPass` set before an `otpFile` change → `otpImportXfer`/`otpImportPass`
  (lines ~177–210, 262–264, 320–330, 377–379, 800–803, 830 and fixtures); `e2e/all-modes.mjs`
  `exchangePad()` — drop the `#otpTools` line; alice: `#otpNewOpen`, fill
  `#otpNewPass`/`#otpLabel`/`#otpSize`, `#otpGenerate`, wait for
  `#otpNewSheet[data-state="done"]`, `#otpNewToExport`, fill `#otpXferPass`, `#otpExport` (blob
  interception unchanged); bob: `#otpImportOpen`, fill `#otpImportXfer`/`#otpImportPass`,
  `uploadFile` on `#otpFile`; Connect as before (the unlocked row means `#otpPass` needs no
  typing, but setting it stays harmless). New tests: role-1 export refused; `recipientRole 0`
  file refused; the carried passphrase trips the must-differ refusal after New pad → Export.
- **New**: `otpEmpty`, `otpPadRow`, `otpPassRow`, `otpUnlocked`, `otpLock`, `otpNewOpen`,
  `otpExportOpen`, `otpImportOpen`, `otpExportNote`, `otpScrim`; New pad: `otpNewSheet`,
  `otpNewTitle`, `otpNewClose`, `otpNewPass`, `otpNewPassWarn`, `otpSizeHint`, `otpNewStatus`,
  `otpNewProgress`, `otpNewDoneBlock`, `otpNewPadLabel`, `otpNewPadMeta`, `otpNewWeak`,
  `otpNewToExport`, `otpNewLater`; Export: `otpExportSheet`, `otpExportTitle`, `otpExportClose`,
  `otpExportPadCard`, `otpExportPadLabel`, `otpExportPadMeta`, `otpXferWarn`, `otpExportStatus`,
  `otpExportProgress`, `otpExportCancel`, `otpShare`, `otpSave`, `otpExportDoneBlock`,
  `otpExportDoneTitle`, `otpHanded`, `otpExportWeak`, `otpExportDone`, `otpSendAgain`; Import:
  `otpImportSheet`, `otpImportTitle`, `otpImportClose`, `otpImportXfer`, `otpImportXferErr`,
  `otpImportPass`, `otpImportPassWarn`, `otpImportStatus`, `otpImportProgress`, `otpImportRetry`,
  `otpImportDoneBlock`, `otpImportPadLabel`, `otpImportPadMeta`, `otpImportWeak`, `otpImportDone`.
- **Removed**: `otpTools` (and `.otp-sub`); round 1's `otpDownloadAgain` (now `otpSendAgain`).
- **Status routing**: `otpStatusMsg(text, isErr, { quiet })` writes `#otpStatus` exactly as now
  (`quiet` → class `hint vh`, used for the four success sentences) and, when a sheet is open,
  that sheet's `…Status` for errors and waits.

### 9. Platforms and the Android native contract (from the UI's side)

- **Browser**: `downloadText()` and `<input type=file>`, unchanged.
- **iOS**: unchanged native side (blob download → share sheet; the document picker for the file
  input — to confirm on a device). The page gets no result, hence "Share sheet opened".
- **Android export**: a new bridge published like the pad floor — an `@JavascriptInterface`
  object captured **at document-start**, methods `.bind()`-captured, republished as
  `window.__SECURE_CHAT_FILES__ = Object.freeze({ share, save })` (non-writable,
  non-configurable); absent → the browser path.
  - (Superseded by § 9a: an id now, the result later through a callback.)
    `share(name, text)` / `save(name, text)` return a `Promise` settling to `"shared"` /
    `"saved"`, `"cancelled"` or `{ error: "<short reason>" }`; never rejects, never hangs past
    the activity result. The way back into the page must not be a writable page-defined global
    (a frozen resolver from the same document-start script, or a `WebMessagePort`).
  - `"shared"` = the chooser returned a chosen target (delivery cannot be confirmed — hence
    "File shared", not "handed over"). `save` uses `ACTION_CREATE_DOCUMENT`
    (`application/json`, suggested `name`); `"saved"` only after the bytes are written and closed.
  - Native validates: `name` must match `^secure-chat-pad-\d{4}-\d{2}-\d{2}-\d{4}\.json$`
    exactly (7) — anything else → `{ error: "bad name" }`; `text` ≤ 4 MiB and parses as the
    pad-file envelope (`fmt: "secure-chat-otp-pad"`); one request at a time (`{ error: "busy" }`);
    app origin only. Share writes one cache file via `FileProvider` (read grant to the chosen
    target only), deleted on the result and at the next start. No other file access; no
    passphrase crosses the bridge.
- **Android import**: `onShowFileChooser` → `ACTION_OPEN_DOCUMENT` (`CATEGORY_OPENABLE`, `*/*`
  with `EXTRA_MIME_TYPES` json/text/octet-stream — Quick Share often delivers
  `application/octet-stream`), single file; `onReceiveValue([uri])` or `null` on cancel; no
  persisted URI permission.
- Share/save/pick screens are other apps' activities (FLAG_SECURE does not cover them; they show
  only the neutral file name). The close confirm (5) is ours and goes through `secureShow`.

### 10. Tokens and measurements (for style.css)

Sheet as `.sheet`; desktop 480px centred, `max-height: min(704px, 100vh - 96px)`. Steps: disc
24, disc→text 12, step gap 20, indent 36, joining line `--border-soft`. Pad card: list card
(radius 12, hairline), tile 40 radius 8 on `--panel-2`. Token: pill 20px high, 12px, `--muted`
on a `rgba(139,148,158,.3)` outline; field icon 16px at left 12. Unlocked row: 44px, `--inset`
well, hairline. Progress bar 4px radius 2. Done disc 40px: ok-tinted with check (created /
imported / shared), neutral `--panel-2` with a glyph (saved / downloaded / share sheet opened).
Invalid field: 2px `--err` border. Icons (stroke 1.5, round): plus, tray-out, tray-in, one
person, two people, file, share, download, check, triangle-alert, info, pad (notepad with a
perforated top). Mono only for the browser's downloaded file name.

### 11. Proof the implementation owes

npm test; pytest once alone; e2e with `all-modes` adapted (8); a new `e2e/otp-transfer.mjs`:
each sheet by pointer and keyboard; × / Escape / scrim close and return focus; Tab wraps; inert
rest; working not dismissible (× hidden, Escape and scrim ignored during a held KDF); exactly one
`.primary` in every state (zero in re-export, and "Don't export" precedes "Export again"); empty
panel: New pad primary, Connect `aria-disabled` and its refusal on tap; unlocked row after New
pad and after Import, Lock restores the field; received pad: no Export, the note, and a forced
export refused with the sentence; must-differ refused in both sheets incl. New pad → Export;
wrong transfer passphrase marks the field (icon + line + `aria-invalid`) and "Try again"
succeeds without a re-pick after fixing it; the file name matches the pattern; closing clears the
inputs. `android-source.test.mjs`: the bridge's document-start capture/freeze, the exact name
pattern, the size cap, `onShowFileChooser`. `screenshots.mjs`: the canvas states at 390×844 and
1280×800. Pentest the diff (bridge, held file texts, dismissal, the role fix).

### 9a. Android bridge contract (as implemented — supersedes the Promise shape in § 9)

The page cannot receive a Promise across `@JavascriptInterface`, so the round trip is an id and a
callback:

- `window.__SECURE_CHAT_FILES__` is captured at document-start by the shell and republished as a
  **frozen** object on a **non-writable, non-configurable** property. app.js reads it ONCE, at
  module start, and accepts it only in exactly that shape (`FILES_BRIDGE`); anything else is "no
  bridge" (on Android the shell then refuses to run the app at all).
- `share(name, text)` / `save(name, text)` are synchronous and return at once: a request id (16
  lowercase hex), `"busy"` (a request is open) or `"invalid"` (name or text refused). The page
  passes `exportPad()`'s string unmodified (the shell checks the canonical envelope — `fmt`, `v`,
  `kdf{salt,iters}`, `iv`, `ct` in that order — and ≤ 4 MiB) and the neutral name
  (`^secure-chat-pad-\d{4}-\d{2}-\d{2}-\d{4}\.json$`, § 7).
- The outcome arrives later as `window.__SECURE_CHAT_FILES_RESULT__(id, outcome)`, outcome one of
  `"shared"`, `"saved"`, `"cancelled"`, `"error"`. app.js defines this callback at module start
  with `Object.defineProperty` (non-writable, non-configurable), so no other script can take the
  name first. It is the page's own code receiving a result about its own request; no secret flows
  back. It acts only on the id of the request in flight, and only on the success that request can
  have (`share` → `"shared"`, `save` → `"saved"`; anything else is an error line).
- `"shared"` means the chooser reported a target; `"cancelled"` means none was reported (Quick
  Share on Android 14 may not report one), so it reads softly — "Not shared." / "Not saved.", with
  Share and Save available again — and re-arms nothing: the pad stays latched as exported.

### 12. Amendments from design critic round 2 and the implementation (binding; they supersede the text above where the two differ)

Critic round 2: `otp-design-critic-r2.md`. Pentest lead F7: `otp-pentest-android-r1.md`.

- **Empty panel (r2 minor 1):** New pad and Import have equal weight — both secondary. The empty
  state has no `.primary` at all; Connect is `aria-disabled` with a `--border-soft` outline (r2
  nit 6) and still gives its refusal on a tap.
- **Emphasis after "Later" (r2 minor 6):** while the selected pad is this device's own (`role 0`)
  and the index says it was never exported, `#otpExportOpen` is the `.primary` and Connect is not
  (Connect stays enabled). Once exported, Connect is the primary again.
- **Received-pad note (r2 nit 7):** "Received pad — only its maker can export it."
- **Entry row (r2 minor 9):** labels never wrap; below 380px the leading icons are hidden. The
  Export entry keeps its label while it unlocks: `aria-busy="true"`, disabled, the icon becomes a
  spinner (no "Unlocking…" text).
- **Carried passphrase (r2 minor 5):** a `change` of `#otpSelect` to a pad other than
  `otpPanel.padId` empties `#otpPass`.
- **Back (r2 N-M2):** Android system back and browser back act as ×. Opening a sheet pushes one
  history entry — synchronously inside the opening click (Chromium's Back skips entries added
  without a user gesture; the Export entry pushes before its unlock and drops the entry again if
  the unlock fails). New pad → Export reuses the entry. On `popstate` while a sheet is open:
  working → push again, nothing else; Android file-ready before `shared`/`saved` → push again and
  ask the close confirm (§ 5), closing only on OK; otherwise close by the × rules. Every other close
  (×, Escape, scrim, Done, Later, Don't export, a view switch) calls `history.back()` once and
  ignores the `popstate` that causes.
- **Which errors mark a field (r2 minor 7):** the wrong-transfer-passphrase import error gets the
  full mark (triangle icon, 2px `--err` border, `aria-invalid`, the "Check this one" line, label
  in `--err-fg`). The two must-differ refusals mark the field they focus (icon, border,
  `aria-invalid`, label colour) without a line — the status sentence names it. Empty-field refusals
  only focus. A mark goes on the field's next `input`.
- **The current step (r2 minor 8):** Import — the first step whose input is empty, else step 3; a
  wrong transfer passphrase makes step 1 current again. Export — step 1 in the form (its field is
  the sheet's only input; steps 2–3 are what the bottom-row action does), step 2 while working or
  confirming, step 3 in Android file-ready. Titles of upcoming steps are `--muted` in Export and
  Import. New pad: idle discs, titles always `--fg`.
- **Export copy (r2 N-M1, minors 2–4, nits 5 and 8):** step 3 in the form: "Give it to them face to
  face."; Android file-ready: "Quick Share or Bluetooth, face to face. Or save it and copy it to a
  USB stick." Done titles and lines: `shared` "File shared" / "Keep this open until it has
  arrived."; `saved` "File saved" + the file name on its own line (UI font) + "Now give it to them
  in person — USB stick, Bluetooth or Quick Share."; iOS "Share sheet opened" / "AirDrop it to
  them, face to face. Keep this open until it has arrived."; browser unchanged ("File downloaded",
  the name in mono, "Now give it to them in person — USB stick or Bluetooth."). Step 1's done
  caption is gone; the warning moved into the done list that every platform shows: its first row
  is "the transfer passphrase — tell them, never send it", under the overline "On their device:
  One-time pad → Import". § 7's "both can read it off the sheet" now holds for the browser and for
  Android file-ready and `saved`.
- **Import placeholder (r2 nit 9):** `#otpImportPass` — "a new one — not the one above".
- **Desktop bottom row (r2 nit 3; changed in § 13):** the "again" link stays in the bottom row at
  every width.
- **Pad card meta:** the size is per side, as the pad selector says ("128 KiB per side" for the
  256 KiB pad; the canvas's "256 KiB per side" was the total). "· exported before" never breaks
  inside itself (r2 nit 1).
- **The working state is bounded:** a pad file's KDF cost is fixed — `importPad` accepts only
  `kdf.iters === 600000` (what every export has written) and refuses anything else before any KDF
  with "this pad file asks for unsupported encryption settings" (pentest F7 lead; a file-level
  error in the sheet). A busy pad is refused at once (the pad lock is taken without waiting) and
  the sheet returns to its form (§ 13). What is not bounded by the page: a hung IndexedDB write
  inside a save; a reload (or, on Android, closing the app) is the way out, as for a live session.
- **Import file picker:** `accept="application/json,.json,.txt,application/octet-stream,text/plain"`
  (Quick Share delivers octet-stream); `importPad` decides what the file is.
- **Held texts only while a sheet is open:** a handler driven with no sheet open (the unit tests)
  hands a browser file out at once and holds nothing.

### 13. Fix round 1 of the build (binding; wins over §§ 1–12 where they differ)

Triage: `otp-fix-round-1.md` (hot critic r1, cold critic r1, design critic r3, pentest r2).

- **Every exit of Export leaves "working"** (hot B1, pentest R2-1): PAD_BUSY, no Web Locks and
  every error go back to the form with the sentence in the sheet's status and × shown. The 30 s
  bound on the export-lock wait is **removed**: that wait is only entered while holding the pad's
  session lock, which every exporter takes first without waiting, so no current client can hold
  the export lock then (the bound guarded a state only a test could build).
- **Back during the Export entry's unlock cancels it** (hot M1, cold MA-1, pentest R2-2): no sheet
  opens afterwards; the pad stays unlocked. No other sheet opens while that unlock runs. A close
  drops the history entry only while it is still the one on top (`history.state.otpSheet`), so a
  close never calls `history.back()` past the app's own entry and the ignore counter cannot stick.
- **Unlocked ⇔ its passphrase is in `#otpPass`** (pentest R2-3, cold MA-2, hot m5): choosing
  another pad locks the panel's pad and empties the field; an unlock caches only the pad on
  screen and leaves in the field exactly the passphrase that unlocked it. Export with an empty
  `#otpPass` fails closed ("Enter this pad's passphrase to unlock it.") instead of skipping the
  must-differ comparison. Nothing is stored or hashed.
- **Panel status while a sheet is up** (design R3-M1, hot m2): `#otpStatus` still receives every
  sentence byte-identical, but as `.vh` while a sheet is open, and a sentence written while a
  sheet was open is removed from the panel when the sheet closes. The "Choose a one-time pad
  first …" refusal is removed once a pad exists (cold mi-1).
- **Delete the file** (cold MA-3): Export done adds "Once they've imported it, delete the file on
  both devices." (the coordinator's "both phones", said as "devices" because the maker may be on a
  computer); Import done adds "Delete the pad file now.". The again link is 13px, muted, and says
  it is the same file: "Download the same file again" / "Share the same file again" (iOS) /
  Android "Didn't arrive? Send the same file again" after `shared`, "Share or save the same file
  again" after `saved` (design r3 minor 6).
- **Sizes** (cold mi-2): the picker's label is "Size, each way" and its options are what each
  side can send (32 / 128 / 512 KiB); every pad card says "128 KiB each way". A received pad's
  card says "· from your contact" (cold mi-7; the label is the maker's, the file format is
  unchanged). An unnamed pad is named by local time (cold n-1).
- **Unlock failure at the Export entry:** "Could not unlock this pad: …" (cold mi-6; nothing was
  exported), focus to `#otpPass` (hot m3).
- **Import:** a file that cannot be read says "Import failed: could not read that file — choose it
  again." (design r3 minor 5); a later file-level error removes the transfer passphrase's mark
  (hot m1); filled steps keep `--fg` titles (`is-filled`, design r3 minor 1).
- **Desktop bottom row** (design r3 minor 2, hot n4): as in the app's other dialogs — the primary
  (or the danger) grows on the left, its one secondary beside it, a ghost on its own line below.
- **Layout:** the pad select and Forget share one line (design r3 minor 3); while working the
  bottom bar is not drawn and the form is inert (minor 4); on a phone viewport under 560px tall
  an OTP sheet may cover the tab bar and app bar it made inert (minor 7; not the contact or
  admission sheet); the weak-transfer line sits under the done line, not in "On their device"
  (minor 8); "· exported" only in done (nit 3); Connect keeps its width when the emphasis moves
  (nit 2); the current step's ring is 2px (hot n3); `text-wrap: pretty` on captions and ledes.
- **Assistive tech** (hot m4): an empty sheet status stays in the accessibility tree; a field
  marked by a refusal is described by its sheet's status too. `role="status"` is on the
  "Unlocked for this session" text only (hot n6). The three "choose a passphrase" fields are
  `autocomplete="new-password"` (cold n-6).

### 14. Fix round 2 of the build (binding; wins over §§ 1–13 where they differ)

Triage: `otp-fix-round-1.md`, "Round 2" sections (hot r2, cold r2, design r4, pentest r3).
Owner decisions 2026-09-27: cold r2 MA-2 (different pads on the two phones → a pad-tag check at
connect) is **deferred** to a separate task; a weak transfer passphrase stays
**warn-never-block**, but visible where it matters (below).

- **Import of a pad still stored here** (the same file twice, the maker's own export):
  `importPad` refuses it as `PAD_PRESENT` before the used check; the sheet says "You already
  have this pad on this device — not importing again (a pad must live on exactly one device per
  side)." and selects it. A forgotten pad keeps the "already been used" refusal.
- **Forget asks**, naming the pad: "Delete the pad "…" from this device? It cannot be imported
  again — you would need to make a new pad and hand it over in person." It stays on the picker's
  line.
- **Unlocked ⇔ passphrase in `#otpPass`** holds for every selection the page makes too
  (`refreshOtpPads`: the already-have path, Forget).
- **The Export entry's unlock** opens no sheet when the Live room or the OTP card is gone by
  then (as for Back and a pad switch).
- **Import working:** only steps 1–2 are inert; the progress keeps focus and is announced.
- **`autocomplete="off"`** on every pad and transfer passphrase field (§ 13's `new-password` is
  withdrawn: it invites generated and saved passphrases).
- **Weak transfer passphrase:** the field's line reads "Weak: <reason>. Anyone who gets a copy of
  the file can try to guess it — use 12 or more characters, e.g. four random words." in a
  warn-tinted box; Android file-ready adds, beside Share / Save, "Weak transfer passphrase:
  whoever gets a copy of this file can try to guess it. Hand it over face to face — not through a
  messenger or a cloud drive."
- **Delete line per result:** shared and iOS "Once they've imported it, they delete the file.";
  downloaded and saved "Once they've imported it, delete the file on both devices." The weak
  line follows it. Import done: "Delete the pad file now." comes before the Connect line.
- **Desktop bottom row** (corrects § 13): the primary grows on the left with its secondary
  beside it and a ghost on its own line below; when a state has two choices and no ghost (the
  re-export confirm, Share / Save) they are equal halves, the safe one first.
- **Smaller:** a panel error from before a sheet opened is cleared when it opens; New pad
  forgets its name, size and drawing on close; the size hint is "~1,400 short messages" (the
  label says "each way"); the pad list reads "Chess club (from your contact, 128 KiB each way)";
  the working sheet keeps its bottom padding; the Export lede is balanced.

### Canvas artboards (row "One-time pad transfer")

OtpPanelEmpty · OtpPanel (unlocked) · OtpPanelImported · OtpNew · OtpNewDone · OtpExport ·
OtpExportWorking · OtpExportReady (Android) · OtpExportDone (Android, shared) · OtpExportAgain ·
OtpImport · OtpImportError · OtpImportDone · OtpExportDesktop (browser, downloaded, 1280×800).
Not drawn, specified above: the locked panel field, New pad / Import working, Android "saved",
iOS done, the Android cancel/error lines, file-level import errors.

### Considered and not done

- **One sheet for New pad + Export** (five steps): too long for a phone, and Export is needed on
  its own for a pad made earlier. Two sheets with a hand-off.
- **Auto-opening the Android share sheet** after the KDF (as iOS does): leaves no room for the
  owner's "Save to device" choice; the two buttons cost one tap.
- **A confirm field for new passphrases**: a typo makes a pad unusable, never unsafe; a pad is
  cheap to make again.
- **A dashed or tinted transfer field** (critic's optional B1 idea): a dashed outline reads as a
  drop zone, and a tint would be colour-only; icon, word and step title carry the difference.
- **Hiding Connect in the empty state**: `e2e/no-dead-ends.mjs` clicks `#connect` there and
  expects an explanation; `aria-disabled` + neutral look + the refusal on tap gives both.
