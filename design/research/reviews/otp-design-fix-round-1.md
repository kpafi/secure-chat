# OTP transfer sheets — design fix round 1 (triage of `otp-design-critic-r1.md`)

Canvas row "One-time pad transfer" republished (version 13, 14 artboards; new: OtpPanelEmpty,
OtpPanelImported). Spec: `otp-transfer-brief.md` § Design decisions, rewritten for this round.
Owner decisions taken in: neutral file name (§ 7 of the spec), transfer == pad passphrase blocked.

## Blocker

| # | Finding | Verdict | What changed |
| --- | --- | --- | --- |
| B1 | "travels with the file" teaches sending the passphrase with the file; the two fields look alike | **Fixed** | Tokens now say who knows it: two-person icon + "you both know it" (transfer) vs one-person icon + "only you know it" (pad), in the field and the tag, everywhere. Step titles carry it too: Import 2 / New 2 "Your own passphrase for this device". The phone and file glyphs are gone. The optional dashed/tinted field was rejected (a dashed field reads as a drop zone; a tint is colour-only). |

## Major

| # | Finding | Verdict | What changed |
| --- | --- | --- | --- |
| M1 | Empty panel not drawn; Connect is its only primary | **Fixed** | New artboard OtpPanelEmpty: the card holds New pad (primary) and Import. Connect is `aria-disabled` with a neutral look, and a tap gives the refusal. It is not hidden, because no-dead-ends clicks it. Hint cut to "One of you makes it, the other imports it." |
| M2 | Passphrase after Export; empty field for an unlocked pad | **Fixed** | Order is now pad → passphrase → entries → Connect. New unlocked state `#otpUnlocked`: check, "Unlocked for this session" and a Lock ghost (OtpPanel). |
| M3 | Must-differ never fires in New pad → Export | **Fixed** | After a successful generate/import the passphrase just used is written into `#otpPass` (a password input, as before this redesign). The rule is now a refusal (owner). |
| M4 | "File handed over" when nothing was handed over | **Fixed** | Done titles are per result: "File shared" (Android, ok disc), "File saved to this device", "File downloaded" or "Share sheet opened" (neutral disc). The last three add "Now give it to them in person — …". Desktop artboard redrawn. |
| M5 | Full-size "Share again / Save again" in the done state | **Fixed** | Replaced by one ghost link, `#otpSendAgain`: "Didn't arrive? Send it again" (Android, returns to the file-ready pair), "Download it again" or "Share it again". Full buttons only in file-ready and after cancel/error. |
| M6 | Re-export has no safe way out but × | **Fixed** | "Don't export" (secondary, closes) comes first, then "Export again" (danger). There is still no primary. Step 1 is shown done with its field hidden. |
| M7 | Wrong passphrase shown by colour alone | **Fixed** | The field icon changes to the triangle shape, the border is 2px, and a line "Check this one — it must match your contact's." is tied in by `aria-describedby`. The pinned sentence is unchanged. |
| M8 | Weak-passphrase wall of text; contradictory sample data | **Fixed** | Done blocks show one line, "Weak pad passphrase — accepted.", plus a "?" holding the full sentence (`#otpStatus` keeps it for the tests). OtpNew now shows a short passphrase with the live weak line, so it matches OtpNewDone. |
| M9 | Export offered for an imported pad (two-time pad) | **Fixed** (design + spec). Code fix by the implementer. | Received pad: Export hidden, and one line "Received pad — only the person who made it can export it." (OtpPanelImported). Forced attempts are refused in `otp.exportPad`, which the sheet shows as "Export failed: you received this pad — only the person who made it can export it". `importPad` refuses `recipientRole !== 1` with its own sentence. Added to the brief's "what is broken" as item 4. |

## Minor

| # | Finding | Verdict | Note |
| --- | --- | --- | --- |
| 1 | "?" on the wrong line in New pad | Fixed | It now sits in the drawing block's title row. |
| 2 | New pad steps add weight | Fixed | Two numbered steps with no current/idle machinery. Drawing is an unnumbered optional block. |
| 3 | "212 motion samples" jargon | Fixed | `#otpEntropyStatus` is visually hidden; the drawn line is the feedback. |
| 4 | Retry costs a file re-pick | Fixed | The picked file's text is held (≤ 4 MiB, dropped on close or success). "Try again" is the primary; "Choose another file" is a ghost. |
| 5 | Handover confirmed twice | Fixed | Done states drop the steps; the disc and title say it once. |
| 6 | "On their device" reuses my step discs | Fixed | Rows now use the passphrase tokens and a file icon, under the overline "On their device: Import". "Import, then" is gone. |
| 7 | Primary placement differs between sheets | Fixed | Rule: every action sits in the sheet's bottom row, pinned on a phone. Export's Create/Share/Save and Import's Choose moved there. |
| 8 | Done states built differently | Fixed | One anatomy everywhere: disc + title + line, pad card, extra content, bottom row. |
| 9 | Disabled × while working | Fixed | The × is hidden while working. |
| 10 | Re-export warning only after the in-person agreement | Fixed | The pad card shows "· exported before" (index hint) when the sheet opens. The authoritative check is unchanged. |
| 11 | "Alice ↔ Bob" placeholder | Fixed | Placeholder is now "e.g. Chess club"; sample data changed everywhere. |

## Nit

| # | Finding | Verdict | Note |
| --- | --- | --- | --- |
| 1 | Desktop file name wraps beside the button | Fixed | The name has its own line; the link sits under it. |
| 2 | Mono file name on Android | Fixed | UI font on Android; mono only for the browser's "Downloaded" name. |
| 3 | Pad icon reads as a table | Fixed | Now a notepad with a perforated top edge. |
| 4 | Import error lost the head's "?" | Fixed | The head is identical across states. The only exception is the × hidden while working. |
| 5 | Size option truncates | Fixed | The option shows the size only; `#otpSizeHint` below says "~1,400 short messages each way". |
| 6 | "Next: hand it to your contact" repeats the button | Fixed | Cut. |
| 7 | Success sentence repeated in the panel | Fixed | The four success sentences go to `#otpStatus` as `.vh` (the tests still read `textContent`). Errors and the budget line stay visible. |

Nothing rejected apart from the optional dashed/tinted transfer field in B1 (reason above).
Connect is shown `aria-disabled` instead of hidden in M1; the reason is in that row.
