# Contact profile — fix round 7 (the Remove row, after the owner's phone test of 0.3.0)

Reviewed the working diff off `v0.3.0` (`a54315f`). Trigger: the owner opened a verified contact
on the phone and found the lone Remove, right-aligned under the Message/Unverify row, "off center
and weird". Round 1 had recorded that alignment as the canvas's choice; this round is the owner
overriding it. Claude Design itself was not reachable from the session that did the work
(`/design-login` needs an interactive terminal), so the canvas was not updated; the design
critic and the pentest ran as agents on the diff and on fresh `e2e/screenshots.mjs` output.

## The change
- `client/style.css`: `.contact-remove-row` is `justify-content: center`; the negative
  `margin-right` on `#contactRemove` (which pulled its text to the content edge) is gone, its
  padding is its hit area. Opened from a conversation there is no Message, so the one decision
  left (`.contact-actions:has(> #contactMessage[hidden])`) is centred too, on Remove's axis
  (hot r7 MINOR-2). The `.contact-actions` block comment no longer says "right-aligned"
  (hot r7 MINOR-1).
- `e2e/contact-profile.mjs`: three new checks in section 6 (64, was 61). Remove is centred
  (|sheet mid − Remove mid| ≤ 1px), not stretched (width < 200), and BELOW the decision row's
  hit area (clearance ≥ 0, `elementFromPoint` at its centre is Remove) — measured in both phone
  arms, the static key-changed row and the sticky Message/Unverify bar (pentest p7 F-1), and the
  lone Unverify without Message is centred.

## Design critic ("hot"), round 7
No blocker, no major. MINOR-1 the stale comment (fixed). MINOR-2 the no-Message state: Unverify
flush left, Remove centred, "two loners on two axes" (fixed by centring the lone action). Nits:
the `width < 200` bound wanted a reason (commented); the check ran in one state only (now both
arms); Users rows still right-align their actions on phones while the sheet centres its lone
one — noted, not changed: a list row's action sits with its row, a sheet's last action with the
sheet. Alternative considered and declined: a full-width quiet Remove settles all states but makes
the danger action the biggest target on the sheet. "Meets the owner's bar: yes."

## Pentest pass 7
Nothing Critical/High/Medium. Verified sound by a grid probe over 7 widths × 9 heights × 4 sheet
states × scroll top/bottom × normal and 200% text: `remove.top − bar.bottom` ∈ {0, 4, 13.8, 16},
never negative; the sticky bar can only move UP from its flow position and carries `z-index: 1`,
so Remove can never take a tap meant for Message/Verify; hit target unchanged at 87.5×44 (phone)
/ 83.6×40 (desktop); no overflow at 320px or 200% text; the check fails against the old rule and
against a full-width Remove.
- F-1 (Low, test strength): the first version of the check ran only in the key-changed arm and
  asserted nothing vertical, so a phone-only "Remove over the sticky bar" mutant passed 62/62.
  Fixed as above; the mutant (`margin-top: -60px; position: relative; z-index: 2` on the phone
  rule) now fails the sticky-arm check with clearance −32.
- F-2 (Low, judgement): centred, Remove now sits under Message — the most-tapped control — with
  4px clearance on desktop (12px on a phone). The 4/12/16px values are the pre-existing rules;
  Remove stays confirm-gated and behind the 500 ms guard. Accepted.

## Mutants run by hand
| mutant | check that turns red |
| --- | --- |
| A — `.contact-remove-row { margin-top: -60px; position: relative; z-index: 2 }` in the phone rule | "verified: Remove is centred under the sticky … below its hit area" (clearance −32) |
| B — `:not(:has(> #contactVerify.primary)) + .contact-remove-row { justify-content: flex-end }` | the same check (removeMid 329 ≠ 195) |
| C — the `#contactMessage[hidden]` centring rule removed | "without Message the lone Unverify is centred on Remove's axis" |
| the old rule restored (`flex-end` + `margin-right: -12px`) | "key changed: Remove is centred under the static row …" |
