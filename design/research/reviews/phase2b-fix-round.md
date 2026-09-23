# Phase 2b — fix round (pentest + design critic; cold critic appended when it arrives)

## Pentest (accepted)
S1 (Low, pre-existing) stale #verifyHint: the clean branch of enterVerification (~app.js 2927) sets the
title but not the hint, so after a key-changed session the next clean session shows the old warning
text. Reset #verifyHint to the default sentence in that branch (the same words index.html carries).
e2e (room-admission or hostile-relay): after a `.changed` gate followed by a clean session in the same
page, #verifyHint equals the default text.
S2 (Info) the "Open anyway" hints (Users and Chats locked cards) dropped the benign examples ("you
forgot this identity on this device yourself / you just upgraded from an old version"); those are how
a user tells a legitimate case from a deleted-store attack. Restore them behind a "?" next to the
Open-anyway button (static markup), visible line unchanged.

## Design critic (accepted)
D0 `.qline { text-wrap: balance }` (or the equivalent on the sentence element) so the trailing "?"
never sits alone on a line (Chat code, verify gate, admission sheet).
D1 Chat code lede: "Share yours, or paste theirs." (one line at 360px) — the "?" keeps the rest.
D2 Help panel placement: the opened "?" panel must render BELOW the field it explains, never between
label and field (the critic's CSS grid fix is in reviews/hot-critic-phase2b.md). Forget on the locked
step 1 leaves the help panel: a quiet last line under the Unlock button — "Forgot your passphrase?
Forget this identity" — as a text-style danger ghost, still confirm-gated (#idForget keeps its id and
handler; only its placement/markup changes).
D3 Step 1 after registering: hide the username input, Register and Log in once the status reports
registered (they compete with Continue). The status line with the handle stays. app.js: where the
registered state is rendered, toggle `hidden` on that row (keep ids; e2e two-user-flow waits for
/registered/ in #accountStatus — unaffected). Re-show the row when not registered / after sign-out.
D4 Chats empty state: two short variants — no saved users: "No users yet. Add someone in Users."
(with the Users tab as the way there); users but no chats: "No chats yet. Pick a user above." (one
app.js line in renderChatList's emptyRow call).
D5 Profile: Forget identity as a quiet red text button (danger ghost), last and separated.
Minors from the review to take now: Add is a filled primary while #addHandle is empty → keep it
primary but visually disabled via `:has(#addHandle:placeholder-shown)` (still clickable; app.js
validates); Profile has three "?" → merge Invite QR and Fingerprint help into one "?" on the section
head or drop the fingerprint one (the well is self-explanatory with its label); "Expecting a specific
person?" collapsed row hides a filled value → when #contact is non-empty keep the details open (2
lines: on load and on input set `details.open = !!value`); "Invite link" alone on its own line in
Users → same row as Copy at ≥360px.

## Proof
npm test; pytest once alone; the five e2e runs (+ the S1 check); screenshots.mjs into
scratchpad/shots/phase2b-v2; look at step 1 (locked, unlocked, registered), Chat code, the gate,
the sheet, Users, Chats empty (both variants), Profile at both sizes.
