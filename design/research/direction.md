# secure-chat rework — design direction (the polish rules)

Read with `direction-contract.md` (IA decisions, hard constraints, tests) in this folder; the two research
briefs `kali-brief.md` and `messenger-patterns.md` are the evidence. This file is the decision.

## The one-line direction

Same palette, same words, same mono-for-keys rule — but built like Kali's site: one accent with one job,
six type sizes, space instead of boxes, one surface ladder with hairlines instead of shadows, one
component anatomy repeated everywhere, restrained motion. A security tool that looks *finished*.

## Diagnosis of today (why it reads as "boxes stacked")

- ~12 font sizes between 0.64 and 1.15rem; nothing is clearly a title, nothing clearly a caption.
- Off-grid spacing (0.35 / 0.45 / 0.6 / 0.85rem) so nothing aligns across panels.
- Every section is a bordered, shadowed `.panel`; every list row is a bordered card inside a panel;
  wells inside cards inside panels: three nested boxes on most screens.
- Emoji trust marks and a `·`-joined status line; a `<select>` doing the job of a chip.
- The live room and the async chat render messages differently.
- The app header is a hamburger + wordmark; navigation is hidden behind it.

## Rules (each with the value to use)

1. **Accent has one job.** `#2f81f7` only for "act here" and "you are here": the one primary action,
   the active tab, focus rings, the selected card, links. Primary fill is flat `#1f6feb` with white text
   (4.6:1), `box-shadow: inset 0 1px 0 rgba(255,255,255,.12)`, no gradient. At most one blue element per
   screen besides the primary button. Glow (`0 8px 24px -12px rgba(47,129,247,.45)`) is reserved for a
   state that deserves it (the verified pill, the connected status), never for decoration.
2. **Six type sizes, tabular numbers.** 12 / 13 / 15 / 17 / 20 / 24px on the system `ui` stack.
   Titles 20–24px, weight 650, `letter-spacing -0.02em`, `line-height 1.2`. Body 15px/1.5.
   Overline labels 12px uppercase, weight 600, `letter-spacing .08em`, muted. Captions/timestamps 12–13px
   in a new `--faint #6e7681` (3.7:1 — metadata only, never for anything the user must read).
   `font-variant-numeric: tabular-nums` on times, counts, safety numbers. Inputs/buttons 16px on phones.
3. **Space separates; borders contain.** 4px base, 8px rhythm: `--sp-1..7` = 4/8/12/16/24/32/48.
   Screen gutter 16px (24px on desktop). One screen-header pattern on every view: overline (the view's
   role, e.g. "STEP 2 OF 3" or "YOUR IDENTITY"), title 22–24px, one muted sentence, `max-width 60ch`;
   content sits under it without a panel around it. Sections are 24–32px apart.
4. **Surface ladder, no shadows on flat things.** `--inset #0a0e13` < `--bg #0d1117` < `--panel #161c23`
   < `--panel-2 #1c232c`. A card = `panel` + `border: 1px solid rgba(240,246,252,.08)` +
   `box-shadow: inset 0 1px 0 rgba(255,255,255,.03)`. `--shadow-1` disappears from panels and bubbles;
   `--shadow-2` only on things that float (sheets, the admission dialog).
   Lists (users, chats, live log) are ONE container with hairline dividers between rows, not a card per row.
5. **One anatomy, one radius per level.** Controls 8px, cards 12px, sheets and bubbles 16px; inner radius =
   outer − padding. Hover changes the border to `--muted` only. Selected = border
   `rgba(47,129,247,.5)` over `linear-gradient(180deg, rgba(47,129,247,.08), rgba(47,129,247,.02))`.
6. **Mono is texture for key material only**, always in a recessed well (`--inset`, hairline, radius 8,
   `letter-spacing .02em`). Safety numbers and fingerprints: large (20–22px), grouped, centred, lines of
   equal group count (2 or 5 groups per line — never a lone group on the last line), the full-width
   well; this is the app's "terminal snippet".
7. **Background without assets.** `radial-gradient(120% 50% at 50% -10%, rgba(47,129,247,.10), transparent
   60%)` over the existing top gradient; optional faint 32px grid at ≤3% alpha faded with a radial mask.
   No `background-attachment: fixed` (WebView jank).
8. **Chrome.** Desktop (>600px): sticky top bar, `rgba(13,17,23,.8)` + `backdrop-filter: blur(12px)`
   (solid fallback), hairline bottom border; wordmark left, the four tabs right with a 2px active
   indicator. Phone: bottom tab bar 56px + `env(safe-area-inset-bottom)`, 20px icons, 11px labels, active
   tab accent. The wordmark alone in a slim top bar. Content never hides under either bar.
9. **Icons.** One inline stroke set: 20px, `stroke-width 1.5`, round caps, `currentColor`. Nav icons are
   the four already in index.html (re-drawn at the same weight). Trust marks: shield-check (verified),
   shield-dot (vouched), shield outline (unverified), triangle-alert (key changed) via CSS masks on
   `.u-mark::before`, plus 3/2/1 filled dots after the word so the level reads without colour. Chat mode:
   a small padlock before the mode name. No emoji anywhere.
10. **Motion.** 120–160ms ease-out on colour/border; 220ms `cubic-bezier(.2,.8,.2,1)` on transforms
    (sheet, view change: a 6px rise + fade on `.view:not([hidden])`); all inside
    `@media (prefers-reduced-motion: no-preference)`.

## Screen by screen (what the rules produce)

- **Live room — step 1 (identity).** First run: the welcome — wordmark, "Your keys are made on this
  device. Nobody else holds them.", three facts as a quiet list (keys stay here · the relay sees ciphertext
  only · you verify each other in person), then the passphrase field and one primary (Create identity).
  Returning: the same header, passphrase + Unlock. Unlocked: the fingerprint in a well, the account
  (username) block as a card below, Continue → as the primary. The step indicator becomes a real
  3-segment progress line (CSS on `.step`), the text stays.
- **Step 2 (room).** Header "Your chat code". The code large in mono in a well with Copy / New code as
  secondary + ghost. "Who are you expecting?" as a plain field. Security options: the `<details>` styled
  as a single row "Encryption · DHKE — recommended ›" that expands to the five cards (one anatomy: name,
  spec in mono, badge). AES/OTP fields appear under the chosen card. Connect pinned as the primary;
  status text beside it becomes a small live pill (grey/green/red dot + word).
- **Step 3 (chat).** Top bar: room id chip (mono), status pill, Disconnect (danger outline). The
  admission section renders as a bottom sheet on phones and a centred dialog on desktop, over a scrim
  (`#scrChat:has(#admit:not([hidden]))`), fingerprint in the mono well, Let them in / Deny with equal
  weight. The verify section is full-screen while visible (hide `#chat` behind it with `:has`), header
  "Compare with your contact — in person", the safety number as the big well, "If it differs, a relay may
  be intercepting you" in err, the two buttons stacked full-width. The live log uses the same bubbles as
  the async chat: `li.me` right/blue, `li.peer` left/panel-2, `li.sys` centred muted small; the `.who`
  label becomes a tiny caption above the bubble. Composer: pill input + round primary send.
- **Users.** Header "Users — known keys & trust". Your handle as a card (handle in mono, Copy, Invite
  link as ghost). Add-by-handle as one field + button. The list as one container: rows with a 40px avatar
  disc (initial, mono), name, the trust pill right, fingerprint in faint mono under; key-changed rows get
  the alert pill and an err caption. Legend as three quiet pills. Empty state: one title, one sentence.
- **Chats.** Same list anatomy (avatar, name + pill, last message preview, time in faint tabular).
  Conversation: header with back, avatar, name + pill, the mode `<select>` styled as a chip. Pending banner
  as a sticky bar above the composer in warn. Bubbles 16px radius, 4px toward the sender, max 78%,
  timestamps optional (not in the data) — no fake times.
- **Profile.** Avatar 56px, name 22px, handle in mono with Copy. QR on a white card with 8px quiet zone.
  Fingerprint well. Keys as the `.kv` grid under an overline "Technical details". Chips. Actions row at the
  bottom: Copy backup, Sign out, Forget identity (danger) — the danger button last and separated.
- **Locked views (Profile/Users/Chats).** One "locked" card: padlock icon, one sentence, passphrase +
  Unlock in one row, status line. Identical on all three.

## Explicitly NOT in this round (behaviour changes; list them in design/README.md as phase 2)

Start | Join segmented control; encryption picker as a sheet; a contact detail screen; "Send anyway"
sheet on key change; typed confirmation for Forget; QR scanning; moving the username to Profile; a
backup-reminder banner; desktop two-pane chat; "Encrypted to <name>" placeholder (needs app.js).
