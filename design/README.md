# Design — Claude Design integration

The visual side of secure-chat lives in two Claude Design artifacts, both
built from this repository. The code stays the source of truth: the design
system is read *from* `client/style.css`, and a rework is implemented back
*into* `client/style.css` and `client/index.html`.

| What | Where | Built from |
| --- | --- | --- |
| **Design system** — tokens, type, spacing, radii, shadows, 18 components as static previews, brand book | https://claude.ai/artifact/X5ZsDXagkxwjraVyUzY1V1 | `client/style.css`, `client/index.html`, `client/app.js` @ `3e55bff` |
| **Design canvas** — the rework proposal: 8 phone artboards (390×844) + 1 desktop (1280×800), clickable in Play | https://claude.ai/artifact/NhVZuUXfC2FsJf93NBn5H2 | the design system above |

Both are private until shared from the page's Share menu.

## Workflow

1. **Explore on the canvas.** Comment on an artboard or ask Claude to change
   it; the design system's tokens are installed on the canvas, so colours and
   text styles come from the app's palette, not a guess.
2. **Implement in code.** A visual change is a `client/style.css` change (and
   `android/app/src/main/res/values/colors.xml` for `bg` / `fg`). A structural
   change also touches `client/index.html` and `client/app.js` — see the staged
   plan below.
3. **Re-sync the design system** after `style.css` changes: ask Claude to
   "re-sync the secure-chat design system from `client/style.css`". It merges
   changed values and keeps the usage notes.

## Constraints every design must respect

- **CSP**: `style-src 'self'`, `script-src 'self'` + one pinned hash, no
  `font-src`, `img-src 'self' data:`. So: one stylesheet, no inline styles, no
  web fonts (system `ui` and `mono` stacks only), no external assets.
- **Android**: the same `client/index.html` is bundled into the WebView app; the
  native status/navigation bars use `bg` and `fg`.
- **Rendering**: everything is `textContent`; no markup from data, ever.
- **One `.primary` per screen**; danger actions stay tinted outlines and are
  confirm-gated in `app.js`.
- **Mono is for key material only** (fingerprints, safety numbers, handles,
  room ids, cipher specs, the wordmark).

## The rework direction

The full decision is in `design/research/direction.md` (polish rules with values, screen by screen)
and `design/research/direction-contract.md` (structural decisions, hard constraints, which tests
change with the code). The evidence behind them: `design/research/kali-brief.md` (what makes the
Kali site read as designed, translated to this app's constraints) and
`design/research/messenger-patterns.md` (how Signal, Threema, Element, SimpleX, Session and Briar
present trust, verification, admission and mode changes).

In one line: same palette, same words, same mono-for-keys rule, built like Kali's site — one accent
with one job, six type sizes, space instead of boxes, one surface ladder with hairlines instead of
shadows, one component anatomy repeated everywhere, restrained motion.

What changes structurally (index.html + a few lines of app.js):

- persistent navigation — a bottom tab bar on phones, a sticky top bar with inline tabs on wider
  screens — instead of the hamburger drawer; same `.navitem[data-view]` buttons, same `showView()`;
- a first-run welcome on the identity step (static copy);
- trust marks as stroke icons drawn by CSS masks plus the same words, instead of 🟢🟡⚪ emoji;
- everything else is `client/style.css`.

What was considered and deliberately NOT done in this round (behaviour changes; each needs its own
design, e2e coverage and a pentest pass):

- one global unlock screen (the e2e suite pins that every locked view unlocks in place, because an
  invite link opens a new, locked tab) and Chats as the home view (identity creation lives in the
  live room's step 1);
- Start | Join segmented control for the chat code; the encryption picker as a bottom sheet;
- ~~a contact detail screen~~ — shipped as the contact profile (below); a "re-verify or send anyway" sheet when a contact's key changed;
- typed confirmation for Forget identity; QR scanning; moving the username to Profile;
- a backup-reminder banner after creating an identity; "Encrypted to <name>" as the composer
  placeholder; a desktop two-pane chat.

## Verification of the rework

Every change went through the project's own gates before it was committed, and through three
independent reviews (their reports are summarised in `design/research/reviews.md`):

- `client` unit tests and `backend` pytest (162) unchanged and green.
- The e2e runs in `e2e/`, with their navigation helper updated for the tab bar and new
  assertions added, never weakened: `two-user-flow` 8/8, `room-admission` 26/26 (was 13; the
  additions pin the admission sheet's geometry, its pointer-events layer, the 500 ms admit/deny
  guard under reduced motion, keyboard activation and a view-switch reveal — each proven by a
  mutant that fails exactly one of them), `no-dead-ends` 17/17 (the current-view mark must
  move), `hostile-relay` 12/12 (a refusal must be hit-testable on a phone), `all-modes` 32/32.
- `e2e/screenshots.mjs`: 20 states at 390×844 and 1280×800 with an empty overflow section (the
  old client overflowed on Profile and on the verify gate at 390px).
- A pentest of the diff (`.claude/agents/pentest-new-code.md`), four passes: nothing Critical, High
  or Medium; three Low findings in the phone layout and the new admission guard (the sheet docked
  over the tab bar, refusal text under the bar, a prompt armed while the page was hidden), each
  fixed with a test that its own mutant fails; no open findings at commit 2bbc64d.
- A harsh design review and a dispassionate correctness/a11y review, each in three rounds; the
  last round found no blocker or major.

## Contact profile (2026-09-23)

A saved user's short profile as a sheet: tap a Users row, a Chats row's avatar or the
conversation's name. Decisions in `design/research/reviews/profile-brief.md`; the canvas has a
"Contact profile" row (ContactProfile, ContactProfileChanged, ContactProfileDesktop, UsersSlim),
updated to the design after the review rounds. Reviewed like the rework — hot and cold critics and
the pentest agent, three rounds each; triage in `reviews/profile-fix-round-1.md` and
`reviews/profile-fix-round-2.md`, summary in `research/reviews.md`. e2e: `e2e/contact-profile.mjs`.
