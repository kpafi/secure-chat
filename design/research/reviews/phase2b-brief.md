# Phase 2b — less text, clearer next step (decisions)

Owner's ask: there is still too much text on screen; hide explanations behind a "?" and make the
design lead to the right button. Base: branch claude/secure-chat-design-rework-rxd4uz at 7361acc.
Constraints as always (design/research/direction-contract.md): CSP, ids, byte-identical import map,
textContent-only, no new markup from data. The admission guard and every refusal/error text stay
untouched (security wording is not "explanation"); e2e strings other checks read stay, and where a
guidance sentence that a check matches is shortened, the check's regex is updated to the new words
(never weakened).

## The two mechanisms
1. **"?" disclosure.** The existing `<details class="why">` becomes an icon variant: `<details
   class="why"><summary><span class="vh">Why?</span></summary><div>…</div></details>` rendered as a
   24px round "?" glyph button (border, muted, accent on hover/focus, 44px hit area on phones) placed
   inline after the title/label it explains; the content opens as a quiet panel below (13px, muted,
   max 60ch, hairline top). No JS. Every long explanation moves into one of these. Rule: at most ONE
   visible sentence per section; everything else is behind "?".
2. **One next step.** Every screen has exactly one primary, at the end of the reading order (bottom
   on phones), and it is the flow's next step; optional inputs are collapsed disclosures or quiet;
   destructive and rarely used actions are ghosts and last.

## Screen by screen (visible copy → what goes behind "?")

Step 1 — identity (#scrIdentity)
- First run: overline "Step 1 of 3", title "Your identity", ONE line: "Made on this device. Nobody
  else holds it." Then passphrase + primary "Create identity". "?" holds the three facts (keys stay
  here / relay sees ciphertext only / you verify each other in person) and "why a passphrase". Drop
  the visible facts list and the pitch title. "Continue without an identity →" stays a quiet text
  link at the bottom.
- Locked: title "Your identity", ONE line "Locked — enter your passphrase.", passphrase + primary
  "Unlock", "?" = what the passphrase protects. `#idForget` is hidden on this screen by CSS (it stays
  in the DOM; Forget lives on Profile).
- Unlocked: title "Your identity", status just "Unlocked." (quiet, green dot). Fingerprint well
  with label "Your fingerprint" + "?" ("what contacts compare with you in person"). Copy backup as
  a quiet ghost. Username: label "Username (optional)" + the row [input][Register] with "Log in" as
  ghost; the long label and "Optional: claim a username…" go: "?" holds "lets people add you by
  name; a username alone never resolves — the handle does". Registered status: "Registered as
  <handle> — share this handle." (keep the word "Registered"). Primary: "Continue →" at the bottom.

Step 2 — room (#scrRoom)
- Overline "Step 2 of 3", title "Chat code", ONE line "Share it with the one person you want to
  talk to." + "?" (both must use the same code; useless on its own; how to join with a pasted code).
  Code well, Copy (secondary), New code (ghost). Remove the visible 3-line hint.
- "Who are you expecting?" becomes a collapsed disclosure `<details id="expectRow">` with summary
  "Expecting a specific person? (optional)"; inside: the #contact field and its hint shortened to
  one line, the rest behind "?". e2e that types into #contact (no-dead-ends "malformed handle")
  must open the disclosure first — adapt the check, do not weaken it.
- Security options: unchanged row; inside, "Every option here is end-to-end encrypted…" → "?".
- OTP panel: each `.otp-sub` keeps ONE visible line — "Generate on one device and hand the file over
  in person." / "Import on one device only — never the same pad twice." — the paragraphs, the
  entropy explanation and "(the OS random generator is used regardless)" go behind "?".
- Primary "Connect" at the bottom with the status pill.

Step 3 — chat
- Verify gate: visible "Read it aloud to your contact. It must match exactly." + "?" holding the
  trusted-channel/MITM explanation. `#verifyHint` is what app.js rewrites for the key-changed case:
  keep that app.js text; shorten only the DEFAULT text (index.html and, if app.js sets a default,
  there too). "If it differs, a relay may be intercepting you" stays visible in err on the changed
  variant as today.
- Admission sheet: "Only let in someone you are expecting. Check the fingerprint with them." + "?"
  (they know your code; what the fingerprint proves). app.js texts for #admitWho/#admitWarn/#admitHint
  unchanged.
- Live chat: "Ready. Messages are end-to-end encrypted." stays (short).

Users
- Handle: label "Your handle" + the handle + Copy (icon) + "Invite link" ghost; "?" = share it so
  others can add you; adding only pre-fills, trust needs the fingerprint check.
- Add row: label "Add a user" + [handle input][Add primary]. Legend → "?" next to the list heading
  ("What the marks mean") with the three lines.
- Locked card (Users/Chats/Profile): "Locked. Enter your passphrase." + "?" (stored encrypted under
  the identity passphrase). The "Open anyway" hint shortens to two sentences that keep the meaning
  (cannot be opened safely; open it only if you know why; treat contacts as unverified / messages
  may repeat). no-dead-ends reads the app.js error text and the button — unchanged.

Chats
- List: label "New chat" + [picker][Open secondary]. Conversation: the mode explanation
  (chatHint 1530/1532 "SEALED — hybrid ECDH…", "AES256 — …") moves out of the composer hint into a
  "?" next to the mode select: app.js writes it into a new `#chatModeWhy` element inside a
  `<details class="why">` (add the id to els); `#chatHint` keeps only errors/actionable lines. The
  "You can send now; to RECEIVE messages, log in…" banner stays visible but shorter: "Not logged
  in — messages cannot arrive. Log in on step 1 of the Live room." (keep "log in").

Profile
- "Invite QR" label + "?" (scanning only pre-fills; they still verify you in person).
- "Fingerprint" label + "?". Keys under a collapsed `<details>` "Technical details".
- Sign out: its 154-char hint → "?" next to the button. Actions: Copy backup (secondary), Sign out
  (ghost), Forget identity (danger, last, separated).

app.js guidance strings to shorten (non-refusal only; refusals/errors untouched):
555 → "Unlocked." · 590 → "" · 614 → "Locked — enter your passphrase." · 616 → "No identity on this
device yet." · 630 → "Generating keys…" · 718 → "Backup copied. It is useless without your
passphrase." · 1113 → "Handle received — review it and press Add." · registered status → "Registered
as <handle> — share this handle." · 1530/1532 → into #chatModeWhy (same words). Everything the
pentest classed as refusal, warning or relay text stays byte-identical.

## Proof
npm test; pytest once alone (162); the five e2e runs (adapt regexes/opens where copy or structure
changed, list every adapted check); screenshots.mjs into scratchpad/shots/phase2b (20 states, no
overflow); a "?" walk: every disclosure opens by click and by keyboard (Enter/Space on the summary),
has an accessible name, and closes again; count visible words per screen before/after (a small
script over the 20 states: sum of visible text nodes' word counts) and report the table. Then LOOK
at every screen at both sizes: one sentence per section, one primary per screen, nothing that reads
as a paragraph.
