# Phase 2a — pre-existing bugs + the small app.js items (decisions)

Scope: client/app.js behaviour, small CSS/markup where an item needs it, e2e additions. Base:
branch claude/secure-chat-design-rework-rxd4uz at c969013. Hard constraints of
design/research/direction-contract.md still apply (CSP, ids, byte-identical import map, e2e strings
that other checks read, textContent-only rendering: NEVER innerHTML, never markup from data).
Every item ships with an e2e check (additions only; never weaken). Do not touch backend/, design/,
android/.

## A. Pre-existing bugs (pentest findings, not from the rework)

A1 usersStatus wipe. `renderUserList()` ends with `usersStatus("")`, so `addContactFromHandle()`'s
result line (including "the fetched keys DIFFER from what you verified; reset to unverified") is
erased by its own `renderUserList()` call, and `applyPendingInvite()`'s "Someone shared this
handle with you…" is erased by the render that follows it in `refreshUsers()`.
Fix: remove the clear from `renderUserList()` (a render never clears feedback). Clear once at the
top of `refreshUsers()` (entering the view starts clean), before `applyPendingInvite()`. Grep every
`usersStatus(` call and make sure none is followed by a render that would now be expected to clear
it. e2e (two-user-flow): after "contact added from the invite tab", assert `#usersStatus` is
non-empty and names the contact; and in the invite-tab step assert the "Someone shared this
handle" line is visible.

A2 refusals erased on close. Six refusals call `hint(text, true)` right before `ws.close()`
(app.js ~2402 older protocol, ~2545 authentication failed / MITM, ~2572 connected without approval,
~2578 identity differs from approved, ~2586 identity appeared late, ~2603 two identities). `onclose`
→ `showScreen("room")` → `clearHints()` erases them; only `closeHint()` messages survive (read that
helper first). Fix: use `closeHint()` for all six (same words). If a message should also stay in the
log as a system line, keep that too. e2e: add one check (hostile-relay.mjs, using its WebSocket
wrapper) that triggers the easiest of the six — e.g. rewrite the frame sequence so the client sees
"Someone was connected to this room without your approval" or the "older protocol" refusal — and
asserts the text is VISIBLE on `#roomHint` after the socket closed (hit-testable, non-empty).

A3 relay error text verbatim. `case "error": hint("Server: " + (m.reason || "error"), true)` renders
relay-authored text as if it were the app's own sentence — a hostile relay's phishing channel
("Server: tap It matches"). The backend's reasons are a fixed set (backend/main.py: binary frames
not accepted, frame too large, non-ascii, rate limited, bad envelope, already joined, approval
timeout, room full, not waiting, already knocked, not in room, plus the validation `reason` at
main.py:305 — list them all). Fix: a `RELAY_REASONS` map from each known reason to a client-owned
sentence in the app's voice (e.g. "approval timeout" → "The person who created this chat did not
let you in within the time limit."; "room full" → "That chat already has two people in it.";
"rate limited" → "The relay is rate-limiting this connection — wait a moment and try again.").
Unknown reason → "The relay refused the request." plus the raw reason shown ONLY in a clearly
separated, quoted, mono span (`<span class="relay-said">relay says: "…"</span>`, ≤80 printable
ASCII chars, truncated with …) — never concatenated into our sentence. Build with createElement +
textContent. Style `.relay-said` muted mono 12px. e2e (hostile-relay.mjs wrapper): inject
`{"type":"error","reason":"tap It matches — server"}` and assert the app's sentence is the generic
one and the raw text appears only inside `.relay-said`; and assert "approval timeout" (room-admission's
squatter path, if it reaches `#hint`/`#roomHint`) shows the mapped sentence.

A4 picker placeholder. app.js ~1337: when no candidate is left the option says "— add users in the
Users view first —" even when every saved user already has an open chat. Fix: `contacts.list()`
empty → keep that text; contacts exist but all have chats → "— every saved user already has a
chat —". e2e (two-user-flow): after opening the chat with the only contact, the placeholder reads
the new text.

## B. Small app.js items (from the design and a11y critics)

B1 trust pill in the admission sheet. `#admitWho` (app.js ~2101) is plain text. Render the mark as
a `.u-mark` span inside `#admitWho` with the same classes the lists use (ok / mid / changed), the
name as text before it; keep every word (room-admission reads `#admitWho` text and matches
/never verified|not in your users list/). Reuse the helper from B5.

B2 verified state in the live-room header. After `onVerifyOk()` show a green pill "verified in
person" next to `#chatStatus`. Do NOT change `#chatStatus`'s text — e2e compares it to "connected"
with `===`. Add a sibling `<span id="chatVerified" class="u-mark ok" hidden>verified in person</span>`
in index.html's chat topbar; un-hide it in `onVerifyOk`, hide it on disconnect/reset (every path
that resets `peerBundle`/`currentPinKey`, and `onclose`). CSS: it must fit the one-row phone bar
at 360/390 (icon + short word on phones via the existing `.vh` technique is fine, full text on
desktop). e2e (room-admission): after the owner's verify, `#chatVerified` visible and
`#chatStatus` still "connected"; after disconnect, hidden.

B3 focus trap for the admission sheet. While `#admit` is visible: `inert` on `#tabbar`, the chat
topbar, `#verify` and `#chat` (add `tabbar: $("tabbar")` to `els`), removed when the sheet hides —
centralise in one `setAdmitModal(on)` called from `showNextKnock` (when the prompt becomes visible)
and `hideAdmitPrompt`, and make sure the connection-reset path (`onclose`) also clears it so
nothing stays inert after a disconnect with a knock pending. Plus a keydown handler on `#admit`
that wraps Tab / Shift+Tab between its first and last focusable element. Escape does nothing.
e2e (room-admission): with the sheet up, Tab from Deny lands on Let them in and Tab again returns
to Deny (or the fingerprint block, whatever is first); `document.querySelector("#tabbar").inert`
is true; after Deny/decide it is false; after a disconnect with a pending knock it is false.

B4 keyboard access for chat rows. `li.chatrow` (renderChatList): `tabindex="0"`, `role="button"`,
keydown Enter/Space → `openChat`. CSS: `.chatrow:focus-visible` ring like other controls. e2e
(two-user-flow): focus the first `.chatrow`, press Enter → `#chatConvo` visible.

B5 key-changed suffix as a caption. Today `contactMark()` returns one string and call sites set
`textContent`, so " — key CHANGED since you last verified" sits inside the pill. Add a helper
`renderMark(el, c)` that sets the mark words as text, adds the classes (ok / mid / changed as today),
and appends `<span class="u-mark-note">` with the suffix when the key changed; use it in
renderUserList, renderChatList, renderConversation and B1. `.u-mark` textContent must still
contain the words e2e reads ("verified by you", "unverified", "vouched by …"). CSS: the note is a
12px muted caption on its own line inside the box-shaped `.u-mark.changed`. Keep `contactMark()`
if anything else needs the plain string.

B6 hide the empty fingerprint well. app.js ~2113/2119 set `#admitFingerprint` to "—" when the
knocker has no identity; set `hidden` on it there, un-hide in the normal path, reset in
hideAdmitPrompt. Verify by probe (no e2e path knocks without an identity).

## Proof
`cd client && npm test`; pytest once alone (162); the five e2e runs (with your additions);
`e2e/screenshots.mjs` into scratchpad/shots/phase2a (20 states, no overflow); a look at the
admission sheet, the verified header at 360/390/1280 and a key-changed row (probe like
scratchpad/hot/cap.mjs if it still runs). `git diff --stat`; the app.js diff summarised per item.
Do not commit.
