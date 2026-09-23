# Phase 2a — fix round (pentest Lows + critics' nits)

## Pentest (accepted)
P1 (Low) two more refusals erased on close: the M-5 key-confirmation `fail` callback (~app.js:2383
"Key confirmation failed: … Disconnecting.") and `otpPersistFailed` (~3036) still use `hint()` before
`ws.close()`. Use `closeHint()` with the same words, like the six A2 refusals.
P2 (Low) a relay-parked fatal reason relabels client-initiated closes (the user's own "It differs —
disconnect", Disconnect, or an M-5 refusal): add one `closeWs(reasonKind)` helper (or a
`clientClosing` flag set right before every app-initiated `ws.close()`), and in `onclose` ignore
`closeRelayReason` when the app started the close. `closeHint` keeps precedence. Audit every
`ws.close()` call in app.js (there are ~14) and route the app-initiated ones through the helper;
the socket's own close (relay/network) is the only path that may show a parked reason.
P3 (Info) the modal sheet leaves no way out but Deny: add a quiet ghost button "Leave chat" inside
#admit after Deny (index.html; app.js: same handler as #disconnect, i.e. the closeWs helper), so the
owner can leave under an endless knock supply. It is not admit/deny, so no 500 ms guard; keep it
visually quiet; it must be in the Tab cycle.
P4 (test gap) e2e: (a) hostile-relay — replay the peer's signed handshake frame after key
confirmation while the gate is up (scratchpad/probe/m5erase.mjs shows how) and assert the M-5
refusal is visible on #roomHint after the close; (b) hostile-relay — park `{"type":"error",
"reason":"room closed"}` while the gate is up, press "It differs — disconnect", assert the room
screen shows the client's own refusal, not the relay's sentence (scratchpad/probe/park.mjs PoC 1);
(c) room-admission — with the sheet up, activating "Leave chat" disconnects and lifts inert.
Mutants: P1 (hint back) fails (a); P2 (flag removed) fails (b).

## Hot critic (accepted)
H1 the knocker's name in #admitWho: mono, main text colour (like every handle).
H2 when #chatVerified is shown, #chatStatus "connected" becomes a neutral pill with a green dot
(only "verified" stays green) — CSS in reviews/hot-critic-round2.md phase-2a section.

## Cold critic — appended when its report arrives.

## Cold critic (accepted)
C1 (MAJOR) focus restore when the sheet closes: `hideAdmitPrompt()` hides the focused button and
focus drops to body after Deny, after "Let them in" (gate appears) and after the knocker leaves. Fix:
if the active element was inside #admit, move focus to `#safetyNumber` when the gate is visible,
else to `#copyRoom` (or the first focusable control in the chat topbar). e2e (room-admission): after
Deny → document.activeElement is not body and is visible; after admit → focus is on the gate.
C2 focus after opening a chat row → move to `#chatText` (the composer) or the conversation header's
back button; after "Back to chats" → to the row that was open (or the list's first row). e2e
(two-user-flow): activeElement after Enter on a row is inside #chatConvo; after Back it is inside
#chatListWrap.
C3 axe `list` on #chatList: the rows are role="button", so set `role="none"` on the `ul#chatList`
(keep the id and the `.userlist` styling).
C4 e2e checks for B1 and B5 (they exist visually but no check pins them): room-admission — `#admitWho
.u-mark.ok` present for the known verified knocker with text containing "verified by you";
two-user-flow (or a DOM-level check in it) — a `.u-mark.changed` renders a `.u-mark-note` child
whose text contains "key CHANGED" (trigger via the store if the flow cannot, e.g. set keyChangedAt on
a contact through the contacts module in page context, then re-render).
C5 hygiene: merge the duplicate `.u-mark.changed` block (:899/:913); make `.vh-narrow` reuse the
`.vh` recipe (one declaration, two selectors) instead of a sixth copy.
