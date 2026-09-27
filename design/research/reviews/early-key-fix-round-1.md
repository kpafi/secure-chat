# Early-key refusal — fix round 1 (triage of pentest round 1)

Scope: `early-key-pentest-r1.md`, run against e919018. The verdict there is
that the change does what it claims. Nothing Critical, High, Medium or Low
was found. The report raised three Info findings (behaviour and comment
accuracy) and three Info test gaps. One of the gaps (T1) left the commit's
stated side effect unbound. The pentest also confirmed the decision's
premise: an honest relay never sends `key` before `pending`/`joined`. It
checked main.py, relay.py and the oldest relay, f071b9d.

| Finding | Verdict | Bound by (mutant → red check) |
| --- | --- | --- |
| I-1 (Info, pre-existing, kept by the owner's decision): a guest in the admission queue still answers a hello with its nonce and signed key (and, in AES256/OTP, a confirmation tag). The `pending` comment said "not even the session nonce" | **Comment fixed.** It now says this holds for an honest relay, what a hostile one gets (no more than seating us would give it), and that `pending` counts as an answer on purpose because the prompt is visible there. The behaviour is unchanged. Treating the queue like "no answer" is a further owner option; this round offers it and does not take it | M9 (keyed on `!joined`) → "E control: after `pending` a key frame is not the early-key refusal" (unchanged) |
| I-2 (Info): a forged handshake dispatched after the relay's close no longer shows the MITM refusal, but the dispatch-gate and `sessionGen` comments still promised it | **Comments qualified.** "Last words" now covers a `key` frame only if its handling began before onclose. One dispatched after onclose is dropped, see the `key` arm. The behaviour is kept: the frame is relay-authored, and the drop also removes the post-close room-screen prompt | — (comments) |
| I-3 (Info): "CLOSING: its onclose says why" holds only if the relay's reason comes after the key frame (the A3 reset) | **Comment reworded:** "its onclose shows whatever reason is still parked (A3 above drops one this frame follows)". Not a regression, and not reachable before an answer in either browser | — (comment) |
| T1 (Info): nothing tested the drop of a key frame dispatched after the close of a session that had got past the hello. Y3 (`&& peerNonce === null`) and Y4 (`&& !helloAnswered`) survived everything, and Y3 brings back the invisible post-close prompt in Chromium | **Bound three ways.** (1) cc block E "CLOSED, seated": AES256 owner past the hello exchange; a handshake and a confirm tag queued before the relay's close, then the close; checks the room hint, the whole log and the sent frames. (2) app-behaviour (h2): a DHKE guest past the hello; a relay-signed handshake queued before the close; no prompt, tab bar not inert, nothing sent. (3) e2e `psecond`: a second handshake (another identity) queued behind the visible prompt, then Close; after the close event, no `admit.hidden=false` and no `tabbar.inert=true`. pguest also gains "no prompt after the close" | Y3 → cc "E (CLOSED, seated): a key frame after the close writes nothing over the room screen", ab "early-key r1 T1: a handshake dispatched after the relay's close raises no prompt", e2e 24/25 (the psecond trail shows `…close-event, …, admit.hidden=false`); Y4 → the same cc and ab checks |
| T2 (Info): the rewritten C1-1 block no longer tested C1-1, because the refusal clears the deadline and hides Cancel. Z1 (C1-1's guard removed from `endUnanswered`) survived | **Both suggestions taken.** The C1-1 block now says it binds only "the refusal ends at once, nothing relabels it", and its OK line says the same. A direct test binds the guard: a `closeWs` on an unanswered socket whose close stalls (Disconnect, clicked through the stub; no relay trigger is left), then the deadline, must not relabel it as unanswered | Z1 → "C1-1 (direct): the deadline ends a socket the app already closed without relabelling it as unanswered" |
| T3 (Info): no check that an early key frame on CLOSING or CLOSED writes no transcript line. Y1 survived | **Bound.** Both cases compare the whole log text (folds included) before and after | Y1 → "E (CLOSING): nothing is narrated (the whole log, folds included)"; M4 now also RED on "E (CLOSED): nothing is narrated after the close" |
| Nit: the e2e's `#toRoom` reset was labelled "‹ Back to room" | Reworded | — |
| Nit: `newLog` folds in forced-late-answer | Noted; no `newLog` check was added for the early cases. psecond compares the whole log (`logUnchanged`) | — |

The original mutants M1–M11 were re-run on this round's app.js. All are
still RED, some now on the stricter log checks (M3/M5 on "E (CLOSING):
nothing is narrated", M4 on "E (CLOSED): nothing is narrated").

Not covered, as in the report: Safari/WebKit, the Android WebView,
PQKEM/OTP in a browser, group rooms (the premise depends on the two-member
room cap).
