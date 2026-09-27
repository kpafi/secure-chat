# Connect deadline + Cancel — fix round 1 (triage of pentest round 1)

Scope: `connect-cancel-pentest-r1.md` against 86a8b03 (the join/lookup deadlines
and the room screen's Cancel, pentest r6 R6-1 / r7 R7-3 of the OTP transfer
sheets). Verdict there: nothing Critical/High/Medium; two Lows in the window
between `closeWs()` and `onclose`, two Infos, three surviving mutants.

## The one root cause of C1-1 and C1-2

Cancel and the deadline ended an unanswered attempt only through `closeWs()`,
which starts the closing handshake; the room screen, Connect, the pad lock and
the Cancel's own visibility came back only in `onclose`. Against a peer that
never answers the Close frame (a hostile relay, a half-open connection),
Chromium fires `close` after its 60 s closing timeout — and the 30 s deadline
fired into the closing socket and re-closed it with its own sentence, over the
refusal that had closed it. Neither test saw it: the stub runs `onclose` inside
`close()`, and the e2e proxy (`ws`) answers Close frames by itself.

**Fix: `endUnanswered(sock, refusal)`.** Used by the deadline and by Cancel's
socket branch, i.e. only while the relay has not answered (`roomRole === null`):

- a socket this app already decided to close (retired) is not closed again, so
  it keeps its own reason (C1-1);
- then its `onclose` runs at once, exactly once: detached from the socket
  (`onclose`, `onerror` = null), so the browser's late close event finds
  nothing and its late "connection error" cannot reach the next attempt's
  status (C1-2). Frames it may still deliver are dropped at dispatch (retired).
- The pad lock still goes through `releaseOtpLockAfterSave()`: before the relay
  answered, no session frame can have been saved; if one were in flight the
  lock would wait for it. The two-time-pad invariant is unchanged.

A socket the relay answered (`pending`, `joined`) is untouched: Disconnect on
the chat screen still waits for the browser's close, as before this branch
(pre-existing, out of scope — noted by the pentest).

## Findings

| Finding | Verdict | Bound by (mutant → red check) |
| --- | --- | --- |
| C1-1 (Low): the deadline overwrote a refusal / a Cancel on a socket still closing | **Fixed** (`endUnanswered` skips `closeWs` for a retired socket) | F2 (re-close a retired socket = the pentest's N7 inverted) → unit "C1-1: after the deadline, the room screen keeps the refusal, not the timeout sentence"; e2e `hung-relay` [5] "C1-1: ...with the refusal's sentence" (Chromium, raw peer that sends `pending` to the creator and never answers Close) |
| C1-2 (Low): Cancel 60 s / deadline 90 s against a peer that never answers Close; Connect disabled, Cancel inert, pad locked meanwhile | **Fixed** (`onclose` run at once, detached) | F1 (no early run) and F5 (Cancel via plain `closeWs`) → unit "C1-2 (Cancel): Connect is enabled again"; F6 (deadline via plain `closeWs`) → "C1-2 (deadline): …"; F3 (`onclose` not detached) and F4 (`onerror` not detached) → "C1-2: the old socket's late error / close do not reach the next attempt"; OTP: "the pad lock to be released while the socket is still closing"; e2e [5]: Cancel back in 0.0 s, the refused creator back at 30.2 s (was 60 s / 90 s) |
| C1-3 (Info): a step that FAILS after a Cancel was still narrated | **Decided per step.** Key setup: silent after a Cancel (`stopped()` at the head of its catch). Pad read: **still narrated** — its failures include the stored pad's tamper / damage warnings, and a Cancel must not silence those (the pentest's own caveat). The commit's claim is corrected here | F7 (no `stopped()` in the key-setup catch) → "C1-3: a key setup failing after the Cancel is not narrated"; F8 (`stopped()` added to the pad-read catch) → "C1-3: a pad read failing after the Cancel is still narrated" |
| C1-4 (Info): Cancel is not immediate across steps that take no signal (pad KDF / IndexedDB in `readPadFresh`, `cipher.init()`) | **Residual, by design** — `connecting` must stay set until `connectInner` returns, or a stale continuation could overlap the next attempt. A hung IndexedDB has no bound here, the same class as the FINISH_WAIT residual | — |
| N1: the focus handoff taken from any element | **Test added** | F9 → "C (N1): a Cancel going away does not take the focus from elsewhere" |
| N2: the lookup sentence not styled as an error | **Test added** (and the join sentence's) | F10 → "L (N2): ...shown as an error" |
| N7: the C1-1 fix untested | **Bound** (F2 above) | — |
| N8, N11 | Equivalent, as the pentest found | — |

## New mutants of this round, all RED

F1–F10 above, plus F11 (`endUnanswered` without its CLOSED check — `onclose`
would run a second time in a browser where it already ran) → red in the J
block. M20 (`connectInner` keeps an old deadline) needed a stronger check once
the deadline could run an `onclose`: the stale timer now ran the OLD socket's
`onclose` over the new attempt, and the test only looked at the old socket and
the sentence; it now asserts the new attempt is untouched ("J: ...and the new
attempt is untouched") and is red. The 29 mutants of 86a8b03 re-run against
this round's code: all RED (patterns updated for `endUnanswered`).
