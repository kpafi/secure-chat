# Connect deadline + Cancel — fix round 2 (triage of pentest round 2)

Scope: `connect-cancel-pentest-r2.md` against 0e31034 (fix round 1:
`endUnanswered`). Verdict there: C1-1 and C1-2 closed for the deadline and
Cancel; the early `onclose` on a still-closing socket is safe (no frame, send,
decrypt or save on that socket afterwards; the pad lock waits for saves — G4
red); nothing Critical/High/Medium; one Low (C2-1), one Info (C2-2), no
non-equivalent surviving mutant.

| Finding | Verdict | Bound by (mutant → red check) |
| --- | --- | --- |
| C2-1 (Low, pre-existing): a refusal of the relay's answer to `join` — some after `roomRole` is set, all before the chat screen — waited for the browser's close; against a peer that never answers the Close the user sat 60 s on the room screen with no Cancel, no Disconnect, "connecting…", an OTP pad locked | **Fixed**: the four refusals of the answer end through `endUnanswered` — `pending` to the creator (F-PROTO-001), `joined` with no role (older relay), the creator seated as a guest, a guest seated without queueing (M-2). Refusals later in the session come after the chat screen (Disconnect is there) and are unchanged; the removed-mode refusal of a `key` frame before the answer keeps `closeWs` (roomRole is null there, so Cancel and the deadline reach it — it is now the C1-1 test's refusal) | H1–H4 (each site back to `closeWs`) → unit "C2-1 (<case>): Connect is enabled again"; e2e `hung-relay` [5]: the demoted creator and the unqueued guest are back on the room screen in 0.2 s with their own sentence (was 30.2 s / 60 s) |
| C2-2 (Info, new behaviour): after a Cancel whose Close was lost, an immediate reconnect as the room's creator meets the relay's leftover seat of the first socket (until its ping drops it, ~40 s) and is refused "You created this code…", whose advice (press New code) is wrong in that case | **Residual, documented.** It fails closed; the wrong part is advice only, and the same sentence is the F-PROTO-001 refusal, which must not be softened for a relay to exploit. 86a8b03 hid it only because its 60 s wait outlasted the relay's ping | — |

The C1-1 test moved to the removed-mode refusal (a `key` frame with `alg:"RSA"`
before the relay answered): `pending` to the creator, which it used, now ends at
once and no longer reaches the deadline or Cancel. F2 stays red on it.

Mutants of this round: H1–H4 red. Every earlier mutant (M1–M30 without M24,
F1–F11) re-run against this code: all red.
