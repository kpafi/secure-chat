# Connect C3-2 — fix round 1 (triage of pentest round 1)

Scope: `connect-cancel-c3-2-pentest-r1.md` against b88afa8. The verdict there:
the change does what it claims, and nothing Critical, High or Medium was found.
The report changed one premise: a hostile relay can FORCE the order in Chromium
(R1-2), so C3-2 was a reproducible Low, not speculative hardening. It also
raised one Low (R1-1), two Info findings (R1-3, R1-4) and five test gaps.

| Finding | Verdict | Bound by (mutant → red check) |
| --- | --- | --- |
| R1-2 (Info, premise): the relay parks the pump on the guest approval prompt (hello, then a handshake signed by itself, before any answer to `join`), queues its answer and hangs up; onclose settles the prompt, and the answer meets the reset state. Deterministic in Chromium | **Taken.** The `joined` comment now states the lever. The PoC is a committed e2e, `e2e/forced-late-answer.mjs` (static server + raw relay, no backend): on 495a12f 6 of 12 checks fail (owner "connected" on the dead socket, the false unqueued accusation, a late `pending`); on b88afa8 2 fail (`pending`, the role-less refusal); on this round all 12 pass. Its fixture checks that the prompt went up before the close event | e2e as described; unit M0 (495a12f) → "C3-2 (owner seated after the close): the room screen is shown" |
| R1-1 (Low, pre-existing): `pending` handled after the relay's close drew a "waiting for approval" chat for the dead socket, sent a knock into it, and left a Disconnect that did nothing | **Fixed**, the same shape as `joined`. The creator's refusal reads only `sessionRoomMine`, so it is still said after the close. The role, `wasPending`, the chat screen and the knock need an OPEN socket | R1 (guard removed) → "R1-1 (pending after the close): the room screen is shown"; R2 (guard `=== CLOSED`) → "{"type":"pending"} on a CLOSING socket draws no chat screen"; R0 (b88afa8) → R1-1; R11 (the creator refusal after the guard) → "R1-4: pending to the creator after the relay's close is still refused" |
| R1-3 (Info): a seat withheld on CLOSING left `roomRole` null, so the join deadline stayed armed; fired, it said "did not answer" over a reason the relay had parked | **Fixed.** The relay did answer, so both withheld paths (`joined`, `pending`) clear the join deadline. `roomRole` stays null, so Cancel stays offered and ends the attempt at once (N11's alternative would have hidden it). The close event, which Chromium delivers about 2 s after a relay Close without FIN, ends the attempt | R3 / R4 (no `clearJoinTimer` in `joined` / `pending`) → "R1-3: the relay's own reason is on the room screen, not the join timeout"; R7 (= N11) → "Cancel stays offered on the CLOSING socket"; R8 (= N12) → "a seat withheld on CLOSING is not narrated as a session end" |
| R1-4 (Info, claim accuracy): the residual covered three refusals, and "every check reads per-connection state" was wrong for the role-less and creator-as-guest checks | **Fixed by narrowing the drop instead of rewording it.** On a CLOSED socket a check runs if what it reads survives onclose: role-less (`m.role`) and creator-as-guest (`sessionRoomMine`) are said on the room screen, as the L2 "last words" design wants. The CLOSED break sits just before the unqueued-guest check (`wasPending` is onclose's). The role-change check reads `roomRole`, which is null after onclose, so it cannot fire there. Nothing is dropped now except checks that would read wiped state | R5 (the CLOSED break back at the top) → "R1-4: joined without a role after the relay's close is still refused"; R6 (CLOSED break removed) → "not judged on the wiped queue state (after pending)" |
| Test gap 1: the role-change refusal, rewritten by b88afa8, was bound by nothing (N21) | **Bound.** `pending`, `joined:guest`, then `joined:owner` → the sentence, still one hello | R9 (= N21) → "role change: the room screen is shown"; R10 (`roomRole !== null` dropped) → "fixture: joined moves to the chat screen" |
| Test gap 2: CLOSING semantics (N11, N12) | **Bound** (R7, R8 above) | — |
| Test gaps 3 and 4: no test for R1-1, no e2e for the forced order | **Bound**: unit R1-1 block, and `e2e/forced-late-answer.mjs` | — |
| Test gap 5: the residual choice (N1) | **Bound** (R5 above) | — |

The equivalents and redundancies the report named stay as they are:

- **Equivalents (N2, N3, N5, N16).**
- **The two `joined` resets.** They are belt and braces. R15 (the connectInner reset removed) survives alone. With the CLOSED break and the late `joined = true` removed too, it binds: R6M5 passes the `denied` check and fails the hint check, and R6M5R15 fails "the next session's `denied` is said (after pending)".

## Mutants of this round

Each mutant ran against `node app-connect-cancel.test.mjs`, with `app.js` compared by `cmp` against the fix after each one.

| Mutant | Result |
| --- | --- |
| R1–R14, R16, R17 | RED |
| R15 | Survives alone (layered, as above) |
| R6M5 / R6M5R15 | RED, on different checks (as above) |
| M0 (495a12f) | RED |
| R0 (b88afa8) | RED |

R12 (`joined`'s seat guard `=== CLOSED`) → "{"type":"joined","role":"owner"} on a CLOSING socket draws no chat screen". R13 / R14 (the M-2 checks back to `roomRole`) → the C2-1 cases. R16 (the `roomRole` write dropped) → "C: no Cancel on the room screen of a session the relay answered". R17 (seat guard removed) → the CLOSING chat check.
