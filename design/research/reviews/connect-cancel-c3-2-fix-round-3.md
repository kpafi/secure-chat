# Connect C3-2 — fix round 3 (triage of pentest round 3)

Scope: `connect-cancel-c3-2-pentest-r3.md` against f15825d.

The verdict there: nothing Critical, High, Medium or Low. Keeping R2-1 is
sound: it is now reproduced in Firefox, and the sentence is one the relay can
already get on OPEN and is true from the page's view. Every new assertion
binds on its own. The e2e fixture did not flake (11 runs). This round is tests
only; `client/app.js` is unchanged since f15825d.

| Finding | Verdict | Bound by (mutant → red check) |
| --- | --- | --- |
| R3-1 (Info, test gap): narration on a CLOSING socket was unbound. Firefox reaches that state (the hello-signing await is enough) | **Bound.** The CLOSING loop and the Cancel loop compare the whole log's text across the withheld answer | Y7c (a `pending` withheld on CLOSING narrates "waiting…") → "C3-2 r3 R3-1: ...and narrates nothing — no session start, no waiting line ({"type":"pending"})"; Y11 (a seat withheld on CLOSING narrates "joined room…") → the same check for `joined:owner` |
| Test gap 2 (e2e, cosmetic): the log checks spanned Connect → end, not the late answer alone | **Taken.** The e2e snapshots the log at the close event and compares against that snapshot | e2e mutants on scratch clients: Z1 (a CLOSED owner seat narrated) → 12/13, "the late seat is not narrated"; X21 (a CLOSED `pending` narrated) → 12/13, "the late pending is not narrated"; 495a12f 7/13 and b88afa8 10/13, as before |
| Test gap 3: the e2e is Chromium-only; Firefox's CLOSING behaviour is covered by the stub tests alone | **Residual, documented.** The pentester's Firefox PoC agrees with the stub tests. A Firefox pass/fail suite would need a different lever (the close event precedes the prompt there) | — |
| Pre-existing Low lead: the invisible guest prompt before any answer to `join` | **Unchanged: an owner decision.** Flagged as a separate task | — |

Mutants of this round, each run against `app-connect-cancel.test.mjs` with `cmp` restores: Y7c and Y11 are RED; X1, X4 and X13 are re-run and RED. `npm test` is green.

No pentest round 4 was run: the round changes only tests, and every new check was shown to bind by hand-run mutants.
