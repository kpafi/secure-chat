# Connect C3-2 — fix round 2 (triage of pentest round 2)

Scope: `connect-cancel-c3-2-pentest-r2.md` against 9f290f3.

The verdict there: the change does what it claims and introduces nothing
Critical, High, Medium or Low. R1-1, R1-3 and R1-4 are closed. The report
raised one behaviour Info (R2-1), four test-quality Infos (R2-2 to R2-5), and
one pre-existing Low lead outside the diff. This round changes no code: one
comment, tests, and the e2e.

| Finding | Verdict | Bound by (mutant → red check) |
| --- | --- | --- |
| R2-1 (Info): on CLOSING, a withheld `pending` leaves `wasPending` false, so a `joined:guest` behind it is refused as unqueued | **Kept, stated and bound.** From the page's own view the sentence is true: it sent no knock, so no owner can have approved it. An honest relay cannot produce the sequence, since it has no knock to forward. A relay gets the same sentence on OPEN by sending `joined:guest` without `pending`. The `joined` comment now says so. | X1 (the withheld `pending` writes `wasPending`) → "R2-1 (pending, joined:guest on a CLOSING socket): Connect is enabled again" |
| R2-2 (Info, test gap): Cancel after a withheld `pending` was checked visible but not working | **Bound.** The Cancel-on-CLOSING block now runs for `joined:owner` and for `pending`, and asserts that the socket is still CLOSING when the room screen is back | X4 (the withheld `pending` sets `roomRole`: Cancel shown but inert) → "C3-2 (Cancel on a CLOSING socket after {"type":"pending"}): Connect is enabled again" |
| R2-3 (Info, test quality): the e2e "late pending is not narrated" check was vacuous, because `addLine` folds a repeated line into "(×2)" in place | **Fixed.** The owner and pending cases now compare the whole log's text before and after | e2e against a scratch copy with X21 (a late `pending` narrated, room screen kept): 12/13, "the late pending is not narrated (the log is unchanged…)" fails. b88afa8 now fails that check too (10/13) |
| R2-4 (Info, test quality): `/connected\|waiting for approval/` also matched "disconnected" | **Fixed:** anchored | X11 / X12 (end a CLOSING answer at once) are now RED on the meaningful check, "Cancel stays offered on the CLOSING socket", not on the regex |
| R2-5 (Info, test gap, b88afa8's line): the role change before any seat (`pending` → `joined:owner`) was unbound | **Bound:** the sentence, and no hello | X13 (the role-change check keyed on `joined`) → "role change before the seat: the room screen is shown" |
| Test gap 5, the e2e fixture | **Tightened.** The prompt must go up before `close-event` and come down only after it. In the pguest case, the honest `pending`'s knock must reach the relay | 13/13 on this round; 7/13 on 495a12f; 10/13 on b88afa8 |
| Pre-existing lead (Low, Chromium): a guest approval prompt raised before any answer to `join` is invisible, because `#admit` lives in the hidden chat screen, and the tab bar goes inert. Cancel works | **Not in this branch: an owner decision.** Draw the prompt over the room screen, or refuse or defer a handshake that arrives before the answer. It is the lever that makes R1-2 deterministic | — |

## Mutants of this round

Each mutant ran against `node app-connect-cancel.test.mjs`, with `app.js` compared by `cmp` against the fix after each one.

- **X1, X4, X11, X12, X13:** RED.
- **Round 1, re-run:** R1–R14, R16, R17 RED. R15 survives alone (the layered connectInner reset). R6M5 / R6M5R15 are RED on different checks, as before.
