# Connect deadline + Cancel — fix round 3 (triage of pentest round 3)

Scope: `connect-cancel-pentest-r3.md` against 40d4077 (fix round 2: the four
refusals of the relay's answer end through `endUnanswered`). Verdict there:
C2-1 closed (Chromium: 0.3 s, was 60.4 s); nothing new at Critical, High,
Medium or Low; H1–H4 red, the pentester's H6–H10 red, H5 equivalent; no
non-equivalent survivor. **This closes the review: nothing Low+ is open.**

| Finding | Verdict | Bound by |
| --- | --- | --- |
| C3-1 (Info): `endUnanswered` is also reached for a RUNNING session (a role-less `joined` injected mid-session hits the older-relay refusal); the comment's premise "nothing of a session can be in flight before the relay answered" is false there | **Comment corrected** to the argument that carries: the lock goes only after every save under it settled, no save starts once it is closing (`persistOtpProgress` checks `lock.closing`), the retired socket delivers, decrypts and sends nothing. The behaviour is unchanged — the pentester executed it with an OTP save in flight: the lock waited, nothing was sent or shown late, the pad reconnected cleanly | comment only (no mutant) |
| C3-2 (Info, pre-existing lead, stub only — not reproduced in Chromium in 20 tries): a `joined` handled after the relay's own close leaves stale state (a "connected" chat screen over a dead socket; `joined = true` surviving into the next session and silencing its `denied`) | **Not in this change** — pre-existing and outside the connect deadline; flagged as its own task (the hardening the report suggests: `joined` returns unless the socket is OPEN, set `joined` after the role checks, reset it in `connectInner`) | — |
| C2-2 (r2, residual) | The decision stands; the reason, corrected per the pentester: a softer sentence would give a relay nothing (the refusal happens whatever the wording) — it stays because in the invitee-connected-first case "press New code" is the right advice | — |
