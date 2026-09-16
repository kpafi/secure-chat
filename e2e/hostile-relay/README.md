# hostile-relay — the F-PROTO-001 regression test

The client-side admission control has no unit-test surface (it lives in
`app.js`'s relay-message path), and the finding it exists for is only reachable
through a relay that lies. So it is tested here, against real browsers.

`hostile.mjs` serves the real client from `client/` and speaks the relay's
websocket protocol at `/ws` on the same origin, so the browser runs the
**shipped** `app.js` against a hostile relay. `proto001.mjs` drives two peers
through it and asserts; it exits non-zero on failure.

```bash
# positive control — a normal session must complete, or nothing below counts.
# SCENARIO=control is REQUIRED: it selects the control assertions, and the
# relay must be POLICY=honest. Expect 5/5.
POLICY=honest node e2e/hostile-relay/hostile.mjs &
SCENARIO=control node e2e/hostile-relay/proto001.mjs

# the attack: both parties told they are guests, so nobody is ever asked.
# Restart hostile.mjs with the new POLICY — it is read once, at startup.
POLICY=demote node e2e/hostile-relay/hostile.mjs &
node e2e/hostile-relay/proto001.mjs                    # both peers shipped, 9/9
SCENARIO=attacker node e2e/hostile-relay/proto001.mjs  # peer runs a patched client, 9/9

# item 14 end to end: the DIRECTORY lies. Needs DIRECTORY=hostile, which is read
# at startup like POLICY. Expect 13/13.
POLICY=demote DIRECTORY=hostile node e2e/hostile-relay/hostile.mjs &
SCENARIO=directory node e2e/hostile-relay/proto001.mjs
```

`DIRECTORY` defaults to `honest`. Under `hostile` the relay answers a lookup for
ANY handle with a DIFFERENT registered identity's bundle — "you asked for bob,
here are mallory's keys" — which is precisely the answer item 14's deleted route
treated as grounds to skip the approval prompt. `SCENARIO=directory` has the peer
register as `mallory`, has the victim look up `bob#harnesstoken`, and asserts the
victim is asked anyway. Until this existed, `expectedPeerBundle` was null in every
run of this harness and the entire directory-driven flow was invisible end to end
(pentest item 8); item 14 could only be argued at the unit level.

If `DIRECTORY=hostile` is set but only one identity has registered, there is no
other bundle to lie with — the relay logs that the lookup was answered honestly
and that the run proves nothing, rather than quietly turning the attack into a
control.

`SCENARIO` defaults to `shipped`. Running the control without it (as this file
told you to until 2026-08-10) runs the ATTACK assertions against an HONEST relay:
it fails 3/9 with messages that read as *the fix is broken* rather than *you
invoked it wrong*. That is pentest item 20, and it is fixed here rather than
being left as folklore, because the whole value of a positive control is that a
person under time pressure can trust what it prints.

No backend is needed: identities are created locally and a live room touches no
account API. Chromium comes from `$CHROMIUM` (default `/usr/bin/chromium`).

## The property under test

> A handshake from an identity no human on **this device** approved never
> establishes a channel — whatever the relay says, and whatever the peer's
> client does.

The two scenarios exist because the interesting endpoint differs. The peer that
*answers* the hello sends the first handshake, so its receiver is the one that
must prompt; the sender then stalls at hello with an open socket, which is not a
second stopping point but this one seen from the other end. `SCENARIO=attacker`
patches the peer so it answers with a handshake of its own
(`EVIL_MODE=autoapprove`), which puts the shipped client in the receiving seat.
That scenario is the direct regression for the 2026-08-07 admission proof, which
an attacker defeated by signing one for its victim.

## Why it is built the way it is

* **The positive control is not optional.** It caught a harness bug on its first
  run: the relay handed out `jid`s like `j2`, and `queueKnock` drops any knock
  whose jid is not 16 hex chars — so the owner's approval prompt never appeared
  and the run looked like a refusal that had nothing to do with the finding.
* **`demote` routes `key`/`msg` frames unconditionally**, without consulting its
  own seat bookkeeping. A hostile relay has no reason to keep that bookkeeping,
  and a harness that does will stall both victims for the *attacker's* reasons
  before the client's check is ever reached — which looks exactly like a fix
  that works. This is what hid the answer in the first place.
* **The attacker patch is checked against an anchor and throws if it misses**, so
  an attacker that quietly stopped attacking cannot report a green. The same
  trap bit once already: a first cut only skipped the victim's prompt block,
  which left `approvedBundle` null so the patched client refused *itself* and
  proved nothing.
* **Frames are logged on both sides** — the relay logs what it routed, and each
  page wraps `window.WebSocket` at document-start so the client's own view is
  recorded and decoded (`hello`, `handshake`, `confirm`). The original harness
  logged only join/knock, so "no key frames in the log" proved nothing either
  way.
* **Prompts are identified by MODE, not by visibility** (item 20, 2026-08-10).
  `#admit` is shared by the owner's knock prompt and the guest's peer-approval
  prompt, so "is `#admit` un-hidden" cannot tell them apart. The victim-selection
  heuristic used to be exactly that, and the check "the peer that received a
  handshake ASKS its user" went GREEN against the OWNER's knock prompt — the
  fourth instance of the false-green class this list catalogues, and the reason
  the list exists. `app.js` now sets `#admit`'s `data-mode` to `knock` or `peer`,
  and every assertion here checks that marker **and** the visible button label
  ("Let them in" vs "Connect"), so a marker that drifts away from what the user
  is shown fails instead of passing.
* **A prompt that never appears fails, it does not skip.** The refusal checks
  used to sit behind `if (promptShown)`, so when no prompt appeared they vanished
  from the run and the summary still read as a pass. They now report NOT RUN and
  fail, and the check count is the same either way.

## Results, 2026-08-10 (re-run after the item 20 fix)

| run | result |
| --- | --- |
| `POLICY=honest SCENARIO=control` | **5/5** — full session, both peers reach the same safety number |
| `POLICY=demote`, both shipped | **9/9** — the receiving peer (`peer`) prompts in `peer` mode, neither side reaches a safety number or messaging unanswered, and refusing disconnects |
| `POLICY=demote SCENARIO=attacker` | **9/9** — the shipped client (`alice`) still prompts against a peer that approves itself and sends a confirm tag |
| `POLICY=honest` with **no** `SCENARIO` (the old wrong recipe) | **3/9**, preceded by an explicit "this is a wrong invocation, not a broken fix" banner |

The attack runs are 9, not the 8 recorded on 2026-08-08: the extra check asserts
that the prompt the marker calls `peer` is also the one the user sees ("Connect"),
so the marker and the label cannot diverge unnoticed. Note the victim differs
between the two attack runs — `peer` under `demote`, `alice` under `attacker` —
which is the point of selecting on mode rather than on visibility.

Against the **previous** (2026-08-07) admission-proof control the attacker
scenario failed: the victim accepted a self-signed admission and reached the
safety-number screen with nobody having approved anything.

## The crypto layer: `tamper.mjs` + `crypto-tamper.mjs` (Phase-7 pentest, 2026-09-16)

`hostile.mjs` forwards every `key`/`msg` frame verbatim — it attacks roles and
the directory, never the key material. Promise #1 of the pentest brief (a
hostile relay cannot read, forge, replay or undetectably tamper with a
conversation) therefore had no end-to-end control at all (F-P7-A8). `tamper.mjs`
is a relay with HONEST role assignment that changes exactly one thing per mode:
`keysub`, `idbswap`, `idbstrip` (the P-03 bundle binding, live), `ctflip`,
`msgreplay`, `confirmpre` (F-P7-19), `algflood` (F-P7-7), `msgflood` (the
transcript must keep its security lines under a junk flood) and `confirmpost`
(the half of F-P7-19 that cannot be fixed: an expected, loud, relay-blaming
teardown). `crypto-tamper.mjs`
spawns it per mode on its own port, drives two real browsers, and asserts what
the shipped client must show — a loud `handshake signature INVALID` and no
sending for the three key attacks, `undecryptable` and no plaintext for the
tampered frame, exactly one render for the replayed one, an intact session and
no blamed peer for confirm tags injected BEFORE the chains exist (and a loud,
relay-blaming teardown for tags injected after — that half is availability
only and is asserted as expected), a bounded transcript with one refusal line
under the alg flood, and the approval/pin lines still present under a junk
message flood.

```bash
node e2e/hostile-relay/run-scenarios.mjs              # all four role/directory scenarios, unattended
node e2e/hostile-relay/crypto-tamper.mjs              # every mode, exits non-zero on failure
EVIL=idbswap MODE=PQKEM node e2e/hostile-relay/crypto-tamper.mjs
```
