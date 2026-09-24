# secure-chat — progress log

Working file so any session can pick up where the last left off. Newest notes
at the top of each section. Dates are absolute (YYYY-MM-DD).

## ⮕ RESUME HERE (2026-09-24, 0.3.0 DEPLOYED + the Remove-row fix on `fix/contact-remove-row`, NOT deployed)

**Shipped today.** The contact profile went out as release 0.3.0: PR #1 merged (`963b402`), version
bump + `deploy/deploy-2026-09-24.sh` + `deploy/release-2026-09-24.md` (`829b509`), merged as `a54315f`
= tag `v0.3.0`. Deploy script clean (accounts 31 = 31, public `/healthz` 0.3.0), debug APK
(versionCode 3) installed on the phone with its data kept. 0.2.0 had gone out the day before the
same way (`b9ff13e` = `v0.2.0`). Both are client-only releases; the two `[object Object]` client
fixes on `android-ondevice-2026-09-21` (`c7c9ccc`, `dfadca9`) are still NOT on master.

**The fix on this branch.** The owner opened a verified contact on the phone: the lone Remove,
right-aligned under Message/Unverify, looked off centre. Now centred (and the lone Unverify when
opened from a conversation, which has no Message); the e2e gained three checks (64) that measure
Remove's centre AND its clearance under the decision row in both phone arms, each shown to bind
by a hand-run mutant. Design critic and pentest pass 7 as agents: no blocker/major, nothing above
Low; record in `design/research/reviews/profile-fix-round-7.md`. Claude Design's canvas was not
updated (no `/design-login` from a non-interactive session) — re-sync the design system from
`client/style.css` when a session with it is available.

**Next.** Merge `fix/contact-remove-row`, release as 0.3.1 (VERSION, versionCode 4, a copy of the
09-24 deploy script with the marker `justify-content: center` on `.contact-remove-row`), deploy,
rebuild the APK. Then decide the master/Phase-7 divergence and the `[object Object]` fixes.

## ⮕ RESUME HERE (2026-09-24, iOS app — branch `claude/vigilant-keller-s9sgs4`, NOT merged, NOT deployed)

**What it is.** An iOS twin of the Android app: `ios/` — a WKWebView shell around the same bundled
client (`../client`, synced into the app at build time), served from `secure-chat://app` by a
`WKURLSchemeHandler`, with the relay config + a frozen pad-floor bridge injected at document start
and the CSP stamped on index.html. Read `ios/README.md` for how it differs from Android: the floor
reaches native code through `window.prompt` (the only synchronous JS→native call WKWebView has),
the HMAC key lives in the Keychain (app-readable, unlike the AndroidKeyStore), `Library/WebKit` is
excluded from backup (Android's allowBackup=false), no FLAG_SECURE (privacy shield window instead;
screenshots cannot be blocked).

**Relay change (must deploy before the app can connect):** `IOS_WEBVIEW_ORIGIN = "secure-chat://app"`
in `backend/config.py` (WS allow-list + CORS), with tests and drift guards (`test_csp_hash.py`
checks the Swift import-map hash and origin constant).

**How it was built.** No Mac here: everything compiles and runs in `.github/workflows/ios.yml`
(Linux gate → macOS: xcodegen, local relay, simulator tests, cold-relaunch storage probe, unsigned
Release IPA; screenshots + test summary force-pushed to `ci/ios-shots` by a separate job). Tests:
unit (relay parsing, floor, scheme handler, bridge protocol), in-page in real WebKit (secure
context + Ed25519, floor bridge incl. poisoning, CSP enforcement, relay reachability, native
dialogs, navigation lock) and a two-user e2e (onboard, register, add by handle, sealed chat both
ways). Reviews: cold critic (correctness/a11y) r1; hot design critic r1–r2 ("meets the bar");
pentest passes 1–4 (`pentest-new-code`), each on the previous pass's fixes. Design rows in the
Claude Design canvas (https://claude.ai/artifact/NhVZuUXfC2FsJf93NBn5H2, "iOS app" row).

**Honest notes.** No finding above Medium in any pass; the one Medium (WebKit storage in iCloud
backups) is fixed. Two of my own fixes regressed and were caught by the next pass (a dialog guard
that silently cancelled a confirm; a crash counter reset that disabled the crash-loop limit) —
both now have tests. Unverified without a device: backup exclusion in a real backup/Quick Start,
whether the app-switcher snapshot contains the keyboard, keychain behaviour under re-signing.
Known design debt and CI notes: end of `ios/README.md`.

**Relay test hangs fixed (same branch).** `backend/tests/test_ws.py` hung intermittently (120 s
to 15+ min, also on master). Two test-harness bugs, both shown by faulthandler stack dumps, neither
in the relay: every test socket had its own event loop (cross-loop wake-ups were lost until a read
timeout fired), and Starlette cancelled the server task on disconnect before the relay's `finally`
could send its notices. Fixed in the harness (shared loop; sessions wait for the handler before
the cancel). 40 consecutive runs of test_ws.py clean (~12 s each). Also a boot-time flake in
`test_accounts.py` (0.0 prune sentinel vs monotonic time). New `.github/workflows/backend.yml`
runs the full relay + client suites on Linux for `backend/` and `client/` changes.

**CI state at hand-off.** Run 9 (0ac36bb): gate green, 41/41 simulator tests, cold relaunch keeps
storage, unsigned Release IPA built (debug hooks absent), screenshots published. 9 runs used about
55 real macOS minutes ≈ 550 billed (10×). Reviews: `design/research/reviews/ios-*.md`.

**Delivery.** CI builds an UNSIGNED IPA (artifact `SecureChat-unsigned-ipa`). Installing needs
either sideloading (AltStore/Sideloadly, free Apple ID, 7-day re-sign) or an Apple Developer
account wired in as signing secrets — the owner's decision. Private repo: macOS minutes bill 10×
(~70–110 billed per run); the workflow only runs on `ios/**`, the workflow file and
`backend/config.py`.

## ⮕ RESUME HERE (2026-09-24, contact profile — branch `claude/user-profile-view-e7qr9y`, NOT merged, NOT deployed)

**What it is.** The owner's ask after testing 0.2.0: tap a saved user's row in Users, the avatar
of a row in Chats, or the name in a conversation → a short profile as a sheet (handle, full
fingerprint, trust mark and warnings, when saved/verified, Message / Verified in person /
Remove). Users rows got lighter (one button; the claim and key-changed lines stay in the list);
Verify and Remove moved into the profile, next to the fingerprint they refer to. Client only —
no relay or protocol change (one exception in scope: `account.vouch` takes an optional abort
signal; `contacts.js` tags its stale-tab refusal `err.code = "STALE"`).

**How it was built.** Brief → Claude Design canvas ("Contact profile" row, updated after the
reviews) → implementation → hot critic, cold critic and pentest in rounds until clean; decisions
and triage in `design/research/reviews/profile-brief.md` and `profile-fix-round-1..6.md`, summary
in `design/research/reviews.md`. e2e `contact-profile.mjs` (61 checks) beside the five existing
runs; all green at the last commit, plus `npm test` and pytest 162.

**Honest notes for the reviewer.** The trust core (Verify marks only the keys on screen) held from
the first pentest pass. Most later findings were in the vouch-retraction bookkeeping the fix rounds
added themselves; one of them (pass 4) was a Medium — a stranger's claimed handle could make us
delete our real vouch — fixed by removing that code, with a mutation-proven regression check;
round 6 then removed the rest of the retraction bookkeeping (vouch only for contacts added by
handle; retract only on the user's own Unverify/Remove). Known limits: end of
`profile-fix-round-6.md`; the clean fix for the vouch ones is a relay-side DELETE that names the
exact vouch.

**Delivery.** Nothing deployed. Review the branch, merge, then relay + client + APK as usual (no
relay change, so the APK is not forced by this change). On the phone: open a contact from each of
the three places, verify one in person, check the Android back button (known: it does not close
the sheet).

## ⮕ RESUME HERE (2026-09-21, the 2026-08-07 pentest: all 14 Medium fixed, NOT deployed)

**Every Medium in `secure-chat-pentest-2026-08-07.md` is fixed on branch
`claude/loving-cannon-ba5tbt`, with a regression test each, verified to FAIL
against the pre-fix code by stashing and re-running (not asserted).** Three
commits, one per cluster (relay, admission/vouch/Android, at-rest). Local gate:
backend full suite green (one pre-existing timing flake in `test_ws.py`
`test_waiters_are_closed_when_the_owner_leaves` — fails under the full run,
passes isolated, unrelated to the diff), client **13 suites**, all five e2e
runs green against a live local relay (`two-user-flow` 8/8, `room-admission`
13/13, `no-dead-ends` 12/12, `all-modes` 32/32, new `hostile-relay` 11/11).
The 18 Low and 15 Info findings in that report were NOT worked (the report
only summarises them; the per-finding files it cites are not in the repo).

**What changed, and the honest calls made:**

1. **Relay (F-RELAY-001/003/004/005/006).** Login is now DUAL-SCHEME:
   `/api/auth/verify` requires an ML-DSA-65 signature beside the Ed25519 one
   (**an Ed25519-only client cannot log in — the APK must ship with the relay**).
   Challenge bucket keyed per USERNAME with a wide per-host bound beside it;
   mailbox POST bucket keyed per RECIPIENT and consumed only after the token
   gate; same-identity re-registration can replace but never remove published
   encryption keys; the `TRUSTED_PROXIES=127.0.0.1` recommendation in
   `config.py` is corrected (the deployed topology already had it unset since
   2026-07-28 — F-RELAY-001 was a stale comment, not a live hole). Not done:
   a signed monotonic counter on registration; the client never rotates its
   encryption keys, so a replayed older *v2* registration is a no-op today.
2. **Admission / vouch / Android (F-PROTO-001/005, F-ANDROID-003).** The room
   CREATOR no longer takes her role from the relay: the client remembers
   whether this page minted the code, and refuses `pending` / `joined:guest`.
   **UX change, deliberate:** a creator whose invitee connected first is now
   refused and told to connect first or make a new code (before, she was
   silently made the guest and nobody approved anybody). Refusal hints now
   survive the socket close (they used to vanish with the chat screen — three
   existing refusals had that bug too). `setVouches` discards a result whose
   keys moved while the fetch was in flight. `FLAG_SECURE` set in
   `MainActivity.onCreate` (**not built here — no SDK in this environment**);
   lock-on-background deliberately NOT done (it ends live sessions; needs a
   timed design and a `lockAll()` first — see android/README.md).
3. **At rest (F-ATREST-001/002/003/004/005/007).** The native floor capture
   moved to `client/nativefloor.js` and now serves, under distinct id
   prefixes, the OTP receive mark, the OTP `exported` flag, and — per identity
   (`sha256(ed public key)`, passed by app.js) — the contact and chat stores.
   The chat store gained the contact store's domain tag / generation / witness
   (two departures, documented in `chats.js`: no CAS refusal on persist because
   two tabs poll the mailbox, and an untagged pre-v2 blob is adopted once
   without a prompt on a device that never ran this code). A gen-less contact
   store is no longer adopted silently (`LEGACY_CONTACTS_ADOPTION`); on Android
   a floor makes it a refusal outright. "Store + witness both deleted" on
   Android is `DELETED_*_ADOPTION`: an explicit **Open anyway** in the Users
   view (new button), because the user's own Forget-then-restore of the same
   identity is the same state as the attack and the floor can never be
   lowered. Pins are marked `revoked` by Unverify/Remove (kept, not deleted, so
   a re-add with new keys still alarms) and the verification gate no longer
   auto-accepts a revoked pin. **Browser residual unchanged and pinned by
   tests:** no floor ⇒ both-restored rewinds undetected, both-deleted is a first
   run (app.js warns when an existing identity finds no store).
   Pad ids are validated to 32 hex chars at import/unlock so a pad file cannot
   address another floor namespace.

**🔧 FIX REVIEW (2026-09-21, pentest-new-code pass over the three commits) — 7
findings, all fixed in a fourth commit.** (1) **Medium, real hole:** chats.js
adopted an untagged blob silently whenever the plaintext epoch marker was
absent — one extra `removeItem` restored the whole of F-ATREST-005 in a
browser (PoC reproduced by the reviewer). Now every untagged chat blob is an
explicit adoption, like contacts; **every existing user sees that prompt once
on upgrade** (Chats view → *Open anyway*). (2) **Dead end:** a chat store that
refused while contacts opened had no visible error and no override (the
button lived in the Users locked panel). The Chats locked panel now shows the
error and its own *Open anyway*, and the per-view unlock status says
"Unlocked, but: …" instead of blank. (3) **New from my fix:** per-username
challenge buckets were an attacker-chosen key space `KeyedRateLimiter` never
pruned (it only dropped FULL idle buckets, and `tokens` is only recomputed in
`allow()`), ~100 MB/day. Buckets are now dropped on idleness alone (idle
longer than a full refill ⇒ indistinguishable from fresh). (4) **New from my
fix:** the ML-DSA verify made `/api/auth/verify` a ~4× louder existence oracle
(15 ms vs 4 ms). The unknown-user path now runs both verifications against a
per-process decoy bundle. (5) `roomCodeMine` was page-instance state and failed
open after a reload + re-paste; minted codes are now also remembered in
localStorage (last 8; attacker-writable, but asymmetric: removal restores
pre-fix behaviour for one code, addition only makes this page refuse). e2e
`hostile-relay.mjs` gained the reload step (11/11). (6) `_USERNAME_RE` used
`match`, and Python `$` matches before a trailing newline: `"alice\n"`
registered as a second row. `fullmatch` now. (7) One *Open anyway* click passed
both flags to both stores; each store now gets exactly the override for the
code it raised, and the browser both-deleted warning is a persistent Users-view
notice, not one transcript line. Tests for 1, 3, 6 and the decoy in 4.

**Pre-fix proofs:** all six relay tests, `hostile-relay.mjs` (3 checks),
F-PROTO-005, F-ATREST-001 (the script stops at its first failure, so -002 is
shown by the same mechanism, not separately), F-ATREST-003/004/007 and
F-ATREST-005 each fail against the stashed pre-fix file.

**Tagged `v0.1.0` on `master` 2026-09-21.** `/healthz` now reports
`config.VERSION` ("0.1.0"), so the running build is one curl away; bump both
together. `e2e/no-dead-ends.mjs` gained the "Open anyway is reachable" check
(16/16; times out against the pre-review client, which is the reviewer's exact
finding). Review decisions confirmed by the user in chat: creator is REFUSED
on demotion (not warned), and the one-time Chats prompt stays.

**Merged to `master` 2026-09-21 (`--no-ff`).** Review guide, deploy order and
the on-device checks are in `deploy/release-2026-09-21.md`; the deploy script
is `deploy/deploy-2026-09-21.sh` (APK FIRST, then the script).

**⬜ DELIVERY — nothing deployed.** In order: (1) review the diff (it touches
the login protocol, at-rest storage, the admission path and the floor module —
the pentest-new-code pass is in this session's notes); (2) merge; (3) deploy
relay + client **together with the APK**: the relay refuses Ed25519-only
logins, so an old APK cannot log in, and the Android client is what gains the
contacts/chats floors; (4) on the phone, no prompt is expected: the existing
contact store is v4-tagged with a generation and gets its floor on the first
persist, and the chat store is untagged and adopts once silently. Only a
pre-2026-07-30 archived contact blob would prompt. (5) Re-run
`android/native-floor-ondevice.mjs` and bump one id per new prefix.


**The last never-started checklist item is done.** The relay is reachable at
`http://626vkwn6znrko2xhorirvv5ttrbzcr3xkdjmk65cks26qkvadplyk5id.onion`
alongside the clearnet site, and a full relay round trip over Tor — including
the P-08 owner-approval flow — is proved from the laptop.

**Shape of it.** Tor 0.4.9.11 on the Debian 13 box publishes one v3 onion
service forwarding to `127.0.0.1:8000` — the *same* uvicorn Caddy proxies to.
Sharing the process is deliberate: rooms, session tokens and login challenges
live in memory, so a second instance would split-brain them (same room id, two
different rooms, one per front end). uvicorn still binds loopback only.

**The decision that mattered: `SECURE_CHAT_TRUSTED_PROXIES` is now UNSET.**
It was `127.0.0.1` so `/api` could rate-limit per client IP behind Caddy. Once
Tor also forwards to that port, loopback stops meaning "came through Caddy" —
the app cannot tell the two apart — so trusting it would let any onion visitor
forge `X-Forwarded-For` and mint a fresh bucket per request. That is **F-03
reopened**, against the anti-enumeration lookup limiter, the challenge limiter
and the mailbox limiter at once. Unset, `client_key()` trusts nobody and
everything keys on one shared bucket: fails closed. Measured on the live onion,
16 parallel lookups, `LOOKUP_RATE_CAPACITY = 10`:

| `X-Forwarded-For` | allowed | 429 |
|---|---|---|
| rotating, 16 distinct values | 10 | 6 |
| fixed, 1 value | 10 | 6 |

Identical, and exactly the bucket capacity — the forged header buys nothing.
Had it been honoured, the rotating run would have scored 16/16, so the probe
distinguishes the two hypotheses on the number alone.

> **🔴 CORRECTION 2026-07-29 — the paragraph above is WRONG and the measurement
> that produced it was inadequate.** `client_key()` does not collapse to one
> bucket; it collapses to **two**, and the client selects which one with a single
> header (`X-Forwarded-For: 127.0.0.1` → `'!untrusted-forwarded'`, anything else
> or absent → `'127.0.0.1'`). Both rows of the table above used `203.0.113.x`,
> which land in the SAME branch, so the probe never separated the hypotheses at
> all — it only ever measured one bucket twice. Every `/api` limiter is 2×, and
> an attacker can starve the bucket honest traffic uses while working the
> uncontended one. See M-1 in `secure-chat-pentest-2026-07-29.md` and item 1 of
> the TODO. The claim is repeated verbatim in `deploy/README.md` and in commit
> `d338e15`'s message; both need the same correction when it is fixed.
>
> **✅ FIXED 2026-07-30.** `client_key()` is now a pure function of the peer: it
> ignores `X-Forwarded-For` entirely when no trusted proxy is configured, so
> there is exactly ONE bucket per peer whatever the headers say. The forgeable
> `peer in hops` detector is gone — with it went L-9, since that predicate was
> also how a remote attacker burned the H-4 warning. Runtime detection of a real
> rewrite now keys on the PORT (uvicorn synthesises `(host, 0)` from a bare-IP
> hop, and no genuine TCP peer has source port 0), which the client cannot set:
> no false positives, so it cannot be provoked. It is explicitly a diagnostic,
> NOT the control — the control is `--no-proxy-headers`, and all three launch
> paths are now held to it by tests, including `deploy/secure-chat.service`,
> which had none. `deploy/README.md` is corrected in place with the third table
> row that separates the hypotheses. Commit `d338e15`'s message cannot be
> rewritten and stays wrong; this note is the correction of record.

**Accepted cost:** the
clearnet side loses per-IP limiting too and shares that global bucket, so one
clearnet abuser can throttle onboarding for everyone. `config.py` already sizes
`REGISTER_RATE_*` for this exact posture. Keeping per-IP limits would need a
Caddy-injected secret header and a code change to `client_key()` — offered and
**not** taken. Tor's `HiddenServicePoWDefensesEnabled 1` is on partly to blunt
the volume attack the shared bucket invites.

**Hardening applied to the tor daemon:** `SOCKSPort 0` (the Debian default
otherwise opens `127.0.0.1:9050` **and a world-writable unix socket** at
`/run/tor/socks` — neither is needed to publish a service, and both would let
any local process route through Tor); `ORPort 0` / `DirPort 0` / `ExitRelay 0`;
and `SafeLogging 1` + `Log warn syslog` so the onion daemon does not reintroduce
the per-connection metadata trail I2 removes everywhere else. Verified after
restart: no 9050, no unix socket, service keys `0600 debian-tor`.

**Verified from the laptop over Tor** (local `tor` as an unprivileged process,
SOCKS on 9050):
- `/healthz` and `/` → 200 on the first attempt.
- **No HSTS on the onion** (correct — `x-forwarded-proto` is absent there, and
  HSTS is meaningless for `.onion`), no `server` header, CSP intact.
- The served assets are the current ones (`CONFIRM_DOMAIN`,
  `sc.contacts.gen.v1`, `sc.otp.wm.v1`, `adoptLegacy`).
- Dev files 404 including the P-10 spellings (`//package.json`,
  `/vendor/lean-qr/package.json`).
- **9/9 relay checks** via `deploy/onion-ws.mjs`: WS upgrade through Tor, owner
  seats first, second peer is *queued not seated* (P-08), knock relayed
  verbatim, admit seats the guest, payloads relayed unchanged both ways,
  **foreign Origin still refused (403)**, absent Origin still accepted.

`deploy/onion-ws.mjs` exists because Node's built-in WebSocket cannot speak
through a SOCKS proxy and `e2e/`'s `puppeteer-core` is gitignored, so it does
SOCKS5 + raw RFC 6455 by hand with no npm dependency. Worth keeping for the same
reason the CDP pad-injection harness was: it tests the deployed thing.

**`deploy/` is new** and holds the unit, the torrc block, and the Caddyfile
**pulled from the running box**, not written from memory, plus the recipe and
the trade-offs.

**Two honest limits.**
1. **This onion is not location-anonymous.** It is colocated with a public
   clearnet site on the same host, so anyone who knows both correlates them, and
   the clearnet site stays an attack surface into the same box. That needs a
   host with no clearnet service, not a config change.
2. **The onion does not fix H-02.** It still serves the JavaScript, so a
   compromised server can still ship backdoored code on the next load. The
   Android app remains the only answer to that. What the onion *does* buy is a
   self-authenticating address (no CA, no DNS) and no client IP at the relay.

**Not done — the Android half.** The app still points at
`https://138-199-144-35.sslip.io`. Pointing it at the onion needs **Orbot** on
the phone (a WebView cannot resolve `.onion` by itself); `RelayUrls.kt` already
accepts `.onion` hosts and `network_security_config.xml` already scopes
cleartext to loopback + `.onion`, so it is an on-device task, not a code change.
The phone was not connected this session.

**Mistake worth recording:** the first unit rewrite used an unquoted heredoc
with `\$ONION`, which wrote the literal string into
`SECURE_CHAT_EXTRA_ORIGINS`. `config._valid_origins()` did exactly its job and
raised at import — so the relay failed to start and the clearnet site was down
for about a minute until the origin was corrected. That fail-closed validator
turned a silent misconfiguration into an immediate, obvious outage, which is the
behaviour its P-15 comment promises. 29 accounts before and after; backups at
`/root/{secure-chat.service,Caddyfile,torrc,accounts.db}.bak-2026-07-28-tor` and
`/root/secure-chat-predeploy-2026-07-28-tor.tar.gz`.

**Not proved:** the counterfactual run (restore `TRUSTED_PROXIES`, watch the
onion score 16/16, revert) was blocked by the sandbox as a live-box hole and was
not worked around. The measured `10` above already separates the hypotheses, but
nobody has *watched* the bypass happen on this deployment.

## ⮕ (superseded) snapshot as of 2026-07-28, every 2026-07-27 pentest finding fixed

**All 4 High, all 7 Medium, and L-1..L-6 from `secure-chat-pentest-2026-07-27.md`
are fixed, with regression tests.** **Committed and pushed 2026-07-28**
(`dc182d7` on `pentest-2026-07-27-fixes`, merged `--no-ff` as `97c0754`; both on
`origin`). **DEPLOYED to Hetzner + APK installed on the phone 2026-07-28** —
backend and client rsynced, `chown securechat` + `systemctl restart`
(relay PID 206611, `--no-proxy-headers` intact), then `adb install -r`
immediately after so the two-client break was never live for more than the
restart. Pre-deploy backups on the box: `/root/accounts.db.bak-2026-07-28-p27`
and `/root/secure-chat-predeploy-2026-07-28-p27.tar.gz`; **28 accounts before
and after**. Verified live over loopback: `/` and `/healthz` 200, and the served
assets are the new ones (`CONFIRM_DOMAIN` in `crypto.js`, `sc.contacts.gen.v1`
in `contacts.js`, `sc.otp.wm.v1` in `otp.js`). Verified on the phone: clean
launch (no `AndroidRuntime`), `sc.identity.v1` / `sc.contacts.v1` /
`sc.chats.v1` / `sc.username.v1` / `sc.lookuptoken.v1` all still present in the
WebView leveldb, relay pref still `https://138-199-144-35.sslip.io`, and
`healthz` 200 from the device.

**Contact-store migration v3→v4 CONFIRMED ON-DEVICE 2026-07-28.** The user
unlocked on the phone; the app opened normally and `sc.contacts.gen.v1` now
exists in the WebView leveldb alongside `sc.contacts.v1`. That is the migration
running forward against a genuine pre-fix store on real hardware — the thing the
unit tests could not prove.

### 🔴 OTP pad migration v2→v3 was BROKEN — found on-device 2026-07-28
**FIXED (`bf6bcd2`), regression-tested, DEPLOYED + APK reinstalled 2026-07-28,
and re-proved on the phone against the fixed client.**

**A pre-fix OTP pad that was ever USED is permanently refused after the upgrade.**
Tested by generating a genuine v2 blob with the pre-fix `otp.js` (from `e86a60b`),
injecting it into the phone's real WebView localStorage over CDP, and calling the
DEPLOYED `unlockPad()`. Result:

| pre-fix v2 pad | legacy `sc.otp.hw.v1` | outcome |
|---|---|---|
| used (`sendOffset` 1234) | present, `1234` | **REFUSED** — *"the rollback record for this pad is missing … exchange a fresh pad"* |
| pristine (`sendOffset` 0) | absent | migrates fine → `v:3`, opaque `sc.otp.wm.v1` written |

**Root cause — `client/otp.js:497-499` contradicts `client/otp.js:511`.**
```js
const knownUsedHere = Number.isInteger(inner.hwSend) || Number.isInteger(inner.hwRecv) ||
  readLegacyHW(padId) > 0 || localStorage.getItem(usedKey(padId)) !== null;
if (outerWm === null && knownUsedHere) throw new Error("the rollback record … is missing");
```
Line 511 already treats `readLegacyHW(padId)` as a legitimate migration floor
(`max(outer, inner, legacy)`), but line 498 treats the mere existence of that
same legacy watermark as proof a v3 record *should* exist, and throws before
reaching it. A pre-fix pad has no `sc.otp.wm.v1` by definition — it predates the
scheme — so every used one hits `outerWm === null && knownUsedHere`.

**Proposed fix: drop `readLegacyHW(padId) > 0` from `knownUsedHere`.** The other
two clauses are the ones that actually catch H-3, and neither false-positives on
a genuine pre-fix pad: `inner.hwSend/hwRecv` live inside the AEAD and exist only
in v3 blobs, and `sc.otp.used.v1.*` is written only by post-fix code. Nothing is
lost — the legacy value still applies as a floor at line 511, and `otp.js:93-95`
already states it is "never load-bearing for a rollback decision on its own"
because it is attacker-writable plaintext. **Do NOT gate on the outer `v` byte
instead** — it is outside the AEAD and `otp.js:466-468` documents that exact
downgrade trap.

**Why the tests missed it:** every pad in `otp-rollback.test.mjs` is built by
`otp.generatePad()` from the NEW module, so it is v3 with a `sc.otp.wm.v1` from
birth. No test ever constructs a v2 blob carrying a legacy `sc.otp.hw.v1`. The
2026-07-28 claim that the migration was "covered by tests" held only for the
pristine case.

**Impact:** fail-CLOSED, so no key material leaks — but anyone holding a pre-fix
pad that has sent even one message is locked out of it and must exchange a fresh
pad in person. **Zero impact on this user right now: the phone has no pads** (the
test pad was removed afterwards; `sc.otp.*` is empty again, verified).

**Fix applied `bf6bcd2`:** the legacy clause is gone from `knownUsedHere`; the
two remaining sources are written only by post-fix code, so neither
false-positives on a genuine pre-fix pad and H-3 still fails closed.
`padWasUsed()` still consults the legacy marker, which is correct — that path is
fail-closed by construction. The regression test reconstructs a real pre-fix pad
and asserts it migrates, that the floor survives as `inner.hwSend`, and that H-3
still bites once the pad is v3; **verified to FAIL before the fix**. Client
suites now 85 checks / 8 suites, backend 129.

**SHIPPED 2026-07-28.** Client-only change, no wire-format or protocol impact, so
this was NOT the two-client break P-08 and key confirmation were. Deployed via
the safe rsync recipe — **exactly one content transfer, `client/otp.js`** —
`chown securechat` + restart; backups `/root/accounts.db.bak-2026-07-28-otpfix`
and `/root/secure-chat-predeploy-2026-07-28-otpfix.tar.gz`; **28 accounts before
and after**; `/` and `/healthz` 200. APK rebuilt (`syncWebClient` picked it up,
`assets/web/otp.js` byte-identical to source and verified BEFORE installing),
`adb install -r` → Success, clean launch.

**Re-proved on real hardware against the FIXED client** by re-injecting the very
pad that had been refused:

| check | result |
|---|---|
| used pre-fix pad (`sendOffset` 1234, legacy hw 1234) | **migrates** → `v:3`, opaque `sc.otp.wm.v1` written |
| offsets preserved through the migration | `sendOffset` 1234, `recvHighWater` 777 |
| re-unlock after migration | still 1234 / 777 |
| delete the watermark post-migration (the H-3 PoC) | **still REFUSED** — the fix did not buy migration at H-3's expense |

**CORRECTION — "H-3 still fails closed" was overstated.** `bf6bcd2`'s commit
message and the row above claim it without qualification; the `pentest-new-code`
review of that diff (2026-07-28) showed it holds **for v3 blobs only**. On a
**v2-shaped** blob there is no `inner.hwSend`, so the whole evidence set is
`sc.otp.used.v1` — one deletable plaintext key — and H-3 is bypassable. See F-1
below. The review confirmed against `bf6bcd2^` that this is **pre-existing and
not a regression**: the old `readLegacyHW` clause was defeated just as cheaply by
deleting `sc.otp.hw.v1`. It also proved the fix **never lowers a floor** in any
attacker-reachable state. So the fix is sound; the claim around it was too broad.

Test residue removed afterwards; `sc.otp.*` is empty again and the phone is back
to exactly its six real keys, verified. Repro tooling kept in the session
scratchpad (`make-v2-pad.mjs`, `migrate-on-phone.mjs`, `h3-still-closed.mjs`,
`cleanup-phone.mjs` — pre-fix `otp.js` from `e86a60b`, CDP over `adb forward` to
`webview_devtools_remote_*`). **That injection harness is the thing worth
keeping**: it is what caught a bug six suites of unit tests could not, because
every unit test builds its pad with the CURRENT code.

**BREAKING protocol change again** (third one, after handshake v3 and P-08): a
key-confirmation frame now gates the verification step, so relay and client are
fine but two CLIENTS must both be new — an old client never sends `confirm`, so
a new peer waits at "Confirming that both sides derived the same key…" forever.
Deploy the client and rebuild the APK together, exactly as for P-08.

Storage formats bumped: contact store **v3 → v4** (adds an authenticated
generation counter + a `sc.contacts.gen.v1` witness), OTP pad blob **v2 → v3**
(watermarks and `exported` move inside the AEAD, new `sc.otp.wm.v1.<id>` record).
Both migrate forward on first unlock and both are covered by tests; a genuine
pre-fix store is adopted, not rejected.

What was done, by finding:
- **H-4** `main.py`'s `uvicorn.run()` now passes `proxy_headers=False` +
  `forwarded_allow_ips=[]` (it did not), and `accounts.client_key` additionally
  DETECTS a rewrite (peer address appearing among the client-supplied hops) and
  falls back to one shared bucket, so no launcher can reopen it.
  **CORRECTION (2026-07-28): this never affected Hetzner, and the earlier note
  here claiming "the live relay is still running the old launcher — restart it"
  was wrong.** It was written from the finding's wording without checking the
  box. Verified on `138.199.144.35`: the systemd `ExecStart` is
  `/opt/secure-chat/venv/bin/python -m uvicorn main:app … --no-proxy-headers …`
  with `Environment=SECURE_CHAT_TRUSTED_PROXIES=127.0.0.1`, and the running
  process (PID 192873, started 2026-07-27 19:35) carries both. Production has
  never used the `python main.py` launcher, so `main.py`'s `uvicorn.run()` args
  are dead code there — a restart could not have applied this fix, and no
  restart was performed. The F-03 defense has been live since 2026-07-25 (see
  the systemd-unit edit at the 2026-07-25 entry, incl. the through-Caddy test
  that a rotating spoofed `X-Forwarded-For` still gets 429 after 10).
  The finding itself was real but scoped to the **local** dev relay: the pentest
  report's own rules-of-engagement note identifies it as the pre-existing
  `python3 main.py` (PID 15001) that held local :8000, and its executive summary
  states production was never contacted. §H-4 called that instance "live", and
  its remediation step hedged accordingly ("or is actually run via `run.sh`").
  The `client_key` half IS genuinely undeployed and ships with the next normal
  deploy — it is defense-in-depth against a future misconfigured launcher, not
  protection against anything running today.
- **H-1 + M-4** `unb64`/`b64ToBuf` are canonical-only (decode → re-encode →
  require equality), so the byte-domain/string-domain split is gone. Bundles
  compare on decoded bytes, received bundles are canonicalized at the handshake
  and knock boundaries, the DHKE reflection guard compares the POINT, and
  `_b64decode_fixed` closes the same hole server-side at registration.
- **H-2 + L-1** `migrateLegacyPins()` is gone (it laundered plaintext pins into
  the authenticated store on every unlock); the plaintext key is now only
  deleted, never read. Contact store gained a monotonic generation + AEAD
  witness: rollback, deletion, and witness removal all fail closed, and
  `hasStore()` reports "expected" so app.js takes the loud P-02 path.
- **H-3 + M-7 + L-3** OTP watermark is an AEAD record under the pad's at-rest
  key, covers send AND recv, is mirrored inside the blob (max wins), and a pad
  that has demonstrably run here but cannot produce a watermark fails closed.
  `exported` moved inside the AEAD. One plaintext marker remains, deliberately:
  `importPad` holds only the transfer passphrase and cannot open the record —
  documented in `padWasUsed`.
- **M-2** owner refuses a handshake when it admitted nobody; guest refuses a seat
  it never queued for (`wasPending`), which closes the "tell both sides they are
  guests" variant.
- **M-3** binary frames and deeply-nested JSON are answered politely; client-input
  errors never reach `log.exception`.
- **M-5** explicit key confirmation (HMAC of the initial chain heads under a
  domain-separated context) before verification unlocks. Note the finding's
  route (a) fell out of the H-1 fix, and a local-invariant fix for route (b) is
  IMPOSSIBLE — the honest staggered PQKEM order is indistinguishable from the
  attack from inside one endpoint (see the comment in `_derive`).
- **M-6** `RATCHET_MAX_SKIP` 1024 → 64. The suggested skipped-key cache was
  deliberately NOT taken: it trades a real forward-secrecy property
  (`crypto.test.mjs` asserts a skipped frame stays undecryptable) for speed
  against an adversary the smaller window already handles.
- **M-1** the relay now tells the owner when joins are turned away (batched by
  `TURNAWAY_NOTICE_SEC` so the warning cannot itself be flooded). A per-source
  sub-quota was rejected: behind Tor every peer is loopback, so it would cap the
  whole queue.
- **L-2** an AES256 chat that receives a message with no inner layer now says so.
  **L-4** handle + lookup token are wiped by "Forget identity". **L-5** the OTP
  receive path gained the send path's spent-keystream check. **L-6**
  `dataExtractionRules` disables device-to-device transfer (it copied the pad
  blobs and watermarks to a new phone).

Green: backend **129 passed** (was 121; +8 new), `client` `npm test` 84 checks
across 8 suites incl. the new `canonical-b64.test.mjs`, and all three e2e
harnesses against a scratch relay — **13/13, 8/8, 12/12**. Note for whoever runs
e2e next: point it at a scratch DB *and* set `SECURE_CHAT_EXTRA_ORIGINS` to the
test origin, or the WS allow-list rejects every connection and it looks like a
code bug.

The APK was **built** (not installed) to prove the L-6 manifest change compiles:
`aapt2 dump xmltree` confirms `dataExtractionRules` resolves to the new resource
with the `<device-transfer>` exclusions, and `assets/web/` carries the fixed
client (gradle `syncWebClient` picked it up). Installing is still to do.

One bug was found and fixed in this session's OWN work while re-reading it:
`Room.turnaway_notified_at` defaulted to `0.0`, and `time.monotonic()` counts
from process/boot start — so the very first M-1 notice would have been swallowed
during the relay's first `TURNAWAY_NOTICE_SEC`. Now `-inf`, with a test.

A reusable `pentest-new-code` agent now lives in `.claude/agents/` (and
`~/.claude/agents/`) — it audits the changed diff rather than the whole system.

## (2026-07-27, P-08 fixed: room entry is now owner-approved)
**User-designed fix for the last accepted-risk finding.** Their proposal: a peer
who joins a chat code it did not create does not get in — the creator gets a
prompt showing that peer's public key and web-of-trust rating and decides.
Implemented, pentested by a separate agent, and driven by two real browser peers.

**BREAKING protocol change** (like handshake v3): relay and client must be
updated together. A new client refuses an old relay's bare `{"joined"}` — no
`role` means no admission control, and silently running the protocol this fix
removes would be the worse failure. Committed and pushed 2026-07-27
(`c753535` + `4a75769` on `master`), and **deployed to Hetzner** (see below).

**PHONE UPDATED 2026-07-27** — it had to be, in the same session: the APK
bundles its own copy of `client/` (gradle copies `../client` into assets), so
between the deploy and the reinstall the installed app was a pre-P-08 client
against a post-P-08 relay — a `join` into an occupied room is answered
`{"type":"pending"}`, which the old client does not understand, so it would
wait forever and never chat. Rebuilt and installed over the top:
`cd ~/secure-chat/android && ANDROID_HOME=$HOME/android-sdk ./gradlew
assembleDebug -Dorg.gradle.java.home=$HOME/jdk-21.0.4+7 && adb install -r
app/build/outputs/apk/debug/app-debug.apk` (`assembleDebug` — a release-signed
APK is rejected as a signature mismatch and forces an uninstall, destroying the
on-device identity). Verified: the APK's `assets/web/app.js` carries
`admittedBundle` BEFORE installing, `adb install -r` → Success, app launches
clean (no `AndroidRuntime` exception), **`sc.identity.v1` / `sc.contacts.v1` /
`sc.chats.v1` all still present** in the WebView leveldb (`adb shell run-as
org.securechat.app`, path is `app_webview/Default/Local Storage/leveldb` — the
`Default/` segment is new vs. what older notes imply), Step 1 renders with the
stored identity LOCKED, and the phone reaches the deployed relay
(`secure_chat_prefs.xml` → `https://138-199-144-35.sslip.io`, `healthz` 200
from the device shell). NOT driven through a full chat on-device — that needs
the identity passphrase, which is the user's.

Incidentally, the 2026-07-25 UI nit below (Unlock should be the primary on a
locked Step 1, not "Continue without an identity") is FIXED — the on-device
screenshot shows Unlock as the blue primary.

**DEPLOYED to Hetzner 2026-07-27** (backend + client via the safe rsync recipe
below, `chown securechat` + `systemctl restart`). Pre-deploy backups on the box:
`/root/accounts.db.bak-2026-07-27-p08` and
`/root/secure-chat-predeploy-2026-07-27-p08.tar.gz`; **28 accounts before and
after**, journal clean, `/` and `/healthz` 200. Verified live against
`wss://138-199-144-35.sslip.io/ws` with a three-step smoke check: owner join →
`{"type":"joined","role":"owner"}`, second join → `{"type":"pending"}` (no
`role`, no member slot), the knock reaching the owner with a 16-hex `jid`, a
waiting socket's `msg` refused `not in room`, and `deny` → `{"type":"denied"}`
+ close. The served assets are the new ones (`admittedBundle` in `app.js`,
`#admitOk` in `index.html`). Backend suite re-run before deploying: **121
passed** (needs a venv from `backend/requirements.lock` — the old one was in a
deleted scratchpad, same trap as `e2e/node_modules`).

**What actually fixes P-08: waiting costs the room nothing.** Membership was
first-come-first-served, so anyone with the room id could take one of the two
slots and lock the invited peer out with `room full`. Now the first joiner OWNS
the room; every later joiner is QUEUED (`{"pending"}`) and consumes no member
slot. `MAX_ROOM_MEMBERS` is enforced at ADMISSION, not at join — that separation
is the fix, not the prompt. Wire: `join` → `{"joined","role":"owner"}` or
`{"pending"}`; the waiter sends `knock` (its opaque self-introduction, forwarded
verbatim with a server-issued 64-bit `jid`); the owner answers `admit`/`deny`.
Relay-side state is a `Conn` object, not the read loop's locals, because a guest
is admitted by the OWNER's coroutine.

**The prompt is not the security boundary — the pin is.** `admittedBundle`
records the identity the owner approved, and the handshake REFUSES any other
identity (`app.js`). Without that, a relay could show the owner a knock from a
trusted contact and then hand the seat to someone else. The knock signature
(`secure-chat/knock/v1`, its own domain so it can never be read as a handshake)
has **no freshness and cannot get any**: the only party who could issue a
challenge is the relay, i.e. the party being constrained. So a hostile relay CAN
replay a genuine knock and make the owner see a real fingerprint — it just
cannot complete that identity's handshake afterwards. The comments say so.

**Three agent-found bugs in my own fix, all real, all fixed** (two rounds — the
agent re-attacked the fixes and found that the first fix had itself introduced a
new primitive):
- **The queue became the new lockout.** A socket that joins and never knocks is
  invisible to the owner — no prompt, no jid, nothing to deny — so 4 silent
  sockets reproduced the exact `room full` lockout for the full 120 s approval
  window. Reproduced by hand before fixing (`INVITED -> room full`). Fixed: a
  queue place is only HELD by an introduction. Un-knocked waiters get
  `KNOCK_TIMEOUT_SEC = 10`, and when the queue is full a newcomer DISPLACES the
  oldest un-knocked waiter; only if every waiter has knocked is a join refused.
  Re-verified: the same PoC now ends `INVITED -> pending`.
- **`decideKnock` moved the pin on every click.** A chat holds two people, so a
  second admit is refused by the relay — but the client had already re-pinned to
  the second knocker, and the peer already in the room then failed the identity
  check and was disconnected *by its own owner*. Fixed: one admit per session
  (`admittedSomeone()` guard + `#admitOk` disabled once someone is in, with the
  reason on screen). The agent flagged this without reproducing it end-to-end and
  said so — it was right on the code.
- **The eviction fix became a weapon of its own (found in round two).** Every
  honest peer is un-knocked for one round trip too — between being told
  `pending` and its knock landing — so an attacker holding the rest of the queue
  could time a join to evict the INVITED peer inside exactly that window,
  before it could introduce itself. ~1 ms on loopback, hundreds of ms over the
  .onion this is meant to run on. Fixed with `KNOCK_GRACE_SEC = 2.0`: nothing is
  displaced before it has had a fair chance to knock, and if that leaves nothing
  displaceable the NEWCOMER is refused rather than an innocent waiter dropped.
  Verified dead by hand: `attacker -> room full`, `invited survived`, and the
  invited peer still completes (`joined, role: guest`).

**One more of my own, found while reading the diff:** the handshake identity
check was gated on `roomRole === "owner"`, and the role comes from the RELAY —
so re-sending `joined` with `role:"guest"` would have switched the check off.
It now keys on `admittedBundle` alone (only ever set by our own click), and the
role is write-once: a role that CHANGES mid-session disconnects.

**Known limits, deliberate (documented, not silently accepted):**
- whoever joins an EMPTY room first owns it, so an attacker who learns a code
  and wins the race owns the room and can refuse everyone;
- four sockets that each knock once still fill the queue and the invited peer
  gets `room full`. The improvement is that this is now VISIBLE and deniable
  (the owner sees four knocks) and costs real connections, where before it was a
  silent 120 s hold — but an automated attacker refills faster than a human
  clicks, so it is mitigation, not closure;
- the owner cannot admit a REPLACEMENT after its peer leaves (one admit per
  session) — the relay sends no "peer left" signal, so the client cannot know
  the slot is free. The UI says to disconnect and start a new chat. Safe, and
  stated rather than silently broken.

All availability-only, all needing the cryptographic room-entry proof P-08 said
it would take. Confidentiality and integrity never depended on any of this.

**What the agent attacked and could NOT break:** waiting-socket isolation (a
knocker receives no `key`/`msg` and cannot send), non-owner and self admit,
forged/cross-room/unknown jids, the envelope rules (`jid` anywhere else is a bad
envelope), knock flooding, the admitted-identity binding ("admit A, route B"
fails closed), client injection via the attacker-controlled knock payload
(every sink is `textContent`, and a bundle is only rendered if `verifyKnock`
passes), protocol skew (old relay refused), I2 (no room ids/payloads/jids
logged), and the eviction path under a 20-socket churn storm (no
use-after-free, no double-close, no admit-vs-evict race — eviction only ever
targets un-knocked sockets, and an admit only ever names a knocked one).

**Green:** backend **121 passed** (was 103; +18 admission tests incl. the
squatter scenario, silent-waiter eviction, the grace that stops eviction being
aimed, non-owner admit, cross-room jid, waiting-peer isolation), client
`npm test` green, both live integration suites
green through the new dance, **`e2e/room-admission.mjs` 13/13** (new: three real
browser peers — owner, invited peer, squatter-who-knocks-first — asserting the
owner sees the knocker's true fingerprint, a waiter gets no key exchange and
cannot send, the squatter is denied, and the invited peer still completes),
two-user-flow 8/8, no-dead-ends 12/12.

**Gotchas for next time.** (1) `e2e/node_modules` was a symlink into a DELETED
session scratchpad — reinstall with `cd e2e && npm install --no-save
puppeteer-core` (it is gitignored). (2) The read loop must re-read `conn` state
AFTER `await receive_text()`: the pre-await snapshot left a just-admitted guest
unable to send, which `test_only_the_owner_may_admit` caught. (3) `#idFingerprint`
carries a `"Your fingerprint: "` label — strip it before comparing in tests.

## (2026-07-27, Android L-10 fixed — installed on the phone)
**The last open code item from the 2026-07-26 pentest is fixed.** `MainActivity`
used to call `addDocumentStartJavaScript` only `if` the WebView supports
`DOCUMENT_START_SCRIPT`, with **no `else`** — on an older WebView the relay
config was never injected, `RELAY` stayed null, and the client loaded anyway:
every fetch/WS went to the app's own unresolvable virtual origin
(`secure-chat.internal`) with an opaque error, and `promptSecret()` stopped
adding `SECRET_PROMPT_MARK`, so **passphrase masking silently degraded to the
substring heuristic F-08 retired**. Two silent failures, one of them security-
relevant.

**Now it refuses to run.** The feature check moved to `onCreate` (before the
relay prompt — it is a device capability, not a relay question) and is re-checked
in `loadWithRelay`, since "Relay settings" re-enters that path. `refuseToRun()`
blanks the WebView to `about:blank` so no half-configured client is left usable
behind the dialog, then shows a non-cancelable dialog naming the cause ("update
Android System WebView") whose only button finishes the activity.

**Plus a belt-and-braces check the finding did not ask for:** `onPageFinished`
evaluates `!!window.__SECURE_CHAT_RELAY__` and refuses if it is not `true`. The
feature check covers the known cause; this covers *any* reason the script did not
run (origin-allow-list mismatch, a WebView that advertises the feature and drops
it) by asking the loaded page itself. `evaluateJavascript` is a shell-level
injection, so the page CSP does not block it. It is scoped to `url == indexUrl`
and latched by `refusedToRun`, so the `about:blank` load cannot re-enter it and
stack dialogs; `refuseToRun` also bails on `isFinishing/isDestroyed` because that
callback is asynchronous.

**NEW test: `UnsupportedWebViewTest`** (Robolectric — its WebView provider
advertises no androidx.webkit features, so simply starting the activity
exercises the unsupported path). Asserts the dialog is shown, that it is OUR
dialog (compares the rendered `android.R.id.message` text — an earlier version
could have passed on the relay-address prompt), and that the WebView loaded
`about:blank` rather than the client. **Verified as a real regression guard:
reverting the fix makes it fail, restoring it makes it pass** (12 tests, 0
failures; the negative control ran both ways).

**Two gotchas worth keeping.** (1) Robolectric could not inflate the activity at
all until `testOptions { unitTests.isIncludeAndroidResources = true }` was added
to `app/build.gradle.kts` — without merged resources it runs in legacy mode and
AppCompat's own drawables are missing (`Resources$NotFoundException` deep inside
`checkVectorDrawableSetup`); `@Config(sdk = [34])` alone did not help. (2) The
dialog is an **androidx** `AlertDialog`, which `ShadowAlertDialog` does not
track — `ShadowDialog.getLatestDialog()` is the one that sees it.

**INSTALLED ON THE PHONE 2026-07-27** (`adb install -r` of the debug APK —
Success), committed on branch `android-l10-fail-loud` (`2ebb0f0`), **not merged
to master and not pushed**. Nothing here touches the backend or the web client,
so **no Hetzner deploy is needed** — this is Android-shell-only. Verified
on-device: the app starts normally on the phone's current WebView (step 1 of 3,
no refusal dialog) and the existing identity survived the update ("Your identity
is locked" — `sc.identity.v1` intact), which is the point of installing
debug-signed; a release-signed APK is rejected as a signature mismatch and would
force an uninstall, destroying the on-device identity.

**What on-device testing did NOT prove.** This phone's WebView supports
`DOCUMENT_START_SCRIPT`, so the refusal path never fired — it is covered only by
`UnsupportedWebViewTest`. And a normal-looking start is equally consistent with
"`verifyRelayConfig` ran and passed" and "it never ran" (e.g. if the
`url == indexUrl` match were ever wrong), because both look identical from
outside. Proving the belt-and-braces check actually fires needs a deliberately
broken build installed temporarily — not done, since it would leave the phone
running a broken app for the duration.

## (2026-07-26, first full pentest of the final product — ALL FIXED)
**Full pentest + remediation in one session.** Report:
`secure-chat-pentest-2026-07-26.md` (findings in §4-6, remediation table in §9).
Method: the two test agents (`e2e/two-user-flow.mjs`) plus a new PQKEM live-room
canary harness drove two real browser peers while **tshark** captured loopback;
four specialist agents then attacked in parallel (packet exploitation + live
relay, whole-codebase review, backend pentest, client-crypto pentest). Every
High/Medium was re-verified by hand — agents were wrong in places (e.g. two
claimed static-path bypass vectors actually 404'd).

**Packet capture result: E2EE was NOT broken.** Zero canary plaintext, keys or
secrets recoverable; wire carries only public keys, dual signatures, random
nonces and unique-IV AES-GCM ciphertext. Active attacks (room hijack, replay,
handshake forgery/downgrade, CSWSH, oversized/malformed frames) all failed
closed. What leaks is **metadata** (room id, usernames, tokens, `alg`, sizes,
timing) — visible here only because loopback is un-TLS'd; in prod (wss/.onion) a
network observer sees none of it, but **the relay operator inherently does**.

**Counts: 0 Critical, 1 High, 6 Medium, 13 Low, 12 Info — all fixed** except
**P-08** (room-slot squatting, availability-only, accepted: a cryptographic
room-entry proof is a protocol change, and a hostile relay can DoS anyway) and
the two Android Lows (need an on-device cycle).

**The High (P-01) is worth remembering:** OTP pad `role`/`padId`/`regionSize`
sat OUTSIDE the AES-GCM tag, so a one-byte localStorage edit (`"role":1`→`0`)
pointed the sender at the peer's pad region — a full two-time pad, no passphrase
needed — and re-keying a blob under a fresh `padId` walked around the M-01
watermark. Stored blobs are now **v2**: everything security-relevant is inside
the AEAD, `unlockPad` asserts `inner.padId === requestedId`, the watermark is
keyed by the REQUESTED id, and v1 blobs migrate on first unlock. **Honest
residual: migration cannot retroactively detect tampering done while a blob was
still v1.**

**Other notable fixes.** Handshake transcript → **v3**, now binding the signer's
own bundle via a fixed-length `Identity.bundleDigest()` (a digest, not the raw
`_bundleBytes`, whose length varies 1984↔3233 and would have reintroduced the
F-07 splice ambiguity) — a relay swapping a peer's `ecdh`/`mlkem` now fails the
signature instead of relying on the human safety-number check. OTP consumption is
**write-ahead + fail-closed**. `forgetPad` KEEPS the watermark (forget+re-import
was the easiest route to a two-time pad, reachable by accident). Contact-store
unlock failure no longer silently disables key-change warnings.

**Gotcha found while fixing:** `backend/tests/` had no `conftest.py`, so the
module-global rate limiters leaked state between tests. The new conftest resets
them **and** must set `SECURE_CHAT_DB` *before* anything imports `config` —
otherwise a module-level import there resolves `DB_PATH` to the REAL
`backend/accounts.db` and the suite reads/writes production data (this happened
once; the 24 test accounts + 2 vouches inserted were identified by timestamp and
removed, leaving the 109 genuine accounts intact).

**An independent agent then reviewed the fix diff and caught a HIGH regression in
the P-01 fix itself** (report §9.1). The migration decided "is this legacy?" from
the OUTER, unauthenticated `v` byte — so deleting `"v"` from a v2 blob downgraded
it back to the vulnerable path and handed `role` to the attacker again (PoC:
`baseline role: 1 → ATTACK role: 0`). **Lesson worth keeping: a version/format
discriminator is a security-relevant input; outside the AEAD it silently
re-enabled the exact weakness the change removed.** Now discriminated on the
AUTHENTICATED plaintext (a real v1 payload has no inner `padId`), with a
regression test in `otp-rollback.test.mjs`. The review also produced 2 Medium +
5 Low fixes: the same dict race still live in `KeyedRateLimiter._prune`
(`relay.py` — every /api request hits it); unvalidated peer-chosen `seenIds`;
origin validation crashing the relay at import on a trailing-slash typo (startup
DoS); `otpPersistFailed`'s stop undone by `sendText`'s `finally`; 3 leftover
in-session `algValue()` reads; mailbox polling starving the shared /api bucket
behind Tor (now its own bucket); and P-17's self-test now proving all four keys
(KEM round-trip + ECDH point re-derivation), not just the signing pair.

**SHIPPED 2026-07-26.** Committed on branch `pentest-2026-07-26-fixes`
(`6fb2861`, NOT yet merged to master), APK rebuilt + installed on the phone, and
**deployed to Hetzner** (backend + client, service restarted, 28 accounts intact
before and after; pre-deploy backup `/root/accounts.db.bak-2026-07-26-0212` plus
a full tree snapshot `/root/secure-chat-predeploy-2026-07-26-0212.tar.gz`).
Verified live: `handshake/v3` served, all six dev-file paths 404 while the real
assets 200, a two-peer PQKEM session + the 8/8 two-user flow both green against
`https://138-199-144-35.sslip.io`, and the phone reaching the relay (`healthz
200`, `phoneHandshake: v3`). The two e2e accounts that run created in the LIVE
directory were removed afterwards (back to exactly 28).

**⚠️ The handshake v3 bump is a BREAKING protocol change** — a v3 client cannot
complete a handshake with a v2 one (the transcripts differ, so verification
fails and it surfaces as the "this is what a MITM attempt looks like" error).
Phone and website were therefore updated together, deliberately. Anyone still
running an older bundled APK must update before they can chat.

**Deploy gotchas confirmed this round:** the safe rsync recipe below is correct
and still necessary (a dry-run showed only the 11 changed files transferring, no
`accounts.db`). The APK must be built with `assembleDebug` — the installed app is
debug-signed, so a release-signed APK is rejected as a signature mismatch and
would force an uninstall, **destroying the on-device identity**; data was
verified intact after the update (`sc.identity.v1`, `sc.contacts.v1`,
`sc.chats.v1` all still present). The systemd unit already had both required env
vars (`SECURE_CHAT_TRUSTED_PROXIES=127.0.0.1`, `SECURE_CHAT_EXTRA_ORIGINS=…`);
the new P-15 origin validation was checked against those exact values BEFORE
restarting, since a malformed one would now abort startup.

**Green after fixes (both rounds):** backend 103 passed, client `npm test` green,
two-user-flow 8/8, no-dead-ends 12/12, live PQKEM canary harness green, all
four modes (DHKE/RSA/AES256/PQKEM) verified delivering in a real browser, and the
P-01-downgrade + P-03-bundle-swap PoCs both failing as they should.

## (2026-07-25, Android: duplicate title bar removed)
The app showed TWO stacked "secure-chat" bars — the native ActionBar plus the
web client's own header. **Fixed by dropping the native TITLE, not the bar:**
`supportActionBar?.setDisplayShowTitleEnabled(false)`.

**Why the bar stays.** Both menu items are `showAsAction="never"`, i.e.
overflow-only, and **"Relay settings" is the sole way to fix a wrong relay
address when the page cannot load at all** — hiding the bar would strand the
recovery path. What remains is a background-matched strip with just the ⋮.
Theme now paints the ActionBar / status bar / nav bar in the client's own `bg`
(`#0D1117`, new `app_bg`/`app_fg` colours) with 0dp elevation, so the native
chrome and the page read as one surface instead of two.
Verified on-device: overflow still opens with Reload + Relay settings.
**Gotcha:** `--` is illegal inside an XML comment; referencing the CSS custom
property names in `colors.xml` broke the resource merger.

## ⮕ (2026-07-25) UX pass: comprehension + accessibility
**Feedback from a real user: "hard to understand at first, very technical", and
"joining a live room without generating a code fails with no error message".**

**The missing error was a bug CLASS, not a missing string.** `#hint` lives
inside screen 3 (chat), which is `hidden` while you are on screen 2 — so all TEN
validation failures in `connect()` (empty code, bad code, missing identity, bad
contact handle, directory miss, no OTP pad, pad locked elsewhere, pad exhausted,
setup failure) wrote their message into an invisible element. Only 3 also called
`setStatus()`. **Fix:** `activeHintEl()` routes feedback to whichever screen is
visible (`#idHint` / `#roomHint` / `#hint`), so every call site is fixed at once;
`clearHints()` on screen change stops stale errors following you.

**Scope chosen by the user: reword + progressive disclosure, same screens/flow**
(not a full intent-first redesign — the safety-number gate and pentest fixes stay
exactly where they are).
- **The empty-code dead end is removed, not just explained**: a chat code is
  generated on arrival. `roomCode()` also normalises pasted whitespace/capitals,
  because a code that travels between two people arrives messy.
- **"Room id (64 hex chars)" → "Your chat code — share it with the one person
  you want to talk to"**, with Copy + New code buttons. The user called it a
  "seed", which was the tell that the old term did not land.
- **Encryption picker collapsed behind `<details>` "Security options — currently:
  X"**. Default DHKE. Choosing a non-default mode force-opens the panel and the
  summary names it, so a changed setting can never hide.
- Plain-language labels/errors throughout; "Skip — no identity (AES-256 / OTP
  only)" → "Continue without an identity", and the primary button moved to
  Create/Unlock (it was emphasising the escape hatch).
- **Accessibility:** 7 unlabelled inputs fixed — including `#text`/`#chatText`
  (the two message fields) and the three unlock inputs I shipped unlabelled last
  session. `aria-live` on all 10 status regions (only `#log` had it, so the
  safety number was silent to screen readers). Drawer: `aria-label`,
  `aria-expanded`, `aria-current`, focus into the drawer on open. Focus moves to
  the step heading on navigation — but NOT on first paint (that just drew an
  unrequested focus ring). Base text bumped (hints 0.78→0.84rem).
  **Contrast was already fine** — every token pair passes WCAG AA (4.58:1 to
  12.76:1), so the palette was left alone.

**NEW: `e2e/no-dead-ends.mjs`** — walks every failure path on the room screen and
asserts visible text appears, plus the a11y basics. 12/12. It deliberately reads
ONLY the dynamic feedback elements: an earlier version passed by matching static
help text, which proved nothing.

## ⮕ (2026-07-25) live two-person test: 2 UX/delivery bugs fixed
**A real test run with a second person found two bugs that every unit test and
single-user harness had missed — both about the SECOND user's experience.** Both
are fixed, and a reusable two-agent run now asserts them so they cannot regress.

- **Async chat delivered NOTHING unless the recipient had clicked "Log in".**
  `pollMailbox` needs a directory session (`apiToken`), and that was only ever
  obtained from the explicit Log-in button — registering did not do it. Sending
  worked, receiving did not, with no visible sign. **Fix:** `autoLogin()` runs
  after registration AND after unlocking an already-registered identity, and
  `pollMailbox` re-authenticates on a 401 (sessions last TOKEN_TTL_SEC = 1 h, so
  mail used to stop arriving silently once it expired). `account.fetchMail` now
  surfaces `err.status` so that is detectable.
- **An invite link was unusable in the tab it opens.** A new tab shares
  localStorage but NOT the in-memory unlocked identity, so it always started
  locked — and the only unlock control lived on the Live-room screen. **Fix:**
  Profile / Users / Chats each have an in-place unlock row (passphrase + Unlock,
  Enter submits), sharing a new `unlockWithPassphrase()`; on success the pending
  invite is applied so the handle is prefilled ready to Add.

**NEW: `e2e/` — reusable two-agent end-to-end run** (`node e2e/two-user-flow.mjs`,
relay must be running). Fixed passphrases in `e2e/test-users.json` (throwaway
test values, committed deliberately) so a failing step can be re-driven by hand
in a browser with the same accounts. Asserts: register-is-enough-to-receive,
invite-link-unlockable-in-place, mail from a stranger delivered as ⚪ under a
key-derived name, replies both ways, and 🟢 verification. **8/8 passing.**
Gotcha for whoever extends it: an invite tab must be opened in the SAME
puppeteer browser context (`newTab(label, alice.ctx)`) — a fresh context has no
localStorage and so no identity blob at all, which tests nothing.

## ⮕ (2026-07-25) pentest: ALL 8 findings fixed
**The remaining six findings (F-01, F-03, F-05, F-06, F-07, F-08) are now fixed,
tested and verified against their own PoCs.** See the updated
`secure-chat-pentest-2026-07-25.md`. Backend **103 passed**, client `npm test`
green, Android unit tests green, all browser harnesses green.

- **F-01 (Medium) — contact injection.** The local contact label is now always
  derived from the sender's KEY (`neutralName()` → `unknown-<key>`); the
  self-claimed handle is kept as `claimedName` and rendered as an explicit
  warning row. **Because the local label no longer matches the directory name,
  addressing had to be split out** — contacts carry `addrUsername`, and every
  mail/vouch/lookup site goes through `dirName()`/`mailHandle()`. The PoC now
  yields `unknown-…` contacts; `regress-reply.mjs` proves replies to an
  auto-created contact still reach the right account (otherwise unsolicited
  chats would silently become one-way — the trap in this fix).
- **F-03 (Medium) — rate-limit keying.** No longer relies on uvicorn defaults:
  `run.sh` passes `--no-proxy-headers` and `accounts.client_key()` honours
  `X-Forwarded-For` only from a peer listed in the new
  `SECURE_CHAT_TRUSTED_PROXIES`, taking the RIGHTMOST hop. Default trusts
  nobody → a direct/.onion deploy fails CLOSED (one shared bucket) instead of
  open. **DEPLOY REQUIREMENT: the systemd unit must set
  `SECURE_CHAT_TRUSTED_PROXIES=127.0.0.1` for the Caddy box; leave it UNSET for
  .onion.** New `tests/test_proxy_headers.py`.
- **F-05 (Low)** — auto-created contacts marked `auto:true`, capped at
  `MAX_AUTO_CONTACTS = 50`; past the cap unknown senders are refused and the
  Chats view says why. `regress-cap.mjs`.
- **F-06 (Low)** — each envelope is filed by `processEnvelope()` in its own
  try/catch so one failure cannot discard the rest of an already-deleted batch.
  Defensive: the window was never demonstrated.
- **F-07 (Info)** — `_bundleBytes` asserts all four key lengths
  (32/1952/65/1184); the Users view shows "fingerprint unavailable" instead of
  hanging on "…".
- **F-08 (Info)** — secret prompts now carry an explicit `SECRET_PROMPT_MARK`
  that the Android shell strips and masks on, instead of guessing from the word
  "passphrase" (old check kept as a fail-SECURE fallback). Marker added only
  in-app, so browser dialogs are unchanged.

**SHIPPED 2026-07-25:** pushed (`88225d2`), deployed, APK rebuilt + installed.
**The systemd unit was edited on the box** (backup at
`/root/secure-chat.service.bak-2026-07-25-1617`): added
`Environment=SECURE_CHAT_TRUSTED_PROXIES=127.0.0.1` and `--no-proxy-headers` to
ExecStart — without BOTH, F-03's fix would silently degrade production to a
single global rate-limit bucket. **Any future re-provision of that unit must
carry these two changes.** Verified on the live box THROUGH Caddy (the real
attacker path): rotating a spoofed `X-Forwarded-For` now gets 429 after 10 —
no extra budget — while honest per-IP limiting still works. F-04 still 404s,
DB byte-identical, site 200.

**STILL OPEN (operational, not a code fix):** the phone runs the **DEBUG** APK,
so WebView debugging is live. Switching to the release build needs an uninstall
(different signing key) which **destroys the on-device identity blob and contact
store** — only do it with an exported backup or a fresh identity.

## ⮕ (superseded) snapshot as of 2026-07-25, in-depth pentest: 2 of 8 fixed
**Full-stack pentest run against `4b9f270`; report in
`secure-chat-pentest-2026-07-25.md`. The crypto core held — nothing broke in
the handshake, ratchet, OTP, sealed envelope or web-of-trust. Every finding is
in the layer ABOVE the crypto: the async mailbox treats AUTHENTICATED data (the
sender really signed it) as TRUSTED (they are who they claim, and their values
are well-formed).** Deps clean (`npm audit` 0, `pip-audit` 0); starlette 1.3.1 /
fastapi 0.139.2 / cryptography 49.0.0 close the 2026-07-18 M-01/M-02/L-03.

**SHIPPED 2026-07-25:** pushed (`91dbdf7`), deployed to Hetzner (backend
changed → full chown+restart recipe; DB excluded and confirmed byte-identical
afterwards, pre-deploy backup at `/root/accounts.db.bak-2026-07-25-1603`), and
installed on the phone — F-02 is a CLIENT fix, so the APK rebuild is required,
not optional. Verified live: all three F-04 endpoints return 404 with no
traceback in the journal, and `isValidMode` is present in the deployed and
bundled `chats.js`/`app.js`.

**FIXED + committed this session (both re-verified against their own PoCs):**
- **F-02 (Medium) — chat mode string was unvalidated.** A peer could propose an
  arbitrary `mode`; on accept the header rendered `🔒 AES256 + verified by
  secure-chat` while `hasSecret:false` and NO inner layer was applied (every
  check is an exact `=== "AES256"`). Fix: `chats.MODES`/`isValidMode`
  allow-list, enforced in `setMode`/`setPending`/`ensure` AND dropped at the
  boundary in `app.js handleControl`; `chats.unlock()` sanitises an
  already-poisoned store (bogus mode → SEALED, phantom secret/salt dropped) so
  a victim heals on next unlock. New `client/chats.test.mjs`.
- **F-04 (Low) — `?t=ü` → HTTP 500 + traceback** on `/api/users/{u}`,
  `/api/users/{u}/vouches` and `/api/mailbox/{u}`: `hmac.compare_digest` raises
  TypeError on non-ASCII `str`. Not an existence oracle (both branches raised
  identically), but it broke fail-closed on the token gate and let anyone write
  tracebacks to the journal on demand (vs. I2). Fix: `accounts.token_matches()`
  compares UTF-8 **bytes** — constant-time preserved, decoy preserved. New
  `backend/tests/test_token_gate.py` (22 parametrised cases).

**STILL OPEN (highest first):**
- **F-01 (Medium) — contact injection.** `app.js:1142` derives a new contact's
  USERNAME from the attacker-chosen sealed `name`. PoC put contacts called
  `bank-support` and `alice` (attacker's keys) into the victim's Users+Chats
  lists, needing only the victim's public handle and no registered account. ⚪
  is shown correctly and is the real mitigation. Fix: use the neutral
  key-derived `fallback` name and show the claimed handle as an explicitly
  untrusted "claims to be …" field.
- **F-03 (Medium, deployment-gated) — rate-limit bypass off the proxy.**
  Rotating `X-Forwarded-For` gives a fresh bucket per request (16/16 allowed vs
  10-then-429). **Production is safe** (Caddy appends the real IP; uvicorn 0.51
  resolves rightmost-untrusted). The exposure is the planned `.onion` deploy,
  which forwards onion→127.0.0.1:8000 with no Caddy. Fix BEFORE that ships:
  `--forwarded-allow-ips=` when not behind a trusted proxy.
- **F-05/F-06 (Low)** — uncapped auto-created contacts (~5.9 KB each, ~880 to
  5 MB) and delete-on-read mail vs. unguarded batch processing. NOTE: I tried
  and **failed** to demonstrate the terminal failure for both — treat as
  resilience hardening, not confirmed defects.
- **F-07/F-08 (Info)** — `_bundleBytes` lacks per-field length checks (safe
  today because sizes are fixed); the phone runs the DEBUG APK so WebView
  debugging is live, and the Android passphrase masking is a `contains
  ("passphrase")` string match.

**Verified after the fixes:** backend **99 passed** (was 77; +22 new), client
`npm test` all green incl. the new chats suite, F-02 PoC no longer produces a
proposal, F-04 endpoints return 404 with no traceback, and the LEGITIMATE
AES256 negotiation (propose → accept → inner-layer round trip between two
honest peers) still works. Live-room + async-chat browser harnesses green.

## ⮕ RESUME HERE (snapshot as of 2026-07-25, redesign stage 2: hierarchy pass)
**User asked to continue the redesign; chose "go deeper on the visual design"
over shipping first. Stage 2 is BUILT and VERIFIED locally — deploy + APK
rebuild still PENDING (same rsync as every snapshot below; one rsync covers
all of them).** Presentation-only again: no crypto, no protocol, no new deps,
importmap untouched (`test_csp_hash.py` green).

Where stage 1 (2026-07-19) refreshed *tokens* — colors, radii, shadows — this
pass fixes *hierarchy*, which is what still read as cheap:

- **Dual type stack (the big one).** `--font-ui` (system-ui — NOT a web font,
  so `font-src` stays untouched and the CSP is unchanged) now carries labels,
  prose, buttons and nav; `--font-mono` is reserved for material read or
  compared character-by-character: fingerprints, safety numbers, room ids,
  handles, usernames, cipher specs (`.alg-desc`, `.badge.pq`), `.kv dd`.
  **User explicitly approved this** even though the stage-1 spec said "keep
  monospace" — it's the single biggest reason the UI looked like a terminal
  dump. Opt-in via a `.mono` selector list at the top of `style.css`.
- **Button tiers.** The DEFAULT `button` is now the quiet secondary; a screen
  earns at most ONE `.primary` (gradient blue) — Continue / Connect / Send /
  Add / Open / "It matches — unlock messaging" / Generate pad / Accept. Before,
  every "Copy handle" shouted as loud as "Connect". `.ghost` is now truly
  fill-less; `.danger` is a tinted red OUTLINE instead of a solid red block
  (every danger button is already confirm-gated in app.js). This DELETED the
  per-id overrides (`button#gen`, `#idCreate`, `#idUnlock`, `#otpImport/Export`)
  that existed only to undo the old loud default.
- **Profile view restructured** — `.idhead` (initial avatar + name + handle)
  replaces the flat "Name" row; Keys is a `<dl class="kv">` label/value grid;
  Status is a row of `.chip`s (on/off) instead of a `·`-joined sentence.
- **Drawer** gained a `.drawer-head` (wordmark) and a pinned `.drawer-foot`
  ("Keys never leave this device. The relay sees ciphertext only.").
- **Empty states**: new `emptyRow()` renders a dashed "No users yet" /
  "No chats yet" block in the list well (Users no longer just sets a hint).
- **Trust legend** is a 3-item `.legend` row, not a run-on paragraph.
- **Latent bug fixed:** added a global `[hidden] { display: none !important }`.
  `display:flex/grid` beats the `hidden` attribute's UA `display:none`, so any
  flex container toggled via `.hidden` stayed visible — the drawer had a
  one-off patch for this; the Profile copy-handle actions hit it the moment
  they became `.inline`. Now enforced once, globally.
- `renderHandleInto` switched from `className =` to `classList.toggle("ok")`
  so both call sites keep their own base classes.

**Verified** (harnesses in `scratchpad/verify/`, system Chromium via
puppeteer-core — `shots.mjs`, `flow.mjs`, `live.mjs`):
- Backend **77 passed** (unchanged), client offline `npm test` all green.
- `flow.mjs`: two real peers register + log in against the local relay, add
  each other by handle, verify (🟢), open an async SEALED chat — **bob received
  alice's message**; screenshots of the populated user rows / chat list /
  conversation, desktop + 390×844.
- `live.mjs`: two contexts join one room on AES-256, **both directions
  delivered**, disconnect clean. NOTE: the safety-number gate does NOT appear
  for two fresh unpinned identities (it needs a pinned contact) — that's
  by design; the harness treats it as optional.
- **Zero horizontal overflow** in every view at both widths; no pageerrors.
  Only console error is the known `/favicon.ico` 404.

**DEPLOYED + SHIPPED 2026-07-25.** Pushed to GitHub (`3e20702`), deployed to
Hetzner, and installed on the user's physical phone (Nothing A063 over USB;
`org.securechat.app`, launches clean, screenshot confirms the new type stack
and button tiers on-device). This ALSO finally made the long-pending
**vouch-v2 + mailbox-race backend fix (`a548f56`, pending since 2026-07-19)
live** — verified `vouch/v2` present in the deployed `accounts.py` and
`account.js`. The box had been serving Jul-18 code until now.

### ⚠️ THE OLD DEPLOY RECIPE WAS DESTRUCTIVE — DO NOT USE IT
Every earlier snapshot in this file records this rsync:
`rsync -az --exclude node_modules --exclude 'package*.json' --exclude
'*.test.mjs' --exclude __pycache__ backend client root@…:/opt/secure-chat/`
A `--dry-run` on 2026-07-25 showed it transfers **`backend/accounts.db`**
(plus `.venv/` and `.pytest_cache/`) — i.e. it **overwrites the live account
database with the local dev one**. Local was 327 KB (full of throwaway test
accounts); live was 176 KB. Always `--dry-run --itemize-changes` first.
**Use this instead:**
```
cd ~/secure-chat && rsync -az --itemize-changes \
  --exclude node_modules --exclude 'package*.json' --exclude '*.test.mjs' \
  --exclude __pycache__ --exclude '.venv' --exclude '.pytest_cache' \
  --exclude 'accounts.db*' --exclude '*.db' --exclude '*.db-shm' --exclude '*.db-wal' \
  --exclude 'tests' \
  backend client root@138.199.144.35:/opt/secure-chat/ \
&& ssh root@138.199.144.35 'chown -R securechat:securechat /opt/secure-chat/backend \
   && systemctl restart secure-chat'
```
A pre-deploy backup now exists at `/root/accounts.db.bak-2026-07-25-1333` on
the box. NOTE: `curl` to `https://138.199.144.35` fails from some networks
(direct-IP TLS); SSH works fine — verify over loopback on the box instead
(`ssh … 'curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:8000/'`).

**APK rebuild (worked as documented):**
`cd ~/secure-chat/android && ANDROID_HOME=$HOME/android-sdk ./gradlew
assembleDebug -Dorg.gradle.java.home=$HOME/jdk-21.0.4+7 && adb install -r
app/build/outputs/apk/debug/app-debug.apk`

**Open UI nit found on-device (not yet fixed):** on the Step-1 screen with a
LOCKED stored identity, `#toRoom` ("Skip — no identity (AES-256 / OTP only)")
is the `.primary` while **Unlock** is a quiet secondary — backwards, since
Unlock is what the user wants there. The primary should move to `#idUnlock`
when a locked identity exists. Separately, the Android shell shows a native
ActionBar titled "secure-chat" ABOVE the web header's own wordmark — a
duplicated title bar; consider hiding the native one (pre-existing, not from
the redesign).

## ⮕ RESUME HERE (snapshot as of 2026-07-23, Android polish: icon + release signing)
**Deploy is STILL PENDING** (blocked again this session by the Claude Code
auto-mode permission classifier on SSH/rsync to the Hetzner box — same class of
block noted in earlier sessions, not a new problem). The 2026-07-19 vouch-v2 +
mailbox-race fix (commit `a548f56`, see snapshot below) is confirmed **still
not live** — diffed the deployed `app.js` against local and it's missing the
`ecdh`/`mlkem` binding in the vouch call sites. Run by hand:
`cd ~/secure-chat && rsync -az --exclude node_modules --exclude 'package*.json'
--exclude '*.test.mjs' --exclude __pycache__ backend client
root@138.199.144.35:/opt/secure-chat/ && ssh root@138.199.144.35 'chown -R
securechat:securechat /opt/secure-chat/backend && systemctl restart
secure-chat'`. Then rebuild/reinstall the APK (client changed).

**Android polish, two of three items done this session:**
- **App icon — DONE.** Adaptive icon (API 26+; no legacy PNG mipmaps needed
  since `minSdk = 26` is the same level adaptive icons were introduced at): a
  monochrome padlock reusing the same path language as the drawer's "Live
  room" nav SVG icon, `--bg` dark background (`#0D1117`) with `--accent` blue
  foreground (`#2F81F7`), plus a `<monochrome>` variant for Android 13+ themed
  icons. New files: `android/app/src/main/res/mipmap-anydpi-v26/ic_launcher.xml`
  (+ `_round`), `res/drawable/ic_launcher_{foreground,monochrome}.xml`,
  `res/values/colors.xml`. Manifest wired (`android:icon`/`android:roundIcon`).
- **Release signing config — DONE.** `signingConfigs { release { ... } }` in
  `app/build.gradle.kts` reads `android/keystore.properties` (gitignored) if
  present; falls back to an **unsigned** release build if absent (documented
  in new `android/keystore.properties.example`, committed). Generated a real
  local release keystore this session — `android/release.keystore` (PKCS12,
  RSA-4096, 10000-day validity, alias `secure-chat-release`, pseudonymous DN,
  no real name/org in the cert). **Gotcha:** PKCS12 keystores ignore a
  distinct `-keypass` — store and key password must be identical or the build
  breaks; documented in the `.example` file. Verified: `assembleDebug` +
  `assembleRelease` both build clean, and `apksigner verify --print-certs`
  confirms the release APK is actually signed (cert DN + SHA-256 fingerprint
  printed). **Both `release.keystore` and `keystore.properties` are gitignored
  + chmod 600, never committed. Back them up somewhere durable (password
  manager / offline storage) before ever shipping a signed build — losing
  them breaks the ability to publish updates under the same signature.**
- Side-effect fix: `assembleRelease` runs `lintVitalAnalyzeRelease`, which
  pulled lint/kotlin-compiler/groovy jars not covered by the existing
  `gradle/verification-metadata.xml` checksum allowlist (first time anyone
  ran a release build here — only `assembleDebug` had ever been exercised).
  Fixed the TOFU way this project already uses for dependency verification:
  ran once with `--write-verification-metadata sha256`, then confirmed a
  clean rebuild (`rm -rf app/build && assembleRelease`) passes verification
  normally — not a permanent bypass.
- **On-device verification-gate pass (DHKE/RSA/PQKEM) — STARTED, NOT
  FINISHED, session interrupted.** State left behind: emulator `sc_test` was
  running headless with the new-icon debug APK installed and launched
  (confirmed it resolves/launches); next step is attaching CDP per the
  on-device verify recipe and driving each of the three untested modes
  end-to-end (only AES256 has ever been verified on-device). Check
  `adb devices` first — may need reboot via the recipe further down this file
  / `memory/secure-chat-project.md`.

## ⮕ RESUME HERE (snapshot as of 2026-07-19, pentest: vouch enc-key gap fixed)
**A fresh in-depth pentest found ONE real issue (MEDIUM) plus one LOW; BOTH are
now fixed, tested, and committed — deploy PENDING (permission-blocked, commands
below).** The rest of the stack (relay, C-01 handshake binding, ratchet, OTP,
identity/contacts/chats at-rest, anti-enumeration, CSP/headers) was attacked and
held up.

- **MEDIUM — web-of-trust vouch (🟡) did not authenticate encryption keys
  (the H-01 gap, still open in the WoT path).** `vouchMessageBytes` /
  `_vouch_message` signed only the target's SIGNING keys (ed+mldsa), so a
  malicious directory could serve a genuinely-vouched contact's REAL signing
  keys + its OWN ecdh/mlkem and read every sealed message the victim sent, while
  the 🟡 "vouched by X" mark still displayed. Proven with a live module-level
  PoC (`scratchpad/verify-sc/pentest-vouch-enckey.mjs`): attacker decrypted the
  plaintext; real recipient could not. **Fix (v2 vouch, mirrors the H-01
  fingerprint fix):** the vouch now signs all four keys under a new
  `secure-chat/vouch/v2` domain when the target has encryption keys (legacy
  no-enc targets stay v1). Server (`accounts._vouch_message` + the `/api/vouch`
  handler now selects+binds ecdh/mlkem), client (`account.vouchMessageBytes`
  v2), publish path (`app.js` vouches over the full in-person bundle) and the
  🟡 award check (`refreshVouchMarks` verifies over the full bundle it holds —
  so swapped enc keys fail the signature and no 🟡 is given). Old v1 vouches
  stop lighting 🟡 for enc-key contacts until re-published (correct, safe
  migration). **Verified:** new `client/vouch.test.mjs` (in `npm test`) +
  `backend/tests/test_vouches.py::test_vouch_v2_binds_encryption_keys`; the
  fixed-code PoC (`scratchpad/verify-sc/pentest-vouch-fixed.mjs`) shows the
  poisoned bundle now earns NO 🟡 while the honest bundle still does.
- **LOW — mailbox fetch was a SELECT-then-DELETE race.** `fetch_mail` deleted
  the whole inbox (`WHERE recipient = ?`) after selecting, so an envelope that
  arrived between the two statements (two overlapping fetches, or a POST racing
  the GET; sync endpoints run in a threadpool) was silently lost. **Fix:** delete
  only the specific ids that were read (`mailbox.py`).

**Verified:** backend **77 passed** (was 76; +1 vouch-v2 test), client offline
suites all green (+ `vouch.test.mjs`), CSP-hash test still green (importmap
untouched), and a two-context Chromium smoke run (all views + live AES-256
round-trip + disconnect) green — no regression from the app.js edits.
**PENDING (permission-blocked — run by hand):** deploy backend+client and
restart (backend changed, so the full recipe incl. the `chown securechat` step):
`rsync -az --exclude node_modules --exclude 'package*.json' --exclude
'*.test.mjs' --exclude __pycache__ backend client
root@138.199.144.35:/opt/secure-chat/ && ssh root@138.199.144.35
'chown -R securechat:securechat /opt/secure-chat/backend && systemctl restart
secure-chat'`. Then rebuild+install the APK (client changed). NOTE: this is on
top of the still-pending cosmetic-pass deploy below — one rsync covers both.

## ⮕ RESUME HERE (snapshot as of 2026-07-19, cosmetic polish pass)
**The user-requested cosmetic polish pass ("make it look less cheap") is BUILT
and VERIFIED locally — deploy + APK rebuild still PENDING (this session's
permission system blocked the rsync and the gradle build; run them by hand,
commands below).** Presentation-only, zero logic/crypto changes, importmap
untouched (`test_csp_hash.py` green — no CSP-hash churn):

- **Drawer emojis removed** (`client/index.html`): the four `👤🔒👥💬` labels
  are now **monochrome inline SVG icons** (16×16 `stroke="currentColor"`,
  CSP-safe) + plain-text labels in `<span>`s. The `☰` menu button and the
  functional 🟢🟡⚪ trust glyphs are KEPT (documented security UX).
- **Design-token refresh** (`client/style.css`, full-file pass, same var
  names + hue language): new tokens `--panel-2` (raised/hover surface),
  `--inset` (input/log wells), `--accent-soft`, `--ring`, `--warn`,
  `--border-soft`, radii `--r-s/m/l`, spacing `--sp-1..5`, shadows
  `--shadow-1/2`. Refined: soft elevation on `.panel`/drawer, gradient
  primary buttons with hover/active/focus-visible states, input focus rings
  (`box-shadow` ring instead of outline), flex nav items with accent-tinted
  active state, uppercase `.step`, pill badges with tinted backgrounds
  (`color-mix`), gradient chat bubbles, polished `.safety`/`.myhandle`/
  `.profile-qr`, surface-layered `#log`/`.alg-cards`/`.userlist`. Mobile
  `@media (max-width:600px)` behavior preserved verbatim.
- **Verified:** new harness `scratchpad/verify-sc/cosmetic-pass.mjs`
  (system Chromium via puppeteer-core): all 4 views render on desktop AND
  390×844 phone, drawer labels pure-ASCII (no emoji) with SVG icons, trust
  glyphs still present, **zero horizontal overflow** in every view/viewport,
  and a full two-context AES-256 flow (generate room → connect ×2 → unlock →
  message both ways → disconnect) green. Client offline `npm test` green;
  backend `test_csp_hash.py` 2/2 green. Screenshots eyeballed (drawer, room
  cards, live chat, phone views).
- **PENDING (blocked remote/exec permissions — run by hand):**
  1. Deploy (client only, no restart/chown needed):
     `cd ~/secure-chat && rsync -az --exclude node_modules --exclude
     'package*.json' --exclude '*.test.mjs' --exclude __pycache__ client
     root@138.199.144.35:/opt/secure-chat/`
  2. APK: `cd ~/secure-chat/android && ANDROID_HOME=$HOME/android-sdk
     ./gradlew assembleDebug -Dorg.gradle.java.home=$HOME/jdk-21.0.4+7`,
     then `adb install -r app/build/outputs/apk/debug/app-debug.apk`.

## ⮕ RESUME HERE (snapshot as of 2026-07-18, Profile tab shipped)
**The 👤 Profile tab (drawer TODO below) is BUILT, VERIFIED, DEPLOYED, and in
the APK.** New drawer entry (first, before Live room) → a presentation-only
view that reads existing unlocked-identity state: **Name** (registered
username or "not registered yet"), **Handle** with **Copy handle** / **Copy
invite link** (the Users-view helpers were factored into a shared
`renderHandleInto()` + the copy wiring reused), an **invite QR** (new vendored
`lean-qr`, `client/vendor/lean-qr/index.mjs`, added to the importmap — no CDN,
CSP-safe), the four-key **fingerprint** (`identity.fingerprint()`), **key
details** (Ed25519 + ML-DSA-65 / ECDH P-256 + ML-KEM-768), a **status line**
(unlocked · registered? · logged in? · N saved users), and the **Copy backup /
Forget identity** actions surfaced here too. Locked state shows the same
"unlock in Live room first" hint as Users/Chats. All `textContent`, no new
network calls or trust surface.

**Importmap changed → CSP hash regenerated** to
`sha256-6Sm2nhNvoa7gr7uuY2hbAbpdWhIlL15/wXLm4dhO9UQ=` in BOTH `backend/main.py`
and `android/.../MainActivity.kt` (guarded by `test_csp_hash.py`, which passes).

**Verified:** new `scratchpad/verify-sc/profile-flow.mjs` (two-context
Chromium) — locked-before-unlock, pre/post-registration fields, key details,
status line, copy buttons present, and the rendered **invite QR decodes back to
the exact invite link** (jsQR). Green LOCAL and LIVE. Offline suites +
backend 76/76 + H-01 flow still green (no nav regression from adding the tab).
**DEPLOYED to Hetzner** (rsync + the `chown securechat` step + restart;
confirmed live: Profile nav, vendored lean-qr 200, served CSP hash matches,
profile flow green against production). **APK rebuilt** (5.8 MB, bundles the
Profile view + lean-qr; unit tests green) — `adb install -r
android/app/build/outputs/apk/debug/app-debug.apk` when the phone is back.

## ⮕ RESUME HERE (snapshot as of 2026-07-18, Codex-Terra audit fixes)
**A second external audit ("Codex Terra", pushed to GitHub as
`secure-chat-security-audit-2026-07-18.md`, auditing commit 70bbfcc) found
1 High + 3 Medium + 3 Low. ALL 7 ARE FIXED, TESTED, AND DEPLOYED TO THE
HETZNER BOX** (deploy commands were run by hand because the session's
permission system blocked remote writes; ownership gotcha below).

- **H-01 (async keys not fully bound into verification):** contact-list
  fingerprint now covers all four keys (`app.js` renderUserList);
  `sameBundle` compares all four normalized (`?? null`); pins store all four
  keys (`contacts.savePin`); `contacts.upsert` treats missing→present as a
  real key change; store blob v2→v3 migration downgrades 🟢 contacts that
  have enc keys (verified against the old signing-only fingerprint) to ⚪
  with a `reverify` UI hint; handshake distinguishes "pin predates
  encryption-key coverage" (specific re-verify prompt) from a real key
  change. Regression tests in `contacts.test.mjs` (5 new) +
  `identity.test.mjs` (per-key fingerprint/SN change) — all green. Full
  two-context Chromium flow green (handshake → verify → pin → reconnect
  silently accepted → messaging), harness
  `scratchpad/verify-sc/h01-flow.mjs`.
- **M-01 (Starlette host-header bypass of the dev-file gate):** middleware
  now gates on `request.scope["path"]`; Starlette upgraded (see M-02); new
  `backend/tests/test_static_hardening.py` (malicious-Host 404s, version
  floor, cheap pathological Range) — verified live on a running local server
  with curl.
- **M-02 (Starlette Range CPU DoS, CVE-2025-62727):** FastAPI 0.139.2 +
  Starlette 1.3.1 (also covers M-01's GHSA-86qp-5c8j-p5mr), cryptography
  49.0.0, uvicorn 0.51.0 etc. — exact pins in `requirements.txt`, hashed
  lockfile `requirements.lock` (pip-compile --generate-hashes). Backend
  suite 76/76 green on the new stack, installed `--require-hashes`.
- **M-03 (WS 16 MiB buffered before the 64 KiB app check):** uvicorn now
  runs with `--ws-max-size 66560` (run.sh; MUST also be added to the
  systemd unit ExecStart on deploy). Live-tested: 1 MiB frame → hard close
  1009, no buffering.
- **L-01 (unbounded PBKDF2 iters):** all four `deriveKey`s
  (identity/contacts/chats/otp) enforce integer iters ∈ [100k, 5M] and salt
  8–64 bytes BEFORE WebCrypto; identity backup capped 256 KiB, pad file
  capped 4 MiB before JSON.parse. Tests in identity/contacts suites.
- **L-02 (Android prompt shows passphrases):** `onJsPrompt` masks input
  (TYPE_TEXT_VARIATION_PASSWORD) when the app-local message asks for a
  passphrase. APK rebuilt (5.8 MB, bundles the new client) — `adb install
  -r android/app/build/outputs/apk/debug/app-debug.apk` when the phone is
  back.
- **L-03 (dependency hardening):** Python exact pins + hashed lock (above);
  gradle wrapper pinned via `distributionSha256Sum`; Gradle dependency
  verification enabled (`android/gradle/verification-metadata.xml`, 631
  sha256 entries — builds fail on any unpinned/tampered artifact).

**DEPLOYED + LIVE-VERIFIED (2026-07-18):** rsync of backend+client (now also
excluding `.venv`/`package*.json`/`*.test.mjs`), venv upgraded with
`pip install --require-hashes -r requirements.lock` (starlette 1.3.1 /
fastapi 0.139.2 / cryptography 49.0.0 confirmed on the box), ExecStart now
carries `--ws-max-size 66560`. **Deploy gotcha for next time:** the rsync
runs as root and re-owns `/opt/secure-chat/backend`, which crash-loops the
service (`sqlite3 … readonly database`, 502s) — always finish with
`chown -R securechat:securechat /opt/secure-chat/backend` before the
restart. Live checks all green: app.js on the site carries the H-01 fix;
`package.json`/`*.test.mjs` 404 (a hostile Host header hits Caddy's
catch-all — empty 200, never reaches the backend); HSTS present; 1 MiB WS
frame → hard close 1009; all 3 live integration suites green; full
two-context Chromium H-01 flow (handshake → verify → pin → reconnect
silently accepted) green AGAINST PRODUCTION. The audit-fix backport to
`~/secure-chat-live` is also DONE and pushed (cdc3ba8). Still pending:
`adb install -r` of the rebuilt APK when the phone is reconnected.

## ⮕ RESUME HERE (snapshot as of 2026-07-18, later)
**Repos split + published to GitHub.** The project now has TWO git repos:
this full one (`~/secure-chat` → `github.com/kpafi/secure-chat`) and a
**live-chat-only** split (`~/secure-chat-live` →
`github.com/kpafi/secure-chat-live`) that keeps only the live-room flow (4 modes,
no OTP, no async/contacts layer) plus an encrypted `pins.js` and a consolidated
`PENTEST-FINDINGS.md`. Both pushed on `master` over SSH (key `kpafi@…-deploy`).

**NEW feature (Users view share UX):** the Users view now shows **"Your handle"**
with **Copy handle** + **Copy invite link** buttons, and an inbound invite link
(`<origin>/#add=<url-encoded handle>`) opens the Users view and **pre-fills** the
add field for review. Security note: the link carries the handle in the URL
FRAGMENT (never sent to the server) and only PRE-FILLS — it never auto-adds and
never conveys trust (verification is still the in-person safety-number check), so
it grants nothing a pasted handle wouldn't. Changed files: `client/index.html`
(handle block in `#usersUnlocked`), `client/app.js` (`renderMyHandle`,
`inviteLink`, `applyPendingInvite`, `handleInviteLink`, copy wiring),
`client/style.css` (`.myhandle`). Web-verified in a two-context Chromium run
(`/tmp/verify-sclive/invite-flow.mjs`): handle shown, both buttons pass the
correct strings, invite pre-fills the peer's add field, contact lands ⚪
unverified. **DEPLOYED to Hetzner** (rsync of `client/` to
`/opt/secure-chat/client/`, no restart needed for static files; confirmed the
live `app.js`/`index.html`/`style.css` carry the change via curl). Phone app
inherits it via the gradle `syncWebClient` copy — APK rebuilt (5.8 MB);
`adb install -r android/app/build/outputs/apk/debug/app-debug.apk` when the phone
is reconnected. Committed + pushed to `github.com/kpafi/secure-chat` (643fc7f).
NOTE for future deploys: this is a SEPARATE step from the git push — the live
site serves `/opt/secure-chat/client/` on the box, so a frontend change is only
live after the rsync.

## ⮕ RESUME HERE (snapshot as of 2026-07-18)
**Status:** live on Hetzner `https://138-199-144-35.sslip.io`. **An external
black-box pentest (2026-07-18) found 9 issues incl. a CRITICAL handshake bug
(C-01); ALL are now fixed, tested, and deployed** — see the 2026-07-18 DONE
entry. Highlights: C-01 (session key ↔ identity now atomically bound: identity
pinned on first handshake, serialized message handling, hard-close on a second
identity — regression-tested); H-01 (fingerprint + safety number now cover the
ecdh/mlkem encryption keys; a change resets verified); M-02 (trust pins moved
into the identity-encrypted store, plaintext pins migrated + deleted); M-01
(OTP rollback tripwire); M-03/L-01/L-02 (challenge rate bucket, HSTS, dev-file
404 + removed from server). Backend **71 pytest passed**; client offline suites
green (crypto/identity/contacts/sealed/otp-rollback); C-01 regression + P6
pentest + full UI flow green local AND live; 3 live integration suites still
green. APK rebuilt (phone unplugged — reconnect + `adb install -r
android/app/build/outputs/apk/debug/app-debug.apk`). Verification harness in
`/tmp/verify-sc/`: `c01-regression.mjs`, `pentest-p6.mjs`, `ui-flow.mjs`.

## ⮕ (previous snapshot 2026-07-17, evening)
**Status:** backend relay + web client working locally **and LIVE on a Hetzner
test server: `https://138-199-144-35.sslip.io`** (all 3 live integration suites
green over the public internet — see the first 2026-07-17 DONE entry for the
server layout, hardening, and the rsync deploy recipe); git repo on `master`.
**BIG feature set landed today (P1–P6, all deployed): a left-drawer menu with a
Users view (contacts + 🟢/🟡/⚪ web-of-trust marks, dual-signed vouches) and a
Chats view (WhatsApp-style async 1:1 over a sealed store-and-forward mailbox;
hybrid ECDH P-256 + ML-KEM-768 sealed envelope with sealed sender; per-chat
mode lock SEALED/AES256 with a signed accept/decline mode change). Identity is
now bundle v2 (adds ECDH + ML-KEM encryption keys; pre-today identities
auto-upgrade + re-publish on first unlock). Contacts + chat history are
encrypted at rest under the identity passphrase.** Backend **70 pytest passed**;
client offline suites (crypto/identity/contacts/sealed) green; full puppeteer
flow (identity→room→chat, users, vouches, async chat both ways, mode
negotiation) green; P6 adversarial pentest green local + live. Tests to run
live: sed-swap `127.0.0.1:8000`→`138-199-144-35.sslip.io` in the three
`*.integration.test.mjs`. NEW client modules: `contacts.js`, `chats.js`,
`sealed.js`; NEW backend: `mailbox.py` (+ vouch endpoints in `accounts.py`).
**Phone:** APK rebuilt (5.8 MB) but the last two installs were skipped (phone
unplugged) — reconnect USB + `adb install -r
android/app/build/outputs/apk/debug/app-debug.apk` to update it.
Backend `pytest` = **57 passed**; client offline suite (`npm test`) green; all
3 live integration suites green; real-browser (puppeteer/Chromium) checks green
(v2 handshake, token-gated directory, RSA ratchet, the double-click send
regression, and the new OTP generate→export/import→two-way→persist flow).
**FIVE working encryption modes now: AES256, DHKE, RSA, PQKEM, and OTP (true
one-time pad, in-person pad exchange — added 2026-07-16, see dated entry).**
**OTP was self-pentested the same day; all 4 findings (concurrent-use lock,
encrypt-at-rest, export single-use, import entropy check) are FIXED + verified.**
**All four 2026-06-19-review accepted-risk items (L1, I1, L2, I2) are CLOSED.**
`pip install -r requirements.txt` also pulls `dilithium-py`. Logging is
minimized (no request/connection metadata at rest); `run.sh` must keep
`--no-access-log --log-level warning`.
**2026-07-16 — all four 2026-07-08 Android pentest findings FIXED** (+ the
informational should-fixes): `RelayUrls.parse` now whitelists the host charset
(Critical Finding 1), the injected config is built with `JSONObject`, the
`shouldOverrideUrlLoading` origin check compares parsed scheme+host (Finding 2),
the app serves from a unique `https://secure-chat.internal` origin via
`WebViewAssetLoader.setDomain` (Finding 4, `APP_WEBVIEW_ORIGIN` updated to
match), WebView remote debugging is `BuildConfig.DEBUG`-gated, cleartext is
scoped to loopback/.onion, and `importMapHash` drift is guarded in
`test_csp_hash.py`. New Robolectric `RelayUrlsTest` (11 tests) rejects the live
PoC payloads; debug APK builds clean. See the 2026-07-16 DONE entry. **Remaining
Android work:** on-device re-run against the new origin + the DHKE/RSA/PQKEM
safety-number gate (needs the emulator), app icon, and release-signing.
**2026-07-07 (four entries, newest first):**
0. **Android app (new `android/` module):** thin Kotlin/WebView shell that
   BUNDLES the audited web client in the APK (closes web-only trust gap H1) and
   points at a remote relay. Debug APK builds clean; verified in a real browser
   AND **on-device** (Android 14 emulator — AES256 end-to-end through the relay,
   both directions). Found + fixed a Mixed-Content constraint: the relay must be
   wss/loopback/.onion (a plain-http LAN relay is browser-blocked); app.js now
   reports it clearly. Backend gained a single allow-listed app origin (WS +
   CORS) and `SECURE_CHAT_EXTRA_ORIGINS`. See the two dated entries.
1. **Ratchet unification:** DHKE + PQKEM ported onto `RatchetChannel`
   (in-session forward secrecy for every mode; `AuthChannel` deleted); DHKE
   drops its private key at derivation, PQKEM seals like RSA on first
   traffic; reflected handshake keys + reflected hellos now refused in all
   modes. DHKE/PQKEM `msg` frames are `dhke-msg/v2`/`pqkem-msg/v2`.
2. **Final crypto review** of the whole stack: no High/Medium findings; full
   verification matrix green incl. a 4-mode real-browser end-to-end run.
3. **Both 2026-07-03 pentest concurrency bugs FIXED** (High: racing decrypts
   could roll the replay counter back; Medium: overlapping encrypts consumed
   the same one-time key and killed the ratchet): all channel encrypt/decrypt
   calls are serialized through a per-instance FIFO `CallQueue`, plus a
   Send-in-flight guard in app.js as defense in depth. See dated entries.
**2026-07-03:** TODO item (d) fully closed — ratcheting for RSA **and** AES256.
1. RSA mode is now **forward-secret** — RSA key transport + a one-way HMAC
   ratchet with one-time AES-GCM message keys; root secret and RSA private key
   are erased once traffic starts (see dated entry). RSA `msg` frames are
   `rsa-msg/v2`; handshake format unchanged.
2. AES256 mode now runs the same ratchet (shared `RatchetChannel`), rooted in
   the passphrase **plus both peers' fresh session nonces** (new plaintext
   hello exchange for AES256, reusing the app's existing hello phase) — this
   **CLOSES the AES256 cross-session-replay residual**. AES256 frames are
   `aes-msg/v2`; `AuthChannel` now serves only DHKE/PQKEM. FS for AES256 is
   honestly limited (passphrase = master secret; see dated entry).
Both committed together in a single commit on top of d5e2f68.
**2026-07-02 (second session), in order:**
1. CLOSED Medium finding **cross-session handshake replay in a reused room** —
   handshake transcript bumped to v2, covers a fresh per-connection nonce from
   BOTH peers (plaintext `hello` before the signed offer/answer, folded
   order-independently). Committed as c756cf9.
2. CLOSED accepted-risk **L1** (server-side ML-DSA-65 dual ownership proof at
   registration, via `dilithium-py`) and **I1** (username namespace made
   non-enumerable: token-gated `username#token` lookup + removed the
   challenge/verify existence oracles + dedicated lookup rate limit). See the
   "accepted-risk closeout" dated entry. NEW backend dep: `dilithium-py`.

Both were committed this session (c756cf9 = handshake replay; 1703a19 = L1/I1).

**Done & verified end-to-end (incl. real-browser checks via puppeteer):**
- Dumb-relay backend (strict validation, rate limit, connection cap, join +
  idle timeouts) + passwordless account directory (`/api`, rate-limited + capped).
- Web client: 5 working encryption modes — **AES256, DHKE, RSA, PQKEM, OTP**
  (PQKEM = hybrid ECDH P-256 + ML-KEM-768; OTP = true XOR one-time pad with an
  in-person pad exchange, added 2026-07-16). Identity = Ed25519 + ML-DSA-65,
  passphrase-encrypted at rest (PBKDF2 600k).
- **Authenticated handshake** (dual-sig) + in-person safety-number gate closes
  the relay-MITM gap. Account register/login + fetch-by-username pinning.
- Security review done; M1/M2/L3 fixed, H1 documented (see 2026-06-19 entry).

**Next options (pick one):** (a) on-device smoke test of the new Android app
(build + cross-origin browser verification DONE 2026-07-07; needs a real
device/emulator to exercise the WebView glue); (b) Tor `.onion` deployment
(pairs naturally with the app — set the relay to the `.onion` and add its
origin via `SECURE_CHAT_EXTRA_ORIGINS`); (c) OTP mode. Full open list in TODO
at the bottom.

**Run it:** see "How to run (quick ref)" at the bottom of this file.

## Project goal (from the user)
- Website + server backend for **simple ASCII-only text chat**.
- **Security is the #1 priority** in every design and code decision. Small,
  simple, auditable codebase is itself a security feature.
- User picks the encryption: **RSA, AES-256, DHKE, post-quantum key exchange,
  and OTP** (OTP = pre-shared large random pad exchanged when users meet in
  person; lower priority, harder to implement — defer for now).
- Eventual clients: a **Tor `.onion` website** and a dedicated **Android app**.
  The **website is the priority**; the app comes later.
- Order of work: **backend first, locally, for testing.**

## Key architectural decisions (locked)
1. **Stack:** Python + FastAPI (small, readable, easy to audit; strong crypto
   ecosystem for later client-side / PQ work).
2. **Crypto model:** **End-to-end encryption; the server is a dumb relay.**
   The server never sees keys or plaintext. It validates the envelope, enforces
   limits, and forwards opaque ciphertext. A full server compromise leaks only
   ciphertext. => All algorithm choice and crypto logic lives in the CLIENT.
   The server's `alg` field is an advisory tag only and is never acted upon.

## DONE
### 2026-07-18 — External pentest response: C-01 (critical) + 8 more, all fixed ✅
An independent black-box audit of the live web instance reported 9 findings.
All addressed, tested, deployed. Full write-up in README ("External pentest").

**C-01 — CRITICAL — session key not atomically bound to peer identity.**
Confirmed by reading the code: `handleMessage` set `peerBundle = idb` then
`cipher.onPeerKey(pub)`, and the ciphers are first-key-wins. A relay could send
its OWN validly-signed offer first (cipher locks attacker key) then relay the
peer's real signed offer (peerBundle → real peer, cipher IGNORES the real key),
so the safety number / pin verified against the honest peer while the live
channel used the attacker's key — decoupling exactly what the safety-number
gate protects. **Fix (app.js):** (1) message handling serialized through a FIFO
`msgChain` (closes the TOCTOU where two frames pass verification before either
pins); (2) the peer identity is PINNED to the first accepted handshake —
`peerBundle` is write-once, and a later frame whose `idb` differs hard-closes
the connection with a MITM notice; (3) `enterVerification(room, verifiedBundle)`
takes the pinned bundle explicitly instead of re-reading a mutable global.
**Regression:** `/tmp/verify-sc/c01-regression.mjs` — a mock relay feeds two
validly-signed DHKE offers from DIFFERENT identities with identical nonces; the
first is accepted, the second hard-closes, messaging never unlocks, a MITM line
is logged.

**H-01 — HIGH — relay could swap the async (ecdh/mlkem) encryption keys.**
Fingerprint/safety-number covered only ed+mldsa, and a contacts enc-key change
did NOT reset verified — so a relay could pair the real signing keys with its
own encryption keys and silently redirect sealed messages. **Fix:**
`identity.js` `_bundleBytes` folds ecdh+mlkem into `fingerprintOf` +
`safetyNumber` (pre-v2 bundles hash unchanged); `contacts.upsert` treats ANY of
the four keys changing as a key change (resets verified, drops stale vouches);
the live-room verify gate mirrors the FULL bundle (incl. enc keys) into
contacts; adding a contact by handle no longer auto-verifies from an
ed/mldsa-only pin.

**M-02 — MEDIUM — trust pins were plaintext localStorage.** A forged
`sc.pins.v1` entry could auto-unlock. **Fix:** pins live inside the
identity-encrypted, GCM-authenticated contact store (`contacts.getPin/savePin`),
blob bumped to v2 `{contacts, pins}`; a one-time migration imports the old
plaintext pins then deletes the key.

**M-01 — MEDIUM — OTP rollback.** A wholesale restore of an old encrypted pad
blob rewound `sendOffset` to reuse keystream (GCM stops edits, not rollback).
**Fix (otp.js):** a SEPARATE monotonic high-water key `sc.otp.hw.v1.<id>`;
unlock refuses a pad whose offset regressed below it. `otp-rollback.test.mjs`
proves an old-blob restore is refused. *Residual (documented):* a full-storage
rollback that also reverts the tripwire needs OS-level trusted storage — out of
scope for browser localStorage.

**M-03 / L-01 / L-02.** Dedicated stricter rate bucket on `/api/auth/challenge`
(`CHALLENGE_RATE_CAPACITY=10`, 0.5/s) + test; `Strict-Transport-Security` sent
when `X-Forwarded-Proto: https` (not on loopback/.onion); middleware 404s
`package.json`/`package-lock.json`/`*.test.mjs` and they were removed from the
deployed client dir. **H-02 / L-03 / PQ-assurance:** documented as accepted /
architectural (web client = honest-but-curious; Android app = malicious-relay
answer; SSH key-only on a disposable box; noble-PQ self-audited).

**Verification:** backend **71 passed**; client offline suites green incl. new
`otp-rollback.test.mjs`; `c01-regression.mjs`, `pentest-p6.mjs`, full
`ui-flow.mjs` green LOCAL and the pentest + 3 integration suites green LIVE
against Hetzner. Deployed; HSTS + dev-file-404 confirmed on the live box; APK
rebuilt.

### 2026-07-17 — P6: hardening pass over the contacts/chats surface + live E2E ✅
Adversarial pass following the project method (attack the running code, prove
it with a live PoC): `/tmp/verify-sc/pentest-p6.mjs`, run against BOTH the
local relay and the live Hetzner box. Every attack refused:

- **Vouch forgery:** zero-signature vouch → 400; a vouch signed by a
  non-owner key but submitted under the attacker's session → 400 (server
  checks the sig against the AUTHENTICATED user's keys). **Client 🟡
  forge-resistance:** proved `Identity.verify` rejects a genuine vouch when
  the voucher keys are swapped to the attacker's, and when the target key is
  rotated — so a lying directory cannot manufacture a 🟡 (the award rule
  re-verifies against the client's OWN pinned voucher keys).
- **Mailbox:** wrong-token-for-real-user and unknown-user POST return
  byte-identical 404 (not an existence oracle); fetch without / with a bogus
  bearer token → 401; a logged-in eve never sees bob's queue (per-recipient);
  an envelope captured off the wire won't `open()` without the recipient's
  keys.
- **Chat sender spoofing:** eve seals a message to bob with alice's
  self-claimed handle — `open()` still binds the sender to EVE's real bundle,
  and since chats are keyed by bundle (never the claimed name), she cannot
  inject into bob's alice-chat.
- **Regression:** the 3 live integration suites (relay 4-mode, account
  directory, authenticated handshake) still pass against Hetzner after all the
  backend changes — the dumb relay + directory are untouched in behaviour.
- Docs: README gained a "Contacts, web of trust, and async chats" section
  (trust marks, sealed envelope, mailbox, mode lock, the FS trade-off). APK
  rebuilt (5.8 MB, ready for the next phone connect).
- NOTE: the pentests + browser runs left a handful of `pt-*`/`bob-*` test
  accounts in the LIVE directory (public keys only, harmless) — restart/redeploy
  starts fresh if you want a clean box for real testing.

### 2026-07-17 — P5: per-chat mode lock + negotiated mode change ✅
- **Modes (async):** SEALED (default, transport only) and AES256 (an inner
  AES-256-GCM layer under a per-chat passphrase, applied to the plaintext
  BEFORE sealing — so even a break of the recipient's long-term TRANSPORT keys
  leaks nothing without the chat passphrase). OTP-over-mailbox deliberately NOT
  offered (async pad sync = two-time-pad risk); it stays live-room only.
- **Negotiation:** the sealed envelope core now carries a `kind`
  (msg / mode-propose / mode-accept / mode-decline) — control messages are
  signed and authenticated exactly like text (`sealed.js` generalised from
  `text` to a `content` object; open() returns the whole signed body). One
  side proposes via the chat's mode picker (AES256 → prompts for a shared
  passphrase, mints a PBKDF2 salt sent in the proposal); the peer sees an
  accept/decline banner; the switch happens only after a signed accept, on
  both sides. Decline/lost-response leave the locked mode untouched.
- **Store:** `chats.js` gained `setMode`/`setPending`/`clearPending`, the
  AES256 fields (`secret`,`salt`), and inner-layer `innerEncrypt/innerDecrypt`
  (+ `newInnerSalt`). Mismatch cases render a clear system line rather than
  garbage. All negotiation state is inside the identity-encrypted chat store.
- **Verified:** `sealed.test.mjs` gains a control-message case (kind/mode/salt
  survive sign+seal); browser flow drives alice→propose AES256, bob→accept
  (both prompts auto-answered with the same passphrase), both lock to AES256,
  then a message round-trips through the inner layer. Offline suites + backend
  70 green; deployed to Hetzner. Screenshot eyeballed; tightened the convo
  header to wrap on narrow screens.

### 2026-07-17 — P4: store-and-forward mailbox + Chats view (WhatsApp-style async DMs) ✅
- **Backend `mailbox.py` (new):** rows are (recipient, opaque envelope,
  arrival time) — the sender is sealed INSIDE the envelope, invisible to the
  server. `POST /api/mailbox/{recipient}?t=<lookup token>` (token gate = same
  anti-enumeration boundary as the bundle lookup: wrong token / unknown user
  are an identical 404; printable-ASCII + 64 KiB envelope cap; dedicated
  per-host rate bucket 30 burst / 1 rps; per-inbox cap 200; global cap 100k;
  14-day TTL pruned on access). `GET /api/mailbox` requires the session token
  and DELETES what it returns — no server-side read history. New
  `tests/test_mailbox.py` (roundtrip+delete-on-fetch, token-gate oracle check,
  auth, size/ASCII/inbox-cap, TTL prune) → backend **70 passed**.
- **Client:** `chats.js` — encrypted chat store (same PBKDF2→AES-GCM posture,
  unlocked with the identity, wiped on forget; 500-msg cap per chat; inbound
  dedup by envelope id). `sealed.js` core gained a signed, self-claimed
  sender handle (display/reply-token only — chats are KEYED by the sender's
  signature-verified bundle, never by the claimed name). `account.js`:
  `sendMail`/`fetchMail`. Chats view: start-a-chat picker (saved users),
  chat list with safety marks + last-message preview, bubble conversation
  (textContent-only rendering), mode line "🔒 SEALED …". Sending needs only
  the contact's handle token; RECEIVING needs login (mailbox auth) — 6s
  polling after login + on view entry. Unknown senders are auto-added as ⚪
  contacts (sealed handle preferred, fingerprint-derived name fallback); a
  known bundle without a reply token adopts the sealed handle's token.
- **Verified:** browser suite extended — alice→bob sealed send, bob logs in,
  chat auto-appears filed under alice's handle, bob replies using the sealed
  token, alice's open conversation updates, chat blob at rest is ciphertext
  (no plaintext leak). Screenshots eyeballed (bubble UI). Deployed to the
  Hetzner box; APK rebuilt (phone was unplugged — install pending reconnect).
- **Known limitation (documented):** sealed envelopes have per-envelope
  ephemerals but NO live ratchet — long-term-key compromise exposes captured
  past envelopes. P5 adds the mode lock/negotiation; the hardening pass (P6)
  revisits mailbox abuse surface end-to-end.

### 2026-07-17 — P3: bundle v2 (encryption keys) + sealed async envelope ✅
Foundation for chats-without-a-live-room:

- **Identity (client):** now also holds ENCRYPTION keypairs — ECDH P-256 +
  ML-KEM-768 (`identity.js`). Blob format v3 (v2 blobs auto-upgrade on
  unlock: enc keys generated, blob re-exported once, bundle re-published to
  the directory opportunistically for registered users). Fingerprint / safety
  number / pins still cover ONLY the signing keys (identity continuity); the
  enc keys are bound to the identity by the registration signature.
- **Directory (backend):** registration v2 under `secure-chat/register/v2`
  (dual sig covers ecdh+mlkem; both-or-neither, strict sizes 65/1184 B).
  `accounts` table gained `ecdh_pub`/`mlkem_pub` (empty for v1 rows; those
  can't receive sealed messages until re-registered). **Same-identity
  re-registration is now a bundle refresh** (verifies the dual sig, matches
  stored ed+mldsa exactly, updates enc keys, returns the EXISTING lookup
  token) — foreign identities still get 409. Lookup returns enc keys when
  present; v1 registration still accepted. `tests/test_bundle_v2.py` (5
  tests): roundtrip, sig-must-cover-enc-keys (v1-sig + keys, post-sign key
  swap), both-or-neither + size validation, refresh-vs-409, v1 compat —
  backend **65 passed**.
- **`sealed.js` (client, new):** async E2EE to a contact's public bundle.
  Hybrid: ephemeral ECDH + ML-KEM-768 encaps → HKDF-SHA256(salt=domain,
  info=recipient-ed) → AES-256-GCM. **Sealed sender:** sender bundle + DUAL
  signature live inside the ciphertext; sig covers domain + RECIPIENT identity
  key + eph + KEM ct + core, so envelopes can't be re-targeted and the mailbox
  never learns the sender. FS trade-off documented (per-envelope ephemerals;
  no live ratchet in store-and-forward). `sealed.test.mjs`: roundtrip, opaque
  envelope (no plaintext/sender leak), wrong-recipient, tamper,
  eve-signs-as-alice forgery, legacy-blob upgrade — all green.
- Contacts store now carries contacts' enc keys (updated on add/lookup; an
  enc-key change alone does NOT reset `verified` — trust anchors stay
  ed/mldsa). Client suites + full browser flow green; deployed to Hetzner +
  phone. NOTE: identities created before today must unlock once (auto-upgrade
  + re-publish) before they can RECEIVE sealed messages.

### 2026-07-17 — P2: web-of-trust vouches (🟡 mark) ✅
- **Backend:** `vouches` table (voucher→target, dual sigs, created_at; PK
  dedups re-vouches). `POST /api/vouch` (session-token auth) verifies BOTH
  signatures against the voucher's registered keys over the TARGET's currently
  registered bundle before storing — the table can only hold statements the
  voucher really signed about the real directory entry. `DELETE /api/vouch/
  {target}` revokes. `GET /api/users/{u}/vouches` is gated by the target's
  lookup token (no graph enumeration) + the strict lookup rate bucket, returns
  ≤50 vouches incl. voucher public keys. Bounds in config: 200/voucher, 200k
  total. Domain-separated message: `secure-chat/vouch/v1\ntarget\ned\nmldsa`.
  Self-vouch 422. New `tests/test_vouches.py` (publish/fetch/revoke; wrong-key,
  cross-target, single-scheme-forgery, auth rejections; token-gated 404
  indistinguishability) — backend now **60 passed**.
- **Client:** `account.js` vouch/unvouch/fetchVouches (+ exported
  `vouchMessageBytes`); login now retains the session token in memory.
  Users view: turning a contact 🟢 offers (confirm, opt-in — it reveals the
  social edge publicly) publishing a vouch signed over MY pinned copy of their
  bundle; Unverify retracts. 🟡 computation is strictly local: a vouch counts
  ONLY if the voucher is a contact I verified in person AND the
  server-returned voucher keys equal my pinned copy AND the dual signature
  verifies over MY stored target bundle — a lying directory cannot invent a 🟡.
  Results cached in the encrypted store (10-min recheck TTL).
- **Verified:** full puppeteer flow incl. new WoT scenario (alice registers,
  logs in, re-verifies bob → publishes vouch; carol verifies alice in person,
  adds bob → 🟡 "vouched by alice"), screenshots eyeballed; all offline suites
  green. Deployed to Hetzner (backend restarted) + phone APK. Found+fixed in
  passing: renderUserList() wiped the just-set vouch status line (order swap).

### 2026-07-17 — P1 of the contacts/chats overhaul: drawer menu + encrypted contact store + Users view ✅
First phase of the planned contacts + web-of-trust + async-chats feature set
(full plan in TODO). Shipped:

- **Drawer menu** (☰ top-left): Live room (the untouched 3-step flow) / Users
  (new) / Chats (placeholder until P4). Pure presentation; switching views
  never touches an active connection. CSS gotcha fixed along the way:
  `.drawer { display:flex }` silently overrode the `hidden` attribute
  (author display beats the UA's `display:none`), leaving an invisible
  click-eating overlay — caught by the browser suite, fixed with an explicit
  `.drawer[hidden] { display:none }`.
- **`contacts.js` — encrypted contact store.** Records
  `{username, token, ed, mldsa, verified, verifiedAt, addedAt, keyChangedAt}`;
  at rest PBKDF2-600k → AES-256-GCM under the IDENTITY passphrase (same
  posture as identity + pads; GCM doubles as tamper protection — flipping
  `verified` in the blob just breaks decryption). Unlocked wherever the
  identity is created/unlocked (before the passphrase field is cleared);
  locked state renders a hint; wiped on identity-forget; a changed key for a
  known username RESETS `verified` (same rule as the pin store). Foreign/
  tampered blob → clear error, resettable via identity-forget.
- **Users view:** add contact by `username#token` (directory lookup),
  fingerprint per contact, marks 🟢 "verified by you" / ⚪ unverified (🟡
  vouched comes with P2), confirm-gated "Verified in person ✓" / Unverify /
  Remove, loud key-changed warning. Auto-🟢: adding a handle whose bundle
  matches an existing in-person pin, and the live-room safety-number confirm
  (`onVerifyOk`) mirrors into the store when the contact-handle field named
  the peer.
- **Tests:** new `contacts.test.mjs` (npm test now runs it): encrypted
  round-trip, wrong-passphrase refusal, GCM tamper refusal, key-change trust
  reset, wipe, opaque-at-rest. Browser suite extended: register→handle→add→
  ⚪→verify→🟢→reload-unlock→persisted→blob-is-ciphertext. All green
  (client offline, backend 57/57, full puppeteer flow); deployed to the
  Hetzner box + phone APK reinstalled.

### 2026-07-17 — UI rework: 3-screen flow + disconnect + copy-room-id (deployed live + on phone)
User feedback from live testing: no way to disconnect once connected, and the
single-page UI felt raw. Reworked the client into a guided **3-screen flow** —
UI structure only, **zero crypto/handshake/connection-logic changes** (all
element ids kept, so the test suites run unmodified):

1. **Identity screen** (identity panel + optional username register/login);
   Continue button (labelled "Skip — no identity (AES-256 / OTP only) →" until
   an identity is unlocked).
2. **Room screen** (room id + Generate, encryption picker, passphrase/OTP
   panel, contact handle, Connect) with Back navigation.
3. **Chat screen** with a sticky **top bar**: shortened room id, **Copy room
   id** button (clipboard), mirrored status, and the new **Disconnect** button
   (`ws.close()` → the existing onclose cleanup now returns to the room
   screen). Verify (safety-number) panel lives inside this screen.

Implementation: `index.html` regrouped into `#scrIdentity/#scrRoom/#scrChat`
wrappers + `showScreen()` in app.js; `joined`/`onclose` swap screens instead of
toggling `#setup`/`#chat`; the inline importmap kept **byte-identical** (CSP
hash — `test_csp_hash.py` still green). style.css: step indicator, topbar,
ghost buttons, `#log` height now `min(55vh, 480px)` for phones.
**Verified:** client `npm test` green, backend 57/57 green, and a new
puppeteer/Chromium two-peer UI-flow check (`/tmp/verify-sc/ui-flow.mjs` —
screen navigation, DHKE session, safety-number match, message delivery,
topbar copy → clipboard content asserted, disconnect → room screen). Deployed
to the Hetzner box and reinstalled on the phone (`adb install -r`) same day.
**Follow-up 2 (same day) — mobile polish + encryption picker cards.** The
`<select>` encryption picker is now a **radio-card group** (`#algCards`, one
`<input type="radio" name="alg">` per mode with name/badge/description —
`els.alg.value` reads became the `algValue()` helper; `syncAlgUI` listens on
the container). Phone-sized screens (`@media max-width: 600px`): tighter
padding, 16px inputs (no focus-zoom), bigger touch targets, `#log` sized via
`100dvh`, and the chat top bar becomes a 2×2 grid (room id | copy // status |
disconnect). Verified: npm test + 57/57 pytest green; ui-flow.mjs (extended
with a card-toggling check) green at a 390×844 viewport; screenshots
eyeballed. Deployed to the Hetzner box + phone same day.
**Follow-up (same day):** the browser kept showing the OLD client after the
deploy — StaticFiles sends only ETag/Last-Modified, no `Cache-Control`, so
browsers cache heuristically without revalidating. Fixed: the security-headers
middleware now also sets `Cache-Control: no-cache` (always revalidate; ETag
makes unchanged loads a 304). One manual hard reload (Ctrl+F5) is needed on
clients that cached before this fix; after that, deploys show up on plain
reload. 57/57 backend tests still green; live-verified on the Hetzner box.

### 2026-07-17 — FIRST LIVE DEPLOYMENT: Hetzner test server, all live suites green 🚀
The relay + web client are live on a Hetzner Cloud box (Debian 13, x86_64,
4 GB) for real-network testing:

- **URL: `https://138-199-144-35.sslip.io`** (sslip.io wildcard DNS → the
  server IP `138.199.144.35`; free Let's Encrypt cert via Caddy — swap in a
  real domain or the `.onion` later without touching the backend).
- Layout on the server: `/opt/secure-chat/{backend,client,venv}`, runs as the
  no-login system user `securechat` under systemd (`secure-chat.service`) with
  sandboxing (`ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`,
  `NoNewPrivileges`). Uvicorn binds **loopback only** and keeps the mandatory
  `--no-access-log --log-level warning`; Caddy terminates TLS on 443 and its
  access log is set to `output discard` (metadata-minimization carried over,
  I2). Public origin allow-listed via
  `Environment=SECURE_CHAT_EXTRA_ORIGINS=https://138-199-144-35.sslip.io` in
  the unit (WS origin check + CORS).
- Host hardening: SSH is key-only (password auth disabled via
  `sshd_config.d/90-no-password.conf`), Hetzner cloud firewall allows only
  22/80/443 TCP inbound, unattended security upgrades enabled. Local test
  `accounts.db` was NOT deployed — the live directory starts empty.
- **Verified from the laptop against the live server:** all 3 live integration
  suites green over the public internet — relay (DHKE/AES256/RSA/PQKEM
  end-to-end via `wss://`), account directory (register→lookup→login→me,
  dup-username 409, wrong-key rejected), authenticated handshake
  (DHKE/RSA/PQKEM safety numbers + cross-session replay REJECTED). Run them
  live by sed-swapping `127.0.0.1:8000` → `138-199-144-35.sslip.io` (ws→wss,
  http→https) in the three `*.integration.test.mjs` files.
- Deploy/update recipe: `rsync -az --delete --exclude '.git' --exclude
  '__pycache__' --exclude 'node_modules' --exclude 'accounts.db*'
  backend client root@138.199.144.35:/opt/secure-chat/ && ssh
  root@138.199.144.35 systemctl restart secure-chat`.
- NOTE: test box is disposable (hourly billing); nothing on it is
  irreplaceable — everything above is reproducible from this repo.

### 2026-07-16 — OTP pentest: 2 Medium + 2 Low found (NOT yet fixed) 🔴
Adversarial review of the just-shipped OTP mode (crypto.js `OtpPad`, otp.js, the
app.js wiring), following this project's "attack the running code, prove it with
a live PoC" method. PoCs run against the actual shipping modules
(`/tmp/verify-sc/pentest-otp.mjs`). **The OTP core crypto held up** — replay,
cross-room replay, cross-session replay, ciphertext tamper, offset-relabeling,
reflection, and forward-secrecy zeroing are all correctly rejected/enforced
(re-proven). Four weaknesses found, all in pad *lifecycle/state management*, not
the cipher:

**Finding 1 — MEDIUM — concurrent pad use = two-time pad (catastrophic reuse).**
Nothing locks a pad to one active session. Two OtpPad instances built from the
same persisted record — exactly what two browser TABS get from `loadPad` (they
share localStorage but each holds its own in-memory offset) — both start at the
same offset and reuse the same keystream. **Live-proven:** `C1^C2 == P1^P2`, the
classic two-time-pad break (an eavesdropping relay recovers plaintext
relationships, and any one known/guessable message reveals the other outright).
`MAX_ROOM_MEMBERS=2` blocks the naïve "two tabs + peer in ONE room" variant, but
NOT (a) two concurrent conversations (two rooms) sharing one pad, nor (b) two
tabs alone in a room unlocking each other. Single-tab sequential use is safe
(offset persisted after every message). Fix: a same-origin lock (BroadcastChannel
lease / a localStorage "pad in use" epoch checked before each send) so a pad can
be live in only one session at a time; refuse or hard-warn on concurrent use.

**Finding 2 — MEDIUM — pad stored UNENCRYPTED at rest.** `otp.savePad` writes
`bytes: b64(record.bytes)` straight to localStorage in the clear, unlike the
identity private keys (which are PBKDF2→AES-GCM encrypted at rest). A device /
browser-profile compromise reads the entire REMAINING pad → decrypts all FUTURE
traffic until a new pad is exchanged. Consumed bytes are zeroed, so past traffic
stays protected (the FS property holds), but the long-term secret sitting in
plaintext is inconsistent with the rest of the app's at-rest posture and
undercuts exactly the high-assurance users who pick OTP. Fix: encrypt the pad at
rest under a passphrase (reuse the identity export machinery), unlocked per
session like the identity is.

**Finding 3 — LOW — export file has no single-use / role binding.** `importPad`
always returns `recipientRole` (= 1), so importing the same export file on more
than one device gives EVERY importer role 1 → two role-1 senders reuse region 1
(two-time pad again). Same if the generator forgets its role-0 copy and
re-imports its own file. **Live-proven** (two imports → identical role → keystream
reuse). Only the otp.js header doc ("import on one device per side") prevents it.
Fix direction: bind the pad to the exchanging identities if available, or at
least track "this file already imported / this pad already has a role-1 peer" and
warn hard; there is no fully-robust cross-device enforcement without identities.

**Finding 4 — LOW/informational — a malicious pad generator can downgrade the
importer's outbound confidentiality.** The generator produces ALL pad bytes,
including the importer's send region. A hostile (or corrupted) pad with an
all-zero / low-entropy send region makes the importer's outbound `ct = pt XOR 0
= pt` — plaintext on the wire, readable by the RELAY, not just the generator.
Bounded: the generator is your trusted in-person contact who receives your
plaintext anyway; the only *new* exposure is to third parties. Fix: a cheap
entropy sanity check on import (reject an all-zero / obviously non-random pad),
and/or document that the pad's randomness is only as trustworthy as whoever
generated it.

**Verified negatives (no finding):** the AD binds domain|room|role|offset|len so
moving a frame across rooms/offsets/regions fails the MAC; the one-time HMAC key
is full 32-byte SHA-256 (untruncated); `crypto.subtle.verify` is constant-time;
auth-failed frames consume no pad (a hostile relay can't burn the pad with
forgeries); the entropy mixer (CSPRNG XOR AES-CTR(H(finger))) is never weaker
than the CSPRNG; the export file is GCM-authenticated (wrong passphrase → clean
reject). `offset | 0` would truncate for >2 GiB pads but max pad is 1 MiB
(unreachable, latent-only). The non-OTP stack (relay, accounts, other four
ciphers) was not changed this session and its previously-closed findings remain
closed; a quick re-confirm left backend `pytest` 57 and all live suites green.

**Not yet fixed** — all four are on the TODO list below. **(All four FIXED later
the same day — see the entry above this one.)**

### 2026-07-16 — OTP pentest findings 1–4 FIXED ✅
Fixed all four findings from the OTP pentest (entry below). The OTP cipher core
was already sound; these harden pad lifecycle/state.
- **F1 (MEDIUM) — concurrent-use two-time pad.** New exclusive same-origin lock
  in app.js: `acquirePadLock(padId)` uses the **Web Locks API**
  (`navigator.locks`, auto-released if the tab dies) with a localStorage-
  heartbeat lease fallback. Taken on connect, released on disconnect; a pad live
  in one tab makes connect in any other tab refuse ("already in use"). Single-tab
  sequential use is unaffected.
- **F2 (MEDIUM) — pad unencrypted at rest.** `otp.js` persistence rewritten: the
  pad bytes AND consumption offsets are stored **encrypted** (PBKDF2-600k →
  AES-256-GCM) under a per-pad passphrase, never in the clear — same at-rest
  posture as the identity blob. `saveNewPad` derives the key once (PBKDF2);
  `unlockPad` decrypts on connect; `savePadProgress` re-encrypts each message
  with the cached key (no per-message PBKDF2). Offsets live INSIDE the GCM blob,
  so a local attacker can't roll `sendOffset` back to force pad reuse. A new
  "pad passphrase" field (distinct from the file "transfer passphrase") unlocks
  the pad per session.
- **F3 (LOW) — export single-use.** Re-exporting an already-shared pad warns and
  requires a confirming second click (`markExported` / `padMeta.exported`);
  import dedups by padId and the UI carries a strong "one device per side"
  warning. Cross-device double-import of a manually-copied file is inherent
  without identities (documented).
- **F4 (LOW) — low-entropy imported pad.** `importPad` now runs `looksRandom`
  (Shannon entropy over a byte histogram) and refuses a pad below 7.0 bits/byte
  (all-zero / grossly low-entropy), so a corrupt/sabotaged pad can't silently
  make outbound `ct == pt`.
- **UI:** two OTP passphrases now — a top-level **pad passphrase** (at-rest,
  per-session unlock) and the export/import **transfer passphrase** (`otpXferPass`).
- **Verified.** `node crypto.test.mjs` + `npm test` green (cipher unchanged);
  module-level checks (localStorage shim): at-rest blob carries only kdf/iv/ct
  (no plaintext bytes), unlock round-trips bytes+offsets, wrong passphrase
  rejected, all-zero pad import rejected, `looksRandom` correct. **Real-browser
  E2E (Chromium/puppeteer, two contexts + extra tabs):** generate (encrypted at
  rest) → export → re-export warns → import (encrypted, both passphrases) →
  connect → two-way messaging, zero undecryptable frames; a second tab is refused
  the in-use pad (F1); a wrong pad passphrase refuses unlock (F2). Backend
  `pytest` 57 + all 3 live integration suites still green.

### 2026-07-16 — OTP mode: true one-time pad, in-person pad exchange ✅
Implemented the deferred OTP mode as a genuine XOR one-time pad. Design forks
were decided with the user: true XOR OTP (not a pad-as-keypool shortcut),
file-based in-person pad transport (not Web Bluetooth), and CSPRNG hardened with
optional draw-to-generate entropy.
- **`OtpPad` cipher (`client/crypto.js`).** Confidentiality is a real one-time
  pad: `ct = plaintext XOR keystream`, keystream = fresh pad bytes never reused.
  The pad is split in half by ROLE (generator = role 0, importer = role 1); each
  side sends from its own region and receives from the other, so no byte is ever
  used to encrypt twice. Integrity: each message carries an HMAC-SHA-256 tag
  under a one-time 32-byte key also drawn from the pad, binding
  domain|room|role|offset|len|ct (stops XOR malleability; honest computational
  limit, since an info-theoretic one-time MAC would be hand-rolled crypto we
  forbid). A strictly increasing receive offset rejects replays AND cross-session
  replays (offsets persist per pad, never rewind). Consumed pad bytes are ZEROED
  on both send and receive (forward secrecy: capture at time T can't decrypt
  earlier traffic). Auth-failed frames consume nothing (a hostile relay can't
  burn pad with forgeries). Serialized through the shared `CallQueue`.
  `needsHandshake=false`, `usesNonces=false`; removed from `UNAVAILABLE`.
- **Pad lifecycle (`client/otp.js`, new).** `generatePad` = OS CSPRNG XOR an
  AES-CTR keystream keyed by SHA-256 of the user's drawn-motion samples (never
  weaker than the CSPRNG alone). `exportPad`/`importPad` = a passphrase-encrypted
  file (PBKDF2-600k → AES-256-GCM) carrying padId + region size + recipient role
  + pad bytes; export refuses a already-used pad (would hand the peer zeroed
  regions that XOR back to plaintext). localStorage persistence of bytes +
  offsets + role, pad index/list/forget. Size presets 64 KiB / 256 KiB / 1 MiB
  with honest per-side message estimates.
- **UI (`index.html`, `style.css`, `app.js`).** OTP panel: pad selector,
  generate (with a draw-to-generate entropy canvas), encrypted export (file
  download) / import (file upload), forget, and a live remaining-budget display.
  OTP unlocks messaging on peer PRESENCE (the pad is the out-of-band secret, like
  AES256's passphrase — no identity/safety-number gate). Offsets persisted after
  every send/receive so consumption survives reload (reuse would be
  catastrophic). `syncAlgUI` shows the panel; `connect()` loads the selected pad.
- **Docs.** README encryption-modes table + a new OTP paragraph state the two
  honest caveats plainly (computational MAC; CSPRNG-not-TRNG pad, so "at least as
  strong as the CSPRNG"). Backend needed no change — the `Algorithm` enum already
  allowed `OTP` (advisory tag; relay never acts on it).
- **Tests / verification.** New `otpChecks` in `crypto.test.mjs` (round-trip both
  directions, replay/tamper/reflection/forgery rejected, exhaustion refused, and
  FS zeroing asserted on sender + receiver) — `node crypto.test.mjs` green.
  Offline `npm test` green; all 3 live integration suites green (no regression to
  the other modes). **Real-browser check (Chromium/puppeteer, two isolated
  contexts):** Alice generated a pad with drawn entropy and exported the
  encrypted file; Bob imported it (wrong transfer passphrase rejected); both
  connected to one room, unlocked on presence, exchanged messages BOTH directions
  with zero undecryptable frames; the budget decremented; and localStorage showed
  the offsets persisted AND the consumed pad bytes zeroed at rest.
- **Known limits (documented):** a pad is a shared secret for exactly two
  devices (never import on more than one per side); pad size = total text budget
  (XOR consumes 1 byte/char + 32/msg); no post-compromise recovery beyond the
  zeroing already described. Cross-tab concurrent use of one pad on the same
  device is not locked — the offset is persisted before/after each send, but two
  tabs are a footgun; documented, IndexedDB/BroadcastChannel hardening is a
  future option if larger pads or multi-tab use are wanted.

### 2026-07-16 — Android pentest findings 1–4 (+ informational) FIXED ✅
Closed all four 2026-07-08 Android pentest findings and the informational
should-fix items. Root cause of Findings 1 & 3 was one permissive value flowing
into two sinks; fixed at the source plus defense in depth at each sink.
- **Finding 1 (CRITICAL) — relay-address → JS execution.** `RelayUrls.parse`
  (`RelayUrls.kt`) now rejects any host with a character outside
  `^[A-Za-z0-9.-]+$` (a `SAFE_HOST` regex) and rejects `user:pass@` authorities,
  BEFORE returning — so `android.net.Uri`'s permissive/percent-decoded `.host`
  can no longer smuggle `"`, `;`, `{`, `}`, spaces, or decoded delimiters
  downstream. Defense in depth: `MainActivity.loadWithRelay()` builds the
  injected `window.__SECURE_CHAT_RELAY__` config with `org.json.JSONObject`
  (proper escaping) instead of hand-interpolating a JS string literal.
- **Finding 2 (Medium) — prefix-confusable origin check.**
  `shouldOverrideUrlLoading` now compares the parsed `request.url.scheme`/`host`
  to the app origin (`https` + `appHost`), not `startsWith(appOrigin)`, so
  `https://secure-chat.internal.evil.com/…` is correctly treated as off-origin.
- **Finding 3 (Low) — CSP corruption.** Covered by the Finding 1 host whitelist:
  the value interpolated into `csp()` can no longer contain `;`/quotes/braces.
- **Finding 4 (Low/docs) — non-unique origin.** The asset loader now calls
  `.setDomain("secure-chat.internal")`, so the app serves from
  `https://secure-chat.internal` — an origin unique to this app, not
  androidx.webkit's shared `DEFAULT_DOMAIN`. `appOrigin`/`indexUrl`/`appHost`
  in `MainActivity.kt`, `APP_WEBVIEW_ORIGIN` in `backend/config.py` (WS + CORS
  allow-lists), and the `android/README.md` doc all updated in lockstep; the
  stale config.py comment claiming the default domain uniquely identifies the
  app is corrected.
- **Informational should-fixes.** `WebView.setWebContentsDebuggingEnabled` is now
  `if (BuildConfig.DEBUG)` (added `buildConfig = true` to `build.gradle.kts`);
  `network_security_config.xml` sets `base-config cleartextTrafficPermitted=
  "false"` and scopes cleartext to a `domain-config` of `127.0.0.1`/`localhost`/
  `onion` only; `importMapHash` drift is now guarded by
  `test_android_importmap_hash_matches` in `backend/tests/test_csp_hash.py`
  (recomputes the hash from index.html, asserts the Kotlin constant matches,
  skips when android/ isn't present so the backend stays standalone-testable).
- **Tests / verification:** new `android/app/src/test/.../RelayUrlsTest.kt`
  (Robolectric, so a REAL `android.net.Uri`) — 11 tests: legit https/loopback/
  onion/trailing-slash parse correctly; the exact Finding 1 PoC payloads
  (`http://y"};window.__pwn=1;%2f%2f`, percent-encoded `%2f%2f`/`%22`, and
  literal quote/brace/semicolon/space hosts) are all rejected; plus
  scheme/credentials/path-query-fragment/empty-host rejections.
  `./gradlew testDebugUnitTest` → 11 passed, 0 failures. Debug APK still builds
  clean (`./gradlew assembleDebug` BUILD SUCCESSFUL). Backend `pytest` = **57
  passed** (was 56 + the new drift guard). Web client untouched.
- **Remaining (unchanged):** on-device re-run of the app against the new origin
  + the identity/safety-number gate for DHKE/RSA/PQKEM (needs the emulator);
  app icon + release-signing config; OTP mode; Tor `.onion` deployment.

### 2026-07-08 — Android app pentest: 1 Critical + 3 Medium/Low found (NOT yet fixed) 🔴
Live pentest of the Android app on the same emulator used for on-device
verification, following this project's usual "attack the running system, prove
it with a live PoC" methodology. All four findings below are reproduced against
the actual installed APK; none require jailbreak/root — `run-as` on a **debug**
build stood in for "an attacker gets a value into `Prefs`", which for finding 1
is realistic via the app's own Settings dialog (see reachability note).

**Finding 1 — CRITICAL — relay-address string → arbitrary JS execution,
pre-page-script, CSP-bypassing (full app compromise).**
`RelayUrls.parse()` (`RelayUrls.kt`) validates a user-supplied "relay address"
using only `android.net.Uri.parse(text)` — scheme must be http/https, host must
be non-empty, and path/query/fragment must be absent. **`android.net.Uri` does
NOT validate hostname characters.** Empirically confirmed on-device: `"`, `;`,
`{`, `}`, and space all survive verbatim in `.host`; percent-encoding decodes
into `.host` too (`%22`→`"`, `%3a`→`:`, `%2f`→`/`) *without* tripping the
path/query rejection (the raw `%XX` bytes don't look like the real delimiter
chars to the top-level splitter, so a percent-encoded `%2f%2f` becomes a
literal `//` in the decoded host that the path check never saw coming).
`MainActivity.loadWithRelay()` then string-interpolates the PARSED value,
unescaped, into a JS snippet:
```kotlin
val js = "window.__SECURE_CHAT_RELAY__ = {api:\"${relay.httpOrigin}\", ws:\"${relay.wsOrigin}/ws\"};"
```
injected via `WebViewCompat.addDocumentStartJavaScript` — a mechanism that
(by design, so it can run before any page script) is **not subject to the
page's CSP**. The same unescaped value is also interpolated into the CSP
header itself (`csp()`), but that's a secondary effect (see Finding 3) — the
PRIMARY bypass is that `addDocumentStartJavaScript` doesn't consult CSP at all.
- **PoC 1 (marker):** relay address
  `http://y"};window.__pwn=1;%2f%2f` → after Uri decoding, httpOrigin becomes
  `http://y"};window.__pwn=1;//`. Substituted into the template, `//` becomes
  a JS line-comment eating the rest of the (single-line) injected script:
  `window.__SECURE_CHAT_RELAY__ = {api:"http://y"};window.__pwn=1;//", ws:...`
  parses as three clean statements (assign the object, `;`, `window.__pwn=1;`)
  followed by a comment. **Confirmed live via CDP: `window.__pwn === 1`.**
- **PoC 2 (real impact):** same technique, payload hooks
  `crypto.subtle.importKey` before any page script runs, then the "Create
  identity" / AES256-connect flow was driven for real. **Captured the actual
  first 8 bytes of the user's typed secret**: `[115,117,112,101,114,32,115,101]`
  = ASCII `"super se"` (from the passphrase "super secret victim passphrase"),
  proving the injected code can intercept identity/passphrase key material as
  the app derives it — a full break of the app's core security property
  (client-side key custody) via its one user-configurable value.
- **Reachability:** the ONLY way `Prefs` gets a relay value is the Settings
  dialog's `RelayUrls.parse(input.text.toString())` (confirmed by reading
  `MainActivity.kt` — no other write path exists). The realistic attack is
  social engineering: an attacker hands the victim a "relay address" to paste
  (a natural ask in this app — relays are meant to be shared), and the
  malicious JS executes the moment they hit Save (`loadWithRelay(parsed)`
  fires immediately with the freshly single-pass-parsed value, no restart
  needed). Note: writing the value to `Prefs` via `run-as` (used for the PoCs,
  since driving the native dialog's EditText through `adb shell input text`
  with these characters fights two layers of shell escaping) exactly reproduces
  what a successful dialog Save persists.
- **Fix direction:** `RelayUrls.parse` must reject any host containing
  characters outside a safe hostname charset (`[A-Za-z0-9.-]`, plus `[...]` for
  literal IPv6 — or just reject IPv6 literals too, unneeded here) BEFORE
  accepting it — don't rely on `Uri` alone. Independently, stop string-building
  JSON/JS by hand: `JSONObject` (or a proper JS-string-escape helper) for the
  injected config, and construct the CSP header via a list of validated tokens
  rather than raw interpolation.

**Finding 2 — Medium — `shouldOverrideUrlLoading` origin check is
prefix-confusable (chainable off Finding 1).**
```kotlin
override fun shouldOverrideUrlLoading(view: WebView, request: WebResourceRequest): Boolean =
    request.url.toString().startsWith(appOrigin).not()
```
`"https://appassets.androidplatform.net.evil.com/x".startsWith("https://appassets.androidplatform.net")`
is `true` — `startsWith` doesn't check for a following `/` or end-of-string.
**Live-confirmed:** ran `location.href = "https://appassets.androidplatform.net.evil.com/probe"`
via CDP inside the loaded page; `window.location.href` afterward was
`chrome-error://chromewebdata/` — a real failed-navigation page, proving the
WebView actually attempted to load the attacker-suffixed host (only failing
because that specific fake domain doesn't resolve in DNS; a real
attacker-owned domain would succeed). On its own this needs a script already
running to trigger `location.href` — but Finding 1 supplies exactly that,
so the two chain into "malicious relay string → JS execution → silent
top-level navigation to an attacker page" as a single attack. Fix: compare
`Uri.parse(request.url.toString()).host == "appassets.androidplatform.net"`
(and scheme), not string-prefix matching.

**Finding 3 — Low/robustness — the same unescaped relay value corrupts the CSP
header.** `csp()` also interpolates `relay.httpOrigin`/`wsOrigin` unescaped
into the `Content-Security-Policy` header value. A payload containing `;`
splits it into bogus extra "directives" (confirmed via WebView console:
`"The Content-Security-Policy directive name 'window.__pwn=1' contains one or
more invalid characters"` etc.) — Chromium safely rejects the malformed
directives, so this isn't itself an escape (script-src, set BEFORE
connect-src in the string, is unaffected), but it can silently swallow the
directives that come AFTER connect-src in the source (`img-src`, `base-uri`,
`form-action`, `frame-ancestors`) if enough injected `;` shift the boundary,
and/or break the app's OWN legitimate relay connection (connect-src ends up
with no valid entries but `'self'`). Same fix as Finding 1 covers this too.

**Finding 4 — Low/docs — `https://appassets.androidplatform.net` is
`androidx.webkit`'s shared default domain, not unique to this app.**
Verified directly from the library bytecode (`WebViewAssetLoader.class`):
`public static final String DEFAULT_DOMAIN = "appassets.androidplatform.net"`,
and `MainActivity.kt` never calls `.setDomain(...)`, so it uses this literal
default. **Any other Android app** using `WebViewAssetLoader` with default
settings presents an identical `Origin` header. `backend/config.py`'s comment
on `APP_WEBVIEW_ORIGIN` — *"a single fixed value, not a wildcard, so
allow-listing it does not open the relay to arbitrary web pages"* — is
therefore not accurate: it doesn't uniquely gate "our app". **Impact is
bounded, not ignored:** CORS only restricts browser/WebView-enforced
`fetch()`; any native Android code could already hit `/api` with a raw HTTP
client with no CORS involved at all, and `/api` is designed to expose nothing
sensitive to an unauthenticated caller (token-gated lookup, signature-verified
registration, no existence oracles — see the I1 closeout). So this doesn't
grant a new capability, but the code comment's claim is false and should be
corrected; fix by calling `.setDomain("secure-chat.internal")` (or similar) to
make the origin genuinely unique, which closes the gap outright.

**Verified negative (no finding):** `WebViewAssetLoader`'s `AssetsPathHandler`
correctly rejects path traversal — tried literal `../`, `%2e%2e/`, `..%2f`,
and `....//` variants against `/assets/web/...`; all either hard-failed
("Failed to fetch") or cleanly 404'd, no content outside `assets/web/` leaked,
while the legitimate `index.html` fetch succeeded normally. Also noted but not
separately itemized (pre-existing, informational): `setWebContentsDebuggingEnabled(true)`
is unconditional (not gated to debug builds — should be `if (BuildConfig.DEBUG)`
before a release build ships); `network_security_config.xml`'s
`cleartextTrafficPermitted="true"` is unscoped (any domain, not just
loopback/.onion) though the Mixed-Content browser check is the actual gate in
practice; `importMapHash` in `MainActivity.kt` is a hardcoded duplicate of the
backend's value with no automated drift guard analogous to
`backend/tests/test_csp_hash.py` (fails closed if it drifts — app breaks
loudly rather than a security hole, but worth a guard).

**Not yet fixed** — all four are on the TODO list below. Diagnostic code used
to characterize `Uri.parse` behavior was added temporarily to
`MainActivity.onCreate` during testing and fully reverted (`git diff` clean
afterward); the device's `Prefs` was reset to a benign
`http://127.0.0.1:8000` relay before finishing.

### 2026-07-08 — Android app verified ON-DEVICE + Mixed-Content fix ✅
Installed the emulator (Android 14 `google_apis;x86_64`, KVM-accelerated) and
ran the app on a real WebView. Findings + fixes:
- **Works on-device.** App installs, renders the full UI in the WebView, and the
  relay config is injected before page scripts (`addDocumentStartJavaScript`
  works on WebView 113). Drove the real app via Chrome DevTools Protocol (over
  the adb-forwarded devtools socket) against a host-side AES256 peer through the
  relay: the on-device WebSocket reached the relay, the AES256 nonce exchange
  completed, and messages decrypted BOTH directions on the device.
- **Real bug found: Mixed-Content transport constraint.** The client page is a
  secure origin (https asset loader — required for `crypto.subtle`), so the
  browser blocks opening an INSECURE `ws://` from it. `ws://10.0.2.2:8000` was
  refused with a SecurityError; the relay must be a *potentially-trustworthy*
  origin — **wss://** (TLS), **loopback** (`127.0.0.1`/`localhost`), or a
  **.onion**. This corrected a wrong doc claim (a plain `http://192.168.x.x`
  LAN relay does NOT work). Emulator test uses `adb reverse tcp:8000 tcp:8000`
  + relay `http://127.0.0.1:8000` (loopback is Mixed-Content-exempt).
- **Fix (`client/app.js`):** `new WebSocket()` throws synchronously on the
  Mixed-Content block, which previously left the UI stuck on "connecting…"
  forever. Now wrapped in try/catch → status "connection blocked" + an
  actionable hint (needs wss/loopback/.onion) + Connect re-enabled. Verified
  on-device: pointing at `http://192.168.50.50:8000` shows the clear error
  instead of hanging. (Web client unaffected — it is same-origin, never
  Mixed-Content.)
- **Docs corrected:** relay-settings dialog text, `network_security_config`
  comment, and `android/README.md` now state the trusted-transport requirement.
- **Regression:** offline `npm test`, all 3 live suites, backend `pytest` 56 —
  all green after the app.js change. APK rebuilt + reinstalled; on-device happy
  path re-passed.
- Remaining app polish: icon, release-signing config, and an on-device pass of
  the identity + safety-number gate (only AES256 driven on-device; DHKE/RSA/
  PQKEM handshakes are covered in-browser).

### 2026-07-07 — Android app: WebView shell bundling the audited client ✅
New `android/` Gradle module. Rationale: the web deployment's one honest trust
gap (H1) is that a browser re-fetches the JS from the server each load, so a
compromised server could serve malicious crypto. The app removes that by
shipping the exact reviewed client INSIDE the APK and using the relay only as a
dumb ciphertext carrier.
- **Design (thin shell, one codebase):** `MainActivity` serves bundled
  `assets/web/` to a WebView from the local secure origin
  `https://appassets.androidplatform.net` (WebViewAssetLoader — secure context,
  so `crypto.subtle` works). The relay is remote, so the app supplies what the
  same-origin web build got for free: (1) the relay location, injected as
  `window.__SECURE_CHAT_RELAY__ = {api, ws}` via `addDocumentStartJavaScript`
  BEFORE any page script; (2) the CSP, stamped as a response header on
  index.html with `connect-src` pinned to exactly the configured relay origin.
  The relay address is entered once (menu → Relay settings), stored in
  SharedPreferences, validated to an http(s) origin (`RelayUrls`). Identity/pins
  stay in the WebView localStorage as on the web.
- **Client change (backward-compatible, keeps ONE codebase):** `app.js` reads
  `window.__SECURE_CHAT_RELAY__` for the ws URL + API base if present, else the
  original same-origin behavior (RELAY null path). Web behavior byte-identical;
  verified by re-running the same-origin 4-mode browser matrix + all 3 live
  suites green.
- **Backend change (deliberate, documented):** the app's origin differs from
  the relay's, so `APP_WEBVIEW_ORIGIN` (`https://appassets.androidplatform.net`)
  is added to `ALLOWED_WS_ORIGINS` (else the relay 1008-rejects the WS) and to a
  new `/api` CORS allow-list (`ALLOWED_HTTP_ORIGINS`, methods GET/POST, no
  credentials — endpoints carry no cookies, only explicit Bearer tokens). It is
  one fixed origin, not a wildcard. New `SECURE_CHAT_EXTRA_ORIGINS` env var adds
  more origins (e.g. the prod `.onion`) at deploy time without editing code.
  Backend `pytest` still 56 passed.
- **Bundle = single source of truth:** the `syncWebClient` Gradle task copies
  `../client` into `assets/web` at build time (excludes tests/manifests), so the
  APK can never drift from the reviewed client; the copy is gitignored.
- **Build:** needs a full JDK 21 *with jlink* (the distro's openjdk-21 here was
  JRE-only — used a self-contained Temurin 21) + Android SDK platform-34 /
  build-tools-34. `./gradlew assembleDebug` → 5.7 MB debug APK,
  `org.securechat.app`, minSdk 26 / target 34. Clean build from source verified
  (assets auto-synced, 21 web files packaged).
- **Verified (real browser, Chromium/puppeteer — the WebView IS Chromium):**
  reproduced the app's exact cross-origin setup (bundled client on origin A,
  relay on origin B, relay config injected before scripts, app CSP applied):
  relay config visible to the page; cross-origin `/api` register succeeded
  (CORS); cross-origin WS DHKE handshake with MATCHING safety numbers; two-way
  messages delivered. This exercises the whole app code path except the Kotlin
  glue (asset loader / document-start injection / menu), which compiles +
  packages but is **NOT yet run on a device/emulator** (none in the build env).
  On-device smoke test is the remaining step.

### 2026-07-07 — DHKE/PQKEM in-session FS + reflection guards (ratchet unification) ✅
Closed the main informational finding from the same-day review (below): DHKE
and PQKEM kept one static AES-GCM session key (`AuthChannel`), so state
compromise mid-session decrypted that entire session. Now ALL FOUR modes run
the same forward-secret `RatchetChannel`; `AuthChannel` is DELETED.
- **DHKE (`crypto.js`):** the ECDH secret is HKDF'd into two direction-
  separated chain heads (info binds each chain to its sender's raw pub, salt =
  room id, domain `secure-chat/dhke-fs/v1`); frames are `dhke-msg/v2`. Exactly
  one derivation ever happens (first key wins), so the ECDH private key is
  dropped the moment the chains exist — in-session FS from the first message.
  `myPub` is cached at init so a (replayed-offer) `handshakePayload()` still
  answers after the keypair is gone.
- **PQKEM (`crypto.js`):** same chains rooted in the hybrid ECDH+ML-KEM ikm
  (info binds the sender's ECDH pub, domain `secure-chat/pqkem-fs/v1`); frames
  are `pqkem-msg/v2`. Seals like RSA on first real traffic (`_seal` zeroes the
  KEM secret key + raw shared secrets, drops the ECDH keypair; post-seal
  handshake frames ignored) — the race path may deliver a second root secret
  until then, and messaging sits behind the safety-number gate so the race has
  settled by first traffic. `ecdhBits`/`ikm` intermediates are zeroed right
  after HKDF import (they weren't before; DHKE's too).
- **Reflection guards (all handshake modes + hello):** an offer/answer carrying
  OUR OWN public key (DHKE pub / RSA pub / PQKEM ECDH or KEM pub) is refused
  outright — never legitimate, and identical pubs would collapse the direction
  separation of the chains. Previously only the human safety-number comparison
  caught a relay echoing someone's own identity back. Likewise app.js now
  refuses a hello carrying OUR OWN nonce (a reflected hello used to wedge the
  handshake via first-write-wins; now the slot stays open for the real peer).
- **Wire format:** DHKE/PQKEM `msg` frames changed (`{iv,ct,n}` ratchet frames
  under new domains; the old `secure-chat/msg/v1` AuthChannel framing is gone).
  Handshake payloads unchanged. Both ends always run the same served code, so
  no compatibility shim.
- **Tests:** new `handshakeRatchetChecks` in `crypto.test.mjs` — DHKE keypair
  dropped at derivation; PQKEM material held until traffic then sealed on
  first encrypt AND first decrypt; skipped-frame keys unrecoverable (both);
  replayed offers ignored post-establishment/post-seal; reflected handshakes
  rejected (DHKE/PQKEM/RSA). Existing reflection/replay/tamper + concurrency
  checks now exercise `RatchetChannel` in all 4 modes.
- **Verified:** client offline `npm test` green; backend pytest 56 passed; all
  3 live integration suites green; real-browser matrix (Chromium/puppeteer,
  two isolated contexts per mode) green for ALL 4 MODES — identities, matching
  safety numbers, two-way traffic, zero undecryptable/dropped frames — plus
  the double-click regression; server log still 0 bytes after all traffic.
- Deliberately NOT fixed (still informational): backend token-lookup timing
  (256-bit random tokens), relay per-peer send stall, verify-panel replay
  cosmetics. Post-compromise recovery (DH ratchet) remains out of scope.

### 2026-07-07 — final crypto review + full verification matrix ✅
White-box review of the whole client crypto stack (crypto.js, auth.js,
identity.js, account.js, app.js flow) + backend front door (validation.py,
relay.py, accounts.py, main.py). **No new High/Medium findings.** Verified
green across the board: client offline `npm test` (32 OK), backend `pytest`
56 passed, all 3 live integration suites, real-browser matrix
(Chromium/puppeteer, two isolated contexts per mode): ALL 4 MODES end-to-end —
identity creation, staggered join, matching safety numbers (handshake modes),
4 two-way messages, zero undecryptable/dropped frames — plus the double-click
regression check; server log EMPTY after all traffic (I2 holds).
Informational notes (as found; the first three were FIXED the same day — see
the ratchet-unification entry above):
- **DHKE/PQKEM have no in-session FS** — CLOSED same day (all modes now run
  `RatchetChannel`; `AuthChannel` deleted).
- Key-material hygiene (`ecdhBits`/`ikm` not zeroed) — CLOSED same day.
- A relay reflecting a peer's OWN hello back wedged the handshake until
  reconnect — CLOSED same day (reflected hello + reflected handshake keys now
  refused in all modes).
- A relay replaying a signed offer FROM THE CURRENT session verifies (same
  nonces) and can re-trigger `enterVerification` — ciphers are idempotent so
  no desync; worst case a duplicate sys line / re-shown verify panel (pin
  short-circuits it after first confirm). Cosmetic; left as is.
- Backend nits (left as is): bearer-token dict lookup isn't constant-time
  (256-bit random tokens — negligible); relay fan-out send has no per-peer
  timeout (a stalled peer only stalls its own room's sender).

### 2026-07-07 — cipher-call serialization: both 2026-07-03 pentest races CLOSED ✅
Fixed the two open concurrency findings (High + Medium) in one change; shared
root cause was that `AuthChannel`/`RatchetChannel` update their anti-replay
state (sequence counters, chain heads) across awaited WebCrypto calls while
their callers don't serialize (`ws.onmessage` fires handlers back-to-back; the
UI could fire overlapping sends).
- **Fix (`client/crypto.js`):** new `CallQueue` — a per-channel FIFO promise
  queue; both channel classes now route the public `encrypt()`/`decrypt()`
  through it into the (renamed) `_encrypt`/`_decrypt`. One call runs at a time,
  in arrival order; a rejected call propagates to its caller but never blocks
  the queue. Covers all 4 modes (AES256/RSA via `RatchetChannel`, DHKE/PQKEM
  via `AuthChannel`) with no wire-format or interface change.
  - Kills the **High** (racing decrypts of already-observed frames could
    commit out of order, roll the replay counter back, and re-accept a message
    the user already saw) and the **Medium** (two overlapping encrypts read the
    same chain head, consumed the same one-time key, and permanently desynced
    the ratchet — the peer saw an undecryptable frame and all later messages
    silently vanished).
- **Defense in depth (`client/app.js`):** `sendText` now has a `sending`
  in-flight flag and disables the Send button while an encrypt is pending
  (re-enabled only if the gate still allows messaging), so a double-click /
  Enter-repeat can't even queue a duplicate send. A disabled default submit
  button also blocks implicit (Enter) form submission per spec.
- **Tests (`crypto.test.mjs`, new `concurrencyChecks`, run for all 4 modes):**
  overlapping unawaited encrypts → both frames decrypt + channel intact after;
  3 concurrent decrypts of the SAME frame → accepted exactly once; the exact
  pentest rollback scenario (two different frames delivered concurrently, then
  both replayed) → both replays rejected. Confirmed the suite CATCHES the bug:
  against the pre-fix `crypto.js` (git stash) it fails at the overlapping-
  encrypt check with the ratchet-desync AEAD failure.
- **Verified:** client offline `npm test` green; backend `pytest` 56 passed;
  all 3 live integration suites green; **real-browser regression check**
  (Chromium/puppeteer, two isolated contexts, AES256): Alice double-clicks
  Send in the same tick → message delivered exactly once, zero undecryptable
  frames, ordinary follow-up messages flow both directions afterwards (the
  pre-fix behavior was a corrupted second frame and a permanently dead channel).

### 2026-07-03 — AES256 ratchet: cross-session replay CLOSED + honest FS ✅
Second half of TODO item (d), building directly on the RSA ratchet (below).
- **Refactor first:** RSA's ratchet framing was extracted into a shared
  `RatchetChannel` (`client/crypto.js`): direction-separated one-way
  HMAC-SHA-256 chains, one-time AES-256-GCM message keys, strictly increasing
  `n`, skip-with-discard bounded by `RATCHET_MAX_SKIP=1024`, scratch-head
  stepping committed only after AEAD success. `Rsa` now delegates to it
  (unchanged wire format/behavior, all RSA FS tests still green); `AuthChannel`
  now serves only DHKE/PQKEM.
- **AES256 redesign.** The mode still puts NO key material on the wire, but the
  ratchet chains are no longer derived from the passphrase alone: on join both
  peers exchange fresh random 32-byte session nonces via the app's existing
  plaintext `hello` phase (previously handshake-modes-only; AES256 has no
  identity requirement, so its hello is unauthenticated — tampering only
  desyncs keys, a loud DoS the relay could always cause). Chains =
  HKDF(PBKDF2-600k(passphrase), salt = room|sorted-nonces, info =
  `secure-chat/aes-fs/v1|` + sender's nonce); frames are `aes-msg/v2`.
  **Your own nonce is fresh and never attacker-controlled, so a frame captured
  in an earlier session (same room + passphrase) can never authenticate in a
  new one — the documented AES256 cross-session-replay residual is CLOSED**
  (relay-forced replay of an old peer nonce just desyncs loudly; it cannot make
  the victim re-derive an old key). Erasure: the cipher's passphrase copy is
  dropped at `init()`, the derived HKDF base right after chain derivation.
- **Honest FS limit (documented in README + KNOWN LIMITATIONS):** captured
  ratchet STATE can't decrypt earlier traffic, but the passphrase is a
  long-term secret outside the code and the nonces are public — passphrase
  compromise + recorded ciphertext still re-derives every session. Inherent to
  passphrase-only; real FS = DHKE/PQKEM/RSA.
- **app.js:** the hello phase now runs for every mode (`joined` sends it
  unconditionally); on hello, AES256 (`cipher.usesNonces`) derives via
  `cipher.setNonces(myNonce, peerNonce)` and unlocks (the passphrase is the
  out-of-band verification — no identity gate, as before, but send/receive now
  unlock only after the peer joins). A phase-2 signed-handshake frame arriving
  in AES256 mode is refused (`!cipher.needsHandshake` guard) — it could only be
  relay-injected.
- **Tests:** `crypto.test.mjs` — AES256 paths now exchange nonces; new
  `aesRatchetChecks`: **cross-session replay REJECTED** (fresh-receiver variant
  too, so it's the key, not the counter, doing the rejecting), passphrase/base
  erasure, skipped-frame-unrecoverable. `integration.test.mjs` harness speaks
  the AES256 hello. All offline suites green; all 3 live integration suites
  green; backend pytest 56 passed. **Verified in a real browser**
  (Chromium/puppeteer, two contexts): send locked before the peer joins,
  unlocks after the nonce exchange, 5 messages both directions, zero
  dropped/undecryptable frames; RSA browser check re-run green (regression, since
  the joined/hello path changed for all modes).

### 2026-07-03 — RSA mode: forward secrecy (key transport + one-way ratchet) ✅
Closed TODO item (d) for RSA. Previously every RSA message's AES key was
RSA-OAEP-wrapped to the peer's session-long RSA key, and the HMAC root secret +
RSA private key lived for the whole session — so state compromise at any point
(or later, with a recorded transcript) decrypted the ENTIRE session. That
per-message wrapping was inherently incompatible with forward secrecy and was
removed.
- **New design (`client/crypto.js`, Rsa class).** The handshake is unchanged on
  the wire (offer `{pub}`, answer `{pub, ws}` with the OAEP-wrapped 32-byte
  root secret; race-tolerant sorted-tag folding; first-write-wins). From the
  root, HKDF derives two direction-separated **HMAC-SHA-256 chain keys** (info
  binds the sender's pub, salt = room id, domain `secure-chat/rsa-fs/v1`). Each
  message uses a **one-time AES-256-GCM key**: `msgKey = HMAC(chain, 0x01)`,
  then `chain = HMAC(chain, 0x02)` — one-way, consumed keys erased (raw bytes
  zeroed after import, keys non-extractable). Frames are `{iv, ct, n}` with AD
  `secure-chat/rsa-msg/v2|room|n` (v1 frames are thus invalid). A gap in `n`
  fast-forwards the chain and DISCARDS the skipped keys (bounded by
  `RSA_MAX_SKIP=1024` against hostile-relay CPU burn); the receive step is
  committed only after the AEAD authenticates, so a garbage frame can't wedge
  the channel or burn keys.
- **Sealing.** On the first real message (either direction) `_seal()` erases
  the root secrets AND drops the RSA private key (+ peer wrap key) — the two
  things that could replay the whole key schedule from a recorded transcript.
  Post-seal handshake frames are ignored (a replayed offer can't desync or
  resurrect state). Sealing at first traffic is safe because messaging sits
  behind the safety-number gate, seconds after the handshake settles; a relay
  withholding a race answer past that point could only cause a loud decrypt
  failure (= DoS it could do anyway). Same documented race window as PQKEM.
- **Properties:** forgery still fails (relay never learns the root → no valid
  AEAD); reflection fails (direction chains); replay fails (strictly increasing
  `n` + one-time keys); **in-session forward secrecy** (state at time T can't
  decrypt before T); cross-session FS was already given by per-session RSA keys.
  NOT provided (out of scope): post-compromise/break-in recovery — that needs a
  DH-style ratchet, pointless to fake with RSA.
- **Tests:** `crypto.test.mjs` — `rsaAttackChecks` updated (forgery/reflection/
  replay/tamper still rejected; + channel survives a rejected frame). New
  `rsaForwardSecrecyChecks`: seal erases kp/secrets on first send AND first
  receive; skipped frame's key unrecoverable while later frames decrypt;
  post-seal replayed offer ignored; far-future `n` rejected. All offline suites
  green; all 3 live integration suites green; backend pytest 56 passed.
  **Verified in a real browser** (Chromium/puppeteer, two isolated contexts):
  RSA staggered join, matching safety numbers, 5 messages both directions
  (ratchet advancing), zero dropped/undecryptable frames.
- app.js unchanged except a comment (generic cipher interface held); README
  encryption-modes table + RSA paragraph rewritten.

### 2026-07-02 — L2/I2 closeout: metadata-at-rest disabled + room-id guarantee ✅
Closed the last two accepted-risk items from the 2026-06-19 review.
- **I2 — no request/connection metadata at rest (code fix).** Uvicorn's access
  log wrote every request line (method/path/status/timing) and its error logger
  emitted INFO connection-lifecycle lines ("connection open/closed") — a
  who-connected-when trail if a `.onion` host is seized. `main.py` now disables
  the access logger and lifts `uvicorn.error` to WARNING at import
  (`_minimize_log_metadata`), the `__main__`/`uvicorn.run` path passes
  `access_log=False, log_level="warning"`, and `run.sh` carries
  `--no-access-log --log-level warning`. Verified live: after healthz + `/api`
  + a full WebSocket relay round-trip, the server log is EMPTY. Only genuine
  error tracebacks (never payloads/room ids) are ever logged. Guard test
  `tests/test_logging.py` (access logger disabled, error logger ≥ WARNING,
  run.sh keeps the flags) fails loudly on regression.
- **I2 does NOT change behavior** — purely removes logging; all suites still green.
- **L2 — room-id bearer-capability risk: closed as a documented bounded
  guarantee (no code change).** A room is joined by knowing its 256-bit id; the
  relay is deliberately anonymous (no joiner auth) to keep who-talks-to-whom off
  the server. A mechanism "fix" (relay-side admission control) would require
  binding identities to the relay and recording exactly that metadata — a net
  loss for the primary threat model. The impact of a leaked room id is already
  bounded to **availability + coarse metadata, never confidentiality or
  impersonation**: the relay forwards only opaque ciphertext, and the
  authenticated + safety-number-gated handshake stops a squatter posing as the
  real contact (AES256's unsent passphrase is its gate). Structural mitigations
  already in place: room ids are high-entropy (256-bit) and single-use/rotatable
  — treat one like a one-time secret. Documented precisely in README
  ("Metadata & residual risks") and the relay/threat notes.
- Backend `pytest` = **56 passed** (+3 logging guards).

### 2026-07-02 — accepted-risk closeout: L1 (PQ ownership proof) + I1 (enumeration) ✅
Closed the two accepted-risk items from the 2026-06-19 security review.
- **L1 — server-side ML-DSA-65 ownership proof at registration.** Registration
  now requires a dual signature over the bundle: the server verifies BOTH the
  Ed25519 proof (as before, via `cryptography`) AND an ML-DSA-65 proof (new,
  via `dilithium-py` — a pure-Python verifier, cross-checked against the
  client's `@noble/post-quantum` signer). A registrant can no longer bind a PQ
  public key they don't control. `RegisterReq` gains `mldsa_sig`; `account.js`
  now signs the register message with `identity.sign()` (dual) instead of
  `signEd()`. New dep: `dilithium-py==1.4.*` (verify only; the server is still
  not the authenticity root — the in-person safety number is).
- **I1 — username namespace made non-enumerable (token-gated lookup + oracle
  removal).** Registration mints a random per-account lookup token
  (`config.LOOKUP_TOKEN_BYTES=18`, ~144 bits); the shareable identifier is now
  the HANDLE `username#token`. `GET /api/users/{name}?t=<token>` returns an
  IDENTICAL 404 for a missing user OR a wrong token (constant-time compare
  against a decoy for missing users), so a bare/guessed username reveals
  nothing. `POST /api/auth/challenge` now issues a challenge for ANY well-formed
  username (no existence 404) and `POST /api/auth/verify` returns 401 for
  unknown-user and bad-sig alike — neither is an existence oracle anymore. A
  dedicated stricter per-host rate limit (`_lookup_limiter`) bounds the lookup
  path. Client: `account.parseHandle`, handle-based `fetchBundle`, register
  stores + displays the handle, the contact field takes a handle. Residual
  (documented, inherent): registering a taken name still 409s — but each probe
  costs a full dual-signed proof and is rate-limited, and enumeration of the
  bundle-fetch path is closed.
- **DB:** `accounts` table gains `lookup_token` (with an ALTER-based migration
  for pre-token DBs).
- **Tests:** `test_accounts.py` rewritten to sign with real ML-DSA (dilithium)
  and cover the new behavior: bad-PQ-sig rejection, missing `mldsa_sig`,
  token-gated lookup (no/wrong token → 404), challenge-doesn't-reveal-existence,
  verify-unknown-user-is-401, and a dedicated lookup rate-limit test. Backend
  `pytest` = **53 passed**. `accounts.integration.test.mjs` updated for the
  handle flow (incl. wrong-token → null). Verified in a real browser
  (Chromium/puppeteer): Alice registers → handle shown; Bob's WRONG token fails
  to resolve; Bob's correct handle → directory lookup, matching safety number,
  message delivered. All offline + live suites green.

### 2026-06-19 — backend v0 (local relay)
- Created project at `~/secure-chat`.
- `backend/config.py` — all hard limits in one auditable place (frame size,
  payload size, room id length, max members/rooms, rate-limit params).
- `backend/validation.py` — strict pydantic `Envelope` (extra fields forbidden,
  immutable), printable-ASCII check, base64 payload check, 64-hex room ids,
  enum message types + advisory algorithm enum, payload-presence rules.
- `backend/relay.py` — in-memory `RoomRegistry` (no storage, empty rooms
  deleted) + per-connection `TokenBucket` rate limiter.
- `backend/main.py` — FastAPI app, single `/ws` WebSocket endpoint, `/healthz`,
  security headers, CORS locked shut, docs/openapi disabled, payloads never
  logged, fail-closed validation, size cap before parse, rate limit.
- `backend/tests/test_validation.py` — unit tests for the validation front door.
- `backend/tests/smoke_client.py` — two-client end-to-end relay smoke test.
- `backend/run.sh`, `requirements.txt`, `README.md`, `.gitignore`.

### Security measures already in place (server side)
- Server does no crypto and holds no keys/plaintext (E2EE dumb relay).
- Strict, fail-closed input validation; unknown fields/types rejected.
- ASCII-only enforced on the whole frame.
- Frame size cap (64 KiB) checked before any parsing.
- Payload size cap (~48 KiB) + base64-only payload.
- Per-connection token-bucket rate limiting.
- Global connection cap + per-connection idle read timeout (zombie reaper).
- Global room cap + per-room member cap (DoS/memory bounds).
- Rooms in-memory only; deleted when empty (no data at rest).
- Message payloads never logged; no stack traces leaked to clients. Access log
  + connection-lifecycle logging disabled (I2) — no request/timing metadata at
  rest; only content-free error tracebacks are recorded.
- CORS disabled; security headers (CSP `default-src 'none'`, nosniff, DENY,
  no-referrer); API docs/OpenAPI endpoints disabled; server header stripped.

### 2026-06-19 — verified locally ✅
- venv created, deps installed.
- `pytest tests/test_validation.py` -> **12 passed**.
- Server started; `/healthz` 200 with all security headers present;
  `/docs` -> 404 (disabled); `Server` header **absent** (stripped via
  `server_header=False` / `--no-server-header`).
- `smoke_client.py` -> two clients joined the same room, opaque base64 payload
  relayed **verbatim** and decoded correctly on the peer. Server log shows
  only connection lifecycle, **no payloads**.

### 2026-06-19 — web client + key exchange + server hardening ✅
- `client/crypto.js` — Web Crypto only (no hand-rolled crypto). Implements:
  - **AES256**: shared passphrase → PBKDF2-SHA256 (310k iters, room id as salt)
    → AES-256-GCM. No network handshake.
  - **DHKE**: ephemeral ECDH P-256 → AES-256-GCM, private key non-extractable.
  - **RSA**: RSA-OAEP-2048 public-key swap, hybrid per-message AES-256-GCM.
  - PQKEM + OTP marked unavailable (documented, UI-disabled).
- `client/index.html` + `style.css` + `app.js` — minimal UI: room id (+256-bit
  generator), encryption selector, passphrase field, message log. No inline
  JS/CSS or inline handlers (CSP-clean). Rendering uses textContent only (no
  innerHTML) → no XSS path.
- Handshake protocol over the relay's `key` message: payload = base64(JSON
  {pub, reply}); `reply` flag makes the early joiner answer exactly once, so
  the exchange converges with no infinite ping-pong (verified).
- Server hardening:
  - **WebSocket Origin allow-list (CSWSH protection)** — present-but-disallowed
    origin → 403; missing Origin (native/CLI) allowed.
  - Static web client served **same-origin** via StaticFiles (path traversal
    blocked); explicit /ws + /healthz routes take precedence.
  - CSP tightened to allow only same-origin script/style/connect, no inline.
- Tests:
  - `client/crypto.test.mjs` — round-trips for all 3 algos + wrong-key reject
    + ascii guard. **All pass** (Node Web Crypto).
  - `client/integration.test.mjs` — two real WebSocket clients through the
    running relay, full handshake + message exchange for all 3 algos.
    **All pass.**
  - curl checks: `/`→200, `/app.js`→200, traversal→404, evil Origin→403,
    CSP header present, relay log shows **no payloads**.

## KNOWN LIMITATIONS / THREAT NOTES (read before trusting E2EE)
- **Key-exchange MITM — CLOSED in the live web client (2026-06-19).** DHKE and
  RSA handshakes are now signed by a long-term identity (Ed25519 + ML-DSA-65)
  and verified against the peer's bundle, gated by an in-person safety-number
  check (option (b) from the original plan). A relay swapping the ephemeral key
  fails signature verification; a relay swapping the whole identity yields
  mismatched safety numbers at the two endpoints. AES256-passphrase mode remains
  not-MITM-able (no key material exchanged). Residual trust assumptions:
  - Users MUST actually compare the safety number out of band; clicking through
    "it matches" without checking reduces this to trust-on-first-use.
  - The account directory (`/api`) is only a convenience for *fetching* a bundle;
    it is not a trust root. Authenticity still comes from the in-person check.
- **AES256 forward secrecy is honest-but-limited (2026-07-03).** AES256 now
  ratchets too (one-time message keys; passphrase copy + derived base erased
  after chain derivation), and its session chains bind BOTH peers' fresh
  session nonces — so captured ratchet STATE can't decrypt earlier traffic and
  cross-session replay is closed. But the passphrase itself is a long-term
  secret outside the code (user's head, input field) and the nonces cross the
  relay in the clear: passphrase compromise + recorded ciphertext still
  decrypts every session, past and future. Inherent to a passphrase-only mode;
  real FS = DHKE/PQKEM/RSA — all three ratchet per message AND erase their
  handshake material (RSA/PQKEM seal on first traffic, DHKE drops its private
  key at derivation; since 2026-07-03/2026-07-07), on top of per-session
  ephemeral keys.
- **AES256 passphrase is offline-attackable by the relay.** The room id (which
  the relay routes on, so it always knows it) is the PBKDF2 salt, and the relay
  sees the ciphertext — so a malicious/compromised relay can mount an offline
  dictionary attack on the passphrase. 600k PBKDF2 iterations slow this, but a
  low-entropy passphrase will fall: AES256 security rests entirely on passphrase
  strength. Prefer a generated high-entropy passphrase, or use DHKE/PQKEM.
- **Reflection/replay — CLOSED for all modes, incl. cross-session
  (2026-07-02, completed 2026-07-03; unified 2026-07-07).** ALL FOUR modes now
  use the same `RatchetChannel`: direction-separated one-way chains + one-time
  message keys + strictly increasing sequence numbers. Reflected handshake
  keys and reflected hellos are additionally refused outright (2026-07-07).
  The old AES256 residual — cross-session replay of a frame captured under the
  same passphrase + room id — is CLOSED since 2026-07-03: the session chains
  bind a fresh random nonce from BOTH peers, so an old frame can never
  authenticate in a new session. DHKE/PQKEM are ephemeral per session and
  never had the residual.
- **Metadata:** relay sees room id + timing + ciphertext sizes (padding TBD).

### 2026-06-19 — identity keys + authenticated handshake (MITM gap closed in core) ✅
- Trust model chosen (per user): **simple accounts, each with a long-term
  identity keypair you verify IN PERSON; verified identity keys authenticate
  the per-session key exchange.** Dual keys — classical + post-quantum:
  - **Ed25519** (classical) via Web Crypto (native, 32-byte pub, 64-byte sig).
  - **ML-DSA-65 / Dilithium** (post-quantum) via `@noble/post-quantum`
    (1952-byte pub, 3309-byte sig). Dependency scoped to PQ only.
- `client/identity.js` — `Identity` class: generate, `publicBundle()`,
  `fingerprint()` (per-key, read aloud to verify), `safetyNumber()` (pair,
  order-independent), dual `sign()`, static dual `verify()` (BOTH schemes must
  pass), encrypted `export()/import()` of private keys at rest (PBKDF2 310k →
  AES-256-GCM, passphrase-protected; private keys never leave the device).
- `client/auth.js` — authenticated handshake: signs transcript
  `DOMAIN || roomId || ephemeralPubKey` with the identity; verifier checks the
  dual signature against the PINNED peer identity before trusting the ephemeral
  key. roomId binding prevents cross-room replay.
- `client/identity.test.mjs` — **proves the security property**: simulates a
  malicious relay (Mallory) swapping the ephemeral key; authenticated handshake
  REJECTS (swapped key + old sig, impostor sig, and cross-room replay) and
  ACCEPTS only the genuine signed key. Also covers dual-sig tamper rejection,
  fingerprint determinism, safety-number order-independence, encrypted
  export/import + wrong-passphrase rejection. **All pass.**
- `client/package.json` — `@noble/post-quantum` dep; `npm test` runs crypto +
  identity suites. Installed clean (0 vulnerabilities).
- Library facts (verified in Node 22): Web Crypto Ed25519 = supported;
  `@noble/post-quantum` API is `ml_dsa65.sign(msg, secretKey)` /
  `verify(sig, msg, pubKey)`; ML-KEM-768 available for future PQ key exchange.

### 2026-06-19 — account directory (passwordless, key-based) ✅
- DECIDED with user: **passwordless / key-based login** (server stores only
  public keys; login = sign a server challenge) + **identity key encrypted in
  the browser** (passphrase-unlocked; manual export/import as backup).
- `backend/accounts.py` — SQLite-backed public-key directory + FastAPI router
  under `/api`. Stores only username -> {ed_pub, mldsa_pub}; never secrets.
  Endpoints:
  - `POST /api/register {username, ed, mldsa, sig}` — sig = Ed25519 over
    `secure-chat/register/v1\n<username>\n<ed>\n<mldsa>`; proves control of the
    classical key + binds the bundle (anti-squatting). Strict size checks.
  - `GET /api/users/{username}` — returns the public identity bundle to pin.
  - `POST /api/auth/challenge {username}` — returns a fresh 32-byte nonce (TTL).
  - `POST /api/auth/verify {username, challenge, sig}` — verifies Ed25519 over
    the nonce, one-time-consumes the challenge, issues a bearer token (TTL).
  - `GET /api/me` (Bearer) — resolves token -> username.
- `backend/config.py` — DB path (env `SECURE_CHAT_DB`), username rules, fixed
  key/sig sizes, challenge/token TTLs.
- Server-side crypto: `cryptography==43.*` for Ed25519 verify. (ML-DSA verified
  CLIENT-side in the handshake; server only stores the PQ pubkey — server is
  not the authenticity root, so no native PQ dep needed server-side.)
- `backend/tests/test_accounts.py` — 12 tests: register+lookup, bad sig,
  duplicate, bad username, wrong key size, unknown user, full login flow,
  wrong-sig login, one-time challenge, token required, extra-field rejection.
  **All pass.** Full server suite now **24 passed**.
- Relay `/ws` intentionally stays **anonymous/room-based** (accounts are a key
  directory + auth, not coupled to the relay) to minimize who-talks-to-whom
  metadata. Documented as a deliberate choice.

### 2026-06-19 — browser wiring of identity/auth (live MITM gap CLOSED) ✅
- **Vendored ESM + import map.** Traced the transitive import closure of
  `@noble/post-quantum/ml-dsa.js` (12 files across post-quantum/hashes/curves,
  ~184 KB) and vendored byte-identical copies into `client/vendor/@noble/...`
  (`client/vendor/README.md` records provenance + versions). `index.html` has an
  inline `<script type="importmap">` mapping the three `@noble/` prefixes into
  `vendor/`. Inline import maps are required by spec, so instead of loosening CSP
  it is **pinned by its exact SHA-256 hash** in `script-src` (no `'unsafe-inline'`).
- **Identity UI** (`app.js` + `index.html`): create / unlock / forget / copy-
  backup. Private keys live only inside the passphrase-encrypted blob in
  `localStorage` (`Identity.export/import`); the fingerprint is shown for the
  contact to verify. Identity is **required** for DHKE/RSA, optional for AES256.
- **Authenticated handshake**: the `key` message now carries
  `{pub, reply, idb, sig}`; the receiver runs `verifyHandshake` (dual Ed25519 +
  ML-DSA) against the received bundle before deriving the shared key, and
  refuses + disconnects on failure (visible MITM signal).
- **In-person verification gate**: after the signature verifies, the UI shows
  the safety number and blocks messaging until the user confirms it matches.
  Confirmed bundles are pinned per room id (`sc.pins.v1`); a later session whose
  key differs raises a loud "identity CHANGED" banner and forces re-verification.
- **Tests**: `client/auth.integration.test.mjs` drives two real WebSocket peers
  through the running relay using the exact app.js authenticated protocol and
  asserts both derive the same key + identical safety number (DHKE + RSA). The
  vendored closure was separately proven self-sufficient under import-map-
  equivalent resolution. Existing suites still green (crypto, identity, legacy
  integration; backend pytest **24 passed**); server serves the pinned-hash CSP,
  the import map, and `vendor/@noble/...` same-origin.

### 2026-06-19 — relay WebSocket endpoint tests + deterministic leave-close ✅
- `backend/tests/test_ws.py` — 16 in-process endpoint tests driving the real
  `/ws` loop via Starlette `TestClient`: join→joined, verbatim msg/key relay,
  not-in-room, double-join, wrong-room, room-full (3rd member), leave-closes,
  oversized-frame, non-ascii, bad-envelope (+ connection survives a soft
  reject), extra-field-over-the-wire, rate-limit flood, and the CSWSH origin
  allow-list (disallowed rejected; allowed + missing accepted). Full backend
  suite now **40 passed**.
- `backend/main.py` — on a `leave` message the server now `await ws.close()`s
  explicitly before breaking, instead of relying on the framework's implicit
  close (which left the peer's socket hanging without a close frame). More
  correct relay behaviour and makes leave deterministically observable.

### 2026-06-19 — connection-level abuse / DoS bounds ✅
- `backend/config.py` — `MAX_CONNECTIONS` (global concurrent-socket cap) and
  `IDLE_TIMEOUT_SEC` (per-connection idle read timeout, 15 min default).
- `backend/relay.py` — `ConnectionLimiter` (`try_acquire`/`release`, single-
  event-loop safe) bounding total concurrent connections.
- `backend/main.py` — refuse over-cap connections at the handshake (close 1013)
  before `accept()`; wrap each `receive_text` in `asyncio.wait_for(IDLE_TIMEOUT)`
  to reap half-open/zombie sockets and connect-but-never-join squatters
  (warn + close 1001); release the slot in `finally`.
- Deliberately **did not** add a per-connection lifetime frame cap (the token
  bucket already bounds throughput; a lifetime cap would punish long chats) or
  per-IP limits (behind Tor all traffic appears from loopback, so per-IP is
  meaningless on `.onion`). Both noted inline.
- `backend/tests/test_ws.py` — +2 tests (cap refuses 3rd over a patched cap of
  2; silent socket is idle-timed-out and closed). Full server suite **42 passed**.

### 2026-06-19 — browser account directory integration ✅
- `client/identity.js` — added `signEd()` (classical-only Ed25519 signature) for
  server account proofs; the directory is not the authenticity root, so the PQ
  key isn't needed there.
- `client/account.js` — new module wrapping the `/api` directory protocol:
  `register` (Ed25519 proof binding username→bundle, byte-for-byte matching the
  server's `_register_message`), `fetchBundle` (lookup by username; null on 404),
  `login` (challenge → sign → token), `me`, and a shared username validator.
- `client/app.js` + `index.html` — account panel (claim username / log in) that
  appears once an identity is unlocked and remembers the username locally; an
  optional **Contact username** field in setup (DHKE/RSA only). On connect the
  client fetches that contact's bundle and uses it in the verification gate:
  pins are now keyed `user:<name>` when a username is in play (else `room:<id>`),
  and a live key that disagrees with the directory entry raises a loud mismatch
  banner. The in-person safety number remains the trust anchor.
- `client/accounts.integration.test.mjs` — drives account.js against the live
  server: register→lookup→login→me round-trip, duplicate-username 409, and
  wrong-key login rejection. All pass. (A static check also confirms every
  element id app.js references exists in index.html.)
- No CSP change needed (`connect-src 'self'` already covers the same-origin
  `/api` fetches; account.js/identity.js load under `script-src 'self'`).

### 2026-06-19 — post-quantum key exchange (PQKEM mode) ✅
- Completes the original encryption menu: the **key exchange** is now post-
  quantum too, not just the authentication. (Authentication was already
  one-classical-one-PQ: Ed25519 + ML-DSA-65 dual signatures on the handshake.)
- `client/crypto.js` — new `Pqkem` cipher: **hybrid ECDH P-256 + ML-KEM-768**,
  combined via HKDF-SHA-256 (salt = room id, domain-separated info) into an
  AES-256-GCM key. Secure unless BOTH primitives break ("harvest now, decrypt
  later" resistance) and no weaker than DHKE if ML-KEM were faulted. Vendored
  `@noble/post-quantum/ml-kem.js` (only new file; rest of the closure was shared
  with ml-dsa → 13 vendored files; import map already covers it).
- The exchange is **symmetric and join-order-race tolerant**: each peer offers a
  KEM public key, the other encapsulates, and secrets are folded in keyed by
  `SHA-256(ek)` so both sides combine the same secret(s) in the same order — one
  secret in the normal (staggered-join) case, two in the simultaneous-join race,
  converging either way. The brief two-step settling in the race is covered by
  the manual safety-number gate (no message is sent until the user confirms,
  seconds later, by which point the key is final).
- `client/app.js` + `index.html` — PQKEM enabled in the menu and treated as
  identity-required (authenticated handshake). Removed the per-connection
  handshake-signature cache (`myEph`): PQKEM's offer and answer are distinct
  payloads, each signed fresh; idempotent and harmless for DHKE/RSA.
- Tests: PQKEM added to `crypto.test.mjs` (2-round = the race path, converges),
  `integration.test.mjs`, and `auth.integration.test.mjs` (safety number
  matched). Integration harnesses now **stagger** joins (the realistic order).
  **Verified in a real browser** (Chromium via puppeteer): PQKEM selectable,
  handshake completes, safety numbers match, and messages decrypt **both
  directions** — confirming the vendored ML-KEM loads under CSP + import map.

### 2026-06-19 — security review + hardening (pentest follow-up) ✅
Ran a white-box review + live attack probes. Fixed the actionable findings:
- **M1 — `/api` abuse bounds.** Added a per-client-host token-bucket
  (`KeyedRateLimiter` in relay.py; on Tor it collapses to one global throttle)
  as a router-wide dependency on `/api` → floods now get `429` (confirmed live:
  27/90 blocked; previously 0). Added hard caps: `MAX_ACCOUNTS` (register →
  `503` when full), `MAX_PENDING_CHALLENGES`, `MAX_ACTIVE_TOKENS` (bounds the
  in-memory auth stores so a flood can't exhaust memory even within the TTL).
- **M2 — join deadline.** Split a short `JOIN_TIMEOUT_SEC` (30 s) for pre-join
  sockets from the generous `IDLE_TIMEOUT_SEC` (15 min) for joined peers, so
  "connect but never join" slot-squatters are dropped fast.
- **L3 — KDF work factor.** PBKDF2-SHA256 raised 310k → **600k** (OWASP 2023)
  for AES256 mode and identity-at-rest. Export blob is now `v:2` and stores
  `iters`; import honours it and falls back to 310k for old `v:1` backups
  (regression-tested).
- **H1 — honest trust boundary.** README now scopes "server compromise → only
  ciphertext" to *passive* compromise and documents that the web client trusts
  the server to serve honest code each load (mitigations: Android app, `.onion`,
  reproducible builds). Not a code change — a corrected security claim.
- Tests: +5 backend (`api` rate limit, account/challenge/token caps, join
  timeout) and +1 client (legacy-blob import). Server suite **47 passed**;
  client crypto/identity + all integration suites green.
- **Accepted / deferred (documented, not fixed):** L1 (ML-DSA pubkey ownership
  not proven at registration — needs a native PQ verify; no impersonation
  results since the in-person safety number is the trust root), L2 (room-slot
  squatting if a 256-bit room id leaks), I1/I2 (username enumeration + access-log
  metadata — inherent to a public directory; scrub logs on the `.onion`).
  **UPDATE 2026-07-02 (second session): ALL FOUR now CLOSED** — L1/I1 in the
  "accepted-risk closeout" entry; L2 (documented bounded guarantee) and I2
  (access/connection logging disabled) in the "L2/I2 closeout" entry below.

### 2026-07-02 — RSA mode: per-message HMAC authentication (forgery fix) ✅
- **Finding (code review):** RSA mode had NO message authenticity. Each message
  was a fresh AES key RSA-OAEP-wrapped to the recipient's public key — but that
  key crosses the relay in the (unencrypted, only signed) handshake, so the
  relay could wrap its own AES key and inject messages that decrypted cleanly
  and rendered as "peer". Encrypting to a public key proves nothing about the
  sender. (DHKE/PQKEM/AES256 don't have this: their GCM key is a shared secret
  the relay never learns.)
- **Fix (`client/crypto.js`, Rsa class):** the handshake answer now transports
  a random 32-byte MAC secret, RSA-OAEP-encrypted to the offerer's public key
  (`ws` field — covered by the existing identity signature over the whole
  payload, so the relay can't strip/replace it). Both sides HKDF-SHA-256 the
  secret (salt = room id) into TWO direction-separated HMAC-SHA-256 keys (info
  binds the sender's public key). Every message now carries a strictly
  increasing sequence number `n` and `mac = HMAC(sendKey,
  domain|room|n|ek|iv|ct)`; receivers verify the MAC BEFORE any decryption and
  reject stale `n`. Defeats: forgery (relay never learns the wrapped secret),
  reflection (direction keys), replay (seq + per-session secret). Wrapped
  secrets are folded into HKDF keyed by SHA-256(recipient pub), sorted — same
  race-tolerant convergence pattern as PQKEM — and first-write-wins so a
  replayed handshake frame can't diverge the keys.
- RSA's offer/answer are now distinct payloads (like PQKEM); app.js already
  handled that generically, so only comments changed there. `makeCipher` passes
  the room id to `Rsa`. Shared byte helpers (`concatBytes`, `sha256Hex`) moved
  above the RSA section (used by RSA + PQKEM).
- **Tests:** `crypto.test.mjs` + `rsaAttackChecks()` — Mallory-as-relay
  completes her own handshake from B's observed offer and injects a message
  (the exact old attack): REJECTED; reflection of A's own frame: REJECTED;
  replay of a genuine frame: REJECTED; tampered ciphertext: REJECTED (MAC
  checked before decrypt). All suites green after the change: client offline
  (`npm test`), both live integration suites (integration + auth, all algos),
  backend `pytest` 47 passed.
- **Still open (documented in KNOWN LIMITATIONS):** AES256/DHKE/PQKEM still
  lack reflection/replay protection; porting this MAC construction (or an AD/
  direction-key variant) to them is a natural next step.

### 2026-07-02 — verification gate now covers receiving (pre-verify display fix) ✅
- **Finding (code review):** the safety-number gate only blocked SENDING.
  Inbound `msg` frames were decrypted and rendered as "peer" as soon as
  `cipher.ready`, i.e. before the user confirmed the safety number. In the
  exact threat the gate exists for — a relay swapping the whole identity and
  running a MITM session — the swapped bundle carries a valid signature (the
  relay's own key), so the handshake verifies and the attacker could display
  messages as a trusted peer pre-verification (e.g. social-engineering the
  user into clicking through the gate).
- **Fix (`client/app.js`):** new `verified` flag, set only by
  `unlockMessaging()` (pin match / user confirms) and by the AES256 no-gate
  path (its passphrase IS the out-of-band verification); reset on connect and
  on socket close. The `msg` handler drops frames (never decrypts, shows a
  "[dropped]" sys line) while `verified` is false.
- **Verified in a real browser** (Chromium via puppeteer-core, DHKE): a
  Node-side authenticated peer completed the handshake and sent a message
  while Alice's verify panel was open → dropped, not rendered, send still
  locked; after clicking "it matches" a follow-up message rendered normally.
  All existing suites still green (client offline `npm test`, all 3 live
  integration suites, backend pytest 47 passed).

### 2026-07-02 — reflection/replay closed everywhere + crypto hardening ✅
Follow-up review after the receive-gate fix; fixed the remaining findings.
- **Reflection/replay for AES256/DHKE/PQKEM (`client/crypto.js`).** New shared
  `AuthChannel`: each frame carries a random per-session sender tag + a strictly
  increasing sequence number, both folded into the AES-GCM additional data (so
  a relay can't alter them without the key). Decrypt rejects a frame whose tag
  is our own (reflection) or whose sequence isn't advancing (replay). AES256,
  DHKE and PQKEM all route through it; RSA keeps its own HMAC construction.
  Residual documented: AES256's static key still permits cross-session replay.
- **PQKEM handshake-replay desync (confirmed bug).** A relay replaying a peer's
  validly-signed PQKEM offer made the recipient re-encapsulate a fresh secret
  and rotate the live session key (DoS). Fixed with first-write-wins per
  encapsulation key + idempotent `_derive` (skips when inputs are unchanged, so
  the channel and its replay counters survive a replay). DHKE made idempotent
  too (`if (this.chan) return`).
- **DHKE key derivation.** Was using the raw ECDH X-coordinate directly as the
  AES key; now runs it through HKDF (room-id salt + domain tag), matching PQKEM.
  `Dhke` now takes the room id; `makeCipher` passes it.
- **Login challenge domain separation (`accounts.py` + `account.js`).** The
  login signature now covers `secure-chat/login/v1\n` || nonce instead of a bare
  nonce, so it can't be cross-used as any other protocol signature. Backend +
  client updated in lockstep; `test_accounts.py` adjusted.
- **CSP import-map hash guard.** New `backend/tests/test_csp_hash.py` recomputes
  the SHA-256 of the inline importmap in index.html and asserts the served CSP
  still pins it — so editing the import map without regenerating the hash fails
  loudly instead of silently breaking the page.
- **Tests:** `crypto.test.mjs` gained reflection/replay/tamper checks for
  AES256/DHKE/PQKEM and a PQKEM replay-doesn't-desync regression. Verified in a
  real browser (Chromium/puppeteer): DHKE handshake, receive-gate, and a two-way
  message exchange under the new framing all work. All suites green.

### 2026-07-02 — cross-session handshake replay CLOSED (session nonces, transcript v2) ✅
- **Finding (2026-07-02 pentest, Medium):** the signed handshake transcript
  (`DOMAIN || roomId || ephemeralPayload`) had no per-connection freshness, so
  a relay could replay a peer's validly-signed handshake from an OLD session
  into a NEW session reusing the same room id → silent key desync with a
  misleading "verified" UI (integrity/availability, not confidentiality).
- **Fix (`client/auth.js` + `client/app.js`):** transcript bumped to
  `secure-chat/handshake/v2` and now covers a fresh random 32-byte nonce from
  BOTH peers' current connections. New plaintext `hello` phase inside the `key`
  message (`{hello:true, n, reply}`): each peer announces its nonce on join;
  the receiver of a reply:false hello answers once (reply:true) and then sends
  the signed offer; the signed answer flows as before. Nonces are folded
  order-independently (sort b64, concat bytes) so both sides sign/verify the
  same transcript regardless of direction; peer nonce is first-write-wins.
  Hellos are unauthenticated in flight but authenticated retroactively by the
  signature that covers them — tampering only makes the handshake fail loudly
  (a relay could always DoS). A stale signed handshake can never cover the
  nonce the victim generated THIS connection → signature verification fails
  instead of desyncing. The domain bump alone also invalidates all pre-v2
  captured handshakes. Note the offer direction reversed in the staggered-join
  case (the EARLY joiner now sends the first signed offer, since it learns both
  nonces first); the ciphers' symmetric/race-tolerant design is direction-
  agnostic, and the simultaneous-join race path is unchanged (dual offer +
  dual answer, idempotent onPeerKey).
- **Tests:** `identity.test.mjs` — new cross-session-replay rejection suite
  (stale sig vs fresh nonce REJECTED, fresh-pair REJECTED, genuine ACCEPTED,
  nonce-order independence). `auth.integration.test.mjs` — peers speak the new
  hello+offer/answer protocol, PLUS a live PoC regression: session 1 captured
  through the real relay, its validly-signed handshake replayed by a Mallory
  client into session 2 (same room) → REJECTED. Verified in a real browser
  (Chromium/puppeteer): two isolated contexts, DHKE staggered join, identical
  safety numbers, two-way messages. All suites green: client `npm test`, all 3
  live integration suites, backend `pytest` 48 passed.

## TODO / NEXT (suggested order)

### ✅ CLOSED — the 2026-07-29 pentest, all 13 items (fixed 2026-07-30)
Every finding in `secure-chat-pentest-2026-07-29.md` is fixed on branch
`pentest-2026-07-29-fixes`. Backend **143 passed**, client **109 checks / 11
suites**, `e2e/all-modes.mjs` **32/32 on 5 consecutive runs** (it used to fail 2
in 5 — root-caused, below). **DEPLOYED 2026-07-30** — see DELIVERY at the end.

Each fix carries a test that FAILS against the pre-fix code — verified by
stashing the fix and re-running, not by assertion. Where that was not possible,
it says so.

1. **✅ M-1 — `client_key()` gives exactly one bucket per peer.** `X-Forwarded-For`
   is ignored outright when no trusted proxy is configured. The forgeable
   `peer in hops` detector is deleted; rewrite detection moved to the PORT
   (uvicorn builds `(host, 0)` from a bare-IP hop; a real TCP peer never has
   source port 0), which the client cannot set — no false positives, so **L-9
   closes with it**. The detector is documented as a diagnostic, not the control.
   Tests: the exact line the report said would have caught it
   (`peer=127.0.0.1, XFF=127.0.0.1`), a one-key-per-peer sweep over 9 header
   shapes, an end-to-end limiter test **through a TestClient bound to
   127.0.0.1** — the module-level client reports `"testclient"`, which is in no
   attacker's header, so the original topology could not reproduce M-1 at all —
   and both directions of the L-9 forgeability property.
2. **✅ H-1 — the native pad floor cannot be cleared or detected away.**
   `PadFloorBridge.clear` is gone (nothing called it), and `PadFloor.kt`'s
   contract no longer claims two things that were false. The app injects
   `__SECURE_CHAT_NATIVE_FLOOR__` at document-start as a **non-configurable**
   property — that is the load-bearing part: `delete window.SecureChatPadFloor`
   still removes the bridge, but `delete` cannot remove the marker, so
   "marker present, bridge missing" is now provable tampering and fails closed
   instead of reading as a plain browser. `verifyRelayConfig` additionally
   refuses to run if the page cannot call the bridge.
   Also closed, and NOT in the report: floor **deletion** was still silent, since
   an absent floor contributes 0 to the rollback comparison. A `nativeFloor`
   flag now lives inside the pad's AEAD, so a blob written while a floor existed
   is refused if the floor is later gone. Tests include the full
   snapshot-restore-then-clear PoC (which silently reopened the pad before, and
   is now refused), and a plain-browser case so the fix cannot become
   "fail closed everywhere".
3. **✅ H-2 — the witness can no longer be opened as the store.** The store
   plaintext carries `d: "secure-chat/contacts-store/v4"` and `unlock()` requires
   it. Pre-v4 blobs have no tag and are adopted, then re-persisted tagged.
   The adoption decision keys on the **tag inside the AEAD, never the outer `v`
   byte** — `v` is attacker-writable and the witness blob has none, so
   `(blob.v || 1) < 4` would have read the witness as legacy and adopted it,
   reopening the hole. That is the same trap the outer `v` byte set for OTP.
4. **⚠️ H-3 — fixed on ANDROID ONLY; the browser residual stands.**
   `padWasUsed()` consults the native floor first and treats TAMPERED as used;
   `saveNewPad` refuses a padId that was ever used here and seeds the watermark
   cache from the surviving floors rather than from zero, so it cannot erase the
   record even if the refusal were bypassed. `app.js`'s `otpFileChosen` still
   skips `unlockPad` **deliberately** — the guard now lives inside the two
   functions it calls, i.e. on the path rather than beside it, for no extra
   600k-iteration KDF.
   **Corrected 2026-07-30 (fix review H-B).** This entry originally read
   "✅ … Reproduced end to end: post-fix it is refused", with no platform
   qualifier. That is false for the WEB CLIENT, which is the primary one: with
   no floor, `nativeFloor` is null and `padWasUsed` still reads only the three
   deletable plaintext keys, so the original PoC — three `removeItem`s, then
   re-import — still rebuilds the pad at offset 0. Re-verified 2026-07-30.
   Closing it in a browser is not possible with deletable storage; the honest
   options are trusted monotonic storage (which is what `PadFloor` is) or
   nothing. **This is exactly the failure mode M-1 was about** — a status line
   claiming a property the measurement did not cover — so it is corrected here
   rather than quietly rewritten, and the test's summary line is now scoped to
   the platform it actually proves.
5. **✅ M-4 — the false premise is corrected where it was written.**
   `network_security_config.xml` no longer claims `.onion` is potentially
   trustworthy; it carries the measured table, the reason
   `cleartextTrafficPermitted` cannot help (it sits below Chromium's
   mixed-content blocker), and an explicit **DO NOT** for the obvious workaround,
   naming why a WebView document origin on the onion is a Critical regression
   twice over. The two workable shapes (loopback Orbot proxy, TLS over the
   onion) are recorded. The `onion` allow-list entry is kept and the comment
   says why it is inert. **No code change is possible here — this finding is a
   plan correction, and the Android-over-Tor work remains unbuilt.**
6. **✅ M-2 — corrected, and the applicable knob is set.** `deploy/README.md`'s
   three wrong claims are corrected in place (it is login for all accounts, not
   onboarding; only `REGISTER_RATE_*` was ever resized; PoW prices introduction,
   not requests). `torrc.secure-chat` gains `HiddenServiceMaxStreams 24` +
   `HiddenServiceMaxStreamsCloseCircuit 1`, validated with `tor --verify-config`.
   Stated plainly in both places: this raises the price, it does not remove the
   DoS, and that remains **accepted**.
7. **✅ M-3 — the harness now has a positive control.** `wsConnect` distinguishes
   "closed before any HTTP status" (`transportFailed`) from a real refusal, and
   the CSWSH check requires all of: the foreign attempt was actually answered,
   it was refused, AND an allowed Origin upgraded in the same run. Verified
   against all five scenarios: it now rejects the Tor-hiccup case that used to
   pass green at `HTTP 0`, and the connection-cap case that a bare
   `code === 403` would also have accepted. **Not re-run over real Tor** — that
   needs the deploy box, so this is verified at the predicate, not end to end.
8. **✅ M-5 — chains are frozen once confirmed, and the race works again.**
   Both halves, which pull in opposite directions:
   the **attack** (a withheld offer delivered after confirmation silently
   rebuilds the chains) is now a loud refusal, gated both in `case "key"` before
   the cipher is touched and in `onChannelReady` after; the **race** (each side
   derives twice in a simultaneous connect, so the first tag is stale) works
   because the peer's tags are kept in a **capped set** — matching any of them
   proves the peer derived our current material, in any arrival order.
   The cap (2, the maximum a legitimate peer can produce) preserves what
   first-write-wins was protecting: the confirm frame is not signature-covered,
   so an uncapped set would be a guessing oracle. A mismatch is no longer
   instantly fatal, so loudness comes from a deadline — which also fixes a case
   the ORIGINAL code hung on forever: a relay that never delivers the confirm
   frame at all.
   The state machine moved to `client/keyconfirm.js` so it can be tested without
   a DOM. That is the point: the report could only model this "line for line" in
   a scratch harness because it lived inline in `app.js`. Ten tests now run
   against the shipped code, and the pre-fix semantics were transcribed and run
   against them to prove they discriminate — the old code fails the attack test
   AND disconnects both honest peers in the race.
9. **✅ M-6 — directory answers go through the canonical gate.**
   `account.fetchBundle` re-spells every key through `b64(unb64(...))`, which
   throws on a non-canonical spelling, so a hostile directory can no longer
   return the same bytes in a different spelling to strip 🟢 and vouches,
   permanently break sealed messaging, or burn the auto-contact budget. Applied
   at the fetch boundary rather than at each consumer.
10. **✅ M-7 — `/api/vouch` is no longer an existence oracle.** The target-existence
    answer is folded into the signature verdict (a random, correctly-sized decoy
    bundle keeps the work and the timing identical), so an absent target and a
    bad signature are byte-identical `400`s. The route also joins
    `lookup_rate_limit`, the same anti-enumeration bucket as `GET /users/{u}`,
    with a test that draining it via `/vouch` throttles `/users` — proving it is
    the same bucket and not merely some limiter. `test_vouches.py:153`, which
    **pinned the oracle in place** with `== 404`, is inverted.
11. **✅ Low/Info.** L-1 knock queue capped at 8, dropping the EXCESS rather than
    the oldest — evicting the oldest would let a flood push a genuine contact's
    knock off the list, turning a nuisance into targeted denial of admission;
    the cap sits before the two signature verifies, so a flood costs a regex.
    L-3 lost updates are now a loud refusal via a compare-and-swap on the witness
    (tested with two real module instances over one localStorage — that is what
    two tabs are). L-4 gains `POST /api/auth/logout` **and** re-login retiring the
    account's previous sessions; logout is deliberately not behind `current_user`,
    or it would be a token-validity oracle needing no signature. L-5 `OtpPad`
    validates its offsets (`| 0` was also turning NaN into 0). L-7 is written
    down in `torrc.secure-chat` as accepted rather than claimed away, with
    `AvoidDiskWrites 1`. L-8 the relay's source is no longer writable
    (`StateDirectory` + `SECURE_CHAT_DB` under `/var/lib`, `ReadWritePaths`
    dropped; **needs the one-off DB move in the unit's comment before restart**).
    L-9 closed by item 1. L-10 the install recipe is idempotent.
    **L-2 is unchanged and remains accepted** — deleting both contact keys still
    yields an empty store; it is the documented whole-storage residual, and the
    honest fix is trusted monotonic storage, not another key.
12. **✅ Test-coverage gaps 1-8, plus the two vacuous tests.**
    `pqkemReplayDoesNotDesync` was vacuous — it replayed AFTER `encrypt()` sealed
    the cipher, so `onPeerKey` returned early and the assertion could never
    observe `_derive`; it now replays pre-seal, where the live path is, and the
    post-seal case is kept and labelled as the different mechanism it is.
    `otp-rollback.test.mjs`'s bridge mock hid both halves of H-1 — no `clear`, so
    the attack could not be expressed, and a final `delete globalThis.SecureChatPadFloor`
    that treated bridge-absence as a clean browser, which IS the downgrade.
    New: `test_service_unit.py` (the production launcher, previously untested),
    `no-fallback.test.mjs` (gap 7 — nothing asserted `crypto.subtle` is required,
    so the best result in the report was one compatibility commit from silently
    inverting), `keyconfirm.test.mjs`, and regression tests for the
    witness→store swap, delete-then-reimport, negative `OtpPad` offsets, and
    the vouch oracle.
    **Not covered, stated plainly:** the L-1 knock flood has no regression test —
    it lives in `app.js`'s relay-message path, which still has no unit tests at
    all (gap 8), and the queue cap is exercised by nothing but review. That is
    the same structural gap that made M-5 untestable until `keyconfirm.js` was
    split out; the admission paths deserve the same treatment.
13. **✅ E2E — the flake is root-caused and fixed, and the harness cannot lie.**
    The cause was a **substring bug in the test, not a race in the app**: the
    harness waited for `/connected/i`, which also matches **"disconnected"** —
    the status left over from the previous mode's teardown. From the second mode
    onward that wait returned instantly, before alice had actually joined, so bob
    could reach the empty room first and become its OWNER; he then never entered
    the approval queue and his "waiting for approval" wait timed out 45 s later.
    That is exactly the reported signature (2 in 5, always bob's approval wait,
    always a later mode). Anchored to an exact match, and the same latent bug
    fixed in `room-admission.mjs`. **5 consecutive runs, 32/32 each.**
    Separately, `SECURE_CHAT_E2E_CHROME_ARGS` now TAINTS the run when it disables
    a security gate: the flags are named up front, the summary never prints a
    bare "all modes good", and the exit code is non-zero unless
    `SECURE_CHAT_E2E_ACK_UNSAFE=1`. A green run in a configuration no user can
    reproduce is worse than a red one, because it gets quoted.

### 🔧 FIX REVIEW of the above (2026-07-30) — 6 findings, all fixed
The `pentest-new-code` agent was run against the fix commit `23bc905`, on the
principle that a fix is new code and the most dangerous kind. It found six
things, **three of them regressions the fixes themselves introduced**. All are
fixed; the review's other verdicts (M-5, H-2, M-6, M-7, L-3, L-5 and the launch
paths) held under independent attack.

- **H-A (High) — the H-1 floor was defeated by SUBSTITUTING the bridge, not
  deleting it.** I hardened the marker and left the lookup alone: `otp.js` found
  the bridge by its ordinary global name and accepted anything with `read`/`bump`
  functions, so an attacker could install a lookalike answering "no floor", or
  just overwrite the two METHODS on the real object — two assignments, no
  `delete`, and it survives making the global itself non-writable. Every new
  check passed, `verifyRelayConfig`'s probe answered true, and the real Keystore
  floor was never consulted: full keystream reuse, F-1 void again. Reproduced.
  **Fixed:** the app captures the interface at document-start, before any page
  script, and republishes it **frozen** under a non-configurable
  `__SECURE_CHAT_PAD_FLOOR__` with `.bind()`-captured methods; `otp.js` reads
  only that name and a test asserts it never touches the writable global. The
  lesson: I keyed the check on SHAPE where it needed to be PROVENANCE.
- **H-B (High, reporting) — my own H-3 claim was false for the web client.**
  Corrected in item 4 above, in the commit trail, and in the test's summary line.
- **M-A (Medium) — my L-1 knock cap made things WORSE than no cap.** Nothing
  pruned the owner's queue when a waiter left (the relay pops `pending` and tells
  nobody), and a knocker whose entry is dropped can never retry, because the
  client knocks exactly once and the relay refuses a second knock per socket. So
  eight cheap connect/knock/disconnect cycles filled the queue with immortal
  ghosts and the invited peer waited forever, unseen — a permanent silent denial
  of admission, and a direct hit on the P-08 property the cap was protecting. My
  own comment claimed a dropped knocker "simply has to knock again"; it cannot.
  **Fixed:** the relay now sends `withdrawn` (join id only — no identity, nothing
  new at rest) and the owner's client prunes; the cap is raised above
  `MAX_ROOM_PENDING` and demoted to a backstop for relays that do not send it.
  Four relay tests, including the flood shape.
- **M-B (Medium) — my M-1 fix deleted H-4's fail-closed collapse.** Removing the
  forgeable detector was right; removing the SAFE COLLAPSE it drove was not,
  because in the H-4 condition `peer` is attacker-chosen, so returning it hands
  out a private bucket per forged header with one log line as the only trace.
  **Fixed:** warn *and* collapse. Port 0 has no remote false positives, which is
  what makes it safe to act on and not merely log — and the suite now asserts
  the BUCKET under a misconfiguration, which it never did.
- **M-C (Medium) — my L-4 fix was a self-inflicted DoS.** One-session-per-account
  plus `pollMailbox`'s 6 s "401 → re-login" made two tabs of the same account
  revoke each other forever: ~0.33 challenges/s against a 0.5/s bucket that,
  since M-1, is GLOBAL to the relay. Two of a user's own tabs ate most of the
  relay's login capacity; three denied login to everyone. Both tabs then sat
  permanently offline for sealed mail with no visible sign — the exact failure
  the 401 handler exists to prevent. **Fixed:** `MAX_SESSIONS_PER_ACCOUNT = 5`
  with oldest-evicted, re-login no longer revokes, failed re-login backs off and
  says so, and revocation is `POST /api/auth/logout` — which is now **wired into
  the profile view** (L-B: it had no caller at all, so the only revocation a user
  could trigger was the one that caused this).
- **L-A (Low) — the fail-closed messages blamed the pad.** "Damaged or forged",
  "already been used", and each recommending a fresh pad exchange, when the real
  cause is the app cannot reach its own floor — so a user burns real pads chasing
  it. Now a distinct message that says so and says *not* to exchange.

(The taint gate and `fetchBundle` length-checking were done in the same commit;
`HiddenServiceMaxStreams 24` remains the value most likely to need revisiting on
the box, and is untestable here without a Tor daemon.)

### 🔧 FIX REVIEW, ROUND 2 (2026-07-30) — 1 High + 5 Low, all fixed
The agent was run again against the fix-review commit `b471cbf`, because those
fixes were themselves written under the assumption that they closed something.
Five of six claims held. One did not, and it is the more instructive failure:

- **H-1 (High) — I hardened the bridge and left every VALUE it produces flowing
  through mutable globals.** `otp.js` parsed the floor with `parseInt` guarded by
  `Number.isFinite`, and the rollback verdict was a single `Math.max` over the
  four floors. So `globalThis.parseInt = () => 0` — one assignment, never naming
  the bridge, no `delete`, no `defineProperty` — made every floor read as zero
  while the frozen bridge, the non-configurable marker and `verifyRelayConfig`'s
  probe all stayed intact. `Math.max = ...` was worse: it overruled the native
  floor, the authenticated watermark, `inner.hwSend` and the legacy watermark in
  one go, **in a plain browser too**. Reproduced: pad reopened at offset 0 with
  the hardware floor still reading 3000.
  **Fixed:** the bridge returns a **number** now (`PadFloorBridge` returns
  `Long`), so there is no parse step to poison; validation uses only `typeof` and
  bitwise ops, which have no global behind them; and every rollback `Math.max` is
  a local `maxOf` built from comparisons. Note capturing primordials at module
  top would NOT have worked — a document-start attacker runs first.
  **The lesson, and it is the same one twice:** in round 1 I keyed the check on
  shape where it needed provenance; here I secured the source of a value and left
  the path it travels. Both times the fix was correct about the PoC and wrong
  about the boundary.
- **M-1 (Medium) — the M-C backoff was dead code.** `pollMailbox` returned at its
  first line when `apiToken` was null, and the 401 branch was the only thing that
  ever called `autoLogin`. So one failed re-login was terminal: no retry, the
  12/24/48/96/120 s ladder unreachable, and the tab permanently offline for
  sealed mail — precisely the state M-C was written to remove, reached by a
  different road. **Fixed:** `pollMailbox` re-authenticates from the top, which
  is what makes the backoff load-bearing rather than decorative.
- **L-1 — `withdrawn` was sent for waiters that never knocked**, which prunes
  nothing (the owner's queue only holds knocked waiters) and is exactly the
  unbatched per-join-attempt frame `note_turned_away` avoids on purpose. Gated on
  `conn.knocked`; the test that asserted the old behaviour is inverted.
- **L-2 — `showNextKnock` is not re-entrant**, and `withdrawn` gave it a second
  concurrent trigger that `msgChain` does not serialise against clicks. Fixed
  with a render generation counter plus a queue-head re-read after the await.
- **L-3 — `forgetIdentity` never revoked the directory session**, leaving a live
  bearer for up to an hour after the control a user reaches for when handing the
  device on. It now calls the `logout` this work introduced.
- **L-4 — the "you are offline" messages went to the chat transcript**, a screen
  the user is usually not on — the same "only if you happen to look" complaint
  M-C was about. Routed to the active screen's hint, and the sign-out message now
  says where to sign back in.

Verified sound across both rounds and not re-broken: M-5/`keyconfirm.js` (byte
identical, re-attacked), H-2/`contacts.js` (byte identical, confirmed the
re-applied version locks before throwing), M-B's port-0 branch (unreachable from
any header), M-C's eviction arithmetic (cannot over-evict; an attacker cannot
force-evict, since the signature is checked before the eviction block), and the
M-A relay path (every way a knocked waiter can leave emits exactly one notice).

**One residual the review could not close and neither could I:** M-B's claim rests
on "a connected TCP socket cannot have source port 0". Neither of us had
`CAP_NET_RAW` to test whether a crafted SYN can surface `sin_port == 0` from
`accept()`. If it can, that branch becomes reachable and is an M-1-shaped second
bucket. The docstring says so rather than claiming "no false positives" flatly.

### 🔧 MERGE REVIEW (2026-07-30) — 1 finding fixed, 1 flagged
Delivery item 1 ("review the diff and merge") read as a real review, not a
formality. The full local gate was re-run first and everything the previous
sessions claimed reproduced: backend **152 passed** (151 before the fix below),
client **112 checks / 10 suites**, the three integration suites green against a
live local relay, and e2e `all-modes` **32/32**, `room-admission` 13/13,
`no-dead-ends` 12/12, `two-user-flow` 8/8.

- **✅ The L-8 fix made the account database world-readable.** Moving the DB out
  of the code tree was right; the mode was never checked. `StateDirectory=` alone
  leaves systemd's **0755 default**, which it re-applies on every start, so
  `/var/lib/secure-chat` would be world-traversable with a 0644 `accounts.db`
  inside it — publishing the directory's lookup TOKENS (the secret half of
  `username#token`, and the entire anti-enumeration control that makes a bare
  username reveal nothing) and the sealed mailbox ciphertext to any local user on
  the box. The unit's own comment asserted "systemd creates it 0700"; it does
  not, and `man systemd.exec` says 0755 in as many words. The migration recipe
  three lines above said 0750, which systemd would have silently overridden — the
  two disagreed and neither was right.
  **Fixed:** `StateDirectoryMode=0700`, the recipe corrected to match, and the
  false claim replaced with why the line is not optional. `test_service_unit.py`
  gains a case that **fails against the pre-fix unit** (verified by reverting the
  file and re-running, not by assertion) and that also holds the comment's recipe
  to the enforced mode, since a divergence there is how this happened.
  Worth noting what class of bug this is: L-8 was verified as "the code tree is
  no longer writable", which was true, and the property that broke was one nobody
  had written down. Same shape as M-1 — a status line the measurement did not
  cover — one layer down.
- **✅ FIXED (in the APK-rebuild step): `PadFloor.kt` was invisible to `git diff`.** It contained
  raw NUL bytes in the HMAC domain separator at line 98
  (`"secure-chat/otp-pad-floor/v1\0$padId\0$value"`, written as literal U+0000 in
  the source rather than `\u0000`), so git classifies it as binary and every diff
  of it renders as `Bin 7111 -> 9149 bytes`. `file` calls it `data`. This is
  **pre-existing on master, not introduced by this branch** — but it means the
  H-1 changes to the one file whose whole job is to be the control the JS context
  cannot reach went to review as an opaque blob. `git diff --text` was used here
  instead and the content is correct.
  **Fixed at the APK rebuild, where a compile could confirm it:** the separator
  is spelled `\u0000` and the file is `UTF-8 text` again, so it diffs normally
  from here on. Byte-identity was not assumed, it was checked in the built
  artifact: `classes3.dex` carries the constant as `secure-chat/otp-pad-floor/v1`
  followed by `c0 80`, which is DEX's MUTF-8 encoding of U+0000. The string the
  HMAC is taken over is therefore unchanged, so every floor already stored on the
  phone still verifies. Worth stating the failure mode had it differed: every
  existing floor would have failed its MAC and read as TAMPERED, which fails
  CLOSED (OTP bricked on the device) rather than open — but that is a reason
  to check, not a reason to assume.

### ✅ DELIVERY — DONE 2026-07-30, all five items, verified not assumed
Merged `--no-ff` as `2918986`, pushed with the branch. Then, in order:

1. **✅ Reviewed + merged.** The review was not a formality — it found the
   world-readable state directory above. Full local gate first: backend **152
   passed**, client **112 checks / 10 suites**, the three integration suites
   green against a live local relay, e2e `all-modes` **32/32**, `room-admission`
   13/13, `no-dead-ends` 12/12, `two-user-flow` 8/8.
2. **✅ Relay + client DEPLOYED**, via `deploy/deploy-2026-07-30.sh` (committed —
   the usual two-line rsync recipe cannot express this release, because the DB
   move is order-dependent and the unit is not covered by the rsync).
   Backup at `/root/accounts.db.bak-2026-07-30-1822`. **The migration worked:
   30 accounts, 2 vouches and 4 mailbox rows survived**, counted through the
   read-only sqlite handle rather than inferred from the file size. `healthz`
   and `/` both 200 over loopback, clearnet 200, no database left in the code
   tree, `SECURE_CHAT_TRUSTED_PROXIES` still absent from the live process
   environment and `--no-proxy-headers` still on its command line.
   **`StateDirectoryMode=0700` was PROVED to be load-bearing, not decorative:**
   `chmod 0755` on the live directory, `systemctl restart`, and systemd put it
   back to `drwx------`. That is the claim the finding was about, so it was
   measured rather than asserted.
3. **✅ APK rebuilt + installed** on device `P21273004544`. Carries the
   `PadFloor.kt` escape fix, compile-verified byte-identical (above).
4. **✅ On-device native-floor proof re-run — 14/14 against the real
   AndroidKeyStore.** The harness is now **committed** at
   `android/native-floor-ondevice.mjs`; the 2026-07-28 one lived in a session
   scratchpad and was gone, which is how a proof of the one control the JS
   context cannot reach stops being re-runnable. It also asserted the OLD
   contract. Proved on hardware: the marker survives `delete` and redefinition;
   the interface is frozen and has **no `clear`**; an unknown pad reads `-1`;
   `bump(500)` → 500 and `bump(5)` → still 500 through the real HMAC; `read()`
   returns a **number**, so there is no parse step to poison; **H-A** —
   replacing `SecureChatPadFloor` wholesale, and overwriting the frozen object's
   own methods, both leave the floor reading 500; **round-2 H-1** — poisoning
   `parseInt` AND `Math.max` together does not move it. Those last two are the
   attacks the Node tests structurally cannot express, because a mock cannot be
   substituted or poisoned.
   *Residual:* the probe left an inert floor at `probe-native-floor-<ts>`. It
   cannot be cleared from JS — by design, no lowering call exists — and no real
   pad can carry that id. The phone still has **0** `sc.otp.*` keys.
5. **✅ `onion-ws.mjs` run over real Tor — 10/10**, against the newly deployed
   relay, through a local unprivileged `tor`. **Including the M-3 positive
   control**, which had only ever been verified at the predicate: an allowed
   Origin upgraded (HTTP 101) in the same run in which a foreign Origin was
   refused (403), so the refusal is now known to be a refusal and not a Tor
   hiccup at `HTTP 0`. Absent Origin still accepted, admission protocol intact
   over the onion (owner seats first, second peer queued not seated, knock
   verbatim, payloads unchanged both ways).

**Still open, deliberately:** the `torrc` change (`HiddenServiceMaxStreams 24`)
is NOT applied. The box's live tor config has never been diffed against the repo
copy, so applying it blind risks clobbering settings that exist only on the box.
The script prints the diff-then-reload recipe. This is a DoS price-raiser on an
accepted DoS, so it is not urgent.

**Previously (superseded by the block above): ⬜ DELIVERY — nothing here is
deployed.** All of the above is committed on a branch and verified locally only.
Still to do, in order:
  1. Review the diff (it touches crypto, at-rest storage, the relay and the
     admission path) and merge.
  2. Deploy the relay + client. **The systemd unit changed**: do the one-off DB
     move in its comment BEFORE the restart, or the relay starts with an empty
     database.
  3. Rebuild + install the APK. **H-1's marker is injected by the app**, so a
     client update WITHOUT an APK update leaves Android on the old feature
     detection — deploy them together, as with the 2026-07-28 release.
  4. Re-run the on-device native-floor proof: H-1 changed `PadFloor.kt` and the
     document-start injection, and the 2026-07-28 hardware proof no longer
     covers the shipped code.
  5. `deploy/onion-ws.mjs`'s new positive control has never run over real Tor.


### ⬜ OPEN from the 2026-07-27 pentest — SHIPPING, not fixing
Every finding in `secure-chat-pentest-2026-07-27.md` is fixed and now merged to
`master` (see the snapshot at the top). What is left is entirely delivery — and
after item 2 was dropped, none of it protects a running instance:

1. ~~**Review + commit the tree.**~~ **DONE 2026-07-28.** Committed as
   `dc182d7` on branch `pentest-2026-07-27-fixes` (23 files, +2547/−98) and
   merged to `master` with `--no-ff` as `97c0754`; both pushed to `origin`. The
   branch is kept on GitHub so the change stays reachable as one review unit.
   Pre-commit: no DB files or secrets staged, backend 129 passed, client 84
   checks across 8 suites.
2. ~~**Restart the live relay** so H-4 actually applies to it.~~ **DROPPED
   2026-07-28 — this item was based on a wrong reading of H-4; do not re-add
   it.** Hetzner was never exposed: its `ExecStart` runs `-m uvicorn …
   --no-proxy-headers` with `SECURE_CHAT_TRUSTED_PROXIES=127.0.0.1` (live since
   the 2026-07-25 F-03 unit edit), verified against the running process. The
   `main.py` launcher this fix touches is not used in production, so a restart
   would have applied nothing; none was performed. Full detail in the corrected
   H-4 paragraph at the top of this file. **Nothing here protects a live
   instance — every remaining item below is next-release delivery.** The one
   genuinely undeployed piece (`accounts.client_key` rewrite detection) ships
   with item 3's normal deploy.
3. ~~**Deploy client + rebuild the APK TOGETHER.**~~ **DONE 2026-07-28** — see
   the snapshot at the top for backups, verification, and the restart/install
   ordering that kept the breaking two-client window to the restart itself.
4. **PARTLY DONE 2026-07-28.** ~~Contact store v3→v4~~ **CONFIRMED on-device**:
   unlocked on the phone, app opened normally, `sc.contacts.gen.v1` written next
   to a genuine pre-fix `sc.contacts.v1`. **⚠️ OTP pad v2→v3 STILL UNVERIFIED
   and untestable on this phone** — it has no pads at all (`grep sc.otp` over
   the leveldb returns 0), so that path had only run against in-memory
   localStorage. **Now tested on-device 2026-07-28 by injecting a genuine
   pre-fix v2 blob — and it is BROKEN: a USED pre-fix pad is permanently
   refused.** Root cause, proposed one-line fix, and why the unit tests missed
   it are in the 🔴 section of the snapshot at the top. **This is the top open
   item — it is shipped and live.**
5. **⬜ NEW from the `pentest-new-code` review of `bf6bcd2` (2026-07-28).** All
   pre-existing, none introduced by that fix — the review verified the fix never
   lowers a floor and that M-01/M-7/P-01/P-05 and the untrusted outer `v` byte
   all still hold. Tooling: PoCs under the session scratchpad `lab/`.
   - ~~**F-1 (High)**~~ / ~~**F-2 (Medium)**~~ **FIXED 2026-07-28, deployed.**
     Two layers, because they protect different platforms. **Browser:** adopting
     a pad with no verifiable usage record is no longer automatic —
     `unlockPad(..., {adoptLegacy:true})` is required, and `app.js` shows a
     confirm that names the danger ("this pad has no usage record on this
     device…"), escalated when `sc.otp.epoch.v1` or `usedKey` says this device
     has run OTP before. Those markers only ESCALATE; being deletable, they can
     never turn the gate off. The gate sits AFTER the rollback checks on purpose:
     adoption is consent to accept state that cannot be VERIFIED, never
     permission to override a rollback that has been DETECTED. **Android:** the
     send floor also lives in `android/…/PadFloor.kt` — app-private
     SharedPreferences under an AndroidKeyStore HMAC, monotone (no lowering call
     exists), keyed per padId so a floor cannot be replayed under another id, and
     bridged to JS as three integer methods. A floor present with no watermark
     beside it is refused outright; an unreadable bridge fails closed rather than
     reading as "no floor". F-2: an unverifiable `exported` now resolves to
     **true** — OR-ing the sources does NOT fix it, since a v1/v2 blob has no
     authenticated copy at all, so the flipped index would still win. Costs a
     confirm on re-export of an adopted legacy pad; closes the laundering path.
     Tests: `otp-rollback.test.mjs` gained the full v2 two-time-pad PoC (loud in
     the browser, refused outright with a simulated bridge), native-floor
     monotonicity, broken-bridge fail-closed, and the F-2 laundering attempt —
     **89 checks / 8 suites**, 0 flakes in 30 runs. **APK installed and the
     native floor PROVED on real hardware 2026-07-28** against the actual
     AndroidKeyStore path (everything before that was a simulated bridge in
     Node): bridge present; absent floor reads `-1`; `bump(500)` → `500`;
     `bump(5)` → still **`500`** (monotone through the real HMAC); `clear` →
     `-1`; using a pad set its floor to `900` unprompted; and **the full v2
     two-time-pad PoC — rewound blob plus the three deletions — was REFUSED even
     with `adoptLegacy:true`**, i.e. even when the user consents. That is the
     exact attack that recovered a plaintext earlier the same day. Probe pad and
     its native floor removed afterwards; the phone is back to its six real keys
     with no `sc.otp.*` residue and no `AndroidRuntime` exception. Harness:
     `native-floor-ondevice.mjs` in the session scratchpad.
   - **F-1 original finding, for the record — H-3 is bypassable on any v2-shaped blob.** With no
     `inner.hwSend` in the AEAD, `knownUsedHere` collapses to the plaintext
     `sc.otp.used.v1`. Restore a v2 snapshot + 3 `removeItem`s → the pad unlocks
     at offset 0 and two messages encrypt under the same keystream; the review
     recovered a plaintext end-to-end. Two ways to get the snapshot: access while
     the pad was genuinely v2 (used pre-fix pads were STUCK there until
     `bf6bcd2`), or manufacture one — a single save from old client code rewrites
     a v3 blob back to `v:2` and strips `hwSend`, permanently re-exempting it.
     **No localStorage marker can fix this** (any marker is deletable); the
     honest control is to make v2 adoption LOUD — prompt "this pad predates
     rollback protection; its consumption cannot be verified" — and/or time-box
     it behind a migration epoch after which v2 is refused outright. **Needs a
     product decision.** Note `bf6bcd2` shrinks the exposure over time by getting
     used pads onto v3, where the guard is AEAD-anchored.
   - **F-2 (Medium) — the L-3 `exported` flag launders through the migrating
     unlock.** `otp.js` falls back to the plaintext index exactly once, on the
     upgrading unlock, then bakes that value into the AEAD permanently. Flip the
     index first and the double-export warning is disarmed for good → one
     pristine pad to two importers → a two-time pad by construction. **Fix: on
     migration take `exported: true` if EITHER source says true; never downgrade
     to `false` from an unauthenticated read.** Small and self-contained.
   - **F-5 (Low)** — `sc.otp.hw.v1` is an un-clearable local DoS (a large value
     bricks the pad, no UI to clear it). Verified it CANNOT be poisoned into the
     AEAD: the rollback throw precedes the migration write, so deleting the key
     restores the pad. Fail-closed and reversible; noted only because it is
     silent to the user.
6. **Residual, deliberate, unchanged:** whole-storage rollback (an attacker who
   snapshots BOTH the store and its witness, or both the pad and its watermark,
   still rewinds undetected — it needs OS-level trusted monotonic storage);
   whoever joins an empty room first owns it; a visible approval queue can still
   be filled (now at least the owner is told). These need protocol/platform
   changes, not another localStorage key.

### ⬜ OPEN from the 2026-07-26 pentest (everything else in it is fixed + shipped)
Full detail per item in `secure-chat-pentest-2026-07-26.md` (§4-6 findings,
§9 remediation). These are the deliberate leftovers, not forgotten work.

1. ~~**P-08 (Low) — room-slot squatting.**~~ **FIXED 2026-07-27** with
   owner-approved room entry (user-designed) — see the snapshot at the top.
   Waiting no longer consumes a member slot, so knowing a room id no longer
   takes the room from the invited peer. **Residual, deliberate:** whoever joins
   an empty room FIRST owns it, and a visible queue can still be filled — both
   availability-only, both needing the cryptographic room-entry proof this
   finding always said it would take. **Committed (`c753535`) and deployed
   2026-07-27; the phone still needs an APK rebuild.**

2. ~~**Android L-10 (Low) — relay config fails SILENTLY on an older WebView.**~~
   **FIXED 2026-07-27 — see the snapshot at the top of this file.** (Its sibling
   L-11, the additive `Copy` task shipping stale assets, was already fixed —
   `syncWebClient` is a `Sync`.) **Still needs the on-device install** — the APK
   is built and the unit test passes, but nothing has been run on the phone.

3. **Info-level backlog (no urgency, listed so it is not lost):**
   - `dilithium-py` upstream says *"under no circumstances should this be used
     for cryptographic applications"*. Here it only VERIFIES signatures over
     PUBLIC data (~6.5 ms, constant-time irrelevant), so the residual risk is
     *correctness* of the PQ ownership proof, which nothing else re-checks.
     Document the accepted risk; prefer liboqs bindings if they become viable.
   - No `Cross-Origin-Opener/Resource/Embedder-Policy` (framing is already
     covered by `frame-ancestors 'none'` + XFO) — cheap isolation win.
   - No session revocation/logout: a leaked bearer token stays valid for the
     full `TOKEN_TTL_SEC = 3600`. `/healthz` is unthrottled.
   - `neutralName()` uses a case-folded 12-char (~62-bit) truncation of the
     sender key as the contact store's PRIMARY KEY. Infeasible to grind today,
     but a derived primary key should be a full-width hash.
   - Dead code / naming: `_reimportExtractable()` is a no-op that asserts
     behaviour it does not implement; unused exports `crypto.UNAVAILABLE`,
     `contacts.hasStore` (now used by the P-02 fix), `account.me`; the v2
     register domain is built with `.replace("/v1","/v2")` instead of a constant.
   - `with sqlite3.connect(...)` commits but never `close()`s (refcount-dependent).
   - One `console.error` in `app.js` reaches Android logcat; gate behind a debug flag.
   - No passphrase policy anywhere; at-rest KDF is PBKDF2-SHA256 600k (correct
     and salted, but GPU-friendly — Argon2id/scrypt would be materially better).

### ✅ DONE (2026-07-25): redesign stage 2 — hierarchy pass
**SHIPPED (built + verified; deploy/APK pending) — see the top snapshot.**
Dual type stack, button tiers, restructured Profile, drawer head/foot, empty
states, trust legend, global `[hidden]` fix. Stage 1 fixed tokens; this fixed
hierarchy. If a stage 3 is ever wanted, the remaining candidates are: the
Live-room 3-step flow as a real progress affordance (it's still a text line),
a mobile bottom-nav instead of the drawer, and the OTP panel (still the
densest, least-designed surface in the app).

### ✅ DONE (2026-07-19): cosmetic polish pass ("make it look less cheap")
**SHIPPED — see the 2026-07-19 snapshot at the top** (built + verified;
deploy/APK were run by hand due to session permissions). Original spec below.

### (original spec, 2026-07-18, user-requested): cosmetic polish pass
User wants the web client + app to look **more polished while KEEPING the
existing design language** (dark GitHub-ish palette, monospace, panel cards).
Explicit ask: **remove the emojis from the drawer menu** — they make it look
cheap. This is presentation-only: no crypto, no logic changes, no new runtime
deps.

**Hard constraints (these rule out the usual redesign tools — do NOT fight them):**
- **Strict CSP:** `style-src 'self'` + no `unsafe-inline`, `default-src 'none'`.
  No inline styles, no CDN, no external stylesheets. **Web fonts are blocked**
  (font-src falls back to `'none'`) unless you add `font-src 'self'` to the CSP
  in BOTH `backend/main.py` and `android/.../MainActivity.kt` AND vendor a
  woff2 — treat a custom typeface as a *separate, security-relevant* change, not
  part of this pass. Default to a refined system stack instead.
- **No build step / vanilla JS, security-audited:** do it as a **hand-written
  CSS token refresh in `client/style.css`** (it already uses CSS custom
  properties — `--bg/--panel/--fg/--muted/--accent/--ok/--err/--border`). NO
  framework, NO Tailwind/CDN. Keep JS `textContent`-only.
- **Bundled into the Android WebView** via gradle `syncWebClient` — whatever you
  ship in `client/` must stay self-contained.
- **Do NOT touch the `<script type="importmap">` line in index.html** — its text
  is pinned by the CSP hash (`test_csp_hash.py`); changing it means regenerating
  the hash in two files. A pure style pass shouldn't need to.

**Do:**
1. **Remove drawer emojis** — `client/index.html:18–21` (`👤 Profile / 🔒 Live
   room / 👥 Users / 💬 Chats`). Prefer **subtle monochrome inline SVG icons**
   (inline SVG is CSP-safe; `img-src 'self' data:` also allows data-URIs) for a
   polished look; plain text labels are the safe fallback. **KEEP** the `☰`
   menu button (standard) and the **functional trust-mark glyphs 🟢🟡⚪** in the
   Users/Chats views (they're documented security UX, not decoration).
2. **Token refresh in `style.css`:** introduce a small design-token layer on top
   of the existing vars — a spacing scale, consistent radii, a real type scale
   (sizes/weights/letter-spacing on labels + `.step`), soft elevation/shadow for
   `.panel` and the drawer, and refined **hover/active/focus-visible** states on
   `.navitem`, `button`, `input/select`, `.alg-card`. Tighten the palette
   (subtle surface layering panel-vs-bg, gentler borders) WITHOUT changing the
   hue language. Polish the chat bubbles, `.safety` block, `.myhandle`,
   `.profile-qr`, badges. Keep the mobile `@media (max-width:600px)` behavior.
3. Keep everything responsive + theme-consistent; no horizontal overflow.

**Optional first step:** prototype 1–2 directions in a **Claude Artifact**
(self-contained, already CSP-shaped) so the user can eyeball before porting into
`style.css`.

**Verify + ship:** puppeteer harness in `scratchpad/verify-sc` (reuse
`profile-flow.mjs` / `h01-flow.mjs`) — confirm every view renders, the menu has
NO emoji, nothing overflows, all flows still work; screenshot a couple of views.
Then **deploy: rsync ONLY `client/`** to the box (backend untouched → no
`chown`/restart needed, static files serve immediately; importmap untouched → no
CSP-hash change). Rebuild the APK (`JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64
./gradlew assembleDebug`, `syncWebClient` copies the client) and `adb install
-r`. Backend `test_csp_hash.py` must still pass. Commit + push; update this file.


### ✅ DONE (2026-07-18): Profile tab in the left drawer
**SHIPPED — see the "Profile tab shipped" snapshot at the top.** Built with ALL
the suggested additions (QR, key details, status line, identity actions,
saved-users count). What follows is the original spec, kept for reference.

Add a **👤 Profile** view to the drawer menu (alongside Live room / Users /
Chats — probably first) that shows the user's OWN data in one place. Read-only
display of what's already in memory when the identity is unlocked; no new crypto.

**Must show (user-specified):**
- **Name** — the registered username (`sc.username.v1`), or "not registered yet".
- **Handle** — `username#token` with the **Copy handle** + **Copy invite link**
  buttons (reuse `myHandle()` / `inviteLink()` / the copy wiring already built
  for the Users view — factor them out so both views share one implementation).
- **Fingerprint** — the identity fingerprint (`identity.fingerprint()`), the same
  string contacts verify in person. Show it prominently.

**Suggested additions (my picks — confirm before building):**
- **QR code of the invite link** — the natural in-person exchange (a contact
  scans it to add you). Needs a tiny self-contained QR generator; keep it inline
  (no CDN — CSP forbids external scripts).
- **Key details** — the algorithms (Ed25519 + ML-DSA-65 signing; ECDH P-256 +
  ML-KEM-768 encryption) and maybe the short public-key fingerprints, so a
  curious/technical user can see what's protecting them.
- **Status line** — identity unlocked? registered? logged in (mailbox reachable)?
- **Identity actions** — surface the existing **Copy backup** (export) and
  **Forget identity** here too (currently only on the Live-room identity screen),
  since a "Profile" page is where users will look for them.
- **Counts** — e.g. "N saved users" (from `contacts.list()`), for a quick sense
  of state. Optional.

**Locked/unlocked:** when the identity is locked, show a "unlock in the Live room
first" hint (same pattern as Users/Chats). No data is available before unlock.

**Security note:** this is presentation-only — it displays existing local state,
adds no network calls and no new trust surface. The fingerprint/handle shown are
already public-shareable. Keep everything `textContent` (no innerHTML), matching
the rest of app.js. Do it in `client/` (the single source of truth) so the phone
app inherits it via the gradle `syncWebClient` copy; then deploy to Hetzner
(rsync — separate from git push) and rebuild the APK.

### ⮕ PLAN (2026-07-17): contacts + web-of-trust + async 1:1 chats ("WhatsApp mode")
User-requested feature set: a left drawer menu with two new views next to the
existing live room — a **Users** list (known users + public keys + 3-level
safety marks, securely stored on-device) and a **Chats** list (persistent 1:1
chats, WhatsApp-style, no shared live room needed). Big change incl. backend
(store-and-forward). Locked design decisions:

- **Safety marks (trust levels):** 🟢 *verified by you* (you compared the
  fingerprint/safety number in person — the existing verify gate or an explicit
  action in the Users view); 🟡 *vouched* (a user YOU verified has published a
  signed vouch for them; UI names the voucher); ⚪ *unverified*. Vouches are
  dual-signed (Ed25519 + ML-DSA-65) statements over the target bundle,
  published to / fetched from the directory. The server is never the trust
  root — marks are computed client-side from signatures it can't forge.
- **Contacts & chats at rest:** encrypted client-side under a key derived from
  the identity passphrase (PBKDF2-600k → AES-256-GCM, own salt; key lives only
  in memory while the identity is unlocked) — same posture as the identity
  blob and OTP pads. Never plaintext in localStorage.
- **Async E2EE (chats without a live room)** needs public ENCRYPTION keys in
  the directory → **bundle v2**: identity adds P-256 ECDH + ML-KEM-768 public
  keys, dual-signed at registration. Async chat modes: **SEALED** (default:
  per-message ephemeral hybrid ECDH+ML-KEM → AES-256-GCM; sender identity +
  dual signature INSIDE the ciphertext), **AES256** (shared passphrase),
  **OTP** (pad). DHKE/RSA stay live-room-only (inherently interactive).
- **Mode lock + negotiated change:** each chat is locked to one mode; a mode
  change is an encrypted in-chat control message the peer must accept (both
  directions signed); the chat renders it as system lines.
- **Mailbox backend (store-and-forward):** server stores ONLY
  (recipient, opaque ciphertext, arrival time) — sender is inside the sealed
  envelope, invisible to the server. Hard caps: per-recipient message + byte
  quota, global cap, TTL (~14 d), delete-on-fetch (auth: session token), own
  rate bucket. No content, no sender metadata, no read receipts server-side.

**Phases** (each ends verified: unit + live-browser + deploy; check off here):
- [x] **P1 — client shell + contacts** — DONE 2026-07-17 (see dated entry):
      drawer menu (Live room / Users / Chats placeholder), `contacts.js`
      encrypted store (PBKDF2-600k → AES-GCM under the identity passphrase,
      unlocked alongside the identity, wiped on identity-forget, key-change
      resets `verified`), Users view (add by handle, fingerprint, 🟢/⚪ marks,
      confirm-gated verify/unverify/remove, auto-🟢 from the live-room verify
      gate + from a matching pin on add). Unit + live-browser verified;
      deployed to Hetzner + phone.
- [x] **P2 — web of trust** — DONE 2026-07-17 (see dated entry): vouch
      endpoints (POST/DELETE `/api/vouch`, GET `/api/users/{u}/vouches`
      token-gated), dual-sig verified server-side over the target's registered
      bundle, caps (200/voucher, 200k total, 50/response); client publishes on
      🟢 (opt-in confirm, requires login), retracts on Unverify, and computes
      🟡 STRICTLY locally (voucher must be a contact I verified, server keys
      must equal my pinned copy, dual sig over MY stored target bundle).
      3 new backend tests; browser flow: alice vouches bob → carol (verified
      alice) sees 🟡 "vouched by alice". Deployed to Hetzner + phone.
- [x] **P3 — bundle v2 + sealed envelope** — DONE 2026-07-17 (see dated
      entry): identity carries ECDH P-256 + ML-KEM-768 keypairs (blob v3;
      pre-v3 blobs auto-upgrade on unlock and re-publish), registration v2
      (own domain, dual sig covers enc keys; same-identity re-registration =
      bundle refresh keeping the lookup token), new `sealed.js`
      (hybrid HKDF→AES-GCM envelope, sealed sender + dual sig inside,
      re-target/forgery/tamper refused). 5 new backend tests (65 total),
      new `sealed.test.mjs`. Deployed.
- [x] **P4 — mailbox + Chats view** — DONE 2026-07-17 (see dated entry):
      `mailbox.py` store-and-forward (token-gated POST, login-gated
      delete-on-fetch GET, size/inbox/global caps + 14d TTL + own rate
      bucket; 5 tests, backend 70 passed); `chats.js` encrypted chat store;
      Chats view (start-chat picker, chat list w/ marks + preview,
      bubble conversation, 6s polling incl. auto-add of unknown senders from
      the sealed handle). Browser-verified both directions; deployed.
- [x] **P5 — mode lock + negotiated mode change** — DONE 2026-07-17 (see
      dated entry): each chat is locked to SEALED or AES256; a change is a
      signed control message the peer must accept/decline; AES256 adds an
      inner AES-256-GCM layer under a per-chat passphrase inside the sealed
      envelope. Browser-verified propose→accept→double-encrypted message;
      deployed (APK rebuilt, phone reconnect pending).
- [x] **P6 — hardening pass over the new surface** — DONE 2026-07-17 (see
      dated entry): adversarial `pentest-p6.mjs` (vouch forgery, client 🟡
      forge-resistance, mailbox enumeration/auth/cross-user isolation,
      captured-envelope, chat sender spoofing) — all attacks refused, local
      AND live. 3 live integration suites still green (no relay regression).
      README documents contacts/WoT/chats. APK rebuilt. Live E2E on Hetzner.
- [x] **MEDIUM — OTP concurrent pad use = two-time pad (2026-07-16 OTP pentest,
      Finding 1)** — FIXED 2026-07-16 (see dated entry): a same-origin exclusive
      lock (Web Locks API, localStorage-heartbeat fallback) is taken on connect;
      a pad live in one tab refuses connect in any other. Live-verified (second
      tab refused).
- [x] **MEDIUM — OTP pad stored unencrypted at rest (2026-07-16 OTP pentest,
      Finding 2)** — FIXED 2026-07-16: the pad bytes AND offsets are now stored
      encrypted (PBKDF2-600k → AES-256-GCM) under a per-pad passphrase, unlocked
      per session (PBKDF2 once; cached key for cheap per-message re-saves).
      Offsets inside the GCM blob, so an attacker can't roll `sendOffset` back to
      force reuse. Live-verified (blob has kdf/iv/ct only; wrong passphrase
      refused).
- [x] **LOW — OTP export file has no single-use/role binding (2026-07-16 OTP
      pentest, Finding 3)** — FIXED 2026-07-16: re-export of an already-shared pad
      warns and requires a confirming second click; import still dedups by padId
      and shows a strong one-device-per-side warning. (Cross-device double-import
      of a manually-copied file remains inherent without identities — documented.)
- [x] **LOW/info — malicious/low-entropy imported pad downgrades the importer's
      outbound confidentiality (2026-07-16 OTP pentest, Finding 4)** — FIXED
      2026-07-16: `importPad` rejects a pad whose Shannon entropy is < 7.0
      bits/byte (all-zero / grossly low-entropy). Live-verified.
- [x] **CRITICAL — relay-address JS injection (2026-07-08 Android pentest,
      Finding 1)** — FIXED 2026-07-16 (see dated entry): `RelayUrls.parse` now
      whitelist-validates the host charset (`^[A-Za-z0-9.-]+$`) and rejects
      credentials in the authority, before accepting; `MainActivity` builds the
      injected relay config with `JSONObject` instead of hand-interpolation.
      Regression tests (`RelayUrlsTest`, Robolectric) reject the live PoC
      payloads against the real `android.net.Uri`.
- [x] **Medium — `shouldOverrideUrlLoading` origin check is prefix-confusable
      (2026-07-08 Android pentest, Finding 2)** — FIXED 2026-07-16: the check now
      compares the PARSED `request.url` scheme+host to the app origin instead of
      `startsWith`, so `…internal.evil.com` no longer matches.
- [x] **Low — relay value also corrupts the CSP header (2026-07-08 Android
      pentest, Finding 3)** — FIXED 2026-07-16 by the Finding 1 host whitelist
      (the CSP interpolation can no longer receive `;`/quote/brace characters).
- [x] **Low/docs — CORS/WS-origin allow-list entry for the app isn't unique
      (2026-07-08 Android pentest, Finding 4)** — FIXED 2026-07-16: the app now
      pins a unique virtual origin via `WebViewAssetLoader.setDomain(
      "secure-chat.internal")`; `APP_WEBVIEW_ORIGIN` + `backend/config.py`'s
      comment updated to match (comment no longer claims the shared default
      domain uniquely identifies the app).
- [x] **Should-fix (informational, same pentest)** — FIXED 2026-07-16:
      `setWebContentsDebuggingEnabled` is now gated behind `BuildConfig.DEBUG`
      (enabled `buildConfig` in build.gradle.kts); `network_security_config.xml`
      scopes cleartext to loopback + `.onion` only (base-config now
      `cleartextTrafficPermitted="false"`); `importMapHash` drift is guarded by
      a new assertion in the backend's `test_csp_hash.py`
      (`test_android_importmap_hash_matches`, skips if android/ absent).
- [x] **Initialize git** in `~/secure-chat` and make the first commit — DONE
      (repo initialized on `master`; initial commit covers backend, client, and
      tests; `.venv`/`node_modules`/DBs/logs ignored).
- [x] **Browser account integration** — DONE (see dated entry above): register /
      login / fetch-by-username with directory-aware pinning, plus an integration
      test for the client directory protocol.
- [x] **Abuse/DoS hardening** — DONE (see dated entry above): global connection
      cap + idle read timeout. Per-IP limits and lifetime frame caps were
      intentionally skipped (see rationale in the entry).
- [x] **Reflection/replay protection for AES256/DHKE/PQKEM** — DONE (2026-07-02):
      `AuthChannel` binds a per-session sender tag + sequence number into the GCM
      additional data. AES256 has a documented cross-session-replay residual
      (static key).
- [x] **Forward secrecy for RSA mode** — DONE (2026-07-03, see dated entry):
      RSA key transport + one-way HMAC ratchet with one-time AES-GCM message
      keys; root secret + RSA private key erased once traffic starts.
- [x] **AES256 ratchet** — DONE (2026-07-03, see dated entry): shared
      `RatchetChannel`, chains rooted in passphrase + both peers' fresh session
      nonces (new AES256 hello exchange). Closes the cross-session-replay
      residual; FS honestly limited by the passphrase being a long-term secret.
- [x] **Concurrent decrypt() reopens replay acceptance (High, found 2026-07-03
      pentest, all 4 modes)** — FIXED 2026-07-07 (see dated entry): per-channel
      `CallQueue` serializes all encrypt/decrypt calls, so the replay counter
      can no longer be read before a prior call commits it. Regression tests
      (`concurrencyChecks` in `crypto.test.mjs`, all 4 modes) cover concurrent
      duplicates and the counter-rollback replay scenario.
- [x] **Concurrent encrypt() permanently kills the ratchet channel (Medium,
      found 2026-07-03 pentest, AES256/RSA)** — FIXED 2026-07-07 (see dated
      entry): same `CallQueue` serialization (overlapping encrypts now step the
      chain sequentially), plus app.js disables Send while a send is in flight.
      Verified live in a real browser: double-click Send delivers exactly once
      and the channel keeps working.
- [~] **Android app** — IN PROGRESS (2026-07-07/08, see dated entries; icon +
      signing done 2026-07-23, see top snapshot): `android/` WebView shell
      bundling the audited client; debug APK builds clean; verified in a real
      browser AND ON-DEVICE (Android 14 emulator — AES256 end-to-end through
      the relay, both directions). Surfaced + fixed the Mixed-Content
      transport constraint (relay must be wss/loopback/.onion). Adaptive app
      icon and a real release-signing config (local keystore, gitignored) are
      now in place. REMAINING: an on-device pass of the identity +
      safety-number gate (DHKE/RSA/PQKEM; only AES256 driven on-device so far
      — started 2026-07-23, interrupted mid-session).
- [x] **OTP mode** — DONE (2026-07-16, see dated entry): true XOR one-time pad
      (`OtpPad` in crypto.js) with two-region split (no reuse across senders),
      strictly-increasing offsets (replay + cross-session replay rejected),
      per-message one-time HMAC-SHA-256 authenticator, and forward-secrecy
      zeroing of consumed bytes. Pad lifecycle in `otp.js`: CSPRNG + draw-to-
      generate entropy, passphrase-encrypted export/import file for the in-person
      exchange, localStorage persistence of bytes + offsets. UI + budget display
      in app.js/index.html. Verified end-to-end in a real browser (generate →
      export/import → two-way messaging → offsets persist → consumed bytes zeroed
      at rest).
- [x] **Tor deployment** — DONE 2026-07-28 (see the dated entry at the top):
      v3 onion service live beside the clearnet site, both proxying to the one
      loopback uvicorn; origin added via `SECURE_CHAT_EXTRA_ORIGINS`;
      `SECURE_CHAT_TRUSTED_PROXIES` **unset** (F-03 would otherwise reopen on the
      onion path); config committed under `deploy/`. **Android still points at
      clearnet** — switching it needs Orbot on the phone, which is the remaining
      piece of "pairs with the app".
- [x] **Handshake replay across sessions in a reused room (Medium, found
      2026-07-02 pentest)** — DONE (2026-07-02 second session, see dated
      entry): transcript v2 folds a fresh per-connection nonce from both peers
      (hello phase) into the signed handshake; live relay replay PoC now
      REJECTED (regression test in `auth.integration.test.mjs`).
- [x] **AES256 cross-session replay (Low, re-confirmed 2026-07-02)** — CLOSED
      2026-07-03 by the AES256 ratchet: session chains bind both peers' fresh
      session nonces, so a captured session-1 frame can no longer authenticate
      in session-2 (regression test `aesRatchetChecks` in `crypto.test.mjs`,
      incl. a fresh-receiver variant proving the key — not the replay counter —
      rejects it).

DONE since this list was first written (pruned from the TODOs above): web client
MVP with the WebCrypto encryption menu; the DHKE/RSA/PQ `key`-message handshake
flow (documented + implemented); authenticated key exchange end-to-end in the
browser; the identity model decision (long-term identity keys verified in person,
relay stays anonymous/room-based); and ASGI endpoint tests for the relay.

## Open questions for the user
- Identity model: fully anonymous/ephemeral, or accounts? (Leaning anonymous
  for the privacy goal.)
- How do two people exchange a room id out of band (QR, link, in person)?
- Group chat (>2) ever needed, or strictly 1:1?

## How to run (quick ref)
```bash
cd ~/secure-chat/backend
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
pytest -q                          # full server suite (validation + accounts + ws)
./run.sh                           # terminal 1: relay + web client on 127.0.0.1:8000

# client-side (Node 20+), from ~/secure-chat/client:
npm test                           # crypto + identity/auth unit suites (offline)
node integration.test.mjs          # relay round-trip (server running)
node auth.integration.test.mjs     # authenticated handshake through relay (server running)
```
