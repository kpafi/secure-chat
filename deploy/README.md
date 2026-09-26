# Deployment

The files here are **copies of what is actually running** on the test box
(pulled from it, not written from memory), so a re-provision reproduces the
live setup instead of approximating it.

| file | goes to | purpose |
|---|---|---|
| `secure-chat.service` | `/etc/systemd/system/` | the relay unit (uvicorn, loopback only) |
| `torrc.secure-chat` | appended to `/etc/tor/torrc` | the v3 onion service |
| `Caddyfile` | `/etc/caddy/` | clearnet TLS front end (shared, see "One Caddy, several services") |
| `caddy-compose.py` | staged by the deploy | keeps other services' blocks in the shared Caddyfile |

Layout on the box: `/opt/secure-chat/{backend,client,venv}`, running as the
no-login system user `securechat`.

## The one rule

**uvicorn binds `127.0.0.1` and is never exposed on a public interface.**
Everything reaches it over loopback — Caddy for clearnet, Tor for the onion.
Check it after any change:

```bash
ss -ltnp | grep 8000        # must show 127.0.0.1:8000, never 0.0.0.0 or *
```

## The unit's sandbox

`secure-chat.service` has two tiers. The first (`NoNewPrivileges`,
`ProtectSystem=strict`, the 0700 `StateDirectory`, `ProtectHome`, `PrivateTmp`,
`PrivateDevices`) keeps the relay from writing anywhere but its database. The
second (pentest F-RELAY-010, added for 0.4.0) fences what a compromised relay
process could still do: sockets only `AF_UNIX`/`AF_INET`/`AF_INET6`, IP traffic
only to and from localhost (`IPAddressDeny=any` + `IPAddressAllow=localhost`;
the relay makes **no** outbound connection), a `@system-service` syscall
allow-list minus `@privileged @resources` with `EPERM` for the rest,
`MemoryDenyWriteExecute`, an empty capability bounding set, the `Protect*`
kernel/clock/hostname/proc switches, `RestrictNamespaces/Realtime/SUIDSGID`,
`LockPersonality`, `RemoveIPC` and `UMask=0077`. `systemd-analyze security
--offline=yes deploy/secure-chat.service` (systemd 261): **7.7 EXPOSED before,
1.1 OK after**. Each line is pinned by `backend/tests/test_service_unit.py`.

Measured, not assumed: the backend suite and the three client integration
suites against a real uvicorn pass under the same properties via
`systemd-run --user` on the dev box. `ProtectProc=` could not be exercised
that way (a user manager ignores it); `PrivateUsers=` is left out on purpose
(see the comment in the unit).

**Installing a changed unit** (the rsync never copies it):

```bash
install -m 0644 -o root -g root deploy/secure-chat.service /etc/systemd/system/secure-chat.service
systemd-analyze verify /etc/systemd/system/secure-chat.service
systemctl daemon-reload && systemctl restart secure-chat && systemctl is-active secure-chat
systemd-analyze security secure-chat | tail -1      # want ~1.1 OK
curl -s http://127.0.0.1:8000/healthz
```

If it does not come up, `journalctl -u secure-chat -n 50` names the failing
line; rolling back is copying the previous unit back and repeating the
daemon-reload (the 0.4.0 deploy script keeps the live unit in its backup
directory and does this by itself). **MailDigest on the same box is unaffected**: it runs in Docker
under its own units, and nothing here touches `docker.service`, Caddy's unit
or any other service. `IPAddressDeny=` applies to this unit's cgroup only.

## Two front ends, one process

Caddy and Tor both proxy to the *same* `127.0.0.1:8000`. That is deliberate:
rooms, session tokens, and login challenges live in **process memory**, so a
second instance would split-brain them — two people who picked the same room id
would land in different rooms, one per front end, and never see each other.

The cost of sharing is the rate-limit keying below.

## One Caddy, several services

`/etc/caddy/Caddyfile` is **not ours alone**: the box also serves the Kiosk
news app (`kiosk.138-199-144-35.sslip.io` → `127.0.0.1:8100`, deployed from
its own repository). The 0.4.0 deploy installed `deploy/Caddyfile` over the
shared file wholesale and so removed Kiosk's site block; `kiosk.…` was down
from 2026-09-26 20:13 UTC until Kiosk's next deploy put the block back at
20:27. From then on:

- **`/etc/caddy/sites.d/*.caddy` is where other services put their sites**,
  one file each (`sites.d/kiosk.caddy`). `deploy/Caddyfile` ends with
  `import /etc/caddy/sites.d/*.caddy`, after the global options block and our
  own site; the path is absolute so that `caddy validate` of the staged copy
  checks it together with those files. The deploy creates the directory
  (root, 0755) if it is missing and otherwise **never touches it or its
  files**. A glob that matches nothing is fine for Caddy (a warning only;
  not tried against a real Caddy here — were it an error, step 4's validate
  would stop the deploy before anything is installed).
- **Marker blocks are carried over.** A service that still keeps its site in
  the shared file between `# >>> name …` and `# <<< name` (Kiosk's deploy does
  this today) keeps it: the deploy installs `deploy/Caddyfile` followed by
  every marker block of the live file, verbatim (`caddy-compose.py`). A
  broken marker (begin without end, nested, duplicate, a near-miss like
  `# >>>kiosk`) stops the deploy before anything is changed — a human
  decides; a dropped block is a site down.
- **Nothing outside a marker block is dropped silently.** Everything in the
  live file outside the marker blocks must also be in `deploy/Caddyfile`
  (the global options, our site, the import); anything else — say another
  service's site without markers — stops the deploy before anything is
  changed. So does anything there the check cannot parse safely (a
  heredoc, a quote open across lines, a line ending other than LF/CRLF).
  The flip side: if a release removes or renames a top-level entry of
  `deploy/Caddyfile`, the deploy refuses until the old one is removed from
  the live file by hand. Only top-level entries are compared: anything
  another service put INSIDE our site or the global options block is not
  kept — those two blocks are ours, never edit them for another service.
- **Their content must not name our site address.** A carried block or a
  `sites.d/*.caddy` file that mentions `138-199-144-35.sslip.io` as a whole
  address, in any letter case (e.g. `log { hostnames 138-199-144-35.sslip.io
  … }`, which would log our traffic, or a second site for our host) stops
  the deploy. `kiosk.138-199-144-35.sslip.io` is a different address and
  fine. It is a check against mistakes, not a sandbox: a wildcard like
  `*.sslip.io`, an `{$ENV}` placeholder or a nested import get past it, and
  whoever writes `sites.d` is root anyway.
- **`sites.d` must be root's alone:** the deploy refuses (and changes
  nothing) if the directory or a file in it has a non-root owner, is group- or
  other-writable, or is a symlink — whatever is in there becomes part of the
  front end of secure-chat.
- Our global options apply to their sites too, but only the default logger
  (discarded box-wide); an access log they configure for their own site is
  theirs.
- Step 4 re-checks the live file just before installing and refuses if
  another service's deploy replaced it meanwhile; on a failed reload it
  restores the file as it was at the start of step 4 (unless someone else's
  file is there by then: left alone, reported) and reloads it only if it
  validates. It never restarts Caddy: a failed reload keeps the last good
  config running, a failed restart would take every site down.

So the live file is `deploy/Caddyfile` plus other services' marker blocks,
not a byte copy of it; step 5 of the deploy checks exactly that (and that
the marker blocks before and after are the same). **Never** put a marker
block into `deploy/Caddyfile` (a test refuses it), and never hand-edit
someone else's block or file here.

Other services: prefer a file in `sites.d/` over a marker block. For Kiosk
that is a follow-up in its repository (write `/etc/caddy/sites.d/kiosk.caddy`
and remove its marker block from the shared file in the same step, or the
site is defined twice and Caddy refuses the config). Test a new
`sites.d/` file with `caddy validate --config /etc/caddy/Caddyfile --adapter
caddyfile` before `systemctl reload caddy`.

## `SECURE_CHAT_TRUSTED_PROXIES` must stay UNSET

It used to be `127.0.0.1` so `/api` limiters could key per client IP behind
Caddy. **Do not restore it while the onion forwards to this port.**

The app cannot tell a Tor visitor from Caddy — both are loopback peers. If
loopback is trusted, `accounts.client_key()` honours the client's own
`X-Forwarded-For`, so an onion visitor mints a fresh rate-limit bucket per
request. That is pentest 2026-07-25 **F-03** reopened, and it defeats the
anti-enumeration lookup limiter, the challenge limiter, and the mailbox limiter
at once.

Unset, `client_key()` trusts nobody: it ignores `X-Forwarded-For` completely and
keys on the real peer, so the onion topology collapses to one shared bucket. It
**fails closed**. Measured on the live onion (16 parallel lookups,
`LOOKUP_RATE_CAPACITY = 10`):

| `X-Forwarded-For` | allowed | rate-limited |
|---|---|---|
| rotating (16 distinct values) | 10 | 6 |
| fixed (1 value) | 10 | 6 |
| **`127.0.0.1` (the peer's own address)** | **10** | **6** |

Identical, and exactly the bucket capacity — forging the header buys nothing.
Were it honoured, the rotating run would have scored 16/16.

> **Corrected 2026-07-29 (pentest M-1).** The third row is new, and until this
> fix it read **10 allowed / 0 limited**: a *second* bucket. The original table
> used `203.0.113.x` for both rows, and both land in the same branch of the old
> `client_key()`, so it measured one bucket twice and never tested the claim.
> The old code treated `peer in hops` as proof that uvicorn had rewritten the
> address; in this deployment the peer is always `127.0.0.1`, so one header
> picked the branch. Honest traffic sat in bucket A while the attacker worked
> bucket B uncontended — and the same header wrote the "proxy headers appear to
> be TRUSTED" warning on a healthy server, burning that signal (L-9).
> `client_key()` is now a pure function of the peer, and
> `test_proxy_headers.py` pins that with the topology the original measurement
> missed.

**Accepted trade-off:** the clearnet side loses per-IP rate limiting too, and
shares that one global bucket with the onion.

> **Corrected 2026-07-29 (pentest M-2).** This paragraph used to say a clearnet
> abuser can "throttle onboarding", that `config.py` "already sizes
> `REGISTER_RATE_*` for exactly this", and that Tor's PoW defence blunts it.
> All three were wrong:
>
> 1. **It is worse than onboarding.** The tightest global bucket is
>    `CHALLENGE_RATE_REFILL_PER_SEC = 0.5`, which gates **login for every
>    existing account**, not registration. Measured: an attacker at ~2 req/s
>    (~300 B/s) on `POST /api/auth/challenge` denied login to all accounts —
>    0 of 4 honest attempts succeeded. `GET /api/mailbox` burns its bucket
>    **unauthenticated**, because the limiter is a route dependency that runs
>    before `current_user`.
> 2. **`config.py` sized the wrong knob.** Only `REGISTER_RATE_*` was
>    re-derived for a global bucket. `CHALLENGE_RATE_*` and `LOOKUP_RATE_*`
>    were sized as *per-IP* limits and silently became global ones.
> 3. **PoW does not apply.** `HiddenServicePoWDefensesEnabled` prices
>    *introduction*; this attack builds one circuit and then sends cheap HTTP
>    on it. The options that do apply are `HiddenServiceMaxStreams` and
>    `HiddenServiceMaxStreamsCloseCircuit`, now set in
>    `torrc.secure-chat`. They cap concurrent streams per circuit, which raises
>    the cost of the attack but does not remove it — an attacker willing to
>    build circuits still gets through, and that remains **accepted**.
>
> Live chat (`/ws`) is unaffected: its token bucket is per-connection.

If per-IP limiting on clearnet is ever needed back, the honest fix is a secret
header that Caddy injects and a Tor visitor cannot know — a code change to
`client_key()`, not a config change.

## Origins

Every origin the client is served from must be in `SECURE_CHAT_EXTRA_ORIGINS`
(comma-separated), or the WebSocket handshake is refused by the CSWSH guard and
`/api` is refused by CORS. The onion is plain `http://` — there is no TLS inside
Tor, and the address itself is the service's public key.

`config._valid_origins()` rejects anything malformed at import, so a typo takes
the relay down at startup rather than silently opening it. If the unit changes
and the service will not start, check that line first.

## Install the onion service

```bash
apt-get install -y tor
# Idempotent (L-10): appending twice gives a duplicate HiddenServiceDir and Tor
# then refuses to start. Guard the append instead of repeating it.
grep -q 'HiddenServiceDir /var/lib/tor/secure-chat' /etc/tor/torrc \
  || cat deploy/torrc.secure-chat >> /etc/tor/torrc
tor --verify-config -f /etc/tor/torrc
systemctl restart tor@default
cat /var/lib/tor/secure-chat/hostname          # the .onion address
```

Then put `http://<address>.onion` into `SECURE_CHAT_EXTRA_ORIGINS` in the unit,
`systemctl daemon-reload && systemctl restart secure-chat`.

`/var/lib/tor/secure-chat/hs_ed25519_secret_key` **is** the onion's identity.
Back it up if the address must survive a rebuild; losing it means a new address
and every user re-exchanging it.

## Verify

```bash
# a throwaway client tor, no root and no system service needed
printf 'SocksPort 9050\nDataDirectory /tmp/tordata\nClientOnly 1\n' > /tmp/torrc.client
mkdir -p /tmp/tordata && chmod 700 /tmp/tordata
tor -f /tmp/torrc.client &

curl --socks5-hostname 127.0.0.1:9050 http://<address>.onion/healthz

# full relay round trip incl. the P-08 admission flow, no npm deps needed
node onion-ws.mjs <address>.onion
```

`onion-ws.mjs` speaks SOCKS5 + raw RFC 6455 because Node's built-in WebSocket
cannot use a proxy and the `e2e/` suite's `puppeteer-core` is gitignored. It
asserts the upgrade succeeds, the onion Origin is allow-listed, a **foreign
Origin is refused with a definite HTTP status while an allowed Origin upgrades
in the same run**, and payloads relay both ways.

> **Corrected 2026-07-29 (pentest M-3).** This used to claim the harness
> verifies a **403**. It did not verify anything: `wsConnect` resolved
> `{code: 0}` on *any* close before the header terminator, so a Tor hiccup or a
> relay restart satisfied the check and it reported OK — proved green at
> `HTTP 0` with the CSWSH guard never exercised. Asserting `code === 403` alone
> is still unsound, because `main.py`'s bad-origin close and its connection-cap
> close both happen before `accept()` and uvicorn collapses them to the same
> status. The harness now runs a **positive control in the same pass**: the
> allowed Origin must upgrade *and* the foreign one must be refused, and the
> run fails if the allowed Origin did not upgrade — which is what distinguishes
> "the guard rejected it" from "the transport died".

## What the onion does and does not buy

**Does:** the address is self-authenticating — it *is* an Ed25519 public key, so
reaching it depends on no certificate authority and no DNS. It removes the
clearnet metadata both parties leak to the network, and the relay never learns a
client IP.

**Does not:** fix the web client's trust boundary. The onion still serves the
JavaScript, so a compromised server can still ship backdoored code on the next
load. That is what the **Android app** is for. See the README's "Trust boundary
of the web client".

**Does not, here:** hide the service's location. This onion is colocated with a
public clearnet site on the same host, so anyone who knows both can correlate
them, and the clearnet site remains an attack surface into the same box. A
location-anonymous deployment needs a host with no clearnet service on it.

## What ships: one list

`client/` leaves the repository four ways: the relay serves it, the deploy
script rsyncs it to the box, Gradle copies it into the APK, and
`ios/scripts/sync-web.sh` copies it into the iOS bundle. Which files are
development-only (tests, package manifests, `node_modules`, dotfiles,
`README.md`) is decided by **`ship-excludes.txt`** alone: the deploy rsync,
Gradle and `sync-web.sh` read it, and the relay repeats it as
`main._DEV_ONLY_PATTERNS` (it cannot read `deploy/`, which is not on the box).
A pattern matches any path component, and a matching directory goes whole.
`backend/tests/test_ship_list.py` runs the deploy rsync and `sync-web.sh` into a
temp dir, fetches one real file per pattern from the relay, and checks the
Gradle task's `**/<p>` + `**/<p>/**` translation; all four must ship the same
set. (Pentest F-P7-18: before this, `vendor/README.md` shipped everywhere and
`vendor/lean-qr/package.json` sat in the APK.) `manifest.webmanifest` and
`icons/` ship everywhere on purpose: `index.html` links both.

`rsync-excludes.txt` holds what only the box needs kept out (the accounts DB
and its `-wal`/`-shm`, caches, `tests`). Every deploy script uses both files
with `--exclude-from` and no inline `--exclude`; the newest
`deploy-*.sh` is the template the next one is copied from.

The rsync has no `--delete`, on purpose: a deletion pass skips EXCLUDED
files, so it would not remove a dev file the ship list now excludes (like
`vendor/README.md`); `--delete-excluded` would, but it would also delete
whatever matches `accounts.db*` / `*.db` under backend/ on the box; and a
wrong source path with `--delete` empties the tree. A stale file on the box is
removed by name in the deploy script instead (0.4.0: step 1b, which also
lists any other file on the box that the release does not ship); the relay
404s dev files regardless. At a release, check the
APK too:

```bash
unzip -l android/app/build/outputs/apk/*/app-*.apk | grep assets/web/ \
  | grep -E 'README|package.*\.json|\.test\.mjs|node_modules|/\.'   # want nothing
```

## Code ownership on the box

`/opt/secure-chat/{backend,client}` are `root:root`, directories 0755 and
files 0644: the service user reads its code and never owns it. The relay
writes exactly one thing, the accounts DB with its `-wal`/`-shm`, in
`/var/lib/secure-chat`, which systemd creates and owns for it
(`StateDirectory=`, mode 0700). Deploys up to 0.3.1 ran
`chown -R securechat:securechat /opt/secure-chat/backend`; that was harmless
under `ProtectSystem=strict` (the code tree is read-only to the service either
way) but it let the service user own its own source outside the sandbox. From
the next deploy on, step 2 of the deploy script does `chown -R root:root` on
backend/, client/ and the venv (whose owner was never recorded here),
`chmod -R u=rwX,go=rX` on backend/ and client/ (the venv keeps pip's modes),
and counts what under `/opt/secure-chat` is still owned by `securechat`
(want 0).

## Done by `deploy-2026-09-26-v0.4.0.sh` (was "Pending on the box")

Package 5 changed only repository files; the box catches up with the 0.4.0
deploy, whose script does each of the steps below. **Not run yet** — the relay
stays 0.3.1 until the owner runs it.

1. The script is a copy of the previous template: rsync with
   `ship-excludes.txt` + `rsync-excludes.txt` and root ownership. Its
   preflight refuses a checkout without both lists, with uncommitted or
   untracked files under backend/ client/ deploy/, or without the 0.4.0
   markers.
2. Removes the dev files the old rsync left behind (no `--delete`, see "What
   ships: one list"), by name: `client/vendor/README.md` (the new relay 404s
   it anyway) and the four `@noble` modules deleted from `vendor/` in package
   1. Anything else on the box that 0.4.0 does not ship is listed, not deleted.
3. Ownership: step 2 (`chown -R root:root` on backend/, client/ and venv/,
   `chmod -R u=rwX,go=rX` on backend/ and client/); its count of files still
   owned by `securechat` must say 0.
4. Unit: backs up the live unit, runs `systemd-analyze verify` on the staged
   file, `install -m 0644 -o root -g root`, `daemon-reload`, start, and waits
   for `/healthz` 0.4.0 with no restart in between. If the relay does not come
   up it prints `journalctl -u secure-chat -n 50`, **puts the previous unit
   back and starts the relay again by itself** (and restores the previous code
   if even that fails), then exits non-zero. `systemd-analyze security
   secure-chat` is printed in step 5 (want about 1.1). A login + a sealed
   message from a phone stays a manual check (the sandbox's first run on the
   real box; see "The unit's sandbox").
5. Caddy: backs up `/etc/caddy/Caddyfile`, creates `/etc/caddy/sites.d` if
   missing, composes `deploy/Caddyfile` + the live file's marker blocks (see
   "One Caddy, several services"; added after the 0.4.0 run took the Kiosk
   site down), runs `caddy validate` on that **before** installing it and
   again in place, then `systemctl reload caddy`; a failed validate or reload
   restores the file as it was just before this step. The `/ios/` block
   goes live with it and answers 404 until an IPA is published (see "iOS app
   downloads"). After some traffic, `journalctl -u caddy --since <reload>`
   must hold no client IP (with the default logger discarded it should hold
   nothing but ACME lines); the script prints the exact command. Note the
   trade-off: Caddy's own runtime messages no longer reach journald either
   (a failed `caddy reload` still prints its error to the terminal and keeps
   the old config); `caddy validate` before every reload is the check.

Backups: every run keeps the accounts DB (taken with the relay stopped), the
live unit, the live Caddyfile and a tarball of the code as it ran in
`/root/secure-chat-0.4.0-<stamp>/` (0700); the first run's directory is also
linked as `/root/secure-chat-pre-0.4.0`, the state a full rollback returns to
(`deploy/release-2026-09-26-v0.4.0.md`, "Rollback").

## iOS app downloads (SideStore / AltStore)

> **Goes live with the 0.4.0 deploy.** The `/ios/` block in `Caddyfile` is
> installed by `deploy-2026-09-26-v0.4.0.sh`; until an IPA is published,
> `/srv/secure-chat-ios` does not exist and every `/ios/` URL answers 404.

The relay's clearnet host also serves the iOS download bundle, as static files,
under `https://<host>/ios/`. The repository is private, so GitHub release
assets are not a public download — this server is the distribution point.

1. Bump `MARKETING_VERSION` / `CURRENT_PROJECT_VERSION` in `ios/project.yml`,
   merge, then tag: `git tag ios-v0.3.0 && git push origin ios-v0.3.0`.
2. The iOS workflow builds the unsigned IPA and a release `ios-v0.3.0` with four
   files: `SecureChat-0.3.0.ipa`, `SecureChat-0.3.0.ipa.sha256`, `apps.json`,
   `icon.png`. `apps.json` points at `https://138-199-144-35.sslip.io/ios`
   unless the repository variable `IOS_DIST_BASE_URL` says otherwise.
3. Check the IPA against the hash in the **GitHub release notes** (the
   release job computed it; the `.sha256` file only proves the bundle agrees
   with itself), then copy the files to the box:
   ```bash
   echo "<hash from the release notes>  SecureChat-0.3.0.ipa" | sha256sum -c
   sudo mkdir -p /srv/secure-chat-ios
   sudo cp SecureChat-0.3.0.ipa SecureChat-0.3.0.ipa.sha256 apps.json icon.png /srv/secure-chat-ios/
   sudo chown -R root:root /srv/secure-chat-ios && sudo chmod 644 /srv/secure-chat-ios/*
   sudo systemctl reload caddy
   ```
4. Send users the **version and the full SHA-256** through a channel other
   than this server, and the download link; they verify and install from the
   file (`ios/README.md`, Option A, step 5). `apps.json` is there for
   SideStore's update notice only — users are told not to install from it.
   Publish only the current version's hash, so an old IPA cannot pass.

Keep old IPAs out of the directory once a new one is published — `apps.json`
lists one version, and a stale file is just attack surface. The Onion does not
serve `/ios/` (Tor forwards straight to the relay); SideStore has no Tor.

**Publish the SHA-256 somewhere other than this server** (e.g. in the chat
where you hand out the address), and take it from the GitHub release notes —
the release job recomputes it from the IPA — not from files on the box.
Whoever controls `/srv/secure-chat-ios/` can replace the IPA *and* `apps.json`
together, including the `sha256` SideStore checks; only users hashing the file
they downloaded and comparing with your second channel catches that
(`ios/README.md`, Option A, step 5).
