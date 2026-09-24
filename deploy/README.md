# Deployment

The files here are **copies of what is actually running** on the test box
(pulled from it, not written from memory), so a re-provision reproduces the
live setup instead of approximating it.

| file | goes to | purpose |
|---|---|---|
| `secure-chat.service` | `/etc/systemd/system/` | the relay unit (uvicorn, loopback only) |
| `torrc.secure-chat` | appended to `/etc/tor/torrc` | the v3 onion service |
| `Caddyfile` | `/etc/caddy/` | clearnet TLS front end |

Layout on the box: `/opt/secure-chat/{backend,client,venv}`, running as the
no-login system user `securechat`.

## The one rule

**uvicorn binds `127.0.0.1` and is never exposed on a public interface.**
Everything reaches it over loopback — Caddy for clearnet, Tor for the onion.
Check it after any change:

```bash
ss -ltnp | grep 8000        # must show 127.0.0.1:8000, never 0.0.0.0 or *
```

## Two front ends, one process

Caddy and Tor both proxy to the *same* `127.0.0.1:8000`. That is deliberate:
rooms, session tokens, and login challenges live in **process memory**, so a
second instance would split-brain them — two people who picked the same room id
would land in different rooms, one per front end, and never see each other.

The cost of sharing is the rate-limit keying below.

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

## iOS app downloads (SideStore / AltStore)

> **Not yet on the box.** The `/ios/` block in `Caddyfile` was added with the
> iOS distribution and has not been deployed; until it is, the file in this
> directory is ahead of the live one.

The relay's clearnet host also serves the iOS download bundle, as static files,
under `https://<host>/ios/`. The repository is private, so GitHub release
assets are not a public download — this server is the distribution point.

1. Bump `MARKETING_VERSION` / `CURRENT_PROJECT_VERSION` in `ios/project.yml`,
   merge, then tag: `git tag ios-v0.3.0 && git push origin ios-v0.3.0`.
2. The iOS workflow builds the unsigned IPA and a release `ios-v0.3.0` with four
   files: `SecureChat-0.3.0.ipa`, `SecureChat-0.3.0.ipa.sha256`, `apps.json`,
   `icon.png`. `apps.json` points at `https://138-199-144-35.sslip.io/ios`
   unless the repository variable `IOS_DIST_BASE_URL` says otherwise.
3. Copy them to the box:
   ```bash
   sudo mkdir -p /srv/secure-chat-ios
   sha256sum -c SecureChat-0.3.0.ipa.sha256        # before copying
   sudo cp SecureChat-0.3.0.ipa SecureChat-0.3.0.ipa.sha256 apps.json icon.png /srv/secure-chat-ios/
   sudo chown -R root:root /srv/secure-chat-ios && sudo chmod 644 /srv/secure-chat-ios/*
   sudo systemctl reload caddy
   ```
4. Users add `https://<host>/ios/apps.json` as a source in SideStore
   (`ios/README.md`, "Getting it onto an iPhone").

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
