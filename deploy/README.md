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

Unset, `client_key()` trusts nobody and every limiter keys on one shared
bucket. It **fails closed**. Measured on the live onion (16 parallel lookups,
`LOOKUP_RATE_CAPACITY = 10`):

| `X-Forwarded-For` | allowed | rate-limited |
|---|---|---|
| rotating (16 distinct values) | 10 | 6 |
| fixed (1 value) | 10 | 6 |

Identical, and exactly the bucket capacity — forging the header buys nothing.
Were it honoured, the rotating run would have scored 16/16.

**Accepted trade-off:** the clearnet side loses per-IP rate limiting too, and
shares that one global bucket with the onion. A single clearnet abuser can
therefore throttle onboarding for everyone. `config.py` already sizes
`REGISTER_RATE_*` for exactly this ("behind Tor the keying collapses to ONE
GLOBAL bucket"). Tor's proof-of-work defence (`HiddenServicePoWDefensesEnabled`)
is on partly to blunt the volume attack this invites.

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
cat deploy/torrc.secure-chat >> /etc/tor/torrc
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
Origin is still refused (403)**, and payloads relay both ways.

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
