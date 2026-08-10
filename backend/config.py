"""Central configuration and hard security limits.

Every value here exists to bound resource usage and shrink the attack
surface. Keep this file tiny and obvious so it can be audited at a glance.
Changing a limit is a security-relevant decision.
"""
from __future__ import annotations

import os
import re

# --- Network / app ---------------------------------------------------------
# Loopback only for local testing. Production (.onion) binding is configured
# separately at deploy time; the app should never be exposed directly to a
# public interface without a hardened reverse proxy / Tor in front of it.
HOST = "127.0.0.1"
PORT = 8000

# --- Message / envelope limits --------------------------------------------
# Maximum size (in bytes) of a single inbound WebSocket text frame. Anything
# larger is rejected and the connection is closed. Bounds per-message memory
# and blocks trivial memory-exhaustion DoS.
MAX_FRAME_BYTES = 64 * 1024  # 64 KiB

# Maximum length of the base64 payload string (ciphertext / key material).
MAX_PAYLOAD_CHARS = 48 * 1024  # ~48 KiB base64 (~36 KiB binary)

# Room id: fixed-length, high-entropy, lowercase hex only. 64 hex chars = 256
# bits of entropy, making room ids effectively unguessable.
ROOM_ID_LENGTH = 64

# Maximum simultaneous ADMITTED members in one room.
MAX_ROOM_MEMBERS = 2  # pairwise chat for now; raise later for group chat

# Maximum sockets WAITING for the room owner's approval at once (pentest
# 2026-07-26 P-08). Waiting does NOT consume a member slot — that separation is
# the actual fix: knowing a room id no longer lets anyone occupy the room, only
# ask to be let in. The cap bounds the queue an owner can be shown (and the
# memory a knocker can cost). Past it a newcomer displaces the oldest waiter
# that has not introduced itself, and only if there is none is the join refused
# — see KNOCK_TIMEOUT_SEC and RoomRegistry.join.
MAX_ROOM_PENDING = 4

# Length (hex chars) of the server-issued join id naming one waiting socket in
# an admit/deny. 16 hex = 64 bits from os.urandom: not a secret (it never
# authorizes anything on its own — the server also checks that the sender IS the
# room owner), but unguessable so one waiting peer cannot name another's slot.
JOIN_ID_LENGTH = 16

# Maximum concurrent rooms server-wide (bounds total memory).
MAX_ROOMS = 1000

# --- Rate limiting (token bucket, per connection) -------------------------
RATE_BUCKET_CAPACITY = 20  # burst allowance (messages)
RATE_REFILL_PER_SEC = 5.0  # sustained messages/second

# --- Connection-level abuse / DoS bounds ----------------------------------
# Hard ceiling on concurrent WebSocket connections, server-wide. Bounds file
# descriptors and per-connection memory so a flood of idle sockets cannot
# exhaust the host. New connections past the cap are refused at the handshake.
MAX_CONNECTIONS = 200

# Idle read timeout (seconds). A connection that sends no frame within this
# window is closed. This reaps half-open / zombie sockets. It is intentionally
# generous so a quiet but active chat (two people reading) is not dropped;
# clients can reconnect transparently.
# NOTE: no per-connection lifetime frame cap is enforced — the token bucket
# already bounds throughput, and a lifetime cap would penalise long sessions.
IDLE_TIMEOUT_SEC = 900  # 15 minutes

# Join deadline (seconds). A connection that has not sent a valid `join` within
# this short window is closed. Distinct from IDLE_TIMEOUT_SEC: a pre-join socket
# holds a connection slot while contributing nothing, so squatters are dropped
# fast (whereas a joined, idle-but-reading peer gets the generous idle window).
JOIN_TIMEOUT_SEC = 30

# Approval deadline (seconds). A socket that has INTRODUCED itself (knocked) is
# dropped if the owner has not decided within this window. Long enough that a
# human can look at the approval prompt and choose.
PENDING_TIMEOUT_SEC = 120

# Introduction deadline (seconds). A socket that is queued but has not knocked
# is waiting for nobody: the owner has not even been told it exists, so it
# cannot be denied. Post-fix review of P-08 showed that MAX_ROOM_PENDING silent
# sockets therefore re-created the original lockout — invisibly, and for the
# full approval window. A queue place must be *held* only by something the owner
# can see and refuse, so an un-knocked socket gets seconds, not minutes (and is
# also the first thing evicted when the queue is under pressure).
KNOCK_TIMEOUT_SEC = 10

# Grace before a waiter may be displaced (seconds). Displacement was added to
# stop silent squatters holding the queue, but it is a primitive that can be
# AIMED: every honest peer is briefly un-knocked too — between being told
# `pending` and its knock landing — and an attacker holding the rest of the
# queue could fire a join in exactly that window to evict the invited peer
# before it could introduce itself. One round trip is milliseconds on loopback
# but hundreds over an .onion, so the window is real. A waiter younger than this
# is never displaced; if nothing else is displaceable the newcomer is refused
# instead. Comfortably longer than a knock round trip, far shorter than the
# 120 s a knocked waiter may hold.
KNOCK_GRACE_SEC = 2.0

# Pentest 2026-07-27 M-1: how often a room's owner may be told that joins are
# being refused ("room full"). One notice per window, carrying the count since
# the last one — so a queue-filling attacker cannot turn the warning into a
# per-attempt frame flood at the owner, and the owner still learns promptly that
# somebody is being locked out.
TURNAWAY_NOTICE_SEC = 5.0

# --- Trusted reverse proxies (rate-limit keying) --------------------------
# Pentest 2026-07-25 F-03: every /api limiter keys on the client address. When
# the app is reached DIRECTLY over loopback — which is exactly what a Tor
# onion service does — uvicorn's proxy-header middleware would trust the
# client's own X-Forwarded-For, so rotating that header handed out a fresh
# rate-limit bucket per request and defeated the anti-enumeration lookup
# limiter, the challenge limiter and the mailbox limiter at once.
#
# We therefore run uvicorn with --no-proxy-headers and resolve the address
# ourselves (see accounts.client_key), trusting X-Forwarded-For ONLY when the
# immediate peer is a proxy the operator explicitly listed here. Default: trust
# nobody, so a misconfigured deployment fails CLOSED (one shared bucket) rather
# than open (unlimited buckets).
#
# DO NOT set SECURE_CHAT_TRUSTED_PROXIES=127.0.0.1. Pentest 2026-08-07
# F-RELAY-001: this file used to recommend exactly that "when running behind
# the Caddy reverse proxy", and on the shipped topology that recommendation
# reopens F-03.
#
# `deploy/Caddyfile` proxies to 127.0.0.1:8000 and `deploy/torrc.secure-chat`
# forwards the onion service to the SAME socket (`HiddenServicePort 80
# 127.0.0.1:8000`). Caddy appends the real client address as the rightmost
# X-Forwarded-For hop, which is why trusting the rightmost hop is sound for
# Caddy — but Tor is a raw TCP forward that neither sanitises nor appends
# anything, and both arrive as the identical loopback peer. Trusting the IP
# 127.0.0.1 therefore trusts Tor's visitors as if they were Caddy: an onion
# visitor sets any X-Forwarded-For it likes and mints a fresh, uncontended
# bucket per request, defeating the anti-enumeration lookup limiter, the
# challenge limiter, the registration limiter and both mailbox limiters at
# once. Measured on a loopback relay: 25 challenge POSTs with a rotating header
# gave 25x 200 / 0x 429 with the variable set, versus 10x 200 / 15x 429 without.
#
# `deploy/secure-chat.service` leaves it unset and `deploy/README.md` says so;
# this file is now consistent with both. An operator who genuinely needs
# X-Forwarded-For must first make the trusted front end distinguishable from a
# raw TCP forward — bind Caddy and Tor to DIFFERENT loopback ports and trust
# only Caddy's, or have Caddy inject a shared secret header Tor cannot supply.
# Trusting a bare IP that two different front ends share is the bug.
TRUSTED_PROXY_IPS = frozenset(
    p.strip() for p in os.environ.get("SECURE_CHAT_TRUSTED_PROXIES", "").split(",") if p.strip()
)

# --- HTTP /api abuse bounds (account directory) ---------------------------
# The /ws relay has its own token bucket; the HTTP account endpoints need their
# own. Keyed per client host — behind Tor every request appears from loopback,
# so this collapses to a single global throttle, which is exactly the meaningful
# control there. Generous enough for normal register/login bursts.
API_RATE_CAPACITY = 60        # burst allowance (requests)
API_RATE_REFILL_PER_SEC = 5.0 # sustained requests/second

# Dedicated, stricter bucket for the login CHALLENGE endpoint (M-03). A
# challenge is cheap for us but seeds pending state, so cap the mint rate well
# below the general /api limiter.
#
# Pentest 2026-08-07 F-RELAY-003: keyed per client host, this was one global
# bucket behind Tor, so any unauthenticated visitor could hold it empty and deny
# login to every account on the relay. It is now keyed per USERNAME (see
# accounts.py), which is the only fairness axis available when every request
# shares one loopback address.
#
# Pentest 2026-08-08 item 19, and the refill is 2.0 rather than the original 0.5
# because of it. The reasoning is counter-intuitive, so it is written down.
#
# Every challenge request is charged to the GLOBAL bucket below BEFORE this
# per-username one is consulted, so an attacker's total spend is capped at
# CHALLENGE_GLOBAL_RATE_REFILL_PER_SEC no matter how they aim it. Holding one
# victim's bucket empty costs this refill rate. So:
#
#     simultaneous victims = CHALLENGE_GLOBAL_RATE_REFILL_PER_SEC
#                          / CHALLENGE_RATE_REFILL_PER_SEC
#
# At the original 0.5/s that was 4/0.5 = EIGHT accounts one unauthenticated
# visitor could silence at once. At 2.0/s it is two. Making this bucket LOOSER
# shrinks the attacker's reach, because the binding constraint on them is the
# global ceiling, not this one.
#
# It costs honest users nothing: a client mints one or two challenges per login
# and logs in about once an hour, and the client's own `autoLogin` backoff caps
# retries at one per 12 s even when it is failing. There is no legitimate caller
# anywhere near 2/s for a single account.
#
# Do not "tighten" this back without redoing that division — a lower number here
# looks stricter and is strictly worse. `test_rate_limit_invariants.py` pins the
# ratio so the mistake fails a test instead of shipping.
CHALLENGE_RATE_CAPACITY = 10        # burst allowance (challenges per username)
CHALLENGE_RATE_REFILL_PER_SEC = 2.0 # sustained challenges/second per username

# The global ceiling that used to be implicit in the shared bucket (F-RELAY-003).
# Sized so honest traffic never meets it — a real user logging in spends 1-2
# challenges — while an attacker draining accounts one at a time still hits a
# wall well before they can cover a directory. Keyed per client host, i.e. one
# bucket behind Tor, which is correct for an absolute capacity limit.
CHALLENGE_GLOBAL_RATE_CAPACITY = 120        # burst allowance (challenges, all accounts)
CHALLENGE_GLOBAL_RATE_REFILL_PER_SEC = 4.0  # sustained challenges/second, all accounts

# Dedicated bucket for REGISTRATION (pentest 2026-07-26 P-09). Registration is
# the one endpoint that must distinguish a taken username (409) from a free one
# (200), so it is an existence oracle for the namespace — inherent to unique
# first-come-first-served names. On the general 5/s bucket a wordlist could be
# walked at 5 names/second; this throttles it to ~1 name every 2 s. It gets its
# OWN bucket rather than sharing the challenge one so that a registration flood
# cannot throttle legitimate logins (or vice versa).
# Deliberately more generous than the lookup/challenge buckets: behind Tor the
# keying collapses to ONE GLOBAL bucket, so an over-tight limit here would let
# anyone hold the whole service's onboarding shut. Rate limiting cannot remove an
# oracle that is inherent to unique names — it only slows probing (5/s -> 1/s) —
# so it is not worth trading registration availability for a bigger slowdown.
REGISTER_RATE_CAPACITY = 20        # burst allowance (registrations)
REGISTER_RATE_REFILL_PER_SEC = 1.0 # sustained registrations/second

# Hard caps so a flood cannot exhaust memory/disk even within TTL windows.
MAX_ACCOUNTS = 100_000           # total rows in the directory
MAX_PENDING_CHALLENGES = 10_000  # outstanding login challenges
MAX_ACTIVE_TOKENS = 50_000       # outstanding session tokens

# Sessions ONE account may hold at once (pentest 2026-07-29 L-4, corrected by
# the M-C fix review). Not 1: pollMailbox re-authenticates on a 401 every 6 s, so
# one-session-per-account made two tabs of the same account revoke each other in
# a loop and drain the global challenge bucket. Not unbounded either, or a leaked
# token lives out its full TTL beside the real one. Room for a laptop, a phone
# and a couple of tabs; the oldest is evicted past that, and /auth/logout is the
# on-demand remedy.
MAX_SESSIONS_PER_ACCOUNT = 5

# --- Static web client -----------------------------------------------------
# Served same-origin so the page, the WebSocket, and the (future) .onion all
# share one origin. Set to None to run as a pure relay with no static files.
CLIENT_DIR = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "client"))

# Origin of the Android app's bundled web client. The app serves the exact same
# client from a local secure origin (WebViewAssetLoader) and reaches this relay
# cross-origin, so its Origin must be allow-listed for both the WS handshake and
# CORS below. The app pins this via WebViewAssetLoader.setDomain(), so it is an
# app-specific virtual origin — NOT androidx.webkit's shared DEFAULT_DOMAIN
# ("appassets.androidplatform.net"), which any default WebViewAssetLoader app
# would also present. It is a single fixed value, not a wildcard. Note that CORS
# and the WS Origin check only bind browser/WebView-enforced requests; native
# code can always reach /api directly, and /api is designed to expose nothing
# sensitive to an unauthenticated caller (token-gated lookup, no existence
# oracles), so this allow-list is a defense-in-depth boundary, not the trust root.
APP_WEBVIEW_ORIGIN = "https://secure-chat.internal"

# --- WebSocket origin allow-list (CSWSH protection) -----------------------
# Browsers send an Origin header on the WS handshake. We reject any *present*
# origin not in this set, which blocks Cross-Site WebSocket Hijacking. A
# missing Origin (native app / CLI client) is allowed through. Add the .onion
# origin here at deploy time.
# Extra origins can be added at deploy time WITHOUT editing this file, via
# SECURE_CHAT_EXTRA_ORIGINS (comma-separated) — e.g. the production .onion
# origin. They are added to both the WS allow-list and the HTTP CORS list.
# Pentest 2026-07-26 P-15: these values land in BOTH the CORS allow-list and the
# WS origin allow-list. CORSMiddleware treats a literal "*" as a wildcard, so one
# typo or copy-paste at deploy time would open /api to every origin — in a file
# whose stated purpose is to fail closed. Accept only well-formed scheme://host
# [:port] origins and drop anything else (a malformed entry is a deploy mistake;
# silently trusting it is the one outcome we must avoid).
_ORIGIN_RE = re.compile(r"^(https?|wss?)://[A-Za-z0-9.\-]+(:\d{1,5})?$")


def _valid_origins(raw: str) -> list[str]:
    """Parse SECURE_CHAT_EXTRA_ORIGINS into a list of exact origins.

    A trailing slash is the one malformation we normalize rather than reject:
    `https://x.onion/` is what a browser address bar shows and what an operator
    will paste, it is unambiguous, and an exception here takes the whole relay
    down at import (uvicorn cannot load the app) — a startup DoS is a worse
    outcome than quietly accepting an obvious typo. Anything genuinely ambiguous
    still raises, because silently DROPPING an entry would leave the operator
    with a relay their .onion cannot reach and no explanation.
    """
    out = []
    for o in (p.strip() for p in raw.split(",")):
        if not o:
            continue
        o = o.rstrip("/")
        if not _ORIGIN_RE.match(o):
            raise ValueError(
                f"SECURE_CHAT_EXTRA_ORIGINS contains an invalid origin: {o!r} "
                "(expected e.g. https://example.onion or http://127.0.0.1:8000)"
            )
        out.append(o)
    return out


_EXTRA_ORIGINS = _valid_origins(os.environ.get("SECURE_CHAT_EXTRA_ORIGINS", ""))

ALLOWED_WS_ORIGINS = {
    "http://127.0.0.1:8000",
    "http://localhost:8000",
    APP_WEBVIEW_ORIGIN,
    *_EXTRA_ORIGINS,
}

# Cross-origin allow-list for the HTTP /api account directory. Empty for the
# same-origin web client; the Android app's fixed origin is included so its
# (optional) directory lookups work cross-origin. The relay endpoints carry no
# cookies / ambient credentials (auth is an explicit Bearer token), so exposing
# them to this single extra origin discloses only what /api already returns:
# public keys, gated by the per-account lookup token and the rate limiter.
ALLOWED_HTTP_ORIGINS = [
    APP_WEBVIEW_ORIGIN,
    *_EXTRA_ORIGINS,
]

# --- Accounts (passwordless, key-based) -----------------------------------
# The server stores ONLY public identity keys (Ed25519 + ML-DSA-65) keyed by
# username. It never stores passwords, private keys, or plaintext. Login proves
# control of the account by signing a server challenge with the Ed25519 key.
DB_PATH = os.environ.get(
    "SECURE_CHAT_DB", os.path.join(os.path.dirname(__file__), "accounts.db")
)
USERNAME_MIN = 3
USERNAME_MAX = 32

# Fixed key/sig sizes we accept (reject anything else outright).
ED25519_PUB_BYTES = 32
ED25519_SIG_BYTES = 64
MLDSA65_PUB_BYTES = 1952
MLDSA65_SIG_BYTES = 3309     # ML-DSA-65 (Dilithium) signature length
# Bundle v2 encryption keys (async sealed envelope). The server stores them
# and binds them via the dual registration signature; it cannot (and need not)
# verify possession — an unusable key only breaks the registrant's own inbox.
ECDH_PUB_BYTES = 65          # P-256 uncompressed point
MLKEM768_PUB_BYTES = 1184    # ML-KEM-768 encapsulation key

CHALLENGE_TTL_SEC = 120      # login challenge lifetime
TOKEN_TTL_SEC = 3600         # issued session-token lifetime

# --- Mailbox (store-and-forward for sealed messages) -----------------------
# The server stores ONLY (recipient, opaque envelope, arrival time). The
# sender is sealed INSIDE the envelope; the server never learns it. Posting is
# gated by the recipient's lookup token (spam needs the handle, and the
# endpoint is not an existence oracle); fetching requires the recipient's
# session token and DELETES what it returns. Everything is bounded.
MAX_ENVELOPE_BYTES = 64 * 1024        # one sealed envelope (matches WS frame cap)
MAX_MAILBOX_PER_RECIPIENT = 200       # queued envelopes per inbox
MAX_MAILBOX_TOTAL = 100_000           # queued envelopes server-wide
MAILBOX_TTL_SEC = 14 * 24 * 3600      # unfetched mail expires
# Pentest 2026-08-07 F-RELAY-004: this bucket was keyed per host (one global
# bucket behind Tor) and charged BEFORE the lookup-token gate, so unauthenticated
# posts to a nonexistent recipient drained mail delivery for everyone. It is now
# keyed per RECIPIENT and charged after the token check (see mailbox.py).
MAILBOX_RATE_CAPACITY = 30            # burst posts per recipient inbox
MAILBOX_RATE_REFILL_PER_SEC = 1.0     # sustained posts/second per recipient inbox

# The absolute ceiling that used to be implicit in the shared bucket. Keyed per
# host, so one bucket behind Tor — deliberate, since this is the "how much
# mailbox POST traffic will this relay accept at all" limit. Generous enough
# that honest senders never meet it.
MAILBOX_GLOBAL_RATE_CAPACITY = 300        # burst posts, all recipients
MAILBOX_GLOBAL_RATE_REFILL_PER_SEC = 10.0 # sustained posts/second, all recipients

# Dedicated bucket for FETCHING mail (pentest 2026-07-26 P-11). GET used to have
# no limiter at all; putting it on the shared /api bucket closed that but created
# a worse problem — clients poll every 6 s, and behind Tor every client shares one
# bucket, so ~30 concurrent users would have exhausted the general 5/s budget and
# starved registration/lookup for everyone. This bucket is sized for polling
# (~180 concurrent pollers) while still bounding a flood, and it cannot starve
# the other endpoints because it is separate.
MAILBOX_FETCH_RATE_CAPACITY = 120     # burst fetches
MAILBOX_FETCH_RATE_REFILL_PER_SEC = 30.0  # sustained fetches/second

# --- Web-of-trust vouches --------------------------------------------------
# A vouch is a dual-signed public statement "voucher has verified target's
# bundle". The server verifies both signatures before storing (no junk), but
# is still NOT the trust root: clients recheck every signature against their
# OWN pinned copy of the voucher's keys. Bounds only.
MAX_VOUCHES_PER_VOUCHER = 200   # statements one account may publish
MAX_VOUCHES_TOTAL = 200_000     # global table bound
MAX_VOUCHES_RETURNED = 50       # per lookup response

# --- Anti-enumeration: token-gated lookup (I1) ----------------------------
# Registration mints a random, unguessable lookup token. A contact fetches a
# bundle by username AND token (the shareable handle is `username#token`), so
# guessing a username without the token yields an indistinguishable 404 — the
# username namespace is not enumerable. 18 bytes = 24 base64url chars (~144
# bits), far beyond brute force under the lookup rate limit below.
LOOKUP_TOKEN_BYTES = 18

# The public bundle lookup is the one endpoint whose existence answer is
# security-relevant, so it gets its own, stricter per-host token bucket on top
# of the shared /api limiter. Behind Tor this collapses to a single global
# throttle (see KeyedRateLimiter), which is the meaningful control there.
LOOKUP_RATE_CAPACITY = 10        # burst allowance (lookups)
LOOKUP_RATE_REFILL_PER_SEC = 0.5 # sustained lookups/second
