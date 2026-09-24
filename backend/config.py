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
# Set SECURE_CHAT_TRUSTED_PROXIES=127.0.0.1 ONLY when the listed peer can be
# nothing but the Caddy reverse proxy. Pentest 2026-08-07 F-RELAY-001: the
# production box also publishes a Tor onion service that forwards to the SAME
# loopback port, so there loopback does not mean "came through Caddy" and
# trusting it would let any onion visitor forge its bucket. It must stay UNSET
# in that topology (see deploy/README.md and deploy/secure-chat.service).
TRUSTED_PROXY_IPS = frozenset(
    p.strip() for p in os.environ.get("SECURE_CHAT_TRUSTED_PROXIES", "").split(",") if p.strip()
)
# Phase-7 pentest 2026-09-16 F-P7-13 (ported from phase7-local 4b9d2c6): the
# paragraph above was the whole control — with 127.0.0.1 in the set the port-0
# detector is never consulted, so every limiter was silently defeatable via
# X-Forwarded-For and nothing at runtime said so. A loopback proxy IP cannot be
# told apart from Tor's raw forward on the shipped topology, so it is refused
# at startup unless the operator states they have separated the two
# (different ports, or a secret header) with
# SECURE_CHAT_TRUSTED_PROXIES_ALLOW_LOOPBACK=1.
_LOOPBACK_PROXIES = {
    ip for ip in TRUSTED_PROXY_IPS
    if ip in ("localhost", "::1", "0:0:0:0:0:0:0:1") or ip.startswith("127.") or ip.startswith("::ffff:127.")
}
if _LOOPBACK_PROXIES and os.environ.get("SECURE_CHAT_TRUSTED_PROXIES_ALLOW_LOOPBACK") != "1":
    raise RuntimeError(
        f"SECURE_CHAT_TRUSTED_PROXIES contains a loopback address {sorted(_LOOPBACK_PROXIES)}: on the shipped "
        "topology Caddy and Tor share 127.0.0.1:8000, so trusting it lets any onion visitor forge its "
        "rate-limit bucket (F-RELAY-001). Separate the two front ends first, then set "
        "SECURE_CHAT_TRUSTED_PROXIES_ALLOW_LOOPBACK=1 to state that you have."
    )

# --- HTTP /api abuse bounds (account directory) ---------------------------
# The /ws relay has its own token bucket; the HTTP account endpoints need their
# own. Keyed per client host — behind Tor every request appears from loopback
# (and on the shipped clearnet path no proxy is trusted, so there too), which
# collapses this to ONE bucket for the whole relay.
#
# ACCEPTED service-wide limit, stated honestly (F-RELAY-003 residual, 2026-07-29
# M-2): anyone, with no account, can hold this bucket empty with
# API_RATE_REFILL_PER_SEC junk requests, and while they do, every route ON it
# answers 429 for everybody: handle lookups (GET /users/{u}, /vouches), POST
# and DELETE /vouch, /me and /auth/logout. Behind Tor client_key carries no
# information to key on, so no tuning of this bucket can fix that; it is a
# ceiling against runaway clients, not a fairness control. What was changed is
# its REACH: login (challenge + verify) and registration are no longer on it
# (accounts.auth_router), because they have dedicated buckets, so junk on the
# directory routes cannot lock anyone out of logging in or registering. The
# mailbox has its own buckets and was never on it. Every per-subject control
# (lookup per target, vouch per voucher, fetch per user, post per recipient)
# is charged AFTER its gate and cannot be drained without the gate's secret.
API_RATE_CAPACITY = 60        # burst allowance (requests)
API_RATE_REFILL_PER_SEC = 5.0 # sustained requests/second

# Dedicated, stricter bucket for the login CHALLENGE endpoint (M-03). A
# challenge is cheap for us but seeds pending state, so cap the mint rate well
# below the general /api limiter.
#
# Pentest 2026-08-07 F-RELAY-003: this used to be ONE bucket keyed per client
# host, which behind Tor (and since the M-1 fix, on the shared clearnet path
# too) is one bucket for the whole relay — so a single unauthenticated client
# sending 0.5 challenges/s held login shut for EVERY account. It is now two
# buckets: a strict one keyed on the USERNAME being logged into, and a much
# wider per-host one that only bounds total pending-challenge churn. A flood
# now has to reach the wide bucket's rate to lock everyone out, and a
# targeted flood on one name locks out only that name (the attacker could
# already do that before, via the shared bucket — the blast radius shrank,
# it did not grow). Pending state itself is bounded by MAX_PENDING_CHALLENGES.
#
# Pentest 2026-08-08 item 19 (ported from phase7-local 40d132e; accepted, but
# hardened): the per-username bucket IS a targeted, unauthenticated login
# lockout — for an attacker whose goal is to silence one person, "denies that
# one account" is the objective, not a rounding error. What it costs the
# victim: nothing until their session token expires (TOKEN_TTL_SEC); live rooms
# never touch the account API; after that sealed mail stops arriving (the
# client retries autoLogin on a capped backoff and recovers once the flood
# stops). Closing it needs proof-of-work or an authenticated pre-token — a
# design change — so it is accepted; what is bounded here is the REACH.
#
# The per-HOST bucket is charged FIRST (accounts.challenge_rate_limit), so a
# client's total spend is capped at CHALLENGE_HOST_RATE_REFILL_PER_SEC however
# it is aimed, and holding one victim's bucket empty costs
# CHALLENGE_RATE_REFILL_PER_SEC. So
#
#     simultaneous victims = CHALLENGE_HOST_RATE_REFILL_PER_SEC
#                          / CHALLENGE_RATE_REFILL_PER_SEC = 20 / 2 = 10
#
# At the old 0.5/s it was 40. Making the per-username bucket LOOSER shrinks the
# attacker's reach, because the binding constraint on them is the host ceiling.
# It costs honest users nothing: a login spends one or two challenges and
# autoLogin's backoff retries far slower than 2/s. Do not "tighten" it back
# without redoing the division — and do not satisfy the ratio by lowering the
# host ceiling either: that is the service-wide login DoS threshold (20
# junk challenges/s behind Tor deny every login; accepted, see API_RATE_*).
# tests/test_rate_limit_invariants.py pins both directions.
CHALLENGE_RATE_CAPACITY = 10        # burst allowance per USERNAME (challenges)
CHALLENGE_RATE_REFILL_PER_SEC = 2.0 # sustained challenges/second per username
CHALLENGE_HOST_RATE_CAPACITY = 200        # burst allowance per host, all names
CHALLENGE_HOST_RATE_REFILL_PER_SEC = 20.0 # sustained challenges/second per host

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

# --- Release version ---------------------------------------------------------
# Reported by /healthz so "which build is running" is answered by one curl,
# not by diffing files over ssh. Bump with the git tag (vX.Y.Z on master).
VERSION = "0.3.1"

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

# Origin of the iOS app's bundled web client. WKWebView cannot serve local
# content under https://, so the iOS shell serves the same bundled client from
# a custom URL scheme (WKURLSchemeHandler, ios/SecureChat/AppSchemeHandler.swift)
# and WebKit sends this scheme://host as the Origin. Same status as the Android
# origin above: a single fixed value, defense in depth, not the trust root —
# any other app could present the same custom scheme. Must match
# AppOrigin.origin in ios/SecureChat/WebShell.swift.
IOS_WEBVIEW_ORIGIN = "secure-chat://app"

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
    IOS_WEBVIEW_ORIGIN,
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
    IOS_WEBVIEW_ORIGIN,
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
# Phase-7 pentest 2026-09-16 F-P7-12: no request body on /api is legitimately
# larger than an envelope plus JSON overhead; a 40 MB body used to be parsed and
# then ECHOED back verbatim inside the 422. main._ApiBodyLimit answers 413 past
# this, on the declared length AND on the bytes actually received (chunked).
MAX_API_BODY_BYTES = 128 * 1024
MAX_MAILBOX_PER_RECIPIENT = 200       # queued envelopes per inbox
# Pentest F-RELAY-008 / Phase-7 F-P7-1 (ported from phase7-local 018652d ->
# 6604d9e): the server-wide cap counted ROWS and a full table was a relay-wide
# 503 "storage full", so ~500 throwaway accounts x 200 one-byte envelopes shut
# off sealed mail for everyone for the 14-day TTL. Now:
#   * envelopes have a realistic MINIMUM size — the only sender, the client's
#     sealed.seal, always carries an ML-KEM-768 ciphertext (1088 B -> 1452
#     base64 chars) plus the ephemeral key, IV and AES-GCM body, so a genuine
#     envelope is well over 1.5 KiB and 256 B refuses nothing real;
#   * each inbox has a hard BYTE share beside its row cap (429, the owner can
#     fetch);
#   * the server-wide budget is BYTES, the row cap only bounds table size (and
#     the cost of the budget query), and when either is full the OLDEST queued
#     mail is EVICTED instead of refusing new mail. Under a sustained flood
#     retention degrades (mail must be fetched sooner) but delivery never
#     stops; with free registration that is the honest limit (mailbox.py).
MIN_ENVELOPE_BYTES = 256
MAX_MAILBOX_TOTAL = 100_000                        # rows server-wide (evict-oldest)
MAX_MAILBOX_TOTAL_BYTES = 256 * 1024 * 1024        # queued bytes server-wide (evict-oldest)
MAX_MAILBOX_PER_RECIPIENT_BYTES = 4 * 1024 * 1024  # queued bytes per inbox (hard, 429)
MAILBOX_TTL_SEC = 14 * 24 * 3600      # unfetched mail expires
# Pentest 2026-08-07 F-RELAY-004: the POST bucket was keyed per host and ran
# BEFORE the recipient-token gate, so an unauthenticated client (no handle, no
# token) drained the one shared bucket and denied mail delivery service-wide.
# It is now keyed per RECIPIENT inbox and consumed only AFTER the token gate:
# a request without the recipient's lookup token is an identical 404 that
# touches no bucket at all, and a flood at one inbox throttles only that inbox.
# (This comment used to say service-wide volume was "bounded by the general
# /api limiter". It was not: the mailbox router was never on that limiter, and
# POST had no pre-gate bound at all. See MAILBOX_POST_HOST_RATE_* below.)
MAILBOX_RATE_CAPACITY = 30            # burst posts per recipient inbox
MAILBOX_RATE_REFILL_PER_SEC = 1.0     # sustained posts/second per inbox

# The one per-host ceiling on mailbox POST, charged BEFORE the token gate
# (ported from phase7-local 6604d9e). Behind Tor this is one bucket for
# everybody, so it is a backstop against runaway clients and nothing more —
# anyone can hold it empty at this rate and deny mail POSTs relay-wide
# (accepted; same class as API_RATE_*). POST-only: GET charges nothing before
# auth, so a POST flood cannot deny fetching.
MAILBOX_POST_HOST_RATE_CAPACITY = 600
MAILBOX_POST_HOST_RATE_REFILL_PER_SEC = 50.0

# Dedicated bucket for FETCHING mail (pentest 2026-07-26 P-11). GET used to have
# no limiter at all; putting it on the shared /api bucket closed that but created
# a worse problem — clients poll every 6 s, and behind Tor every client shares one
# bucket. Phase-7 pentest 2026-09-16 F-P7-2: it is keyed PER AUTHENTICATED USER
# and charged after `current_user` (it was per host, charged before the session
# check — one shared bucket anyone with no account could drain). One account
# polls every 6 s per session and holds at most MAX_SESSIONS_PER_ACCOUNT
# sessions, so ~1/s sustained with a burst of 30 is ample.
MAILBOX_FETCH_RATE_CAPACITY = 30          # burst fetches per user
MAILBOX_FETCH_RATE_REFILL_PER_SEC = 1.0   # sustained fetches/second per user

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
# bits), far beyond brute force under the /api rate limit.
LOOKUP_TOKEN_BYTES = 18

# The public bundle lookup is the one endpoint whose existence answer is
# security-relevant, so it gets its own, stricter bucket on top of the shared
# /api limiter. Phase-7 pentest 2026-09-16 F-P7-3: it is charged AFTER the token
# gate and keyed on the TARGET handle (per authenticated voucher for POST
# /vouch) — it used to be per host, charged before the gate, i.e. one global
# bucket behind Tor that eleven garbage lookups drained. Guessing tokens is
# therefore bounded by the shared /api limiter (5/s relay-wide), which at 144
# bits is still far beyond brute force. See accounts._charge_lookup.
LOOKUP_RATE_CAPACITY = 10        # burst allowance (lookups)
LOOKUP_RATE_REFILL_PER_SEC = 0.5 # sustained lookups/second

# POST /vouch per-host ceiling (6604d9e review L-3): accounts are free, so the
# per-voucher bucket alone scales with throwaway accounts. Charged after the
# session check, so a caller with no session cannot drain it.
VOUCH_HOST_RATE_CAPACITY = 30
VOUCH_HOST_RATE_REFILL_PER_SEC = 1.0
