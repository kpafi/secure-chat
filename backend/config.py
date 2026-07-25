"""Central configuration and hard security limits.

Every value here exists to bound resource usage and shrink the attack
surface. Keep this file tiny and obvious so it can be audited at a glance.
Changing a limit is a security-relevant decision.
"""
from __future__ import annotations

import os

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

# Maximum simultaneous members in one room.
MAX_ROOM_MEMBERS = 2  # pairwise chat for now; raise later for group chat

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
# Set SECURE_CHAT_TRUSTED_PROXIES=127.0.0.1 when running behind the Caddy
# reverse proxy. Leave it UNSET for a direct/.onion deployment.
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
# below the general /api limiter. Keyed per client host (one global bucket
# behind Tor, which is the meaningful control there).
CHALLENGE_RATE_CAPACITY = 10        # burst allowance (challenges)
CHALLENGE_RATE_REFILL_PER_SEC = 0.5 # sustained challenges/second

# Hard caps so a flood cannot exhaust memory/disk even within TTL windows.
MAX_ACCOUNTS = 100_000           # total rows in the directory
MAX_PENDING_CHALLENGES = 10_000  # outstanding login challenges
MAX_ACTIVE_TOKENS = 50_000       # outstanding session tokens

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
_EXTRA_ORIGINS = [o.strip() for o in os.environ.get("SECURE_CHAT_EXTRA_ORIGINS", "").split(",") if o.strip()]

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
MAILBOX_RATE_CAPACITY = 30            # burst posts per host
MAILBOX_RATE_REFILL_PER_SEC = 1.0     # sustained posts/second per host

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
