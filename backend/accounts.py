"""Passwordless, key-based accounts.

The server is a public-key DIRECTORY, not a trust root. It stores only public
identity keys (Ed25519 + ML-DSA-65) keyed by username. Authenticity of those
keys is established by the users IN PERSON (fingerprint / safety number); the
server is assumed untrusted for key authenticity. What the server enforces:

  * registration carries a valid Ed25519 signature binding (username, ed, mldsa)
    -> proves the registrant holds the classical private key (anti-squatting,
    key-binding integrity);
  * login = sign a fresh random server challenge with the Ed25519 key
    -> proves account control without any stored secret.

It never stores passwords, private keys, or message content. A full DB leak
yields only public keys (which are meant to be public) plus lookup tokens
(which merely gate remote fetching of those same public bundles — so leaking
them alongside the bundles they gate discloses nothing extra).

Ownership proof at registration (L1): the registrant signs the bundle with
BOTH identity keys and the server verifies BOTH — Ed25519 via `cryptography`
and ML-DSA-65 via `dilithium-py` — so a bundle cannot be registered with a PQ
public key the registrant does not control. (Authenticity of the keys to a
human still comes from the in-person safety number; this only stops a squatter
binding someone else's PQ key into their own directory entry.)

Anti-enumeration (I1): lookups are gated by a per-account random token
(`username#token` handle), and challenge/verify do not reveal whether a username
exists. See `get_user` / `auth_*`, and `mailbox.post_mail` for the same gate.

  KNOWN EXCEPTION (pentest 2026-07-26 P-09): `register` necessarily answers
  409 "taken" vs 200 "registered", so it IS an existence oracle for the
  username namespace. That is inherent to first-come-first-served unique
  names; it discloses only whether a name is in use — never the bundle, the
  lookup token, or any message — and it is throttled by the strict challenge
  bucket. Do not describe the namespace as strictly non-enumerable.
"""
from __future__ import annotations

import base64
import hmac
import logging
import re
import secrets
import sqlite3
import threading
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from dilithium_py.ml_dsa import ML_DSA_65
from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field

import config
from relay import KeyedRateLimiter

# Per-client-host rate limiter for the HTTP account endpoints. The /ws relay has
# its own; these endpoints would otherwise be an unthrottled flood target.
_api_limiter = KeyedRateLimiter(config.API_RATE_CAPACITY, config.API_RATE_REFILL_PER_SEC)

# A second, stricter bucket dedicated to the bundle lookup — the one endpoint
# whose existence answer is security-relevant (anti-enumeration). Even with a
# valid token, this bounds how fast the namespace can be probed.
_lookup_limiter = KeyedRateLimiter(config.LOOKUP_RATE_CAPACITY, config.LOOKUP_RATE_REFILL_PER_SEC)

# Dedicated, stricter bucket for minting login challenges (M-03).
#
# Pentest 2026-08-07 F-RELAY-003: keyed on `client_key`, which behind Tor is the
# same loopback peer for everybody, so this was ONE GLOBAL bucket — 10 burst,
# 0.5/s sustained — in front of an unauthenticated endpoint. Ten rapid requests
# drained it and one request every two seconds held it empty, after which no
# user anywhere could obtain a challenge, and with no challenge no one can reach
# /auth/verify to get a session token. Login denied service-wide, by any onion
# visitor, at near-zero cost.
#
# The keying has to give per-account fairness, and behind Tor the IP cannot
# provide it. So the tight bucket is keyed on the USERNAME being logged in as:
# draining it denies that one account, and denying everybody now costs one full
# bucket per account rather than one bucket total.
#
# Pentest 2026-08-08 item 19 — the accepted residual, stated properly, because
# the sentence above used to treat "denies that one account" as though it
# settled the matter. It does not: for an attacker whose goal is to silence one
# specific person, denying that one account IS the objective, not a rounding
# error on the way to a service-wide outage. This is a precise, unauthenticated,
# targeted login lockout against any well-formed username, and the victim cannot
# evade it — the bucket is keyed on the name they are known by.
#
# What it costs the victim, measured rather than assumed:
#   * Nothing at all until their current session token expires (TOKEN_TTL_SEC,
#     1 h). Live rooms are unaffected in any case — a room join touches no
#     account API, so live chat keeps working throughout.
#   * After that, sealed/async mail stops arriving. It is NOT silent: the client
#     surfaces "Not signed in to the directory — sealed messages will not
#     arrive" through hint() on the 1st and 4th consecutive failure. It is NOT
#     permanent either: autoLogin keeps retrying on a capped backoff and the
#     victim recovers ~2 s after the attacker stops paying.
#
# What it costs the attacker: CHALLENGE_RATE_REFILL_PER_SEC sustained, per
# victim, forever, from an endpoint that is charged against the global bucket
# first — see the arithmetic at CHALLENGE_RATE_REFILL_PER_SEC in config.py,
# which is why that number was RAISED to 2.0. Two simultaneous victims, not
# eight.
#
# ACCEPTED, deliberately, and here is the alternative that was rejected:
# refunding the charge on a successful verify rewards honest logins but does not
# help the victim, who needs one challenge to REACH verify and is being denied
# exactly that. Closing this properly means making challenge minting cost the
# asker something (proof-of-work) or gating it behind an authenticated
# pre-token; both are design changes, not tuning, and neither is justified by an
# outage whose worst case is delayed async mail with a visible warning.
#
# The service-wide DoS is NOT closed and cannot be by this bucket: 4 req/s
# saturates the global ceiling and denies logins to everyone, because behind Tor
# client_key carries no information to key on. F-RELAY-003 raised that from
# 0.5 req/s to 4 req/s. That is an 8x improvement, not a fix.
#
# This does not weaken anti-enumeration (I1): a bucket is minted for any
# well-formed username whether or not the account exists, so a 429 says only
# "somebody has been asking about this name recently" — a state the asker can
# always produce themselves — and never distinguishes a real account from a
# nonexistent one.
_challenge_limiter = KeyedRateLimiter(config.CHALLENGE_RATE_CAPACITY, config.CHALLENGE_RATE_REFILL_PER_SEC)

# The absolute ceiling that the per-username buckets no longer provide. Keyed
# on `client_key` exactly as before, so the shared-loopback collapse is
# deliberate here: this is the "how much challenge minting will this relay do at
# all" limit, and it is sized so that ordinary use never reaches it while an
# attacker enumerating usernames to drain them one at a time still hits a wall.
_challenge_global_limiter = KeyedRateLimiter(
    config.CHALLENGE_GLOBAL_RATE_CAPACITY, config.CHALLENGE_GLOBAL_RATE_REFILL_PER_SEC
)

# Dedicated bucket for registration (P-09): it is the one namespace-existence
# oracle we cannot remove, so it is throttled like the other sensitive paths —
# but on its own bucket, so registrations and logins cannot starve each other.
_register_limiter = KeyedRateLimiter(config.REGISTER_RATE_CAPACITY, config.REGISTER_RATE_REFILL_PER_SEC)


def client_key(request: Request) -> str:
    """The address every rate limiter is keyed on.

    Pentest 2026-07-25 F-03. `X-Forwarded-For` is attacker-controlled unless a
    trusted proxy rewrote it, so it is honoured ONLY when the immediate peer is
    a proxy the operator listed in SECURE_CHAT_TRUSTED_PROXIES. We take the
    RIGHTMOST entry, which is the one that proxy appended (anything further
    left was supplied by the client and can say whatever it likes).

    With no trusted proxy configured this IGNORES the header completely and
    returns the real peer address. In a direct/.onion deployment every request
    arrives from the same loopback peer, so that is one shared bucket —
    throttled, which is the safe direction — instead of handing out a bucket
    per forged header.

    Requires uvicorn to run with --no-proxy-headers; otherwise its middleware
    rewrites request.client before we ever see it. All three launch paths pass
    it, and `test_service_unit.py` / `test_proxy_headers.py` hold them to it.

    Pentest 2026-07-29 M-1: this function used to ALSO try to detect that
    rewrite per-request, by treating `peer in hops` as proof that uvicorn had
    honoured the header, and collapsing to a constant bucket when it did. That
    was unsound in both directions and was the bug:

      * The predicate is client-controlled. In this deployment `peer` is always
        127.0.0.1, so `X-Forwarded-For: 127.0.0.1` satisfied it on a CORRECTLY
        configured server. The result was TWO buckets the client chose between
        with one header — honest traffic in `'127.0.0.1'`, the attacker alone
        in the constant — so every limiter was 2x and bucket A could be starved
        while bucket B ran uncontended. Exactly the private bucket the design
        says a forged header cannot buy.
      * The same forged header wrote the "proxy headers appear to be TRUSTED"
        warning on a healthy server, burning the only runtime signal for the
        real H-4 condition (L-9).

    So the key is now a pure function of the peer: for any given peer there is
    exactly ONE bucket, whatever the headers say. Detecting the misconfiguration
    is a separate concern, handled below on a signal the client cannot set.
    """
    peer = request.client.host if request.client else "unknown"
    if peer not in config.TRUSTED_PROXY_IPS:
        # Fix review 2026-07-30 (M-B). The M-1 fix removed the forgeable
        # detector, correctly — but it also removed the fail-CLOSED collapse that
        # detector was driving, leaving nothing but a log line. In the one
        # condition H-4 is about (an ASGI server honouring the header while we
        # trust no proxy) `peer` IS attacker-chosen, so returning it hands out a
        # fresh uncontended bucket per forged value: F-03 reopened, with a single
        # once-per-process warning as the only trace.
        #
        # The two are not exclusive. Port 0 has no REMOTE false positives (a
        # connected TCP socket cannot have source port 0, so no header can
        # provoke this), which is exactly why it was safe to base the warning on
        # — and equally safe to base the collapse on. So: warn AND collapse.
        # Rate limiting is then throttled-but-shared in the misconfigured case,
        # which is the safe direction, while a correctly configured server is
        # untouched and L-9 stays closed.
        if _client_addr_was_rewritten(request):
            _warn_proxy_headers_trusted()
            return _UNTRUSTED_FORWARDED_KEY
        return peer
    forwarded = request.headers.get("x-forwarded-for", "")
    hops = [h.strip() for h in forwarded.split(",") if h.strip()]
    return hops[-1] if hops else peer


def _client_addr_was_rewritten(request: Request) -> bool:
    """True if the ASGI server looks like it synthesised `request.client`.

    Replaces the L-9 detector, which inferred the rewrite from `peer in hops` —
    a predicate the client sets itself, so it produced false positives on demand
    and burned the signal (see `client_key`).

    The signal used instead is the PORT, which the client cannot choose:
    uvicorn's ProxyHeadersMiddleware builds the replacement address with
    `_parse_host_port()`, which yields port 0 for the bare-IP forms every real
    proxy emits (`X-Forwarded-For: 1.2.3.4`). A genuine TCP peer never has
    source port 0 — the kernel cannot assign it to a connected socket — so
    port 0 together with a forwarded header means something synthesised that
    address.

    Deliberately one-directional, and that asymmetry is what makes it safe to
    act on rather than merely log:

      * NO false positives. Nothing a remote client can send produces port 0, so
        this cannot be provoked — that is L-9 closed, and it is why `client_key`
        may collapse to the shared bucket here without handing an attacker a way
        to move themselves out of the honest bucket.
      * There ARE false negatives: a forged `X-Forwarded-For: 1.2.3.4:5678`
        keeps its port and stays quiet. So this is defence in depth, NOT the
        control. The control is `--no-proxy-headers` on every launch path, which
        `test_proxy_headers.py` and `test_service_unit.py` hold all three to.

    A unix-socket deployment has `request.client is None` (uvicorn's
    `get_remote_addr` returns None for AF_UNIX), which reads as not-rewritten —
    correct, since there is no header-derived address to be fooled by.
    """
    if not request.headers.get("x-forwarded-for"):
        return False
    client = request.client
    return client is not None and getattr(client, "port", None) == 0

# One shared bucket for every request whose source address we cannot trust — the
# H-4 fail-closed fallback (restored by the M-B fix review). A constant, so the
# misconfigured case is throttled-but-shared rather than a fresh private bucket
# per forged header. Unreachable on a correctly configured server.
_UNTRUSTED_FORWARDED_KEY = "!untrusted-forwarded"

_proxy_warning_lock = threading.Lock()
_proxy_warning_emitted = False


def _warn_proxy_headers_trusted() -> None:
    """Log ONCE that the server is trusting client-supplied forwarded headers.

    Content-free (no address, no path, no timing of a specific user's request)
    so it does not violate I2, and rate-limited to a single line for the process
    lifetime so it cannot itself be used as a log-amplification lever.
    """
    global _proxy_warning_emitted
    if _proxy_warning_emitted:
        return
    with _proxy_warning_lock:
        if _proxy_warning_emitted:
            return
        _proxy_warning_emitted = True
    logging.getLogger("relay").warning(
        "proxy headers appear to be TRUSTED by the ASGI server while no trusted "
        "proxy is configured; rate limiting has fallen back to a single shared "
        "bucket. Relaunch with proxy_headers=False / --no-proxy-headers.",
    )


def rate_limit(request: Request) -> None:
    if not _api_limiter.allow(client_key(request)):
        raise HTTPException(status_code=429, detail="rate limited")


def challenge_rate_limit(request: Request) -> None:
    """The global backstop only — see F-RELAY-003.

    The per-username charge cannot live in a dependency, because the username is
    in the request BODY and dependencies run before it is parsed. It happens in
    `auth_challenge` instead, right after the username is validated.
    """
    if not _challenge_global_limiter.allow(client_key(request)):
        raise HTTPException(status_code=429, detail="rate limited")


# Phase-7 pentest 2026-09-16 F-P7-3: `_lookup_limiter` used to be a dependency
# keyed on the client host and charged before the token gate — eleven
# unauthenticated garbage lookups drained it, and at 1 req / 2 s nobody behind
# Tor could look up a handle (add-by-handle, or a Live room with a handle
# filled in). It is now charged INSIDE each handler, after the token gate, keyed
# on the TARGET (or on the authenticated voucher for POST /vouch): garbage
# without a token spends nothing, and a token holder can only exhaust the one
# handle they hold a token for. The per-host `_api_limiter` on the router is the
# ceiling in front of the gate.
# ACCEPTED, stated at the acceptance level (review of the first fix, L-4): a
# holder of a handle's lookup token can exhaust THAT handle's bucket for every
# other holder — 10 lookups, then 0.5/s to keep it there — and nobody can add
# that one person by handle until they stop. Same trade as `"mail:" + recipient`
# (F-RELAY-004): the harm is bounded to one handle its own owner shared, versus
# the previous per-host bucket, which anyone with no token could drain for
# every handle on the relay.
def _charge_lookup(key: str) -> None:
    if not _lookup_limiter.allow(key):
        raise HTTPException(status_code=429, detail="rate limited")


# POST /vouch is also bounded per HOST: accounts are free, so a per-voucher
# bucket alone scales with throwaway accounts (review of the first fix, L-3).
_vouch_host_limiter = KeyedRateLimiter(config.VOUCH_HOST_RATE_CAPACITY, config.VOUCH_HOST_RATE_REFILL_PER_SEC)


def vouch_host_rate_limit(request: Request) -> None:
    if not _vouch_host_limiter.allow(client_key(request)):
        raise HTTPException(status_code=429, detail="rate limited")


def register_rate_limit(request: Request) -> None:
    if not _register_limiter.allow(client_key(request)):
        raise HTTPException(status_code=429, detail="rate limited")


# All /api routes share the rate-limit dependency.
router = APIRouter(prefix="/api", tags=["accounts"], dependencies=[Depends(rate_limit)])

_USERNAME_RE = re.compile(r"^[a-z0-9_.-]+$")
_B64_RE = re.compile(r"^[A-Za-z0-9+/]*={0,2}$")

# Domain-separated, canonical bytes the client signs at registration. Must be
# reconstructed identically here. Newline-delimited, no ambiguity.
_REGISTER_DOMAIN = b"secure-chat/register/v1"

# Bundle v2: registration additionally carries public ENCRYPTION keys (P-256
# ECDH + ML-KEM-768) for the async sealed envelope, under a bumped domain so
# v1 and v2 registration signatures can never be confused.
_REGISTER_V2_DOMAIN = b"secure-chat/register/v2"

# Bundle v3 (pentest 2026-08-07 F-RELAY-005): the signed message additionally
# carries a monotone counter, so a same-identity re-registration cannot be
# REPLAYED. Without it, every registration a user ever signed stayed valid
# forever, and a hostile relay could resend an older one to roll their published
# encryption keys back to a superseded pair — or, replaying a v1 registration,
# strip them entirely, silently downgrading every future sealed message to an
# account that can no longer receive one.
_REGISTER_V3_DOMAIN = b"secure-chat/register/v3"

# Login challenges are signed under their own domain prefix so a login signature
# can never be mistaken for (or replayed as) a signature of any other protocol
# message. The client prepends the same prefix before signing the raw nonce.
_LOGIN_DOMAIN = b"secure-chat/login/v1"


def _login_message(challenge_raw: bytes) -> bytes:
    return _LOGIN_DOMAIN + b"\n" + challenge_raw


# --- low-level helpers -----------------------------------------------------

def _b64decode_fixed(s: str, n: int) -> bytes:
    """Strictly decode CANONICAL base64 to exactly n bytes, else raise 422.

    Pentest 2026-07-27 H-1 (server half). `validate=True` only rejects
    characters outside the alphabet; like the browser's `atob` it silently
    DISCARDS the trailing slack bits, so four distinct strings decode to the
    same 32-byte Ed25519 key. Every key size here is ≡ 2 (mod 3), so every key
    has four spellings. The signature checks below operate on the decoded
    BYTES, but what this table stores — and hands to the client as the
    directory's answer — is the STRING. Without this check a registrant could
    park a non-canonical spelling of their own key in the directory, and every
    client-side comparison against the live handshake bundle (which the client
    canonicalizes) would report a mismatch: a self-inflicted permanent
    "directory mismatch" the user cannot explain or clear. Canonicalize at the
    boundary so only one spelling per key can ever be stored.
    """
    if not _B64_RE.match(s or ""):
        raise HTTPException(status_code=422, detail="invalid base64")
    try:
        raw = base64.b64decode(s, validate=True)
    except Exception:
        raise HTTPException(status_code=422, detail="invalid base64")
    if len(raw) != n:
        raise HTTPException(status_code=422, detail="unexpected key/sig length")
    if base64.b64encode(raw).decode("ascii") != s:
        raise HTTPException(status_code=422, detail="base64 is not canonical")
    return raw


def token_matches(provided: str, stored: str) -> bool:
    """Constant-time lookup-token comparison that cannot be crashed by input.

    Pentest 2026-07-25 F-04: `hmac.compare_digest` raises TypeError on `str`
    arguments containing non-ASCII, and the provided token comes straight off
    the query string — so `?t=ü` turned the token gate into an unhandled 500
    (plus a traceback written to the journal on demand, against I2). Comparing
    the UTF-8 BYTES accepts any input while keeping the constant-time property.

    Callers must still pass a decoy `stored` for missing users so that a wrong
    token and an unknown user remain indistinguishable (I1).
    """
    return hmac.compare_digest(provided.encode("utf-8"), stored.encode("utf-8"))


def _ed25519_verify(pub_raw: bytes, sig: bytes, msg: bytes) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(pub_raw).verify(sig, msg)
        return True
    except (InvalidSignature, ValueError):
        return False


# Pentest 2026-08-08 item 15: `dilithium_py` is NOT thread-safe in this
# deployment, and every endpoint that verifies an ML-DSA signature is a sync
# `def` — which FastAPI runs in the anyio threadpool (see the note above the
# endpoints). So these calls really are concurrent.
#
# The library prefers `xoflib`, whose `shake256(seed)` returns a FRESH reader per
# call. Without it, it falls back to `dilithium_py/shake/shake_wrapper.py`, whose
# `shake128`/`shake256` are MODULE-LEVEL SINGLETONS carrying mutable state
# (`buf`, `index`, `xof_read`), imported at module scope by both
# `ml_dsa.ml_dsa` and `polynomials.polynomials`. Two threads verifying at once
# interleave `absorb`/`read` on the same object and read each other's keystream.
#
# There is no xoflib in this venv, and the effect is not subtle: 8 threads over
# one VALID signature rejected 153 of 320. It FAILS CLOSED — a corrupted verify
# returns False, never True, so this is a login denial-of-service and never an
# auth bypass — but a login path that rejects half of its valid signatures under
# ordinary concurrency is broken.
#
# Serialising is the fix rather than adding the dependency, because it is
# correct WHATEVER backend is installed. That property is the point: the failure
# mode being closed off here is "someone deploys without xoflib and nothing
# says so". Adopting xoflib later is a fine change, but it is a separate one that
# must come with the concurrency test below (`test_mldsa_verify_concurrent`) run
# against the new backend — do not delete this lock on the strength of a
# requirements pin alone.
#
# Cost, measured, not assumed: one verify is ~15 ms here, so this caps ML-DSA
# verification at ~66/s process-wide. The relay's own throttles sit far below
# that (per-username challenges refill at 0.5/s, the per-host backstop at 4/s),
# and legitimate login traffic for a directory of this size is nowhere near it.
# The lock serialises work that was already CPU-bound; it does not add any.
#
# This is the single call site for `dilithium_py` in the process, so the lock
# here covers every path — `/auth/verify` and `register` both, which also closes
# the same latent bug in `register` (it predates this branch).
_mldsa_lock = threading.Lock()


def _mldsa65_verify(pub_raw: bytes, sig: bytes, msg: bytes) -> bool:
    try:
        with _mldsa_lock:
            return bool(ML_DSA_65.verify(pub_raw, msg, sig))
    except Exception:
        # A malformed key/sig must fail closed, never raise past the handler.
        return False


def _register_message(username: str, ed: str, mldsa: str) -> bytes:
    return b"\n".join(
        [_REGISTER_DOMAIN, username.encode("ascii"), ed.encode("ascii"), mldsa.encode("ascii")]
    )


def _register_message_v2(username: str, ed: str, mldsa: str, ecdh: str, mlkem: str) -> bytes:
    return b"\n".join(
        [_REGISTER_V2_DOMAIN, username.encode("ascii"), ed.encode("ascii"),
         mldsa.encode("ascii"), ecdh.encode("ascii"), mlkem.encode("ascii")]
    )


def _register_message_v3(username: str, ed: str, mldsa: str, ecdh: str, mlkem: str, seq: int) -> bytes:
    return b"\n".join(
        [_REGISTER_V3_DOMAIN, username.encode("ascii"), ed.encode("ascii"),
         mldsa.encode("ascii"), ecdh.encode("ascii"), mlkem.encode("ascii"),
         str(seq).encode("ascii")]
    )


# Web-of-trust vouch: the voucher dual-signs the TARGET's (username, bundle)
# under its own domain, so a vouch can never be confused with a registration
# or login signature. Client builds the identical bytes (account.js).
#
# H-01 (2026-07-19): the v1 vouch covered only the SIGNING keys (ed + mldsa),
# so a malicious directory could pair a genuinely-vouched contact's real
# signing keys with its OWN encryption keys and read sealed messages while the
# 🟡 mark still displayed. v2 folds the target's ENCRYPTION keys (ecdh + mlkem)
# into the signed statement — mirroring the fingerprint/safety-number fix — so
# a vouch now attests all four keys. A target with encryption keys is vouched
# under v2; a legacy target without them (can't receive sealed mail anyway)
# stays v1. The domain differs so a v1 signature can never be read as a v2 one.
_VOUCH_DOMAIN = b"secure-chat/vouch/v1"
_VOUCH_V2_DOMAIN = b"secure-chat/vouch/v2"


# A well-formed but meaningless bundle, used when /vouch's target does not
# exist (M-7). Built once at import so the oracle cannot be re-opened as a
# TIMING one: it is the same size as a real v2 bundle, so `_vouch_message`
# builds the same length of message and both verifications do the same work as
# they would for a real target. Random rather than fixed so it can never
# collide with a genuine registered bundle.
_DECOY_BUNDLE = {
    "ed_pub": base64.b64encode(secrets.token_bytes(config.ED25519_PUB_BYTES)).decode("ascii"),
    "mldsa_pub": base64.b64encode(secrets.token_bytes(config.MLDSA65_PUB_BYTES)).decode("ascii"),
    "ecdh_pub": base64.b64encode(secrets.token_bytes(config.ECDH_PUB_BYTES)).decode("ascii"),
    "mlkem_pub": base64.b64encode(secrets.token_bytes(config.MLKEM768_PUB_BYTES)).decode("ascii"),
}


def _vouch_message(target: str, ed: str, mldsa: str, ecdh: str = "", mlkem: str = "") -> bytes:
    if ecdh and mlkem:
        return b"\n".join(
            [_VOUCH_V2_DOMAIN, target.encode("ascii"), ed.encode("ascii"),
             mldsa.encode("ascii"), ecdh.encode("ascii"), mlkem.encode("ascii")]
        )
    return b"\n".join(
        [_VOUCH_DOMAIN, target.encode("ascii"), ed.encode("ascii"), mldsa.encode("ascii")]
    )


# --- storage ---------------------------------------------------------------

def _db() -> sqlite3.Connection:
    conn = sqlite3.connect(config.DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    # Review of the Phase-7 fixes (L-2): under a flood, overlapping writers hit
    # "database is locked" after sqlite's default 5 s and each one was a 500
    # plus a traceback on disk (an I2 violation, per relay.py's own docstring).
    # Wait longer, and main.py maps what still fails to a bare 503.
    conn.execute("PRAGMA busy_timeout=15000")
    return conn


def init_db() -> None:
    with _db() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS accounts (
                username     TEXT PRIMARY KEY,
                ed_pub       TEXT NOT NULL,
                mldsa_pub    TEXT NOT NULL,
                lookup_token TEXT NOT NULL,
                created_at   INTEGER NOT NULL
            )
            """
        )
        # Migrate pre-token directories: add the column if an older DB lacks it.
        cols = {r["name"] for r in conn.execute("PRAGMA table_info(accounts)")}
        if "lookup_token" not in cols:
            conn.execute("ALTER TABLE accounts ADD COLUMN lookup_token TEXT NOT NULL DEFAULT ''")
        # Bundle v2: public encryption keys (empty for pre-v2 rows; those
        # accounts simply cannot receive sealed messages until re-registered).
        if "ecdh_pub" not in cols:
            conn.execute("ALTER TABLE accounts ADD COLUMN ecdh_pub TEXT NOT NULL DEFAULT ''")
            conn.execute("ALTER TABLE accounts ADD COLUMN mlkem_pub TEXT NOT NULL DEFAULT ''")
        # Pentest 2026-08-07 F-RELAY-005: monotone registration counter. Pre-v3
        # rows start at 0, which is below every counter a v3 client will send,
        # so an existing account can adopt the control by re-registering once.
        if "reg_seq" not in cols:
            conn.execute("ALTER TABLE accounts ADD COLUMN reg_seq INTEGER NOT NULL DEFAULT 0")
        # Web-of-trust vouches: one row per (voucher -> target) statement. The
        # signatures cover the target bundle AT VOUCH TIME; if the target's key
        # changes later, clients' signature checks fail and the vouch goes dead
        # on its own (no server-side key tracking needed).
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS vouches (
                voucher    TEXT NOT NULL,
                target     TEXT NOT NULL,
                sig_ed     TEXT NOT NULL,
                sig_mldsa  TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                PRIMARY KEY (voucher, target)
            )
            """
        )


# In-memory, expiring stores for login challenges and session tokens. These are
# ephemeral by design (no persistence of auth state); they reset on restart.
_challenges: dict[str, tuple[str, float]] = {}  # challenge_b64 -> (username, expiry)
_tokens: dict[str, tuple[str, float]] = {}      # token -> (username, expiry)

# Pentest 2026-07-26 P-12: these endpoints are sync `def`s, so FastAPI runs them
# in the anyio threadpool (40 workers by default) — genuinely concurrent, unlike
# the single-threaded event loop the rest of the app assumes. `_prune` iterated
# these dicts while other workers inserted into them, which can raise
# "RuntimeError: dictionary changed size during iteration" -> an unhandled 500
# plus a traceback on disk (against the I2 no-metadata-at-rest goal). The same
# race made the `len(...) >= MAX_...` check-then-insert pairs non-atomic, so the
# caps could be overshot. One lock guards both stores.
_store_lock = threading.Lock()


def _prune(store: dict[str, tuple[str, float]]) -> None:
    """Drop expired entries. Caller MUST hold `_store_lock`."""
    now = time.monotonic()
    for k in [k for k, (_, exp) in list(store.items()) if exp < now]:
        store.pop(k, None)


# --- request/response models (strict) --------------------------------------

class RegisterReq(BaseModel):
    model_config = ConfigDict(extra="forbid")
    username: str = Field(min_length=config.USERNAME_MIN, max_length=config.USERNAME_MAX)
    ed: str
    mldsa: str
    sig: str        # Ed25519 signature over the register message
    mldsa_sig: str  # ML-DSA-65 signature over the same message (PQ ownership proof)
    # Bundle v2 (both or neither): public encryption keys for sealed messages.
    ecdh: str | None = None
    mlkem: str | None = None
    # Bundle v3 (F-RELAY-005): monotone counter, signed. Absent from pre-v3
    # clients; see `register` for what a registration without one may still do.
    seq: int | None = Field(default=None, ge=1, le=2**53 - 1)


class ChallengeReq(BaseModel):
    model_config = ConfigDict(extra="forbid")
    username: str = Field(min_length=config.USERNAME_MIN, max_length=config.USERNAME_MAX)


class VerifyReq(BaseModel):
    model_config = ConfigDict(extra="forbid")
    username: str = Field(min_length=config.USERNAME_MIN, max_length=config.USERNAME_MAX)
    challenge: str
    sig: str
    # Pentest 2026-08-07 F-RELAY-006: the ML-DSA half of the login proof.
    # Optional in the model so a legacy client gets a clean 401 from the
    # verification below rather than a 422 that would distinguish it.
    mldsa_sig: str | None = None


def _check_username(u: str) -> None:
    if not _USERNAME_RE.match(u):
        raise HTTPException(status_code=422, detail="username must be [a-z0-9_.-]")


# --- endpoints (sync defs run in a threadpool; sqlite stays off the loop) --

@router.post("/register", dependencies=[Depends(register_rate_limit)])
def register(req: RegisterReq) -> dict:
    # Pentest 2026-07-26 P-09: registration is the one endpoint that still
    # distinguishes an existing username (409) from a free one (200), so it is a
    # namespace-existence oracle — the single exception to the I1 property the
    # module docstring describes (see the note there). Making the responses
    # indistinguishable is not possible without giving up first-come-first-served
    # naming, so instead it is moved off the general 5/s bucket onto its own
    # strict bucket (10 burst, 0.5/s sustained), matching the throttle on the
    # other existence-sensitive paths. Probing a wordlist now costs ~2 s per name
    # instead of 200 ms.
    _check_username(req.username)
    ed_raw = _b64decode_fixed(req.ed, config.ED25519_PUB_BYTES)
    mldsa_raw = _b64decode_fixed(req.mldsa, config.MLDSA65_PUB_BYTES)
    sig_raw = _b64decode_fixed(req.sig, config.ED25519_SIG_BYTES)
    mldsa_sig_raw = _b64decode_fixed(req.mldsa_sig, config.MLDSA65_SIG_BYTES)

    # Bundle v2 keys come together or not at all.
    if (req.ecdh is None) != (req.mlkem is None):
        raise HTTPException(status_code=422, detail="ecdh and mlkem must be provided together")
    if req.ecdh is not None:
        _b64decode_fixed(req.ecdh, config.ECDH_PUB_BYTES)
        _b64decode_fixed(req.mlkem, config.MLKEM768_PUB_BYTES)

    # Prove the registrant controls BOTH keys in the bundle (L1). The Ed25519
    # proof binds the classical key + the whole bundle (anti-squatting); the
    # ML-DSA proof stops binding a PQ public key the registrant does not hold.
    # v2 bundles sign the extended message (incl. the encryption keys) under
    # the v2 domain, binding those keys to the identity as well.
    # F-RELAY-005: a v3 registration signs a monotone counter as well, which is
    # what makes it un-replayable. The domain differs, so a v2 signature can
    # never be read as a v3 one (or vice versa).
    if req.seq is not None:
        if req.ecdh is None:
            raise HTTPException(status_code=422, detail="a counter-bearing registration must carry encryption keys")
        msg = _register_message_v3(req.username, req.ed, req.mldsa, req.ecdh, req.mlkem, req.seq)
    elif req.ecdh is not None:
        msg = _register_message_v2(req.username, req.ed, req.mldsa, req.ecdh, req.mlkem)
    else:
        msg = _register_message(req.username, req.ed, req.mldsa)
    if not _ed25519_verify(ed_raw, sig_raw, msg):
        raise HTTPException(status_code=400, detail="ownership signature invalid")
    if not _mldsa65_verify(mldsa_raw, mldsa_sig_raw, msg):
        raise HTTPException(status_code=400, detail="post-quantum ownership signature invalid")

    # Random, unguessable capability token so the username is not enumerable.
    token = base64.urlsafe_b64encode(secrets.token_bytes(config.LOOKUP_TOKEN_BYTES)).decode("ascii").rstrip("=")
    with _db() as conn:
        # Bound the directory size so a flood cannot exhaust disk.
        count = conn.execute("SELECT COUNT(*) FROM accounts").fetchone()[0]
        if count >= config.MAX_ACCOUNTS:
            raise HTTPException(status_code=503, detail="directory full")
        try:
            conn.execute(
                "INSERT INTO accounts (username, ed_pub, mldsa_pub, lookup_token, ecdh_pub, mlkem_pub, created_at, reg_seq) VALUES (?,?,?,?,?,?,?,?)",
                (req.username, req.ed, req.mldsa, token, req.ecdh or "", req.mlkem or "",
                 int(time.time()), req.seq or 0),
            )
        except sqlite3.IntegrityError:
            # Same-identity re-registration = bundle refresh (e.g. an upgraded
            # identity publishing its new encryption keys). The valid dual
            # signature already proved control of the identity keys; if they
            # match the stored row exactly, update the encryption keys and
            # return the EXISTING lookup token. Anyone else: taken.
            row = conn.execute(
                "SELECT ed_pub, mldsa_pub, lookup_token, ecdh_pub, mlkem_pub, reg_seq FROM accounts WHERE username = ?",
                (req.username,),
            ).fetchone()
            if row is None or row["ed_pub"] != req.ed or row["mldsa_pub"] != req.mldsa:
                raise HTTPException(status_code=409, detail={
                    "error": "username_taken",
                    "message": "username already taken",
                })

            # Pentest 2026-08-07 F-RELAY-005. The dual signature proves the
            # registrant controls the identity keys, but it proves nothing about
            # WHEN: every registration a user ever signed stayed valid forever,
            # and this branch applied whichever one arrived last. So a hostile
            # relay that captured an earlier registration could resend it to roll
            # the victim's published encryption keys back to a superseded pair,
            # or — replaying a v1 registration, which carries no encryption keys
            # at all — clear them outright. Both are silent, and both downgrade
            # every future sealed message to an account that cannot read it.
            #
            # A v3 registration carries a signed monotone counter, so a replay is
            # a counter that does not move forward, and it is refused.
            if req.seq is not None:
                if req.seq <= row["reg_seq"]:
                    # The 409 ECHOES the stored counter (decided with the owner,
                    # 2026-08-21). Without it a client can only GUESS its way
                    # forward, and the guess is computed from its own clock — so a
                    # device whose clock is wrong, or merely skewed against a
                    # second device registering the same identity, ratchets itself
                    # out permanently (A4/M-1, A4/M-2, and the wrong-clock
                    # residual: three findings with one repair). With the stored
                    # value in hand the client jumps to `stored + 1` and converges
                    # in one retry.
                    #
                    # Who learns it: this branch is reachable only AFTER both
                    # ownership signatures verified over this exact bundle AND the
                    # stored row's ed/mldsa matched the requester. So the counter
                    # is disclosed only to whoever already controls the identity
                    # keys that own the account — its owner. It is not an oracle
                    # for anyone else, and it says nothing about accounts you
                    # cannot already sign for.
                    raise HTTPException(status_code=409, detail={
                        "error": "stale_counter",
                        "stored_seq": row["reg_seq"],
                        "message": "registration counter is not newer than the stored one (replayed registration)",
                    })
                conn.execute(
                    "UPDATE accounts SET ecdh_pub = ?, mlkem_pub = ?, reg_seq = ? WHERE username = ?",
                    (req.ecdh or "", req.mlkem or "", req.seq, req.username),
                )
                return {"status": "updated", "username": req.username, "lookup_token": row["lookup_token"]}

            # No counter: a pre-v3 client, or a replay of one of its
            # registrations. It cannot be told which, so it is allowed to do
            # only the one thing a replay cannot abuse — ADD encryption keys to
            # an account that has none (the v2 upgrade path, which is why this
            # branch exists at all). It may never change or clear keys that are
            # already published, because that is exactly the attack.
            if row["ecdh_pub"] or row["mlkem_pub"]:
                if (req.ecdh or "") != row["ecdh_pub"] or (req.mlkem or "") != row["mlkem_pub"]:
                    raise HTTPException(status_code=409, detail={
                        "error": "keys_locked",
                        "message": "this account already publishes encryption keys; changing them needs a counter-bearing registration",
                    })
                return {"status": "updated", "username": req.username, "lookup_token": row["lookup_token"]}
            conn.execute(
                "UPDATE accounts SET ecdh_pub = ?, mlkem_pub = ? WHERE username = ?",
                (req.ecdh or "", req.mlkem or "", req.username),
            )
            return {"status": "updated", "username": req.username, "lookup_token": row["lookup_token"]}
    # The registrant shares `username#lookup_token` with contacts.
    return {"status": "registered", "username": req.username, "lookup_token": token}


@router.get("/users/{username}")
def get_user(username: str, t: str = Query(default="", max_length=64)) -> dict:
    # Anti-enumeration (I1): a lookup must present the per-account token. A
    # missing user AND a wrong token return an IDENTICAL 404, so probing a
    # username without its token reveals nothing about whether it exists. The
    # token is compared in constant time (against a decoy for missing users so
    # the comparison happens either way).
    _check_username(username)
    with _db() as conn:
        row = conn.execute(
            "SELECT ed_pub, mldsa_pub, lookup_token, ecdh_pub, mlkem_pub FROM accounts WHERE username = ?",
            (username,),
        ).fetchone()
    stored = row["lookup_token"] if row is not None else secrets.token_urlsafe(config.LOOKUP_TOKEN_BYTES)
    if not token_matches(t, stored) or row is None:
        raise HTTPException(status_code=404, detail="no such user")
    _charge_lookup("lookup:" + username)  # F-P7-3: after the gate, per target
    # The public identity bundle others will pin + verify in person. Encryption
    # keys (bundle v2) are included when the account has published them.
    out = {"username": username, "ed": row["ed_pub"], "mldsa": row["mldsa_pub"]}
    if row["ecdh_pub"] and row["mlkem_pub"]:
        out["ecdh"] = row["ecdh_pub"]
        out["mlkem"] = row["mlkem_pub"]
    return out


@router.post("/auth/challenge", dependencies=[Depends(challenge_rate_limit)])
def auth_challenge(req: ChallengeReq) -> dict:
    # Anti-enumeration (I1): issue a challenge for ANY well-formed username,
    # whether or not it exists. A nonexistent account simply cannot produce a
    # valid signature at verify time, so this endpoint reveals nothing.
    _check_username(req.username)
    # F-RELAY-003: the per-account bucket. Charged AFTER `_check_username` so a
    # malformed name cannot mint buckets, and identically for existing and
    # nonexistent accounts so the 429 is not an existence oracle.
    if not _challenge_limiter.allow("challenge:" + req.username):
        raise HTTPException(status_code=429, detail="rate limited")
    challenge = base64.b64encode(secrets.token_bytes(32)).decode("ascii")
    # Prune + cap-check + insert must be one atomic step (P-12).
    with _store_lock:
        _prune(_challenges)
        if len(_challenges) >= config.MAX_PENDING_CHALLENGES:
            raise HTTPException(status_code=503, detail="too many pending challenges")
        _challenges[challenge] = (req.username, time.monotonic() + config.CHALLENGE_TTL_SEC)
    return {"challenge": challenge}


@router.post("/auth/verify")
def auth_verify(req: VerifyReq) -> dict:
    _check_username(req.username)
    with _store_lock:
        _prune(_challenges)
        entry = _challenges.pop(req.challenge, None)  # one-time use (atomic: P-12)
    if entry is None or entry[0] != req.username:
        raise HTTPException(status_code=400, detail="unknown or expired challenge")

    challenge_raw = _b64decode_fixed(req.challenge, 32)
    sig_raw = _b64decode_fixed(req.sig, config.ED25519_SIG_BYTES)
    with _db() as conn:
        row = conn.execute(
            "SELECT ed_pub, mldsa_pub FROM accounts WHERE username = ?", (req.username,)
        ).fetchone()
    # Unknown user and bad signature are indistinguishable (both 401), so verify
    # is not an existence oracle either (I1). Decoys keep the work identical on
    # both branches so the 401 is not a timing oracle either — F-RELAY-007 noted
    # the missing-user branch returned early, and the dual verification below
    # would have widened that gap considerably.
    ed_stored = row["ed_pub"] if row is not None else _DECOY_BUNDLE["ed_pub"]
    mldsa_stored = row["mldsa_pub"] if row is not None else _DECOY_BUNDLE["mldsa_pub"]
    msg = _login_message(challenge_raw)

    # Pentest 2026-08-07 F-RELAY-006: login used to be Ed25519-ONLY.
    #
    # Registration proves control of BOTH identity keys and the handshake
    # requires BOTH signatures (PR-3, AND-composed) — the whole point of the
    # dual-scheme identity is that breaking one scheme is not enough. The
    # directory session was the exception: a token minted on the classical
    # signature alone, and that token drains and DELETES the account's mailbox
    # and deletes its vouches. So an adversary who broke Ed25519 — the scheme
    # the ML-DSA half exists to hedge against — got full directory control while
    # every other surface still held.
    #
    # Both signatures now, over the same challenge, AND-composed exactly as the
    # handshake does it.
    ed_ok = _ed25519_verify(base64.b64decode(ed_stored, validate=True), sig_raw, msg)

    mldsa_ok = False
    if req.mldsa_sig is not None:
        try:
            mldsa_sig_raw = _b64decode_fixed(req.mldsa_sig, config.MLDSA65_SIG_BYTES)
        except HTTPException:
            mldsa_sig_raw = b"\x00" * config.MLDSA65_SIG_BYTES
        mldsa_ok = _mldsa65_verify(base64.b64decode(mldsa_stored, validate=True), mldsa_sig_raw, msg)
    else:
        # Legacy client: run the verification anyway, against a signature that
        # cannot pass, so the refusal costs the same time as a wrong one.
        #
        # Item 15 note: this decoy runs for legacy clients, so it is reachable by
        # unauthenticated traffic. Before the verify was serialised that meant
        # garbage requests could CORRUPT concurrent real logins; now the worst
        # they do is hold the ML-DSA lock briefly, bounded by the challenge and
        # per-host buckets far below its capacity. Keeping the decoy is
        # deliberate — dropping it reopens the F-RELAY-006 timing oracle.
        #
        # Measured, because the first version of this note guessed and was wrong
        # by ~45x: an all-zero signature is rejected in **0.33 ms**, not the
        # ~14.5 ms a well-formed one costs, because ML-DSA rejects it on a
        # structural check long before any expensive work. So this branch is a
        # far smaller lock-holder than the real verify path.
        #
        # That asymmetry does NOT leak anything: it separates a legacy client
        # from a dual-scheme one, which is already plain from whether the request
        # carries `mldsa_sig` at all. The equalisation that actually matters —
        # existing vs nonexistent user — is the `_DECOY_BUNDLE` above, which
        # verifies the SUBMITTED signature against a decoy key and so costs the
        # same as the real branch (measured 20.9 ms vs 21.2 ms median).
        _mldsa65_verify(
            base64.b64decode(mldsa_stored, validate=True),
            b"\x00" * config.MLDSA65_SIG_BYTES,
            msg,
        )

    if row is None or not ed_ok or not mldsa_ok:
        raise HTTPException(status_code=401, detail="challenge signature invalid")

    token = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii").rstrip("=")
    with _store_lock:
        _prune(_tokens)
        # Pentest 2026-07-29 L-4: bound how many sessions one account can hold,
        # so a leaked token cannot be retained indefinitely and a reconnect loop
        # cannot fill MAX_ACTIVE_TOKENS with one user's dead sessions.
        #
        # The first cut of this retired ALL the account's other tokens on login,
        # which the fix review (M-C) showed was a self-inflicted DoS: pollMailbox
        # runs every 6 s and treats a 401 by calling autoLogin, so two tabs of
        # the SAME account revoke each other forever. That sustains ~0.33
        # challenges/s against CHALLENGE_RATE_REFILL_PER_SEC = 0.5 — which, since
        # the M-1 fix, is one bucket for the whole relay — so two of a user's own
        # tabs ate most of the relay's login capacity and three saturated it,
        # denying login to every account. The tabs then sat permanently offline
        # for sealed mail with no visible sign, which is the exact failure the
        # 401 handler was written to prevent.
        #
        # LRU eviction instead: several tabs and a phone coexist happily, and the
        # oldest session is what goes when the cap is reached. Revocation on
        # demand is what /auth/logout is for — that is the honest remedy for a
        # leaked token, and unlike "log in again" it does not fight the poller.
        mine = [t for t, (owner, _exp) in _tokens.items() if owner == req.username]
        for old in mine[: max(0, len(mine) + 1 - config.MAX_SESSIONS_PER_ACCOUNT)]:
            del _tokens[old]  # dict order is insertion order, so this is oldest-first
        if len(_tokens) >= config.MAX_ACTIVE_TOKENS:
            raise HTTPException(status_code=503, detail="too many active sessions")
        _tokens[token] = (req.username, time.monotonic() + config.TOKEN_TTL_SEC)
    return {"token": token, "ttl": config.TOKEN_TTL_SEC}


@router.post("/auth/logout")
def auth_logout(authorization: str | None = Header(default=None)) -> dict:
    """Drop the presented session token (pentest 2026-07-29 L-4).

    Deliberately NOT behind `current_user`: an already-invalid token must get
    the same answer as a valid one, or this becomes a token-validity oracle
    that needs no signature. Always 200, always idempotent, and it reveals
    nothing about whether anything was actually removed.
    """
    if authorization and authorization.startswith("Bearer "):
        with _store_lock:
            _tokens.pop(authorization[len("Bearer "):], None)
    return {"status": "logged out"}


def current_user(authorization: str | None = Header(default=None)) -> str:
    """Resolve a Bearer token to a username, or 401."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="missing bearer token")
    token = authorization[len("Bearer "):]
    with _store_lock:
        _prune(_tokens)
        entry = _tokens.get(token)
    if entry is None:
        raise HTTPException(status_code=401, detail="invalid or expired token")
    return entry[0]


@router.get("/me")
def me(username: str = Depends(current_user)) -> dict:
    return {"username": username}


# --- web-of-trust vouches ---------------------------------------------------

class VouchReq(BaseModel):
    model_config = ConfigDict(extra="forbid")
    target: str = Field(min_length=config.USERNAME_MIN, max_length=config.USERNAME_MAX)
    sig: str        # voucher's Ed25519 signature over the vouch message
    mldsa_sig: str  # voucher's ML-DSA-65 signature over the same message


@router.post("/vouch", dependencies=[Depends(vouch_host_rate_limit)])
def vouch(req: VouchReq, username: str = Depends(current_user)) -> dict:
    """Publish (or refresh) a dual-signed vouch for `target`.

    The server verifies both signatures against the VOUCHER's registered keys
    and the TARGET's currently registered bundle before storing, so the table
    can only ever hold statements the voucher really signed about the target's
    real directory entry. Clients still re-verify against their own pins.
    """
    _charge_lookup("vouch:" + username)  # F-P7-3: per authenticated voucher
    _check_username(req.target)
    if req.target == username:
        raise HTTPException(status_code=422, detail="cannot vouch for yourself")
    with _db() as conn:
        target_row = conn.execute(
            "SELECT ed_pub, mldsa_pub, ecdh_pub, mlkem_pub FROM accounts WHERE username = ?", (req.target,)
        ).fetchone()
        voucher_row = conn.execute(
            "SELECT ed_pub, mldsa_pub FROM accounts WHERE username = ?", (username,)
        ).fetchone()
    if voucher_row is None:
        raise HTTPException(status_code=401, detail="voucher not registered")

    # Anti-enumeration (pentest 2026-07-29 M-7). This used to answer
    # `404 "no such target user"` HERE, before any signature or base64
    # validation, while a real name fell through to a 400/422 — a username
    # oracle that, unlike the registration oracle the module docstring
    # acknowledges, consumes nothing, creates nothing, leaves no directory
    # trace and had no dedicated limiter.
    #
    # Two changes: the route now shares `lookup_rate_limit`, the same
    # anti-enumeration bucket `GET /users/{username}` uses; and the existence
    # answer is folded into the signature check below so that a missing target
    # and a bad signature are indistinguishable. A decoy bundle keeps the work
    # (and so the timing) the same either way — the same shape as `get_user`'s
    # length-matched token decoy. Verification against the decoy always fails,
    # which is exactly the outcome we want to be indistinguishable from.
    missing_target = target_row is None
    if missing_target:
        target_row = _DECOY_BUNDLE

    sig_raw = _b64decode_fixed(req.sig, config.ED25519_SIG_BYTES)
    mldsa_sig_raw = _b64decode_fixed(req.mldsa_sig, config.MLDSA65_SIG_BYTES)
    # v2 covers the target's encryption keys when present (H-01); the client
    # signs the identical bytes (account.vouchMessageBytes).
    msg = _vouch_message(
        req.target, target_row["ed_pub"], target_row["mldsa_pub"],
        target_row["ecdh_pub"], target_row["mlkem_pub"],
    )
    ed_raw = base64.b64decode(voucher_row["ed_pub"], validate=True)
    mldsa_raw = base64.b64decode(voucher_row["mldsa_pub"], validate=True)
    ed_ok = _ed25519_verify(ed_raw, sig_raw, msg)
    mldsa_ok = _mldsa65_verify(mldsa_raw, mldsa_sig_raw, msg)
    # Both verifications always run, and the verdict is combined afterwards, so
    # neither the status code nor the number of expensive operations depends on
    # whether the target exists.
    # Phase-7 pentest 2026-09-16 F-P7-11: two different strings told a holder
    # of the target's bundle whether the target exists (a valid Ed25519 vouch
    # with junk ML-DSA answered "post-quantum … invalid" only for a REAL target)
    # — M-7's oracle, without the lookup token. One message for all three.
    if missing_target or not ed_ok or not mldsa_ok:
        raise HTTPException(status_code=400, detail="vouch signature invalid")

    with _db() as conn:
        total = conn.execute("SELECT COUNT(*) FROM vouches").fetchone()[0]
        mine = conn.execute(
            "SELECT COUNT(*) FROM vouches WHERE voucher = ?", (username,)
        ).fetchone()[0]
        replacing = conn.execute(
            "SELECT 1 FROM vouches WHERE voucher = ? AND target = ?", (username, req.target)
        ).fetchone() is not None
        if not replacing and (total >= config.MAX_VOUCHES_TOTAL or mine >= config.MAX_VOUCHES_PER_VOUCHER):
            raise HTTPException(status_code=503, detail="vouch limit reached")
        conn.execute(
            "INSERT OR REPLACE INTO vouches (voucher, target, sig_ed, sig_mldsa, created_at) VALUES (?,?,?,?,?)",
            (username, req.target, req.sig, req.mldsa_sig, int(time.time())),
        )
    return {"status": "vouched", "target": req.target}


@router.delete("/vouch/{target}")
def unvouch(target: str, username: str = Depends(current_user)) -> dict:
    _check_username(target)
    with _db() as conn:
        conn.execute("DELETE FROM vouches WHERE voucher = ? AND target = ?", (username, target))
    return {"status": "removed", "target": target}


@router.get("/users/{username}/vouches")
def get_vouches(username: str, t: str = Query(default="", max_length=64)) -> dict:
    """Vouches ABOUT `username`, gated by the same lookup token as the bundle.

    Includes each voucher's public keys so a client can check the signatures —
    but a client must only award the 🟡 mark when the voucher matches a contact
    it has ITSELF verified in person (pinned keys), so a lying server gains
    nothing by inventing vouchers here.
    """
    _check_username(username)
    with _db() as conn:
        row = conn.execute(
            "SELECT lookup_token FROM accounts WHERE username = ?", (username,)
        ).fetchone()
        stored = row["lookup_token"] if row is not None else secrets.token_urlsafe(config.LOOKUP_TOKEN_BYTES)
        if not token_matches(t, stored) or row is None:
            raise HTTPException(status_code=404, detail="no such user")
        _charge_lookup("lookup:" + username)  # F-P7-3: after the gate, per target
        rows = conn.execute(
            """
            SELECT v.voucher, v.sig_ed, v.sig_mldsa, v.created_at, a.ed_pub, a.mldsa_pub
            FROM vouches v JOIN accounts a ON a.username = v.voucher
            WHERE v.target = ? ORDER BY v.created_at DESC LIMIT ?
            """,
            (username, config.MAX_VOUCHES_RETURNED),
        ).fetchall()
    return {
        "target": username,
        "vouches": [
            {
                "voucher": r["voucher"], "voucher_ed": r["ed_pub"], "voucher_mldsa": r["mldsa_pub"],
                "sig": r["sig_ed"], "mldsa_sig": r["sig_mldsa"], "created_at": r["created_at"],
            }
            for r in rows
        ],
    }
