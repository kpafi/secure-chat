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

Anti-enumeration (I1): the username namespace is NOT enumerable. Lookups are
gated by a per-account random token (`username#token` handle); challenge/verify
no longer reveal whether a username exists. See `get_user` / `auth_*`.
"""
from __future__ import annotations

import base64
import hmac
import re
import secrets
import sqlite3
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
_challenge_limiter = KeyedRateLimiter(config.CHALLENGE_RATE_CAPACITY, config.CHALLENGE_RATE_REFILL_PER_SEC)


def rate_limit(request: Request) -> None:
    host = request.client.host if request.client else "unknown"
    if not _api_limiter.allow(host):
        raise HTTPException(status_code=429, detail="rate limited")


def challenge_rate_limit(request: Request) -> None:
    host = request.client.host if request.client else "unknown"
    if not _challenge_limiter.allow(host):
        raise HTTPException(status_code=429, detail="rate limited")


def lookup_rate_limit(request: Request) -> None:
    host = request.client.host if request.client else "unknown"
    if not _lookup_limiter.allow(host):
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

# Login challenges are signed under their own domain prefix so a login signature
# can never be mistaken for (or replayed as) a signature of any other protocol
# message. The client prepends the same prefix before signing the raw nonce.
_LOGIN_DOMAIN = b"secure-chat/login/v1"


def _login_message(challenge_raw: bytes) -> bytes:
    return _LOGIN_DOMAIN + b"\n" + challenge_raw


# --- low-level helpers -----------------------------------------------------

def _b64decode_fixed(s: str, n: int) -> bytes:
    """Strictly decode base64 to exactly n bytes, else raise 422."""
    if not _B64_RE.match(s or ""):
        raise HTTPException(status_code=422, detail="invalid base64")
    try:
        raw = base64.b64decode(s, validate=True)
    except Exception:
        raise HTTPException(status_code=422, detail="invalid base64")
    if len(raw) != n:
        raise HTTPException(status_code=422, detail="unexpected key/sig length")
    return raw


def _ed25519_verify(pub_raw: bytes, sig: bytes, msg: bytes) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(pub_raw).verify(sig, msg)
        return True
    except (InvalidSignature, ValueError):
        return False


def _mldsa65_verify(pub_raw: bytes, sig: bytes, msg: bytes) -> bool:
    try:
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


# Web-of-trust vouch: the voucher dual-signs the TARGET's (username, bundle)
# under its own domain, so a vouch can never be confused with a registration
# or login signature. Client builds the identical bytes (account.js).
_VOUCH_DOMAIN = b"secure-chat/vouch/v1"


def _vouch_message(target: str, ed: str, mldsa: str) -> bytes:
    return b"\n".join(
        [_VOUCH_DOMAIN, target.encode("ascii"), ed.encode("ascii"), mldsa.encode("ascii")]
    )


# --- storage ---------------------------------------------------------------

def _db() -> sqlite3.Connection:
    conn = sqlite3.connect(config.DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
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


def _prune(store: dict[str, tuple[str, float]]) -> None:
    now = time.monotonic()
    for k in [k for k, (_, exp) in store.items() if exp < now]:
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


class ChallengeReq(BaseModel):
    model_config = ConfigDict(extra="forbid")
    username: str = Field(min_length=config.USERNAME_MIN, max_length=config.USERNAME_MAX)


class VerifyReq(BaseModel):
    model_config = ConfigDict(extra="forbid")
    username: str = Field(min_length=config.USERNAME_MIN, max_length=config.USERNAME_MAX)
    challenge: str
    sig: str


def _check_username(u: str) -> None:
    if not _USERNAME_RE.match(u):
        raise HTTPException(status_code=422, detail="username must be [a-z0-9_.-]")


# --- endpoints (sync defs run in a threadpool; sqlite stays off the loop) --

@router.post("/register")
def register(req: RegisterReq) -> dict:
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
    if req.ecdh is not None:
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
                "INSERT INTO accounts (username, ed_pub, mldsa_pub, lookup_token, ecdh_pub, mlkem_pub, created_at) VALUES (?,?,?,?,?,?,?)",
                (req.username, req.ed, req.mldsa, token, req.ecdh or "", req.mlkem or "", int(time.time())),
            )
        except sqlite3.IntegrityError:
            # Same-identity re-registration = bundle refresh (e.g. an upgraded
            # identity publishing its new encryption keys). The valid dual
            # signature already proved control of the identity keys; if they
            # match the stored row exactly, update the encryption keys and
            # return the EXISTING lookup token. Anyone else: taken.
            row = conn.execute(
                "SELECT ed_pub, mldsa_pub, lookup_token FROM accounts WHERE username = ?",
                (req.username,),
            ).fetchone()
            if row is None or row["ed_pub"] != req.ed or row["mldsa_pub"] != req.mldsa:
                raise HTTPException(status_code=409, detail="username already taken")
            conn.execute(
                "UPDATE accounts SET ecdh_pub = ?, mlkem_pub = ? WHERE username = ?",
                (req.ecdh or "", req.mlkem or "", req.username),
            )
            return {"status": "updated", "username": req.username, "lookup_token": row["lookup_token"]}
    # The registrant shares `username#lookup_token` with contacts.
    return {"status": "registered", "username": req.username, "lookup_token": token}


@router.get("/users/{username}", dependencies=[Depends(lookup_rate_limit)])
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
    if not hmac.compare_digest(t, stored) or row is None:
        raise HTTPException(status_code=404, detail="no such user")
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
    _prune(_challenges)
    if len(_challenges) >= config.MAX_PENDING_CHALLENGES:
        raise HTTPException(status_code=503, detail="too many pending challenges")
    challenge = base64.b64encode(secrets.token_bytes(32)).decode("ascii")
    _challenges[challenge] = (req.username, time.monotonic() + config.CHALLENGE_TTL_SEC)
    return {"challenge": challenge}


@router.post("/auth/verify")
def auth_verify(req: VerifyReq) -> dict:
    _check_username(req.username)
    _prune(_challenges)
    entry = _challenges.pop(req.challenge, None)  # one-time use
    if entry is None or entry[0] != req.username:
        raise HTTPException(status_code=400, detail="unknown or expired challenge")

    challenge_raw = _b64decode_fixed(req.challenge, 32)
    sig_raw = _b64decode_fixed(req.sig, config.ED25519_SIG_BYTES)
    with _db() as conn:
        row = conn.execute(
            "SELECT ed_pub FROM accounts WHERE username = ?", (req.username,)
        ).fetchone()
    # Unknown user and bad signature are indistinguishable (both 401), so verify
    # is not an existence oracle either (I1).
    if row is None:
        raise HTTPException(status_code=401, detail="challenge signature invalid")
    ed_raw = base64.b64decode(row["ed_pub"], validate=True)
    if not _ed25519_verify(ed_raw, sig_raw, _login_message(challenge_raw)):
        raise HTTPException(status_code=401, detail="challenge signature invalid")

    _prune(_tokens)
    if len(_tokens) >= config.MAX_ACTIVE_TOKENS:
        raise HTTPException(status_code=503, detail="too many active sessions")
    token = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii").rstrip("=")
    _tokens[token] = (req.username, time.monotonic() + config.TOKEN_TTL_SEC)
    return {"token": token, "ttl": config.TOKEN_TTL_SEC}


def current_user(authorization: str | None = Header(default=None)) -> str:
    """Resolve a Bearer token to a username, or 401."""
    _prune(_tokens)
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="missing bearer token")
    token = authorization[len("Bearer "):]
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


@router.post("/vouch")
def vouch(req: VouchReq, username: str = Depends(current_user)) -> dict:
    """Publish (or refresh) a dual-signed vouch for `target`.

    The server verifies both signatures against the VOUCHER's registered keys
    and the TARGET's currently registered bundle before storing, so the table
    can only ever hold statements the voucher really signed about the target's
    real directory entry. Clients still re-verify against their own pins.
    """
    _check_username(req.target)
    if req.target == username:
        raise HTTPException(status_code=422, detail="cannot vouch for yourself")
    with _db() as conn:
        target_row = conn.execute(
            "SELECT ed_pub, mldsa_pub FROM accounts WHERE username = ?", (req.target,)
        ).fetchone()
        voucher_row = conn.execute(
            "SELECT ed_pub, mldsa_pub FROM accounts WHERE username = ?", (username,)
        ).fetchone()
    # The voucher is authenticated (session token), so telling them the target
    # is unknown leaks nothing beyond what registering that name would.
    if target_row is None:
        raise HTTPException(status_code=404, detail="no such target user")
    if voucher_row is None:
        raise HTTPException(status_code=401, detail="voucher not registered")

    sig_raw = _b64decode_fixed(req.sig, config.ED25519_SIG_BYTES)
    mldsa_sig_raw = _b64decode_fixed(req.mldsa_sig, config.MLDSA65_SIG_BYTES)
    msg = _vouch_message(req.target, target_row["ed_pub"], target_row["mldsa_pub"])
    ed_raw = base64.b64decode(voucher_row["ed_pub"], validate=True)
    mldsa_raw = base64.b64decode(voucher_row["mldsa_pub"], validate=True)
    if not _ed25519_verify(ed_raw, sig_raw, msg):
        raise HTTPException(status_code=400, detail="vouch signature invalid")
    if not _mldsa65_verify(mldsa_raw, mldsa_sig_raw, msg):
        raise HTTPException(status_code=400, detail="post-quantum vouch signature invalid")

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


@router.get("/users/{username}/vouches", dependencies=[Depends(lookup_rate_limit)])
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
        if not hmac.compare_digest(t, stored) or row is None:
            raise HTTPException(status_code=404, detail="no such user")
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
