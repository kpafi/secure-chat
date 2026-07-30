"""Tests for the passwordless account directory.

Uses a throwaway SQLite DB and real keys — Ed25519 via `cryptography` and
ML-DSA-65 via `dilithium_py` — to sign the registration proof (both keys) and
the login challenge, exercising the happy paths and the security-relevant
rejections, including L1 (dual ownership proof) and I1 (no enumeration).
"""
import base64
import os
import sys
import tempfile
from pathlib import Path

# Point the app at a temp DB BEFORE importing it, and make backend importable.
_TMP_DB = os.path.join(tempfile.mkdtemp(), "test_accounts.db")
os.environ["SECURE_CHAT_DB"] = _TMP_DB
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402
from cryptography.hazmat.primitives import serialization  # noqa: E402
from dilithium_py.ml_dsa import ML_DSA_65  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from main import app  # noqa: E402
import accounts  # noqa: E402
import config  # noqa: E402

client = TestClient(app)


@pytest.fixture(autouse=True)
def _reset_api_limiter():
    # Each test starts with a fresh rate-limit budget (TestClient shares one
    # client host, so otherwise the buckets would deplete across the suite).
    accounts._api_limiter._buckets.clear()
    accounts._lookup_limiter._buckets.clear()
    accounts._challenge_limiter._buckets.clear()
    yield


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _new_identity():
    """Return (ed_priv, ed_pub_b64, mldsa_pub_b64, mldsa_secret) with real keys
    for BOTH schemes — the server now verifies both at registration (L1)."""
    ed_priv = Ed25519PrivateKey.generate()
    ed_pub = ed_priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    mldsa_pub, mldsa_secret = ML_DSA_65.keygen()
    return ed_priv, _b64(ed_pub), _b64(mldsa_pub), mldsa_secret


def _register_message(username, ed, mldsa):
    return b"\n".join([b"secure-chat/register/v1", username.encode(), ed.encode(), mldsa.encode()])


def _login_message(challenge_b64):
    # Mirror accounts._login_message: domain prefix + the raw challenge bytes.
    return b"secure-chat/login/v1\n" + base64.b64decode(challenge_b64)


def _register_body(username, ident):
    """Fully signed, valid register body for an identity (dual signature)."""
    ed_priv, ed, mldsa, mldsa_secret = ident
    msg = _register_message(username, ed, mldsa)
    return {
        "username": username,
        "ed": ed,
        "mldsa": mldsa,
        "sig": _b64(ed_priv.sign(msg)),
        "mldsa_sig": _b64(ML_DSA_65.sign(mldsa_secret, msg)),
    }


def _register(username):
    ident = _new_identity()
    resp = client.post("/api/register", json=_register_body(username, ident))
    return ident, resp


def _lookup(username, token):
    return client.get(f"/api/users/{username}", params={"t": token})


def test_register_and_lookup():
    ident, resp = _register("alice")
    assert resp.status_code == 200, resp.text
    token = resp.json()["lookup_token"]
    assert token, "registration returns a lookup token"
    # Lookup requires the token; with it, we get exactly the bundle to pin.
    got = _lookup("alice", token)
    assert got.status_code == 200
    assert got.json() == {"username": "alice", "ed": ident[1], "mldsa": ident[2]}


def test_register_rejects_bad_signature():
    ident = _new_identity()
    body = _register_body("mallory", ident)
    # Replace the Ed25519 signature with one from a DIFFERENT key.
    wrong = Ed25519PrivateKey.generate()
    body["sig"] = _b64(wrong.sign(_register_message("mallory", ident[1], ident[2])))
    resp = client.post("/api/register", json=body)
    assert resp.status_code == 400


def test_register_rejects_bad_mldsa_signature():
    # L1: a valid Ed25519 proof but an ML-DSA signature from a DIFFERENT PQ key
    # (i.e. binding a PQ pubkey the registrant does not control) must be refused.
    ident = _new_identity()
    body = _register_body("pqmallory", ident)
    _, _, _, other_secret = _new_identity()
    body["mldsa_sig"] = _b64(ML_DSA_65.sign(other_secret, _register_message("pqmallory", ident[1], ident[2])))
    resp = client.post("/api/register", json=body)
    assert resp.status_code == 400, resp.text
    assert "post-quantum" in resp.json()["detail"]


def test_register_rejects_duplicate_username():
    _register("bob")
    _, resp = _register("bob")
    assert resp.status_code == 409


def test_register_rejects_bad_username():
    ident = _new_identity()
    resp = client.post("/api/register", json=_register_body("Bad Name!", ident))
    assert resp.status_code == 422


def test_register_rejects_wrong_key_size():
    ident = _new_identity()
    body = _register_body("shorty", ident)
    body["ed"] = _b64(b"too short")  # wrong ed size; sig no longer matches either
    resp = client.post("/api/register", json=body)
    assert resp.status_code == 422


def test_register_requires_mldsa_sig_field():
    ident = _new_identity()
    body = _register_body("noproof", ident)
    del body["mldsa_sig"]
    resp = client.post("/api/register", json=body)
    assert resp.status_code == 422  # pydantic: missing required field


# ---- anti-enumeration: token-gated lookup (I1) ---------------------------

def test_lookup_without_token_is_404():
    _, resp = _register("hidden")
    assert resp.status_code == 200
    # No token at all, and a WRONG token, both look identical to a missing user.
    assert client.get("/api/users/hidden").status_code == 404
    assert _lookup("hidden", "wrongtoken").status_code == 404


def test_lookup_unknown_user_is_404():
    # A well-formed username that was never registered: identical 404, so a
    # probe cannot distinguish "exists but wrong token" from "does not exist".
    assert _lookup("nobody", "anything").status_code == 404
    assert client.get("/api/users/nobody").status_code == 404


# ---- anti-enumeration: challenge/verify are not oracles (I1) -------------

def test_challenge_does_not_reveal_existence():
    # A challenge is issued for a NONEXISTENT username just the same as a real
    # one (200) — the endpoint no longer leaks who exists.
    assert client.post("/api/auth/challenge", json={"username": "ghostuser"}).status_code == 200


def test_verify_unknown_user_is_401_not_404():
    # Unknown user and bad signature are indistinguishable at verify (both 401).
    ch = client.post("/api/auth/challenge", json={"username": "ghostuser2"}).json()["challenge"]
    other = Ed25519PrivateKey.generate()
    ver = client.post(
        "/api/auth/verify",
        json={"username": "ghostuser2", "challenge": ch, "sig": _b64(other.sign(_login_message(ch)))},
    )
    assert ver.status_code == 401


def test_full_login_flow():
    ident, _ = _register("carol")
    ed_priv = ident[0]
    ch = client.post("/api/auth/challenge", json={"username": "carol"})
    assert ch.status_code == 200
    challenge = ch.json()["challenge"]
    sig = ed_priv.sign(_login_message(challenge))
    ver = client.post("/api/auth/verify", json={"username": "carol", "challenge": challenge, "sig": _b64(sig)})
    assert ver.status_code == 200, ver.text
    token = ver.json()["token"]

    me = client.get("/api/me", headers={"Authorization": f"Bearer {token}"})
    assert me.status_code == 200
    assert me.json()["username"] == "carol"


def _login(username, ed_priv):
    """Complete a real challenge/response login and return the bearer token."""
    ch = client.post("/api/auth/challenge", json={"username": username}).json()["challenge"]
    sig = ed_priv.sign(_login_message(ch))
    r = client.post("/api/auth/verify", json={"username": username, "challenge": ch, "sig": _b64(sig)})
    assert r.status_code == 200, r.text
    return r.json()["token"]


def _me(token):
    return client.get("/api/me", headers={"Authorization": f"Bearer {token}"}).status_code


# --- Pentest 2026-07-29 L-4: session revocation ------------------------------
# There was none. No logout existed, and re-login left the previous bearer
# valid for the full TOKEN_TTL_SEC (3600 s) — verified at the time: the old
# token still answered 200 on /api/me. So a leaked token could not be revoked
# by any action available to the user, including the one everybody tries first.

def test_relogin_invalidates_the_previous_session():
    ident, _ = _register("revoke-relogin")
    first = _login("revoke-relogin", ident[0])
    assert _me(first) == 200, "precondition: the first token works"

    second = _login("revoke-relogin", ident[0])
    assert second != first, "a fresh login must mint a new token"
    assert _me(second) == 200, "the new session works"
    assert _me(first) == 401, "L-4: logging in again must retire the old session"


def test_logout_revokes_the_presented_token():
    ident, _ = _register("revoke-logout")
    token = _login("revoke-logout", ident[0])
    assert _me(token) == 200

    r = client.post("/api/auth/logout", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200, r.text
    assert _me(token) == 401, "L-4: logout must actually revoke"


def test_logout_is_idempotent_and_not_a_validity_oracle():
    """The answer must not depend on whether the token was real.

    Putting logout behind current_user would have made it a free token-validity
    check requiring no signature — a smaller oracle than M-7's, but the same
    mistake, so it is pinned here.
    """
    ident, _ = _register("revoke-oracle")
    token = _login("revoke-oracle", ident[0])
    real = client.post("/api/auth/logout", headers={"Authorization": f"Bearer {token}"})
    again = client.post("/api/auth/logout", headers={"Authorization": f"Bearer {token}"})
    bogus = client.post("/api/auth/logout", headers={"Authorization": "Bearer not-a-real-token"})
    none = client.post("/api/auth/logout")
    for r in (again, bogus, none):
        assert (r.status_code, r.json()) == (real.status_code, real.json()), (
            f"logout distinguishes token validity: {r.status_code} {r.json()}"
        )


def test_other_accounts_sessions_survive_a_login():
    """Revocation is per-account; one user logging in must not log everyone out."""
    a_ident, _ = _register("revoke-a")
    b_ident, _ = _register("revoke-b")
    a_tok = _login("revoke-a", a_ident[0])
    b_tok = _login("revoke-b", b_ident[0])
    _login("revoke-a", a_ident[0])  # a logs in again
    assert _me(a_tok) == 401, "a's old session is gone"
    assert _me(b_tok) == 200, "b's session is untouched"


def test_login_rejects_wrong_signature():
    _register("dave")
    other = Ed25519PrivateKey.generate()
    ch = client.post("/api/auth/challenge", json={"username": "dave"}).json()["challenge"]
    sig = other.sign(_login_message(ch))  # signed by the wrong key
    ver = client.post("/api/auth/verify", json={"username": "dave", "challenge": ch, "sig": _b64(sig)})
    assert ver.status_code == 401


def test_challenge_is_one_time():
    ident, _ = _register("erin")
    ed_priv = ident[0]
    ch = client.post("/api/auth/challenge", json={"username": "erin"}).json()["challenge"]
    sig = _b64(ed_priv.sign(_login_message(ch)))
    first = client.post("/api/auth/verify", json={"username": "erin", "challenge": ch, "sig": sig})
    assert first.status_code == 200
    # Replaying the same challenge must fail (consumed).
    second = client.post("/api/auth/verify", json={"username": "erin", "challenge": ch, "sig": sig})
    assert second.status_code == 400


# ---- abuse / DoS bounds (M1) ---------------------------------------------

def test_api_rate_limit(monkeypatch):
    from relay import KeyedRateLimiter
    # Tiny budget so the limit is deterministic: 3 allowed, then 429.
    monkeypatch.setattr(accounts, "_api_limiter", KeyedRateLimiter(3, 0.001))
    codes = [client.post("/api/auth/challenge", json={"username": "whoever"}).status_code for _ in range(6)]
    assert 429 in codes, codes
    assert codes.count(429) >= 2, codes  # most of the burst past the cap is blocked


def test_lookup_rate_limit(monkeypatch):
    from relay import KeyedRateLimiter
    # The lookup path has its own, stricter bucket (anti-enumeration).
    monkeypatch.setattr(accounts, "_lookup_limiter", KeyedRateLimiter(3, 0.001))
    codes = [client.get("/api/users/whoever", params={"t": "x"}).status_code for _ in range(6)]
    assert 429 in codes, codes
    assert codes.count(429) >= 2, codes


def test_account_cap_enforced(monkeypatch):
    monkeypatch.setattr(config, "MAX_ACCOUNTS", 0)  # directory "full"
    ident = _new_identity()
    resp = client.post("/api/register", json=_register_body("capped.user", ident))
    assert resp.status_code == 503, resp.text


def test_pending_challenge_cap_enforced(monkeypatch):
    _register("chalcap")
    accounts._challenges.clear()
    monkeypatch.setattr(config, "MAX_PENDING_CHALLENGES", 1)
    first = client.post("/api/auth/challenge", json={"username": "chalcap"})
    assert first.status_code == 200
    second = client.post("/api/auth/challenge", json={"username": "chalcap"})
    assert second.status_code == 503, second.text


def test_active_token_cap_enforced(monkeypatch):
    ident, _ = _register("tokcap")
    ed_priv = ident[0]
    accounts._tokens.clear()
    monkeypatch.setattr(config, "MAX_ACTIVE_TOKENS", 0)
    ch = client.post("/api/auth/challenge", json={"username": "tokcap"}).json()["challenge"]
    sig = _b64(ed_priv.sign(_login_message(ch)))
    ver = client.post("/api/auth/verify", json={"username": "tokcap", "challenge": ch, "sig": sig})
    assert ver.status_code == 503, ver.text


def test_me_requires_valid_token():
    assert client.get("/api/me").status_code == 401
    assert client.get("/api/me", headers={"Authorization": "Bearer nope"}).status_code == 401


def test_register_forbids_extra_fields():
    ident = _new_identity()
    body = _register_body("frank", ident)
    body["admin"] = True
    resp = client.post("/api/register", json=body)
    assert resp.status_code == 422


def test_challenge_endpoint_is_rate_limited():
    # M-03: a dedicated bucket caps challenge minting well below the general
    # /api limiter. Burst = CHALLENGE_RATE_CAPACITY; the next one is 429.
    accounts._challenge_limiter._buckets.clear()
    _register("rl-user")
    ok = 0
    for _ in range(config.CHALLENGE_RATE_CAPACITY):
        if client.post("/api/auth/challenge", json={"username": "rl-user"}).status_code == 200:
            ok += 1
    assert ok == config.CHALLENGE_RATE_CAPACITY
    # The next challenge within the same burst is throttled.
    assert client.post("/api/auth/challenge", json={"username": "rl-user"}).status_code == 429


# --- Pentest 2026-07-27 H-1 (server half) ------------------------------------
# `base64.b64decode(s, validate=True)` rejects out-of-alphabet characters but —
# exactly like the browser's `atob` — silently DISCARDS the trailing slack bits.
# Every key size here is ≡ 2 (mod 3), so every key has FOUR spellings that decode
# to the same bytes. The signature checks operate on those bytes, but what the
# directory STORES and serves is the STRING. A registrant could therefore park a
# non-canonical spelling of their own key in the directory, and the client (which
# canonicalizes what it receives) would report a permanent, unexplainable
# "directory mismatch" against the same person's live handshake.

def _respell(canonical: str) -> str:
    """Another base64 string for the same bytes (vary the discarded slack bits)."""
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    pad = len(canonical) - len(canonical.rstrip("="))
    assert pad, "expected a value with slack bits"
    slack_bits = 2 if pad == 1 else 4
    idx = len(canonical) - pad - 1
    mask = (1 << slack_bits) - 1
    cur = alphabet.index(canonical[idx])
    return canonical[:idx] + alphabet[(cur & ~mask) | ((cur & mask) ^ 1)] + canonical[idx + 1:]


def test_respelling_really_is_the_same_bytes():
    """Ground truth for the finding — otherwise the test below proves nothing."""
    ident = _new_identity()
    alt = _respell(ident[1])
    assert alt != ident[1]
    assert base64.b64decode(alt, validate=True) == base64.b64decode(ident[1], validate=True)


def test_register_rejects_non_canonical_base64():
    ident = _new_identity()
    body = _register_body("canon-user", ident)
    # The SIGNATURE still covers the original message, and the bytes the
    # signature check sees are identical — so this used to register fine and
    # store a key spelling no honest client would ever produce.
    body["ed"] = _respell(body["ed"])
    resp = client.post("/api/register", json=body)
    assert resp.status_code == 422, resp.text
    assert "canonical" in resp.text

    # Every field with slack bits goes through the same gate. (An ML-DSA-65
    # signature is 3309 bytes — a multiple of 3 — so it has no slack to vary and
    # only one spelling exists; nothing to test there.)
    for field in ("mldsa", "sig"):
        body = _register_body(f"canon-{field}", ident)
        body[field] = _respell(body[field])
        assert client.post("/api/register", json=body).status_code == 422, field

    # …and the canonical original is still accepted, unchanged.
    assert client.post("/api/register", json=_register_body("canon-ok", ident)).status_code == 200
