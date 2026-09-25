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


def _login_body(username, ident, challenge_b64):
    """Dual-signed verify body (F-RELAY-006: both keys must sign the challenge)."""
    ed_priv, _ed, _mldsa, mldsa_secret = ident
    msg = _login_message(challenge_b64)
    return {
        "username": username,
        "challenge": challenge_b64,
        "sig": _b64(ed_priv.sign(msg)),
        "mldsa_sig": _b64(ML_DSA_65.sign(mldsa_secret, msg)),
    }


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
    ver = client.post("/api/auth/verify", json=_login_body("ghostuser2", _new_identity(), ch))
    assert ver.status_code == 401


def test_full_login_flow():
    ident, _ = _register("carol")
    ch = client.post("/api/auth/challenge", json={"username": "carol"})
    assert ch.status_code == 200
    challenge = ch.json()["challenge"]
    ver = client.post("/api/auth/verify", json=_login_body("carol", ident, challenge))
    assert ver.status_code == 200, ver.text
    token = ver.json()["token"]

    me = client.get("/api/me", headers={"Authorization": f"Bearer {token}"})
    assert me.status_code == 200
    assert me.json()["username"] == "carol"


def _login(username, ident):
    """Complete a real challenge/response login and return the bearer token."""
    ch = client.post("/api/auth/challenge", json={"username": username}).json()["challenge"]
    r = client.post("/api/auth/verify", json=_login_body(username, ident, ch))
    assert r.status_code == 200, r.text
    return r.json()["token"]


def _me(token):
    return client.get("/api/me", headers={"Authorization": f"Bearer {token}"}).status_code


# --- Pentest 2026-07-29 L-4: session revocation ------------------------------
# There was none. No logout existed, and re-login left the previous bearer
# valid for the full TOKEN_TTL_SEC (3600 s) — verified at the time: the old
# token still answered 200 on /api/me. So a leaked token could not be revoked
# by any action available to the user, including the one everybody tries first.

def test_relogin_does_not_revoke_the_previous_session():
    """Two tabs of the same account must COEXIST.

    The first cut of L-4 retired every other token on login. The fix review
    (M-C) showed that was a self-inflicted DoS: pollMailbox re-authenticates on
    a 401 every 6 s, so two tabs revoked each other in a loop, sustaining ~0.33
    challenges/s against a 0.5/s bucket that — since the M-1 fix — is GLOBAL to
    the relay. Two of one user's tabs ate most of the relay's login capacity;
    three denied login to everybody. Both tabs then sat silently offline for
    sealed mail. Revocation on demand is /auth/logout's job, not login's.
    """
    ident, _ = _register("revoke-relogin")
    first = _login("revoke-relogin", ident)
    assert _me(first) == 200, "precondition: the first token works"

    second = _login("revoke-relogin", ident)
    assert second != first, "a fresh login must mint a new token"
    assert _me(second) == 200, "the new session works"
    assert _me(first) == 200, "M-C: a second tab must not revoke the first"


def test_sessions_per_account_are_capped_with_oldest_evicted():
    """…but not unbounded, or a leaked token outlives every remedy but the TTL."""
    ident, _ = _register("revoke-cap")
    tokens = [_login("revoke-cap", ident) for _ in range(config.MAX_SESSIONS_PER_ACCOUNT)]
    assert all(_me(t) == 200 for t in tokens), "every session up to the cap is live"

    extra = _login("revoke-cap", ident)
    assert _me(extra) == 200, "the newest session works"
    assert _me(tokens[0]) == 401, "the OLDEST session is the one evicted"
    assert all(_me(t) == 200 for t in tokens[1:]), "the rest are untouched"


def test_logout_revokes_the_presented_token():
    ident, _ = _register("revoke-logout")
    token = _login("revoke-logout", ident)
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
    token = _login("revoke-oracle", ident)
    real = client.post("/api/auth/logout", headers={"Authorization": f"Bearer {token}"})
    again = client.post("/api/auth/logout", headers={"Authorization": f"Bearer {token}"})
    bogus = client.post("/api/auth/logout", headers={"Authorization": "Bearer not-a-real-token"})
    none = client.post("/api/auth/logout")
    for r in (again, bogus, none):
        assert (r.status_code, r.json()) == (real.status_code, real.json()), (
            f"logout distinguishes token validity: {r.status_code} {r.json()}"
        )


def test_eviction_and_logout_are_scoped_to_one_account():
    """Neither the cap nor logout may reach another user's sessions."""
    a_ident, _ = _register("revoke-a")
    b_ident, _ = _register("revoke-b")
    b_tok = _login("revoke-b", b_ident)

    # Drive account A past its cap; B must be untouched throughout.
    for _ in range(config.MAX_SESSIONS_PER_ACCOUNT + 2):
        _login("revoke-a", a_ident)
    assert _me(b_tok) == 200, "another account's session survives A's evictions"

    # And A signing out does not touch B either.
    a_tok = _login("revoke-a", a_ident)
    client.post("/api/auth/logout", headers={"Authorization": f"Bearer {a_tok}"})
    assert _me(a_tok) == 401
    assert _me(b_tok) == 200, "another account's session survives A's logout"


def test_login_rejects_wrong_signature():
    _register("dave")
    ch = client.post("/api/auth/challenge", json={"username": "dave"}).json()["challenge"]
    ver = client.post("/api/auth/verify", json=_login_body("dave", _new_identity(), ch))  # wrong keys
    assert ver.status_code == 401


# ---- Pentest 2026-08-07 F-RELAY-006: login is dual-scheme --------------------

def test_login_requires_both_signatures_to_be_valid():
    """Control of the Ed25519 key ALONE must not open the directory session.

    Pre-fix, `sig` was the only proof and the body had no `mldsa_sig` at all,
    so an attacker holding just the classical key (a leak, or a classical
    break) could drain/delete the mailbox and delete vouches. Now a valid
    Ed25519 signature with a wrong ML-DSA one is refused, and vice versa, with
    the same 401 either way (no scheme-level oracle).
    """
    ident, _ = _register("dual-login")
    stranger = _new_identity()

    def fresh():
        return client.post("/api/auth/challenge", json={"username": "dual-login"}).json()["challenge"]

    ch = fresh()
    body = _login_body("dual-login", ident, ch)
    body["mldsa_sig"] = _login_body("dual-login", stranger, ch)["mldsa_sig"]  # Ed OK, PQ wrong
    assert client.post("/api/auth/verify", json=body).status_code == 401

    ch = fresh()
    body = _login_body("dual-login", ident, ch)
    body["sig"] = _login_body("dual-login", stranger, ch)["sig"]  # PQ OK, Ed wrong
    assert client.post("/api/auth/verify", json=body).status_code == 401

    # A verify body with no ML-DSA signature at all is a schema error, not a
    # login: the field is required, so an Ed25519-only client cannot fall back
    # to the weaker proof.
    ch = fresh()
    body = _login_body("dual-login", ident, ch)
    del body["mldsa_sig"]
    assert client.post("/api/auth/verify", json=body).status_code == 422

    # And the honest dual-signed login still works with a fresh challenge.
    assert client.post("/api/auth/verify", json=_login_body("dual-login", ident, fresh())).status_code == 200


def test_challenge_is_one_time():
    ident, _ = _register("erin")
    ch = client.post("/api/auth/challenge", json={"username": "erin"}).json()["challenge"]
    body = _login_body("erin", ident, ch)
    first = client.post("/api/auth/verify", json=body)
    assert first.status_code == 200
    # Replaying the same challenge must fail (consumed).
    second = client.post("/api/auth/verify", json=body)
    assert second.status_code == 400


# ---- abuse / DoS bounds (M1) ---------------------------------------------

def test_api_rate_limit(monkeypatch):
    from relay import KeyedRateLimiter
    # Tiny budget so the limit is deterministic: 3 allowed, then 429. Probed on
    # a directory route: login/register are deliberately NOT on this bucket
    # (see test_junk_directory_traffic_cannot_lock_out_login_or_register).
    monkeypatch.setattr(accounts, "_api_limiter", KeyedRateLimiter(3, 0.001))
    codes = [client.get("/api/users/whoever", params={"t": "x"}).status_code for _ in range(6)]
    assert codes == [404] * 3 + [429] * 3, codes


def test_junk_directory_traffic_cannot_lock_out_login_or_register(monkeypatch):
    """F-RELAY-003 residual / 2026-07-29 M-2: the router-wide /api bucket is
    ONE bucket behind Tor, and login + registration used to sit on it, so ~70
    junk lookups 429'd every login and registration on the relay. They have
    their own buckets and are off the shared one now."""
    from relay import KeyedRateLimiter
    monkeypatch.setattr(accounts, "_api_limiter", KeyedRateLimiter(3, 0.001))
    junk = [client.get(f"/api/users/junk{i}", params={"t": "x"}).status_code for i in range(10)]
    assert junk.count(429) == 7, junk  # the shared bucket is empty...
    # ...and a full registration + login still goes through.
    ident = _new_identity()
    r = client.post("/api/register", json=_register_body("m2-user", ident))
    assert r.status_code == 200, r.text
    ch = client.post("/api/auth/challenge", json={"username": "m2-user"})
    assert ch.status_code == 200, ch.text
    ver = client.post("/api/auth/verify", json=_login_body("m2-user", ident, ch.json()["challenge"]))
    assert ver.status_code == 200, ver.text
    # The routes that stay on it are still throttled by it.
    assert client.get("/api/me", headers={"Authorization": "Bearer " + ver.json()["token"]}).status_code == 429


def test_lookup_rate_limit(monkeypatch):
    from relay import KeyedRateLimiter
    # The lookup path has its own, stricter bucket (anti-enumeration). Phase-7
    # pentest 2026-09-16 F-P7-3: it is charged AFTER the token gate and keyed on
    # the TARGET, so garbage without a token spends nothing and a token holder
    # can only exhaust the one handle they hold a token for.
    monkeypatch.setattr(accounts, "_lookup_limiter", KeyedRateLimiter(3, 0.001))
    ident = _new_identity()
    r = client.post("/api/register", json=_register_body("lookup-target", ident))
    assert r.status_code == 200, r.text
    token = r.json()["lookup_token"]
    # 1. Unauthenticated garbage (no token) never reaches the bucket.
    garbage = [client.get("/api/users/lookup-target", params={"t": "x"}).status_code for _ in range(8)]
    garbage += [client.get("/api/users/lookup-target/vouches", params={"t": "x"}).status_code for _ in range(4)]
    assert garbage == [404] * 12, garbage
    # 2. ...so the target is still reachable with its token afterwards, and the
    #    bundle and vouch-list lookups of one target share its bucket.
    codes = [client.get("/api/users/lookup-target", params={"t": token}).status_code for _ in range(2)]
    codes += [client.get("/api/users/lookup-target/vouches", params={"t": token}).status_code for _ in range(2)]
    codes += [client.get("/api/users/lookup-target", params={"t": token}).status_code]
    assert codes == [200, 200, 200, 429, 429], codes
    # 3. Exhausting one target's bucket says nothing about another's.
    ident2 = _new_identity()
    r = client.post("/api/register", json=_register_body("lookup-other", ident2))
    assert r.status_code == 200, r.text
    assert client.get("/api/users/lookup-other", params={"t": r.json()["lookup_token"]}).status_code == 200


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
    accounts._tokens.clear()
    monkeypatch.setattr(config, "MAX_ACTIVE_TOKENS", 0)
    ch = client.post("/api/auth/challenge", json={"username": "tokcap"}).json()["challenge"]
    ver = client.post("/api/auth/verify", json=_login_body("tokcap", ident, ch))
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


# ---- Pentest 2026-08-07 F-RELAY-003: one client cannot lock everyone out -----

def test_challenge_bucket_is_per_username_not_service_wide():
    """Draining one name's challenge bucket must leave every other name loginable.

    Pre-fix the bucket was keyed per client host, which behind Tor (and on the
    shared clearnet path since M-1) is ONE bucket for the whole relay: the loop
    below at 0.5/s held login shut for every account. The TestClient presents a
    single host, so this test reproduces exactly that topology.
    """
    accounts._challenge_limiter._buckets.clear()
    accounts._challenge_host_limiter._buckets.clear()
    victim, _ = _register("rl-victim")
    for _ in range(config.CHALLENGE_RATE_CAPACITY):
        assert client.post("/api/auth/challenge", json={"username": "rl-attacker"}).status_code == 200
    assert client.post("/api/auth/challenge", json={"username": "rl-attacker"}).status_code == 429
    # The victim, from the SAME host, still gets a challenge and can log in.
    ch = client.post("/api/auth/challenge", json={"username": "rl-victim"})
    assert ch.status_code == 200, ch.text
    assert client.post("/api/auth/verify", json=_login_body("rl-victim", victim, ch.json()["challenge"])).status_code == 200


def test_challenge_host_bucket_bounds_total_churn(monkeypatch):
    # Spreading a flood over many names still hits the (wide) per-host bound.
    from relay import KeyedRateLimiter
    accounts._challenge_limiter._buckets.clear()
    monkeypatch.setattr(accounts, "_challenge_host_limiter", KeyedRateLimiter(5, 0.001))
    codes = [client.post("/api/auth/challenge", json={"username": f"spread-{i}"}).status_code for i in range(8)]
    assert codes == [200] * 5 + [429] * 3, codes


def test_challenge_host_ceiling_is_charged_before_the_per_name_bucket(monkeypatch):
    """Pentest 2026-08-08 item 19: the per-host bucket is the ceiling on what one
    client can make /auth/challenge do, so it is charged FIRST — a request the
    per-name bucket refuses still costs the sender. It used to be charged second,
    so hammering one name was free, and the host bucket was not a ceiling."""
    from relay import KeyedRateLimiter
    monkeypatch.setattr(accounts, "_challenge_host_limiter", KeyedRateLimiter(3, 0.001))
    monkeypatch.setattr(accounts, "_challenge_limiter", KeyedRateLimiter(1, 0.001))
    assert client.post("/api/auth/challenge", json={"username": "one-name"}).status_code == 200
    assert client.post("/api/auth/challenge", json={"username": "one-name"}).status_code == 429  # per-name
    assert client.post("/api/auth/challenge", json={"username": "one-name"}).status_code == 429  # per-name
    # Those two refusals were paid for out of the host budget: it is empty now.
    assert client.post("/api/auth/challenge", json={"username": "other-a"}).status_code == 429


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


# ---- Fix review 2026-09-21 of the F-RELAY-003/006 fixes ------------------------

def test_username_regex_rejects_trailing_newline():
    # Python's `$` matches before a final newline; fullmatch does not.
    assert client.post("/api/auth/challenge", json={"username": "alice\n"}).status_code == 422
    ident = _new_identity()
    body = _register_body("newline\n", ident)
    body["username"] = "newline\n"
    assert client.post("/api/register", json=body).status_code == 422


def test_challenge_buckets_are_pruned_when_idle(monkeypatch):
    """Per-username keys are attacker-chosen: an idle bucket must be collected
    even though it is not full (tokens are only recomputed inside allow())."""
    from relay import KeyedRateLimiter
    # "Force a prune" is a -inf sentinel, not 0.0: time.monotonic() counts from
    # boot on Linux, so on a machine up for under 60 s (a fresh CI runner, a
    # restarted container) 0.0 read as "pruned just now", the prune was skipped
    # and this test failed intermittently. Same lesson as Room's
    # turnaway_notified_at (test_ws.py).
    lim = KeyedRateLimiter(10, 0.5)
    for i in range(500):
        assert lim.allow(f"u:probe-{i}")
    assert len(lim._buckets) == 500
    # Nothing is idle yet: a prune keeps them.
    lim._last_prune = float("-inf")
    lim.allow("u:keeper")
    assert len(lim._buckets) == 501
    # Make every bucket look idle for longer than a full refill (capacity/refill = 20 s, floor 60 s).
    for b in lim._buckets.values():
        b.last -= 61.0
    lim._last_prune = float("-inf")
    lim.allow("u:after")
    assert len(lim._buckets) == 1, "idle buckets must be dropped regardless of fill level"


def test_verify_unknown_user_does_the_same_work_as_known_user():
    # Timing-oracle guard: the unknown-user path must run both verifications
    # against a decoy, not return early. Asserted structurally (the decoys exist
    # and are well-formed) and behaviourally (still 401, never 404/200).
    assert len(base64.b64decode(accounts._DECOY_ED_PUB_B64)) == config.ED25519_PUB_BYTES
    assert len(base64.b64decode(accounts._DECOY_MLDSA_PUB_B64)) == config.MLDSA65_PUB_BYTES
    ch = client.post("/api/auth/challenge", json={"username": "ghost-timing"}).json()["challenge"]
    assert client.post("/api/auth/verify", json=_login_body("ghost-timing", _new_identity(), ch)).status_code == 401


# --- Phase-7 pentest 2026-09-16 F-P7-12: every request string is bounded -------

@pytest.mark.parametrize("field", ["ed", "mldsa", "sig", "mldsa_sig", "ecdh", "mlkem"])
def test_register_fields_are_length_bounded(field):
    ident = _new_identity()
    body = _register_body("bounded-user", ident)
    body[field] = "A" * 5000
    r = client.post("/api/register", json=body)
    assert r.status_code == 422, r.text
    assert any(e.get("type") == "string_too_long" for e in r.json()["detail"]), r.text


@pytest.mark.parametrize("field", ["challenge", "sig", "mldsa_sig"])
def test_verify_fields_are_length_bounded(field):
    body = {"username": "whoever", "challenge": "A" * 44, "sig": "A" * 88, "mldsa_sig": "A" * 4412}
    body[field] = "A" * 5000
    r = client.post("/api/auth/verify", json=body)
    assert r.status_code == 422, r.text
    assert any(e.get("type") == "string_too_long" for e in r.json()["detail"]), r.text


def test_db_connections_are_closed_after_use():
    """Every `with _db() as conn:` used to leave the connection (an fd plus a
    WAL read mark) to the garbage collector. The block now closes it — and
    still commits on success and rolls back on an exception."""
    import sqlite3
    with accounts._db() as conn:
        conn.execute("CREATE TABLE IF NOT EXISTS _closetest (x INTEGER)")
        conn.execute("INSERT INTO _closetest VALUES (1)")
    with pytest.raises(sqlite3.ProgrammingError):
        conn.execute("SELECT 1")
    with pytest.raises(RuntimeError):
        with accounts._db() as conn2:
            conn2.execute("INSERT INTO _closetest VALUES (2)")
            raise RuntimeError("abort")
    with pytest.raises(sqlite3.ProgrammingError):
        conn2.execute("SELECT 1")
    with accounts._db() as conn3:
        assert [r[0] for r in conn3.execute("SELECT x FROM _closetest")] == [1]
        conn3.execute("DROP TABLE _closetest")
