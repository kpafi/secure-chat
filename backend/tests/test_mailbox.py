"""Tests for the store-and-forward mailbox.

Must hold: posting is gated by the recipient's lookup token (identical 404 for
wrong token / unknown user), fetch requires login and deletes what it returns,
and every bound (envelope size, per-inbox cap, TTL) is enforced.
"""
import base64
import os
import sys
import tempfile
import time
from pathlib import Path

_TMP_DB = os.path.join(tempfile.mkdtemp(), "test_mailbox.db")
os.environ["SECURE_CHAT_DB"] = _TMP_DB
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402
from cryptography.hazmat.primitives import serialization  # noqa: E402
from dilithium_py.ml_dsa import ML_DSA_65  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from main import app  # noqa: E402
import accounts  # noqa: E402
import mailbox  # noqa: E402
import config  # noqa: E402

client = TestClient(app)


@pytest.fixture(autouse=True)
def _reset_limiters():
    accounts._api_limiter._buckets.clear()
    accounts._lookup_limiter._buckets.clear()
    accounts._challenge_limiter._buckets.clear()
    mailbox._post_limiter._buckets.clear()
    yield


def _b64(b):
    return base64.b64encode(b).decode("ascii")


def _register(username):
    ed_priv = Ed25519PrivateKey.generate()
    ed = _b64(ed_priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw))
    mldsa_pub, mldsa_secret = ML_DSA_65.keygen()
    mldsa = _b64(mldsa_pub)
    msg = b"\n".join([b"secure-chat/register/v1", username.encode(), ed.encode(), mldsa.encode()])
    r = client.post("/api/register", json={
        "username": username, "ed": ed, "mldsa": mldsa,
        "sig": _b64(ed_priv.sign(msg)), "mldsa_sig": _b64(ML_DSA_65.sign(mldsa_secret, msg)),
    })
    assert r.status_code == 200
    # F-RELAY-006: login is dual-scheme now, so the ML-DSA secret has to survive.
    return {"username": username, "token": r.json()["lookup_token"],
            "ed_priv": ed_priv, "mldsa_secret": mldsa_secret}


def _login(ident):
    ch = client.post("/api/auth/challenge", json={"username": ident["username"]}).json()["challenge"]
    msg = b"secure-chat/login/v1\n" + base64.b64decode(ch)
    r = client.post("/api/auth/verify", json={
        "username": ident["username"], "challenge": ch,
        "sig": _b64(ident["ed_priv"].sign(msg)),
        "mldsa_sig": _b64(ML_DSA_65.sign(ident["mldsa_secret"], msg)),
    })
    assert r.status_code == 200
    return r.json()["token"]


def _auth(token):
    return {"Authorization": f"Bearer {token}"}


def test_post_fetch_delete_roundtrip():
    bob = _register("mb-bob")
    tok = _login(bob)

    r = client.post(f"/api/mailbox/{bob['username']}", params={"t": bob["token"]},
                    json={"envelope": '{"v":1,"ct":"abc"}'})
    assert r.status_code == 200
    r = client.post(f"/api/mailbox/{bob['username']}", params={"t": bob["token"]},
                    json={"envelope": '{"v":1,"ct":"def"}'})
    assert r.status_code == 200

    # Fetch returns both in order and empties the box.
    r = client.get("/api/mailbox", headers=_auth(tok))
    assert r.status_code == 200
    msgs = r.json()["messages"]
    assert [m["envelope"] for m in msgs] == ['{"v":1,"ct":"abc"}', '{"v":1,"ct":"def"}']
    assert client.get("/api/mailbox", headers=_auth(tok)).json()["messages"] == []


def test_post_is_token_gated_and_not_an_oracle():
    bob = _register("mb-carol")
    r1 = client.post(f"/api/mailbox/{bob['username']}", params={"t": "wrong"},
                     json={"envelope": "x"})
    r2 = client.post("/api/mailbox/mb-ghost", params={"t": "wrong"}, json={"envelope": "x"})
    assert r1.status_code == r2.status_code == 404
    assert r1.json() == r2.json()


def test_fetch_requires_login():
    assert client.get("/api/mailbox").status_code == 401
    assert client.get("/api/mailbox", headers=_auth("bogus")).status_code == 401


def test_bounds():
    bob = _register("mb-dave")
    # Envelope size cap (pydantic max_length).
    big = "a" * (config.MAX_ENVELOPE_BYTES + 1)
    r = client.post(f"/api/mailbox/{bob['username']}", params={"t": bob["token"]},
                    json={"envelope": big})
    assert r.status_code == 422
    # Non-printable-ASCII refused.
    r = client.post(f"/api/mailbox/{bob['username']}", params={"t": bob["token"]},
                    json={"envelope": "abcé"})
    assert r.status_code == 422

    # Per-recipient cap.
    old_cap = config.MAX_MAILBOX_PER_RECIPIENT
    config.MAX_MAILBOX_PER_RECIPIENT = 3
    try:
        for i in range(3):
            mailbox._post_limiter._buckets.clear()
            assert client.post(f"/api/mailbox/{bob['username']}", params={"t": bob["token"]},
                               json={"envelope": f"m{i}"}).status_code == 200
        mailbox._post_limiter._buckets.clear()
        r = client.post(f"/api/mailbox/{bob['username']}", params={"t": bob["token"]},
                        json={"envelope": "overflow"})
        assert r.status_code == 429
    finally:
        config.MAX_MAILBOX_PER_RECIPIENT = old_cap
    # Drain for other tests.
    client.get("/api/mailbox", headers=_auth(_login(bob)))


def test_ttl_prune():
    bob = _register("mb-eve")
    tok = _login(bob)
    assert client.post(f"/api/mailbox/{bob['username']}", params={"t": bob["token"]},
                       json={"envelope": "stale"}).status_code == 200
    # Age the row past the TTL directly in the DB, then any access prunes it.
    with accounts._db() as conn:
        conn.execute("UPDATE mailbox SET created_at = ?",
                     (int(time.time()) - config.MAILBOX_TTL_SEC - 5,))
    assert client.get("/api/mailbox", headers=_auth(tok)).json()["messages"] == []
