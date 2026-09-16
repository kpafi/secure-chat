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
    mailbox._post_global_limiter._buckets.clear()
    mailbox._fetch_limiter._buckets.clear()
    mailbox._host_limiter._buckets.clear()
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


# ---- Phase-7 pentest 2026-09-16: F-P7-1, F-P7-2, F-P7-4 ------------------------

def test_unauthenticated_fetch_flood_cannot_deny_authenticated_polling(monkeypatch):
    """F-P7-2: the fetch bucket used to be keyed per HOST and charged BEFORE the
    token gate — behind Tor one bucket for everybody, drainable with no account.
    It is per authenticated user now, charged after `current_user`."""
    from relay import KeyedRateLimiter
    monkeypatch.setattr(mailbox, "_fetch_limiter", KeyedRateLimiter(2, 0.001))
    bob = _register("f2-bob")
    tok = _login(bob)
    flood = [client.get("/api/mailbox").status_code for _ in range(20)]
    assert flood == [401] * 20, flood
    codes = [client.get("/api/mailbox", headers=_auth(tok)).status_code for _ in range(3)]
    assert codes == [200, 200, 429], codes  # bob's OWN bucket, untouched by the flood
    alice = _register("f2-alice")
    assert client.get("/api/mailbox", headers=_auth(_login(alice))).status_code == 200, "another user's bucket is separate"


def test_unauthenticated_posts_cannot_spend_the_global_post_budget(monkeypatch):
    """F-P7-4: the global ceiling was charged before the 404 for a nonexistent
    recipient, so posts with a bogus token to made-up handles drained it. It is
    charged after the token gate now."""
    from relay import KeyedRateLimiter
    monkeypatch.setattr(mailbox, "_post_global_limiter", KeyedRateLimiter(2, 0.001))
    bob = _register("f4-bob")
    garbage = [client.post(f"/api/mailbox/nobody{i}", params={"t": "x"}, json={"envelope": "QUJD"}).status_code for i in range(20)]
    assert garbage == [404] * 20, garbage
    wrong = [client.post("/api/mailbox/f4-bob", params={"t": "x"}, json={"envelope": "QUJD"}).status_code for _ in range(5)]
    assert wrong == [404] * 5, wrong
    codes = [client.post("/api/mailbox/f4-bob", params={"t": bob["token"]}, json={"envelope": "QUJD"}).status_code for _ in range(3)]
    assert codes == [200, 200, 429], codes  # the ceiling still exists, for real senders


def test_mailbox_budget_is_bytes_not_rows(monkeypatch):
    """F-P7-1: a 100 000-ROW budget let ~100 KB of one-byte envelopes shut off
    mail for everyone for the full TTL. Bytes, server-wide and per inbox."""
    monkeypatch.setattr(config, "MAX_MAILBOX_TOTAL_BYTES", 100)
    monkeypatch.setattr(config, "MAX_MAILBOX_PER_RECIPIENT_BYTES", 60)
    bob = _register("f1-bob")
    alice = _register("f1-alice")
    big = "A" * 40
    assert client.post("/api/mailbox/f1-bob", params={"t": bob["token"]}, json={"envelope": big}).status_code == 200
    r = client.post("/api/mailbox/f1-bob", params={"t": bob["token"]}, json={"envelope": big})
    assert r.status_code == 429 and "inbox full" in r.text, r.text  # 80 > 60 for this inbox
    assert client.post("/api/mailbox/f1-alice", params={"t": alice["token"]}, json={"envelope": big}).status_code == 200
    r = client.post("/api/mailbox/f1-alice", params={"t": alice["token"]}, json={"envelope": "B" * 30})
    assert r.status_code == 503 and "storage full" in r.text, r.text  # 40 + 40 + 30 > 100 server-wide
    assert client.post("/api/mailbox/f1-alice", params={"t": alice["token"]}, json={"envelope": "C" * 10}).status_code == 200


def test_mail_to_an_inbox_that_never_fetched_expires_early():
    """F-P7-1: rows for a recipient that has NEVER fetched die on the short TTL;
    an inbox that has fetched keeps its mail for the full TTL."""
    bob = _register("f1-never")      # never fetches — an attacker's throwaway
    alice = _register("f1-fetcher")
    assert client.get("/api/mailbox", headers=_auth(_login(alice))).status_code == 200  # alice has fetched once
    for who in (bob, alice):
        assert client.post(f"/api/mailbox/{who['username']}", params={"t": who["token"]}, json={"envelope": "QUJD"}).status_code == 200
    old = int(time.time()) - config.MAILBOX_UNFETCHED_TTL_SEC - 1
    with accounts._db() as conn:
        conn.execute("UPDATE mailbox SET created_at = ? WHERE recipient IN (?, ?)", (old, "f1-never", "f1-fetcher"))
    # Any prune trigger — here a post to a third inbox.
    carol = _register("f1-carol")
    assert client.post("/api/mailbox/f1-carol", params={"t": carol["token"]}, json={"envelope": "QUJD"}).status_code == 200
    with accounts._db() as conn:
        left = {r["recipient"] for r in conn.execute("SELECT recipient FROM mailbox").fetchall()}
    assert "f1-never" not in left, "mail to an inbox nobody ever fetched must expire on the short TTL"
    assert "f1-fetcher" in left, "an inbox that has fetched keeps its mail until the full TTL"
