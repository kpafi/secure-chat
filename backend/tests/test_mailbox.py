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
    return {"username": username, "token": r.json()["lookup_token"], "ed_priv": ed_priv,
            "mldsa_secret": mldsa_secret}


def _login(ident):
    ch = client.post("/api/auth/challenge", json={"username": ident["username"]}).json()["challenge"]
    msg = b"secure-chat/login/v1\n" + base64.b64decode(ch)
    r = client.post("/api/auth/verify", json={
        "username": ident["username"], "challenge": ch,
        "sig": _b64(ident["ed_priv"].sign(msg)),
        "mldsa_sig": _b64(ML_DSA_65.sign(ident["mldsa_secret"], msg)),
    })
    assert r.status_code == 200, r.text
    return r.json()["token"]


def _auth(token):
    return {"Authorization": f"Bearer {token}"}


def _env(n=None, fill="A"):
    """A syntactically valid envelope of `n` bytes (default: the minimum)."""
    return fill * (n or config.MIN_ENVELOPE_BYTES)


def test_unauthenticated_fetch_flood_cannot_deny_authenticated_polling(monkeypatch):
    """F-P7-2: the fetch bucket used to be keyed per HOST and charged BEFORE the
    session check — behind Tor one bucket for everybody, drainable with no
    account (~400 unauthenticated GETs made every honest poll 429). It is per
    authenticated user now, charged after `current_user`."""
    from relay import KeyedRateLimiter
    monkeypatch.setattr(mailbox, "_fetch_limiter", KeyedRateLimiter(2, 0.001))
    bob = _register("f2-bob")
    tok = _login(bob)
    flood = [client.get("/api/mailbox").status_code for _ in range(10)]
    flood += [client.get("/api/mailbox", headers=_auth("nope")).status_code for _ in range(10)]
    assert flood == [401] * 20, flood
    codes = [client.get("/api/mailbox", headers=_auth(tok)).status_code for _ in range(3)]
    assert codes == [200, 200, 429], codes  # bob's OWN bucket, untouched by the flood
    alice = _register("f2-alice")
    assert client.get("/api/mailbox", headers=_auth(_login(alice))).status_code == 200, "another user's bucket is separate"


def test_post_fetch_delete_roundtrip():
    bob = _register("mb-bob")
    tok = _login(bob)

    r = client.post(f"/api/mailbox/{bob['username']}", params={"t": bob["token"]},
                    json={"envelope": _env(fill="a")})
    assert r.status_code == 200
    r = client.post(f"/api/mailbox/{bob['username']}", params={"t": bob["token"]},
                    json={"envelope": _env(fill="b")})
    assert r.status_code == 200

    # Fetch returns both in order and empties the box.
    r = client.get("/api/mailbox", headers=_auth(tok))
    assert r.status_code == 200
    msgs = r.json()["messages"]
    assert [m["envelope"] for m in msgs] == [_env(fill="a"), _env(fill="b")]
    assert client.get("/api/mailbox", headers=_auth(tok)).json()["messages"] == []


def test_post_is_token_gated_and_not_an_oracle():
    bob = _register("mb-carol")
    r1 = client.post(f"/api/mailbox/{bob['username']}", params={"t": "wrong"},
                     json={"envelope": _env(fill="x")})
    r2 = client.post("/api/mailbox/mb-ghost", params={"t": "wrong"}, json={"envelope": _env(fill="x")})
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
                    json={"envelope": _env() + "é"})
    assert r.status_code == 422
    # §9 I-2: `$` matched before a trailing newline, so this used to pass the
    # printable-ASCII check.
    r = client.post(f"/api/mailbox/{bob['username']}", params={"t": bob["token"]},
                    json={"envelope": _env() + "\n"})
    assert r.status_code == 422, r.text

    # Per-recipient cap.
    old_cap = config.MAX_MAILBOX_PER_RECIPIENT
    config.MAX_MAILBOX_PER_RECIPIENT = 3
    try:
        for i in range(3):
            mailbox._post_limiter._buckets.clear()
            assert client.post(f"/api/mailbox/{bob['username']}", params={"t": bob["token"]},
                               json={"envelope": _env(fill=str(i))}).status_code == 200
        mailbox._post_limiter._buckets.clear()
        r = client.post(f"/api/mailbox/{bob['username']}", params={"t": bob["token"]},
                        json={"envelope": _env(fill="o")})
        assert r.status_code == 429
    finally:
        config.MAX_MAILBOX_PER_RECIPIENT = old_cap
    # Drain for other tests.
    client.get("/api/mailbox", headers=_auth(_login(bob)))


def test_ttl_prune():
    bob = _register("mb-eve")
    tok = _login(bob)
    assert client.post(f"/api/mailbox/{bob['username']}", params={"t": bob["token"]},
                       json={"envelope": _env(fill="s")}).status_code == 200
    # Age the row past the TTL directly in the DB, then any access prunes it.
    with accounts._db() as conn:
        conn.execute("UPDATE mailbox SET created_at = ?",
                     (int(time.time()) - config.MAILBOX_TTL_SEC - 5,))
    assert client.get("/api/mailbox", headers=_auth(tok)).json()["messages"] == []


# ---- Pentest 2026-08-07 F-RELAY-004: POST bucket is per inbox, behind the gate --

def test_unauthenticated_posts_cannot_burn_the_mailbox_bucket():
    """A caller without the recipient's lookup token must not consume ANY bucket.

    Pre-fix the limiter ran as a `Depends` before the token gate and was keyed
    per host, so a flood of token-less POSTs (identical 404s) from one client
    exhausted the single shared bucket and every honest sender got 429 for
    every inbox. The TestClient is one host, so this reproduces that topology.
    """
    mailbox._post_limiter._buckets.clear()
    bob = _register("burn-bob")
    for _ in range(config.MAILBOX_RATE_CAPACITY + 5):
        r = client.post("/api/mailbox/burn-bob", params={"t": "wrong"}, json={"envelope": _env()})
        assert r.status_code == 404, r.text  # identical 404, never 429
    for _ in range(config.MAILBOX_RATE_CAPACITY + 5):
        r = client.post("/api/mailbox/nobody-here", params={"t": "wrong"}, json={"envelope": _env()})
        assert r.status_code == 404, r.text
    # The honest sender, from the SAME host, is not throttled.
    r = client.post("/api/mailbox/burn-bob", params={"t": bob["token"]}, json={"envelope": _env(fill="h")})
    assert r.status_code == 200, r.text


def test_mailbox_post_bucket_is_per_recipient(monkeypatch):
    """Flooding one inbox (with its token) throttles that inbox only."""
    mailbox._post_limiter._buckets.clear()
    # Freeze the refill: at 1 token/s, a slow CI runner that needs over a
    # second for the burst below earned one extra token and failed with 31
    # accepted posts instead of 30. The test is about the per-recipient key,
    # not about refill timing.
    monkeypatch.setattr(mailbox._post_limiter, "_refill", 0.0)
    bob = _register("flood-bob")
    carol = _register("flood-carol")
    codes = [
        client.post("/api/mailbox/flood-bob", params={"t": bob["token"]}, json={"envelope": _env()}).status_code
        for _ in range(config.MAILBOX_RATE_CAPACITY + 3)
    ]
    assert codes.count(200) == config.MAILBOX_RATE_CAPACITY, codes
    assert codes[-1] == 429, codes
    # carol's inbox, same host, is untouched.
    r = client.post("/api/mailbox/flood-carol", params={"t": carol["token"]}, json={"envelope": _env(fill="c")})
    assert r.status_code == 200, r.text


# ---- F-RELAY-008 / F-P7-1: the storage budget (ported from phase7-local) ------

def test_envelopes_have_a_minimum_size():
    """F-P7-1: a one-byte envelope only ever existed to spend budget. Every
    envelope the client sends is a sealed.seal() output (>1.5 KiB)."""
    bob = _register("f1-min")
    r = client.post("/api/mailbox/f1-min", params={"t": bob["token"]},
                    json={"envelope": "A" * (config.MIN_ENVELOPE_BYTES - 1)})
    assert r.status_code == 422, r.text
    assert client.post("/api/mailbox/f1-min", params={"t": bob["token"]}, json={"envelope": _env()}).status_code == 200
    client.get("/api/mailbox", headers=_auth(_login(bob)))


def _clear_mailbox():
    with accounts._db() as conn:
        conn.execute("DELETE FROM mailbox")


def test_mailbox_budget_is_bytes_and_evicts_oldest(monkeypatch):
    """F-RELAY-008 / F-P7-1: the server-wide budget is BYTES, and when it is
    full the OLDEST queued mail is evicted instead of a relay-wide 503 "storage
    full" (which ~500 throwaway accounts could hold for the whole 14-day TTL).
    The per-inbox share stays a hard 429 — the recipient can fetch."""
    _clear_mailbox()
    n = config.MIN_ENVELOPE_BYTES
    monkeypatch.setattr(config, "MAX_MAILBOX_TOTAL_BYTES", 3 * n)
    monkeypatch.setattr(config, "MAX_MAILBOX_PER_RECIPIENT_BYTES", 2 * n)
    bob = _register("f1-bob")
    alice = _register("f1-alice")

    def post(who, fill):
        return client.post(f"/api/mailbox/{who['username']}", params={"t": who["token"]},
                           json={"envelope": _env(n, fill)})

    assert post(bob, "1").status_code == 200
    assert post(bob, "2").status_code == 200
    r = post(bob, "3")
    assert r.status_code == 429 and "inbox full" in r.text, r.text  # bob's share (2n) is hard
    assert post(alice, "a").status_code == 200                      # 3n total: full
    assert post(alice, "b").status_code == 200                      # evicts bob's oldest ("1"), never refuses
    with accounts._db() as conn:
        rows = [(r["recipient"], r["envelope"][0])
                for r in conn.execute("SELECT recipient, envelope FROM mailbox ORDER BY id").fetchall()]
    assert rows == [("f1-bob", "2"), ("f1-alice", "a"), ("f1-alice", "b")], rows
    got = client.get("/api/mailbox", headers=_auth(_login(alice))).json()["messages"]
    assert [m["envelope"][0] for m in got] == ["a", "b"], "new mail was delivered under a full budget"
    _clear_mailbox()


def test_mailbox_row_cap_evicts_oldest_instead_of_503(monkeypatch):
    """Master's shape: the row cap was a relay-wide 503 "mailbox storage full".
    It now bounds the table and evicts the oldest row to fit."""
    _clear_mailbox()
    monkeypatch.setattr(config, "MAX_MAILBOX_TOTAL", 2)
    bob = _register("f1-rows")
    for fill in "xyz":
        r = client.post("/api/mailbox/f1-rows", params={"t": bob["token"]}, json={"envelope": _env(fill=fill)})
        assert r.status_code == 200, r.text
    got = client.get("/api/mailbox", headers=_auth(_login(bob))).json()["messages"]
    assert [m["envelope"][0] for m in got] == ["y", "z"], got


# ---- §9 L-2 / master-only: POST throttling, prune placement, sqlite busy -----

def test_post_host_ceiling_bounds_unauthenticated_posts(monkeypatch):
    """The mailbox POST route had NO pre-gate bound on master (config claimed
    the /api limiter covered it; the mailbox router was never on it). A
    generous per-host ceiling now sits in front of the token gate."""
    from relay import KeyedRateLimiter
    monkeypatch.setattr(mailbox, "_post_host_limiter", KeyedRateLimiter(3, 0.001))
    codes = [client.post(f"/api/mailbox/nobody{i}", params={"t": "x"}, json={"envelope": _env()}).status_code
             for i in range(6)]
    assert codes == [404] * 3 + [429] * 3, codes


def test_post_flood_cannot_deny_authenticated_fetch(monkeypatch):
    """6604d9e M-1: one pre-gate host bucket on BOTH verbs let an
    unauthenticated POST flood deny every authenticated GET. The POST ceiling
    is POST-only; GET is gated by auth and its per-user bucket."""
    from relay import KeyedRateLimiter
    monkeypatch.setattr(mailbox, "_post_host_limiter", KeyedRateLimiter(3, 0.001))
    bob = _register("m1-bob")
    tok = _login(bob)
    flood = [client.post(f"/api/mailbox/nobody{i}", params={"t": "x"}, json={"envelope": _env()}).status_code
             for i in range(10)]
    assert 429 in flood and 404 in flood, flood  # the POST ceiling is exhausted...
    assert client.get("/api/mailbox", headers=_auth(tok)).status_code == 200, "...and GET does not share it"


def test_nothing_is_written_before_the_token_gate(monkeypatch):
    """§9 L-2: the TTL prune (a write-locking DELETE) ran before the token gate,
    so every unauthenticated POST took the database write lock — and queued
    behind any other writer — before being refused (the DELETE was then rolled
    back with the 404, so only the LOCK is observable, not the data).

    Observed directly: another connection holds the write lock; a refused POST
    must still answer its 404 (it only reads, and WAL readers do not block),
    while an accepted POST does need the lock (positive control) and prunes
    once it gets it."""
    import sqlite3
    _clear_mailbox()
    bob = _register("l2-bob")
    with accounts._db() as conn:
        conn.execute("INSERT INTO mailbox (recipient, envelope, created_at) VALUES (?,?,?)",
                      ("l2-expired", _env(), int(time.time()) - config.MAILBOX_TTL_SEC - 5))

    def fast_db():
        conn = accounts._db()
        conn.execute("PRAGMA busy_timeout=200")  # fail fast instead of 15 s
        return conn

    monkeypatch.setattr(mailbox, "_db", fast_db)
    blocker = sqlite3.connect(config.DB_PATH)
    blocker.execute("BEGIN IMMEDIATE")  # hold the write lock
    try:
        for recipient, t in (("l2-bob", "wrong"), ("l2-bob", ""), ("l2-ghost", "x")):
            r = client.post(f"/api/mailbox/{recipient}", params={"t": t}, json={"envelope": _env()})
            assert r.status_code == 404, (
                f"an unauthenticated POST needed the write lock before the gate: {r.status_code} {r.text}")
        r = client.post("/api/mailbox/l2-bob", params={"t": bob["token"]}, json={"envelope": _env()})
        assert r.status_code == 503, "positive control: an accepted POST writes, so it waits for the lock"
    finally:
        blocker.rollback()
        blocker.close()
    assert client.post("/api/mailbox/l2-bob", params={"t": bob["token"]}, json={"envelope": _env()}).status_code == 200
    with accounts._db() as conn:
        left = conn.execute("SELECT COUNT(*) FROM mailbox WHERE recipient = 'l2-expired'").fetchone()[0]
    assert left == 0, "the prune must still run for accepted posts"
    _clear_mailbox()


def test_prune_is_indexed_on_created_at():
    """§9 L-2: the prune's `WHERE created_at < ?` scanned the whole table under
    the write lock; it uses an index now."""
    with accounts._db() as conn:
        plan = " ".join(str(tuple(r)) for r in conn.execute(
            "EXPLAIN QUERY PLAN DELETE FROM mailbox WHERE created_at < ?", (0,)).fetchall())
    assert "idx_mailbox_created" in plan, plan


def test_sqlite_waits_for_the_lock_and_maps_failure_to_a_bare_503(monkeypatch, caplog):
    """§9 L-2: no busy_timeout (sqlite's default 5 s) and no handler, so a
    "database is locked" under a write flood was a 500 plus a traceback on
    disk. Connections now wait 15 s, and what still fails is a bare 503."""
    import sqlite3
    with accounts._db() as conn:
        assert conn.execute("PRAGMA busy_timeout").fetchone()[0] == 15000
    bob = _register("l2-busy")
    tok = _login(bob)

    def locked():
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(mailbox, "_db", locked)
    r = client.get("/api/mailbox", headers=_auth(tok))
    assert (r.status_code, r.text) == (503, "busy"), (r.status_code, r.text)
    assert "database is locked" not in caplog.text, "the failure must not be logged with its traceback"


def test_per_inbox_cap_holds_under_concurrent_posts(monkeypatch):
    """The cap checks run inside the write transaction the prune opens, so
    concurrent POSTs (sync handlers on the threadpool) cannot all read the same
    pre-insert count and overshoot the per-inbox cap."""
    import concurrent.futures as cf
    _clear_mailbox()
    monkeypatch.setattr(config, "MAX_MAILBOX_PER_RECIPIENT", 3)
    monkeypatch.setattr(mailbox._post_limiter, "_refill", 0.0)
    bob = _register("race-bob")

    def post(i):
        return client.post("/api/mailbox/race-bob", params={"t": bob["token"]},
                           json={"envelope": _env(fill=str(i % 10))}).status_code

    for _ in range(5):
        mailbox._post_limiter._buckets.clear()
        with cf.ThreadPoolExecutor(max_workers=12) as ex:
            codes = list(ex.map(post, range(12)))
        with accounts._db() as conn:
            n = conn.execute("SELECT COUNT(*) FROM mailbox WHERE recipient = 'race-bob'").fetchone()[0]
        assert n <= 3, f"per-inbox cap overshot under concurrency: {n} rows, codes {codes}"
        _clear_mailbox()
