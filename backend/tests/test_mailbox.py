"""Tests for the store-and-forward mailbox.

Must hold: posting is gated by the recipient's lookup token (identical 404 for
wrong token / unknown user), fetch requires login and deletes what it returns,
and every bound (envelope size, per-inbox cap, TTL) is enforced.
"""
import base64
import logging
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
    # Raw edits bypass the maintained counters (F2), so resync them.
    with accounts._db() as conn:
        conn.execute("DELETE FROM mailbox")
        mailbox._rebuild_counters(conn)


def test_mailbox_budget_is_bytes_and_evicts_from_the_heaviest_inbox(monkeypatch):
    """F-RELAY-008 / F-P7-1: the server-wide budget is BYTES, and when it is
    full queued mail is evicted — from the HEAVIEST inbox, oldest first (fix
    review F1) — instead of a relay-wide 503 "storage full" (which ~500
    throwaway accounts could hold for the whole 14-day TTL). The per-inbox
    share stays a hard 429 — the recipient can fetch."""
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
    assert post(alice, "b").status_code == 200                      # bob is heaviest: his oldest ("1") goes
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
        conn.execute("INSERT INTO mailbox (recipient, envelope, created_at, size) VALUES (?,?,?,?)",
                      ("l2-expired", _env(), int(time.time()) - config.MAILBOX_TTL_SEC - 5, len(_env())))
        mailbox._rebuild_counters(conn)

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


def _traced(monkeypatch):
    """Record every SQL statement mailbox.py runs (parameters expanded)."""
    seen = []

    def traced_db():
        conn = accounts._db()
        conn.set_trace_callback(seen.append)
        return conn

    monkeypatch.setattr(mailbox, "_db", traced_db)
    return seen


def _full_scans(statements):
    """Statements whose query plan reads the whole mailbox table."""
    import re
    bad = []
    with accounts._db() as conn:
        for sql in statements:
            head = sql.lstrip().split(None, 1)[0].upper() if sql.strip() else ""
            if head not in ("SELECT", "INSERT", "UPDATE", "DELETE"):
                continue
            plan = [r[3] for r in conn.execute("EXPLAIN QUERY PLAN " + sql).fetchall()]
            if any(re.search(r"SCAN mailbox(\s|$)", line) for line in plan):
                bad.append((sql[:120], plan))
    return bad


def test_request_path_never_scans_the_mailbox_table(monkeypatch):
    """§9 L-2 and fix review F2: the first budget fix ran
    SUM(LENGTH(CAST(envelope AS BLOB))) over the WHOLE table on every accepted
    POST, inside the write transaction (~60 ms at 256 MiB: POST throughput
    capped at ~16/s relay-wide, polls stalled for seconds). Every statement a
    POST (including prune and eviction) and a fetch run must now be an index
    or counter lookup — no `SCAN mailbox` in any query plan."""
    _clear_mailbox()
    n = config.MIN_ENVELOPE_BYTES
    monkeypatch.setattr(config, "MAX_MAILBOX_TOTAL_BYTES", 3 * n)
    bob = _register("f2-scan-bob")
    alice = _register("f2-scan-alice")
    with accounts._db() as conn:  # one expired row, so the prune really deletes
        conn.execute("INSERT INTO mailbox (recipient, envelope, created_at, size) VALUES (?,?,?,?)",
                     ("f2-expired", _env(), int(time.time()) - config.MAILBOX_TTL_SEC - 5, n))
        mailbox._rebuild_counters(conn)
    tok = _login(bob)
    seen = _traced(monkeypatch)
    for who, fill in ((bob, "1"), (bob, "2"), (alice, "a"), (alice, "b")):  # the last one evicts
        r = client.post(f"/api/mailbox/{who['username']}", params={"t": who["token"]},
                        json={"envelope": _env(n, fill)})
        assert r.status_code == 200, r.text
    assert client.get("/api/mailbox", headers=_auth(tok)).status_code == 200
    joined = " | ".join(seen)
    assert "DELETE FROM mailbox WHERE id" in joined, "precondition: prune/eviction/fetch deletes were traced"
    assert "INSERT INTO mailbox " in joined
    bad = _full_scans(seen)
    assert not bad, f"full mailbox scans on the request path: {bad}"
    _clear_mailbox()


def _counters_match():
    with accounts._db() as conn:
        real = conn.execute("SELECT COUNT(*), COALESCE(SUM(LENGTH(CAST(envelope AS BLOB))), 0) FROM mailbox").fetchone()
        kept = conn.execute("SELECT rows, bytes FROM mailbox_totals WHERE id = 1").fetchone()
        real_inbox = {r[0]: (r[1], r[2]) for r in conn.execute(
            "SELECT recipient, COUNT(*), SUM(LENGTH(CAST(envelope AS BLOB))) FROM mailbox GROUP BY recipient")}
        kept_inbox = {r[0]: (r[1], r[2]) for r in conn.execute("SELECT recipient, rows, bytes FROM mailbox_inbox")}
    assert tuple(kept) == tuple(real), f"totals drifted: kept {tuple(kept)} vs real {tuple(real)}"
    assert kept_inbox == real_inbox, f"per-inbox counters drifted: {kept_inbox} vs {real_inbox}"


def test_counters_equal_the_real_sums_after_mixed_traffic(monkeypatch):
    """F2: the counters are only safe if every INSERT and DELETE maintains
    them — post, fetch, TTL prune and eviction, in any mix."""
    _clear_mailbox()
    n = config.MIN_ENVELOPE_BYTES
    monkeypatch.setattr(config, "MAX_MAILBOX_TOTAL_BYTES", 10 * n)
    monkeypatch.setattr(mailbox._post_limiter, "_refill", 0.0)
    users = [_register(f"f2-mix{i}") for i in range(3)]
    toks = [_login(u) for u in users]

    def post(u, size, fill):
        return client.post(f"/api/mailbox/{u['username']}", params={"t": u["token"]},
                           json={"envelope": _env(size, fill)}).status_code

    for i in range(9):  # fills and then evicts (sizes vary)
        assert post(users[i % 3], n + 37 * i, str(i)) == 200
    _counters_match()
    assert client.get("/api/mailbox", headers=_auth(toks[1])).status_code == 200  # fetch-delete
    _counters_match()
    with accounts._db() as conn:  # age one inbox past the TTL, then any access prunes it
        conn.execute("UPDATE mailbox SET created_at = ? WHERE recipient = ?",
                     (int(time.time()) - config.MAILBOX_TTL_SEC - 5, users[2]["username"]))
    assert post(users[0], 2 * n, "p") == 200  # prune + possibly evict + insert
    _counters_match()
    with accounts._db() as conn:
        assert conn.execute("SELECT COUNT(*) FROM mailbox_inbox WHERE recipient = ?",
                            (users[2]["username"],)).fetchone()[0] == 0, "an emptied inbox leaves no counter row"
    for t in toks:
        client.get("/api/mailbox", headers=_auth(t))
    _counters_match()
    _clear_mailbox()


def test_flood_of_full_throwaway_inboxes_cannot_evict_a_small_victim(monkeypatch):
    """Fix review F1: evicting the globally OLDEST rows let throwaway accounts
    flooding their OWN inboxes silently delete everyone else's queued mail
    (PoC: 80 accounts, the victim's 3 envelopes: 0 delivered, every flood POST
    200). Eviction now takes from the HEAVIEST inbox, so attackers sitting at
    their per-inbox cap evict each other, and a victim holding one small
    envelope survives however long the flood runs."""
    _clear_mailbox()
    n = config.MIN_ENVELOPE_BYTES
    monkeypatch.setattr(config, "MAX_MAILBOX_PER_RECIPIENT_BYTES", 4 * n)
    monkeypatch.setattr(config, "MAX_MAILBOX_TOTAL_BYTES", 13 * n)
    monkeypatch.setattr(mailbox._post_limiter, "_refill", 0.0)
    victim = _register("f1-victim")
    attackers = [_register(f"f1-att{i}") for i in range(5)]

    def post(u, fill):
        return client.post(f"/api/mailbox/{u['username']}", params={"t": u["token"]},
                           json={"envelope": _env(n, fill)}).status_code

    assert post(victim, "V") == 200                      # queued BEFORE the flood: the oldest row
    for a in attackers[:3]:                              # fill the budget, attackers at their cap
        for _ in range(4):
            assert post(a, "Z") == 200
    codes = []
    for i in range(60):                                  # keep flooding past a full budget
        mailbox._post_limiter._buckets.clear()
        codes.append(post(attackers[i % 5], "Z"))
    assert 200 in codes, f"precondition: the flood kept being accepted (evicting): {codes}"
    got = client.get("/api/mailbox", headers=_auth(_login(victim))).json()["messages"]
    assert [m["envelope"][0] for m in got] == ["V"], "the victim's queued envelope was evicted by the flood"
    _clear_mailbox()


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
        exc = sqlite3.OperationalError("database is locked")
        exc.sqlite_errorname = "SQLITE_BUSY"  # what sqlite3 sets on a real one
        raise exc

    monkeypatch.setattr(mailbox, "_db", locked)
    with caplog.at_level(logging.DEBUG):
        r = client.get("/api/mailbox", headers=_auth(tok))
    assert (r.status_code, r.text) == (503, "busy"), (r.status_code, r.text)
    assert not [rec for rec in caplog.records if rec.levelno >= logging.WARNING], (
        "lock contention is routine: it must not be logged at all")


def test_other_sqlite_failures_are_not_silent_but_log_only_their_name(monkeypatch, caplog):
    """Fix review F4: the busy handler mapped EVERY OperationalError (disk
    full, I/O error, malformed DB, missing table) to the same silent 503, so a
    relay that lost its storage looked quiet to its operator. Non-contention
    errors are a 500 plus ONE log line with only sqlite's error name — no
    request data (I2) — rate-limited per name."""
    import sqlite3
    import main
    monkeypatch.setattr(main, "_sqlite_logged_at", {})
    bob = _register("f4-disk")
    tok = _login(bob)

    def broken():
        exc = sqlite3.OperationalError("disk I/O error")
        exc.sqlite_errorname = "SQLITE_IOERR"
        raise exc

    monkeypatch.setattr(mailbox, "_db", broken)
    with caplog.at_level(logging.DEBUG):
        codes = [client.get("/api/mailbox", headers=_auth(tok)).status_code for _ in range(3)]
    assert codes == [500] * 3, codes
    lines = [rec.getMessage() for rec in caplog.records if rec.levelno >= logging.WARNING]
    assert lines == ["sqlite error SQLITE_IOERR"], lines  # once, not three times
    server_side = " ".join(rec.getMessage() for rec in caplog.records if not rec.name.startswith(("httpx", "asyncio")))
    for secret in (tok, "f4-disk", "/api/mailbox", "disk I/O error"):
        assert secret not in server_side, f"request data or message text leaked into the log: {secret!r}"


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
