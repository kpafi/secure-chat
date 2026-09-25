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
    full queued mail is evicted — the NEWEST envelope of the HEAVIEST other
    inbox (fix review F1, re-review R2) — instead of a relay-wide 503 "storage
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
    assert post(alice, "b").status_code == 200                      # bob is heaviest: his NEWEST ("2") goes
    with accounts._db() as conn:
        rows = [(r["recipient"], r["envelope"][0])
                for r in conn.execute("SELECT recipient, envelope FROM mailbox ORDER BY id").fetchall()]
    assert rows == [("f1-bob", "1"), ("f1-alice", "a"), ("f1-alice", "b")], rows
    got = client.get("/api/mailbox", headers=_auth(_login(alice))).json()["messages"]
    assert [m["envelope"][0] for m in got] == ["a", "b"], "new mail was delivered under a full budget"
    _clear_mailbox()


def test_mailbox_full_budget_evicts_instead_of_503(monkeypatch):
    """Master's shape: a full mailbox was a relay-wide 503 "mailbox storage
    full". It now evicts to fit (heaviest other inbox, newest envelope). Ties are broken AWAY from the recipient: the index hands back
    equal weights in rowid order, so both directions are exercised — in one of
    them the recipient comes back first and must not be refused."""
    monkeypatch.setattr(config, "MAX_MAILBOX_TOTAL_BYTES", 2 * config.MIN_ENVELOPE_BYTES)
    for k, (first, second) in enumerate((("a", "b"), ("b", "a"))):
        _clear_mailbox()
        users = {x: _register(f"f1-rows{k}{x}") for x in "ab"}

        def post(u, fill):
            return client.post(f"/api/mailbox/{u['username']}", params={"t": u["token"]},
                               json={"envelope": _env(fill=fill)}).status_code

        assert post(users[second], "c") == 200
        assert post(users[first], "x") == 200      # budget full (2 envelopes), the two inboxes tie;
        # the recipient's counter row is the NEWER one, which a descending
        # index scan returns first among equal weights.
        assert post(users[first], "z") == 200, "a recipient tied for heaviest must not be refused"
        got = client.get("/api/mailbox", headers=_auth(_login(users[first]))).json()["messages"]
        assert [m["envelope"][0] for m in got] == ["x", "z"], got
        assert client.get("/api/mailbox", headers=_auth(_login(users[second]))).json()["messages"] == []
    _clear_mailbox()


def test_full_budget_refuses_new_mail_to_the_heaviest_inbox_loudly(monkeypatch):
    """Re-review R2, the reverse order: when the budget is full and the
    recipient's OWN inbox is the heaviest, the NEW envelope is refused with a
    429 the sender sees, rather than silently evicting older mail."""
    _clear_mailbox()
    n = config.MIN_ENVELOPE_BYTES
    monkeypatch.setattr(config, "MAX_MAILBOX_TOTAL_BYTES", 3 * n)
    monkeypatch.setattr(mailbox._post_limiter, "_refill", 0.0)
    bob = _register("r2-heavy")
    alice = _register("r2-light")

    def post(u, fill):
        return client.post(f"/api/mailbox/{u['username']}", params={"t": u["token"]},
                           json={"envelope": _env(n, fill)})

    assert post(bob, "1").status_code == 200
    assert post(bob, "2").status_code == 200
    assert post(alice, "a").status_code == 200           # full; bob (2n) is the heaviest
    r = post(bob, "3")
    assert r.status_code == 429 and "inbox full" in r.text, r.text
    got = client.get("/api/mailbox", headers=_auth(_login(bob))).json()["messages"]
    assert [m["envelope"][0] for m in got] == ["1", "2"], "nothing already queued was evicted"
    _clear_mailbox()


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
    """Counters == real sums of the per-row CHARGE (round-3 M-1), and every
    row's size is its real length and its charge is at least that."""
    with accounts._db() as conn:
        bad = conn.execute("SELECT COUNT(*) FROM mailbox WHERE size != LENGTH(CAST(envelope AS BLOB)) "
                           "OR charge < size").fetchone()[0]
        assert bad == 0, f"{bad} rows with a wrong size or a charge below their size"
        real = conn.execute("SELECT COUNT(*), COALESCE(SUM(charge), 0) FROM mailbox").fetchone()
        kept = conn.execute("SELECT rows, bytes FROM mailbox_totals WHERE id = 1").fetchone()
        real_inbox = {r[0]: (r[1], r[2]) for r in conn.execute(
            "SELECT recipient, COUNT(*), SUM(charge) FROM mailbox GROUP BY recipient")}
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


# ---- Re-review R1 / R1b / R2 (reviewer's binding tests, folded in) -----------

def _real_bytes():
    with accounts._db() as conn:
        return conn.execute("SELECT COALESCE(SUM(LENGTH(CAST(envelope AS BLOB))),0) FROM mailbox").fetchone()[0]


def _plant_expired(recipient, count, size):
    with accounts._db() as conn:
        old = int(time.time()) - config.MAILBOX_TTL_SEC - 5
        for _ in range(count):
            conn.execute("INSERT INTO mailbox (recipient, envelope, created_at, size) VALUES (?,?,?,?)",
                         (recipient, _env(size), old, size))
        mailbox._rebuild_counters(conn)


def test_R1_concurrent_prunes_do_not_double_count_expired_rows():
    """Re-review R1 (HIGH): _prune SELECTed the expired rows OUTSIDE any write
    transaction, so N concurrent requests all saw the same victims and each
    subtracted them from the counters (live: 20 GETs -> (-1140, -74 MB))."""
    import concurrent.futures as cf
    _clear_mailbox()
    att = _register("r1-att")
    tok = _login(att)
    _plant_expired("r1-att", 20, 4096)
    with cf.ThreadPoolExecutor(max_workers=12) as ex:   # the attacker's OWN session; fetch burst is 30
        codes = list(ex.map(lambda _: client.get("/api/mailbox", headers=_auth(tok)).status_code, range(12)))
    assert set(codes) == {200}, codes
    _counters_match()
    _clear_mailbox()


def test_R1_counters_match_after_a_mixed_concurrent_burst(monkeypatch):
    """Concurrent POSTs and fetches over freshly expired rows: whatever the
    interleaving, the counters equal the real sums afterwards."""
    import concurrent.futures as cf
    _clear_mailbox()
    monkeypatch.setattr(mailbox._post_limiter, "_refill", 0.0)
    users = [_register(f"r1-mix{i}") for i in range(6)]
    toks = [_login(u) for u in users]
    _plant_expired("r1-mix0", 30, 2048)

    def work(i):
        u = users[i % 6]
        if i % 2:
            return client.get("/api/mailbox", headers=_auth(toks[i % 6])).status_code
        return client.post(f"/api/mailbox/{u['username']}", params={"t": u["token"]},
                           json={"envelope": _env(700)}).status_code

    with cf.ThreadPoolExecutor(max_workers=16) as ex:
        codes = list(ex.map(work, range(48)))
    assert set(codes) <= {200, 429}, codes
    _counters_match()
    _clear_mailbox()


def test_R1b_drift_cannot_lift_the_global_budget(monkeypatch):
    """Consequence of R1: after one burst of concurrent fetches over an expired
    full budget the counters sat far below reality, and the relay accepted a
    multiple of MAX_MAILBOX_TOTAL_BYTES (live: 10x) with no evictions."""
    import concurrent.futures as cf
    _clear_mailbox()
    n = 4096
    budget = 40 * n
    monkeypatch.setattr(config, "MAX_MAILBOX_TOTAL_BYTES", budget)
    monkeypatch.setattr(config, "MAX_MAILBOX_PER_RECIPIENT_BYTES", 1_000_000)
    monkeypatch.setattr(mailbox._post_limiter, "_refill", 0.0)
    att = _register("r1b-att")
    tok = _login(att)
    _plant_expired("r1b-att", 40, n)  # a full budget, planted 14 days ago, now expired
    with cf.ThreadPoolExecutor(max_workers=12) as ex:
        list(ex.map(lambda _: client.get("/api/mailbox", headers=_auth(tok)).status_code, range(12)))
    sinks = [_register(f"r1b-s{i}") for i in range(4)]
    for i in range(4 * 100):
        mailbox._post_limiter._buckets.clear()
        s_ = sinks[i % 4]
        client.post(f"/api/mailbox/{s_['username']}", params={"t": s_["token"]}, json={"envelope": _env(n)})
    real = _real_bytes()
    assert real <= budget, f"budget {budget} B, queued {real} B ({real / budget:.1f}x)"
    _counters_match()
    _clear_mailbox()


def test_R2_handle_holder_cannot_evict_mail_queued_before_the_padding(monkeypatch):
    """Re-review R2 (Medium): anyone holding the victim's handle pads the
    victim's inbox to the per-inbox cap, then keeps budget/cap + 1 own inboxes
    just under the cap, which made the victim the heaviest inbox and evicted
    its OLDEST envelope — the honest mail queued before the padding (~65
    accounts, ~2 minutes at production sizes). Newest-first evicts the
    padding instead."""
    _clear_mailbox()
    n = config.MIN_ENVELOPE_BYTES
    cap = 8 * n
    monkeypatch.setattr(config, "MAX_MAILBOX_PER_RECIPIENT_BYTES", cap)
    monkeypatch.setattr(config, "MAX_MAILBOX_TOTAL_BYTES", 8 * cap)      # 8 "full inboxes" of budget
    monkeypatch.setattr(mailbox._post_limiter, "_refill", 0.0)
    victim = _register("r2-victim")
    atts = [_register(f"r2-att{i}") for i in range(10)]

    def post(u, fill):
        mailbox._post_limiter._buckets.clear()
        return client.post(f"/api/mailbox/{u['username']}", params={"t": u["token"]},
                           json={"envelope": _env(n, fill)}).status_code

    assert post(victim, "H") == 200                         # honest mail, queued while victim is offline
    for _ in range(7):
        assert post(victim, "P") == 200                     # attacker (has the handle) pads to the cap
    for a in atts[:8]:                                      # 8 attacker inboxes at cap - 1 envelope
        for _ in range(7):
            post(a, "Z")
    codes = [post(atts[9], "Z") for _ in range(3)]          # budget now full; flood a fresh inbox
    assert 200 in codes, f"precondition: the flood was accepted (so something was evicted): {codes}"
    got = client.get("/api/mailbox", headers=_auth(_login(victim))).json()["messages"]
    assert "H" in [m["envelope"][0] for m in got], "the victim's honest mail was evicted"
    _counters_match()
    _clear_mailbox()


# ---- Re-review R3: an interrupted migration must not leave size = 0 ----------

def test_R3_interrupted_size_migration_is_repaired_on_start():
    """The ALTER TABLE ... ADD COLUMN size commits on its own; a crash before
    the backfill left size = 0 forever, invisible to every budget."""
    _clear_mailbox()
    with accounts._db() as conn:
        for i in range(5):
            conn.execute("INSERT INTO mailbox (recipient, envelope, created_at, size) VALUES (?,?,?,0)",
                         (f"r3-u{i % 2}", _env(300 + i), int(time.time())))
    mailbox.init_db()  # the next start
    with accounts._db() as conn:
        assert conn.execute("SELECT COUNT(*) FROM mailbox WHERE size = 0").fetchone()[0] == 0
    _counters_match()
    _clear_mailbox()


def test_R3_migration_from_a_pre_size_schema_and_after_a_crash(tmp_path):
    """migr.py, as a test: an old-schema DB, and one where the ALTER ran but
    the backfill did not, both come up with exact sizes and counters, twice."""
    import sqlite3
    import subprocess
    import sys
    backend = str(Path(__file__).resolve().parents[1])
    for case in ("old_schema", "crash_after_alter"):
        db = str(tmp_path / f"{case}.db")
        c = sqlite3.connect(db)
        c.execute("CREATE TABLE mailbox (id INTEGER PRIMARY KEY AUTOINCREMENT, recipient TEXT NOT NULL, "
                  "envelope TEXT NOT NULL, created_at INTEGER NOT NULL)")
        for i in range(50):
            c.execute("INSERT INTO mailbox (recipient, envelope, created_at) VALUES (?,?,?)",
                      (f"u{i % 5}", "E" * (300 + i), int(time.time())))
        if case == "crash_after_alter":
            c.execute("ALTER TABLE mailbox ADD COLUMN size INTEGER NOT NULL DEFAULT 0")
        c.commit()
        c.close()
        code = "import accounts, mailbox; accounts.init_db(); mailbox.init_db()"
        env = dict(os.environ, SECURE_CHAT_DB=db)
        for _ in range(2):
            subprocess.run([sys.executable, "-c", code], cwd=backend, env=env, check=True)
        c = sqlite3.connect(db)
        floor = -(-config.MAX_MAILBOX_TOTAL_BYTES // config.MAX_MAILBOX_TOTAL)
        real = c.execute("SELECT COUNT(*), SUM(MAX(LENGTH(CAST(envelope AS BLOB)), ?)) FROM mailbox",
                         (floor,)).fetchone()
        assert c.execute("SELECT rows, bytes FROM mailbox_totals").fetchone() == real, case
        assert c.execute("SELECT COUNT(*) FROM mailbox WHERE size != LENGTH(CAST(envelope AS BLOB)) "
                         "OR charge != MAX(size, ?)", (floor,)).fetchone()[0] == 0, case
        c.close()


# ---- Re-review Info a/b: busy detection and DatabaseError --------------------

def test_a_real_sqlite_busy_is_a_silent_503(monkeypatch, caplog):
    """Info a: the F4 tests set sqlite_errorname by hand. This one makes sqlite
    raise a REAL SQLITE_BUSY (another connection holds the write lock,
    busy_timeout 0) and checks the handler recognises it."""
    import sqlite3
    bob = _register("ia-busy")
    tok = _login(bob)

    def impatient_db():
        conn = accounts._db()
        conn.execute("PRAGMA busy_timeout=0")
        return conn

    monkeypatch.setattr(mailbox, "_db", impatient_db)
    blocker = sqlite3.connect(config.DB_PATH)
    blocker.execute("BEGIN IMMEDIATE")
    try:
        with caplog.at_level(logging.DEBUG):
            r = client.get("/api/mailbox", headers=_auth(tok))
    finally:
        blocker.rollback()
        blocker.close()
    assert (r.status_code, r.text) == (503, "busy"), (r.status_code, r.text)
    assert not [rec for rec in caplog.records if rec.levelno >= logging.WARNING], caplog.text


@pytest.mark.parametrize("attrs", [{}, {"sqlite_errorcode": 5}, {"sqlite_errorcode": 517}])
def test_busy_is_recognised_without_sqlite_errorname(monkeypatch, caplog, attrs):
    """Info a: without `sqlite_errorname` (older Python, or a hand-raised
    error) contention is still recognised — by code, then by message."""
    import sqlite3
    bob = _register(f"ia-noname{attrs.get('sqlite_errorcode', 0)}")
    tok = _login(bob)

    def locked():
        exc = sqlite3.OperationalError("database is locked" if not attrs else "whatever")
        for k, v in attrs.items():
            setattr(exc, k, v)
        raise exc

    monkeypatch.setattr(mailbox, "_db", locked)
    with caplog.at_level(logging.DEBUG):
        r = client.get("/api/mailbox", headers=_auth(tok))
    assert (r.status_code, r.text) == (503, "busy"), (r.status_code, r.text)
    assert not [rec for rec in caplog.records if rec.levelno >= logging.WARNING], caplog.text


def test_malformed_database_is_a_500_with_one_name_only_log_line(monkeypatch, caplog):
    """Info b: a malformed database raises sqlite3.DatabaseError (not
    OperationalError), which bypassed the handler: Starlette's default 500
    with a traceback in the journal. Same treatment as any other fault now."""
    import sqlite3
    import main
    monkeypatch.setattr(main, "_sqlite_logged_at", {})
    bob = _register("ib-corrupt")
    tok = _login(bob)

    def corrupt():
        exc = sqlite3.DatabaseError("database disk image is malformed")
        exc.sqlite_errorname = "SQLITE_CORRUPT"
        raise exc

    monkeypatch.setattr(mailbox, "_db", corrupt)
    with caplog.at_level(logging.DEBUG):
        codes = [client.get("/api/mailbox", headers=_auth(tok)).status_code for _ in range(2)]
    assert codes == [500, 500], codes
    lines = [rec.getMessage() for rec in caplog.records if rec.levelno >= logging.WARNING]
    assert lines == ["sqlite error SQLITE_CORRUPT"], lines
    assert not any(rec.exc_info for rec in caplog.records), "no traceback"


def test_delete_rows_decrements_only_what_was_actually_deleted():
    """Re-review R1, second layer: the decrement follows `DELETE ... RETURNING`,
    so deleting an id that is already gone (or an unknown one) changes no
    counter, whatever the caller believed."""
    _clear_mailbox()
    bob = _register("r1-ret")
    assert client.post("/api/mailbox/r1-ret", params={"t": bob["token"]}, json={"envelope": _env()}).status_code == 200
    with accounts._db() as conn:
        rid = conn.execute("SELECT id FROM mailbox WHERE recipient = 'r1-ret'").fetchone()[0]
        mailbox._delete_rows(conn, [rid, rid, 10**9])
        mailbox._delete_rows(conn, [rid])
    _counters_match()
    _clear_mailbox()


# ---- Round-3 review: M-1 row cap vs byte budget, Info a/b/c/d/e -------------

def _plant(conn, recipient, n, size, created=None):
    created = created or int(time.time())
    conn.executemany("INSERT INTO mailbox (recipient, envelope, created_at, size) VALUES (?,?,?,?)",
                     [(recipient, "Z" * size, created, size)] * n)


def test_ROWCAP_minimum_size_filler_cannot_make_a_63KB_inbox_the_heaviest(monkeypatch):
    """Round-3 M-1, the reviewer's scenario with the SHIPPED constants. The row
    cap (100 000) used to be a second "budget full" trigger: 500 accounts x 200
    x 256 B filled it at 25.6 MB, every inbox over 51 200 B was then "the
    heaviest", mail to it was refused and any post elsewhere evicted its
    newest envelope. Rows are now charged at least budget/row-cap, so that
    filler weighs a full byte budget and its own inboxes are the heaviest."""
    _clear_mailbox()
    monkeypatch.setattr(mailbox._post_limiter, "_refill", 0.0)
    victim = _register("rc-victim")
    sender_to = _register("rc-x")

    def post(u, n, fill):
        mailbox._post_limiter._buckets.clear()
        return client.post(f"/api/mailbox/{u['username']}", params={"t": u["token"]},
                           json={"envelope": _env(n, fill)}).status_code

    assert post(victim, 3000, "O") == 200      # honest, old
    assert post(victim, 60000, "N") == 200     # honest, a photo — victim now 63 000 B
    with accounts._db() as conn:               # == 100 000 POSTs of 256 B to 500 own inboxes
        for i in range(500):
            _plant(conn, f"rc-att{i:03d}", 200, 256)
        conn.execute("DELETE FROM mailbox WHERE recipient LIKE 'rc-att%' AND id IN "
                     "(SELECT id FROM mailbox WHERE recipient LIKE 'rc-att%' LIMIT 2)")  # 100 000 rows total
        mailbox._rebuild_counters(conn)
        rows, charged = mailbox._totals(conn)
    assert rows == config.MAX_MAILBOX_TOTAL
    assert charged >= config.MAX_MAILBOX_TOTAL_BYTES, "the filler must weigh a full byte budget"
    r_victim = post(victim, 2000, "V")         # honest mail to the victim
    r_other = post(sender_to, 300, "x")        # anyone posts anywhere else
    got = client.get("/api/mailbox", headers=_auth(_login(victim))).json()["messages"]
    kinds = [m["envelope"][0] for m in got]
    _counters_match()
    _clear_mailbox()
    assert (r_victim, r_other) == (200, 200), (r_victim, r_other)
    assert kinds == ["O", "N", "V"], kinds


def test_row_cap_cannot_fill_before_the_byte_budget():
    """The invariant M-1 rests on: with every row charged at least the floor,
    MAX_MAILBOX_TOTAL rows always weigh at least the whole byte budget."""
    assert config.MAX_MAILBOX_TOTAL * mailbox._row_charge(config.MIN_ENVELOPE_BYTES) >= config.MAX_MAILBOX_TOTAL_BYTES
    assert mailbox._row_charge(config.MAX_ENVELOPE_BYTES) == config.MAX_ENVELOPE_BYTES
    assert 2048 < mailbox._row_charge(1) < 4096  # ~2.6 KiB at the shipped numbers


def test_noroom_after_partial_eviction_rolls_back(monkeypatch):
    """(Reviewer round 3.) Evictions made while looking for room are undone
    when the post is refused in the end: the 429 leaves every inbox as it was."""
    _clear_mailbox()
    n = config.MIN_ENVELOPE_BYTES
    monkeypatch.setattr(config, "MAX_MAILBOX_PER_RECIPIENT_BYTES", 64 * n)
    monkeypatch.setattr(config, "MAX_MAILBOX_TOTAL_BYTES", 20 * n)
    monkeypatch.setattr(mailbox._post_limiter, "_refill", 0.0)
    r = _register("nr-r")
    o = _register("nr-o")

    def post(u, size):
        mailbox._post_limiter._buckets.clear()
        return client.post(f"/api/mailbox/{u['username']}", params={"t": u["token"]},
                           json={"envelope": _env(size)}).status_code
    for _ in range(11):
        assert post(o, n) == 200          # O = 11n
    for _ in range(9):
        assert post(r, n) == 200          # R = 9n, budget 20n full
    code = post(r, 6 * n)                 # evicts O, O (tie away from R), then R heaviest -> 429
    with accounts._db() as conn:
        inb = dict((a, b) for a, b in conn.execute("SELECT recipient, bytes FROM mailbox_inbox"))
    _counters_match()
    _clear_mailbox()
    assert code == 429 and inb["nr-o"] == 11 * n, (code, inb)


def test_startup_refuses_an_sqlite_without_returning(monkeypatch):
    """Round-3 Info a: DELETE ... RETURNING needs sqlite >= 3.35; refuse to
    start loudly instead of failing on the first delete."""
    import sqlite3
    monkeypatch.setattr(sqlite3, "sqlite_version_info", (3, 34, 1))
    with pytest.raises(RuntimeError, match="too old"):
        mailbox.init_db()


def test_startup_repair_reads_the_index_not_the_bodies(monkeypatch):
    """Round-3 Info b: the size/charge repair on every start used to scan every
    envelope body. It finds the rows to fix through the covering age index."""
    import re
    seen = []

    def traced_db():
        conn = accounts._db()
        conn.set_trace_callback(seen.append)
        return conn

    monkeypatch.setattr(mailbox, "_db", traced_db)
    mailbox.init_db()
    repairs = [q for q in seen if q.lstrip().upper().startswith("UPDATE MAILBOX SET")]
    assert len(repairs) == 2, repairs
    with accounts._db() as conn:
        for q in repairs:
            plan = [r[3] for r in conn.execute("EXPLAIN QUERY PLAN " + q)]
            # A full pass over the (small) covering index is the point; a pass
            # over the TABLE reads every envelope body.
            assert not any(re.fullmatch(r"SCAN mailbox\s*", line) for line in plan), (q, plan)
            assert any("COVERING INDEX idx_mailbox_age" in line for line in plan), (q, plan)


@pytest.mark.parametrize("err", ["IntegrityError", "ProgrammingError"])
def test_programming_errors_are_not_swallowed(monkeypatch, err):
    """Round-3 Info c: the DatabaseError handler also caught IntegrityError /
    ProgrammingError — bugs in our code — and turned them into a quiet 500.
    They propagate to the default handler (and so fail any test that hits
    them)."""
    import sqlite3
    bob = _register(f"ic-{err.lower()}")
    tok = _login(bob)

    def buggy():
        raise getattr(sqlite3, err)("a bug")

    monkeypatch.setattr(mailbox, "_db", buggy)
    with pytest.raises(getattr(sqlite3, err)):
        client.get("/api/mailbox", headers=_auth(tok))


def test_begin_write_refuses_to_join_an_open_transaction():
    """Round-3 Info d: _begin_write used to skip BEGIN IMMEDIATE silently if a
    transaction was already open — possibly a deferred one that had read
    without the lock (R1 again)."""
    with accounts._db() as conn:
        conn.execute("UPDATE mailbox_totals SET rows = rows WHERE id = 1")  # opens a deferred txn
        assert conn.in_transaction
        with pytest.raises(RuntimeError, match="already open"):
            mailbox._begin_write(conn)


def test_prune_of_more_rows_than_sqlite_can_bind_at_once(monkeypatch):
    """Round-3 Info e (the surviving mutant): one statement may bind at most
    SQLITE_LIMIT_VARIABLE_NUMBER parameters — 32 766 in a default sqlite
    build, 250 000 in this venv's — and a prune after downtime can exceed it.
    _delete_rows chunks its ids. The limit is lowered on the connection so the
    test binds whatever the local build's default is."""
    import sqlite3
    _clear_mailbox()
    bob = _register("ie-prune")
    tok = _login(bob)
    old = int(time.time()) - config.MAILBOX_TTL_SEC - 5
    with accounts._db() as conn:
        _plant(conn, "ie-filler", 1500, 256, created=old)
        mailbox._rebuild_counters(conn)

    def limited_db():
        conn = accounts._db()
        conn.setlimit(sqlite3.SQLITE_LIMIT_VARIABLE_NUMBER, 999)
        return conn

    monkeypatch.setattr(mailbox, "_db", limited_db)
    r = client.get("/api/mailbox", headers=_auth(tok))
    assert r.status_code == 200, r.text
    with accounts._db() as conn:
        assert conn.execute("SELECT COUNT(*) FROM mailbox WHERE recipient = 'ie-filler'").fetchone()[0] == 0
    _counters_match()
    _clear_mailbox()


def test_ROWCAP_scaled_through_the_api(monkeypatch):
    """Round-3 M-1 again, but every filler envelope goes through POST (so
    through _insert's charge, not the startup repair): with a 20-row cap and
    a 20-row-floor budget, 20 minimum-size filler posts (4 accounts at a
    5-row inbox cap) used to fill the ROW cap at 5 KB and make a 6 KB inbox
    the heaviest. Charged per row, the same filler weighs the whole byte
    budget, and the victim's mail survives and keeps arriving."""
    _clear_mailbox()
    monkeypatch.setattr(config, "MAX_MAILBOX_TOTAL", 20)
    monkeypatch.setattr(config, "MAX_MAILBOX_TOTAL_BYTES", 20 * 2048)   # row floor 2048
    monkeypatch.setattr(config, "MAX_MAILBOX_PER_RECIPIENT", 5)
    monkeypatch.setattr(mailbox._post_limiter, "_refill", 0.0)
    victim = _register("rcs-victim")
    other = _register("rcs-x")
    atts = [_register(f"rcs-att{i}") for i in range(4)]

    def post(u, n, fill):
        mailbox._post_limiter._buckets.clear()
        return client.post(f"/api/mailbox/{u['username']}", params={"t": u["token"]},
                           json={"envelope": _env(n, fill)}).status_code

    assert post(victim, 3000, "O") == 200
    assert post(victim, 3000, "N") == 200              # victim: 6 000 B queued
    for i in range(20):                                   # minimum-size filler, inbox by inbox
        assert post(atts[i // 5], 256, "Z") == 200
    r_victim = post(victim, 2000, "V")
    r_other = post(other, 256, "x")
    got = client.get("/api/mailbox", headers=_auth(_login(victim))).json()["messages"]
    kinds = [m["envelope"][0] for m in got]
    _counters_match()
    _clear_mailbox()
    assert (r_victim, r_other) == (200, 200), (r_victim, r_other)
    assert kinds == ["O", "N", "V"], kinds
