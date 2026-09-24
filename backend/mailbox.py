"""Store-and-forward mailbox for sealed envelopes.

The asynchronous counterpart of the live relay, with the same trust model:
the server is dumb storage for OPAQUE ciphertext. A mailbox row is
(recipient, envelope, arrival time) — nothing else. The sender's identity is
sealed inside the envelope (see client sealed.js), so a full DB leak reveals
only who RECEIVES mail and roughly when, never who wrote it or what it says.

Abuse bounds:
  * POST is gated by the recipient's lookup token (the same capability that
    gates the bundle lookup) — no existence oracle, and spamming an inbox
    requires knowing its handle. Plus a per-inbox rate bucket behind that gate,
    and one generous per-host ceiling in front of it (POST only).
  * Envelope size has a floor and a ceiling; each inbox has a hard row and
    byte share (429 when full — its owner can fetch). The server-wide budget
    is BYTES, and when it is full queued mail is evicted — heaviest inbox
    first — rather than refusing new mail (F-P7-1, fix review F1): with free
    registration the budget can always be filled, so what a flood may cost is
    RETENTION, never delivery, and it costs the flooders' own full inboxes
    first. That is the honest limit, not a closed one (see config).
  * Old mail expires (TTL) and is pruned — only past the gates.
  * GET requires the recipient's session token (login) and DELETES what it
    returns — the server keeps no read history.
"""
from __future__ import annotations

import hmac
import re
import secrets
import time

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field

import config
from relay import KeyedRateLimiter
from accounts import _db, current_user, _check_username, token_matches, client_key

_post_limiter = KeyedRateLimiter(config.MAILBOX_RATE_CAPACITY, config.MAILBOX_RATE_REFILL_PER_SEC)
# The one charge that happens before any gate, and only on POST: a generous
# per-host ceiling (see config.MAILBOX_POST_HOST_RATE_*). GET has NO pre-auth
# charge — one pre-gate bucket on both verbs would let a POST flood deny every
# authenticated fetch (phase7-local 6604d9e, review M-1).
_post_host_limiter = KeyedRateLimiter(
    config.MAILBOX_POST_HOST_RATE_CAPACITY, config.MAILBOX_POST_HOST_RATE_REFILL_PER_SEC
)
_fetch_limiter = KeyedRateLimiter(
    config.MAILBOX_FETCH_RATE_CAPACITY, config.MAILBOX_FETCH_RATE_REFILL_PER_SEC
)

# Envelopes are JSON of base64 fields — printable ASCII by construction.
# `\Z`, not `$` (§9 I-2): Python's `$` also matches before a trailing newline,
# so "…\n" passed the "printable ASCII" check. The byte budget below also
# counts on every accepted envelope being one byte per character.
_ASCII_RE = re.compile(r"^[\x20-\x7e]+\Z")

router = APIRouter(prefix="/api/mailbox", tags=["mailbox"])


def _post_host_rate_limit(request: Request) -> None:
    """The only charge in front of any mailbox gate: POST, per host, generous.

    Master's POST route had no pre-gate bound at all (config claimed "the
    general /api limiter" covered it; the mailbox router was never on it), so
    unauthenticated junk ran the token-gate SELECT at line rate. Behind Tor
    this is one bucket for everybody, so it is only a backstop against runaway
    clients; the controls that matter are charged after the gates and keyed on
    the subject the gate proved (the recipient, or the authenticated user).
    """
    if not _post_host_limiter.allow(client_key(request)):
        raise HTTPException(status_code=429, detail="rate limited")


def _fetch_rate_limit(username: str) -> None:
    # Pentest 2026-07-26 P-11: `GET /api/mailbox` was the only /api endpoint with
    # NO limiter. Each fetch runs a TTL prune plus a SELECT that can return a
    # whole inbox, so an authenticated user could hammer it unthrottled. It gets
    # its OWN bucket rather than the shared /api one, because clients poll this
    # endpoint every 6 s.
    #
    # Phase-7 pentest 2026-09-16 F-P7-2 (ported from phase7-local 018652d +
    # 6604d9e M-1): this bucket used to be keyed per HOST and charged as a
    # `Depends` BEFORE `current_user` — behind Tor one bucket for everybody, so
    # ~400 unauthenticated GETs made every honest poll 429 and sealed mail
    # stopped arriving. It is now keyed per AUTHENTICATED user and called by the
    # handler only after `current_user` resolved: a request without a valid
    # session spends nothing. GET charges nothing before auth at all (the POST
    # host ceiling is POST-only, so a POST flood cannot deny fetches either).
    if not _fetch_limiter.allow("fetch:" + username):
        raise HTTPException(status_code=429, detail="rate limited")


def _post_rate_limit(recipient: str) -> None:
    # Pentest 2026-08-07 F-RELAY-004: keyed per RECIPIENT inbox, and called by
    # the handler only AFTER the recipient's lookup token has been checked, so
    # a caller who does not hold the handle cannot touch any bucket (see config
    # MAILBOX_RATE_*). Was: per-host, as a `Depends` ahead of the token gate.
    if not _post_limiter.allow("inbox:" + recipient):
        raise HTTPException(status_code=429, detail="rate limited")


def init_db() -> None:
    with _db() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS mailbox (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                recipient  TEXT NOT NULL,
                envelope   TEXT NOT NULL,
                created_at INTEGER NOT NULL
            )
            """
        )
        # Fix review of the budget (F2): every accepted POST used to run
        # SUM(LENGTH(CAST(envelope AS BLOB))) over the WHOLE table inside the
        # write transaction — ~60 ms at a full 256 MiB, capping relay-wide POST
        # throughput at ~16/s and stalling everyone's polls behind the lock.
        # The size of each row is stored beside it, and the totals live in two
        # small counter tables maintained in the SAME transaction as every
        # INSERT and DELETE (_insert / _delete_rows). Nothing on the request
        # path reads more than one inbox or one index entry.
        cols = {r["name"] for r in conn.execute("PRAGMA table_info(mailbox)")}
        if "size" not in cols:
            conn.execute("ALTER TABLE mailbox ADD COLUMN size INTEGER NOT NULL DEFAULT 0")
            conn.execute("UPDATE mailbox SET size = LENGTH(CAST(envelope AS BLOB))")
        # Covering indexes, so the per-inbox, eviction and prune paths read the
        # sizes from the index and never touch the (up to 64 KiB) row bodies.
        conn.execute("DROP INDEX IF EXISTS idx_mailbox_recipient")
        conn.execute("DROP INDEX IF EXISTS idx_mailbox_created")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_mailbox_inbox ON mailbox(recipient, id, size)")
        # The TTL prune is `created_at < ?` on every POST and GET; without an
        # index it scanned the whole table under the write lock (§9 L-2).
        conn.execute("CREATE INDEX IF NOT EXISTS idx_mailbox_expiry ON mailbox(created_at, recipient, size)")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS mailbox_totals (
                id    INTEGER PRIMARY KEY CHECK (id = 1),
                rows  INTEGER NOT NULL,
                bytes INTEGER NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS mailbox_inbox (
                recipient TEXT PRIMARY KEY,
                rows      INTEGER NOT NULL,
                bytes     INTEGER NOT NULL
            )
            """
        )
        # "Which inbox is heaviest?" is one index probe (F1 eviction order).
        conn.execute("CREATE INDEX IF NOT EXISTS idx_mailbox_inbox_bytes ON mailbox_inbox(bytes)")
        # Rebuild the counters from the table at every start: one scan at boot,
        # and any drift (a crash between versions, a manual edit) self-heals.
        _rebuild_counters(conn)


def _rebuild_counters(conn) -> None:
    """Recompute both counter tables from the mailbox table (startup only —
    this is the one full scan, and it is deliberately off the request path)."""
    conn.execute("DELETE FROM mailbox_totals")
    conn.execute(
        "INSERT INTO mailbox_totals (id, rows, bytes) SELECT 1, COUNT(*), COALESCE(SUM(size), 0) FROM mailbox"
    )
    conn.execute("DELETE FROM mailbox_inbox")
    conn.execute(
        "INSERT INTO mailbox_inbox (recipient, rows, bytes) "
        "SELECT recipient, COUNT(*), SUM(size) FROM mailbox GROUP BY recipient"
    )


def _insert(conn, recipient: str, envelope: str) -> None:
    """INSERT one envelope and bump both counters, in the caller's transaction."""
    size = len(envelope.encode("ascii"))
    conn.execute(
        "INSERT INTO mailbox (recipient, envelope, created_at, size) VALUES (?,?,?,?)",
        (recipient, envelope, int(time.time()), size),
    )
    conn.execute("UPDATE mailbox_totals SET rows = rows + 1, bytes = bytes + ? WHERE id = 1", (size,))
    conn.execute(
        "INSERT INTO mailbox_inbox (recipient, rows, bytes) VALUES (?, 1, ?) "
        "ON CONFLICT(recipient) DO UPDATE SET rows = rows + 1, bytes = bytes + excluded.bytes",
        (recipient, size),
    )


def _delete_rows(conn, victims) -> None:
    """DELETE rows given as (id, recipient, size) and decrement both counters,
    in the caller's transaction. Every delete of mailbox rows goes through here
    (prune, fetch, eviction), so the counters cannot drift."""
    if not victims:
        return
    conn.executemany("DELETE FROM mailbox WHERE id = ?", [(v[0],) for v in victims])
    per: dict[str, list[int]] = {}
    for _id, recipient, size in victims:
        agg = per.setdefault(recipient, [0, 0])
        agg[0] += 1
        agg[1] += size
    total_rows = sum(a[0] for a in per.values())
    total_bytes = sum(a[1] for a in per.values())
    conn.execute(
        "UPDATE mailbox_totals SET rows = rows - ?, bytes = bytes - ? WHERE id = 1", (total_rows, total_bytes)
    )
    for recipient, (n, b) in per.items():
        conn.execute(
            "UPDATE mailbox_inbox SET rows = rows - ?, bytes = bytes - ? WHERE recipient = ?", (n, b, recipient)
        )
        conn.execute("DELETE FROM mailbox_inbox WHERE recipient = ? AND rows <= 0", (recipient,))


def _prune(conn) -> None:
    cutoff = int(time.time()) - config.MAILBOX_TTL_SEC
    # Read from the covering expiry index. Unlike the plain DELETE it replaced,
    # this ALWAYS issues a write statement (the counter UPDATE below with a
    # zero delta when nothing expired), so it still opens the write
    # transaction ahead of the cap checks in post_mail.
    victims = [tuple(r) for r in conn.execute(
        "SELECT id, recipient, size FROM mailbox INDEXED BY idx_mailbox_expiry WHERE created_at < ?", (cutoff,)
    ).fetchall()]
    if victims:
        _delete_rows(conn, victims)
    else:
        conn.execute("UPDATE mailbox_totals SET rows = rows WHERE id = 1")


def _totals(conn) -> tuple[int, int]:
    row = conn.execute("SELECT rows, bytes FROM mailbox_totals WHERE id = 1").fetchone()
    return (row[0], row[1]) if row else (0, 0)


def _evict_to_fit(conn, incoming: int) -> None:
    """F-P7-1 + fix review F1: when the server-wide budget is full, evict from
    the HEAVIEST inbox first (its oldest envelope), one envelope at a time and
    only as much as the incoming envelope needs.

    The first cut evicted the globally OLDEST rows, 1/64 of the table at a
    time — so 80 throwaway accounts flooding their OWN inboxes silently
    deleted a victim's three queued envelopes (reviewer PoC: delivered 0 of 3,
    every flood POST answered 200). Heaviest-first turns that around: a flood
    fills the attacker's own inboxes to the per-inbox cap, and those are what
    get evicted. A victim's inbox is reached only once it is the heaviest one
    left, i.e. after the attacker holds the whole budget in inboxes no bigger
    than the victim's — about MAX_MAILBOX_TOTAL_BYTES / (victim's queued
    bytes) accounts (for a few KiB of queued mail, tens of thousands of
    registrations at the register bucket's rate). That, and an honest inbox
    that is simply the heaviest (someone offline receiving a lot) losing its
    oldest mail first, is the residual; stated in config.
    """
    for _ in range(4096):
        rows, total = _totals(conn)
        if rows < config.MAX_MAILBOX_TOTAL and total + incoming <= config.MAX_MAILBOX_TOTAL_BYTES:
            return
        heaviest = conn.execute(
            "SELECT recipient FROM mailbox_inbox ORDER BY bytes DESC LIMIT 1"
        ).fetchone()
        if heaviest is None:
            return
        victim = conn.execute(
            "SELECT id, recipient, size FROM mailbox INDEXED BY idx_mailbox_inbox "
            "WHERE recipient = ? ORDER BY id LIMIT 1",
            (heaviest[0],),
        ).fetchone()
        if victim is None:  # counters out of step with the table: resync this inbox
            conn.execute("DELETE FROM mailbox_inbox WHERE recipient = ?", (heaviest[0],))
            continue
        _delete_rows(conn, [tuple(victim)])


class PostReq(BaseModel):
    model_config = ConfigDict(extra="forbid")
    # F-P7-1: a real sealed envelope is well over 1 KiB (its ML-KEM-768
    # ciphertext alone is 1452 base64 chars); a one-byte "envelope" only ever
    # existed to spend budget.
    envelope: str = Field(min_length=config.MIN_ENVELOPE_BYTES, max_length=config.MAX_ENVELOPE_BYTES)


@router.post("/{recipient}", dependencies=[Depends(_post_host_rate_limit)])
def post_mail(recipient: str, req: PostReq, t: str = Query(default="", max_length=64)) -> dict:
    _check_username(recipient)
    if not _ASCII_RE.match(req.envelope):
        raise HTTPException(status_code=422, detail="envelope must be printable ASCII")
    with _db() as conn:
        # §9 L-2: nothing writes before the token gate. The TTL prune used to
        # run first, so every unauthenticated request took the write lock for a
        # full-table DELETE (no created_at index) before being refused.
        row = conn.execute(
            "SELECT lookup_token FROM accounts WHERE username = ?", (recipient,)
        ).fetchone()
        # Token gate doubles as the anti-enumeration boundary: wrong token and
        # unknown recipient are the identical 404 (constant-time compare against
        # a decoy for missing users, same as the bundle lookup).
        stored = row["lookup_token"] if row is not None else secrets.token_urlsafe(config.LOOKUP_TOKEN_BYTES)
        if not token_matches(t, stored) or row is None:
            raise HTTPException(status_code=404, detail="no such user")
        _post_rate_limit(recipient)
        # The prune is also the FIRST WRITE of this transaction, and it must
        # stay ahead of the cap checks: sqlite3 opens the (deferred)
        # transaction at the first DML statement, so the write lock is held
        # from here to the commit and the count/byte checks below cannot be
        # interleaved with another POST's insert. Past the gate only.
        _prune(conn)
        # F-P7-1: per-inbox share first (hard — the recipient can fetch), then
        # the server-wide budget, which evicts from the heaviest inbox to fit.
        # Both read the maintained counters (F2), never the table.
        inbox = conn.execute(
            "SELECT rows, bytes FROM mailbox_inbox WHERE recipient = ?", (recipient,)
        ).fetchone()
        count, inbox_bytes = (inbox[0], inbox[1]) if inbox else (0, 0)
        if (count >= config.MAX_MAILBOX_PER_RECIPIENT
                or inbox_bytes + len(req.envelope) > config.MAX_MAILBOX_PER_RECIPIENT_BYTES):
            raise HTTPException(status_code=429, detail="recipient inbox full")
        _evict_to_fit(conn, len(req.envelope))
        _insert(conn, recipient, req.envelope)
    return {"status": "queued"}


@router.get("")
def fetch_mail(username: str = Depends(current_user)) -> dict:
    """Return AND DELETE the queued envelopes for the authenticated user.

    Delete only the rows we actually read, by id — never a blanket
    `WHERE recipient = ?`. Two overlapping fetches (sync endpoints run in a
    threadpool) or a POST racing the fetch could otherwise have the DELETE
    remove an envelope that arrived after the SELECT and was never returned,
    losing it silently.
    """
    _fetch_rate_limit(username)  # F-P7-2: per user, after `current_user`
    with _db() as conn:
        _prune(conn)
        # Bound the response explicitly (P-11) rather than relying on the
        # per-inbox insert cap to be the only limit. Anything beyond this stays
        # queued for the next fetch.
        rows = conn.execute(
            "SELECT id, envelope, created_at, size FROM mailbox WHERE recipient = ? ORDER BY id LIMIT ?",
            (username, config.MAX_MAILBOX_PER_RECIPIENT),
        ).fetchall()
        _delete_rows(conn, [(r["id"], username, r["size"]) for r in rows])
    return {"messages": [{"envelope": r["envelope"], "created_at": r["created_at"]} for r in rows]}
