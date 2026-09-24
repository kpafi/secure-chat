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
    is BYTES, and when it is full the OLDEST queued mail is evicted rather than
    refusing new mail (F-P7-1): with free registration the budget can always
    be filled, so what a flood may cost is RETENTION (mail must be fetched
    sooner), never delivery. That is the honest limit, not a closed one.
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
        conn.execute("CREATE INDEX IF NOT EXISTS idx_mailbox_recipient ON mailbox(recipient)")
        # The TTL prune is `DELETE ... WHERE created_at < ?` on every POST and
        # GET; without this index it scanned the whole table under the write
        # lock (§9 L-2).
        conn.execute("CREATE INDEX IF NOT EXISTS idx_mailbox_created ON mailbox(created_at)")


def _prune(conn) -> None:
    conn.execute("DELETE FROM mailbox WHERE created_at < ?", (int(time.time()) - config.MAILBOX_TTL_SEC,))


def _evict_oldest_to_fit(conn, incoming: int) -> None:
    """F-P7-1: the server-wide budget evicts the OLDEST queued mail instead of
    refusing new mail. A 503 for everyone until the TTL ran out was the
    finding's impact; with free registration the budget can always be filled,
    so what a flood may cost is retention, never delivery. Bounded loop: each
    pass drops at least one row (1/64 of the table)."""
    for _ in range(64):
        rows, total = conn.execute(
            "SELECT COUNT(*), COALESCE(SUM(LENGTH(CAST(envelope AS BLOB))), 0) FROM mailbox"
        ).fetchone()
        if rows < config.MAX_MAILBOX_TOTAL and total + incoming <= config.MAX_MAILBOX_TOTAL_BYTES:
            return
        if rows == 0:
            return
        conn.execute(
            "DELETE FROM mailbox WHERE id IN (SELECT id FROM mailbox ORDER BY id LIMIT ?)",
            (max(1, rows // 64),),
        )


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
        # the server-wide budget, which evicts the oldest queued mail to fit.
        count, inbox_bytes = conn.execute(
            "SELECT COUNT(*), COALESCE(SUM(LENGTH(CAST(envelope AS BLOB))), 0) FROM mailbox WHERE recipient = ?",
            (recipient,),
        ).fetchone()
        if (count >= config.MAX_MAILBOX_PER_RECIPIENT
                or inbox_bytes + len(req.envelope) > config.MAX_MAILBOX_PER_RECIPIENT_BYTES):
            raise HTTPException(status_code=429, detail="recipient inbox full")
        _evict_oldest_to_fit(conn, len(req.envelope))
        conn.execute(
            "INSERT INTO mailbox (recipient, envelope, created_at) VALUES (?,?,?)",
            (recipient, req.envelope, int(time.time())),
        )
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
            "SELECT id, envelope, created_at FROM mailbox WHERE recipient = ? ORDER BY id LIMIT ?",
            (username, config.MAX_MAILBOX_PER_RECIPIENT),
        ).fetchall()
        if rows:
            ids = [r["id"] for r in rows]
            conn.executemany("DELETE FROM mailbox WHERE id = ?", [(i,) for i in ids])
    return {"messages": [{"envelope": r["envelope"], "created_at": r["created_at"]} for r in rows]}
