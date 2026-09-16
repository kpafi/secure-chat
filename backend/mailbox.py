"""Store-and-forward mailbox for sealed envelopes.

The asynchronous counterpart of the live relay, with the same trust model:
the server is dumb storage for OPAQUE ciphertext. A mailbox row is
(recipient, envelope, arrival time) — nothing else. The sender's identity is
sealed inside the envelope (see client sealed.js), so a full DB leak reveals
only who RECEIVES mail and roughly when, never who wrote it or what it says.

Abuse bounds:
  * POST is gated by the recipient's lookup token (the same capability that
    gates the bundle lookup) — no existence oracle, and spamming an inbox
    requires knowing its handle. Plus a dedicated per-host rate bucket.
  * Envelope size, per-inbox count, and global count are hard-capped; old
    mail expires (TTL) and is pruned opportunistically.
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

# Per-RECIPIENT bucket, charged only after the lookup token proves the sender
# knows this handle (F-RELAY-004). Draining it now costs a valid token and
# denies delivery to that one inbox, not to the whole relay.
_post_limiter = KeyedRateLimiter(config.MAILBOX_RATE_CAPACITY, config.MAILBOX_RATE_REFILL_PER_SEC)
# The absolute ceiling, keyed per client host as the old bucket was.
_post_global_limiter = KeyedRateLimiter(
    config.MAILBOX_GLOBAL_RATE_CAPACITY, config.MAILBOX_GLOBAL_RATE_REFILL_PER_SEC
)
# Phase-7 pentest 2026-09-16 F-P7-2: keyed per AUTHENTICATED user, charged
# inside the handler after `current_user` — not per host, not before auth.
_fetch_limiter = KeyedRateLimiter(
    config.MAILBOX_FETCH_RATE_CAPACITY, config.MAILBOX_FETCH_RATE_REFILL_PER_SEC
)
# The only thing charged before a gate, and only on POST: a generous per-host
# ceiling. See config. GET has NO pre-auth charge — a shared pre-gate bucket on
# both verbs let a POST flood deny every authenticated GET (review of the first
# F-P7-2 fix).
_post_host_limiter = KeyedRateLimiter(config.MAILBOX_POST_HOST_RATE_CAPACITY, config.MAILBOX_POST_HOST_RATE_REFILL_PER_SEC)

# Envelopes are JSON of base64 fields — printable ASCII by construction. `\Z`,
# not `$`: `$` matches before a trailing newline, and the byte budget below
# counts on every accepted envelope being one byte per character.
_ASCII_RE = re.compile(r"^[\x20-\x7e]+\Z")

router = APIRouter(prefix="/api/mailbox", tags=["mailbox"])


def _post_host_rate_limit(request: Request) -> None:
    """The one charge that happens before any gate: a generous per-host ceiling.

    Pentest 2026-07-26 P-11 gave `GET /api/mailbox` a bucket; 2026-08-07
    F-RELAY-004 moved the tight POST charge behind the token gate. The Phase-7
    pentest (2026-09-16, F-P7-2 / F-P7-4) found what was left in front of the
    gates: the fetch bucket was keyed per HOST and charged before `current_user`
    (200 unauthenticated GETs denied polling to everyone behind Tor, silently),
    and the POST "backstop" was small enough (300 / 10 per s) that unauthenticated
    posts to NONEXISTENT recipients — charged before the 404 — still took mail
    delivery down relay-wide at ~31 req/s.

    Behind Tor every client is one host, so anything charged here is one shared
    bucket for everybody and can only ever be a backstop against runaway
    clients. Every control that matters is charged AFTER its gate and keyed on
    the subject the gate proved: the recipient (a token holder), or the
    authenticated user.
    """
    if not _post_host_limiter.allow(client_key(request)):
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
        conn.execute("CREATE INDEX IF NOT EXISTS idx_mailbox_created ON mailbox(created_at)")
        # The first F-P7-1 fix added a `mailbox_fetches` table (who has ever
        # fetched, with a timestamp) to expire never-fetched inboxes early. Its
        # review showed it was a per-user last-seen log at rest that nothing
        # read (I2), that one authenticated GET per throwaway inbox bought the
        # long TTL back, and that it deleted real mail on deploy day and on a
        # user's first poll. Dropped; the relay keeps no read history.
        conn.execute("DROP TABLE IF EXISTS mailbox_fetches")


def _prune(conn) -> None:
    conn.execute("DELETE FROM mailbox WHERE created_at < ?", (int(time.time()) - config.MAILBOX_TTL_SEC,))


def _evict_oldest_to_fit(conn, incoming: int) -> None:
    """F-P7-1: the server-wide budget evicts the OLDEST queued mail instead of
    refusing new mail. A 503 for everyone until the TTL ran out was the
    finding's impact; with free registration the budget can always be filled,
    so what a flood may cost is RETENTION (mail must be fetched sooner), never
    delivery. Bounded loop: each pass drops at least one row."""
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
    # F-P7-1: a real sealed envelope is well over 1 KiB (it carries an ML-KEM
    # ciphertext); a one-byte "envelope" only ever existed to spend budget.
    envelope: str = Field(min_length=config.MIN_ENVELOPE_BYTES, max_length=config.MAX_ENVELOPE_BYTES)


@router.post("/{recipient}", dependencies=[Depends(_post_host_rate_limit)])
def post_mail(request: Request, recipient: str, req: PostReq, t: str = Query(default="", max_length=64)) -> dict:
    _check_username(recipient)
    if not _ASCII_RE.match(req.envelope):
        raise HTTPException(status_code=422, detail="envelope must be printable ASCII")
    with _db() as conn:
        row = conn.execute(
            "SELECT lookup_token FROM accounts WHERE username = ?", (recipient,)
        ).fetchone()
        # Token gate doubles as the anti-enumeration boundary: wrong token and
        # unknown recipient are the identical 404 (constant-time compare against
        # a decoy for missing users, same as the bundle lookup).
        stored = row["lookup_token"] if row is not None else secrets.token_urlsafe(config.LOOKUP_TOKEN_BYTES)
        if not token_matches(t, stored) or row is None:
            raise HTTPException(status_code=404, detail="no such user")
        # F-RELAY-004: charge the tight bucket HERE — past the token gate, so a
        # sender with no valid token cannot spend anyone's budget, and keyed per
        # recipient, so a sender who does hold one can only exhaust the inbox
        # they actually hold a token for.
        if not _post_limiter.allow("mail:" + recipient):
            raise HTTPException(status_code=429, detail="rate limited")
        # F-P7-4: the global ceiling is charged HERE too — past the token gate —
        # so a sender with no valid token cannot spend it. Keyed per host, so
        # behind Tor it is shared, but only among real senders.
        if not _post_global_limiter.allow(client_key(request)):
            raise HTTPException(status_code=429, detail="rate limited")
        # The TTL prune runs only past the gates (review of the first fix: two
        # full scans per unauthenticated request, rolled back on the 404 anyway).
        _prune(conn)
        # F-P7-1: per-inbox share first (hard — the recipient can fetch), then
        # the server-wide budget, which evicts the oldest queued mail to fit.
        count, inbox_bytes = conn.execute(
            "SELECT COUNT(*), COALESCE(SUM(LENGTH(CAST(envelope AS BLOB))), 0) FROM mailbox WHERE recipient = ?",
            (recipient,),
        ).fetchone()
        if count >= config.MAX_MAILBOX_PER_RECIPIENT or inbox_bytes + len(req.envelope) > config.MAX_MAILBOX_PER_RECIPIENT_BYTES:
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
    # F-P7-2: the fetch bucket is per authenticated user, charged only once
    # `current_user` has resolved — an unauthenticated request never reaches it.
    if not _fetch_limiter.allow("fetch:" + username):
        raise HTTPException(status_code=429, detail="rate limited")
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
