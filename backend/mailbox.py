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

_post_limiter = KeyedRateLimiter(config.MAILBOX_RATE_CAPACITY, config.MAILBOX_RATE_REFILL_PER_SEC)

# Envelopes are JSON of base64 fields — printable ASCII by construction.
_ASCII_RE = re.compile(r"^[\x20-\x7e]+$")

router = APIRouter(prefix="/api/mailbox", tags=["mailbox"])


def _post_rate_limit(request: Request) -> None:
    # Same trusted-proxy-aware keying as the /api limiters (pentest F-03).
    if not _post_limiter.allow(client_key(request)):
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


def _prune(conn) -> None:
    conn.execute("DELETE FROM mailbox WHERE created_at < ?", (int(time.time()) - config.MAILBOX_TTL_SEC,))


class PostReq(BaseModel):
    model_config = ConfigDict(extra="forbid")
    envelope: str = Field(min_length=1, max_length=config.MAX_ENVELOPE_BYTES)


@router.post("/{recipient}", dependencies=[Depends(_post_rate_limit)])
def post_mail(recipient: str, req: PostReq, t: str = Query(default="", max_length=64)) -> dict:
    _check_username(recipient)
    if not _ASCII_RE.match(req.envelope):
        raise HTTPException(status_code=422, detail="envelope must be printable ASCII")
    with _db() as conn:
        _prune(conn)
        row = conn.execute(
            "SELECT lookup_token FROM accounts WHERE username = ?", (recipient,)
        ).fetchone()
        # Token gate doubles as the anti-enumeration boundary: wrong token and
        # unknown recipient are the identical 404 (constant-time compare against
        # a decoy for missing users, same as the bundle lookup).
        stored = row["lookup_token"] if row is not None else secrets.token_urlsafe(config.LOOKUP_TOKEN_BYTES)
        if not token_matches(t, stored) or row is None:
            raise HTTPException(status_code=404, detail="no such user")
        total = conn.execute("SELECT COUNT(*) FROM mailbox").fetchone()[0]
        if total >= config.MAX_MAILBOX_TOTAL:
            raise HTTPException(status_code=503, detail="mailbox storage full")
        count = conn.execute(
            "SELECT COUNT(*) FROM mailbox WHERE recipient = ?", (recipient,)
        ).fetchone()[0]
        if count >= config.MAX_MAILBOX_PER_RECIPIENT:
            raise HTTPException(status_code=429, detail="recipient inbox full")
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
    with _db() as conn:
        _prune(conn)
        rows = conn.execute(
            "SELECT id, envelope, created_at FROM mailbox WHERE recipient = ? ORDER BY id",
            (username,),
        ).fetchall()
        if rows:
            ids = [r["id"] for r in rows]
            conn.executemany("DELETE FROM mailbox WHERE id = ?", [(i,) for i in ids])
    return {"messages": [{"envelope": r["envelope"], "created_at": r["created_at"]} for r in rows]}
