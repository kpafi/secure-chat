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
import sqlite3
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


# `DELETE ... RETURNING` (what the counter decrements are derived from, see
# _delete_rows) needs sqlite >= 3.35. Refuse to start loudly rather than fail
# on the first delete (round-3 Info a; the production box has 3.46.1).
_MIN_SQLITE = (3, 35, 0)


def _require_sqlite() -> None:
    if sqlite3.sqlite_version_info < _MIN_SQLITE:
        raise RuntimeError(
            f"sqlite {sqlite3.sqlite_version} is too old: the mailbox needs >= "
            f"{'.'.join(map(str, _MIN_SQLITE))} (DELETE ... RETURNING)"
        )


def _row_floor() -> int:
    """The least any row is charged: MAX_MAILBOX_TOTAL_BYTES / MAX_MAILBOX_TOTAL,
    rounded up, so the ROW cap can never fill before the BYTE budget does."""
    return -(-config.MAX_MAILBOX_TOTAL_BYTES // config.MAX_MAILBOX_TOTAL)


def _row_charge(size: int) -> int:
    """What one envelope costs the global budget, the per-inbox share and the
    heaviest-inbox ranking.

    Round-3 review M-1: the row cap (MAX_MAILBOX_TOTAL) was a second "budget
    full" trigger while victims were ranked by BYTES. 500 accounts x 200
    minimum envelopes (256 B) filled the row cap at only 25.6 MB, and from
    then on every inbox over 51 200 B was "the heaviest" — reaching a 63 KB
    inbox cost 500 accounts, not the ~4 000 the byte budget implies. Charging
    every row at least the per-row share of the byte budget (~2.6 KiB at the
    shipped numbers) makes the two budgets one: the byte budget always fills
    first, the row cap stays as a backstop only, and a minimum-size filler
    weighs what a row of the table really costs. A real sealed envelope is
    ~1.5-3 KB, so honest mail is charged at or near its size."""
    return max(size, _row_floor())


def init_db() -> None:
    _require_sqlite()
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
        # Round-3 review M-1: what a row COSTS the budgets, max(size, the row
        # floor) — see _row_charge. Stored per row so a decrement always takes
        # back exactly what the insert charged, whatever the config says now.
        if "charge" not in cols:
            conn.execute("ALTER TABLE mailbox ADD COLUMN charge INTEGER NOT NULL DEFAULT 0")
        # Indexes first, so the startup repair in _rebuild_counters can find
        # the rows it has to fix from an index instead of reading every
        # envelope body (round-3 Info b: 0.003 s vs 0.058 s measured).
        conn.execute("DROP INDEX IF EXISTS idx_mailbox_recipient")
        conn.execute("DROP INDEX IF EXISTS idx_mailbox_created")
        conn.execute("DROP INDEX IF EXISTS idx_mailbox_expiry")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_mailbox_inbox ON mailbox(recipient, id, size)")
        # The TTL prune is `created_at < ?` on every POST and GET; without an
        # index it scanned the whole table under the write lock (§9 L-2). It
        # also covers size and charge for the startup repair.
        conn.execute("CREATE INDEX IF NOT EXISTS idx_mailbox_age ON mailbox(created_at, size, charge)")
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
    """Repair per-row sizes and charges, then recompute both counter tables
    from the mailbox table (startup only — off the request path).

    Re-review R3: the ALTER that adds a column commits on its own, so a crash
    before a backfill used to leave size = 0 forever and the rebuild summed
    zeros. No real envelope is 0 bytes (MIN_ENVELOPE_BYTES) and no charge is
    below the row floor, so repairing `size = 0` and `charge < max(size,
    floor)` on EVERY start is exact and idempotent. Both are found through the
    covering age index, not by reading envelope bodies (round-3 Info b)."""
    floor = _row_floor()
    conn.execute(
        "UPDATE mailbox SET size = LENGTH(CAST(envelope AS BLOB)) "
        "WHERE id IN (SELECT id FROM mailbox INDEXED BY idx_mailbox_age WHERE size = 0)"
    )
    conn.execute(
        "UPDATE mailbox SET charge = MAX(size, ?) "
        "WHERE id IN (SELECT id FROM mailbox INDEXED BY idx_mailbox_age WHERE charge < MAX(size, ?))",
        (floor, floor),
    )
    conn.execute("DELETE FROM mailbox_totals")
    conn.execute(
        "INSERT INTO mailbox_totals (id, rows, bytes) SELECT 1, COUNT(*), COALESCE(SUM(charge), 0) FROM mailbox"
    )
    conn.execute("DELETE FROM mailbox_inbox")
    conn.execute(
        "INSERT INTO mailbox_inbox (recipient, rows, bytes) "
        "SELECT recipient, COUNT(*), SUM(charge) FROM mailbox GROUP BY recipient"
    )


def _insert(conn, recipient: str, envelope: str) -> None:
    """INSERT one envelope and bump both counters by its CHARGE, in the
    caller's transaction."""
    size = len(envelope.encode("ascii"))
    charge = _row_charge(size)
    conn.execute(
        "INSERT INTO mailbox (recipient, envelope, created_at, size, charge) VALUES (?,?,?,?,?)",
        (recipient, envelope, int(time.time()), size, charge),
    )
    conn.execute("UPDATE mailbox_totals SET rows = rows + 1, bytes = bytes + ? WHERE id = 1", (charge,))
    conn.execute(
        "INSERT INTO mailbox_inbox (recipient, rows, bytes) VALUES (?, 1, ?) "
        "ON CONFLICT(recipient) DO UPDATE SET rows = rows + 1, bytes = bytes + excluded.bytes",
        (recipient, charge),
    )


def _begin_write(conn) -> None:
    """Open the write transaction NOW, before anything is read.

    Re-review R1 (HIGH): with sqlite3's legacy transaction control a SELECT
    opens no transaction and takes no lock. `_prune` read its victims first,
    so N concurrent requests past their gates all saw the same expired rows,
    each then took the lock in turn, and every one of them subtracted the full
    size from the counters although only the first actually deleted anything
    (live PoC: 20 concurrent GETs over 60 x 64 KiB expired rows -> counters
    (-1140, -74 711 040) vs real (0, 0); the budgets were off until restart).
    BEGIN IMMEDIATE takes the write lock up front, so every read that a
    counter update is derived from happens under the lock that also covers
    the update. (It also serialises two overlapping fetches of one inbox,
    which used to be able to return the same envelopes twice.)
    """
    # Round-3 Info d: never "join" a transaction someone already opened — a
    # deferred one may have read without the lock, which is the R1 bug again.
    if conn.in_transaction:
        raise RuntimeError("_begin_write: a transaction is already open")
    conn.execute("BEGIN IMMEDIATE")


def _delete_rows(conn, ids) -> None:
    """DELETE the rows with these ids and decrement both counters by what was
    ACTUALLY deleted (`RETURNING`), in the caller's transaction.

    Every delete of mailbox rows goes through here (prune, fetch, eviction).
    Re-review R1: the decrement used to be computed from the caller's earlier
    SELECT, so a row someone else had already deleted was subtracted again.
    Counting the RETURNING rows makes the update follow the table whatever
    the caller believed."""
    ids = list(ids)
    per: dict[str, list[int]] = {}
    # Chunked: one statement may bind at most SQLITE_MAX_VARIABLE_NUMBER
    # (32 766) parameters, and a prune after downtime can exceed that.
    for i in range(0, len(ids), 500):
        chunk = ids[i:i + 500]
        gone = conn.execute(
            "DELETE FROM mailbox WHERE id IN (%s) RETURNING recipient, charge" % ",".join("?" * len(chunk)),
            chunk,
        ).fetchall()
        for recipient, charge in gone:
            agg = per.setdefault(recipient, [0, 0])
            agg[0] += 1
            agg[1] += charge
    if not per:
        return
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
    """Delete expired mail. Caller has opened the write transaction
    (`_begin_write`), so the victim list cannot be stale."""
    cutoff = int(time.time()) - config.MAILBOX_TTL_SEC
    ids = [r[0] for r in conn.execute(
        "SELECT id FROM mailbox INDEXED BY idx_mailbox_age WHERE created_at < ?", (cutoff,)
    ).fetchall()]
    _delete_rows(conn, ids)


def _totals(conn) -> tuple[int, int]:
    row = conn.execute("SELECT rows, bytes FROM mailbox_totals WHERE id = 1").fetchone()
    return (row[0], row[1]) if row else (0, 0)


class _NoRoom(Exception):
    """The budget is full and the recipient's own inbox is the heaviest."""


def _evict_to_fit(conn, recipient: str, incoming: int) -> None:  # incoming = the new row's CHARGE
    """When the server-wide budget is full, evict the NEWEST envelope of the
    HEAVIEST inbox other than the recipient's, one at a time and only until
    the incoming envelope fits. If the recipient's own inbox is the heaviest,
    refuse the incoming envelope instead (`_NoRoom` -> 429).

    History. F-P7-1 replaced a relay-wide 503 with eviction. The first cut
    evicted the globally OLDEST rows, so throwaway accounts flooding their own
    inboxes silently deleted everyone's queued mail (fix review F1: victim got
    0 of 3). Heaviest-OLDEST fixed that for strangers, but the re-review (R2)
    showed a HANDLE HOLDER could pad the victim's inbox to the per-inbox cap,
    keep ~budget/cap own inboxes just under it (~65 accounts, ~2 minutes) and
    have the victim's OLDEST envelope — the honest mail queued before the
    padding — evicted next. Weights are CHARGES (_row_charge), so the row cap
    can no longer make a light inbox "the heaviest" (round-3 M-1).

    Why NEWEST of the heaviest. The relay cannot tell padding from mail under
    sealed sender, so the eviction order is the only lever it has. Newest-
    first means that mail queued before a flood or before padding is the last
    thing an inbox loses; where it can, the relay degrades LOUDLY instead: an
    inbox at its per-inbox cap refuses new mail with 429, and while the
    recipient's own inbox is the heaviest under a full budget, new mail to it
    is refused (429) rather than evicting anything.

    Residual, stated precisely (round-3 M-2 — it is continuous, not one-off):
      * a HANDLE HOLDER can suppress a victim's incoming mail CONTINUOUSLY, for
        as long as the victim is offline: pad the victim's inbox so it is the
        heaviest but leave room under the per-inbox cap, keep the budget full
        with lighter inboxes of their own (~MAX_MAILBOX_TOTAL_BYTES /
        MAX_MAILBOX_PER_RECIPIENT_BYTES + 1 accounts, ~65), then loop: fetch
        some of their own filler to open space, honest mail to the victim
        lands (its sender sees 200), post filler again, and the overflow evicts
        the victim's NEWEST envelope — that honest mail. The running cost is
        flat. Mail queued BEFORE the padding survives until all newer mail in
        that inbox is gone. The relay cannot distinguish padding from mail
        under sealed sender, so this is inherent to a bounded, shared store;
        the victim sees it (their inbox is full of undecryptable junk) once
        they come online and fetch;
      * WITHOUT the handle, an inbox is reached only once it is the heaviest
        left, i.e. after the attacker holds the whole budget in inboxes
        charged no more than it: ~MAX_MAILBOX_TOTAL_BYTES / (its charged
        bytes) accounts — ~4 300 for a 63 KB inbox, ~29 000 for 9 KiB, and
        never fewer than MAX_MAILBOX_TOTAL / MAX_MAILBOX_PER_RECIPIENT = 500
        (a full inbox of minimum-size filler is charged 200 x ~2.6 KiB);
      * an honest inbox that is simply the heaviest (someone offline receiving
        a lot) loses its newest mail first, and while it is the heaviest new
        mail to it is refused (429) under a full budget.
    Ties are broken away from the recipient (see below), so a recipient tied
    for heaviest is not refused while another inbox of equal weight exists.
    """
    for _ in range(4096):
        rows, total = _totals(conn)
        if rows < config.MAX_MAILBOX_TOTAL and total + incoming <= config.MAX_MAILBOX_TOTAL_BYTES:
            return
        top = conn.execute(
            "SELECT recipient, bytes FROM mailbox_inbox ORDER BY bytes DESC LIMIT 2"
        ).fetchall()
        if not top:
            return
        # Tie-break away from the recipient: the index returns equal weights
        # in no particular order, so look at the first two.
        pick = top[0][0]
        if pick == recipient:
            if len(top) > 1 and top[1][1] == top[0][1]:
                pick = top[1][0]
            else:
                raise _NoRoom()
        victim = conn.execute(
            "SELECT id FROM mailbox INDEXED BY idx_mailbox_inbox WHERE recipient = ? ORDER BY id DESC LIMIT 1",
            (pick,),
        ).fetchone()
        if victim is None:  # counter row with no mail behind it: drop it and look again
            conn.execute("DELETE FROM mailbox_inbox WHERE recipient = ?", (pick,))
            continue
        _delete_rows(conn, [victim[0]])


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
        # Past the gate only: take the write lock NOW (re-review R1), so the
        # prune's victim list, the cap checks and the insert all happen under
        # one lock and cannot interleave with another request's writes.
        _begin_write(conn)
        _prune(conn)
        # F-P7-1: per-inbox share first (hard — the recipient can fetch), then
        # the server-wide budget, which evicts from the heaviest inbox to fit.
        # Both read the maintained counters (F2), never the table.
        inbox = conn.execute(
            "SELECT rows, bytes FROM mailbox_inbox WHERE recipient = ?", (recipient,)
        ).fetchone()
        count, inbox_bytes = (inbox[0], inbox[1]) if inbox else (0, 0)
        charge = _row_charge(len(req.envelope))
        if (count >= config.MAX_MAILBOX_PER_RECIPIENT
                or inbox_bytes + charge > config.MAX_MAILBOX_PER_RECIPIENT_BYTES):
            raise HTTPException(status_code=429, detail="recipient inbox full")
        try:
            _evict_to_fit(conn, recipient, charge)
        except _NoRoom:
            # Loud, not silent: the budget is full and this inbox is the
            # heaviest, so the NEW envelope is refused rather than evicting
            # older mail (re-review R2). The sender can retry.
            raise HTTPException(status_code=429, detail="recipient inbox full")
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
        _begin_write(conn)  # re-review R1: lock before reading anything we delete
        _prune(conn)
        # Bound the response explicitly (P-11) rather than relying on the
        # per-inbox insert cap to be the only limit. Anything beyond this stays
        # queued for the next fetch.
        rows = conn.execute(
            "SELECT id, envelope, created_at FROM mailbox WHERE recipient = ? ORDER BY id LIMIT ?",
            (username, config.MAX_MAILBOX_PER_RECIPIENT),
        ).fetchall()
        _delete_rows(conn, [r["id"] for r in rows])
    return {"messages": [{"envelope": r["envelope"], "created_at": r["created_at"]} for r in rows]}
