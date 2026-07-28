"""In-memory room registry and per-connection rate limiting.

No message content is ever stored or logged. Rooms live only in memory and
disappear the moment they are empty, so there is no at-rest data to leak.
"""
from __future__ import annotations

import secrets
import threading
import time
from dataclasses import dataclass, field
from enum import Enum

from fastapi import WebSocket

import config
from config import (
    JOIN_ID_LENGTH,
    MAX_CONNECTIONS,
    MAX_ROOM_MEMBERS,
    MAX_ROOM_PENDING,
    MAX_ROOMS,
    RATE_BUCKET_CAPACITY,
    RATE_REFILL_PER_SEC,
)


@dataclass
class TokenBucket:
    """Classic token bucket for per-connection rate limiting.

    Starts full so a fresh connection may burst up to `capacity`, then refills
    at `refill_per_sec`. Cheap, allocation-free, and easy to reason about.
    """

    capacity: int = RATE_BUCKET_CAPACITY
    refill_per_sec: float = RATE_REFILL_PER_SEC
    tokens: float = field(default=0.0)
    last: float = field(default_factory=time.monotonic)

    def __post_init__(self) -> None:
        self.tokens = float(self.capacity)

    def allow(self) -> bool:
        now = time.monotonic()
        self.tokens = min(
            float(self.capacity),
            self.tokens + (now - self.last) * self.refill_per_sec,
        )
        self.last = now
        if self.tokens >= 1.0:
            self.tokens -= 1.0
            return True
        return False


class KeyedRateLimiter:
    """Per-key token-bucket rate limiter (e.g. one bucket per client host).

    Behind Tor all requests share the loopback key, so this collapses to a
    single global throttle — the meaningful control there. Off-Tor it limits
    per source. Stale (full, untouched) buckets are pruned to bound memory.
    """

    def __init__(self, capacity: int, refill_per_sec: float) -> None:
        self._capacity = capacity
        self._refill = refill_per_sec
        self._buckets: dict[str, TokenBucket] = {}
        self._last_prune = time.monotonic()
        # Pentest 2026-07-26 (fix review): these limiters back the /api HTTP
        # endpoints, whose handlers are sync `def`s and therefore run in the
        # anyio THREADPOOL — genuinely concurrent, unlike the single-event-loop
        # assumption the WS relay is written against. `_prune` iterated
        # `_buckets` while other worker threads inserted into it via `allow`,
        # which can raise "dictionary changed size during iteration" -> an
        # unhandled 500 plus a traceback on disk (against the I2 no-metadata-at-
        # rest goal). The read-modify-write in `allow` was likewise not atomic,
        # so two threads could each mint a bucket for the same key and one
        # request would escape the limit. One lock covers both.
        self._lock = threading.Lock()

    def _prune(self, now: float) -> None:
        """Drop fully-refilled idle buckets. Caller MUST hold `self._lock`."""
        if now - self._last_prune < 60.0:
            return
        self._last_prune = now
        stale = [
            k for k, b in list(self._buckets.items())
            if b.tokens >= b.capacity and now - b.last > 60.0
        ]
        for k in stale:
            self._buckets.pop(k, None)

    def allow(self, key: str) -> bool:
        with self._lock:
            self._prune(time.monotonic())
            bucket = self._buckets.get(key)
            if bucket is None:
                bucket = TokenBucket(capacity=self._capacity, refill_per_sec=self._refill)
                self._buckets[key] = bucket
            return bucket.allow()


@dataclass
class ConnectionLimiter:
    """Bounds total concurrent connections (FD / memory DoS guard).

    Single-event-loop use only: `try_acquire`/`release` mutate `active` without
    awaiting, so there is no interleaving on asyncio's cooperative scheduler.
    """

    max_connections: int = MAX_CONNECTIONS
    active: int = 0

    def try_acquire(self) -> bool:
        """Reserve a slot if one is free. Returns False when at capacity."""
        if self.active >= self.max_connections:
            return False
        self.active += 1
        return True

    def release(self) -> None:
        if self.active > 0:
            self.active -= 1


@dataclass
class Conn:
    """Per-connection relay state, shared between the socket's own read loop and
    whichever coroutine acts on it.

    Admission is performed by the OWNER's coroutine, not the joiner's, so the
    joiner's "am I in?" state cannot live in a local variable of its own loop —
    the owner would have no way to flip it. It lives here instead, and every
    branch of the read loop consults this object.
    """

    ws: WebSocket
    room: str | None = None   # set when admitted (owner: at join; guest: at admit)
    admitted: bool = False
    waiting_room: str | None = None  # room whose queue we are in, while waiting
    jid: str | None = None           # our place in that queue
    knocked: bool = False            # one introduction per socket
    queued_at: float = 0.0           # when we entered the queue (displacement grace)


@dataclass
class Room:
    """One room's membership: who is in, who is waiting, and who decides.

    `members` are ADMITTED connections and are the only ones that may exchange
    frames; `pending` are connections waiting for the owner's verdict, keyed by
    the server-issued join id. The two are counted separately on purpose — see
    RoomRegistry.join.
    """

    # Insertion-ordered so the oldest member is unambiguous (ownership passes
    # down that order when an owner leaves).
    members: list[Conn] = field(default_factory=list)
    pending: dict[str, Conn] = field(default_factory=dict)

    # Pentest 2026-07-27 M-1: how many joins this room has refused since the
    # owner was last told, and when it was last told. A KNOCKED waiter holds its
    # place for the full approval window and is not displaceable, so filling all
    # MAX_ROOM_PENDING places with knocked sockets makes every honest join fail
    # with "room full" BEFORE it is issued a jid — it cannot knock, and the owner
    # never learns anyone was turned away. The lockout itself is inherent (a
    # hostile relay can deny service regardless, and the real fix is the
    # cryptographic room-entry proof the design already notes); what was missing
    # is that it was SILENT, so both people sat waiting for each other with no
    # sign that the room was under pressure. Now the owner is told.
    turned_away: int = 0
    # -inf, not 0.0: `time.monotonic()` is measured from an arbitrary point that
    # on Linux is process/boot start, so a 0.0 sentinel would read as "notified
    # just now" for the relay's first TURNAWAY_NOTICE_SEC seconds and swallow the
    # very first notice — precisely when a room is most likely to be raced.
    turnaway_notified_at: float = float("-inf")

    @property
    def owner(self) -> Conn | None:
        """The connection that created the room, or the oldest remaining one."""
        return self.members[0] if self.members else None

    def is_empty(self) -> bool:
        return not self.members and not self.pending


class JoinResult(str, Enum):
    """Outcome of a join attempt (see RoomRegistry.join)."""

    admitted = "admitted"   # room was empty: caller created it and owns it
    waiting = "waiting"     # room exists: caller is queued for approval
    full = "full"           # no room left in the waiting queue
    no_rooms = "no_rooms"   # server-wide room cap reached


class RoomRegistry:
    """Maps room id -> Room. Pure relay bookkeeping; no crypto, no content.

    Pentest 2026-07-26 P-08 (room-slot squatting): membership used to be
    first-come-first-served, so anyone who learned a room id could take one of
    the two slots and lock the real peer out with "room full". Now the first
    joiner OWNS the room and every later joiner only WAITS; a waiting connection
    occupies no member slot, so a squatter can no longer take the room from the
    invited peer — it can only ask to be let in, which the owner sees and
    refuses. What the relay does NOT do is decide who anyone is: the knock is an
    opaque blob it forwards, and the identity that matters is re-checked by the
    clients during the signed handshake.

    Two availability limits remain, deliberately (a real fix is a cryptographic
    room-entry proof, i.e. a protocol change, and a hostile relay can deny
    service anyway):
      * whoever joins an EMPTY room first owns it, so an attacker who learns a
        room id and wins the race owns the room and can refuse everyone;
      * the waiting queue is finite, so knockers can still fill it — but only
        while visible to the owner, who can deny them (see `join`).
    """

    def __init__(self) -> None:
        self._rooms: dict[str, Room] = {}

    def join(self, room: str, conn: Conn) -> tuple[JoinResult, Conn | None]:
        """Admit `conn` as owner of an empty `room`, or queue it for approval.

        Mutates `conn` with the resulting state (room/admitted, or jid). The
        second element is a silent waiter evicted to make room, if any — the
        caller closes it.
        """
        entry = self._rooms.get(room)
        if entry is None:
            if len(self._rooms) >= MAX_ROOMS:
                return JoinResult.no_rooms, None
            entry = Room()
            self._rooms[room] = entry
            entry.members.append(conn)
            conn.room = room
            conn.admitted = True
            return JoinResult.admitted, None
        # A room whose members have all left has nobody to approve anyone, so
        # it can admit nobody; it is torn down in leave() rather than lingering.
        if not entry.members:
            return JoinResult.full, None
        now = time.monotonic()
        evicted: Conn | None = None
        if len(entry.pending) >= MAX_ROOM_PENDING:
            # Post-fix review of P-08: a socket that joined but never knocked is
            # invisible to the owner, so it cannot be denied — MAX_ROOM_PENDING
            # of them reproduced the original lockout for the whole approval
            # window. A queue place is therefore only *held* by an introduction:
            # under pressure the oldest silent waiter yields to the newcomer.
            # (pending is insertion-ordered, so this is oldest-first.)
            #
            # The KNOCK_GRACE_SEC condition is what stops that becoming a weapon
            # of its own: an honest peer is also un-knocked for one round trip,
            # and without the grace an attacker holding the rest of the queue
            # could time a join to evict the invited peer inside exactly that
            # window. Nobody is displaced before they have had a fair chance to
            # introduce themselves; if that leaves nothing displaceable, the
            # NEWCOMER is refused rather than an innocent waiter dropped.
            evicted = next(
                (
                    c for c in entry.pending.values()
                    # Read live from `config` (not import-bound) so the grace stays
                    # tunable and testable, like the read timeouts in main.py.
                    if not c.knocked and now - c.queued_at >= config.KNOCK_GRACE_SEC
                ),
                None,
            )
            if evicted is None:
                return JoinResult.full, None
            entry.pending.pop(evicted.jid, None)
            evicted.waiting_room = None
            evicted.jid = None
        jid = secrets.token_hex(JOIN_ID_LENGTH // 2)
        entry.pending[jid] = conn
        conn.waiting_room = room
        conn.jid = jid
        conn.queued_at = now
        return JoinResult.waiting, evicted

    def note_turned_away(self, room: str) -> tuple[Conn | None, int]:
        """Record a refused join and, at most once per notice window, report it.

        Returns (owner, count-since-last-notice) when the owner should be told,
        else (None, 0). The window is what stops the notice being a weapon of its
        own: without it, an attacker holding the queue could also make the relay
        send the owner one frame per join attempt — turning a signal meant to
        reveal the flood into an amplifier for it. Batched, the owner learns the
        room is under pressure at a bounded rate, and the count carries the scale.
        """
        entry = self._rooms.get(room)
        if entry is None or not entry.members:
            return None, 0
        entry.turned_away += 1
        now = time.monotonic()
        if now - entry.turnaway_notified_at < config.TURNAWAY_NOTICE_SEC:
            return None, 0
        entry.turnaway_notified_at = now
        count = entry.turned_away
        entry.turned_away = 0
        return entry.owner, count

    def has_free_slot(self, room: str) -> bool:
        entry = self._rooms.get(room)
        return entry is not None and len(entry.members) < MAX_ROOM_MEMBERS

    def is_owner(self, room: str, conn: Conn) -> bool:
        entry = self._rooms.get(room)
        return entry is not None and entry.owner is conn

    def owner_of(self, room: str) -> Conn | None:
        entry = self._rooms.get(room)
        return entry.owner if entry else None

    def admit(self, room: str, jid: str) -> Conn | None:
        """Seat a waiting connection. None if it cannot be seated.

        The member cap is enforced HERE, not at join time: that is what stops
        the cap from being a squatting tool. An admit into a full room fails and
        the knocker stays queued, so the owner is told rather than someone being
        silently dropped.
        """
        entry = self._rooms.get(room)
        if entry is None:
            return None
        conn = entry.pending.get(jid)
        if conn is None or len(entry.members) >= MAX_ROOM_MEMBERS:
            return None
        del entry.pending[jid]
        entry.members.append(conn)
        conn.room = room
        conn.admitted = True
        conn.waiting_room = None
        conn.jid = None
        return conn

    def deny(self, room: str, jid: str) -> Conn | None:
        """Drop a waiting connection from the queue and return it (to close)."""
        entry = self._rooms.get(room)
        if entry is None:
            return None
        conn = entry.pending.pop(jid, None)
        if conn is not None:
            conn.waiting_room = None
            conn.jid = None
        return conn

    def leave(self, room: str, conn: Conn) -> list[Conn]:
        """Remove `conn` from `room`, member or waiting.

        Returns the connections left orphaned by this departure: when the last
        MEMBER goes, nobody can approve the queue any more, so those waiters are
        handed back to be closed instead of waiting out the approval timeout.
        """
        entry = self._rooms.get(room)
        if entry is None:
            return []
        if conn in entry.members:
            entry.members.remove(conn)
        if conn.jid is not None:
            entry.pending.pop(conn.jid, None)
        conn.admitted = False
        conn.waiting_room = None
        conn.jid = None
        orphans: list[Conn] = []
        if not entry.members:
            orphans = list(entry.pending.values())
            for orphan in orphans:
                orphan.waiting_room = None
                orphan.jid = None
            entry.pending.clear()
        if entry.is_empty():
            del self._rooms[room]  # empty rooms leave no trace
        return orphans

    def peers(self, room: str, exclude: Conn) -> list[Conn]:
        """Every ADMITTED member of `room` except `exclude` (the sender).

        Waiting connections are deliberately excluded: until the owner admits
        them they receive nothing, so a knocker cannot harvest the handshake.
        """
        entry = self._rooms.get(room)
        if entry is None:
            return []
        return [c for c in entry.members if c is not exclude]
