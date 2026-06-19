"""In-memory room registry and per-connection rate limiting.

No message content is ever stored or logged. Rooms live only in memory and
disappear the moment they are empty, so there is no at-rest data to leak.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field

from fastapi import WebSocket

from config import (
    MAX_CONNECTIONS,
    MAX_ROOM_MEMBERS,
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


class RoomRegistry:
    """Maps room id -> set of connected sockets. Pure relay bookkeeping."""

    def __init__(self) -> None:
        self._rooms: dict[str, set[WebSocket]] = {}

    def join(self, room: str, ws: WebSocket) -> bool:
        """Add `ws` to `room`. Returns False if global/room limits are hit."""
        members = self._rooms.get(room)
        if members is None:
            if len(self._rooms) >= MAX_ROOMS:
                return False
            members = set()
            self._rooms[room] = members
        if len(members) >= MAX_ROOM_MEMBERS:
            return False
        members.add(ws)
        return True

    def leave(self, room: str, ws: WebSocket) -> None:
        members = self._rooms.get(room)
        if not members:
            return
        members.discard(ws)
        if not members:
            del self._rooms[room]  # empty rooms leave no trace

    def peers(self, room: str, exclude: WebSocket) -> list[WebSocket]:
        """Everyone in `room` except `exclude` (the sender)."""
        return [w for w in self._rooms.get(room, ()) if w is not exclude]
