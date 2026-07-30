"""Endpoint tests for the relay WebSocket — the full request path, in process.

These exercise main.py's `/ws` loop end to end (size cap, ASCII guard, rate
limit, strict validation, room/dispatch logic, CSWSH origin allow-list) using
Starlette's TestClient, complementing the pure-unit tests in test_validation.py.

Run with:  pytest backend/tests/test_ws.py
"""
import json
import os
import sys
import tempfile
import time
from pathlib import Path

# Point the app at a throwaway DB before importing it (accounts.init_db runs at
# import time), and make backend modules importable.
os.environ.setdefault("SECURE_CHAT_DB", os.path.join(tempfile.mkdtemp(), "test_ws.db"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from starlette.websockets import WebSocketDisconnect  # noqa: E402

import config  # noqa: E402
import main  # noqa: E402
from main import app  # noqa: E402

client = TestClient(app)

_room_seq = 0


def _room() -> str:
    """A fresh, valid 64-hex room id per call (keeps tests independent)."""
    global _room_seq
    _room_seq += 1
    return f"{_room_seq:064x}"


def _recv(ws) -> dict:
    return json.loads(ws.receive_text())


def _join(ws, room: str) -> dict:
    ws.send_text(json.dumps({"type": "join", "room": room}))
    return _recv(ws)


def _knock(ws, room: str, payload: str = "aGk=") -> None:
    ws.send_text(json.dumps({"type": "knock", "room": room, "payload": payload}))


def _admit(owner, room: str, jid: str) -> None:
    owner.send_text(json.dumps({"type": "admit", "room": room, "jid": jid}))


def _pair(owner, guest, room: str) -> str:
    """Run the full admission dance and return the guest's join id.

    P-08: the second party no longer just walks in — it waits, introduces
    itself, and the owner admits it. Every test that needs two peers in a room
    goes through this, so the tests exercise the real path.
    """
    assert _join(owner, room) == {"type": "joined", "role": "owner"}
    assert _join(guest, room) == {"type": "pending"}
    _knock(guest, room)
    knock = _recv(owner)
    assert knock["type"] == "knock" and knock["payload"] == "aGk="
    _admit(owner, room, knock["jid"])
    assert _recv(guest) == {"type": "joined", "role": "guest"}
    return knock["jid"]


# ---- happy paths ----------------------------------------------------------

def test_join_returns_joined_as_owner():
    with client.websocket_connect("/ws") as ws:
        assert _join(ws, _room()) == {"type": "joined", "role": "owner"}


def test_msg_relayed_verbatim_between_peers():
    room = _room()
    with client.websocket_connect("/ws") as a, client.websocket_connect("/ws") as b:
        _pair(a, b, room)
        a.send_text(json.dumps({"type": "msg", "room": room, "payload": "QUJD", "alg": "DHKE"}))
        relayed = _recv(b)
        # The server forwards the opaque payload unchanged; it never decrypts.
        assert relayed["type"] == "msg"
        assert relayed["payload"] == "QUJD"
        assert relayed["alg"] == "DHKE"


def test_key_handshake_relayed():
    room = _room()
    with client.websocket_connect("/ws") as a, client.websocket_connect("/ws") as b:
        _pair(a, b, room)
        a.send_text(json.dumps({"type": "key", "room": room, "payload": "QUJD"}))
        relayed = _recv(b)
        assert relayed["type"] == "key"
        assert relayed["payload"] == "QUJD"


# ---- dispatch / state rules ----------------------------------------------

def test_msg_before_join_rejected():
    with client.websocket_connect("/ws") as ws:
        ws.send_text(json.dumps({"type": "msg", "room": _room(), "payload": "QUJD"}))
        assert _recv(ws) == {"type": "error", "reason": "not in room"}


def test_double_join_rejected():
    room = _room()
    with client.websocket_connect("/ws") as ws:
        assert _join(ws, room)["type"] == "joined"
        ws.send_text(json.dumps({"type": "join", "room": room}))
        assert _recv(ws) == {"type": "error", "reason": "already joined"}


def test_msg_to_other_room_rejected():
    with client.websocket_connect("/ws") as ws:
        _join(ws, _room())
        ws.send_text(json.dumps({"type": "msg", "room": _room(), "payload": "QUJD"}))
        assert _recv(ws) == {"type": "error", "reason": "not in room"}


def test_third_party_waits_and_cannot_be_seated_in_a_full_room():
    room = _room()
    with client.websocket_connect("/ws") as a, client.websocket_connect("/ws") as b:
        _pair(a, b, room)
        with client.websocket_connect("/ws") as c:
            # A third party is queued, not refused outright...
            assert _join(c, room) == {"type": "pending"}
            _knock(c, room)
            knock = _recv(a)
            # ...and the owner cannot seat it, because both slots are taken.
            _admit(a, room, knock["jid"])
            assert _recv(a) == {"type": "error", "reason": "room full"}


def test_leave_closes_connection():
    room = _room()
    with client.websocket_connect("/ws") as ws:
        _join(ws, room)
        ws.send_text(json.dumps({"type": "leave", "room": room}))
        with pytest.raises(WebSocketDisconnect):
            ws.receive_text()


# ---- room admission (pentest 2026-07-26 P-08) -----------------------------
#
# The finding: room entry was authorized solely by knowing the room id, so
# anyone who learned it could take a slot and lock the invited peer out with
# "room full". These tests pin the property that fixes it — WAITING COSTS THE
# ROOM NOTHING — plus the rules that keep the approval itself meaningful.

def test_squatter_cannot_lock_the_invited_peer_out():
    """The finding itself: a squatter in the queue must not deny the real peer.

    The attacker knows the room id and joins first-but-second (the owner is
    already there). Previously that consumed the last slot. Now the owner can
    still admit the peer it actually invited, and the squatter is left waiting.
    """
    room = _room()
    with client.websocket_connect("/ws") as owner, \
         client.websocket_connect("/ws") as squatter, \
         client.websocket_connect("/ws") as invited:
        assert _join(owner, room) == {"type": "joined", "role": "owner"}
        assert _join(squatter, room) == {"type": "pending"}
        _knock(squatter, room)
        squat_knock = _recv(owner)
        assert _join(invited, room) == {"type": "pending"}
        _knock(invited, room)
        invited_knock = _recv(owner)
        assert squat_knock["jid"] != invited_knock["jid"]

        # The owner admits the peer it wanted and denies the squatter.
        _admit(owner, room, invited_knock["jid"])
        assert _recv(invited) == {"type": "joined", "role": "guest"}
        owner.send_text(json.dumps({"type": "deny", "room": room, "jid": squat_knock["jid"]}))
        assert _recv(squatter) == {"type": "denied"}
        with pytest.raises(WebSocketDisconnect):
            squatter.receive_text()

        # And the real session works.
        owner.send_text(json.dumps({"type": "msg", "room": room, "payload": "QUJD"}))
        assert _recv(invited)["payload"] == "QUJD"


def test_waiting_peer_receives_nothing_before_admission():
    """A knocker must not harvest the handshake while it waits."""
    room = _room()
    with client.websocket_connect("/ws") as owner, \
         client.websocket_connect("/ws") as guest, \
         client.websocket_connect("/ws") as lurker:
        _pair(owner, guest, room)
        assert _join(lurker, room) == {"type": "pending"}
        _knock(lurker, room)
        _recv(owner)  # the knock notification
        owner.send_text(json.dumps({"type": "key", "room": room, "payload": "QUJD"}))
        # The admitted guest gets it; the waiter must not.
        assert _recv(guest)["payload"] == "QUJD"
        lurker.send_text(json.dumps({"type": "msg", "room": room, "payload": "QUJD"}))
        assert _recv(lurker) == {"type": "error", "reason": "not in room"}


def test_waiting_peer_cannot_send_before_admission():
    room = _room()
    with client.websocket_connect("/ws") as owner, client.websocket_connect("/ws") as guest:
        _join(owner, room)
        assert _join(guest, room) == {"type": "pending"}
        for frame in (
            {"type": "msg", "room": room, "payload": "QUJD"},
            {"type": "key", "room": room, "payload": "QUJD"},
        ):
            guest.send_text(json.dumps(frame))
            assert _recv(guest) == {"type": "error", "reason": "not in room"}


def test_only_the_owner_may_admit():
    """The second member must not be able to decide who else comes in."""
    room = _room()
    with client.websocket_connect("/ws") as owner, \
         client.websocket_connect("/ws") as guest, \
         client.websocket_connect("/ws") as third:
        _pair(owner, guest, room)
        assert _join(third, room) == {"type": "pending"}
        _knock(third, room)
        knock = _recv(owner)
        _admit(guest, room, knock["jid"])
        assert _recv(guest) == {"type": "error", "reason": "not the room owner"}


def test_waiting_peer_cannot_admit_itself():
    room = _room()
    with client.websocket_connect("/ws") as owner, client.websocket_connect("/ws") as guest:
        _join(owner, room)
        _join(guest, room)
        _knock(guest, room)
        knock = _recv(owner)
        # Even holding its own (server-issued) jid, a waiter is not in the room.
        _admit(guest, room, knock["jid"])
        assert _recv(guest) == {"type": "error", "reason": "not in room"}


def test_unknown_jid_rejected():
    room = _room()
    with client.websocket_connect("/ws") as owner:
        _join(owner, room)
        _admit(owner, room, "0" * config.JOIN_ID_LENGTH)
        assert _recv(owner) == {"type": "error", "reason": "no such waiting peer"}


def test_jid_from_another_room_does_not_transfer():
    """A jid names a slot in ONE room; it must not be replayable into another."""
    room_a, room_b = _room(), _room()
    with client.websocket_connect("/ws") as owner_a, \
         client.websocket_connect("/ws") as owner_b, \
         client.websocket_connect("/ws") as guest:
        _join(owner_a, room_a)
        _join(owner_b, room_b)
        _join(guest, room_a)
        _knock(guest, room_a)
        knock = _recv(owner_a)
        _admit(owner_b, room_b, knock["jid"])
        assert _recv(owner_b) == {"type": "error", "reason": "no such waiting peer"}


def test_one_knock_per_socket():
    """A knocker cannot flood the owner's approval prompt with identities."""
    room = _room()
    with client.websocket_connect("/ws") as owner, client.websocket_connect("/ws") as guest:
        _join(owner, room)
        _join(guest, room)
        _knock(guest, room)
        _recv(owner)
        _knock(guest, room, "QUJD")
        assert _recv(guest) == {"type": "error", "reason": "already knocked"}


# --- Fix review 2026-07-30 (M-A) ---------------------------------------------
# The owner's approval queue had NO liveness signal: the relay popped a departing
# waiter from `pending` and told nobody, so the owner's client kept the knock
# forever. That was survivable while the client queue was unbounded. Once the
# L-1 cap landed it became a permanent, silent denial of admission — cheap
# connect/knock/disconnect cycles fill the queue with ghosts, and a knocker whose
# entry is dropped can never retry, because the client knocks exactly once and
# `already knocked` refuses a second attempt on the same socket.

def test_owner_is_told_when_a_waiter_departs():
    room = _room()
    with client.websocket_connect("/ws") as owner:
        _join(owner, room)
        with client.websocket_connect("/ws") as guest:
            assert _join(guest, room) == {"type": "pending"}
            _knock(guest, room)
            knock = _recv(owner)
            assert knock["type"] == "knock"
            jid = knock["jid"]
        # The guest is gone; the owner must learn, and by the SAME jid it queued.
        gone = _recv(owner)
        assert gone == {"type": "withdrawn", "room": room, "jid": jid}


def test_withdrawal_carries_no_identity():
    """I2: the notice must add nothing about who was connected when."""
    room = _room()
    with client.websocket_connect("/ws") as owner:
        _join(owner, room)
        with client.websocket_connect("/ws") as guest:
            _join(guest, room)
            _knock(guest, room, "QUJD")
            _recv(owner)
        gone = _recv(owner)
        assert set(gone) == {"type", "room", "jid"}, gone


def test_a_waiter_that_never_knocked_is_also_reported():
    """Otherwise the ghost is simply invisible instead of immortal."""
    room = _room()
    with client.websocket_connect("/ws") as owner:
        _join(owner, room)
        with client.websocket_connect("/ws") as guest:
            assert _join(guest, room) == {"type": "pending"}
        gone = _recv(owner)
        assert gone["type"] == "withdrawn" and gone["room"] == room


def test_repeated_join_and_drop_cycles_do_not_accumulate_pending():
    """The flood shape from the PoC: the queue must return to empty every time.

    MAX_ROOM_PENDING is 4, so without pruning the fifth cycle would find the
    relay-side queue full; with the owner also never told, the owner's client
    queue would keep every one of them.
    """
    room = _room()
    with client.websocket_connect("/ws") as owner:
        _join(owner, room)
        for _ in range(config.MAX_ROOM_PENDING * 3):
            with client.websocket_connect("/ws") as ghost:
                assert _join(ghost, room) == {"type": "pending"}
                _knock(ghost, room)
                assert _recv(owner)["type"] == "knock"
            assert _recv(owner)["type"] == "withdrawn"
        # A genuine peer still gets in afterwards — the point of the whole fix.
        with client.websocket_connect("/ws") as real:
            assert _join(real, room) == {"type": "pending"}
            _knock(real, room)
            assert _recv(owner)["type"] == "knock"


def test_knock_before_join_rejected():
    with client.websocket_connect("/ws") as ws:
        _knock(ws, _room())
        assert _recv(ws) == {"type": "error", "reason": "not waiting"}


def test_owner_cannot_knock():
    room = _room()
    with client.websocket_connect("/ws") as owner:
        _join(owner, room)
        _knock(owner, room)
        assert _recv(owner) == {"type": "error", "reason": "not waiting"}


def test_waiters_are_closed_when_the_owner_leaves():
    """No owner means nobody can approve: the queue is ended, not left hanging."""
    room = _room()
    with client.websocket_connect("/ws") as guest:
        with client.websocket_connect("/ws") as owner:
            _join(owner, room)
            assert _join(guest, room) == {"type": "pending"}
        assert _recv(guest) == {"type": "error", "reason": "room closed"}
        with pytest.raises(WebSocketDisconnect):
            guest.receive_text()


def test_room_with_no_members_admits_nobody():
    """After everyone leaves, a room id is free again — not a haunted queue."""
    room = _room()
    with client.websocket_connect("/ws") as first:
        _join(first, room)
    with client.websocket_connect("/ws") as second:
        # The room was torn down, so this join creates it fresh and owns it.
        assert _join(second, room) == {"type": "joined", "role": "owner"}


def test_denied_peer_can_retry_but_still_takes_no_slot():
    """Denial is not a ban — but a retry is still only a knock, never a seat."""
    room = _room()
    with client.websocket_connect("/ws") as owner, client.websocket_connect("/ws") as guest:
        _join(owner, room)
        _join(guest, room)
        _knock(guest, room)
        knock = _recv(owner)
        owner.send_text(json.dumps({"type": "deny", "room": room, "jid": knock["jid"]}))
        assert _recv(guest) == {"type": "denied"}
    with client.websocket_connect("/ws") as owner2, client.websocket_connect("/ws") as retry:
        _join(owner2, room)
        assert _join(retry, room) == {"type": "pending"}


def test_silent_waiters_cannot_lock_out_the_invited_peer(monkeypatch):
    """Post-fix review of P-08: the queue must not become the new lockout.

    A socket that joins and never knocks is invisible to the owner, so it cannot
    be denied. MAX_ROOM_PENDING of them used to reproduce the original "room
    full" lockout for the full approval window. A newcomer now displaces the
    oldest silent waiter instead of being refused — once that waiter is past the
    grace it gets to introduce itself in (see the next test).
    """
    monkeypatch.setattr(config, "KNOCK_GRACE_SEC", 0.01)
    room = _room()
    with client.websocket_connect("/ws") as owner:
        _join(owner, room)
        silent = [client.websocket_connect("/ws") for _ in range(config.MAX_ROOM_PENDING)]
        opened = [s.__enter__() for s in silent]
        try:
            for s in opened:
                assert _join(s, room) == {"type": "pending"}
            time.sleep(0.02)  # let the squatters age past the grace
            with client.websocket_connect("/ws") as invited:
                # The invited peer gets in the queue...
                assert _join(invited, room) == {"type": "pending"}
                # ...at the cost of the oldest silent squatter, which is closed.
                assert _recv(opened[0]) == {"type": "error", "reason": "approval timeout"}
                # And it can still be admitted for real.
                _knock(invited, room)
                knock = _recv(owner)
                _admit(owner, room, knock["jid"])
                assert _recv(invited) == {"type": "joined", "role": "guest"}
        finally:
            for s in silent:
                s.__exit__(None, None, None)


def test_a_waiter_inside_the_grace_is_never_displaced():
    """The displacement primitive must not be aimable at the invited peer.

    Post-fix pentest (G-3): every honest peer is un-knocked for one round trip
    too — between being told `pending` and its knock landing. An attacker
    holding the rest of the queue could fire a join in exactly that window and
    evict the invited peer before it could introduce itself (milliseconds on
    loopback, hundreds over an .onion). Nothing is displaced inside the grace,
    so the newcomer is refused instead of an innocent waiter dropped.
    """
    room = _room()
    with client.websocket_connect("/ws") as owner:
        _join(owner, room)
        waiters = [client.websocket_connect("/ws") for _ in range(config.MAX_ROOM_PENDING)]
        opened = [w.__enter__() for w in waiters]
        try:
            for w in opened:
                assert _join(w, room) == {"type": "pending"}
            # The last one in stands for the invited peer, still pre-knock.
            with client.websocket_connect("/ws") as attacker:
                assert _join(attacker, room) == {"type": "error", "reason": "room full"}
            # Pentest 2026-07-27 M-1: the refused join is now REPORTED to the
            # owner, so the lockout is visible instead of silent.
            assert _recv(owner) == {"type": "turned-away", "count": 1}
            # It is still queued, and can still introduce itself.
            _knock(opened[-1], room)
            knock = _recv(owner)
            _admit(owner, room, knock["jid"])
            assert _recv(opened[-1]) == {"type": "joined", "role": "guest"}
        finally:
            for w in waiters:
                w.__exit__(None, None, None)


def test_knockers_are_not_displaced_by_a_newcomer():
    """Only SILENT waiters yield: a peer the owner can see keeps its place."""
    room = _room()
    with client.websocket_connect("/ws") as owner:
        _join(owner, room)
        waiters = [client.websocket_connect("/ws") for _ in range(config.MAX_ROOM_PENDING)]
        opened = [w.__enter__() for w in waiters]
        try:
            for w in opened:
                _join(w, room)
                _knock(w, room)
                _recv(owner)  # the owner is shown each one
            with client.websocket_connect("/ws") as extra:
                assert _join(extra, room) == {"type": "error", "reason": "room full"}
            # No knocker was evicted.
            for w in opened:
                w.send_text(json.dumps({"type": "knock", "room": room, "payload": "QUJD"}))
                assert _recv(w) == {"type": "error", "reason": "already knocked"}
        finally:
            for w in waiters:
                w.__exit__(None, None, None)


def test_silent_waiter_gets_the_short_deadline(monkeypatch):
    """A queue place is only HELD by an introduction the owner can refuse."""
    monkeypatch.setattr(config, "KNOCK_TIMEOUT_SEC", 0.05)
    monkeypatch.setattr(config, "PENDING_TIMEOUT_SEC", 30)
    room = _room()
    with client.websocket_connect("/ws") as owner, client.websocket_connect("/ws") as silent:
        _join(owner, room)
        assert _join(silent, room) == {"type": "pending"}
        assert _recv(silent) == {"type": "error", "reason": "approval timeout"}


def test_approval_timeout_drops_a_silent_waiter(monkeypatch):
    monkeypatch.setattr(config, "PENDING_TIMEOUT_SEC", 0.05)
    room = _room()
    with client.websocket_connect("/ws") as owner, client.websocket_connect("/ws") as guest:
        _join(owner, room)
        assert _join(guest, room) == {"type": "pending"}
        assert _recv(guest) == {"type": "error", "reason": "approval timeout"}
        with pytest.raises(WebSocketDisconnect):
            guest.receive_text()


# ---- front-door rejections ------------------------------------------------

def test_oversized_frame_rejected():
    big = "A" * (config.MAX_FRAME_BYTES + 10)
    raw = '{"type":"msg","room":"' + ("a" * 64) + '","payload":"' + big + '"}'
    assert len(raw.encode()) > config.MAX_FRAME_BYTES
    with client.websocket_connect("/ws") as ws:
        ws.send_text(raw)
        assert _recv(ws) == {"type": "error", "reason": "frame too large"}


def test_non_ascii_frame_rejected():
    with client.websocket_connect("/ws") as ws:
        ws.send_text('{"type":"join","room":"café"}')
        assert _recv(ws) == {"type": "error", "reason": "non-ascii"}


def test_bad_envelope_rejected():
    with client.websocket_connect("/ws") as ws:
        ws.send_text("{not json")
        assert _recv(ws) == {"type": "error", "reason": "bad envelope"}
        # Connection stays open after a soft rejection.
        ws.send_text(json.dumps({"type": "join", "room": _room()}))
        assert _recv(ws)["type"] == "joined"


def test_extra_field_rejected_over_the_wire():
    with client.websocket_connect("/ws") as ws:
        ws.send_text(json.dumps({"type": "join", "room": _room(), "evil": "x"}))
        assert _recv(ws) == {"type": "error", "reason": "bad envelope"}


def test_rate_limit_kicks_in_under_flood():
    # Bucket starts full (capacity) then refills slowly; a tight burst of
    # capacity+ frames must produce at least one rate-limit rejection.
    n = config.RATE_BUCKET_CAPACITY + 15
    reasons = []
    with client.websocket_connect("/ws") as ws:
        for _ in range(n):
            ws.send_text("{}")  # ascii, in-size, but invalid envelope
            reasons.append(_recv(ws).get("reason"))
    assert "rate limited" in reasons
    assert reasons.count("bad envelope") <= config.RATE_BUCKET_CAPACITY


# ---- CSWSH origin allow-list ---------------------------------------------

def test_disallowed_origin_rejected():
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect("/ws", headers={"origin": "http://evil.example"}):
            pass


def test_allowed_origin_accepted():
    origin = next(iter(config.ALLOWED_WS_ORIGINS))
    with client.websocket_connect("/ws", headers={"origin": origin}) as ws:
        assert _join(ws, _room())["type"] == "joined"


def test_missing_origin_accepted():
    # Native/CLI clients send no Origin header and must be allowed.
    with client.websocket_connect("/ws") as ws:
        assert _join(ws, _room())["type"] == "joined"


# ---- connection-level DoS bounds -----------------------------------------

def test_connection_cap_refuses_when_full(monkeypatch):
    monkeypatch.setattr(main.connections, "max_connections", 2)
    main.connections.active = 0  # start from a clean count for this test
    with client.websocket_connect("/ws") as a, client.websocket_connect("/ws") as b:
        assert _join(a, _room())["type"] == "joined"
        assert _join(b, _room())["type"] == "joined"
        # Third connection is over the cap -> refused at the handshake.
        with pytest.raises(WebSocketDisconnect):
            with client.websocket_connect("/ws"):
                pass
    # Slots are released as connections close.
    assert main.connections.active == 0


def test_idle_timeout_closes_silent_connection(monkeypatch):
    # Generous JOIN window so this exercises the post-join IDLE path.
    monkeypatch.setattr(config, "JOIN_TIMEOUT_SEC", 5)
    monkeypatch.setattr(config, "IDLE_TIMEOUT_SEC", 0.3)
    with client.websocket_connect("/ws") as ws:
        assert _join(ws, _room())["type"] == "joined"
        # Joined but then silent: the server times out, warns, and closes.
        assert _recv(ws) == {"type": "error", "reason": "idle timeout"}
        with pytest.raises(WebSocketDisconnect):
            ws.receive_text()


def test_join_timeout_drops_unjoined_connection(monkeypatch):
    # A connection that never joins must be dropped fast (slot-squat defence),
    # on the short JOIN deadline rather than the generous idle window.
    monkeypatch.setattr(config, "JOIN_TIMEOUT_SEC", 0.3)
    monkeypatch.setattr(config, "IDLE_TIMEOUT_SEC", 999)
    with client.websocket_connect("/ws") as ws:
        assert _recv(ws) == {"type": "error", "reason": "join timeout"}
        with pytest.raises(WebSocketDisconnect):
            ws.receive_text()


# --- Pentest 2026-07-27 M-3: client input must never write a traceback -------
# `receive_text()` does message["text"] unconditionally, so a BINARY frame raised
# a bare KeyError — neither WebSocketDisconnect nor a validation error — which
# fell through to the catch-all `log.exception` and put a full traceback on disk.
# One 3-byte frame produced 636 bytes of log; 200 connections × 1 byte produced
# 127 KB in 0.31 s. That is an I2 defeat (precisely-timestamped who-connected-when
# entries, mintable on demand by anyone) and a log-amplification DoS.

def test_binary_frame_is_answered_politely_not_logged(caplog):
    with caplog.at_level("ERROR"):
        with client.websocket_connect("/ws") as ws:
            ws.send_bytes(b"\x00\x01\x02")
            assert _recv(ws) == {"type": "error", "reason": "binary frames not accepted"}
    assert not [r for r in caplog.records if r.exc_info], "no traceback may be logged"


def test_deeply_nested_json_is_a_bad_envelope_not_a_traceback(caplog):
    # RecursionError from json.loads was not in the except clause either.
    deep = "[" * 20000 + "]" * 20000
    with caplog.at_level("ERROR"):
        with client.websocket_connect("/ws") as ws:
            ws.send_text(deep)
            assert _recv(ws) == {"type": "error", "reason": "bad envelope"}
    assert not [r for r in caplog.records if r.exc_info], "no traceback may be logged"


# --- Pentest 2026-07-27 M-1: a filled queue is reported to the owner ---------

def test_turnaway_notice_is_not_suppressed_on_a_fresh_room():
    """The batching sentinel must not swallow the FIRST notice.

    `time.monotonic()` counts from an arbitrary origin that on Linux is process
    or boot start, so a 0.0 "last notified" sentinel reads as "notified just
    now" for the relay's first TURNAWAY_NOTICE_SEC seconds — exactly the window
    in which a freshly published room is most likely to be raced.
    """
    from relay import Room

    assert Room().turnaway_notified_at == float("-inf")
    assert time.monotonic() - Room().turnaway_notified_at >= config.TURNAWAY_NOTICE_SEC


def test_owner_is_told_when_joins_are_turned_away():
    """A knocked waiter is not displaceable, so a full queue locks everyone out.

    The lockout itself is inherent (the real fix is a cryptographic room-entry
    proof), but it used to be SILENT: the invited peer saw "room full" and the
    owner saw nothing at all. Now the owner is told, with a count, and the
    notices are batched so they cannot themselves be flooded.
    """
    room = _room()
    with client.websocket_connect("/ws") as owner:
        _join(owner, room)
        waiters = [client.websocket_connect("/ws") for _ in range(config.MAX_ROOM_PENDING)]
        opened = [w.__enter__() for w in waiters]
        try:
            for w in opened:
                assert _join(w, room) == {"type": "pending"}
                _knock(w, room)               # knocked waiters are not displaceable
                assert _recv(owner)["type"] == "knock"
            # Every honest join from here is refused before it can even knock.
            with client.websocket_connect("/ws") as invited:
                assert _join(invited, room) == {"type": "error", "reason": "room full"}
            assert _recv(owner) == {"type": "turned-away", "count": 1}

            # Batching: further refusals inside the window do not each mint a
            # frame at the owner (that would make the warning an amplifier).
            for _ in range(3):
                with client.websocket_connect("/ws") as more:
                    assert _join(more, room) == {"type": "error", "reason": "room full"}
            # Nothing further arrives; prove it by round-tripping a real frame.
            owner.send_text(json.dumps({"type": "knock", "room": room, "payload": "aGk="}))
            assert _recv(owner) == {"type": "error", "reason": "not waiting"}
        finally:
            for w in waiters:
                w.__exit__(None, None, None)
