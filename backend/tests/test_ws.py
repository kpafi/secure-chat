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


# ---- happy paths ----------------------------------------------------------

def test_join_returns_joined():
    with client.websocket_connect("/ws") as ws:
        assert _join(ws, _room()) == {"type": "joined"}


def test_msg_relayed_verbatim_between_peers():
    room = _room()
    with client.websocket_connect("/ws") as a, client.websocket_connect("/ws") as b:
        assert _join(a, room)["type"] == "joined"
        assert _join(b, room)["type"] == "joined"
        a.send_text(json.dumps({"type": "msg", "room": room, "payload": "QUJD", "alg": "DHKE"}))
        relayed = _recv(b)
        # The server forwards the opaque payload unchanged; it never decrypts.
        assert relayed["type"] == "msg"
        assert relayed["payload"] == "QUJD"
        assert relayed["alg"] == "DHKE"


def test_key_handshake_relayed():
    room = _room()
    with client.websocket_connect("/ws") as a, client.websocket_connect("/ws") as b:
        _join(a, room)
        _join(b, room)
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


def test_room_full_third_member_rejected():
    room = _room()
    with client.websocket_connect("/ws") as a, client.websocket_connect("/ws") as b:
        _join(a, room)
        _join(b, room)
        with client.websocket_connect("/ws") as c:
            c.send_text(json.dumps({"type": "join", "room": room}))
            assert _recv(c) == {"type": "error", "reason": "room full"}


def test_leave_closes_connection():
    room = _room()
    with client.websocket_connect("/ws") as ws:
        _join(ws, room)
        ws.send_text(json.dumps({"type": "leave", "room": room}))
        with pytest.raises(WebSocketDisconnect):
            ws.receive_text()


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
