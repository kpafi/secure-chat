"""Unit tests for the validation layer — the security-critical front door.

These tests need only `pydantic` (no network, no server). Run with:
    pytest backend/tests/test_validation.py
"""
import sys
from pathlib import Path

import pytest
from pydantic import ValidationError

# Make backend modules importable when running from the repo root.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from config import MAX_PAYLOAD_CHARS, ROOM_ID_LENGTH  # noqa: E402
from validation import Envelope, is_ascii_printable  # noqa: E402

ROOM = "a" * ROOM_ID_LENGTH


def test_ascii_printable():
    assert is_ascii_printable("hello WORLD 123 ~!@#")
    assert is_ascii_printable("")
    assert not is_ascii_printable("café")        # non-ascii
    assert not is_ascii_printable("line\nbreak")  # control char
    assert not is_ascii_printable("\x00")         # NUL


def test_valid_join():
    env = Envelope.model_validate({"type": "join", "room": ROOM})
    assert env.type.value == "join"
    assert env.payload == ""


def test_valid_msg():
    env = Envelope.model_validate(
        {"type": "msg", "room": ROOM, "payload": "QUJD", "alg": "AES256"}
    )
    assert env.payload == "QUJD"
    assert env.alg.value == "AES256"


def test_rejects_extra_fields():
    with pytest.raises(ValidationError):
        Envelope.model_validate(
            {"type": "join", "room": ROOM, "evil": "x"}
        )


def test_rejects_bad_room_length():
    with pytest.raises(ValidationError):
        Envelope.model_validate({"type": "join", "room": "abc"})


def test_rejects_non_hex_room():
    with pytest.raises(ValidationError):
        Envelope.model_validate({"type": "join", "room": "Z" * ROOM_ID_LENGTH})


def test_rejects_non_base64_payload():
    with pytest.raises(ValidationError):
        Envelope.model_validate(
            {"type": "msg", "room": ROOM, "payload": "not base64!!"}
        )


def test_rejects_oversized_payload():
    with pytest.raises(ValidationError):
        Envelope.model_validate(
            {"type": "msg", "room": ROOM, "payload": "A" * (MAX_PAYLOAD_CHARS + 1)}
        )


def test_msg_requires_payload():
    with pytest.raises(ValidationError):
        Envelope.model_validate({"type": "msg", "room": ROOM})


def test_join_forbids_payload():
    with pytest.raises(ValidationError):
        Envelope.model_validate({"type": "join", "room": ROOM, "payload": "QUJD"})


def test_rejects_unknown_type():
    with pytest.raises(ValidationError):
        Envelope.model_validate({"type": "exec", "room": ROOM})


def test_rejects_unknown_algorithm():
    with pytest.raises(ValidationError):
        Envelope.model_validate(
            {"type": "msg", "room": ROOM, "payload": "QUJD", "alg": "ROT13"}
        )
