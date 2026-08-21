"""Strict, fail-closed validation of everything that crosses the wire.

The server is a *dumb relay*: it never decrypts and it never trusts the
client. Every inbound frame must pass these checks before it is touched or
forwarded. The default for anything unrecognized is rejection.
"""
from __future__ import annotations

import re
from enum import Enum
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from config import JOIN_ID_LENGTH, MAX_PAYLOAD_CHARS, ROOM_ID_LENGTH

# Printable ASCII only (0x20-0x7E): no control chars, no Unicode. Enforces the
# project rule that only ASCII is allowed, checked on the raw frame.
_ASCII_RE = re.compile(r"^[\x20-\x7E]*$")

# Standard base64 alphabet with optional padding — the only shape we ever
# accept as ciphertext / key material.
_B64_RE = re.compile(r"^[A-Za-z0-9+/]*={0,2}$")

# Room id: exactly ROOM_ID_LENGTH lowercase hex characters.
_ROOM_RE = re.compile(r"^[0-9a-f]{%d}$" % ROOM_ID_LENGTH)

# Join id: the server-issued handle for one waiting socket, quoted back by the
# owner in admit/deny. Server-generated and never a secret — it only has to be
# unguessable enough that a *waiting* peer cannot name someone else's slot, and
# well-formed enough that it can never be used as an injection vector.
_JID_RE = re.compile(r"^[0-9a-f]{%d}$" % JOIN_ID_LENGTH)


def is_ascii_printable(s: str) -> bool:
    """True if every character is printable ASCII (space..~)."""
    return bool(_ASCII_RE.match(s))


class MsgType(str, Enum):
    join = "join"
    leave = "leave"
    key = "key"  # key-exchange handshake material (opaque to the server)
    msg = "msg"  # encrypted chat message (opaque to the server)
    # Room admission (pentest 2026-07-26 P-08). A join into an occupied room no
    # longer takes a slot; it waits, and the OWNER decides. `knock` carries the
    # waiting party's self-introduction (an opaque blob the server forwards
    # verbatim, like every other payload); `admit`/`deny` are the owner's
    # verdict and name a waiting socket by the server-issued join id.
    knock = "knock"
    admit = "admit"
    deny = "deny"


class Algorithm(str, Enum):
    """Advisory tag only. The server does not implement these; it just relays.

    The tag lets the *receiving client* know how to decrypt. The server must
    never branch on this for any crypto decision because it does no crypto.
    """

    # Kept for wire compatibility with clients predating 2026-08-21 only. The
    # current client neither emits nor accepts RSA (pentest F-CRYPTO-009: peer-
    # chosen RSA key transport was removed); it refuses a frame tagged with it.
    # Dropping the member here would buy nothing — the relay never reads `alg`.
    rsa = "RSA"
    aes256 = "AES256"
    dhke = "DHKE"
    pqkem = "PQKEM"
    otp = "OTP"


class Envelope(BaseModel):
    """The one and only message shape the server accepts.

    extra="forbid" means unknown fields are rejected outright (no silent
    pass-through of attacker-controlled keys). frozen=True makes instances
    immutable after validation.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    type: MsgType
    room: str = Field(min_length=ROOM_ID_LENGTH, max_length=ROOM_ID_LENGTH)
    payload: str = Field(default="", max_length=MAX_PAYLOAD_CHARS)
    alg: Optional[Algorithm] = None
    # Only ever present on an owner's admit/deny; the server issues the value.
    jid: Optional[str] = Field(default=None, max_length=JOIN_ID_LENGTH)

    @field_validator("room")
    @classmethod
    def _room_format(cls, v: str) -> str:
        if not _ROOM_RE.match(v):
            raise ValueError("invalid room id")
        return v

    @field_validator("payload")
    @classmethod
    def _payload_format(cls, v: str) -> str:
        if not _B64_RE.match(v):
            raise ValueError("payload must be base64")
        return v

    @field_validator("jid")
    @classmethod
    def _jid_format(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and not _JID_RE.match(v):
            raise ValueError("invalid join id")
        return v

    @model_validator(mode="after")
    def _payload_presence(self) -> "Envelope":
        # msg/key must carry a payload; join/leave must not. `knock` carries the
        # waiting party's opaque self-introduction, so it is payload-bearing
        # like msg/key; admit/deny carry a jid and nothing else.
        if self.type in (MsgType.msg, MsgType.key, MsgType.knock) and not self.payload:
            raise ValueError("payload required for msg/key/knock")
        if self.type in (
            MsgType.join, MsgType.leave, MsgType.admit, MsgType.deny,
        ) and self.payload:
            raise ValueError("payload not allowed for join/leave/admit/deny")
        # A verdict must name exactly one waiting socket; nothing else may carry
        # a jid (an unused-but-accepted field is a free covert channel through
        # the relay, and this envelope is deliberately the whole vocabulary).
        if self.type in (MsgType.admit, MsgType.deny) and not self.jid:
            raise ValueError("jid required for admit/deny")
        if self.type not in (MsgType.admit, MsgType.deny) and self.jid is not None:
            raise ValueError("jid only allowed on admit/deny")
        return self
