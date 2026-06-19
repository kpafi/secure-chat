"""Tests for the passwordless account directory.

Uses a throwaway SQLite DB and real Ed25519 keys (via `cryptography`) to sign
the registration proof and the login challenge, exercising the happy paths and
the security-relevant rejections.
"""
import base64
import os
import sys
import tempfile
from pathlib import Path

# Point the app at a temp DB BEFORE importing it, and make backend importable.
_TMP_DB = os.path.join(tempfile.mkdtemp(), "test_accounts.db")
os.environ["SECURE_CHAT_DB"] = _TMP_DB
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402
from cryptography.hazmat.primitives import serialization  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from main import app  # noqa: E402

client = TestClient(app)


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _new_identity():
    """Return (ed_priv, ed_pub_b64, fake_mldsa_pub_b64). PQ key is opaque to
    the server, so a correctly sized random blob stands in for it here."""
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    mldsa = os.urandom(1952)
    return priv, _b64(pub), _b64(mldsa)


def _register_message(username, ed, mldsa):
    return b"\n".join([b"secure-chat/register/v1", username.encode(), ed.encode(), mldsa.encode()])


def _register(username):
    priv, ed, mldsa = _new_identity()
    sig = priv.sign(_register_message(username, ed, mldsa))
    resp = client.post("/api/register", json={"username": username, "ed": ed, "mldsa": mldsa, "sig": _b64(sig)})
    return priv, ed, mldsa, resp


def test_register_and_lookup():
    priv, ed, mldsa, resp = _register("alice")
    assert resp.status_code == 200, resp.text
    got = client.get("/api/users/alice")
    assert got.status_code == 200
    assert got.json() == {"username": "alice", "ed": ed, "mldsa": mldsa}


def test_register_rejects_bad_signature():
    _, ed, mldsa = _new_identity()[0:3] if False else (None, *_new_identity()[1:])
    # Sign with a DIFFERENT key than the ed we submit.
    wrong = Ed25519PrivateKey.generate()
    sig = wrong.sign(_register_message("mallory", ed, mldsa))
    resp = client.post("/api/register", json={"username": "mallory", "ed": ed, "mldsa": mldsa, "sig": _b64(sig)})
    assert resp.status_code == 400


def test_register_rejects_duplicate_username():
    _register("bob")
    _, _, _, resp = _register("bob")
    assert resp.status_code == 409


def test_register_rejects_bad_username():
    priv, ed, mldsa = _new_identity()
    sig = priv.sign(_register_message("Bad Name!", ed, mldsa))
    resp = client.post("/api/register", json={"username": "Bad Name!", "ed": ed, "mldsa": mldsa, "sig": _b64(sig)})
    assert resp.status_code == 422


def test_register_rejects_wrong_key_size():
    priv, ed, mldsa = _new_identity()
    short = _b64(b"too short")
    sig = priv.sign(_register_message("shorty", short, mldsa))
    resp = client.post("/api/register", json={"username": "shorty", "ed": short, "mldsa": mldsa, "sig": _b64(sig)})
    assert resp.status_code == 422


def test_lookup_unknown_user():
    assert client.get("/api/users/nobody").status_code == 404


def test_full_login_flow():
    priv, _, _, _ = _register("carol")
    ch = client.post("/api/auth/challenge", json={"username": "carol"})
    assert ch.status_code == 200
    challenge = ch.json()["challenge"]
    sig = priv.sign(base64.b64decode(challenge))
    ver = client.post("/api/auth/verify", json={"username": "carol", "challenge": challenge, "sig": _b64(sig)})
    assert ver.status_code == 200, ver.text
    token = ver.json()["token"]

    me = client.get("/api/me", headers={"Authorization": f"Bearer {token}"})
    assert me.status_code == 200
    assert me.json()["username"] == "carol"


def test_login_rejects_wrong_signature():
    _register("dave")
    other = Ed25519PrivateKey.generate()
    ch = client.post("/api/auth/challenge", json={"username": "dave"}).json()["challenge"]
    sig = other.sign(base64.b64decode(ch))  # signed by the wrong key
    ver = client.post("/api/auth/verify", json={"username": "dave", "challenge": ch, "sig": _b64(sig)})
    assert ver.status_code == 401


def test_challenge_is_one_time():
    priv, _, _, _ = _register("erin")
    ch = client.post("/api/auth/challenge", json={"username": "erin"}).json()["challenge"]
    sig = _b64(priv.sign(base64.b64decode(ch)))
    first = client.post("/api/auth/verify", json={"username": "erin", "challenge": ch, "sig": sig})
    assert first.status_code == 200
    # Replaying the same challenge must fail (consumed).
    second = client.post("/api/auth/verify", json={"username": "erin", "challenge": ch, "sig": sig})
    assert second.status_code == 400


def test_me_requires_valid_token():
    assert client.get("/api/me").status_code == 401
    assert client.get("/api/me", headers={"Authorization": "Bearer nope"}).status_code == 401


def test_challenge_unknown_user():
    assert client.post("/api/auth/challenge", json={"username": "ghost"}).status_code == 404


def test_register_forbids_extra_fields():
    priv, ed, mldsa = _new_identity()
    sig = _b64(priv.sign(_register_message("frank", ed, mldsa)))
    resp = client.post(
        "/api/register",
        json={"username": "frank", "ed": ed, "mldsa": mldsa, "sig": sig, "admin": True},
    )
    assert resp.status_code == 422
