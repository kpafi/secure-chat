"""Bundle v2: registration with public encryption keys (ECDH P-256 + ML-KEM-768).

Checks: v2 registration binds the encryption keys via the dual signature under
the v2 domain; lookup returns them; malformed/mismatched inputs are refused;
same-identity re-registration refreshes the keys (keeping the lookup token)
while a foreign identity still gets 409; v1 (no enc keys) keeps working.
"""
import base64
import os
import sys
import tempfile
from pathlib import Path

_TMP_DB = os.path.join(tempfile.mkdtemp(), "test_bundle_v2.db")
os.environ["SECURE_CHAT_DB"] = _TMP_DB
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402
from cryptography.hazmat.primitives import serialization  # noqa: E402
from dilithium_py.ml_dsa import ML_DSA_65  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from main import app  # noqa: E402
import accounts  # noqa: E402
import config  # noqa: E402

client = TestClient(app)


@pytest.fixture(autouse=True)
def _reset_api_limiter():
    accounts._api_limiter._buckets.clear()
    accounts._lookup_limiter._buckets.clear()
    accounts._challenge_limiter._buckets.clear()
    yield


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _new_identity():
    ed_priv = Ed25519PrivateKey.generate()
    ed_pub = ed_priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    mldsa_pub, mldsa_secret = ML_DSA_65.keygen()
    return {"ed_priv": ed_priv, "ed": _b64(ed_pub), "mldsa": _b64(mldsa_pub), "mldsa_secret": mldsa_secret}


def _enc_keys():
    # The server validates only size/base64 (it cannot verify possession).
    return {
        "ecdh": _b64(os.urandom(config.ECDH_PUB_BYTES)),
        "mlkem": _b64(os.urandom(config.MLKEM768_PUB_BYTES)),
    }


def _v2_body(username, ident, enc):
    msg = b"\n".join([
        b"secure-chat/register/v2", username.encode(), ident["ed"].encode(),
        ident["mldsa"].encode(), enc["ecdh"].encode(), enc["mlkem"].encode(),
    ])
    return {
        "username": username, "ed": ident["ed"], "mldsa": ident["mldsa"],
        "sig": _b64(ident["ed_priv"].sign(msg)),
        "mldsa_sig": _b64(ML_DSA_65.sign(ident["mldsa_secret"], msg)),
        **enc,
    }


def test_v2_register_and_lookup_roundtrip():
    ident, enc = _new_identity(), _enc_keys()
    r = client.post("/api/register", json=_v2_body("v2-alice", ident, enc))
    assert r.status_code == 200, r.text
    token = r.json()["lookup_token"]
    r = client.get("/api/users/v2-alice", params={"t": token})
    assert r.status_code == 200
    body = r.json()
    assert body["ecdh"] == enc["ecdh"] and body["mlkem"] == enc["mlkem"]


def test_v2_signature_must_cover_enc_keys():
    ident, enc = _new_identity(), _enc_keys()
    # Sign the V1 message but attach enc keys -> the v2 check must fail.
    msg_v1 = b"\n".join([b"secure-chat/register/v1", b"v2-bob", ident["ed"].encode(), ident["mldsa"].encode()])
    body = {
        "username": "v2-bob", "ed": ident["ed"], "mldsa": ident["mldsa"],
        "sig": _b64(ident["ed_priv"].sign(msg_v1)),
        "mldsa_sig": _b64(ML_DSA_65.sign(ident["mldsa_secret"], msg_v1)),
        **enc,
    }
    assert client.post("/api/register", json=body).status_code == 400

    # Swapped enc keys after signing -> refused (signature covers them).
    good = _v2_body("v2-bob", ident, enc)
    tampered = dict(good, **_enc_keys())
    assert client.post("/api/register", json=tampered).status_code == 400


def test_v2_input_validation():
    ident, enc = _new_identity(), _enc_keys()
    only_one = _v2_body("v2-carol", ident, enc)
    only_one.pop("mlkem")
    assert client.post("/api/register", json=only_one).status_code == 422
    wrong_size = _v2_body("v2-carol", ident, {"ecdh": _b64(os.urandom(10)), "mlkem": enc["mlkem"]})
    assert client.post("/api/register", json=wrong_size).status_code == 422


def test_same_identity_reregistration_refreshes_keys():
    ident = _new_identity()
    enc1, enc2 = _enc_keys(), _enc_keys()
    r1 = client.post("/api/register", json=_v2_body("v2-dave", ident, enc1))
    assert r1.status_code == 200 and r1.json()["status"] == "registered"
    token = r1.json()["lookup_token"]

    # Same identity, new enc keys: refresh, SAME token.
    r2 = client.post("/api/register", json=_v2_body("v2-dave", ident, enc2))
    assert r2.status_code == 200 and r2.json()["status"] == "updated"
    assert r2.json()["lookup_token"] == token
    r = client.get("/api/users/v2-dave", params={"t": token})
    assert r.json()["ecdh"] == enc2["ecdh"]

    # A DIFFERENT identity claiming the name is still refused.
    other = _new_identity()
    r3 = client.post("/api/register", json=_v2_body("v2-dave", other, _enc_keys()))
    assert r3.status_code == 409


def test_v1_registration_still_works():
    ident = _new_identity()
    msg = b"\n".join([b"secure-chat/register/v1", b"v1-eve", ident["ed"].encode(), ident["mldsa"].encode()])
    body = {
        "username": "v1-eve", "ed": ident["ed"], "mldsa": ident["mldsa"],
        "sig": _b64(ident["ed_priv"].sign(msg)),
        "mldsa_sig": _b64(ML_DSA_65.sign(ident["mldsa_secret"], msg)),
    }
    r = client.post("/api/register", json=body)
    assert r.status_code == 200
    r = client.get("/api/users/v1-eve", params={"t": r.json()["lookup_token"]})
    assert r.status_code == 200
    assert "ecdh" not in r.json()  # no enc keys published
