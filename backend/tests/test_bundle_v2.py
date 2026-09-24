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


# ---- Pentest 2026-08-07 F-RELAY-005: re-registration cannot strip enc keys --

def test_replayed_v1_registration_cannot_strip_published_enc_keys():
    """The account's original v1 registration stays a valid dual-signed message
    forever. Pre-fix, replaying it after the v2 upgrade wiped `ecdh`/`mlkem`
    from the directory row — a downgrade from "can receive sealed mail" to
    "cannot", by anyone holding the captured request (the relay included).
    """
    ident = _new_identity()
    # 1. The original v1 registration (no encryption keys), kept by the attacker.
    msg = b"\n".join([b"secure-chat/register/v1", b"strip-frank", ident["ed"].encode(), ident["mldsa"].encode()])
    v1_body = {
        "username": "strip-frank", "ed": ident["ed"], "mldsa": ident["mldsa"],
        "sig": _b64(ident["ed_priv"].sign(msg)),
        "mldsa_sig": _b64(ML_DSA_65.sign(ident["mldsa_secret"], msg)),
    }
    r1 = client.post("/api/register", json=v1_body)
    assert r1.status_code == 200, r1.text
    token = r1.json()["lookup_token"]
    # 2. The legacy upgrade publishes encryption keys.
    enc = _enc_keys()
    r2 = client.post("/api/register", json=_v2_body("strip-frank", ident, enc))
    assert r2.status_code == 200 and r2.json()["status"] == "updated"
    # 3. Replay of step 1: refused, and the published keys survive.
    r3 = client.post("/api/register", json=v1_body)
    assert r3.status_code == 409, r3.text
    got = client.get("/api/users/strip-frank", params={"t": token}).json()
    assert got["ecdh"] == enc["ecdh"] and got["mlkem"] == enc["mlkem"]
    # A replay of the v2 registration itself is a harmless no-op refresh.
    r4 = client.post("/api/register", json=_v2_body("strip-frank", ident, enc))
    assert r4.status_code == 200 and r4.json()["lookup_token"] == token



# Phase-7 pentest 2026-09-16, F-P7-A4 (test only; ported from phase7-local
# 1d240d0). test_accounts.py respells only the v1 fields (ed, mldsa, sig); ecdh
# (65 bytes) and mlkem (1184 bytes) are both = 2 (mod 3) and so have four base64
# spellings each — and NOTHING pinned that the relay refuses the non-canonical
# ones. That is load-bearing: `_vouch_message` builds from the STORED string
# while the client builds from its canonical copy, so a non-canonical stored key
# would silently kill every vouch mark for that account (H-1's failure mode).
_B64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"


def _respell_enc(canonical: str) -> str:
    """Another base64 string for the same bytes (flip a discarded slack bit)."""
    body = canonical.rstrip("=")
    pad = canonical[len(body):]
    assert pad, "a field with no padding has no slack bits to respell"
    last = body[-1]
    alt = _B64_ALPHABET[_B64_ALPHABET.index(last) ^ 1]
    respelled = body[:-1] + alt + pad
    assert respelled != canonical
    assert base64.b64decode(respelled, validate=True) == base64.b64decode(canonical, validate=True)
    return respelled


def test_register_rejects_non_canonical_encryption_keys():
    ident, enc = _new_identity(), _enc_keys()
    for field in ("ecdh", "mlkem"):
        # Signed OVER the respelled string, so the signature is valid and the
        # canonical-base64 check is the only thing that can refuse it.
        body = _v2_body("noncanon-enc", ident, dict(enc, **{field: _respell_enc(enc[field])}))
        r = client.post("/api/register", json=body)
        assert r.status_code == 422, (field, r.text)
        assert "canonical" in r.text, (field, r.text)
    # ...and the canonical original is still accepted, unchanged.
    r = client.post("/api/register", json=_v2_body("noncanon-enc", ident, enc))
    assert r.status_code == 200, r.text
    served = client.get("/api/users/noncanon-enc", params={"t": r.json()["lookup_token"]}).json()
    assert served["ecdh"] == enc["ecdh"] and served["mlkem"] == enc["mlkem"]
