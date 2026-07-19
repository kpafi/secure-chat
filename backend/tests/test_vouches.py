"""Tests for the web-of-trust vouch endpoints.

A vouch is a dual-signed statement "voucher verified target's bundle". The
server must (1) only accept vouches whose BOTH signatures verify against the
voucher's registered keys over the target's registered bundle, (2) gate reads
behind the target's lookup token (no graph enumeration), and (3) enforce the
size bounds. Real keys throughout.
"""
import base64
import os
import sys
import tempfile
from pathlib import Path

_TMP_DB = os.path.join(tempfile.mkdtemp(), "test_vouches.db")
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


def _register(username):
    ident = _new_identity()
    msg = b"\n".join([b"secure-chat/register/v1", username.encode(), ident["ed"].encode(), ident["mldsa"].encode()])
    resp = client.post("/api/register", json={
        "username": username, "ed": ident["ed"], "mldsa": ident["mldsa"],
        "sig": _b64(ident["ed_priv"].sign(msg)),
        "mldsa_sig": _b64(ML_DSA_65.sign(ident["mldsa_secret"], msg)),
    })
    assert resp.status_code == 200, resp.text
    ident["username"] = username
    ident["token"] = resp.json()["lookup_token"]
    return ident


def _login(ident):
    ch = client.post("/api/auth/challenge", json={"username": ident["username"]}).json()["challenge"]
    sig = ident["ed_priv"].sign(b"secure-chat/login/v1\n" + base64.b64decode(ch))
    resp = client.post("/api/auth/verify", json={
        "username": ident["username"], "challenge": ch, "sig": _b64(sig),
    })
    assert resp.status_code == 200, resp.text
    return resp.json()["token"]


def _vouch_message(target):
    return b"\n".join([b"secure-chat/vouch/v1", target["username"].encode(), target["ed"].encode(), target["mldsa"].encode()])


def _vouch_body(voucher, target):
    msg = _vouch_message(target)
    return {
        "target": target["username"],
        "sig": _b64(voucher["ed_priv"].sign(msg)),
        "mldsa_sig": _b64(ML_DSA_65.sign(voucher["mldsa_secret"], msg)),
    }


def _auth(token):
    return {"Authorization": f"Bearer {token}"}


def test_vouch_publish_fetch_revoke():
    alice = _register("wot-alice")
    bob = _register("wot-bob")
    tok = _login(alice)

    # Publish: alice vouches for bob.
    r = client.post("/api/vouch", json=_vouch_body(alice, bob), headers=_auth(tok))
    assert r.status_code == 200 and r.json()["status"] == "vouched"

    # Fetch (with bob's lookup token): exactly one vouch, by alice, with keys.
    r = client.get(f"/api/users/{bob['username']}/vouches", params={"t": bob["token"]})
    assert r.status_code == 200
    vs = r.json()["vouches"]
    assert len(vs) == 1
    assert vs[0]["voucher"] == "wot-alice"
    assert vs[0]["voucher_ed"] == alice["ed"]
    # The returned signature verifies over the target bundle (client-side check).
    msg = _vouch_message(bob)
    accounts._ed25519_verify(base64.b64decode(alice["ed"]), base64.b64decode(vs[0]["sig"]), msg)

    # Re-vouch replaces, not duplicates.
    r = client.post("/api/vouch", json=_vouch_body(alice, bob), headers=_auth(tok))
    assert r.status_code == 200
    r = client.get(f"/api/users/{bob['username']}/vouches", params={"t": bob["token"]})
    assert len(r.json()["vouches"]) == 1

    # Revoke.
    r = client.delete(f"/api/vouch/{bob['username']}", headers=_auth(tok))
    assert r.status_code == 200
    r = client.get(f"/api/users/{bob['username']}/vouches", params={"t": bob["token"]})
    assert r.json()["vouches"] == []


def test_vouch_rejects_bad_signatures_and_auth():
    alice = _register("wot-carol")
    bob = _register("wot-dave")
    eve = _register("wot-eve")
    tok = _login(alice)

    # No/invalid session token.
    assert client.post("/api/vouch", json=_vouch_body(alice, bob)).status_code == 401
    assert client.post("/api/vouch", json=_vouch_body(alice, bob), headers=_auth("nope")).status_code == 401

    # Signature by the WRONG key (eve signs, alice submits) is refused.
    body = _vouch_body(eve, bob)
    assert client.post("/api/vouch", json=body, headers=_auth(tok)).status_code == 400

    # Valid Ed25519 but wrong ML-DSA sig is refused (dual check).
    good = _vouch_body(alice, bob)
    bad = dict(good, mldsa_sig=_vouch_body(eve, bob)["mldsa_sig"])
    assert client.post("/api/vouch", json=bad, headers=_auth(tok)).status_code == 400

    # Signature over a DIFFERENT target's bundle is refused.
    swapped = dict(_vouch_body(alice, eve), target=bob["username"])
    assert client.post("/api/vouch", json=swapped, headers=_auth(tok)).status_code == 400

    # Self-vouch and unknown target are refused.
    assert client.post("/api/vouch", json=_vouch_body(alice, alice), headers=_auth(tok)).status_code == 422
    ghost = dict(_vouch_body(alice, bob), target="wot-ghost")
    assert client.post("/api/vouch", json=ghost, headers=_auth(tok)).status_code == 404

    # Nothing slipped into storage.
    r = client.get(f"/api/users/{bob['username']}/vouches", params={"t": bob["token"]})
    assert r.json()["vouches"] == []


def _register_v2(username):
    """Register a bundle-v2 identity (with encryption keys), like a real client."""
    ident = _new_identity()
    ecdh = _b64(os.urandom(config.ECDH_PUB_BYTES))
    mlkem = _b64(os.urandom(config.MLKEM768_PUB_BYTES))
    msg = b"\n".join([
        b"secure-chat/register/v2", username.encode(), ident["ed"].encode(),
        ident["mldsa"].encode(), ecdh.encode(), mlkem.encode(),
    ])
    resp = client.post("/api/register", json={
        "username": username, "ed": ident["ed"], "mldsa": ident["mldsa"],
        "sig": _b64(ident["ed_priv"].sign(msg)),
        "mldsa_sig": _b64(ML_DSA_65.sign(ident["mldsa_secret"], msg)),
        "ecdh": ecdh, "mlkem": mlkem,
    })
    assert resp.status_code == 200, resp.text
    ident.update(username=username, token=resp.json()["lookup_token"], ecdh=ecdh, mlkem=mlkem)
    return ident


def _vouch_message_v2(target):
    return b"\n".join([
        b"secure-chat/vouch/v2", target["username"].encode(), target["ed"].encode(),
        target["mldsa"].encode(), target["ecdh"].encode(), target["mlkem"].encode(),
    ])


def _vouch_body_v2(voucher, target, msg=None):
    msg = msg if msg is not None else _vouch_message_v2(target)
    return {
        "target": target["username"],
        "sig": _b64(voucher["ed_priv"].sign(msg)),
        "mldsa_sig": _b64(ML_DSA_65.sign(voucher["mldsa_secret"], msg)),
    }


def test_vouch_v2_binds_encryption_keys():
    """H-01: a vouch for a target WITH encryption keys must be signed over the
    v2 message (covering ecdh + mlkem). A v1 (signing-only) signature for such a
    target is refused, so a 🟡 can never attest keys the vouch didn't cover."""
    alice = _register("wot-v2a")
    bob = _register_v2("wot-v2b")
    tok = _login(alice)

    # v1 signature (signing keys only) for a v2 target is rejected by the server.
    v1_body = _vouch_body(alice, bob)  # uses the signing-only _vouch_message
    assert client.post("/api/vouch", json=v1_body, headers=_auth(tok)).status_code == 400

    # The correct v2 vouch (covers the encryption keys) is accepted.
    r = client.post("/api/vouch", json=_vouch_body_v2(alice, bob), headers=_auth(tok))
    assert r.status_code == 200 and r.json()["status"] == "vouched"

    # A v2 signature over SWAPPED encryption keys (what a malicious directory
    # would need) does not verify against the registered bundle → refused.
    poisoned = dict(bob, ecdh=_b64(os.urandom(config.ECDH_PUB_BYTES)),
                    mlkem=_b64(os.urandom(config.MLKEM768_PUB_BYTES)))
    bad = _vouch_body_v2(alice, bob, msg=_vouch_message_v2(poisoned))
    assert client.post("/api/vouch", json=bad, headers=_auth(tok)).status_code == 400

    # The stored vouch's signature verifies over bob's REAL v2 bundle (the exact
    # client-side check refreshVouchMarks performs before awarding 🟡).
    r = client.get(f"/api/users/{bob['username']}/vouches", params={"t": bob["token"]})
    vs = r.json()["vouches"]
    assert len(vs) == 1
    assert accounts._ed25519_verify(
        base64.b64decode(alice["ed"]), base64.b64decode(vs[0]["sig"]), _vouch_message_v2(bob)
    )
    # ...and does NOT verify over a poisoned-enc-key bundle → no 🟡 client-side.
    assert not accounts._ed25519_verify(
        base64.b64decode(alice["ed"]), base64.b64decode(vs[0]["sig"]), _vouch_message_v2(poisoned)
    )


def test_vouch_list_is_token_gated():
    alice = _register("wot-frank")
    bob = _register("wot-grace")
    tok = _login(alice)
    client.post("/api/vouch", json=_vouch_body(alice, bob), headers=_auth(tok))

    # Wrong/missing token and unknown user are the identical 404.
    r1 = client.get(f"/api/users/{bob['username']}/vouches", params={"t": "wrong"})
    r2 = client.get("/api/users/wot-nobody/vouches", params={"t": "wrong"})
    assert r1.status_code == r2.status_code == 404
    assert r1.json() == r2.json()
