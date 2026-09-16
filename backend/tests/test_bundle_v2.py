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
    accounts._vouch_host_limiter._buckets.clear()
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


def _v3_body(username, ident, enc, seq):
    """A counter-bearing registration (F-RELAY-005)."""
    msg = b"\n".join([
        b"secure-chat/register/v3", username.encode(), ident["ed"].encode(),
        ident["mldsa"].encode(), enc["ecdh"].encode(), enc["mlkem"].encode(),
        str(seq).encode(),
    ])
    return {
        "username": username, "ed": ident["ed"], "mldsa": ident["mldsa"],
        "sig": _b64(ident["ed_priv"].sign(msg)),
        "mldsa_sig": _b64(ML_DSA_65.sign(ident["mldsa_secret"], msg)),
        "seq": seq,
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
    """Pentest 2026-08-07 F-RELAY-005 changed this contract deliberately.

    Key ROTATION used to be "whichever valid registration arrived last wins",
    which is indistinguishable from a hostile relay replaying an older one. So a
    rotation now has to carry a monotone signed counter, and a registration
    without one may only ADD encryption keys to an account that has none.
    """
    ident = _new_identity()
    enc1, enc2, enc3 = _enc_keys(), _enc_keys(), _enc_keys()
    r1 = client.post("/api/register", json=_v2_body("v2-dave", ident, enc1))
    assert r1.status_code == 200 and r1.json()["status"] == "registered"
    token = r1.json()["lookup_token"]

    # Same identity, same keys, no counter: a no-op refresh, still fine.
    r2 = client.post("/api/register", json=_v2_body("v2-dave", ident, enc1))
    assert r2.status_code == 200 and r2.json()["status"] == "updated"
    assert r2.json()["lookup_token"] == token

    # Same identity, DIFFERENT keys, no counter: refused. This is the shape of
    # the replay, and the server cannot tell it from a genuine rotation.
    r3 = client.post("/api/register", json=_v2_body("v2-dave", ident, enc2))
    assert r3.status_code == 409, r3.text
    r = client.get("/api/users/v2-dave", params={"t": token})
    assert r.json()["ecdh"] == enc1["ecdh"], "a counter-less registration must not rotate keys"

    # With a counter: rotation works, same token.
    r4 = client.post("/api/register", json=_v3_body("v2-dave", ident, enc2, 1))
    assert r4.status_code == 200 and r4.json()["status"] == "updated", r4.text
    assert r4.json()["lookup_token"] == token
    r = client.get("/api/users/v2-dave", params={"t": token})
    assert r.json()["ecdh"] == enc2["ecdh"]

    # Replaying that exact registration is refused...
    r5 = client.post("/api/register", json=_v3_body("v2-dave", ident, enc2, 1))
    assert r5.status_code == 409, r5.text
    # ...and so is an OLDER counter carrying the superseded keys, which is the
    # rollback the finding is about.
    r6 = client.post("/api/register", json=_v3_body("v2-dave", ident, enc1, 1))
    assert r6.status_code == 409, r6.text
    r = client.get("/api/users/v2-dave", params={"t": token})
    assert r.json()["ecdh"] == enc2["ecdh"], "a replayed registration must not roll the keys back"

    # Moving forward still works.
    r7 = client.post("/api/register", json=_v3_body("v2-dave", ident, enc3, 2))
    assert r7.status_code == 200 and r7.json()["status"] == "updated"

    # A DIFFERENT identity claiming the name is still refused.
    other = _new_identity()
    r8 = client.post("/api/register", json=_v2_body("v2-dave", other, _enc_keys()))
    assert r8.status_code == 409


def test_v1_replay_cannot_strip_published_encryption_keys():
    """F-RELAY-005, the sharpest form: a v1 registration carries no encryption
    keys at all, so replaying one used to CLEAR them — silently downgrading the
    account to one that cannot receive sealed mail."""
    ident, enc = _new_identity(), _enc_keys()
    r1 = client.post("/api/register", json=_v2_body("v2-strip", ident, enc))
    assert r1.status_code == 200
    token = r1.json()["lookup_token"]

    msg = b"\n".join([b"secure-chat/register/v1", b"v2-strip",
                      ident["ed"].encode(), ident["mldsa"].encode()])
    v1 = {
        "username": "v2-strip", "ed": ident["ed"], "mldsa": ident["mldsa"],
        "sig": _b64(ident["ed_priv"].sign(msg)),
        "mldsa_sig": _b64(ML_DSA_65.sign(ident["mldsa_secret"], msg)),
    }
    r2 = client.post("/api/register", json=v1)
    assert r2.status_code == 409, r2.text
    r = client.get("/api/users/v2-strip", params={"t": token})
    assert r.json()["ecdh"] == enc["ecdh"], "a replayed v1 registration must not strip the keys"


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


# --- the 409 contract (owner decision, 2026-08-21) --------------------------
# `/api/register` produces three different 409s, and until now all three were an
# opaque human string. The client branched on the STATUS ALONE, so a counter
# replay was reported to the user as "username already taken" and they were
# advised to pick another name — the one action that loses their handle and every
# contact's pin (A4/M-3). Worse, a client that lost its counter could only guess
# its way forward from its own clock, so a wrong or merely skewed clock ratcheted
# the account out permanently (A4/M-1, A4/M-2, wrong-clock residual).
#
# So each 409 now carries a machine-readable `error`, and the counter case echoes
# the stored value so the client can jump to `stored + 1` and converge in one
# retry.

def test_409_errors_are_machine_readable_and_distinct():
    ident, enc1, enc2 = _new_identity(), _enc_keys(), _enc_keys()
    r = client.post("/api/register", json=_v3_body("c409-alice", ident, enc1, 5))
    assert r.status_code == 200, r.text

    # 1. a DIFFERENT identity claiming the name: the genuine "taken".
    other = _new_identity()
    r = client.post("/api/register", json=_v3_body("c409-alice", other, _enc_keys(), 1))
    assert r.status_code == 409, r.text
    assert r.json()["detail"]["error"] == "username_taken"
    assert "stored_seq" not in r.json()["detail"], (
        "the counter must NOT be echoed to someone who does not own the account — "
        "this branch is reached by anyone who can pick the same name"
    )

    # 2. the owner replaying/lagging its counter: distinct code, and the stored
    #    value is echoed so the client can advance instead of guessing.
    r = client.post("/api/register", json=_v3_body("c409-alice", ident, enc2, 5))
    assert r.status_code == 409, r.text
    detail = r.json()["detail"]
    assert detail["error"] == "stale_counter"
    assert detail["stored_seq"] == 5, "the 409 must echo the stored counter"

    # ...and acting on the echo converges in exactly one retry.
    r = client.post("/api/register", json=_v3_body("c409-alice", ident, enc2, detail["stored_seq"] + 1))
    assert r.status_code == 200 and r.json()["status"] == "updated", r.text


def test_409_keys_locked_is_distinct_from_username_taken():
    # 3. a pre-v3 (counter-less) client trying to CHANGE already-published keys.
    ident, enc1, enc2 = _new_identity(), _enc_keys(), _enc_keys()
    r = client.post("/api/register", json=_v2_body("c409-bob", ident, enc1))
    assert r.status_code == 200, r.text
    r = client.post("/api/register", json=_v2_body("c409-bob", ident, enc2))
    assert r.status_code == 409, r.text
    assert r.json()["detail"]["error"] == "keys_locked", (
        "a counter-less key change must not be reported as 'username already taken' — "
        "the account is the caller's own and renaming would lose it"
    )
    assert "stored_seq" not in r.json()["detail"]


def test_stale_counter_echo_requires_proving_ownership():
    # The echo is only reachable AFTER both ownership signatures verified over
    # this exact bundle AND the stored row's ed/mldsa matched. A bad signature
    # dies at 400 long before any counter is read, so the endpoint is not a
    # counter oracle for a name you cannot sign for.
    ident, enc = _new_identity(), _enc_keys()
    r = client.post("/api/register", json=_v3_body("c409-carol", ident, enc, 9))
    assert r.status_code == 200, r.text

    body = _v3_body("c409-carol", ident, enc, 9)
    body["sig"] = _b64(b"\x00" * 64)          # forged Ed25519 signature
    r = client.post("/api/register", json=body)
    assert r.status_code == 400, r.text
    assert "stored_seq" not in str(r.json()), "no counter may leak on a failed signature"


# Phase-7 pentest 2026-09-16, F-P7-A4. test_accounts.py respells only the v1
# fields (ed, mldsa, sig); ecdh (65 bytes) and mlkem (1184 bytes) are both
# ≡ 2 (mod 3) and so have four base64 spellings each — and NOTHING pinned that
# the relay refuses the non-canonical ones. With `_b64decode_fixed` replaced by
# a length+alphabet check, both suites stayed green while a non-canonical ecdh
# registered and was served verbatim. That is load-bearing: `_vouch_message`
# builds from the STORED string while the client builds from its canonical
# copy, so a non-canonical stored key silently kills every vouch mark for that
# account (H-1's exact failure mode, on the relay).
_B64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"


def _respell_enc(canonical: str) -> str:
    """Another base64 string for the same bytes (flip the discarded slack bit)."""
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
        for maker in (lambda u, i, e: _v2_body(u, i, e), lambda u, i, e: _v3_body(u, i, e, 1)):
            body = maker("noncanon-enc", ident, enc)
            body[field] = _respell_enc(body[field])
            r = client.post("/api/register", json=body)
            assert r.status_code == 422, (field, r.text)
            assert "canonical" in r.text, (field, r.text)
    # ...and the canonical original is still accepted, unchanged.
    r = client.post("/api/register", json=_v2_body("noncanon-enc", ident, enc))
    assert r.status_code == 200, r.text
    served = client.get("/api/users/noncanon-enc", params={"t": r.json()["lookup_token"]}).json()
    assert served["ecdh"] == enc["ecdh"] and served["mlkem"] == enc["mlkem"]
