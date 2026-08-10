"""Concurrency regressions for the auth path (pentest 2026-08-08, item 15).

WHY THIS FILE EXISTS. The 154-test suite drives `TestClient` SERIALLY, so it is
structurally blind to every concurrency bug in the backend — item 26 of the same
pentest. Item 15 was exactly that shape: `dilithium_py` without `xoflib` shares
mutable SHAKE state across threads, every signature-verifying endpoint is a sync
`def` (so FastAPI runs it in the anyio threadpool), and 8 threads over one VALID
ML-DSA signature rejected 153 of 320 — while the same signature passed serially
every time. Real threads are the only way to see it, so this file uses them.

The bug fails CLOSED (a corrupted verify returns False), so it was a login
denial-of-service and never an auth bypass. The tests therefore assert BOTH
directions: valid signatures must survive concurrency, and tampered ones must
still be refused under it.
"""
import base64
import concurrent.futures as cf
import os
import sys
import tempfile
from pathlib import Path

_TMP_DB = os.path.join(tempfile.mkdtemp(), "test_concurrency.db")
os.environ["SECURE_CHAT_DB"] = _TMP_DB
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402
from cryptography.hazmat.primitives import serialization  # noqa: E402
from dilithium_py.ml_dsa import ML_DSA_65  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from main import app  # noqa: E402
import accounts  # noqa: E402

client = TestClient(app)

THREADS = 8
ROUNDS = 320


@pytest.fixture(autouse=True)
def _reset_limiters():
    accounts._api_limiter._buckets.clear()
    accounts._lookup_limiter._buckets.clear()
    accounts._challenge_limiter._buckets.clear()
    yield


def _b64(b):
    return base64.b64encode(b).decode("ascii")


def _register(username):
    ed_priv = Ed25519PrivateKey.generate()
    ed = _b64(ed_priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw))
    mldsa_pub, mldsa_secret = ML_DSA_65.keygen()
    mldsa = _b64(mldsa_pub)
    msg = b"\n".join([b"secure-chat/register/v1", username.encode(), ed.encode(), mldsa.encode()])
    r = client.post("/api/register", json={
        "username": username, "ed": ed, "mldsa": mldsa,
        "sig": _b64(ed_priv.sign(msg)), "mldsa_sig": _b64(ML_DSA_65.sign(mldsa_secret, msg)),
    })
    assert r.status_code == 200, r.text
    return {"username": username, "ed_priv": ed_priv, "mldsa_secret": mldsa_secret}


# --- the primitive ---------------------------------------------------------

def test_mldsa_verify_concurrent():
    """A VALID ML-DSA signature must verify under concurrency, every time.

    This is the direct regression for item 15. Against the unserialised call it
    fails at roughly half the attempts; the count is deliberately large enough
    that a reintroduction cannot slip through on luck.
    """
    pub, secret = ML_DSA_65.keygen()
    msg = b"secure-chat/concurrency-probe"
    sig = ML_DSA_65.sign(secret, msg)
    assert accounts._mldsa65_verify(pub, sig, msg), "precondition: it verifies serially"

    with cf.ThreadPoolExecutor(max_workers=THREADS) as ex:
        results = list(ex.map(lambda _: accounts._mldsa65_verify(pub, sig, msg), range(ROUNDS)))

    rejected = ROUNDS - sum(results)
    assert rejected == 0, (
        f"{rejected}/{ROUNDS} VALID ML-DSA signatures were rejected under {THREADS} threads — "
        "the ML-DSA verify is not thread-safe (pentest item 15). dilithium_py shares mutable "
        "SHAKE state process-wide when xoflib is absent; it must stay serialised."
    )


def test_mldsa_verify_concurrent_still_refuses_tampered():
    """Serialising must not have turned the verify into a rubber stamp."""
    pub, secret = ML_DSA_65.keygen()
    msg = b"secure-chat/concurrency-probe"
    sig = bytearray(ML_DSA_65.sign(secret, msg))
    sig[-1] ^= 0x01
    sig = bytes(sig)

    with cf.ThreadPoolExecutor(max_workers=THREADS) as ex:
        results = list(ex.map(lambda _: accounts._mldsa65_verify(pub, sig, msg), range(64)))

    assert sum(results) == 0, "a tampered signature must never verify, concurrently or not"


# --- the endpoint ----------------------------------------------------------

def test_concurrent_logins_all_succeed():
    """Concurrent VALID logins must all succeed.

    End-to-end half of item 15: the pentest saw 5 concurrent valid logins yield
    a spurious `401 challenge signature invalid` while the same users all passed
    serially. Distinct usernames, so the per-username challenge bucket (item 19)
    cannot be what denies them.
    """
    users = [_register(f"conc{i}") for i in range(THREADS)]

    # Challenges serially — only the VERIFY step is under test.
    for u in users:
        r = client.post("/api/auth/challenge", json={"username": u["username"]})
        assert r.status_code == 200, r.text
        u["challenge"] = r.json()["challenge"]

    # Sign SERIALLY. `ML_DSA_65.sign` shares the same process-global SHAKE state
    # as the verify, so signing inside the threads would corrupt the test's own
    # signatures and blame the server for it. Only the POST is concurrent, which
    # is the thing under test: the SERVER verifying on the anyio threadpool.
    payloads = []
    for u in users:
        msg = b"secure-chat/login/v1\n" + base64.b64decode(u["challenge"])
        payloads.append({
            "username": u["username"],
            "challenge": u["challenge"],
            "sig": _b64(u["ed_priv"].sign(msg)),
            "mldsa_sig": _b64(ML_DSA_65.sign(u["mldsa_secret"], msg)),
        })

    def login(body):
        return client.post("/api/auth/verify", json=body)

    with cf.ThreadPoolExecutor(max_workers=THREADS) as ex:
        responses = list(ex.map(login, payloads))

    codes = [r.status_code for r in responses]
    assert all(c == 200 for c in codes), (
        f"concurrent valid logins returned {codes} — a spurious 401 here is item 15: "
        "the ML-DSA verify corrupting itself across threads, which denies real users."
    )
    assert all(r.json().get("token") for r in responses), "each successful login must issue a token"


def test_concurrent_logins_still_reject_bad_signatures():
    """The concurrent path must stay fail-closed for wrong signatures."""
    users = [_register(f"concbad{i}") for i in range(4)]
    wrong = Ed25519PrivateKey.generate()

    for u in users:
        r = client.post("/api/auth/challenge", json={"username": u["username"]})
        assert r.status_code == 200
        u["challenge"] = r.json()["challenge"]

    payloads = []
    for u in users:
        msg = b"secure-chat/login/v1\n" + base64.b64decode(u["challenge"])
        payloads.append({
            "username": u["username"],
            "challenge": u["challenge"],
            "sig": _b64(wrong.sign(msg)),                       # not this user's key
            "mldsa_sig": _b64(ML_DSA_65.sign(u["mldsa_secret"], msg)),
        })

    with cf.ThreadPoolExecutor(max_workers=4) as ex:
        codes = [r.status_code for r in
                 ex.map(lambda b: client.post("/api/auth/verify", json=b), payloads)]

    assert all(c == 401 for c in codes), f"a wrong Ed25519 signature must be refused, got {codes}"
