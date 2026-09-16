"""Regression tests for the lookup-token gate (pentest 2026-07-25 F-04).

`hmac.compare_digest` raises TypeError when given `str` arguments containing
non-ASCII characters. The lookup token arrives straight off the query string,
so `?t=ü` turned every token-gated endpoint into an unhandled HTTP 500 — which
also wrote a full traceback to the journal on demand, against the project's I2
"no metadata at rest" goal.

The gate must treat hostile input as simply "wrong token": an ordinary 404,
indistinguishable from an unknown user (I1).
"""
import os
import sys
import tempfile
from pathlib import Path

_TMP_DB = os.path.join(tempfile.mkdtemp(), "test_token_gate.db")
os.environ["SECURE_CHAT_DB"] = _TMP_DB
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from main import app  # noqa: E402
from accounts import token_matches  # noqa: E402
import accounts  # noqa: E402
import config  # noqa: E402
import mailbox  # noqa: E402

client = TestClient(app)


@pytest.fixture(autouse=True)
def _reset_limiters():
    # These endpoints share the stricter lookup/post buckets; the parametrised
    # cases below would otherwise throttle each other and mask the real result.
    accounts._api_limiter._buckets.clear()
    accounts._lookup_limiter._buckets.clear()
    accounts._vouch_host_limiter._buckets.clear()
    accounts._challenge_limiter._buckets.clear()
    mailbox._post_limiter._buckets.clear()

# Inputs that used to crash the gate, plus ordinary wrong-token values.
HOSTILE_TOKENS = [
    "ü",                 # non-ASCII (the original crash)
    "日本語",             # multi-byte
    "\x00",              # NUL
    "\U0001F600",        # astral plane (surrogate pair in UTF-16)
    "café" * 16,         # long + non-ASCII
    "",                  # empty
    "plain-wrong-token",  # ASCII, simply incorrect
]


@pytest.mark.parametrize("t", HOSTILE_TOKENS)
def test_bundle_lookup_never_500s(t):
    r = client.get("/api/users/nosuchuser", params={"t": t})
    assert r.status_code == 404, f"{t!r} -> {r.status_code}"


@pytest.mark.parametrize("t", HOSTILE_TOKENS)
def test_vouch_lookup_never_500s(t):
    r = client.get("/api/users/nosuchuser/vouches", params={"t": t})
    assert r.status_code == 404, f"{t!r} -> {r.status_code}"


@pytest.mark.parametrize("t", HOSTILE_TOKENS)
def test_mailbox_post_never_500s(t):
    r = client.post(
        "/api/mailbox/nosuchuser", params={"t": t}, json={"envelope": "A" * config.MIN_ENVELOPE_BYTES}
    )
    assert r.status_code == 404, f"{t!r} -> {r.status_code}"


def test_token_matches_semantics():
    # Correct comparison is preserved, and hostile input is False, not an error.
    assert token_matches("abc", "abc")
    assert not token_matches("abc", "abd")
    assert not token_matches("ü", "abc")
    assert not token_matches("abc", "ü")
    assert not token_matches("", "abc")
    # Equal non-ASCII strings still compare equal (no silent truncation).
    assert token_matches("ü", "ü")
