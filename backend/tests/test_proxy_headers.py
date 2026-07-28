"""Rate-limit keying vs. X-Forwarded-For (pentest 2026-07-25 F-03).

The finding: every /api limiter keys on the client address, and when the app is
reached directly over loopback — exactly what a Tor onion service does — uvicorn's
proxy-header middleware trusted the CLIENT's own X-Forwarded-For. Rotating that
header therefore handed out a fresh bucket per request and defeated the
anti-enumeration lookup limiter, the challenge limiter and the mailbox limiter.

`accounts.client_key` now resolves the address itself and honours the header
only when the immediate peer is a configured trusted proxy, taking the
RIGHTMOST hop (the one that proxy appended).
"""
import os
import sys
import tempfile
from pathlib import Path

_TMP_DB = os.path.join(tempfile.mkdtemp(), "test_proxy_headers.db")
os.environ["SECURE_CHAT_DB"] = _TMP_DB
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from main import app  # noqa: E402
import accounts  # noqa: E402
import config  # noqa: E402
import mailbox  # noqa: E402

client = TestClient(app)


@pytest.fixture(autouse=True)
def _reset():
    accounts._api_limiter._buckets.clear()
    accounts._lookup_limiter._buckets.clear()
    accounts._challenge_limiter._buckets.clear()
    mailbox._post_limiter._buckets.clear()
    yield
    config.TRUSTED_PROXY_IPS = frozenset()


class _Req:
    """Minimal stand-in for a Starlette Request (host + headers only)."""

    def __init__(self, peer, xff=None):
        self.client = type("C", (), {"host": peer})()
        self.headers = {"x-forwarded-for": xff} if xff else {}


def test_untrusted_peer_xff_is_ignored():
    # No trusted proxies configured (the default, and the .onion topology).
    config.TRUSTED_PROXY_IPS = frozenset()
    assert accounts.client_key(_Req("127.0.0.1", "1.2.3.4")) == "127.0.0.1"
    assert accounts.client_key(_Req("127.0.0.1", "9.9.9.9, 8.8.8.8")) == "127.0.0.1"
    assert accounts.client_key(_Req("203.0.113.5", "1.2.3.4")) == "203.0.113.5"


def test_trusted_proxy_uses_rightmost_hop():
    config.TRUSTED_PROXY_IPS = frozenset({"127.0.0.1"})
    # The proxy appends the real peer, so the rightmost entry is the trustworthy one.
    assert accounts.client_key(_Req("127.0.0.1", "203.0.113.9")) == "203.0.113.9"
    assert accounts.client_key(_Req("127.0.0.1", "1.2.3.4, 203.0.113.9")) == "203.0.113.9"
    assert accounts.client_key(_Req("127.0.0.1", "127.0.0.1, 203.0.113.9")) == "203.0.113.9"
    # A peer that is NOT the configured proxy is still never trusted.
    assert accounts.client_key(_Req("198.51.100.1", "1.2.3.4")) == "198.51.100.1"
    # Trusted proxy but no header at all: fall back to the peer.
    assert accounts.client_key(_Req("127.0.0.1")) == "127.0.0.1"


def test_rotating_xff_cannot_mint_fresh_buckets():
    """The actual exploit: with no trusted proxy, rotation must not help."""
    config.TRUSTED_PROXY_IPS = frozenset()
    codes = []
    for i in range(config.LOOKUP_RATE_CAPACITY + 6):
        r = client.get(
            f"/api/users/nobody{i}",
            params={"t": "zz"},
            headers={"X-Forwarded-For": f"10.0.0.{i}"},
        )
        codes.append(r.status_code)
    assert 429 in codes, f"rotating X-Forwarded-For bypassed the limiter: {codes}"


def test_run_sh_disables_uvicorn_proxy_headers():
    """client_key is only authoritative if uvicorn is not rewriting client.host."""
    run_sh = (Path(__file__).resolve().parents[1] / "run.sh").read_text()
    assert "--no-proxy-headers" in run_sh


# --- Pentest 2026-07-27 H-4 --------------------------------------------------
# The F-03 defense above was only ever a CLI flag in run.sh. The in-repo
# programmatic launcher (`python main.py`) — which is how the live instance was
# actually started — called uvicorn.run() without it, so uvicorn trusted a
# loopback client's own X-Forwarded-For and rewrote request.client BEFORE
# client_key ever ran. Every HTTP throttle was bypassable at full speed by
# rotating one header: username enumeration via the register oracle, and
# pending-challenge exhaustion as a login-availability DoS.

def test_main_launcher_disables_uvicorn_proxy_headers():
    """Both launch paths must agree; a flag in only one of them is not a control."""
    main_py = (Path(__file__).resolve().parents[1] / "main.py").read_text()
    assert "proxy_headers=False" in main_py
    assert "forwarded_allow_ips=[]" in main_py


def test_rewritten_client_address_falls_back_to_one_shared_bucket():
    """Defense in depth: detect the rewrite instead of trusting the launcher.

    If some ASGI server honours a forwarded header anyway, the address we are
    handed is by construction one of the hops the CLIENT supplied. Keying on it
    would hand out a bucket per forged header — so this case collapses to a
    single shared bucket, which is the fail-CLOSED direction.
    """
    config.TRUSTED_PROXY_IPS = frozenset()
    # Peer address equals a hop in the header => uvicorn rewrote it.
    shared = accounts.client_key(_Req("1.2.3.4", "1.2.3.4"))
    assert shared == accounts._UNTRUSTED_FORWARDED_KEY
    # …and every forged value lands in that SAME bucket, so rotating buys nothing.
    for forged in ("9.9.9.9", "8.8.8.8", "203.0.113.7"):
        assert accounts.client_key(_Req(forged, forged)) == shared
    # A normal request (peer not present in the header) is unaffected.
    assert accounts.client_key(_Req("203.0.113.5", "1.2.3.4")) == "203.0.113.5"
    assert accounts.client_key(_Req("203.0.113.5")) == "203.0.113.5"
