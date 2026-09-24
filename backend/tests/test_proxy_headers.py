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
    """Minimal stand-in for a Starlette Request.

    `port` matters (2026-07-29 M-1): a real TCP peer always has a nonzero
    source port, and port 0 is how the rewrite detector recognises an address
    uvicorn synthesised from a header. Default to a plausible ephemeral port so
    these stubs look like genuine connections unless a test says otherwise.
    """

    def __init__(self, peer, xff=None, port=54321):
        self.client = type("C", (), {"host": peer, "port": port})()
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
    """The actual exploit: with no trusted proxy, rotation must not help.

    Measured on the per-host `/api` ceiling (`_api_limiter`), the limiter still
    keyed on `client_key` in front of the lookup gate. (Phase-7 pentest
    2026-09-16 F-P7-3 moved the strict lookup bucket BEHIND the token gate and
    keyed it per target, so garbage lookups no longer touch it.)
    """
    config.TRUSTED_PROXY_IPS = frozenset()
    codes = []
    for i in range(config.API_RATE_CAPACITY + 6):
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


# --- Pentest 2026-07-29 M-1 --------------------------------------------------
# The H-4 detector above keyed "did uvicorn rewrite this?" on `peer in hops` —
# a predicate the CLIENT controls. In the shipped topology `peer` is always
# 127.0.0.1, so `X-Forwarded-For: 127.0.0.1` satisfied it and moved the sender
# into a second bucket, uncontended, while all honest traffic stayed in the
# first. Two attacker-selectable buckets, not the one the docs claimed.

def test_loopback_xff_does_not_buy_a_second_bucket():
    """The one line that would have caught M-1: THIS deployment's topology.

    The old table exercised peer=127.0.0.1 with XFF=1.2.3.4 and peer=1.2.3.4
    with XFF=1.2.3.4, both of which land in a single branch. The value that
    separates the branches — the peer's OWN address — was never sent.
    """
    config.TRUSTED_PROXY_IPS = frozenset()
    assert accounts.client_key(_Req("127.0.0.1", "127.0.0.1")) == accounts.client_key(
        _Req("127.0.0.1")
    )


def test_exactly_one_bucket_per_peer_whatever_the_header_says():
    """M-1's invariant, stated directly: the key is a function of the peer alone."""
    config.TRUSTED_PROXY_IPS = frozenset()
    for peer in ("127.0.0.1", "203.0.113.5", "::1"):
        keys = {
            accounts.client_key(_Req(peer, xff))
            for xff in (
                None,
                peer,                      # the M-1 value
                f"{peer}, 9.9.9.9",
                f"9.9.9.9, {peer}",
                "1.2.3.4",
                "9.9.9.9, 8.8.8.8",
                "",
                "  ,  ",
                "!untrusted-forwarded",    # the retired constant, as a header
            )
        }
        assert keys == {peer}, f"peer {peer} reachable under {len(keys)} keys: {keys}"


def test_rotating_loopback_xff_cannot_bypass_the_limiter():
    """End-to-end M-1, over the topology that actually ships.

    Note the dedicated client: the module-level TestClient reports its peer as
    `"testclient"`, which is in no X-Forwarded-For any attacker would send, so
    both halves of the alternation collapse into one bucket and the test passes
    no matter what `client_key` does. That is the SAME wrong-topology mistake
    that let M-1 through in the first place — the peer must be 127.0.0.1, the
    address Tor and Caddy actually connect from, or this proves nothing.
    """
    config.TRUSTED_PROXY_IPS = frozenset()
    onion = TestClient(app, client=("127.0.0.1", 54321))
    codes = []
    for i in range(config.API_RATE_CAPACITY + 6):
        # Alternate between the two buckets the old code handed out.
        xff = "127.0.0.1" if i % 2 else "203.0.113.7"
        r = onion.get(
            f"/api/users/nobody{i}", params={"t": "zz"}, headers={"X-Forwarded-For": xff}
        )
        codes.append(r.status_code)
    assert 429 in codes, f"loopback X-Forwarded-For bought a second bucket: {codes}"


def test_rewrite_detector_is_not_remotely_forgeable():
    """L-9: a forged header must not be able to burn the H-4 warning.

    The detector now keys on the PORT, which the client cannot choose. Sending
    your own address in X-Forwarded-For — the L-9 trigger — must stay silent.
    """
    config.TRUSTED_PROXY_IPS = frozenset()
    accounts._proxy_warning_emitted = False
    for xff in ("127.0.0.1", "1.2.3.4", "127.0.0.1, 9.9.9.9"):
        accounts.client_key(_Req("127.0.0.1", xff))
    assert not accounts._proxy_warning_emitted, "L-9: warning is remotely forgeable"


def test_rewrite_detector_still_fires_on_the_real_condition():
    """…but a genuinely rewritten address (synthetic port 0) is still reported."""
    config.TRUSTED_PROXY_IPS = frozenset()
    accounts._proxy_warning_emitted = False
    # uvicorn's ProxyHeadersMiddleware builds (host, 0) from a bare-IP hop.
    accounts.client_key(_Req("1.2.3.4", "1.2.3.4", port=0))
    assert accounts._proxy_warning_emitted
    accounts._proxy_warning_emitted = False


# --- Fix review 2026-07-30 (M-B) ---------------------------------------------
# The M-1 fix removed the forgeable detector, and with it the fail-CLOSED
# collapse that detector drove — leaving one log line as the entire response to
# the H-4 condition. In that condition `peer` IS attacker-chosen, so returning
# it hands out a fresh uncontended bucket per forged header: F-03 reopened.
# Nothing in the suite asserted the BUCKET under a misconfiguration, only the
# warning, so the loss was invisible. It is asserted now.

def test_rewritten_addresses_collapse_to_one_shared_bucket():
    """The H-4 misconfiguration must be throttled-but-shared, not per-header."""
    config.TRUSTED_PROXY_IPS = frozenset()
    accounts._proxy_warning_emitted = False
    keys = {
        accounts.client_key(_Req(forged, forged, port=0))
        for forged in ("1.2.3.4", "5.6.7.8", "9.9.9.9", "203.0.113.7", "10.0.0.1")
    }
    assert keys == {accounts._UNTRUSTED_FORWARDED_KEY}, (
        f"M-B: a rewritten client address must not buy a private bucket: {keys}"
    )
    accounts._proxy_warning_emitted = False


def test_the_collapse_is_not_reachable_from_a_forged_header():
    """…and the collapse must not become a way to LEAVE the honest bucket.

    That is the trap M-1 fell into: if a client could move itself into the
    shared bucket on demand, honest traffic and attacker traffic would sit in
    different buckets again. Port 0 is unreachable for a real socket, so no
    header can select this branch — which is what makes acting on it safe.
    """
    config.TRUSTED_PROXY_IPS = frozenset()
    for xff in ("127.0.0.1", "1.2.3.4", "127.0.0.1, 9.9.9.9", "0.0.0.0:0", "1.2.3.4:0"):
        assert accounts.client_key(_Req("127.0.0.1", xff)) == "127.0.0.1", (
            f"M-B: header {xff!r} escaped the peer's own bucket"
        )


def test_unix_socket_deployment_is_one_bucket_and_silent():
    """`request.client is None` (AF_UNIX) must not read as a rewrite."""
    config.TRUSTED_PROXY_IPS = frozenset()
    accounts._proxy_warning_emitted = False

    class _UdsReq:
        client = None

        def __init__(self, xff=None):
            self.headers = {"x-forwarded-for": xff} if xff else {}

    assert accounts.client_key(_UdsReq()) == "unknown"
    assert accounts.client_key(_UdsReq("1.2.3.4")) == "unknown"
    assert not accounts._proxy_warning_emitted, "a UDS deployment must stay silent"


@pytest.mark.parametrize("proxies", ["127.0.0.1", "10.0.0.1, 127.0.0.1", "::1", "localhost", "127.0.0.2"])
def test_loopback_trusted_proxy_is_refused_at_startup(proxies):
    """Phase-7 pentest 2026-09-16 F-P7-13: SECURE_CHAT_TRUSTED_PROXIES=127.0.0.1
    silently defeated every limiter (F-RELAY-001's fix was documentation only).
    On the shipped topology a loopback proxy cannot be told from Tor's raw
    forward, so config refuses it unless the operator states they separated
    the two."""
    import subprocess
    backend = str(Path(__file__).resolve().parents[1])
    env = dict(os.environ, SECURE_CHAT_TRUSTED_PROXIES=proxies)
    env.pop("SECURE_CHAT_TRUSTED_PROXIES_ALLOW_LOOPBACK", None)
    r = subprocess.run([sys.executable, "-c", "import config"], cwd=backend, env=env, capture_output=True, text=True)
    assert r.returncode != 0 and "loopback" in r.stderr, r.stderr[-400:]
    env["SECURE_CHAT_TRUSTED_PROXIES_ALLOW_LOOPBACK"] = "1"
    r = subprocess.run([sys.executable, "-c", "import config"], cwd=backend, env=env, capture_output=True, text=True)
    assert r.returncode == 0, r.stderr[-400:]


def test_non_loopback_trusted_proxy_still_starts():
    import subprocess
    backend = str(Path(__file__).resolve().parents[1])
    env = dict(os.environ, SECURE_CHAT_TRUSTED_PROXIES="10.0.0.5")
    env.pop("SECURE_CHAT_TRUSTED_PROXIES_ALLOW_LOOPBACK", None)
    r = subprocess.run([sys.executable, "-c", "import config"], cwd=backend, env=env, capture_output=True, text=True)
    assert r.returncode == 0, r.stderr[-400:]
