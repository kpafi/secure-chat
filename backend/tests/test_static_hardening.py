"""Static-file hardening regressions (audit 2026-07-18 M-01 / M-02).

M-01: the dev-file gate must decide on the raw ASGI path (`scope["path"]`),
never on `request.url.path` — affected Starlette versions reconstruct `url`
from the client-controlled Host header, so a crafted Host could desync the
checked path from the routed path and expose package.json / test modules
(GHSA-86qp-5c8j-p5mr).

M-02: Starlette < 0.49.1 parses Range headers with quadratic cost
(CVE-2025-62727, GHSA-7f5h-v6xp-fcq8) — an unauthenticated CPU DoS against
static serving. We pin the dependency floor here so a downgrade fails CI.
"""
import os
import sys
import tempfile
import time
from pathlib import Path

os.environ.setdefault("SECURE_CHAT_DB", os.path.join(tempfile.mkdtemp(), "static.db"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import starlette  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from main import app  # noqa: E402

client = TestClient(app)

BLOCKED = ["/package.json", "/package-lock.json", "/contacts.test.mjs"]

# Host values that made request.url.path deviate from the routed path on
# vulnerable Starlette versions (path smuggled into the authority component).
EVIL_HOSTS = [
    "evil.example/smuggled",
    "evil.example/smuggled/package.json",
    "localhost:8000/x",
]


def test_blocked_dev_files_are_404():
    for path in BLOCKED:
        assert client.get(path).status_code == 404, path


def test_blocked_dev_files_stay_404_with_malicious_host_header():
    """M-01: the gate must not be bypassable via the Host header."""
    for path in BLOCKED:
        for host in EVIL_HOSTS:
            resp = client.get(path, headers={"host": host})
            assert resp.status_code != 200, (path, host, resp.status_code)


def test_client_assets_still_served():
    resp = client.get("/index.html")
    assert resp.status_code == 200
    assert "importmap" in resp.text


def test_starlette_floor_covers_known_cves():
    """M-02 (and M-01): fail CI if the dependency is ever downgraded below the
    patched versions (range DoS fixed in 0.49.1, host-header fix well below
    the 1.x floor we pin in requirements.txt)."""
    version = tuple(int(p) for p in starlette.__version__.split(".")[:2])
    assert version >= (1, 0), f"starlette {starlette.__version__} predates the audited fixes"


def test_pathological_range_header_is_cheap():
    """M-02 regression: a many-range header must not cost quadratic CPU."""
    ranges = ",".join(f"{i}-{i}" for i in range(0, 2000, 2))
    start = time.monotonic()
    resp = client.get("/index.html", headers={"range": "bytes=" + ranges})
    elapsed = time.monotonic() - start
    assert resp.status_code in (200, 206, 416)
    assert elapsed < 2.0, f"range parsing took {elapsed:.2f}s"


def test_healthz_reports_the_release_version():
    import re
    r = client.get("/healthz")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"
    assert re.fullmatch(r"\d+\.\d+\.\d+", r.json()["version"]), r.json()
