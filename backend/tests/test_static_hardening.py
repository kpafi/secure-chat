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

import config  # noqa: E402
from main import app  # noqa: E402

client = TestClient(app)

BLOCKED = ["/package.json", "/package-lock.json", "/contacts.test.mjs",
           "/test-source.mjs", "/vendor/README.md"]  # F-P7-18

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


def test_the_three_ship_lists_agree():
    """Phase-7 pentest 2026-09-16 F-P7-18: what this gate 404s must also be
    excluded by the deploy rsync and by the APK's Sync task, or a file the relay
    refuses to serve still ships inside the app and onto the box. client/
    test-source.mjs matched none of the three lists."""
    root = Path(__file__).resolve().parents[2]
    # Comments are stripped first (review of the first fix, M-7: a substring
    # check was satisfied by the exclusion moved into a comment).
    import re
    deploy = re.sub(r"#.*", "", (root / "deploy" / "deploy-2026-07-30.sh").read_text())
    gradle = re.sub(r"//.*", "", (root / "android" / "app" / "build.gradle.kts").read_text())
    for pattern in ("*.test.mjs", "package*.json", "node_modules", "test-source.mjs", "README.md"):
        assert f"--exclude '{pattern}'" in deploy or f"--exclude {pattern}" in deploy, f"deploy script does not exclude {pattern}"
        assert f'"{pattern}"' in gradle, f"APK Sync task does not exclude {pattern}"
    import main as _main
    for basename in ("package.json", "package-lock.json", "test-source.mjs", "README.md"):
        assert _main._is_blocked_static("/" + basename), basename
    assert _main._is_blocked_static("/vendor/README.md")
    assert not _main._is_blocked_static("/app.js")


def test_api_paths_are_not_shadowed_by_the_static_gate():
    """F-P7-16 (and the review's L-6): the static gate runs on the static mount
    only. A legal username that looks like a blocked file must stay reachable."""
    import main as _main
    assert _main._is_blocked_static("/test-source.mjs")
    r = client.get("/api/users/test-source.mjs", params={"t": "x"})
    assert r.status_code == 404 and r.json()["detail"] == "no such user", r.text  # the API answered, not the gate
    r = client.get("/api/users/.alice", params={"t": "x"})
    assert r.status_code == 404 and r.json()["detail"] == "no such user", r.text


def test_oversize_api_bodies_are_refused_and_422s_do_not_echo():
    """Phase-7 pentest 2026-09-16 F-P7-12: a 40 MB envelope was parsed and then
    echoed back inside the 422. Declared bodies past MAX_API_BODY_BYTES are 413
    before being read; a validation error never reflects the input."""
    big = "A" * (config.MAX_API_BODY_BYTES + 1024)
    r = client.post("/api/mailbox/nobody", params={"t": "x"}, content=big.encode(), headers={"content-type": "application/json"})
    assert r.status_code == 413, r.status_code
    r = client.post("/api/mailbox/nobody", params={"t": "x"}, json={"envelope": "A" * 300, "extra": "MARKER_do_not_echo_9f2c"})
    assert r.status_code == 422, r.text
    assert "MARKER_do_not_echo_9f2c" not in r.text, "F-P7-12: the 422 must not reflect the request body"
    assert r.json()["detail"][0]["type"], "...but still says what was wrong"
