"""Guards the inline import-map CSP hash.

index.html carries the ONE inline script the CSP allows: a `<script
type="importmap">`. Instead of loosening CSP with 'unsafe-inline', main.py pins
that script by its exact SHA-256 in `script-src`. If the import map text ever
changes without the pinned hash being regenerated, the browser silently refuses
to run it and the app breaks. This test recomputes the hash from index.html and
asserts the served CSP still pins it, so that drift fails loudly in CI instead.
"""
import base64
import hashlib
import os
import re
import sys
import tempfile
from pathlib import Path

os.environ.setdefault("SECURE_CHAT_DB", os.path.join(tempfile.mkdtemp(), "csp.db"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fastapi.testclient import TestClient  # noqa: E402

import config  # noqa: E402
from main import app  # noqa: E402

client = TestClient(app)

_IMPORTMAP_RE = re.compile(r'<script type="importmap">(.*?)</script>', re.DOTALL)


def _importmap_hash() -> str:
    html = Path(config.CLIENT_DIR, "index.html").read_text(encoding="utf-8")
    match = _IMPORTMAP_RE.search(html)
    assert match, "index.html must contain an inline importmap script"
    digest = hashlib.sha256(match.group(1).encode("utf-8")).digest()
    return "sha256-" + base64.b64encode(digest).decode("ascii")


def test_csp_pins_current_importmap_hash():
    expected = _importmap_hash()
    csp = client.get("/healthz").headers["content-security-policy"]
    assert expected in csp, (
        f"served CSP script-src does not pin the current import map hash.\n"
        f"expected {expected}\nCSP: {csp}"
    )


# The Android app stamps its OWN CSP (it serves index.html from a local origin,
# not through main.py) and hardcodes the import-map hash in MainActivity.kt. That
# constant has no other automated drift guard, so if the import map changes the
# app would silently break. Recompute the hash here and assert the Kotlin copy
# still matches. Skipped when the android/ module isn't checked out alongside the
# backend, so the backend stays independently testable.
_MAIN_ACTIVITY = Path(
    config.CLIENT_DIR, "..", "android", "app", "src", "main", "java",
    "org", "securechat", "app", "MainActivity.kt",
)
_KT_HASH_RE = re.compile(r'importMapHash\s*=\s*"([^"]+)"')


def test_android_importmap_hash_matches():
    if not _MAIN_ACTIVITY.exists():
        import pytest

        pytest.skip("android/ module not present")
    kt = _MAIN_ACTIVITY.read_text(encoding="utf-8")
    match = _KT_HASH_RE.search(kt)
    assert match, "MainActivity.kt must declare importMapHash"
    assert match.group(1) == _importmap_hash(), (
        "MainActivity.kt importMapHash has drifted from the web client's import "
        "map. Regenerate it to match index.html or the app's CSP will block the "
        "inline import map and the app will break."
    )


# The iOS shell (ios/SecureChat/WebShell.swift) stamps its own CSP too and pins
# the same hash in Swift. Same drift guard, same skip rule.
_WEB_SHELL = Path(config.CLIENT_DIR, "..", "ios", "SecureChat", "WebShell.swift")
_SWIFT_HASH_RE = re.compile(r'importMapHash\s*=\s*"([^"]+)"')


def test_ios_importmap_hash_matches():
    if not _WEB_SHELL.exists():
        import pytest

        pytest.skip("ios/ module not present")
    swift = _WEB_SHELL.read_text(encoding="utf-8")
    match = _SWIFT_HASH_RE.search(swift)
    assert match, "WebShell.swift must declare importMapHash"
    assert match.group(1) == _importmap_hash(), (
        "WebShell.swift importMapHash has drifted from the web client's import "
        "map. Regenerate it to match index.html or the iOS app's CSP will block "
        "the inline import map and the app will break."
    )


def test_ios_origin_matches_relay_allow_list():
    if not _WEB_SHELL.exists():
        import pytest

        pytest.skip("ios/ module not present")
    swift = _WEB_SHELL.read_text(encoding="utf-8")
    match = re.search(r'static let origin\s*=\s*"([^"]+)"', swift)
    assert match, "WebShell.swift must declare AppOrigin.origin"
    assert match.group(1) == config.IOS_WEBVIEW_ORIGIN
    assert config.IOS_WEBVIEW_ORIGIN in config.ALLOWED_WS_ORIGINS
    assert config.IOS_WEBVIEW_ORIGIN in config.ALLOWED_HTTP_ORIGINS
