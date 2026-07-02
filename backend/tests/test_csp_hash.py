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
