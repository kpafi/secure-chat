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
import main  # noqa: E402
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


# ---- Home Screen web app ---------------------------------------------------

def test_web_app_manifest_is_served_as_a_manifest():
    import json

    resp = client.get("/manifest.webmanifest")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("application/manifest+json")
    m = json.loads(resp.text)
    assert m["display"] == "standalone" and m["start_url"] == "./" and m["scope"] == "./"
    # Every icon it names is actually served, as a PNG, from this origin.
    for icon in m["icons"]:
        assert not icon["src"].startswith(("http:", "https:", "//")), icon
        r = client.get("/" + icon["src"])
        assert r.status_code == 200 and r.headers["content-type"] == "image/png", icon
    assert client.get("/icons/icon-180.png").headers["content-type"] == "image/png"


def test_csp_allows_the_manifest_and_nothing_more():
    csp = client.get("/index.html").headers["content-security-policy"]
    directives = {d.strip().split(" ", 1)[0]: d.strip() for d in csp.split(";") if d.strip()}
    assert directives["manifest-src"] == "manifest-src 'self'"
    assert directives["default-src"] == "default-src 'none'"
    # Service workers are explicitly OFF: an absent worker-src falls back to
    # script-src 'self' and would ALLOW a persistent worker (pentest dist-1 F3).
    assert directives["worker-src"] == "worker-src 'none'"
    assert "child-src" not in directives and "frame-src" not in directives
    assert "http" not in csp and "*" not in csp and "unsafe" not in csp


# ---- Phase-7 pentest 2026-09-16 Lows (ported from phase7-local) --------------

def test_api_paths_are_not_shadowed_by_the_static_gate():
    """F-P7-16: the static gate runs on the static mount only. A legal username
    that looks like a blocked file must stay reachable through /api."""
    assert main._is_blocked_static("/x.test.mjs")
    for name in (".alice", "evil.test.mjs", "package.json"):
        r = client.get(f"/api/users/{name}", params={"t": "x"})
        assert r.status_code == 404 and r.json() == {"detail": "no such user"}, (name, r.text)  # the API answered


def test_blocked_static_404_carries_the_security_headers():
    """F-P7-25: the gate's 404 returned before the headers were set."""
    for path in BLOCKED:
        r = client.get(path)
        assert r.status_code == 404, path
        for h in ("Content-Security-Policy", "X-Content-Type-Options", "X-Frame-Options",
                  "Referrer-Policy", "Cache-Control", "Cross-Origin-Opener-Policy",
                  "Cross-Origin-Resource-Policy"):
            assert h in r.headers, (path, h)


def test_cross_origin_isolation_headers():
    """2026-07-26 Info: COOP everywhere, CORP same-origin on everything but
    /api (the Android/iOS shells reach /api cross-origin under CORS and never
    load relay static files). No COEP."""
    page = client.get("/")
    assert page.headers["Cross-Origin-Opener-Policy"] == "same-origin"
    assert page.headers["Cross-Origin-Resource-Policy"] == "same-origin"
    assert client.get("/app.js").headers["Cross-Origin-Resource-Policy"] == "same-origin"
    api = client.get("/api/users/nobody", params={"t": "x"},
                     headers={"Origin": config.APP_WEBVIEW_ORIGIN})
    assert api.headers["Cross-Origin-Opener-Policy"] == "same-origin"
    assert "Cross-Origin-Resource-Policy" not in api.headers, "CORP stays off /api"
    assert api.headers.get("access-control-allow-origin") == config.APP_WEBVIEW_ORIGIN
    assert "Cross-Origin-Embedder-Policy" not in page.headers


def test_oversize_api_bodies_are_refused_and_422s_do_not_echo():
    """F-P7-12: a 40 MB envelope was parsed and then echoed back inside the
    422. Declared bodies past MAX_API_BODY_BYTES are 413 before being read; a
    validation error never reflects the input."""
    big = b"A" * (config.MAX_API_BODY_BYTES + 1024)
    r = client.post("/api/mailbox/nobody", params={"t": "x"}, content=big,
                    headers={"content-type": "application/json"})
    assert r.status_code == 413, r.status_code
    assert r.headers.get("X-Content-Type-Options") == "nosniff", "the 413 still carries the security headers"
    r = client.post("/api/mailbox/nobody", params={"t": "x"},
                    json={"envelope": "A" * 300, "extra": "MARKER_do_not_echo_9f2c"})
    assert r.status_code == 422, r.text
    assert "MARKER_do_not_echo_9f2c" not in r.text, "F-P7-12: the 422 must not reflect the request body"
    assert r.json()["detail"][0]["type"], "...but still says what was wrong"
    r = client.post("/api/register", json={"username": "echo-me", "ed": "MARKER_ed_9f2c" * 10,
                                            "mldsa": "x", "sig": "x", "mldsa_sig": "x"})
    assert r.status_code == 422 and "MARKER_ed_9f2c" not in r.text, r.text


def test_declared_oversize_body_is_refused_before_it_is_read():
    """F-P7-12: a declared Content-Length past the cap is answered 413 without
    reading a single body byte or running the app (not merely by counting the
    bytes as they arrive)."""
    import asyncio

    async def app_must_not_run(scope, receive, send):
        raise AssertionError("the app ran for an oversize declared body")

    async def receive_must_not_be_called():
        raise AssertionError("the body was read")

    sent = []

    async def send(message):
        sent.append(message)

    scope = {"type": "http", "path": "/api/mailbox/x", "method": "POST",
             "headers": [(b"content-length", str(config.MAX_API_BODY_BYTES + 1).encode())]}
    asyncio.run(main._ApiBodyLimit(app_must_not_run)(scope, receive_must_not_be_called, send))
    assert sent[0]["type"] == "http.response.start" and sent[0]["status"] == 413, sent


def test_chunked_api_bodies_are_capped_too():
    """F-P7-12, the half phase7-local left open: a chunked body has no declared
    length, so a Content-Length check alone lets it through. The bytes actually
    received are counted as well."""
    chunk = b"A" * 16384
    n = config.MAX_API_BODY_BYTES // len(chunk) + 4

    def body():
        yield b'{"envelope": "'
        for _ in range(n):
            yield chunk
        yield b'"}'

    r = client.post("/api/mailbox/nobody", params={"t": "x"}, content=body(),
                    headers={"content-type": "application/json"})
    assert r.status_code == 413, (r.status_code, r.text[:200])
    # A body under the cap, chunked, still reaches the handler.
    r = client.post("/api/mailbox/nobody", params={"t": "x"},
                    content=iter([b'{"envelope": "', b"A" * 300, b'"}']),
                    headers={"content-type": "application/json"})
    assert r.status_code == 404, r.text


def _vendor_closure(root: Path) -> tuple[set, set]:
    """(vendored module files, files reachable from the client's imports)."""
    import re
    imp = re.compile(r"""^\s*(?:import|export)\b[^;]*?\bfrom\s*["']([^"']+)["']|^\s*import\s*["']([^"']+)["']""", re.M)
    dyn = re.compile(r"""import\(\s*["']([^"']+)["']\s*\)""")
    html = (root / "index.html").read_text()
    import json as _json
    imap = _json.loads(re.search(r'<script type="importmap">(.*?)</script>', html, re.S).group(1))["imports"]

    def resolve(spec, frm):
        for k, v in imap.items():
            if spec == k:
                return (root / v).resolve()
            if k.endswith("/") and spec.startswith(k):
                return (root / (v + spec[len(k):])).resolve()
        if spec.startswith("."):
            return (frm.parent / spec).resolve()
        return None

    seen, todo = set(), [p.resolve() for p in root.glob("*.js")]
    while todo:
        f = todo.pop()
        if f in seen or not f.exists():
            continue
        seen.add(f)
        src = re.sub(r"/\*.*?\*/", "", f.read_text(), flags=re.S)
        src = re.sub(r"(?m)^\s*//.*$", "", src)
        for m in list(imp.finditer(src)) + list(dyn.finditer(src)):
            r = resolve(next(g for g in m.groups() if g), f)
            if r:
                todo.append(r)
    vendored = {p.resolve() for p in (root / "vendor").rglob("*") if p.suffix in (".js", ".mjs")}
    return vendored, {p for p in seen if "vendor" in p.parts}


def test_only_the_import_closure_is_vendored():
    """F-WEB-002: @noble/hashes/{sha2,hmac,_md}.js and curves/abstract/modular.js
    were served although nothing imports them (JSDoc @example lines only).
    The vendored tree must equal what the client can actually import."""
    root = Path(__file__).resolve().parents[2] / "client"
    vendored, reached = _vendor_closure(root)
    assert reached, "the closure walk found nothing — the test itself is broken"
    unused = sorted(str(p.relative_to(root)) for p in vendored - reached)
    assert not unused, f"vendored but never imported (served for nothing): {unused}"
    missing = sorted(str(p.relative_to(root)) for p in reached - vendored)
    assert not missing, f"imported but not vendored: {missing}"
