"""Secure E2EE chat relay — FastAPI WebSocket backend.

Design: the server is a *dumb relay*. It authenticates the envelope shape,
enforces hard resource limits, and forwards opaque ciphertext between the
members of a room. It never holds keys, never decrypts, and never stores or
logs message content. A full compromise of this server yields only ciphertext.

Threat-model notes (see PROGRESS.md for the full list):
  * Untrusted client input -> strict pydantic validation, fail closed.
  * Memory-exhaustion DoS    -> frame/payload size caps, room/member caps.
  * Message-flood DoS        -> per-connection token-bucket rate limit.
  * Connection-flood DoS     -> global concurrent-connection cap.
  * Idle / zombie sockets    -> per-connection idle read timeout reaps them.
  * Plaintext/key exposure   -> server does no crypto; payloads are opaque.
  * Metadata leakage in logs -> payloads are never logged, AND per-request
    access logging + per-connection lifecycle logging are disabled by default
    (I2), so no who-connected-when / which-endpoint timing metadata is written
    to disk. Only genuine, content-free error tracebacks are logged. Operators
    MUST NOT re-enable access logging on the .onion.
"""
from __future__ import annotations

import asyncio
import fnmatch
import json
import logging
import os
import posixpath
import sqlite3

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
import mimetypes

# StaticFiles types files via `mimetypes`, which does not know .webmanifest on
# every platform; with nosniff a text/plain manifest can be refused.
mimetypes.add_type("application/manifest+json", ".webmanifest")
from pydantic import ValidationError
from starlette.requests import Request
from starlette.responses import Response
from starlette.websockets import WebSocketState

import accounts
import config
import mailbox
from relay import Conn, ConnectionLimiter, JoinResult, RoomRegistry, TokenBucket
from validation import Envelope, MsgType, is_ascii_printable


class _ClientProtocolNoiseFilter(logging.Filter):
    """Drop uvicorn's per-request client protocol errors (F-P7-15)."""

    NOISE = ("Invalid HTTP request received", "Unsupported upgrade request")

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            msg = record.getMessage()
        except Exception:  # noqa: BLE001 - a broken record is not worth a traceback
            return True
        return not any(n in msg for n in self.NOISE)


def _minimize_log_metadata() -> None:
    """Silence request/connection metadata at rest (I2).

    Uvicorn's access logger records every request line (method, path, status,
    timing) and its error logger emits INFO connection-lifecycle lines
    ("connection open/closed"). On a seized .onion host those logs are a
    who-talked-when metadata trail. We disable the access log entirely and lift
    the error logger to WARNING, so routine activity leaves no record while real
    errors (never containing payloads or room ids) are still surfaced. Applied
    here at import so it holds regardless of how the app is launched; the run.sh
    launcher also passes the matching CLI flags.
    """
    access = logging.getLogger("uvicorn.access")
    access.handlers.clear()
    access.disabled = True
    error = logging.getLogger("uvicorn.error")
    error.setLevel(logging.WARNING)
    # Phase-7 pentest 2026-09-16 F-P7-15 (ported from phase7-local 4b9d2c6): a
    # malformed request line, header or Content-Length, or a TLS ClientHello on
    # the plain port, is rejected by h11 BELOW the app and logged at WARNING
    # once per request — unauthenticated, unthrottled, and over the .onion any
    # visitor. Same class as the 2026-07-27 M-3 WebSocket fix. The line carries
    # no client data; it is dropped. Genuine warnings still pass.
    if not any(isinstance(f, _ClientProtocolNoiseFilter) for f in error.filters):
        error.addFilter(_ClientProtocolNoiseFilter())


_minimize_log_metadata()

# Our own logger emits ONLY content-free error tracebacks (no payloads, no room
# ids). Kept at WARNING so nothing routine is written to disk.
logging.basicConfig(
    level=logging.WARNING,
    format="%(asctime)s %(levelname)s %(message)s",
)
log = logging.getLogger("relay")

# Disable the interactive API docs and schema endpoints: this service has a
# single WebSocket endpoint and exposes nothing else for an attacker to probe.
app = FastAPI(
    title="secure-chat relay",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)


class _ApiBodyLimit:
    """Phase-7 pentest 2026-09-16 F-P7-12: cap /api request bodies.

    No request body on /api is legitimately larger than one envelope plus JSON
    overhead, but nothing bounded it: a 40 MB body was read, parsed and then
    ECHOED back inside the 422. phase7-local (4b9d2c6) refused on the DECLARED
    Content-Length only, which a chunked body skips; this also counts the bytes
    actually received and refuses once they pass the cap, before the handler
    ever sees the body. Pure ASGI, added INNERMOST (before CORS and the security
    headers), so the 413 still carries CORS and the security headers.
    """

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or not scope["path"].startswith("/api/"):
            return await self.app(scope, receive, send)
        limit = config.MAX_API_BODY_BYTES
        declared = 0
        for k, v in scope.get("headers", ()):
            if k == b"content-length":
                try:
                    declared = int(v)
                except ValueError:
                    declared = 0
        if declared > limit:
            await Response("request body too large", status_code=413, media_type="text/plain")(scope, receive, send)
            return
        received = 0

        async def limited_receive():
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > limit:
                    # An HTTPException is re-raised as-is by FastAPI's body
                    # reader (anything else becomes a generic 400).
                    raise HTTPException(status_code=413, detail="request body too large")
            return message

        await self.app(scope, limited_receive, send)


app.add_middleware(_ApiBodyLimit)


# CORS is shut for the web client (served same-origin via the .onion) and opened
# to exactly one extra origin: the Android app's bundled-client origin, whose
# /api directory fetches are cross-origin. Only GET/POST/DELETE + the two headers the
# client actually sends are allowed; no credentials mode (auth is an explicit
# Bearer token, never a cookie). The WS handshake is guarded separately by the
# origin allow-list in ws_endpoint.
# Added AFTER _ApiBodyLimit, so it sits outside it (Starlette: last added is
# outermost) and a 413 still carries the CORS headers the apps need to read it.
app.add_middleware(
    CORSMiddleware,
    allow_origins=config.ALLOWED_HTTP_ORIGINS,
    # DELETE: the apps' unvouch is DELETE /api/vouch/{target} (client
    # account.js), and without it here the cross-origin preflight from the
    # Android/iOS shells failed, so "remove vouch" never reached the relay
    # there (fix review F5, pre-existing on master).
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["content-type", "authorization"],
)

registry = RoomRegistry()
connections = ConnectionLimiter()

# Account directory (passwordless, key-based). Public keys only — see accounts.py.
accounts.init_db()
app.include_router(accounts.router)
# Login + registration: off the shared /api bucket, each on its own (see
# accounts.auth_router).
app.include_router(accounts.auth_router)

# Store-and-forward mailbox for sealed messages (opaque ciphertext only).
mailbox.init_db()
app.include_router(mailbox.router)


# Development/tooling files that live in the client dir but must never be
# served to the public (L-02). StaticFiles would otherwise expose them; this
# guard 404s them regardless of what is on disk (defense in depth alongside the
# deploy excludes).
#
# Phase-7 pentest F-P7-18: THE SAME LIST as deploy/ship-excludes.txt, which the
# deploy rsync, the APK's Gradle sync and the iOS bundle's sync-web.sh read.
# The relay cannot read it (deploy/ is not on the box), so it is repeated here
# and backend/tests/test_ship_list.py holds the two equal. Semantics are
# rsync's for a slash-free pattern: it matches ANY path segment, so a matching
# directory blocks everything below it. `client/vendor/README.md` used to be
# served because only package*.json, *.test.mjs, node_modules and dotfile
# BASENAMES were refused (a file inside a dot-directory was served too).
_DEV_ONLY_PATTERNS = ("*.test.mjs", "package*.json", "node_modules", ".*", "README.md")


def _is_blocked_static(path: str) -> bool:
    """True if `path` names a development/tooling file that must not be served.

    Pentest 2026-07-26 P-10: this used to compare the raw path against an EXACT
    set ({"/package.json", ...}). StaticFiles normalizes the path before
    resolving the file, so every non-canonical spelling of the same file sailed
    past the gate and returned real content — `//package.json`, `/package.json/`,
    and any nested copy such as `/vendor/lean-qr/package.json`. The entire
    `client/node_modules/` tree (including `.package-lock.json`, precisely the
    file class L-02 set out to block) was never covered at all. We now normalize
    first and match on path SEGMENTS + basenames, so spelling variants and nested
    copies are all caught, and the control no longer depends on the deploy-time
    excludes being right.
    """
    # Collapse "//", "/./" and any "/x/../" the way the static mount will.
    normalized = posixpath.normpath("/" + path.strip("/"))
    segments = [s for s in normalized.split("/") if s]
    # Every segment, not just the basename: /node_modules/x.js, /.git/config
    # and /vendor/README.md alike. Dotfiles (.package-lock.json, .env, .git*)
    # are never client assets.
    return any(
        fnmatch.fnmatchcase(seg, pat) for seg in segments for pat in _DEV_ONLY_PATTERNS
    )


# Fix review F4: which sqlite failures are routine contention (silent) and how
# often a real one may be logged. The window is per error name, process-wide.
_SQLITE_CONTENTION = ("SQLITE_BUSY", "SQLITE_LOCKED")  # incl. extended codes (SQLITE_BUSY_SNAPSHOT, ...)
_SQLITE_LOG_WINDOW_SEC = 60.0
_sqlite_logged_at: dict[str, float] = {}


# Primary result codes (low byte of the extended code) for lock contention.
_SQLITE_BUSY_CODES = (5, 6)  # SQLITE_BUSY, SQLITE_LOCKED
_SQLITE_BUSY_TEXT = ("database is locked", "database table is locked")


def _sqlite_error_name(exc: sqlite3.Error) -> str:
    """sqlite's own name for the error, robust to where it came from.

    `sqlite_errorname` / `sqlite_errorcode` exist since Python 3.11 and are
    only set on errors sqlite itself raised (the production venv is 3.13.5;
    re-review Info a). Fall back to the numeric code, then to the two fixed
    lock-contention messages, so contention is never misread as a fault."""
    name = getattr(exc, "sqlite_errorname", None)
    if name:
        return name
    code = getattr(exc, "sqlite_errorcode", None)
    if isinstance(code, int) and (code & 0xFF) in _SQLITE_BUSY_CODES:
        return "SQLITE_BUSY" if (code & 0xFF) == 5 else "SQLITE_LOCKED"
    if any(t in str(exc) for t in _SQLITE_BUSY_TEXT):
        return "SQLITE_BUSY"
    return "SQLITE_UNKNOWN"


# Registered for sqlite3.DatabaseError, the parent of OperationalError: a
# malformed database (SQLITE_CORRUPT / SQLITE_NOTADB) raises DatabaseError
# itself, which used to reach Starlette's default 500 with a traceback in the
# journal (re-review Info b). Every sqlite failure now takes this path.
@app.exception_handler(sqlite3.DatabaseError)
async def _sqlite_busy(request: Request, exc: sqlite3.DatabaseError) -> Response:
    # §9 L-2 (ported from phase7-local 6604d9e): "database is locked" under
    # load used to escape as a 500 with a traceback in the journal (I2). A bare
    # 503 says "try again" and writes nothing.
    #
    # Fix review F4: that mapping swallowed EVERY OperationalError — disk full,
    # I/O error, a missing table — as the same silent "busy", so a relay that
    # had lost its storage looked, to its operator, like a quiet one. Only lock
    # contention is silent now. Anything else (including a malformed database,
    # a DatabaseError) is a 500 plus ONE log line carrying only sqlite's error
    # NAME (no path, no query, no request data — I2), at most once per name per
    # minute so a failing disk cannot become a log flood.
    # Round-3 Info c: only OperationalError and DatabaseError PROPER are the
    # environment failing (lock, disk, I/O, corruption). ProgrammingError,
    # IntegrityError, InterfaceError, DataError, NotSupportedError are bugs in
    # OUR code; they must stay loud — re-raised to the default handler (500 +
    # traceback, and they fail the tests that hit them).
    if type(exc) not in (sqlite3.OperationalError, sqlite3.DatabaseError):
        raise exc
    name = _sqlite_error_name(exc)
    if name.startswith(_SQLITE_CONTENTION):
        return Response(status_code=503, content="busy", media_type="text/plain")
    now = asyncio.get_running_loop().time()
    last = _sqlite_logged_at.get(name)
    if last is None or now - last >= _SQLITE_LOG_WINDOW_SEC:
        _sqlite_logged_at[name] = now
        log.error("sqlite error %s", name)
    return Response(status_code=500, content="internal error", media_type="text/plain")


@app.exception_handler(RequestValidationError)
async def _validation_without_echo(request: Request, exc: RequestValidationError) -> Response:
    # Phase-7 pentest 2026-09-16 F-P7-12 (ported from 4b9d2c6): FastAPI's
    # default 422 echoes the offending INPUT back — for an oversize body that
    # was the whole body, for a mistyped envelope the ciphertext reflected.
    # Keep loc/msg/type (the client's formatDetail renders exactly those),
    # drop `input` and `ctx`.
    #
    # Fix review F3: for an unknown key (`extra_forbidden`) the LAST element of
    # `loc` is the attacker-chosen key itself, so the key was still reflected.
    # Drop it: the location becomes its container (["body"]), which is all the
    # client needs to render "Extra inputs are not permitted (body)".
    detail = []
    for e in exc.errors():
        item = {k: v for k, v in e.items() if k in ("loc", "msg", "type")}
        if e.get("type") == "extra_forbidden":
            item["loc"] = list(e.get("loc", ()))[:-1] or ["body"]
        detail.append(item)
    return JSONResponse(status_code=422, content={"detail": detail})


@app.middleware("http")
async def security_headers(request: Request, call_next):
    # Audit 2026-07-18 M-01: decide on the raw ASGI path, NOT request.url.path.
    # Affected Starlette versions reconstruct `url` using the client-controlled
    # Host header, which can desync it from the routed path and bypass this
    # gate (GHSA-86qp-5c8j-p5mr). scope["path"] is what routing actually uses.
    path = request.scope["path"]
    api = path.startswith("/api/")
    # Phase-7 pentest 2026-09-16 F-P7-16: the gate is for the static mount only.
    # Run on every path, it made legal usernames (a leading ".", a ".test.mjs"
    # suffix) register fine and then 404 on every /api/users lookup,
    # indistinguishably from "no such user".
    if not api and _is_blocked_static(path):
        # F-P7-25: this 404 used to return before the headers below were set,
        # so it went out with none of them. Same headers as every response.
        resp: Response = Response(status_code=404)
    else:
        resp = await call_next(request)
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    # HSTS only when actually reached over HTTPS (L-01). Caddy terminates TLS
    # and forwards X-Forwarded-Proto; loopback dev and .onion are plain HTTP
    # (and HSTS is meaningless/harmful for .onion), so we don't send it there.
    if request.headers.get("x-forwarded-proto") == "https":
        resp.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
    # Tight CSP: only same-origin script/style, WebSocket to same origin, no
    # inline anything (app.js/style.css are external; no inline handlers). The
    # one exception is the static <script type="importmap"> in index.html, which
    # the spec requires to be inline; it is pinned by its exact SHA-256 hash so
    # CSP stays strict (no 'unsafe-inline'). If the import map text changes, this
    # hash must be regenerated to match.
    resp.headers["Content-Security-Policy"] = (
        "default-src 'none'; "
        "script-src 'self' 'sha256-6Sm2nhNvoa7gr7uuY2hbAbpdWhIlL15/wXLm4dhO9UQ='; "
        "style-src 'self'; "
        "connect-src 'self'; "
        "img-src 'self' data:; "
        # Home Screen web app: the browser fetches manifest.webmanifest under
        # manifest-src, which default-src 'none' would block. Same origin only.
        "manifest-src 'self'; "
        # No workers: without this, worker-src falls back to script-src 'self',
        # so a same-origin script the relay never meant to serve (a write to
        # client/, a future injection bug) could register a service worker that
        # outlives the fix. It does NOT stop a compromised relay, which writes
        # its own headers. The client uses no workers (pentest dist-1 F3/2 L1).
        "worker-src 'none'; "
        "base-uri 'none'; "
        "form-action 'none'; "
        "frame-ancestors 'none'"
    )
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    # Pentest 2026-07-26 Info: process isolation. COOP severs any cross-origin
    # opener, so a page that opens (or is opened by) the client cannot keep a
    # window handle into it. CORP same-origin forbids other sites from
    # embedding the relay's static files as no-cors subresources. Not COEP (the
    # client needs no cross-origin isolation, and it would constrain the apps).
    # CORP is left off /api: the Android (https://secure-chat.internal) and iOS
    # (secure-chat://app) shells reach /api cross-origin under CORS, and never
    # load relay static files (their CSP allows img/script/style from their own
    # origin only), so CORP on the static mount cannot affect them while the
    # spec's CORS-mode exemption is not something /api needs to lean on.
    resp.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    if not api:
        resp.headers["Cross-Origin-Resource-Policy"] = "same-origin"
    # no-cache = always revalidate (cheap 304 via the ETag StaticFiles sends).
    # Without it browsers cache heuristically and keep serving a stale client
    # after a deploy — for a security-critical client, staleness is a bug.
    resp.headers["Cache-Control"] = "no-cache"
    return resp


@app.get("/healthz")
async def healthz() -> dict[str, str]:
    return {"status": "ok", "version": config.VERSION}


async def _safe_send(ws: WebSocket, text: str) -> None:
    """Send without ever raising into the main loop (peer may have vanished)."""
    if ws.application_state == WebSocketState.CONNECTED:
        try:
            await ws.send_text(text)
        except Exception:
            pass


async def _safe_close(ws: WebSocket) -> None:
    """Close someone else's socket without raising into this loop.

    Used when one connection ends another (a denied knocker, a waiter orphaned
    by its owner leaving): the target's own read loop then raises
    WebSocketDisconnect and runs its normal cleanup.
    """
    if ws.application_state == WebSocketState.CONNECTED:
        try:
            await ws.close()
        except Exception:
            pass


class _NonTextFrame(Exception):
    """The peer sent a non-text WebSocket frame (binary, or a close message)."""


async def _receive_text(ws: WebSocket) -> str:
    """Read one TEXT frame, or raise a typed error the loop can answer politely.

    Pentest 2026-07-27 M-3. Starlette's `receive_text()` indexes
    `message["text"]` unconditionally, so a binary frame raises a bare KeyError
    that is neither WebSocketDisconnect nor a validation error — it reached the
    catch-all `log.exception` and put a traceback on disk for any anonymous
    socket that asked. We do the dispatch ourselves: a text frame returns its
    text, a disconnect raises WebSocketDisconnect exactly as before, and
    anything else raises _NonTextFrame, which the loop turns into the same kind
    of polite error frame every other malformed input gets.
    """
    message = await ws.receive()
    if message["type"] == "websocket.disconnect":
        raise WebSocketDisconnect(message.get("code", 1000))
    text = message.get("text")
    if text is None:
        raise _NonTextFrame()
    return text


@app.websocket("/ws")
async def ws_endpoint(ws: WebSocket) -> None:
    # CSWSH protection: reject a present-but-disallowed browser Origin before
    # accepting. A missing Origin (non-browser client) is permitted.
    origin = ws.headers.get("origin")
    if origin is not None and origin not in config.ALLOWED_WS_ORIGINS:
        await ws.close(code=1008)  # policy violation
        return

    # Global connection cap: refuse before accepting so a flood of sockets
    # cannot exhaust file descriptors / memory. 1013 = "try again later".
    if not connections.try_acquire():
        await ws.close(code=1013)
        return

    await ws.accept()
    bucket = TokenBucket()
    # Connection state lives in a shared object, not in locals: a guest is
    # admitted by the OWNER's coroutine, which has to be able to flip this
    # socket's "am I in?" state (see relay.Conn).
    conn = Conn(ws=ws)
    try:
        while True:
            # State for the TIMEOUT decision only. It must be re-read after the
            # await below: this socket may be admitted by the owner's coroutine
            # while we are blocked in receive_text(), and acting on the
            # pre-await snapshot would leave a just-admitted guest unable to
            # send anything until its next frame.
            joined_room = conn.room if conn.admitted else None
            waiting_room = conn.waiting_room
            # Read timeout: a short JOIN deadline before the socket has joined a
            # room (drops "connect but never join" slot squatters fast), the
            # APPROVAL deadline while it waits in a room's pending queue (so a
            # knocker cannot hold a queue place forever), then the generous IDLE
            # window once admitted (so a quiet-but-reading peer is not dropped).
            # Either way, half-open / zombie sockets are reaped.
            if joined_room:
                timeout = config.IDLE_TIMEOUT_SEC
            elif waiting_room:
                # A waiter that has not introduced itself is waiting for nobody
                # — the owner has not been told it exists and so cannot deny it.
                # It gets seconds; only a knock buys the human-length window.
                timeout = (
                    config.PENDING_TIMEOUT_SEC if conn.knocked
                    else config.KNOCK_TIMEOUT_SEC
                )
            else:
                timeout = config.JOIN_TIMEOUT_SEC
            try:
                raw = await asyncio.wait_for(_receive_text(ws), timeout=timeout)
            except _NonTextFrame:
                # Pentest 2026-07-27 M-3: a BINARY frame used to reach
                # Starlette's receive_text(), which does message["text"]
                # unconditionally and raises KeyError — not WebSocketDisconnect,
                # so it fell through to the catch-all and wrote a full traceback
                # to disk. Any unauthenticated socket could therefore mint
                # precisely-timestamped log entries on demand (an I2 defeat and
                # a ~640x log-amplification DoS). Answer politely instead.
                await _safe_send(ws, '{"type":"error","reason":"binary frames not accepted"}')
                break
            except asyncio.TimeoutError:
                # Phase-7 pentest 2026-09-16 F-P7-10 (ported from 4b9d2c6): the
                # reason and the armed timeout were the PRE-await snapshot, so a
                # guest admitted by the owner while blocked here, that then
                # stayed silent, was closed at the pending deadline with
                # "approval timeout" instead of getting the idle window a member
                # is owed. Re-read the state: admitted mid-wait means re-arm
                # with the idle window, not close.
                if conn.admitted and conn.room and not joined_room:
                    continue
                if conn.admitted and conn.room:
                    reason = "idle timeout"
                elif conn.waiting_room:
                    reason = "approval timeout"
                else:
                    reason = "join timeout"
                await _safe_send(ws, '{"type":"error","reason":"' + reason + '"}')
                await ws.close(code=1001)  # going away
                break

            # 1) Hard size cap before any parsing or allocation.
            if len(raw.encode("utf-8", "ignore")) > config.MAX_FRAME_BYTES:
                await _safe_send(ws, '{"type":"error","reason":"frame too large"}')
                break

            # 2) ASCII-only on the whole frame.
            if not is_ascii_printable(raw):
                await _safe_send(ws, '{"type":"error","reason":"non-ascii"}')
                break

            # 3) Rate limit (after cheap checks, before JSON work).
            if not bucket.allow():
                await _safe_send(ws, '{"type":"error","reason":"rate limited"}')
                continue

            # 4) Parse + strict-validate the envelope. Anything off -> reject.
            # RecursionError (M-3): deeply nested JSON blows the C parser's
            # stack, and that is a client-input error like any other — without
            # it here the traceback landed in the catch-all logger.
            try:
                data = json.loads(raw)
                env = Envelope.model_validate(data)
            except (json.JSONDecodeError, ValidationError, RecursionError):
                await _safe_send(ws, '{"type":"error","reason":"bad envelope"}')
                continue

            # 5) Dispatch — against the CURRENT state, not the pre-await one.
            joined_room = conn.room if conn.admitted else None
            waiting_room = conn.waiting_room

            if env.type == MsgType.join:
                if joined_room is not None or waiting_room is not None:
                    await _safe_send(ws, '{"type":"error","reason":"already joined"}')
                    continue
                result, evicted = registry.join(env.room, conn)
                if evicted is not None:
                    await _safe_send(evicted.ws, '{"type":"error","reason":"approval timeout"}')
                    await _safe_close(evicted.ws)
                if result is JoinResult.admitted:
                    # First in: this connection created the room and owns it.
                    # `role` also tells the client the relay speaks this
                    # protocol at all — an old relay answers without it.
                    await _safe_send(ws, '{"type":"joined","role":"owner"}')
                elif result is JoinResult.waiting:
                    # P-08: waiting takes NO member slot. Nothing is forwarded
                    # to or from this socket until the owner admits it.
                    await _safe_send(ws, '{"type":"pending"}')
                else:
                    await _safe_send(ws, '{"type":"error","reason":"room full"}')
                    # M-1: make the lockout VISIBLE to the owner. A knocked
                    # waiter is not displaceable, so a filled queue turns every
                    # honest join away before it can even knock — the owner used
                    # to see nothing at all while the person they invited was
                    # told "room full". Batched by the registry so this cannot
                    # itself be flooded.
                    owner, count = registry.note_turned_away(env.room)
                    if owner is not None and owner is not conn:
                        await _safe_send(owner.ws, json.dumps({
                            "type": "turned-away", "count": count,
                        }))
                continue

            # A waiting socket may do exactly one thing: introduce itself to the
            # owner. Everything else is refused until it is admitted.
            if env.type == MsgType.knock:
                if waiting_room is None or env.room != waiting_room:
                    await _safe_send(ws, '{"type":"error","reason":"not waiting"}')
                    continue
                if conn.knocked:
                    # One introduction per socket, so a knocker cannot flood the
                    # owner's approval prompt with a stream of identities.
                    await _safe_send(ws, '{"type":"error","reason":"already knocked"}')
                    continue
                owner = registry.owner_of(waiting_room)
                if owner is None:
                    await _safe_send(ws, '{"type":"error","reason":"not in room"}')
                    continue
                conn.knocked = True
                # Forwarded verbatim: the introduction is opaque to the relay,
                # exactly like every other payload. The jid is the server's own.
                await _safe_send(owner.ws, json.dumps({
                    "type": "knock", "jid": conn.jid, "payload": env.payload,
                }))
                continue

            # Every remaining type requires ADMITTED membership of the room in
            # the envelope. A waiting socket falls through to here and is
            # refused, so it can neither send nor provoke a relay.
            if joined_room is None or env.room != joined_room:
                await _safe_send(ws, '{"type":"error","reason":"not in room"}')
                continue

            if env.type in (MsgType.admit, MsgType.deny):
                # Only the room owner decides. Membership alone is not enough:
                # in a 2-slot room the second member could otherwise admit or
                # deny on the owner's behalf.
                if not registry.is_owner(joined_room, conn):
                    await _safe_send(ws, '{"type":"error","reason":"not the room owner"}')
                    continue
                if env.type == MsgType.admit:
                    if not registry.has_free_slot(joined_room):
                        # Distinct from "no such waiting peer" so the owner is
                        # told the truth: the knocker is still there, the room
                        # is not. (The knocker stays queued either way.)
                        await _safe_send(ws, '{"type":"error","reason":"room full"}')
                        continue
                    seated = registry.admit(joined_room, env.jid)
                    if seated is None:
                        await _safe_send(ws, '{"type":"error","reason":"no such waiting peer"}')
                        continue
                    await _safe_send(seated.ws, '{"type":"joined","role":"guest"}')
                else:
                    denied = registry.deny(joined_room, env.jid)
                    if denied is None:
                        await _safe_send(ws, '{"type":"error","reason":"no such waiting peer"}')
                        continue
                    await _safe_send(denied.ws, '{"type":"denied"}')
                    await _safe_close(denied.ws)
                continue

            if env.type == MsgType.leave:
                await ws.close()  # explicit, deterministic close on leave
                break

            # type is msg or key: relay the opaque payload to peers verbatim.
            out = env.model_dump_json(exclude_none=True)
            for peer in registry.peers(joined_room, exclude=conn):
                await _safe_send(peer.ws, out)

    except WebSocketDisconnect:
        pass
    except (_NonTextFrame, RecursionError, ValueError, KeyError, TypeError):
        # Pentest 2026-07-27 M-3: failures whose cause is peer-supplied bytes
        # are not server faults, and a traceback per crafted frame is a
        # log-amplification DoS plus the who-connected-when metadata trail I2
        # promises not to keep. Swallow them silently; the socket just ends.
        pass
    except Exception:  # noqa: BLE001 - never leak a stack trace to the client
        # Genuine server faults still get a full (content-free) traceback.
        log.exception("unexpected error in ws loop")
    finally:
        connections.release()
        room = conn.room or conn.waiting_room
        if room is not None:
            # Waiters left with nobody to approve them are closed rather than
            # left to time out (the owner's departure ends the room).
            orphans, withdrawn = registry.leave(room, conn)
            for orphan in orphans:
                await _safe_send(orphan.ws, '{"type":"error","reason":"room closed"}')
                await _safe_close(orphan.ws)
            # Fix review 2026-07-30 (M-A): a waiter that gave up (or was cut off)
            # must be removed from the OWNER's approval queue. Nothing else tells
            # the owner, so without this the entry sits there forever and — with
            # the queue now capped — cheap connect/knock/disconnect cycles fill
            # it with ghosts and a genuine knock is dropped with no way to retry.
            # Carries only the server-issued join id, which the owner already
            # has: no identity, nothing new about who was connected when (I2).
            if withdrawn is not None:
                owner_conn, gone_jid = withdrawn
                await _safe_send(
                    owner_conn.ws,
                    json.dumps({"type": "withdrawn", "room": room, "jid": gone_jid}),
                )


# Serve the static web client same-origin. Mounted last so the explicit /ws and
# /healthz routes win. StaticFiles serves only files under CLIENT_DIR and blocks
# path traversal; html=True makes "/" return index.html.
if config.CLIENT_DIR and os.path.isdir(config.CLIENT_DIR):
    app.mount("/", StaticFiles(directory=config.CLIENT_DIR, html=True), name="client")


if __name__ == "__main__":
    import uvicorn

    # server_header=False strips uvicorn's `Server: uvicorn` fingerprint, which
    # is added below the ASGI layer and so cannot be removed by middleware.
    # access_log=False + log_level="warning": no request/connection metadata at
    # rest (I2); see _minimize_log_metadata above.
    #
    # Pentest 2026-07-27 H-4: proxy_headers=False + forwarded_allow_ips=[] are
    # NOT optional. Uvicorn defaults to trusting X-Forwarded-For from a loopback
    # peer and rewrites request.client BEFORE accounts.client_key ever runs, so
    # rotating that header mints a fresh rate-limit bucket per request and every
    # HTTP throttle (lookup anti-enumeration, challenge, register, mailbox) is
    # bypassed. run.sh passes the equivalent --no-proxy-headers CLI flag; this
    # programmatic launcher previously did not, which is how the live instance
    # ran without the F-03 defense. Both launch paths must match.
    # ws_max_size mirrors run.sh's --ws-max-size for the same reason: without it
    # uvicorn buffers up to 16 MiB per frame before the app's 64 KiB cap runs.
    uvicorn.run(
        app,
        host=config.HOST,
        port=config.PORT,
        server_header=False,
        access_log=False,
        log_level="warning",
        proxy_headers=False,
        forwarded_allow_ips=[],
        ws_max_size=config.MAX_FRAME_BYTES + 1024,
    )
