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
  * Metadata leakage in logs -> payloads are never logged.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import ValidationError
from starlette.requests import Request
from starlette.responses import Response
from starlette.websockets import WebSocketState

import accounts
import config
from relay import ConnectionLimiter, RoomRegistry, TokenBucket
from validation import Envelope, MsgType, is_ascii_printable

# Connection-lifecycle logging only. Message payloads are NEVER logged.
logging.basicConfig(
    level=logging.INFO,
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

# CORS locked shut. The browser client is served same-origin (via the .onion),
# so no cross-origin access is ever required.
app.add_middleware(
    CORSMiddleware,
    allow_origins=[],
    allow_methods=[],
    allow_headers=[],
)

registry = RoomRegistry()
connections = ConnectionLimiter()

# Account directory (passwordless, key-based). Public keys only — see accounts.py.
accounts.init_db()
app.include_router(accounts.router)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    resp: Response = await call_next(request)
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    # Tight CSP: only same-origin script/style, WebSocket to same origin, no
    # inline anything (app.js/style.css are external; no inline handlers). The
    # one exception is the static <script type="importmap"> in index.html, which
    # the spec requires to be inline; it is pinned by its exact SHA-256 hash so
    # CSP stays strict (no 'unsafe-inline'). If the import map text changes, this
    # hash must be regenerated to match.
    resp.headers["Content-Security-Policy"] = (
        "default-src 'none'; "
        "script-src 'self' 'sha256-8alK18bvJunVDTi6IeRPvle6KjTYfSgRbp5alxxa+M8='; "
        "style-src 'self'; "
        "connect-src 'self'; "
        "img-src 'self' data:; "
        "base-uri 'none'; "
        "form-action 'none'; "
        "frame-ancestors 'none'"
    )
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    return resp


@app.get("/healthz")
async def healthz() -> dict[str, str]:
    return {"status": "ok"}


async def _safe_send(ws: WebSocket, text: str) -> None:
    """Send without ever raising into the main loop (peer may have vanished)."""
    if ws.application_state == WebSocketState.CONNECTED:
        try:
            await ws.send_text(text)
        except Exception:
            pass


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
    joined_room: str | None = None
    try:
        while True:
            # Read timeout: a short JOIN deadline before the socket has joined a
            # room (drops "connect but never join" slot squatters fast), then the
            # generous IDLE window once joined (so a quiet-but-reading peer is not
            # dropped). Either way, half-open / zombie sockets are reaped.
            timeout = config.IDLE_TIMEOUT_SEC if joined_room else config.JOIN_TIMEOUT_SEC
            try:
                raw = await asyncio.wait_for(ws.receive_text(), timeout=timeout)
            except asyncio.TimeoutError:
                reason = "idle timeout" if joined_room else "join timeout"
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
            try:
                data = json.loads(raw)
                env = Envelope.model_validate(data)
            except (json.JSONDecodeError, ValidationError):
                await _safe_send(ws, '{"type":"error","reason":"bad envelope"}')
                continue

            # 5) Dispatch.
            if env.type == MsgType.join:
                if joined_room is not None:
                    await _safe_send(ws, '{"type":"error","reason":"already joined"}')
                    continue
                if not registry.join(env.room, ws):
                    await _safe_send(ws, '{"type":"error","reason":"room full"}')
                    continue
                joined_room = env.room
                await _safe_send(ws, '{"type":"joined"}')
                continue

            # Every non-join type requires an active room matching the envelope.
            if joined_room is None or env.room != joined_room:
                await _safe_send(ws, '{"type":"error","reason":"not in room"}')
                continue

            if env.type == MsgType.leave:
                await ws.close()  # explicit, deterministic close on leave
                break

            # type is msg or key: relay the opaque payload to peers verbatim.
            out = env.model_dump_json(exclude_none=True)
            for peer in registry.peers(joined_room, exclude=ws):
                await _safe_send(peer, out)

    except WebSocketDisconnect:
        pass
    except Exception:  # noqa: BLE001 - never leak a stack trace to the client
        log.exception("unexpected error in ws loop")
    finally:
        connections.release()
        if joined_room is not None:
            registry.leave(joined_room, ws)


# Serve the static web client same-origin. Mounted last so the explicit /ws and
# /healthz routes win. StaticFiles serves only files under CLIENT_DIR and blocks
# path traversal; html=True makes "/" return index.html.
if config.CLIENT_DIR and os.path.isdir(config.CLIENT_DIR):
    app.mount("/", StaticFiles(directory=config.CLIENT_DIR, html=True), name="client")


if __name__ == "__main__":
    import uvicorn

    # server_header=False strips uvicorn's `Server: uvicorn` fingerprint, which
    # is added below the ASGI layer and so cannot be removed by middleware.
    uvicorn.run(app, host=config.HOST, port=config.PORT, server_header=False)
