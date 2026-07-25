#!/usr/bin/env bash
# Launch the relay locally for testing (loopback only).
# --no-access-log + --log-level warning: no per-request / per-connection
# metadata is written to disk (I2). Keep these on any .onion deployment.
set -euo pipefail
cd "$(dirname "$0")"
# --ws-max-size (audit 2026-07-18 M-03): reject oversize WebSocket frames at
# the protocol layer. Without it uvicorn buffers up to 16 MiB per message
# BEFORE the app's 64 KiB check runs — a memory-exhaustion vector across many
# connections. 66560 = MAX_FRAME_BYTES (64 KiB) + 1 KiB headroom so frames just
# over the app limit still get the app's polite "frame too large" error while
# anything larger is hard-closed (1009) without being buffered.
# --no-proxy-headers (pentest 2026-07-25 F-03): uvicorn would otherwise trust a
# client-supplied X-Forwarded-For whenever the peer is loopback, handing out a
# fresh rate-limit bucket per forged header. The app resolves the client address
# itself (accounts.client_key) against SECURE_CHAT_TRUSTED_PROXIES.
exec python -m uvicorn main:app --host 127.0.0.1 --port 8000 --no-server-header \
    --no-proxy-headers --no-access-log --log-level warning --ws-max-size 66560
