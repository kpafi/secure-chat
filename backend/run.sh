#!/usr/bin/env bash
# Launch the relay locally for testing (loopback only).
# --no-access-log + --log-level warning: no per-request / per-connection
# metadata is written to disk (I2). Keep these on any .onion deployment.
set -euo pipefail
cd "$(dirname "$0")"
exec python -m uvicorn main:app --host 127.0.0.1 --port 8000 --no-server-header \
    --no-access-log --log-level warning
