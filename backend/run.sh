#!/usr/bin/env bash
# Launch the relay locally for testing (loopback only).
set -euo pipefail
cd "$(dirname "$0")"
exec python -m uvicorn main:app --host 127.0.0.1 --port 8000 --no-server-header
