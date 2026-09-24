"""Guard: request/connection metadata is not logged at rest (I2).

If someone re-enables uvicorn's access log or drops the run.sh flags, these
tests fail loudly — the point of I2 is that a seized .onion host holds no
who-connected-when metadata trail.
"""
import logging
import os
import sys
import tempfile
from pathlib import Path

# Point the app's DB at a throwaway path BEFORE importing it.
os.environ.setdefault("SECURE_CHAT_DB", os.path.join(tempfile.mkdtemp(), "test_logging.db"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import main  # noqa: E402  (import runs _minimize_log_metadata)


def test_access_log_disabled():
    # Uvicorn's per-request access logger must be disabled (no method/path/
    # status/timing lines written).
    assert logging.getLogger("uvicorn.access").disabled is True


def test_connection_lifecycle_log_quieted():
    # Connection open/close INFO lines are suppressed; only WARNING+ (real
    # errors, never payloads) are recorded.
    assert logging.getLogger("uvicorn.error").level >= logging.WARNING


def test_runsh_keeps_metadata_off():
    # The deployment launcher must carry the flags too, since the CLI path
    # configures logging independently of the import-time guard above.
    run_sh = (Path(__file__).resolve().parents[1] / "run.sh").read_text()
    assert "--no-access-log" in run_sh
    assert "--log-level warning" in run_sh
    assert main is not None  # import kept referenced



def test_client_protocol_noise_is_not_logged():
    """Phase-7 pentest 2026-09-16 F-P7-15: h11 rejects a malformed request
    below the app and uvicorn logs "Invalid HTTP request received." at WARNING
    once per request — unauthenticated, unthrottled, from any onion visitor.
    The line carries no client data and is dropped; real warnings still pass."""
    log = logging.getLogger("uvicorn.error")
    for text in ("Invalid HTTP request received.", "Unsupported upgrade request."):
        noise = logging.LogRecord("uvicorn.error", logging.WARNING, __file__, 1, text, None, None)
        assert not log.filter(noise), f"F-P7-15: {text!r} must be dropped"
    real = logging.LogRecord("uvicorn.error", logging.WARNING, __file__, 1, "Exception in ASGI application", None, None)
    assert log.filter(real), "...while genuine warnings still reach the log"
