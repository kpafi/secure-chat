"""Shared test fixtures.

IMPORTANT: this file must point the app at a throwaway DB *before* anything
imports `config`. pytest imports conftest.py ahead of the test modules, so the
`os.environ["SECURE_CHAT_DB"] = ...` lines inside individual test modules run too
late to help anything conftest itself imports — without the assignment below, a
module-level `import accounts` here would resolve `config.DB_PATH` to the real
backend/accounts.db and the suite would read and write production data.

The rate limiters are module-global and keyed per client host, so under the test
client every test shares one bucket. Without a reset, tests leak throttle state
into each other and the suite's pass/fail depends on execution order and on how
many accounts earlier tests registered (pentest 2026-07-26 P-09 added a dedicated
registration bucket, which made that pre-existing coupling visible). Clearing the
buckets before each test isolates them; tests that assert throttling behaviour
still exercise it explicitly within their own test body.
"""
import os
import sys
import tempfile
from pathlib import Path

# Throwaway DB + importable backend, BEFORE any app import below.
os.environ.setdefault("SECURE_CHAT_DB", os.path.join(tempfile.mkdtemp(), "conftest_accounts.db"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest  # noqa: E402


@pytest.fixture(autouse=True)
def _reset_rate_limiters():
    import accounts
    import mailbox

    for limiter in (
        accounts._api_limiter,
        accounts._lookup_limiter,
        accounts._vouch_host_limiter,
        accounts._challenge_limiter,
        accounts._challenge_host_limiter,
        accounts._register_limiter,
        mailbox._post_limiter,
        mailbox._fetch_limiter,
    ):
        limiter._buckets.clear()
    yield
