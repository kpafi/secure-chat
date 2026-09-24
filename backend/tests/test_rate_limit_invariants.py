"""Rate-limit invariants (pentest 2026-08-08, item 19).

Ported to master from phase7-local 40d132e. Master calls the absolute ceiling
the per-HOST challenge bucket (CHALLENGE_HOST_RATE_*); behind Tor it is the
relay-wide ceiling, which is what phase7-local calls "global".

These pin RELATIONSHIPS between the limiter settings, not the settings
themselves. Tuning them individually is fine and expected; what must not happen
silently is a change that widens how many accounts one unauthenticated visitor
can hold offline at once.

The arithmetic, because it is counter-intuitive and a reviewer will otherwise
"fix" it in the wrong direction:

Every /auth/challenge request is charged to the per-client_key HOST bucket
BEFORE the per-username one is consulted, so an attacker's total spend is capped
at CHALLENGE_HOST_RATE_REFILL_PER_SEC however they aim it. Keeping one victim's
bucket empty costs CHALLENGE_RATE_REFILL_PER_SEC. Therefore

    simultaneous victims = host refill / per-username refill

and LOWERING the per-username refill — which reads as "stricter" — multiplies the
attacker's reach. On master (host ceiling 20/s) the original 0.5/s gave forty
accounts; at 2.0/s it is ten.
"""
import os
import sys
import tempfile
from pathlib import Path

_TMP_DB = os.path.join(tempfile.mkdtemp(), "test_rate_invariants.db")
os.environ["SECURE_CHAT_DB"] = _TMP_DB
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fastapi.testclient import TestClient  # noqa: E402

from main import app  # noqa: E402
import accounts  # noqa: E402
import config  # noqa: E402

client = TestClient(app)

# How many accounts one attacker may be able to silence at once. Chosen, not
# derived: raising it is a decision someone must make on purpose.
MAX_SIMULTANEOUS_VICTIMS = 10

# The other half of that bound, and the reason it needs one. `reach` is a RATIO,
# so it can be satisfied from either end — and lowering the global ceiling to
# "pass the invariant" would throttle login capacity for the entire relay while
# turning the test green. That is a worse outcome than the finding the ratio
# exists to bound, so the global ceiling gets an availability floor of its own.
#
# Derived rather than hard-coded: an honest login spends at most this many
# challenges, and the relay must sustain at least this many logins per second
# service-wide.
CHALLENGES_PER_LOGIN = 2
MIN_RELAY_LOGINS_PER_SEC = 2.0

# Limiter buckets are reset by conftest's autouse fixture.


def test_targeted_lockout_reach_is_bounded():
    """The item 19 invariant itself."""
    reach = config.CHALLENGE_HOST_RATE_REFILL_PER_SEC / config.CHALLENGE_RATE_REFILL_PER_SEC
    assert reach <= MAX_SIMULTANEOUS_VICTIMS, (
        f"one attacker could hold {reach:.0f} accounts offline at once "
        f"(host {config.CHALLENGE_HOST_RATE_REFILL_PER_SEC}/s ÷ per-username "
        f"{config.CHALLENGE_RATE_REFILL_PER_SEC}/s). Item 19: LOWERING the "
        "per-username refill reads as stricter and is strictly worse — it makes "
        "each victim cheaper to hold. RAISE the per-username refill. Do not "
        "'fix' this by lowering the global ceiling: that satisfies the ratio by "
        "throttling everyone's logins, and test_global_ceiling_keeps_the_relay_"
        "usable exists to stop exactly that."
    )


def test_global_ceiling_keeps_the_relay_usable():
    """The availability floor under the ratio above.

    `reach` is a ratio and can be satisfied from either end. Lowering the global
    ceiling would pass it while throttling login capacity for the whole relay —
    a self-inflicted version of the F-RELAY-003 outage the per-username keying
    was introduced to fix. So the global ceiling has a floor of its own.
    """
    floor = MIN_RELAY_LOGINS_PER_SEC * CHALLENGES_PER_LOGIN
    assert config.CHALLENGE_HOST_RATE_REFILL_PER_SEC >= floor, (
        f"the relay-wide challenge ceiling is "
        f"{config.CHALLENGE_HOST_RATE_REFILL_PER_SEC}/s, below the "
        f"{floor}/s needed to sustain {MIN_RELAY_LOGINS_PER_SEC} logins/sec at "
        f"{CHALLENGES_PER_LOGIN} challenges each. Satisfying the attacker-reach "
        "bound by lowering this throttles every honest user instead."
    )


def test_per_username_bucket_is_not_the_global_ceiling():
    """The per-username bucket must stay well under the global one.

    If it ever exceeded the global refill, one account could absorb the entire
    relay's challenge budget and F-RELAY-003 would be back by another road.
    """
    assert config.CHALLENGE_RATE_REFILL_PER_SEC < config.CHALLENGE_HOST_RATE_REFILL_PER_SEC, (
        "a single username may not be allowed to spend the whole relay's "
        "challenge budget — that is F-RELAY-003 with extra steps"
    )


def test_honest_login_has_ample_headroom():
    """Tuning must not squeeze real users.

    A login spends one challenge; the client's autoLogin backoff caps retries at
    one per 12 s. A burst allowance below a handful would start denying honest
    users, which is how a DoS control becomes the DoS.
    """
    assert config.CHALLENGE_RATE_CAPACITY >= 5, "burst allowance too small for honest retries"
    assert config.CHALLENGE_RATE_REFILL_PER_SEC >= 1.0, (
        "an honest client retrying a failed login must never be throttled; "
        "autoLogin's fastest retry is one per 12 s"
    )


def test_pending_challenge_store_cannot_be_flooded():
    """The global refill and the TTL together must stay far under the cap.

    Raising the global ceiling to buy reach (the other way to satisfy the item 19
    invariant) trades against this: pending challenges are what an attacker
    accumulates, and exhausting them 503s the endpoint for everyone.
    """
    worst_case_pending = config.CHALLENGE_HOST_RATE_REFILL_PER_SEC * config.CHALLENGE_TTL_SEC
    assert worst_case_pending < config.MAX_PENDING_CHALLENGES / 2, (
        f"sustained challenge minting could hold {worst_case_pending:.0f} pending "
        f"challenges against a {config.MAX_PENDING_CHALLENGES} cap"
    )


def test_targeted_lockout_still_spares_bystanders():
    """The property the per-username keying exists to provide, end to end.

    Draining one username must not deny another. If this fails the bucket has
    been re-keyed onto something shared and F-RELAY-003 is open again.
    """
    for _ in range(config.CHALLENGE_RATE_CAPACITY + 3):
        client.post("/api/auth/challenge", json={"username": "i19victim"})
    victim = client.post("/api/auth/challenge", json={"username": "i19victim"})
    bystander = client.post("/api/auth/challenge", json={"username": "i19bystander"})
    assert victim.status_code == 429, "precondition: the victim's bucket is drained"
    assert bystander.status_code == 200, (
        "draining one username must not deny another — that is the whole point "
        "of keying per username (F-RELAY-003)"
    )


def test_challenge_denial_is_not_an_existence_oracle():
    """Anti-enumeration (I1) must survive the keying.

    A bucket is minted for any well-formed username, so a 429 says only
    "somebody asked about this name recently" — a state the asker produces
    themselves — and never distinguishes a real account from a nonexistent one.
    """
    for name in ("i19realuser", "i19nosuchuser"):
        codes = [
            client.post("/api/auth/challenge", json={"username": name}).status_code
            for _ in range(config.CHALLENGE_RATE_CAPACITY + 2)
        ]
        assert codes[0] == 200, f"{name}: a challenge is issued regardless of existence"
        assert codes[-1] == 429, f"{name}: the bucket applies regardless of existence"
