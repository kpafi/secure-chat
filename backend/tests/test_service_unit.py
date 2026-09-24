"""The systemd unit is a launch path, and it is the one that starts production.

Pentest 2026-07-29, test-coverage gap 3. `run.sh` and `main.py` have both been
held to the F-03/H-4 flags by tests since 2026-07-27, but `deploy/secure-chat.service`
— the only one of the three that runs on the Hetzner box — had no test at all.
Its correctness rests on two things that are invisible unless you read the file:
a flag that must be PRESENT, and a variable that must be ABSENT.

These are text assertions against a config file, which is a weak form of test.
They are here because the alternative is no coverage of the shipped launcher,
and because both properties are one careless edit away from silently inverting.
"""
import re
from pathlib import Path

import pytest

_UNIT = Path(__file__).resolve().parents[2] / "deploy" / "secure-chat.service"


@pytest.fixture(scope="module")
def unit() -> str:
    assert _UNIT.exists(), f"the production unit file is missing: {_UNIT}"
    return _UNIT.read_text()


def _exec_start(unit: str) -> str:
    lines = [l for l in unit.splitlines() if l.startswith("ExecStart=")]
    assert len(lines) == 1, f"expected exactly one ExecStart, got {len(lines)}"
    return lines[0]


def _directives(unit: str, key: str) -> list[str]:
    """Values of `key`, ignoring comments — a commented-out line is not config."""
    out = []
    for line in unit.splitlines():
        stripped = line.strip()
        if stripped.startswith("#") or "=" not in stripped:
            continue
        name, _, value = stripped.partition("=")
        if name.strip() == key:
            out.append(value.strip())
    return out


def test_execstart_disables_uvicorn_proxy_headers(unit):
    """Without this, uvicorn rewrites request.client before client_key runs (H-4)."""
    assert "--no-proxy-headers" in _exec_start(unit)


def test_unit_does_not_configure_a_trusted_proxy(unit):
    """The single line the whole rate-limit posture rests on — by being absent.

    Tor and Caddy both reach the relay from 127.0.0.1 and the app cannot tell
    them apart, so trusting loopback would let any onion visitor forge
    X-Forwarded-For and mint a private bucket: F-03 reopened. The comment in the
    unit says DO NOT re-add it; this asserts it.
    """
    assert not _directives(unit, "Environment") or not any(
        "SECURE_CHAT_TRUSTED_PROXIES" in v for v in _directives(unit, "Environment")
    ), "SECURE_CHAT_TRUSTED_PROXIES is set in the production unit (F-03/H-4)"
    # Belt and braces: not smuggled in via EnvironmentFile either.
    assert not _directives(unit, "EnvironmentFile"), (
        "EnvironmentFile makes the trusted-proxy posture unverifiable from this unit"
    )


def test_execstart_keeps_the_other_hardening_flags(unit):
    """These were all deliberate; a rewrite of the line must not drop one."""
    exec_start = _exec_start(unit)
    for flag in (
        "--host 127.0.0.1",      # never bind a public interface
        "--no-server-header",    # no version banner
        "--no-access-log",       # I2: no who-connected-when on disk
        "--log-level warning",
    ):
        assert flag in exec_start, f"production launcher lost {flag!r}"


def test_state_is_not_written_into_the_code_tree(unit):
    """Pentest 2026-07-29 L-8: the relay must not be able to rewrite its own source."""
    assert "StateDirectory=secure-chat" in unit
    rw = _directives(unit, "ReadWritePaths")
    assert not rw, f"ReadWritePaths reintroduces a writable path: {rw}"
    db = [v for v in _directives(unit, "Environment") if "SECURE_CHAT_DB" in v]
    assert db, "SECURE_CHAT_DB must be set, or the DB defaults next to the code"
    assert re.search(r"SECURE_CHAT_DB=/var/lib/secure-chat/", db[0]), db


def test_state_directory_is_not_world_readable(unit):
    """Moving the DB out of the code tree must not make it readable to everyone.

    systemd defaults StateDirectoryMode= to 0755 and enforces that mode on every
    start, so relying on the default (or on a 0750 the migration recipe created)
    leaves /var/lib/secure-chat world-traversable with a 0644 accounts.db inside.
    That publishes the directory's lookup TOKENS — the secret half of
    `username#token`, and the whole anti-enumeration control — plus the sealed
    mailbox ciphertext, to any local user. The unit must say 0700 explicitly.
    """
    modes = _directives(unit, "StateDirectoryMode")
    assert modes, (
        "StateDirectoryMode is unset, so systemd applies its 0755 default and "
        "the account database is world-readable"
    )
    assert modes[-1] == "0700", f"state directory must be 0700, got {modes[-1]!r}"
    # The migration recipe in the comments creates the directory by hand; if it
    # disagrees with the enforced mode the two silently diverge.
    install_lines = [ln for ln in unit.splitlines() if "install -d" in ln]
    assert install_lines, "the one-off migration recipe went missing from the unit"
    for ln in install_lines:
        assert "-m 0700" in ln, f"migration recipe creates the wrong mode: {ln.strip()!r}"


def test_sandboxing_directives_are_present(unit):
    for directive in (
        "NoNewPrivileges=yes",
        "ProtectSystem=strict",
        "ProtectHome=yes",
        "PrivateTmp=yes",
        "PrivateDevices=yes",
    ):
        assert directive in unit, f"production unit lost {directive}"



def test_ws_max_size_matches_the_frame_cap_everywhere(unit):
    """Phase-7 pentest 2026-09-16 F-P7-26: `66560` was a literal in run.sh, the
    production unit, the iOS CI relay and this test, while main.py computes
    MAX_FRAME_BYTES + 1024. Changing the frame cap would have left every
    launcher on the old value with this test still green. All derive from
    config now."""
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    import config
    flag = f"--ws-max-size {config.MAX_FRAME_BYTES + 1024}"
    root = Path(__file__).resolve().parents[2]
    assert flag in _exec_start(unit), f"production unit lost {flag!r}"
    assert flag in (root / "backend" / "run.sh").read_text(), f"run.sh lost {flag!r}"
    assert flag in (root / ".github" / "workflows" / "ios.yml").read_text(), f"iOS CI relay lost {flag!r}"
    assert "ws_max_size=config.MAX_FRAME_BYTES + 1024" in (root / "backend" / "main.py").read_text()
