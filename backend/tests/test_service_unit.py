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
    """Values of `key` in the [Service] section, ignoring comments — a
    commented-out line is not config, and a sandboxing key under [Unit] or
    [Install] is ignored by systemd ("Unknown key ... ignoring"), so it is
    not config either (package-5 review)."""
    out = []
    section = None
    for line in unit.splitlines():
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            section = stripped[1:-1]
            continue
        if section != "Service" or stripped.startswith(("#", ";")) or "=" not in stripped:
            continue
        name, _, value = stripped.partition("=")
        if name.strip() == key:
            out.append(value.strip())
    return out


def test_execstart_has_no_privilege_prefix(unit):
    """Package-5 re-review: systemd reads prefix characters on ExecStart.
    `+` runs the command with FULL privileges (as root, ignoring User=,
    the capability bounding set, namespacing and the rest of the sandbox),
    `!`/`!!` ignore User=/Group= and the capability settings, `-` hides a
    failure, `@`/`:`/`|` change argv, expansion or the shell. The value must
    start with the interpreter path itself, nothing before it."""
    value = _exec_start(unit)[len("ExecStart="):]
    assert value.startswith("/opt/secure-chat/venv/bin/python "), (
        f"ExecStart must start with the venv python, no prefix: {value[:60]!r}")


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


_FIRST_TIER = {
    "NoNewPrivileges": ["yes"],
    "ProtectSystem": ["strict"],
    "ProtectHome": ["yes"],
    "PrivateTmp": ["yes"],
    "PrivateDevices": ["yes"],
    "StateDirectory": ["secure-chat"],
}


@pytest.mark.parametrize("key", sorted(_FIRST_TIER))
def test_sandboxing_directives_are_present(unit, key):
    """Exact values in [Service]: a substring check passed with the line
    commented out, or with `PrivateTmp=no` added after `PrivateTmp=yes`
    (the later assignment wins) - package-5 review."""
    got = _directives(unit, key)
    assert got == _FIRST_TIER[key], f"{key}: want {_FIRST_TIER[key]!r}, unit has {got!r}"


# Pentest F-RELAY-010: the second tier. Each value is the WHOLE list of values
# the unit may give that key (systemd accumulates most of these across lines,
# so a second `IPAddressAllow=any` further down would silently widen the first).
_SECOND_TIER = {
    # The relay listens on loopback and makes no outbound connection at all.
    "RestrictAddressFamilies": ["AF_UNIX AF_INET AF_INET6"],
    "IPAddressDeny": ["any"],
    "IPAddressAllow": ["localhost"],
    "SystemCallArchitectures": ["native"],
    "SystemCallFilter": ["@system-service", "~@privileged @resources"],
    "SystemCallErrorNumber": ["EPERM"],
    "MemoryDenyWriteExecute": ["yes"],
    "CapabilityBoundingSet": [""],
    "AmbientCapabilities": [""],
    "ProtectKernelTunables": ["yes"],
    "ProtectKernelModules": ["yes"],
    "ProtectKernelLogs": ["yes"],
    "ProtectControlGroups": ["yes"],
    "ProtectClock": ["yes"],
    "ProtectHostname": ["yes"],
    "ProtectProc": ["invisible"],
    "RestrictNamespaces": ["yes"],
    "RestrictRealtime": ["yes"],
    "RestrictSUIDSGID": ["yes"],
    "LockPersonality": ["yes"],
    "RemoveIPC": ["yes"],
    "UMask": ["0077"],
}


@pytest.mark.parametrize("key", sorted(_SECOND_TIER))
def test_second_tier_sandboxing(unit, key):
    got = _directives(unit, key)
    assert got == _SECOND_TIER[key], f"{key}: want {_SECOND_TIER[key]!r}, unit has {got!r}"


def test_no_directive_reopens_what_the_sandbox_closes(unit):
    """Keys that would undo the tiers above from a line nobody reads: a
    writable or bind-mounted path, a device allow-list, a switch of the
    service user (root would get the capabilities the bounding set removes)."""
    assert _directives(unit, "User") == ["securechat"]
    assert _directives(unit, "Group") == ["securechat"]
    for key in ("ReadWritePaths", "BindPaths", "DeviceAllow", "ExecPaths",
                "PermissionsStartOnly", "ExecStartPre", "ExecStartPost"):
        assert not _directives(unit, key), f"{key} is set: {_directives(unit, key)!r}"


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


def test_every_uvicorn_launch_in_the_repo_carries_the_frame_cap():
    """F-P7-26 residual (package 5): the test above names the launchers that
    existed. A NEW one - a per-release deploy script that restarts uvicorn by
    hand, a second CI job, a helper script - would not be covered. So scan
    every tracked file that is not prose (Markdown is history and docs): each
    logical line that launches `uvicorn main:app` must carry the flag, and
    every --ws-max-size / ws_max_size literal anywhere must equal the cap."""
    import subprocess
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    import config
    want = config.MAX_FRAME_BYTES + 1024
    root = Path(__file__).resolve().parents[2]
    tracked = subprocess.run(["git", "ls-files", "-z"], cwd=root, check=True,
                             capture_output=True).stdout.decode().split("\0")
    launches = 0
    for rel in tracked:
        if not rel or rel.endswith(".md") or rel.startswith("backend/tests/"):
            continue
        path = root / rel
        try:
            text = path.read_text()
        except (UnicodeDecodeError, FileNotFoundError, IsADirectoryError):
            continue
        for lit in re.findall(r"(?:--ws-max-size[ =]|ws_max_size\s*=\s*)(\d+)", text):
            assert int(lit) == want, f"{rel}: ws max size {lit}, the cap is {want}"
        logical = re.sub(r"\\\n", " ", text)
        if rel.endswith(".py"):
            continue  # a Python launcher passes ws_max_size=, checked as a literal above
        for line in logical.splitlines():
            # Any spelling: `-m uvicorn --app-dir X main:app`, `.../uvicorn "main:app"`.
            if (re.search(r"\buvicorn\b", line) and re.search(r"""(^|[\s"'=])main:app\b""", line)
                    and not line.lstrip().startswith("#")):
                launches += 1
                assert f"--ws-max-size {want}" in line, f"{rel}: uvicorn launch without the cap: {line.strip()[:160]}"
    # run.sh, the production unit and the iOS CI relay at least.
    assert launches >= 3, f"found only {launches} uvicorn launches - the scan is broken"


# ---- Caddy (the clearnet front end) ------------------------------------------

_CADDYFILE = Path(__file__).resolve().parents[2] / "deploy" / "Caddyfile"


def _caddy_blocks(text: str) -> list[tuple[str, list]]:
    """Parse a Caddyfile into [(header, children)] by brace matching.

    Enough of the grammar for these assertions: comments are dropped, a line
    ending in `{` opens a block named by the rest of the line, `}` closes it,
    anything else is a leaf directive (stored as its text)."""
    root: list = []
    stack = [root]
    for raw in text.splitlines():
        # A `#` starts a comment only at the start of a token.
        line = re.sub(r"(^|\s)#.*$", "", raw).strip()
        if not line:
            continue
        if line == "}":
            stack.pop()
            assert stack, "unbalanced '}' in the Caddyfile"
        elif line.endswith("{"):
            children: list = []
            stack[-1].append((line[:-1].strip(), children))
            stack.append(children)
        else:
            stack[-1].append(line)
    assert len(stack) == 1, "unclosed '{' in the Caddyfile"
    return root


def _log_blocks(node) -> list[tuple[str, list]]:
    out = []
    for child in node:
        if isinstance(child, tuple):
            header, children = child
            if header == "log" or header.startswith("log "):
                out.append(child)
            out.extend(_log_blocks(children))
    return out


def test_caddy_default_logger_is_discarded_too():
    """Pentest F-RELAY-009: the site's `log { output discard }` only governs
    the ACCESS log (http.log.access.*). Every other logger — `http.log.error`
    with the client IP and URI of every failed request, `http.stdlib` with the
    peer address of every failed TLS handshake — goes to Caddy's DEFAULT
    logger, which writes to stderr and so to journald. A global options block
    must send the default logger to discard as well."""
    blocks = _caddy_blocks(_CADDYFILE.read_text())
    first = blocks[0]
    assert isinstance(first, tuple) and first[0] == "", (
        "the Caddyfile must open with a global options block `{ ... }` "
        f"(Caddy only accepts it first), got {first!r}")
    default = [b for b in first[1] if isinstance(b, tuple) and b[0] == "log default"]
    assert len(default) == 1, "the global options block must configure `log default`"
    assert default[0][1] == ["output discard"], (
        f"the default logger must be `output discard` and nothing else, got {default[0][1]!r}")


def test_every_caddy_logger_discards_or_is_limited_to_certificate_upkeep():
    """No logger may write request metadata anywhere. The one exception is a
    logger that INCLUDEs only the certificate-management namespaces (ACME
    obtain/renew), which log the site's own domain and the CA's answer but no
    client data; it keeps a failing renewal visible in journald."""
    blocks = _caddy_blocks(_CADDYFILE.read_text())
    logs = _log_blocks(blocks)
    assert logs, "no log blocks at all"
    for header, children in logs:
        outputs = [c for c in children if isinstance(c, str) and c.startswith("output ")]
        includes = [c for c in children if isinstance(c, str) and c.startswith("include ")]
        excludes = [c for c in children if isinstance(c, str) and c.startswith("exclude ")]
        assert not any(isinstance(c, tuple) for c in children), (header, children)
        if outputs == ["output discard"]:
            continue
        assert header != "log" and header != "log default", (
            f"{header!r} writes somewhere: {outputs}")
        assert len(includes) == 1 and not excludes, (header, children)
        namespaces = includes[0].split()[1:]
        assert namespaces and all(n in ("tls.obtain", "tls.renew") for n in namespaces), (
            f"{header!r} includes loggers other than certificate upkeep: {namespaces}")
