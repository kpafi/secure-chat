"""/etc/caddy/Caddyfile is shared with other services on the box.

The 0.4.0 deploy (2026-09-26 20:13 UTC) installed deploy/Caddyfile over it
wholesale and so removed the Kiosk news app's site block (kept between
`# >>> kiosk (managed by deploy.sh)` and `# <<< kiosk`); kiosk.<host> was down
until Kiosk's next deploy put it back at 20:27. From then on:

  - deploy/Caddyfile imports /etc/caddy/sites.d/*.caddy, a directory the
    deploy creates if missing and whose files it never touches;
  - the deploy installs deploy/Caddyfile PLUS every marker block of the live
    file (deploy/caddy-compose.py), so a service that still keeps its block
    in the shared file survives a secure-chat deploy; anything else outside
    the marker blocks that it would drop stops the deploy instead.

Nothing here needs Caddy: the step-4 test runs the deploy script's own remote
code against a temporary /etc/caddy with `caddy` and `systemctl` faked.
"""
import importlib.util
import os
import pwd
import re
import stat
import subprocess
from pathlib import Path

import pytest

from test_ship_list import _deploy_scripts
from test_service_unit import _CADDYFILE, _caddy_blocks

ROOT = Path(__file__).resolve().parents[2]
COMPOSE = ROOT / "deploy" / "caddy-compose.py"
IMPORT = "import /etc/caddy/sites.d/*.caddy"

_spec = importlib.util.spec_from_file_location("caddy_compose", COMPOSE)
cc = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(cc)

# Kiosk's block exactly as its deploy writes it (nachrichtenapp
# deploy/Caddyfile.kiosk, abridged inside the site).
KIOSK = """\
# >>> kiosk (managed by deploy.sh)
# Dieser Block wird von deploy/deploy.sh zwischen den Markern ersetzt; nicht von Hand ändern.
kiosk.138-199-144-35.sslip.io {
\treverse_proxy 127.0.0.1:8100
\tlog {
\t\toutput discard
\t}
}
# <<< kiosk
"""


# ---- deploy/Caddyfile --------------------------------------------------------

def test_caddyfile_imports_the_other_services_sites_last():
    """One top-level import of the absolute sites.d glob, after the global
    options block and secure-chat's own site. Absolute, so `caddy validate` of
    the STAGED copy (in /root/secure-chat-*/stage/) sees the same files as the
    installed one; a relative path would resolve next to the staged copy and
    validate without them."""
    blocks = _caddy_blocks(_CADDYFILE.read_text())
    assert isinstance(blocks[0], tuple) and blocks[0][0] == "", "global options block first"
    imports = [b for b in blocks if isinstance(b, str) and b.startswith("import ")]
    assert imports == [IMPORT], imports
    assert blocks[-1] == IMPORT, "the import must come after secure-chat's own site"
    sites = [b[0] for b in blocks[1:] if isinstance(b, tuple)]
    assert sites == ["138-199-144-35.sslip.io"], sites


def test_caddyfile_holds_no_marker_lines():
    """Marker blocks belong to other services. One in deploy/Caddyfile would be
    ambiguous with the live file's (compose refuses it)."""
    text = _CADDYFILE.read_text()
    assert not re.search(r"(?m)^\s*#\s*(>>>|<<<)", text)
    assert cc.marker_blocks(text) == []


# ---- deploy/caddy-compose.py -------------------------------------------------

NEW = _CADDYFILE.read_text()
HOST = "138-199-144-35.sslip.io"
# The live file as the 0.4.0 run found it: an older secure-chat part (no
# import, other directives) and Kiosk's block after it.
OLD_LIVE = "{\n\tlog default {\n\t\toutput discard\n\t}\n}\n\n" + HOST + " {\n\treverse_proxy 127.0.0.1:8000\n}\n\n" + KIOSK


def test_compose_keeps_the_kiosk_block_the_0_4_0_deploy_dropped():
    """The incident: the live file held the Kiosk block after secure-chat's
    old site; the new file must carry it over verbatim."""
    out, names = cc.compose(NEW, OLD_LIVE)
    assert names == ["kiosk"]
    assert out.startswith(NEW.rstrip("\n") + "\n")
    assert out.endswith("\n" + KIOSK)
    assert out.count("kiosk.138-199-144-35.sslip.io {") == 1


def test_compose_without_marker_blocks_is_deploy_caddyfile():
    out, names = cc.compose(NEW, HOST + " {\n\treverse_proxy 127.0.0.1:8000\n}\n")
    assert names == [] and out == NEW.rstrip("\n") + "\n"


def test_compose_is_idempotent_and_keeps_order_and_bytes():
    other = "  # >>> maildigest\nmail.example {\n\trespond 204\n}\n\t# <<< maildigest"  # indented, no final newline
    live = HOST + " {\n}\n" + KIOSK + "\n" + other
    once, names = cc.compose(NEW, live)
    assert names == ["kiosk", "maildigest"]
    twice, _ = cc.compose(NEW, once)
    assert twice == once
    assert KIOSK in once and other + "\n" in once


@pytest.mark.parametrize("live", [
    HOST + " {\n}\n\nkiosk.x {\n\treverse_proxy 127.0.0.1:8100\n}\n",   # Kiosk's pre-marker form
    OLD_LIVE + "\nimport /etc/caddy/conf.d/*\n",
    "(shared) {\n\tencode gzip\n}\n" + KIOSK,
], ids=["unmarked-site", "foreign-import", "foreign-snippet"])
def test_compose_refuses_to_drop_unmarked_content(live):
    """Pentest finding 1: only marker blocks are carried, so anything else
    outside them that deploy/Caddyfile does not have would vanish - the
    incident again, with step 5 none the wiser. Refused instead."""
    with pytest.raises(cc.MarkerError, match="would be dropped"):
        cc.compose(NEW, live)


@pytest.mark.parametrize("live", [
    HOST + " {\n\trespond \"}{ # not a comment\"\n\trespond `{`\n}\n" + KIOSK,   # braces in strings
    HOST + " {\n\t# a \"quote\" and a ` in a comment, <<heredoc talk\n}\n" + KIOSK,
    HOST + " {\r\n}\r\n" + KIOSK,
], ids=["quoted-braces", "comment-chars", "crlf"])
def test_compose_models_what_it_accepts(live):
    cc.compose(NEW, live)


@pytest.mark.parametrize("live, why", [
    (HOST + " {\n\trespond <<EOF\n\t{\n\tEOF\n}\nkiosk.x {\n}\n", "heredoc"),
    (HOST + " {\n\trespond \"a\n{\"\n}\nkiosk.x {\n}\n", "quote left open"),
    (HOST + " {\n\trespond `a\n{`\n}\nkiosk.x {\n}\n", "quote left open"),
    (HOST + " {\n# note\r{\n}\nkiosk.x {\n}\n# x\r}\n", "line ending"),
    (HOST + " {\n}\n}\n", "unbalanced '}'"),
    (HOST + " {\n", "unbalanced '{'"),
], ids=["heredoc", "multiline-quote", "multiline-backtick", "cr-only", "extra-close", "unclosed"])
def test_compose_refuses_what_it_cannot_model(live, why):
    """Pentest round 2, finding 4: a brace hidden where this parser and
    Caddy's lexer disagree could put a foreign site at an apparent depth > 0,
    and it would be dropped silently. Refused instead."""
    with pytest.raises(cc.MarkerError, match=why):
        cc.compose(NEW, live)


@pytest.mark.parametrize("content", [
    "(common) {\n\tencode gzip\n}\nkiosk.x {\n\timport common\n}\n",
    "kiosk.x {\n\t# we do not import anything\n}\n",
    "import /etc/caddy/snippets/*\nkiosk.x {\n}\n",
    f"kiosk.x {{\n\trespond \"see {HOST}.example\"\n}}\n",       # another name that starts with ours
])
@pytest.mark.parametrize("where", ["block", "sites.d"])
def test_compose_accepts_ordinary_foreign_content(content, where):
    """Pentest round 2, finding 1: only site-block headers of deploy/Caddyfile
    are our addresses - not the words of its `import` line."""
    if where == "block":
        cc.compose(NEW, OLD_LIVE + "# >>> k\n" + content + "# <<< k\n")
    else:
        cc.compose(NEW, OLD_LIVE, [("k.caddy", content)])


def test_compose_host_check_ignores_case():
    with pytest.raises(cc.MarkerError, match="names our own site address"):
        cc.compose(NEW, OLD_LIVE, [("k.caddy", "x {\n\tlog {\n\t\thostnames " + HOST.upper() + "\n\t}\n}\n")])


@pytest.mark.parametrize("where", ["block", "sites.d"])
def test_compose_refuses_foreign_content_naming_our_host(where):
    """Pentest lead 9: a logger with `hostnames <our host>` in someone else's
    config would log secure-chat's traffic; a second site for our host is not
    theirs to define. Their own subdomain of the same sslip name is fine."""
    evil = f"kiosk.x {{\n\tlog {{\n\t\thostnames {HOST}\n\t\toutput file /var/log/x\n\t}}\n}}\n"
    live, sites = OLD_LIVE, [("kiosk.caddy", KIOSK)]
    if where == "block":
        live += "# >>> evil\n" + evil + "# <<< evil\n"
    else:
        sites.append(("evil.caddy", evil))
    with pytest.raises(cc.MarkerError, match=f"names our own site address {re.escape(HOST)}"):
        cc.compose(NEW, live, sites)
    cc.compose(NEW, OLD_LIVE, [("kiosk.caddy", KIOSK)])  # kiosk.<HOST> is not our address


@pytest.mark.parametrize("live, why", [
    ("# >>> kiosk\nkiosk.x {\n}\n", "never closed"),
    ("kiosk.x {\n}\n# <<< kiosk\n", "never opened"),
    ("# >>> kiosk\n# >>> other\n# <<< other\n# <<< kiosk\n", "inside"),
    ("# >>> kiosk\nkiosk.x {\n}\n# <<< other\n", "closes"),
    (KIOSK + KIOSK, "more than once"),
    ("# >>>kiosk\nkiosk.x {\n}\n# <<< kiosk\n", "looks like a marker"),
    ("# >>> kiosk\nkiosk.x {\n}\n#<<<\n", "looks like a marker"),
    ("# >>> kiosk\nkiosk.x {\n}\n# <<< kiosk trailing\n", "looks like a marker"),
], ids=["unclosed", "unopened", "nested", "wrong-end", "duplicate", "begin-typo", "end-typo", "end-trailing"])
def test_compose_refuses_broken_markers(live, why):
    with pytest.raises(cc.MarkerError, match=why):
        cc.compose(NEW, live)


def test_compose_refuses_a_marker_block_in_deploy_caddyfile():
    with pytest.raises(cc.MarkerError, match="deploy/Caddyfile"):
        cc.compose(NEW + "\n" + KIOSK, "")


def _cli(*args):
    return subprocess.run(["python3", str(COMPOSE), *map(str, args)], capture_output=True, text=True)


def test_compose_cli_writes_nothing_on_refusal(tmp_path):
    new, live, out = tmp_path / "new", tmp_path / "live", tmp_path / "out"
    new.write_text(NEW)
    live.write_text("# >>> kiosk\nkiosk.x {\n}\n")
    r = _cli(new, live, out)
    assert r.returncode == 1 and "never closed" in r.stderr
    assert not out.exists()
    live.write_text(KIOSK)
    r = _cli(new, live, out)
    assert r.returncode == 0 and "kiosk" in r.stdout
    assert out.read_text().endswith(KIOSK)


def test_compose_cli_keeps_the_bytes_of_carried_blocks(tmp_path):
    """Pentest finding 8: no newline translation - CRLF lines and a lone CR
    inside a token come out as they went in."""
    new, live, out = tmp_path / "new", tmp_path / "live", tmp_path / "out"
    new.write_text(NEW)
    block = b'# >>> crlf\r\nx.example {\r\n\trespond "a\rb"\r\n}\r\n# <<< crlf\r\n'
    live.write_bytes(block)
    assert _cli(new, live, out).returncode == 0
    assert out.read_bytes() == (NEW.rstrip("\n") + "\n\n").encode() + block


def test_compose_cli_reads_the_sites_dir(tmp_path):
    new, live, out, sites = tmp_path / "new", tmp_path / "live", tmp_path / "out", tmp_path / "sites.d"
    new.write_text(NEW)
    live.write_text(OLD_LIVE)
    sites.mkdir()
    (sites / "evil.caddy").write_text(f"x {{\n\tlog {{\n\t\thostnames {HOST}\n\t}}\n}}\n")
    r = _cli(new, live, out, sites)
    assert r.returncode == 1 and "sites.d/evil.caddy" in r.stderr and not out.exists()
    (sites / "evil.caddy").rename(sites / "evil.caddy.off")  # not imported, not checked
    assert _cli(new, live, out, sites).returncode == 0


# ---- the deploy script's Caddy step, run -------------------------------------

def _caddy_step(script: Path) -> str:
    src = script.read_text()
    start = src.index('echo "==> 4. Caddy')
    body = src.index("<<'REMOTE'\n", start) + len("<<'REMOTE'\n")
    return src[body:src.index("\nREMOTE\n", body) + 1]


def _exe(path: Path, text: str) -> None:
    path.write_text(text)
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


@pytest.fixture
def box(tmp_path):
    """A temporary /etc/caddy + the deploy's work dir, and fake tools:
      - `caddy validate` fails on a config containing BROKEN (or importing a
        sites.d file that does); with $W/race it changes the live file while
        validating the composed one (another service's deploy landing);
      - `systemctl reload` fails when $W/reload-fails exists, and with
        $W/reload-swaps it also replaces the live file first;
      - `caddy validate` of the installed file fails with $W/live-invalid;
      - `install` drops -o/-g (the test does not run as root) and, with
        $W/install-fails, half-writes a file and fails."""
    etc = tmp_path / "etc-caddy"
    etc.mkdir()
    w = tmp_path / "w"
    (w / "stage").mkdir(parents=True)
    (w / "stage" / "Caddyfile").write_text(NEW.replace("/etc/caddy", str(etc)))
    (w / "stage" / "caddy-compose.py").write_bytes(COMPOSE.read_bytes())
    bin_ = tmp_path / "bin"
    bin_.mkdir()
    _exe(bin_ / "caddy", f"""#!/bin/sh
cfg=$3
echo "$cfg" >> "{w}/validated"
case "$cfg" in
  *.composed) [ -e "{w}/race" ] && echo "# kiosk moved to 8200" >> "{etc}/Caddyfile" ;;
  */Caddyfile) [ -e "{w}/live-invalid" ] && {{ echo "Error: in place" >&2; exit 1; }} ;;
esac
if grep -q BROKEN "$cfg" || cat "{etc}"/sites.d/*.caddy 2>/dev/null | grep -q BROKEN; then
  echo "Error: adapting config: BROKEN" >&2; exit 1
fi
exit 0
""")
    _exe(bin_ / "systemctl", f"""#!/bin/sh
echo "$*" >> "{w}/systemctl"
case "$1" in
  reload) [ -e "{w}/reload-swaps" ] && echo "# someone else's" >> "{etc}/Caddyfile"
          [ ! -e "{w}/reload-fails" ] ;;
  is-active) [ "$2" = --quiet ] || echo active ;;
  *) exit 0 ;;
esac
""")
    _exe(bin_ / "install", f"""#!/bin/sh
for last; do :; done
args=""
dir=no
while [ $# -gt 0 ]; do
  case "$1" in -o|-g) shift 2 ;; -d) dir=yes; args="$args $1"; shift ;; *) args="$args $1"; shift ;; esac
done
if [ $dir = no ] && [ -e "{w}/install-fails" ]; then
  echo "half-writ" > "$last"   # a partial write, then the failure
  echo "install: No space left on device" >&2; exit 1
fi
exec /usr/bin/install $args
""")
    return etc, w, bin_


def validated(w):
    return (w / "validated").read_text().split()


def _run_step(script, etc, w, bin_):
    code = _caddy_step(script).replace("/etc/caddy", str(etc))
    assert str(etc) + "/Caddyfile" in code and str(etc) + "/sites.d" in code
    # The ownership check wants root; here the test user stands in for it.
    assert code.count("! -user root ") == 1
    code = code.replace("! -user root ", f"! -user {pwd.getpwuid(os.getuid()).pw_name} ")
    env = dict(os.environ, PATH=f"{bin_}:{os.environ['PATH']}", LC_ALL="C")
    return subprocess.run(["bash", "-s", "--", str(w)], input=code, env=env,
                          capture_output=True, text=True, timeout=60)


def _caddy_deploy_scripts() -> list[Path]:
    """Every non-historical deploy script that changes /etc/caddy (0.3.1's did
    not touch Caddy). The newest is the template for the next release."""
    scripts = [p for p in _deploy_scripts() if "/etc/caddy" in p.read_text()]
    assert _deploy_scripts()[-1] in scripts, "the template deploy script has no Caddy step"
    return scripts


@pytest.fixture(params=_caddy_deploy_scripts(), ids=lambda p: p.name)
def script(request):
    return request.param


def _unchanged(r, etc, w, before, why):
    assert r.returncode == 1 and why in r.stdout, r.stdout + r.stderr
    assert (etc / "Caddyfile").read_text() == before
    assert not (w / "systemctl").exists(), "no reload"


def test_step4_keeps_the_kiosk_block_and_creates_sites_d(script, box):
    etc, w, bin_ = box
    live = etc / "Caddyfile"
    live.write_text(OLD_LIVE)
    live.chmod(0o600)
    r = _run_step(script, etc, w, bin_)
    assert r.returncode == 0, r.stdout + r.stderr
    text = live.read_text()
    assert text.endswith(KIOSK), "the Kiosk block must survive the deploy"
    assert f"import {etc}/sites.d/*.caddy" in text
    assert stat.S_IMODE(live.stat().st_mode) == 0o644
    sites = etc / "sites.d"
    assert sites.is_dir() and list(sites.iterdir()) == []
    assert stat.S_IMODE(sites.stat().st_mode) == 0o755
    # Validated BEFORE it was installed, then again in place, then reloaded.
    assert validated(w) == [str(w / "Caddyfile.composed"), str(live)]
    assert "reload caddy" in (w / "systemctl").read_text()
    # A re-run changes nothing.
    r = _run_step(script, etc, w, bin_)
    assert r.returncode == 0 and "already the new one" in r.stdout
    assert live.read_text() == text


def test_step4_never_touches_an_existing_sites_d(script, box):
    etc, w, bin_ = box
    sites = etc / "sites.d"
    sites.mkdir(mode=0o750)
    (sites / "kiosk.caddy").write_text("kiosk.x {\n}\n")
    (sites / "kiosk.caddy").chmod(0o644)
    os.utime(sites / "kiosk.caddy", (1_000_000_000, 1_000_000_000))
    (etc / "Caddyfile").write_text(HOST + " {\n}\n")
    r = _run_step(script, etc, w, bin_)
    assert r.returncode == 0, r.stdout + r.stderr
    assert stat.S_IMODE(sites.stat().st_mode) == 0o750
    assert [p.name for p in sites.iterdir()] == ["kiosk.caddy"]
    assert (sites / "kiosk.caddy").read_text() == "kiosk.x {\n}\n"
    assert (sites / "kiosk.caddy").stat().st_mtime == 1_000_000_000
    assert "kiosk.caddy" in r.stdout, "step 4 lists what the other services have there"


@pytest.mark.parametrize("bad", ["dir-group-writable", "file-other-writable", "symlink"])
def test_step4_refuses_a_sites_d_that_is_not_roots_alone(script, box, bad):
    """Pentest finding 5: Caddy imports sites.d into the front end of
    secure-chat. Refused, not fixed (the directory is never touched)."""
    etc, w, bin_ = box
    sites = etc / "sites.d"
    sites.mkdir(mode=0o755)
    f = sites / "kiosk.caddy"
    if bad == "symlink":
        (etc / "elsewhere.caddy").write_text("kiosk.x {\n}\n")
        f.symlink_to(etc / "elsewhere.caddy")
    else:
        f.write_text("kiosk.x {\n}\n")
        f.chmod(0o646 if bad == "file-other-writable" else 0o644)
        if bad == "dir-group-writable":
            sites.chmod(0o775)
    before = OLD_LIVE
    (etc / "Caddyfile").write_text(before)
    r = _run_step(script, etc, w, bin_)
    _unchanged(r, etc, w, before, "not root's alone")
    assert stat.S_IMODE(sites.stat().st_mode) == (0o775 if bad == "dir-group-writable" else 0o755)


def test_step4_changes_nothing_on_broken_markers(script, box):
    etc, w, bin_ = box
    before = HOST + " {\n}\n# >>> kiosk\nkiosk.x {\n}\n"
    (etc / "Caddyfile").write_text(before)
    _unchanged(_run_step(script, etc, w, bin_), etc, w, before, "nothing changed")


def test_step4_changes_nothing_when_it_would_drop_an_unmarked_site(script, box):
    etc, w, bin_ = box
    before = HOST + " {\n}\n\nkiosk.x {\n\treverse_proxy 127.0.0.1:8100\n}\n"
    (etc / "Caddyfile").write_text(before)
    r = _run_step(script, etc, w, bin_)
    _unchanged(r, etc, w, before, "could not compose")
    assert "would be dropped" in r.stderr


def test_step4_refuses_a_sites_d_file_naming_our_host(script, box):
    etc, w, bin_ = box
    (etc / "sites.d").mkdir()
    (etc / "sites.d").chmod(0o755)
    f = etc / "sites.d" / "other.caddy"
    f.write_text(f"other.x {{\n\tlog {{\n\t\thostnames {HOST}\n\t}}\n}}\n")
    f.chmod(0o644)
    (etc / "Caddyfile").write_text(OLD_LIVE)
    r = _run_step(script, etc, w, bin_)
    _unchanged(r, etc, w, OLD_LIVE, "could not compose")
    assert "sites.d/other.caddy names our own site address" in r.stderr


def test_step4_validates_before_installing(script, box):
    """A sites.d file that breaks the config stops the deploy before the
    shared file is replaced (Caddy keeps running on the old one)."""
    etc, w, bin_ = box
    (etc / "sites.d").mkdir()
    (etc / "sites.d").chmod(0o755)
    (etc / "sites.d" / "other.caddy").write_text("BROKEN\n")
    (etc / "sites.d" / "other.caddy").chmod(0o644)
    (etc / "Caddyfile").write_text(OLD_LIVE)
    _unchanged(_run_step(script, etc, w, bin_), etc, w, OLD_LIVE, "does not validate; nothing changed")


def test_step4_does_not_undo_a_concurrent_change(script, box):
    """Pentest finding 3: another service's deploy replacing the file while
    step 4 runs must not be overwritten with what step 4 composed earlier."""
    etc, w, bin_ = box
    (etc / "Caddyfile").write_text(OLD_LIVE)
    (w / "race").touch()
    r = _run_step(script, etc, w, bin_)
    _unchanged(r, etc, w, OLD_LIVE + "# kiosk moved to 8200\n", "changed while this step ran")


def test_step4_backup_failure_changes_nothing(script, box):
    etc, w, bin_ = box
    (etc / "Caddyfile").write_text(OLD_LIVE)
    (w / "Caddyfile.before-step4").write_text("read-only leftover\n")
    (w / "Caddyfile.before-step4").chmod(0o444)
    _unchanged(_run_step(script, etc, w, bin_), etc, w, OLD_LIVE, "could not back up")


def test_step4_install_failure_is_not_reported_as_live(script, box):
    """Pentest finding 6: a failed install used to fall through to "new
    Caddyfile live"."""
    etc, w, bin_ = box
    (etc / "Caddyfile").write_text(OLD_LIVE)
    (w / "install-fails").touch()
    r = _run_step(script, etc, w, bin_)
    _unchanged(r, etc, w, OLD_LIVE, "could not install")
    assert "new Caddyfile live" not in r.stdout


def test_step4_restores_the_file_as_it_was_on_a_failed_reload(script, box):
    etc, w, bin_ = box
    (etc / "Caddyfile").write_text(OLD_LIVE)
    (w / "Caddyfile").write_text("the 0b backup, older than the live file\n")
    (w / "reload-fails").touch()
    r = _run_step(script, etc, w, bin_)
    assert r.returncode == 1 and "restoring" in r.stdout
    assert (etc / "Caddyfile").read_text() == OLD_LIVE
    # Reload first (keeps the other sites up), restart only if that fails;
    # never a stop.
    calls = [c for c in (w / "systemctl").read_text().splitlines() if not c.startswith("is-active")]
    assert calls == ["reload caddy", "reload caddy"], calls  # never a restart (all sites down if it fails)
    assert validated(w) == [str(w / "Caddyfile.composed"), str(etc / "Caddyfile"), str(etc / "Caddyfile")]


def test_step4_does_not_reload_a_restored_file_that_does_not_validate(script, box):
    """Pentest round 2, finding 3: the restored file imports sites.d, so it
    is not known-good by itself; if it does not validate, Caddy is left on
    its last good config instead of being reloaded or restarted onto it."""
    etc, w, bin_ = box
    (etc / "Caddyfile").write_text(OLD_LIVE)
    (w / "live-invalid").touch()
    r = _run_step(script, etc, w, bin_)
    assert r.returncode == 1 and "does not load either" in r.stdout, r.stdout
    assert (etc / "Caddyfile").read_text() == OLD_LIVE
    assert not (w / "systemctl").exists(), "neither reload nor restart"


def test_step4_leaves_someone_elses_newer_file_on_a_failed_reload(script, box):
    etc, w, bin_ = box
    (etc / "Caddyfile").write_text(OLD_LIVE)
    (w / "reload-fails").touch()
    (w / "reload-swaps").touch()
    r = _run_step(script, etc, w, bin_)
    assert r.returncode == 1 and "left as it is" in r.stdout
    assert (etc / "Caddyfile").read_text().endswith("# someone else's\n")


def _verify_caddy(script: Path) -> str:
    """Step 5's Caddy checks, verbatim, with its `want` helper."""
    src = script.read_text()
    start = src.index('want "Caddyfile = the one step 4 composed"')
    last = src.index('want "/etc/caddy/sites.d"', start)
    end = src.index("\n", last) + 1
    helper = src[src.index("want() {"):]
    helper = helper[:helper.index("\n}\n") + 3]
    return "W=$1\nFAILS=0\n" + helper + src[start:end] + 'echo "FAILS=$FAILS"\n'


@pytest.mark.parametrize("tamper", [None, "ours", "theirs", "dropped"])
def test_step5_checks_the_caddyfile_it_should(script, box, tamper):
    """Pentest finding 4: step 5 must see a live file that is not
    deploy/Caddyfile + the same marker blocks byte for byte - not just the
    same block names."""
    etc, w, bin_ = box
    live = etc / "Caddyfile"
    live.write_text(OLD_LIVE)
    assert _run_step(script, etc, w, bin_).returncode == 0
    text = live.read_text()
    if tamper == "ours":
        text = text.replace("output discard", "output stderr", 1)
    elif tamper == "theirs":
        text = text.replace("127.0.0.1:8100", "127.0.0.1:8200")
    elif tamper == "dropped":
        text = text[:text.index("# >>> kiosk")]
    live.write_text(text)
    code = _verify_caddy(script).replace("/etc/caddy", str(etc))
    r = subprocess.run(["bash", "-s", "--", str(w)], input=code, capture_output=True, text=True,
                       env=dict(os.environ, LC_ALL="C"), timeout=60)
    assert r.returncode == 0, r.stderr
    fails = [l.split(":")[0].strip() for l in r.stdout.splitlines() if l.strip().startswith("FAIL ")]
    want = {
        None: [],
        "ours": ["FAIL  Caddyfile = the one step 4 composed", "FAIL  Caddyfile begins with deploy/Caddyfile"],
        "theirs": ["FAIL  Caddyfile = the one step 4 composed", "FAIL  other services' marker blocks kept"],
        "dropped": ["FAIL  Caddyfile = the one step 4 composed", "FAIL  other services' marker blocks kept"],
    }[tamper]
    assert fails == want, r.stdout
    assert f"FAILS={len(want)}" in r.stdout
