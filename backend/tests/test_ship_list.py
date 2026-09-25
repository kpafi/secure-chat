"""One ship list for the web client (Phase-7 pentest F-P7-18).

The same client/ tree leaves this repository through four channels, and each
used to carry its own idea of which files are development-only:

  relay     backend/main.py `_is_blocked_static` 404s them on the static mount
  deploy    the per-release deploy script's rsync to the box
  Android   android/app/build.gradle.kts `syncWebClient` into the APK assets
  iOS       ios/scripts/sync-web.sh into the app bundle

They disagreed. `client/vendor/README.md` was served, rsynced and bundled in
both apps; the Gradle excludes were Ant ROOT-only patterns, so
`vendor/lean-qr/package.json` shipped in the APK although the relay 404s it.

Now `deploy/ship-excludes.txt` is the list. The deploy script, Gradle and
sync-web.sh read it; the relay cannot (deploy/ is not on the box), so it keeps
the same patterns in `main._DEV_ONLY_PATTERNS` and this test holds them equal.
Semantics everywhere are rsync's for a pattern without a slash: it matches ANY
path component, and excluding a directory excludes everything under it.

The deploy-time rsync and sync-web.sh are RUN here (into a temp dir), not
string-matched; Gradle cannot run inside pytest, so its task is checked for the
exact `**/<p>` + `**/<p>/**` translation that gives Ant the same semantics, and
the APK itself is checked by hand at release (`unzip -l`, see deploy/README.md).
"""
import fnmatch
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

os.environ.setdefault("SECURE_CHAT_DB", os.path.join(tempfile.mkdtemp(), "ship.db"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest  # noqa: E402
from fastapi.staticfiles import StaticFiles  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

import main  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
CLIENT = ROOT / "client"
SHIP_LIST = ROOT / "deploy" / "ship-excludes.txt"
BOX_LIST = ROOT / "deploy" / "rsync-excludes.txt"
GRADLE = ROOT / "android" / "app" / "build.gradle.kts"
SYNC_WEB = ROOT / "ios" / "scripts" / "sync-web.sh"

# Deploy scripts that already RAN before the shared list existed. They are
# records of what was done and stay as they were; every newer script (copied
# from the newest one, as each release does) must use the shared lists.
_HISTORICAL_DEPLOY_SCRIPTS = {
    "deploy-2026-07-30.sh",
    "deploy-2026-09-21.sh",
    "deploy-2026-09-23.sh",
    "deploy-2026-09-24.sh",
}


def _patterns(path: Path) -> list[str]:
    """An rsync --exclude-from file: '#'/';' comments and blank lines skipped."""
    out = []
    for line in path.read_text().splitlines():
        s = line.strip()
        if s and not s.startswith(("#", ";")):
            out.append(s)
    return out


def _files(root: Path) -> set[str]:
    """Every regular file under root, relative, WITHOUT following symlinks (a
    dev checkout may have client/node_modules as a symlink)."""
    out = set()
    for dirpath, _dirs, names in os.walk(root, followlinks=False):
        for n in names:
            p = Path(dirpath, n)
            if p.is_file() and not p.is_symlink():
                out.add(p.relative_to(root).as_posix())
    return out


def _dev_only(rel: str, patterns) -> bool:
    return any(fnmatch.fnmatchcase(seg, p) for seg in rel.split("/") for p in patterns)


@pytest.fixture(scope="module")
def ship_patterns() -> list[str]:
    pats = _patterns(SHIP_LIST)
    assert pats, f"{SHIP_LIST} is empty"
    assert len(pats) == len(set(pats)), f"duplicate patterns: {pats}"
    assert all("/" not in p for p in pats), (
        "a pattern with a slash is anchored in rsync but not after Gradle's **/ "
        f"prefix; keep them component patterns: {pats}")
    return pats


@pytest.fixture(scope="module")
def shipped_by_relay() -> set[str]:
    return {f for f in _files(CLIENT) if not main._is_blocked_static("/" + f)}


def _deploy_scripts() -> list[Path]:
    return sorted(p for p in (ROOT / "deploy").glob("deploy-*.sh")
                  if p.name not in _HISTORICAL_DEPLOY_SCRIPTS)


def test_the_list_covers_the_known_dev_files(ship_patterns):
    """What the finding named, and what the relay already refused before."""
    for dev in ("vendor/README.md", "README.md", "vendor/lean-qr/package.json",
                "package.json", "package-lock.json", "crypto.test.mjs",
                "accounts.integration.test.mjs", "node_modules/x/index.js",
                ".env", ".git/config", "vendor/.cache/x.js"):
        assert _dev_only(dev, ship_patterns), f"{dev} is not excluded by {SHIP_LIST.name}"


def test_relay_blocks_exactly_the_ship_list(ship_patterns):
    assert sorted(main._DEV_ONLY_PATTERNS) == sorted(ship_patterns), (
        "backend/main.py and deploy/ship-excludes.txt disagree")


def test_every_blocked_pattern_really_404s_on_the_relay(ship_patterns, tmp_path, monkeypatch):
    """Not a string check: a client tree with one real file per pattern, at the
    root and nested (and inside a matching directory), is mounted in place of
    client/, and each is fetched. The positive controls in the same tree must
    come back 200, or the 404s would prove nothing."""
    def sample(p: str) -> str:
        return p.replace("*", "x")

    blocked, served = [], ["index.html", "vendor/lib/ok.js", "icons/i.png",
                           "manifest.webmanifest", "vendor/lean-qr/LICENSE"]
    for p in ship_patterns:
        name = sample(p)
        # (a file and a directory cannot share a path, hence dirs/ for the latter)
        blocked += [name, f"vendor/deep/{name}", f"dirs/{name}/inside.js", f"vendor/d/{name}/inside.js"]
    for rel in blocked + served:
        f = tmp_path / rel
        f.parent.mkdir(parents=True, exist_ok=True)
        if not f.exists():
            f.write_text("x")
    mount = next(r for r in main.app.routes if getattr(r, "name", None) == "client")
    static = StaticFiles(directory=str(tmp_path), html=True)
    monkeypatch.setattr(mount, "app", static)
    monkeypatch.setattr(mount, "_base_app", static)
    client = TestClient(main.app)
    for rel in served:
        assert client.get("/" + rel).status_code == 200, f"control {rel} not served"
    for rel in blocked:
        r = client.get("/" + rel)
        assert r.status_code == 404, f"/{rel} -> {r.status_code}"
        assert r.content == b"", f"/{rel} returned content"


def test_gradle_sync_applies_the_ship_list_at_any_depth():
    src = GRADLE.read_text()
    m = re.search(r'val syncWebClient = tasks\.register<Sync>\("syncWebClient"\) \{(.*?)\n\}\n', src, re.S)
    assert m, "syncWebClient task not found in build.gradle.kts"
    task = m.group(1)
    # Reads the one list...
    assert re.search(r'val shipExcludesFile = rootProject\.file\("\.\./deploy/ship-excludes\.txt"\)\n'
                     r'val shipExcludes = shipExcludesFile\.readLines\(\)', src), (
        "build.gradle.kts must read deploy/ship-excludes.txt")
    assert "inputs.file(shipExcludesFile)" in task, "editing the list must invalidate the Sync task"
    # ...and applies every entry as both **/<p> and **/<p>/**: Ant's plain
    # "<p>" only matches at the ROOT of the copy (the F-P7-18 APK leak).
    assert re.search(r'shipExcludes\.forEach \{ exclude\("\*\*/\$it", "\*\*/\$it/\*\*"\) \}', task), task
    # No second, hand-kept list beside it.
    assert task.count("exclude(") == 1, task
    # The same comment/blank rules as rsync's --exclude-from.
    assert re.search(r'!it\.startsWith\("#"\)', src) and re.search(r'!it\.startsWith\(";"\)', src)


def _run_sync_web(dest_root: Path) -> set[str]:
    """Run the real build phase into a fake bundle. The bundle is pre-seeded
    with dev files and a stale module, as an incremental Xcode build directory
    from an older build would be: a mirror must remove all of them."""
    web = dest_root / "App.app" / "web"
    for stale in ("vendor/README.md", "vendor/lean-qr/package.json", "gone.js"):
        (web / stale).parent.mkdir(parents=True, exist_ok=True)
        (web / stale).write_text("stale")
    env = dict(os.environ, SRCROOT=str(ROOT / "ios"), TARGET_BUILD_DIR=str(dest_root),
               UNLOCALIZED_RESOURCES_FOLDER_PATH="App.app")
    subprocess.run(["sh", str(SYNC_WEB)], env=env, check=True, capture_output=True, text=True)
    return _files(web)


def _rsync_like_the_deploy(dest: Path) -> set[str]:
    subprocess.run(["rsync", "-a", "--exclude-from", str(SHIP_LIST), "--exclude-from", str(BOX_LIST),
                    str(CLIENT), str(dest)], check=True, capture_output=True, text=True)
    return _files(dest / "client")


def test_the_four_channels_ship_the_same_client(ship_patterns, shipped_by_relay, tmp_path):
    assert shutil.which("rsync"), "rsync is needed to run the deploy and iOS copies"
    ios = _run_sync_web(tmp_path / "ios")
    deploy = _rsync_like_the_deploy(tmp_path / "box")
    expected = {f for f in _files(CLIENT) if not _dev_only(f, ship_patterns)}
    assert shipped_by_relay == expected, sorted(shipped_by_relay ^ expected)
    assert ios == expected, sorted(ios ^ expected)
    assert deploy == expected, sorted(deploy ^ expected)
    # Sanity on the result itself.
    assert "index.html" in expected and "app.js" in expected
    for f in expected:
        base = f.rsplit("/", 1)[-1]
        assert base != "README.md" and not fnmatch.fnmatchcase(base, "package*.json"), f
        assert not base.endswith(".test.mjs") and "node_modules" not in f.split("/"), f
    # The Home Screen web app needs these; they ship everywhere (index.html
    # links both, so leaving them out of the apps would only add 404s).
    assert "manifest.webmanifest" in expected
    icons = {f for f in _files(CLIENT) if f.startswith("icons/")}
    assert icons and icons <= expected, icons - expected


def test_sync_web_reads_the_one_list():
    src = SYNC_WEB.read_text()
    rsync = src[src.index("rsync "):]
    assert '--exclude-from "${SRCROOT}/../deploy/ship-excludes.txt"' in rsync
    assert "--exclude " not in rsync and "--exclude=" not in rsync, "a second, hand-kept list"


def test_deploy_scripts_use_the_shared_lists():
    """Every non-historical deploy script (future ones are copies of the newest)
    rsyncs with both shared lists and no inline --exclude beside them."""
    scripts = _deploy_scripts()
    assert scripts, "no current deploy script: the newest one is the template"
    for script in scripts:
        src = script.read_text()
        rsyncs = re.findall(r"^rsync .*?(?<!\\)\n", src, re.S | re.M)
        assert rsyncs, f"{script.name}: no rsync"
        for cmd in rsyncs:
            assert "--exclude-from deploy/ship-excludes.txt" in cmd, (script.name, cmd)
            assert "--exclude-from deploy/rsync-excludes.txt" in cmd, (script.name, cmd)
            assert not re.search(r"--exclude[ =]", cmd), (script.name, "inline --exclude", cmd)


def test_deploy_scripts_leave_the_code_root_owned():
    """Package 5: deploys up to 0.3.1 ran `chown -R securechat:securechat
    /opt/secure-chat/backend`, so the service user owned its own source. The
    relay writes only its DB under StateDirectory (systemd owns that for it),
    so the code is root:root 0755/0644, set AFTER the rsync (rsync -a as root
    carries the dev box's uid over) and BEFORE the service starts."""
    for script in _deploy_scripts():
        src = script.read_text()
        assert not re.search(r"chown\b[^\n]*securechat", src), (
            f"{script.name} hands something to the service user")
        chown = "chown -R root:root /opt/secure-chat/backend /opt/secure-chat/client"
        chmod = "chmod -R u=rwX,go=rX /opt/secure-chat/backend /opt/secure-chat/client"
        audit = "find /opt/secure-chat -user securechat"
        for need in (chown, chmod, audit):
            assert need in src, f"{script.name} lost {need!r}"
        rsync_at = src.index("\nrsync ")
        start_at = src.index("systemctl start secure-chat")
        assert rsync_at < src.index(chown) < start_at, f"{script.name}: chown must sit between rsync and start"
        assert rsync_at < src.index(chmod) < start_at, f"{script.name}: chmod must sit between rsync and start"


def test_box_only_excludes_keep_the_database_out():
    """rsync-excludes.txt is what the ship list does not cover: the relay's own
    state and caches. The accounts.db lines are the ones that must never go."""
    pats = _patterns(BOX_LIST)
    for need in ("accounts.db*", "*.db", "*.db-wal", "*.db-shm", "__pycache__", ".venv", "tests"):
        assert need in pats, f"{BOX_LIST.name} lost {need!r}"
