"""Checks for the iOS release tooling, run by the Linux gate in ios.yml.

  python3 ios/scripts/test_dist.py
"""
import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ICON = ROOT / "ios/SecureChat/Assets.xcassets/AppIcon.appiconset/icon-1024.png"
fails = []


def check(name, ok, detail=""):
    print(("OK   " if ok else "FAIL ") + name + (f" — {detail}" if detail else ""))
    if not ok:
        fails.append(name)


def run(*args, out):
    return subprocess.run(
        [sys.executable, str(ROOT / "ios/scripts/make-dist.py"), *args, "--icon", str(ICON), "--out", str(out)],
        capture_output=True, text=True)


# 1. The workflow still runs on branch pushes (pentest dist-1 F1: adding
#    `tags` without `branches` silently turned branch runs off). Run from
#    backend.yml too, since a broken trigger stops ios.yml from running.
try:
    import yaml  # type: ignore
    wf = yaml.safe_load((ROOT / ".github/workflows/ios.yml").read_text())
    push = (wf.get("on") or wf.get(True))["push"]
    # Exactly all branches: `branches: [main]` would silently stop runs on
    # feature branches, `branches: []` on every branch.
    check("ios.yml runs on every branch push", push.get("branches") == ["**"], str(push.get("branches")))
    check("ios.yml runs on ios-v* tags", "ios-v*" in (push.get("tags") or []))
except ImportError:
    check("pyyaml available for the trigger lint", False)

with tempfile.TemporaryDirectory() as d:
    d = Path(d)
    ipa = d / "in.ipa"
    ipa.write_bytes(b"not really an ipa")
    out = d / "dist"
    r = run("--ipa", str(ipa), "--version", "1.2.3", "--build", "7",
            "--base-url", "https://relay.example/ios", "--date", "2026-01-02", out=out)
    check("valid input builds a bundle", r.returncode == 0, r.stderr.strip())
    if r.returncode == 0:
        digest = hashlib.sha256(ipa.read_bytes()).hexdigest()
        src = json.loads((out / "apps.json").read_text())
        v = src["apps"][0]["versions"][0]
        check("sha256 field matches the IPA", v["sha256"] == digest)
        check("checksum file matches", (out / "SecureChat-1.2.3.ipa.sha256").read_text() == f"{digest}  SecureChat-1.2.3.ipa\n")
        check("download URL", v["downloadURL"] == "https://relay.example/ios/SecureChat-1.2.3.ipa")
        check("no hash in the description text (F2)", digest not in v["localizedDescription"])
        check("bundle id", src["apps"][0]["bundleIdentifier"] == "org.securechat.app")
    for label, args in [
        ("non-ASCII version", ["--version", "١.٢.٣", "--build", "1"]),
        ("version with junk", ["--version", "1.2.3;x", "--build", "1"]),
        ("bad build", ["--version", "1.2.3", "--build", "1a"]),
        ("http base URL", ["--version", "1.2.3", "--build", "1", "--base-url", "http://a.b/ios"]),
        ("quote in base URL", ["--version", "1.2.3", "--build", "1", "--base-url", 'https://a.b/"x']),
        ("dot-dot path", ["--version", "1.2.3", "--build", "1", "--base-url", "https://a.b/.."]),
        ("bad host", ["--version", "1.2.3", "--build", "1", "--base-url", "https://-a..b/ios"]),
        ("bad date", ["--version", "1.2.3", "--build", "1", "--date", "x"]),
        ("impossible date", ["--version", "1.2.3", "--build", "1", "--date", "9999-99-99"]),
    ]:
        args = list(args)
        if "--base-url" not in args:
            args += ["--base-url", "https://a.b/ios"]
        r = run("--ipa", str(ipa), *args, out=d / "bad")
        check(f"rejects {label}", r.returncode != 0)

print(f"{len(fails)} failed" if fails else "all good")
sys.exit(1 if fails else 0)
