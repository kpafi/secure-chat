"""Build the SideStore / AltStore download bundle for one iOS release.

    python3 ios/scripts/make-dist.py --ipa SecureChat-unsigned.ipa \
        --version 0.3.0 --build 3 --base-url https://relay.example/ios \
        --icon ios/SecureChat/Assets.xcassets/AppIcon.appiconset/icon-1024.png \
        --out dist

Writes into --out:
  SecureChat-<version>.ipa          the unsigned IPA (each user signs it with
                                    their own Apple ID in SideStore/AltStore)
  SecureChat-<version>.ipa.sha256   its checksum, `sha256sum -c` format
  apps.json                         the source users add in SideStore/AltStore
  icon.png                          the icon the source points at

The bundle is meant to be served by the relay's own web server under /ios/
(deploy/Caddyfile, deploy/README.md). The repository is private, so GitHub
release assets are not publicly downloadable — the self-hosted server is the
distribution point.

apps.json follows the AltStore source format, which SideStore also reads.
"""
import argparse
import datetime as dt
import hashlib
import json
import re
import shutil
import sys
from pathlib import Path

BUNDLE_ID = "org.securechat.app"
MIN_OS = "17.0"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--ipa", required=True, type=Path)
    ap.add_argument("--version", required=True)
    ap.add_argument("--build", required=True)
    ap.add_argument("--base-url", required=True)
    ap.add_argument("--icon", required=True, type=Path)
    ap.add_argument("--out", required=True, type=Path)
    ap.add_argument("--date", default=dt.date.today().isoformat())
    a = ap.parse_args()

    try:
        if not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", a.date):
            raise ValueError
        dt.date.fromisoformat(a.date)
    except ValueError:
        sys.exit(f"date must be YYYY-MM-DD, got {a.date!r}")
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", a.version):
        sys.exit(f"version must be X.Y.Z, got {a.version!r}")
    if not re.fullmatch(r"[0-9]+", a.build):
        sys.exit(f"build must be an integer, got {a.build!r}")
    # The URL lands in a JSON file users' devices fetch; keep it a plain https
    # origin + path so nothing odd can ride along.
    base = a.base_url.rstrip("/")
    if not re.fullmatch(r"https://[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)*"
                        r"(:[0-9]{1,5})?(/[A-Za-z0-9_~-][A-Za-z0-9._~-]*)*", base) or "/.." in base:
        sys.exit(f"base URL must be https://host[/path], got {a.base_url!r}")

    a.out.mkdir(parents=True, exist_ok=True)
    ipa_name = f"SecureChat-{a.version}.ipa"
    ipa_out = a.out / ipa_name
    shutil.copyfile(a.ipa, ipa_out)
    data = ipa_out.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    (a.out / f"{ipa_name}.sha256").write_text(f"{digest}  {ipa_name}\n")
    shutil.copyfile(a.icon, a.out / "icon.png")

    # No hash in the description (pentest dist-1 F2): SideStore shows this
    # free text, but verifies the separate `sha256` field — a hostile server
    # could print the genuine hash here and serve a different file. Users
    # verify by hashing the downloaded .ipa themselves (ios/README.md).
    notes = (
        "Unsigned build: SideStore/AltStore signs it with your own Apple ID. "
        "To verify it, hash the downloaded .ipa yourself and compare with the "
        "value the operator sent you through another channel."
    )
    source = {
        "name": "secure-chat",
        "identifier": "org.securechat.source",
        "subtitle": "End-to-end encrypted chat, self-hosted.",
        "description": (
            "The secure-chat iOS app. The client code ships inside the app, so this "
            "server cannot change it on the next page load — only a new version you "
            "choose to install can."
        ),
        "iconURL": f"{base}/icon.png",
        "tintColor": "2F81F7",
        "apps": [
            {
                "name": "secure-chat",
                "bundleIdentifier": BUNDLE_ID,
                "developerName": "secure-chat",
                "subtitle": "End-to-end encrypted chat.",
                "localizedDescription": (
                    "End-to-end encrypted chat. Enter your relay address on first "
                    "start; the relay only ever sees ciphertext."
                ),
                "iconURL": f"{base}/icon.png",
                "tintColor": "2F81F7",
                "category": "social",
                "versions": [
                    {
                        "version": a.version,
                        "buildVersion": a.build,
                        "date": a.date,
                        "localizedDescription": notes,
                        "downloadURL": f"{base}/{ipa_name}",
                        "size": len(data),
                        "sha256": digest,
                        "minOSVersion": MIN_OS,
                    }
                ],
                "appPermissions": {"entitlements": [], "privacy": {}},
            }
        ],
        "news": [],
    }
    (a.out / "apps.json").write_text(json.dumps(source, indent=2) + "\n")
    print(f"{ipa_name} {len(data)} bytes sha256 {digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
