#!/bin/sh
# Copy the audited web client into the app bundle at build time — the iOS twin
# of the Android `syncWebClient` Gradle task. Single source of truth: ../client.
# `--delete` mirrors the source exactly, so a module deleted or renamed there
# can never keep shipping inside the app (Android pentest 2026-07-26 L-11).
# What is NOT copied is deploy/ship-excludes.txt, the one ship list the relay,
# the deploy rsync and the APK also use (Phase-7 pentest F-P7-18: vendor/README.md
# used to ship here; backend/tests/test_ship_list.py runs this script).
set -eu
SRC="${SRCROOT}/../client/"
EXCLUDES="${SRCROOT}/../deploy/ship-excludes.txt"
DEST="${TARGET_BUILD_DIR}/${UNLOCALIZED_RESOURCES_FOLDER_PATH}/web/"
[ -f "${SRC}index.html" ] || { echo "error: ${SRC}index.html not found" >&2; exit 1; }
[ -f "$EXCLUDES" ] || { echo "error: $EXCLUDES not found" >&2; exit 1; }
mkdir -p "$DEST"
# --delete-excluded: plain --delete PROTECTS excluded names already in the
# destination, so a README.md an older build copied into an incremental
# build directory would stay in the bundle for good.
rsync -a --delete --delete-excluded \
  --exclude-from "${SRCROOT}/../deploy/ship-excludes.txt" \
  "$SRC" "$DEST"
