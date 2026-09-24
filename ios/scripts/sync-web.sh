#!/bin/sh
# Copy the audited web client into the app bundle at build time — the iOS twin
# of the Android `syncWebClient` Gradle task. Single source of truth: ../client.
# `--delete` mirrors the source exactly, so a module deleted or renamed there
# can never keep shipping inside the app (Android pentest 2026-07-26 L-11).
set -eu
SRC="${SRCROOT}/../client/"
DEST="${TARGET_BUILD_DIR}/${UNLOCALIZED_RESOURCES_FOLDER_PATH}/web/"
[ -f "${SRC}index.html" ] || { echo "error: ${SRC}index.html not found" >&2; exit 1; }
mkdir -p "$DEST"
rsync -a --delete \
  --exclude '*.test.mjs' --exclude 'package.json' --exclude 'package-lock.json' \
  --exclude 'node_modules' --exclude '.*' \
  "$SRC" "$DEST"
