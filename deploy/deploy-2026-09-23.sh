#!/usr/bin/env bash
# Deploy of release 0.2.0 — the design rework (merge of
# claude/secure-chat-design-rework-rxd4uz): client/index.html, client/style.css
# and client/app.js changed; the relay changed only its reported VERSION.
#
# The wire format, the accounts DB and the systemd unit are untouched, so this
# release is NOT coupled to the APK the way 2026-09-21 was: an old APK keeps
# working against the new relay (it just shows the old design until rebuilt).
# Order therefore does not matter; deploy the relay first, build the APK when
# convenient (see deploy/release-2026-09-23.md).
#
# Run from the repo root, on master:  bash deploy/deploy-2026-09-23.sh
set -euo pipefail

BOX=root@138.199.144.35
STAMP=$(date +%Y-%m-%d-%H%M)

test -f client/nativefloor.js || { echo "run from the repo root, on master"; exit 1; }
grep -q 'id="tabbar"' client/index.html || { echo "this checkout is not the 0.2.0 client (no tab bar)"; exit 1; }
grep -q 'VERSION = "0.2.0"' backend/config.py || { echo "backend/config.py is not 0.2.0"; exit 1; }

echo "==> 0. backup, with the service STOPPED so the WAL is checkpointed first"
ssh "$BOX" "systemctl stop secure-chat \
  && cp -a /var/lib/secure-chat/accounts.db /root/accounts.db.bak-$STAMP \
  && ls -la /root/accounts.db.bak-$STAMP \
  && python3 -c \"import sqlite3;print('    accounts before:',sqlite3.connect('file:/var/lib/secure-chat/accounts.db?mode=ro',uri=True).execute('select count(*) from accounts').fetchone()[0])\""

echo "==> 1. code (NEVER without the accounts.db excludes)"
rsync -az --itemize-changes \
  --exclude node_modules --exclude 'package*.json' --exclude '*.test.mjs' \
  --exclude __pycache__ --exclude '.venv' --exclude '.pytest_cache' \
  --exclude 'accounts.db*' --exclude '*.db' --exclude '*.db-shm' --exclude '*.db-wal' \
  --exclude 'tests' \
  backend client "$BOX":/opt/secure-chat/

echo "==> 2. restart"
ssh "$BOX" 'chown -R securechat:securechat /opt/secure-chat/backend \
  && systemctl start secure-chat \
  && sleep 2 \
  && systemctl is-active secure-chat'

echo "==> 3. verify over loopback ON the box"
ssh "$BOX" 'curl -s http://127.0.0.1:8000/healthz | sed "s/^/    healthz: /" \
  && curl -s http://127.0.0.1:8000/healthz | grep -q "\"version\":\"0.2.0\"" \
  && curl -s -o /dev/null -w "index=%{http_code}\n" http://127.0.0.1:8000/ \
  && echo "--- the served client must be the 0.2.0 one:" \
  && curl -s http://127.0.0.1:8000/ | grep -c "id=\"tabbar\"" | sed "s/^/    index.html tab bar (want 1): /" \
  && curl -s http://127.0.0.1:8000/app.js | grep -c "armAdmitGuard" | sed "s/^/    app.js admission guard lines (want >0): /" \
  && curl -s http://127.0.0.1:8000/style.css | grep -c "accent-fill" | sed "s/^/    style.css accent-fill lines (want >0): /" \
  && echo "--- the import map hash the CSP pins must still match (a 200 with the same importmap line):" \
  && curl -s http://127.0.0.1:8000/ | grep -c "type=\"importmap\"" | sed "s/^/    importmap lines (want 1): /" \
  && echo "--- accounts after (must equal before):" \
  && python3 -c "import sqlite3;print(\"    \",sqlite3.connect(\"file:/var/lib/secure-chat/accounts.db?mode=ro\",uri=True).execute(\"select count(*) from accounts\").fetchone()[0])" \
  && echo "--- process environment: TRUSTED_PROXIES must be absent, --no-proxy-headers present" \
  && (tr "\0" "\n" < /proc/$(systemctl show -p MainPID --value secure-chat)/environ | grep -c SECURE_CHAT_TRUSTED_PROXIES || true) | sed "s/^/    TRUSTED_PROXIES vars (want 0): /" \
  && tr "\0" " " < /proc/$(systemctl show -p MainPID --value secure-chat)/cmdline | grep -o -- "--no-proxy-headers"'

echo
echo "==> 4. open https://<your host>/ in a fresh browser tab (Cache-Control is"
echo "        no-cache, so a reload is enough): the bottom tab bar on a phone, the"
echo "        top bar with tabs on a desktop. Then rebuild the APK when convenient."
echo
