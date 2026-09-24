#!/usr/bin/env bash
# Deploy of release 0.3.1: everything on master since 0.3.0.
#   - relay: the iOS app's origin (secure-chat://app) on the WS allow-list and
#     in CORS (PR #2); CSP gains manifest-src 'self' and worker-src 'none', and
#     .webmanifest is served as application/manifest+json (PR #3, Home Screen
#     web app); VERSION 0.3.1.
#   - client: manifest + icons (Home Screen web app), safe-area padding,
#     formatDetail (an error never shows '[object Object]'), the centred lone
#     Remove / Unverify in the contact profile.
#
# The wire format, the accounts DB and the systemd unit are untouched; an old
# APK keeps working against this relay. The Caddyfile's /ios/ block is NOT
# part of this deploy (see deploy/README.md, "iOS app downloads").
#
# Run from the repo root, on a checkout of v0.3.1:
#   bash deploy/deploy-2026-09-24-v0.3.1.sh
set -euo pipefail

BOX=root@138.199.144.35
STAMP=$(date +%Y-%m-%d-%H%M)

test -f client/nativefloor.js || { echo "run from the repo root"; exit 1; }
grep -q 'VERSION = "0.3.1"' backend/config.py || { echo "backend/config.py is not 0.3.1"; exit 1; }
grep -q 'IOS_WEBVIEW_ORIGIN = "secure-chat://app"' backend/config.py || { echo "no iOS origin in config.py"; exit 1; }
grep -q 'export function formatDetail' client/account.js || { echo "client/account.js has no formatDetail"; exit 1; }
grep -q '\.contact-remove-row { display: flex; justify-content: center' client/style.css || { echo "style.css is not the round-7 one"; exit 1; }
test -f client/manifest.webmanifest || { echo "no client/manifest.webmanifest"; exit 1; }

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
  && curl -s http://127.0.0.1:8000/healthz | grep -q "\"version\":\"0.3.1\"" \
  && curl -s -o /dev/null -w "    index=%{http_code}\n" http://127.0.0.1:8000/ \
  && echo "--- the served client must be the 0.3.1 one:" \
  && curl -s http://127.0.0.1:8000/ | grep -c "id=\"contactSheet\"" | sed "s/^/    index.html contact sheet (want 1): /" \
  && curl -s http://127.0.0.1:8000/ | grep -c "manifest.webmanifest" | sed "s/^/    index.html manifest link (want 1): /" \
  && curl -s http://127.0.0.1:8000/account.js | grep -c "export function formatDetail" | sed "s/^/    account.js formatDetail (want 1): /" \
  && curl -s http://127.0.0.1:8000/style.css | grep -c "contact-remove-row { display: flex; justify-content: center" | sed "s/^/    style.css centred remove row (want 1): /" \
  && curl -s -o /dev/null -w "    manifest: %{http_code} %{content_type}\n" http://127.0.0.1:8000/manifest.webmanifest \
  && curl -s -D - -o /dev/null http://127.0.0.1:8000/ | grep -io "worker-src [^;]*" | sed "s/^/    CSP (want worker-src '\''none'\''): /" \
  && curl -s -o /dev/null -w "    CORS preflight from the iOS origin (want 200): %{http_code}\n" -X OPTIONS -H "Origin: secure-chat://app" -H "Access-Control-Request-Method: POST" http://127.0.0.1:8000/api/auth/challenge \
  && curl -s -o /dev/null -w "    CORS preflight from a foreign origin (want 400): %{http_code}\n" -X OPTIONS -H "Origin: https://evil.example" -H "Access-Control-Request-Method: POST" http://127.0.0.1:8000/api/auth/challenge \
  && curl -s http://127.0.0.1:8000/ | grep -c "type=\"importmap\"" | sed "s/^/    importmap lines (want 1): /" \
  && echo "--- accounts after (must equal before):" \
  && python3 -c "import sqlite3;print(\"    \",sqlite3.connect(\"file:/var/lib/secure-chat/accounts.db?mode=ro\",uri=True).execute(\"select count(*) from accounts\").fetchone()[0])" \
  && echo "--- process environment: TRUSTED_PROXIES must be absent, --no-proxy-headers present, loopback only" \
  && (tr "\0" "\n" < /proc/$(systemctl show -p MainPID --value secure-chat)/environ | grep -c SECURE_CHAT_TRUSTED_PROXIES || true) | sed "s/^/    TRUSTED_PROXIES vars (want 0): /" \
  && tr "\0" " " < /proc/$(systemctl show -p MainPID --value secure-chat)/cmdline | grep -o -- "--no-proxy-headers" \
  && ss -ltn | grep ":8000 " | sed "s/^/    listen: /"'

echo
echo "==> 4. open https://<your host>/ in a fresh tab: Users -> tap a verified"
echo "        contact -> Remove sits centred under the buttons."
echo
