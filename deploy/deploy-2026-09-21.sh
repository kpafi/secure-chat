#!/usr/bin/env bash
# Deploy of the 2026-08-07 pentest fixes (merge of claude/loving-cannon-ba5tbt).
#
# WHY A SCRIPT: not because the steps are order-dependent on the box (the DB
# already lives in /var/lib/secure-chat since 2026-07-30 and the unit did not
# change) but because the release is ONE unit with the APK: the relay now
# refuses Ed25519-only logins, so an old APK cannot log in. INSTALL THE APK
# FIRST (see deploy/release-2026-09-21.md), then run this.
#
# Run from the repo root, on master:  bash deploy/deploy-2026-09-21.sh
# (the box's python3 is used for the row counts — no sqlite3 CLI needed; a
# failure AFTER the stop in step 0 would otherwise leave the relay down)
set -euo pipefail

BOX=root@138.199.144.35
STAMP=$(date +%Y-%m-%d-%H%M)

test -f client/nativefloor.js || { echo "run from the repo root, on master"; exit 1; }

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
ssh "$BOX" 'curl -s -o /dev/null -w "healthz=%{http_code}\n" http://127.0.0.1:8000/healthz \
  && curl -s -o /dev/null -w "index=%{http_code}\n" http://127.0.0.1:8000/ \
  && curl -s -o /dev/null -w "nativefloor.js=%{http_code}\n" http://127.0.0.1:8000/nativefloor.js \
  && echo "--- the served client must be the new one:" \
  && curl -s http://127.0.0.1:8000/account.js | grep -c "mldsa_sig" | sed "s/^/    account.js mldsa_sig lines: /" \
  && curl -s http://127.0.0.1:8000/chats.js | grep -c "chats-store/v2" | sed "s/^/    chats.js v2 tag lines: /" \
  && echo "--- an Ed25519-only verify body must be a 422 now (schema), not a login:" \
  && curl -s -o /dev/null -w "    verify-without-mldsa=%{http_code}\n" \
       -H "content-type: application/json" -d "{\"username\":\"nobody\",\"challenge\":\"x\",\"sig\":\"x\"}" \
       http://127.0.0.1:8000/api/auth/verify \
  && echo "--- accounts after (must equal before):" \
  && python3 -c "import sqlite3;print(\"    \",sqlite3.connect(\"file:/var/lib/secure-chat/accounts.db?mode=ro\",uri=True).execute(\"select count(*) from accounts\").fetchone()[0])" \
  && echo "--- process environment: TRUSTED_PROXIES must be absent, --no-proxy-headers present" \
  && (tr "\0" "\n" < /proc/$(systemctl show -p MainPID --value secure-chat)/environ | grep -c SECURE_CHAT_TRUSTED_PROXIES || true) | sed "s/^/    TRUSTED_PROXIES vars (want 0): /" \
  && tr "\0" " " < /proc/$(systemctl show -p MainPID --value secure-chat)/cmdline | grep -o -- "--no-proxy-headers"'

echo
echo "==> 4. now open the app on the phone: expect ONE 'Open anyway' in the Chats"
echo "        view, none in Users; then log in and check adb logcat stays quiet."
echo
echo "ROLLBACK (code only — the DB schema did not change):"
echo "  git checkout 80a002d -- backend client && bash deploy/deploy-2026-09-21.sh"
echo "  (and reinstall the previous APK; the old client cannot talk to the new relay's login)"
