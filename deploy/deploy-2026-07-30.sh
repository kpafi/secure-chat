#!/usr/bin/env bash
# One-off deploy of the 2026-07-29 pentest fixes (merge 2918986 + 6d1a06f).
#
# WHY THIS EXISTS AS A SCRIPT: this release moves the account database, so the
# steps are order-dependent in a way the usual two-line rsync recipe is not. Get
# the order wrong and the relay starts against an empty database.
#
# Run from the repo root:  bash deploy/deploy-2026-07-30.sh
set -euo pipefail

BOX=root@138.199.144.35
STAMP=$(date +%Y-%m-%d-%H%M)

echo "==> 0. backup, with the service STOPPED so the WAL is checkpointed first"
# Stopping before the copy is the point: a live WAL-mode sqlite copied file by
# file can be inconsistent. This is also the start of the downtime window.
ssh "$BOX" "systemctl stop secure-chat \
  && cp -a /opt/secure-chat/backend/accounts.db /root/accounts.db.bak-$STAMP \
  && ls -la /root/accounts.db.bak-$STAMP"

echo "==> 1. code (NEVER without the accounts.db excludes — the old recipe"
echo "        overwrote the live database with the local dev one)"
rsync -az --itemize-changes \
  --exclude node_modules --exclude 'package*.json' --exclude '*.test.mjs' \
  --exclude 'test-source.mjs' --exclude 'README.md' \
  --exclude __pycache__ --exclude '.venv' --exclude '.pytest_cache' \
  --exclude 'accounts.db*' --exclude '*.db' --exclude '*.db-shm' --exclude '*.db-wal' \
  --exclude 'tests' \
  backend client "$BOX":/opt/secure-chat/

echo "==> 2. the systemd unit — NEW this release, and not covered by the rsync"
echo "        above (it only syncs backend/ and client/)"
scp deploy/secure-chat.service "$BOX":/etc/systemd/system/secure-chat.service

echo "==> 3. the one-off DB move (pentest 2026-07-29 L-8)"
# The new unit sets SECURE_CHAT_DB=/var/lib/secure-chat/accounts.db. If the DB is
# not moved BEFORE the start below, the relay creates an empty one there and
# every account is gone until the backup is restored.
# 0700, not systemd's 0755 default: the DB holds the directory's lookup tokens
# (the secret half of `username#token`) and the sealed mailbox ciphertext.
# StateDirectoryMode=0700 in the unit re-applies this on every start.
ssh "$BOX" 'install -d -o securechat -g securechat -m 0700 /var/lib/secure-chat \
  && mv /opt/secure-chat/backend/accounts.db* /var/lib/secure-chat/ \
  && chown securechat:securechat /var/lib/secure-chat/accounts.db* \
  && ls -la /var/lib/secure-chat/'

echo "==> 4. restart"
ssh "$BOX" 'chown -R securechat:securechat /opt/secure-chat/backend \
  && systemctl daemon-reload \
  && systemctl start secure-chat \
  && sleep 2 \
  && systemctl is-active secure-chat'

echo "==> 5. verify — over loopback ON the box; direct-IP TLS fails from some"
echo "        networks, so a curl from here proves nothing either way"
ssh "$BOX" 'curl -s -o /dev/null -w "healthz=%{http_code}\n" http://127.0.0.1:8000/healthz \
  && curl -s -o /dev/null -w "index=%{http_code}\n" http://127.0.0.1:8000/ \
  && echo "--- state dir (want drwx------ securechat, and a NON-EMPTY accounts.db):" \
  && ls -la /var/lib/secure-chat/ \
  && echo "--- the code tree must have NO database left behind:" \
  && ls -la /opt/secure-chat/backend/accounts.db* 2>/dev/null || echo "    (none — correct)"'

echo
echo "==> 6. Tor: torrc.secure-chat gained HiddenServiceMaxStreams 24 +"
echo "        HiddenServiceMaxStreamsCloseCircuit 1 (M-2). NOT applied by this"
echo "        script — install the block into the tor config and reload tor"
echo "        separately, after checking it against what is already on the box:"
echo "          diff <(ssh $BOX 'cat /etc/tor/torrc') deploy/torrc.secure-chat"
echo "          ssh $BOX 'tor --verify-config && systemctl reload tor@default'"
echo
echo "ROLLBACK, if the relay comes up with an empty directory:"
echo "  ssh $BOX 'systemctl stop secure-chat"
echo "    && cp -a /root/accounts.db.bak-$STAMP /var/lib/secure-chat/accounts.db"
echo "    && chown securechat:securechat /var/lib/secure-chat/accounts.db"
echo "    && systemctl start secure-chat'"
