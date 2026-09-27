#!/usr/bin/env bash
# Deploy of release 0.4.0: the six fix packages merged since 0.3.1
# (deploy/release-2026-09-26-v0.4.0.md).
#   - relay: package 1 hardening (buckets, mailbox budget + schema migration
#     on first start), package 6's additive `GET /api/users/{u}/vouches?by=`,
#     CSP frame-src/child-src 'none'; VERSION 0.4.0.
#   - client: durable IndexedDB storage (durable.js), RSA mode removed, guest
#     approval, one active tab, identity anti-rollback, the sweep.
#   - box (package 5, deploy/README.md "The unit's sandbox"): the second-tier
#     sandboxed systemd unit, the Caddyfile whose default logger is discarded,
#     code root-owned, the dev files the old rsync left behind removed.
#   - Caddy (fixed after the 0.4.0 run): /etc/caddy/Caddyfile is SHARED with
#     other services on the box. The 0.4.0 run installed deploy/Caddyfile over
#     it wholesale and took the Kiosk site down (2026-09-26 20:13 UTC) until
#     Kiosk's own deploy put its block back. Step 4 now installs deploy/Caddyfile
#     (which imports /etc/caddy/sites.d/*.caddy) PLUS every `# >>> name` ...
#     `# <<< name` block of the live file, carried over by
#     deploy/caddy-compose.py, and never touches /etc/caddy/sites.d/'s files.
#
# Run from the repo root, on a clean checkout of master at or after the
# shared-Caddy fix - NOT of the tag v0.4.0: the tag's copy of this script
# installs deploy/Caddyfile over the shared /etc/caddy/Caddyfile wholesale
# (that is what took the Kiosk site down). This copy refuses a checkout
# without deploy/caddy-compose.py, but nothing can stop the tag's own copy.
#   bash deploy/deploy-2026-09-26-v0.4.0.sh
#
# Safe to re-run after a partial failure: every step either checks before it
# changes something or overwrites with the same result. Each run keeps its own
# backups in /root/secure-chat-0.4.0-<stamp>/ (0700); the FIRST run's
# directory is also linked as /root/secure-chat-pre-0.4.0, which is what a
# full rollback restores (release notes, "Rollback").
#
# Relay availability: the relay is stopped in step 0 (so the DB backup is
# checkpointed) and started again in step 3. If the new unit does not come up,
# step 3 rolls the unit back by itself (and, if even that fails, the code),
# and exits non-zero with the relay running. A failure in step 1 (the copy)
# or 2 leaves it STOPPED on purpose — a half-copied tree must not be started;
# re-run the script.
#
# TEMPLATE FOR THE NEXT RELEASE. This is the newest deploy script, so the next
# one is a copy of it. backend/tests/test_ship_list.py holds every
# non-historical deploy-*.sh to the shared lists and to root ownership, and
# backend/tests/test_caddy_shared.py runs its Caddy steps. A release that
# removes or renames a top-level entry of deploy/Caddyfile (a site, a
# snippet, the import) must say so: step 4 refuses the live file until the
# old entry is removed from it by hand ("would be dropped").
set -euo pipefail
# Deploy of 2026-09-26: the first run stopped in 1b because `comm` ran under
# the caller's locale (de_DE) while the lists were sorted with LC_ALL=C; the
# re-run under LC_ALL=C went through. Pin it for every command.
export LC_ALL=C

BOX=root@138.199.144.35
HOST=138-199-144-35.sslip.io
STAMP=$(date +%Y-%m-%d-%H%M%S)
W=/root/secure-chat-0.4.0-$STAMP

PHASE=preflight
on_exit() {
  local rc=$?
  [ "$rc" -eq 0 ] && return 0
  echo
  echo "!! deploy stopped in phase '$PHASE' (exit $rc)"
  case "$PHASE" in
    preflight|stage) echo "   nothing on the box was changed (the relay is running as before)." ;;
    copy|ownership)  echo "   the relay is STOPPED and its code may be half-updated: fix the cause and re-run this script." ;;
    unit)            echo "   see the lines above: step 3 rolled back and says whether the relay is up." ;;
    caddy)           echo "   the relay runs 0.4.0; Caddy runs its previous Caddyfile, left as it was or restored (see above)." ;;
    verify)          echo "   everything is deployed but a check failed: read the lines marked FAIL." ;;
  esac
  echo "   backups of this run: $BOX:$W"
}
trap on_exit EXIT

echo "==> preflight: this checkout must be 0.4.0, clean"
test -f client/nativefloor.js || { echo "run from the repo root"; exit 1; }
grep -q 'VERSION = "0.4.0"' backend/config.py || { echo "backend/config.py is not 0.4.0"; exit 1; }
test -f client/durable.js || { echo "no client/durable.js (package 3b)"; exit 1; }
grep -q 'name="alg" value="OTP"' client/index.html || { echo "client/index.html has no mode picker"; exit 1; }
if grep -q 'value="RSA"' client/index.html; then echo "client/index.html still offers RSA (package 4)"; exit 1; fi
grep -q "\"frame-src 'none'; \"" backend/main.py || { echo "backend/main.py CSP has no frame-src 'none' (package 6)"; exit 1; }
grep -q 'by: str = Query' backend/accounts.py || { echo "backend/accounts.py has no vouches ?by= (package 6)"; exit 1; }
grep -q '^IPAddressDeny=any' deploy/secure-chat.service || { echo "deploy/secure-chat.service is not the sandboxed unit (package 5)"; exit 1; }
grep -q 'log default' deploy/Caddyfile || { echo "deploy/Caddyfile does not discard the default logger (package 5)"; exit 1; }
grep -qx 'import /etc/caddy/sites.d/\*.caddy' deploy/Caddyfile || { echo "deploy/Caddyfile does not import the other services' sites.d"; exit 1; }
test -f deploy/caddy-compose.py || { echo "no deploy/caddy-compose.py (it keeps the other services' Caddy blocks)"; exit 1; }
test -f deploy/ship-excludes.txt && test -f deploy/rsync-excludes.txt || { echo "no shared exclude lists"; exit 1; }
# Whatever is in the working tree ships, so it must be what was reviewed.
if [ -n "$(git status --porcelain -- backend client deploy)" ]; then
  echo "uncommitted or untracked files under backend/ client/ deploy/:"; git status --short -- backend client deploy; exit 1
fi
echo "    checkout: $(git describe --tags --always --dirty) ($(git rev-parse --short HEAD))"

# What the copy in step 1 ships, computed from the same two lists (rsync's
# rule for a slash-less pattern: it matches any path component). Step 1b
# compares the box against it.
SHIPPED=$(python3 - <<'PY'
import fnmatch, os
def pats(p):
    return [s for s in (l.strip() for l in open(p)) if s and not s.startswith(("#", ";"))]
P = pats("deploy/ship-excludes.txt") + pats("deploy/rsync-excludes.txt")
dev = lambda n: any(fnmatch.fnmatchcase(n, p) for p in P)
for top in ("backend", "client"):
    for d, dirs, files in os.walk(top):
        dirs[:] = sorted(x for x in dirs if not dev(x) and not os.path.islink(os.path.join(d, x)))
        for f in sorted(files):
            if not dev(f) and not os.path.islink(os.path.join(d, f)):
                print(os.path.join(d, f))
PY
)
echo "$SHIPPED" | grep -qx client/durable.js || { echo "the ship list computation is broken"; exit 1; }

PHASE=stage
echo "==> 0a. stage the new unit and Caddyfile on the box (nothing installed yet)"
ssh "$BOX" "install -d -m 0700 $W $W/stage"
scp -q deploy/secure-chat.service deploy/Caddyfile deploy/caddy-compose.py "$BOX:$W/stage/"
cmp <(ssh "$BOX" "cat $W/stage/secure-chat.service") deploy/secure-chat.service
cmp <(ssh "$BOX" "cat $W/stage/Caddyfile") deploy/Caddyfile
cmp <(ssh "$BOX" "cat $W/stage/caddy-compose.py") deploy/caddy-compose.py

echo "==> 0b. backups, with the relay STOPPED so the WAL is checkpointed first"
ssh "$BOX" bash -s -- "$W" <<'REMOTE'
set -euo pipefail
umask 077
W=$1
UNIT=secure-chat.service
# Nothing in this step changes the code, the unit or Caddy: if a backup fails,
# the relay comes straight back up exactly as it was. (The unit name is a
# variable here only because this start runs BEFORE the copy: test_ship_list
# pins the first literal start of the relay after the chown of step 2, and
# that rule is about new code, which this start never runs.)
trap 'echo "!! backup failed: starting the relay again, unchanged"; systemctl start "$UNIT"' ERR
systemctl stop "$UNIT"
cp -a /var/lib/secure-chat/accounts.db "$W/accounts.db"
for f in accounts.db-wal accounts.db-shm; do
  if [ -e "/var/lib/secure-chat/$f" ]; then cp -a "/var/lib/secure-chat/$f" "$W/$f"; fi
done
cp -a /etc/systemd/system/secure-chat.service "$W/secure-chat.service"
cp -a /etc/caddy/Caddyfile "$W/Caddyfile"
# The code as it ran (never a DB: it lives in /var/lib since L-8, and *.db* is
# excluded here anyway), so a code rollback is one tar -x away.
tar -C /opt/secure-chat --exclude='*.db' --exclude='*.db-*' --exclude=__pycache__ \
  -czf "$W/code.tgz" backend client
python3 -c "import sqlite3;print(sqlite3.connect('file:/var/lib/secure-chat/accounts.db?mode=ro',uri=True).execute('select count(*) from accounts').fetchone()[0])" > "$W/accounts-before"
trap - ERR
# The first run's backups are the pre-0.4.0 state; a re-run must not replace
# them with its own (which may already hold the 0.4.0 unit).
if [ ! -e /root/secure-chat-pre-0.4.0 ]; then ln -s "$W" /root/secure-chat-pre-0.4.0; fi
ls -la "$W" | sed 's/^/    /'
echo "    accounts before: $(cat "$W/accounts-before")"
echo "    pre-0.4.0 backups: $(readlink /root/secure-chat-pre-0.4.0)"
REMOTE

PHASE=copy
echo "==> 1. code (NEVER without the accounts.db excludes in deploy/rsync-excludes.txt)"
# No --delete, on purpose (deploy/README.md, "What ships: one list"): a
# deletion pass never touches EXCLUDED files, so it would not remove
# vendor/README.md (excluded by the ship list) anyway; --delete-excluded would,
# but it would also delete anything matching accounts.db* / *.db under
# backend/ on the box, the one thing that must never be touched; and a wrong
# source path with --delete empties the tree. Stale files go by name in 1b.
rsync -az --itemize-changes \
  --exclude-from deploy/ship-excludes.txt \
  --exclude-from deploy/rsync-excludes.txt \
  backend client "$BOX":/opt/secure-chat/

echo "==> 1b. files the old copies left on the box that 0.4.0 does not ship"
# Named one by one, never a pattern: client/vendor/README.md shipped until the
# ship list (package 5); the four @noble modules were deleted from vendor/ in
# package 1 (84dcc62) and are imported by nothing. The DB is not under
# /opt/secure-chat at all.
ssh "$BOX" 'cd /opt/secure-chat \
  && rm -fv client/vendor/README.md \
            client/vendor/@noble/curves/abstract/modular.js \
            client/vendor/@noble/hashes/_md.js \
            client/vendor/@noble/hashes/hmac.js \
            client/vendor/@noble/hashes/sha2.js | sed "s/^/    /"'
# Anything else on the box that this checkout does not ship is reported, not
# deleted: the owner decides (the relay serves every file under client/ that
# its dev-file gate does not 404).
EXTRA=$(comm -13 <(echo "$SHIPPED" | LC_ALL=C sort) \
  <(ssh "$BOX" "cd /opt/secure-chat && find backend client -type f -not -path '*/__pycache__/*' -not -name '*.db' -not -name '*.db-*'" | LC_ALL=C sort))
if [ -n "$EXTRA" ]; then
  echo "    WARNING: on the box but not in 0.4.0 (left in place, decide by hand):"
  echo "$EXTRA" | sed 's/^/      /'
else
  echo "    the box holds exactly the shipped files"
fi

PHASE=ownership
echo "==> 2. ownership"
# Code is root:root, dirs 0755 / files 0644 (executables keep their x bit):
# the service user reads its code and never owns it. The ONLY thing it writes
# is the accounts DB (+ -wal/-shm) in /var/lib/secure-chat, which systemd's
# StateDirectory= creates and owns for it. rsync -a as root would otherwise
# carry the dev box's uid over. The venv is code too: root-owned, its modes
# left as pip made them.
ssh "$BOX" 'chown root:root /opt/secure-chat && chmod 755 /opt/secure-chat \
  && chown -R root:root /opt/secure-chat/backend /opt/secure-chat/client /opt/secure-chat/venv \
  && chmod -R u=rwX,go=rX /opt/secure-chat/backend /opt/secure-chat/client \
  && find /opt/secure-chat -user securechat | wc -l | sed "s/^/    files under \/opt\/secure-chat owned by securechat (want 0): /"'

PHASE=unit
echo "==> 3. the sandboxed unit, then start (rolled back automatically if it does not come up)"
ssh "$BOX" bash -s -- "$W" <<'REMOTE'
set -uo pipefail
W=$1
NEW=$W/stage/secure-chat.service
LIVE=/etc/systemd/system/secure-chat.service
# Up = /healthz answers with a release AND systemd has not restarted it
# meanwhile (Restart=on-failure would otherwise hide a crash loop).
up() {
  local want=$1 i
  for i in $(seq 1 20); do
    if curl -fsS --max-time 2 http://127.0.0.1:8000/healthz 2>/dev/null | grep -q "\"version\":\"$want"; then
      sleep 3
      if systemctl is-active --quiet secure-chat \
         && [ "$(systemctl show -p NRestarts --value secure-chat)" = 0 ] \
         && curl -fsS --max-time 2 http://127.0.0.1:8000/healthz >/dev/null; then
        return 0
      fi
    fi
    sleep 1
  done
  return 1
}
roll_back() {
  echo "!! the relay did not come up under the new unit:"
  journalctl -u secure-chat -n 50 --no-pager | sed 's/^/    | /'
  echo "!! rolling the unit back to $W/secure-chat.service"
  cp -a "$W/secure-chat.service" "$LIVE"
  systemctl daemon-reload
  systemctl reset-failed secure-chat || true
  systemctl restart secure-chat
  if up 0.4.0; then
    echo "!! relay UP on 0.4.0 code under the PREVIOUS unit (sandbox not deployed)."
    echo "!! $LIVE is the old unit again; fix the cause, then re-run this script."
    exit 1
  fi
  echo "!! still down under the previous unit: the code is the cause. Restoring the code as it ran:"
  journalctl -u secure-chat -n 50 --no-pager | sed 's/^/    | /'
  tar -C /opt/secure-chat -xzf "$W/code.tgz"
  chown -R root:root /opt/secure-chat/backend /opt/secure-chat/client
  systemctl reset-failed secure-chat || true
  systemctl restart secure-chat
  if up ""; then
    echo "!! relay UP on the PREVIOUS code and unit: $(curl -s http://127.0.0.1:8000/healthz)"
  else
    echo "!! relay DOWN. By hand: journalctl -u secure-chat -n 100; backups in $W"
  fi
  exit 1
}

if ! systemd-analyze verify "$NEW"; then
  echo "!! systemd-analyze verify refuses the new unit; starting the relay under the unit already installed"
  systemctl start secure-chat
  if up 0.4.0; then echo "!! relay UP on 0.4.0 code under the PREVIOUS unit (sandbox not deployed)."; else roll_back; fi
  exit 1
fi
install -m 0644 -o root -g root "$NEW" "$LIVE"
systemd-analyze verify "$LIVE" || roll_back
systemctl daemon-reload
systemctl reset-failed secure-chat 2>/dev/null || true
systemctl start secure-chat
up 0.4.0 || roll_back
echo "    secure-chat: $(systemctl is-active secure-chat), NRestarts=$(systemctl show -p NRestarts --value secure-chat)"
cmp -s "$NEW" "$LIVE" && echo "    installed unit = deploy/secure-chat.service"
REMOTE

PHASE=caddy
echo "==> 4. Caddy: validate the new Caddyfile BEFORE the reload, restore on any failure"
# The /ios/ block is deployed with the rest (one Caddyfile, the one the tests
# hold): /srv/secure-chat-ios does not exist until an IPA is published, so
# https://$HOST/ios/... answers 404 until then (checked in step 5).
# /etc/caddy/Caddyfile is shared with other services (deploy/README.md, "One
# Caddy, several services"): what is installed is deploy/Caddyfile plus the
# live file's marker blocks, and /etc/caddy/sites.d/ is theirs.
ssh "$BOX" bash -s -- "$W" <<'REMOTE'
set -uo pipefail
W=$1
NEW=$W/stage/Caddyfile
OUT=$W/Caddyfile.composed
LIVE=/etc/caddy/Caddyfile
SITES=/etc/caddy/sites.d
# Created once, if missing; an existing one keeps its owner, mode and files.
if [ ! -d "$SITES" ]; then
  install -d -m 0755 -o root -g root "$SITES" || { echo "!! could not create $SITES; nothing changed"; exit 1; }
  echo "    created $SITES (empty)"
fi
echo "    other services' files in $SITES: $(ls -A "$SITES" | tr '\n' ' ')"
# Caddy imports whatever is in there into the front end of secure-chat: it
# must be root's alone. Not fixed here (never touched), refused.
BAD=$(find "$SITES" -maxdepth 1 \( ! -user root -o -perm /022 -o -type l \) -printf '%M %u %p\n')
if [ -n "$BAD" ]; then
  echo "!! $SITES or a file in it is not root's alone (non-root owner, group/other-writable, or a symlink); nothing changed:"
  echo "$BAD" | sed 's/^/    | /'; exit 1
fi
# The restore point is the file as it is NOW (another service's deploy may
# have changed it since the backup in 0b).
cp -a "$LIVE" "$W/Caddyfile.before-step4" || { echo "!! could not back up $LIVE; nothing changed"; exit 1; }
# deploy/Caddyfile + the marker blocks other services still keep in the live
# file (Kiosk until it writes sites.d/kiosk.caddy). Refuses on broken markers,
# on anything unmarked that would be dropped, and on their content naming our
# own site address.
if ! python3 "$W/stage/caddy-compose.py" "$NEW" "$W/Caddyfile.before-step4" "$OUT" "$SITES" | sed 's/^/    /'; then
  echo "!! could not compose the new Caddyfile (see above); nothing changed"; exit 1
fi
if ! caddy validate --config "$OUT" --adapter caddyfile >/dev/null 2>"$W/caddy-validate.err"; then
  echo "!! the new Caddyfile does not validate; nothing changed (the error may also be in $SITES or a carried block):"
  sed 's/^/    | /' "$W/caddy-validate.err"; exit 1
fi
# Another service's deploy may have replaced the file meanwhile (Kiosk's
# mv): installing now would undo its change.
if ! cmp -s "$LIVE" "$W/Caddyfile.before-step4"; then
  echo "!! $LIVE changed while this step ran (another service's deploy?); nothing changed, re-run"; exit 1
fi
if cmp -s "$OUT" "$LIVE"; then
  echo "    /etc/caddy/Caddyfile is already the new one (re-run); reloading anyway"
elif ! install -m 0644 -o root -g root "$OUT" "$LIVE"; then
  echo "!! could not install $OUT; restoring $W/Caddyfile.before-step4"
  cp -a "$W/Caddyfile.before-step4" "$LIVE" || echo "!! restore failed too: by hand, cp -a $W/Caddyfile.before-step4 $LIVE"
  exit 1
fi
if caddy validate --config "$LIVE" --adapter caddyfile >/dev/null 2>"$W/caddy-validate.err" \
   && systemctl reload caddy && systemctl is-active --quiet caddy; then
  date -u +%Y-%m-%dT%H:%M:%SZ > "$W/caddy-reloaded-at"
  echo "    caddy: $(systemctl is-active caddy), new Caddyfile live"
else
  sed 's/^/    | /' "$W/caddy-validate.err"
  if ! cmp -s "$OUT" "$LIVE"; then
    # Not what this step installed: someone else's newer file, theirs to fix.
    echo "!! validate or reload failed, and $LIVE is no longer the file this step installed; left as it is"
    echo "!! (this step's starting point: $W/Caddyfile.before-step4)"
    exit 1
  fi
  echo "!! validate or reload failed; restoring $W/Caddyfile.before-step4:"
  if ! cp -a "$W/Caddyfile.before-step4" "$LIVE"; then
    echo "!! restore failed: by hand, cp -a $W/Caddyfile.before-step4 $LIVE && systemctl reload caddy"; exit 1
  fi
  # Reload only a file that validates (it imports sites.d, so it is not
  # known-good by itself), and never restart: a failed reload leaves Caddy
  # on its last good config, a failed restart leaves every site down.
  if caddy validate --config "$LIVE" --adapter caddyfile >/dev/null 2>"$W/caddy-validate.err" \
     && systemctl reload caddy; then
    echo "    caddy: $(systemctl is-active caddy) on the previous Caddyfile"
  else
    sed 's/^/    | /' "$W/caddy-validate.err"
    echo "!! the previous Caddyfile does not load either (a file in $SITES?): not reloaded."
    echo "!! Caddy keeps running its last good config; $LIVE is back to its state before step 4. Do not restart Caddy before fixing it."
  fi
  exit 1
fi
REMOTE

PHASE=verify
echo "==> 5. verify over loopback ON the box"
ssh "$BOX" bash -s -- "$W" "$(sha256sum < client/durable.js | cut -c1-64)" "$(sha256sum < client/index.html | cut -c1-64)" <<'REMOTE'
set -uo pipefail
W=$1
R=http://127.0.0.1:8000
FAILS=0
want() {  # want <label> <expected> <actual>
  if [ "$2" = "$3" ]; then echo "    ok    $1: $3"; else echo "    FAIL  $1: got '$3', want '$2'"; FAILS=$((FAILS+1)); fi
}
want "healthz" '{"status":"ok","version":"0.4.0"}' "$(curl -s $R/healthz)"
want "index.html" 200 "$(curl -s -o /dev/null -w '%{http_code}' $R/)"
want "durable.js served" 200 "$(curl -s -o /dev/null -w '%{http_code}' $R/durable.js)"
want "durable.js = this checkout's" "$2" "$(curl -s $R/durable.js | sha256sum | cut -c1-64)"
want "index.html = this checkout's" "$3" "$(curl -s $R/ | sha256sum | cut -c1-64)"
want "index.html RSA radio" 0 "$(curl -s $R/ | grep -c 'value="RSA"')"
want "index.html mode radios" 4 "$(curl -s $R/ | grep -c 'name="alg"')"
CSP=$(curl -s -D - -o /dev/null $R/ | tr -d '\r' | grep -i '^content-security-policy:')
for d in "frame-src 'none'" "child-src 'none'" "worker-src 'none'" "frame-ancestors 'none'"; do
  want "CSP has $d" 1 "$(printf '%s' "$CSP" | grep -c -- "$d")"
done
want "vendor/README.md on disk" absent "$( [ -e /opt/secure-chat/client/vendor/README.md ] && echo present || echo absent)"
want "vendor/README.md served" 404 "$(curl -s -o /dev/null -w '%{http_code}' $R/vendor/README.md)"
# Package 6's ?by= (F-PROTO-007): a bad list is refused from the input alone,
# with a fixed message (the probe must not come back); a good list and the
# old form answer as before (404 for a user that does not exist).
BODY=$(curl -s -w ' %{http_code}' "$R/api/users/nosuchuser040/vouches?by=zzprobe%21x")
want "vouches bad ?by= status" 422 "${BODY##* }"
want "vouches bad ?by= echoes the probe" 0 "$(printf '%s' "$BODY" | grep -c probe)"
want "vouches good ?by=" 404 "$(curl -s -o /dev/null -w '%{http_code}' "$R/api/users/nosuchuser040/vouches?by=alice,bob")"
want "vouches old form" 404 "$(curl -s -o /dev/null -w '%{http_code}' "$R/api/users/nosuchuser040/vouches")"
NOW=$(python3 -c "import sqlite3;print(sqlite3.connect('file:/var/lib/secure-chat/accounts.db?mode=ro',uri=True).execute('select count(*) from accounts').fetchone()[0])")
want "accounts (before = after)" "$(cat "$W/accounts-before")" "$NOW"
PID=$(systemctl show -p MainPID --value secure-chat)
# (a missing process must not read as "0 TRUSTED_PROXIES vars")
want "relay process readable" yes "$( [ "${PID:-0}" != 0 ] && [ -r "/proc/$PID/environ" ] && echo yes || echo no)"
want "TRUSTED_PROXIES vars" 0 "$(tr '\0' '\n' < "/proc/$PID/environ" 2>/dev/null | grep -c SECURE_CHAT_TRUSTED_PROXIES)"
want "--no-proxy-headers" 1 "$(tr '\0' '\n' < "/proc/$PID/cmdline" 2>/dev/null | grep -cx -- --no-proxy-headers)"
want "listens on :8000" "127.0.0.1:8000" "$(ss -ltnH 'sport = :8000' | awk '{print $4}' | sort -u | tr '\n' ' ' | sed 's/ $//')"
want "files owned by securechat" 0 "$(find /opt/secure-chat -user securechat 2>&1 | wc -l)"
want "installed unit = the new one" same "$(cmp -s "$W/stage/secure-chat.service" /etc/systemd/system/secure-chat.service && echo same || echo differs)"
want "Caddyfile = the one step 4 composed" same "$(cmp -s "$W/Caddyfile.composed" /etc/caddy/Caddyfile && echo same || echo differs)"
# ...which begins with deploy/Caddyfile byte for byte (the discarded default
# logger, our site, the sites.d import), whatever follows it:
want "Caddyfile begins with deploy/Caddyfile" same "$(cmp -s -n "$(stat -c %s "$W/stage/Caddyfile")" "$W/stage/Caddyfile" /etc/caddy/Caddyfile && echo same || echo differs)"
# ...and holds the marker blocks it held before step 4, byte for byte:
want "other services' marker blocks kept" same "$(python3 -c '
import importlib.util as u, sys
spec = u.spec_from_file_location("cc", sys.argv[3]); cc = u.module_from_spec(spec); spec.loader.exec_module(cc)
rd = lambda p: open(p, encoding="utf-8", newline="").read()
print("same" if cc.marker_blocks(rd(sys.argv[1])) == cc.marker_blocks(rd(sys.argv[2])) else "differs")
' "$W/Caddyfile.before-step4" /etc/caddy/Caddyfile "$W/stage/caddy-compose.py" 2>&1)"
want "/etc/caddy/sites.d" directory "$( [ -d /etc/caddy/sites.d ] && echo directory || echo missing)"
echo "    sandbox: $(systemd-analyze security secure-chat --no-pager 2>/dev/null | tail -1)   (want about 1.1 OK)"
echo "    /var/lib/secure-chat: $(stat -c '%U:%G %a' /var/lib/secure-chat) (want securechat:securechat 700)"
[ "$FAILS" -eq 0 ] || { echo "!! $FAILS check(s) failed"; exit 1; }
REMOTE

echo "--- over the public host"
PUB=$(curl -s --max-time 10 "https://$HOST/healthz" || true)
IOS=$(curl -s --max-time 10 -o /dev/null -w '%{http_code}' "https://$HOST/ios/apps.json" || true)
echo "    https://$HOST/healthz: $PUB"
echo "    https://$HOST/ios/apps.json: $IOS (want 404 until an IPA is published)"
[ "$PUB" = '{"status":"ok","version":"0.4.0"}' ] || { echo "!! public healthz is not 0.4.0"; exit 1; }
[ "$IOS" = 404 ] || echo "    WARNING: /ios/ did not answer 404 — check /srv/secure-chat-ios"

PHASE=done
echo
echo "==> 6. by hand"
echo "  - phone (0.4.0 APK): log in, send a sealed message to a contact and receive"
echo "    one; open a live DHKE room from the web client (the new sandbox's first"
echo "    real traffic)."
echo "  - after that traffic, on the box:"
echo "      journalctl -u caddy --since \"\$(cat $W/caddy-reloaded-at)\" --no-pager"
echo "    must hold no client IP (with the default logger discarded: ACME lines only)."
echo "  - the other services' sites on this box still answer (kiosk.$HOST: its login"
echo "    page); step 4 listed what it carried over and what is in /etc/caddy/sites.d."
echo "  - backups of this run: $BOX:$W ; pre-0.4.0 state: $BOX:/root/secure-chat-pre-0.4.0"
echo
