#!/usr/bin/env bash
#
# End-to-end check of scripts/install.sh on a REAL systemd host, as root.
# Run by the `installer-e2e` job of .github/workflows/ci.yml on a fresh
# ubuntu-24.04 runner VM; never run it on a host you care about — it installs the
# bot into /opt/vpn-service.
#
#   sudo MOCK_PYTHON=/path/to/python-with-aiohttp bash tests/e2e/run_install_e2e.sh
#
# The Bot API is tests/e2e/mock_telegram_api.py; both the installer and the bot
# are pointed at it through TELEGRAM_API_BASE. The code under test is THIS
# checkout (INSTALL_REPO=file://…, INSTALL_REF=HEAD).
#
# Phases, each one a hard assertion:
#   A. relay mode with a code that is not a pairing code exits 1 and changes
#      nothing on disk (the relay mode itself: tests/e2e/run_relay_install_e2e.sh);
#   B. a failure injected after the bot started rolls back: no path of the
#      manifest is left, the unit is gone;
#   C. a real install: unit active, NRestarts=0, readiness marker, no token or
#      claim code in any log;
#   D. /start claim_<code> makes the operator superadmin (DB row, role,
#      claim.json gone), alerts reach them at once (no restart), a second claim
#      with the same link is refused;
#   E. a re-run is a REPAIR: .env and vpn.db byte-for-byte unchanged (sha256),
#      the bot healthy again; --reclaim is inert while a superadmin exists.

set -Eeuo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
INSTALL_SH="${REPO_ROOT}/scripts/install.sh"
MOCK_PYTHON="${MOCK_PYTHON:?MOCK_PYTHON must point at a python with aiohttp}"
MOCK_PORT="${MOCK_PORT:-8081}"
MOCK="http://127.0.0.1:${MOCK_PORT}"
TOKEN="7000000001:AAE2e$(head -c 24 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 32)"
OPERATOR=424242
INTRUDER=515151
NEWCOMER=616161
APP_DIR=/opt/vpn-service
WORK="$(mktemp -d)"
MOCK_PID=""

step() { printf '\n=== %s\n' "$*"; }
fail() { printf 'E2E FAILURE: %s\n' "$*" >&2; exit 1; }

cleanup() {
  [[ -n "$MOCK_PID" ]] && kill "$MOCK_PID" 2>/dev/null || true
}
trap cleanup EXIT

[[ "${EUID}" -eq 0 ]] || fail "run as root"
[[ ! -e "$APP_DIR" ]] || fail "$APP_DIR already exists — this must run on a fresh VM"

export INSTALL_REPO="file://${REPO_ROOT}"
export INSTALL_REF
INSTALL_REF="$(git -C "$REPO_ROOT" rev-parse HEAD)"
export TELEGRAM_API_BASE="$MOCK"
# The checkout belongs to the CI user; git (and its upload-pack) running as root
# would refuse it as "dubious ownership" without this.
export GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=safe.directory GIT_CONFIG_VALUE_0='*'

installer() { bash "$INSTALL_SH" "$@"; }

mock_get() { curl -fsS --max-time 5 "${MOCK}/_control/$1"; }

inject() {
  curl -fsS --max-time 5 -H 'Content-Type: application/json' \
    -d "{\"user_id\": $1, \"text\": \"$2\"}" "${MOCK}/_control/inject" >/dev/null
}

# Wait (bounded) until the bot has sent chat $1 a message containing $2.
wait_sent() {
  local chat="$1" needle="$2" deadline=$((SECONDS + 30))
  while (( SECONDS < deadline )); do
    if mock_get sent | python3 -c '
import json, sys
chat, needle = int(sys.argv[1]), sys.argv[2]
sys.exit(0 if any(m["chat_id"] == chat and needle in m["text"] for m in json.load(sys.stdin)) else 1)
' "$chat" "$needle"; then
      return 0
    fi
    sleep 0.5
  done
  fail "the bot never sent chat ${chat} a message containing '${needle}'"
}

# Wait until the bot confirmed (polled past) every injected update.
wait_delivered() {
  local deadline=$((SECONDS + 30))
  while (( SECONDS < deadline )); do
    if mock_get delivered | python3 -c 'import json,sys; d=json.load(sys.stdin); sys.exit(0 if d["confirmed"] >= d["queued"] else 1)'; then
      return 0
    fi
    sleep 0.5
  done
  fail "updates were not confirmed by the bot"
}

db_query() {
  python3 - "$1" <<'PY'
import sqlite3, sys
conn = sqlite3.connect("file:/opt/vpn-service/data/vpn.db?mode=ro", uri=True)
print("\n".join("|".join(map(str, row)) for row in conn.execute(sys.argv[1])))
PY
}

# Newest installer log/manifest. `|| true`: with pipefail, ls on no match would
# end the whole script silently.
newest() { { ls -1t /var/log/vpn-bot-install.*."$1" 2>/dev/null || true; } | head -n1; }

count_install_files() {
  local f n=0
  for f in /var/log/vpn-bot-install.*; do [[ -e "$f" ]] && n=$((n + 1)); done
  printf '%s' "$n"
}

assert_unit_healthy() {
  [[ "$(systemctl is-active vpn-bot.service)" == active ]] || fail "vpn-bot.service is not active"
  local restarts
  restarts="$(systemctl show -p NRestarts --value vpn-bot.service)"
  [[ "$restarts" == 0 ]] || fail "NRestarts=${restarts}, expected 0"
}

assert_no_secret_in_logs() {
  local secret="$1" what="$2" f
  for f in /var/log/vpn-bot-install.* "$APP_DIR"/logs/bot.log*; do
    [[ -f "$f" ]] || continue
    if grep -qF -- "$secret" "$f"; then fail "${what} found in ${f}"; fi
  done
  if journalctl -u vpn-bot.service --no-pager 2>/dev/null | grep -qF -- "$secret"; then
    fail "${what} found in the journal"
  fi
}

# --------------------------------------------------------------------------- #
step "mock Telegram API on ${MOCK}"
MOCK_BOT_TOKEN="$TOKEN" "$MOCK_PYTHON" "${REPO_ROOT}/tests/e2e/mock_telegram_api.py" --port "$MOCK_PORT" \
  >"${WORK}/mock.log" 2>&1 &
MOCK_PID=$!
for _ in $(seq 1 50); do mock_get health >/dev/null 2>&1 && break; sleep 0.2; done
mock_get health >/dev/null || fail "mock did not come up"

# --------------------------------------------------------------------------- #
step "A. relay mode with a bad pairing code: exit 1, nothing on disk"
logs_before="$(count_install_files)"
set +e
printf '2\nnot-a-pairing-code\n' | installer
rc=$?
set -e
[[ "$rc" == 1 ]] || fail "relay mode with a bad code exited ${rc}, expected 1"
[[ ! -e "$APP_DIR" && ! -e /etc/systemd/system/vpn-bot.service && ! -e /etc/vpn-bot && ! -e /etc/vpn-relay ]] \
  || fail "relay mode changed the disk"
[[ "$(count_install_files)" == "$logs_before" ]] || fail "relay mode wrote a log"
[[ ! -e /run/vpn-bot-install.lock ]] || fail "relay mode took the lock"

# --------------------------------------------------------------------------- #
step "B. failure injected after the bot started: full rollback"
set +e
printf '1\n%s\n' "$TOKEN" | INSTALL_INJECT_FAILURE=after_start installer >"${WORK}/b.out" 2>"${WORK}/b.err"
rc=$?
set -e
cat "${WORK}/b.err"
[[ "$rc" == 1 ]] || fail "injected failure exited ${rc}, expected 1"
manifest="$(newest manifest)"
[[ -n "$manifest" ]] || fail "no manifest"
tail -n1 "$manifest" | grep -q '^# rolled back' || fail "manifest does not end with '# rolled back'"
grep -q $'^enabled\tvpn-bot.service' "$manifest" || fail "the late failure did not get as far as enabling the unit"
left=0
while IFS=$'\t' read -r kind path _; do
  case "$kind" in
    dir | file)
      if [[ -e "$path" ]]; then echo "left behind: ${path}"; left=1; fi ;;
  esac
done <"$manifest"
[[ "$left" == 0 ]] || fail "rollback left manifest paths behind"
if systemctl is-active --quiet vpn-bot.service; then fail "vpn-bot.service still active after rollback"; fi
[[ "$(systemctl show -p LoadState --value vpn-bot.service)" == not-found ]] || fail "vpn-bot.service still loaded"
assert_no_secret_in_logs "$TOKEN" "the bot token"

# --------------------------------------------------------------------------- #
step "C. install"
printf '1\n%s\n' "$TOKEN" | installer >"${WORK}/c.out" 2>"${WORK}/c.err"
cat "${WORK}/c.err"
link="$(grep -oE 'https://t\.me/vpnbot_ci_bot\?start=claim_[A-Za-z0-9_-]+' "${WORK}/c.out" | head -n1)"
[[ -n "$link" ]] || fail "no claim link in the installer's output"
code="${link##*start=claim_}"
[[ "${#code}" == 22 ]] || fail "claim code has ${#code} chars, expected 22"
assert_unit_healthy
grep -q 'Run polling for bot @vpnbot_ci_bot' "$APP_DIR/logs/bot.log" || fail "no readiness marker in bot.log"
[[ "$(stat -c '%U:%G %a' "$APP_DIR/.env")" == "root:root 600" ]] || fail ".env is $(stat -c '%U:%G %a' "$APP_DIR/.env")"
[[ "$(stat -c '%U:%G %a' /etc/vpn-bot/claim.json)" == "root:root 600" ]] || fail "claim.json permissions"
if grep -qF "$code" /etc/vpn-bot/claim.json; then fail "claim.json contains the code itself"; fi
grep -q '^ADMIN_IDS=$' "$APP_DIR/.env" || fail "ADMIN_IDS is not empty in .env"
if grep -E '^[A-Z0-9_]+_ENABLED=' "$APP_DIR/.env" | grep -v '=false$'; then fail "a *_ENABLED is not false"; fi
tail -n1 "$(newest manifest)" | grep -q '^# committed' || fail "manifest not committed"
assert_no_secret_in_logs "$TOKEN" "the bot token"
assert_no_secret_in_logs "$code" "the claim code"

# --------------------------------------------------------------------------- #
step "D. claim"
inject "$OPERATOR" "/start claim_${code}"
wait_sent "$OPERATOR" "суперадминистратор"
[[ "$(db_query 'SELECT telegram_user_id FROM claimed_superadmins')" == "$OPERATOR" ]] || fail "claimed_superadmins"
[[ "$(db_query "SELECT role FROM users WHERE telegram_user_id = ${OPERATOR}")" == SUPERADMIN ]] || fail "operator role"
[[ ! -e /etc/vpn-bot/claim.json ]] || fail "claim.json was not removed"
[[ -z "$(ls -A /etc/vpn-bot)" ]] || fail "leftovers in /etc/vpn-bot: $(ls -A /etc/vpn-bot)"
[[ "$(db_query "SELECT count(*) FROM audit_log WHERE action = 'superadmin_claimed'")" == 1 ]] || fail "audit row"

# The new superadmin is effective at once, without a restart: a newcomer's access
# request is announced to them.
inject "$NEWCOMER" "/start"
wait_sent "$OPERATOR" "$NEWCOMER"

# The same link a second time, from someone else: refused, nothing changes.
inject "$INTRUDER" "/start claim_${code}"
wait_sent "$INTRUDER" "недействительна"
[[ "$(db_query 'SELECT count(*) FROM claimed_superadmins')" == 1 ]] || fail "a second claim was accepted"
[[ "$(db_query "SELECT count(*) FROM users WHERE role = 'SUPERADMIN'")" == 1 ]] || fail "a second superadmin appeared"
wait_delivered
assert_unit_healthy
assert_no_secret_in_logs "$code" "the claim code"

# --------------------------------------------------------------------------- #
step "E. repair: .env and vpn.db byte-for-byte unchanged"
systemctl stop vpn-bot.service
env_before="$(sha256sum "$APP_DIR/.env" | cut -d' ' -f1)"
db_before="$(sha256sum "$APP_DIR/data/vpn.db" | cut -d' ' -f1)"
python3 -c 'import sqlite3; print("\n".join(sqlite3.connect("file:/opt/vpn-service/data/vpn.db?mode=ro", uri=True).iterdump()))' \
  >"${WORK}/db_before.sql"

printf '1\n' | installer >"${WORK}/e.out" 2>"${WORK}/e.err"
cat "${WORK}/e.err"
grep -q 'REPAIR' "${WORK}/e.err" || fail "the re-run was not a repair"
if grep -q 'start=claim_' "${WORK}/e.out"; then fail "repair issued a claim although a superadmin exists"; fi
assert_unit_healthy
wait_delivered

systemctl stop vpn-bot.service
python3 -c 'import sqlite3; print("\n".join(sqlite3.connect("file:/opt/vpn-service/data/vpn.db?mode=ro", uri=True).iterdump()))' \
  >"${WORK}/db_after.sql"
[[ "$(sha256sum "$APP_DIR/.env" | cut -d' ' -f1)" == "$env_before" ]] || fail ".env changed during repair"
if [[ "$(sha256sum "$APP_DIR/data/vpn.db" | cut -d' ' -f1)" != "$db_before" ]]; then
  diff "${WORK}/db_before.sql" "${WORK}/db_after.sql" || true
  fail "vpn.db changed during repair"
fi
systemctl start vpn-bot.service

step "E2. --reclaim is inert while a superadmin exists"
installer --reclaim >"${WORK}/r.out" 2>"${WORK}/r.err"
cat "${WORK}/r.err"
[[ ! -e /etc/vpn-bot/claim.json ]] || fail "--reclaim issued a claim although a superadmin exists"
if grep -q 'start=claim_' "${WORK}/r.out"; then fail "--reclaim printed a link"; fi

step "ALL E2E CHECKS PASSED"
