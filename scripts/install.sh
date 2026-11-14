#!/usr/bin/env bash
#
# scripts/install.sh — install the VPN Telegram bot on a fresh Ubuntu 24.04 host
# with ONE command; everything after that happens in Telegram.
#
#   sudo bash install.sh            install (or repair an existing install)
#   sudo bash install.sh --reclaim  issue a new superadmin claim link, nothing else
#   printf '%s\n' '<pairing code>' | sudo bash install.sh --relay
#                                   install a RELAY (the code comes from the bot:
#                                   Мастер настройки → Relay → Добавить)
#   sudo bash install.sh --relay-update
#                                   reinstall a relay from its checkout (what the
#                                   relay agent's `update` runs after a checkout)
#
# Get it from a GitHub release together with SHA256SUMS and verify it first
# (docs/install.md); never pipe it from a branch into bash.
#
# --------------------------------------------------------------------------- #
# WHAT IT DOES (mode "main server")
# --------------------------------------------------------------------------- #
#   1. Read-only preconditions: root, Ubuntu 24.04, x86_64|aarch64, systemd,
#      free space, reachability of github.com, pypi.org and the Bot API.
#   2. Asks the mode: 1) main server  2) relay (see MODE "relay" below).
#   3. Asks for the bot token (hidden input) and checks it with getMe. That is
#      the only input. The token never reaches a process argv (curl reads it from
#      a config on stdin), the log or the terminal.
#   4. Installs: apt packages, a checkout of the LATEST RELEASE TAG (INSTALL_REF
#      overrides) in /opt/vpn-service, a venv from the hash-pinned
#      constraints-hashed.txt, .env from .env.example (the token, ADMIN_IDS empty,
#      every *_ENABLED=false; root:root 0600 like production), the
#      vpn-bot-db-perms helper and deploy/vpn-bot.service verbatim. The root/api
#      privilege model of deploy/vpn-bot.service is not changed.
#   5. Starts the bot and waits for REAL readiness: aiogram's "Run polling" line
#      in bot.log after the byte offset the log had before the start (90 s),
#      then scans that same range for ERROR / CRITICAL / Traceback.
#   6. Issues the first-superadmin claim: a 128-bit code; /etc/vpn-bot/claim.json
#      (root 0600) holds only its sha256 and an expiry (30 min). Prints
#      https://t.me/<bot>?start=claim_<code> and a QR (qrencode, if available) to
#      the terminal only. The bot side is services/superadmin_claim.py.
#
# --------------------------------------------------------------------------- #
# WHAT IT DOES (mode "relay", docs/relay.md#installing-a-relay-with-one-command)
# --------------------------------------------------------------------------- #
# A relay has NO Telegram bot and never talks to the Telegram API. Its only input
# is the pairing code the bot shows (base64url JSON: v, target_host — the main
# server's DNS name —, ports, main_pubkey, one_time_token, exp = 30 min). It is read
# from stdin (never an argv); the token is reduced to its sha256 at once.
#   1. Read-only preconditions: the same host checks, the code valid and not
#      expired, root may log in with a key (sshd -T; sshd_config is NEVER changed),
#      ufw not active (its forward policy would drop the relayed traffic), the
#      target resolves, no forwarded TCP port is an sshd port, not a main server.
#   2. Installs: nftables, a checkout of INSTALL_REF (the bot's command pins the
#      main server's own commit) in /opt/vpn-service, a relay .env
#      (RELAY_UPSTREAM_HOST = the target NAME, the ports, RELAY_INPUT_FILTER=off,
#      SSH_PORT = where sshd listens now), /etc/vpn-relay/pairing.json (the token's
#      hash, the expiry), vpn-relay-apply and vpn-relay-agent, vpn-relay.service and
#      vpn-relay-resolve.{service,timer} (re-resolves the name every 5 minutes),
#      and ONE authorized_keys line for root:
#      restrict,command="/usr/local/sbin/vpn-relay-agent" ssh-ed25519 <main key>
#   3. Starts vpn-relay (one atomic nft -f: DNAT tcp+udp -> target, masquerade,
#      MSS clamp, forward policy drop but the DNAT; ip_forward via sysctl.d) and
#      checks it: `vpn-relay-apply check`, exactly ONE DNAT rule per forwarded port
#      in the whole ruleset, the timer active.
#   4. ADOPTION: a relay installed by hand (/etc/vpn-relay.nft, vpn-relay.service,
#      table ip vpnrelay) is replaced atomically — the same table name, so the one
#      transaction swaps it, never two DNATs — and everything old goes to
#      /var/backups/vpn-relay/adopt-<ts>/ (kept); the rollback puts it all back,
#      the live table from its dump.
#   A re-run with a new code on an installed relay re-pairs it (repair).
#
# ATOMIC: every path, unit and replaced file is appended to a manifest BEFORE it
# is created; any failure (ERR trap, Ctrl-C, SIGTERM) rolls back strictly by that
# manifest in reverse order. apt packages are logged but never removed — they may
# have been there before. The manifest and the log stay in /var/log.
#
# IDEMPOTENT: on a host that already has /opt/vpn-service with .env, a re-run is a
# REPAIR: .env and the database are never written; the helper and the unit are
# reinstalled from the checkout, the bot is restarted and checked, and a new claim
# is issued only if there is still no superadmin. --reclaim does only that last
# part.
#
# --------------------------------------------------------------------------- #
# ENVIRONMENT
# --------------------------------------------------------------------------- #
#   INSTALL_REF=<tag|commit>  install this ref instead of the latest release.
#   INSTALL_REPO=<git url>    clone from here (default: the GitHub repository).
#   TELEGRAM_API_BASE=<url>   Bot API server (default https://api.telegram.org).
#                             A non-default value is also written to .env, so
#                             the bot talks to the same server. CI points both at
#                             a local mock (tests/e2e/mock_telegram_api.py).
#   INSTALL_SELFTEST=1        test seam, like DEPLOY_SELFTEST in deploy.sh: define
#                             every function and return before doing anything.
#   INSTALL_INJECT_FAILURE=<step>
#                             test seam for the CI rollback check: fail at that
#                             step (after_clone, after_venv, after_env,
#                             after_unit, after_start; relay: after_relay_clone,
#                             after_relay_files, after_relay_start). NEVER set it
#                             otherwise.
#
# EXIT CODES: 0 done · 1 failed (and rolled back) · 2 usage.

set -Eeuo pipefail
umask 022

readonly DEFAULT_REPO_URL="https://github.com/Egor051/vpnbot.git"
readonly RELEASES_LATEST_URL="https://api.github.com/repos/Egor051/vpnbot/releases/latest"
readonly DEFAULT_TELEGRAM_API_BASE="https://api.telegram.org"

APP_DIR="/opt/vpn-service"
ENV_FILE="${APP_DIR}/.env"
UNIT_NAME="vpn-bot.service"
UNIT_PATH="/etc/systemd/system/${UNIT_NAME}"
DB_PERMS_HELPER="/usr/local/sbin/vpn-bot-db-perms"
SBIN_DIR="/usr/local/sbin"
# The other helpers a main server needs from its first minute (docs/wizard.md): the
# setup wizard the bot launches — «Обновить бота» is how a fresh install reaches its
# first redeploy — and the emergency TOTP reset, which must be on the host BEFORE the
# day the phone and the codes are gone. The same entries as deploy.sh's
# OUT_OF_REPO_HELPERS (role main, required); tests/test_install_script.py keeps them
# equal. Installed through install_file, so a rollback removes them like the rest.
INSTALL_HELPERS=(
  scripts/wizard/vpn-bot-wizard
  scripts/wizard/vpn-bot-wizard-lib
  scripts/wizard/vpn-bot-wizard-selfcheck
  scripts/wizard/vpn-bot-wizard-dump
  scripts/wizard/vpn-bot-wizard-update
  scripts/vpn-bot-totp-reset
)
CLAIM_DIR="/etc/vpn-bot"
CLAIM_FILE="${CLAIM_DIR}/claim.json"
LOCK_FILE="/run/vpn-bot-install.lock"
INSTALL_LOG_DIR="/var/log"
# The checkout must carry the bot side of the claim. Releases before it do not.
CLAIM_SUPPORT_MARKER="services/superadmin_claim.py"

READY_TIMEOUT=90
CLAIM_TTL_SECONDS=1800
MIN_FREE_MB=2048
TOKEN_RE='^[0-9]{6,12}:[A-Za-z0-9_-]{30,}$'

# Relay mode (docs/relay.md#installing-a-relay-with-one-command).
RELAY_SUPPORT_MARKER="scripts/vpn-relay-agent"
SYSTEMD_DIR="/etc/systemd/system"
RELAY_UNITS=(vpn-relay.service vpn-relay-resolve.service vpn-relay-resolve.timer)
RELAY_STATE_DIR="/etc/vpn-relay"
RELAY_VAR_DIR="/var/lib/vpn-relay"
RELAY_SYSCTL_FILE="/etc/sysctl.d/90-vpn-relay.conf"
RELAY_LEGACY_NFT="/etc/vpn-relay.nft"
RELAY_BACKUP_ROOT="/var/backups/vpn-relay"
# The forced command of the bot's key: ALWAYS this literal path (tests re-root
# SBIN_DIR, never this).
readonly RELAY_AGENT_COMMAND="/usr/local/sbin/vpn-relay-agent"
RELAY_MIN_FREE_MB=300
# Accepted clock skew between the main server and the relay for the code's expiry.
RELAY_CODE_SKEW=300
APT_RELAY_PACKAGES=(git ca-certificates curl nftables)

APT_PACKAGES=(git python3-venv ca-certificates curl)
APT_OPTIONAL_PACKAGES=(qrencode)

TS="$(date -u +%Y%m%dT%H%M%SZ)"
INSTALL_LOG=""
MANIFEST=""
ROLLING_BACK=0
ROLLBACK_ARMED=0
COMMITTED=0
BOT_TOKEN=""
BOT_USERNAME=""
CLAIM_LINK=""
MODE=""
# The pairing code, decoded and validated (relay mode). Never the token itself.
PAIR_TARGET=""
PAIR_TCP=""
PAIR_UDP=""
PAIR_KEY_BLOB=""
PAIR_TOKEN_SHA256=""
PAIR_EXP=""
# The relay's authorized_keys for root (from sshd -T), the adoption backup dir,
# whether this run created /opt/vpn-service, ip_forward before the install.
AUTH_KEYS=""
RELAY_ADOPT_DIR=""
RELAY_CREATED_APP_DIR=0
RELAY_FORWARD_BEFORE=""
RELAY_EXISTING_CHECKOUT=0
TG_API_BASE="${TELEGRAM_API_BASE:-$DEFAULT_TELEGRAM_API_BASE}"
TG_API_BASE="${TG_API_BASE%/}"

# --------------------------------------------------------------------------- #
# Output and the log
# --------------------------------------------------------------------------- #
# Everything that can reach the log goes through redact first: a bot token or a
# claim code that slipped into some command's output must never land on disk.
redact() {
  sed -u -E \
    -e 's/[0-9]{6,12}:[A-Za-z0-9_-]{30,}/<redacted-bot-token>/g' \
    -e 's/claim_[A-Za-z0-9_-]{8,}/claim_<redacted>/g' \
    -e 's/[A-Za-z0-9_-]{150,}/<redacted-pairing-code>/g'
}

log() {
  [[ -n "$INSTALL_LOG" ]] || return 0
  printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" | redact >>"$INSTALL_LOG"
}

say() {
  printf '%s\n' "$*" | redact >&2
  log "$*"
}

warn() { say "ВНИМАНИЕ: $*"; }

# A deliberate stop. Once mutations have begun (arm_rollback) it rolls back
# first: `exit` does not fire the ERR trap, so without this a refusal half-way
# (a release without claim support, a file missing from the checkout) would leave
# /opt/vpn-service behind and every later run would stop at "conflict".
die() {
  say "ОШИБКА: $*"
  if [[ "$ROLLBACK_ARMED" == 1 && "$COMMITTED" == 0 ]]; then
    rollback
  fi
  exit 1
}

# Run a command with its output in the log only. pipefail makes the pipeline
# fail exactly when the command does.
run() {
  log "+ $*"
  "$@" 2>&1 | redact >>"${INSTALL_LOG:-/dev/null}"
}

open_log() {
  local old_umask
  old_umask="$(umask)"
  umask 077
  INSTALL_LOG="${INSTALL_LOG_DIR}/vpn-bot-install.${TS}.log"
  MANIFEST="${INSTALL_LOG_DIR}/vpn-bot-install.${TS}.manifest"
  : >"$INSTALL_LOG"
  : >"$MANIFEST"
  chmod 0600 "$INSTALL_LOG" "$MANIFEST"
  umask "$old_umask"
  printf '# vpn-bot install manifest %s — rolled back in reverse order on failure\n' "$TS" >>"$MANIFEST"
  log "vpn-bot installer started (log ${INSTALL_LOG}, manifest ${MANIFEST})"
}

# --------------------------------------------------------------------------- #
# Manifest and rollback
# --------------------------------------------------------------------------- #
# One record per line, tab-separated, appended BEFORE the thing exists:
#   dir      <path>             created directory  -> rm -rf
#   file     <path>             created file       -> rm -f
#   replaced <path> <backup>    overwritten file   -> backup moved back
#   enabled  <unit>             unit we enabled    -> disable --now
#   started  <unit>             unit we started    -> stop
#   restart  <unit>             unit we restarted  -> restarted after the rest
#   apt      <package>          package we installed -> logged, never removed
# relay mode:
#   adopted  <path> <backup>    a relay file that existed (adoption, re-pair)
#                               -> copied back from the backup; the backup in
#                               /var/backups/vpn-relay STAYS, also after a commit
#   nft      <family> <table> <dump|->
#                               the live table before -> restored from its dump in
#                               one nft transaction, or deleted ("-": none before)
#   sysctl   <key> <value>      a runtime sysctl before -> sysctl -w back
#   gitref   <dir> <sha>        a checkout we moved -> checked out back
manifest_add() {
  [[ -n "$MANIFEST" ]] || die "internal: manifest is not open"
  local IFS=$'\t'
  printf '%s\n' "$*" >>"$MANIFEST"
}

# Rollback removes only paths it could have created. Anything else in a manifest
# (an edited file, a bug) is refused rather than deleted.
path_is_ours() {
  local p="${1-}" src dst
  [[ -n "$p" && "$p" == /* && "$p" != *..* && "$p" != */ ]] || return 1
  for src in "${INSTALL_HELPERS[@]}"; do
    dst="${SBIN_DIR}/${src##*/}"
    [[ "$p" == "$dst" || "$p" == "$dst".* ]] && return 0
  done
  case "$p" in
    "$APP_DIR" | "$APP_DIR"/* | "$CLAIM_DIR" | "$CLAIM_DIR"/* | "$UNIT_PATH" | "$UNIT_PATH".* | \
      "$DB_PERMS_HELPER" | "$DB_PERMS_HELPER".*) return 0 ;;
  esac
  [[ "$MODE" == relay ]] || return 1
  local unit
  for unit in "${RELAY_UNITS[@]}"; do
    [[ "$p" == "${SYSTEMD_DIR}/${unit}" || "$p" == "${SYSTEMD_DIR}/${unit}".* ]] && return 0
  done
  case "$p" in
    "${SBIN_DIR}/vpn-relay-apply" | "${SBIN_DIR}/vpn-relay-apply".* | "${SBIN_DIR}/vpn-relay-agent" | \
      "${SBIN_DIR}/vpn-relay-agent".* | "$RELAY_STATE_DIR" | "$RELAY_STATE_DIR"/* | "$RELAY_VAR_DIR" | \
      "$RELAY_VAR_DIR"/* | "$RELAY_SYSCTL_FILE" | "$RELAY_SYSCTL_FILE".* | "$RELAY_LEGACY_NFT" | \
      "$RELAY_BACKUP_ROOT"/*) return 0 ;;
  esac
  if [[ -n "$AUTH_KEYS" ]]; then
    [[ "$p" == "$AUTH_KEYS" || "$p" == "$AUTH_KEYS".* || "$p" == "$(dirname "$AUTH_KEYS")" ]] && return 0
  fi
  return 1
}

rollback() {
  [[ "$ROLLING_BACK" == 0 ]] || return 0
  ROLLING_BACK=1
  set +e
  trap - ERR
  [[ -n "$MANIFEST" && -f "$MANIFEST" ]] || return 0
  say "Откат по manifest ${MANIFEST}…"
  local kind a b c restarts=()
  while IFS=$'\t' read -r kind a b c; do
    case "$kind" in
      '' | '#'*) continue ;;
      enabled)
        log "rollback: disable --now ${a}"
        systemctl disable --now "$a" >>"$INSTALL_LOG" 2>&1
        ;;
      started)
        log "rollback: stop ${a}"
        systemctl stop "$a" >>"$INSTALL_LOG" 2>&1
        ;;
      restart) restarts+=("$a") ;;
      file)
        if path_is_ours "$a"; then log "rollback: rm -f ${a}"; rm -f -- "$a"; else log "rollback: REFUSED to remove ${a}"; fi
        ;;
      dir)
        if path_is_ours "$a"; then log "rollback: rm -rf ${a}"; rm -rf -- "$a"; else log "rollback: REFUSED to remove ${a}"; fi
        ;;
      replaced)
        if path_is_ours "$a" && path_is_ours "$b" && [[ -e "$b" ]]; then
          log "rollback: restore ${a} from ${b}"
          mv -f -- "$b" "$a"
        else
          log "rollback: REFUSED to restore ${a} from ${b}"
        fi
        ;;
      apt) log "rollback: package ${a} stays installed (it may have been wanted before)" ;;
      adopted)
        if path_is_ours "$a" && path_is_ours "$b" && [[ -e "$b" ]]; then
          log "rollback: put back ${a} from ${b} (the backup stays)"
          cp -a -- "$b" "$a"
        else
          log "rollback: REFUSED to put back ${a} from ${b}"
        fi
        ;;
      nft) rollback_nft "$a" "$b" "$c" ;;
      sysctl)
        if [[ "$a" =~ ^net\.[a-z0-9_.]+$ && "$b" =~ ^[0-9]+$ ]]; then
          log "rollback: sysctl ${a}=${b}"
          sysctl -q -w "${a}=${b}" >>"$INSTALL_LOG" 2>&1
        fi
        ;;
      gitref)
        if [[ "$a" == "$APP_DIR" && "$b" =~ ^[0-9a-f]{40}$ ]]; then
          log "rollback: checkout ${b} in ${a}"
          git -C "$a" -c advice.detachedHead=false checkout --quiet --detach "$b" >>"$INSTALL_LOG" 2>&1
        fi
        ;;
      *) log "rollback: unknown record '${kind}' ignored" ;;
    esac
  done < <(tac "$MANIFEST")
  systemctl daemon-reload >>"$INSTALL_LOG" 2>&1
  systemctl reset-failed "$UNIT_NAME" >>"$INSTALL_LOG" 2>&1
  if [[ "$MODE" == relay ]]; then systemctl reset-failed "${RELAY_UNITS[@]}" >>"$INSTALL_LOG" 2>&1; fi
  local unit
  for unit in "${restarts[@]}"; do
    log "rollback: restart ${unit} with the restored files"
    systemctl restart "$unit" >>"$INSTALL_LOG" 2>&1
  done
  printf '# rolled back %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >>"$MANIFEST"
  say "Откат завершён. Подробности: ${INSTALL_LOG}"
}

on_error() {
  local rc=$1 line=$2
  trap - ERR
  [[ "$COMMITTED" == 1 ]] && exit "$rc"
  say "Шаг завершился ошибкой (код ${rc}, строка ${line})."
  rollback
  exit 1
}

on_signal() {
  trap - ERR INT TERM HUP
  say "Прервано."
  [[ "$COMMITTED" == 1 ]] || rollback
  exit 130
}

arm_rollback() {
  ROLLBACK_ARMED=1
  trap 'on_error $? $LINENO' ERR
  trap on_signal INT TERM HUP
}

commit() {
  COMMITTED=1
  trap - ERR INT TERM HUP
  local kind a b
  # The backups only existed for a rollback; drop them now.
  while IFS=$'\t' read -r kind a b; do
    if [[ "$kind" == replaced ]] && path_is_ours "$b"; then rm -f -- "$b"; fi
  done <"$MANIFEST"
  printf '# committed %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >>"$MANIFEST"
  log "committed"
}

# One nft record: the table back as it was, in ONE transaction (create + delete +
# the dump), or deleted when it did not exist before ("-").
rollback_nft() {
  local family="$1" table="$2" dump="$3"
  [[ "$family" =~ ^(ip|inet)$ && "$table" =~ ^vpnrelay(_input)?$ ]] || { log "rollback: REFUSED nft ${family} ${table}"; return 0; }
  if [[ "$dump" == - ]]; then
    if nft list table "$family" "$table" >/dev/null 2>&1; then
      log "rollback: nft delete table ${family} ${table} (it did not exist before)"
      nft delete table "$family" "$table" >>"$INSTALL_LOG" 2>&1
    fi
  elif path_is_ours "$dump" && [[ -f "$dump" ]]; then
    log "rollback: table ${family} ${table} restored from ${dump}"
    { printf 'table %s %s\ndelete table %s %s\n' "$family" "$table" "$family" "$table"; cat -- "$dump"; } \
      | nft -f - >>"$INSTALL_LOG" 2>&1
  else
    log "rollback: REFUSED nft dump ${dump}"
  fi
}

# Test seam for the CI rollback check (see the header).
fail_point() {
  if [[ "${INSTALL_INJECT_FAILURE:-}" == "$1" ]]; then
    log "test seam: injected failure at '$1'"
    return 1
  fi
  return 0
}

# --------------------------------------------------------------------------- #
# Small helpers
# --------------------------------------------------------------------------- #
# One value out of an .env file: last assignment wins, `export` and quotes and an
# inline comment are stripped. Same reader as scripts/vpn-bot-db-perms.
env_value() {
  local file="$1" name="$2"
  [[ -r "$file" ]] || return 0
  sed -n "s/^[[:space:]]*\(export[[:space:]]\+\)\?${name}[[:space:]]*=[[:space:]]*//p" "$file" \
    | tail -n1 \
    | sed -e 's/[[:space:]]#.*$//' -e 's/[[:space:]]*$//' -e 's/^"\(.*\)"$/\1/' -e "s/^'\(.*\)'$/\1/"
}

valid_token_format() { [[ "${1-}" =~ $TOKEN_RE ]]; }

# getMe with the token on curl's STDIN (-K -): never in an argv, where any local
# user could read it from /proc. Prints the bot's username.
telegram_get_me() {
  local token="$1" body
  body="$(printf 'url = "%s/bot%s/getMe"\n' "$TG_API_BASE" "$token" \
    | curl -sS --max-time 20 --retry 2 --retry-connrefused -K - 2>/dev/null)" || return 1
  printf '%s' "$body" | python3 -c '
import json, re, sys
try:
    data = json.load(sys.stdin)
except ValueError:
    sys.exit(1)
result = data.get("result") if isinstance(data, dict) and data.get("ok") is True else None
username = result.get("username") if isinstance(result, dict) and result.get("is_bot") else None
if not isinstance(username, str) or not re.fullmatch(r"[A-Za-z0-9_]{5,32}", username):
    sys.exit(1)
print(username)
'
}

# Copy src to dst atomically (temp file + rename in the same directory). A
# pre-existing different dst is backed up and recorded as `replaced`; an identical
# one is left alone; a new one is recorded as `file`.
install_file() {
  local src="$1" dst="$2" mode="$3" backup tmp
  [[ -f "$src" ]] || die "в checkout нет ${src#"$APP_DIR"/}"
  if [[ -e "$dst" ]]; then
    if cmp -s -- "$src" "$dst"; then
      chmod "$mode" -- "$dst"
      log "unchanged: ${dst}"
      return 0
    fi
    backup="${dst}.vpn-bot-install.${TS}.bak"
    manifest_add replaced "$dst" "$backup"
    cp -a -- "$dst" "$backup"
  else
    manifest_add file "$dst"
  fi
  tmp="${dst}.vpn-bot-install.${TS}.tmp"
  manifest_add file "$tmp"
  install -o root -g root -m "$mode" -- "$src" "$tmp"
  mv -f -- "$tmp" "$dst"
  log "installed: ${dst}"
}

# --------------------------------------------------------------------------- #
# Preconditions (read-only)
# --------------------------------------------------------------------------- #
check_reachable() {
  local url="$1" code
  code="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 15 --retry 2 --retry-connrefused -- "$url" 2>/dev/null || true)"
  [[ -n "$code" && "$code" != 000 ]] || die "нет доступа к ${url} — проверьте сеть/DNS/прокси"
}

# The same rule as the bot's TELEGRAM_API_BASE (config/settings.py): the token
# travels in every request path, so plain http only towards a loopback host.
valid_api_base() {
  local base="${1-}"
  [[ "$base" =~ ^https://[A-Za-z0-9.-]+(:[0-9]{1,5})?(/[A-Za-z0-9._~/-]*)?$ ]] && return 0
  [[ "$base" =~ ^http://(127\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|localhost|\[::1\])(:[0-9]{1,5})?(/[A-Za-z0-9._~/-]*)?$ ]]
}

preflight() {
  valid_api_base "$TG_API_BASE" \
    || die "TELEGRAM_API_BASE должен быть https://… (или http:// на loopback): ${TG_API_BASE}"
  [[ "${EUID}" -eq 0 ]] || die "запустите от root: sudo bash install.sh"
  [[ -r /etc/os-release ]] || die "нет /etc/os-release"
  local id version arch free_mb probe
  id="$(. /etc/os-release && printf '%s' "${ID:-}")"
  version="$(. /etc/os-release && printf '%s' "${VERSION_ID:-}")"
  [[ "$id" == ubuntu && "$version" == 24.04 ]] \
    || die "поддерживается только Ubuntu 24.04 (найдено: ${id:-?} ${version:-?})"
  arch="$(uname -m)"
  [[ "$arch" == x86_64 || "$arch" == aarch64 ]] || die "архитектура ${arch} не поддерживается (нужна x86_64 или aarch64)"
  [[ -d /run/systemd/system ]] && command -v systemctl >/dev/null \
    || die "нужен systemd как init (контейнеры без systemd не поддерживаются)"
  local tool
  for tool in curl python3 sha256sum flock install mktemp tac cmp sed; do
    command -v "$tool" >/dev/null || die "нет команды ${tool} (apt-get install -y ${tool})"
  done
  python3 -c 'import sys; sys.exit(0 if sys.version_info[:2] == (3, 12) else 1)' \
    || die "нужен системный python3 3.12 (Ubuntu 24.04)"
  probe="$APP_DIR"
  while [[ ! -d "$probe" ]]; do probe="$(dirname "$probe")"; done
  free_mb="$(df -Pm -- "$probe" | awk 'NR == 2 {print $4}')"
  [[ "${free_mb:-0}" -ge "$MIN_FREE_MB" ]] || die "мало места на ${probe}: ${free_mb:-?} МБ, нужно ≥ ${MIN_FREE_MB} МБ"
  check_reachable "https://github.com"
  check_reachable "https://pypi.org/simple/pip/"
  check_reachable "${TG_API_BASE}/"
}

# --------------------------------------------------------------------------- #
# Questions
# --------------------------------------------------------------------------- #
ask_mode() {
  local answer attempt
  for attempt in 1 2 3; do
    printf 'Режим установки:\n  1) основной сервер\n  2) relay\nВыберите [1/2]: ' >&2
    IFS= read -r answer || die "нет ответа на вопрос о режиме"
    case "${answer//[[:space:]]/}" in
      1) MODE=main; return 0 ;;
      2) MODE=relay; return 0 ;;
    esac
    printf 'Введите 1 или 2.\n' >&2
  done
  die "режим не выбран"
}

read_token() {
  local attempt token username
  for attempt in 1 2 3; do
    printf 'Токен бота от @BotFather (ввод скрыт): ' >&2
    IFS= read -rs token || { printf '\n' >&2; die "токен не введён"; }
    printf '\n' >&2
    token="${token//[[:space:]]/}"
    if ! valid_token_format "$token"; then
      say "Это не похоже на токен бота (ожидается 123456789:AA…)."
      continue
    fi
    if username="$(telegram_get_me "$token")"; then
      BOT_TOKEN="$token"
      BOT_USERNAME="$username"
      say "Токен принят: бот @${BOT_USERNAME}"
      return 0
    fi
    say "Telegram не принял этот токен (getMe)."
  done
  die "не удалось получить рабочий токен"
}

# --------------------------------------------------------------------------- #
# State of the host
# --------------------------------------------------------------------------- #
detect_state() {
  if [[ -d "${APP_DIR}/.git" && -f "$ENV_FILE" ]]; then
    STATE=repair
  elif [[ -e "$APP_DIR" || -e "$UNIT_PATH" ]]; then
    STATE=conflict
  else
    STATE=fresh
  fi
}

require_no_deploy_running() {
  if systemctl is-active --quiet vpn-bot-deploy.service 2>/dev/null; then
    die "идёт деплой (vpn-bot-deploy.service) — дождитесь его окончания"
  fi
}

acquire_lock() {
  exec 9>"$LOCK_FILE"
  flock -n 9 || die "установщик уже запущен (${LOCK_FILE})"
}

# Whether the bot already has a superadmin: ADMIN_IDS in .env, a claimed one, or
# a user with the SUPERADMIN role. The database is opened READ-ONLY (mode=ro):
# a repair must not write it, not even a WAL frame.
has_superadmin() {
  local admin_ids db_path
  admin_ids="$(env_value "$ENV_FILE" ADMIN_IDS)"
  [[ "$admin_ids" =~ [0-9] ]] && return 0
  db_path="$(env_value "$ENV_FILE" DB_PATH)"
  db_path="${db_path:-${APP_DIR}/data/vpn.db}"
  [[ -f "$db_path" ]] || return 1
  python3 - "$db_path" <<'PY'
import sqlite3, sys
from urllib.parse import quote
conn = sqlite3.connect(f"file:{quote(sys.argv[1])}?mode=ro", uri=True, timeout=10)
try:
    tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
    found = False
    if "claimed_superadmins" in tables:
        found = conn.execute("SELECT EXISTS (SELECT 1 FROM claimed_superadmins)").fetchone()[0] == 1
    if not found and "users" in tables:
        found = conn.execute("SELECT EXISTS (SELECT 1 FROM users WHERE role = 'SUPERADMIN')").fetchone()[0] == 1
finally:
    conn.close()
sys.exit(0 if found else 1)
PY
}

# --------------------------------------------------------------------------- #
# Install steps
# --------------------------------------------------------------------------- #
apt_install() {
  export DEBIAN_FRONTEND=noninteractive
  local pkg missing=()
  for pkg in "${APT_PACKAGES[@]}" "${APT_OPTIONAL_PACKAGES[@]}"; do
    if [[ "$(dpkg-query -W -f='${Status}' "$pkg" 2>/dev/null || true)" != *"install ok installed"* ]]; then
      missing+=("$pkg")
      manifest_add apt "$pkg"
    fi
  done
  say "Пакеты: ${missing[*]:-всё уже установлено}"
  [[ ${#missing[@]} -gt 0 ]] || return 0
  run apt-get -o DPkg::Lock::Timeout=300 update -qq
  run apt-get -o DPkg::Lock::Timeout=300 install -y -qq --no-install-recommends "${APT_PACKAGES[@]}"
  if ! run apt-get -o DPkg::Lock::Timeout=300 install -y -qq --no-install-recommends "${APT_OPTIONAL_PACKAGES[@]}"; then
    warn "qrencode недоступен — QR-кода не будет, только ссылка"
  fi
}

resolve_ref() {
  local ref="${INSTALL_REF:-}"
  if [[ -z "$ref" ]]; then
    ref="$(curl -fsSL --max-time 20 --retry 2 -H 'Accept: application/vnd.github+json' -- "$RELEASES_LATEST_URL" \
      | python3 -c 'import json, sys; print(json.load(sys.stdin)["tag_name"])')" \
      || die "не удалось узнать последний релиз (задайте INSTALL_REF=<tag>)"
  fi
  [[ "$ref" =~ ^[A-Za-z0-9][A-Za-z0-9._/-]*$ ]] || die "недопустимый ref: ${ref}"
  INSTALL_REF_RESOLVED="$ref"
}

clone_repo() {
  local repo="${INSTALL_REPO:-$DEFAULT_REPO_URL}" ref="$INSTALL_REF_RESOLVED"
  say "Клонирую ${repo} @ ${ref}…"
  manifest_add dir "$APP_DIR"
  run git clone --quiet --no-checkout -- "$repo" "$APP_DIR"
  if ! run git -C "$APP_DIR" -c advice.detachedHead=false checkout --quiet --detach "${ref}^{commit}"; then
    run git -C "$APP_DIR" fetch --quiet origin -- "$ref"
    run git -C "$APP_DIR" -c advice.detachedHead=false checkout --quiet --detach FETCH_HEAD
  fi
}

clone_checkout() {
  local ref="$INSTALL_REF_RESOLVED"
  clone_repo
  [[ -f "${APP_DIR}/${CLAIM_SUPPORT_MARKER}" ]] \
    || die "ref ${ref} не поддерживает установку через claim (нет ${CLAIM_SUPPORT_MARKER}); укажите более новый INSTALL_REF"
  local f
  for f in .env.example constraints-hashed.txt deploy/vpn-bot.service scripts/vpn-bot-db-perms main.py; do
    [[ -f "${APP_DIR}/${f}" ]] || die "в checkout нет ${f}"
  done
  log "checkout: $(git -C "$APP_DIR" rev-parse HEAD)"
}

build_venv() {
  say "Создаю venv и ставлю зависимости (hash-pinned)…"
  run python3 -m venv "${APP_DIR}/.venv"
  run "${APP_DIR}/.venv/bin/pip" install --quiet --disable-pip-version-check --no-input \
    --require-hashes -r "${APP_DIR}/constraints-hashed.txt"
  run "${APP_DIR}/.venv/bin/pip" check
}

# .env from .env.example: BOT_TOKEN, ADMIN_IDS empty, every *_ENABLED=false and a
# non-default TELEGRAM_API_BASE. The token travels to python on stdin. Refuses to
# leave any other `<placeholder>` value behind.
write_env() {
  local tmp
  install -d -o root -g root -m 0700 "${APP_DIR}/data" "${APP_DIR}/logs"
  tmp="$(mktemp "${APP_DIR}/.env.XXXXXX")"
  manifest_add file "$tmp"
  manifest_add file "$ENV_FILE"
  local api_base=""
  [[ "$TG_API_BASE" != "$DEFAULT_TELEGRAM_API_BASE" ]] && api_base="$TG_API_BASE"
  printf '%s\n' "$BOT_TOKEN" | python3 /dev/fd/3 "${APP_DIR}/.env.example" "$tmp" "$api_base" 3<<'PY'
import os, re, sys
example, target, api_base = sys.argv[1], sys.argv[2], sys.argv[3]
token = sys.stdin.readline().strip()
line_re = re.compile(r"^(?P<name>[A-Z][A-Z0-9_]*)=(?P<value>.*)$")
out, seen = [], set()
for line in open(example, encoding="utf-8").read().splitlines():
    match = line_re.match(line)
    if match is None:
        out.append(line)
        continue
    name, value = match["name"], match["value"]
    seen.add(name)
    if name == "BOT_TOKEN":
        value = token
    elif name == "ADMIN_IDS":
        value = ""
    elif name.endswith("_ENABLED"):
        value = "false"
    elif name == "TELEGRAM_API_BASE":
        value = api_base
    if value.startswith("<") and value.endswith(">"):
        sys.exit(f"unfilled placeholder left for {name} in .env.example")
    out.append(f"{name}={value}")
if "BOT_TOKEN" not in seen or "ADMIN_IDS" not in seen:
    sys.exit(".env.example has no BOT_TOKEN/ADMIN_IDS line")
if api_base and "TELEGRAM_API_BASE" not in seen:
    out += ["", "# Bot API server (set by install.sh)", f"TELEGRAM_API_BASE={api_base}"]
fd = os.open(target, os.O_WRONLY | os.O_TRUNC)
with os.fdopen(fd, "w", encoding="utf-8") as fh:
    fh.write("\n".join(out) + "\n")
    fh.flush()
    os.fsync(fh.fileno())
PY
  chown root:root "$tmp"
  chmod 0600 "$tmp"
  mv -f -- "$tmp" "$ENV_FILE"
  log "wrote ${ENV_FILE} (root:root 0600)"
}

install_unit() {
  local src
  install_file "${APP_DIR}/scripts/vpn-bot-db-perms" "$DB_PERMS_HELPER" 0755
  for src in "${INSTALL_HELPERS[@]}"; do
    # A ref from before the wizard (INSTALL_REF) has none of them: nothing to install,
    # the bot then says «helpers not installed» and the first deploy brings them.
    if [[ ! -f "${APP_DIR}/${src}" ]]; then
      log "not in this checkout: ${src} — skipped"
      continue
    fi
    install_file "${APP_DIR}/${src}" "${SBIN_DIR}/${src##*/}" 0755
  done
  install_file "${APP_DIR}/deploy/vpn-bot.service" "$UNIT_PATH" 0644
  run systemctl daemon-reload
  if ! systemctl is-enabled --quiet "$UNIT_NAME" 2>/dev/null; then
    manifest_add enabled "$UNIT_NAME"
    run systemctl enable "$UNIT_NAME"
  fi
}

# claim.json: only sha256(code) and the expiry, root 0600, replaced atomically.
# The code itself lives in this process and on the operator's terminal only.
issue_claim() {
  local code digest expires tmp
  if [[ ! -d "$CLAIM_DIR" ]]; then
    manifest_add dir "$CLAIM_DIR"
    install -d -o root -g root -m 0755 "$CLAIM_DIR"
  fi
  code="$(python3 -c 'import secrets; print(secrets.token_urlsafe(16))')"
  [[ "$code" =~ ^[A-Za-z0-9_-]{22}$ ]] || die "internal: bad claim code"
  digest="$(printf '%s' "$code" | sha256sum | awk '{print $1}')"
  expires=$(( $(date +%s) + CLAIM_TTL_SECONDS ))
  [[ -e "$CLAIM_FILE" ]] || manifest_add file "$CLAIM_FILE"
  tmp="$(mktemp "${CLAIM_DIR}/.claim.json.XXXXXX")"
  manifest_add file "$tmp"
  printf '{"version": 1, "code_sha256": "%s", "expires_at": %d}\n' "$digest" "$expires" >"$tmp"
  chown root:root "$tmp"
  chmod 0600 "$tmp"
  mv -f -- "$tmp" "$CLAIM_FILE"
  CLAIM_LINK="https://t.me/${BOT_USERNAME}?start=claim_${code}"
  log "claim issued: expires $(date -u -d "@${expires}" +%Y-%m-%dT%H:%M:%SZ) (the code is not logged)"
}

# --------------------------------------------------------------------------- #
# Start and readiness
# --------------------------------------------------------------------------- #
bot_log_path() {
  local dir
  dir="$(env_value "$ENV_FILE" LOG_DIR)"
  printf '%s/bot.log' "${dir:-${APP_DIR}/logs}"
}

file_size() { stat -c %s -- "$1" 2>/dev/null || printf '0'; }

# The bytes of bot.log from $2 on. A log rotated meanwhile (smaller than the
# offset) is read from its start.
log_since() {
  local file="$1" offset="$2"
  [[ -f "$file" ]] || return 0
  [[ "$(file_size "$file")" -ge "$offset" ]] || offset=0
  tail -c "+$((offset + 1))" -- "$file"
}

# Waits for the condition, not for a time: the readiness marker, a failed unit or
# an extra restart end the wait at once; the deadline only bounds it.
wait_ready() {
  local bot_log="$1" offset="$2" base_restarts="$3" deadline=$((SECONDS + READY_TIMEOUT)) state restarts
  while :; do
    # Plain grep, not grep -q: -q stops reading at the first match, tail then dies
    # of SIGPIPE, and pipefail reports the MATCH as a failure.
    if log_since "$bot_log" "$offset" | grep -F 'Run polling for bot @' >/dev/null; then
      break
    fi
    state="$(systemctl show -p ActiveState --value "$UNIT_NAME" 2>/dev/null || true)"
    restarts="$(systemctl show -p NRestarts --value "$UNIT_NAME" 2>/dev/null || printf '0')"
    if [[ "$state" == failed ]] || [[ "${restarts:-0}" -gt "$base_restarts" ]]; then
      say "Бот упал при запуске (ActiveState=${state}, NRestarts=${restarts})."
      log_since "$bot_log" "$offset" | tail -n 40 | redact >>"$INSTALL_LOG"
      journalctl -u "$UNIT_NAME" -n 40 --no-pager 2>/dev/null | redact >>"$INSTALL_LOG" || true
      return 1
    fi
    if [[ "$SECONDS" -ge "$deadline" ]]; then
      say "Бот не дошёл до готовности за ${READY_TIMEOUT} с."
      journalctl -u "$UNIT_NAME" -n 40 --no-pager 2>/dev/null | redact >>"$INSTALL_LOG" || true
      return 1
    fi
    sleep 0.5
  done
  local bad
  bad="$(log_since "$bot_log" "$offset" | grep -E '^[^ ]+ (ERROR|CRITICAL) \[|Traceback \(most recent call last\)' || true)"
  if [[ -n "$bad" ]]; then
    say "Бот запустился, но в логе с момента старта есть ошибки:"
    printf '%s\n' "$bad" | sed -n '1,20p' | redact >&2
    printf '%s\n' "$bad" | redact >>"$INSTALL_LOG"
    return 1
  fi
  say "Бот готов: polling запущен, ошибок в логе нет."
}

start_and_verify() {
  local bot_log offset base_restarts
  bot_log="$(bot_log_path)"
  offset="$(file_size "$bot_log")"
  log "bot.log ${bot_log}, offset ${offset}"
  if systemctl is-active --quiet "$UNIT_NAME"; then
    manifest_add restart "$UNIT_NAME"
  else
    manifest_add started "$UNIT_NAME"
  fi
  run systemctl restart "$UNIT_NAME"
  base_restarts="$(systemctl show -p NRestarts --value "$UNIT_NAME" 2>/dev/null || printf '0')"
  wait_ready "$bot_log" "$offset" "${base_restarts:-0}"
}

print_claim() {
  # The link goes to the terminal only — never to the log.
  printf '\n%s\n' "Откройте эту ссылку в Telegram с аккаунта, который станет администратором." >&2
  printf '%s\n\n' "Ссылка одноразовая и действует $((CLAIM_TTL_SECONDS / 60)) минут:" >&2
  printf '  %s\n\n' "$CLAIM_LINK"
  if command -v qrencode >/dev/null; then
    # Via stdin: an argv would show the code to every local user for a moment.
    printf '%s' "$CLAIM_LINK" | qrencode -t ANSIUTF8 || true
    printf '\n'
  fi
  printf '%s\n' "Если ссылка истекла: sudo bash install.sh --reclaim" >&2
  log "claim link printed to the terminal"
}

# --------------------------------------------------------------------------- #
# Flows
# --------------------------------------------------------------------------- #
fresh_install() {
  read_token
  open_log
  arm_rollback
  apt_install
  resolve_ref
  clone_checkout
  fail_point after_clone
  build_venv
  fail_point after_venv
  write_env
  fail_point after_env
  install_unit
  fail_point after_unit
  issue_claim
  start_and_verify
  fail_point after_start
  commit
  say "Готово: бот @${BOT_USERNAME} установлен (${INSTALL_REF_RESOLVED}) и работает."
  print_claim
  say "Лог установки: ${INSTALL_LOG}"
}

load_existing_bot() {
  local token base
  token="$(env_value "$ENV_FILE" BOT_TOKEN)"
  base="$(env_value "$ENV_FILE" TELEGRAM_API_BASE)"
  [[ -n "$base" ]] && TG_API_BASE="${base%/}"
  valid_api_base "$TG_API_BASE" || die "недопустимый TELEGRAM_API_BASE в ${ENV_FILE}"
  valid_token_format "$token" || die "в ${ENV_FILE} нет корректного BOT_TOKEN"
  BOT_USERNAME="$(telegram_get_me "$token")" || die "Telegram не принимает BOT_TOKEN из ${ENV_FILE}"
}

require_claim_support() {
  [[ -f "${APP_DIR}/${CLAIM_SUPPORT_MARKER}" ]] \
    || die "код в ${APP_DIR} не поддерживает claim (нет ${CLAIM_SUPPORT_MARKER}) — обновите бота или задайте ADMIN_IDS в .env"
}

repair_install() {
  [[ -x "${APP_DIR}/.venv/bin/python" ]] || die "нет ${APP_DIR}/.venv — это не установка install.sh/deploy.sh"
  open_log
  say "Найдена установка в ${APP_DIR}: режим REPAIR (.env и БД не трогаются)."
  arm_rollback
  install_unit
  start_and_verify
  fail_point after_start
  if has_superadmin; then
    commit
    say "Суперадмин уже есть — новая ссылка не нужна. Установка исправна."
  else
    require_claim_support
    load_existing_bot
    issue_claim
    commit
    print_claim
  fi
  say "Лог: ${INSTALL_LOG}"
}

reclaim() {
  [[ -d "${APP_DIR}/.git" && -f "$ENV_FILE" ]] || die "бот не установлен в ${APP_DIR} — запустите install.sh без --reclaim"
  open_log
  if has_superadmin; then
    say "Суперадмин уже есть — claim не выпускается (он был бы инертен)."
    return 0
  fi
  require_claim_support
  load_existing_bot
  arm_rollback
  issue_claim
  commit
  print_claim
}

# --------------------------------------------------------------------------- #
# Relay mode (docs/relay.md#installing-a-relay-with-one-command)
# --------------------------------------------------------------------------- #
preflight_relay() {
  [[ "${EUID}" -eq 0 ]] || die "запустите от root: sudo bash install.sh --relay"
  [[ -r /etc/os-release ]] || die "нет /etc/os-release"
  local id version arch free_mb tool
  id="$(. /etc/os-release && printf '%s' "${ID:-}")"
  version="$(. /etc/os-release && printf '%s' "${VERSION_ID:-}")"
  [[ "$id" == ubuntu && "$version" == 24.04 ]] \
    || die "поддерживается только Ubuntu 24.04 (найдено: ${id:-?} ${version:-?})"
  arch="$(uname -m)"
  [[ "$arch" == x86_64 || "$arch" == aarch64 ]] || die "архитектура ${arch} не поддерживается (нужна x86_64 или aarch64)"
  [[ -d /run/systemd/system ]] && command -v systemctl >/dev/null \
    || die "нужен systemd как init (контейнеры без systemd не поддерживаются)"
  for tool in curl python3 sha256sum flock install mktemp tac cmp sed ip ss getent sshd sysctl; do
    command -v "$tool" >/dev/null || die "нет команды ${tool}"
  done
  free_mb="$(df -Pm -- /opt 2>/dev/null | awk 'NR == 2 {print $4}')"
  [[ "${free_mb:-0}" -ge "$RELAY_MIN_FREE_MB" ]] || die "мало места: ${free_mb:-?} МБ, нужно ≥ ${RELAY_MIN_FREE_MB} МБ"
  # No Telegram here: a relay never talks to the Bot API. Only the repository.
  case "${INSTALL_REPO:-$DEFAULT_REPO_URL}" in
    file://*) ;;
    *) check_reachable "https://github.com" ;;
  esac
}

# The pairing code -> PAIR_* (validated). One line from stdin; on a terminal it
# is asked for (hidden). The token itself never leaves python: only its sha256.
read_pairing_code() {
  local code="" attempt parsed
  for attempt in 1 2 3; do
    if [[ -t 0 ]]; then
      printf 'Pairing-код из бота (Мастер настройки → Relay → Добавить; ввод скрыт): ' >&2
      IFS= read -rs code || { printf '\n' >&2; die "pairing-код не введён"; }
      printf '\n' >&2
    else
      IFS= read -r code || true
    fi
    code="${code//[[:space:]]/}"
    if parsed="$(printf '%s\n' "$code" | parse_pairing_code)"; then
      code=""
      eval "$parsed"
      say "Pairing-код принят: цель ${PAIR_TARGET}, tcp ${PAIR_TCP}, udp ${PAIR_UDP}, действует до $(date -u -d "@${PAIR_EXP}" '+%Y-%m-%d %H:%M UTC')"
      return 0
    fi
    [[ -t 0 ]] || break
  done
  code=""
  die "pairing-код не принят — выпустите новый в боте (Мастер настройки → Relay → Добавить)"
}

# stdin: the code. stdout: PAIR_*=<value> lines, every value matched against a
# strict pattern (eval'ed by the caller). The same format as services/relay_pairing.py.
parse_pairing_code() {
  python3 -I - "$RELAY_CODE_SKEW" 3<&0 <<'PY'
import base64, hashlib, json, os, re, struct, sys, time
skew = int(sys.argv[1])
raw = os.fdopen(3).readline().strip()
def fail(why):
    print(f"pairing-код: {why}", file=sys.stderr)
    sys.exit(1)
if not re.fullmatch(r"[A-Za-z0-9_-]{40,4096}", raw):
    fail("это не pairing-код (ожидается одна строка base64url)")
try:
    data = json.loads(base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4)).decode("utf-8"))
except (ValueError, UnicodeDecodeError):
    fail("не декодируется")
if not isinstance(data, dict) or set(data) != {"v", "target_host", "ports", "main_pubkey", "one_time_token", "exp"}:
    fail("неизвестный формат (поля)")
if data["v"] != 1:
    fail(f"версия {data['v']!r} не поддерживается этим установщиком")
host = data["target_host"]
label = re.compile(r"(?!-)[A-Za-z0-9-]{1,63}(?<!-)")
if (not isinstance(host, str) or len(host) > 253 or "." not in host
        or not all(label.fullmatch(x) for x in host.split(".")) or host.split(".")[-1].isdigit()):
    fail("target_host — не DNS-имя")
ports = data["ports"]
if not isinstance(ports, list) or not 2 <= len(ports) <= 16 or len(set(map(str, ports))) != len(ports):
    fail("ports: нужен список вида [\"443/tcp\", \"443/udp\"]")
tcp, udp = [], []
for item in ports:
    m = re.fullmatch(r"([1-9][0-9]{0,4})/(tcp|udp)", item) if isinstance(item, str) else None
    if m is None or int(m[1]) > 65535:
        fail(f"ports: {item!r}")
    (tcp if m[2] == "tcp" else udp).append(int(m[1]))
if not tcp or not udp or len(tcp) > 8 or len(udp) > 8:
    fail("ports: нужен хотя бы один tcp и один udp (не больше 8 каждого)")
key = data["main_pubkey"]
m = re.fullmatch(r"ssh-ed25519 ([A-Za-z0-9+/]{68})(?: [!-~]{1,64})?", key) if isinstance(key, str) else None
if m is None:
    fail("main_pubkey — не ssh-ed25519")
blob = base64.b64decode(m[1])
if len(blob) != 51 or blob[:4] != struct.pack(">I", 11) or blob[4:15] != b"ssh-ed25519" or blob[15:19] != struct.pack(">I", 32):
    fail("main_pubkey повреждён")
token = data["one_time_token"]
if not isinstance(token, str) or not re.fullmatch(r"[A-Za-z0-9_-]{43}", token):
    fail("one_time_token")
exp = data["exp"]
now = int(time.time())
if not isinstance(exp, int) or isinstance(exp, bool):
    fail("exp")
if now > exp + skew:
    fail("истёк — выпустите новый в боте")
if exp > now + 7200:
    fail("exp слишком далеко в будущем (часы этого хоста?)")
print(f"PAIR_TARGET={host}")
print(f"PAIR_TCP={','.join(map(str, sorted(tcp)))}")
print(f"PAIR_UDP={','.join(map(str, sorted(udp)))}")
print(f"PAIR_KEY_BLOB={m[1]}")
print(f"PAIR_TOKEN_SHA256={hashlib.sha256(token.encode('ascii')).hexdigest()}")
print(f"PAIR_EXP={exp}")
PY
}

# TCP ports sshd listens on (or systemd holds for ssh.socket), one per line.
sshd_ports() {
  {
    ss -Hltnp 2>/dev/null | awk '/"sshd/ {n = split($4, a, ":"); print a[n]}'
    systemctl show -p Listen ssh.socket 2>/dev/null | grep -oE ':[0-9]{1,5} \(Stream\)' | tr -dc '0-9\n'
  } | grep -E '^[0-9]+$' | sort -n -u || true
}

# The first address the target resolves to (empty when it does not).
resolve_target() {
  getent ahostsv4 "$1" 2>/dev/null | awk '$1 ~ /^[0-9.]+$/ {print $1; exit}' || true
}

# Root may log in with a key, judged by `sshd -T` for a connection from the main
# server (Match blocks included); sets AUTH_KEYS. sshd_config itself is never touched.
relay_check_ssh() {
  local target_ip="$1" out verdict
  if ! out="$(sshd -T -C "user=root,host=${PAIR_TARGET},addr=${target_ip}" 2>&1)"; then
    if [[ "$out" == *"privilege separation directory"* ]]; then
      install -d -m 0755 /run/sshd   # what ssh.service's RuntimeDirectory= creates
      out="$(sshd -T -C "user=root,host=${PAIR_TARGET},addr=${target_ip}" 2>&1)" \
        || die "sshd -T не отработал: ${out}"
    else
      die "sshd -T не отработал: ${out}"
    fi
  fi
  verdict="$(printf '%s\n' "$out" | ssh_login_verdict "$(id -Gn root 2>/dev/null || echo root)")" || die "$verdict"
  AUTH_KEYS="$verdict"
}

# stdin: `sshd -T` output; $1: root's groups. stdout: root's authorized_keys path,
# or (exit 1) why the bot's key could not log in.
ssh_login_verdict() {
  python3 -I -c '
import fnmatch, re, sys
groups = sys.argv[1].split()
conf = {}
for line in sys.stdin:
    key, _, value = line.strip().partition(" ")
    conf.setdefault(key.lower(), []).append(value)
def first(key):
    return (conf.get(key) or [""])[0]
def words(key):
    return " ".join(conf.get(key, [])).split()
def users_match(patterns):
    return any(fnmatch.fnmatchcase("root", p.split("@", 1)[0]) for p in patterns)
def groups_match(patterns):
    return any(fnmatch.fnmatchcase(g, p) for g in groups for p in patterns)
def no(why):
    print(why)
    sys.exit(1)
if first("pubkeyauthentication") != "yes":
    no("в sshd выключен вход по ключу (PubkeyAuthentication) — бот не сможет управлять relay")
if first("permitrootlogin") not in ("yes", "prohibit-password", "without-password", "forced-commands-only"):
    no("sshd не пускает root (PermitRootLogin no) — разрешите вход по ключу: prohibit-password или forced-commands-only")
if users_match(words("denyusers")):
    no("root в DenyUsers — бот не сможет войти")
if words("allowusers") and not users_match(words("allowusers")):
    no("root нет в AllowUsers — бот не сможет войти")
if groups_match(words("denygroups")):
    no("группа root в DenyGroups — бот не сможет войти")
if words("allowgroups") and not groups_match(words("allowgroups")):
    no("ни одной группы root нет в AllowGroups — бот не сможет войти")
files = words("authorizedkeysfile")
if not files or files[0] == "none":
    no("AuthorizedKeysFile не задан (none) — некуда добавить ключ бота")
path = re.sub(r"%(.)", lambda m: {"%": "%", "h": "/root", "u": "root", "U": "0"}.get(m[1], "\x00"), files[0])
if not path.startswith("/"):
    path = "/root/" + path
if "\x00" in path or ".." in path or not re.fullmatch(r"/[A-Za-z0-9._/-]+", path):
    no(f"непонятный AuthorizedKeysFile: {files[0]}")
print(path)
' "$1"
}

relay_preconditions() {
  local target_ip clash p
  target_ip="$(resolve_target "$PAIR_TARGET")"
  [[ -n "$target_ip" ]] || die "${PAIR_TARGET} не резолвится в IPv4 на этом хосте — проверьте DNS"
  relay_check_ssh "$target_ip"
  if [[ -r /etc/ufw/ufw.conf ]] && grep -qE '^[[:space:]]*ENABLED[[:space:]]*=[[:space:]]*yes' /etc/ufw/ufw.conf; then
    die "ufw включён: его forward-политика DROP отбросит пересылаемый трафик. Выключите: ufw disable && systemctl mask ufw.service (docs/relay.md)"
  fi
  clash=""
  for p in ${PAIR_TCP//,/ }; do
    if grep -qx -- "$p" <<< "$(sshd_ports)"; then clash+=" ${p}"; fi
  done
  [[ -z "$clash" ]] || die "sshd слушает TCP${clash} — этот порт нельзя пересылать (бот потерял бы доступ)"
  [[ -n "$(sshd_ports)" ]] || die "не найден порт sshd — бот не сможет подключиться"
  if systemctl is-enabled --quiet nftables.service 2>/dev/null && grep -qs 'dnat to' /etc/nftables.conf; then
    warn "/etc/nftables.conf (nftables.service включён) содержит DNAT: при загрузке он добавит свой — проверьте, что там нет 443"
  fi
}

relay_detect_state() {
  RELAY_EXISTING_CHECKOUT=0
  if [[ -e "$UNIT_PATH" ]] || systemctl cat "$UNIT_NAME" >/dev/null 2>&1; then
    die "это основной сервер (${UNIT_NAME} есть) — relay ставится на отдельный хост"
  fi
  if [[ -e "$APP_DIR" ]]; then
    if [[ -d "${APP_DIR}/.git" && "$(env_value "$ENV_FILE" NODE_ROLE)" == relay ]]; then
      RELAY_EXISTING_CHECKOUT=1
    else
      die "${APP_DIR} есть, но это не checkout relay (NODE_ROLE=relay) — разберите вручную"
    fi
  fi
  if [[ -f "${RELAY_STATE_DIR}/install.json" ]] \
      && python3 -I -c 'import json,sys; sys.exit(0 if json.load(open(sys.argv[1])).get("installer") == "vpn-relay" else 1)' \
        "${RELAY_STATE_DIR}/install.json" 2>/dev/null; then
    STATE=repair
  elif [[ "$RELAY_EXISTING_CHECKOUT" == 1 || -e "$RELAY_LEGACY_NFT" || -e "${SYSTEMD_DIR}/vpn-relay.service" ]] \
      || nft list table ip vpnrelay >/dev/null 2>&1; then
    STATE=adopt
  else
    STATE=fresh
  fi
}

relay_apt_install() {
  export DEBIAN_FRONTEND=noninteractive
  local pkg missing=()
  for pkg in "${APT_RELAY_PACKAGES[@]}"; do
    if [[ "$(dpkg-query -W -f='${Status}' "$pkg" 2>/dev/null || true)" != *"install ok installed"* ]]; then
      missing+=("$pkg")
      manifest_add apt "$pkg"
    fi
  done
  say "Пакеты: ${missing[*]:-всё уже установлено}"
  [[ ${#missing[@]} -gt 0 ]] || return 0
  run apt-get -o DPkg::Lock::Timeout=300 update -qq
  run apt-get -o DPkg::Lock::Timeout=300 install -y -qq --no-install-recommends "${APT_RELAY_PACKAGES[@]}"
}

relay_require_checkout_files() {
  local f
  for f in "$RELAY_SUPPORT_MARKER" scripts/vpn-relay-apply deploy/relay/relay.env.example "${RELAY_UNITS[@]/#/deploy/relay/}"; do
    [[ -f "${APP_DIR}/${f}" ]] || die "в checkout нет ${f} (ref без relay-установщика? задайте более новый INSTALL_REF)"
  done
}

# Fresh: a new checkout of INSTALL_REF. An existing relay checkout moves to
# INSTALL_REF only forward (never backwards past a newer update), recorded.
relay_checkout() {
  local head target
  if [[ "$RELAY_EXISTING_CHECKOUT" == 0 ]]; then
    resolve_ref
    clone_repo
    RELAY_CREATED_APP_DIR=1
  elif [[ -n "${INSTALL_REF:-}" ]]; then
    resolve_ref
    head="$(git -C "$APP_DIR" rev-parse HEAD)"
    run git -C "$APP_DIR" fetch --quiet origin -- "$INSTALL_REF_RESOLVED" || true
    target="$(git -C "$APP_DIR" rev-parse --verify --quiet "${INSTALL_REF_RESOLVED}^{commit}" 2>/dev/null \
      || git -C "$APP_DIR" rev-parse --verify --quiet "FETCH_HEAD^{commit}" 2>/dev/null || true)"
    if [[ "$target" =~ ^[0-9a-f]{40}$ && "$target" != "$head" ]] \
        && git -C "$APP_DIR" merge-base --is-ancestor "$head" "$target" 2>/dev/null; then
      manifest_add gitref "$APP_DIR" "$head"
      run git -C "$APP_DIR" -c advice.detachedHead=false checkout --quiet --detach "$target"
    else
      log "checkout stays at ${head} (INSTALL_REF ${INSTALL_REF_RESOLVED} is not ahead of it)"
    fi
  fi
  relay_require_checkout_files
  log "checkout: $(git -C "$APP_DIR" rev-parse HEAD)"
}

# A copy of an existing file into the adoption backup, recorded as `adopted`.
relay_adopt_file() {
  local path="$1" copy
  [[ -e "$path" ]] || return 0
  copy="${RELAY_ADOPT_DIR}/files${path}"
  install -d -m 0700 "$(dirname "$copy")"
  cp -a -- "$path" "$copy"
  manifest_add adopted "$path" "$copy"
}

# Everything a relay already has goes to /var/backups/vpn-relay/adopt-<ts>/ first:
# the live tables (as nft lists them), the hand-made /etc/vpn-relay.nft (then moved
# away, so nothing loads it again), the unit, the sysctl file, the helpers, .env.
relay_backup_existing() {
  # Files vpn-relay-apply writes itself: gone again on a rollback when they are new.
  [[ -e "$RELAY_SYSCTL_FILE" ]] || manifest_add file "$RELAY_SYSCTL_FILE"
  [[ -e "${RELAY_STATE_DIR}/upstream.resolved" ]] || manifest_add file "${RELAY_STATE_DIR}/upstream.resolved"
  if [[ "$STATE" == fresh ]]; then
    # Nothing to keep; the records make a rollback delete whatever got applied.
    relay_record_tables
    return 0
  fi
  RELAY_ADOPT_DIR="${RELAY_BACKUP_ROOT}/adopt-${TS}"
  install -d -m 0700 "$RELAY_BACKUP_ROOT" "$RELAY_ADOPT_DIR"
  relay_record_tables
  relay_adopt_file "$RELAY_LEGACY_NFT"
  relay_adopt_file "$RELAY_SYSCTL_FILE"
  relay_adopt_file "${SBIN_DIR}/vpn-relay-apply"
  relay_adopt_file "${SBIN_DIR}/vpn-relay-agent"
  local unit
  for unit in "${RELAY_UNITS[@]}"; do relay_adopt_file "${SYSTEMD_DIR}/${unit}"; done
  [[ "$RELAY_EXISTING_CHECKOUT" == 1 ]] && relay_adopt_file "$ENV_FILE"
  [[ "$STATE" == repair ]] && relay_adopt_file "${RELAY_STATE_DIR}/pairing.json"
  if [[ -e "$RELAY_LEGACY_NFT" ]]; then
    rm -f -- "$RELAY_LEGACY_NFT"
    log "moved ${RELAY_LEGACY_NFT} to ${RELAY_ADOPT_DIR}/files${RELAY_LEGACY_NFT} — nothing loads it any more"
  fi
  say "Найдена существующая установка relay (${STATE}): копия в ${RELAY_ADOPT_DIR}"
}

relay_record_sysctls() {
  local key value
  RELAY_FORWARD_BEFORE="$(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo 0)"
  for key in net.ipv4.ip_forward net.netfilter.nf_conntrack_max net.netfilter.nf_conntrack_tcp_timeout_established; do
    value="$(sysctl -n "$key" 2>/dev/null || true)"
    if [[ "$value" =~ ^[0-9]+$ ]]; then manifest_add sysctl "$key" "$value"; fi
  done
}

# .env: from the template (fresh) or the existing relay .env, with the target NAME,
# the ports, NODE_ROLE=relay; a new relay also gets SSH_PORT = where sshd listens
# now (a later redeploy must not move ssh away from the bot) and the input filter off.
relay_write_env() {
  local base tmp ssh_port filter=""
  if [[ "$RELAY_EXISTING_CHECKOUT" == 1 ]]; then base="$ENV_FILE"; else base="${APP_DIR}/deploy/relay/relay.env.example"; fi
  ssh_port="$(sshd_ports | head -n1)"
  [[ "$RELAY_EXISTING_CHECKOUT" == 1 ]] || filter=off
  [[ -n "$(env_value "$ENV_FILE" SSH_PORT)" ]] && ssh_port=""
  tmp="$(mktemp "${APP_DIR}/.env.XXXXXX")"
  manifest_add file "$tmp"
  [[ -e "$ENV_FILE" ]] || manifest_add file "$ENV_FILE"
  python3 -I - "$base" "$tmp" "$PAIR_TARGET" "$PAIR_TCP" "$PAIR_UDP" "$ssh_port" "$filter" <<'PY'
import os, re, sys
base, target, host, tcp, udp, ssh_port, filt = sys.argv[1:8]
lines = open(base, encoding="utf-8").read().splitlines()
values = {"NODE_ROLE": "relay", "RELAY_UPSTREAM_IPV4": None, "RELAY_UPSTREAM_HOST": host,
          "RELAY_FORWARD_TCP_PORTS": tcp, "RELAY_FORWARD_UDP_PORTS": udp}
if ssh_port:
    values["SSH_PORT"] = ssh_port
if filt:
    values["RELAY_INPUT_FILTER"] = filt
for key, value in values.items():
    pattern = re.compile(rf"^\s*(?:export\s+)?{key}\s*=")
    hits = [i for i, line in enumerate(lines) if pattern.match(line)]
    if value is None:
        lines = [line for i, line in enumerate(lines) if i not in hits]
    elif hits:
        lines[hits[-1]] = f"{key}={value}"
        lines = [line for i, line in enumerate(lines) if i not in hits[:-1]]
    else:
        lines.append(f"{key}={value}")
fd = os.open(target, os.O_WRONLY | os.O_TRUNC)
with os.fdopen(fd, "w", encoding="utf-8") as fh:
    fh.write("\n".join(lines) + "\n")
PY
  chown root:root "$tmp"
  chmod 0600 "$tmp"
  mv -f -- "$tmp" "$ENV_FILE"
  log "wrote ${ENV_FILE} (target ${PAIR_TARGET}, tcp ${PAIR_TCP}, udp ${PAIR_UDP})"
}

# /etc/vpn-relay/pairing.json: the token's hash and the code's expiry — what the
# agent's `hello` checks. A re-pair replaces it (the old one is in the backup).
relay_write_pairing() {
  local file="${RELAY_STATE_DIR}/pairing.json" tmp
  if [[ ! -d "$RELAY_STATE_DIR" ]]; then
    manifest_add dir "$RELAY_STATE_DIR"
    install -d -o root -g root -m 0755 "$RELAY_STATE_DIR"
  fi
  [[ -e "$file" ]] || manifest_add file "$file"
  tmp="$(mktemp "${RELAY_STATE_DIR}/.pairing.json.XXXXXX")"
  manifest_add file "$tmp"
  printf '{"v": 1, "token_sha256": "%s", "exp": %d, "paired_at": null, "main_key": "ssh-ed25519 %s", "target_host": "%s", "created_at": %d}\n' \
    "$PAIR_TOKEN_SHA256" "$PAIR_EXP" "$PAIR_KEY_BLOB" "$PAIR_TARGET" "$(date +%s)" >"$tmp"
  chown root:root "$tmp"
  chmod 0600 "$tmp"
  mv -f -- "$tmp" "$file"
  log "wrote ${file} (the token's sha256 only)"
}

relay_install_files() {
  local unit
  install_file "${APP_DIR}/scripts/vpn-relay-apply" "${SBIN_DIR}/vpn-relay-apply" 0755
  install_file "${APP_DIR}/scripts/vpn-relay-agent" "${SBIN_DIR}/vpn-relay-agent" 0755
  for unit in "${RELAY_UNITS[@]}"; do
    install_file "${APP_DIR}/deploy/relay/${unit}" "${SYSTEMD_DIR}/${unit}" 0644
  done
}

# ONE line for the bot's key: restrict + the agent as the forced command. Any other
# line with the same key goes (an unrestricted copy would be a root shell), every
# other line stays byte-identical.
relay_authorize_key() {
  local dir tmp backup
  dir="$(dirname "$AUTH_KEYS")"
  if [[ ! -d "$dir" ]]; then
    manifest_add dir "$dir"
    install -d -o root -g root -m 0700 "$dir"
  fi
  tmp="$(mktemp "${AUTH_KEYS}.vpn-bot-install.XXXXXX")"
  manifest_add file "$tmp"
  python3 -I - "$AUTH_KEYS" "$PAIR_KEY_BLOB" "$RELAY_AGENT_COMMAND" >"$tmp" <<'PY'
import sys
path, blob, agent = sys.argv[1:4]
try:
    lines = open(path, encoding="utf-8").read().splitlines(keepends=True)
except FileNotFoundError:
    lines = []
marker = f'command="{agent}"'
kept = [l for l in lines if marker not in l and f"ssh-ed25519 {blob}" not in l]
if kept and not kept[-1].endswith("\n"):
    kept[-1] += "\n"
removed = len(lines) - len(kept)
if removed:
    print(f"authorized_keys: {removed} old line(s) of this key replaced", file=sys.stderr)
sys.stdout.write("".join(kept) + f'restrict,{marker} ssh-ed25519 {blob} vpn-relay-agent\n')
PY
  if [[ -e "$AUTH_KEYS" ]]; then
    if cmp -s -- "$tmp" "$AUTH_KEYS"; then rm -f -- "$tmp"; log "unchanged: ${AUTH_KEYS}"; return 0; fi
    backup="${AUTH_KEYS}.vpn-bot-install.${TS}.bak"
    manifest_add replaced "$AUTH_KEYS" "$backup"
    cp -a -- "$AUTH_KEYS" "$backup"
  else
    manifest_add file "$AUTH_KEYS"
  fi
  chown root:root "$tmp"
  chmod 0600 "$tmp"
  mv -f -- "$tmp" "$AUTH_KEYS"
  log "authorized the bot's key in ${AUTH_KEYS} (forced command ${RELAY_AGENT_COMMAND})"
}

# vpn-relay.service applies the table (one atomic nft -f) and the sysctls; the
# timer re-resolves the name. A RUNNING unit (the hand-made one too, once
# daemon-reload loaded ours) is RELOADED — ExecReload is the same atomic apply — never
# restarted: a restart runs ExecStop first and deletes the table, a moment with no
# DNAT. The rollback restores the table from the nft record (its dump) in one
# transaction too, so no unit is restarted on the way back either.
relay_start() {
  local unit="vpn-relay.service"
  run systemctl daemon-reload
  if ! systemctl is-enabled --quiet "$unit" 2>/dev/null; then manifest_add enabled "$unit"; fi
  if ! systemctl is-enabled --quiet vpn-relay-resolve.timer 2>/dev/null; then manifest_add enabled vpn-relay-resolve.timer; fi
  run systemctl enable "$unit" vpn-relay-resolve.timer
  if systemctl is-active --quiet "$unit"; then
    run systemctl reload "$unit"
  else
    manifest_add started "$unit"
    run systemctl start "$unit"
  fi
  if ! systemctl is-active --quiet vpn-relay-resolve.timer; then manifest_add started vpn-relay-resolve.timer; fi
  run systemctl restart vpn-relay-resolve.timer
}

# The live tables, recorded for the rollback: a dump (restored in one transaction)
# or "-" (deleted). Dumps go to the adoption backup dir when there is one.
relay_record_tables() {
  local family table dump dir="${RELAY_ADOPT_DIR:-${RELAY_VAR_DIR}}"
  for family in ip inet; do
    table=vpnrelay; [[ "$family" == inet ]] && table=vpnrelay_input
    if nft list table "$family" "$table" >/dev/null 2>&1; then
      if [[ ! -d "$dir" ]]; then manifest_add dir "$dir"; install -d -m 0700 "$dir"; fi
      dump="${dir}/${family}-${table}.${TS}.nft"
      nft list table "$family" "$table" >"$dump"
      manifest_add nft "$family" "$table" "$dump"
    else
      manifest_add nft "$family" "$table" -
    fi
  done
}

# check + exactly ONE DNAT rule per forwarded port in the whole ruleset + the timer.
relay_verify() {
  local out rc p n ruleset
  set +e
  out="$("${SBIN_DIR}/vpn-relay-apply" check 2>&1)"
  rc=$?
  set -e
  printf '%s\n' "$out" | redact >>"$INSTALL_LOG"
  case "$rc" in
    0) say "Проверка relay: OK" ;;
    13 | 14) warn "основной сервер (${PAIR_TARGET}) не ответил с relay на forwarded TCP — бот проверит путь сам при подключении" ;;
    *) say "vpn-relay-apply check: exit ${rc}"; printf '%s\n' "$out" | tail -n 15 | redact >&2; return 1 ;;
  esac
  ruleset="$(nft list ruleset 2>/dev/null)"
  for p in ${PAIR_TCP//,/ }; do
    n="$(grep -cE "tcp dport ${p} .*dnat (ip )?to" <<< "$ruleset" || true)"
    [[ "$n" == 1 ]] || { say "TCP ${p}: ${n} DNAT-правил в ruleset, ожидалось ровно 1"; return 1; }
  done
  for p in ${PAIR_UDP//,/ }; do
    n="$(grep -cE "udp dport ${p} .*dnat (ip )?to" <<< "$ruleset" || true)"
    [[ "$n" == 1 ]] || { say "UDP ${p}: ${n} DNAT-правил в ruleset, ожидалось ровно 1"; return 1; }
  done
  systemctl is-active --quiet vpn-relay-resolve.timer || { say "vpn-relay-resolve.timer не активен"; return 1; }
}

# /etc/vpn-relay/install.json — what uninstall needs to undo this install.
relay_write_install_record() {
  local file="${RELAY_STATE_DIR}/install.json" prev_created=0 prev_forward="" prev_backup=""
  if [[ -f "$file" ]]; then
    prev_created="$(python3 -I -c 'import json,sys; print(1 if json.load(open(sys.argv[1])).get("created_app_dir") else 0)' "$file" 2>/dev/null || echo 0)"
    prev_forward="$(python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1])).get("ip_forward_before", ""))' "$file" 2>/dev/null || true)"
    prev_backup="$(python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1])).get("adoption_backup") or "")' "$file" 2>/dev/null || true)"
  else
    manifest_add file "$file"
  fi
  [[ "$RELAY_CREATED_APP_DIR" == 1 ]] && prev_created=1
  [[ -n "$prev_forward" ]] || prev_forward="${RELAY_FORWARD_BEFORE:-0}"
  [[ "$STATE" == adopt ]] && prev_backup="$RELAY_ADOPT_DIR"
  python3 -I - "$file" "$prev_created" "$prev_forward" "$AUTH_KEYS" "$prev_backup" "$(git -C "$APP_DIR" rev-parse HEAD)" <<'PY'
import json, os, sys, time
path, created, forward, keys, backup, ref = sys.argv[1:7]
data = {"installer": "vpn-relay", "v": 1, "installed_at": int(time.time()), "ref": ref,
        "created_app_dir": created == "1", "ip_forward_before": "1" if forward == "1" else "0",
        "authorized_keys": keys, "adoption_backup": backup or None}
tmp = path + ".tmp"
with open(tmp, "w", encoding="utf-8") as fh:
    json.dump(data, fh, indent=2, sort_keys=True)
    fh.write("\n")
os.chmod(tmp, 0o600)
os.replace(tmp, path)
PY
}

relay_report() {
  local target_ip src port
  target_ip="$(resolve_target "$PAIR_TARGET")"
  src="$(ip -4 route get "${target_ip:-1.1.1.1}" 2>/dev/null | sed -n 's/.* src \([0-9.]*\).*/\1/p' | head -n1)"
  port="$(sshd_ports | head -n1)"
  printf '\n%s\n' "Relay установлен: TCP ${PAIR_TCP} и UDP ${PAIR_UDP} → ${PAIR_TARGET}." >&2
  printf '%s\n\n' "Вернитесь в бот и нажмите «Подключить», отправив адрес этого relay:" >&2
  if [[ -n "$src" ]]; then printf '  %s\n\n' "${src}:${port:-22}"; fi
  if [[ -z "$src" ]] || python3 -I -c 'import ipaddress,sys; sys.exit(0 if ipaddress.ip_address(sys.argv[1]).is_private else 1)' "$src" 2>/dev/null; then
    printf '%s\n' "(адрес выше внутренний — этот хост за NAT: отправьте его публичный IPv4 или DNS-имя и ssh-порт ${port:-22})" >&2
  fi
  printf '%s\n' "Pairing-код действует до $(date -u -d "@${PAIR_EXP}" '+%H:%M UTC'); бот завершит подключение по SSH." >&2
  log "relay installed (${STATE}); address hint ${src:-?}:${port:-?}"
}

relay_install() {
  MODE=relay
  preflight_relay
  read_pairing_code
  acquire_lock
  relay_detect_state
  relay_preconditions
  open_log
  say "Режим relay: ${STATE} (лог ${INSTALL_LOG})"
  arm_rollback
  relay_apt_install
  relay_checkout
  fail_point after_relay_clone
  relay_backup_existing
  relay_record_sysctls
  relay_write_env
  relay_write_pairing
  relay_install_files
  relay_authorize_key
  fail_point after_relay_files
  relay_start
  relay_verify
  fail_point after_relay_start
  relay_write_install_record
  commit
  relay_report
  say "Лог установки: ${INSTALL_LOG}"
}

# What the agent's `update` runs from the NEW checkout: the helpers and units
# reinstalled from it, vpn-relay restarted and checked; .env, the pairing and the
# key are not touched. Any failure rolls the files back (the agent then moves the
# checkout back).
relay_update() {
  MODE=relay
  [[ "${EUID}" -eq 0 ]] || die "запустите от root"
  acquire_lock
  [[ -f "${RELAY_STATE_DIR}/install.json" && -f "$ENV_FILE" ]] || die "это не relay, установленный install.sh"
  [[ "$(env_value "$ENV_FILE" NODE_ROLE)" == relay ]] || die "в ${ENV_FILE} нет NODE_ROLE=relay"
  STATE=repair
  PAIR_TCP="$(env_value "$ENV_FILE" RELAY_FORWARD_TCP_PORTS)"; PAIR_TCP="${PAIR_TCP:-443}"
  PAIR_UDP="$(env_value "$ENV_FILE" RELAY_FORWARD_UDP_PORTS)"; PAIR_UDP="${PAIR_UDP:-443}"
  PAIR_TARGET="$(env_value "$ENV_FILE" RELAY_UPSTREAM_HOST)"
  open_log
  arm_rollback
  relay_require_checkout_files
  relay_record_tables
  relay_install_files
  relay_start
  relay_verify
  commit
  say "Relay обновлён до $(git -C "$APP_DIR" describe --tags --always 2>/dev/null || echo '?')"
}

usage() {
  sed -n '3,16p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
}

main() {
  local reclaim_only=0 action=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --reclaim) reclaim_only=1 ;;
      --relay) action=relay ;;
      --relay-update) action=relay-update ;;
      -h | --help) usage; exit 0 ;;
      *) printf 'неизвестный аргумент: %s (см. --help)\n' "$1" >&2; exit 2 ;;
    esac
    shift
  done
  case "$action" in
    relay) relay_install; exit 0 ;;
    relay-update) relay_update; exit 0 ;;
  esac
  if [[ "$reclaim_only" == 1 ]]; then
    preflight
    acquire_lock
    reclaim
    exit 0
  fi
  ask_mode
  if [[ "$MODE" == relay ]]; then
    relay_install
    exit 0
  fi
  preflight
  acquire_lock
  require_no_deploy_running
  detect_state
  case "$STATE" in
    fresh) fresh_install ;;
    repair) repair_install ;;
    conflict) die "найдены следы другой установки (${APP_DIR} без .env или ${UNIT_PATH}) — разберите их вручную" ;;
  esac
}

# Test seam, mirroring DEPLOY_SELFTEST in scripts/deploy.sh: define everything,
# do nothing. tests/test_install_script.py drives the functions one by one.
if [[ "${INSTALL_SELFTEST:-0}" == "1" ]]; then return 0 2>/dev/null || exit 0; fi

main "$@"
