#!/usr/bin/env bash
#
# scripts/install.sh — install the VPN Telegram bot on a fresh Ubuntu 24.04 host
# with ONE command; everything after that happens in Telegram.
#
#   sudo bash install.sh            install (or repair an existing install)
#   sudo bash install.sh --reclaim  issue a new superadmin claim link, nothing else
#
# Get it from a GitHub release together with SHA256SUMS and verify it first
# (docs/install.md); never pipe it from a branch into bash.
#
# --------------------------------------------------------------------------- #
# WHAT IT DOES (mode "main server")
# --------------------------------------------------------------------------- #
#   1. Read-only preconditions: root, Ubuntu 24.04, x86_64|aarch64, systemd,
#      free space, reachability of github.com, pypi.org and the Bot API.
#   2. Asks the mode: 1) main server  2) relay. Relay is not in this version: it
#      says so and exits 2 having changed NOTHING on disk.
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
#                             after_unit, after_start). NEVER set it otherwise.
#
# EXIT CODES: 0 done · 1 failed (and rolled back) · 2 relay mode (not available).

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

APT_PACKAGES=(git python3-venv ca-certificates curl)
APT_OPTIONAL_PACKAGES=(qrencode)

TS="$(date -u +%Y%m%dT%H%M%SZ)"
INSTALL_LOG=""
MANIFEST=""
ROLLING_BACK=0
COMMITTED=0
BOT_TOKEN=""
BOT_USERNAME=""
CLAIM_LINK=""
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
    -e 's/claim_[A-Za-z0-9_-]{8,}/claim_<redacted>/g'
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

die() {
  say "ОШИБКА: $*"
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
manifest_add() {
  [[ -n "$MANIFEST" ]] || die "internal: manifest is not open"
  local IFS=$'\t'
  printf '%s\n' "$*" >>"$MANIFEST"
}

# Rollback removes only paths it could have created. Anything else in a manifest
# (an edited file, a bug) is refused rather than deleted.
path_is_ours() {
  local p="${1-}"
  [[ -n "$p" && "$p" == /* && "$p" != *..* && "$p" != */ ]] || return 1
  case "$p" in
    "$APP_DIR" | "$APP_DIR"/* | "$CLAIM_DIR" | "$CLAIM_DIR"/* | "$UNIT_PATH" | "$UNIT_PATH".* | \
      "$DB_PERMS_HELPER" | "$DB_PERMS_HELPER".*) return 0 ;;
  esac
  return 1
}

rollback() {
  [[ "$ROLLING_BACK" == 0 ]] || return 0
  ROLLING_BACK=1
  set +e
  trap - ERR
  [[ -n "$MANIFEST" && -f "$MANIFEST" ]] || return 0
  say "Откат по manifest ${MANIFEST}…"
  local kind a b restarts=()
  while IFS=$'\t' read -r kind a b; do
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
      *) log "rollback: unknown record '${kind}' ignored" ;;
    esac
  done < <(tac "$MANIFEST")
  systemctl daemon-reload >>"$INSTALL_LOG" 2>&1
  systemctl reset-failed "$UNIT_NAME" >>"$INSTALL_LOG" 2>&1
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

clone_checkout() {
  local repo="${INSTALL_REPO:-$DEFAULT_REPO_URL}" ref="$INSTALL_REF_RESOLVED"
  say "Клонирую ${repo} @ ${ref}…"
  manifest_add dir "$APP_DIR"
  run git clone --quiet --no-checkout -- "$repo" "$APP_DIR"
  if ! run git -C "$APP_DIR" -c advice.detachedHead=false checkout --quiet --detach "${ref}^{commit}"; then
    run git -C "$APP_DIR" fetch --quiet origin -- "$ref"
    run git -C "$APP_DIR" -c advice.detachedHead=false checkout --quiet --detach FETCH_HEAD
  fi
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
  install_file "${APP_DIR}/scripts/vpn-bot-db-perms" "$DB_PERMS_HELPER" 0755
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

usage() {
  sed -n '3,9p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
}

main() {
  local reclaim_only=0
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --reclaim) reclaim_only=1 ;;
      -h | --help) usage; exit 0 ;;
      *) die "неизвестный аргумент: $1 (см. --help)" ;;
    esac
    shift
  done
  preflight
  if [[ "$reclaim_only" == 1 ]]; then
    acquire_lock
    reclaim
    exit 0
  fi
  ask_mode
  if [[ "$MODE" == relay ]]; then
    say "Режим relay будет в следующей версии установщика. Ничего не изменено."
    exit 2
  fi
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
