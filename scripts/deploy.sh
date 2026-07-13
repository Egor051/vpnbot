#!/usr/bin/env bash
#
# Idempotent, privilege-model-aware production deploy for the VPN Telegram bot.
#
# This script replaces the ad-hoc "paste a command block into an ssh shell"
# redeploy. It always deploys the current origin/main and is fetched FROM
# origin/main so it deploys itself from tip-of-main:
#
#   git -C /opt/vpn-service fetch origin main
#   git -C /opt/vpn-service show origin/main:scripts/deploy.sh > /tmp/deploy.sh
#   # run detached so an ssh disconnect can never strand a half-finished deploy:
#   sudo systemd-run --unit=vpn-bot-deploy --collect --pty bash /tmp/deploy.sh
#
# Invariant: after a run either the new code is running with every assertion
# green, or the system is rolled back to PREV_SHA (code + venv + DB + control-
# plane configs + unit) and the bot is running. The bot is never left stopped.
#
# The two supported deployment models are detected, never hardcoded:
#   api-root       XRAY_APPLY_MODE=api, User=root, PRIVILEGE_HELPERS_ENABLED unset
#   helper-nonroot PRIVILEGE_HELPERS_ENABLED=true, User!=root, XRAY_APPLY_MODE!=api
#
# deploy/vpn-bot.service is authoritative and is installed verbatim; the model is
# switched by editing that repo file (guarded by ALLOW_MODEL_SWITCH).
#
# Env knobs (all overridable): FORCE, ALLOW_MODEL_SWITCH, ALLOW_UNIT_DRIFT,
# PHASE1_ONLY, and the paths listed below.
#
# PHASE1_ONLY=1 runs the entire read-only Phase 1 (guards, lock, fetch, tests,
# model detection, pre-flight matrix, drift check, UNIT_SET snapshot, WARP
# rollback-path facts), prints a full report, and exits 0 WITHOUT entering
# Phase 2 — no `systemctl stop`, no config/unit/venv mutations. It is the
# mandatory first step on a new host: it surfaces every fact an operator must
# vet before allowing a real deploy. Independent of FORCE.

set -euo pipefail

# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #
APP_DIR="${APP_DIR:-/opt/vpn-service}"
DB_PATH="${DB_PATH:-${APP_DIR}/data/vpn.db}"
VENV="${VENV:-${APP_DIR}/.venv}"
VENV_PREV="${VENV_PREV:-${APP_DIR}/.venv.prev}"   # same FS as $VENV so mv is atomic
SYSTEM_UNIT="${SYSTEM_UNIT:-/etc/systemd/system/vpn-bot.service}"
SUDOERS_FILE="${SUDOERS_FILE:-/etc/sudoers.d/vpn-bot}"
BACKUP_DIR="${BACKUP_DIR:-/var/backups/vpn-bot}"
TEST_VENV="${TEST_VENV:-/var/lib/vpn-bot-deploy/.venv-test}"
LOCK="${LOCK:-/run/vpn-bot-deploy.lock}"
BACKUP_KEEP="${BACKUP_KEEP:-10}"
ALLOW_MODEL_SWITCH="${ALLOW_MODEL_SWITCH:-0}"
ALLOW_UNIT_DRIFT="${ALLOW_UNIT_DRIFT:-0}"
FORCE="${FORCE:-0}"
PHASE1_ONLY="${PHASE1_ONLY:-0}"   # 1 = run all of Phase 1, print report, exit 0 (no mutations)

ENV_FILE="${ENV_FILE:-${APP_DIR}/.env}"
XRAY_CONF="${XRAY_CONF:-/usr/local/etc/xray/config.json}"
AWG_CONF="${AWG_CONF:-/etc/amnezia/amneziawg/awg0.conf}"
MTPROXY_DIR="${MTPROXY_DIR:-/etc/mtproxy}"
MTPROXY_DROPIN="${MTPROXY_DROPIN:-/etc/systemd/system/mtproxy.service.d/vpn-bot-managed.conf}"

XRAY_UNIT="${XRAY_UNIT:-xray.service}"
AWG_UNIT="${AWG_UNIT:-awg-quick@awg0.service}"
WARP_IFACE="${WARP_IFACE:-out-warp}"
WARP_SRC="${WARP_SRC:-10.0.0.0/24}"
# WARP data-plane oneshots to reapply after an AWG restart, in dependency order
# (per each unit's After=/Requires=, NOT alphabetical). Host-verify the names.
WARP_ONESHOTS=(warp-routes.service vpn-bot-warp-split.service vpnbot-hy2-warp-mark.service warp-failsafe.service)

BOT_UNIT="vpn-bot.service"
HEALTH_TIMEOUT="${HEALTH_TIMEOUT:-60}"

# --------------------------------------------------------------------------- #
# Output helpers
# --------------------------------------------------------------------------- #
log()  { printf '[deploy] %s\n' "$*"; }
warn() { printf '[deploy][WARN] %s\n' "$*" >&2; }
die()  { printf '[deploy][FAIL] %s\n' "$*" >&2; exit 1; }

# --------------------------------------------------------------------------- #
# Mutable state used by traps / rollback
# --------------------------------------------------------------------------- #
WT=""
STAGE=""
LOCK_FD=""
ARCHIVE=""
PREV_SHA=""
SCHEMA_BEFORE=""
DEPLOY_START=""
INSTALLED_USER=""
INCOMING_USER=""
MODE=""
VENV_SNAPSHOT_DONE=0
PHASE="preflight"   # preflight | interim | armed | done
declare -a UNIT_SET=()
declare -a MANAGED_LIST=()   # only the names read from deploy/managed-units.list, in order
declare -A U_CLASS=() U_TARGET=() U_PRE_ACTIVE=() U_PRE_ENABLED=()

# --------------------------------------------------------------------------- #
# EXIT cleanup (worktree, stage, venv-snapshot safety net)
# --------------------------------------------------------------------------- #
cleanup() {
  set +e
  # Guard against a SIGKILL between `cp -a $VENV $VENV_PREV` and the pip install:
  # if the live venv vanished but the snapshot survived, put it back.
  if [[ ! -x "${VENV}/bin/python" && -x "${VENV_PREV}/bin/python" ]]; then
    warn "live venv missing; restoring from ${VENV_PREV}"
    rm -rf "$VENV" && mv "$VENV_PREV" "$VENV"
  fi
  [[ -n "$WT"    && -d "$WT"    ]] && git worktree remove --force "$WT" >/dev/null 2>&1
  git worktree prune >/dev/null 2>&1
  [[ -n "$STAGE" && -d "$STAGE" ]] && rm -rf "$STAGE"
}
trap cleanup EXIT

# --------------------------------------------------------------------------- #
# Two-phase failure trap
#   interim (bot stopped, nothing else changed): just start the bot again
#   armed   (mutation in progress):               full rollback()
# --------------------------------------------------------------------------- #
on_interim() {
  trap - ERR INT TERM HUP
  set +e
  warn "failure before the backup was verified — restarting vpn-bot (nothing else changed)"
  systemctl start "$BOT_UNIT"
  exit 1
}
arm_interim()  { PHASE="interim"; trap 'on_interim' ERR INT TERM HUP; }
arm_rollback() { PHASE="armed";   trap 'rollback'   ERR INT TERM HUP; }
disarm()       { PHASE="done";    trap - ERR INT TERM HUP; }
# Explicit assertion failure while armed -> route through rollback with a message.
rollback_now() { warn "$1"; rollback; }

# --------------------------------------------------------------------------- #
# Small utilities
# --------------------------------------------------------------------------- #
require_tools() {
  local t missing=()
  for t in "$@"; do command -v "$t" >/dev/null 2>&1 || missing+=("$t"); done
  [[ ${#missing[@]} -eq 0 ]] || die "missing required tools: ${missing[*]}"
}

# Free bytes on the filesystem holding $1.
fs_avail_bytes() { df -PB1 "$1" | awk 'NR==2 {print $4}'; }

sha256_of() { [[ -f "$1" ]] && sha256sum "$1" | awk '{print $1}' || echo "absent"; }

# LoadState=loaded means the unit (or its template, for instance units) exists.
unit_installed() { [[ "$(systemctl show -p LoadState --value "$1" 2>/dev/null)" == "loaded" ]]; }

# Last active (non-comment) value of KEY= in a unit file; empty if absent.
unit_val() {
  local file="$1" key="$2" line
  [[ -f "$file" ]] || { printf ''; return 0; }
  line=$(grep -E "^[[:space:]]*${key}=" "$file" 2>/dev/null | grep -vE '^[[:space:]]*[#;]' | tail -n1 || true)
  line="${line#*=}"
  # Trim surrounding whitespace (same approach as env_val; avoids xargs de-quoting/splitting).
  line="$(printf '%s' "$line" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
  printf '%s' "$line"
}
unit_has() { grep -E "^[[:space:]]*${2}=" "$1" 2>/dev/null | grep -qvE '^[[:space:]]*[#;]'; }

# Read a KEY from the (root-owned) .env file; last active wins, quotes stripped.
env_val() {
  local key="$1" line val
  [[ -f "$ENV_FILE" ]] || { printf ''; return 0; }
  line=$(grep -E "^[[:space:]]*${key}=" "$ENV_FILE" 2>/dev/null | grep -vE '^[[:space:]]*#' | tail -n1 || true)
  val="${line#*=}"
  val="$(printf '%s' "$val" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' \
                                  -e 's/^"\(.*\)"$/\1/' -e "s/^'\(.*\)'$/\1/")"
  printf '%s' "$val"
}
is_true() { case "${1,,}" in true|1|yes|on) return 0;; *) return 1;; esac; }

schema_version() {
  local v
  v=$(sqlite3 "$DB_PATH" "SELECT value FROM schema_meta WHERE key='schema_version';" 2>/dev/null || true)
  [[ "$v" =~ ^[0-9]+$ ]] || v=0
  printf '%s' "$v"
}

rotate_backups() {
  local f
  # `|| true`: on a fresh host the glob matches nothing and `ls` exits non-zero;
  # with `set -o pipefail` + `set -e` that would otherwise abort the whole deploy.
  ls -1t "$BACKUP_DIR"/backup-*.tar.gz 2>/dev/null | tail -n +"$((BACKUP_KEEP + 1))" | while IFS= read -r f; do
    rm -f "$f"
  done || true
}

# --------------------------------------------------------------------------- #
# Hardening non-regression (compare VALUES, not just presence)
# --------------------------------------------------------------------------- #
ps_rank()   { case "${1,,}" in strict) echo 3;; full) echo 2;; yes|true) echo 1;; *) echo 0;; esac; }
# yes/tmpfs make $HOME empty+inaccessible (strongest); read-only only blocks writes.
ph_rank()   { case "${1,,}" in yes|true|tmpfs) echo 2;; read-only) echo 1;; *) echo 0;; esac; }
bool_rank() { case "${1,,}" in yes|true|1|on) echo 1;; *) echo 0;; esac; }

check_hardening_regression() {
  local old="$1" new="$2" k ov nv
  for k in NoNewPrivileges PrivateTmp; do
    ov=$(bool_rank "$(unit_val "$old" "$k")"); nv=$(bool_rank "$(unit_val "$new" "$k")")
    (( nv < ov )) && die "hardening regression: $k lowered ($(unit_val "$old" "$k" || true) -> $(unit_val "$new" "$k" || true))"
  done
  ov=$(ps_rank "$(unit_val "$old" ProtectSystem)"); nv=$(ps_rank "$(unit_val "$new" ProtectSystem)")
  (( nv < ov )) && die "hardening regression: ProtectSystem lowered ($(unit_val "$old" ProtectSystem) -> $(unit_val "$new" ProtectSystem))"
  local new_ps_rank="$nv"
  ov=$(ph_rank "$(unit_val "$old" ProtectHome)"); nv=$(ph_rank "$(unit_val "$new" ProtectHome)")
  (( nv < ov )) && die "hardening regression: ProtectHome lowered ($(unit_val "$old" ProtectHome) -> $(unit_val "$new" ProtectHome))"
  if unit_has "$old" ReadWritePaths && (( new_ps_rank == 3 )) && ! unit_has "$new" ReadWritePaths; then
    die "hardening regression: ReadWritePaths removed while ProtectSystem=strict"
  fi
  return 0
}

# --------------------------------------------------------------------------- #
# WARP data-plane fact check (used after an AWG restart during rollback)
# --------------------------------------------------------------------------- #
warp_dataplane_ok() {
  local fwmark tbl
  if ! ip rule show 2>/dev/null | grep -qF "from ${WARP_SRC}"; then
    echo "ip rule 'from ${WARP_SRC}' absent"; return 1
  fi
  fwmark=$(awg show "$WARP_IFACE" fwmark 2>/dev/null || true)
  if [[ -z "$fwmark" || "$fwmark" == "off" || ! "$fwmark" =~ ^(0x[0-9a-fA-F]+|[0-9]+)$ ]]; then
    echo "WARP routing table undetermined (fwmark='${fwmark:-}') — NOT verified"; return 1
  fi
  tbl=$(( fwmark ))   # hex (0x..) or decimal -> decimal table id (never hardcode 51820)
  if [[ -z "$(ip route show table "$tbl" 2>/dev/null)" ]]; then
    echo "WARP route table $tbl is empty"; return 1
  fi
  echo "ip rule + route table $tbl present"; return 0
}

# --------------------------------------------------------------------------- #
# Rollback — fault-tolerant, data-plane-aware, always reports
# --------------------------------------------------------------------------- #
rollback() {
  trap - ERR INT TERM HUP
  set +e
  local -a report=()
  local rc
  warn "ROLLBACK: restoring PREV_SHA=${PREV_SHA:-<unknown>}"

  git reset --hard "$PREV_SHA"; report+=("git reset --hard ${PREV_SHA}: rc=$?")

  # Restore venv from the on-disk snapshot, NOT the network (R6): a network-caused
  # failure would otherwise make the venv rollback fail too. If the failure hit
  # before the venv was ever touched, there is nothing to restore.
  if [[ "$VENV_SNAPSHOT_DONE" != "1" ]]; then
    report+=("venv not modified before failure — no restore needed")
  elif [[ -x "${VENV_PREV}/bin/python" ]]; then
    rm -rf "$VENV" && mv "$VENV_PREV" "$VENV"; report+=("venv restored from snapshot: rc=$?")
    "${VENV}/bin/pip" check >/dev/null 2>&1; report+=("pip check (post-restore, informational): rc=$?")
  else
    report+=("venv snapshot MISSING (${VENV_PREV}) — venv NOT restored — MANUAL ACTION REQUIRED")
  fi

  # Snapshot control-plane config hashes BEFORE we overwrite them, to decide
  # whether the data-plane actually needs a restart.
  local xray_before awg_before
  xray_before=$(sha256_of "$XRAY_CONF"); awg_before=$(sha256_of "$AWG_CONF")

  systemctl stop "$BOT_UNIT"; report+=("stop vpn-bot: rc=$?")
  rm -f "${DB_PATH}-wal" "${DB_PATH}-shm"
  if [[ -n "$ARCHIVE" && -f "$ARCHIVE" ]]; then
    tar -p --xattrs --acls -xzf "$ARCHIVE" -C /; rc=$?; report+=("restore DB+configs+unit from archive: rc=$rc")
  else
    report+=("backup archive MISSING (${ARCHIVE:-<none>}) — DB/configs/unit NOT restored — MANUAL ACTION REQUIRED")
  fi
  fix_db_perms; report+=("fix DB ownership/mode: rc=$?")
  systemctl daemon-reload; report+=("daemon-reload: rc=$?")

  # Data-plane: restart a service only if its config actually changed (R1).
  local xray_after awg_after dp_restarted="no" warp_reapplied="no" warp_check="n/a"
  xray_after=$(sha256_of "$XRAY_CONF"); awg_after=$(sha256_of "$AWG_CONF")
  if [[ "$xray_before" != "$xray_after" ]]; then
    systemctl restart "$XRAY_UNIT"; report+=("restart ${XRAY_UNIT} (config changed): rc=$?"); dp_restarted="yes"
  else
    report+=("${XRAY_UNIT} not restarted (config unchanged)")
  fi
  if [[ "$awg_before" != "$awg_after" ]]; then
    systemctl restart "$AWG_UNIT"; report+=("restart ${AWG_UNIT} (config changed): rc=$?"); dp_restarted="yes"
    # awg-quick down/up recreates the iface; the RemainAfterExit WARP oneshots
    # will NOT reapply on their own — reapply them in dependency order.
    local w
    for w in "${WARP_ONESHOTS[@]}"; do
      if unit_installed "$w"; then
        systemctl restart "$w"; report+=("reapply ${w}: rc=$?"); warp_reapplied="yes"
      fi
    done
    local msg; msg=$(warp_dataplane_ok); rc=$?
    if (( rc == 0 )); then warp_check="pass ($msg)"
    else warp_check="FAIL ($msg) — MANUAL ACTION REQUIRED"; fi
  else
    report+=("${AWG_UNIT} not restarted (config unchanged); WARP left untouched")
  fi

  systemctl start "$BOT_UNIT"; report+=("start vpn-bot: rc=$?")
  if systemctl is-active --quiet "$BOT_UNIT"; then report+=("vpn-bot is-active: yes")
  else report+=("vpn-bot is-active: NO — MANUAL ACTION REQUIRED"); fi

  printf '\n===== ROLLBACK REPORT =====\n' >&2
  printf '  - %s\n' "${report[@]}" >&2
  printf '  data-plane restarted: %s | WARP reapplied: %s | WARP check: %s\n' \
    "$dp_restarted" "$warp_reapplied" "$warp_check" >&2
  printf '===========================\n' >&2
  exit 1
}

fix_db_perms() {
  [[ -f "$DB_PATH" ]] || return 0
  # The restored (previous) unit defines the run user; match its ownership.
  local owner="root:root"
  if [[ -n "$INSTALLED_USER" && "$INSTALLED_USER" != "root" ]]; then
    owner="${INSTALLED_USER}:${INSTALLED_USER}"
  fi
  chown "$owner" "$DB_PATH" 2>/dev/null
  chmod 0600 "$DB_PATH" 2>/dev/null
  return 0
}

# =========================================================================== #
# PHASE 1 — validate with the bot still running (zero-downtime, no rollback)
# =========================================================================== #
[[ "${EUID}" -eq 0 ]] || die "run as root (recommended: sudo systemd-run --unit=vpn-bot-deploy --collect --pty bash /tmp/deploy.sh)"
require_tools git sqlite3 flock systemd-analyze systemctl tar visudo python3 sha256sum \
              awk df du date journalctl

cd "$APP_DIR" || die "APP_DIR ${APP_DIR} not found"
git worktree prune >/dev/null 2>&1 || true
install -d -m700 "$BACKUP_DIR"
rotate_backups   # also rotate at start so a series of failures does not pile up

# Serialize against parallel deploys (lock lives outside the systemd RuntimeDirectory).
exec {LOCK_FD}>"$LOCK" || die "cannot open lock ${LOCK}"
flock -n "$LOCK_FD" || die "another deploy already holds ${LOCK}"

log "fetching origin/main"
git fetch origin main
TAG="$(git rev-parse --short origin/main)"

if [[ "$(git rev-parse HEAD)" == "$(git rev-parse origin/main)" ]]; then
  if [[ "$PHASE1_ONLY" == "1" ]]; then
    log "HEAD already at origin/main (${TAG}); PHASE1_ONLY=1: running Phase 1 checks anyway (no deploy)."
  elif [[ "$FORCE" != "1" ]]; then
    log "HEAD already at origin/main (${TAG}); nothing to deploy. Set FORCE=1 to redeploy anyway."
    exit 0
  else
    warn "FORCE=1: redeploying although HEAD already equals origin/main"
  fi
fi

# Preconditions -------------------------------------------------------------
dirty="$(git status --porcelain)"
if [[ -n "$dirty" ]]; then
  warn "working tree is not clean:"; printf '%s\n' "$dirty" >&2
  die "commit, stash, or clean the working tree before deploying"
fi

[[ -x "${VENV}/bin/python" ]] || die "prod venv missing at ${VENV}"

need_app=$(( 1073741824 + $(du -sb "$VENV" | awk '{print $1}') ))   # 1GiB + room for .venv.prev
avail_app=$(fs_avail_bytes "$APP_DIR")
(( avail_app > need_app )) || die "insufficient space on ${APP_DIR} FS: need >$((need_app/1024/1024))MiB, have $((avail_app/1024/1024))MiB"
avail_bak=$(fs_avail_bytes "$BACKUP_DIR")
(( avail_bak > 1073741824 )) || die "insufficient space on ${BACKUP_DIR} FS: need >1GiB, have $((avail_bak/1024/1024))MiB"

[[ -f "${APP_DIR}/deploy/managed-units.list" ]]  || die "deploy/managed-units.list is missing (refusing to guess a unit set)"
[[ -f "${APP_DIR}/deploy/log-scan-ignore.txt" ]] || die "deploy/log-scan-ignore.txt is missing"

# Tests in an isolated worktree + a separate test venv (never the prod venv) ---
WT="$(mktemp -d)"
git worktree add --detach "$WT" origin/main >/dev/null
log "worktree at ${WT} (origin/main ${TAG})"

want_stamp="$(sha256sum "$WT/constraints-hashed.txt" "$WT/constraints-dev-hashed.txt" | sha256sum | awk '{print $1}')"
have_stamp="$(cat "${TEST_VENV}/.constraints-stamp" 2>/dev/null || true)"
if [[ ! -x "${TEST_VENV}/bin/python" || "$have_stamp" != "$want_stamp" ]]; then
  log "building test venv ${TEST_VENV} (constraints changed or venv absent)"
  rm -rf "$TEST_VENV"
  install -d "$(dirname "$TEST_VENV")"
  python3 -m venv "$TEST_VENV"
  "${TEST_VENV}/bin/pip" install --quiet --upgrade pip
  "${TEST_VENV}/bin/pip" install --require-hashes -r "$WT/constraints-hashed.txt"
  "${TEST_VENV}/bin/pip" install --require-hashes -r "$WT/constraints-dev-hashed.txt"
  printf '%s' "$want_stamp" > "${TEST_VENV}/.constraints-stamp"
else
  log "reusing test venv ${TEST_VENV}"
fi

log "running ruff / compileall / pytest against origin/main"
( cd "$WT" && "${TEST_VENV}/bin/python" -m ruff check . )
( cd "$WT" && "${TEST_VENV}/bin/python" -m compileall -q . )
( cd "$WT" && "${TEST_VENV}/bin/python" -m pytest -q )

# Model detection -----------------------------------------------------------
INCOMING_USER="$(unit_val "$WT/deploy/vpn-bot.service" User)"; [[ -n "$INCOMING_USER" ]] || INCOMING_USER="root"
if [[ -f "$SYSTEM_UNIT" ]]; then
  INSTALLED_USER="$(unit_val "$SYSTEM_UNIT" User)"; [[ -n "$INSTALLED_USER" ]] || INSTALLED_USER="root"
else
  INSTALLED_USER=""   # fresh install
fi
XRAY_APPLY_MODE="$(env_val XRAY_APPLY_MODE)"
PRIV_HELPERS="$(env_val PRIVILEGE_HELPERS_ENABLED)"
if [[ "$INCOMING_USER" == "root" ]]; then MODE="api-root"; else MODE="helper-nonroot"; fi
log "model: incoming User=${INCOMING_USER} installed User=${INSTALLED_USER:-<none>} -> MODE=${MODE}"
log ".env: XRAY_APPLY_MODE=${XRAY_APPLY_MODE:-<unset>} PRIVILEGE_HELPERS_ENABLED=${PRIV_HELPERS:-<unset>}"

# Pre-flight compatibility matrix (incoming unit vs .env) --------------------
api="no";     [[ "$XRAY_APPLY_MODE" == "api" ]] && api="yes"
helpers="no"; is_true "$PRIV_HELPERS" && helpers="yes"
if [[ "$api" == "yes" && "$helpers" == "yes" ]]; then
  die "incompatible .env: XRAY_APPLY_MODE=api and PRIVILEGE_HELPERS_ENABLED=true are mutually exclusive (the bot refuses to start). Fix ${ENV_FILE} before deploying."
fi
if [[ "$api" == "yes" && "$INCOMING_USER" != "root" ]]; then
  die "the PR unit runs as User=${INCOMING_USER} but ${ENV_FILE} has XRAY_APPLY_MODE=api (requires root). This PR changes the privilege model. Update .env: set XRAY_APPLY_MODE=restart (or reload) and PRIVILEGE_HELPERS_ENABLED=true, then re-run."
fi
if [[ "$helpers" == "yes" && "$INCOMING_USER" == "root" ]]; then
  die "the PR unit runs as User=root but ${ENV_FILE} has PRIVILEGE_HELPERS_ENABLED=true (requires non-root). Update .env or the unit so they agree, then re-run."
fi

# Model-switch gate ---------------------------------------------------------
if [[ -n "$INSTALLED_USER" && "$INSTALLED_USER" != "$INCOMING_USER" ]]; then
  if [[ "$ALLOW_MODEL_SWITCH" != "1" ]]; then
    die "model switch ${INSTALLED_USER} -> ${INCOMING_USER} is NOT a backward-compatible deploy. Migrate the host first, then re-run with ALLOW_MODEL_SWITCH=1. This script never migrates the host."
  fi
  warn "ALLOW_MODEL_SWITCH=1: verifying target-model preconditions before stopping the bot"
  if [[ "$MODE" == "helper-nonroot" ]]; then
    python3 "$WT/deploy/check-nonroot-helper-mode.py" --mode pre-start --repo "$APP_DIR" \
      --unit "$WT/deploy/vpn-bot.service" --sudoers "$SUDOERS_FILE" --db "$DB_PATH" \
      || die "target helper-nonroot preconditions are not met — run deploy/setup-nonroot-helper-mode.sh first"
  else
    [[ "$INCOMING_USER" == "root" ]] || die "target api-root requires User=root in the incoming unit"
  fi
fi

# Universal unit / sudoers asserts (both models) ----------------------------
log "systemd-analyze verify (advisory) on incoming unit"
sa_out="$(systemd-analyze verify "$WT/deploy/vpn-bot.service" 2>&1)" || true
if [[ -n "$sa_out" ]]; then
  if printf '%s\n' "$sa_out" | grep -qiE 'Unknown lvalue|Invalid|Failed to parse|not a valid'; then
    printf '%s\n' "$sa_out" >&2
    die "systemd-analyze verify reported errors in deploy/vpn-bot.service"
  fi
  warn "systemd-analyze verify warnings (advisory, not fatal):"; printf '%s\n' "$sa_out" >&2
fi

# Hardening non-regression only makes sense within the same model.
if [[ -f "$SYSTEM_UNIT" && "$INSTALLED_USER" == "$INCOMING_USER" ]]; then
  check_hardening_regression "$SYSTEM_UNIT" "$WT/deploy/vpn-bot.service"
fi

if [[ -f "$SUDOERS_FILE" ]]; then
  log "validating ${SUDOERS_FILE}"
  visudo -cf "$SUDOERS_FILE" >/dev/null || die "${SUDOERS_FILE} fails visudo -c"
  sudoers_active="$(grep -vE '^[[:space:]]*[#;]' "$SUDOERS_FILE" || true)"
  printf '%s\n' "$sudoers_active" | grep -qE 'NOPASSWD:[[:space:]]*ALL' \
    && die "${SUDOERS_FILE} contains a NOPASSWD: ALL grant"
  printf '%s\n' "$sudoers_active" | grep -qE '/(sh|bash|dash|zsh|su|env|python[0-9.]*|perl|ruby|tee|find|vi|vim|less|more|awk|nmap|man)([[:space:]]|,|$)' \
    && die "${SUDOERS_FILE} grants a generic shell / interpreter command"
fi

# Mode-dependent asserts ----------------------------------------------------
if [[ "$MODE" == "helper-nonroot" ]]; then
  log "helper-nonroot pre-start validation (deploy/check-nonroot-helper-mode.py)"
  python3 "$WT/deploy/check-nonroot-helper-mode.py" --mode pre-start --repo "$APP_DIR" \
    --unit "$WT/deploy/vpn-bot.service" --sudoers "$SUDOERS_FILE" --db "$DB_PATH" \
    || die "helper-nonroot preconditions failed"
else
  log "api-root model: sudoers optional, no file-ownership checks"
fi

# Unit drift check (R3): other units are asserted but never installed here ---
drift=()
shopt -s nullglob
for f in "$WT"/deploy/*.service; do
  base="$(basename "$f")"
  [[ "$base" == *.example.service ]] && continue
  [[ "$base" == "$BOT_UNIT" ]] && continue
  inst="/etc/systemd/system/${base}"
  [[ -f "$inst" ]] && { cmp -s "$f" "$inst" || drift+=("deploy/${base}|${inst}"); }
done
if [[ -f "$WT/deploy/mtproxy-vpn-bot-managed.conf" && -f "$MTPROXY_DROPIN" ]]; then
  cmp -s "$WT/deploy/mtproxy-vpn-bot-managed.conf" "$MTPROXY_DROPIN" \
    || drift+=("deploy/mtproxy-vpn-bot-managed.conf|${MTPROXY_DROPIN}")
fi
shopt -u nullglob
if [[ ${#drift[@]} -gt 0 ]]; then
  warn "these units changed in the PR but deploy.sh does NOT install them — apply manually:"
  for d in "${drift[@]}"; do
    src="${d%%|*}"; dst="${d##*|}"; unit="$(basename "$dst")"
    printf '    install -m0644 %s %s\n' "$src" "$dst" >&2
    printf '    systemctl daemon-reload && systemctl restart %s\n' "$unit" >&2
  done
  if [[ "$ALLOW_UNIT_DRIFT" == "1" ]]; then
    warn "ALLOW_UNIT_DRIFT=1: continuing despite the drift above"
  elif [[ "$PHASE1_ONLY" == "1" ]]; then
    warn "PHASE1_ONLY=1: drift reported (above and in the report) but not fatal in inspection mode"
  else
    die "unit drift detected (set ALLOW_UNIT_DRIFT=1 to deploy vpn-bot anyway and apply the rest by hand)"
  fi
fi

# UNIT_SET assembly + classification + pre-state snapshot --------------------
while IFS= read -r raw; do
  line="${raw%%#*}"; line="$(printf '%s' "$line" | xargs)"
  [[ -n "$line" ]] && { UNIT_SET+=("$line"); MANAGED_LIST+=("$line"); }
done < "$WT/deploy/managed-units.list"
shopt -s nullglob
for f in "$WT"/deploy/*.service; do
  base="$(basename "$f")"; [[ "$base" == *.example.service ]] && continue
  UNIT_SET+=("$base")
done
shopt -u nullglob
readarray -t UNIT_SET < <(printf '%s\n' "${UNIT_SET[@]}" | awk 'NF && !seen[$0]++')

skipped=()
for u in "${UNIT_SET[@]}"; do
  [[ "$u" == "$BOT_UNIT" ]] && continue   # vpn-bot is checked absolutely, later
  if ! unit_installed "$u"; then skipped+=("$u"); continue; fi
  utype="$(systemctl show -p Type --value "$u" 2>/dev/null)"
  urae="$(systemctl show -p RemainAfterExit --value "$u" 2>/dev/null)"
  if [[ "$utype" == "oneshot" && "$urae" == "yes" ]]; then
    U_CLASS[$u]="state-only"; U_TARGET[$u]="$u"
  elif [[ "$utype" == "oneshot" ]]; then
    tmr="${u%.service}.timer"
    if unit_installed "$tmr"; then U_CLASS[$u]="timer"; U_TARGET[$u]="$tmr"
    else U_CLASS[$u]="oneshot-no-timer"; U_TARGET[$u]="$u"; fi
  else
    U_CLASS[$u]="regular"; U_TARGET[$u]="$u"
  fi
  t="${U_TARGET[$u]}"
  U_PRE_ACTIVE[$u]="$(systemctl is-active "$t" 2>/dev/null || true)"
  U_PRE_ENABLED[$u]="$(systemctl is-enabled "$t" 2>/dev/null || true)"
done
if [[ ${#skipped[@]} -gt 0 ]]; then
  log "units not installed (skipped from the health check): ${skipped[*]}"
fi

# --------------------------------------------------------------------------- #
# PHASE1_ONLY report — consolidate every Phase 1 fact an operator must vet on a
# new host before any mutation is permitted. Reads only globals populated above.
# --------------------------------------------------------------------------- #
phase1_report() {
  printf '\n===== PHASE 1 REPORT (PHASE1_ONLY=1 — no mutations performed) =====\n'

  local head_sha uptodate=""
  head_sha="$(git rev-parse --short HEAD)"
  [[ "$head_sha" == "$TAG" ]] && uptodate=" (already up to date)"
  printf '  checkout          : %s -> origin/main %s%s\n' "$head_sha" "$TAG" "$uptodate"

  # --- Model detection: MODE and the exact facts it was derived from ---
  local basis="helper-nonroot"
  [[ "$INCOMING_USER" == "root" ]] && basis="api-root"
  printf '\n  --- Model detection (MODE + basis) ---\n'
  printf '    incoming User  (origin/main deploy/vpn-bot.service) : %s\n' "$INCOMING_USER"
  printf '    installed User (%s) : %s\n' "$SYSTEM_UNIT" "${INSTALLED_USER:-<none> (fresh install)}"
  printf '    .env XRAY_APPLY_MODE                                : %s\n' "${XRAY_APPLY_MODE:-<unset>}"
  printf '    .env PRIVILEGE_HELPERS_ENABLED                      : %s\n' "${PRIV_HELPERS:-<unset>}"
  printf '    => detected MODE : %s  (basis: incoming User=%s => %s)\n' "$MODE" "$INCOMING_USER" "$basis"

  # --- Pre-flight compatibility matrix (reaching here means it passed) ---
  printf '\n  --- Pre-flight compatibility matrix (incoming unit vs .env) ---\n'
  printf '    XRAY_APPLY_MODE=api       : %s\n' "$api"
  printf '    PRIVILEGE_HELPERS_ENABLED : %s\n' "$helpers"
  printf '    result                    : PASS (no api+helpers clash, no api/non-root clash)\n'

  # --- Model-switch gate ---
  printf '\n  --- Model-switch gate ---\n'
  if [[ -n "$INSTALLED_USER" && "$INSTALLED_USER" != "$INCOMING_USER" ]]; then
    printf '    switch %s -> %s : ALLOW_MODEL_SWITCH=%s, target preconditions verified above\n' \
      "$INSTALLED_USER" "$INCOMING_USER" "$ALLOW_MODEL_SWITCH"
  else
    printf '    no switch (installed and incoming User match, or fresh install)\n'
  fi

  # --- Unit drift: diverged units + ready-to-run apply commands ---
  printf '\n  --- Unit drift (PR deploy/*.service units deploy.sh does NOT install) ---\n'
  if [[ ${#drift[@]} -gt 0 ]]; then
    printf '    %d unit(s) differ from the host — apply by hand:\n' "${#drift[@]}"
    local d src dst unit
    for d in "${drift[@]}"; do
      src="${d%%|*}"; dst="${d##*|}"; unit="$(basename "$dst")"
      printf '      install -m0644 %s %s\n' "$src" "$dst"
      printf '      systemctl daemon-reload && systemctl restart %s\n' "$unit"
    done
    [[ "$ALLOW_UNIT_DRIFT" == "1" ]] && printf '    (ALLOW_UNIT_DRIFT=1 set — a real deploy would continue past this)\n'
  else
    printf '    none (shipped deploy/*.service units match the host, or are not installed there)\n'
  fi

  # --- UNIT_SET: per-unit class + current is-active/is-enabled ---
  printf '\n  --- UNIT_SET (watched for an active-state regression across a deploy) ---\n'
  local u class disp t via
  for u in "${UNIT_SET[@]}"; do
    if [[ "$u" == "$BOT_UNIT" ]]; then
      printf '    %-40s %-16s is-active=%s is-enabled=%s\n' "$u" "bot-unit" \
        "$(systemctl is-active "$u" 2>/dev/null || true)" \
        "$(systemctl is-enabled "$u" 2>/dev/null || true)"
      continue
    fi
    class="${U_CLASS[$u]:-}"
    if [[ -z "$class" ]]; then
      printf '    %-40s %s\n' "$u" "NOT INSTALLED (skipped)"
      continue
    fi
    case "$class" in
      regular)          disp="normal" ;;
      state-only)       disp="state-only" ;;
      timer)            disp="timer-backed" ;;
      oneshot-no-timer) disp="oneshot-no-timer" ;;
      *)                disp="$class" ;;
    esac
    t="${U_TARGET[$u]}"; via=""
    [[ "$t" != "$u" ]] && via=" (via ${t})"
    printf '    %-40s %-16s is-active=%s is-enabled=%s%s\n' "$u" "$disp" \
      "${U_PRE_ACTIVE[$u]}" "${U_PRE_ENABLED[$u]}" "$via"
  done

  # --- LOUD: managed-units.list names that are NOT installed on this host ---
  local missing=()
  if [[ ${#MANAGED_LIST[@]} -gt 0 ]]; then
    for u in "${MANAGED_LIST[@]}"; do
      unit_installed "$u" || missing+=("$u")
    done
  fi
  printf '\n'
  if [[ ${#missing[@]} -gt 0 ]]; then
    printf '  ##############################################################################\n'
    printf '  ## CONFIG ERROR: managed-units.list names NOT present on this host           ##\n'
    printf '  ## This is a configuration error, not normal. A wrong or renamed name        ##\n'
    printf '  ## silently drops a unit from the deploy safety net. Fix                      ##\n'
    printf '  ## deploy/managed-units.list to match real names (systemctl list-unit-files) ##\n'
    printf '  ## before deploying:                                                          ##\n'
    printf '  ##############################################################################\n'
    for u in "${missing[@]}"; do printf '  ##   MISSING ON HOST: %s\n' "$u"; done
    printf '  ##############################################################################\n'
  else
    printf '  managed-units.list: every listed name resolves to an installed unit. OK\n'
  fi

  # --- WARP rollback-path facts (verify BEFORE a rollback would need them) ---
  printf '\n  --- WARP rollback-path data-plane facts (verified now, pre-emptively) ---\n'
  printf '    WARP_IFACE : %s\n' "$WARP_IFACE"
  printf '    WARP_SRC   : %s\n' "$WARP_SRC"
  local fwmark tbl ruleok warp_msg warp_rc
  if command -v awg >/dev/null 2>&1; then
    fwmark="$(awg show "$WARP_IFACE" fwmark 2>/dev/null || true)"
  else
    fwmark=""; printf '    (awg not found on host — fwmark undetermined)\n'
  fi
  if [[ -n "$fwmark" && "$fwmark" != "off" && "$fwmark" =~ ^(0x[0-9a-fA-F]+|[0-9]+)$ ]]; then
    tbl=$(( fwmark ))
    printf '    awg fwmark : %s -> WARP routing table (decimal) : %s\n' "$fwmark" "$tbl"
  else
    printf '    awg fwmark : %s -> WARP routing table : UNDETERMINED (rollback cannot verify WARP)\n' "${fwmark:-<none>}"
  fi
  if command -v ip >/dev/null 2>&1; then
    if ip rule show 2>/dev/null | grep -qF "from ${WARP_SRC}"; then ruleok="present"; else ruleok="ABSENT"; fi
  else
    ruleok="ip not found on host"
  fi
  printf '    ip rule from %s : %s\n' "$WARP_SRC" "$ruleok"
  warp_msg="$(warp_dataplane_ok)" && warp_rc=0 || warp_rc=$?
  if (( warp_rc == 0 )); then
    printf '    rollback WARP check : PASS (%s)\n' "$warp_msg"
  else
    printf '    rollback WARP check : NOT VERIFIED (%s)\n' "$warp_msg"
    printf '                          if a rollback restarts AWG, WARP may need manual reapply\n'
  fi

  printf '\n===================================================================\n'
}

# --------------------------------------------------------------------------- #
# PHASE1_ONLY exit — print the full report and stop before any mutation.
# --------------------------------------------------------------------------- #
if [[ "$PHASE1_ONLY" == "1" ]]; then
  phase1_report
  log "PHASE1_ONLY=1: Phase 1 complete; NOT entering Phase 2 (no systemctl stop, no mutations)."
  exit 0
fi

# =========================================================================== #
# PHASE 2 — mutate (traps armed)
# =========================================================================== #
PREV_SHA="$(git rev-parse HEAD)"
SCHEMA_BEFORE="$(schema_version)"
log "PREV_SHA=${PREV_SHA} schema_version(before)=${SCHEMA_BEFORE}"

arm_interim                 # a failure now (or SIGINT/TERM/HUP) just restarts the bot
log "stopping vpn-bot for a consistent backup"
systemctl stop "$BOT_UNIT"

STAGE="$(mktemp -d)"
manifest=()
stage_path() {
  local p="$1"
  if [[ -e "$p" ]]; then
    install -d "${STAGE}$(dirname "$p")"
    cp -a "$p" "${STAGE}${p}"
    manifest+=("${p#/}")
    log "  backed up ${p}"
  else
    log "  (absent, skipped) ${p}"
  fi
}
install -d "${STAGE}$(dirname "$DB_PATH")"
sqlite3 "$DB_PATH" ".backup '${STAGE}${DB_PATH}'"
manifest+=("${DB_PATH#/}")
log "  backed up ${DB_PATH} (sqlite .backup snapshot)"
stage_path "$SYSTEM_UNIT"
stage_path "$ENV_FILE"
stage_path "$XRAY_CONF"
stage_path "$AWG_CONF"
stage_path "$MTPROXY_DIR"

ARCHIVE="${BACKUP_DIR}/backup-${TAG}-$(date +%Y%m%dT%H%M%S).tar.gz"
tar --xattrs --acls -czf "$ARCHIVE" -C "$STAGE" .
log "backup archive ${ARCHIVE}"

# Verify the archive lists every file that actually existed at backup time.
[[ -s "$ARCHIVE" ]] || { warn "backup archive is empty"; false; }
listing="$(tar -tzf "$ARCHIVE")"
for entry in "${manifest[@]}"; do
  printf '%s\n' "$listing" | grep -qF "$entry" || { warn "backup archive is missing ${entry}"; false; }
done
log "backup verified (${#manifest[@]} entries)"

arm_rollback                # from here, any failure triggers full rollback()

log "advancing working tree to origin/main (${TAG})"
git reset --hard origin/main

log "snapshotting venv to ${VENV_PREV} (file-level, for a network-independent rollback)"
rm -rf "$VENV_PREV"
cp -a "$VENV" "$VENV_PREV"
VENV_SNAPSHOT_DONE=1

log "installing prod dependencies"
"${VENV}/bin/pip" install -r requirements.txt -c constraints.txt
"${VENV}/bin/pip" check

log "installing ${BOT_UNIT} from deploy/vpn-bot.service (verbatim)"
install -m0644 "deploy/vpn-bot.service" "$SYSTEM_UNIT"
systemctl daemon-reload

# Start + health poll (replaces a blind sleep) ------------------------------
DEPLOY_START="$(date '+%Y-%m-%d %H:%M:%S')"
log "starting vpn-bot"
systemctl start "$BOT_UNIT"
deadline=$(( SECONDS + HEALTH_TIMEOUT ))
until systemctl is-active --quiet "$BOT_UNIT"; do
  (( SECONDS < deadline )) || rollback_now "vpn-bot did not become active within ${HEALTH_TIMEOUT}s"
  sleep 2
done
nrestarts="$(systemctl show -p NRestarts --value "$BOT_UNIT")"
[[ "$nrestarts" == "0" ]] || rollback_now "vpn-bot restart-loop detected (NRestarts=${nrestarts})"
log "vpn-bot active (NRestarts=0)"

# Post-state regression for the rest of UNIT_SET ----------------------------
for u in "${UNIT_SET[@]}"; do
  [[ "$u" == "$BOT_UNIT" ]] && continue
  class="${U_CLASS[$u]:-}"; [[ -n "$class" ]] || continue   # skipped/not installed
  t="${U_TARGET[$u]}"
  pre="${U_PRE_ACTIVE[$u]}"
  post="$(systemctl is-active "$t" 2>/dev/null || true)"
  case "$class" in
    state-only)
      log "  ${u}: state-only check (is-active=${post}; data-plane not probed here)"
      [[ "$pre" == "active" && "$post" != "active" ]] && rollback_now "${u} regressed: active -> ${post}"
      ;;
    oneshot-no-timer)
      log "  ${u}: oneshot without a timer — not health-checked"
      ;;
    timer|regular)
      if [[ "$pre" == "active" && "$post" != "active" ]]; then
        rollback_now "${t} regressed: was active before deploy, now ${post}"
      elif [[ "$pre" != "active" && "$post" != "active" ]]; then
        warn "${t}: was ${pre} before and ${post} after — pre-existing, not caused by this deploy"
      else
        log "  ${t}: OK (${pre} -> ${post})"
      fi
      ;;
  esac
done

# helper-nonroot: live post-start validation (run dir writable, sudo reachable)
if [[ "$MODE" == "helper-nonroot" ]]; then
  python3 "deploy/check-nonroot-helper-mode.py" --mode post-start --repo "$APP_DIR" \
    --unit "$SYSTEM_UNIT" --sudoers "$SUDOERS_FILE" --db "$DB_PATH" \
    || rollback_now "helper-nonroot post-start validation failed"
fi

# Schema non-regression -----------------------------------------------------
SCHEMA_AFTER="$(schema_version)"
(( SCHEMA_AFTER >= SCHEMA_BEFORE )) || rollback_now "schema_version regressed: ${SCHEMA_BEFORE} -> ${SCHEMA_AFTER}"
log "schema_version(after)=${SCHEMA_AFTER}"

# Log scan for this run only (content-based, allowlist-filtered) ------------
scan="$(journalctl -u "$BOT_UNIT" --since "$DEPLOY_START" --no-pager -o cat 2>/dev/null || true)"
hits="$(printf '%s\n' "$scan" | grep -E '(Traceback \(most recent call last\)|(^|[[:space:]])(ERROR|CRITICAL)([[:space:]]|:))' || true)"
if [[ -n "$hits" ]]; then
  ignore="$(mktemp)"
  grep -vE '^[[:space:]]*(#|$)' "$WT/deploy/log-scan-ignore.txt" > "$ignore" || true
  if [[ -s "$ignore" ]]; then hits="$(printf '%s\n' "$hits" | grep -vE -f "$ignore" || true)"; fi
  rm -f "$ignore"
fi
if [[ -n "$hits" ]]; then
  warn "error signatures in vpn-bot journal since deploy:"; printf '%s\n' "$hits" >&2
  rollback_now "vpn-bot logged errors after start"
fi
log "journal scan clean"

# Optional PR-specific hook -------------------------------------------------
HOOK="scripts/hooks/${TAG}.sh"
if [[ -f "$HOOK" ]]; then
  log "running PR hook ${HOOK}"
  bash "$HOOK" || rollback_now "PR hook ${HOOK} failed"
fi

# Success -------------------------------------------------------------------
rm -rf "$VENV_PREV"
rotate_backups
disarm

cat <<EOF

===== DEPLOY OK =====
  model            : ${MODE}
  deployed         : ${PREV_SHA} -> ${TAG}
  schema_version   : ${SCHEMA_BEFORE} -> ${SCHEMA_AFTER}
  backup           : ${ARCHIVE}
  units skipped    : ${skipped[*]:-none}
=====================
EOF
