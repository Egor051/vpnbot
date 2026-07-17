#!/usr/bin/env bash
#
# Idempotent, privilege-model-aware production deploy for the VPN Telegram bot.
#
# This script replaces the ad-hoc "paste a command block into an ssh shell"
# redeploy. It always deploys the current origin/main and is fetched FROM
# origin/main so it deploys itself from tip-of-main.
#
# The supported entry point is scripts/redeploy.sh, which does exactly this:
#
#   sudo CHECK=1 bash scripts/redeploy.sh    # inspect (PHASE1_ONLY=1), then:
#   sudo bash scripts/redeploy.sh            # deploy
#
# The wrapper fetches origin/main, extracts THIS file from tip-of-main
# (`git show origin/main:scripts/deploy.sh > /tmp/deploy.sh`) and runs it detached
# under `systemd-run --unit=vpn-bot-deploy` so an ssh disconnect can never strand
# a half-finished deploy. Running that sequence by hand is the no-wrapper fallback.
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
# --------------------------------------------------------------------------- #
# ENVIRONMENT KNOBS
# --------------------------------------------------------------------------- #
# Every knob defaults to the safe value; you opt into risk explicitly. The four
# behaviour knobs below change WHAT the script does. The path knobs further down
# in the Configuration block only relocate files and are covered there.
#
#   PHASE1_ONLY=1
#     What:   Run the ENTIRE read-only Phase 1 (guards, lock, fetch, ruff /
#             compileall / pytest in an isolated worktree, model detection,
#             pre-flight matrix, unit-drift + helper-drift scan, UNIT_SET
#             snapshot, WARP rollback-path facts), print the full report, and
#             exit 0 WITHOUT entering Phase 2 — no `systemctl stop`, no
#             config/unit/venv/helper mutations. Independent of FORCE (runs even
#             when the checkout already matches origin/main).
#     When:   The MANDATORY first step on any new host, and any time you want to
#             inspect what a deploy would do without touching production.
#     Risk:   None — it never mutates. The only "risk" is skipping it and
#             deploying a host you have not vetted.
#
#   FORCE=1
#     What:   Redeploy even when HEAD already equals origin/main (normally that
#             is a no-op exit 0).
#     When:   Re-running a deploy to re-assert unit/helper/config state on a host
#             that is already at tip-of-main (e.g. after a manual change on the
#             box), or to force the helper-drift refresh without a new commit.
#     Risk:   Repeats the full Phase 2 mutation (stop bot, backup, restart) with
#             its brief health-poll data window (see the rollback note below) for
#             no code change. Cheap, but not free — do it in low-traffic windows.
#
#   ALLOW_MODEL_SWITCH=1
#     What:   Permit a deploy whose incoming deploy/vpn-bot.service changes the
#             privilege model (api-root <-> helper-nonroot) relative to the unit
#             installed on the host. Without it, a model mismatch aborts at zero
#             downtime.
#     When:   ONLY after the host itself has already been migrated to the target
#             model (user created, sudoers + helpers installed, .env aligned) and
#             you have verified the target-model preconditions. This script never
#             migrates the host for you.
#     Risk:   Set on an un-migrated host, the bot restarts under a model the host
#             cannot support (wrong user, missing sudoers/helpers) and fails —
#             triggering a rollback. Never a shortcut for the migration itself.
#
#   ALLOW_UNIT_DRIFT=1
#     What:   BYPASSES THE REAL UNIT-DRIFT GATE. deploy.sh installs only
#             vpn-bot.service; when another shipped deploy/*.service differs from
#             the copy installed on the host, that is drift and the deploy stops.
#             This knob continues past it anyway, deploying vpn-bot while leaving
#             the other units stale.
#     When:   Apply ONLY consciously, when the drift is already known and safe —
#             e.g. you have inspected the diff, it is cosmetic or you will apply
#             the units by hand immediately after (the report prints the exact
#             install/restart commands). Never as a reflex to silence the gate.
#     Risk:   You ship new bot code against stale data-plane units. That is
#             exactly the class of failure this gate exists to catch; overriding
#             it blindly can leave a backend running the wrong config.
#             (Out-of-repo HELPER drift is different: Phase 2 now refreshes those
#             helpers itself — see install_out_of_repo_helpers — so it needs no
#             override knob.)
#
#   DEPLOY_SELFTEST=1
#     What:   Test seam only. Sources every function definition then returns
#             before Phase 1, so the pytest harness can drive individual
#             functions with stubbed systemctl/awg/ip/install. NEVER set in
#             production — it would turn a real deploy into a no-op.

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
# MTProxy managed drop-in: the directory is derived from ${MTPROTO_SERVICE_NAME}
# and BOTH filename spellings (vpn-bot-managed.conf, legacy vpnbot-managed.conf)
# are probed at use — see resolve_mtproxy_dropin(). Never hardcode a single path.

XRAY_UNIT="${XRAY_UNIT:-xray.service}"   # re-derived from ${XRAY_SERVICE_NAME} once .env is read
AWG_UNIT="${AWG_UNIT:-awg-quick@awg0.service}"
WARP_IFACE="${WARP_IFACE:-out-warp}"
# WARP source selectors to verify. The host carries more than one `ip rule`
# (the AWG client subnet AND the Hysteria2 source address), so this is a list.
# Override with a space-separated WARP_SRCS env value.
read -r -a WARP_SRCS <<< "${WARP_SRCS:-10.0.0.0/24 172.16.0.2}"
# WARP data-plane oneshots to reapply after an AWG restart, in dependency order
# (per each unit's After=/Requires=, NOT alphabetical). Host-verify the names.
WARP_ONESHOTS=(warp-routes.service vpn-bot-warp-split.service vpnbot-hy2-warp-mark.service warp-failsafe.service)

# Out-of-repo privileged helpers: tracked SOURCE lives in the checkout, the
# INSTALLED copy lives under /usr/local/sbin. `git reset --hard origin/main`
# advances the source but NEVER the installed copy, so a fixed helper would keep
# running stale — which is exactly how a broken vpn-bot-warp-routes survived a
# source fix and took warp-routes.service down (deploy/helpers/README.md L101-106).
# Phase 2 (install_out_of_repo_helpers) now closes that drift: it reinstalls any
# helper whose installed copy differs from the checkout. Only the WARP helpers are
# managed here — they are the ones the WARP deploy presupposes (README L94-99) with
# no other install step; the backend helpers under deploy/helpers/ are installed by
# deploy/setup-nonroot-helper-mode.sh and are out of scope for this refresh.
# Format per entry: "<checkout-relative-source>|<installed-absolute-path>".
OUT_OF_REPO_HELPERS=(
  "scripts/vpn-bot-warp-install|/usr/local/sbin/vpn-bot-warp-install"
  "scripts/vpn-bot-warp-iface|/usr/local/sbin/vpn-bot-warp-iface"
  "scripts/vpn-bot-warp-routes|/usr/local/sbin/vpn-bot-warp-routes"
  "scripts/vpn-bot-warp-status|/usr/local/sbin/vpn-bot-warp-status"
)
# The one helper that is EXECUTED by a systemd unit (warp-routes.service runs it),
# so a fresh binary only takes effect on restart. Refreshing it triggers a
# daemon-reload + `systemctl restart warp-routes` (guarded on pre-state below).
WARP_ROUTES_HELPER="/usr/local/sbin/vpn-bot-warp-routes"
WARP_ROUTES_UNIT="warp-routes.service"

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
# .env-derived facts, resolved once .env is readable (source of truth for backend
# unit names + modular-protocol gates). Declared here so the report is set -u safe.
LOG_DIR=""
declare -a drift=() absent=()
# Out-of-repo helper drift, scanned read-only in Phase 1 (against the origin/main
# worktree) and closed by Phase 2. Each entry: "<base>|<src>|<dst>|<state>".
declare -a helper_drift=()
MTPROXY_DROPIN_FOUND=""
# Modular-protocol matrix (parallel arrays): label, gate var, gate on (yes/no), unit.
declare -a PROTO_LABEL=() PROTO_GATE=() PROTO_ON=() PROTO_UNIT=()

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

# Whether a unit exists, using LoadState — NOT `systemctl list-unit-files`, which
# does not list template *instances* (awg-quick@awg0, awg-quick@out-warp) even
# when they are loaded+active, and would silently drop them from the safety net.
# `systemctl show -p LoadState` reports `loaded` for template instances too.
unit_exists() { [[ "$(systemctl show -p LoadState --value "$1" 2>/dev/null)" == "loaded" ]]; }

# LoadState/ActiveState pair for reporting, e.g. "loaded/active" or "not-found/inactive".
unit_states() {
  local load act
  load="$(systemctl show -p LoadState  --value "$1" 2>/dev/null || true)"
  act="$(systemctl show -p ActiveState --value "$1" 2>/dev/null || true)"
  printf '%s/%s' "${load:-unknown}" "${act:-unknown}"
}

# --------------------------------------------------------------------------- #
# Out-of-repo helper drift (see OUT_OF_REPO_HELPERS above)
# --------------------------------------------------------------------------- #
# Scan each managed helper's installed copy against the tracked source under
# <root> (Phase 1 passes $WT = origin/main worktree; Phase 2 passes $APP_DIR =
# the post-`git reset` working tree). Prints one line per helper:
#   "<base>|<resolved-src>|<dst>|<state>"   state ∈ absent | synced | drift
# ABSENT (no installed copy) means WARP is not deployed on this host — installing
# a helper without its config/units/symlink would be pointless, so absent is NOT
# drift and is never "fixed" here. Only a present-but-different copy is drift.
scan_out_of_repo_helpers() {
  local root="${1%/}" entry src_rel dst base src
  for entry in "${OUT_OF_REPO_HELPERS[@]}"; do
    src_rel="${entry%%|*}"; dst="${entry##*|}"; base="$(basename "$dst")"
    src="${root}/${src_rel}"
    if   [[ ! -e "$dst" ]];    then printf '%s|%s|%s|absent\n' "$base" "$src" "$dst"
    elif cmp -s "$src" "$dst"; then printf '%s|%s|%s|synced\n' "$base" "$src" "$dst"
    else                            printf '%s|%s|%s|drift\n'  "$base" "$src" "$dst"; fi
  done
}

# Phase 2: close out-of-repo helper drift from the checkout. Reinstalls every
# drifted helper, restarts warp-routes ONLY when its helper actually changed AND
# it was active pre-deploy, then verifies no drift remains. Runs while traps are
# armed, so a failure routes through rollback_now (bot never left stopped).
install_out_of_repo_helpers() {
  local base src dst state changed=0 routes_changed=0
  log "refreshing out-of-repo privileged helpers from the checkout (closes helper drift)"
  # Process substitution (not a pipe) keeps the loop in this shell so changed /
  # routes_changed survive it.
  while IFS='|' read -r base src dst state; do
    [[ -n "$base" ]] || continue
    case "$state" in
      absent) log "  ${base}: not installed on this host (WARP not deployed here) — leaving absent" ;;
      synced) log "  ${base}: already in sync with the checkout" ;;
      drift)
        log "  ${base}: installed copy drifted from the checkout — reinstalling"
        install -o root -g root -m 0755 "$src" "$dst" \
          || rollback_now "failed to install ${base} from ${src} to ${dst}"
        changed=1
        [[ "$dst" == "$WARP_ROUTES_HELPER" ]] && routes_changed=1
        ;;
    esac
  done < <(scan_out_of_repo_helpers "$APP_DIR")

  # The routes helper is the code warp-routes.service executes; a fresh binary
  # only takes effect on restart. Restart ONLY when it changed AND the unit was
  # active before this deploy — restarting a unit an operator had deliberately
  # stopped would re-activate WARP they took down (mirrors rollback()'s policy).
  if [[ "$routes_changed" == "1" ]]; then
    local pre="${U_PRE_ACTIVE[$WARP_ROUTES_UNIT]:-}"
    if [[ "$pre" == "active" ]]; then
      log "  ${WARP_ROUTES_UNIT} was active pre-deploy — daemon-reload + restart to load the fresh helper"
      systemctl daemon-reload
      # The restart runs the helper's counter self-check (#242). With an idle
      # client the data-plane probe SKIPS and the helper still exits 0, so a skip
      # can never fail this restart — we deliberately do NOT fail the deploy on a
      # skipped data-plane check. A non-zero exit here is a REAL routing failure.
      systemctl restart "$WARP_ROUTES_UNIT" \
        || rollback_now "${WARP_ROUTES_UNIT} restart failed after the helper refresh (real routing failure — an idle-client data-plane SKIP would have exited 0)"
    else
      warn "  ${WARP_ROUTES_UNIT} pre-state=${pre:-<none>} (not active) — fresh helper installed but NOT restarted (respecting operator intent)"
    fi
  fi

  # Verify: after the install no managed helper may still be in drift. This is the
  # hard gate the task requires — the repo copy and the installed copy MUST match.
  local bad=()
  while IFS='|' read -r base src dst state; do
    [[ "$state" == "drift" ]] && bad+=("$base")
  done < <(scan_out_of_repo_helpers "$APP_DIR")
  [[ ${#bad[@]} -eq 0 ]] || rollback_now "out-of-repo helper drift NOT closed after install: ${bad[*]}"

  if [[ "$changed" == "1" ]]; then
    log "out-of-repo helpers now match the checkout (drift closed)"
  else
    log "out-of-repo helpers already matched the checkout (no drift to close)"
  fi
}

# --------------------------------------------------------------------------- #
# bot.log scanning — the bot logs to a FILE ($LOG_DIR/bot.log), NOT journald, so
# a journal-only scan is always green (a false all-clear). We capture the file's
# byte size before starting the bot and read only the bytes appended afterwards.
# --------------------------------------------------------------------------- #
# The single error regex, shared by the live scan and the report's 7-day sample.
LOG_ERR_RE='(Traceback \(most recent call last\)|(^|[[:space:]])(ERROR|CRITICAL)([[:space:]]|:))'

# Byte size of a file, or 0 if it does not exist.
file_size() { [[ -f "$1" ]] && stat -c %s "$1" 2>/dev/null || echo 0; }

# Emit the text appended to bot.log after byte offset $1. If the live file is now
# SMALLER than the offset it was rotated between snapshot and scan: emit the tail
# of the rotated predecessor (bot.log.1 or bot.log.1.gz) from the offset onward,
# followed by the whole new bot.log — so no appended line is missed. No time
# filtering: bot.log stamps differ from DEPLOY_START and Traceback continuation
# lines carry no timestamp at all; only the byte offset is trustworthy.
collect_bot_log_tail() {
  local off="$1" cur
  [[ -f "$BOT_LOG" ]] || return 0
  cur="$(file_size "$BOT_LOG")"
  if (( cur >= off )); then
    tail -c +"$((off + 1))" "$BOT_LOG"
  else
    if   [[ -f "${BOT_LOG}.1" ]]; then
      tail -c +"$((off + 1))" "${BOT_LOG}.1"
    elif [[ -f "${BOT_LOG}.1.gz" ]] && command -v gzip >/dev/null 2>&1; then
      gzip -dc "${BOT_LOG}.1.gz" 2>/dev/null | tail -c +"$((off + 1))"
    fi
    cat "$BOT_LOG"
  fi
}

# Apply LOG_ERR_RE to stdin text, then drop allowlisted lines
# (deploy/log-scan-ignore.txt). Surviving lines are echoed (empty if clean).
scan_text_for_errors() {
  local text hits ignore
  text="$(cat)"
  hits="$(printf '%s\n' "$text" | grep -E "$LOG_ERR_RE" || true)"
  if [[ -n "$hits" && -f "$WT/deploy/log-scan-ignore.txt" ]]; then
    ignore="$(mktemp)"
    grep -vE '^[[:space:]]*(#|$)' "$WT/deploy/log-scan-ignore.txt" > "$ignore" || true
    if [[ -s "$ignore" ]]; then hits="$(printf '%s\n' "$hits" | grep -vE -f "$ignore" || true)"; fi
    rm -f "$ignore"
  fi
  printf '%s' "$hits"
}

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
# Sudoers audit across the WHOLE /etc/sudoers.d/ directory, not just $SUDOERS_FILE.
# A dangerous grant (NOPASSWD: ALL, or a generic shell/interpreter) in ANY active
# file is fatal. sudo ignores filenames containing a '.' or ending in '~', so
# such a file is inert TODAY but one rename from live — flag it (WARN), don't
# ignore it. (The host carries vpnbot.bak-pr118 exactly like this.)
check_sudoers_dir() {
  shopt -s nullglob
  local f base inert active
  local shell_re='/(sh|bash|dash|zsh|su|env|python[0-9.]*|perl|ruby|tee|find|vi|vim|less|more|awk|nmap|man)([[:space:]]|,|$)'
  for f in /etc/sudoers.d/*; do
    [[ -f "$f" ]] || continue
    base="$(basename "$f")"
    inert="no"
    if [[ "$base" == *.* || "$base" == *"~" ]]; then inert="yes"; fi
    log "validating sudoers file ${f} (inert=${inert})"
    if ! visudo -cf "$f" >/dev/null 2>&1; then
      if [[ "$inert" == "no" ]]; then die "${f} fails visudo -c"
      else warn "${f} fails visudo -c (inert: sudo ignores this name)"; fi
    fi
    active="$(grep -vE '^[[:space:]]*[#;]' "$f" 2>/dev/null || true)"
    if printf '%s\n' "$active" | grep -qE 'NOPASSWD:[[:space:]]*ALL'; then
      if [[ "$inert" == "no" ]]; then die "${f} contains a NOPASSWD: ALL grant"
      else warn "${f} contains a NOPASSWD: ALL grant (currently inert)"; fi
    fi
    if printf '%s\n' "$active" | grep -qE "$shell_re"; then
      if [[ "$inert" == "no" ]]; then die "${f} grants a generic shell / interpreter command"
      else warn "${f} grants a generic shell / interpreter command (currently inert)"; fi
    fi
    if [[ "$inert" == "yes" ]]; then
      warn "backup/inert file in active sudoers dir: ${f} — sudo ignores names with a '.' (or trailing '~'), but one rename activates it; move it OUT of /etc/sudoers.d/"
    fi
  done
  shopt -u nullglob
}

# --------------------------------------------------------------------------- #
# WARP data-plane fact check (used after an AWG restart during rollback)
# --------------------------------------------------------------------------- #
warp_dataplane_ok() {
  local fwmark tbl src rules missing=()
  rules="$(ip rule show 2>/dev/null || true)"
  for src in "${WARP_SRCS[@]}"; do
    printf '%s\n' "$rules" | grep -qF "from ${src}" || missing+=("$src")
  done
  if (( ${#missing[@]} > 0 )); then
    echo "ip rule 'from <src>' absent for: ${missing[*]}"; return 1
  fi
  fwmark=$(awg show "$WARP_IFACE" fwmark 2>/dev/null || true)
  if [[ -z "$fwmark" || "$fwmark" == "off" || ! "$fwmark" =~ ^(0x[0-9a-fA-F]+|[0-9]+)$ ]]; then
    echo "WARP routing table undetermined (fwmark='${fwmark:-}') — NOT verified"; return 1
  fi
  tbl=$(( fwmark ))   # hex (0x..) or decimal -> decimal table id (never hardcode 51820)
  if [[ -z "$(ip route show table "$tbl" 2>/dev/null)" ]]; then
    echo "WARP route table $tbl is empty"; return 1
  fi
  echo "ip rule for [${WARP_SRCS[*]}] + route table $tbl present"; return 0
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
    # will NOT reapply on their own — reapply them in dependency order. But ONLY
    # those that were ACTIVE in the Phase 1 pre-state snapshot: reapplying an
    # oneshot that was deliberately stopped would (re)start what the operator had
    # intentionally taken down. Inactive oneshots are listed, never restarted.
    local w pre
    for w in "${WARP_ONESHOTS[@]}"; do
      pre="${U_PRE_ACTIVE[$w]:-<not snapshotted>}"
      if [[ "$pre" == "active" ]]; then
        systemctl restart "$w"; report+=("reapply ${w} (was active pre-deploy): rc=$?"); warp_reapplied="yes"
      else
        report+=("skip reapply ${w} (pre-state=${pre}; not reactivating)")
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

# --------------------------------------------------------------------------- #
# Backend-unit resolution + UNIT_SET assembly (factored into functions so the
# self-test harness can drive them with stubbed systemctl/awg/ip/stat).
# --------------------------------------------------------------------------- #
# .env value or a default when unset/empty (defaults mirror config/settings.py).
env_or() { local v; v="$(env_val "$1")"; [[ -n "$v" ]] && printf '%s' "$v" || printf '%s' "$2"; }
yesno()  { is_true "$1" && echo yes || echo no; }
proto_add() { PROTO_LABEL+=("$1"); PROTO_GATE+=("$2"); PROTO_ON+=("$3"); PROTO_UNIT+=("$4"); }

# MTProxy managed drop-in: directory derived from ${MTPROTO_SERVICE_NAME}; probe
# BOTH the new (vpn-bot-managed.conf) and legacy (vpnbot-managed.conf) spellings.
resolve_mtproxy_dropin() {
  local dir="/etc/systemd/system/${MTPROTO_SERVICE_NAME_V}.service.d"
  MTPROXY_DROPIN_FOUND=""
  if   [[ -f "${dir}/vpn-bot-managed.conf" ]]; then MTPROXY_DROPIN_FOUND="${dir}/vpn-bot-managed.conf"
  elif [[ -f "${dir}/vpnbot-managed.conf"  ]]; then MTPROXY_DROPIN_FOUND="${dir}/vpnbot-managed.conf"; fi
}

# Backend unit names + which protocols are enabled come from .env (the single
# source of truth on the host); protocols are MODULAR, toggled at runtime, so a
# missing backend unit is NORMAL, not a config error. Populates *_V / *_ON /
# PROTO_* and points XRAY_UNIT (rollback's restart target) at the .env name.
resolve_backend_units() {
  XRAY_SERVICE_NAME_V="$(env_or XRAY_SERVICE_NAME xray)"
  SOCKS5_SERVICE_NAME_V="$(env_or SOCKS5_SERVICE_NAME danted)"
  MTPROTO_SERVICE_NAME_V="$(env_or MTPROTO_SERVICE_NAME mtproxy)"
  HY2_SERVICE_NAME_V="$(env_or HYSTERIA2_SERVICE_NAME hysteria-server)"
  HY2_AUTH_SERVICE_NAME_V="$(env_or HYSTERIA2_AUTH_SERVICE_NAME vpn-bot-hy2-auth)"
  SOCKS5_ON="$(yesno "$(env_val SOCKS5_ENABLED)")"
  MTPROTO_ON="$(yesno "$(env_val MTPROTO_ENABLED)")"
  HYSTERIA2_ON="$(yesno "$(env_val HYSTERIA2_ENABLED)")"
  XRAY_UNIT="${XRAY_SERVICE_NAME_V}.service"
  # Modular-protocol matrix (label | gate var | gate on | unit). Reset first so
  # repeated calls (tests) do not accumulate.
  PROTO_LABEL=(); PROTO_GATE=(); PROTO_ON=(); PROTO_UNIT=()
  proto_add "Xray"           "always"            "yes"           "${XRAY_SERVICE_NAME_V}.service"
  proto_add "SOCKS5"         "SOCKS5_ENABLED"    "$SOCKS5_ON"    "${SOCKS5_SERVICE_NAME_V}.service"
  proto_add "MTProto"        "MTPROTO_ENABLED"   "$MTPROTO_ON"   "${MTPROTO_SERVICE_NAME_V}.service"
  proto_add "Hysteria2"      "HYSTERIA2_ENABLED" "$HYSTERIA2_ON" "${HY2_SERVICE_NAME_V}.service"
  proto_add "Hysteria2-auth" "HYSTERIA2_ENABLED" "$HYSTERIA2_ON" "${HY2_AUTH_SERVICE_NAME_V}.service"
  resolve_mtproxy_dropin
}

# Assemble the watched UNIT_SET as the de-duplicated union of, in order:
#   (a) backend units DERIVED FROM .env (only enabled protocols),
#   (b) the data-plane units in $WT/deploy/managed-units.list (no .env var),
#   (c) the basenames of every shipped deploy/*.service (excluding *.example),
# then snapshot each installed unit's class + pre-state (active/enabled).
assemble_unit_set() {
  local raw line f base u utype urae tmr t
  UNIT_SET=(); MANAGED_LIST=()
  UNIT_SET+=("${XRAY_SERVICE_NAME_V}.service")            # Xray: always expected
  if [[ "$SOCKS5_ON"    == "yes" ]]; then UNIT_SET+=("${SOCKS5_SERVICE_NAME_V}.service"); fi
  if [[ "$MTPROTO_ON"   == "yes" ]]; then UNIT_SET+=("${MTPROTO_SERVICE_NAME_V}.service"); fi
  if [[ "$HYSTERIA2_ON" == "yes" ]]; then
    UNIT_SET+=("${HY2_SERVICE_NAME_V}.service")
    UNIT_SET+=("${HY2_AUTH_SERVICE_NAME_V}.service")
  fi
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
    if ! unit_exists "$u"; then skipped+=("$u"); continue; fi
    utype="$(systemctl show -p Type --value "$u" 2>/dev/null)"
    urae="$(systemctl show -p RemainAfterExit --value "$u" 2>/dev/null)"
    if [[ "$utype" == "oneshot" && "$urae" == "yes" ]]; then
      U_CLASS[$u]="state-only"; U_TARGET[$u]="$u"
    elif [[ "$utype" == "oneshot" ]]; then
      tmr="${u%.service}.timer"
      if unit_exists "$tmr"; then U_CLASS[$u]="timer"; U_TARGET[$u]="$tmr"
      else U_CLASS[$u]="oneshot-no-timer"; U_TARGET[$u]="$u"; fi
    else
      U_CLASS[$u]="regular"; U_TARGET[$u]="$u"
    fi
    t="${U_TARGET[$u]}"
    U_PRE_ACTIVE[$u]="$(systemctl is-active "$t" 2>/dev/null || true)"
    U_PRE_ENABLED[$u]="$(systemctl is-enabled "$t" 2>/dev/null || true)"
  done
}

# Classify one modular-protocol backend for the report. A disabled protocol whose
# unit is absent is NORMAL (INFO); only *enabled but not loaded* is a real
# breakage (WARN). Args: label gate on unit. Echoes a single status phrase.
classify_proto() {
  local gate="$2" on="$3" unit="$4"
  if unit_exists "$unit"; then
    echo "OK"
  elif [[ "$gate" == "always" ]]; then
    echo "WARN: expected backend not loaded"
  elif [[ "$on" == "yes" ]]; then
    echo "WARN: ${gate}=true but unit not loaded (real breakage)"
  else
    echo "INFO: protocol not deployed (${gate}=false)"
  fi
}

# Reverse guard: running services (vpn/xray/awg/warp/hy2/proxy) that are NOT in
# UNIT_SET — the real detector of a rename or a config gap. Prints one per line.
running_not_watched() {
  local -A inset=()
  local x svc running
  for x in "${UNIT_SET[@]}"; do inset["$x"]=1; done
  running="$(systemctl list-units --type=service --state=running --no-legend 2>/dev/null \
             | awk '{for(i=1;i<=NF;i++) if($i ~ /\.service$/){print $i; break}}' || true)"
  while IFS= read -r svc; do
    [[ -n "$svc" ]] || continue
    printf '%s' "$svc" | grep -qiE 'vpn|xray|awg|hy2|hyster|warp|mtpro|dante|socks' || continue
    [[ -n "${inset[$svc]:-}" ]] || printf '%s\n' "$svc"
  done <<< "$running"
}

# =========================================================================== #
# PHASE 1 — validate with the bot still running (zero-downtime, no rollback)
# =========================================================================== #
# Test seam: let the self-test harness source every definition above without
# running a real deploy. Never set DEPLOY_SELFTEST in production.
if [[ "${DEPLOY_SELFTEST:-0}" == "1" ]]; then return 0 2>/dev/null || exit 0; fi

[[ "${EUID}" -eq 0 ]] || die "run as root (recommended entry point: sudo bash scripts/redeploy.sh)"
require_tools git sqlite3 flock systemd-analyze systemctl tar visudo python3 sha256sum \
              awk df du date journalctl stat tail

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

# The bot logs to a FILE, not journald, so the post-deploy log scan reads
# ${LOG_DIR}/bot.log. If that directory is missing or empty we would silently
# scan nothing and always come up green — a false all-clear that is worse than
# no scan. Refuse to deploy blind. (Resolved from .env; default matches the code.)
LOG_DIR="$(env_val LOG_DIR)"; [[ -n "$LOG_DIR" ]] || LOG_DIR="/opt/vpn-service/logs"
[[ -d "$LOG_DIR" ]] || die "LOG_DIR ${LOG_DIR} does not exist — the post-deploy log scan would read nothing; refusing to deploy blind"
[[ -n "$(ls -A "$LOG_DIR" 2>/dev/null)" ]] || die "LOG_DIR ${LOG_DIR} is empty — no bot.log to scan; refusing to deploy blind"
BOT_LOG="${LOG_DIR}/bot.log"

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
# INVARIANT: this test phase is DETERMINISTIC and reproduces CI 1:1, so Phase 1
# is a real gate — a flaky pass here would silently green-light a broken deploy.
#   * `-p no:cacheprovider`: never read/write a .pytest_cache. From this detached
#     worktree pytest's rootdir/cache could resolve under $APP_DIR (/opt/vpn-service),
#     which is not writable from the worktree; a cold first run would then diverge
#     from warm reruns (the historical warp-split flake). Disabling the cache makes
#     the FIRST run in a fresh worktree identical to every later run.
#   * Collection order matches CI by construction: same rootdir-relative paths
#     (testpaths=["tests"] in pyproject.toml), no pytest-xdist (no parallelism) and
#     no pytest-randomly (no shuffle) in constraints-dev-hashed.txt. If either
#     plugin is ever added it MUST go to BOTH this phase and .github/workflows/ci.yml
#     with a pinned seed, or the two stop reproducing each other.
( cd "$WT" && "${TEST_VENV}/bin/python" -m pytest -q -p no:cacheprovider )

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

# Resolve backend unit names + modular-protocol gates from .env, and locate the
# MTProxy managed drop-in (see resolve_backend_units in the definitions above).
resolve_backend_units

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

# Audit every file in /etc/sudoers.d/, not just $SUDOERS_FILE (fix H).
log "auditing /etc/sudoers.d/ (all files, active and inert)"
check_sudoers_dir

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
# DRIFT (a unit that exists on BOTH sides with different content) is a real
# divergence and fails at ALLOW_UNIT_DRIFT=0. A unit shipped in the repo whose
# installed file is ABSENT is NOT drift — most often it is a rename (the repo
# ships deploy/vpn-bot-hy2-auth.service while the host runs vpnbot-hy2-auth), and
# treating it as a hard-fail would sink the first real deploy. It is reported as
# INFO so the operator can reconcile names, never as a failure.
drift=()
absent=()
shopt -s nullglob
for f in "$WT"/deploy/*.service; do
  base="$(basename "$f")"
  [[ "$base" == *.example.service ]] && continue
  [[ "$base" == "$BOT_UNIT" ]] && continue
  inst="/etc/systemd/system/${base}"
  if [[ -f "$inst" ]]; then
    cmp -s "$f" "$inst" || drift+=("deploy/${base}|${inst}")
  else
    absent+=("${base} (not installed under /etc/systemd/system/)")
  fi
done
if [[ -f "$WT/deploy/mtproxy-vpn-bot-managed.conf" ]]; then
  if [[ -n "$MTPROXY_DROPIN_FOUND" ]]; then
    cmp -s "$WT/deploy/mtproxy-vpn-bot-managed.conf" "$MTPROXY_DROPIN_FOUND" \
      || drift+=("deploy/mtproxy-vpn-bot-managed.conf|${MTPROXY_DROPIN_FOUND}")
  else
    absent+=("mtproxy drop-in (/etc/systemd/system/${MTPROTO_SERVICE_NAME_V}.service.d/{vpn-bot,vpnbot}-managed.conf)")
  fi
fi
shopt -u nullglob
if [[ ${#absent[@]} -gt 0 ]]; then
  log "repo units NOT installed on this host (INFO, not drift — reconcile if this is a rename):"
  for a in "${absent[@]}"; do log "    ${a}"; done
fi
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

# Out-of-repo helper drift (R3b): read-only scan against origin/main ($WT). Unlike
# unit drift this is NOT a gate — Phase 2 closes it automatically
# (install_out_of_repo_helpers), so here we only record + report it. Helpers that
# are absent (WARP not deployed on this host) are not drift and stay silent.
helper_drift=()
while IFS='|' read -r hd_base hd_src hd_dst hd_state; do
  [[ "$hd_state" == "drift" ]] && helper_drift+=("${hd_base}|${hd_src}|${hd_dst}|${hd_state}")
done < <(scan_out_of_repo_helpers "$WT")
if [[ ${#helper_drift[@]} -gt 0 ]]; then
  log "out-of-repo helper drift (installed copy != origin/main) — Phase 2 will refresh these automatically:"
  for hd in "${helper_drift[@]}"; do
    IFS='|' read -r hd_base _ hd_dst _ <<< "$hd"
    log "    ${hd_base} -> ${hd_dst}"
  done
fi

# UNIT_SET assembly + classification + pre-state snapshot (see assemble_unit_set).
assemble_unit_set
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

  # --- Out-of-repo helper drift: closed automatically by Phase 2 (no gate) ---
  printf '\n  --- Out-of-repo helper drift (/usr/local/sbin copies vs origin/main) ---\n'
  if [[ ${#helper_drift[@]} -gt 0 ]]; then
    printf '    %d helper(s) differ from origin/main — a REAL deploy refreshes them itself:\n' "${#helper_drift[@]}"
    local hrow hbase hsrc hdst
    for hrow in "${helper_drift[@]}"; do
      IFS='|' read -r hbase hsrc hdst _ <<< "$hrow"
      printf '      install -o root -g root -m 0755 %s %s\n' "$hsrc" "$hdst"
    done
    printf '    (no override knob needed — Phase 2 install_out_of_repo_helpers closes this,\n'
    printf '     and restarts %s when its helper changed and it was active.)\n' "$WARP_ROUTES_UNIT"
  else
    printf '    none (installed helpers match origin/main, or WARP is not deployed on this host)\n'
  fi

  # --- UNIT_SET: per-unit class + LoadState/ActiveState + is-enabled ---
  printf '\n  --- UNIT_SET (watched for an active-state regression across a deploy) ---\n'
  local u class disp t via
  for u in "${UNIT_SET[@]}"; do
    if [[ "$u" == "$BOT_UNIT" ]]; then
      printf '    %-40s %-16s %-18s is-enabled=%s\n' "$u" "bot-unit" \
        "$(unit_states "$u")" "$(systemctl is-enabled "$u" 2>/dev/null || true)"
      continue
    fi
    class="${U_CLASS[$u]:-}"
    if [[ -z "$class" ]]; then
      printf '    %-40s %-16s %-18s (not loaded — skipped)\n' "$u" "not-loaded" "$(unit_states "$u")"
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
    printf '    %-40s %-16s %-18s is-enabled=%s%s\n' "$u" "$disp" \
      "$(unit_states "$t")" "${U_PRE_ENABLED[$u]}" "$via"
  done

  # --- Modular protocols (backend units derived from .env) ---
  # A disabled protocol whose unit is absent is a NORMAL, expected state — INFO,
  # never a config error. Only *enabled but not loaded* is a real breakage (WARN).
  printf '\n  --- Modular protocols (backend units derived from .env) ---\n'
  local i lbl gate on unit states
  for i in "${!PROTO_UNIT[@]}"; do
    lbl="${PROTO_LABEL[$i]}"; gate="${PROTO_GATE[$i]}"; on="${PROTO_ON[$i]}"; unit="${PROTO_UNIT[$i]}"
    states="$(unit_states "$unit")"
    printf '    %-15s %-30s %-18s %s\n' "$lbl" "$unit" "$states" "$(classify_proto "$lbl" "$gate" "$on" "$unit")"
  done

  # --- Data-plane units from managed-units.list (not loaded => WARN, not fatal) ---
  printf '\n  --- managed-units.list (data-plane units with no .env variable) ---\n'
  if [[ ${#MANAGED_LIST[@]} -gt 0 ]]; then
    for u in "${MANAGED_LIST[@]}"; do
      if unit_exists "$u"; then
        printf '    %-40s %-18s OK\n' "$u" "$(unit_states "$u")"
      else
        printf '    %-40s %-18s WARN: listed but not loaded (typo, rename, or removed?)\n' "$u" "$(unit_states "$u")"
      fi
    done
  else
    printf '    (none listed)\n'
  fi

  # --- Repo units not installed on the host (INFO, from the drift check) ---
  printf '\n  --- Repo deploy/*.service units NOT installed on this host (INFO, not drift) ---\n'
  if [[ ${#absent[@]} -gt 0 ]]; then
    local a
    for a in "${absent[@]}"; do
      printf '    %s\n' "$a"
    done
    printf '    (if any of these is a rename, reconcile host/repo names — not fatal)\n'
  else
    printf '    none\n'
  fi

  # --- REVERSE CHECK: services RUNNING on the host but NOT in UNIT_SET ---
  # This is the real defence against a rename/typo: anything the host is actually
  # running that we are NOT watching is loud. Expected to be EMPTY after fix B.
  printf '\n  --- Running-but-not-watched (rename / config-gap detector) ---\n'
  local unwatched x
  readarray -t unwatched < <(running_not_watched)
  if [[ ${#unwatched[@]} -gt 0 ]]; then
    printf '  ##############################################################################\n'
    for x in "${unwatched[@]}"; do
      printf '  ## RUNNING but NOT WATCHED: %-45s ##\n' "$x"
    done
    printf '  ## a rename or a gap in the config — reconcile before deploying              ##\n'
    printf '  ##############################################################################\n'
  else
    printf '    none — every running vpn/xray/awg/warp/hy2/proxy service is in UNIT_SET. OK\n'
  fi

  # --- MTProxy managed drop-in (both filename spellings probed) ---
  printf '\n  --- MTProxy managed drop-in (%s.service.d/) ---\n' "$MTPROTO_SERVICE_NAME_V"
  if [[ -n "$MTPROXY_DROPIN_FOUND" ]]; then
    printf '    found : %s\n' "$MTPROXY_DROPIN_FOUND"
  else
    printf '    found : none (looked for vpn-bot-managed.conf and legacy vpnbot-managed.conf)\n'
  fi

  # --- WARP rollback-path facts (verify BEFORE a rollback would need them) ---
  printf '\n  --- WARP rollback-path data-plane facts (verified now, pre-emptively) ---\n'
  printf '    WARP_IFACE : %s\n' "$WARP_IFACE"
  printf '    WARP_SRCS  : %s\n' "${WARP_SRCS[*]}"
  local fwmark tbl warp_msg warp_rc src
  if command -v awg >/dev/null 2>&1; then
    fwmark="$(awg show "$WARP_IFACE" fwmark 2>/dev/null || true)"
  else
    fwmark=""; printf '    (awg not found on host — fwmark undetermined)\n'
  fi
  if [[ -n "$fwmark" && "$fwmark" != "off" && "$fwmark" =~ ^(0x[0-9a-fA-F]+|[0-9]+)$ ]]; then
    tbl=$(( fwmark ))
    printf '    awg fwmark : %s (hex ok) -> WARP routing table (decimal) : %s\n' "$fwmark" "$tbl"
  else
    printf '    awg fwmark : %s -> WARP routing table : UNDETERMINED (rollback cannot verify WARP)\n' "${fwmark:-<none>}"
  fi
  if command -v ip >/dev/null 2>&1; then
    for src in "${WARP_SRCS[@]}"; do
      if ip rule show 2>/dev/null | grep -qF "from ${src}"; then
        printf '    ip rule from %-16s : present\n' "$src"
      else
        printf '    ip rule from %-16s : ABSENT\n' "$src"
      fi
    done
  else
    printf '    (ip not found on host — rules undetermined)\n'
  fi
  warp_msg="$(warp_dataplane_ok)" && warp_rc=0 || warp_rc=$?
  if (( warp_rc == 0 )); then
    printf '    rollback WARP check : PASS (%s)\n' "$warp_msg"
  else
    printf '    rollback WARP check : NOT VERIFIED (%s)\n' "$warp_msg"
    printf '                          if a rollback restarts AWG, WARP may need manual reapply\n'
  fi

  # --- Post-deploy log scan visibility (bot.log is the PRIMARY source) ---
  # Prove the scanner can actually see content: list the files it would read with
  # sizes, and run the same error regex over the last 7 days of bot.log so the
  # operator sees a live match count instead of trusting a silent green.
  printf '\n  --- Post-deploy log scan source (%s) ---\n' "$LOG_DIR"
  local lf
  for lf in "$BOT_LOG" "${BOT_LOG}.1" "${BOT_LOG}.1.gz"; do
    if [[ -f "$lf" ]]; then
      printf '    scan file : %-40s %s bytes\n' "$lf" "$(file_size "$lf")"
    fi
  done
  local cutoff recent nmatch
  cutoff="$(date -d '7 days ago' '+%Y-%m-%d' 2>/dev/null || true)"
  if [[ -f "$BOT_LOG" && -n "$cutoff" ]]; then
    recent="$(awk -v c="$cutoff" 'substr($0,1,10) >= c' "$BOT_LOG" 2>/dev/null || true)"
    nmatch="$(printf '%s\n' "$recent" | grep -Ec "$LOG_ERR_RE" || true)"
    printf '    bot.log ERROR/CRITICAL/Traceback matches (last 7 days, pre-allowlist) : %s\n' "${nmatch:-0}"
    if [[ "${nmatch:-0}" != "0" ]]; then
      printf '    up to 3 examples:\n'
      printf '%s\n' "$recent" | grep -E "$LOG_ERR_RE" | head -n3 | sed 's/^/      /'
    fi
  else
    printf '    (bot.log absent or date unavailable — cannot sample last 7 days)\n'
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

# Refresh out-of-repo privileged helpers from the freshly-advanced tree. This is
# the structural fix for the /usr/local/sbin drift: `git reset` above updated the
# tracked source but not the installed copy, so without this step a fixed helper
# would keep running stale (the vpn-bot-warp-routes incident). Done here, right
# before the unit install, so the helper the units execute is current before any
# unit is (re)started. Restarting warp-routes may run its idle-tolerant self-check;
# a skipped data-plane probe does NOT fail the deploy (see the function).
install_out_of_repo_helpers

log "installing ${BOT_UNIT} from deploy/vpn-bot.service (verbatim)"
install -m0644 "deploy/vpn-bot.service" "$SYSTEM_UNIT"
systemctl daemon-reload

# Start + health poll (replaces a blind sleep) ------------------------------
DEPLOY_START="$(date '+%Y-%m-%d %H:%M:%S')"
# Byte offset of bot.log BEFORE start, so the post-deploy scan reads only what
# the new process appends (see collect_bot_log_tail).
LOG_OFFSET="$(file_size "$BOT_LOG")"
log "starting vpn-bot (bot.log offset=${LOG_OFFSET})"
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
# PRIMARY source: bot.log tail (the bot logs to a file, not journald), read by
# byte offset with rotation handling. SECONDARY source: the journal, which still
# catches interpreter crashes / systemd messages that never reach bot.log.
file_hits="$(collect_bot_log_tail "$LOG_OFFSET" | scan_text_for_errors)"
journal_scan="$(journalctl -u "$BOT_UNIT" --since "$DEPLOY_START" --no-pager -o cat 2>/dev/null || true)"
journal_hits="$(printf '%s\n' "$journal_scan" | scan_text_for_errors)"
if [[ -n "$file_hits" ]]; then
  warn "error signatures in ${BOT_LOG} since deploy (bytes > offset ${LOG_OFFSET}):"
  printf '%s\n' "$file_hits" | sed 's/^/    /' >&2
fi
if [[ -n "$journal_hits" ]]; then
  warn "error signatures in vpn-bot journal since deploy:"
  printf '%s\n' "$journal_hits" | sed 's/^/    /' >&2
fi
if [[ -n "$file_hits" || -n "$journal_hits" ]]; then
  rollback_now "vpn-bot logged errors after start (bot.log and/or journal)"
fi
log "log scan clean (bot.log tail + journal)"

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
