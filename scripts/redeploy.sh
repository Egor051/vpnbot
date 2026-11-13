#!/usr/bin/env bash
#
# redeploy.sh — the single entry point for production redeploys of the VPN bot.
#
# It is a thin, self-contained wrapper around scripts/deploy.sh. It performs NO
# production mutation itself: it fetches origin/main, pulls deploy.sh straight
# FROM tip-of-main (never the working tree), and launches it detached under
# systemd so an SSH disconnect can never strand a half-finished deploy. deploy.sh
# does all the real work — including refreshing the out-of-repo /usr/local/sbin
# helpers (install_out_of_repo_helpers) — so this wrapper deliberately does NOT
# touch helpers.
#
# Usage (always as root):
#   sudo bash scripts/redeploy.sh           # normal deploy of origin/main
#   sudo CHECK=1 bash scripts/redeploy.sh   # inspection only: Phase 1, no mutations (PHASE1_ONLY=1)
#   sudo FORCE=1 bash scripts/redeploy.sh   # redeploy even when HEAD already == origin/main
#   sudo ALLOW_BACKEND_CONFIG_DRIFT=1 bash scripts/redeploy.sh   # forward a deploy.sh knob
#   sudo REDEPLOY_ATTACH=pipe bash scripts/redeploy.sh   # no terminal: wait, exit with deploy.sh's code
#
# deploy.sh's gate bypasses (ALLOW_*) and tuning timeouts go on the same command
# line, AFTER `sudo` (sudo drops the caller's environment). Only the names in
# DEPLOY_ENV_PASSTHROUGH below are forwarded; an ALLOW_* that is not on that list
# stops the wrapper before it does anything.
#
# The same commands deploy an L4 relay host: deploy.sh reads NODE_ROLE from the
# host's .env (main | relay) and runs the matching flow, so this wrapper has no
# role of its own (docs/relay.md, "A new relay from scratch").
#
# CHECK and FORCE are independent. CHECK maps to deploy.sh's PHASE1_ONLY=1 and is
# the recommended first step on any host you have not just deployed. Recommended
# flow: `sudo CHECK=1 bash scripts/redeploy.sh` (read the report), then
# `sudo bash scripts/redeploy.sh`.

set -euo pipefail

# --------------------------------------------------------------------------- #
# Tunables — overridable, with defaults that match scripts/deploy.sh.
# --------------------------------------------------------------------------- #
APP_DIR="${APP_DIR:-/opt/vpn-service}"          # production checkout
DEPLOY_UNIT="${DEPLOY_UNIT:-vpn-bot-deploy}"    # transient systemd unit name for the run
TMP_DEPLOY="${TMP_DEPLOY:-/tmp/deploy.sh}"      # where tip-of-main deploy.sh is written
LOG_DIR="${REDEPLOY_LOG_DIR:-/root}"            # where the tee'd run log is kept
CHECK="${CHECK:-0}"                             # 1 => inspection only  (=> PHASE1_ONLY=1)
FORCE="${FORCE:-0}"                             # 1 => redeploy even if already up to date
# How the detached run is attached to THIS process: `pty` (default) streams it to the
# operator's terminal; `pipe` is for a caller without a terminal — the setup wizard
# (scripts/wizard/vpn-bot-wizard-update, docs/wizard.md): `systemd-run --wait --pipe`
# under `set -o pipefail`, so this wrapper waits for deploy.sh and exits with ITS code
# (with --pty the pipeline's code is tee's). Anything else is refused before any work.
REDEPLOY_ATTACH="${REDEPLOY_ATTACH:-pty}"

# --------------------------------------------------------------------------- #
# deploy.sh knobs forwarded to the detached run — an explicit allowlist.
# --------------------------------------------------------------------------- #
# systemd-run starts deploy.sh in a fresh environment: nothing set on THIS command
# line reaches it unless it is put on the `env` line in launch_deploy. Each name
# below is forwarded when it is set to a non-empty value, verbatim; nothing else
# is, and the environment is never forwarded wholesale.
#   * Every ALLOW_* gate bypass deploy.sh reads.
#     tests/test_redeploy_env_passthrough.py compares this list with the ALLOW_*
#     names in deploy.sh and fails when deploy.sh gains one that is missing here.
#   * The tuning timeouts an operator actually sets.
# An ALLOW_* that is set but NOT listed (a typo, or a new deploy.sh flag nobody
# added here) used to be dropped silently, and deploy.sh then stopped on the very
# gate it was meant to open. check_allow_env refuses to run instead.
DEPLOY_ENV_PASSTHROUGH=(
  ALLOW_MODEL_SWITCH
  ALLOW_UNIT_DRIFT
  ALLOW_BACKEND_CONFIG_DRIFT
  ALLOW_SCHEMA_DOWNGRADE
  ALLOW_SSH_CHANGE
  SCHEMA_WAIT_TIMEOUT
  HY2_AUTH_BIND_TIMEOUT
)
deploy_env=()

# Refuse an ALLOW_* variable this wrapper would not forward. Any value counts —
# empty and 0 included — because the name itself is the mistake.
check_allow_env() {
  local name known
  local -a unknown=()
  for name in ${!ALLOW_@}; do
    for known in "${DEPLOY_ENV_PASSTHROUGH[@]}"; do
      [[ "$name" == "$known" ]] && continue 2
    done
    unknown+=("$name")
  done
  (( ${#unknown[@]} == 0 )) && return 0
  {
    echo "redeploy: refusing to run — unknown ALLOW_* variable(s): ${unknown[*]}"
    echo "redeploy:   deploy.sh runs under systemd-run and never sees this shell's environment, so the gate it was meant to open would stay shut."
    echo "redeploy:   names this wrapper forwards: ${DEPLOY_ENV_PASSTHROUGH[*]}"
    echo "redeploy:   fix the spelling, or add the new deploy.sh flag to DEPLOY_ENV_PASSTHROUGH in scripts/redeploy.sh"
  } >&2
  return 1
}

# Translate this wrapper's CHECK/FORCE into deploy.sh's own env knobs, then add
# every DEPLOY_ENV_PASSTHROUGH name that is set and non-empty, as NAME=value words
# for `env`. CHECK=1 => PHASE1_ONLY=1 (read-only Phase 1); FORCE is passed
# through as-is.
build_deploy_env() {
  local name
  deploy_env=()
  [[ "$CHECK" == "1" ]] && deploy_env+=("PHASE1_ONLY=1")
  [[ "$FORCE" == "1" ]] && deploy_env+=("FORCE=1")
  for name in "${DEPLOY_ENV_PASSTHROUGH[@]}"; do
    [[ -n "${!name:-}" ]] && deploy_env+=("${name}=${!name}")
  done
  return 0
}

# Launch deploy.sh DETACHED under systemd, output tee'd to a timestamped log.
# --collect reaps the transient unit when it exits; --pty streams live output
# while keeping the run attached to systemd (not our SSH session), so an SSH
# disconnect can never kill a half-finished deploy. The env prefix injects
# deploy_env (PHASE1_ONLY/FORCE and the forwarded knobs); the log file survives
# for post-mortem. ${deploy_env[@]+...} makes the empty-array expansion safe
# under `set -u`.
launch_deploy() {
  local ts log_file
  ts="$(date -u +%Y%m%dT%H%M%SZ)"
  log_file="${LOG_DIR%/}/deploy-${ts}.log"
  echo "redeploy: launching ${DEPLOY_UNIT} (log: ${log_file})"
  echo "redeploy:   deploy.sh env: ${deploy_env[*]:-<none>}"
  if [[ "$REDEPLOY_ATTACH" == "pipe" ]]; then
    systemd-run --unit="$DEPLOY_UNIT" --collect --wait --pipe --quiet \
      env ${deploy_env[@]+"${deploy_env[@]}"} \
      bash -c "set -o pipefail; bash ${TMP_DEPLOY} 2>&1 | tee ${log_file}"
    return
  fi
  systemd-run --unit="$DEPLOY_UNIT" --collect --pty \
    env ${deploy_env[@]+"${deploy_env[@]}"} \
    bash -c "bash ${TMP_DEPLOY} 2>&1 | tee ${log_file}"
}

# REDEPLOY_ATTACH is one of two words; a typo must not silently pick the default.
check_attach() {
  case "$REDEPLOY_ATTACH" in
    pty|pipe) return 0 ;;
  esac
  echo "redeploy: refusing to run — REDEPLOY_ATTACH must be pty or pipe, got '${REDEPLOY_ATTACH}'" >&2
  return 1
}

# --------------------------------------------------------------------------- #
# Test seam: tests/test_redeploy_env_passthrough.py SOURCES this file with
# REDEPLOY_SELFTEST=1 and drives the functions above with systemd-run stubbed.
# Run (not sourced) with it set, the wrapper refuses instead of turning a
# redeploy into a silent no-op. Never set it in production.
# --------------------------------------------------------------------------- #
if [[ "${REDEPLOY_SELFTEST:-0}" == "1" ]]; then
  return 0 2>/dev/null || { echo "redeploy: REDEPLOY_SELFTEST=1 is a test seam for sourcing this file — refusing to run" >&2; exit 1; }
fi

# --------------------------------------------------------------------------- #
# 0. Refuse an unknown ALLOW_* before anything else — before the root guard, the
#    fetch or the launch — so a typo never costs a deploy run that then stops on
#    the gate the flag was meant to open.
# --------------------------------------------------------------------------- #
check_allow_env || exit 1
check_attach || exit 1

# --------------------------------------------------------------------------- #
# 1. Root guard. deploy.sh stops the bot and writes under /etc, /usr/local/sbin,
#    and the systemd manager — all of which require root.
# --------------------------------------------------------------------------- #
[[ "${EUID}" -eq 0 ]] || { echo "redeploy: run as root (sudo bash scripts/redeploy.sh)" >&2; exit 1; }

# --------------------------------------------------------------------------- #
# 2. Operate from the production checkout (deploy.sh is fetched from its remote).
# --------------------------------------------------------------------------- #
cd "$APP_DIR" || { echo "redeploy: APP_DIR ${APP_DIR} not found" >&2; exit 1; }

# --------------------------------------------------------------------------- #
# 3. Fetch the latest origin/main only (the one branch we deploy), not the world.
# --------------------------------------------------------------------------- #
echo "redeploy: fetching origin/main"
git fetch origin main

# --------------------------------------------------------------------------- #
# 4. Show where the host stands relative to the tip we are about to deploy, and
#    spell out what will happen given CHECK / FORCE when they already match.
# --------------------------------------------------------------------------- #
host_head="$(git rev-parse --short HEAD)"
origin_head="$(git rev-parse --short origin/main)"
echo "redeploy: host HEAD=${host_head}  origin/main=${origin_head}"
if [[ "$host_head" == "$origin_head" ]]; then
  if   [[ "$CHECK" == "1" ]]; then echo "redeploy: host already at origin/main — CHECK=1 runs Phase 1 anyway (no mutations)"
  elif [[ "$FORCE" == "1" ]]; then echo "redeploy: host already at origin/main — FORCE=1 will redeploy anyway"
  else echo "redeploy: host already at origin/main — deploy.sh will no-op (use FORCE=1 to redeploy)"
  fi
fi

# --------------------------------------------------------------------------- #
# 5. Take deploy.sh FROM tip-of-main, never the (possibly stale) working tree.
#    The script is designed to deploy itself from origin/main, so it must be the
#    origin/main copy that runs — reading it out of the checkout could execute an
#    older deploy.sh than the one being deployed.
# --------------------------------------------------------------------------- #
echo "redeploy: extracting deploy.sh from origin/main -> ${TMP_DEPLOY}"
git show origin/main:scripts/deploy.sh > "$TMP_DEPLOY"

# --------------------------------------------------------------------------- #
# 6. Build deploy.sh's environment: CHECK/FORCE plus the allowlisted knobs
#    (build_deploy_env above).
# --------------------------------------------------------------------------- #
build_deploy_env

# --------------------------------------------------------------------------- #
# 7. Clear any lingering "failed" state from a previous run of the transient
#    unit — systemd refuses to start a unit name still in the failed state.
#    reset-failed is a no-op when the name is clean, so it is always safe first.
# --------------------------------------------------------------------------- #
systemctl reset-failed "$DEPLOY_UNIT" 2>/dev/null || true

# --------------------------------------------------------------------------- #
# 8. Launch deploy.sh detached (launch_deploy above). The `deploy.sh env:` line it
#    prints names every forwarded variable, so a CHECK=1 report already shows
#    whether a flag will reach the real run too.
# --------------------------------------------------------------------------- #
launch_deploy
