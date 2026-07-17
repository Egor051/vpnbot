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
# 6. Translate this wrapper's CHECK/FORCE into deploy.sh's own env knobs.
#    CHECK=1 => PHASE1_ONLY=1 (read-only Phase 1); FORCE is passed through as-is.
# --------------------------------------------------------------------------- #
deploy_env=()
[[ "$CHECK" == "1" ]] && deploy_env+=("PHASE1_ONLY=1")
[[ "$FORCE" == "1" ]] && deploy_env+=("FORCE=1")

# --------------------------------------------------------------------------- #
# 7. Clear any lingering "failed" state from a previous run of the transient
#    unit — systemd refuses to start a unit name still in the failed state.
#    reset-failed is a no-op when the name is clean, so it is always safe first.
# --------------------------------------------------------------------------- #
systemctl reset-failed "$DEPLOY_UNIT" 2>/dev/null || true

# --------------------------------------------------------------------------- #
# 8. Launch deploy.sh DETACHED under systemd, output tee'd to a timestamped log.
#    --collect reaps the transient unit when it exits; --pty streams live output
#    while keeping the run attached to systemd (not our SSH session), so an SSH
#    disconnect can never kill a half-finished deploy. The env prefix injects the
#    PHASE1_ONLY/FORCE flags; the log file survives for post-mortem.
#    ${deploy_env[@]+...} makes the empty-array expansion safe under `set -u`.
# --------------------------------------------------------------------------- #
ts="$(date -u +%Y%m%dT%H%M%SZ)"
log_file="${LOG_DIR%/}/deploy-${ts}.log"
echo "redeploy: launching ${DEPLOY_UNIT} (log: ${log_file})"
echo "redeploy:   deploy.sh env: ${deploy_env[*]:-<none>}"
systemd-run --unit="$DEPLOY_UNIT" --collect --pty \
  env ${deploy_env[@]+"${deploy_env[@]}"} \
  bash -c "bash ${TMP_DEPLOY} 2>&1 | tee ${log_file}"
