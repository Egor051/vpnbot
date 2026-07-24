#!/usr/bin/env bash
# Open (or close) the public TCP port of the all-in-one subscription endpoint in ufw.
#
# WHY THIS IS A FILE AND NOT A COMMAND YOU TYPE ONCE
# A hand-typed `ufw allow` lives only in /etc/ufw/user.rules on one box. It is
# invisible in review, absent from a rebuilt host, and silently lost by a
# `ufw reset` — and its loss looks exactly like "the subscription URL stopped
# working for no reason". Keeping the rule here makes it reviewable, re-runnable
# and rebuildable.
#
# The port is read from .env (SUBSCRIPTION_PUBLIC_PORT), never hardcoded, so the
# firewall cannot drift from what the endpoint actually binds.
#
# Usage:
#   sudo bash deploy/ufw-subscription.sh            # add the allow rule
#   sudo bash deploy/ufw-subscription.sh --delete   # remove it
#   ENV_FILE=/path/to/.env sudo -E bash deploy/ufw-subscription.sh
#
# Idempotent: ufw skips a rule it already has, and --delete on a missing rule is
# a no-op. Nothing else about the firewall is touched.

set -euo pipefail

ENV_FILE="${ENV_FILE:-/opt/vpn-service/.env}"
ACTION="allow"
COMMENT="vpn-bot all-in-one subscription (HTTPS)"

case "${1:-}" in
  ""|--allow) ACTION="allow" ;;
  --delete|--remove) ACTION="delete" ;;
  -h|--help) sed -n '2,22p' "$0"; exit 0 ;;
  *) echo "unknown argument: $1 (expected --allow or --delete)" >&2; exit 2 ;;
esac

die() { echo "ufw-subscription: $*" >&2; exit 1; }

command -v ufw >/dev/null 2>&1 || die "ufw is not installed on this host"
[[ -r "$ENV_FILE" ]] || die "cannot read ${ENV_FILE} (set ENV_FILE=... to override)"

# Read the value without sourcing the file: .env holds the bot token and every
# backend secret, and sourcing it would export all of them into this shell.
read_env() {
  local key="$1" line
  line="$(grep -E "^[[:space:]]*${key}=" "$ENV_FILE" | tail -n1 || true)"
  line="${line#*=}"
  line="${line%\"}"; line="${line#\"}"
  line="${line%\'}"; line="${line#\'}"
  printf '%s' "$(echo "$line" | xargs)"
}

PORT="$(read_env SUBSCRIPTION_PUBLIC_PORT)"
ENABLED="$(read_env SUBSCRIPTION_ENABLED)"

[[ -n "$PORT" ]] || die "SUBSCRIPTION_PUBLIC_PORT is unset in ${ENV_FILE} — nothing to open"
[[ "$PORT" =~ ^[0-9]+$ ]] || die "SUBSCRIPTION_PUBLIC_PORT is not a number: ${PORT}"
(( PORT >= 1 && PORT <= 65535 )) || die "SUBSCRIPTION_PUBLIC_PORT out of range: ${PORT}"

if [[ "$ACTION" == "allow" ]]; then
  # A public port with the feature switched off would be an open door to a 404.
  # Refuse rather than "help": turning the flag on is the operator's decision.
  case "${ENABLED,,}" in
    1|true|yes|y|on) ;;
    *) die "SUBSCRIPTION_ENABLED is not true in ${ENV_FILE} — enable the feature before opening the port" ;;
  esac
  echo "ufw-subscription: allowing ${PORT}/tcp (${COMMENT})"
  ufw allow "${PORT}/tcp" comment "$COMMENT"
else
  echo "ufw-subscription: deleting allow rule for ${PORT}/tcp"
  ufw delete allow "${PORT}/tcp" || true
fi

ufw status | grep -E "^${PORT}/tcp" || echo "ufw-subscription: no rule for ${PORT}/tcp is present"
