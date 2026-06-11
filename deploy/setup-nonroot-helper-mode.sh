#!/usr/bin/env bash
set -euo pipefail

# Idempotent sudo-helper non-root production preparation.
# This script installs helpers and permissions only; it does not restart the
# active vpn-bot systemd service.

BOT_USER="${BOT_USER:-vpn-bot}"
BOT_GROUP="${BOT_GROUP:-vpn-bot}"
BOT_HOME="${BOT_HOME:-/var/lib/vpn-bot}"
BOT_SHELL="${BOT_SHELL:-/usr/sbin/nologin}"
APP_DIR="${APP_DIR:-/opt/vpn-service}"
ENV_FILE="${ENV_FILE:-${APP_DIR}/.env}"
XRAY_CONFIG_PATH="${XRAY_CONFIG_PATH:-/usr/local/etc/xray/config.json}"
AWG_CONFIG_PATH="${AWG_CONFIG_PATH:-/etc/amnezia/amneziawg/awg0.conf}"
MTPROTO_MANAGED_DIR="${MTPROTO_MANAGED_DIR:-/etc/mtproxy/vpnbot}"
HELPER_SOURCE_DIR="${HELPER_SOURCE_DIR:-deploy/helpers}"
WARP_HELPER_SOURCE_DIR="${WARP_HELPER_SOURCE_DIR:-scripts}"
SUDOERS_SOURCE="${SUDOERS_SOURCE:-deploy/sudoers.d/vpnbot.example}"
SUDOERS_TARGET="${SUDOERS_TARGET:-/etc/sudoers.d/vpnbot}"

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run this script as root on the VDS." >&2
  exit 1
fi

if getent group "${BOT_GROUP}" >/dev/null; then
  echo "Group ${BOT_GROUP} already exists."
else
  groupadd --system "${BOT_GROUP}"
  echo "Created system group ${BOT_GROUP}."
fi

if id -u "${BOT_USER}" >/dev/null 2>&1; then
  echo "User ${BOT_USER} already exists."
else
  useradd \
    --system \
    --gid "${BOT_GROUP}" \
    --home-dir "${BOT_HOME}" \
    --no-create-home \
    --shell "${BOT_SHELL}" \
    --comment "VPN Telegram Bot" \
    "${BOT_USER}"
  echo "Created system user ${BOT_USER}."
fi

install -d -o "${BOT_USER}" -g "${BOT_GROUP}" -m 0700 "${APP_DIR}/data"
# Fix ownership of existing DB files left behind by a previous root-owned install.
find "${APP_DIR}/data" -maxdepth 1 -type f \( -name 'vpn.db' -o -name 'vpn.db-wal' -o -name 'vpn.db-shm' \) \
  -exec chown "${BOT_USER}:${BOT_GROUP}" {} \;
install -d -o "${BOT_USER}" -g "${BOT_GROUP}" -m 0700 "${APP_DIR}/logs"
install -d -o "${BOT_USER}" -g "${BOT_GROUP}" -m 0700 /run/vpn-bot
install -d -o "${BOT_USER}" -g "${BOT_GROUP}" -m 0700 /run/vpn-bot/xray
install -d -o "${BOT_USER}" -g "${BOT_GROUP}" -m 0700 /run/vpn-bot/awg
install -d -o "${BOT_USER}" -g "${BOT_GROUP}" -m 0700 /run/vpn-bot/mtproxy
install -d -o "${BOT_USER}" -g "${BOT_GROUP}" -m 0700 /run/vpn-bot/warp

if [[ -f "${ENV_FILE}" ]]; then
  chown root:"${BOT_GROUP}" "${ENV_FILE}"
  chmod 0640 "${ENV_FILE}"
fi

install -o root -g root -m 0755 "${HELPER_SOURCE_DIR}/vpnbot-socks5-user" /usr/local/sbin/vpnbot-socks5-user
install -o root -g root -m 0755 "${HELPER_SOURCE_DIR}/vpnbot-xray-apply" /usr/local/sbin/vpnbot-xray-apply
install -o root -g root -m 0755 "${HELPER_SOURCE_DIR}/vpnbot-awg-apply" /usr/local/sbin/vpnbot-awg-apply
install -o root -g root -m 0755 "${HELPER_SOURCE_DIR}/vpnbot-mtproxy-apply" /usr/local/sbin/vpnbot-mtproxy-apply

# WARP outbound-IP masking helpers live in scripts/ (not deploy/helpers/). They
# must be (re)installed here too, otherwise a `git reset` deploy leaves the stale
# /usr/local/sbin copy in place — which is exactly what shipped the broken routing
# helper before. Keep them byte-for-byte in sync with the checkout on every run.
install -o root -g root -m 0755 "${WARP_HELPER_SOURCE_DIR}/vpnbot-warp-install" /usr/local/sbin/vpnbot-warp-install
install -o root -g root -m 0755 "${WARP_HELPER_SOURCE_DIR}/vpnbot-warp-iface" /usr/local/sbin/vpnbot-warp-iface
install -o root -g root -m 0755 "${WARP_HELPER_SOURCE_DIR}/vpnbot-warp-routes" /usr/local/sbin/vpnbot-warp-routes
install -o root -g root -m 0755 "${WARP_HELPER_SOURCE_DIR}/vpnbot-warp-status" /usr/local/sbin/vpnbot-warp-status

if [[ -f "${XRAY_CONFIG_PATH}" ]]; then
  chown nobody:"${BOT_GROUP}" "${XRAY_CONFIG_PATH}"
  chmod 0640 "${XRAY_CONFIG_PATH}"
fi

if [[ -f "${AWG_CONFIG_PATH}" ]]; then
  chown root:"${BOT_GROUP}" "${AWG_CONFIG_PATH}"
  chmod 0640 "${AWG_CONFIG_PATH}"
fi

if [[ -d "${MTPROTO_MANAGED_DIR}" ]]; then
  chown root:"${BOT_GROUP}" "${MTPROTO_MANAGED_DIR}"
  chmod 0750 "${MTPROTO_MANAGED_DIR}"
  find "${MTPROTO_MANAGED_DIR}" -maxdepth 1 -type f -name 'managed-secrets.json' -exec chown root:"${BOT_GROUP}" {} \; -exec chmod 0640 {} \;
  find "${MTPROTO_MANAGED_DIR}" -maxdepth 1 -type f -name 'mtproxy.env' -exec chown root:"${BOT_GROUP}" {} \; -exec chmod 0640 {} \;
fi

visudo -cf "${SUDOERS_SOURCE}"
install -o root -g root -m 0440 "${SUDOERS_SOURCE}" "${SUDOERS_TARGET}"
visudo -cf "${SUDOERS_TARGET}"

cat <<EOF

sudo-helper non-root production preparation is installed.

Next manual steps:
- set PRIVILEGE_HELPERS_ENABLED=true and helper paths in ${ENV_FILE};
- run: python3 deploy/check-nonroot-helper-mode.py
- install deploy/vpn-bot.service if the active unit is not already non-root.

This script did not restart vpn-bot or replace the active systemd unit.
EOF
