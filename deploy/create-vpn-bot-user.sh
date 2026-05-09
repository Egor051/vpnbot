#!/usr/bin/env bash
set -euo pipefail

# This script creates the unprivileged production runtime identity.
# It intentionally does not install or restart deploy/vpn-bot.service, install
# sudoers files, or change ownership of the application tree.
#
# Keep /opt/vpn-service, the repository checkout, and .venv root-owned so a
# compromised bot process cannot rewrite its own code or dependencies.

BOT_USER="vpn-bot"
BOT_GROUP="vpn-bot"
BOT_HOME="/var/lib/vpn-bot"
BOT_SHELL="/usr/sbin/nologin"

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
  primary_group="$(id -gn "${BOT_USER}")"
  if [[ "${primary_group}" != "${BOT_GROUP}" ]]; then
    echo "Warning: ${BOT_USER} primary group is ${primary_group}, expected ${BOT_GROUP}." >&2
    echo "Review manually before installing the non-root production unit." >&2
  fi
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

cat <<'EOF'

Completed only the runtime identity preparation step.

This script did not:
- install or restart vpn-bot.service;
- restart any production service;
- install sudoers rules;
- change ownership of /opt/vpn-service or .venv.

Required production helper-mode steps:
- keep /opt/vpn-service and .venv root-owned and not writable by vpn-bot;
- grant vpn-bot write access only to /opt/vpn-service/data, /opt/vpn-service/logs if file logs remain enabled, and /run/vpn-bot;
- install root-owned helper scripts under /usr/local/sbin;
- validate a narrow sudoers file with visudo;
- install deploy/vpn-bot.service only after helper wiring is tested.
EOF
