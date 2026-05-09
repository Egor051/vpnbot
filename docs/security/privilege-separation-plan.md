# Package 5 Privilege Separation Plan

Status: Package 5D post-cutover production state. The recommended production mode is non-root `vpn-bot:vpn-bot` plus fixed sudo helpers. The root/direct unit remains only as a legacy rollback template.

Production helper entrypoints:

- `/usr/local/sbin/vpnbot-socks5-user`
- `/usr/local/sbin/vpnbot-xray-apply`
- `/usr/local/sbin/vpnbot-awg-apply`
- `/usr/local/sbin/vpnbot-mtproxy-apply`

Recommended `.env` helper-mode settings:

```env
PRIVILEGE_HELPERS_ENABLED=true
HELPER_STAGING_ROOT=/run/vpn-bot
SOCKS5_USER_HELPER_PATH=/usr/local/sbin/vpnbot-socks5-user
XRAY_APPLY_HELPER_PATH=/usr/local/sbin/vpnbot-xray-apply
AWG_APPLY_HELPER_PATH=/usr/local/sbin/vpnbot-awg-apply
MTPROTO_APPLY_HELPER_PATH=/usr/local/sbin/vpnbot-mtproxy-apply
XRAY_HELPER_STAGING_DIR=/run/vpn-bot/xray
AWG_HELPER_STAGING_DIR=/run/vpn-bot/awg
MTPROTO_HELPER_STAGING_DIR=/run/vpn-bot/mtproxy
BOT_LOCK_PATH=/run/vpn-bot/vpn-bot.lock
```

## Systemd Model

`deploy/vpn-bot.service` is the recommended production unit:

- `Description=VPN Telegram Bot`
- `User=vpn-bot`
- `Group=vpn-bot`
- `Environment=BOT_LOCK_PATH=/run/vpn-bot/vpn-bot.lock`
- `RuntimeDirectory=vpn-bot`
- `RuntimeDirectoryMode=0700`
- no `NoNewPrivileges=true`, because sudo helpers require privilege elevation through the sudo/setuid boundary
- `ProtectSystem=strict` remains enabled. `ReadWritePaths` includes the local account database files only because sudo-launched SOCKS5 helper processes inherit the service mount namespace and need those exact files for `useradd`, `chpasswd`, `passwd -l`, and `userdel`.

`deploy/vpn-bot.root-legacy.example.service` is kept only for rollback to root/direct mode. Do not treat the root/direct unit as the normal production deployment.

## Ownership Model

| Path | Owner | Group | Mode | Bot access |
| --- | --- | --- | --- | --- |
| `/opt/vpn-service` | `root` | `root` | admin-managed | read/execute only |
| `/opt/vpn-service/.env` | `root` | `vpn-bot` | `0640` | read only |
| `/opt/vpn-service/.venv` | `root` | `root` | admin-managed | read/execute only |
| `/opt/vpn-service/data` | `vpn-bot` | `vpn-bot` | `0700` | read/write |
| `/opt/vpn-service/logs` | `vpn-bot` | `vpn-bot` | `0700` | read/write |
| `/run/vpn-bot` | `vpn-bot` | `vpn-bot` | `0700` | read/write staging and lock |
| `/usr/local/sbin/vpnbot-*` | `root` | `root` | `0755` | sudo entrypoint only |
| `/usr/local/etc/xray/config.json` | `nobody` | `vpn-bot` | `0640` | read only |
| `/etc/amnezia/amneziawg/awg0.conf` | `root` | `vpn-bot` | `0640` | read only |
| `/etc/mtproxy/vpnbot` | `root` | `vpn-bot` | `0750` | traverse/read managed files |
| `/etc/mtproxy/vpnbot/managed-secrets.json` | `root` | `vpn-bot` | `0640` | read only |
| `/etc/mtproxy/vpnbot/mtproxy.env` | `root` | `vpn-bot` | `0640` | read only |
| `/etc/sudoers.d/vpnbot` | `root` | `root` | `0440` | sudo policy only |

The bot must not directly write account databases, canonical Xray config, canonical AWG config, or canonical MTProxy managed state. It stages candidates under `/run/vpn-bot`, then calls fixed helpers through `sudo -n`. The unit exposes account database paths as writable to the mount namespace for the SOCKS5 helper, but normal bot access is still blocked by Unix ownership and the sudoers policy remains helper-only.

## Helper Contracts

### SOCKS5

Path: `/usr/local/sbin/vpnbot-socks5-user`.

Required properties:

- Callable by `vpn-bot` only through `/etc/sudoers.d/vpnbot`.
- Allowed actions: `exists <login>`, `create <login>`, `set-password <login>` with the password read from stdin, `lock <login>`, and `delete <login>`.
- Enforces the configured login prefix, for example `vpn_socks_`.
- Enforces strict login regex compatible with Linux account naming, for example `^[A-Za-z_][A-Za-z0-9_]{0,31}$`.
- Never accepts arbitrary usernames, shell paths from untrusted args, or password material in argv.
- Never prints passwords.

### Xray

Path: `/usr/local/sbin/vpnbot-xray-apply`.

Required properties:

- Accepts candidates only from `/run/vpn-bot/xray`.
- Validates JSON and Xray syntax before install.
- Atomically installs `/usr/local/etc/xray/config.json` as `nobody:vpn-bot` mode `0640`.
- Applies only the fixed `xray` service and verifies active state.
- Rolls back inside the helper on apply failure.

### AWG

Path: `/usr/local/sbin/vpnbot-awg-apply`.

Required properties:

- Accepts candidates only from `/run/vpn-bot/awg`.
- Validates with the configured AWG/WG strip tool before install.
- Atomically installs `/etc/amnezia/amneziawg/awg0.conf` as `root:vpn-bot` mode `0640`.
- Applies runtime only for fixed interface `awg0`.
- Provides sanitized read-only status/peer/transfer output for the fixed interface.
- Rolls back inside the helper on apply failure.

### MTProxy

Path: `/usr/local/sbin/vpnbot-mtproxy-apply`.

Required properties:

- Accepts candidate directories only from `/run/vpn-bot/mtproxy`.
- Validates `managed-secrets.json` and `mtproxy.env` without printing raw secrets.
- Never prints raw MTProto secrets or generated links.
- Redacts secrets in errors, logs, and rollback summaries.
- Installs `/etc/mtproxy/vpnbot` as `root:vpn-bot` mode `0750`.
- Installs managed secret/env files as `root:vpn-bot` mode `0640`.
- Applies only the fixed `mtproxy` service and verifies active/listening state.
- Rolls back inside the helper on apply failure.

## Sudoers Requirements

Validate before installing:

```bash
visudo -cf deploy/sudoers.d/vpnbot.example
install -o root -g root -m 0440 deploy/sudoers.d/vpnbot.example /etc/sudoers.d/vpnbot
visudo -cf /etc/sudoers.d/vpnbot
```

The sudoers policy must grant only fixed helper commands and actions. It must not grant unrestricted sudo, broad account-management commands, broad service-manager commands, raw backend binaries, or shell access.

## Production Runbook

Pre-change backup:

```bash
set -euo pipefail
sudo install -d -o root -g root -m 0700 /root/vpnbot-package5d-backup
sudo cp -a /opt/vpn-service/.env /root/vpnbot-package5d-backup/env.backup
sudo cp -a /etc/systemd/system/vpn-bot.service /root/vpnbot-package5d-backup/vpn-bot.service.backup
sudo cp -a /usr/local/etc/xray/config.json /root/vpnbot-package5d-backup/xray-config.json.backup
sudo cp -a /etc/amnezia/amneziawg/awg0.conf /root/vpnbot-package5d-backup/awg0.conf.backup
sudo tar -C /etc/mtproxy -czf /root/vpnbot-package5d-backup/mtproxy-vpnbot.tgz vpnbot
sudo sqlite3 /opt/vpn-service/data/vpn.db ".backup '/root/vpnbot-package5d-backup/vpn.db.backup'"
```

Install identity, helpers, sudoers, runtime directories, and read permissions:

```bash
sudo bash deploy/setup-nonroot-helper-mode.sh
sudo visudo -cf deploy/sudoers.d/vpnbot.example
sudo visudo -cf /etc/sudoers.d/vpnbot
```

Preflight before restart:

```bash
sudo python3 deploy/check-nonroot-helper-mode.py
sudo -u vpn-bot test -r /opt/vpn-service/.env
sudo -u vpn-bot test -w /opt/vpn-service/data
sudo -u vpn-bot test -w /opt/vpn-service/logs
sudo -u vpn-bot test -w /run/vpn-bot
sudo -u vpn-bot test -r /usr/local/etc/xray/config.json
sudo -u vpn-bot test -r /etc/amnezia/amneziawg/awg0.conf
sudo -u vpn-bot test -r /etc/mtproxy/vpnbot/managed-secrets.json
sudo -u vpn-bot sudo -n /usr/local/sbin/vpnbot-xray-apply status
sudo -u vpn-bot sudo -n /usr/local/sbin/vpnbot-awg-apply status
sudo -u vpn-bot sudo -n /usr/local/sbin/vpnbot-mtproxy-apply status
sudo -u vpn-bot sudo -n /usr/local/sbin/vpnbot-socks5-user exists vpn_socks_preflight
```

Install or refresh the production unit:

```bash
sudo install -o root -g root -m 0644 deploy/vpn-bot.service /etc/systemd/system/vpn-bot.service
sudo systemctl daemon-reload
sudo systemctl restart vpn-bot
sudo systemctl status vpn-bot --no-pager
```

Post-cutover checklist:

- `deploy/check-nonroot-helper-mode.py` reports `failures=0 warnings=0`.
- Process user is `vpn-bot:vpn-bot`.
- `vpn-bot`, `xray`, `awg-quick@awg0`, `danted`, and `mtproxy` are active when those backends are enabled.
- `journalctl -b -u vpn-bot` has no `degraded`, `critical`, `error`, `traceback`, `permission denied`, or `not permitted` entries.
- Reboot verification passed after a full host reboot.
- Post-reboot backup made after the verified boot.

## Rollback

Use rollback only when production helper mode cannot be repaired quickly:

```bash
sudo sed -i 's/^PRIVILEGE_HELPERS_ENABLED=.*/PRIVILEGE_HELPERS_ENABLED=false/' /opt/vpn-service/.env
sudo install -o root -g root -m 0644 deploy/vpn-bot.root-legacy.example.service /etc/systemd/system/vpn-bot.service
sudo systemctl daemon-reload
sudo systemctl restart vpn-bot
sudo systemctl status vpn-bot --no-pager
sudo journalctl -u vpn-bot -n 100 --no-pager
```

After rollback, keep helper files and sudoers only if they are still needed for a planned retry. Validate any sudoers removal or replacement with `visudo -cf`.

## Non-Changes

- No SQLite schema change is required.
- No business logic for issuing or revoking VPN/proxy access changes.
- Helper mode remains controlled by explicit environment configuration.
- The sudoers policy remains helper-only and does not grant broad root command access.
