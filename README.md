# VPN Telegram Bot

Telegram bot for self-hosted VPN access management on an Ubuntu VDS. The bot manages users, access approval, Xray VLESS Reality keys, AmneziaWG keys, key revocation/deletion, audit records, and basic traffic statistics.

This project is designed for a single-server deployment without Docker, Redis, PostgreSQL, or a heavy ORM.

## Features

- Telegram user registration and access approval flow.
- Admin panel for pending requests, users, key issuance, audit, stats, and announcements.
- Xray VLESS Reality key creation, config delivery, revocation, deletion, and startup reconciliation.
- AmneziaWG key creation, client config delivery, revocation, deletion, IP allocation, and startup reconciliation.
- Separate one-page Telegram section "Прокси" for SOCKS5/Dante auto-issue and Telegram MTProto Proxy links.
- MTProto supports `static` compatibility mode and `managed` mode with per-user secrets, safe apply, and rollback.
- Optional legacy proxy entry table seeded from `DEFAULT_PROXY_*` remains internal/compatibility storage; the user-facing proxy UX uses `proxy_accesses`.
- Ownership checks so users can view their own configs/stats; destructive VPN and proxy lifecycle actions are admin-only.
- Audit log with recursive masking for sensitive values.
- SQLite storage with migrations from `db/schema.sql`.
- Rotating local logs in `LOG_DIR`.
- systemd deployment using `deploy/vpn-bot.service` in non-root sudo-helper mode.
- Intended target: Ubuntu VDS with existing Xray and/or AmneziaWG installation.

## Stack

- Python 3
- aiogram 3
- SQLite via aiosqlite
- python-dotenv
- systemd
- Xray VLESS Reality
- AmneziaWG / WireGuard-compatible tooling
- Ubuntu / Linux VDS

## Repository Layout

```text
main.py                    # Bot entry point
init_db.py                 # SQLite schema bootstrap/migration entry point
requirements.txt           # Runtime dependencies
constraints.txt            # Pinned production dependency constraints
.env.example               # Environment variable template
db/schema.sql              # Database schema
deploy/vpn-bot.service     # recommended non-root sudo-helper systemd unit
deploy/vpn-bot.root-legacy.example.service # legacy root/direct fallback unit
deploy/run-mtproxy-managed # MTProxy managed-mode wrapper installed during deploy
deploy/mtproxy-vpnbot-managed.conf # MTProxy drop-in installed during deploy
bot/                       # Telegram handlers, keyboards, FSM, formatting
services/                  # Business workflows and permissions
repositories/              # SQLite access layer
adapters/                  # Xray, AWG, systemctl, backups, shell adapters
config/settings.py         # Environment parsing and validation
tests/                     # Regression and hardening tests
```

## Security Warning

This project handles operational VPN and Telegram secrets. Never commit or publish:

- `.env` files.
- Telegram bot tokens.
- Private keys or preshared keys.
- Real Xray Reality server/client configuration.
- Real AmneziaWG server/client configuration.
- Full VPN client configs.
- SQLite databases or database dumps.
- Server IP addresses combined with credentials.
- SSH, panel, hosting, or other server credentials.
- Recommended BotFather setting: disable adding this bot to groups. The bot is designed to work in private chats only; group chats may expose user data, admin actions, or sensitive operational messages.

Use `.env.example` only as a template. Keep production configuration on the server and outside Git history.

## Environment Variables

Copy `.env.example` to `.env` and replace placeholders with values for your server. `BOT_TOKEN` and `ADMIN_IDS` are required for startup. Fill the relevant Xray or AWG values before issuing that key type.

```dotenv
BOT_TOKEN=<telegram_bot_token>
ADMIN_IDS=<telegram_user_id>,<telegram_user_id>

DB_PATH=/opt/vpn-service/data/vpn.db
SQLITE_SYNCHRONOUS=FULL
LOG_DIR=/opt/vpn-service/logs
BOT_LOCK_PATH=/run/vpn-bot/vpn-bot.lock

PRIVILEGE_HELPERS_ENABLED=true
HELPER_STAGING_ROOT=/run/vpn-bot
SOCKS5_USER_HELPER_PATH=/usr/local/sbin/vpnbot-socks5-user
XRAY_APPLY_HELPER_PATH=/usr/local/sbin/vpnbot-xray-apply
AWG_APPLY_HELPER_PATH=/usr/local/sbin/vpnbot-awg-apply
MTPROTO_APPLY_HELPER_PATH=/usr/local/sbin/vpnbot-mtproxy-apply
XRAY_HELPER_STAGING_DIR=/run/vpn-bot/xray
AWG_HELPER_STAGING_DIR=/run/vpn-bot/awg
MTPROTO_HELPER_STAGING_DIR=/run/vpn-bot/mtproxy

XRAY_CONFIG_PATH=/usr/local/etc/xray/config.json
XRAY_SERVICE_NAME=xray
XRAY_INBOUND_TAG=
XRAY_PUBLIC_HOST=<vpn_public_host>
XRAY_PUBLIC_PORT=443
XRAY_REALITY_PUBLIC_KEY=<xray_reality_public_key>
XRAY_SNI=<xray_reality_sni>
XRAY_FLOW=xtls-rprx-vision
XRAY_FINGERPRINT=chrome
XRAY_NETWORK_TYPE=tcp
XRAY_SHORT_ID=<xray_short_id>
XRAY_MANAGE_SHORT_IDS=false
XRAY_ALLOW_RESTART_ON_ROLLBACK=false
XRAY_STATS_SERVER=

AWG_CONFIG_PATH=/etc/amnezia/amneziawg/awg0.conf
AWG_INTERFACE=awg0
AWG_NETWORK=10.0.0.0/24
AWG_SERVER_ADDRESS=10.0.0.1
AWG_ENDPOINT_HOST=<awg_endpoint_host>
AWG_ENDPOINT_PORT=<awg_endpoint_port>
AWG_SERVER_PUBLIC_KEY=<awg_server_public_key>
AWG_DNS=1.1.1.1
AWG_MTU=
AWG_ALLOWED_IPS=0.0.0.0/0, ::/0
AWG_PERSISTENT_KEEPALIVE=25
AWG_USE_PRESHARED_KEY=true

DEFAULT_PROXY_TYPE=
DEFAULT_PROXY_HOST=
DEFAULT_PROXY_PORT=
DEFAULT_PROXY_LOGIN=
DEFAULT_PROXY_PASSWORD=
DEFAULT_PROXY_NOTE=

SOCKS5_ENABLED=false
SOCKS5_HOST=
SOCKS5_PORT=31337
SOCKS5_LOGIN_PREFIX=vpn_socks_
SOCKS5_SYSTEM_USER_SHELL=/usr/sbin/nologin
SOCKS5_SERVICE_NAME=danted
SOCKS5_PUBLIC_NAME=SOCKS5 Proxy
SOCKS5_NOTE=SOCKS5 Dante proxy on VDS

MTPROTO_ENABLED=false
MTPROTO_MODE=static
MTPROTO_HOST=
MTPROTO_PORT=8443
MTPROTO_SECRET=
MTPROTO_PUBLIC_NAME=Telegram MTProto Proxy
MTPROTO_NOTE=MTProto proxy for Telegram

# Managed MTProto per-user secrets mode
MTPROTO_SERVICE_NAME=mtproxy
MTPROTO_BINARY_PATH=/usr/local/bin/mtproto-proxy
MTPROTO_RUN_USER=mtproxy
MTPROTO_RUN_GROUP=mtproxy
MTPROTO_CONFIG_DIR=/etc/mtproxy
MTPROTO_PROXY_SECRET_PATH=/etc/mtproxy/proxy-secret
MTPROTO_PROXY_MULTI_CONF_PATH=/etc/mtproxy/proxy-multi.conf
MTPROTO_MANAGED_DIR=/etc/mtproxy/vpnbot
MTPROTO_MANAGED_SECRETS_PATH=/etc/mtproxy/vpnbot/managed-secrets.json
MTPROTO_MANAGED_ENV_PATH=/etc/mtproxy/vpnbot/mtproxy.env
MTPROTO_MANAGED_WRAPPER_PATH=/opt/vpn-service/scripts/run-mtproxy-managed
MTPROTO_BACKUP_DIR=/etc/mtproxy/vpnbot/backups
MTPROTO_INTERNAL_STATS_PORT=8888
MTPROTO_WORKERS=1
MTPROTO_APPLY_TIMEOUT_SECONDS=10
MTPROTO_ROLLBACK_ON_APPLY_FAILURE=true
MTPROTO_KEEP_LAST_BACKUPS=10
MTPROTO_STATS_URL=

AUDIT_RETENTION_DAYS=180
CONFIG_BACKUP_KEEP_LAST=20
```

Notes:

- Recommended production mode is `deploy/vpn-bot.service` running as `vpn-bot:vpn-bot` with `PRIVILEGE_HELPERS_ENABLED=true` and fixed sudo helpers installed. Use `deploy/vpn-bot.root-legacy.example.service` only as a legacy rollback/fallback unit.
- If `XRAY_INBOUND_TAG` is empty, the adapter uses the first inbound with `settings.clients`.
- If `XRAY_MANAGE_SHORT_IDS=false`, `XRAY_SHORT_ID` must be set.
- `XRAY_APPLY_MODE=restart` is the default production apply mode; use `reload` only when your Xray unit reliably applies reload.
- `SQLITE_SYNCHRONOUS=FULL` is the safer default for this control-plane database. `NORMAL` is faster but can lose the last committed transactions on OS or power failure while VPN backend state has already changed.
- `AWG_CLIENT_DNS` is supported only as a legacy alias; use `AWG_DNS` for new deployments.
- `AWG_ENDPOINT_HOST` and `AWG_ENDPOINT_PORT` should point to the public AWG endpoint clients will use.
- `SOCKS5_ENABLED=true` requires `SOCKS5_HOST`, `SOCKS5_PORT`, and a safe `SOCKS5_LOGIN_PREFIX`. Dante must already be installed and listening; the bot only creates/locks/deletes managed Linux users with that prefix.
- `MTPROTO_ENABLED=true` requires `MTPROTO_HOST`. `MTPROTO_MODE=static` also requires `MTPROTO_SECRET`.
- `MTPROTO_MODE=static` is compatibility mode: the bot shows a shared MTProto secret and can only deactivate a user's SQLite record. True per-user server-side revoke is impossible in static mode without rotating the shared secret.
- `MTPROTO_MODE=managed` creates one unique secret per user, writes managed secrets/env files under `/etc/mtproxy/vpnbot`, restarts `mtproxy`, verifies service/port health, and rolls back managed files if apply fails. The systemd drop-in and wrapper are installed during deploy, not written by the bot at runtime.
- `MTPROTO_SECRET`, SOCKS5 passwords, and real production endpoints with credentials must never be committed. `.env.example` intentionally keeps proxy secrets empty.
- `DEFAULT_PROXY_*` is legacy compatibility storage and does not drive the new user-facing proxy access flow.

## Access Lifecycle Policy

- Approved users may create their own Xray/AWG keys, view their own active configs, view stats, and edit their own key notes.
- Approved users may issue and view their own SOCKS5/MTProto proxy access when the backend is enabled.
- Revoke/delete for Xray and AWG keys is admin-only. Normal users do not get revoke/delete buttons, and direct callbacks/service calls are rejected.
- Revoke/delete for SOCKS5 and MTProto proxy access is admin-only. The user-facing proxy page only issues/shows active access and stats.
- Blocking a user is an admin action. It blocks bot access and attempts to revoke active/problem VPN keys and SOCKS5/MTProto proxy access.
- In `MTPROTO_MODE=static`, blocking/revoking only deactivates the bot/SQLite record; a copied shared secret keeps working until the shared secret is rotated.
- In `MTPROTO_MODE=managed`, admin revoke removes that user's MTProto secret from the managed active list while other users remain active.

## Backend Degraded Mode

The bot marks a backend DEGRADED when reconciliation or post-apply compensation cannot prove that SQLite and the server runtime are safe to mutate automatically. DEGRADED is backend-specific:

- Xray DEGRADED blocks Xray create/revoke/delete/manual reconcile only.
- AWG DEGRADED blocks AWG create/revoke/delete/manual reconcile only.
- SOCKS5 DEGRADED blocks SOCKS5 issue/revoke/delete only.
- MTProto DEGRADED blocks MTProto issue/revoke/delete only.
- Other backends continue working unless they are also DEGRADED.

The admin panel has `Диагностика backend`, which shows `OK` or `DEGRADED` for Xray, AWG, SOCKS5, and MTProto plus a non-secret reason. For full context, check `journalctl -u vpn-bot`, audit rows, SQLite lifecycle statuses, and the backend config/runtime listed in the runbooks below. Recover by fixing the server state from backups or manual inspection, then restart `vpn-bot` so startup reconciliation can re-check the backend.

## Proxy Deployment Notes

The bot does not install Dante or MTProxy. Prepare them on the VDS first, then enable the relevant env flags.

SOCKS5/Dante expectations:

- Dante listens on the configured public host/port, for example `0.0.0.0:31337`.
- Authentication is Linux username/password.
- In recommended production mode the bot calls `/usr/local/sbin/vpnbot-socks5-user` through `sudo -n`; sudoers grants only that fixed helper and actions.
- The bot refuses to manage Linux users whose login does not start with `SOCKS5_LOGIN_PREFIX`.

MTProto static mode:

- Set `MTPROTO_MODE=static` and provide `MTPROTO_SECRET`.
- MTProxy is managed outside the bot by its own systemd unit.
- The bot does not edit MTProxy files in static mode.
- User output always includes both Telegram links: plain secret first, then the `dd` random-padding variant.
- Static mode uses a shared secret; blocking one user only deactivates the bot record and does not revoke that user server-side.

MTProto managed mode:

- Set `MTPROTO_MODE=managed`; do not set a shared production secret in `MTPROTO_SECRET` for new users.
- MTProxy must already be installed and have valid `proxy-secret` and `proxy-multi.conf` files.
- Install the managed wrapper/drop-in once during deploy. The default model is root-wrapper: wrapper запускается от root; systemd starts the wrapper as root, the wrapper reads root-only managed env/secrets, and the wrapper starts `mtproto-proxy` with `-u mtproxy` from `MTPROTO_RUN_USER` so the proxy process drops privileges internally.
  ```bash
  sudo install -m 700 -d /opt/vpn-service/scripts
  sudo install -m 700 deploy/run-mtproxy-managed /opt/vpn-service/scripts/run-mtproxy-managed
  sudo install -m 700 -d /etc/systemd/system/mtproxy.service.d
  sudo install -m 600 deploy/mtproxy-vpnbot-managed.conf /etc/systemd/system/mtproxy.service.d/vpnbot-managed.conf
  sudo install -m 750 -o root -g vpn-bot -d /etc/mtproxy/vpnbot
  sudo install -m 700 -o root -g root -d /etc/mtproxy/vpnbot/backups
  sudo chown root:root /opt/vpn-service/scripts/run-mtproxy-managed
  sudo /opt/vpn-service/.venv/bin/python - <<'PY'
  import json, secrets
  from pathlib import Path
  managed = Path("/etc/mtproxy/vpnbot")
  placeholder = secrets.token_hex(16)
  (managed / "managed-secrets.json").write_text(json.dumps({
      "version": 1,
      "generation": 0,
      "managed_by": "vpn-bot",
      "secrets": [],
      "runtime_secrets": [{"secret": placeholder, "fingerprint": "empty-placeholder", "purpose": "empty-placeholder"}],
  }, indent=2, sort_keys=True) + "\n", encoding="utf-8")
  (managed / "mtproxy.env").write_text(
      "MTPROTO_BINARY_PATH=/usr/local/bin/mtproto-proxy\n"
      "MTPROTO_RUN_USER=mtproxy\n"
      "MTPROTO_RUN_GROUP=mtproxy\n"
      "MTPROTO_PROXY_SECRET_PATH=/etc/mtproxy/proxy-secret\n"
      "MTPROTO_PROXY_MULTI_CONF_PATH=/etc/mtproxy/proxy-multi.conf\n"
      "MTPROTO_MANAGED_SECRETS_PATH=/etc/mtproxy/vpnbot/managed-secrets.json\n"
      "MTPROTO_PORT=8443\n"
      "MTPROTO_INTERNAL_STATS_PORT=8888\n"
      "MTPROTO_WORKERS=1\n",
      encoding="utf-8",
  )
  PY
  sudo chmod 640 /etc/mtproxy/vpnbot/managed-secrets.json /etc/mtproxy/vpnbot/mtproxy.env
  sudo chown root:vpn-bot /etc/mtproxy/vpnbot/managed-secrets.json /etc/mtproxy/vpnbot/mtproxy.env
  sudo systemctl daemon-reload
  sudo systemctl restart mtproxy
  sudo systemctl status mtproxy --no-pager
  sudo ss -tlnp | grep 8443
  ```
- The drop-in clears any existing `User=`/`Group=` from `mtproxy.service`; `systemctl show mtproxy -p User -p Group -p ExecStart` should show empty `User`/`Group` and `ExecStart=/opt/vpn-service/scripts/run-mtproxy-managed`.
- If `MTPROTO_MANAGED_WRAPPER_PATH` or `MTPROTO_MANAGED_ENV_PATH` differs from the defaults, edit the installed wrapper/drop-in during deploy and run `systemctl daemon-reload` manually.
- Do not set `MTPROTO_MODE=managed` in `vpn-bot` until the placeholder managed baseline above has restarted successfully and `mtproxy` is active/listening. Bot issue/revoke refuses to proceed when `MTPROTO_MANAGED_SECRETS_PATH` or `MTPROTO_MANAGED_ENV_PATH` is missing, so the first user apply always has known-good files to roll back to.
- At runtime the bot writes only:
  - `MTPROTO_MANAGED_SECRETS_PATH`, containing active per-user secrets and a private runtime placeholder when no user secrets exist.
  - `MTPROTO_MANAGED_ENV_PATH`, containing non-secret runtime paths/options.
  - `MTPROTO_BACKUP_DIR/<backup-id>/`, containing private backups of managed secrets/env.
- On issue/revoke the bot backs up managed files, writes changes atomically, restarts `mtproxy`, checks `systemctl is-active`, checks that `MTPROTO_PORT` is listening, and restores the previous managed files on apply failure. It does not write `/etc/systemd/system` and does not run `systemctl daemon-reload` during normal issue/revoke.
- Managed mode gives real per-user revoke by removing only that user's secret from the active MTProxy list. Other users' secrets remain in the managed file.
- Raw MTProto secrets are not shown in admin status, audit, logs, README, or `.env.example`; admin diagnostics use counts and fingerprints only.
- In recommended non-root mode, managed secrets and env files are `root:vpn-bot` `0640`, and `/etc/mtproxy/vpnbot` is `root:vpn-bot` `0750`, so the bot can read before staging but cannot write canonical state. Backup directories remain root-only, and backup files that may contain secrets stay root-only. The wrapper is `root:root` `0700`; the systemd drop-in contains no secrets and can be `root:root` `0600`.

MTProto managed mode visibility checks:

- `systemctl cat mtproxy` and `systemctl show mtproxy -p User -p Group -p ExecStart -p Environment` should show only the wrapper/env paths, not raw secrets. In the default root-wrapper model, `User` and `Group` are empty at service level.
- `journalctl -u vpn-bot` and `journalctl -u mtproxy` should not contain raw MTProto secrets; the bot redacts audit/error details and the wrapper does not print secrets. If your MTProxy build logs accepted secrets or generated links, do not use managed mode until that logging is disabled or the binary is replaced.
- The official `mtproto-proxy` binary accepts client secrets as `-S <secret>` arguments. That means raw secrets can be visible in process argv to root, and to unprivileged users unless `/proc` is hardened. Restrict shell access, consider mounting `/proc` with `hidepid=2`, and do not enable managed mode with this binary if your requirement is "raw MTProto secrets are never visible to root-level process inspection".

Manual rollback for managed MTProto:

1. Stop `vpn-bot`.
2. Inspect `MTPROTO_BACKUP_DIR`, default `/etc/mtproxy/vpnbot/backups`.
3. Restore the previous managed secrets/env files from the latest known-good backup if automatic rollback did not recover.
4. Run `sudo systemctl restart mtproxy`.
5. Check `sudo systemctl status mtproxy --no-pager` and `sudo ss -tlnp | grep 8443`.

Proxy statistics are lifecycle/accounting stats from SQLite: issued, active, revoked/deactivated, timestamps, status, reason, and error. The bot does not invent per-user traffic for Dante or MTProxy. Without Dante per-login accounting or a safe aggregate MTProxy stats endpoint, traffic is shown as unavailable.

## Deployment Overview

The supplied systemd unit expects the project in `/opt/vpn-service`. If you deploy elsewhere, update `deploy/vpn-bot.service` before installing it.

Recommended production mode is non-root `vpn-bot:vpn-bot` with fixed sudo helpers. The root/direct unit is kept only as `deploy/vpn-bot.root-legacy.example.service` for rollback.

Short order:

1. Clone the repository and keep code plus `.venv` root-owned.
2. Create a virtual environment.
3. Install `requirements.txt`.
4. Copy `.env.example` to `.env`.
5. Fill `.env`, keeping `PRIVILEGE_HELPERS_ENABLED=true`.
6. Install the `vpn-bot` identity, helpers, sudoers, runtime directories, and backend read permissions.
7. Initialize the database as `vpn-bot`.
8. Run non-root helper preflight.
9. Install the systemd service.

```bash
sudo mkdir -p /opt/vpn-service
sudo git clone https://github.com/Egor051/vpnbot.git /opt/vpn-service
cd /opt/vpn-service

sudo python3 -m venv .venv
sudo .venv/bin/pip install --upgrade pip
sudo .venv/bin/pip install -r requirements.txt -c constraints.txt

sudo cp .env.example .env
sudo nano .env

sudo chown -R root:root /opt/vpn-service
sudo bash deploy/setup-nonroot-helper-mode.sh
sudo -u vpn-bot .venv/bin/python init_db.py
sudo python3 deploy/check-nonroot-helper-mode.py
```

Install and start the systemd service:

```bash
sudo install -o root -g root -m 0644 deploy/vpn-bot.service /etc/systemd/system/vpn-bot.service
sudo systemctl daemon-reload
sudo systemctl enable --now vpn-bot
sudo systemctl status vpn-bot --no-pager
```

If `MTPROTO_MODE=managed` is enabled, keep the supplied unit's write access narrowed to `/etc/mtproxy/vpnbot` for helper-owned managed secrets/env/backups. Do not grant `vpn-bot.service` runtime write access to `/etc/systemd/system` or broad write access to `/etc/mtproxy`; install or update the MTProxy drop-in and wrapper manually during deploy, then run `systemctl daemon-reload` outside the bot runtime.

## Local Checks

Install runtime and development dependencies before running checks:

```bash
python -m pip install -r requirements.txt -c constraints.txt
python -m pip install -r requirements-dev.txt
```

Run the same core gates used by CI:

```bash
python -m ruff check . --select=E9,F63,F7,F82
python -m compileall .
python -m pytest
python -m pip_audit -r requirements.txt -r constraints.txt --no-deps
```

## CI Checks

GitHub Actions runs the local gates without production secrets or live services:

- Python 3.11 and 3.12: install runtime/dev dependencies, `python -m ruff check . --select=E9,F63,F7,F82`, `python -m compileall .`, and `python -m pytest`.
- Dependency audit on Python 3.12: `python -m pip_audit -r requirements.txt -r constraints.txt --no-deps`.

## Maintenance

Update from GitHub:

```bash
cd /opt/vpn-service
git pull --ff-only
.venv/bin/pip install -r requirements.txt -c constraints.txt
.venv/bin/python init_db.py
sudo systemctl restart vpn-bot
```

Check status:

```bash
sudo systemctl status vpn-bot
```

Restart the service:

```bash
sudo systemctl restart vpn-bot
```

View logs:

```bash
sudo journalctl -u vpn-bot -f
tail -f /opt/vpn-service/logs/bot.log
```

## Production Operations Runbook

### Pre-deploy checklist

- `.env` exists, is not committed, and is `root:vpn-bot` mode `0640`.
- `PRIVILEGE_HELPERS_ENABLED=true` and helper paths point to `/usr/local/sbin/vpnbot-*`.
- `DB_PATH` parent, `LOG_DIR`, and `/run/vpn-bot` are writable by `vpn-bot:vpn-bot` and not world-readable.
- The installed systemd unit matches `deploy/vpn-bot.service` and runs as `vpn-bot:vpn-bot`.
- `RuntimeDirectory=vpn-bot`, `RuntimeDirectoryMode=0700`, and `BOT_LOCK_PATH=/run/vpn-bot/vpn-bot.lock` are present.
- `NoNewPrivileges=true` is not set on the sudo-helper unit.
- Helpers are installed as `root:root` mode `0755` under `/usr/local/sbin`.
- `/etc/sudoers.d/vpnbot` is `root:root` mode `0440` and passes `visudo -cf`.
- Xray canonical config, AWG canonical config, and MTProxy managed secrets/env are readable by `vpn-bot` where those backends are enabled, but not writable by it.
- Firewall rules are known before opening VPN ports.
- Backup destination exists and backup files are not world-readable.
- Code and `.venv` are not writable by untrusted users or by `vpn-bot`.
- If managed MTProto is enabled, `vpn-bot.service` does not have `ReadWritePaths=/etc/systemd/system`; the MTProxy wrapper/drop-in were installed manually and contain no raw secrets.

### General bot health check

```bash
sudo systemctl status vpn-bot --no-pager
sudo journalctl -u vpn-bot -n 100 --no-pager
sqlite3 /opt/vpn-service/data/vpn.db "PRAGMA quick_check;"
cd /opt/vpn-service
.venv/bin/python -m compileall .
.venv/bin/python -m pytest
```

### Post-cutover checklist

- `python3 deploy/check-nonroot-helper-mode.py` reports `failures=0 warnings=0`.
- `vpn-bot` process user is `vpn-bot:vpn-bot`.
- `vpn-bot`, `xray`, `awg-quick@awg0`, `danted`, and `mtproxy` are active when those backends are enabled.
- `journalctl -b -u vpn-bot` contains no `degraded`, `critical`, `error`, `traceback`, `permission denied`, or `not permitted` entries.
- Reboot verification passed after a full host reboot.
- Post-reboot backup made after the verified boot.

### Backup

Back up at least these files before deploys, migrations, and manual backend edits:

```bash
sudo install -m 700 -d /root/vpn-service-backups
sudo tar --xattrs --acls -czf /root/vpn-service-backups/vpn-service-$(date -u +%Y%m%dT%H%M%SZ).tar.gz \
  /opt/vpn-service/.env \
  /opt/vpn-service/data/vpn.db \
  /usr/local/etc/xray/config.json \
  /etc/amnezia/amneziawg/awg0.conf \
  /etc/mtproxy
sudo chmod 600 /root/vpn-service-backups/vpn-service-*.tar.gz
```

Include `/opt/vpn-service/logs` only if operational logs are needed for incident analysis. Treat all backups as sensitive because they can contain Telegram tokens, VPN keys, Xray UUIDs, AWG private/preshared keys, and server endpoints.

### Restore

```bash
sudo systemctl stop vpn-bot
sudo tar -xzf /root/vpn-service-backups/<backup>.tar.gz -C /
sudo xray run -test -config /usr/local/etc/xray/config.json
sudo awg-quick strip /etc/amnezia/amneziawg/awg0.conf >/dev/null
. /opt/vpn-service/.venv/bin/activate
cd /opt/vpn-service
python init_db.py
sudo systemctl start vpn-bot
sudo systemctl status vpn-bot
sudo journalctl -u vpn-bot -n 100 --no-pager
```

If `awg-quick` is unavailable but `wg-quick` is the intended tool on the server, run the equivalent `wg-quick strip` check. Do not run `awg set`, `wg set`, `systemctl restart xray`, or runtime-changing commands during restore validation until the config files have passed read-only checks.

### Firewall and exposed ports

- Keep SSH open only from trusted sources where possible.
- Open the public Xray TCP port, usually `443/tcp`.
- Open the public AWG endpoint UDP port from `AWG_ENDPOINT_PORT` or the AWG config `ListenPort`.
- Open Dante/SOCKS only if a separate proxy is intentionally deployed and protected.
- Keep `XRAY_STATS_SERVER` bound to localhost only, for example `127.0.0.1:<port>`. Never expose the Xray stats API to the internet.
- If UFW default routed policy is `deny`, explicitly allow routed traffic required by AWG clients.

Example read-only checks:

```bash
sudo ufw status verbose
sudo ss -tulnp
```

### Read-only health checks

```bash
sudo systemctl status vpn-bot --no-pager
sudo systemctl status xray --no-pager
sudo systemctl status danted --no-pager
sudo ss -tlnp | grep 31337
sudo systemctl status mtproxy --no-pager
sudo ss -tlnp | grep 8443
sudo journalctl -u vpn-bot -n 100 --no-pager
sudo xray run -test -config /usr/local/etc/xray/config.json
sudo awg show
sudo awg-quick strip /etc/amnezia/amneziawg/awg0.conf >/dev/null
sqlite3 /opt/vpn-service/data/vpn.db "PRAGMA quick_check; SELECT status, key_type, COUNT(*) FROM vpn_keys GROUP BY status, key_type;"
```

If `XRAY_STATS_SERVER` is configured locally, query it only from the server or localhost. Confirm that bot DB status, Xray config clients, AWG config peers, and AWG runtime peers agree after create/revoke/delete operations.

### Xray degraded recovery

Xray DEGRADED blocks only Xray create/revoke/delete/manual reconcile. AWG, SOCKS5, and MTProto continue unless separately degraded.

```bash
sudo systemctl status xray --no-pager
sudo xray run -test -config /usr/local/etc/xray/config.json
sudo jq '[.inbounds[]?.settings.clients[]? | {email}]' /usr/local/etc/xray/config.json
sqlite3 /opt/vpn-service/data/vpn.db "SELECT status, key_type, COUNT(*) FROM vpn_keys WHERE key_type='xray' GROUP BY status, key_type;"
sudo journalctl -u vpn-bot -n 150 --no-pager
```

Check for manual clients/orphans, failed pending statuses, and config syntax errors. Restore from backup or remove only confirmed bot-managed drift, then restart `vpn-bot` and re-open admin backend diagnostics.

### AWG degraded recovery

AWG DEGRADED blocks only AWG create/revoke/delete/manual reconcile. Xray, SOCKS5, and MTProto continue unless separately degraded.

```bash
sudo systemctl status awg-quick@awg0 --no-pager
sudo awg show
sudo awk '/^# vpnbot key_id=|^PublicKey =|^AllowedIPs =/{print}' /etc/amnezia/amneziawg/awg0.conf
sqlite3 /opt/vpn-service/data/vpn.db "SELECT status, key_type, COUNT(*) FROM vpn_keys WHERE key_type='awg' GROUP BY status, key_type;"
sudo journalctl -u vpn-bot -n 150 --no-pager
```

Do not print AWG private keys or preshared keys into tickets/chat. Compare public keys/client IPs only, fix confirmed drift from backup or manual state, then restart `vpn-bot`.

### SOCKS5 degraded recovery

SOCKS5 DEGRADED blocks only SOCKS5 issue/revoke/delete. Xray, AWG, and MTProto continue unless separately degraded.

```bash
sudo systemctl status danted --no-pager
getent passwd | awk -F: '$1 ~ /^vpn_socks_/ {print $1}'
sqlite3 /opt/vpn-service/data/vpn.db "SELECT status, access_type, COUNT(*) FROM proxy_accesses WHERE access_type='socks5' GROUP BY status, access_type;"
sudo journalctl -u vpn-bot -n 150 --no-pager
```

Check that every managed Linux user starts with `SOCKS5_LOGIN_PREFIX`; do not print SOCKS5 passwords. Lock/delete only confirmed bot-managed stray users, restore SQLite from backup if needed, then restart `vpn-bot`.

### MTProto degraded recovery

MTProto DEGRADED blocks only MTProto issue/revoke/delete. Xray, AWG, and SOCKS5 continue unless separately degraded.

```bash
sudo systemctl status mtproxy --no-pager
sudo jq '{secret_count: (.secrets | length), fingerprints: [.secrets[]?.fingerprint]}' /etc/mtproxy/vpnbot/managed-secrets.json
sqlite3 /opt/vpn-service/data/vpn.db "SELECT status, access_type, COUNT(*) FROM proxy_accesses WHERE access_type='mtproto' GROUP BY status, access_type;"
sudo journalctl -u vpn-bot -n 150 --no-pager
```

Do not print raw MTProto secrets. In static mode, per-user server-side revoke is impossible; rotate `MTPROTO_SECRET` if a copied shared secret must be invalidated. In managed mode, compare counts/fingerprints, restore managed files from `/etc/mtproxy/vpnbot/backups` if needed, restart `mtproxy`, then restart `vpn-bot`.

### Rollback after a bad deploy

```bash
cd /opt/vpn-service
git log --oneline -5
git reset --hard <previous_commit>
.venv/bin/pip install -r requirements.txt -c constraints.txt
.venv/bin/python init_db.py
sudo systemctl restart vpn-bot
sudo journalctl -u vpn-bot -n 100 --no-pager
```

Only use `git reset --hard` when you intentionally discard local code changes on the server. Restore `.env`, SQLite DB, Xray config, and AWG config from backup if the failed deploy changed runtime state.

Rollback to the legacy root/direct unit only when helper mode cannot be repaired quickly:

```bash
sudo sed -i 's/^PRIVILEGE_HELPERS_ENABLED=.*/PRIVILEGE_HELPERS_ENABLED=false/' /opt/vpn-service/.env
sudo install -o root -g root -m 0644 deploy/vpn-bot.root-legacy.example.service /etc/systemd/system/vpn-bot.service
sudo systemctl daemon-reload
sudo systemctl restart vpn-bot
sudo systemctl status vpn-bot --no-pager
sudo journalctl -u vpn-bot -n 100 --no-pager
```

Keep or remove `/etc/sudoers.d/vpnbot` only after validating the final sudoers state with `visudo -cf`.

### Manual VDS verification after fixes

On a staging user before production use:

1. Create one Xray key, verify it is active in DB and present in Xray config.
2. Revoke and delete the Xray key, verify DB/config/runtime no longer allow access.
3. Create one AWG key, verify DB, `awg0.conf`, and `awg show` agree.
4. Revoke and delete the AWG key, verify peer removal from config and runtime.
5. Open "Прокси" as an approved test user, issue SOCKS5 after confirmation, and verify the message contains Host, Port, Login, Password, and URL.
6. Issue MTProto after confirmation and verify the plain Telegram link appears before the `dd` link.
7. In `MTPROTO_MODE=managed`, issue MTProto for test user A and record only the non-secret fingerprint/count from admin status.
8. Issue MTProto for test user B and confirm admin status shows two active managed MTProto accesses.
9. Hard-block or admin-revoke test user A, then confirm the managed secrets file no longer contains A's fingerprint while B's fingerprint remains active.
10. Confirm user B's Telegram MTProto link still works after user A is revoked.
11. Simulate a failed apply on staging, for example by temporarily pointing `MTPROTO_SERVICE_NAME` to a failing test unit or stopping the listener check path, then revoke/issue and confirm rollback restores the previous managed secrets/env files and `mtproxy` returns to active/listening.
12. In `MTPROTO_MODE=static`, block the user and confirm MTProto is deactivated only in SQLite.
13. Check that bot logs and audit output do not contain SOCKS5 passwords, `MTPROTO_SECRET`, or managed raw MTProto secrets.
14. Check `systemctl cat mtproxy`, `systemctl show mtproxy -p User -p Group -p ExecStart -p Environment`, and `journalctl -u mtproxy -n 100 --no-pager` for absence of raw MTProto secrets.
15. Check managed file permissions:
    ```bash
    sudo stat -c '%U:%G %a %n' /opt/vpn-service/scripts/run-mtproxy-managed /etc/mtproxy/vpnbot/managed-secrets.json /etc/mtproxy/vpnbot/mtproxy.env
    sudo find /etc/mtproxy/vpnbot/backups -maxdepth 2 -printf '%u:%g %m %p\n'
    ```
16. Send an announcement with approved, pending, and blocked test users; only approved users and superadmins should receive it.

## Database

SQLite is used as the local storage backend. By default the database path is:

```text
/opt/vpn-service/data/vpn.db
```

`init_db.py` opens the database and applies schema bootstrap/migrations. The bot also bootstraps the database during app creation.

Current schema tables include:

- `users`
- `access_requests`
- `vpn_keys`
- `proxy_entries`
- `proxy_accesses`
- `audit_log`
- `vpn_key_traffic_stats`

## Project Status

Early self-hosted project. It is usable as a focused VPN management bot, but production use requires careful review, server-specific testing, operational backups, secret handling discipline, and hardening of the surrounding Xray/AWG/server setup.

## License

MIT License. See [LICENSE](LICENSE).
