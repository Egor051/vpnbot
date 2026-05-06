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
- Ownership checks so users can only view and manage their own keys unless they are admins.
- Audit log with recursive masking for sensitive values.
- SQLite storage with migrations from `db/schema.sql`.
- Rotating local logs in `LOG_DIR`.
- systemd deployment using `deploy/vpn-bot.service`.
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
deploy/vpn-bot.service     # vpn-bot systemd unit template
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
BOT_LOCK_PATH=/run/vpn-bot.lock

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
MTPROTO_MANAGED_SECRETS_PATH=/etc/mtproxy/vpnbot-managed-secrets.json
MTPROTO_MANAGED_ENV_PATH=/etc/mtproxy/vpnbot-mtproxy.env
MTPROTO_MANAGED_WRAPPER_PATH=/opt/vpn-service/scripts/run-mtproxy-managed
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

- If `XRAY_INBOUND_TAG` is empty, the adapter uses the first inbound with `settings.clients`.
- If `XRAY_MANAGE_SHORT_IDS=false`, `XRAY_SHORT_ID` must be set.
- `XRAY_APPLY_MODE=restart` is the default production apply mode; use `reload` only when your Xray unit reliably applies reload.
- `SQLITE_SYNCHRONOUS=FULL` is the safer default for this control-plane database. `NORMAL` is faster but can lose the last committed transactions on OS or power failure while VPN backend state has already changed.
- `AWG_CLIENT_DNS` is supported only as a legacy alias; use `AWG_DNS` for new deployments.
- `AWG_ENDPOINT_HOST` and `AWG_ENDPOINT_PORT` should point to the public AWG endpoint clients will use.
- `SOCKS5_ENABLED=true` requires `SOCKS5_HOST`, `SOCKS5_PORT`, and a safe `SOCKS5_LOGIN_PREFIX`. Dante must already be installed and listening; the bot only creates/locks/deletes managed Linux users with that prefix.
- `MTPROTO_ENABLED=true` requires `MTPROTO_HOST`. `MTPROTO_MODE=static` also requires `MTPROTO_SECRET`.
- `MTPROTO_MODE=static` is compatibility mode: the bot shows a shared MTProto secret and can only deactivate a user's SQLite record. True per-user server-side revoke is impossible in static mode without rotating the shared secret.
- `MTPROTO_MODE=managed` creates one unique secret per user, writes managed secrets/env files under `/etc/mtproxy`, restarts `mtproxy`, verifies service/port health, and rolls back managed files if apply fails. The systemd drop-in and wrapper are installed during deploy, not written by the bot at runtime.
- `MTPROTO_SECRET`, SOCKS5 passwords, and real production endpoints with credentials must never be committed. `.env.example` intentionally keeps proxy secrets empty.
- `DEFAULT_PROXY_*` is legacy compatibility storage and does not drive the new user-facing proxy access flow.

## Proxy Deployment Notes

The bot does not install Dante or MTProxy. Prepare them on the VDS first, then enable the relevant env flags.

SOCKS5/Dante expectations:

- Dante listens on the configured public host/port, for example `0.0.0.0:31337`.
- Authentication is Linux username/password.
- The bot runs with enough permissions to call `getent`, `useradd`, `chpasswd`, `passwd -l`, and `userdel`.
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
- Install the managed wrapper/drop-in once during deploy:
  ```bash
  sudo install -m 700 -d /opt/vpn-service/scripts
  sudo install -m 700 deploy/run-mtproxy-managed /opt/vpn-service/scripts/run-mtproxy-managed
  sudo install -m 700 -d /etc/systemd/system/mtproxy.service.d
  sudo install -m 600 deploy/mtproxy-vpnbot-managed.conf /etc/systemd/system/mtproxy.service.d/vpnbot-managed.conf
  sudo systemctl daemon-reload
  ```
- If `MTPROTO_MANAGED_WRAPPER_PATH` or `MTPROTO_MANAGED_ENV_PATH` differs from the defaults, edit the installed wrapper/drop-in during deploy and run `systemctl daemon-reload` manually.
- On a fresh managed install, do not restart `mtproxy` onto the wrapper until the managed secrets/env files exist. The first bot issue/revoke apply writes those files before restarting `mtproxy`. If you want to restart `mtproxy` immediately during setup, create valid placeholder managed secrets/env files first and keep them mode `0600`.
- At runtime the bot writes only:
  - `MTPROTO_MANAGED_SECRETS_PATH`, containing active per-user secrets and a private runtime placeholder when no user secrets exist.
  - `MTPROTO_MANAGED_ENV_PATH`, containing non-secret runtime paths/options.
  - `/etc/mtproxy/vpnbot-backups/<backup-id>/`, containing private backups of managed secrets/env.
- On issue/revoke the bot backs up managed files, writes changes atomically, restarts `mtproxy`, checks `systemctl is-active`, checks that `MTPROTO_PORT` is listening, and restores the previous managed files on apply failure. It does not write `/etc/systemd/system` and does not run `systemctl daemon-reload` during normal issue/revoke.
- Managed mode gives real per-user revoke by removing only that user's secret from the active MTProxy list. Other users' secrets remain in the managed file.
- Raw MTProto secrets are not shown in admin status, audit, logs, README, or `.env.example`; admin diagnostics use counts and fingerprints only.
- Managed secrets and env files are written with mode `0600`; backup directories use `0700`; backup files that may contain secrets use `0600`; the wrapper should be installed with mode `0700`; the systemd drop-in contains no secrets and can be `0600`.

MTProto managed mode visibility checks:

- `systemctl cat mtproxy` and `systemctl show mtproxy -p ExecStart -p Environment` should show only the wrapper/env paths, not raw secrets.
- `journalctl -u vpn-bot` and `journalctl -u mtproxy` should not contain raw MTProto secrets; the bot redacts audit/error details and the wrapper does not print secrets. If your MTProxy build logs accepted secrets or generated links, do not use managed mode until that logging is disabled or the binary is replaced.
- The official `mtproto-proxy` binary accepts client secrets as `-S <secret>` arguments. That means raw secrets can be visible in process argv to root, and to unprivileged users unless `/proc` is hardened. Restrict shell access, consider mounting `/proc` with `hidepid=2`, and do not enable managed mode with this binary if your requirement is "raw MTProto secrets are never visible to root-level process inspection".

Manual rollback for managed MTProto:

1. Stop `vpn-bot`.
2. Inspect `/etc/mtproxy/vpnbot-backups/` under the directory configured by `MTPROTO_MANAGED_SECRETS_PATH`.
3. Restore the previous managed secrets/env files from the latest known-good backup if automatic rollback did not recover.
4. Run `sudo systemctl restart mtproxy`.
5. Check `sudo systemctl status mtproxy --no-pager` and `sudo ss -tlnp | grep 8443`.

Proxy statistics are lifecycle/accounting stats from SQLite: issued, active, revoked/deactivated, timestamps, status, reason, and error. The bot does not invent per-user traffic for Dante or MTProxy. Without Dante per-login accounting or a safe aggregate MTProxy stats endpoint, traffic is shown as unavailable.

## Deployment Overview

The supplied systemd unit expects the project in `/opt/vpn-service`. If you deploy elsewhere, update `deploy/vpn-bot.service` before installing it.

Short order:

1. Clone the repository.
2. Create a virtual environment.
3. Install `requirements.txt`.
4. Copy `.env.example` to `.env`.
5. Fill `.env`.
6. Initialize the database.
7. Run the bot manually.
8. Install the systemd service.

```bash
sudo mkdir -p /opt/vpn-service
sudo chown -R "$USER":"$USER" /opt/vpn-service
git clone https://github.com/Egor051/vpnbot.git /opt/vpn-service
cd /opt/vpn-service

python3 -m venv .venv
. .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt -c constraints.txt

cp .env.example .env
nano .env

python init_db.py
python main.py
```

Install and start the systemd service:

```bash
sudo cp deploy/vpn-bot.service /etc/systemd/system/vpn-bot.service
sudo systemctl daemon-reload
sudo systemctl enable --now vpn-bot
sudo systemctl status vpn-bot
```

If SOCKS5 auto-issue is enabled under the supplied hardened unit, keep the service running as root and allow the password database files in `ReadWritePaths`, as shown in `deploy/vpn-bot.service`.

If `MTPROTO_MODE=managed` is enabled, keep the supplied unit's write access to `/etc/mtproxy` only for managed secrets/env/backups. Do not grant `vpn-bot.service` runtime write access to `/etc/systemd/system`; install or update the MTProxy drop-in and wrapper manually during deploy, then run `systemctl daemon-reload` outside the bot runtime.

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

- `.env` exists, is not committed, and is readable only by the service operator/root.
- `DB_PATH` parent and `LOG_DIR` exist and are not world-readable.
- The systemd unit is installed and matches the paths in `.env`.
- Xray config exists at `XRAY_CONFIG_PATH` and validates before the bot writes to it.
- AWG config/interface exist if AWG keys will be issued.
- Firewall rules are known before opening VPN ports.
- Backup destination exists and backup files are not world-readable.
- Code and `.venv` are not writable by untrusted users.
- If managed MTProto is enabled, `vpn-bot.service` does not have `ReadWritePaths=/etc/systemd/system`; the MTProxy wrapper/drop-in were installed manually and contain no raw secrets.
- If managed MTProto is enabled, `/etc/mtproxy/vpnbot-managed-secrets.json`, `/etc/mtproxy/vpnbot-mtproxy.env`, and `/etc/mtproxy/vpnbot-backups/*` are readable only by root/service operators.

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
14. Check `systemctl cat mtproxy`, `systemctl show mtproxy -p ExecStart -p Environment`, and `journalctl -u mtproxy -n 100 --no-pager` for absence of raw MTProto secrets.
15. Check managed file permissions:
    ```bash
    sudo stat -c '%a %n' /etc/mtproxy/vpnbot-managed-secrets.json /etc/mtproxy/vpnbot-mtproxy.env
    sudo find /etc/mtproxy/vpnbot-backups -maxdepth 2 -printf '%m %p\n'
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
