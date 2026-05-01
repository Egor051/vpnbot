# VPN Telegram Bot

Telegram bot for self-hosted VPN access management on an Ubuntu VDS. The bot manages users, access approval, Xray VLESS Reality keys, AmneziaWG keys, key revocation/deletion, audit records, and basic traffic statistics.

This project is designed for a single-server deployment without Docker, Redis, PostgreSQL, or a heavy ORM.

## Features

- Telegram user registration and access approval flow.
- Admin panel for pending requests, users, key issuance, audit, stats, and announcements.
- Xray VLESS Reality key creation, config delivery, revocation, deletion, and startup reconciliation.
- AmneziaWG key creation, client config delivery, revocation, deletion, IP allocation, and startup reconciliation.
- Optional proxy entry display seeded from `DEFAULT_PROXY_*` environment variables. The bot does not install or manage Dante by itself.
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
deploy/vpn-bot.service     # systemd unit template
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
- `DEFAULT_PROXY_*` seeds one proxy entry only when the proxy table is empty.

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

### Backup

Back up at least these files before deploys, migrations, and manual backend edits:

```bash
sudo install -m 700 -d /root/vpn-service-backups
sudo tar --xattrs --acls -czf /root/vpn-service-backups/vpn-service-$(date -u +%Y%m%dT%H%M%SZ).tar.gz \
  /opt/vpn-service/.env \
  /opt/vpn-service/data/vpn.db \
  /usr/local/etc/xray/config.json \
  /etc/amnezia/amneziawg/awg0.conf
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
5. Block an approved test user and confirm bot access is denied even if a backend revoke error is simulated on staging.
6. Send an announcement with approved, pending, and blocked test users; only approved users and superadmins should receive it.

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
- `audit_log`
- `vpn_key_traffic_stats`

## Project Status

Early self-hosted project. It is usable as a focused VPN management bot, but production use requires careful review, server-specific testing, operational backups, secret handling discipline, and hardening of the surrounding Xray/AWG/server setup.

## License

MIT License. See [LICENSE](LICENSE).
