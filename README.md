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
- systemd deployment using `deploy/vpn-bot.service`.
- Intended target: Ubuntu VDS with existing Xray and/or AmneziaWG installation.

## Stack

- Python 3.12+
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
BOT_LOCK_PATH=/run/vpn-bot/vpn-bot.lock

# Root+api mode (default): PRIVILEGE_HELPERS_ENABLED=false or omit. Non-root helper mode: set true with helper paths below.
PRIVILEGE_HELPERS_ENABLED=false
HELPER_STAGING_ROOT=/run/vpn-bot
SOCKS5_USER_HELPER_PATH=/usr/local/sbin/vpnbot-socks5-user
XRAY_APPLY_HELPER_PATH=/usr/local/sbin/vpnbot-xray-apply
AWG_APPLY_HELPER_PATH=/usr/local/sbin/vpnbot-awg-apply
MTPROTO_APPLY_HELPER_PATH=/usr/local/sbin/vpnbot-mtproxy-apply

XRAY_CONFIG_PATH=/usr/local/etc/xray/config.json
XRAY_SERVICE_NAME=xray
XRAY_APPLY_MODE=api
XRAY_INBOUND_TAG=vless-in
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
XRAY_STATS_SERVER=127.0.0.1:10085

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

### Complete Environment Variable Reference

All variables parsed by `config/settings.py`. Variables marked **Required** must be set before startup; variables not marked are optional with the shown default.

> ⚠️ **Security-sensitive variables** are marked with 🔒. Never commit them; keep them on the server in `.env` (mode `0600`, root-only).

#### Core

| Variable | Required | Default | Description | Example |
|---|---|---|---|---|
| `BOT_TOKEN` | **Yes** | — | Telegram Bot API token from BotFather. 🔒 | `123456:ABC-DEF...` |
| `ADMIN_IDS` | **Yes** | — | Comma-separated list of Telegram user IDs with full admin access. | `123456,789012` |
| `DB_PATH` | No | `/opt/vpn-service/data/vpn.db` | Path to the SQLite database file. | `/opt/vpn-service/data/vpn.db` |
| `SQLITE_SYNCHRONOUS` | No | `FULL` | SQLite synchronous mode: `FULL`, `NORMAL`, or `EXTRA`. `FULL` is safest. | `FULL` |
| `LOG_DIR` | No | `/opt/vpn-service/logs` | Directory for rotating log files. | `/opt/vpn-service/logs` |
| `BOT_LOCK_PATH` | No | `/run/vpn-bot.lock` | Path to the single-instance PID lock file. | `/run/vpn-bot/vpn-bot.lock` |
| `BOT_DROP_PENDING_UPDATES` | No | `false` | Drop queued Telegram updates on startup. Useful after downtime. | `false` |
| `BOT_LANGUAGE` | No | `ru` | Bot UI language. Supported: `ru`, `en`. | `ru` |
| `AUDIT_RETENTION_DAYS` | No | `180` | Days to retain audit log entries (0 = forever, max 3650). | `180` |
| `CONFIG_BACKUP_KEEP_LAST` | No | `20` | Number of config backups to keep per backend (1–500). | `20` |

#### Health Endpoint

| Variable | Required | Default | Description | Example |
|---|---|---|---|---|
| `HEALTH_HOST` | No | `127.0.0.1` | Host for the optional HTTP health endpoint. | `127.0.0.1` |
| `HEALTH_PORT` | No | _(disabled)_ | Port for the HTTP health endpoint. Omit to disable. | `8080` |

#### Privilege Helpers (non-root deployment)

| Variable | Required | Default | Description | Example |
|---|---|---|---|---|
| `PRIVILEGE_HELPERS_ENABLED` | No | `false` | Enable non-root deployment via sudo helpers. Incompatible with `XRAY_APPLY_MODE=api`. | `false` |
| `HELPER_STAGING_ROOT` | No | `/run/vpn-bot` | Root directory for staging files passed to sudo helpers. | `/run/vpn-bot` |
| `SOCKS5_USER_HELPER_PATH` | No | `/usr/local/sbin/vpnbot-socks5-user` | Absolute path to the SOCKS5 user management sudo helper. | `/usr/local/sbin/vpnbot-socks5-user` |
| `XRAY_APPLY_HELPER_PATH` | No | `/usr/local/sbin/vpnbot-xray-apply` | Absolute path to the Xray config apply sudo helper. | `/usr/local/sbin/vpnbot-xray-apply` |
| `AWG_APPLY_HELPER_PATH` | No | `/usr/local/sbin/vpnbot-awg-apply` | Absolute path to the AWG config apply sudo helper. | `/usr/local/sbin/vpnbot-awg-apply` |
| `MTPROTO_APPLY_HELPER_PATH` | No | `/usr/local/sbin/vpnbot-mtproxy-apply` | Absolute path to the MTProto apply sudo helper. | `/usr/local/sbin/vpnbot-mtproxy-apply` |
| `XRAY_HELPER_STAGING_DIR` | No | `$HELPER_STAGING_ROOT/xray` | Staging directory for Xray helper files. | `/run/vpn-bot/xray` |
| `AWG_HELPER_STAGING_DIR` | No | `$HELPER_STAGING_ROOT/awg` | Staging directory for AWG helper files. | `/run/vpn-bot/awg` |
| `MTPROTO_HELPER_STAGING_DIR` | No | `$HELPER_STAGING_ROOT/mtproxy` | Staging directory for MTProto helper files. | `/run/vpn-bot/mtproxy` |

#### Xray VLESS Reality

| Variable | Required | Default | Description | Example |
|---|---|---|---|---|
| `XRAY_CONFIG_PATH` | No | `/usr/local/etc/xray/config.json` | Path to the Xray config file. | `/usr/local/etc/xray/config.json` |
| `XRAY_SERVICE_NAME` | No | `xray` | systemd service name for Xray. | `xray` |
| `XRAY_APPLY_MODE` | No | `restart` | How to apply Xray config changes: `restart`, `reload`, or `api`. `api` requires root and is incompatible with helpers. | `api` |
| `XRAY_INBOUND_TAG` | No* | _(first inbound)_ | Tag of the VLESS inbound in `config.json`. Required for `api` mode. | `vless-in` |
| `XRAY_PUBLIC_HOST` | No* | — | Public hostname/IP clients use to connect. Required to issue keys. | `vpn.example.com` |
| `XRAY_PUBLIC_PORT` | No | `443` | Public TCP port for VLESS connections. | `443` |
| `XRAY_REALITY_PUBLIC_KEY` | No* | — | Xray Reality public key (base64url). Required to issue keys. | `ABC123...` |
| `XRAY_SNI` | No* | — | SNI (Server Name Indication) for Reality. Required to issue keys. | `www.microsoft.com` |
| `XRAY_FLOW` | No | `xtls-rprx-vision` | VLESS flow control. | `xtls-rprx-vision` |
| `XRAY_FINGERPRINT` | No | `chrome` | TLS fingerprint. One of: `chrome`, `firefox`, `safari`, `ios`, `android`, `edge`, `randomized`, `randomizedalpn`, `randomizednoalpn`. | `chrome` |
| `XRAY_NETWORK_TYPE` | No | `tcp` | Network type: `tcp` or `raw`. | `tcp` |
| `XRAY_SHORT_ID` | No* | — | Hex short ID (≤16 chars). Required if `XRAY_MANAGE_SHORT_IDS=false`. | `abcd1234` |
| `XRAY_MANAGE_SHORT_IDS` | No | `false` | Let the bot manage short IDs automatically. | `false` |
| `XRAY_ALLOW_RESTART_ON_ROLLBACK` | No | `false` | Allow service restart during config rollback. | `false` |
| `XRAY_STATS_SERVER` | No* | — | Address of the Xray gRPC stats/API server. Required for `api` mode. | `127.0.0.1:10085` |
| `XRAY_ACCESS_LOG_PATH` | No | _(empty)_ | Path to the Xray access log for anomaly detection. Leave empty to disable. | `/var/log/xray/access.log` |

_Legacy aliases accepted: `XRAY_SERVER_ADDRESS` (= `XRAY_PUBLIC_HOST`), `XRAY_SERVER_PORT` (= `XRAY_PUBLIC_PORT`), `XRAY_PUBLIC_KEY` (= `XRAY_REALITY_PUBLIC_KEY`), `XRAY_SERVER_NAME` (= `XRAY_SNI`)._

#### AmneziaWG

| Variable | Required | Default | Description | Example |
|---|---|---|---|---|
| `AWG_CONFIG_PATH` | No | `/etc/amnezia/amneziawg/awg0.conf` | Path to the AWG server config file. | `/etc/amnezia/amneziawg/awg0.conf` |
| `AWG_INTERFACE` | No | `awg0` | AWG/WireGuard network interface name. | `awg0` |
| `AWG_NETWORK` | No | `10.0.0.0/24` | IPv4 subnet for the VPN. | `10.0.0.0/24` |
| `AWG_SERVER_ADDRESS` | No | `10.0.0.1` | Server's IPv4 address inside the VPN subnet. | `10.0.0.1` |
| `AWG_ENDPOINT_HOST` | No* | — | Public hostname/IP for AWG endpoint. Required to issue keys. | `vpn.example.com` |
| `AWG_ENDPOINT_PORT` | No | `0` | Public UDP port for AWG endpoint. | `51820` |
| `AWG_SERVER_PUBLIC_KEY` | No | _(empty)_ | AWG server public key (base64). Shown in client configs. | `ABC123...` |
| `AWG_DNS` | No | `1.1.1.1` | DNS server for AWG clients. | `1.1.1.1` |
| `AWG_MTU` | No | _(auto)_ | MTU for AWG client interface (576–1500). Omit to let client decide. | `1280` |
| `AWG_ALLOWED_IPS` | No | `0.0.0.0/0, ::/0` | Allowed IPs for AWG client routing (full-tunnel by default). | `0.0.0.0/0, ::/0` |
| `AWG_PERSISTENT_KEEPALIVE` | No | `25` | Keepalive interval in seconds (0–86400). | `25` |
| `AWG_USE_PRESHARED_KEY` | No | `true` | Generate and include a preshared key per client. | `true` |
| `AWG_STATS_INTERVAL` | No | `60` | Background traffic stats sampling interval in seconds (0–3600). | `60` |

_Legacy alias: `AWG_CLIENT_DNS` (= `AWG_DNS`)._

#### SOCKS5 / Dante

| Variable | Required | Default | Description | Example |
|---|---|---|---|---|
| `SOCKS5_ENABLED` | No | `false` | Enable SOCKS5 proxy backend. | `false` |
| `SOCKS5_HOST` | No* | _(empty)_ | Public host for SOCKS5 (required if `SOCKS5_ENABLED=true`). | `vpn.example.com` |
| `SOCKS5_PORT` | No | `31337` | Public port for SOCKS5 connections. | `31337` |
| `SOCKS5_LOGIN_PREFIX` | No | `vpn_socks_` | Prefix for all managed Linux users. Must be unique and non-generic. | `vpn_socks_` |
| `SOCKS5_SYSTEM_USER_SHELL` | No | `/usr/sbin/nologin` | Shell for managed SOCKS5 Linux users. | `/usr/sbin/nologin` |
| `SOCKS5_SERVICE_NAME` | No | `danted` | systemd service name for Dante. | `danted` |
| `SOCKS5_PUBLIC_NAME` | No | `SOCKS5 Proxy` | Display name shown in the bot UI. | `SOCKS5 Proxy` |
| `SOCKS5_NOTE` | No | `SOCKS5 Dante proxy on VDS` | Description shown in proxy access cards. | `SOCKS5 Dante proxy on VDS` |

#### MTProto Proxy

| Variable | Required | Default | Description | Example |
|---|---|---|---|---|
| `MTPROTO_ENABLED` | No | `false` | Enable MTProto proxy backend. | `false` |
| `MTPROTO_MODE` | No | `static` | Proxy mode: `static` (shared secret) or `managed` (per-user secrets). | `static` |
| `MTPROTO_HOST` | No* | _(empty)_ | Public host for MTProto (required if `MTPROTO_ENABLED=true`). | `vpn.example.com` |
| `MTPROTO_PORT` | No | `8443` | Public port for MTProto connections. | `8443` |
| `MTPROTO_SECRET` | No* | _(empty)_ | 🔒 Shared MTProto secret (required if `MTPROTO_MODE=static` and enabled). | _(hex string)_ |
| `MTPROTO_PUBLIC_NAME` | No | `Telegram MTProto Proxy` | Display name shown in the bot UI. | `Telegram MTProto Proxy` |
| `MTPROTO_NOTE` | No | `MTProto proxy for Telegram` | Description shown in proxy access cards. | `MTProto proxy for Telegram` |
| `MTPROTO_STATS_URL` | No | _(empty)_ | URL for MTProto statistics endpoint. | `http://127.0.0.1:8888/stats` |
| `MTPROTO_SERVICE_NAME` | No | `mtproxy` | systemd service name for MTProxy. | `mtproxy` |
| `MTPROTO_BINARY_PATH` | No | `/usr/local/bin/mtproto-proxy` | Path to the MTProto proxy binary. | `/usr/local/bin/mtproto-proxy` |
| `MTPROTO_RUN_USER` | No | `mtproxy` | User to run the MTProto proxy process as. | `mtproxy` |
| `MTPROTO_RUN_GROUP` | No | `mtproxy` | Group to run the MTProto proxy process as. | `mtproxy` |
| `MTPROTO_CONFIG_DIR` | No | `/etc/mtproxy` | Directory containing MTProxy base config files. | `/etc/mtproxy` |
| `MTPROTO_PROXY_SECRET_PATH` | No | `/etc/mtproxy/proxy-secret` | Path to the MTProxy `proxy-secret` file. | `/etc/mtproxy/proxy-secret` |
| `MTPROTO_PROXY_MULTI_CONF_PATH` | No | `/etc/mtproxy/proxy-multi.conf` | Path to the MTProxy `proxy-multi.conf` file. | `/etc/mtproxy/proxy-multi.conf` |
| `MTPROTO_MANAGED_DIR` | No | `/etc/mtproxy/vpnbot` | Directory for bot-managed MTProto files. | `/etc/mtproxy/vpnbot` |
| `MTPROTO_MANAGED_SECRETS_PATH` | No | `$MTPROTO_MANAGED_DIR/managed-secrets.json` | 🔒 Path to managed secrets JSON. | `/etc/mtproxy/vpnbot/managed-secrets.json` |
| `MTPROTO_MANAGED_ENV_PATH` | No | `$MTPROTO_MANAGED_DIR/mtproxy.env` | Path to managed MTProxy env file. | `/etc/mtproxy/vpnbot/mtproxy.env` |
| `MTPROTO_MANAGED_WRAPPER_PATH` | No | `/opt/vpn-service/scripts/run-mtproxy-managed` | Path to the managed-mode wrapper script. | `/opt/vpn-service/scripts/run-mtproxy-managed` |
| `MTPROTO_BACKUP_DIR` | No | `$MTPROTO_MANAGED_DIR/backups` | Directory for MTProto managed-file backups. | `/etc/mtproxy/vpnbot/backups` |
| `MTPROTO_INTERNAL_STATS_PORT` | No | `8888` | Internal MTProxy stats port (1–65535). | `8888` |
| `MTPROTO_WORKERS` | No | `1` | Number of MTProxy worker processes (1–1024). | `1` |
| `MTPROTO_APPLY_TIMEOUT_SECONDS` | No | `10` | Timeout in seconds for apply + health check (1–3600). | `10` |
| `MTPROTO_ROLLBACK_ON_APPLY_FAILURE` | No | `true` | Automatically restore backup on apply failure. | `true` |
| `MTPROTO_KEEP_LAST_BACKUPS` | No | `10` | Number of managed-file backups to retain (0–1000). | `10` |

#### Key Expiry and Trial Access

| Variable | Required | Default | Description | Example |
|---|---|---|---|---|
| `KEY_EXPIRY_CHECK_INTERVAL` | No | `1800` | How often (seconds) to check for expiring/expired keys (0–86400). | `1800` |
| `KEY_EXPIRY_NOTIFY_DAYS` | No | _(empty)_ | Comma-separated list of days before expiry to send user notifications. | `7,3,1` |
| `KEY_MAX_TRIAL_DAYS` | No | `365` | Maximum duration (days) for trial VPN keys (1–3650). | `30` |

#### Off-site Encrypted Backup

| Variable | Required | Default | Description | Example |
|---|---|---|---|---|
| `OFFSITE_BACKUP_ENCRYPTION_KEY` | No | _(disabled)_ | 🔒 Fernet key for encrypting off-site DB backups. Generate with: `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`. Leave empty to disable off-site backups. | _(44-char base64url)_ |
| `OFFSITE_BACKUP_INTERVAL` | No | `604800` | Interval (seconds) between off-site backup uploads (0 = disabled). Default is 7 days. | `604800` |

#### Anomaly Detection

| Variable | Required | Default | Description | Example |
|---|---|---|---|---|
| `ANOMALY_CHECK_INTERVAL` | No | `300` | How often (seconds) to run the anomaly detection scan (0–86400). | `300` |
| `ANOMALY_WINDOW_SECONDS` | No | `3600` | Traffic observation window in seconds (60–86400). | `3600` |
| `ANOMALY_MIN_UNIQUE_IPS` | No | `3` | Minimum unique source IPs within the window to flag a key (1–1000). | `3` |
| `ANOMALY_AUTO_REVOKE` | No | `false` | Automatically revoke flagged keys without admin confirmation. | `false` |
| `ANOMALY_COOLDOWN_SECONDS` | No | `7200` | Cooldown before re-flagging the same key (0–86400). | `7200` |
| `ANOMALY_CONCURRENT_WINDOW_SECONDS` | No | `600` | Window for concurrent-connection anomaly detection (0–86400). | `600` |

#### Legacy / Compatibility

| Variable | Required | Default | Description |
|---|---|---|---|
| `DEFAULT_PROXY_TYPE` | No | _(empty)_ | Legacy proxy entry type (internal use only; does not drive user-facing proxy flow). |
| `DEFAULT_PROXY_HOST` | No | _(empty)_ | Legacy proxy host. |
| `DEFAULT_PROXY_PORT` | No | _(empty)_ | Legacy proxy port. |
| `DEFAULT_PROXY_LOGIN` | No | _(empty)_ | Legacy proxy login. |
| `DEFAULT_PROXY_PASSWORD` | No | _(empty)_ | 🔒 Legacy proxy password. |
| `DEFAULT_PROXY_NOTE` | No | _(empty)_ | Legacy proxy note. |

Notes:

- If `XRAY_INBOUND_TAG` is empty, the adapter uses the first inbound with `settings.clients`.
- If `XRAY_MANAGE_SHORT_IDS=false`, `XRAY_SHORT_ID` must be set.
- `XRAY_APPLY_MODE=restart` is the default apply mode; use `reload` only when your Xray unit reliably applies reload.

> ⚠️ **IMPORTANT — XRAY_APPLY_MODE=api and root deployment:**
> - `XRAY_APPLY_MODE=api` is the **only** mode that adds/removes Xray keys without restarting the Xray service. Without it, every key creation or deletion causes a full Xray restart, which drops all active connections.
> - `XRAY_APPLY_MODE=api` is **INCOMPATIBLE** with `PRIVILEGE_HELPERS_ENABLED=true` — the bot will refuse to start if both are set simultaneously.
> - To use api mode, the bot **MUST run as root** (`User=root` in the service file) with `PRIVILEGE_HELPERS_ENABLED=false`.
> - `deploy/vpn-bot.service` in the repo is the **authoritative source** — every deploy overwrites `/etc/systemd/system/vpn-bot.service` from it. Manual edits to the system service file are lost on the next deploy. The repo file must reflect the intended production configuration.
> - See [Xray API Mode](#xray-api-mode) for required env vars and one-time server setup.

- `XRAY_APPLY_MODE=api` is incompatible with `PRIVILEGE_HELPERS_ENABLED=true`. When privilege helpers are enabled the bot applies Xray config changes through the `vpnbot-xray-apply` sudo helper, which always calls `systemctl restart xray` regardless of `XRAY_APPLY_MODE`. Use `restart` mode with privilege helpers; `reload` and `api` modes are not honoured by the helper.
- `SQLITE_SYNCHRONOUS=FULL` is the safer default for this control-plane database. `NORMAL` is faster but can lose the last committed transactions on OS or power failure while VPN backend state has already changed.
- `AWG_CLIENT_DNS` is supported only as a legacy alias; use `AWG_DNS` for new deployments.
- `AWG_ENDPOINT_HOST` and `AWG_ENDPOINT_PORT` should point to the public AWG endpoint clients will use.
- `SOCKS5_ENABLED=true` requires `SOCKS5_HOST`, `SOCKS5_PORT`, and a safe `SOCKS5_LOGIN_PREFIX`. Dante must already be installed and listening; the bot only creates/locks/deletes managed Linux users with that prefix.
- `MTPROTO_ENABLED=true` requires `MTPROTO_HOST`. `MTPROTO_MODE=static` also requires `MTPROTO_SECRET`.
- `MTPROTO_MODE=static` is compatibility mode: the bot shows a shared MTProto secret and can only deactivate a user's SQLite record. True per-user server-side revoke is impossible in static mode without rotating the shared secret.
- `MTPROTO_MODE=managed` creates one unique secret per user. In production helper mode the bot stages managed files under `/run/vpn-bot/mtproxy`; `/usr/local/sbin/vpnbot-mtproxy-apply` writes `/etc/mtproxy/vpnbot`, restarts `mtproxy`, verifies service/port health, and rolls back managed files if apply fails. The systemd drop-in and wrapper are installed during deploy, not written by the bot at runtime.
- `MTPROTO_SECRET`, SOCKS5 passwords, and real production endpoints with credentials must never be committed. `.env.example` intentionally keeps proxy secrets empty.
- `DEFAULT_PROXY_*` is legacy compatibility storage and does not drive the new user-facing proxy access flow.
- **Root deployment with api mode** (current `deploy/vpn-bot.service` default): `User=root`, `PRIVILEGE_HELPERS_ENABLED=false`, `XRAY_APPLY_MODE=api`. The bot writes Xray config and applies changes directly via the Xray gRPC API; no sudo helpers are needed. See [Xray API Mode](#xray-api-mode).
- **Alternative non-root deployment with privilege helpers**: Run the bot as `vpn-bot:vpn-bot` with `PRIVILEGE_HELPERS_ENABLED=true`. Root-only backend changes go through fixed sudo helpers documented in `deploy/helpers/README.md`. Use `XRAY_APPLY_MODE=restart` or `reload` in this model; api mode is not honoured when helpers are enabled.
- Keep project code, deploy files, `.env`, and `.venv` not writable by the service account. In root mode all paths are accessible; in non-root mode only `/opt/vpn-service/data`, `/opt/vpn-service/logs` if file logs are enabled, and `/run/vpn-bot` should be writable by `vpn-bot`.

## Xray API Mode

> ⚠️ **IMPORTANT — `XRAY_APPLY_MODE=api` requires root and is incompatible with privilege helpers:**
> - `XRAY_APPLY_MODE=api` is the **only** mode that adds/removes Xray keys without restarting the Xray service. Without it, every key creation or deletion causes a full Xray restart, which drops all active connections.
> - `XRAY_APPLY_MODE=api` is **INCOMPATIBLE** with `PRIVILEGE_HELPERS_ENABLED=true` — the bot will refuse to start if both are set simultaneously.
> - To use api mode, the bot **MUST run as root** (`User=root` in the service file) with `PRIVILEGE_HELPERS_ENABLED=false`.
> - `deploy/vpn-bot.service` in the repo is the **authoritative source** — every deploy overwrites `/etc/systemd/system/vpn-bot.service` from it. Manual edits to the system service file are lost on the next deploy. The repo file must reflect the intended production configuration.

### Required .env variables for api mode

```dotenv
XRAY_APPLY_MODE=api
XRAY_INBOUND_TAG=vless-in          # must match the "tag" field on the VLESS inbound in config.json
XRAY_STATS_SERVER=127.0.0.1:10085  # must match the dokodemo-door api inbound port
```

Also set `PRIVILEGE_HELPERS_ENABLED=false` (or omit it) when using api mode.

### One-time server preparation

Before starting the bot in api mode, configure the Xray API inbound and tag the VLESS inbound in `/usr/local/etc/xray/config.json`:

1. Add `"tag": "vless-in"` to your VLESS inbound object (use whatever tag you set as `XRAY_INBOUND_TAG`):

```json
{
  "inbounds": [
    {
      "tag": "vless-in",
      "port": 443,
      "protocol": "vless",
      "...": "..."
    }
  ]
}
```

2. Ensure the Xray API block and a `dokodemo-door` API inbound are present in `config.json`. The port must match `XRAY_STATS_SERVER`:

```json
{
  "api": {
    "tag": "api",
    "services": ["HandlerService", "StatsService", "LoggerService"]
  },
  "inbounds": [
    {
      "tag": "api-in",
      "listen": "127.0.0.1",
      "port": 10085,
      "protocol": "dokodemo-door",
      "settings": { "address": "127.0.0.1" }
    }
  ],
  "routing": {
    "rules": [
      { "inboundTag": ["api-in"], "outboundTag": "api", "type": "field" }
    ]
  }
}
```

3. Restart Xray once so the tag takes effect and verify the config:

```bash
sudo xray run -test -config /usr/local/etc/xray/config.json
sudo systemctl restart xray
sudo systemctl status xray --no-pager
```

4. Install the service file and start the bot:

```bash
sudo cp deploy/vpn-bot.service /etc/systemd/system/vpn-bot.service
sudo systemctl daemon-reload
sudo systemctl enable --now vpn-bot
sudo systemctl status vpn-bot
```

`deploy/vpn-bot.service` already contains `User=root`, `ProtectSystem=false`, and no `ReadWritePaths` restrictions — no manual edits to the service file are needed.

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
- The bot process does not call account-management tools directly in production. It uses `sudo -n /usr/local/sbin/vpnbot-socks5-user ...`; the helper is the only code allowed to call `getent`, `useradd`, `chpasswd`, `passwd -l`, and `userdel`.
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
  sudo install -m 700 -d /etc/mtproxy/vpnbot /etc/mtproxy/vpnbot/backups
  sudo chown root:root /opt/vpn-service/scripts/run-mtproxy-managed /etc/mtproxy/vpnbot /etc/mtproxy/vpnbot/backups
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
  sudo chmod 600 /etc/mtproxy/vpnbot/managed-secrets.json /etc/mtproxy/vpnbot/mtproxy.env
  sudo chown root:root /etc/mtproxy/vpnbot/managed-secrets.json /etc/mtproxy/vpnbot/mtproxy.env
  sudo systemctl daemon-reload
  sudo systemctl restart mtproxy
  sudo systemctl status mtproxy --no-pager
  sudo ss -tlnp | grep 8443
  ```
- The drop-in clears any existing `User=`/`Group=` from `mtproxy.service`; `systemctl show mtproxy -p User -p Group -p ExecStart` should show empty `User`/`Group` and `ExecStart=/opt/vpn-service/scripts/run-mtproxy-managed`.
- If `MTPROTO_MANAGED_WRAPPER_PATH` or `MTPROTO_MANAGED_ENV_PATH` differs from the defaults, edit the installed wrapper/drop-in during deploy and run `systemctl daemon-reload` manually.
- Do not set `MTPROTO_MODE=managed` in `vpn-bot` until the placeholder managed baseline above has restarted successfully and `mtproxy` is active/listening. Bot issue/revoke refuses to proceed when `MTPROTO_MANAGED_SECRETS_PATH` or `MTPROTO_MANAGED_ENV_PATH` is missing, so the first helper apply always has known-good files to roll back to.
- At runtime the non-root bot stages MTProxy candidates under `/run/vpn-bot/mtproxy`. The `/usr/local/sbin/vpnbot-mtproxy-apply` helper validates the staged files, writes `MTPROTO_MANAGED_SECRETS_PATH`, writes `MTPROTO_MANAGED_ENV_PATH`, maintains `MTPROTO_BACKUP_DIR/<backup-id>/`, restarts `mtproxy`, checks `systemctl is-active`, checks that `MTPROTO_PORT` is listening, and restores the previous managed files on apply failure.
- Normal issue/revoke does not write `/etc/systemd/system` and does not run `systemctl daemon-reload`; install or update the MTProxy unit/drop-in manually during deploy.
- Managed mode gives real per-user revoke by removing only that user's secret from the active MTProxy list. Other users' secrets remain in the managed file.
- Raw MTProto secrets are not shown in admin status, audit, logs, README, or `.env.example`; admin diagnostics use counts and fingerprints only.
- Managed secrets and env files are root:root `0600`; backup directories are root:root `0700`; backup files that may contain secrets are root:root `0600`; the wrapper is root:root `0700`; the systemd drop-in contains no secrets and can be root:root `0600`.

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

> ⚠️ **IMPORTANT — `deploy/vpn-bot.service` is the authoritative source:**
> Every deploy copies `deploy/vpn-bot.service` verbatim to `/etc/systemd/system/vpn-bot.service`. Manual edits to the system service file are overwritten on the next deploy. The current repo file runs the bot as `User=root` with `ProtectSystem=false` for `XRAY_APPLY_MODE=api` operation. If you switch deployment models, update `deploy/vpn-bot.service` first — do not edit the system file directly.

The supplied systemd unit expects the project in `/opt/vpn-service`. If you deploy elsewhere, update `deploy/vpn-bot.service` before installing it.

**Root deployment model (current default — api mode, `User=root`):**

The repo service file is already configured for root+api mode. See [Xray API Mode](#xray-api-mode) for required `.env` variables and one-time Xray config preparation. There is no need to create a `vpn-bot` system user or install sudo helpers for this model.

**Non-root deployment model (privilege helper mode, `User=vpn-bot`):**

Update `deploy/vpn-bot.service` to set `User=vpn-bot`, `Group=vpn-bot`, `ProtectSystem=strict`, and restore `ReadWritePaths` before deploying. Then follow these steps:

1. Keep `/opt/vpn-service`, deploy files, `.env`, and `.venv` owned by root/operator and not writable by `vpn-bot`.
2. Create the `vpn-bot:vpn-bot` system identity.
3. Grant `vpn-bot` write access only to runtime state: `/opt/vpn-service/data`, `/opt/vpn-service/logs` if file logs are enabled, and `/run/vpn-bot` created by systemd.
4. Install fixed helpers under `/usr/local/sbin` and install `/etc/sudoers.d/vpnbot` with only those helper entrypoints.
5. Enable `PRIVILEGE_HELPERS_ENABLED=true`.
6. Install `deploy/vpn-bot.service`; it is the non-root unit.

Fresh install outline:

```bash
sudo install -o root -g root -m 0755 -d /opt/vpn-service
sudo git clone https://github.com/Egor051/vpnbot.git /opt/vpn-service
cd /opt/vpn-service

sudo python3 -m venv .venv
sudo /opt/vpn-service/.venv/bin/pip install --upgrade pip
sudo /opt/vpn-service/.venv/bin/pip install -r requirements.txt -c constraints.txt

sudo deploy/create-vpn-bot-user.sh
sudo install -o vpn-bot -g vpn-bot -m 0700 -d /opt/vpn-service/data /opt/vpn-service/logs
sudo install -o root -g root -m 0600 .env.example .env
sudoedit .env
```

Helper and sudoers install:

```bash
sudo install -o root -g root -m 0755 deploy/helpers/vpnbot-socks5-user /usr/local/sbin/vpnbot-socks5-user
sudo install -o root -g root -m 0755 deploy/helpers/vpnbot-xray-apply /usr/local/sbin/vpnbot-xray-apply
sudo install -o root -g root -m 0755 deploy/helpers/vpnbot-awg-apply /usr/local/sbin/vpnbot-awg-apply
sudo install -o root -g root -m 0755 deploy/helpers/vpnbot-mtproxy-apply /usr/local/sbin/vpnbot-mtproxy-apply
sudo install -o root -g root -m 0440 deploy/sudoers.d/vpnbot.example /etc/sudoers.d/vpnbot
sudo visudo -cf /etc/sudoers.d/vpnbot
```

Install and start the systemd service:

```bash
python deploy/check-nonroot-helper-mode.py
sudo cp deploy/vpn-bot.service /etc/systemd/system/vpn-bot.service
sudo systemctl daemon-reload
sudo systemctl enable --now vpn-bot
sudo systemctl status vpn-bot
python deploy/check-nonroot-helper-mode.py
```

Do not recursively chown the whole application tree to a login user for production. Do not make the repository checkout, deploy files, or `.venv` writable by `vpn-bot`; a compromised bot process must not be able to rewrite its own code, dependencies, units, or helper source.

If `MTPROTO_MODE=managed` is enabled, keep `/etc/mtproxy/vpnbot` root-owned and helper-managed. Do not grant `vpn-bot.service` runtime write access to `/etc/systemd/system` or broad write access to `/etc/mtproxy`; install or update the MTProxy drop-in and wrapper manually during deploy, then run `systemctl daemon-reload` outside the bot runtime.

Post-deploy smoke checklist:

1. `python deploy/check-nonroot-helper-mode.py` passes.
2. `systemctl show vpn-bot -p User -p Group -p RuntimeDirectory -p NoNewPrivileges -p ReadWritePaths` shows `vpn-bot`, `vpn-bot`, `vpn-bot`, no enabled `NoNewPrivileges`, and only the expected writable paths.
3. `sudo -u vpn-bot test ! -w /opt/vpn-service/.venv && sudo -u vpn-bot test ! -w /opt/vpn-service/deploy`.
4. `sudo visudo -cf /etc/sudoers.d/vpnbot` passes and the file contains no `NOPASSWD: ALL`.
5. Issue/revoke one staging Xray or AWG key and one enabled proxy backend access, then check `journalctl -u vpn-bot -n 100 --no-pager` for helper errors or secret leakage.

## Local Checks

Install runtime and development dependencies before running checks:

```bash
python -m pip install -r requirements.txt -c constraints.txt
python -m pip install -r requirements-dev.txt
```

Run the same core gates used by CI:

```bash
python -m pip_audit -r requirements.txt -r constraints.txt
python -m ruff check .
python -m compileall .
python -m mypy --strict bot/ services/ adapters/ config/ models/ utils/ repositories/
python -m pytest --cov=. --cov-report=term-missing --cov-fail-under=60
```

> **TODO (supply-chain hardening):** CI currently installs without `--require-hashes`. To detect tampered packages on PyPI, generate a hashed constraints file with `pip-compile --generate-hashes` and use `pip install --require-hashes -c constraints-hashed.txt`. Track as a follow-up issue.

## CI Checks

GitHub Actions runs the local gates without production secrets or live services:

- `dependency-audit`: `python -m pip_audit -r requirements.txt -r constraints.txt` — blocks the `tests` job if vulnerabilities are found.
- `tests` (needs `dependency-audit`): Python 3.12 — install runtime/dev dependencies, `ruff check .` (style + security + bugbear rules), `compileall`, `mypy --strict`, and `pytest ≥60% coverage`.

## Maintenance

Update from GitHub:

```bash
cd /opt/vpn-service
sudo git pull --ff-only
sudo /opt/vpn-service/.venv/bin/pip install -r requirements.txt -c constraints.txt
python deploy/check-nonroot-helper-mode.py
sudo systemctl restart vpn-bot
python deploy/check-nonroot-helper-mode.py
```

Do not run production DB migrations as root against `/opt/vpn-service/data/vpn.db`. The service bootstraps schema/migrations on startup as `vpn-bot`; if you must run `init_db.py` manually, run it with the same non-root identity and environment as the service.

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
- The installed systemd unit matches `deploy/vpn-bot.service`. In the default root+api configuration: `User=root`, `Group=root`, `ProtectSystem=false`, `RuntimeDirectory=vpn-bot`, `BOT_LOCK_PATH=/run/vpn-bot/vpn-bot.lock`.
- For root+api mode: `PRIVILEGE_HELPERS_ENABLED=false` (or absent), `XRAY_APPLY_MODE=api`, `XRAY_INBOUND_TAG` set, `XRAY_STATS_SERVER` pointing to the Xray API address. For non-root helper mode: `PRIVILEGE_HELPERS_ENABLED=true`, helper paths point to `/usr/local/sbin/vpnbot-*`, and `/etc/sudoers.d/vpnbot` validates with `visudo -cf`.
- `python deploy/check-nonroot-helper-mode.py` passes before the service restart.
- Xray config exists at `XRAY_CONFIG_PATH` and validates before the bot writes to it.
- AWG config/interface exist if AWG keys will be issued.
- Firewall rules are known before opening VPN ports.
- Backup destination exists and backup files are not world-readable.
- Code, deploy files, and `.venv` are not writable by `vpn-bot` or other untrusted users.
- If managed MTProto is enabled, `vpn-bot.service` does not have `ReadWritePaths=/etc/systemd/system`; the MTProxy wrapper/drop-in were installed manually and contain no raw secrets.
- If managed MTProto is enabled, `/etc/mtproxy/vpnbot/managed-secrets.json`, `/etc/mtproxy/vpnbot/mtproxy.env`, and `/etc/mtproxy/vpnbot/backups/*` are readable only by root/service operators.

### General bot health check

```bash
cd /opt/vpn-service
python deploy/check-nonroot-helper-mode.py
sudo systemctl status vpn-bot --no-pager
sudo journalctl -u vpn-bot -n 100 --no-pager
sqlite3 /opt/vpn-service/data/vpn.db "PRAGMA quick_check;"
.venv/bin/python -m compileall .
.venv/bin/python -m pytest
```

### Package 7 Healthcheck — preflight, postflight, and admin diagnostics

> ⚠️ **Note:** `deploy/check-nonroot-helper-mode.py` is designed for the **non-root privilege-helper deployment model** (`User=vpn-bot` + `PRIVILEGE_HELPERS_ENABLED=true`). If you are running the **root+api mode** (`User=root` + `XRAY_APPLY_MODE=api`), this checker will report `FAIL: User=root` — that is expected and correct for root deployment. Skip this checker in root mode; use `systemctl status vpn-bot` and the bot's admin diagnostics panel instead.

`deploy/check-nonroot-helper-mode.py` is the mandatory preflight and postflight tool for the non-root privilege-separated deployment. Run it before and after every deploy.

**Human-readable output (default):**

```bash
cd /opt/vpn-service
python deploy/check-nonroot-helper-mode.py
```

Exit codes:
- `0` — all checks passed (warnings are informational, not failures)
- `1` — one or more checks failed; address failures before starting or restarting the service

**Machine-readable JSON output (for automation/CI):**

```bash
python deploy/check-nonroot-helper-mode.py --json
```

JSON format: `{"overall": "ok|warning|failed", "failures": N, "warnings": N, "checks": [{"status": "ok|warning|failed", "message": "..."}]}`

**Pre-start mode (default — before `systemctl start vpn-bot`):**

```bash
python deploy/check-nonroot-helper-mode.py --mode pre-start
```

In `pre-start` mode, `/run/vpn-bot` absence is expected (systemd creates the `RuntimeDirectory` when the service starts) and will produce a warning, not a failure.

**Post-start mode (after `systemctl start vpn-bot`):**

```bash
python deploy/check-nonroot-helper-mode.py --mode post-start
```

In `post-start` mode, `/run/vpn-bot` must exist and be writable by `vpn-bot`. Absence is a failure.

**What the checker validates (Package 5D + Package 7):**

- `vpn-bot.service` contains `User=vpn-bot`, `Group=vpn-bot`, `RuntimeDirectory=vpn-bot`, `RuntimeDirectoryMode=0700`, `ProtectSystem=strict`
- `vpn-bot.service` does not contain `User=root`, `Group=root`, `NoNewPrivileges=true`
- `/etc/sudoers.d/vpnbot` is root:root 0440, grants only the 4 fixed helpers, no broad grants (`NOPASSWD: ALL`, `ALL=(ALL)`)
- Helper binaries are root:root 0755
- `/opt/vpn-service`, `.venv`, `deploy` are not writable by `vpn-bot`
- `/run/vpn-bot` existence and writability (mode-dependent)
- `.env` is not world-readable and is readable by `vpn-bot`
- SQLite `PRAGMA quick_check`
- Xray config syntax test (`xray run -test -config`)
- AWG config strip (`awg-quick strip`)
- MTProxy managed files readable and structurally valid JSON
- `sudo -n <helper> status` calls succeed (verifies sudoers grants work end-to-end)
- `systemctl is-active` for: `vpn-bot`, `xray`, `awg-quick@awg0`, `danted`, `mtproxy`

**Admin diagnostics in the bot (on-demand):**

Open the admin panel in Telegram → *Диагностика backend*. This runs a live read-only health check and shows:

```
Diagnostics  OK
2026-05-12 10:30:00 UTC

✓ Non-root OK (uid=1001)
✓ PRIVILEGE_HELPERS_ENABLED=true
✓ Xray: OK
✓ AWG: OK
✓ SOCKS5: OK
✓ MTProto: OK
✓ SQLite PRAGMA quick_check: ok
✓ vpn-bot: active
✓ xray: active
✓ awg-quick@awg0: active
...
```

Overall status is `OK / WARNING / DEGRADED / FAILED`. Secrets, tokens, private keys, and raw hex values are never shown — only the sanitised status and reason.

**Expected sudo log entries:**

When `PRIVILEGE_HELPERS_ENABLED=true`, every privileged operation (Xray/AWG config apply, SOCKS5 user create/delete, MTProto secret apply) produces a sudo log entry like:

```
vpn-bot : TTY=... ; PWD=... ; USER=root ; COMMAND=/usr/local/sbin/vpnbot-xray-apply apply ...
```

These entries are **expected and normal**. They confirm the least-privilege model is working correctly.

**Signs that require rollback:**

- `FAIL: ... User=root` in checker output — the service is configured to run as root (expected and correct in root+api mode; only a failure in non-root helper mode)
- `FAIL: ... NOPASSWD: ALL` — broad sudo grant is present
- `FAIL: ... writable by vpn-bot` on code/venv/deploy directories
- SQLite `PRAGMA quick_check` returns anything other than `ok`
- Bot starts, issues one key, but Xray/AWG service is immediately DEGRADED with a config apply error
- `sudo -n <helper> status` returns permission errors — sudoers file is incorrect
- Any helper binary not root:root 0755 — must be fixed before the bot can use them

If rollback is needed, see the "Rollback after a bad deploy" section below.

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
cd /opt/vpn-service
sudo install -o vpn-bot -g vpn-bot -m 0700 -d /opt/vpn-service/data /opt/vpn-service/logs
sudo chown -R vpn-bot:vpn-bot /opt/vpn-service/data /opt/vpn-service/logs
python deploy/check-nonroot-helper-mode.py
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

> ⚠️ **Back up first.** Always create a backup before rolling back code (see [Backup](#backup)). A code rollback does not roll back runtime state — SQLite, Xray config, and AWG config need separate restoration if the deploy already modified them.

**Step 1 — stop the service and back up runtime state:**

```bash
sudo systemctl stop vpn-bot
sudo tar --xattrs --acls -czf /root/vpn-service-backups/pre-rollback-$(date -u +%Y%m%dT%H%M%SZ).tar.gz \
  /opt/vpn-service/.env \
  /opt/vpn-service/data/vpn.db \
  /usr/local/etc/xray/config.json \
  /etc/amnezia/amneziawg/awg0.conf
sudo chmod 600 /root/vpn-service-backups/pre-rollback-*.tar.gz
```

**Step 2 — roll back the code:**

```bash
cd /opt/vpn-service
git log --oneline -5
git reset --hard <previous_commit>
.venv/bin/pip install -r requirements.txt -c constraints.txt
```

`git reset --hard` discards all local code changes on the server. Only use it when rolling back an unwanted deploy.

> **`init_db.py` is for fresh installs only.** Do NOT run `init_db.py` during rollback — it requires `BOT_TOKEN`/`ADMIN_IDS` and will attempt forward migrations on the existing database. The bot bootstraps the schema on startup; if the previous version is schema-compatible, simply restarting the service is sufficient.

**Step 3 — restore runtime state from backup if the failed deploy modified it:**

```bash
# Restore SQLite DB if the failed deploy changed DB schema or data
sudo cp /root/vpn-service-backups/<backup>.tar.gz /tmp/
sudo tar -xzf /tmp/<backup>.tar.gz -C / opt/vpn-service/data/vpn.db

# Restore Xray config if changed
sudo tar -xzf /tmp/<backup>.tar.gz -C / usr/local/etc/xray/config.json
sudo xray run -test -config /usr/local/etc/xray/config.json

# Restore AWG config if changed
sudo tar -xzf /tmp/<backup>.tar.gz -C / etc/amnezia/amneziawg/awg0.conf
```

**Step 4 — restart and verify:**

```bash
sudo systemctl start vpn-bot
sudo systemctl status vpn-bot
sudo journalctl -u vpn-bot -n 100 --no-pager
```

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
