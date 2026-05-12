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
BOT_LOCK_PATH=/run/vpn-bot/vpn-bot.lock

# Production non-root helper mode
PRIVILEGE_HELPERS_ENABLED=true
HELPER_STAGING_ROOT=/run/vpn-bot
SOCKS5_USER_HELPER_PATH=/usr/local/sbin/vpnbot-socks5-user
XRAY_APPLY_HELPER_PATH=/usr/local/sbin/vpnbot-xray-apply
AWG_APPLY_HELPER_PATH=/usr/local/sbin/vpnbot-awg-apply
MTPROTO_APPLY_HELPER_PATH=/usr/local/sbin/vpnbot-mtproxy-apply

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

- If `XRAY_INBOUND_TAG` is empty, the adapter uses the first inbound with `settings.clients`.
- If `XRAY_MANAGE_SHORT_IDS=false`, `XRAY_SHORT_ID` must be set.
- `XRAY_APPLY_MODE=restart` is the default production apply mode; use `reload` only when your Xray unit reliably applies reload.
- `SQLITE_SYNCHRONOUS=FULL` is the safer default for this control-plane database. `NORMAL` is faster but can lose the last committed transactions on OS or power failure while VPN backend state has already changed.
- `AWG_CLIENT_DNS` is supported only as a legacy alias; use `AWG_DNS` for new deployments.
- `AWG_ENDPOINT_HOST` and `AWG_ENDPOINT_PORT` should point to the public AWG endpoint clients will use.
- `SOCKS5_ENABLED=true` requires `SOCKS5_HOST`, `SOCKS5_PORT`, and a safe `SOCKS5_LOGIN_PREFIX`. Dante must already be installed and listening; the bot only creates/locks/deletes managed Linux users with that prefix.
- `MTPROTO_ENABLED=true` requires `MTPROTO_HOST`. `MTPROTO_MODE=static` also requires `MTPROTO_SECRET`.
- `MTPROTO_MODE=static` is compatibility mode: the bot shows a shared MTProto secret and can only deactivate a user's SQLite record. True per-user server-side revoke is impossible in static mode without rotating the shared secret.
- `MTPROTO_MODE=managed` creates one unique secret per user. In production helper mode the bot stages managed files under `/run/vpn-bot/mtproxy`; `/usr/local/sbin/vpnbot-mtproxy-apply` writes `/etc/mtproxy/vpnbot`, restarts `mtproxy`, verifies service/port health, and rolls back managed files if apply fails. The systemd drop-in and wrapper are installed during deploy, not written by the bot at runtime.
- `MTPROTO_SECRET`, SOCKS5 passwords, and real production endpoints with credentials must never be committed. `.env.example` intentionally keeps proxy secrets empty.
- `DEFAULT_PROXY_*` is legacy compatibility storage and does not drive the new user-facing proxy access flow.
- Production deployment runs the bot as `vpn-bot:vpn-bot` with `PRIVILEGE_HELPERS_ENABLED=true`. Root-only backend changes go through the fixed sudo helpers documented in `deploy/helpers/README.md`.
- Keep project code, deploy files, `.env`, and `.venv` outside `vpn-bot` write access. Only `/opt/vpn-service/data`, `/opt/vpn-service/logs` if file logs are enabled, and `/run/vpn-bot` should be writable by the service user.

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

The supplied systemd unit expects the project in `/opt/vpn-service`. If you deploy elsewhere, update `deploy/vpn-bot.service` before installing it.

Production deployment model:

1. Keep `/opt/vpn-service`, deploy files, `.env`, and `.venv` owned by root/operator and not writable by `vpn-bot`.
2. Create the `vpn-bot:vpn-bot` system identity.
3. Grant `vpn-bot` write access only to runtime state: `/opt/vpn-service/data`, `/opt/vpn-service/logs` if file logs are enabled, and `/run/vpn-bot` created by systemd.
4. Install fixed helpers under `/usr/local/sbin` and install `/etc/sudoers.d/vpnbot` with only those helper entrypoints.
5. Enable `PRIVILEGE_HELPERS_ENABLED=true`.
6. Install `deploy/vpn-bot.service`; it is the production non-root unit.

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
- The installed systemd unit matches `deploy/vpn-bot.service`, runs as `User=vpn-bot` and `Group=vpn-bot`, uses `RuntimeDirectory=vpn-bot`, and sets `BOT_LOCK_PATH=/run/vpn-bot/vpn-bot.lock`.
- `PRIVILEGE_HELPERS_ENABLED=true`, helper paths point to `/usr/local/sbin/vpnbot-*`, and `/etc/sudoers.d/vpnbot` validates with `visudo -cf`.
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

- `FAIL: ... User=root` in checker output — the service is configured to run as root
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
