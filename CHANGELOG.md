# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [1.0.0] — 2026-05-23

### Added

#### Core bot
- Telegram bot (aiogram 3) with user registration and access approval flow (pending → approved/blocked).
- Role-based access control: `SUPERADMIN`, `MODERATOR`, `APPROVED_USER`, `PENDING_USER`, `BLOCKED_USER`.
- `MODERATOR` role between `APPROVED_USER` and `SUPERADMIN`; moderators can approve/block pending users without full admin access.
- Bot UI language support via `BOT_LANGUAGE` (`ru` / `en`).
- Single-instance lock (`utils/single_instance.py`).
- Optional HTTP health endpoint (`adapters/health_server.py`, `HEALTH_HOST` / `HEALTH_PORT`).

#### Xray VLESS Reality
- Key creation, VLESS link + JSON config delivery, revocation, deletion.
- Startup reconciliation between SQLite and live Xray config.
- Traffic stats via Xray gRPC stats API (`XRAY_STATS_SERVER`).
- `XRAY_APPLY_MODE=api` — applies config changes through the Xray management API without restarting the service; incompatible with `PRIVILEGE_HELPERS_ENABLED=true` (validated at startup).
- `XRAY_MANAGE_SHORT_IDS` — optional automatic per-client short-ID management.

#### AmneziaWG
- Key creation, client config delivery (INI format), revocation, deletion.
- `amnezia://` deep-link alongside the INI config; MTU selectable during key creation.
- IPAM (automatic IP allocation within `AWG_NETWORK`), preshared key support.
- Startup reconciliation between SQLite, `awg0.conf`, and AWG runtime.
- Background traffic accounting: periodic transfer-counter sampling under the refresh lock.

#### Proxy backends
- **SOCKS5/Dante** — per-user Linux account management (create, lock, delete) via `vpnbot-socks5-user` sudo helper. `SOCKS5_LOGIN_PREFIX` enforcement prevents managing arbitrary system users.
- **MTProto** — `static` mode (shared secret) and `managed` mode (per-user secrets, atomic apply, backup/rollback via `vpnbot-mtproxy-apply` sudo helper). Output always includes plain and `dd` random-padding Telegram links.
- Proxy access lifecycle: issue, revoke, delete, per-user stats from SQLite.

#### Admin panel
- Pending request queue, user management (approve, block, view), key issuance per user.
- Audit log viewer with recursive secret masking; configurable retention via `AUDIT_RETENTION_DAYS`.
- Traffic stats (Xray via gRPC, AWG via background sampler).
- Backend diagnostics: per-backend `OK` / `DEGRADED` status with sanitised reason.
- Announcements to all approved users.
- Scheduled announcements: future delivery time set by admin; background scheduler dispatches at the configured moment.
- User notes: free-text memos attached to any user card, stored per-user.

#### Key lifecycle extras
- Key expiry notifications — `KEY_EXPIRY_NOTIFY_DAYS` controls how many days before expiry users are notified.
- Trial access — time-limited VPN keys for `PENDING_USER` and `BLOCKED_USER`; trial state tracked in DB with admin reset capability.
- User self-service key management — approved users can revoke or delete their own VPN keys without admin intervention.

#### Anomaly detection
- Background monitor flags keys with suspiciously high traffic or concurrent-connection patterns.
- Configurable window, IP threshold, cooldown, and optional auto-revoke (`ANOMALY_AUTO_REVOKE`).
- Flagged keys appear in the admin panel.

#### Off-site encrypted backups
- Periodic DB snapshots encrypted with `cryptography` (Fernet, `OFFSITE_BACKUP_ENCRYPTION_KEY`) and uploaded to a configured Telegram chat.

#### Storage
- SQLite via `aiosqlite` with schema bootstrap and migrations (`db/schema.sql`).
- Tables: `users`, `access_requests`, `vpn_keys`, `trial_key_requests`, `proxy_entries`, `proxy_accesses`, `audit_log`, `vpn_key_traffic_stats`.
- `SQLITE_SYNCHRONOUS` setting; configurable DB path via `DB_PATH`.

#### Deployment
- **Root + api mode** (default): `User=root`, `PRIVILEGE_HELPERS_ENABLED=false`, `XRAY_APPLY_MODE=api` — bot writes Xray config and applies changes directly via gRPC API; no sudo helpers required.
- **Non-root privilege-helper mode**: bot runs as `vpn-bot:vpn-bot`; root-only operations go through four fixed sudo helpers (`vpnbot-socks5-user`, `vpnbot-xray-apply`, `vpnbot-awg-apply`, `vpnbot-mtproxy-apply`) with restricted sudoers grants.
- `deploy/vpn-bot.service` — authoritative systemd unit; overwrites the system service file on every deploy.
- `deploy/check-nonroot-helper-mode.py` — preflight and postflight healthcheck with human-readable and JSON output, pre-start and post-start modes.
- `deploy/create-vpn-bot-user.sh` — helper to create the `vpn-bot` system account.
- Rotating file logs via `LOG_DIR`.
- Config backup with retention policy (`CONFIG_BACKUP_KEEP_LAST`).

#### CI and quality
- GitHub Actions: `dependency-audit` (pip_audit) → `tests` (ruff, compileall, mypy --strict, pytest ≥ 60 % coverage) on Python 3.12.
- Hashed constraints files (`constraints-hashed.txt`, `constraints-dev-hashed.txt`) installed with `--require-hashes` to guard against supply-chain tampering.
- Dependabot for pip and GitHub Actions.
- `CONTRIBUTING.md` — development setup, code quality gates, commit format, branch naming, security considerations, PR process.
- `CODE_OF_CONDUCT.md` — Contributor Covenant 2.1.
- `.github/ISSUE_TEMPLATE/` — bug report, feature request, security hardening templates; blank issues disabled.
- `.github/SECURITY.md` — security policy and responsible disclosure guide.

### Security
- Privilege separation: all root operations go through four fixed-path sudo entrypoints; bot process runs unprivileged in non-root mode.
- `SOCKS5_LOGIN_PREFIX` enforcement prevents the bot from managing arbitrary Linux users.
- Secret redaction in all audit records, error messages, and log output.
- Config writes are atomic: staged file → validate → swap, with backup and automatic rollback on apply failure.
- Managed MTProto secrets and env files are `root:root 0600`; backup directories are `root:root 0700`.
- `XRAY_APPLY_MODE=api` + `PRIVILEGE_HELPERS_ENABLED=true` combination rejected at startup.

[1.0.0]: https://github.com/Egor051/vpnbot/releases/tag/v1.0.0
