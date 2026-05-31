# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- **WARP Telegram routing module** — optional server-side AmneziaWG (`tg-warp`) tunnel that routes the traffic defined by the uploaded config's `AllowedIPs` and automatically falls back to the direct path on tunnel loss. Disabled by default; managed from a new admin-panel tab (📡 WARP-туннель) with config upload, enable/disable/restart, settings and delete. An asyncio health monitor pings the tunnel every 10 s, removing routes after 2 consecutive failures and restoring them after 3 consecutive successes. The bot stays unprivileged: all root actions go through new `vpnbot-warp-install` / `-iface` / `-routes` / `-status` sudo helpers. `AllowedIPs` is never modified; the server DNS resolver and default route are never touched. Adds the `warp_settings` table (schema version 20), the `warp/` package, `bot/handlers/admin_warp.py`, `bot/keyboards/warp_keyboard.py` and `scripts/vpnbot-warp-*`.

## [1.1.0] — 2026-05-30

### Added

- **Xray TLS fingerprint selection** — a new step in the Xray key creation flow lets users (and admins) choose a TLS fingerprint right after the note prompt; the selected value is embedded in the VLESS link (`fp=`) and stored in the key payload. Ten fingerprints are supported: `firefox` (default), `chrome`, `safari`, `ios`, `android`, `edge`, `360`, `qq`, `random`, `randomized`. Legacy keys without a stored fingerprint transparently fall back to the global `XRAY_FINGERPRINT` env variable. (#115)
- **Per-key fingerprint editing** — the key detail card for active Xray keys now includes a «Изменить Fingerprint» button that opens an inline keyboard to change the fingerprint; the VLESS link is regenerated and the detail card updated immediately. (#115)
- **Anomaly alert dismiss button** — anomaly alert messages now include an inline «✅ Я прочитал» button; clicking it silently deletes the alert only from that admin's chat, leaving other admins' copies intact. (#116)

## [1.0.2] — 2026-05-28

### Fixed

- **AWG key detail** — removed IP and public key fields from the AmneziaWG key detail card; MTU is now displayed instead. Config hint after showing an AWG config updated from «AmneziaWG» to «AmneziaVPN» in both locales. (#106)
- **Offsite backup timer** — weekly backup timer no longer resets after a bot reboot. The last-backup timestamp is now persisted in `schema_meta`; on startup the loop sleeps only for the remaining interval, or sends immediately if 7+ days have elapsed. (#112)

### Changed

- **Prompt message cleanup** — the inline-keyboard prompt message shown when the bot awaits a text reply (note or custom MTU) is now deleted before the next message is sent, reducing chat clutter. Covers all key-creation and note-editing flows for both users and admins. (#107)
- **Python version declaration** — declared Python support narrowed to `>=3.12,<3.13` in `pyproject.toml` and updated in `README.md`, `README_RU.md`, `CONTRIBUTING.md` to reflect that only Python 3.12.x is tested and verified. (#111)
- **Docstrings** — added concise one-line docstrings to all public methods and functions across `services/`, `adapters/`, `repositories/`, `bot/handlers/`, `bot/keyboards/`, and `bot/middlewares/`. (#110)

## [1.0.1] — 2026-05-25

### Fixed

- **Xray API mode** — `xray api adu` / `xray api rmu` silently fail for VLESS in Xray 26.3.27 (exit 0, «Added 0 user(s)»). Replaced both with `_api_reload_inbound`: reads the target inbound from the on-disk config, then calls `rmi` + `adi` to atomically replace it in the running Xray process. `rmi` errors on first run (inbound not yet loaded) are logged at DEBUG and ignored; an exception is raised only when `adi` fails. Rollback in `_install_candidate_api` now also goes through `_api_reload_inbound` after restoring the backup, falling back to `systemctl reload/restart` only if `adi` itself fails. (#103)

### Changed

- **Protocol selection menu** — menu heading «Выберите тип ключа:» renamed to «Выберите протокол:» (ru/en); button labels updated: «Xray» → «Xray (VLESS+XReality)», «AWG» → «AmneziaWG 2.0» across all three keyboards. (#104)

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

[1.1.0]: https://github.com/Egor051/vpnbot/compare/v1.0.2...v1.1.0
[1.0.2]: https://github.com/Egor051/vpnbot/compare/v1.0.1...v1.0.2
[1.0.1]: https://github.com/Egor051/vpnbot/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/Egor051/vpnbot/releases/tag/v1.0.0
