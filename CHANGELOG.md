# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [1.3.0] — 2026-06-04

### Added

- **Live admin dashboard** — new «📊 Дашборд» button in the admin panel opens a
  single auto-refreshable message with six stat blocks: 👥 Users (role breakdown,
  new in 7/30 d, active keys, pending requests), 🔑 VPN keys (active Xray/AWG,
  expiring in 7/30 d, stale, average per user), 📊 Traffic (totals Xray/AWG,
  per-key average, Top-5 users), 🌐 Proxy (active SOCKS5/MTProto, stale), ⚙️
  System (backend status, WARP, DB size, last backup time), 📋 Activity (audit
  24 h/7 d, announcements in 30 d, last 3 actions). All 17 data sources are
  queried in parallel via `asyncio.gather`. Adds `repositories/dashboard.py`,
  `services/dashboard.py`, and `bot/handlers/admin_dashboard.py`. (#132)
- **WARP tunnel Telegram alerts** — `WarpHealthMonitor` now fires optional
  `on_tunnel_down` / `on_tunnel_recovered` callbacks on every route-state
  transition; `WarpManager` wires them to send a dismissible inline alert to all
  admins (🔴 tunnel down / 🟢 recovered). The alert message is deleted when the
  admin taps «✅ Понял». (#134)

### Changed

- **Usage rules formatting** — removed the blank line between the «ПРАВИЛА
  ПОЛЬЗОВАНИЯ:» header and the first prohibition icon, making the block more
  compact. (#133)
- **Dashboard layout** — Top-5 traffic users and recent audit actions are now
  displayed in a column (one entry per line) instead of a pipe-separated single
  line. (#148)
- **Server restart notice** — schedule wording updated from «по чётным числам» to
  «по числам, кратным пяти», and the expected downtime from «несколько минут» to
  «несколько десятков секунд». (#149)

### Fixed

- **AWG keys hide IP on listing page** — `key_list_card` no longer shows the
  assigned IP for AmneziaWG keys (IP is meaningful in the config file, not as a
  display label); Xray keys are unaffected. (#145)
- **Deleted-key traffic preserved in dashboard totals** — `hard_delete_with_stats`
  previously removed both the key row and its `vpn_key_traffic_stats` entry,
  silently dropping lifetime bytes from the dashboard. A new
  `deleted_key_traffic_archive` table (schema version 22) captures the byte counts
  at deletion time within the same transaction; `traffic_totals()` and
  `top_users_by_traffic()` `UNION ALL` the archive so lifetime traffic is always
  reflected. (#146)
- **Deleted-key traffic archive consistency** — follow-up to #146: migration v22
  is now properly wired into the versioned ladder (`_migrate_v22`,
  `CURRENT_SCHEMA_VERSION = 22`); dashboard `avg_per_key_bytes` is now computed
  over the same live-plus-archive dataset as `total_bytes` so `avg × keys = total`;
  `top_users_by_traffic` username is deterministic (`MAX(username)`); covering
  indexes added on the archive table for index-only aggregation scans. (#147)
- **Dependency audit set realigned with the installed set** — `constraints.txt`
  (scanned by `pip-audit`) had drifted from `constraints-hashed.txt` (installed
  with `--require-hashes`): five transitive pins disagreed (`aiohappyeyeballs`,
  `certifi`, `idna`, `propcache`, `yarl`) and `cffi`/`pycparser` were missing
  entirely. `constraints.txt` is now generated as the un-hashed mirror of
  `constraints-hashed.txt` via `scripts/sync-constraints.py` (wired into
  `make update-hashes`), so the audited and installed sets can no longer diverge.
  (#141)
- **i18n key parity** — removed the orphan `btn_proxy_stats` key that existed only
  in the English catalogue, restoring ru/en parity; `i18n.t()` now falls back to
  the base (ru) string before the raw identifier when a key is missing in the
  active locale. Added `tests/test_i18n_parity.py` (key/placeholder/HTML parity)
  and `tests/test_env_settings_drift.py` (settings ↔ .env.example/README drift).
  (#141)
- **Documentation drift** — documented the WARP Telegram routing module and
  `WARP_PING_TARGET` in `README_RU.md` (previously English-only) and in
  `.env.example`; fixed the `BOT_LOCK_PATH` default and the `XRAY_FINGERPRINT`
  value list in `README.md`; refreshed the database-table list in both READMEs;
  surfaced previously undocumented tunables (`ANOMALY_*`, `KEY_EXPIRY_*`,
  `BOT_LANGUAGE`, staging dirs, …) in `.env.example`; aligned `CONTRIBUTING.md`
  with the actual CI gates. (#141)

### Security

- **WARP root-RCE via config hooks closed** — `awg-quick` executes
  `PreUp/PostUp/PreDown/PostDown` as root; both the bot-side
  `warp/config_validator.py` and the `vpnbot-warp-install` root boundary now
  reject any of these directives (case-insensitive). (#140)
- **AWG arbitrary root file-write and rollback corruption fixed** — `vpnbot-awg-apply`
  wrote the stripped config into the bot-writable staging directory via a plain
  `open("wb")`, allowing a symlink to redirect the write to any root-owned path;
  rollback aliased the canonical config, causing self-truncation. The helper now
  stages the strip-input in the root-owned canonical directory with
  `O_CREAT|O_EXCL|O_NOFOLLOW`. (#140)
- **Default-route guard extended** — `vpnbot-warp-routes` now skips any
  default-equivalent route (`default`, prefix length 0 or 1, including the
  two-`/1` split-default trick); `vpnbot-warp-install` validates every
  `AllowedIPs` token as a real CIDR at the root boundary. (#140)
- **Privileged-process zombie on timeout prevented** — `shell_runner.py` now
  launches subprocesses in a new session and sends `SIGKILL` to the entire process
  group on timeout, ensuring grandchild processes (e.g. `awg`) are also reaped;
  `xray_config._apply_helper` no longer retries on timeout to avoid a concurrent
  double-apply race. (#139)
- **Adapter injection vectors closed** — AWG config `label` field rejects
  whitespace/control characters; `dante_users` validates the password for `\n`,
  `\r`, `\x00`, and `:` at the adapter boundary (not only in the helper); the
  `email_label` field in `xray_config.add_client` is validated against
  `_EMAIL_SAFE_RE`. (#139)
- **Secrets no longer leak through ShellResult or logs** — `ShellResult.stderr` is
  now stored redacted; redaction happens before truncation so secrets cannot appear
  in the tail of a long error output. REALITY inbound API config (containing the
  private key) is written with `umask 0600` + `fsync` instead of to `/tmp`. (#139)
- **Staging symlink attacks prevented** — `privileged_helpers.py` enforces 0700 on
  an already-existing staging directory, forbids symlink staging roots, correctly
  removes symlinks on cleanup, and rejects `..` and symlinks in the helper path;
  `vpnbot-warp-install` rejects a symlinked source file and operates on `realpath`.
  (#139, #140)
- **Moderator-initiated block now revokes all backend access** — `block_user` was
  reachable by moderators but the wired revokers required superadmin, leaving every
  VPN key and proxy access active on the backend after a moderator block. The block
  flow now uses system revokers (`revoke_*_system`) with correct audit attribution.
  (#137)
- **`disable_protocol` no longer orphans live backend access** — it previously
  hard-deleted database rows without revoking the corresponding Xray client / AWG
  peer / Dante user / MTProto secret. It now revokes each key/access through the
  full delete pipeline, enforces superadmin, writes an audit record, and refuses to
  run if purge handlers are not wired. (#137)
- **Concurrent trial approval no longer double-issues keys** — `approve_trial_request`
  provisioned the key before atomically claiming the request, allowing two
  concurrent approvals to each create a key. A decision lock and fresh status
  re-check now guarantee exactly one provisioning. (#137)
- **Trial flow rejects blocked users** — `create_trial_request` and the trial
  request handlers now reject blocked users; `/start` no longer offers the trial
  button to blocked users. (#136, #137)
- **IDOR in key detail view fixed** — `open_key` now cross-checks the `owner` from
  callback data against the key's real owner, matching the behaviour of `revoke`
  and `delete`. (#136)
- **HTML truncation and escaping fixes** — `cap_telegram_html` now closes
  `i`/`u`/`s`/`blockquote` tags (not just `b`/`code`/`pre`) on truncation and
  drops a trailing half-cut HTML entity; the user note in the admin «edit note»
  prompt is now HTML-escaped (every other note render already escaped it). (#136)
- **`RateLimiter` eviction bypass fixed** — throttled entries are now kept
  most-recently-used so they cannot be evicted (which would reset the cooldown)
  under high churn. (#136)
- **Secrets excluded from `repr()` and tracebacks** — `Settings.bot_token` and
  `Settings.default_proxy_password` are marked `repr=False`; `VpnKey`, `ProxyAccess`,
  and `ProxyEntry` DTOs have redacting `__repr__` so `payload`/`password` fields
  do not appear in logs or tracebacks. (#135, #138)
- **Central log redaction** — a redaction formatter is applied to every log handler
  so secrets are masked in every record even if the call site omits `redact()`;
  log files remain `0600` after rotation via a secure `RotatingFileHandler`. (#135)
- **Config validation hardened** — control characters are now banned in network
  values (host/SNI/DNS/AllowedIPs/flow) to prevent injection into configs and
  links; Fernet key is validated to decode to exactly 32 bytes; non-positive
  `ADMIN_IDS` are rejected; empty `HEALTH_HOST` defaults to `127.0.0.1` instead of
  binding all interfaces. (#135)
- **DB file created mode 0600** — the database file is created with `0600`
  permissions before `aiosqlite` opens it, closing the world-readable window; WAL
  checkpoint (`TRUNCATE`) added to `close()` to limit WAL growth; FK enforcement
  after migration v16 fixed (raw connection + `commit()` before `finally`). (#138)
- **Dashboard timestamp timezone consistency** — dashboard cutoffs now use the same
  `+00:00` format as stored values, eliminating boundary skew in
  `keys_summary`/`count_new_users_since`/`count_announcements_since`; the audit
  prune and `count_audit_since` queries now use `idx_audit_log_created_at` again
  (the `REPLACE()` that prevented index use was removed). (#138)
- **CI action pinning** — `actions/checkout` and `actions/setup-python` are now
  pinned by commit SHA (with version comments) instead of mutable tags; `push`
  CI is scoped to `main`. (#141)
- **Lint suppressions scoped** — the project-wide `S608` (SQL injection) and
  `S603`/`S607`/`S404` (subprocess) ruff ignores are now scoped to the
  directories that legitimately need them (`db/`, `repositories/`, `deploy/`,
  `tests/`), so the rest of the tree is guarded against new violations. Added
  `*-wal`/`*-shm`/`*-journal` ignores and a vulnerability-response timeframe to
  `SECURITY.md`. (#141)
- **aiohttp advisories triaged (VEX)** — `pip-audit` now runs via `make audit`
  with a documented `--ignore-vuln` list for `CVE-2026-34993` and
  `CVE-2026-47265`. Both are fixed only in aiohttp 3.14.0, which the tree cannot
  adopt while `aiogram` (≤3.28.2) caps `aiohttp<3.14`, and neither applies to the
  bot's client-only, trusted-host usage. To be revisited when `aiogram` raises the
  cap. (#141)

## [1.2.0] — 2026-06-01

### Added

- **WARP Telegram routing module** — optional server-side AmneziaWG (`tg-warp`) tunnel that routes traffic defined by the uploaded config's `AllowedIPs` through a dedicated tunnel interface, with automatic health-based fallback to the direct path on tunnel loss. Disabled by default; managed from a new admin panel tab (📡 WARP-туннель) with config upload, enable/disable/restart, settings and delete. An asyncio health monitor pings the tunnel every 10 s, removing routes after 2 consecutive failures and restoring them after 3 consecutive successes. The bot stays unprivileged: all root actions go through new `vpnbot-warp-install` / `-iface` / `-routes` / `-status` sudo helpers. `AllowedIPs` is never modified; the server DNS resolver and default route are never touched. Adds the `warp_settings` table (schema version 20), the `warp/` package, `bot/handlers/admin_warp.py`, `bot/keyboards/warp_keyboard.py` and `scripts/vpnbot-warp-*`. (#118)
- **Protocol modules management** — new «⚙️ Модули протоколов» tab in the admin panel lets superadmins enable or disable any protocol (Xray, AWG, SOCKS5, MTProto) independently. Disabling a protocol requires two-step confirmation and hard-deletes all related keys and proxy entries from the database; the bot UI hides all buttons and menus for the disabled protocol. Re-enabling restores access in one click (historical data is not recovered). Server-side configs and Linux accounts are unaffected. Adds the `protocol_modules` table (schema version 21). (#125)
- **Usage rules on main menu** — the main menu screen now displays a usage rules block warning users that MAX messenger and torrent traffic through VPN are strictly prohibited. (#128)

### Changed

- **Admin panel proxy tab unified** — «Статус прокси» and «Статистика прокси» tabs merged into a single «🌐 Прокси: статус и статистика» tab. The new combined view shows service configuration, lifecycle counters, and the per-user table in one message; zero-value fields are hidden to reduce noise. (#124)
- **Admin panel button order and emojis** — admin panel buttons are now sorted from most to least frequently used and all labels carry emojis (📋 Заявки, 👥 Пользователи, 🔑 Выдать ключ, 🧪 Пробные доступы, 📊 Статистика ключей, 🌐 Прокси, 📢 Объявление, 📡 WARP-туннель, ⚙️ Модули протоколов, 🔍 Диагностика, 📜 Логи, 🔄 Восстановление, 💾 Бэкап). (#126)
- **WARP ping target configurable** — `PING_TARGET` default switched from `149.154.167.50` to `162.159.140.245` (Cloudflare anycast, reliably responds to ICMP and present in typical WARP `AllowedIPs`). Deployments with Telegram-only `AllowedIPs` can override via the new `WARP_PING_TARGET` env variable to prevent false health-monitor failures. (#130)
- **Health diagnostics severity** — running as root and `PRIVILEGE_HELPERS_ENABLED=false` are now reported as `warning` (⚠) instead of `failed` (✗); the overall backend diagnostics status no longer shows FAILED in these configurations. (#129)

### Fixed

- **WARP config delete removes files from disk** — `delete_config` now calls the new `vpnbot-warp-install remove` sub-command to delete `/etc/amnezia/tg-warp.conf` and `/etc/amnezia/tg-warp-routes.list`, preventing the PrivateKey from persisting after config deletion. A helper failure is propagated as `WarpError` so the database is kept intact if the removal fails. (#119)
- **WARP config install uses secure temp files** — `vpnbot-warp-install` now creates mode-600 temp files with `install -m 600 /dev/null` before writing any content, then atomically `mv`s them into place, eliminating the window where an intermediate file containing the PrivateKey could be world-readable. (#119)
- **WARP DB migration version counter** — `_apply_migrations` was missing the `version = 20` assignment after `_set_schema_version(20)`, breaking the consistent pattern used by every other migration block. (#119)
- **WARP routes skip default routes** — `vpnbot-warp-routes` now skips `0.0.0.0/0` and `::/0` entries from `AllowedIPs` with a warning to stderr, preventing accidental capture of the default route and host isolation. The `del` branch mirrors this symmetrically. (#120)
- **WARP cap_net_raw probe on startup** — `WarpManager._start_locked` now runs one test ping immediately after the interface comes up and logs a `WARNING` pointing the operator to `getcap $(which ping)` if it fails, before the health monitor starts its loop. (#120)
- **WARP upload size validated after download** — `warp_upload_receive` now checks `len(buffer.getvalue())` after `bot.download()` completes to enforce the 64 KB limit on actual downloaded bytes rather than relying solely on the client-reported `file_size`. (#120)
- **WARP CIDR validation** — `validate_amnezia_config` now validates each `AllowedIPs` token via `ipaddress.ip_network(strict=False)` and raises `WarpConfigError` for invalid CIDRs, preventing bogus route-count inflation. (#121)
- **WARP upload rate-limit** — `warp_upload_receive` now enforces the same per-user rate-limit as other WARP admin actions (30 s cooldown). (#121)
- **AWG client traffic NATted through tg-warp** — `vpnbot-warp-routes` now adds an `iptables -t nat POSTROUTING MASQUERADE` rule for traffic leaving via `tg-warp`, so AWG clients (source `10.0.0.x`) reach the WARP endpoint correctly. The rule is idempotent (`-C` check before `-A`) and removed symmetrically in the `del` branch. (#122)
- **FORWARD rules for awg0↔tg-warp** — `vpnbot-warp-routes` now manages two iptables `FORWARD` rules: allow `awg0→tg-warp` and allow `tg-warp→awg0 RELATED,ESTABLISHED`, ensuring bidirectional packet forwarding for VPN clients routed through the WARP tunnel. (#123)
- **WARP upload prompt deleted on success** — the upload prompt message is now saved to FSM state and deleted after a config is successfully installed, consistent with the behaviour in other bot input flows. Validation errors leave the prompt intact so the user can retry. (#127)
- **Anomaly dismiss i18n** — hardcoded `«✅ Я прочитал»` string in `services/anomaly_detection.py` replaced with the new `btn_anomaly_dismiss` i18n key (ru + en); dead `anomaly_dismiss_keyboard()` helper removed from `bot/keyboards/admin.py`. (#121)

### Security

- **WARP PrivateKey protection** — config install now writes exclusively through mode-600 temp files and config delete propagates helper errors rather than silently clearing the database, preventing PrivateKey material from being exposed in world-readable intermediate files or from persisting on disk after deletion. (#119)

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

[1.3.0]: https://github.com/Egor051/vpnbot/compare/v1.2.0...v1.3.0
[1.2.0]: https://github.com/Egor051/vpnbot/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/Egor051/vpnbot/compare/v1.0.2...v1.1.0
[1.0.2]: https://github.com/Egor051/vpnbot/compare/v1.0.1...v1.0.2
[1.0.1]: https://github.com/Egor051/vpnbot/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/Egor051/vpnbot/releases/tag/v1.0.0
