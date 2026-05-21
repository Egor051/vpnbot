# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added
- **MODERATOR role** — new role between `APPROVED_USER` and `ADMIN`; moderators
  can approve/block pending users without full admin access.
- **Scheduled announcements** — admins can create announcements with a future
  delivery time; a background scheduler dispatches them at the configured moment.
- **Key expiry notifications** — `KEY_EXPIRY_NOTIFY_DAYS` env var; bot
  proactively notifies users N days before their VPN key expires.
- **User notes** — admins can attach free-text memos to any user card; notes are
  stored per-user and shown in the admin panel.
- **AWG `amnezia://` link format** — AmneziaWG key delivery now includes an
  `amnezia://` deep-link alongside the existing INI config; MTU is selected
  interactively during key creation.
- **Anomaly detection for VPN keys** — background monitor flags keys with
  suspiciously high traffic deltas (potential credential sharing); flagged keys
  appear in the admin panel.
- **Encrypted off-site DB backups via Telegram** — periodic database snapshots
  are encrypted with `cryptography` (Fernet) and uploaded to a configured
  Telegram chat for off-site storage.
- **Trial access for pending/blocked users** — time-limited VPN keys can be
  issued to `PENDING_USER` and `BLOCKED_USER` accounts; trial state tracked in
  DB with admin reset capability.
- **`XRAY_APPLY_MODE=api`** — optional mode that patches the running Xray config
  via the management API instead of restarting the service; incompatible with
  `PRIVILEGE_HELPERS_ENABLED` (validated at startup).
- **AWG traffic accounting** — background collector periodically samples
  AmneziaWG transfer counters; sampling runs inside the refresh lock to prevent
  stale-snapshot inflation.
- **User self-service key management** — approved users can revoke or delete
  their own VPN keys without admin intervention.
- **Root + API deployment mode** — `deploy/` docs and service file updated to
  cover running the bot as root with `XRAY_APPLY_MODE=api`.
- `CONTRIBUTING.md` — development setup, code quality gates, commit format, branch
  naming, security considerations, and PR process.
- `CODE_OF_CONDUCT.md` — Contributor Covenant 2.1.
- `.github/ISSUE_TEMPLATE/config.yml` — disables blank issues; routes security
  reports to GitHub Security Advisories.

### Changed
- Proxy stats button removed from the user-facing proxy menu (admin-only
  operation; was surfaced by mistake).
- Emoji removed from proxy stats button labels and section headers for a
  cleaner, consistent UI.
- Redundant "you are blocked" message on `/start` removed; the inline keyboard
  already conveys blocked status.
- Traffic-stats refresh parallelised; hot-path regex patterns pre-compiled at
  module load — measurable latency reduction on large user bases.
- Codebase simplification: duplicated helpers merged, sequential `await` chains
  parallelised, dead `getattr` branches removed.
- `README.md` CI section: corrected Python version matrix to 3.12 only (matches
  the workflow).
- `.github/ISSUE_TEMPLATE/bug_report.md`: added `triage` label; added
  "Relevant protocol/component" field to the Environment section.
- `.gitignore`: fixed UTF-16/CRLF encoding corruption on the last line; normalised
  all line endings to LF.

### Fixed
- `ProtectSystem=strict` in `vpn-bot.service` was blocking helper writes and AWG
  config validation; `ReadWritePaths` entries added for all affected paths.
- `XRAY_APPLY_MODE=api`: fallback to `systemctl restart` when a `short_id` is
  absent in `remove_client`; `inbound_tag` now enforced; helper + api combination
  rejected at startup.
- Trial button shown to `PENDING_USER` with no active `access_request` (was
  hidden incorrectly).
- Trial-reset button missing from admin panel; rejected trials could not be
  retried — both corrected.
- `allow_pending_owner` flag not forwarded to the third `_ensure_can_create` call
  in the Xray and AWG adapters.
- Blocked users were unable to submit trial access requests.
- MTProxy helper: bot now waits for the proxy port to become reachable after a
  restart before running the post-apply verification.
- `vpnbot-socks5-user` helper: added `status` subcommand and corresponding
  sudoers grant (required by health-check script).

### Security
- `cryptography` bumped to **46.0.7** (fixes PYSEC-2026-35 / CVE-2026-26007).

## [0.1.0] — 2026-05-13

Initial tracked development state. Covers all features described in `README.md`
at time of first changelog entry.

### Added
- Telegram bot with user registration and access approval flow (pending →
  approved/blocked).
- Role-based access control: `SUPERADMIN`, `APPROVED_USER`, `PENDING_USER`,
  `BLOCKED_USER`.
- **Xray VLESS Reality** key management: create, config delivery (VLESS link +
  JSON), revoke, delete, startup reconciliation, traffic stats via Xray stats API.
- **AmneziaWG** key management: create, client config delivery (INI format),
  revoke, delete, IPAM, preshared key support, startup reconciliation.
- **SOCKS5/Dante** proxy access: per-user Linux account creation via
  `vpnbot-socks5-user` sudo helper, issue/revoke/delete lifecycle.
- **MTProto** proxy access: `static` mode (shared secret) and `managed` mode
  (per-user secrets, atomic apply, backup/rollback via `vpnbot-mtproxy-apply`
  sudo helper).
- Admin panel: pending requests, user management, key issuance, audit log,
  traffic stats, backend diagnostics, announcements.
- Backend degraded mode: per-backend health tracking; DEGRADED blocks mutations
  for that backend only.
- Audit log with recursive secret masking.
- SQLite storage with schema bootstrap and migrations (`db/schema.sql`, 8 tables).
- Rotating file logs via `LOG_DIR`.
- Non-root systemd deployment (`deploy/vpn-bot.service`) with four fixed sudo
  helpers and restricted sudoers grants.
- Pre/post-deploy healthcheck script (`deploy/check-nonroot-helper-mode.py`)
  with human-readable and JSON output modes.
- Single-instance lock (`utils/single_instance.py`).
- Optional HTTP health endpoint (`adapters/health_server.py`).
- CI pipeline: ruff, compileall, mypy, pytest (≥ 60% coverage), pip_audit.
- Dependabot for pip and GitHub Actions.
- Regression and hardening test suite (~14 500 lines across 31 test files).

### Security
- Privilege separation: all root operations go through four fixed-path sudo
  entrypoints; the bot process runs as `vpn-bot:vpn-bot`.
- `SOCKS5_LOGIN_PREFIX` enforcement prevents the bot from managing arbitrary
  Linux users.
- Secret redaction in all audit records, error messages, and log output.
- Config writes are atomic: staged file → validate → swap, with backup and
  automatic rollback on apply failure.
- Managed MTProto secrets and env files are `root:root 0600`; backup dirs are
  `root:root 0700`.

[Unreleased]: https://github.com/Egor051/vpnbot/compare/main...HEAD
[0.1.0]: https://github.com/Egor051/vpnbot/releases/tag/v0.1.0
