# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added
- `CONTRIBUTING.md` — development setup, code quality gates, commit format, branch
  naming, security considerations, and PR process.
- `CODE_OF_CONDUCT.md` — Contributor Covenant 2.1.
- `.github/ISSUE_TEMPLATE/config.yml` — disables blank issues; routes security
  reports to GitHub Security Advisories.

### Changed
- `README.md` CI section: corrected Python version matrix to 3.12 only (matches
  the workflow).
- `.github/ISSUE_TEMPLATE/bug_report.md`: added `triage` label; added
  "Relevant protocol/component" field to the Environment section.
- `.gitignore`: fixed UTF-16/CRLF encoding corruption on the last line; normalised
  all line endings to LF.

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
