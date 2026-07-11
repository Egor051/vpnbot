# Security Policy

## Supported Versions

Only the `main` branch is supported for security fixes and hardening updates.

## Sensitive Data

Do not publish secrets, live configuration, or operational data in public issues, pull requests, screenshots, logs, or examples.

Never disclose:

- Telegram bot tokens.
- `.env` files or copied `.env` values.
- Private keys or preshared keys.
- Xray Reality private/public key pairs if they belong to an active server.
- AmneziaWG private keys.
- Full VPN client configs.
- SQLite databases or database dumps.
- Server IP addresses together with SSH, panel, hosting, or other credentials.
- Admin IDs together with working bot tokens.

## Reporting a Vulnerability

If a vulnerability exposes secrets, live VPN configs, access control bypasses, database contents, or server credentials, do not open a public issue with details.

Use responsible disclosure:

1. Open a private report via [GitHub Security Advisories](https://github.com/Egor051/vpnbot/security/advisories/new), or contact the maintainer through another private channel known to you.
2. Share the minimal technical description needed to confirm the issue.
3. Redact tokens, keys, client configs, database rows, server IPs, and user identifiers.
4. Provide safe reproduction steps using placeholders or a local test setup.
5. Wait for confirmation before publishing details.

If no private channel is available, open a minimal public issue asking for a private security contact. Do not include exploit details, secrets, logs, or real configs in that issue.

### Response expectations

This is a small self-hosted project maintained on a best-effort basis. Expect an
initial acknowledgment within **7 days** and a triage/status update within
**30 days**. Issues that expose secrets, allow access-control bypass, or leak
database contents are prioritized over other reports. Please allow time for a fix
before any public disclosure.

## Scope

Security-sensitive areas include:

- Telegram authentication and admin checks.
- User ownership checks for VPN keys and stats.
- Access approval and user blocking flows.
- Xray config mutation and service reload.
- AmneziaWG config mutation and runtime peer changes.
- SQLite database migrations and storage.
- Audit logging and secret masking.
- systemd deployment permissions.
- Backup and rollback behavior for VPN configs.

## Operational Guidance

- Keep `.env`, SQLite databases, logs, backups, and generated VPN configs outside Git.
- Rotate any token or key that was committed, logged, shared, or pasted into an issue.
- Review logs before attaching them to reports.
- Prefer synthetic test configs when demonstrating bugs.
- Treat bot admins, server credentials, VPN configs, and database files as sensitive production data.
