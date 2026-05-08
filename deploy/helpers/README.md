# Package 5B Helper Contracts

This directory is documentation-only in Package 5A. No helper here is wired into the Python adapters or production service unit yet.

Future helpers should be installed as root-owned files under `/usr/local/sbin`, not executed from the writable application checkout. The `vpn-bot` user should reach them only through a narrow sudoers file.

## Common requirements

- Root-owned and not writable by `vpn-bot`.
- Fixed canonical paths for backend config files.
- No arbitrary command execution.
- No `shell=True` wrappers.
- Strict argument validation before any privileged operation.
- Secrets redacted from stdout, stderr, logs, and exceptions.
- Non-zero exit codes for rejected input or failed backend apply.

## SOCKS5 helper

Interface:

- `vpnbot-socks5-user exists <login>`
- `vpnbot-socks5-user create <login>`
- `vpnbot-socks5-user set-password <login>` with the password read from stdin
- `vpnbot-socks5-user lock <login>`
- `vpnbot-socks5-user delete <login>`

Rules:

- Enforce the configured login prefix such as `vpn_socks_`.
- Enforce a strict login regex before touching account state.
- Use a fixed safe shell such as `/usr/sbin/nologin`.
- Never accept a shell path, UID, group, home directory, or arbitrary username from bot-supplied args.
- Never print passwords.

## Xray helper

Interface candidate:

- `vpnbot-xray-apply --candidate <path>`
- `vpnbot-xray-apply --stdin`

Rules:

- Candidate path must be inside a restricted staging directory if a path is used.
- Validate JSON and run Xray config validation before install.
- Atomically install `/usr/local/etc/xray/config.json`.
- Preserve owner/mode expected by the Xray service.
- Apply by the selected reload or restart policy.
- Verify active state after apply.
- Own rollback or explicitly document the adapter/helper rollback split before cutover.

## AWG helper

Interface candidate:

- `vpnbot-awg-apply --candidate <path>`
- `vpnbot-awg-apply --stdin`
- `vpnbot-awg-apply --status`

Rules:

- Candidate path must be inside a restricted staging directory if a path is used.
- Validate with the configured quick-strip tool before install.
- Atomically install `/etc/amnezia/amneziawg/awg0.conf`.
- Preserve private key permissions.
- Apply runtime using the Package 5B selected policy.
- Return only sanitized status or transfer output for read-only queries.

## MTProto helper

Interface candidate:

- `vpnbot-mtproxy-apply --candidate-dir <path>`
- `vpnbot-mtproxy-apply --stdin`
- `vpnbot-mtproxy-apply --status`

Rules:

- Package 5B must decide whether `/etc/mtproxy/vpnbot` remains root-owned helper territory or becomes narrowly owned by `vpn-bot`.
- Atomically install managed secrets and env files with private modes.
- Use a fixed MTProxy service and port check policy.
- Never print raw MTProto secrets or generated links.
