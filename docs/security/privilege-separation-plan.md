# Package 5 Privilege Separation Plan

Status: Package 5D completed and promoted to production. The live production model is a non-root `vpn-bot.service` running as `User=vpn-bot` and `Group=vpn-bot`, with privileged backend mutation isolated behind fixed sudo helper entrypoints.

## Live Production Model

- `deploy/vpn-bot.service` is the production non-root unit, not a placeholder.
- `PRIVILEGE_HELPERS_ENABLED=true`.
- `BOT_LOCK_PATH=/run/vpn-bot/vpn-bot.lock`.
- systemd creates `/run/vpn-bot` with `RuntimeDirectory=vpn-bot` and `RuntimeDirectoryMode=0700`.
- Code, deploy files, `.env`, service units, and `.venv` are not writable by `vpn-bot`.
- `vpn-bot` writes only runtime state:
  - `/opt/vpn-service/data`
  - `/opt/vpn-service/logs` if file logs remain enabled
  - `/run/vpn-bot` helper staging and lock files
- Canonical backend state remains root-owned:
  - `/usr/local/etc/xray/config.json`
  - `/etc/amnezia/amneziawg/awg0.conf`
  - `/etc/mtproxy/vpnbot`
  - `/etc/passwd`, `/etc/shadow`, `/etc/group`, `/etc/gshadow`, and `/etc/.pwd.lock`

The only privileged entrypoints allowed through `/etc/sudoers.d/vpnbot` are:

- `/usr/local/sbin/vpnbot-socks5-user`
- `/usr/local/sbin/vpnbot-xray-apply`
- `/usr/local/sbin/vpnbot-awg-apply`
- `/usr/local/sbin/vpnbot-mtproxy-apply`

Validate live hosts before and after service restarts:

```bash
python deploy/check-nonroot-helper-mode.py
visudo -cf /etc/sudoers.d/vpnbot
```

## Why NoNewPrivileges Is Not Enabled

`NoNewPrivileges=true` blocks privilege gain through setuid binaries. The helper architecture intentionally uses `sudo -n` from the unprivileged Python process to reach a narrow set of root-owned helper entrypoints. Enabling `NoNewPrivileges` would prevent sudo from performing that transition and would break Xray, AWG, SOCKS5, and managed MTProxy applies.

The security boundary is therefore:

- the bot process remains non-root;
- sudoers grants only fixed helper commands, never `NOPASSWD: ALL`;
- helper files are `root:root` `0755`;
- `/etc/sudoers.d/vpnbot` is `root:root` `0440`;
- helpers validate argv, staged paths, prefixes, file shape, and backend targets before mutating root-owned state.

## Privileged Operation Inventory

| Component | Production behavior | Root-only boundary | Telegram-facing bot direct access |
| --- | --- | --- | --- |
| vpn-bot systemd runtime | Runs as `vpn-bot:vpn-bot` from `deploy/vpn-bot.service`; `ProtectSystem=strict`; `ReadWritePaths=/opt/vpn-service/data /opt/vpn-service/logs /run/vpn-bot`. | Unit install, code install, `.env`, and service management remain operator/root work. | No root runtime. |
| SQLite data directory | `DB_PATH` defaults to `/opt/vpn-service/data/vpn.db`; DB/WAL/SHM files are bot runtime state. | No sudoers needed. | Yes, direct read/write to SQLite is expected. |
| `.env` handling | systemd reads `EnvironmentFile=/opt/vpn-service/.env`; file must not be writable by `vpn-bot`. | Root/operator owns production secrets and restart-time config. | Environment is inherited; no direct write. |
| Logs and lock paths | `LOG_DIR=/opt/vpn-service/logs`; `BOT_LOCK_PATH=/run/vpn-bot/vpn-bot.lock`; `RuntimeDirectory=vpn-bot`. | No sudoers needed. | Yes, direct write to narrow runtime paths. |
| Xray config apply | Bot stages a candidate under `/run/vpn-bot/xray`; helper validates JSON and Xray syntax, installs canonical config atomically, restarts fixed service `xray`, verifies active state, and rolls back on failure. | `/usr/local/sbin/vpnbot-xray-apply` via sudoers. | No direct write to canonical Xray config or generic service control. |
| AWG config/runtime apply | Bot stages a candidate under `/run/vpn-bot/awg`; helper validates with `awg-quick strip` or compatible tooling, installs `/etc/amnezia/amneziawg/awg0.conf`, applies fixed-interface runtime sync, and verifies `awg-quick@awg0`. | `/usr/local/sbin/vpnbot-awg-apply` via sudoers. | No direct write to canonical AWG config or generic network mutation. |
| AWG status/traffic reads | Helper returns sanitized status, peer, and transfer data for fixed interface `awg0`. | `/usr/local/sbin/vpnbot-awg-apply status`, `show-peers`, and `show-transfer`. | No raw AWG/WG command grant in sudoers. |
| SOCKS5 Linux user lifecycle | Helper manages only logins with the configured login prefix such as `vpn_socks_`; password remains stdin-only. | `/usr/local/sbin/vpnbot-socks5-user` actions `exists`, `create`, `set-password`, `lock`, and `delete`. | No direct account database write or raw `useradd`/`chpasswd`/`passwd`/`userdel` grant. |
| Dante service state | Bot assumes Dante is installed and listening; it does not restart Dante. | Service lifecycle remains operator/root work unless a future fixed helper is added. | No service mutation. |
| MTProxy managed files/apply | Bot stages `managed-secrets.json` and `mtproxy.env` under `/run/vpn-bot/mtproxy`; helper validates shape without printing secrets, installs `/etc/mtproxy/vpnbot` files atomically, restarts fixed service `mtproxy`, verifies service/port, and rolls back on failure. | `/usr/local/sbin/vpnbot-mtproxy-apply` via sudoers. | No direct `/etc/mtproxy` write or generic service control. |
| Backend backups | Helpers create and retain backups for canonical Xray/AWG/MTProxy files with private modes. | Helper-owned root paths. | No direct backend backup write. |
| Deployment scripts and ownership | Deploy and updates are root/operator work. Recursive ownership changes must not make code or `.venv` writable by `vpn-bot`. | `deploy/create-vpn-bot-user.sh`, helper install, sudoers install, and unit install. | No deploy-time write access to code or unit files. |

## Helper Contracts

### SOCKS5 helper

Path: `/usr/local/sbin/vpnbot-socks5-user`.

Required properties:

- Root-owned and not writable by `vpn-bot`.
- Callable by `vpn-bot` only through sudoers.
- Allowed actions: `exists <login>`, `create <login>`, `set-password <login>` with the password read from stdin, `lock <login>`, and `delete <login>`.
- Enforces the configured login prefix, for example `vpn_socks_`.
- Enforces strict login regex compatible with Linux account naming, for example `^[A-Za-z_][A-Za-z0-9_]{0,31}$`.
- Never accepts arbitrary usernames.
- Never accepts shell paths from untrusted args. The login shell must be a fixed safe value such as `/usr/sbin/nologin`.
- Never prints passwords.
- Redacts secrets in errors and logs.

### Xray helper

Path: `/usr/local/sbin/vpnbot-xray-apply`.

Required properties:

- Accepts candidates only from `/run/vpn-bot/xray`.
- Validates JSON before invoking Xray.
- Runs `xray run -test -config <candidate>` against the candidate.
- Atomically installs to `/usr/local/etc/xray/config.json`.
- Applies by fixed restart of service `xray`.
- Verifies Xray is active after apply.
- Implements rollback inside the helper because it owns canonical config installation and service apply.

### AWG helper

Path: `/usr/local/sbin/vpnbot-awg-apply`.

Required properties:

- Accepts candidates only from `/run/vpn-bot/awg`.
- Validates with `awg-quick strip` or the configured compatible tool.
- Atomically installs `/etc/amnezia/amneziawg/awg0.conf`.
- Preserves private key permissions as `root:root` mode `0600`.
- Applies runtime with fixed-interface `syncconf` for `awg0`, consistent with the existing adapter design that avoids a full tunnel restart.
- Verifies `awg-quick@awg0` is active.
- Provides sanitized read-only status/peer/transfer output for the fixed interface.

### MTProxy helper

Path: `/usr/local/sbin/vpnbot-mtproxy-apply`.

Required properties:

- Accepts candidates only from `/run/vpn-bot/mtproxy`.
- Installs managed secret and env files atomically with mode `0600`.
- Restarts `mtproxy` using a fixed service name.
- Verifies service active state and listening port.
- Never prints raw MTProto secrets or generated links.
- Redacts secrets in errors, logs, and rollback summaries.

## Sudoers Boundary

`/etc/sudoers.d/vpnbot` must grant only the helper aliases from `deploy/sudoers.d/vpnbot.example`. It must not contain `NOPASSWD: ALL`, `ALL=(ALL) ALL`, raw `systemctl`, raw Linux account tools, copy/install tools, raw `xray`, raw `awg`/`wg`, or raw MTProxy binaries.

Wildcard arguments in sudoers are acceptable only because they are attached to fixed helper entrypoints and the helpers independently validate staging roots, symlinks, action names, and backend identifiers.

## Deployment State

Package 5D closes the earlier Package 5B/5C rollout plan:

1. Helpers are implemented and installed as fixed root-owned entrypoints.
2. `deploy/vpn-bot.service` is the production non-root unit.
3. `deploy/vpn-bot.nonroot.example.service` is retained only as a compatibility reference for old rollout notes and must stay aligned with production behavior.
4. Helper mode is production-on with `PRIVILEGE_HELPERS_ENABLED=true`.
5. `deploy/check-nonroot-helper-mode.py` is the mandatory preflight and postflight host check.

## Emergency Rollback Notes

Root-run mode is no longer the recommended production path. Use it only as an emergency rollback while restoring service availability or investigating helper-mode deployment breakage.

Rollback shape:

1. Stop `vpn-bot`.
2. Restore the backed-up pre-cutover systemd unit and matching `.env` from the live backup set.
3. Set `PRIVILEGE_HELPERS_ENABLED=false` only for the rollback unit.
4. Run `systemctl daemon-reload`.
5. Start `vpn-bot` and verify logs/backend state.
6. Re-enter the non-root helper-mode path as soon as the incident is fixed.

Do not widen sudoers as a rollback shortcut. Do not use `NOPASSWD: ALL`. Do not make `/opt/vpn-service`, deploy files, or `.venv` writable by `vpn-bot`.
