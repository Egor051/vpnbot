# Privilege Separation Architecture

Status: The privilege-separation helper architecture is implemented and shipped. Two deployment modes are supported:

- **root+api mode (shipped default).** `deploy/vpn-bot.service` runs as `User=root` with `ProtectSystem=false`; backend changes go through the Xray API and direct service control, and `PRIVILEGE_HELPERS_ENABLED` defaults to `false`. The sudo helpers are not used in this mode.
- **non-root helper mode (hardened opt-in).** The bot runs as `User=vpn-bot`/`Group=vpn-bot` from `deploy/vpn-bot.nonroot.example.service`, and every privileged backend mutation is isolated behind fixed sudo helper entrypoints. This is the model the rest of this document and `deploy/check-nonroot-helper-mode.py` describe and validate.

## Non-root Helper Mode

- Install `deploy/vpn-bot.nonroot.example.service` as the active unit. The shipped `deploy/vpn-bot.service` runs root+api and is intentionally **not** non-root; it would not pass the non-root preflight.
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
  - `/etc/mtproxy/vpn-bot`
  - `/etc/passwd`, `/etc/shadow`, `/etc/group`, `/etc/gshadow`, and `/etc/.pwd.lock`

The core backend privileged entrypoints allowed through `/etc/sudoers.d/vpn-bot` are:

- `/usr/local/sbin/vpn-bot-socks5-user`
- `/usr/local/sbin/vpn-bot-xray-apply`
- `/usr/local/sbin/vpn-bot-awg-apply`
- `/usr/local/sbin/vpn-bot-mtproxy-apply`

When the optional WARP outbound-IP masking module is enabled, the same sudoers file
additionally grants its fixed helper entrypoints — `vpn-bot-warp-install`,
`vpn-bot-warp-iface`, `vpn-bot-warp-routes`, `vpn-bot-warp-status`, and the
split-routing helpers `vpn-bot-warp-split-apply` / `vpn-bot-warp-split-state` (see
[`../warp.md`](../warp.md) and `deploy/sudoers.d/vpn-bot.example`). They obey the same
boundary as the backend helpers: fixed paths, per-verb pinning (no wildcard on the
split verbs), and helper-side argv validation. The authoritative grant list is
`deploy/sudoers.d/vpn-bot.example`, and `deploy/check-nonroot-helper-mode.py`
validates both the core and the WARP helper sets.

Validate live hosts before and after service restarts:

```bash
python deploy/check-nonroot-helper-mode.py
visudo -cf /etc/sudoers.d/vpn-bot
```

## Why NoNewPrivileges Is Not Enabled

`NoNewPrivileges=true` blocks privilege gain through setuid binaries. The helper architecture intentionally uses `sudo -n` from the unprivileged Python process to reach a narrow set of root-owned helper entrypoints. Enabling `NoNewPrivileges` would prevent sudo from performing that transition and would break Xray, AWG, SOCKS5, and managed MTProxy applies.

The security boundary is therefore:

- the bot process remains non-root;
- sudoers grants only fixed helper commands, never `NOPASSWD: ALL`;
- helper files are `root:root` `0755`;
- `/etc/sudoers.d/vpn-bot` is `root:root` `0440`;
- helpers validate argv, staged paths, prefixes, file shape, and backend targets before mutating root-owned state.

## Privileged Operation Inventory

| Component | Production behavior | Root-only boundary | Telegram-facing bot direct access |
| --- | --- | --- | --- |
| vpn-bot systemd runtime | In non-root helper mode runs as `vpn-bot:vpn-bot` from `deploy/vpn-bot.nonroot.example.service`; `ProtectSystem=strict`; `ReadWritePaths=/opt/vpn-service/data /opt/vpn-service/logs /run/vpn-bot`. | Unit install, code install, `.env`, and service management remain operator/root work. | No root runtime. |
| SQLite data directory | `DB_PATH` defaults to `/opt/vpn-service/data/vpn.db`; DB/WAL/SHM files are bot runtime state. | No sudoers needed. | Yes, direct read/write to SQLite is expected. |
| `.env` handling | systemd reads `EnvironmentFile=/opt/vpn-service/.env`; file must not be writable by `vpn-bot`. | Root/operator owns production secrets and restart-time config. | Environment is inherited; no direct write. |
| Logs and lock paths | `LOG_DIR=/opt/vpn-service/logs`; `BOT_LOCK_PATH=/run/vpn-bot/vpn-bot.lock`; `RuntimeDirectory=vpn-bot`. | No sudoers needed. | Yes, direct write to narrow runtime paths. |
| Xray config apply | Bot stages a candidate under `/run/vpn-bot/xray`; helper validates JSON and Xray syntax, installs canonical config atomically, restarts fixed service `xray`, verifies active state, and rolls back on failure. | `/usr/local/sbin/vpn-bot-xray-apply` via sudoers. | No direct write to canonical Xray config or generic service control. |
| AWG config/runtime apply | Bot stages a candidate under `/run/vpn-bot/awg`; helper validates with `awg-quick strip` or compatible tooling, installs `/etc/amnezia/amneziawg/awg0.conf`, applies fixed-interface runtime sync, and verifies `awg-quick@awg0`. | `/usr/local/sbin/vpn-bot-awg-apply` via sudoers. | No direct write to canonical AWG config or generic network mutation. |
| AWG status/traffic reads | Helper returns sanitized status, peer, and transfer data for fixed interface `awg0`. | `/usr/local/sbin/vpn-bot-awg-apply status`, `show-peers`, and `show-transfer`. | No raw AWG/WG command grant in sudoers. |
| SOCKS5 Linux user lifecycle | Helper manages only logins with the configured login prefix such as `vpn_socks_`; password remains stdin-only. | `/usr/local/sbin/vpn-bot-socks5-user` actions `exists`, `create`, `set-password`, `lock`, and `delete`. | No direct account database write or raw `useradd`/`chpasswd`/`passwd`/`userdel` grant. |
| Dante service state | Bot assumes Dante is installed and listening; it does not restart Dante. | Service lifecycle remains operator/root work unless a future fixed helper is added. | No service mutation. |
| MTProxy managed files/apply | Bot stages `managed-secrets.json` and `mtproxy.env` under `/run/vpn-bot/mtproxy`; helper validates shape without printing secrets, installs `/etc/mtproxy/vpn-bot` files atomically, restarts fixed service `mtproxy`, verifies service/port, and rolls back on failure. | `/usr/local/sbin/vpn-bot-mtproxy-apply` via sudoers. | No direct `/etc/mtproxy` write or generic service control. |
| Backend backups | Helpers create and retain backups for canonical Xray/AWG/MTProxy files with private modes. | Helper-owned root paths. | No direct backend backup write. |
| Deployment scripts and ownership | Deploy and updates are root/operator work. Recursive ownership changes must not make code or `.venv` writable by `vpn-bot`. | `deploy/create-vpn-bot-user.sh`, helper install, sudoers install, and unit install. | No deploy-time write access to code or unit files. |

## Helper Contracts

### SOCKS5 helper

Path: `/usr/local/sbin/vpn-bot-socks5-user`.

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

Path: `/usr/local/sbin/vpn-bot-xray-apply`.

Required properties:

- Accepts candidates only from `/run/vpn-bot/xray`.
- Validates JSON before invoking Xray.
- Runs `xray run -test -config <candidate>` against the candidate.
- Atomically installs to `/usr/local/etc/xray/config.json`.
- Applies by fixed restart of service `xray`.
- Verifies Xray is active after apply.
- Implements rollback inside the helper because it owns canonical config installation and service apply.

### AWG helper

Path: `/usr/local/sbin/vpn-bot-awg-apply`.

Required properties:

- Accepts candidates only from `/run/vpn-bot/awg`.
- Validates with `awg-quick strip` or the configured compatible tool.
- Atomically installs `/etc/amnezia/amneziawg/awg0.conf`.
- Installs as `root:vpn-bot` mode `0640` (world-unreadable; group-readable so the bot can read status). Note: this makes the server WireGuard `PrivateKey` readable by the `vpn-bot` group — an accepted trade-off for non-root status reads; keep the bot process and group membership tightly scoped.
- Applies runtime with fixed-interface `syncconf` for `awg0`, consistent with the existing adapter design that avoids a full tunnel restart.
- Verifies `awg-quick@awg0` is active.
- Provides sanitized read-only status/peer/transfer output for the fixed interface.

### MTProxy helper

Path: `/usr/local/sbin/vpn-bot-mtproxy-apply`.

Required properties:

- Accepts candidates only from `/run/vpn-bot/mtproxy`.
- Installs managed secret and env files atomically as `root:vpn-bot` mode `0640` in a `0750` `root:vpn-bot` directory (world-unreadable; group-readable for non-root reads).
- Restarts `mtproxy` using a fixed service name.
- Verifies service active state and listening port.
- Never prints raw MTProto secrets or generated links.
- Redacts secrets in errors, logs, and rollback summaries.

## Sudoers Boundary

`/etc/sudoers.d/vpn-bot` must grant only the helper aliases from `deploy/sudoers.d/vpn-bot.example`. It must not contain `NOPASSWD: ALL`, `ALL=(ALL) ALL`, raw `systemctl`, raw Linux account tools, copy/install tools, raw `xray`, raw `awg`/`wg`, or raw MTProxy binaries.

Wildcard arguments in sudoers are acceptable only because they are attached to fixed helper entrypoints and the helpers independently validate staging roots, symlinks, action names, and backend identifiers.

## Deployment State

The privilege-separation rollout is complete:

1. Helpers are implemented and installed as fixed root-owned entrypoints.
2. `deploy/vpn-bot.service` is the shipped root+api unit; `deploy/vpn-bot.nonroot.example.service` is the non-root helper-mode unit to install when opting into that model.
3. `deploy/vpn-bot.root-legacy.example.service` is retained only as an emergency root/direct fallback.
4. Helper mode is opt-in via `PRIVILEGE_HELPERS_ENABLED=true` (default `false`).
5. `deploy/check-nonroot-helper-mode.py` is the mandatory preflight and postflight host check for the non-root helper mode.

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
