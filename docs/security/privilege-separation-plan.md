# Package 5 Privilege Separation Plan

Status: Package 5C cutover preparation. Package 5C hardens the root-owned helper scripts, adds non-root setup and preflight tooling, documents the manual Ubuntu cutover, and keeps the repository's active production unit root-run until an operator deliberately switches the VDS.

Package 5B implemented helpers intended for `/usr/local/sbin`; Package 5C fixes their final non-root permission model:

- `/usr/local/sbin/vpnbot-socks5-user`
- `/usr/local/sbin/vpnbot-xray-apply`
- `/usr/local/sbin/vpnbot-awg-apply`
- `/usr/local/sbin/vpnbot-mtproxy-apply`

Default adapter behavior remains direct/root-compatible. Helper mode is controlled by `PRIVILEGE_HELPERS_ENABLED=false` by default plus fixed helper path and staging settings:

- `HELPER_STAGING_ROOT=/run/vpn-bot`
- `SOCKS5_USER_HELPER_PATH=/usr/local/sbin/vpnbot-socks5-user`
- `XRAY_APPLY_HELPER_PATH=/usr/local/sbin/vpnbot-xray-apply`
- `AWG_APPLY_HELPER_PATH=/usr/local/sbin/vpnbot-awg-apply`
- `MTPROTO_APPLY_HELPER_PATH=/usr/local/sbin/vpnbot-mtproxy-apply`
- `XRAY_HELPER_STAGING_DIR=/run/vpn-bot/xray`
- `AWG_HELPER_STAGING_DIR=/run/vpn-bot/awg`
- `MTPROTO_HELPER_STAGING_DIR=/run/vpn-bot/mtproxy`

Validate the sudoers example before any installation:

```bash
visudo -cf /path/to/vpnbot.example
```

The active production unit remains root-run for rollback compatibility. The sudo-helper non-root unit in `deploy/vpn-bot.nonroot.example.service` intentionally does not set `NoNewPrivileges=true`, because sudo helpers require privilege elevation through the sudo/setuid boundary. Use `NoNewPrivileges=true` only in a future non-sudo privileged-daemon or IPC design.

## Goals

- Inventory every privileged operation currently performed by the Telegram-facing Python process.
- Define the target Package 5B/5C privilege boundary before any runtime cutover.
- Keep code, virtualenv, deployment units, and backend configuration under root control.
- Allow the future `vpn-bot` service account to write only bot runtime state.
- Move root-only backend mutations behind fixed, root-owned helpers or equally constrained sudoers boundaries.

## Target Model

- The Telegram-facing process will run as `User=vpn-bot` and `Group=vpn-bot`.
- `/opt/vpn-service` and `.venv` stay root-owned and are not writable by `vpn-bot`.
- Runtime-writable paths are narrow:
  - `/opt/vpn-service/data`
  - `/opt/vpn-service/logs` if file logs remain enabled
  - `/run/vpn-bot` or another dedicated runtime lock directory
  - MTProto staged files under `/run/vpn-bot/mtproxy`; canonical `/etc/mtproxy/vpnbot` stays root-owned helper territory.
- The bot must not directly write:
  - `/etc/passwd`
  - `/etc/shadow`
  - `/etc/group`
  - `/etc/gshadow`
  - `/etc/.pwd.lock`
  - `/usr/local/etc/xray/config.json`
  - `/etc/amnezia/amneziawg/awg0.conf`
- Privileged backend mutation should go through fixed helpers installed under `/usr/local/sbin` and callable by `vpn-bot` only through a narrow sudoers file.

## Privileged Operation Inventory

| Component | Current operation | Current command or file path | Current privilege requirement | Current risk | Target Package 5B/5C design | Proposed helper or sudoers boundary | Must stay root-only | Telegram-facing bot direct access |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| vpn-bot systemd runtime | Runs the Telegram bot and all adapters as root. | `deploy/vpn-bot.service`; `User=root`; `Group=root`; `ReadWritePaths=/opt/vpn-service /run /usr/local/etc/xray /etc/amnezia/amneziawg /etc/mtproxy/vpnbot /etc/passwd /etc/shadow /etc/group /etc/gshadow /etc/.pwd.lock` | Root for Linux account mutation, backend config writes, and service control. | Bot token compromise, handler bug, dependency RCE, or local code execution can mutate system accounts and backend configs. | Repository active unit remains root for rollback. The cutover unit runs as `vpn-bot` with strict filesystem sandboxing and sudo helpers for root-only changes. | `deploy/vpn-bot.nonroot.example.service` plus helper-only sudoers. | No for the Python process; yes for helper operations. | No direct privileged backend access after cutover. |
| SQLite data directory | Creates and writes the SQLite DB, WAL, and SHM files. | `DB_PATH`, default `/opt/vpn-service/data/vpn.db`; `db/database.py` creates parent and chmods files. | Write access to the data directory only. | If the bot remains root, DB compromise also runs with unnecessary root filesystem reach. | Own `/opt/vpn-service/data` by `vpn-bot:vpn-bot`, mode `0700`; keep DB files mode `0600`. | No sudoers needed. | No. | Yes, direct read/write to SQLite is expected. |
| .env handling | systemd loads environment variables with bot token and backend settings. | `EnvironmentFile=/opt/vpn-service/.env`; loaded by systemd before Python starts. | Read access by systemd and effective service context; file should not be writable by `vpn-bot`. | Write access to `.env` would let a compromised bot change runtime settings or secrets for the next restart. | Keep `.env` root-owned. Make it readable to `vpn-bot` only if systemd/environment setup requires it; otherwise systemd reads it before dropping privileges. | No sudoers needed. Consider `LoadCredential` only if a later package chooses that migration. | File ownership and writes should remain root-only. | Read via inherited environment only; no direct write. |
| Logs and runtime lock paths | Creates file logs and a single-instance lock. | `LOG_DIR`, default `/opt/vpn-service/logs`; `BOT_LOCK_PATH`, default `/run/vpn-bot.lock`; `utils/logging.py`; `utils/single_instance.py` | Write access to log and lock locations. | Root-owned log writes and broad `/run` write access increase damage from a compromised process. | Use `/opt/vpn-service/logs` and `/run/vpn-bot/vpn-bot.lock` owned by `vpn-bot:vpn-bot`; systemd `RuntimeDirectory=vpn-bot`. | No sudoers needed. | No. | Yes, direct write to these narrow paths. |
| Xray config read/write/test/apply | Reads JSON config, writes temp candidate in the Xray config dir, creates backup, atomically replaces config, then applies. | `/usr/local/etc/xray/config.json`; temp files and `*.bak` beside it; `xray run -test -config <path>` | Read/write on Xray config directory; often root-owned; ability to run Xray validation. | Compromised bot can rewrite Xray inbounds, keys, and routing, or remove service access. | Bot stages desired config under a bot-owned staging directory or passes stdin to helper. Helper validates JSON and Xray syntax, installs atomically, preserves owner/mode, applies, verifies active, and handles rollback policy. | `/usr/local/sbin/vpnbot-xray-apply` via sudoers. | Yes for installing canonical config and applying service. | No direct write to canonical Xray config. Direct read only if needed and safe, otherwise helper supplies sanitized reads. |
| Xray service restart/reload/is-active | Applies Xray changes and verifies service health. | `systemctl reload xray`; `systemctl restart xray`; `systemctl is-active xray`; `adapters/systemctl.py` | Root or service-manager privilege for reload/restart. | Unrestricted service control could stop or alter unrelated services if exposed broadly. | Helper owns the fixed Xray apply policy and calls only the configured Xray service. | Same `/usr/local/sbin/vpnbot-xray-apply`; no direct generic service-manager command in sudoers. | Yes for restart/reload. | No. |
| AWG config read/write/apply | Reads and modifies AmneziaWG config, creates backups, validates candidate, and synchronizes runtime. | `/etc/amnezia/amneziawg/awg0.conf`; temp files beside config; `awg-quick strip`; `wg-quick strip`; `awg syncconf`; `wg syncconf`; `awg set`; `wg set` | Root/CAP_NET_ADMIN and config file ownership. | Compromised bot can expose private keys, add arbitrary peers, or break tunnel runtime. | Bot stages candidate under a bot-owned staging directory or passes stdin. Helper validates, installs atomically, preserves private key permissions, and applies runtime using the chosen AWG policy. | `/usr/local/sbin/vpnbot-awg-apply` via sudoers. | Yes for canonical config install and runtime mutation. | No direct write to canonical AWG config. |
| AWG runtime inspection | Checks interface state, peers, and transfer counters. | `awg show awg0`; `wg show awg0`; `awg show awg0 transfer`; `wg show awg0 transfer` | May require root or CAP_NET_ADMIN depending host policy. | Direct runtime tool access gives a compromised bot kernel networking visibility and potentially becomes mutation if command surface broadens. | Split read-only status from mutation if needed, or implement a helper action that returns sanitized peer/transfer data for the fixed interface. | `/usr/local/sbin/vpnbot-awg-apply status` or a future `/usr/local/sbin/vpnbot-awg-status`; sudoers should not grant the raw tools. | Host dependent; treat as root-only until proven otherwise. | Prefer no direct access after cutover. |
| AWG service restart/is-active | Production currently uses runtime sync/set operations and expects `awg-quick@awg0` active. Admin diagnostics expect AWG OK from adapter health state, not direct generic service control. | Service name `awg-quick@awg0`; current adapter does not call service control for AWG restart. | Root if a future restart policy is used. | Broad service control could disrupt unrelated services or tunnel state. | If restart becomes the apply policy, encapsulate fixed service restart and active check in the AWG helper. | `/usr/local/sbin/vpnbot-awg-apply` with a fixed interface/service. | Yes if restart policy is used. | No. |
| SOCKS5 Linux user exists/create/set-password/lock/delete | Manages one Linux user per SOCKS5 access. | `getent passwd <login>`; `useradd -r -s <shell> <login>`; `chpasswd` via stdin; `passwd -l <login>`; `userdel <login>` | Root for account database writes. | Current unit has write access to account databases; a bot compromise could create, alter, or delete system accounts if validation is bypassed. | Replace direct account commands with a root-owned helper enforcing configured prefix and strict login validation. Password remains stdin-only. | `/usr/local/sbin/vpnbot-socks5-user` via sudoers actions: `exists`, `create`, `set-password`, `lock`, `delete`. | Yes for create, password set, lock, delete. `exists` can be helper-mediated for a uniform boundary. | No direct account database or account tool access. |
| Dante service state | Bot stores and displays Dante service name and assumes the daemon is preinstalled/listening. It does not currently restart Dante. | `SOCKS5_SERVICE_NAME=danted`; runtime details in `services/proxy.py` and formatters. | None today for service control. | If generic service control is later added, it could broaden root reach. | Keep service installation and daemon lifecycle outside the bot, or add a fixed helper action for a narrow health check only. | No Package 5A sudoers command. Future helper only if diagnostics require it. | Restart remains root-only if ever added. | No service mutation. |
| MTProto managed secrets/env files | Writes managed secret store, env file, backups, and runtime wrapper inputs. | `/etc/mtproxy/vpnbot/managed-secrets.json`; `/etc/mtproxy/vpnbot/mtproxy.env`; `/etc/mtproxy/vpnbot/backups`; `deploy/run-mtproxy-managed` | Currently root because the bot runs as root and files are under `/etc`. | Compromised bot can add/remove MTProto secrets, expose proxy secrets, or poison wrapper environment. | Package 5C uses a helper that installs files after validation while preserving `vpn-bot` read access to managed state. | `/usr/local/sbin/vpnbot-mtproxy-apply` via sudoers. | Restart and canonical install under `/etc` stay root-only. | No direct `/etc` write; read-only managed state access is required for read-before-stage. |
| MTProxy service restart/is-active/port check | Restarts mtproxy, checks active state, and verifies listening port. | `systemctl restart mtproxy`; `systemctl is-active mtproxy`; `ss -tlnp` | Root/service-manager privilege for restart; port check may be unprivileged but can expose process info. | Broad restart permission could affect services; raw output could leak process details. | Helper runs a fixed restart and health check for the configured MTProxy service and port, redacting secrets. | `/usr/local/sbin/vpnbot-mtproxy-apply` via sudoers. | Restart is root-only. Port check can be helper-mediated. | No generic service control. |
| Backups created by adapters | Creates config backups beside sensitive config files or under MTProto backup root. | Xray `config.json.*.bak`; AWG `awg0.conf.*.bak`; MTProto `/etc/mtproxy/vpnbot/backups` | Same privilege as canonical config directory. | Backup files may contain private keys or secrets and can accumulate in sensitive directories. | Helper owns backup creation for canonical configs and restores final files with the same root-owned, group-readable canonical permission model. Bot-owned SQLite/log backups, if any, remain under bot data/log paths. | Xray/AWG/MTProto helpers create and clean their own backups. | Yes for backend config backups. | No direct access to backend backup dirs unless helper returns sanitized status. |
| Deployment scripts and ownership model | Deploy currently installs root-run service and MTProxy wrapper/drop-in assets. | `deploy/vpn-bot.service`; `deploy/run-mtproxy-managed`; `deploy/mtproxy-vpnbot-managed.conf`; `/opt/vpn-service` | Root for install, ownership, unit reloads, and service restarts. | Recursive ownership changes could make code writable by the bot or accidentally expose secrets. | Keep deploy as root/admin work. Add idempotent user creation and documented future ownership steps. Do not recursively chown `/opt/vpn-service` to `vpn-bot`. | `deploy/create-vpn-bot-user.sh`; `deploy/sudoers.d/vpnbot.example`; future helper install docs. | Install and unit management remain root-only. | No deploy-time write access to code or unit files. |

## Package 5C Helper Interfaces

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

- Accepts a candidate config from `/run/vpn-bot/xray`.
- Validates JSON before invoking Xray.
- Runs `xray run -test -config <candidate>` against the candidate.
- Atomically installs to `/usr/local/etc/xray/config.json`.
- Installs as owner `nobody`, group `vpn-bot`, mode `0640`, so Xray keeps owner read access and the non-root bot keeps read-only access for read-before-stage adapter operations.
- Applies by fixed restart of service `xray`.
- Verifies Xray is active after apply.
- Implements rollback inside the helper because it owns canonical config installation and service apply.

### AWG helper

Path: `/usr/local/sbin/vpnbot-awg-apply`.

Required properties:

- Accepts a candidate `awg0.conf` from `/run/vpn-bot/awg`.
- Validates with `awg-quick strip` or the configured compatible tool.
- Atomically installs `/etc/amnezia/amneziawg/awg0.conf`.
- Preserves private key write protection as `root:vpn-bot` mode `0640`, so the bot can read the canonical config but cannot write it directly.
- Applies runtime with fixed-interface `syncconf` for `awg0`, consistent with the existing adapter design that avoids a full tunnel restart.
- Verifies `awg-quick@awg0` is active.
- Provides sanitized read-only status/peer/transfer output for the fixed interface.

### MTProto helper

Path: `/usr/local/sbin/vpnbot-mtproxy-apply`.

Required properties:

- Package 5C uses the helper model; `/etc/mtproxy/vpnbot` remains root-owned helper territory.
- Installs `/etc/mtproxy/vpnbot` as `root:vpn-bot` mode `0750` and managed secret/env files atomically as `root:vpn-bot` mode `0640`.
- Restarts `mtproxy` using a fixed service name.
- Verifies service active state and listening port.
- Never prints raw MTProto secrets or generated links.
- Redacts secrets in errors, logs, and rollback summaries.

## Deploy And Ownership Plan

Package 5A added scaffolding only:

- `deploy/create-vpn-bot-user.sh` creates the future system user and group without switching the service.
- `deploy/vpn-bot.nonroot.example.service` shows the future non-root unit and narrow writable paths.
- `deploy/sudoers.d/vpnbot.example` shows a conservative helper-only sudoers boundary.
- `deploy/helpers/README.md` specified helper contracts before implementation.

Package 5B added implemented helpers and helper-mode adapter wiring, but left the active unit unchanged. Package 5C prepares the cutover path but still leaves the VDS switch as a manual operator action:

1. Install root-owned helpers under `/usr/local/sbin`, mode `0750` or stricter.
2. Validate helpers with unit tests and VDS preflight.
3. Validate sudoers with `visudo -cf /path/to/vpnbot.example`, then install sudoers only for the cutover.
4. Prepare `/opt/vpn-service/data`, `/opt/vpn-service/logs`, and `/run/vpn-bot` for `vpn-bot` writes.
5. Keep `/opt/vpn-service`, `.venv`, deploy files, and service units root-owned and not writable by `vpn-bot`.
6. Preserve `vpn-bot` read access to canonical config/state files that adapters read before staging: Xray config, AWG config, MTProxy managed files.
7. Enable `PRIVILEGE_HELPERS_ENABLED=true` and run staged issue/revoke tests for Xray, AWG, SOCKS5, and managed MTProto.
8. Switch to the non-root unit only after `deploy/check-nonroot-helper-mode.py` passes.

## Package 5C Ubuntu Runbook

Preflight backup commands before changing the VDS:

```bash
set -euo pipefail
sudo install -d -o root -g root -m 0700 /root/vpnbot-package5c-backup
sudo cp -a /opt/vpn-service/.env /root/vpnbot-package5c-backup/env.backup
sudo cp -a /etc/systemd/system/vpn-bot.service /root/vpnbot-package5c-backup/vpn-bot.service.backup
sudo cp -a /usr/local/etc/xray/config.json /root/vpnbot-package5c-backup/xray-config.json.backup
sudo cp -a /etc/amnezia/amneziawg/awg0.conf /root/vpnbot-package5c-backup/awg0.conf.backup
sudo tar -C /etc/mtproxy -czf /root/vpnbot-package5c-backup/mtproxy-vpnbot.tgz vpnbot
sudo sqlite3 /opt/vpn-service/data/vpn.db ".backup '/root/vpnbot-package5c-backup/vpn.db.backup'"
```

Install identity, helpers, sudoers, runtime directories, and read permissions from the repository checkout:

```bash
sudo bash deploy/setup-nonroot-helper-mode.sh
sudo visudo -cf deploy/sudoers.d/vpnbot.example
sudo visudo -cf /etc/sudoers.d/vpnbot
```

Ownership and permission target:

| Path | Owner | Group | Mode | Bot access |
| --- | --- | --- | --- | --- |
| `/opt/vpn-service` | `root` | `root` | admin-managed | read/execute only |
| `/opt/vpn-service/.env` | `root` | `vpn-bot` | `0640` | read only |
| `/opt/vpn-service/.venv` | `root` | `root` | admin-managed | read/execute only |
| `/opt/vpn-service/data` | `vpn-bot` | `vpn-bot` | `0700` | read/write |
| `/opt/vpn-service/logs` | `vpn-bot` | `vpn-bot` | `0700` | read/write |
| `/run/vpn-bot` | `vpn-bot` | `vpn-bot` | `0700` | read/write staging |
| `/usr/local/sbin/vpnbot-*` | `root` | `root` | `0750` or stricter | sudo entrypoint only |
| `/usr/local/etc/xray/config.json` | `nobody` | `vpn-bot` | `0640` | read only |
| `/etc/amnezia/amneziawg/awg0.conf` | `root` | `vpn-bot` | `0640` | read only |
| `/etc/mtproxy/vpnbot` | `root` | `vpn-bot` | `0750` | traverse/read managed files |
| `/etc/mtproxy/vpnbot/managed-secrets.json` | `root` | `vpn-bot` | `0640` | read only |
| `/etc/mtproxy/vpnbot/mtproxy.env` | `root` | `vpn-bot` | `0640` | read only |
| `/etc/sudoers.d/vpnbot` | `root` | `root` | `0440` | sudo policy only |

Required `.env` flags for helper mode:

```env
PRIVILEGE_HELPERS_ENABLED=true
HELPER_STAGING_ROOT=/run/vpn-bot
SOCKS5_USER_HELPER_PATH=/usr/local/sbin/vpnbot-socks5-user
XRAY_APPLY_HELPER_PATH=/usr/local/sbin/vpnbot-xray-apply
AWG_APPLY_HELPER_PATH=/usr/local/sbin/vpnbot-awg-apply
MTPROTO_APPLY_HELPER_PATH=/usr/local/sbin/vpnbot-mtproxy-apply
XRAY_HELPER_STAGING_DIR=/run/vpn-bot/xray
AWG_HELPER_STAGING_DIR=/run/vpn-bot/awg
MTPROTO_HELPER_STAGING_DIR=/run/vpn-bot/mtproxy
BOT_LOCK_PATH=/run/vpn-bot/vpn-bot.lock
```

Validate before switching:

```bash
sudo python3 deploy/check-nonroot-helper-mode.py
sudo -u vpn-bot test -r /opt/vpn-service/.env
sudo -u vpn-bot test -w /opt/vpn-service/data
sudo -u vpn-bot test -w /opt/vpn-service/logs
sudo -u vpn-bot test -w /run/vpn-bot
sudo -u vpn-bot test -r /usr/local/etc/xray/config.json
sudo -u vpn-bot test -r /etc/amnezia/amneziawg/awg0.conf
sudo -u vpn-bot test -r /etc/mtproxy/vpnbot/managed-secrets.json
sudo -u vpn-bot sudo -n /usr/local/sbin/vpnbot-xray-apply status
sudo -u vpn-bot sudo -n /usr/local/sbin/vpnbot-awg-apply status
sudo -u vpn-bot sudo -n /usr/local/sbin/vpnbot-mtproxy-apply status
sudo -u vpn-bot sudo -n /usr/local/sbin/vpnbot-socks5-user exists vpn_socks_preflight
```

Switch to the non-root service only after preflight succeeds:

```bash
sudo install -o root -g root -m 0644 deploy/vpn-bot.nonroot.example.service /etc/systemd/system/vpn-bot.service
sudo systemctl daemon-reload
sudo systemctl restart vpn-bot
sudo systemctl status vpn-bot --no-pager
```

Backend verification after switch:

- Xray: issue a test key, revoke it, and confirm `sudo -u vpn-bot sudo -n /usr/local/sbin/vpnbot-xray-apply status` stays active.
- AWG: issue a test key, revoke it, and confirm `sudo -u vpn-bot sudo -n /usr/local/sbin/vpnbot-awg-apply show-peers` no longer lists the revoked public key.
- SOCKS5: issue/revoke a test SOCKS5 access and confirm only `vpn_socks_` prefixed accounts are touched.
- MTProxy managed mode: issue/revoke a test access and confirm `sudo -u vpn-bot sudo -n /usr/local/sbin/vpnbot-mtproxy-apply status` reports active/listening.
- Bot diagnostics: check the admin diagnostics screen. A degraded backend means startup reconciliation detected unsafe drift or a helper/status failure; fix the backend before issuing new access for that backend.

Rollback to root/direct mode:

```bash
sudo sed -i 's/^PRIVILEGE_HELPERS_ENABLED=.*/PRIVILEGE_HELPERS_ENABLED=false/' /opt/vpn-service/.env
sudo cp -a /root/vpnbot-package5c-backup/vpn-bot.service.backup /etc/systemd/system/vpn-bot.service
sudo systemctl daemon-reload
sudo systemctl restart vpn-bot
sudo systemctl status vpn-bot --no-pager
```

Rollback keeps helper files and sudoers harmless if helper mode is disabled, but you can remove `/etc/sudoers.d/vpnbot` after returning to direct/root mode and validating with `visudo -cf /etc/sudoers`.

Warnings:

- Do not add broad sudoers entries to compensate for helper failures. The sudoers file must grant only fixed helper entrypoints/actions.
- Do not set `NoNewPrivileges=true` in the sudo-helper unit. That blocks the privilege elevation sudo needs.
- Do not recursively chown `/opt/vpn-service` to `vpn-bot`; code, deploy files, and `.venv` must remain root-controlled.
- Do not make canonical backend configs writable by `vpn-bot`. The bot needs read access because adapters read before staging; helpers own privileged writes and restarts.

Rollback remains:

1. Disable `PRIVILEGE_HELPERS_ENABLED`.
2. Keep or restore the root-run direct `deploy/vpn-bot.service`.
3. Restore the previous systemd unit if a cutover was attempted.
4. Restart `vpn-bot`.

## Package 5A Non-Changes

- `deploy/vpn-bot.service` remains the active root-run production unit.
- No sudoers file is installed automatically.
- No Python adapter is changed to call sudo.
- No live backend config path is changed.
- No SQLite schema is changed.
- No production service is restarted by the new scaffolding.

## Package 5B Non-Changes

- `deploy/vpn-bot.service` remains the active root-run production unit.
- Sudoers is still example-only and is not installed automatically.
- Helper mode is opt-in and disabled by default.
- No SQLite schema changes are introduced.
- Historical failed rows are not deleted.

## Package 5C Non-Changes

- The repository does not claim the VDS has been switched to `User=vpn-bot`.
- `deploy/vpn-bot.service` remains root/direct-compatible for rollback.
- `PRIVILEGE_HELPERS_ENABLED=false` remains the safe default.
- The sudoers file remains helper-only and does not grant broad root command access.
- No SQLite schema migration is required for the cutover.
