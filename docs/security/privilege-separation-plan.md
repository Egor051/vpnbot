# Package 5 Privilege Separation Plan

Status: Package 5A preparatory document. This package does not switch the production bot to a non-root user, does not install sudoers rules, and does not change live backend paths.

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
  - `/etc/mtproxy/vpnbot` only if Package 5B explicitly accepts direct MTProto ownership; otherwise MTProto writes move to a helper.
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
| vpn-bot systemd runtime | Runs the Telegram bot and all adapters as root. | `deploy/vpn-bot.service`; `User=root`; `Group=root`; `ReadWritePaths=/opt/vpn-service /run /usr/local/etc/xray /etc/amnezia/amneziawg /etc/mtproxy/vpnbot /etc/passwd /etc/shadow /etc/group /etc/gshadow /etc/.pwd.lock` | Root for Linux account mutation, backend config writes, and service control. | Bot token compromise, handler bug, dependency RCE, or local code execution can mutate system accounts and backend configs. | Active unit remains root in Package 5A. Future unit runs as `vpn-bot` with strict filesystem sandboxing and helpers for root-only changes. | `deploy/vpn-bot.nonroot.example.service` plus future helper sudoers. | No for the Python process; yes for helper operations. | No direct privileged backend access after cutover. |
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
| MTProto managed secrets/env files | Writes managed secret store, env file, backups, and runtime wrapper inputs. | `/etc/mtproxy/vpnbot/managed-secrets.json`; `/etc/mtproxy/vpnbot/mtproxy.env`; `/etc/mtproxy/vpnbot/backups`; `deploy/run-mtproxy-managed` | Currently root because the bot runs as root and files are under `/etc`. | Compromised bot can add/remove MTProto secrets, expose proxy secrets, or poison wrapper environment. | Package 5B must choose either direct `vpn-bot` ownership of `/etc/mtproxy/vpnbot` with strict modes, or a helper that installs files after validation. Helper is safer if `/etc` remains root-only. | Preferred: `/usr/local/sbin/vpnbot-mtproxy-apply`; alternative: tightly owned `/etc/mtproxy/vpnbot` with no broader `/etc` write. | Restart and canonical install under `/etc` should stay root-only unless a deliberate group/write model is accepted. | No direct `/etc` write preferred; direct access only if explicitly justified. |
| MTProxy service restart/is-active/port check | Restarts mtproxy, checks active state, and verifies listening port. | `systemctl restart mtproxy`; `systemctl is-active mtproxy`; `ss -tlnp` | Root/service-manager privilege for restart; port check may be unprivileged but can expose process info. | Broad restart permission could affect services; raw output could leak process details. | Helper runs a fixed restart and health check for the configured MTProxy service and port, redacting secrets. | `/usr/local/sbin/vpnbot-mtproxy-apply` via sudoers. | Restart is root-only. Port check can be helper-mediated. | No generic service control. |
| Backups created by adapters | Creates config backups beside sensitive config files or under MTProto backup root. | Xray `config.json.*.bak`; AWG `awg0.conf.*.bak`; MTProto `/etc/mtproxy/vpnbot/backups` | Same privilege as canonical config directory. | Backup files may contain private keys or secrets and can accumulate in sensitive directories. | Helper owns backup creation for canonical configs and enforces `0600` plus retention. Bot-owned SQLite/log backups, if any, remain under bot data/log paths. | Xray/AWG/MTProto helpers create and clean their own backups. | Yes for backend config backups. | No direct access to backend backup dirs unless helper returns sanitized status. |
| Deployment scripts and ownership model | Deploy currently installs root-run service and MTProxy wrapper/drop-in assets. | `deploy/vpn-bot.service`; `deploy/run-mtproxy-managed`; `deploy/mtproxy-vpnbot-managed.conf`; `/opt/vpn-service` | Root for install, ownership, unit reloads, and service restarts. | Recursive ownership changes could make code writable by the bot or accidentally expose secrets. | Keep deploy as root/admin work. Add idempotent user creation and documented future ownership steps. Do not recursively chown `/opt/vpn-service` to `vpn-bot`. | `deploy/create-vpn-bot-user.sh`; `deploy/sudoers.d/vpnbot.example`; future helper install docs. | Install and unit management remain root-only. | No deploy-time write access to code or unit files. |

## Future Helper Interfaces

### SOCKS5 helper

Candidate path: `/usr/local/sbin/vpnbot-socks5-user`.

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

Candidate path: `/usr/local/sbin/vpnbot-xray-apply`.

Required properties:

- Accepts a candidate config from a restricted staging directory or stdin.
- Validates JSON before invoking Xray.
- Runs `xray run -test -config <candidate>` against the candidate.
- Atomically installs to `/usr/local/etc/xray/config.json`.
- Preserves owner and mode expected by `xray.service`.
- Applies by the configured policy: reload if reliable, otherwise restart.
- Verifies Xray is active after apply.
- Implements rollback inside the helper, or documents that rollback remains an adapter-level transaction. Preferred final decision: helper owns rollback because it owns canonical config installation and service apply.

### AWG helper

Candidate path: `/usr/local/sbin/vpnbot-awg-apply`.

Required properties:

- Accepts a candidate `awg0.conf` from a restricted staging directory or stdin.
- Validates with `awg-quick strip` or the configured compatible tool.
- Atomically installs `/etc/amnezia/amneziawg/awg0.conf`.
- Preserves private key permissions.
- Applies runtime using the selected policy from Package 5B: current adapter design favors runtime `syncconf`/peer changes; a restart of `awg-quick@awg0` is acceptable only if explicitly chosen.
- Verifies the interface is active and the expected peer state is present.
- Provides sanitized read-only status/transfer output if the unprivileged bot cannot run runtime inspection directly.

### MTProto helper

Candidate path: `/usr/local/sbin/vpnbot-mtproxy-apply`.

Required properties:

- Package 5B must decide whether direct `vpn-bot` ownership of `/etc/mtproxy/vpnbot` is acceptable. Preferred default: use a helper because files live under `/etc` and contain secrets.
- Installs managed secret and env files atomically with mode `0600`.
- Restarts `mtproxy` using a fixed service name.
- Verifies service active state and listening port.
- Never prints raw MTProto secrets or generated links.
- Redacts secrets in errors, logs, and rollback summaries.

## Deploy And Ownership Plan

Package 5A adds scaffolding only:

- `deploy/create-vpn-bot-user.sh` creates the future system user and group without switching the service.
- `deploy/vpn-bot.nonroot.example.service` shows the future non-root unit and narrow writable paths.
- `deploy/sudoers.d/vpnbot.example` shows a conservative helper-only sudoers boundary.
- `deploy/helpers/README.md` specifies helper contracts and states that no helper is wired into production yet.

Package 5B/5C should perform the cutover only after helpers are implemented and tested:

1. Install root-owned helpers under `/usr/local/sbin`, mode `0750` or stricter as appropriate.
2. Validate helpers with unit tests and a VDS temp copy.
3. Install sudoers with `visudo -cf` validation.
4. Prepare `/opt/vpn-service/data`, `/opt/vpn-service/logs`, and `/run/vpn-bot` for `vpn-bot` writes.
5. Keep `/opt/vpn-service`, `.venv`, deploy files, and service units root-owned and not writable by `vpn-bot`.
6. Switch to the non-root unit only after Xray, AWG, SOCKS5, and MTProto helper paths are wired and tested.

## Package 5A Non-Changes

- `deploy/vpn-bot.service` remains the active root-run production unit.
- No sudoers file is installed automatically.
- No Python adapter is changed to call sudo.
- No live backend config path is changed.
- No SQLite schema is changed.
- No production service is restarted by the new scaffolding.
