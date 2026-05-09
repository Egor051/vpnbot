# Privileged Helpers

Recommended production mode is non-root `vpn-bot` plus fixed sudo helpers. The Python process runs as `vpn-bot:vpn-bot`; root-only backend mutations go only through these helper entrypoints:

- `/usr/local/sbin/vpnbot-socks5-user`
- `/usr/local/sbin/vpnbot-xray-apply`
- `/usr/local/sbin/vpnbot-awg-apply`
- `/usr/local/sbin/vpnbot-mtproxy-apply`

Install helpers as `root:root` mode `0755` under `/usr/local/sbin`, not from the application checkout:

```bash
install -o root -g root -m 0755 deploy/helpers/vpnbot-socks5-user /usr/local/sbin/vpnbot-socks5-user
install -o root -g root -m 0755 deploy/helpers/vpnbot-xray-apply /usr/local/sbin/vpnbot-xray-apply
install -o root -g root -m 0755 deploy/helpers/vpnbot-awg-apply /usr/local/sbin/vpnbot-awg-apply
install -o root -g root -m 0755 deploy/helpers/vpnbot-mtproxy-apply /usr/local/sbin/vpnbot-mtproxy-apply
visudo -cf deploy/sudoers.d/vpnbot.example
install -o root -g root -m 0440 deploy/sudoers.d/vpnbot.example /etc/sudoers.d/vpnbot
visudo -cf /etc/sudoers.d/vpnbot
```

`deploy/setup-nonroot-helper-mode.sh` performs these idempotent install steps, prepares runtime/data/log directories, validates sudoers before and after installation, and preserves `vpn-bot` read access to canonical backend files. It does not restart the bot or replace the active systemd unit.

## Helper Mode Settings

The recommended production `.env` values are:

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

Keep `/opt/vpn-service/.env` as `root:vpn-bot` mode `0640`. The `vpn-bot` process needs read-only env access, but must not be able to rewrite its next runtime configuration.

`/run/vpn-bot` must be writable by `vpn-bot:vpn-bot`; the production unit keeps `RuntimeDirectory=vpn-bot` and `RuntimeDirectoryMode=0700` to recreate it on boot.

## Interfaces

SOCKS5:

- `vpnbot-socks5-user exists <login>`
- `vpnbot-socks5-user create <login>`
- `vpnbot-socks5-user set-password <login>` with the password read from stdin
- `vpnbot-socks5-user lock <login>`
- `vpnbot-socks5-user delete <login>`

The SOCKS5 helper enforces `vpn_socks_` and `^[A-Za-z_][A-Za-z0-9_]{0,31}$`, uses `/usr/sbin/nologin`, never accepts password material in argv, and must never print passwords.

Because sudo-launched helpers inherit the `vpn-bot.service` mount namespace, the production unit keeps `ProtectSystem=strict` but exposes `/etc/passwd`, `/etc/shadow`, `/etc/group`, `/etc/gshadow`, and `/etc/.pwd.lock` in `ReadWritePaths`. Those paths are for the fixed SOCKS5 helper account operations only; sudoers must still grant no broad account-management commands.

Xray:

- `vpnbot-xray-apply apply <candidate_config_path>`
- `vpnbot-xray-apply validate <candidate_config_path>`
- `vpnbot-xray-apply status`

Candidates must live under `/run/vpn-bot/xray`. The helper validates JSON, runs `/usr/local/bin/xray run -test -config <candidate>`, installs `/usr/local/etc/xray/config.json` atomically with owner `nobody`, group `vpn-bot`, mode `0640`, restarts fixed service `xray`, verifies active state, and restores the previous config on failure. The canonical Xray config must remain readable, not writable, for `vpn-bot`.

AWG:

- `vpnbot-awg-apply apply <candidate_config_path>`
- `vpnbot-awg-apply validate <candidate_config_path>`
- `vpnbot-awg-apply status`
- `vpnbot-awg-apply show-peers`
- `vpnbot-awg-apply show-transfer`

Candidates must live under `/run/vpn-bot/awg`. The helper validates with `awg-quick strip` or `wg-quick strip`, installs `/etc/amnezia/amneziawg/awg0.conf` atomically as `root:vpn-bot` mode `0640`, applies runtime with fixed-interface `syncconf` for `awg0`, checks `awg-quick@awg0`, and restores the previous config on failure. The canonical AWG config must remain readable, not writable, for `vpn-bot`.

MTProxy:

- `vpnbot-mtproxy-apply apply <candidate_dir>`
- `vpnbot-mtproxy-apply status`

The candidate directory must live under `/run/vpn-bot/mtproxy` and contain `managed-secrets.json` plus `mtproxy.env`. The helper validates managed-secrets JSON shape without printing secrets, never prints raw MTProto secrets or generated links, installs `/etc/mtproxy/vpnbot` as `root:vpn-bot` mode `0750`, installs `managed-secrets.json` and `mtproxy.env` as `root:vpn-bot` mode `0640`, restarts fixed service `mtproxy`, verifies active state and the configured port, and restores previous files on failure. MTProxy managed secrets/env must remain readable, not writable, for `vpn-bot`.

## Production Rollout

1. Install the `vpn-bot` user and group.
2. Install helpers as `root:root 0755` under `/usr/local/sbin`.
3. Validate `deploy/sudoers.d/vpnbot.example` with `visudo -cf`.
4. Install `/etc/sudoers.d/vpnbot` as `root:root 0440` and validate it with `visudo -cf`.
5. Create and own `/run/vpn-bot`, `/opt/vpn-service/data`, and `/opt/vpn-service/logs` for `vpn-bot:vpn-bot`.
6. Keep `/opt/vpn-service/.env` as `root:vpn-bot 0640`.
7. Ensure canonical Xray config, AWG config, and MTProxy managed secrets/env are readable by `vpn-bot` where the adapters need read-before-stage access.
8. Enable helper mode in `.env`.
9. Run `python3 deploy/check-nonroot-helper-mode.py` and require `failures=0 warnings=0`.
10. Install `deploy/vpn-bot.service` as the active unit and restart the bot.

Post-cutover checklist:

- `python3 deploy/check-nonroot-helper-mode.py` reports `failures=0 warnings=0`.
- `vpn-bot` process user is `vpn-bot:vpn-bot`.
- `vpn-bot`, `xray`, `awg-quick@awg0`, `danted`, and `mtproxy` are active when those backends are enabled.
- `journalctl -b -u vpn-bot` contains no `degraded`, `critical`, `error`, `traceback`, `permission denied`, or `not permitted` entries.
- Reboot verification passed.
- A post-reboot backup was made.

Rollback is to disable `PRIVILEGE_HELPERS_ENABLED`, install `deploy/vpn-bot.root-legacy.example.service` as `/etc/systemd/system/vpn-bot.service`, run `systemctl daemon-reload`, restart `vpn-bot`, and validate status/logs. Keep or remove `/etc/sudoers.d/vpnbot` only after validating the final sudoers state with `visudo -cf`.

The sudo-helper production unit must not set `NoNewPrivileges=true`: sudo needs privilege elevation through its setuid boundary.
