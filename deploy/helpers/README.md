# Privileged Helpers

> ⚠️ **Note:** These helpers are for the **non-root privilege-separated deployment model** (`User=vpn-bot` + `PRIVILEGE_HELPERS_ENABLED=true`). If you are running the **root+api mode** (`User=root` + `XRAY_APPLY_MODE=api`), helpers are not used and this README does not apply. See the main README [Xray API Mode](../../README.md#xray-api-mode) section.

The non-root deployment runs `vpn-bot.service` as `User=vpn-bot` and `Group=vpn-bot`. Privileged backend mutation is restricted to fixed sudo helper entrypoints installed under `/usr/local/sbin`; the application checkout copy is source material only.

Install helpers and sudoers as root:

```bash
install -o root -g root -m 0755 deploy/helpers/vpnbot-socks5-user /usr/local/sbin/vpnbot-socks5-user
install -o root -g root -m 0755 deploy/helpers/vpnbot-xray-apply /usr/local/sbin/vpnbot-xray-apply
install -o root -g root -m 0755 deploy/helpers/vpnbot-awg-apply /usr/local/sbin/vpnbot-awg-apply
install -o root -g root -m 0755 deploy/helpers/vpnbot-mtproxy-apply /usr/local/sbin/vpnbot-mtproxy-apply
install -o root -g root -m 0440 deploy/sudoers.d/vpnbot.example /etc/sudoers.d/vpnbot
visudo -cf /etc/sudoers.d/vpnbot
```

Expected ownership and modes:

- Helpers: `root:root` `0755`.
- Sudoers: `/etc/sudoers.d/vpnbot` `root:root` `0440`.
- Code, deploy files, and `.venv`: not writable by `vpn-bot`.
- Runtime state writable by `vpn-bot`: `/opt/vpn-service/data`, `/opt/vpn-service/logs` if file logs are enabled, and `/run/vpn-bot`.

## Helper Mode Settings

Production helper mode uses:

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
```

The Python adapters call helpers through `sudo -n`, pass arguments as argv lists, and stage sensitive config files under the helper staging directories with private modes. The helpers validate staged paths again and reject symlinks, relative paths, and paths outside their fixed staging roots.

Helpers are not a generic root shell. Sudoers grants no raw account-management, service-manager, file-copy, Xray, AWG/WG, or MTProxy binaries. Each helper accepts only its fixed backend target and validates all actions, paths, prefixes, and staged file contents before touching root-owned state.

## Interfaces

SOCKS5:

- `vpnbot-socks5-user exists <login>`
- `vpnbot-socks5-user create <login>`
- `vpnbot-socks5-user set-password <login>` with the password read from stdin
- `vpnbot-socks5-user lock <login>`
- `vpnbot-socks5-user delete <login>`

The SOCKS5 helper enforces `vpn_socks_` and `^[A-Za-z_][A-Za-z0-9_]{0,31}$`, uses `/usr/sbin/nologin`, never accepts password material in argv, and must never print passwords.

Xray:

- `vpnbot-xray-apply apply <candidate_config_path>`
- `vpnbot-xray-apply validate <candidate_config_path>`
- `vpnbot-xray-apply status`

Candidates must live under `/run/vpn-bot/xray`. The helper validates JSON, runs `/usr/local/bin/xray run -test -config <candidate>`, installs `/usr/local/etc/xray/config.json` atomically with mode `0600` for `nobody:nogroup`, restarts fixed service `xray`, verifies active state, and restores the previous config on failure.

AWG:

- `vpnbot-awg-apply apply <candidate_config_path>`
- `vpnbot-awg-apply validate <candidate_config_path>`
- `vpnbot-awg-apply status`
- `vpnbot-awg-apply show-peers`
- `vpnbot-awg-apply show-transfer`

Candidates must live under `/run/vpn-bot/awg`. The helper validates with `awg-quick strip` or `wg-quick strip`, installs `/etc/amnezia/amneziawg/awg0.conf` atomically as `root:root` mode `0600`, applies runtime with fixed-interface `syncconf` for `awg0`, checks `awg-quick@awg0`, and restores the previous config on failure.

MTProxy:

- `vpnbot-mtproxy-apply apply <candidate_dir>`
- `vpnbot-mtproxy-apply status`

The candidate directory must live under `/run/vpn-bot/mtproxy` and contain `managed-secrets.json` plus `mtproxy.env`. The helper validates managed-secrets JSON shape without printing secrets, installs `/etc/mtproxy/vpnbot/managed-secrets.json` and `/etc/mtproxy/vpnbot/mtproxy.env` atomically as `root:root` mode `0600`, restarts fixed service `mtproxy`, verifies active state and the configured port, and restores previous files on failure.

## WARP Telegram Routing helpers

The WARP module ships four additional sudo helpers (in `scripts/`, installed to
`/usr/local/sbin`). Unlike the backend helpers above, the WARP helpers are
**always** invoked via `sudo` regardless of `PRIVILEGE_HELPERS_ENABLED` (the
module manages a dedicated `tg-warp` AmneziaWG interface and its routes; the bot
itself stays unprivileged). The module is disabled by default and does nothing
until an admin uploads a config and enables it.

```bash
install -o root -g root -m 0755 scripts/vpnbot-warp-install /usr/local/sbin/vpnbot-warp-install
install -o root -g root -m 0755 scripts/vpnbot-warp-iface   /usr/local/sbin/vpnbot-warp-iface
install -o root -g root -m 0755 scripts/vpnbot-warp-routes  /usr/local/sbin/vpnbot-warp-routes
install -o root -g root -m 0755 scripts/vpnbot-warp-status  /usr/local/sbin/vpnbot-warp-status
```

Interfaces:

- `vpnbot-warp-install install <staged_config>` — validates the AmneziaWG format
  (`[Interface]`/`[Peer]`, `Jc`/`S1`/`S2`, non-empty `AllowedIPs`), strips `DNS`,
  adds `Table = off` and `PersistentKeepalive = 25`, writes
  `/etc/amnezia/tg-warp.conf` (mode `0600`) and
  `/etc/amnezia/tg-warp-routes.list` (one CIDR per line from `AllowedIPs`, which
  is never modified). The bot stages the upload under
  `/run/vpn-bot/warp/warp-upload-*.conf`.
- `vpnbot-warp-install remove` — deletes `/etc/amnezia/tg-warp.conf` and
  `/etc/amnezia/tg-warp-routes.list` from disk. Called by `delete_config` to
  ensure the PrivateKey does not persist after config removal.
- `vpnbot-warp-iface {up|down} /etc/amnezia/tg-warp.conf` — runs
  `awg-quick up|down` (AmneziaWG, **not** `wg-quick`).
- `vpnbot-warp-routes {add|del} tg-warp` — adds/removes `ip route` entries read
  from `tg-warp-routes.list`. Skips `0.0.0.0/0` and `::/0` to protect the default
  route; never touches the DNS resolver.
- `vpnbot-warp-status tg-warp` — runs `awg show tg-warp`.

`awg-quick`/`awg` (AmneziaWG userspace tools) must be installed at
`/usr/bin/awg-quick` and `/usr/bin/awg`; the module blocks startup with a clear
admin-panel error when the binary is missing.

### Prerequisites

Before enabling the WARP module, verify that the `ping` binary has the
`cap_net_raw` file capability (required by `ping -I <iface>`):

```bash
getcap $(which ping)
# Expected output contains: cap_net_raw=ep
# e.g. /usr/bin/ping cap_net_raw=ep
```

If the capability is missing, the health monitor's probes will silently fail on
startup and the routes will be pulled down immediately. To add the capability:

```bash
sudo setcap cap_net_raw+ep $(which ping)
```

On most modern distros `ping` ships with this capability set. If yours does not,
add the `setcap` call to your server provisioning script.

## Rollout Checks

1. Install helpers and `/etc/sudoers.d/vpnbot` with the ownership and modes above.
2. Validate sudoers with `visudo -cf /etc/sudoers.d/vpnbot`.
3. Set `PRIVILEGE_HELPERS_ENABLED=true` and `BOT_LOCK_PATH=/run/vpn-bot/vpn-bot.lock`.
4. Install `deploy/vpn-bot.service` as the production non-root unit.
5. Run `python deploy/check-nonroot-helper-mode.py` before and after restarting the service.
6. Run a staged issue/revoke test for Xray, AWG, SOCKS5, and managed MTProxy.

Emergency rollback from non-root mode is to restore the backed-up pre-cutover unit and matching `.env`, disable `PRIVILEGE_HELPERS_ENABLED`, and restart `vpn-bot`.
