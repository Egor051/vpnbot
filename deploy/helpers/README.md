# Package 5B Privileged Helpers

Package 5B adds real helper scripts and optional application helper-mode wiring. It still does not switch the production `vpn-bot.service` to `User=vpn-bot`, does not install sudoers automatically, and does not require operators to enable helper mode yet.

Helpers are intended to be installed as root-owned files under `/usr/local/sbin`, not executed from the application checkout:

```bash
install -o root -g root -m 0750 deploy/helpers/vpnbot-socks5-user /usr/local/sbin/vpnbot-socks5-user
install -o root -g root -m 0750 deploy/helpers/vpnbot-xray-apply /usr/local/sbin/vpnbot-xray-apply
install -o root -g root -m 0750 deploy/helpers/vpnbot-awg-apply /usr/local/sbin/vpnbot-awg-apply
install -o root -g root -m 0750 deploy/helpers/vpnbot-mtproxy-apply /usr/local/sbin/vpnbot-mtproxy-apply
visudo -cf /path/to/vpnbot.example
```

Install the sudoers file only during the Package 5C cutover or a deliberate manual helper-mode test.

## Helper Mode Settings

Default runtime behavior remains direct/root-compatible. Helper mode is enabled only with:

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

## Package 5C Rollout

1. Install helpers root-owned under `/usr/local/sbin`.
2. Validate `deploy/sudoers.d/vpnbot.example` with `visudo -cf`.
3. Install the sudoers file with only the helper commands.
4. Create and own `/run/vpn-bot`, `/opt/vpn-service/data`, and `/opt/vpn-service/logs` for `vpn-bot:vpn-bot`.
5. Enable helper mode in `.env`.
6. Run a staged issue/revoke test for Xray, AWG, SOCKS5, and managed MTProxy.
7. Switch to `deploy/vpn-bot.nonroot.example.service` only after the helper-mode test passes.

Rollback is to disable `PRIVILEGE_HELPERS_ENABLED`, keep or restore the root-run direct unit, restore the previous systemd unit if needed, and restart `vpn-bot`. Package 5B keeps the active production unit root-run specifically so this rollback remains available.
