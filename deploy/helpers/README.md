# Privileged Helpers

> ⚠️ **Note:** These helpers are for the **non-root privilege-separated deployment model** (`User=vpn-bot` + `PRIVILEGE_HELPERS_ENABLED=true`). If you are running the **root+api mode** (`User=root` + `XRAY_APPLY_MODE=api`), helpers are not used and this README does not apply. See [Deployment → Xray API Mode](../../docs/deployment.md#xray-api-mode).

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

Candidates must live under `/run/vpn-bot/xray`. The helper validates JSON, runs `/usr/local/bin/xray run -test -config <candidate>`, installs `/usr/local/etc/xray/config.json` atomically as `nobody:vpn-bot` mode `0640` (world-unreadable; group-readable for non-root reads), restarts fixed service `xray`, verifies active state, and restores the previous config on failure.

AWG:

- `vpnbot-awg-apply apply <candidate_config_path>`
- `vpnbot-awg-apply validate <candidate_config_path>`
- `vpnbot-awg-apply status`
- `vpnbot-awg-apply show-peers`
- `vpnbot-awg-apply show-transfer`

Candidates must live under `/run/vpn-bot/awg`. The helper validates with `awg-quick strip` or `wg-quick strip`, installs `/etc/amnezia/amneziawg/awg0.conf` atomically as `root:vpn-bot` mode `0640` (world-unreadable; group-readable for non-root reads — note this exposes the server WireGuard PrivateKey to the `vpn-bot` group, an accepted trade-off), applies runtime with fixed-interface `syncconf` for `awg0`, checks `awg-quick@awg0`, and restores the previous config on failure.

MTProxy:

- `vpnbot-mtproxy-apply apply <candidate_dir>`
- `vpnbot-mtproxy-apply status`

The candidate directory must live under `/run/vpn-bot/mtproxy` and contain `managed-secrets.json` plus `mtproxy.env`. The helper validates managed-secrets JSON shape without printing secrets, installs `/etc/mtproxy/vpnbot/managed-secrets.json` and `/etc/mtproxy/vpnbot/mtproxy.env` atomically as `root:vpn-bot` mode `0640` in a `0750` `root:vpn-bot` directory (world-unreadable; group-readable for non-root reads), restarts fixed service `mtproxy`, verifies active state and the configured port, and restores previous files on failure.

## WARP outbound-IP masking helpers

The WARP module ships four additional sudo helpers (in `scripts/`, installed to
`/usr/local/sbin`). Unlike the backend helpers above, the WARP helpers are
**always** invoked via `sudo` regardless of `PRIVILEGE_HELPERS_ENABLED` (the
module manages a dedicated `out-warp` AmneziaWG interface and its routes so that
selected apps' traffic leaves from the tunnel endpoint, masking the server's
outbound IP; the bot itself stays unprivileged). The module is disabled by
default and does nothing until an admin uploads a config and enables it.

```bash
install -o root -g root -m 0755 scripts/vpnbot-warp-install /usr/local/sbin/vpnbot-warp-install
install -o root -g root -m 0755 scripts/vpnbot-warp-iface   /usr/local/sbin/vpnbot-warp-iface
install -o root -g root -m 0755 scripts/vpnbot-warp-routes  /usr/local/sbin/vpnbot-warp-routes
install -o root -g root -m 0755 scripts/vpnbot-warp-status  /usr/local/sbin/vpnbot-warp-status
```

`deploy/setup-nonroot-helper-mode.sh` now installs (and refreshes) these four
WARP helpers as well, so a standard non-root deploy keeps `/usr/local/sbin` in
sync with the checkout. Previously they were not part of any deploy step, so a
`git reset` left the stale `/usr/local/sbin/vpnbot-warp-routes` in place — which
is how the broken routing helper kept running after the source was fixed. Re-run
that script (or the `install` commands above) after pulling new helper versions.

### Ownership model: systemd owns the interface and routes; the bot only observes

The `out-warp` interface and its policy routes have **one** owner: **systemd**.
The interface is brought up by the stock `awg-quick@out-warp.service`; the policy
rules, table-200 default route and per-daemon marks by `warp-routes.service`. The
bot's WARP health monitor runs in **observer mode** (the default,
`WARP_MONITOR_OBSERVER_MODE=true`): it pings the tunnel, records state in the DB
and notifies admins, but it **never** runs `awg-quick`, `ip route` or `ip rule`.

This is deliberate. Previously both `warp-routes.service` (at boot) and the bot's
monitor managed the same `ip rule`/`ip route` entries; a flaky probe in the bot
would tear down routes that the service had installed, producing a
recovered → add → fail → del → down flap every ~30–60 s. With a single owner the
flapping is gone, and the WARP toggle in the admin panel now starts/stops **only**
the observer monitor — toggling it off no longer drops the tunnel or wipes the
routes.

`awg-quick up out-warp` resolves the interface name to
`/etc/amnezia/amneziawg/out-warp.conf`, whereas the install helper writes the
canonical config to `/etc/amnezia/out-warp.conf`. Do **not** duplicate the file —
point the name awg-quick expects at the canonical one with a symlink, so there is
still a single source of truth (and the bot's pinned sudoers paths stay valid):

```bash
install -o root -g root -m 0644 deploy/warp-routes.service /etc/systemd/system/warp-routes.service
systemctl daemon-reload

# 1. Let awg-quick@out-warp find the installed config by interface name.
mkdir -p /etc/amnezia/amneziawg
ln -sf /etc/amnezia/out-warp.conf /etc/amnezia/amneziawg/out-warp.conf

# 2. Bring the interface up via systemd (NOT the bot).
systemctl enable --now awg-quick@out-warp

# 3. Install the policy routing. warp-routes.service is bound to the interface unit
#    (Requires=/After=/PartOf=awg-quick@out-warp.service) so routes land only after
#    the interface is up and are re-applied whenever it restarts.
systemctl enable --now warp-routes.service
```

To restore the legacy model where the bot manages the interface and routes itself
(not recommended — it reintroduces the two-owner flapping), set
`WARP_MONITOR_OBSERVER_MODE=false` and leave the systemd units disabled.

Interfaces:

- `vpnbot-warp-install install <staged_config>` — validates the AmneziaWG format
  (`[Interface]`/`[Peer]`, `Jc`/`S1`/`S2`, non-empty `AllowedIPs`), **rejects**
  `PreUp`/`PostUp`/`PreDown`/`PostDown` hooks (awg-quick would run them as root),
  validates every `AllowedIPs` token as a real CIDR, strips `DNS`, forces
  `Table = auto` and adds `PersistentKeepalive = 25`, writes
  `/etc/amnezia/out-warp.conf` (mode `0600`) and `/etc/amnezia/out-warp-routes.list`
  (one CIDR per line from `AllowedIPs`, which is never modified — kept for the
  admin-panel route count), and points `/etc/amnezia/amneziawg/out-warp.conf` at
  the canonical config via a symlink so `awg-quick@out-warp` resolves it by name.
  `Table = auto` is mandatory: it makes awg-quick set an fwmark on the WG socket
  (loop protection) and create the dynamic routing table the routes helper diverts
  the client subnet into; the previous `Table = off` is what caused the routing
  loop. The source must be a non-symlink file inside the staging dir; the bot
  stages the upload under `/run/vpn-bot/warp/warp-upload-*.conf`.
- `vpnbot-warp-install remove` — deletes `/etc/amnezia/out-warp.conf`,
  `/etc/amnezia/out-warp-routes.list` and the
  `/etc/amnezia/amneziawg/out-warp.conf` symlink from disk. Called by
  `delete_config` to ensure the PrivateKey does not persist after config removal.
- `vpnbot-warp-iface {up|down} /etc/amnezia/out-warp.conf` — runs
  `awg-quick up|down` (AmneziaWG, **not** `wg-quick`).
- `vpnbot-warp-routes {add|del} out-warp` — installs the production-proven policy
  routing that diverts the **AmneziaWG client subnet** (`10.0.0.0/24`) through the
  tunnel while the host itself stays on the direct path. The tunnel is brought up
  by `awg-quick@out-warp` with `Table = auto`, which creates a **dynamic** routing
  table (the first free number from 51820 up, equal to the WG-socket fwmark) with
  a default route via `out-warp`, plus the host-bypass rules
  `not fwmark <T> table <T>` and `table main suppress_prefixlength 0` that would
  otherwise tunnel the whole box. `add` therefore: (1) reads the table number from
  `awg show out-warp fwmark` (never hardcoded); (2) **strips the host-bypass
  immediately** so SSH/the bot keep egressing directly — the critical safety step;
  (3) installs a single narrow rule `from 10.0.0.0/24 lookup <T>` (priority 1000);
  (4) pins the WARP endpoint (read from `awg show`) to the real WAN gateway in
  **both** the main and the tunnel table (anti-loop); (5) swaps the NAT — drops any
  direct `MASQUERADE -s 10.0.0.0/24 -o <wan>` and adds `MASQUERADE -o out-warp`;
  (6) inserts the `FORWARD` accepts **above UFW** (`-I FORWARD 1`, `awg0`↔`out-warp`,
  since UFW's FORWARD policy is DROP); (7) sets `rp_filter=2`. It then self-checks
  (host egress NOT in the tunnel + client subnet routed via `out-warp`) and rolls
  back to direct client egress on failure. Every add step is idempotent. `del`
  reverses everything, restores the direct WAN `MASQUERADE` for the client subnet
  and is safe on a clean system; it never restores the host-bypass (the host must
  always stay direct). The table number and endpoint are always resolved at
  runtime. Forwarding **Dante/Xray/MTProto** through WARP is out of scope here —
  this helper diverts AmneziaWG clients only.
- `vpnbot-warp-status out-warp` — runs `awg show out-warp`.

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
