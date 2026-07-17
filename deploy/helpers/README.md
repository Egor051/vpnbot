# Privileged Helpers

> ⚠️ **Note:** These helpers are for the **non-root privilege-separated deployment model** (`User=vpn-bot` + `PRIVILEGE_HELPERS_ENABLED=true`). If you are running the **root+api mode** (`User=root` + `XRAY_APPLY_MODE=api`), helpers are not used and this README does not apply. See [Deployment → Xray API Mode](../../docs/deployment.md#xray-api-mode).

The non-root deployment runs `vpn-bot.service` as `User=vpn-bot` and `Group=vpn-bot`. Privileged backend mutation is restricted to fixed sudo helper entrypoints installed under `/usr/local/sbin`; the application checkout copy is source material only.

Install helpers and sudoers as root:

```bash
install -o root -g root -m 0755 deploy/helpers/vpn-bot-socks5-user /usr/local/sbin/vpn-bot-socks5-user
install -o root -g root -m 0755 deploy/helpers/vpn-bot-xray-apply /usr/local/sbin/vpn-bot-xray-apply
install -o root -g root -m 0755 deploy/helpers/vpn-bot-awg-apply /usr/local/sbin/vpn-bot-awg-apply
install -o root -g root -m 0755 deploy/helpers/vpn-bot-mtproxy-apply /usr/local/sbin/vpn-bot-mtproxy-apply
install -o root -g root -m 0440 deploy/sudoers.d/vpn-bot.example /etc/sudoers.d/vpn-bot
visudo -cf /etc/sudoers.d/vpn-bot
```

Expected ownership and modes:

- Helpers: `root:root` `0755`.
- Sudoers: `/etc/sudoers.d/vpn-bot` `root:root` `0440`.
- Code, deploy files, and `.venv`: not writable by `vpn-bot`.
- Runtime state writable by `vpn-bot`: `/opt/vpn-service/data`, `/opt/vpn-service/logs` if file logs are enabled, and `/run/vpn-bot`.

## Helper Mode Settings

Production helper mode uses:

```env
PRIVILEGE_HELPERS_ENABLED=true
HELPER_STAGING_ROOT=/run/vpn-bot
SOCKS5_USER_HELPER_PATH=/usr/local/sbin/vpn-bot-socks5-user
XRAY_APPLY_HELPER_PATH=/usr/local/sbin/vpn-bot-xray-apply
AWG_APPLY_HELPER_PATH=/usr/local/sbin/vpn-bot-awg-apply
MTPROTO_APPLY_HELPER_PATH=/usr/local/sbin/vpn-bot-mtproxy-apply
XRAY_HELPER_STAGING_DIR=/run/vpn-bot/xray
AWG_HELPER_STAGING_DIR=/run/vpn-bot/awg
MTPROTO_HELPER_STAGING_DIR=/run/vpn-bot/mtproxy
```

The Python adapters call helpers through `sudo -n`, pass arguments as argv lists, and stage sensitive config files under the helper staging directories with private modes. The helpers validate staged paths again and reject symlinks, relative paths, and paths outside their fixed staging roots.

Helpers are not a generic root shell. Sudoers grants no raw account-management, service-manager, file-copy, Xray, AWG/WG, or MTProxy binaries. Each helper accepts only its fixed backend target and validates all actions, paths, prefixes, and staged file contents before touching root-owned state.

## Interfaces

SOCKS5:

- `vpn-bot-socks5-user exists <login>`
- `vpn-bot-socks5-user create <login>`
- `vpn-bot-socks5-user set-password <login>` with the password read from stdin
- `vpn-bot-socks5-user lock <login>`
- `vpn-bot-socks5-user delete <login>`

The SOCKS5 helper enforces `vpn_socks_` and `^[A-Za-z_][A-Za-z0-9_]{0,31}$`, uses `/usr/sbin/nologin`, never accepts password material in argv, and must never print passwords.

Xray:

- `vpn-bot-xray-apply apply <candidate_config_path>`
- `vpn-bot-xray-apply validate <candidate_config_path>`
- `vpn-bot-xray-apply status`

Candidates must live under `/run/vpn-bot/xray`. The helper validates JSON, runs `/usr/local/bin/xray run -test -config <candidate>`, installs `/usr/local/etc/xray/config.json` atomically as `nobody:vpn-bot` mode `0640` (world-unreadable; group-readable for non-root reads), restarts fixed service `xray`, verifies active state, and restores the previous config on failure.

AWG:

- `vpn-bot-awg-apply apply <candidate_config_path>`
- `vpn-bot-awg-apply validate <candidate_config_path>`
- `vpn-bot-awg-apply status`
- `vpn-bot-awg-apply show-peers`
- `vpn-bot-awg-apply show-transfer`

Candidates must live under `/run/vpn-bot/awg`. The helper validates with `awg-quick strip` or `wg-quick strip`, installs `/etc/amnezia/amneziawg/awg0.conf` atomically as `root:vpn-bot` mode `0640` (world-unreadable; group-readable for non-root reads — note this exposes the server WireGuard PrivateKey to the `vpn-bot` group, an accepted trade-off), applies runtime with fixed-interface `syncconf` for `awg0`, checks `awg-quick@awg0`, and restores the previous config on failure.

MTProxy:

- `vpn-bot-mtproxy-apply apply <candidate_dir>`
- `vpn-bot-mtproxy-apply status`

The candidate directory must live under `/run/vpn-bot/mtproxy` and contain `managed-secrets.json` plus `mtproxy.env`. The helper validates managed-secrets JSON shape without printing secrets, installs `/etc/mtproxy/vpn-bot/managed-secrets.json` and `/etc/mtproxy/vpn-bot/mtproxy.env` atomically as `root:vpn-bot` mode `0640` in a `0750` `root:vpn-bot` directory (world-unreadable; group-readable for non-root reads), restarts fixed service `mtproxy`, verifies active state and the configured port, and restores previous files on failure.

These `root:vpn-bot 0640` modes are for the **non-root helper deployment**: they let the unprivileged bot read managed status, and the managed-mode wrapper (which always runs as root — see [Proxy → MTProto managed mode](../../docs/proxy.md)) reads them regardless. The **root+direct manual install** documented in `docs/proxy.md` instead uses `root:root 0600`. Both are correct because the wrapper runs as root and drops the proxy to `MTPROTO_RUN_USER` via `-u`; they are not a contradiction.

## WARP outbound-IP masking helpers

The WARP module ships four additional sudo helpers (in `scripts/`, installed to
`/usr/local/sbin`). Unlike the backend helpers above, the WARP helpers are
**always** invoked via `sudo` regardless of `PRIVILEGE_HELPERS_ENABLED` (the
module manages a dedicated `out-warp` AmneziaWG interface and its routes so that
selected apps' traffic leaves from the tunnel endpoint, masking the server's
outbound IP; the bot itself stays unprivileged). The module is disabled by
default and does nothing until an admin uploads a config and enables it.

```bash
install -o root -g root -m 0755 scripts/vpn-bot-warp-install /usr/local/sbin/vpn-bot-warp-install
install -o root -g root -m 0755 scripts/vpn-bot-warp-iface   /usr/local/sbin/vpn-bot-warp-iface
install -o root -g root -m 0755 scripts/vpn-bot-warp-routes  /usr/local/sbin/vpn-bot-warp-routes
install -o root -g root -m 0755 scripts/vpn-bot-warp-status  /usr/local/sbin/vpn-bot-warp-status
```

`scripts/deploy.sh` now refreshes these WARP helpers itself in Phase 2
(`install_out_of_repo_helpers`): after it advances the tree to `origin/main` it
reinstalls any helper whose installed `/usr/local/sbin` copy differs from the
checkout, and — because `warp-routes.service` *executes*
`vpn-bot-warp-routes` — it runs `systemctl daemon-reload && systemctl restart
warp-routes.service` whenever that helper changed and the unit was active before
the deploy. So a normal `sudo bash scripts/redeploy.sh` keeps `/usr/local/sbin`
in sync automatically; you no longer install these by hand after a deploy.

> **Why this step exists (the drift it closes).** The helpers' tracked source
> lives in the checkout, but the installed copy lives out-of-repo under
> `/usr/local/sbin`. `git reset --hard` advances the source and **never** the
> installed copy, so before this step a `git reset` left the stale
> `/usr/local/sbin/vpn-bot-warp-routes` in place — which is exactly how the broken
> routing helper kept running after the source was fixed, taking
> `warp-routes.service` down. Phase 2 now closes that drift structurally; the
> `PHASE1_ONLY=1` / `CHECK=1` report lists any helper drift it *would* refresh, as
> information only (there is no `ALLOW_*` override for it — it is not a gate).
> `deploy/setup-nonroot-helper-mode.sh` also still installs (and refreshes) these
> four helpers, for first-time setup and for hosts provisioned outside the deploy
> script; the `install` commands above remain the manual equivalent.
>
> The restart runs the helper's counter self-check (#242). On an idle client the
> data-plane probe **skips** (an idle tunnel is not a broken one) and the helper
> still exits `0`, so a skipped probe never fails the deploy; only a genuine
> routing failure (non-zero exit) does, and that triggers the normal rollback.

### Ownership model: systemd owns the interface and routes; the bot only observes

The `out-warp` interface and its policy routes have **one** owner: **systemd**.
The interface is brought up by the stock `awg-quick@out-warp.service`; the policy
rules, the dynamic routing table's default route (table number read at runtime from
`awg show out-warp fwmark`, never hardcoded) and per-daemon marks by
`warp-routes.service`. The
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

- `vpn-bot-warp-install install <staged_config>` — validates the AmneziaWG format
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
- `vpn-bot-warp-install remove` — deletes `/etc/amnezia/out-warp.conf`,
  `/etc/amnezia/out-warp-routes.list` and the
  `/etc/amnezia/amneziawg/out-warp.conf` symlink from disk. Called by
  `delete_config` to ensure the PrivateKey does not persist after config removal.
- `vpn-bot-warp-iface {up|down} /etc/amnezia/out-warp.conf` — runs
  `awg-quick up|down` (AmneziaWG, **not** `wg-quick`).
- `vpn-bot-warp-routes {add|del} out-warp` — installs the production-proven policy
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
  and rolls back to direct client egress on failure. The self-check confirms the
  **host** is NOT in the tunnel (host route + `warp=off` curl trace) and the client
  routing is installed (rule + tunnel-table default), then **observes the tunnel's
  byte counters** to confirm real client egress. It deliberately never simulates the
  client path with `ip route get`: that mark is set from **conntrack**, which the
  stateless `ip route get` cannot reproduce, so it would report false negatives. A
  quiet tunnel (no live client) skips the data-plane check rather than failing.
  Every add step is idempotent. `del`
  reverses everything, restores the direct WAN `MASQUERADE` for the client subnet
  and is safe on a clean system; it never restores the host-bypass (the host must
  always stay direct). The table number and endpoint are always resolved at
  runtime. Forwarding **Dante/Xray/MTProto** through WARP is out of scope here —
  this helper diverts AmneziaWG clients only.
- `vpn-bot-warp-status out-warp` — runs `awg show out-warp`.

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

1. Install helpers and `/etc/sudoers.d/vpn-bot` with the ownership and modes above.
2. Validate sudoers with `visudo -cf /etc/sudoers.d/vpn-bot`.
3. Set `PRIVILEGE_HELPERS_ENABLED=true` and `BOT_LOCK_PATH=/run/vpn-bot/vpn-bot.lock`.
4. Install `deploy/vpn-bot.nonroot.example.service` as the active non-root unit. (The shipped `deploy/vpn-bot.service` is the root+api default; if you install from it instead, edit it to the non-root profile — `User=vpn-bot`, `Group=vpn-bot`, `ProtectSystem=strict`, `ReadWritePaths` — first.)
5. Run `python deploy/check-nonroot-helper-mode.py` before and after restarting the service.
6. Run a staged issue/revoke test for Xray, AWG, SOCKS5, and managed MTProxy.

Emergency rollback from non-root mode is to restore the backed-up pre-cutover unit and matching `.env`, disable `PRIVILEGE_HELPERS_ENABLED`, and restart `vpn-bot`.
