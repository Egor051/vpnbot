# WARP Outbound IP Masking

Optional server-side module that masks the server's outbound IP for selected
applications (e.g. data-harvesting "spy" apps): it routes their traffic through
an AmneziaWG (`out-warp`) tunnel so their connections leave from the tunnel
endpoint instead of the real server IP, and automatically falls back to the
direct path when the tunnel is unreachable. It is **disabled by default** and
does nothing until a superadmin uploads a config and enables it from the admin
panel (📡 WARP tunnel).

All WARP environment variables are documented in
[Configuration → WARP Outbound IP Masking](configuration.md#warp-outbound-ip-masking).

## How it works

1. `awg-quick up` brings the `out-warp` interface up from `/etc/amnezia/out-warp.conf`.
2. System `ip route` entries are added for the CIDRs in the config via `out-warp`.
3. An asyncio background task pings the tunnel every 10 s, speeding up to every 3 s the
   moment a probe gets no response. After **60 s** of continuous no-response the routes
   are removed (traffic → direct); after **60 s** of continuous success they are restored.
4. Disabling the module removes the routes and brings the interface down.

> **Steps 1–4 describe the legacy (non-observer) mode.** The production default is
> **observer mode** (see below), where systemd owns the interface and routes and the
> bot never adds/removes them.
>
> **Failure semantics differ by mode.** In legacy mode a tunnel-down *removes* the
> routes, so masked traffic falls back to the **direct path and exits on the real
> server IP** — availability over masking. If you need the opposite (fail-closed),
> turn on the **kill-switch** (⚙️ Settings): on a tunnel-down the routes are *kept*,
> so masked traffic blackholes on the dead interface instead of leaking the real IP.
> The kill-switch is **off by default** and only enforces in legacy mode — in observer
> mode the routes are systemd-owned and any fail-closed behaviour comes from
> `warp-failsafe`, not the bot.
>
> Independently of the routes, a **degraded** detector watches a sliding window of
> recent probes and alerts the admins when the tunnel keeps dropping probes without
> ever failing *continuously* (so the down latch never trips). This alert is
> observability-only — it never removes routes, and a single dropped probe can never
> raise it.

The bot runs unprivileged: every root action goes through the `vpn-bot-warp-*`
sudo helpers. The server DNS resolver is never touched. Default routes
(`0.0.0.0/0`, `::/0`) in `AllowedIPs` are silently skipped by the routes helper
to prevent accidental host isolation — the helper logs a warning when it skips
them. If you need full-tunnel routing, configure a separate routing table and
policy rules outside the bot instead of relying on `AllowedIPs`.

## Config format

Upload an **AmneziaWG** client config (not plain WireGuard) as a `.conf`
document. It must contain `[Interface]`/`[Peer]`, `PrivateKey`/`PublicKey`/
`Endpoint`, the AmneziaWG obfuscation fields (`Jc`, `S1`, `S2`, …) and a
non-empty `AllowedIPs`. The module diverts **every AmneziaWG client**
(`10.0.0.0/24`) out through the tunnel so the clients' outbound IP is the WARP
endpoint instead of the real server IP, while the host itself (SSH, the bot,
updates) always stays on the direct path. Use a full-tunnel `AllowedIPs =
0.0.0.0/0, ::/0` so `Table = auto` builds the tunnel's default route. `AllowedIPs`
is never modified: the install helper extracts it verbatim into
`/etc/amnezia/out-warp-routes.list` (one CIDR per line, kept for the admin-panel
route count).

> **Note:** the host is protected by design — `vpn-bot-warp-routes` strips the
> awg-quick host-bypass immediately after the interface comes up and installs a
> single narrow `from 10.0.0.0/24` policy rule, so a full-tunnel `AllowedIPs`
> never pulls the host (or your SSH session) into the tunnel. The helper
> self-checks this — it confirms the host is NOT tunneled and then **observes the
> `out-warp` byte counters** (real client traffic) rather than simulating the
> client path with `ip route get`, which cannot see the conntrack-set mark — and
> rolls back to direct client egress if the host is ever captured.

On install the helper strips any `DNS = …` line, forces `Table = auto` on
`[Interface]` (mandatory — it sets the WG-socket fwmark and the dynamic routing
table; the old `Table = off` caused a routing loop) and adds
`PersistentKeepalive = 25` to `[Peer]` if missing.

## Installation

`awg-quick`/`awg` (AmneziaWG userspace tools) must be installed at
`/usr/bin/awg-quick` / `/usr/bin/awg`. Install the helpers and grant sudo
(see [`../deploy/helpers/README.md`](../deploy/helpers/README.md) and `deploy/sudoers.d/vpn-bot.example`):

```bash
install -o root -g root -m 0755 scripts/vpn-bot-warp-install /usr/local/sbin/vpn-bot-warp-install
install -o root -g root -m 0755 scripts/vpn-bot-warp-iface   /usr/local/sbin/vpn-bot-warp-iface
install -o root -g root -m 0755 scripts/vpn-bot-warp-routes  /usr/local/sbin/vpn-bot-warp-routes
install -o root -g root -m 0755 scripts/vpn-bot-warp-status  /usr/local/sbin/vpn-bot-warp-status
install -o root -g root -m 0440 deploy/sudoers.d/vpn-bot.example /etc/sudoers.d/vpn-bot
visudo -cf /etc/sudoers.d/vpn-bot
```

If `awg-quick` is missing, the module refuses to start and shows a clear error in
the admin panel.

## Interface/route ownership (observer mode)

In the default observer mode there is a single owner for the `out-warp` interface and its
policy routes: **systemd**. The interface is brought up by `awg-quick@out-warp.service` and
the policy rules/routes by `warp-routes.service`; the bot's health monitor is a pure observer
that reports tunnel state but never runs `awg-quick`, `ip route`, or `ip rule`. This removes
the flapping that occurred when both the boot-time `warp-routes.service` and the bot fought
over the same `ip rule`/`ip route` entries. Enabling/disabling the WARP toggle in the admin
panel now starts/stops **only** the observer monitor — it no longer drops the tunnel or wipes
the routes.

Deploy both units (interface first, then the routes that ride on it):

```bash
# awg-quick resolves "out-warp" to /etc/amnezia/amneziawg/out-warp.conf; the install
# helper writes /etc/amnezia/out-warp.conf, so point the awg-quick name at it once:
mkdir -p /etc/amnezia/amneziawg
ln -sf /etc/amnezia/out-warp.conf /etc/amnezia/amneziawg/out-warp.conf
systemctl enable --now awg-quick@out-warp
systemctl enable --now warp-routes.service
```

### Keep the routing rules alive: reassert timer + networkd drop-in

`warp-routes.service` installs the WARP source rules **once** at boot. Anything that
later flushes the routing-policy rules leaves the tunnel and its table healthy while
client traffic silently egresses direct — the tunnel looks fine, so nothing alerts.
The concrete trigger seen in production (2026-07-24) was **systemd-networkd**: it
defaults to `ManageForeignRoutingPolicyRules=yes` and, on any (re)start, removes every
`ip rule` it did not create — including WARP's `from <client-subnet>` /
`from <tunnel-ip>` rules. Two additive, non-destructive safeguards close that gap.

> **deploy.sh does not auto-install these** (it only installs `vpn-bot.service`
> itself; every other unit is reported as drift for a conscious `install`). Phase 1
> *sees* them — both are in `deploy/managed-units.list` and the informational
> networkd check runs on every deploy — but you apply them by hand:

```bash
# 1. Stop networkd from flushing WARP's foreign ip rules (primary fix).
install -o root -g root -m 0644 deploy/networkd/10-keep-foreign-rules.conf \
    /etc/systemd/networkd.conf.d/10-keep-foreign-rules.conf
systemctl restart systemd-networkd
# verify it merged into the effective config:
systemd-analyze cat-config systemd/networkd.conf | grep -i ManageForeign

# 2. Belt-and-braces: reassert the source rules every 5 minutes. `reassert` is
#    idempotent and ADD-ONLY (never a teardown), so it is safe against live clients.
install -o root -g root -m 0644 deploy/warp-routes-reassert.service /etc/systemd/system/warp-routes-reassert.service
install -o root -g root -m 0644 deploy/warp-routes-reassert.timer   /etc/systemd/system/warp-routes-reassert.timer
systemctl daemon-reload
systemctl enable --now warp-routes-reassert.timer
```

Why a separate `reassert` verb instead of `systemctl restart warp-routes.service`?
`warp-routes.service` has `ExecStop=… del out-warp`, so a restart runs the full
teardown and briefly **removes** the client rule + NAT before re-adding them — a
multi-second window with no WARP path for connected clients. Unacceptable on a
five-minute cycle. `reassert` only re-delivers what is missing and tears nothing
down. The bot's health monitor also watches for the source rules directly now: if
they vanish it reports `routes_active=false` and raises a degraded alert (observer
mode — it reports, systemd owns the repair via the timer).

## WARP proxy egress (masking the proxies' outbound IP)

By default WARP diverts only the AmneziaWG **client** subnet (`10.0.0.0/24`). The
local egress proxies — Dante SOCKS5, Xray VLESS, MTProto — keep leaving from the
host's real IP. Enabling **proxy egress** routes those proxies through the tunnel
too, so their outbound IP is masked just like the clients'.

A local proxy cannot be matched by source subnet: its packets carry the host's real
IP, and `MASQUERADE -o out-warp` does **not** rewrite locally-generated,
fwmark-rerouted packets (they would enter the tunnel with the host IP and WARP would
drop them). The fix makes the inner source equal to the tunnel IP
(`[Interface] Address`, e.g. `172.16.0.2`) two ways:

- **Source-bind daemons** (Dante, Xray) bind their egress source to the tunnel IP;
  `vpn-bot-warp-routes` then adds a single `ip rule from <tunnel-ip> lookup <T>` and
  needs **no** NAT (the source is already correct):
  - **Xray** — bot-managed. `config.json` is rewritten by the bot, so a hand-added
    field is lost; instead set `WARP_PROXY_EGRESS_ENABLED=true` and the config writer emits
    `"sendThrough": "<tunnel-ip>"` on the **freedom outbound** on every write (only
    the outbound is touched — the hybrid REALITY/XHTTP inbounds are untouched).
  - **Dante** — *not* bot-managed (a prerequisite). Edit `/etc/danted.conf` and set
    `external: 172.16.0.2` (the tunnel IP) in place of the WAN device, then install
    the ordering drop-in `deploy/danted-warp.conf` so it starts after the tunnel is
    up.
- **MTProto / mtg** cannot source-bind. `vpn-bot-warp-routes` cgroup-marks its unit's
  egress (`fwmark 0x2`) and adds an **explicit SNAT** to the tunnel IP, inserted
  *above* the broad `out-warp` MASQUERADE. Because the `-m cgroup --path` match needs
  the daemon's cgroup to exist, the unit drop-in `deploy/mtproxy-warp.conf` re-asserts
  it from a privileged `ExecStartPost` once mtg is running.

The tunnel IP is never hardcoded — both `vpn-bot-warp-routes` and the Xray writer read
it from the config's `[Interface] Address`. The `add`/`del` recipe is idempotent and
safe when a proxy daemon is absent.

> ⚠️ **Activation is a manual, host-routing change** — a mistake that drops SSH means
> a reboot. Flip from the legacy hand-rolled `warp-clients.service` to the bot/systemd
> schema deliberately, off-hours, with console access:
>
> 1. Back up the working setup (`.WORKING` snapshot).
> 2. `deploy/setup-nonroot-helper-mode.sh` — refresh the helpers in `/usr/local/sbin`.
> 3. Re-install the tunnel config so `[Interface]` carries `Table = auto`
>    (`vpn-bot-warp-install`).
> 4. Set the proxy source-binds: `external: 172.16.0.2` in `danted.conf`;
>    `WARP_PROXY_EGRESS_ENABLED=true` in `.env` (Xray `sendThrough` is then emitted by the bot).
> 5. Install the ordering drop-ins:
>    ```bash
>    install -m 700 -d /etc/systemd/system/danted.service.d
>    install -m 644 deploy/danted-warp.conf  /etc/systemd/system/danted.service.d/vpn-bot-warp.conf
>    install -m 700 -d /etc/systemd/system/mtproxy.service.d   # only if MTProto is enabled
>    install -m 644 deploy/mtproxy-warp.conf /etc/systemd/system/mtproxy.service.d/vpn-bot-warp.conf
>    systemctl daemon-reload
>    ```
> 6. `systemctl disable --now warp-clients.service` (the legacy schema), then
>    `systemctl enable --now awg-quick@out-warp warp-routes.service`.
> 7. **Reboot** (do not live-restart — the host-routing flip can drop the SSH window),
>    then verify: the host reports `warp=off` and SSH is alive, while
>    AWG / Dante / Xray (and MTProto if enabled) report `warp=on`
>    (`curl -s https://www.cloudflare.com/cdn-cgi/trace`).
> 8. **Rollback:** re-enable `warp-clients.service`, restore the `.WORKING` snapshot
>    and reboot.

## WARP selective-split and boot-failsafe activation

The selective-split layer routes only the prefixes in `/etc/vpn-bot/warp-split.list`
through WARP; everything else exits directly via `eth0`. The boot-failsafe watchdog
prevents a misconfigured tunnel from locking out SSH after a reboot.

Both features are **additive** on top of the full-tunnel base (`warp-routes.service`).
`AllowedIPs = 0.0.0.0/0` stays in `out-warp.conf` — split routing is handled entirely
in the routing table, not in WireGuard.

**Prerequisites:** `awg-quick@out-warp` and `warp-routes.service` already enabled and
tested (full-tunnel working).

### Activation runbook

1. **Base full-tunnel** — enable and start the tunnel if not already running:

   ```bash
   sudo systemctl enable --now awg-quick@out-warp warp-routes.service
   ```

2. **Install the new layer** (run from the repo root as root):

   ```bash
   sudo bash deploy/setup-nonroot-helper-mode.sh
   ```

   This installs `vpn-bot-warp-split`, `warp-failsafe`, their unit files, reloads
   systemd, and updates the danted drop-in (removing the stale `10-after-warp.conf`).
   It does NOT auto-enable either unit.

3. *(Optional)* **Enable selective-split:**

   ```bash
   sudo cp deploy/warp-split.list.example /etc/vpn-bot/warp-split.list
   # Edit the list — add/remove CIDRs to taste. Broad ranges preferred over /32s.
   sudo systemctl enable --now vpn-bot-warp-split
   ```

4. **Enable the boot-failsafe** (always recommended):

   ```bash
   sudo systemctl enable warp-failsafe
   ```

5. **Reboot** and verify:

   ```bash
   # Host egress must be direct (eth0), not through the tunnel
   ip route get 1.1.1.1          # → dev eth0

   # Selective routing table (T = decimal of `awg show out-warp fwmark`):
   T=$(printf '%d\n' "$(awg show out-warp fwmark)")
   ip route show table "$T"      # no 'default dev out-warp'; prefixes visible

   # Client traffic: listed prefix → out-warp, non-listed → eth0
   ip route get 91.108.4.1  iif awg0   # → dev out-warp
   ip route get 8.8.8.8     iif awg0   # → dev eth0 (if 8.8.8.0/24 not listed)

   # Proxy services running
   sudo systemctl is-active danted
   ```

6. **Confirm WARP transfer increases** on a Telegram fetch:

   ```bash
   awg show out-warp transfer
   # fetch any Telegram content; re-check — rx/tx counters must grow
   ```

### Rollback

- **Selective-split only:** `sudo systemctl disable --now vpn-bot-warp-split` then
  reboot → returns to full-tunnel (every client prefix exits via WARP again).
- **Full WARP rollback:** `sudo systemctl disable --now warp-routes awg-quick@out-warp`
  then reboot.

### On/Off/Restart buttons (split ROUTING control)

The **Enable / Disable / Restart** buttons in the «Outbound IP masking» panel act
on the split **routes** in the dynamic table `T`, NOT on the tunnel: the `out-warp`
interface and the `awg-quick@out-warp` process stay owned by systemd (observer
model) and the bot never touches them.

- **Disable** — reconcile table `T` to empty: every per-prefix `<prefix> dev
  out-warp` route is retracted and all client/proxy traffic egresses direct. The
  saved list (`/etc/vpn-bot/warp-split.list`) is **not erased**, and the anti-loop
  `162.159.195.1/32 via eth0-gw`, the `ip rules` and the NAT/FORWARD chains are
  left untouched.
- **Enable** — reconcile table `T` back to the saved list (selective).
- **Restart** — flush then re-apply the list (final state: enabled).

The on/off state is **persistent**: "disable" writes a root-owned marker
(`/etc/vpn-bot/warp-split.disabled`) that `vpn-bot-warp-split` honours on every
boot-apply, so an "off" state survives a reboot. All table-`T` mutation goes through
`vpn-bot-warp-split-state` (sudoers grants the exact `on|off|restart|status` verbs,
no wildcard). The panel's Tunnel (observer) and Routes (marker intent + actual table
`T`) lines come from `status()`; a drift between intent and reality is shown as a
warning and the status never fails in any state. When the actual table `T` cannot be
read, the Routes line is shown with a "(actual table not read)" note rather than
being presented as a confirmed in-sync state.

### Kill-switch (fail-closed on tunnel-down)

The **⚙️ Settings** sub-panel has a **🛡 kill-switch** toggle, persisted in
`warp_settings.kill_switch` and **off by default**. When on, a tunnel-down in legacy
(non-observer) mode keeps the routes in place so masked traffic blackholes on the
dead interface instead of falling back to the direct path and leaking the real
server IP. It is a bot-side control and therefore only enforces in legacy mode; in
observer mode the routes are owned by systemd, so fail-closed behaviour there is the
job of `warp-failsafe`.

### Managing the split list from the bot (superadmin)

Once `vpn-bot-warp-split` is active, the prefix list can be managed from Telegram —
no SSH required:

- **GUI:** the **WARP settings** sub-panel (⚙️ Settings) has a **🌐 Split routes**
  button that opens a paginated panel (≈8 prefixes per page, each with a 🗑 button),
  plus **➕ Add** (send one or more IPv4 CIDRs separated by spaces/commas/newlines),
  **🔄 Apply** (re-apply the current list), and a Yes/No confirmation before each
  delete. (The entry point moved here from the main WARP panel; Back returns to
  Settings.)
- **Commands:** `/warp_split_list`, `/warp_split_add <cidr…>`,
  `/warp_split_del <cidr…>`, `/warp_split_reload`.

Both paths are pure presentation over `WarpSplitManager`: input is IPv4-only with a
mandatory mask, host bits are normalised, guard ranges (`0.0.0.0/0`, the AWG client
subnet, `172.16.0.0/12`, loopback/link-local/multicast, the server's own `eth0`
subnet) are rejected, duplicates are skipped, and emptying the list is refused. The
bot never calls `ip`/`iptables` — writes go only through the privileged helper.
