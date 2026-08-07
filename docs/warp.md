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
  out-warp` route **and the table default `default dev out-warp`** are retracted, and
  the direct-WAN `MASQUERADE` for the client subnet and the proxy source plus the
  `awg0 <-> <wan>` FORWARD accepts are (re)installed idempotently (`-C … || -A/-I`),
  so all client/proxy traffic egresses direct and NATed. The saved list
  (`/etc/vpn-bot/warp-split.list`) is **not erased**, and the anti-loop
  `162.159.195.1/32 via eth0-gw` and the `ip rules` are left untouched.

  Both halves matter on the **boot path**, where this runs after `awg-quick@out-warp`
  (`Table=auto` planted `default dev out-warp` in table `T`) and after
  `vpn-bot-warp-routes` (which swapped the NAT: dropped the direct
  `-s 10.0.0.0/24 -o <wan> -j MASQUERADE`, added `-o out-warp -j MASQUERADE`).
  Retracting only the per-prefix routes there would leave the tunnel default in place
  — "off" would silently be a **full tunnel** — while dropping the default without
  restoring the NAT would send clients out of the WAN un-masqueraded.
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
subnet, its default gateway, and **the live WARP endpoint**) are rejected,
duplicates are skipped, and emptying the list is refused. The bot never calls
`ip`/`iptables` — writes go only through the privileged helper.

The endpoint guard is the one worth understanding. `vpn-bot-warp-split` pins
`<endpoint>/32 via <gw> dev <wan>` into table T *before* it installs the per-prefix
routes, and it installs them with `ip route replace` — so an exact `<endpoint>/32`
in the list overwrites that pin and sends the tunnel's own packets into the tunnel.
A supernet covering the endpoint does not overwrite the pin (longest-prefix keeps it
winning) but is rejected too, because it becomes a loop the moment the endpoint
moves. The endpoint is read through `vpn-bot-warp-status` (already in the sudoers
allowlist, so no new privilege is granted) and the last value seen is remembered, so
a momentarily unreachable tunnel does not quietly drop the guard.

Every mutation is a read-modify-write under one lock, shared with the feed
refresher below: the list is a single file with no compare-and-swap, so two
concurrent "add a prefix" flows would otherwise each read N entries and write N+1,
losing one of the two additions with no error anywhere.

The helper installs the routes with `ip -batch -` (and reconciles stale ones with
`ip -force -batch -`) rather than one `ip` process per prefix. Feeds make lists
large enough for that to matter: measured on this host, installing 1500 prefixes
takes **4.275 s** as separate processes and **0.096 s** as a batch; the live
108-prefix apply went from 0.385 s to 0.098 s. The semantics are unchanged — the
delete phase keeps `-force`, which continues past a route that raced away, exactly
as the old per-command `|| true` did, while the add phase uses plain `-batch`,
which aborts at the first failure just as the loop did under `set -e`.

### Prefix feeds (automatic list updates)

Beyond hand-typed CIDRs, the split list can be assembled from published prefix
feeds. **Источники** ("Sources") in the split panel lists them with their state,
prefix count, last refresh and last error, and offers Refresh now / On / Off /
Add URL / Delete.

Three sources ship pre-configured:

| Slug | Feed | Mode | Default |
| --- | --- | --- | --- |
| `telegram-cidr` | `core.telegram.org/resources/cidr.txt` | add | enabled |
| `google-goog` | `gstatic.com/ipranges/goog.json` | add | **disabled** |
| `google-cloud` | `gstatic.com/ipranges/cloud.json` | subtract from `google-goog` | **disabled** |

Both Google rows ship off deliberately. `goog.json` is *everything* Google
announces, which includes the GCP customer ranges — turning it on alone routes
other people's cloud servers through your tunnel. `cloud.json` is exactly those GCP
ranges, so subtracting it leaves Google's own services (search, YouTube, gstatic,
Gmail). The panel warns when you enable `goog` without `cloud`.

**Subtraction happens over addresses, not strings.** `cloud.json`'s prefixes are
subnets *inside* `goog.json`'s, so a textual set-difference would remove almost
nothing (7 of 99 entries on the real data) and silently leave every GCP range
routed. The merge uses `ipaddress.address_exclude`, which means it also
**fragments**: measured on 2026-08-06, `goog − cloud` turns 99 prefixes into
**262**, and `collapse` cannot put them back because the holes are real. The panel
shows the before/after counts, and `WARP_SPLIT_MAX_PREFIXES` refuses the whole
update if the result is too large — the rejection names the subtraction that caused
it and offers the two ways out (raise the cap, or drop the subtraction and take the
base source whole).

Order of evaluation:

```
result = collapse( union(add sources, manual) - subtract sources - exclusions )
```

A subtract source with a **scope** applies only to that one source's contribution;
without a scope it applies to the whole merged set. Manual exclusions are the same
mechanism at the same step. A source may not subtract from itself, and chains of
subtraction deeper than one level are rejected when the source is added.

Note the consequence of a scope: if the same prefixes also exist as *manual*
entries — which is the case on a host whose list was originally seeded by hand from
`goog.json` — the scoped subtraction is inert, because the manual copies
re-introduce exactly the ranges being carved out. The panel offers **«Перенести
manual → feed»**, which drops the manual prefixes an enabled add-source already
covers. It is a manual action with a delta preview and a confirmation; nothing is
migrated automatically.

Failure behaviour, in one line: **a feed failure never shortens the list.** Network
error, HTTP 500, oversized body, malformed document and empty response are all
treated identically — the error is recorded on the source row, an alert goes to the
admins, and the merge uses that source's last good contribution from
`WARP_SPLIT_FEED_CACHE_DIR`. A source that is enabled but has *never* succeeded
aborts the merge entirely rather than contributing nothing, because "base fresh,
subtrahend empty" is precisely how all of GCP would end up in the tunnel.

Deleting a feed-supplied prefix with 🗑 records an **exclusion** instead of deleting
it — a plain delete would be undone by the next refresh. Exclusions survive
refreshes.

### Supervised refresh (review and auto)

The scheduler answers *when* a refresh runs; `WARP_SPLIT_FEEDS_MODE` answers what a
run is allowed to **do**. They are separate switches because turning automation on
and trusting it to write unattended are separate decisions, and only one of them is
undone by reading a message.

| Mode | What a run does |
| --- | --- |
| `off` | Applies nothing. Only the panel's buttons touch the list. |
| `review` (default) | Runs the full cycle — fetch, merge, analysis — and applies **nothing** on its own. Every non-empty delta, including one that passes every threshold and including pure re-aggregation, goes to the admins as a card and waits. |
| `auto` | Applies a change that clears the ratchet *and* the confirmation streak. Everything else goes to the same card. |

Interval `0` disables the run at any mode; `off` disables applying at any interval.

#### The metric: addresses, not prefixes

Every threshold below is computed on **address counts** (the sum of `2^(32−len)`
after collapsing), per source and for the merged list. Prefix counts are unusable as
a safety metric because `collapse` merges adjacent siblings: on this host, adopting
the 108-entry list file produces **106** prefixes covering byte-identical address
space. A prefix-count threshold would call that a change — and a subtraction that
quietly halves a feed's coverage while keeping its entry count no change at all.

That specific case has a name in the code: **pure aggregation** (identical
addresses, different prefix count). In `auto` it is applied without waiting for the
confirmation streak, because there is nothing to confirm; in `review` it still goes
to the card, because `review` means every change is applied by hand.

#### The ratchet

The comparison point is the **last state that was actually applied** — stored in
`warp_split_baseline`, one row per source plus one for the merged list — not the
previous run's candidate. A feed that loses 5% of its coverage on each of four runs
is caught on the fourth, because it is still being measured against the state a
human accepted.

A candidate is held for approval when any of these is true:

* an **add** source lost more than `WARP_SPLIT_MAX_SHRINK_PCT` of its coverage;
* a **subtract** source lost more than the same threshold — checked separately and
  reported in its own words, because the direction is mirrored: less subtracted
  means *more* foreign address space in the tunnel. On the Google pair, a shrunken
  `cloud.json` silently re-admits every GCP customer range it stopped listing;
* the merged list would **grow** by more than `WARP_SPLIT_MAX_GROWTH_PCT`;
* a source published **no usable prefix** on this run (the merge still succeeds from
  cache — which is exactly why this has to be noticed rather than inferred);
* any enabled source's last successful fetch is older than
  `WARP_SPLIT_FEED_STALE_AFTER_SEC`, which makes the whole state incomplete.

The baseline moves **only when an apply actually happens** — including an apply made
from the panel or a `/warp_split_*` command, which the next run detects by hash and
adopts. Declining a card does not move it; if it did, a shrink refused today would be
the accepted baseline tomorrow, and the ratchet would be decoration.

#### What is *not* queued

The manager's guards — the prefix cap, the minimum mask, the WARP endpoint, the
default gateway, the server's own WAN, the AWG subnet — reject a candidate outright.
Those are not "suspicious changes" but invalid ones, so they produce a rejection
notice and no card: a button offering to apply a list the manager will refuse anyway
is a button that teaches admins to distrust buttons.

#### The card, and what pressing Apply does

The card names the mode, lists every reason the change is held (or states that
nothing suspicious was found, in `review`), gives before/after in prefixes **and**
addresses for the list and for each source, and shows the first ten prefixes each way
behind a "show in full" button.

Apply takes exactly the path a manual apply takes: the merge is recomputed under the
list lock, the guards run again, the byte-identity check still applies. The one
addition is a hash check inside that recompute — if the merge no longer produces the
list the card described (someone added a prefix in another chat, a feed moved on),
nothing is written and the admin is told to recompute and decide again. Checking
outside the lock would be a race; checking inside it is what stops a stale card from
applying something nobody looked at.

#### Notifications

Admins hear about: a candidate queued for approval, a change that was applied
(briefly: ±N prefixes, ±N addresses, per source), a rejection by a guard, a source
that has failed `WARP_SPLIT_FEED_FAIL_STREAK` runs in a row, and a source that has
gone stale. They do **not** hear "nothing changed" — that goes to the log only.

Identical messages about the same source are suppressed for
`WARP_SPLIT_ALERT_COOLDOWN_SEC`. That ledger is held **in memory**: a bot restart
clears it, so the first run after a restart can repeat one message the admin already
has. This is deliberate — persisting it would buy one avoided duplicate at the cost
of a table whose staleness nobody would ever think about again. Approval cards are
never suppressed by the cooldown, but re-queuing the *same* candidate does not send a
second card, and replacing a waiting candidate with a new one sends one message
rather than two.

#### The run journal

Every run writes a row to `warp_split_runs`: timestamp, mode, per-source status and
metrics, and one of `applied | queued | nochange | rejected | failed` with a reason.
(`nochange` means the host was not touched — either there was no delta, or `auto` is
still waiting for the streak.) The last 200 rows are kept, trimmed by the same run
that writes them; «Источники» → «История» shows the last ten.

This is the evidence for the decision the modes exist to support. Recommended order
for turning automation on:

1. set `WARP_SPLIT_FEEDS_MODE=review` and an interval (`21600` = 6 h);
2. live with it for a week or two, reading the history: how many changes were there,
   and did each one look safe?
3. when the answer is yes for all of them, switch to `auto`.

#### Feed environment variables

| Variable | Default | Meaning |
| --- | --- | --- |
| `WARP_SPLIT_FEEDS_INTERVAL_SEC` | `0` | Unattended refresh interval; `0` disables the scheduler. Manual refresh from the panel always works. |
| `WARP_SPLIT_FEEDS_MODE` | `review` | What a run may do: `off` / `review` / `auto` (above). |
| `WARP_SPLIT_FEED_TIMEOUT_SEC` | `20` | Per-fetch total timeout. |
| `WARP_SPLIT_FEED_MAX_BYTES` | `2000000` | Response ceiling; a larger body is a failed fetch. `cloud.json` is ~112 KB. |
| `WARP_SPLIT_FEED_CACHE_DIR` | `/var/lib/vpn-bot/warp-feeds` | Last good copy of each feed (files `0600`, directory `0700`). |
| `WARP_SPLIT_MAX_SHRINK_PCT` | `20` | Coverage a source may lose before its change is held for approval. Add and subtract sources alike. |
| `WARP_SPLIT_MAX_GROWTH_PCT` | `50` | Coverage the merged list may gain before the change is held. |
| `WARP_SPLIT_CONFIRM_STREAK` | `2` | `auto` only: identical candidates in a row before applying. |
| `WARP_SPLIT_FEED_STALE_AFTER_SEC` | `259200` | Age of a source's last success past which the state counts as incomplete. |
| `WARP_SPLIT_ALERT_COOLDOWN_SEC` | `3600` | De-duplication window per source and message (in memory). |
| `WARP_SPLIT_FEED_FAIL_STREAK` | `3` | Consecutive failures of one source before alerting. |
| `WARP_SPLIT_MAX_PREFIXES` | `1500` | Hard ceiling; exceeding it refuses the whole update, never part of it. |
| `WARP_SPLIT_MIN_PREFIXLEN` | `8` | Shortest accepted mask. |

`WARP_SPLIT_FEED_ALERT_DELTA_PCT` was **removed** in this version. It notified when
an automatic refresh changed the list by more than N% of its prefix *count*; both
halves of that job are now done better — every applied change is announced, and a
large change is held rather than applied — and keeping a third threshold on a third
metric would have cost more clarity than it bought. A leftover value in `.env` is
ignored.

The scheduler defaults to **off**. Enabling it lets a background job rewrite the
routing policy for every client, which should be a decision rather than something
inherited from an upgrade. With no scheduler and no feed enabled, deploying this
subsystem leaves `/etc/vpn-bot/warp-split.list` byte-for-byte unchanged and makes no
helper call at all — the manager renders the candidate list, compares it against the
file, and skips the apply when they match. The scheduler's first run is also delayed
rather than immediate, so a restart loop cannot become a policy loop.

Conditional GET is used where the feed supports it, and the two real feeds disagree:
`core.telegram.org` serves an `ETag` *and* a `Last-Modified`, `gstatic.com` serves
`Last-Modified` only. Whichever validators are held get sent, and a 304 from either
means "no change".

#### Adding your own source

**Источники → Добавить URL**, then supply a slug, a title, the URL and the format
(`cidr_text` for one CIDR per line with `#`/`;` comments, `google_json` for the
gstatic `prefixes[].ipv4Prefix` shape). New sources start disabled; enable one and
use Refresh now to see the delta before it is applied. IPv6 entries are dropped
silently — this host has no IPv6.
