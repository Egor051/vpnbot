# Relay ("via relay" keys)

A **relay** is a second entry point into this server: a small VPS (here: in Russia)
that forwards client traffic at L4 to the main server. A key issued "via relay" is an
ordinary key whose link points at the relay instead of the main host. There can be
**several relays**; they are managed in the bot's admin panel (**🛡 Админ-панель →
🧩 Протоколы и маршрутизация → 🛰 Управлять relay**) and stored in the `relays` table of `vpn.db`. With no relay in
the table the feature is invisible. A new relay is installed fastest
[with one command from the bot](#installing-a-relay-with-one-command).

## Topology

```
client ──TCP+UDP/443──▶ relay (RU VPS)
                          nftables DNAT tcp+udp dport 443 → <main server>:443
                                         │
                                         ▼
                    main server :443 ── xray vless-in (REALITY)
                                         ├─ XHTTP fallback → vless-xhttp-reality
                                         └─ (UDP) hysteria2
```

- The relay rewrites only the destination (DNAT) and masquerades the source, so the
  main server sees every relayed connection as coming from the **relay's egress IP**.
  There is no PROXY protocol — the client's real address never reaches the server.
- A relayed client lands in the **same inbounds** as a direct one: VLESS (TCP) and
  every VLESS (HTTP) profile on vless-in :443, Hysteria2 on UDP/443. Nothing on the
  main server is relay-aware.
- The relay host itself (nftables tables, `ip_forward`, its systemd unit) is deployed **from
  this repository** with the same `scripts/redeploy.sh`, in the host role
  `NODE_ROLE=relay` — see [The relay host](#the-relay-host-node_rolerelay).

### DNS — use a name, not an address

Point a DNS name at the relay — e.g. `relay.anycastedge.net` — in Cloudflare with
**proxying off** (DNS only, grey cloud): Cloudflare's HTTP proxy cannot carry
REALITY or QUIC. Use that name as the relay's **host**.

This matters because a single key's link carries the host verbatim. If the host is a
name, moving the relay to a new IP is an A-record change and no key has to be
re-imported. If the host is an IPv4 address, changing it in the panel immediately
re-points **subscriptions** (they are rendered on every fetch), but every **single
relay key** a user imported as a link still holds the old address and has to be
re-imported — the panel says how many there are when the host changes.

## The relay host (`NODE_ROLE=relay`)

A relay host runs **one thing**: `vpn-relay.service`, a oneshot that executes
`/usr/local/sbin/vpn-relay-apply apply`. That helper renders two nftables tables from the
relay's `.env` — `ip vpnrelay` (forwarding) and `inet vpnrelay_input` (the
[input filter](#the-input-filter)) — applies both in **one atomic `nft -f` transaction**
(for each: `table …` + `delete table …` + the new table — nft commits all of it or leaves the
previous tables as they were) and then sets the sysctls — `net.ipv4.ip_forward = 1` and
the two conntrack values from `.env` (see [conntrack](#conntrack)) — at runtime and in
`/etc/sysctl.d/90-vpn-relay.conf`.

Nothing else from this repository runs there: no `vpn-bot`, no `vpn-bot-subscription`, no
`hy2_auth`, no database, no Xray, AmneziaWG or WARP, and **no Telegram at all** — the bot's
`BOT_TOKEN` on a second host would fight the main bot for `getUpdates`. `config/settings.py`
is never loaded; the relay has its own minimal `.env`. The forwarding table has no
`input`/`output` hook (pinned by tests): what comes in to the relay itself is the
[input filter](#the-input-filter)'s business, and nothing hooks `output`.

For the default ports the forwarding table is exactly what the hand-made relay ran (the input
table follows it in the same file, see [below](#the-input-filter)):

```
table ip vpnrelay
delete table ip vpnrelay
table ip vpnrelay {
  chain pre {
    type nat hook prerouting priority dstnat; policy accept;
    iifname "eth0" tcp dport 443 counter dnat to <upstream>:443
    iifname "eth0" udp dport 443 counter dnat to <upstream>:443
  }
  chain post {
    type nat hook postrouting priority srcnat; policy accept;
    oifname "eth0" ip daddr <upstream> ct status dnat counter masquerade
  }
  chain relayfwd {
    type filter hook forward priority filter; policy drop;
    tcp flags syn tcp option maxseg size set rt mtu
    ct state established,related accept
    ct status dnat ip daddr <upstream> accept
    counter
  }
}
```

Every forwarded port gets one DNAT rule to the **same** port on the upstream; masquerade,
the MSS clamp and the forward chain (policy drop, only DNAT'ed flows and their replies pass)
do not depend on the ports. No flowtable or other tuning: on the 1-vCPU relay 107 Mbit/s of
forwarding left the CPU 96–98 % idle.

### The input filter

What comes in to the relay **itself** is dropped by default — the way UFW does it on the main
server, but with a table this repository owns: `table inet vpnrelay_input` (`inet`: sshd
listens on IPv4 and IPv6), applied by `vpn-relay-apply` in the same transaction as
`ip vpnrelay`. The relayed traffic is not affected: DNAT'ed flows go through the forward hook
and never reach `input`.

```
table inet vpnrelay_input {
  chain input {
    type filter hook input priority filter; policy drop;
    iif "lo" accept
    ct state established,related accept
    ct state invalid drop
    ip protocol icmp accept
    meta l4proto ipv6-icmp accept
    ip6 saddr fe80::/10 udp dport 546 accept comment "dhcpv6 client"
    tcp dport 22 accept comment "ssh"
    tcp dport { … } accept comment "RELAY_INPUT_EXTRA_TCP"
    udp dport { … } accept comment "RELAY_INPUT_EXTRA_UDP"
    counter
  }
}
```

- ICMPv6 always passes (without it NDP, and with it IPv6, breaks), and so does the DHCPv6
  client (udp 546 from link-local). The trailing `counter` counts what the policy drops.
- **The SSH ports are never configured.** They come from `ss -Hltunp`: every TCP listener on a
  non-loopback address owned by `sshd` (or `sshd-session`), or held by systemd for a port that
  `ssh.socket` declares (`systemctl show -p Listen ssh.socket` — socket activation before sshd
  ever ran). Move sshd to another port and the next apply follows it — that is how the
  [SSH port migration](host-state.md#the-ssh-port) (`SSH_PORT`, default 54321: a relay still on
  22 moves at its next deploy) needs no rule here: in phase 1 ssh listens on 22 and 54321 and the
  restart of `vpn-relay` lets both in (a changed TCP set, so main's probe confirms it — and that
  confirmation of 54321 is the migration's proof); in phase 2 22 leaves `ssh.socket` and the next
  apply drops it. **No SSH port found →
  nothing is applied**: `no SSH port found — refusing to install a drop policy`, exit `8`,
  neither table changes. The unit is ordered `After=ssh.socket ssh.service`, so at boot sshd
  listens before apply looks.
- The rules are written exactly as `nft list` prints them (one port without braces), so
  `check` compares the live table with the render directly.
- **UFW stays masked on the relay** — never `ufw enable` there: UFW's forward chain
  (policy DROP) is a second base chain on the same hook and drops the relayed 443 whatever
  `table ip vpnrelay` says. The host check holds it: `ufw.service` `UnitFileState=masked` is a
  relay invariant (`deploy/host/invariants.list`), a MISMATCH otherwise — fatal in deploy
  Phase 1.
- `RELAY_INPUT_FILTER=off` removes the table in the same transaction; nothing filters INPUT and
  `check` expects the table absent.

#### Keeping access: the dead-man and `input-confirm`

No console is ever needed. The TCP port set the filter lets in (the SSH ports plus
`RELAY_INPUT_EXTRA_TCP`) is hashed; `/etc/vpn-relay/input.confirmed` holds the hash of the last
confirmed set.

- **The first enable, and any change of that set** (a new extra TCP port, sshd on another
  port): `apply` first arms a dead-man,
  `systemd-run --on-active=300 --unit=vpn-relay-input-deadman vpn-relay-apply input-off`, and
  only then applies the tables. A dead-man that cannot be armed → nothing is applied (exit
  `9`).
- **The main server confirms it** ([below](#main-confirms-the-filter-post-relayssh-probe)):
  right after that apply the relay asks main to connect to its SSH ports from outside. When
  every one answers, the filter is confirmed exactly as `input-confirm` would do it, and the
  deploy ends with

  ```
  input filter     : CONFIRMED by main probe (tcp 22; 2026-11-12 10:00:05 UTC)
  ```

  and nothing to do. When main cannot confirm it, the deploy ends with

  ```
  input filter     : PENDING CONFIRM (reverts at 2026-11-12 10:05:00 UTC) — main probe did not confirm it: <why>
  ```

  instead of `OK`, followed by the instruction.
- **Or confirm by hand: open a NEW ssh session** to the relay and run
  `vpn-relay-apply input-confirm` within 5 minutes: it stops the timer and writes the marker
  with the hash. Without either, the timer runs `input-off`: only `table inet vpnrelay_input`
  goes (forwarding is untouched), the reason goes to the journal
  (`journalctl -u vpn-relay-input-deadman`, or `-t vpn-relay-apply` when run by hand), and the
  relay is reachable exactly as before. Re-deploy and confirm in time.
- **The session you deployed from proves nothing**: it rides an established connection, which
  the filter always lets through. `input-confirm` checks that its own ssh session (the nearest
  `sshd` ancestor of the command) began after the filter was applied, and refuses otherwise —
  also from a console or from a tmux/screen started earlier. Run it directly in the new
  session; `ssh root@<relay> vpn-relay-apply input-confirm` from your machine is a new session
  too.
- **The same set as the marker → no dead-man, no confirmation**: an ordinary deploy stays
  fully automatic. UDP ports never ask for a confirmation (they cannot cost ssh).
- At boot `vpn-relay.service` applies both tables: a confirmed set needs nothing, an
  unconfirmed one arms the dead-man again.
- `vpn-relay-apply input-status` prints the state in one line — `OK (tcp 22; confirmed … by
  ssh-session|main-probe)`, `CONFIRMED by main probe (tcp 22; …)` (right after the apply whose
  probe confirmed it), `PENDING CONFIRM (reverts at …) — <why main did not confirm it>`,
  `ABSENT — the dead-man removed it at …`, `off (RELAY_INPUT_FILTER=off)`; DEPLOY OK prints it as
  `input filter`. The marker says who confirmed: `confirmed_by=ssh-session` or `main-probe`.

#### Main confirms the filter: `POST /relay/ssh-probe`

What `input-confirm` proves is that a **new** TCP connection from outside reaches the SSH port
through the filter. The main server can prove the same, so a relay deploy needs no ssh session
either:

1. After an `apply` that left the filter PENDING (dead-man armed, tables and sysctls in place),
   the relay POSTs its SSH ports — a JSON array, e.g. `[22]` — to main's subscription endpoint,
   `RELAY_CONFIRM_URL` (default `https://<RELAY_CHECK_SNI>:2096/relay/ssh-probe`). curl verifies
   the certificate, uses no proxy, follows no redirect, and always connects to
   `RELAY_UPSTREAM_IPV4` (`--resolve`): the request never goes anywhere but the main server.
2. Main answers only a caller whose address is inside the **source IPs of an enabled relay** in
   the admin panel (read live from the `relays` table); anyone else, and every request while
   `SUBSCRIPTION_ENABLED=false`, gets the endpoint's usual empty `404`. A body that is not 1–4
   distinct ports in 1..65535 is a `400`. Then main TCP-connects back to **the caller's own
   address** — never to an address from the request — on each port, concurrently, 5 s each, and
   answers `{"22":"ok"}` (or `"fail"`). It has its own rate limit (6 requests per minute per
   address, before the relay check) and logs the relay's name and the verdicts, nothing else.
3. **Every SSH port `ok`** → the relay confirms through the very path `input-confirm` runs (dead-man
   stopped, marker written with `confirmed_by=main-probe`). **Anything else** — no URL, `curl`
   missing, main unreachable (one retry), `404`, a port that failed, more than 4 SSH ports, an SSH
   port that is also forwarded (main would reach itself through the DNAT) — leaves the filter
   PENDING with the reason in `input-status` and in DEPLOY OK; the dead-man reverts it unless
   `input-confirm` comes, which works exactly as before. The probe never fails `apply`.

What it needs:

- **On main**: the subscription endpoint public (`SUBSCRIPTION_ENABLED=true`,
  `SUBSCRIPTION_PUBLIC_PORT`, TLS — [docs/subscription.md](subscription.md)), and the relay
  **added in the admin panel, enabled, with the address it reaches main from in its source IPs**
  — before its first deploy.
- **On the relay**: `curl`, and a URL — `RELAY_CHECK_SNI` for the default
  (`https://<RELAY_CHECK_SNI>:2096/relay/ssh-probe`: on a main server whose `XRAY_SNI` is its own
  domain, as with the self-steal decoy, that is the subscription's domain and port) or
  `RELAY_CONFIRM_URL=https://<subscription domain>[:<port>]` (path `/relay/ssh-probe` by default).
  `RELAY_CONFIRM_URL=off` turns the probe off: confirmation by hand only.

A failed probe whose URL is the default says so (`… set RELAY_CONFIRM_URL`): a certificate that
does not match `RELAY_CHECK_SNI`, or nothing listening on `:2096`, means the subscription lives
elsewhere.

#### Opening a port

For a service on the relay itself that must be reachable from outside (say, an exporter on
9100):

1. `RELAY_INPUT_EXTRA_TCP=9100` (or `RELAY_INPUT_EXTRA_UDP=…`) in `/opt/vpn-service/.env`;
2. `sudo FORCE=1 bash scripts/redeploy.sh` — a new TCP port changes the set: the dead-man is
   armed and main's probe confirms it (DEPLOY OK: `CONFIRMED by main probe`);
3. only if DEPLOY OK says PENDING CONFIRM: in a NEW ssh session, `vpn-relay-apply input-confirm`.

A port that listens on a public address but is **not** let in is an error of `check` (exit
`18`, `tcp/9100 listening but filtered: …`), and every deploy ends with `check` — a new service
is never silently dead behind the drop policy. Open it as above, bind it to loopback, or — when
it must stay closed from outside — declare it: `RELAY_INPUT_CLOSED_TCP=9100`
(`RELAY_INPUT_CLOSED_UDP` for UDP). Loopback listeners and the DHCPv6 client are not judged.

### The relay's `.env`

`/opt/vpn-service/.env`, from [`deploy/relay/relay.env.example`](../deploy/relay/relay.env.example).
Read with the same sed parser as `deploy.sh` uses for `NODE_ROLE` (and the Hysteria2 fwmark
helper for `HYSTERIA2_PORT`): optional `export`, spaces around `=`, quotes, trailing
`# comments`, the **last** assignment wins, an empty value counts as unset.

| Variable | Default | Meaning |
|---|---|---|
| `NODE_ROLE` | `main` | `relay` on a relay host. Any other value is refused before the deploy changes anything. |
| `SSH_PORT` | `54321` | The port ssh listens on — [the SSH port](host-state.md#the-ssh-port). The deploy moves ssh there in two phases (both ports, then — proven by main's probe or by a connection from outside in the sshd log — the new one alone), no `ALLOW_SSH_CHANGE`. Never a forwarded, extra or closed TCP port (refused). |
| `RELAY_UPSTREAM_IPV4` | — | IPv4 of the main server; or |
| `RELAY_UPSTREAM_HOST` | — | its DNS name instead (exactly one of the two; the installer writes this one) — [a DNS name as the upstream](#a-dns-name-as-the-upstream). |
| `RELAY_FORWARD_TCP_PORTS` | `443` | Comma-separated, 1..65535; each forwarded 1:1. |
| `RELAY_FORWARD_UDP_PORTS` | `443` | Same for UDP (Hysteria2). |
| `RELAY_WAN_IFACE` | the IPv4 default-route interface | WAN interface of the DNAT/masquerade rules. Without it the helper refuses a host with no default route or with default routes through several interfaces. |
| `RELAY_CHECK_SNI` | — | When set (and 443 is forwarded), `vpn-relay-apply check` also does a TLS handshake to the upstream with this SNI and **verifies the certificate**. Use the main server's `XRAY_SNI`: REALITY hands an unknown client to its decoy, whose certificate is valid for that name. |
| `RELAY_CONNTRACK_MAX` | `65536` | `net.netfilter.nf_conntrack_max`, an integer in 8192..1048576. Every relayed flow is one conntrack entry; when the table is full the kernel drops new flows. |
| `RELAY_CONNTRACK_TCP_ESTABLISHED_TIMEOUT` | `86400` | `net.netfilter.nf_conntrack_tcp_timeout_established`, seconds, 300..432000 (the kernel default is 432000 = 5 days). |
| `RELAY_INPUT_FILTER` | `on` | `on`: the [input filter](#the-input-filter) (policy drop). `off`: no `table inet vpnrelay_input`, INPUT is not filtered. |
| `RELAY_INPUT_EXTRA_TCP` | — | Comma-separated TCP ports the input filter lets in besides SSH. A change asks for `input-confirm` again. |
| `RELAY_INPUT_EXTRA_UDP` | — | The same for UDP (no confirmation). |
| `RELAY_INPUT_CLOSED_TCP`, `RELAY_INPUT_CLOSED_UDP` | — | Ports that listen on a public address but are meant to stay closed from outside: `check` does not call them "listening but filtered". A port cannot be both extra and closed; an SSH port cannot be closed. |
| `RELAY_CONFIRM_URL` | `https://<RELAY_CHECK_SNI>:2096/relay/ssh-probe`; none without `RELAY_CHECK_SNI` | Where `apply` asks main to [confirm a pending filter](#main-confirms-the-filter-post-relayssh-probe): `https://<dns name>[:<port>][/<path>]` (no path = `/relay/ssh-probe`; an address, `http`, a query or userinfo are refused), always sent to `RELAY_UPSTREAM_IPV4`. `off` = no probe. |

A value outside its range, with a sign, a unit or a leading zero is refused with exit `3`
before anything is applied, like a bad port.

### `vpn-relay-apply`

| Command | Does |
|---|---|
| `apply` | Render + apply both tables atomically (the dead-man first when the input filter's TCP set is not confirmed), then the sysctl file and the three runtime values (conntrack first, `ip_forward=1` last); for a set that is not confirmed, last, [main's probe](#main-confirms-the-filter-post-relayssh-probe). What the unit runs. |
| `check` | Read-only: both live tables equal the render (counters ignored; a diff is printed), every port that listens on a public address is let in or declared closed, `ip_forward=1`, both conntrack values equal `.env`, a TCP connect to the upstream on **every** forwarded TCP port, and the TLS handshake when `RELAY_CHECK_SNI` is set. A pending confirmation is shown, not a failure; a conntrack table more than 80 % full is a warning. Every deploy ends with it. |
| `check --dry-run` | Validate `.env`, find the SSH ports and render; say whether the TCP set is confirmed and which URL main's probe would use; as root also `nft -c` (syntax check, nothing applied). Deploy Phase 1 runs it from the checkout. |
| `show` | Print the rendered ruleset. |
| `input-confirm` | Keep the input filter: from a NEW ssh session, while the dead-man is armed. Stops the timer, writes `/etc/vpn-relay/input.confirmed` (`confirmed_by=ssh-session`) — the same path main's probe takes. |
| `input-off` | Remove `table inet vpnrelay_input` only, the reason to the journal. What the dead-man runs; by hand it lasts until the next apply. |
| `input-status` | The input filter's state in one line (DEPLOY OK prints it). |
| `resolve` | `RELAY_UPSTREAM_HOST` only: resolve again and apply when the live DNAT target is no longer one of its addresses (what `vpn-relay-resolve.timer` runs every 5 minutes). |

Exit codes: `0` ok · `2` usage · `3` bad/missing `.env` value · `4` WAN interface unresolved ·
`5` not root / tool missing · `6` nft rejected the ruleset (live tables unchanged) · `7` the
sysctl file or a sysctl could not be set (incl. `nf_conntrack_max` still absent after `modprobe
nf_conntrack`) · `8` no SSH port found — nothing applied · `9` the dead-man could not be armed —
nothing applied · `10` table absent · `11` live table differs from the render · `12` ip_forward
is not 1 · `13` the upstream does not answer on a forwarded TCP port · `14` TLS handshake failed ·
`15` a conntrack sysctl differs from `.env` · `16` `table inet vpnrelay_input` absent although
`RELAY_INPUT_FILTER=on` (e.g. the dead-man removed it), or present although it is `off` · `17`
the input table differs from the render · `18` a port listens but is filtered · `19`
`input-confirm` refused (nothing pending, too late, or not a new ssh session) · `20`
`RELAY_UPSTREAM_HOST` does not resolve and there is no last-known address for it (apply/check), or
`resolve` could not resolve it (the live table stays). `check` runs
table → input table → listening ports → ip_forward → conntrack → TCP → TLS, reports every
failure and exits with the first one.

### conntrack

Every relayed flow (each VLESS connection, each Hysteria2 UDP flow) is an entry in the kernel's
conntrack table: DNAT and masquerade live there. When the table is full the kernel drops **new**
flows (`nf_conntrack: table full, dropping packet` in `dmesg`), so the relay sets the limit
itself instead of relying on the kernel default, and shortens the 5-day timeout of established
TCP entries, which otherwise keeps entries of clients that vanished without a FIN.

`apply` renders `/etc/sysctl.d/90-vpn-relay.conf` whole:

```
net.ipv4.ip_forward = 1
net.netfilter.nf_conntrack_max = <RELAY_CONNTRACK_MAX>
net.netfilter.nf_conntrack_tcp_timeout_established = <RELAY_CONNTRACK_TCP_ESTABLISHED_TIMEOUT>
```

and sets the same values with `sysctl -w` **after** `nft -f`, reading each one back. The file
alone is not enough: at boot `systemd-sysctl` applies it early, **before nf_conntrack is
loaded** — the module is loaded by the table's ct/nat expressions, i.e. by `nft -f` in `apply` —
so the `net.netfilter.*` keys do not exist yet and it skips them (a `Couldn't write … ignoring`
line for them in its journal is expected). That is why `apply` sets them on every start of
`vpn-relay.service`. If `net.netfilter.nf_conntrack_max` is still absent after `nft -f`, `apply`
runs `modprobe nf_conntrack` and retries; if that does not help it exits `7`.

`check` reads the fill level from the `net.netfilter.nf_conntrack_count` sysctl (not
`/proc/net/stat/nf_conntrack`, which the relay's 6.8 kernel does not have) and prints a
`WARNING` above 80 % of `nf_conntrack_max` — raise `RELAY_CONNTRACK_MAX` then.

A relay deployed before these keys existed runs with the kernel's values, so the first deploy
that brings them shows exit `15` in Phase 1's live check ("the table and ip_forward match; the
conntrack sysctls differ") instead of PASS; Phase 2 sets them. The rollback puts back the
runtime values from before the deploy.

### What `scripts/redeploy.sh` does on a relay

The same commands as on the main server; `deploy.sh` reads `NODE_ROLE` and refuses a host
whose services contradict it (role `relay` while `vpn-bot` or `xray` is active; role `main`
while `vpn-relay` is active and there is no `vpn-bot` unit at all).

- **Phase 1** (read-only; `CHECK=1` stops here and prints a report): fetch `origin/main`, the
  same ruff / compileall / pytest gate on the checkout as on the main server (a test venv is
  built under `/var/lib/vpn-bot-deploy/`, so the relay needs `python3-venv` and ~1 GiB free),
  `vpn-relay-apply check --dry-run` from the checkout, the relay's pre-state (including the
  runtime `nf_conntrack_max` and `nf_conntrack_tcp_timeout_established`), the installed unit
  compared with `deploy/relay/vpn-relay.service`, and the checkout's `check` against the live
  relay — on a relay that still runs the hand-made ruleset `ok: table ip vpnrelay matches`
  there proves the repo reproduces it 1:1 (the exit is `16` until the
  [input filter](#the-input-filter) exists, `15` before the [conntrack](#conntrack) values are
  set, PASS after both). The dry-run names the SSH ports it found and whether the input
  filter's TCP set is confirmed — i.e. whether Phase 2 arms the dead-man — and the URL of main's
  probe that will confirm it, and a port that listens but would be filtered is called out:
  Phase 2's `check` would roll back.
- **Phase 2**: back up the live `nft list table ip vpnrelay` and
  `nft list table inet vpnrelay_input`, the installed helper, the unit, the sysctl file and the
  confirmation marker `/etc/vpn-relay/input.confirmed` (`/var/backups/vpn-bot/backup-relay-<sha>-<ts>.tar.gz`; nothing is
  stopped for it); `git reset --hard origin/main`; install `vpn-relay-apply` through
  `OUT_OF_REPO_HELPERS` (role `relay`) and `deploy/relay/vpn-relay.service` verbatim;
  `daemon-reload`, `enable`, `restart vpn-relay` (established flows keep their conntrack NAT
  across the millisecond gap; a set that is not confirmed is confirmed by main's probe here);
  verify with `vpn-relay-apply check`. Around the host files the [SSH port](host-state.md#the-ssh-port)
  moves when `SSH_PORT` asks for it (phase 1: both ports; the restart of `vpn-relay` then lets
  them in and main's probe confirms them); right after DEPLOY OK `vpn-bot-ssh-port.service` looks
  for the proof once, so the relay usually finishes the migration in the same run.
  DEPLOY OK carries `ssh port: …` and `input filter : …` from
  `vpn-relay-apply input-status` — `CONFIRMED by main probe (…)` with nothing to do, or
  `PENDING CONFIRM (…) — <why>` followed by the reason and the instruction to run
  `input-confirm` from a NEW ssh session within 5 minutes.
- **Any failure** rolls back: the previous checkout, helper, unit and sysctl file (or their
  absence), the saved forwarding table re-applied in one transaction, the input filter as it
  was — a confirmed one from its dump, one that did not exist removed, one that was still
  waiting for `input-confirm` removed too (restored, it could outlive its dead-man; removing is
  the safe direction) — the confirmation marker as it was (a confirmation main's probe wrote
  during the restart is for a set that is no longer live), the dead-man the deploy armed
  stopped, the unit's enabled/active state, the
  previous `ip_forward` and the previous runtime conntrack values (each read back; a value that
  was unreadable before the deploy — nf_conntrack not loaded — is left as `apply` set it). The
  deploy exits non-zero with a rollback report.
- A unit installed by hand that loads `/etc/vpn-relay.nft` is the **expected first
  transition**, not drift. After the first successful deploy `/etc/vpn-relay.nft` is renamed to
  `/etc/vpn-relay.nft.pre-repo.<ts>` (never deleted) and nothing reads it any more.

### A new relay from scratch

On the relay (Ubuntu 24.04, root SSH with a key):

```bash
apt-get update && apt-get install -y git python3-venv nftables
```

UFW must stay off on a relay ([why](#the-input-filter)) — mask it (works whether the package is
installed or not; the host check refuses a relay where it is not masked):

```bash
systemctl mask --now ufw.service
```

```bash
git clone https://github.com/Egor051/vpnbot.git /opt/vpn-service
```

```bash
install -m 0600 -o root -g root /opt/vpn-service/deploy/relay/relay.env.example /opt/vpn-service/.env
```

Edit `/opt/vpn-service/.env`: `RELAY_UPSTREAM_IPV4` = the main server's IPv4, and preferably
`RELAY_CHECK_SNI` = the main server's `XRAY_SNI` — it also makes the URL main's probe is asked at
(`https://<RELAY_CHECK_SNI>:2096/relay/ssh-probe`); when the subscription endpoint is on another
domain or port, set `RELAY_CONFIRM_URL=https://<that domain>:<port>` too.

Before the first deploy, on the **main server**: a DNS A record for the relay and the relay in
the admin panel, **enabled**, with the relay's egress IPv4 in its source IPs (steps 1–2 below) —
main's probe answers only the address of an enabled relay. (Switch «в подписках» off until the
deploy is done if new bundles must not get relay members a few minutes early.) Then inspect, and
deploy:

```bash
cd /opt/vpn-service && sudo CHECK=1 bash scripts/redeploy.sh
```

```bash
cd /opt/vpn-service && sudo FORCE=1 bash scripts/redeploy.sh
```

`FORCE=1` only on this first run: a fresh clone is already at `origin/main`, and a plain run
would say "nothing to deploy" — exactly as on the main server. Every later update is the usual
`sudo CHECK=1 bash scripts/redeploy.sh`, then `sudo bash scripts/redeploy.sh`.

The first deploy enables the [input filter](#the-input-filter), main's probe confirms it, and
DEPLOY OK says `input filter : CONFIRMED by main probe (…)` — nothing to run. Only if it says
`PENDING CONFIRM (reverts at …) — <why>`: fix what it names, or open a **new** ssh session within
5 minutes and run

```bash
vpn-relay-apply input-confirm
```

Check it: `systemctl status vpn-relay`, `nft list table ip vpnrelay`,
`nft list table inet vpnrelay_input`, `/usr/local/sbin/vpn-relay-apply input-status`,
`/usr/local/sbin/vpn-relay-apply check`.

On the **main server** (steps 1–2 before the relay's first deploy, see above):

1. A DNS A record for the relay — e.g. `relay2.anycastedge.net` → the relay's IPv4 — with
   Cloudflare proxying **off** (see [DNS](#dns--use-a-name-not-an-address)).
2. **🛡 Админ-панель → 🧩 Протоколы и маршрутизация → 🛰 Управлять relay → Добавить relay**: host = that name, source IPs = the
   relay's egress IPv4 (for a DNAT relay usually the address it is reached at), name and label
   as in [Managing relays](#managing-relays-in-the-admin-panel). (`RELAY_HOST` /
   `RELAY_SOURCE_IPS` in the main `.env` are legacy since relays moved to the panel: they only
   seed an empty `relays` table once.)
3. **«Проверить сейчас»** on the relay's card: the health probe goes through the relay's DNAT
   to the main inbound and back.

Changing `RELAY_FORWARD_*` (or any relay `.env` value) does not move `HEAD`, so apply it with
`sudo FORCE=1 bash scripts/redeploy.sh` — backup, restart, check and rollback included — rather
than a bare `systemctl restart vpn-relay`.

### Forwarding the subscription port (2096) through a relay

Not done in this release; what it would take:

- **On the relay** — the easy half: `RELAY_FORWARD_TCP_PORTS=443,2096` and
  `sudo FORCE=1 bash scripts/redeploy.sh`. TCP/2096 then reaches the main server's
  subscription endpoint, and `check` also probes `<upstream>:2096`.
- **On the main server** — the part that needs code:
  - the subscription URL a user gets is built on the main domain
    (`https://<HYSTERIA2_SNI>:<SUBSCRIPTION_PUBLIC_PORT>/sub/<token>`); fetching through a
    relay needs a URL with the relay's host, i.e. a per-relay subscription URL in the bot;
  - TLS terminates on the main server with the main domain's certificate, so the relay's name
    must be in that certificate (a SAN; with the relay forwarding 443 to the main server, a
    DNS-01 issuance is the practical way);
  - the endpoint's rate limit is per peer address, and every fetch through the relay arrives
    from the relay's egress IP — the relay's users would share one bucket
    (`SUBSCRIPTION_RATE_LIMIT_BURST` per `SUBSCRIPTION_RATE_LIMIT_SECONDS`) unless the relay's
    source IPs get their own treatment;
  - the UFW rule for `SUBSCRIPTION_PUBLIC_PORT` (module `subscription` of
    `scripts/vpn-bot-ufw-apply`) already admits the relay (it is not source-restricted), and
    the health monitor would still only probe `XRAY_PUBLIC_PORT`.

## Installing a relay with one command

The quickest way to a new relay: **🛡 Админ-панель → 🧙 Мастер настройки → 🛰 Relay →
➕ Добавить relay**. The bot issues a pairing code and shows **one line** to paste on the
relay; the relay installs itself from it, and the bot connects to it over SSH and manages it
from then on. The relay has **no Telegram bot and never talks to the Telegram API**: the only
thing the main server and the relay share is the bot's SSH key, whose line in the relay's
`authorized_keys` runs nothing but [the agent](#the-agent-vpn-relay-agent).

### The pairing code

`base64url(JSON)` without padding, exactly these fields (`services/relay_pairing.py`; the
installer decodes it with the same rules):

```json
{"v": 1, "target_host": "vpn.example.com", "ports": ["443/tcp", "443/udp"],
 "main_pubkey": "ssh-ed25519 AAAA…", "one_time_token": "<43 chars>", "exp": 1763300000}
```

- `target_host` — the main server's **DNS name**, never an address: the relay re-resolves it
  every 5 minutes ([below](#a-dns-name-as-the-upstream)), so a new IP of the main server is an
  A-record change and nothing on the relay. The bot offers `XRAY_PUBLIC_HOST` (else
  `HYSTERIA2_HOST`, `HYSTERIA2_SNI`) when it is a name; another name can be typed.
- `ports` — `XRAY_PUBLIC_PORT/tcp` and `HYSTERIA2_PORT/udp` (443 both), forwarded 1:1.
- `main_pubkey` — the bot's key for every relay, `/etc/vpn-bot/relay_ssh/id_ed25519`, generated
  once (ed25519, `0600`, owned by the bot's user, never replaced; a key file that is a symlink or
  readable by anyone else is refused). In the helper-nonroot model, where the bot cannot write
  `/etc/vpn-bot`, create it once as root:
  `install -d -m 0700 -o vpn-bot /etc/vpn-bot/relay_ssh && sudo -u vpn-bot ssh-keygen -t ed25519 -N '' -C vpn-bot-relay -f /etc/vpn-bot/relay_ssh/id_ed25519`.
- `one_time_token` — 32 random bytes; the relay keeps only its sha256. The bot keeps the token
  while the pairing is pending (table `relay_pairings`) and clears it the moment the pairing is
  completed, cancelled or expired.
- `exp` — 30 minutes. The installer accepts a code up to 5 minutes past it (clock skew); the bot
  completes a pairing, and the relay's agent accepts its first `hello`, up to 15 minutes past it.

Issuing a code is a [dangerous action](wizard.md#where-it-is-asked) (TOTP).

### The command for the relay

```bash
curl -fsSL -o install.sh https://raw.githubusercontent.com/<owner>/<repo>/<commit>/scripts/install.sh && echo '<sha256>  install.sh' | sha256sum -c --quiet - && printf '%s\n' '<code>' | sudo env INSTALL_REF=<commit> bash install.sh --relay
```

- `<commit>` is the main server's own `HEAD` and `<sha256>` the hash of its own
  `scripts/install.sh`: the relay installs exactly the code the main server runs, and a file that
  differs is refused before it runs. `<owner>/<repo>` is the checkout's `origin` on GitHub (a fork
  adds `INSTALL_REPO=`).
- The code reaches the installer on **stdin**, from the shell builtin `printf` — never an argv.
  Only one input: no bot token, no Telegram ID.

### What the installer does on the relay

`scripts/install.sh --relay` (or mode `2` interactively) on Ubuntu 24.04, as root — the same
frame as the main installer: read-only preconditions, a manifest, rollback on any error or
signal, a log in `/var/log/vpn-bot-install.<ts>.log` (the code and the token never in it).

1. **Preconditions** (nothing changes when one fails): the code is valid and not expired; root
   may log in with a key — judged by `sshd -T -C user=root,addr=<main>` (`PubkeyAuthentication`,
   `PermitRootLogin` not `no`, `AllowUsers`/`DenyUsers`/`AllowGroups`/`DenyGroups`,
   `AuthorizedKeysFile`); **`sshd_config` is never written**. ufw must not be enabled (its
   forward chain, policy DROP, would drop the relayed traffic — `ufw disable && systemctl mask
   ufw.service`); the target resolves; no forwarded TCP port is a port sshd listens on; the host is
   not a main server.
2. **Install**: `nftables`, a checkout of `<commit>` in `/opt/vpn-service`, the relay `.env`
   from `deploy/relay/relay.env.example` (`NODE_ROLE=relay`, `RELAY_UPSTREAM_HOST=<target>`, the
   ports, `RELAY_INPUT_FILTER=off`, `SSH_PORT` = the port sshd listens on now, so a later
   `redeploy.sh` does not move ssh away from the bot), `/etc/vpn-relay/pairing.json` (the token's
   sha256, the expiry, `0600`), `vpn-relay-apply` and `vpn-relay-agent` in `/usr/local/sbin`,
   `vpn-relay.service`, `vpn-relay-resolve.service` + `.timer`, and **one** line in root's
   `authorized_keys`:

   ```
   restrict,command="/usr/local/sbin/vpn-relay-agent" ssh-ed25519 AAAA… vpn-relay-agent
   ```

   Every other line stays byte-identical; an older agent line, and any other line with the same
   key (an unrestricted copy would be a root shell), goes.
3. **Start**: `vpn-relay.service` applies `table ip vpnrelay` in one atomic `nft -f` — DNAT
   tcp+udp 443 → the target's address, masquerade, the SYN MSS clamp, the forward chain with
   policy drop that lets only the DNAT'ed flows through — and `net.ipv4.ip_forward=1` through
   `/etc/sysctl.d/90-vpn-relay.conf` (see [The relay host](#the-relay-host-node_rolerelay)).
   A unit that is already running is **reloaded** (`ExecReload` = the same atomic apply), never
   restarted: a restart runs `ExecStop` first and would leave a moment without DNAT.
4. **Verify**: `vpn-relay-apply check`; **exactly one DNAT rule per forwarded port in the whole
   ruleset** (another table that also DNATs 443 fails the install); the timer active. The main
   server not answering from the relay (`check` exit 13/14) is a warning — the bot checks the path
   itself when it connects.
5. The installer prints the address to send to the bot — `ip -4 route get <target>`'s source
   address and the ssh port; behind NAT it says to send the public one.

A re-run with a new code on a relay this installer installed is a **re-pair**: same checkout,
new `pairing.json`, the key line replaced, everything re-applied.

#### Adoption of a hand-made relay

A relay that was set up by hand — `/etc/vpn-relay.nft`, a `vpn-relay.service` that loads it,
`table ip vpnrelay` — or deployed with `redeploy.sh` is **adopted**, not stacked on:

- everything it had goes to `/var/backups/vpn-relay/adopt-<ts>/` first: the live tables as `nft
  list` prints them, `/etc/vpn-relay.nft`, the unit, the sysctl file, the helpers, the `.env`. That
  copy **stays** (after a commit and after a rollback);
- `/etc/vpn-relay.nft` is moved away, so nothing loads it again;
- the table has the same name, so the one `nft -f` transaction swaps the old `table ip vpnrelay`
  for the new one — never two DNATs, never a moment with none;
- **the rollback puts all of it back**: the files from the backup, and the live table from its
  dump in one transaction (`table …; delete table …; <dump>`), not by restarting the old unit
  (whose `nft -f` could add its rules on top). CI proves it on a real VM (below).

### Completing the pairing

«🔌 Подключить» → send the relay's address (`IP`, `IP:port` or a DNS name). The bot:

1. connects as `root` with its key — **trust on first use**: the relay's host key is learned
   now and pinned in `relay_agents.host_key`; every later call runs with
   `StrictHostKeyChecking=yes` under `HostKeyAlias=vpn-relay-<id>`, and a relay that shows another
   key is refused («ключ хоста relay изменился»);
2. runs `hello <token>`; the agent compares the sha256 in constant time, within the expiry, and
   marks itself paired. A repeated `hello` with the same token answers again (the bot may retry
   its checks), any other token is refused;
3. checks the relay **from outside**, both through its DNAT to this server: **TCP** — a verified
   TLS handshake with `XRAY_SNI` to `<relay>:XRAY_PUBLIC_PORT` (the [health probe](#health-monitor));
   **UDP** (when Hysteria2 is on) — a QUIC packet with a reserved version to
   `<relay>:HYSTERIA2_PORT`, which every QUIC server answers with version negotiation. A failure of
   either registers nothing and offers «Подключить снова»;
4. **registers** it in the existing relay model: a row in `relays` (enabled, «в подписках», label
   `relay` or the name), whose **source IPs** — the address it is reached at plus the source
   address the agent reports for the upstream, when that is public — are what the
   [anomaly detector excludes](#limitations); the row in `relay_agents`; the token cleared;
5. the [health monitor](#health-monitor) probes it from the next pass on and alerts the
   superadmins on down / back up (`RELAY_HEALTH_INTERVAL`, default 300 s; with `0` the card says
   there will be no alerts).

### The agent (`vpn-relay-agent`)

`scripts/vpn-relay-agent` (stdlib Python). sshd runs it for the bot's key whatever the client
asks; the request comes in `SSH_ORIGINAL_COMMAND` and must match one of these **exactly**
(full-string patterns, ASCII, at most 512 characters); everything else — shell syntax, a second
line, extra words, an argv, an interactive login — is refused with exit 2 before anything runs:

| Request | Does |
|---|---|
| `hello <token>` | Complete the pairing; answers the relay's facts. The only request before pairing. |
| `status` | Facts: target, ports, the live DNAT target, what the name resolves to now, `ip_forward`, the units, the ssh ports, the egress source address, the checkout, the last update, and `vpn-relay-apply check`. |
| `apply target=<dns name> tcp=<ports> udp=<ports>` | Re-point / re-port: refused for a name that is not a name or does not resolve on the relay, a port outside 1..65535, more than 8, a TCP port sshd listens on. Rewrites only `RELAY_UPSTREAM_HOST` / `RELAY_FORWARD_*`, applies, checks; puts `.env` back and re-applies when the ruleset or the check (table, sysctls, the upstream not answering) fails. |
| `update` | In a transient unit (`systemd-run --wait`): fetch the release tags, move the checkout to the newest `vX.Y.Z` — only forward, never backwards or sideways — and run its `install.sh --relay-update` (helpers and units reinstalled, vpn-relay reloaded, checked; rolled back on failure, the checkout moved back). |
| `uninstall` | In a transient unit: the units stopped and removed, both tables deleted, the sysctl file removed and `ip_forward` back to what it was before the install, the helpers, `/etc/vpn-relay`, `/var/lib/vpn-relay`, the checkout (when the installer created it) and the agent's key line removed. The adoption backup stays. Refused on a host without the installer's `/etc/vpn-relay/install.json`. |

Exit codes: `0` ok · `2` refused · `3` not allowed (token, not paired, expired) · `4` failed (what
it changed was put back) · `5` busy (another mutating call holds the lock). One JSON object on
stdout. Every call is logged with `logger -t vpn-relay-agent` — the request name, the caller's
address, the verdict; never the token. The key line carries `restrict`: no pty, no port, agent or
X11 forwarding.

### A DNS name as the upstream

nftables resolves a name only when a ruleset is **loaded**, so `dnat to <name>` would freeze the
address of that moment. The relay therefore never puts a name into the table:

- `RELAY_UPSTREAM_HOST` (instead of `RELAY_UPSTREAM_IPV4`; exactly one of the two) is resolved
  by `vpn-relay-apply` at every render (`getent ahostsv4`); among several A records the one the live
  table already uses is kept (a round-robin answer does not reload the table), else the lowest.
- `vpn-relay-resolve.timer` runs `vpn-relay-apply resolve` 2 minutes after boot and every 5
  minutes: when the live DNAT target is no longer one of the name's addresses it applies (one
  atomic `nft -f`), otherwise it logs `unchanged` and does nothing.
- Each apply remembers the address in `/etc/vpn-relay/upstream.resolved`; a name that does not
  resolve (DNS down at boot) falls back to it — for the **same** name only; otherwise `apply`
  exits `20` with nothing applied, and `resolve` leaves the live table alone (exit `20`, the next
  pass retries).

### Managing it from the wizard

**🧙 Мастер настройки → 🛰 Relay** lists the relays the bot manages and the codes still waiting.
A relay's card: «🔄 Статус» (`status`, kept in `relay_agents.last_status`), «⬆️ Обновить»
(`update`), «⚙️ Порты / цель» (`apply` — send `vpn.example.com tcp=443 udp=443`), «🗑 Удалить»
(`uninstall` on the relay, then the relay row — with its keys when there are some; a relay that
does not answer offers «Удалить только запись»), and its card in the admin panel for host, label,
on/off. Issuing a code, update, ports/target and delete ask for the TOTP code; a step that waits
for typed input checks the elevation again before it acts. Every action is audited (entity
`relay`: `relay_pairing_issued`, `relay_pairing_cancelled`, `relay_pairing_check_failed`,
`relay_paired`, `relay_agent_update`, `relay_agent_apply`, `relay_agent_uninstall`).

### Limits of the installer relay

- **No input filter**: the installer sets `RELAY_INPUT_FILTER=off` — what comes in to the relay
  itself is not filtered (as on a fresh VPS). [The input filter](#the-input-filter) can be
  switched on by hand; its dead-man then needs a confirmation as described there.
- Mixing with `redeploy.sh`: an installer relay can be deployed with `redeploy.sh` (it is a
  `NODE_ROLE=relay` checkout), but that tracks `origin/main`, not releases, and the host files
  come with it; keep one way per relay.
- IPv4 only, like the rest of the relay.

## Managing relays in the admin panel

SUPERADMIN only. **🛡 Админ-панель → 🧩 Протоколы и маршрутизация → 🛰 Управлять relay** lists every relay with its
label, name, host, on/off, «в подписках», the number of active keys and the result of
the latest health probe.

**Add a relay** — a four-step wizard, each value validated by the same functions the
old `.env` loader used (a bad value is explained and the step is asked again):

1. **name** — `^[a-z0-9][a-z0-9-]{0,31}$`, e.g. `ru1`. It is written into every key of
   the relay (`vpn_keys.relay`) and **can never be changed**. A name that any key row
   still carries — in any status, deleted ones included — cannot be given to a new
   relay, because those keys would silently start pointing at another host.
2. **host** — DNS name (recommended) or IPv4; IPv6 is refused.
3. **source IPs** — the relay's egress IPv4 addresses / CIDR networks as this server
   sees them, comma-separated, never empty. If the host is an IPv4 address the step
   offers «Как host».
4. **label** — the marker in key names, unique per relay: 1–16 characters on one line, no
   control characters; emoji and any symbols are fine (`🇷🇺➜`). It is followed by the flag
   directly, with no `_`, so a separator, if wanted, goes into the label (`ru_`). The step
   offers `relay` while no other relay uses it.

A confirmation card shows everything before the relay is created.

**The relay card** edits host, source IPs, label and note, switches the relay on/off
and «в подписках» on/off, runs **«Проверить сейчас»** (the health probe, once — the
result and its time stay on the card) and deletes the relay. Every change is audited
with the values before and after, and **takes effect on the next rendered link**:

- the bot keeps an in-memory snapshot of the table that every write through the panel
  replaces immediately (the bot is the only writer);
- the subscription endpoint (`vpn-bot-subscription`) reads the table on **every
  request** through its read-only connection, so it serves the change without a
  restart.

After a host change the card says that subscriptions already point at the new address
and how many single relay keys must be re-imported. If the new host is an IPv4 address
the source IPs do not cover, it offers to add it (a DNAT relay usually egresses from
the address it is reached at).

### Switching a relay off

- **off** (`enabled=0`): its keys' links are refused (`RelayUnavailable`, the bot shows
  an error instead of a link), its members are skipped in subscriptions (logged at
  WARNING; direct members are still served), and it is not offered for new keys or
  bundles. Its source IPs **stay excluded** from anomaly detection — clients may still
  be connected. Switching it back on brings everything back unchanged.
- **not in subscriptions** (`in_subscriptions=0`): new all-in-one bundles get no
  members through it; single keys can still be issued through it while it is on.
  Existing bundles keep the members they have.

### Deleting a relay

- **No keys** go through it (outside status `deleted`): one confirmation, then it is
  deleted.
- **Keys remain**: the screen says how many (and how many of them are in how many
  subscriptions) and offers:
  - **Удалить ключи и relay** — every key through the relay is deleted through the
    **same path as from the key's own screen** (Xray client removed, traffic archived,
    audited). A bundle child is removed from its bundle; the bundle stays with its
    other members. The first key that fails stops the whole operation: the relay is
    kept and the screen reports how many keys were deleted, which one failed and why.
    Running the delete again continues with the keys that are left.
  - **Отключить вместо удаления** — the relay is switched off; nothing is deleted.
  - **Отмена**.

The relay row is removed only if, at that very moment, no key names it any more (one
SQL statement), so a key issued while the delete runs cannot be orphaned.

## Migrating from `.env` (`RELAY_*`)

Relays used to be configured with `RELAY_ENABLED`, `RELAY_NAME`, `RELAY_HOST` and
`RELAY_SOURCE_IPS`. These are **no longer a source of truth**:

- On bot startup, if the `relays` table is **empty** and `.env` has
  `RELAY_ENABLED=true` with `RELAY_HOST` and `RELAY_SOURCE_IPS`, that relay is created
  once — name `RELAY_NAME` (default `ru1`, exactly what the existing relay keys
  carry), label `relay`, enabled, in subscriptions — and an INFO line says so.
- In every other case where any of these variables is set, the bot logs
  `WARNING RELAY_* в .env игнорируются: relay управляется из админки`.
- The variables are still parsed as strictly as before: garbage (a bad host, a bad
  source IP, `RELAY_ENABLED=true` without host or source IPs) fails startup with a
  `SettingsError`.

So: deploy, check the relay appeared in the panel, then delete the `RELAY_*` lines from
`.env`. `RELAY_HEALTH_INTERVAL` and `SERVER_FLAG_EMOJI` stay in `.env`.

> If a deployment had relay keys but `RELAY_ENABLED=false` at the moment of the upgrade,
> nothing is seeded and those keys stay refused. Their name is already carried by keys,
> so it cannot be re-created by hand in the panel: start once with `RELAY_ENABLED=true`
> (and the old host/source IPs) to seed it, then switch it off in the panel if needed.

## What a relay key is

Relay is an **attribute of a key** (`vpn_keys.relay`, `NULL` for a direct key, otherwise
the relay's `name`), not a new key type or transport:

- it is created through the same per-protocol path as a direct key and gets its own
  uuid / secret / label with the usual prefix (`xray_tcp_*`, `xray_http_<profile>_*`,
  `hy2_*`), so `hy2_auth`, Xray reconciliation (`XRAY_MANAGED_LABEL_RE`), traffic
  stats and the email-label scheme are untouched;
- its link differs from a direct key's in exactly two places: the **host** (the
  relay's host instead of `XRAY_PUBLIC_HOST` / `HYSTERIA2_HOST`) and the **display
  name** (the relay's label after the key's label, glued to the flag/circle:
  `<label>_<relay label><flag|circle>`, e.g. `xray_tcp_ab12c_🇷🇺➜🇫🇮` for the label `🇷🇺➜`). Port,
  REALITY `sni`/`pbk`/`sid`/`spx`/`fp`, `flow`, XHTTP `path`/`mode`/`extra`, and
  Hysteria2's `sni` are the same — the relay forwards 1:1, so TLS still terminates on
  the main server with its own certificate / REALITY keys;
- the host is chosen in one place (`services.relay.relay_link_host`) for every path —
  config screen, QR, create wizard, cached `public_payload.link`, the subscription. A
  key whose relay is switched off, deleted or unknown is **refused**
  (`RelayUnavailable`), never silently pointed at the main host: a link that quietly
  bypasses the relay the user chose is the failure this guards against.

Users choose it in the create wizard: after the protocol (and XHTTP profile) step, while
at least one relay is enabled, the bot asks **«Как подключаться?»** with **«Напрямую»**
plus one **«Через <label>»** button per enabled relay (user and admin wizards alike;
AmneziaWG never gets the step — it is not on 443). The confirm step re-checks the relay,
so one switched off meanwhile is refused before anything is written.

### Several relays in subscriptions

A new all-in-one bundle gets a copy of every member through **each** relay that is
enabled and «в подписках», in groups ordered by the relay's `id`: all direct members
first, then the members through relay #1, then through relay #2, and so on — each group
in the usual member order (basic: 2 per group, extended: 5). A relay member carries its
direct twin's circle. See [docs/subscription.md](subscription.md#two-kinds-of-all-in-one).

## Settings

Full reference: [Configuration → Relay](configuration.md#relay).

| Variable | Default | Meaning |
|---|---|---|
| `RELAY_HEALTH_INTERVAL` | `300` | Health probe period, seconds; `0` = off. |
| `SERVER_FLAG_EMOJI` | `🇫🇮` | Flag in the display name of standalone keys and basic members. |
| `RELAY_ENABLED`, `RELAY_NAME`, `RELAY_HOST`, `RELAY_SOURCE_IPS` | — | **Legacy.** Only seed an empty `relays` table once (see above); ignored afterwards. |

**There is no relay port setting**: the port in a relay link is the protocol's own
public port (`XRAY_PUBLIC_PORT`, `HYSTERIA2_PORT`), because the relay forwards 1:1.

## Health monitor

With `RELAY_HEALTH_INTERVAL > 0` the bot runs **one** background loop for every relay,
modelled on the WARP monitor. Each pass reads the relays from the database (so a relay
added or edited in the panel is picked up with no restart) and probes every **enabled**
relay: a TCP connection to `<relay host>:XRAY_PUBLIC_PORT` and a TLS handshake with
`server_hostname=XRAY_SNI`, **verifying the certificate**. The bot runs on the main
server, so the probe goes out to the relay and comes back in through its DNAT (a
hairpin); REALITY does not recognise it as a client and hands it to the decoy, whose
certificate is valid for `XRAY_SNI`. A passing probe therefore means "TCP/443 through
the relay reaches the main inbound end to end" (checked by hand: HTTP 200, `verify=0`,
TLS ≈ 0.29 s).

- **UDP** (when `HYSTERIA2_ENABLED=true`): a QUIC packet with a reserved ("greasing") version,
  padded to 1200 bytes, to `<relay host>:HYSTERIA2_PORT` — every QUIC server answers an unknown
  version with version negotiation (RFC 9000 §6), so the answer proves the UDP DNAT end to end
  without any credentials. The same packet to `127.0.0.1` first is the control: when this host's
  own hysteria-server does not answer it either, UDP is "not judged", never "down". A relay is up
  when TCP passes and UDP did not fail.
- One probe never takes more than 10 s and never raises.
- One time-based latch **per relay** (`relays.id`): a relay is reported **down** after
  one interval of continuous failure (two failed probes in a row) and **back** after one
  interval of continuous success. Every admin in `ADMIN_IDS` gets exactly one message
  per transition, naming the relay's label, name and host. A new relay starts healthy;
  a relay switched off or deleted loses its latch; one relay's state never affects
  another's.
- The latest probe of each relay (loop or «Проверить сейчас») is shown on its card; it
  lives in the bot's memory only.
- A dead relay does **not** mark Xray degraded and does not block issuing keys.
- Each probe leaves one line like
  `REALITY: processed invalid connection from <relay IP>` in Xray's error log. That is
  expected — it is the probe being handed to the decoy.

## Limitations

- **Anomaly detection is IP-blind for relayed traffic, by design.** L4 without PROXY
  protocol means every relayed connection carries the relay's address; for Hysteria2
  over UDP there is no client address at all. The source IPs of **every** relay —
  switched-off ones included — are therefore never recorded (neither the IP nor its
  network/ASN); the list is re-read from the database at the start of every detection
  cycle. Because the inbound is shared, this takes the IP signal away from **any** key
  that is used through a relay — a direct key whose link a user re-points at the relay
  included. Hysteria2's `/online` connection count is unaffected.
- **UDP is judged only against this host's own server.** When this host's hysteria-server does
  not answer the control probe, the relay's UDP is not judged (the TCP verdict alone decides).
- **Ports are 1:1.** A relay must forward to the same port numbers the main server
  publishes.
- **The inbound is shared.** There is no per-relay inbound, tag or credential; the
  relay is visible only in the link the user holds.
- **The subscription URL stays on the main domain.** The sub-URL (`:2096` in the live
  deployment) is fetched from the main server's domain, not through a relay; only the
  links inside it point at relays. What moving it behind a relay would take:
  [Forwarding the subscription port](#forwarding-the-subscription-port-2096-through-a-relay).
- **Existing bundles gain relay members only through the admin reconcile.** Adding a relay
  or switching one on does not touch existing bundles by itself. Admin panel →
  «🧩 Протоколы и маршрутизация» → «🔗 All-in-One» → «Дополнить все подписки по текущим настройкам» adds the members through
  every relay that is enabled and «в подписках» to every active bundle (or «Перевести все
  подписки в базовый вид», which also drops the XHTTP members) — see
  [docs/subscription.md](subscription.md#bringing-existing-bundles-in-line).
