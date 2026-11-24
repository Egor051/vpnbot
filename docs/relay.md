# Relay ("via relay" keys)

A **relay** is a second entry point into this server: a small VPS (here: in Russia)
that forwards client traffic at L4 to the main server. A key issued "via relay" is an
ordinary key whose link points at the relay instead of the main host. There can be
**several relays**. They live in ONE table (`relays` in `vpn.db`) and on ONE screen of the
bot: **🛡 Админ-панель → 🧩 Протоколы и маршрутизация → 🛰 Relay** (the setup wizard's
«🛰 Relay» opens the same screen). With no relay in the table the feature is invisible.

**One model.** How a relay is managed is a property of the relay, not a separate entity:

- **with an agent** — the bot reaches `vpn-relay-agent` on the relay over SSH with its own key
  and runs status, update, ports/target and uninstall from the relay's page;
- **without an agent** — a relay set up by hand (the one that used to come from `RELAY_*` in
  `.env` among them). It works exactly as before; its page offers **«🔗 Подключить агент (ключи не
  меняются)»**, which connects an agent without changing the relay's name, host, label or keys.

A new relay is added with [one command from the bot](#installing-a-relay-with-one-command) —
**«➕ Добавить relay»** is the only way to create one.

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
- **The bot confirms it** on a relay with an agent: every agent call is a NEW ssh session of
  the bot's — through the hub in the fallback mode ([below](#managing-the-ru-relays-through-the-hub)) —
  so when `status` reports `PENDING CONFIRM`, the bot sends `input-confirm` and the agent runs
  `vpn-relay-apply input-confirm` inside that session (its «session began after the apply»
  check is the proof; the marker says `confirmed_by=ssh-session`). It does so right after
  «⬆️ Обновить агент», in the health loop, and on «🛡 Подтвердить входной фильтр» on the relay's
  card. Main's probe is then not needed.
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
  When main's probe could not run or did not answer, the PENDING line says why in plain words
  (`no answer in time: main is not reachable from this relay (blocked on the way? the fallback
  mode)`, `the connection to main was cut`, a 404 that also covers a request through the hub, …;
  `main probe: no result for this TCP set` when there is none) and the way that is left: a new
  ssh session — the bot's (by itself, or the card's button) or yours.

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

- **Phase 1** (read-only; `CHECK=1` stops here and prints a report): fetch `origin/main` and the
  tags, pick the [revision to deploy](#which-revision-a-relay-deploys) — the newest release by
  default, forward only — and hand over to THAT revision's `deploy.sh`; the
  same ruff / compileall / pytest gate on it as on the main server (a test venv is
  built under `/var/lib/vpn-bot-deploy/`, so the relay needs `python3-venv` — `deploy.sh` installs
  `python3.X-venv` itself when `ensurepip` is missing ([deployment.md](deployment.md#ensurepip)) —
  and ~1 GiB free; a fully green `CHECK=1` lets the deploy right after it skip the tests:
  [the Phase 1 stamp](deployment.md#the-phase-1-stamp)),
  `vpn-relay-apply check --dry-run` from the checkout, the relay's pre-state (including the
  runtime `nf_conntrack_max` and `nf_conntrack_tcp_timeout_established`), every unit of the
  relay's [unit set](#the-units-a-relay-deploy-installs) compared with its `deploy/relay/` copy
  (`absent`, `synced`, `differs`; `legacy` for the hand-made `vpn-relay.service`), and the checkout's `check` against the live
  relay — on a relay that still runs the hand-made ruleset `ok: table ip vpnrelay matches`
  there proves the repo reproduces it 1:1 (the exit is `16` until the
  [input filter](#the-input-filter) exists, `15` before the [conntrack](#conntrack) values are
  set, PASS after both). The dry-run names the SSH ports it found and whether the input
  filter's TCP set is confirmed — i.e. whether Phase 2 arms the dead-man — and the URL of main's
  probe that will confirm it, and a port that listens but would be filtered is called out:
  Phase 2's `check` would roll back.
- **Phase 2**: back up the live `nft list table ip vpnrelay` and
  `nft list table inet vpnrelay_input`, the installed helpers (`vpn-relay-apply`, the agent, …), every unit of the set, the sysctl file and the
  confirmation marker `/etc/vpn-relay/input.confirmed` (`/var/backups/vpn-bot/backup-relay-<sha>-<ts>.tar.gz`; nothing is
  stopped for it); `git checkout -f --detach <target>` (a relay's checkout is detached at its
  release — a local branch it was on stays where it is); install the helpers through
  `OUT_OF_REPO_HELPERS` (role `relay`) and every unit of the set verbatim (a copy that already
  matches is left as it is); `daemon-reload`, `enable` `vpn-relay` and every timer,
  `reload-or-restart vpn-relay` (a running relay is **reloaded**: `ExecReload` is the same atomic
  apply, with no `ExecStop` before it, so there is no moment without DNAT — what the installer has
  always done; a relay that is not running is started; a set that is not confirmed is confirmed by
  main's probe here), `start` a timer that is not active;
  verify with `vpn-relay-apply check` and **exactly one DNAT per forwarded port in the whole
  ruleset** (a second one in another table — `/etc/nftables.conf` at boot, say — would race the
  relay's; the installer always checked it). **An upstream that did not answer before the deploy
  either does not roll it back**: when the only failures of the verify's `check` are the upstream
  probe's (`FAIL: TCP connect …` / `FAIL: TLS handshake …`, exit 13/14 — the tables, the input
  filter and the sysctls passed) and every one of them was among the failures of Phase 1's check
  of the live relay (the same address and ports), the deploy is DEPLOY OK with a `WARN`
  `upstream unreachable before and after (pre-existing)` and the marker
  `[deploy:warn upstream_preexisting]` — the main server blocked on the relay's path (TSPU) is
  something no deploy can cause or fix. Any other failure, an upstream that answered before, or
  another address or port than Phase 1 saw rolls back as always (`reason=upstream` for the
  upstream's). The verdict is read from the FAIL lines, like the agent's
  `only_input_filter_failures`: `check` exits with its FIRST failure only. Around the host files the [SSH port](host-state.md#the-ssh-port)
  moves when `SSH_PORT` asks for it (phase 1: both ports; the reload of `vpn-relay` then lets
  them in and main's probe confirms them); right after DEPLOY OK `vpn-bot-ssh-port.service` looks
  for the proof once — when main's probe got through, the relay finishes in the same run; when it
  did not (the fallback mode, a blocked port), the bot asks a superadmin to confirm closing the old
  port and proves the new one by its own agent call on it, with no redeploy
  ([host-state.md](host-state.md#a-relays-migration-from-the-bot)).
  DEPLOY OK carries `ssh port: …` and `input filter : …` from
  `vpn-relay-apply input-status` — `CONFIRMED by main probe (…)` with nothing to do, or
  `PENDING CONFIRM (…) — <why>` followed by the reason and the instruction to run
  `input-confirm` from a NEW ssh session within 5 minutes.
- **Any failure** rolls back: the previous checkout (`PREV_SHA`, detached), helpers, units and sysctl file (or their
  absence), the saved forwarding table re-applied in one transaction, the input filter as it
  was — a confirmed one from its dump, one that did not exist removed, one that was still
  waiting for `input-confirm` removed too (restored, it could outlive its dead-man; removing is
  the safe direction) — the confirmation marker as it was (a confirmation main's probe wrote
  during the restart is for a set that is no longer live), the dead-man the deploy armed
  stopped, the enabled/active state of every unit (one that was not installed before is
  stopped, disabled and removed; a timer that was not active / enabled before is stopped /
  disabled again; the rollback report names every unit), the
  previous `ip_forward` and the previous runtime conntrack values (each read back; a value that
  was unreadable before the deploy — nf_conntrack not loaded — is left as `apply` set it). The
  deploy exits non-zero with a rollback report.
- A unit installed by hand that loads `/etc/vpn-relay.nft` is the **expected first
  transition**, not drift. After the first successful deploy `/etc/vpn-relay.nft` is renamed to
  `/etc/vpn-relay.nft.pre-repo.<ts>` (never deleted) and nothing reads it any more.

#### Progress of «Обновить агент»

**One message, one confirmation.** «⬆️ Обновить агент» edits THIS message: the deploy's steps ⚪
(preflight, fetch, tests, checks, backup, install, restart, verify) with «✅ Подтвердить» / «✖️ Отмена».
When TOTP is needed, the code is asked in the same message and is the confirmation itself — no second
step, no «▶️ Продолжить» (`require_totp_in_place`, bot/totp_gate.py). While the update runs the message
carries only «📄 Лог» (agent 5's `update-log`: the end of the deploy log as a file; an older agent —
the log's path on the relay); a second press of «Обновить» answers «уже идёт, запуск #N» and changes
nothing. At the end: the result, «📄 Лог» and «Назад» (for a [foreign sshd
override](#a-foreign-sshd-override) its button too).

Then the run: the long `update` call, and
next to it, every 10 s, **`update-status`** — a light, lock-free agent request answering
`/var/lib/vpn-relay/update.json`, where the agent writes the deploy's progress
(`deploy_progress`: the steps from deploy.sh's [step markers](deployment.md#step-and-result-markers)
and the tests — done of `[deploy:tests total=N]`) at most every 2 s while it reads the output.
Between polls the activity line moves locally. Why a state file and polling, not a stream: the
agent answers ONE JSON per call and its `update` channel is blocked on `systemd-run --wait`; a
file survives a dropped ssh connection (and the hub's hop) and costs one short ssh session per
poll. The result closes the steps — ✅, or ❌ on the step deploy.sh failed in, with the cause.

- **A poll answered after the update ended is dropped.** The poller stops before the result sets
  the final states, and the result is drawn without waiting for a poll still in flight (its ssh
  call finishes on its own). Up to v3.2.1 such a late «running» answer put «🔄 тесты — N/M» back
  over the ✅ — the Phase 1 flake of he2 (one vCPU) was this very race in its test.
- **An agent without `update-status`** (older than AGENT_VERSION 3, i.e. released before v3.2.1 —
  its version from the last `status`, or its «not an agent command» to the first poll) gets no list
  of steps that cannot move: ONE line «агент v3.2.0 — прогресс по шагам появится после этого
  обновления» with the activity line, and no further polls.
- **The failing step** is the result's `step` (deploy.sh's
  [result line](deployment.md#step-and-result-markers)); an agent older than the markers hands only
  its one-line message, so the step is read from it: a `[deploy:result failed step=…]` line in it,
  else the reason its text tells (`Phase 1 gate: pytest/ruff/compileall failed` → tests, a rollback
  → «проверка после рестарта», …) through ONE table, `REASON_STEPS` of services/deploy_result.py —
  the inverse of deploy.sh's `deploy_fail_reason` (a test runs that function for every step
  against it). Nothing tells it → no ❌ on any step and «шаг неизвестен» — never a guess onto the
  first step (he2: ❌ landed on «проверки перед деплоем» while pytest had failed).
- **A stop before any change** («stopped before any change … — nothing was changed»): the step and
  the reason come from the «result text → step» table — `TEXT_STEPS` of services/deploy_result.py:
  deploy.sh's own words with the step it dies in (`host invariants:` → checks, `NODE_ROLE` →
  preflight, a relay's release target → fetch, the test venv → tests, the backup → backup, …). A test
  walks EVERY «nothing was changed» of deploy.sh and pins its step — a new message without a row
  fails it. he2 (agent v3.2.0): «host invariants: 2 fatal finding(s)» showed «шаг неизвестен» — now
  «проверки».
- **The host check's findings** in the result: the key, file:line, what beat what
  («passwordauthentication: 00-password-login.conf:1 = yes beats the repo value no of
  00-vpnrelay-keyonly.conf»). Agent 5 hands them as `findings` (the DEPLOY VERDICT block reads the
  deploy's `FAIL BEATEN …` lines); for an older agent the text itself carries them: deploy.sh appends
  the findings to its refusal line («… — nothing was changed. Fatal: BEATEN sshd
  passwordauthentication: …»), which the agent forwards as it is.

#### Which revision a relay deploys

A relay follows **releases**, and has ONE update engine: this deploy. `sudo bash
scripts/redeploy.sh` on the relay and «⬆️ Обновить агент» in the bot (the agent's
[`update`](#the-agent-vpn-relay-agent)) both end in `deploy.sh`, and both pick the same revision:

- **default** — the newest release tag: `vMAJOR.MINOR[.PATCH[.BUILD]]`, compared as numbers
  (`v1.10.0` is newer than `v1.9.0`). Anything else is not a release: `v.3.1.0` (the typo tag
  on the repository), `v3.2.0-rc1`, `v3`. The rule is written twice — `relay_latest_release`
  in `deploy.sh`, `latest_release` in the agent — and `tests/test_relay_release_tag.py` runs
  both on the same tags, so they cannot drift apart.
- **`DEPLOY_REF=main`** — `origin/main`; **`DEPLOY_REF=<tag>`** or **`DEPLOY_REF=<commit sha>`**
  — that commit. On the main server `DEPLOY_REF` is refused unless it is `main`: main always
  deploys `origin/main` on local `main`.

And only **forward**:

| The checkout is | The deploy |
|---|---|
| behind the target (an ancestor of it) | deploys it; the checkout ends **detached** at the target, a rollback puts `PREV_SHA` back detached |
| at the target | `nothing to deploy` (`FORCE=1` redeploys it, `CHECK=1` inspects it) |
| ahead of the target | `INFO: … is ahead of latest release vX.Y.Z … nothing to deploy; DEPLOY_REF=main to follow main` — exit 0, a relay never goes backwards |
| on another line of history | refused before any change ("never moves sideways") |

Detached on a release tag, or ahead of one, is the normal state of a relay: Phase 1 reports where
the tree is and where it goes (`tree : … -> latest release vX.Y.Z (…), detached`) without a WARN.

The `deploy.sh` that runs is the **target's own**: `redeploy.sh` (itself `origin/main`'s copy —
a relay's checkout on a release tag usually differs from it, so the wrapper re-executes as that
copy after the fetch: [docs/operations.md](operations.md#which-copy-of-redeploysh-runs)) starts
`origin/main`'s `deploy.sh`, which picks the target and hands over (`exec`) to the `deploy.sh` of
that revision — a relay
deploying an older release must not run newer registry code against an older tree. A target
whose `deploy.sh` predates release-based relay deploys is refused (it would deploy `origin/main`);
`DEPLOY_REF=main` deploys main.

A relay deployed from `main` before this — 2026-11-16: ru1 at `1a87f67`, while the newest release
`v3.1.0` is older — stays where it is on a plain run (the INFO line above); it follows releases
again once a release newer than its commit exists. To keep it on main meanwhile (that run also
installs the agent that updates through `deploy.sh`), run **`origin/main`'s** `redeploy.sh` with
`DEPLOY_REF=main`, not the checkout's: the copy at `1a87f67` predates both `DEPLOY_REF`
forwarding and the re-exec, so `sudo DEPLOY_REF=main bash scripts/redeploy.sh` there prints
`deploy.sh env: <none>` and the knob never reaches `deploy.sh` (measured on 2026-11-16):

```bash
sudo git -C /opt/vpn-service fetch origin main
```

```bash
sudo git -C /opt/vpn-service show origin/main:scripts/redeploy.sh | sudo tee /root/redeploy-main.sh > /dev/null
```

```bash
sudo CHECK=1 DEPLOY_REF=main bash /root/redeploy-main.sh
```

```bash
sudo DEPLOY_REF=main bash /root/redeploy-main.sh
```

The `deploy.sh env:` line must read `DEPLOY_REF=main` (`PHASE1_ONLY=1 DEPLOY_REF=main` for the
`CHECK=1` run). Once the relay is on main, `scripts/redeploy.sh` re-executes as `origin/main`'s
copy by itself.

#### The units a relay deploy installs

The relay's unit set is **every `deploy/relay/*.service` and `*.timer`** (an `*.example.*` file
is not a unit). It is one rule (`relay_unit_names`), carried verbatim by `scripts/deploy.sh`,
`scripts/install.sh --relay` and `scripts/vpn-bot-host-check`, so a deploy installs exactly
what the installer installs and what the host check expects — never a hard-coded list
(`tests/test_deploy_relay_units.py` pins the three together). Today:

| Unit | Phase 2 |
|---|---|
| `vpn-relay.service` | installed verbatim, enabled, reloaded when running — started when not (`systemctl reload-or-restart`: `vpn-relay-apply apply`, no stop in between) |
| `vpn-relay-resolve.timer` | installed verbatim, enabled, started when it is not active |
| `vpn-relay-resolve.service` | installed verbatim only — its timer runs it; the deploy never starts it |

A unit whose installed copy already matches is not rewritten: a second deploy reports every
unit `synced` and changes none of them. The [host invariants](host-state.md#effective-state)
check after the install stays the gate — a unit of the set that is missing, not loaded from
`/etc/systemd/system/`, or a timer that is not enabled + active is a MISMATCH and rolls the
deploy back. With `RELAY_UPSTREAM_IPV4` (an address, not a [name](#a-dns-name-as-the-upstream))
the timer is installed and active all the same: `vpn-relay-apply resolve` then logs
`no RELAY_UPSTREAM_HOST (the upstream is an address) — nothing to do`, exits 0 and touches
nothing. A relay deployed before the deploy installed the resolve units (it has
`vpn-relay.service` only) gets them on its next deploy — they used to make the host check roll
that deploy back.

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
main's probe answers only the address of an enabled relay. (A new relay is created **out of**
«в подписках»: subscriptions get it only once you press «➕ Добавить в подписки» on its page —
conveniently after the deploy.) Then inspect, and deploy:

```bash
cd /opt/vpn-service && sudo CHECK=1 DEPLOY_REF=main bash scripts/redeploy.sh
```

```bash
cd /opt/vpn-service && sudo FORCE=1 DEPLOY_REF=main bash scripts/redeploy.sh
```

`DEPLOY_REF=main` and `FORCE=1` only on this first run: a fresh clone is already at `origin/main`
— ahead of the newest release, which a plain run would only report
([which revision a relay deploys](#which-revision-a-relay-deploys)) — and `FORCE=1` because it is
already at the target. Every later update is the usual `sudo CHECK=1 bash scripts/redeploy.sh`,
then `sudo bash scripts/redeploy.sh`: the next release newer than that commit; keep
`DEPLOY_REF=main` on both to follow main instead.

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

On the **main server**:

1. A DNS A record for the relay — e.g. `relay2.anycastedge.net` → the relay's IPv4 — with
   Cloudflare proxying **off** (see [DNS](#dns--use-a-name-not-an-address)).
2. The relay must be a row of `relays` before its first deploy (main's probe answers only the
   address of an enabled relay). The panel creates relays only through a pairing code: for a NEW
   relay use **«➕ Добавить relay»** — [the installer](#installing-a-relay-with-one-command) does
   everything this section does by hand, and the relay comes with its agent. A relay deployed by
   hand that is already in the table (the legacy one) gets its agent with **«🔗 Подключить агент»**
   on its page: the installer [adopts](#adoption-of-a-hand-made-relay) the hand-made setup.
3. **«🔍 Проверить сейчас»** on the relay's page: the health probe goes through the relay's DNAT
   to the main inbound and back (and asks the agent, when there is one).

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

**🛡 Админ-панель → 🧩 Протоколы и маршрутизация → 🛰 Relay → ➕ Добавить relay** (or the wizard's
«🛰 Relay», the same screen) asks three things and shows **one line** to paste on the relay:

1. the relay's **name** — written into every key of it, never changes (a free `relayN` is offered);
2. the **public host for links** — what every key's link points at. A DNS name (recommended: a new
   IP of the relay is then an A-record change, no key is re-imported); an IPv4 address is accepted
   with a warning — a burned IP has to be changed at every client. This is NOT the address the bot
   manages the relay through: the SSH address is asked separately when the pairing completes and
   kept apart (the agent's `ssh_host`);
3. the **main server's DNS name** the relay forwards to (the bot offers `XRAY_PUBLIC_HOST`).

The relay installs itself from the line, and the bot connects to it over SSH and manages it from
then on. The relay has **no Telegram bot and never talks to the Telegram API**: the only thing the
main server and the relay share is the bot's SSH key, whose line in the relay's `authorized_keys`
runs nothing but [the agent](#the-agent-vpn-relay-agent).

The same code mechanism **connects an agent to an existing relay** («🔗 Подключить агент» on a
relay's page, [below](#connecting-an-agent-to-an-existing-relay)): no name is asked, and nothing
about the relay or its keys changes.

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
  Next to it lives the bot's **jump key**, `/etc/vpn-bot/relay_ssh/id_ed25519_jump` — the same
  model (generated on the first call through the hub; in the helper-nonroot model create it the
  same way with `-C vpn-bot-relay-jump -f …/id_ed25519_jump`). It never reaches an agent: only the
  hub's sshd knows it, and only to forward to the relays behind the hub
  ([below](#managing-the-ru-relays-through-the-hub)).
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

«🔌 Подключить» (TOTP) → send the relay's SSH address (`IP`, `IP:port` or a DNS name). The bot:

1. connects as `root` with its key — **trust on first use**: the relay's host key is learned
   now and pinned in `relays.host_key`; every later call runs with `StrictHostKeyChecking=yes`
   under `HostKeyAlias=vpn-relay-<id>`, and a relay that shows another key is refused («ключ хоста
   relay изменился»);
2. runs `hello <token>`; the agent compares the sha256 in constant time, within the expiry, and
   marks itself paired. A repeated `hello` with the same token answers again (the bot may retry
   its checks), any other token is refused;
3. checks the relay **from outside**, both through its DNAT to this server: **TCP** — a verified
   TLS handshake with `XRAY_SNI` to `<relay>:XRAY_PUBLIC_PORT` (the [health probe](#health-monitor));
   **UDP** (when Hysteria2 is on) — a QUIC packet with a reserved version to
   `<relay>:HYSTERIA2_PORT`, which every QUIC server answers with version negotiation. A failure of
   either changes nothing and offers «Подключить снова»;
4. **a new relay**: creates the row of `relays` WITH its agent, in one transaction with closing the
   code — enabled, **not** «в подписках» (it joins them with «➕ Добавить в подписки»,
   [below](#in-subscriptions-an-action-on-every-subscription)), «👁 в базовых», label `relay` or the
   name, `host` = the public host for links
   from the code, **source IPs** = the address it is reached at plus the source address the agent
   reports for the upstream, when that is public (what the [anomaly detector excludes](#limitations)).
   When the public host does not resolve to the relay, the result says so;
5. the [health monitor](#health-monitor) watches it from the next pass on and alerts the
   superadmins when its state changes (`RELAY_HEALTH_INTERVAL`, default 300 s; with `0` the result
   says there will be no alerts).

### Connecting an agent to an existing relay

A relay without an agent (set up by hand — the legacy `ru1`) keeps working as it is. Its page says
«⚠️ без агента» and offers **«🔗 Подключить агент (ключи не меняются)»** (TOTP): a pairing code
for THAT relay — no name asked — and the one line for it. On the relay the installer
[adopts](#adoption-of-a-hand-made-relay) the hand-made setup (the old files and tables go to
`/var/backups/vpn-relay/`, the forwarding is never interrupted). Then «🔌 Подключить» with the
relay's SSH address, as above, except:

- **it must be the same server**: the SSH address equals the relay's host, lies inside its source
  IPs, or is an address the relay's host resolves to — otherwise **«это другой сервер»**, nothing is
  asked of that server and the code stays pending for the right address;
- **nothing about the relay changes** but the agent columns: name, label, host for links, on/off,
  «в подписках» and every key stay byte-identical, so links and subscriptions do not change.
  `source_ips` may only **grow** — by the addresses the agent reports that the list does not cover
  yet; nothing is removed;
- **any failure leaves the relay exactly as it was**: the agent columns, the source IPs and the
  code are written in ONE transaction, after the checks;
- a relay that already has an agent cannot get a second one; a code already waiting is shown again
  instead of a new one; deleting the relay cancels its waiting code.

**«🔌 Отключить агент»** is the reverse: the agent columns are cleared — the relay and its keys stay,
it is a hand-made relay again (nothing lost: host, label, source IPs as they were). Optionally
«🧹 Отключить и снять с relay» runs `uninstall` on the relay first; that also removes its forwarding,
so its keys stop working until the relay is set up again (the screen says so).

### The agent (`vpn-relay-agent`)

`scripts/vpn-relay-agent` (stdlib Python). sshd runs it for the bot's key whatever the client
asks; the request comes in `SSH_ORIGINAL_COMMAND` and must match one of these **exactly**
(full-string patterns, ASCII, at most 4096 characters — the `jump` list is the longest); everything else — shell syntax, a second
line, extra words, an argv, an interactive login — is refused with exit 2 before anything runs:

| Request | Does |
|---|---|
| `hello <token>` | Complete the pairing; answers the relay's facts. The only request before pairing. |
| `status` | Facts: target, ports, the live DNAT target, what the name resolves to now, `ip_forward`, the units (`vpn-relay.service` and every timer of the set below), the ssh ports, the egress source address, the checkout, the last update, `vpn-relay-apply check`, `vpn-relay-apply input-status` (`input_status`), on a hub its jump line (`jump`: the relays it opens, the key's fingerprint), and from agent 5 `sshd_drift` (the login keys whose `sshd -T` value is not the repo's; cheap, every call) and `sshd_overrides` / `host_check_at` (what the host check's last run named — its `last.json`), [a foreign sshd override](#a-foreign-sshd-override). |
| `apply target=<dns name> tcp=<ports> udp=<ports>` | Re-point / re-port: refused for a name that is not a name or does not resolve on the relay, a port outside 1..65535, more than 8, a TCP port sshd listens on. Rewrites only `RELAY_UPSTREAM_HOST` / `RELAY_FORWARD_*`, applies, checks; puts `.env` back and re-applies when the ruleset or the check (table, sysctls, the upstream not answering) fails. |
| `update` | In a transient unit (`systemd-run --wait`): fetch the release tags, pick the newest release ([the same rule as the deploy](#which-revision-a-relay-deploys)) — only forward, never backwards or sideways — and run the relay's deploy for it: `scripts/redeploy.sh` with `DEPLOY_REF=<tag>` (that tag's `deploy.sh`, in its own transient unit, log `/root/deploy-<ts>.log`): the pytest gate, helpers, units and host files, the reload of vpn-relay, the checks; `deploy.sh` rolls back by itself. The agent never checks anything out. The result (`running` / `noop` / `failed` / `succeeded`, `from_commit`, `to_commit`, `release`, `log`; for a failure `reason`, `step`, `excerpt` — the cause deploy.sh reported in its [result line](deployment.md#step-and-result-markers), its step and the lines that tell it; for a success `warnings`) is in `/var/lib/vpn-relay/update.json` and in `status`; a failed `update` answers with the whole result, and the bot shows the cause, the step, those lines and the log path instead of «the relay refused». Minutes: the agent waits up to 45 minutes. |
| `uninstall` | In a transient unit: the units of the set below stopped and removed (timers first, `vpn-relay.service` last), both tables deleted, the sysctl file removed and `ip_forward` back to what it was before the install, the helpers, `/etc/vpn-relay`, `/var/lib/vpn-relay`, the checkout (when the installer created it), the agent's key line and the jump line removed. The adoption backup stays. Refused on a host without the installer's `/etc/vpn-relay/install.json`. |
| `input-confirm` | Runs `vpn-relay-apply input-confirm` as a direct child — the bot's ssh session (a new one) is among its ancestors, which is the proof that check wants ([dead-man](#keeping-access-the-dead-man-and-input-confirm)). Answers the helper's lines and the new `input-status`. Takes no agent lock: the filter waits for its confirmation exactly while `update` holds it. |
| `jump key=<ed25519 blob> open=<host>:<port>[,…]` | A hub: write the bot's ONE jump line in root's authorized_keys (`restrict,port-forwarding,permitopen="<host>:<port>"[,…],command="/bin/false" ssh-ed25519 <blob> vpn-bot-relay-jump`) — [below](#managing-the-ru-relays-through-the-hub). A DNS name or IPv4 (not loopback, link-local, multicast), port 1..65535, unique, at most 32; a key that already has another line in the file (the agent's own) is refused; refused while `sshd -T` allows remote forwarding (not `allowtcpforwarding local`). Every other line stays byte-identical. Its own lock, so a hub's `update` does not hold it up. |
| `jump-off` | A hub: remove that line. |
| `ssh-port-finish port=<p> since=<s>` | Phase 2 of the SSH port migration — only from a session that came in on `<p>` (its `SSH_CONNECTION`): `vpn-bot-ssh-port confirm-session` writes the proof and closes the old port ([host-state.md](host-state.md#a-relays-migration-from-the-bot)). |
| `ssh-port-keep since=<s>` / `ssh-port-resume since=<s>` | Hold phase 1 (the old port stays, no proof finishes it) / go on with the migration. |
| `ssh-port-set port=<p>` | `SSH_PORT=<p>` in `.env`, then `vpn-bot-ssh-port begin --keep <this session's port>`: both ports listen now, no deploy; the port the bot came in on never closes; `.env` restored on a failure (a failed input filter included). A forwarded port is refused. |
| `input-filter on` / `input-filter off` | Agent 4. `on`: the filter is applied from a **staged** copy of `.env` with `RELAY_INPUT_FILTER=on` (`/etc/vpn-relay/input-filter.env`, `RELAY_ENV=<stage> vpn-relay-apply apply`) — the live `.env` is not touched yet; an unconfirmed TCP set arms the [dead-man](#keeping-access-the-dead-man-and-input-confirm), main's probe may confirm it in that apply. Confirmed (`input-status` OK / CONFIRMED) → `.env` gets `on` (`"committed": true`); still PENDING → the bot runs `input-confirm` from a NEW session and asks `on` again, which commits. Never confirmed → the dead-man removes the table and `.env` never said `on`. A failed apply → the live `.env` applied again, exit 4. `off`: `RELAY_INPUT_FILTER=off` and apply (the table goes, a waiting dead-man is disarmed); a failed apply puts `.env` back. [Bringing a relay to the defaults](#bringing-a-relay-to-the-defaults). |
| `sshd-check` | Agent 5. A fresh `vpn-bot-host-check` run (read-only; it writes only its own `last.json`): the files in `sshd_config.d` that beat a repo login key (`sshd_overrides`: path, keys, the check's texts, mtime) and `sshd_drift`. |
| `sshd-override-off path=<file>` | Agent 5. Move ONE [foreign sshd override](#a-foreign-sshd-override) to `/root/attic/<name>.<epoch>` (never delete it), `sshd -t`, `systemctl try-reload-or-restart ssh`, `sshd -T`; rolled back on any failure. The path is only a file directly in `/etc/ssh/sshd_config.d/` (no glob, no `/`, not the repo's file), and only one a FRESH host check run names; without an own key in root's authorized_keys — refused. |
| `update-log` | Agent 5. The end (96 KiB) of the deploy log of the last (or the running) update — the `/root/deploy-<ts>.log` redeploy.sh named (`update.json`); read-only. The «📄 Лог» button under an update. |

**The units** are not a list in the agent. They are read from the checkout by the same rule deploy.sh,
install.sh and the host check use (`relay_unit_names`): every `deploy/relay/*.service` and `*.timer` of
`/opt/vpn-service`, never an `*.example.*`. So a unit added there is stopped, disabled and removed by
`uninstall` and shown by `status` as soon as deploy/install install it. `uninstall` stops the timers first,
so none fires its oneshot halfway through. The oneshots go next, and `vpn-relay.service` goes last, because
its `ExecStop` removes the tables. With a checkout, only its set is touched. Without one (removed, or on a
ref without `deploy/relay/`), `uninstall` uses the `vpn-relay.service` / `vpn-relay-<name>.service|.timer`
files present in `/etc/systemd/system`, plus `vpn-relay.service`.

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

### Managing it from the relay's page

A relay with an agent shows «агент vX», the SSH address, the target and the ports, and the agent's
last `status` (the live DNAT target, the units, `vpn-relay-apply check`, the version, the last
update). Its page adds: «⬆️ Обновить агент» (`update`), «⚙️ Порты / цель» (`apply` — send
`vpn.example.com tcp=443 udp=443`), «🔌 Отключить агент», and «🗑 Удалить» runs `uninstall` on the
relay before the row goes (a relay that does not answer offers «Удалить только запись»). An agent
call that takes minutes (update, apply, uninstall) marks only THAT relay busy — the screen stays
usable, another change of that relay meanwhile is refused («relay занят»). Every change asks for the
TOTP code ([below](#managing-relays-in-the-admin-panel)) and is audited (entity `relay`).
With the fallback screen on, a relay that is not a hub also has **«🛟 Через hub: вкл/выкл»**
([through the hub](#managing-the-ru-relays-through-the-hub)), and the page says when its agent is
reached through the hub. While the agent's last `status` reports the input filter `PENDING CONFIRM`,
**«🛡 Подтвердить входной фильтр»** sends `input-confirm` (the status lines show the filter's state).
While the relay is not [at the defaults](#bringing-a-relay-to-the-defaults), the page says so in a
warning line and has **«🛡 Довести до нормы»**.

### Limits of the installer relay

- **No input filter, SSH where it was**: the installer sets `RELAY_INPUT_FILTER=off` and
  `SSH_PORT=<the port sshd listens on now>` — on purpose, so the first deploy cannot cut the bot off.
  The bot brings it to the defaults afterwards, with a superadmin's «Довести»
  ([below](#bringing-a-relay-to-the-defaults)).
- `redeploy.sh` and the agent's `update` are the same engine (`deploy.sh` in the relay role, the
  newest release by default): an installer relay can be deployed by hand at any time, and the
  host files come with every update either way. An agent from before that (it called
  `install.sh --relay-update`, which now only refuses) gets the new one with ONE manual
  `sudo bash /opt/vpn-service/scripts/redeploy.sh` on the relay — `DEPLOY_REF=main` on a relay
  that is already ahead of the newest release.
- `/etc/vpn-relay/install.json` records what `uninstall` needs; its `ref` is the commit the
  **install** put in place (a re-install rewrites it) — never kept current: deploys and
  `update` move the checkout without touching the file. The commit a relay runs is
  `git -C /opt/vpn-service rev-parse HEAD` (`status`: `checkout.commit`).
- IPv4 only, like the rest of the relay.

### Bringing a relay to the defaults

**Why.** `install.sh` (`relay_write_env`) writes a NEW relay `SSH_PORT=<the port sshd listens on
now>` and `RELAY_INPUT_FILTER=off`, so its first deploy cannot cut the bot off. Nothing moved them
on: he2 — the hub, through which ALL traffic goes in the fallback mode — kept `SSH_PORT=22`,
`RELAY_INPUT_FILTER=off`, sshd on `:22` only.

**What is left** is read from the agent's last `status` (`hardening_of`, services/relays.py):
*SSH on 22* — `ssh_migration.ssh_port` (the SSH_PORT in effect) is 22 and no migration is under way
(an agent without the plan: `ssh_ports` is `[22]`); *the filter off* — `input_status` starts with
`off`. A custom port (2222) is left alone.

**The alert.** Right after a pairing (its `hello` is the relay's first status) and, for a relay that
was there before, from a kept status (the health loop, a check) or when its card is opened, the
superadmins get ONE message in bold — «⚠️ relay X: SSH на 22, входной фильтр выключен — довести до
нормы?» — with **«🛡 Довести до нормы»** and **«Позже»**. Once per pairing (`schema_meta`
`relay_hardening_told`, keyed by the relay and its `paired_at`: a re-pair asks again); «Позже» is
remembered too (`relay_hardening_later`) and nothing asks again. The way back is always there: the
warning line and the button on the relay's card, the wizard's «🔑 SSH-порт relay» (the relay's
screen) and **«🛡 Входной фильтр relay»** (every relay with an agent, its `input-status`, «Довести»
for each one not at the defaults).

**«Довести»** (TOTP: `relay_harden`; an agent older than it needs — `input-filter` is agent 4,
`ssh-port-set` agent 3 — gets «сначала обновите агент» with «⬆️ Обновить агент», and nothing is
sent) shows the plan (each step ⚪, «✅ Подтвердить»), then runs it with
[the progress](#progress-of-обновить-агент) in the same message (`RelayService.harden`):

0. **A foreign sshd override** — always first: `sshd-check` (a fresh host check), then
   `sshd-override-off` for each file it names ([below](#a-foreign-sshd-override)). An agent older
   than 5 — the step is ⏭ (its status cannot name an override).
1. **The input filter** — `input-filter on` (the staged apply, the dead-man armed); unless main's
   probe confirmed it already, `input-confirm` from a NEW ssh session of the bot (through the
   hub's jump for a relay behind the hub — [below](#managing-the-ru-relays-through-the-hub)); then
   `input-filter on` again, which finds the set confirmed and commits `.env`. **Rollback**:
   `input-filter off`; a relay the bot cannot reach at all is rolled back by the dead-man within
   5 minutes (`.env` never said `on`).
2. **SSH off 22** — `ssh-port-set port=54321` (phase 1: 22 and 54321; the filter follows the
   listeners, its new TCP set confirmed by main's probe or the bot's new session), then
   `finish_ssh_port` — the bot's call ON 54321 is the proof, phase 2 closes 22
   ([host-state.md](host-state.md#a-relays-migration-from-the-bot)). **Rollback**: 54321 does not
   answer → `ssh-port-set port=22` cancels phase 1 (22 alone again).

Each step is atomic; a failed one is rolled back and the step before it stays done. **The filter
goes first** on purpose: it is the bigger protection (every listener but sshd closed on the host
that carries the traffic) and the step that heals itself (the dead-man), so a port move that
cannot finish — a provider's firewall dropping 54321 — leaves the relay filtered, on 22. The move
then runs the path every default relay takes (filter on; main's probe of {22, 54321} is also a
proof for phase 2). The price: two more dead-man rounds, each confirmed by the bot itself.

### A foreign sshd override

**What happened on he2 (the hub).** On 2026-11-18 `/etc/ssh/sshd_config.d/00-password-login.conf`
appeared (not from the repo; most likely the hoster's panel on a password reset) with
`PasswordAuthentication yes` / `PermitRootLogin yes`. By file order (sshd takes the FIRST value) it
beats `00-vpnrelay-keyonly.conf`: the hub takes passwords again. `vpn-bot-host-check --pre-install`
reports it BEATEN and the relay's deploy stops in Phase 1 — rightly; but the bot showed only «2 fatal
finding(s)», and only a hand could fix it.

**What shows now.** The update's result names the findings — the key, file:line, what beat what
([progress](#progress-of-обновить-агент)) — and the step «проверки». For a finding of the class «a
file directly in `sshd_config.d` that the repo does not install beats a repo login key»
(`passwordauthentication`, `kbdinteractiveauthentication`, `permitrootlogin`, `permitemptypasswords`,
`pubkeyauthentication`, `authenticationmethods` — the list of deploy.sh's
`HOST_CHECK_SSHD_AUTH_KEYS`) — the button **«🧹 Убрать чужой override»**.

**What the button does** (TOTP `relay_sshd_override`, the code in the same message; agent 5,
`sshd-override-off path=<file>`):

- the path is only a file directly in `/etc/ssh/sshd_config.d/` (the agent's and the bot's
  whitelist, `WHITELIST` and `_REQUEST`, in step; no glob, no subdirectory, not a file the repo
  installs);
- the agent runs the host check again and removes the file only when that run names it (never
  because the bot says so);
- root's `authorized_keys` must hold at least one line without `command=` — an operator's own key;
  otherwise refused, «add your own key, or you will lose your way in» (with the agent's and the jump
  key's lines only, key-only login would shut the operator out);
- the file is **moved** to `/root/attic/<name>.<epoch>` (never deleted), `sshd -t`, `systemctl
  try-reload-or-restart ssh`, `sshd -T` compared with the repo's value of every key it beat (a key
  ANOTHER foreign file still beats is not a rollback: that file is named in the answer, remove it
  too). Any failure puts the file back, `sshd -t` and the reload again.

**An agent older than 5** (he2 on v3.2.0): the update that would bring the new agent stops on this
very file. The bot shows the one-time fix by hand (over ssh with your own key):

```bash
mkdir -m 700 -p /root/attic
mv /etc/ssh/sshd_config.d/00-password-login.conf /root/attic/
sshd -t && systemctl reload ssh
```

then «⬆️ Обновить агент»; from then on the bot removes such a file itself.

**When the file comes back.** Agent 5's `status` carries `sshd_drift` (the login keys whose `sshd -T`
is not the repo's — cheap, every call of the health loop) and `sshd_overrides` (what the check's last
run named — `vpn-bot-host-check.timer`, daily and 5 minutes after boot). The monitor
(services/relay_sshd_override.py) sends the superadmins a message with the same button — ONCE per
file and its mtime (`schema_meta`, a restart does not repeat it): a repeated «password reset» in the
hoster's panel is a new file, a new mtime — told again. A drift with no file named yet makes the bot
ask `sshd-check` itself, at most hourly per relay. A second password reset never silently re-opens
password login on the hub. The same check is the first step of [«Довести до
нормы»](#bringing-a-relay-to-the-defaults).

## Managing relays in the admin panel

SUPERADMIN only. **🛡 Админ-панель → 🧩 Протоколы и маршрутизация → 🛰 Relay** — ONE screen for
every relay; the setup wizard's «🛰 Relay» opens it too (it has no list of its own). The list shows
each relay with its label, name, host for links, on/off, «в подписках», «👁 в базовых», the number
of active keys, its [health](#health-monitor) (one icon, one reason) and how it is managed —
«агент vX» or «⚠️ без агента»; then the codes still waiting. Above the relays is the **main
server's** line (the direct keys) with its «👁 в базовых», and below them its switch **«👁 Основной
сервер в базовых: да/нет»** ([below](#in-basic-a-servers-visibility-in-basic-subscriptions)): the
main server has no page of its own.

**A relay's page** — common actions for every relay:

- **«✏️ Хост ссылок»** — the host links point at (DNS name or IPv4; IPv6 is refused). After a change
  the page says that subscriptions already point at the new address and how many single relay keys
  must be re-imported; an IPv4 host gets the «burned IP» warning, and one the source IPs do not
  cover is offered as a source IP;
- **«✏️ Переименовать»** — the label: the relay's name in lists and its marker in key names, unique
  per relay, 1–16 characters on one line, emoji welcome (`🇷🇺➜`), glued to the flag with no `_`.
  The **name** (`^[a-z0-9][a-z0-9-]{0,31}$`, what keys carry in `vpn_keys.relay`) never changes;
  a name any key row still carries — in any status — is never given to a new relay;
- **«✏️ Source IPs»**, **«✏️ Заметка»**, **on/off** ([below](#switching-a-relay-off)),
  **«➕ Добавить в подписки» / «➖ Убрать из подписок»**
  ([below](#in-subscriptions-an-action-on-every-subscription)), **«👁 В базовых: да/нет»**
  ([below](#in-basic-a-servers-visibility-in-basic-subscriptions)),
  **«🔍 Проверить сейчас»** (one health pass: traffic and the agent; the verdict stays on the page),
  **«🗑 Удалить»** ([below](#deleting-a-relay));
- the **agent block**: «🔗 Подключить агент» for a relay without one, or status / update / ports and
  target / disconnect for a relay with one ([above](#managing-it-from-the-relays-page)).

**«➕ Добавить relay»** is the only way to create a relay — through a pairing code, so a new relay
always comes with its agent ([above](#installing-a-relay-with-one-command)). The panel offers no
form that writes a relay without one.

**Every change is a dangerous action**: with TOTP on, the button asks for the code first
([wizard.md](wizard.md#where-it-is-asked)) — on/off, «➕ Добавить в подписки» / «➖ Убрать из
подписок» (the code is asked on «✅ Выполнить» under the plan), «👁 в базовых» of a relay and of the
main server, every edit, the source IP
offer, delete (with or without keys, record only), «Добавить relay», «Подключить агент»,
«Подключить», update, ports/target, disconnect. A step that waits for typed input checks the
elevation again before it acts. Every change is audited (entity `relay`) with the values before
and after: `relay_updated`, `relay_deleted`, `relay_delete_incomplete`, `relay_pairing_issued`,
`relay_pairing_cancelled`, `relay_pairing_check_failed`, `relay_paired`, `relay_attach_refused`,
`relay_agent_attached`, `relay_agent_detached`, `relay_agent_update`, `relay_agent_apply`,
`relay_agent_uninstall`, `relay_main_basic_visibility_changed` (the main server «в базовых»).
Adding and removing a relay's members in subscriptions is audited per subscription (entity
`key_bundle`): `key_bundle_relay_members_added` / `key_bundle_relay_members_removed`, on a failure
`key_bundle_reconcile_rolled_back` / `key_bundle_reconcile_partial`; the details carry `relay` and
`relay_action`.

Every change **takes effect on the next rendered link**: the bot keeps an in-memory snapshot of the
table that every write replaces immediately (the bot is the only writer); the subscription endpoint
(`vpn-bot-subscription`) reads the table on **every request** through its read-only connection.

**Buttons from before** — messages in the chat history of the two former sections («🛰 Управлять
relay» and «Мастер настройки → Relay», `wrl:*`) and of the old manual «Добавить relay» lead to this
screen: a relay's button to its page, a code's to the code, everything else to the list — never to
an error, and an old button never changes anything by itself. The former «Убрать из подписок /
Вернуть в подписки» toggle opens the plan of what it means now (add or remove, by the relay's
current state) and changes nothing without a confirmation either.

### «In subscriptions»: an action on every subscription

«В подписках» is not a "for new bundles" flag but an action on **every** issued subscription at
once:

- **A new relay is created out of subscriptions** (`in_subscriptions=0` — through the pairing and
  in `RelayService.create`). Existing relays do not change. The schema column keeps `DEFAULT 1`:
  SQLite cannot change a column default without rebuilding the table, and rebuilding `relays`
  inside the bootstrap transaction (where `PRAGMA foreign_keys` cannot be switched off) would fire
  the `ON DELETE SET NULL` of `relay_pairings.relay_id` and orphan pending codes. So the code sets
  the value: every insert names the column explicitly and the default is never used.
- **«➕ Добавить в подписки»** — a dry run over every active subscription and a plan screen («to be
  topped up N, keys to create X, skipped …»); nothing changes before «✅ Выполнить». Once confirmed,
  the relay is marked «в подписках» (new subscriptions get it on their own), and in the background
  every active subscription gets **only this relay's members**: basic — 2 (VLESS (TCP),
  Hysteria2), extended — 5 (plus the three VLESS (HTTP)); a protocol switched off right now is not
  created, exactly as on creation. The subscription's kind, the direct keys, VLESS (HTTP) and the
  members of other relays are not touched. A disabled relay cannot be added — a clear refusal
  («enable it first»).
- **«➖ Убрать из подписок»** — the same with a plan «affected N subscriptions, keys to delete Y»;
  once confirmed, the relay leaves «в подписках» and each of its members is deleted from every
  active subscription the way a subscription delete removes it (Xray client, traffic archive,
  audit). A subscription that would be left with no active key at all (its others revoked one by
  one) is skipped with the reason.
- The guarantees are those of the bulk reconcile
  ([docs/subscription.md](subscription.md#bringing-existing-bundles-in-line)): creates first, and a
  failure rolls back what this subscription got; then deletes, and after a failure a re-run
  finishes the job (the «🔁 Повторить» button under the report); new keys get the subscription's
  shared `expires_at` and VLESS fingerprint; the token never changes; an unusual subscription
  (mixed expiry, a duplicate member, an inactive member, a degraded backend) is skipped with the
  reason. A child of this relay whose earlier removal did not finish (`delete_failed`) is cleaned
  up and its slot filled afresh.
- The run goes in the background with progress (at most every 3 s) and a final report — on the
  same runner as «🔗 All-in-One», so only one bulk run of either kind goes at a time.
- With `SUBSCRIPTION_ENABLED=false` no subscription is issued: the button only flips the flag.

### «In basic»: a server's visibility in basic subscriptions

**«👁 В базовых: да/нет»** on a relay's page (`relays.basic_visible`, yes by default) and
**«👁 Основной сервер в базовых: да/нет»** on the list (the `basic_visible_main` key in
`schema_meta` — the database's runtime settings store, not `.env`; no key means shown) decide
whether a **basic** subscription serves that server's children:

- applied **only when rendering** and **only to basic** subscriptions; extended ones are unchanged.
  Keys, Xray clients and subscription rows are untouched, so the switch is instant and reversible:
  clients see it on their next subscription update;
- **a basic subscription is never empty**: hiding a server (or taking a relay out of
  subscriptions) after which basic subscriptions would have no visible server left — the main one,
  or a relay that is enabled, «в подписках» and «👁 в базовых» — is refused, and the bot says why.
  Switching a relay off or deleting it is never refused (those are emergency actions); when that
  leaves no visible server, the relay list warns about it and the endpoint serves basic
  subscriptions **unfiltered** with a `WARNING` in the log (fail-open) — showing a hidden server
  beats serving an empty subscription.

### Switching a relay off

- **off** (`enabled=0`): its keys' links are refused (`RelayUnavailable`, the bot shows
  an error instead of a link), its members are skipped in subscriptions (logged at
  WARNING; direct members are still served), and it is not offered for new keys or
  bundles. Its source IPs **stay excluded** from anomaly detection — clients may still
  be connected. Switching it back on brings everything back unchanged.
- **not in subscriptions** (`in_subscriptions=0`): neither new nor issued all-in-one
  bundles carry members through it — «➖ Убрать из подписок» deletes them from the issued
  ones ([above](#in-subscriptions-an-action-on-every-subscription)); single keys can still be
  issued through it while it is on.

### Deleting a relay

- A relay **with an agent**: `uninstall` runs on the relay **first** — so no DNAT to this server is
  left behind — and only then is the row deleted. A relay that refuses or does not answer: nothing
  is deleted, and the screen offers **«Удалить только запись»** (the relay itself keeps forwarding
  until it is cleaned up by hand). After an `uninstall` the relay is marked, so an interrupted
  delete resumes without a second one.
- A relay **without an agent**: only the record is deleted; nothing is done on the relay itself.
- **No keys** go through it (outside status `deleted`): one confirmation.
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
SQL statement), so a key issued while the delete runs cannot be orphaned; its waiting
«Подключить агент» code is cancelled in the same transaction.

## The obsolete `RELAY_*` in `.env`

Relays used to be configured with `RELAY_ENABLED`, `RELAY_NAME`, `RELAY_HOST` and
`RELAY_SOURCE_IPS`; an earlier release seeded the relay they described into the table once (that
is how `ru1` got there). They are **not read any more — not even parsed**:

- a value left in `.env` cannot stop the bot, malformed or not;
- the bot logs ONE `WARNING RELAY_* в .env устарели и не читаются … — удалите их: <names>` at
  startup;
- the wizard's self-check shows the same as a yellow item (`legacy_env`).

Delete the lines. `RELAY_HEALTH_INTERVAL` and `SERVER_FLAG_EMOJI` are live settings and stay.

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
| `RELAY_ENABLED`, `RELAY_NAME`, `RELAY_HOST`, `RELAY_SOURCE_IPS` | — | **Obsolete.** Not read; one WARNING at startup and a yellow self-check item until they are deleted ([above](#the-obsolete-relay_-in-env)). |

**There is no relay port setting**: the port in a relay link is the protocol's own
public port (`XRAY_PUBLIC_PORT`, `HYSTERIA2_PORT`), because the relay forwards 1:1.

## Fallback mode (hub)

**Why.** The TSPU blocks the main server's IP at the Russian border **in both directions**:
clients in Russia, the RU relays and the main server cannot reach each other, and the main
server's egress IP cannot change. The way out is the **hub**: a relay **outside Russia** with a
clean IP that the main server still sees. In the fallback mode only the hub talks to the main
server, and every name of the **failover set** points at the hub:

```
normal mode:                            fallback mode:

client ─▶ RU relay ─▶ main              client ─▶ RU relay ─▶ hub ─▶ main
client ─────────────▶ main              client ─────────────▶ hub ─▶ main
          (A: anycastedge.net → main)             (A: anycastedge.net → hub)
                                         hub → origin.anycastedge.net → main's IPv4 (always)
```

**The RU relays need no switching** — nor could they get it: the main server cannot reach them
at that moment. They forward to a DNS name (`RELAY_UPSTREAM_HOST`,
[above](#a-dns-name-as-the-upstream)), and `vpn-relay-resolve.timer` re-points their DNAT to the
new A record by itself every 5 minutes. Subscriptions (`HYSTERIA2_SNI:2096`) are rendered per
request and go through the hub too when the subscription's name is in the set.

Screen: **🛰 Relay → 🛟 Fallback mode**. The relay list carries one line with the state (off / ON /
⚠️ the switch is not finished).

### What the hub needs

- **outside Russia** with a **clean** IP: both the clients / RU relays and the main server must
  reach it;
- a relay **with an agent** (the bot re-points its forward itself), switched on;
- **deployed** with local-only forwarding (`00-vpnrelay-forwarding.conf`, installed by every relay
  deploy) before the bot can manage the RU relays through it
  ([below](#managing-the-ru-relays-through-the-hub)) — «⬆️ Обновить агент» deploys it;
- **conntrack and bandwidth**: **ALL** traffic of every client and every RU relay goes through the
  hub — size `RELAY_CONNTRACK_MAX` ([conntrack](#conntrack)) and the link for the whole audience;
- the hub forwards TCP `XRAY_PUBLIC_PORT` + `SUBSCRIPTION_PUBLIC_PORT` and UDP `HYSTERIA2_PORT`
  (the bot sets that itself when it gives the role);
- **one** enabled hub is supported for now. The model allows several (`relays.role`); the choice
  goes through `services.relay.select_hub` — the place for a future balancer.

### The origin name: why there is a loop without it

The hub forwards to the **origin** — a separate name (e.g. `origin.anycastedge.net`) that
**always** points at the main server's IPv4 and is **never** in the failover set. If the hub
forwarded to a name of the set, that name would point at the hub itself after the switch — the
hub would DNAT into itself and **every** client would lose the connection. Hence:

- **«🛟 Make it the hub»** on the page of a relay with an agent asks for the origin (suggesting
  `origin.<the zone of HYSTERIA2_SNI>`); the bot creates/corrects its A record through the DNS
  API (`proxied=false`, TTL 60) → waits until public resolvers (DoH) answer the main server's
  IPv4 → the agent runs `apply target=<origin> tcp=443,2096 udp=443` (the agent's check is a TCP
  connect to the main server on **each** port; a failure rolls the relay back) → checks that the
  hub looks at the main server (the agent's `live_target` / `resolved`) → the role `hub`. Any
  failure leaves the role as it was;
- the origin and the hub's host **cannot** join the set; a name of the set cannot be the origin;
- the loop is checked when the role is given and **before every switch-on** (the preflight).

The role can be removed only when no name of the set points at the hub — the mode is off **and**
the switch-off finished (a name the bot moved to the hub and could not write back keeps the role).
The hub's forward is left as it is. While a relay is the hub it cannot be deleted, have its agent
detached (`uninstall` included) or its ports/target changed from its page: every client goes
through it, and its own key count sees none of them. «🛟 Remove the hub role» first.

### The DNS API token

The DNS is switched through Cloudflare's API. It needs an **API token** with nothing but
**«Zone · DNS · Edit»** on the failover names' zone. **Do not reuse** acme.sh's token: it serves
something else (ACME `dns_cf` on the main server), and the switch does not get in its way.

The token is entered only in the admin panel (**🔑 DNS API token**) — no `.env`, no CLI. The
message with it is **deleted at once** after it is read (if Telegram refuses, the bot asks to
delete it by hand); the token is checked against the API and only then stored in
`/etc/vpn-bot/dns_failover/cloudflare_token` (0600, owned by the bot's user, no symlinks — the
checks of the relay key and the TOTP key). Logs and the audit never carry it: the value is masked
by exact match wherever redaction runs, and the audit stores only a fingerprint (8 hex of
sha256). In the helper-nonroot model (`ProtectSystem=strict`) create the directory first —
`install -d -m 0700 -o vpn-bot -g vpn-bot /etc/vpn-bot/dns_failover` — and let the unit write it:
`ReadWritePaths=-/etc/vpn-bot/dns_failover` (already in `deploy/vpn-bot.nonroot.example.service`;
the `-` keeps the unit starting without the directory).

### The failover set

**📝 Names** — the names whose A record is switched: the main server's IPv4 in the normal mode,
the hub's in the fallback mode. Stored in the database (`failover_names`). The bot suggests
`HYSTERIA2_SNI` (the subscription's and the hy2 certificate's domain) and the names relays with an
agent forward to (an RU relay's `target_host`). The addresses are derived: main — `XRAY_PUBLIC_HOST`,
else `HYSTERIA2_HOST` (when an IPv4); the hub — its host, else its SSH address, else its single /32
source IP. Both can be overridden with «Main IPv4» / «Hub IPv4» (while the mode is off).

### Switching on and off

**«🟥 Switch the fallback mode on»** (confirmation + TOTP):

1. **preflight** — exactly one enabled hub with an agent; the agent answers a fresh `status`; the
   hub forwards the needed ports and **reaches** the main server on TCP `XRAY_PUBLIC_PORT` and
   `SUBSCRIPTION_PUBLIC_PORT` **by itself** (the agent's `vpn-relay-apply check` lines; an exit
   16–18 counts only when **every** FAIL line is about the input filter, not `ip_forward` or the
   forward); no loop (the origin is outside the set and points at the main server — by DoH and by
   the hub's own view — and the upstream name and ports the hub reports in its fresh `status`
   **now** are the origin and the hub ports: a hub
   re-pointed by hand to a failover name resolves to main before the switch and would loop
   after it); the token is active; every name has **exactly one** A record that is **not proxied**
   (grey cloud) and points at the main server or the hub — a foreign address is never silently
   overwritten. An AAAA record is a warning (IPv6 clients bypass the hub), not a blocker. A failed
   preflight leaves the DNS untouched and the mode off;
2. every A record → the hub's IPv4 (`proxied=false`, TTL 60);
3. **DoH check** (cloudflare-dns.com and dns.google — never the system resolver): up to 30 s
   waiting for the resolvers to answer the new address;
4. **the report** per name: ✅ written and visible / ⏳ written, resolvers still answer the old one
   (they may keep it up to the previous TTL — not an error) / ❌ not written (the reason).

**«🟩 Switch off»** writes the main server's IPv4 back (only the token is needed; the hub may be
switched off already).

The mode the admin asked for is kept in the database, what the last write did — **per name**. When
some names were not updated, the screen and the relay list say «⚠️ the switch is not finished»
with those names, and **«🔁 Repeat»** finishes it (names already in place are left alone).
Everything is audited (entity `relay`): `relay_hub_assigned`, `relay_hub_cleared`,
`failover_name_added`/`_removed`, `failover_token_set`/`_deleted`/`_rejected`,
`failover_preflight_failed`, `failover_enabled`, `failover_disabled`, `failover_setting_changed`,
`failover_direct_host_changed`.

The switch shows its **progress** in the same message (bot/progress.py): first the plan — the
steps ⚪ (preflight, the hub's jump line, the A records, the resolvers' check) with «✅ Да» — then
🔄 / ✅ / ❌ per step, «N/M» for the records, an activity line, at most one edit per 3 s; the result
closes it.

### The screen, the setup, «Включить» with an empty set

**Not set up** (no DNS API token or no hub): the screen says what is missing and offers ONE button,
**«⚙️ Настроить фолбэк»** — a wizard (TOTP), each step skipped when already done:

1. **the token** — asked by the bot; the message is deleted at once; checked with the API and
   **against the zone** of `HYSTERIA2_SNI` right away («Токен управляет зоной …» or why not);
2. **the hub** — among the relays with an agent **outside Russia** (by the IP-to-ASN database's
   country of their IPv4; a relay whose country is unknown is offered, marked so);
3. **the origin** — `origin.<zone>` offered, one tap to confirm (or another name);
4. **the failover set** — the bot suggests the candidates itself, **each with why** (HYSTERIA2_SNI:
   the hy2 certificate; the subscription's name; the names the RU relays forward to, with those
   relays; a DNS-named XRAY_PUBLIC_HOST), **all checked**; uncheck what is not wanted — one
   confirmation, no typing;
5. **the preflight** — with a button for each thing it finds wrong.

**Set up**: the state, the hub, the names with their statuses — and only **«Включить/Выключить
режим»**, **«Проверить»**, **«⚙️ Настройки»**, **«⬅️ Назад»** («🔁 Повторить» appears only while a
switch did not reach every name). Names, the token, the main/hub IPv4, the direct links' host,
`fallback-url` and «Автопереключение» are in «⚙️ Настройки». No «Обновить»: the screen is drawn
anew when opened and after every action.

**«Включить» with an empty failover set** never refuses silently: it opens the candidates screen
(checked, each with why) with ONE button **«🛟 Включить с этими именами»** — the checked names join
the set and the SAME action goes on with the switch, no detour through the screen. Every refusal
of «Включить» — an empty set, the preflight, a loop, the token, no hub — shows **its cause and the
button that removes it** («🔑 Задать токен DNS API», «🧭 Выбрать имена», «🛟 Выбрать hub», «🛰
Карточка hub», «🧭 Имена набора», the IPv4), never a bare refusal.

### Automatics

The health loop already sees the RU (edge) relays — directly and through the hub. When **every**
enabled edge relay with an agent is **cut from main** in a pass — its own check says the upstream
does not answer (exit 13/14), or main reaches neither its traffic port nor its agent — while the
hub is reachable from main, that is a pass of an incident. **Stably** = 3 passes in a row **and**
at least 10 minutes (`services/fallback_auto.py`: `PASSES`, `MIN_SECONDS`). Then:

* **«Автопереключение» off** (the default): every superadmin gets ONE message with ONE button
  **«🛟 Включить режим фолбэка»** (the screen's confirmation, behind TOTP);
* **on** (⚙️ Настройки): the bot switches itself (`_switch` with no actor — the full preflight,
  the hub's status asked as the bot itself; the hub chosen by `select_hub`, the seam a balancer
  will use) and **always** tells the superadmins, with the result.

One message per incident (it ends only when a pass sees an edge relay reachable again); after any
switch — by hand or automatic — nothing automatic happens for an hour (`COOLDOWN_SECONDS`): no
flapping. **Back to normal only by hand**: once the mode is on, the RU relays forward to the hub,
so the signal that switched it on is no longer observable (their check probes the hub and passes);
a «recovery» read from it would be false and send every client back into the blocked path. A
switch-off that comes late costs the hub's traffic; one that comes too early, the outage.

### What moves and what does not

- **Subscriptions** are rendered per request: their URL (`HYSTERIA2_SNI`) and their relay children
  follow the DNS by themselves.
- **Direct links** (`XRAY_PUBLIC_HOST` / `HYSTERIA2_HOST`) are an **IPv4** in the live deployment:
  the DNS does not move them. **«🔗 Direct links' host»** replaces that IPv4 with a DNS name in every
  new render — the bot's and the subscriptions' (`schema_meta`, empty by default = as before). The
  name must resolve to the main server now. When it is **in the set**, the subscriptions' direct
  entries go through the hub in the fallback mode; otherwise always directly. Existing keys do not
  break: REALITY and hy2 do not depend on the address in the link (the SNI stays), and a link
  imported with the IPv4 works as long as the main server does. **Single** direct keys
  (VLESS/Hysteria2, not subscription children) issued before the name was set were imported with
  the IPv4 and **do not move** — the screen shows how many (an upper bound: a user may have
  re-imported).
- **`fallback-url` in subscriptions** (off by default): the subscription carries
  `fallback-url: https://<hub host>:<SUBSCRIPTION_PUBLIC_PORT>/sub/<token>`. Happ reads it **only**
  for a subscription with a Provider ID. The subscription port's certificate must cover the hub's
  host (an IPv4 host gets a warning on the screen). The DNS is the real mechanism.

### The proxies through the hub

**Why.** SOCKS5 (and MTProto, when on) is handed out as `SOCKS5_HOST:SOCKS5_PORT` — today main's IPv4
and port 31337. In the fallback mode main's IP is banned at the border: the proxy is dead for users in
Russia, while the hub still reaches main.

**The address — one source.** While the mode is on, the module is on and the hub forwards its port,
the «Прокси» section and everything the bot hands out — `Host`/`Port`, `socks5://…`, the
`https://t.me/socks?…` link, MTProto's `https://t.me/proxy?…` links, the stats lines — are rendered
with **the hub's IPv4** (the address the failover names get), the port unchanged. The mode off —
`SOCKS5_HOST` / `MTPROTO_HOST` again. One source: `ProxyEndpoints.endpoint()`
(services/proxy_endpoint.py); no template reads `SOCKS5_HOST` itself, and the payload stored at issue
is rewritten with the address «now» on every show. Logins, passwords and MTProto secrets do not
change: the hub is an L4 forward, main's danted / mtproxy authenticate. Why the IPv4 and not the
hub's host: the name may itself be a failover name or move with the mode; a name needs DNS on the
client — exactly what is unreliable where the proxy is needed; the IPv4 is what the switch writes into
the A records, so the proxy and the VPN names move together.

**The forward on the hub.** «Включить» adds `SOCKS5_PORT/tcp` (and `MTPROTO_PORT` when that module is
on) to the hub's TCP set — the same agent `apply` as 443/2096, BEFORE the DNS is written; the `apply`
itself proves the hub reaches main:<port> or rolls the forward back. «Выключить» takes the port off
after the names point at main again; switching a proxy module off while the mode is on takes it off
at once (on — adds it). Chosen at the switch, not with the hub's role: outside the mode nobody needs
danted through the hub, and every forwarded port is probed by the hub's own check (its health, its
deploy's verify, the agent's `apply`) — a danted outage on main must not look like a dead hub, or roll
its update back, while no proxy user needs it. A port that cannot be forwarded **never blocks** the
switch: the VPN goes first, the report says what the proxies did, and users stay on the address that
works. A port equal to the hub's SSH port is never sent (the agent would refuse it anyway).

**Reconciled, not only at the switch.** The switch is an event, and a mode switched on before the bot
could forward proxies never saw it: the hub never got SOCKS5_PORT and the proxy stayed on main's
banned address for as long as the mode was on (prod, v3.3.0 installed after the mode). So the bot
also brings the hub's proxy ports to what the mode wants whenever it looks —
`FallbackService.reconcile_proxies`:

- **when**: at startup (right after `refresh_state()`), on every pass of the fallback's health loop
  (the relay health loop's pass listener, `FallbackAutoSwitch.observe`), when the «🛟 Режим фолбэка»
  screen opens, and with «🔁 Довести прокси до hub». All but the button run in the background, one at a
  time: an agent's `apply` (up to its 300 s timeout) never holds the bot's start or the health pass
  that decides the automatic switch, and the screen waits for it 10 s at most. A switch in progress is
  waited for in the background, never interleaved;
- **what**: the mode on and a proxying module on whose port the hub does not forward → the port is
  added (the same agent `apply`: its check proves main:<port> or rolls back), the proxy then shows the
  hub's IPv4 and «📣 Разослать» is offered; a proxy port the hub forwards that the mode does not want
  (the mode off, the module off) → taken off. Only the configured proxy ports are ever added or taken
  off: the rest of the hub's TCP set (443/2096 and anything else), its UDP set and its upstream are
  sent back exactly as they are, and a hub whose set lacks a VPN port is left to the preflight (the
  button says so). Before the `apply` the hub is asked for its live forward: one that is neither the
  bot's copy nor already the wanted set (changed on the relay by hand, another upstream) is **not
  overwritten** — a failure with that reason;
- **a failure**: the port is not sent again for an hour (`RECONCILE_BACKOFF_SECONDS`; the button does
  not wait). When the agent's check names the port it could not reach, only that one waits — another
  proxy goes on the next pass without it. The superadmins get ONE message per (port, error), with the
  agent's own error and a button to the screen; an alert raised before the bot is up is delivered on
  the next pass. A «relay busy» refusal is neither backed off nor told.

Never fix it by switching the SOCKS5 module off and on: `disable_protocol` deletes every SOCKS5 access.

**The checks.** «🔍 Проверить» shows the proxy as a row of its own: the mode off — ℹ️ «the port goes
on at the switch, the apply proves main:<port>»; on — ✅/⚠️ «the hub reaches main:<port>» (the hub's
own check). An unreachable main:SOCKS5_PORT is a clear refusal of the PROXY (⚠️ and the error), not
of the VPN: «the hub reaches main on 443/2096» does not count the proxy port. The mode on and the proxy
still handed out «напрямую» — ⚠️ «режим включён, но hub не форвардит SOCKS5:<port>» (with the last
`apply`'s error, if any) and **«🔁 Довести прокси до hub»** under it (TOTP, `fallback_proxy_reconcile`;
the same button is on the mode's screen while a proxy is direct): the reconcile at once.

**danted sees the hub.** Every connection through the hub reaches main from the hub's IP. Checked:
`deploy/danted.conf.example` has `client pass` and `socks pass` `from: 0.0.0.0/0`, no network that
would exclude the hub (keep the live, hand-made `/etc/danted.conf` the same); the bot neither limits
nor counts SOCKS5 by the client's IP (the anomaly detector reads Xray's access log only, and it skips
the relays' source IPs — the hub's among them — anyway); the socks5 module's UFW rule is `allow`, not
`limit`. A fail2ban of your own on danted at main needs the hub's source IPs in `ignoreip`.

**TCP CONNECT only.** UDP ASSOCIATE does not work through an L4 hub: danted hands the client its own
address (main) for UDP, which the client cannot reach in the mode. Telegram needs TCP only.

**Saved links** carry main's IP and do not move by themselves. After a switch that moved a proxy's
address, the mode's screen offers **«📣 Разослать пользователям с прокси новую ссылку»** — optional,
never automatic: a confirmation with the number of recipients (an active access to a moved proxy) and
the text, TOTP (`fallback_proxy_notice`), sent through the regular announcements (a segment by
protocol, the delivery ledger). The text carries the new address (the same for everyone) and says the
ready link is in «Прокси».

### Through the hub: the subscription limit, ssh-probe, health, anomaly detection

- **The subscription's rate limit.** Through the hub every client reaches the main server from one
  IP, so a bucket per peer would be one bucket for everybody. Requests whose peer is inside a hub's
  source IPs are limited per **token hash** (its own prefix: neither the token nor its fingerprint
  can be recovered from the bucket; the token is never logged). The 429 still comes **before** the
  token is looked up. The hubs' networks are cached in the subscription process for 30 s (an
  expired cache is re-read by one request, the others wait for it) so the limiter does not read
  the database per request. Residual risk: through the hub, cycling random
  tokens is not held back by the per-peer limit — malformed tokens never reach the database,
  well-formed ones cost one indexed lookup.
- **`POST /relay/ssh-probe`** ([above](#main-confirms-the-filter-post-relayssh-probe)) answers
  **404** when the caller's IP is inside the source IPs of **any** hub (enabled or not), even when
  an ordinary relay covers that address too. A hub masquerades the subscription port: in the
  fallback mode an RU relay's probe arrives from the hub's address, and the main server would dial
  the hub's SSH ports and "confirm" somebody else's filter. Consequence: the input filter of **the
  hub itself** and of RU relays in the fallback mode is confirmed by `input-confirm` from a new
  SSH session — which the bot opens itself, through the hub
  ([dead-man](#keeping-access-the-dead-man-and-input-confirm),
  [below](#managing-the-ru-relays-through-the-hub)).
- **Health.** In the fallback mode, a relay forwarding to a name of the set (or a relay without an
  agent) whose hairpin probe fails gets the level **🛟 «behind the hub, not reachable directly»**:
  moving into it, and from it back to 🟢, **alerts nobody**. Its agent is still asked — through the
  hub — so its status stays fresh and a pending input filter is confirmed. The mode switched off and
  the relay still unreachable — an ordinary 🔴 with its alert.
- **Anomaly detection** loses the IP signal: all traffic through the hub arrives from the hub's IP,
  and its source IPs are excluded like any relay's. While the mode is on, IP anomalies are not seen.

Not done here: an automatic switch on health.

### Managing the RU relays through the hub

The TSPU cuts SSH from the main server to the RU relays too. The hub still reaches both, so the
bot manages them **through the hub**:

```
bot ──ssh (jump key)──▶ hub sshd ──-W ru1:22──▶ ru1 sshd ──▶ vpn-relay-agent
     pinned hub key                    pinned ru1 key, the agent key, forced command
```

- **When.** A relay goes through the hub when its card says **«🛟 Через hub: вкл»**
  (`relays.via_hub`, schema v47 — always), and **every relay but a hub while the fallback mode is
  on** (automatically, no flag). A hub is always reached directly. A relay behind the hub with no
  hub (or a hub without an agent) is refused with a clear message, not a timeout. The card says how
  the agent is reached: «SSH к агенту — через hub … (флаг «через hub» | режим фолбэка)».
- **The ssh.** One `ssh` with a `ProxyCommand` — a second, fully pinned `ssh` (`-F /dev/null`, the
  same option set, the **jump key**, the hub's own `HostKeyAlias` and pinned host key,
  `StrictHostKeyChecking=yes` always) that only does `-W <relay ssh_host>:<ssh_port>`. Not `-J`:
  ProxyJump starts the jump ssh with defaults (`~/.ssh`, any identity) that cannot be pinned. The
  relay's hop is exactly a direct call: the agent key, its own alias and pinned key (TOFU on a
  pairing). The ProxyCommand runs in `/bin/sh` (the bot's own `$SHELL` is nologin). The hub's hop
  logs at `INFO`, so a refusal is named: «hub не пускает к …» (not in its permitopen) or «hub не
  достучался до …».
- **The hub's line.** The hub's agent keeps ONE line for the jump key in root's authorized_keys:

  ```
  restrict,port-forwarding,permitopen="<ssh_host>:<ssh_port>"[,permitopen="…"],command="/bin/false" ssh-ed25519 <jump key> vpn-bot-relay-jump
  ```

  `restrict` (no pty, no agent/X11 forwarding), port forwarding back — but only to the listed
  relays' sshd — and `/bin/false` for a session: no shell. **`permitopen` limits only local
  forwarding**: with port forwarding on, a key could also open listeners on the hub (`-R`: a TCP
  port on loopback, a root-owned Unix socket at a new path), and no authorized_keys option forbids
  that (`permitlisten` does not cover Unix sockets and has no `none`). So every relay's sshd forwards
  **local TCP only** (Unix-socket forwarding off in both directions — `permitopen` already refuses
  socket paths it does not list, so that part is defense in depth): `deploy.sh` installs `/etc/ssh/sshd_config.d/00-vpnrelay-forwarding.conf`
  (`AllowTcpForwarding local`, `AllowStreamLocalForwarding no`; `-R` is off for everyone on a
  relay), the host check holds it in effect, and the hub's agent refuses `jump` until `sshd -T`
  shows it — a hub installed but not deployed since gets no jump line (update it first). `permitopen` lists **exactly** the
  relays with an agent that are behind the hub. The bot writes it (`jump key=… open=…`, or
  `jump-off` when nothing is behind the hub) whenever that set changes — the flag, the mode
  switched on/off, a hub given or taken (its line goes with the role), a pairing, a detach, a
  delete — and before the first call through the hub after a restart. The client refuses a
  target that is not in that list before any process starts; a hub that refuses the forward
  anyway (re-installed, edited by hand) gets its line written again, once. The agent's own line —
  `restrict,command="vpn-relay-agent"` — is untouched: it can never be a jump.
- **A pairing during the ban** (the fallback mode on, or attaching an agent to a relay «через
  hub») says `hello` through the hub: the hub's line opens that address for the pairing (and
  closes it again if the pairing fails). The outside checks from the main server cannot pass then,
  so the relay's own `vpn-relay-apply check` (TCP to its upstream on every forwarded port, TLS),
  asked through the hub with the key the hello just learned, stands in for them (the result says
  «relay's own check, via hub»).
- **The input filter.** A session through the hub is a NEW ssh session on the relay. When `status`
  reports `PENDING CONFIRM`, the bot sends `input-confirm` (after an update, in the health loop, or
  «🛡 Подтвердить входной фильтр» on the card) — main's probe is not needed
  ([dead-man](#keeping-access-the-dead-man-and-input-confirm)).

## Health monitor

With `RELAY_HEALTH_INTERVAL > 0` the bot runs **one** background loop for every relay,
modelled on the WARP monitor, and keeps **one verdict per relay** — one icon and one line of
reason on the list and the page, one latch, one alert per change. Each pass reads the relays
from the database (so a relay added or edited in the panel is picked up with no restart) and,
for every **enabled** relay:

1. **traffic** — a TCP connection to `<relay host>:XRAY_PUBLIC_PORT` and a TLS handshake with
   `server_hostname=XRAY_SNI`, **verifying the certificate** (and UDP, below). The bot runs on
   the main server, so the probe goes out to the relay and comes back in through its DNAT (a
   hairpin); REALITY does not recognise it as a client and hands it to the decoy, whose
   certificate is valid for `XRAY_SNI`. A passing probe therefore means "TCP/443 through the relay
   reaches the main inbound end to end" (checked by hand: HTTP 200, `verify=0`, TLS ≈ 0.29 s);
2. **the agent**, for a relay with one — `status` over SSH (kept on the relay's row and shown on its
   page). It did not answer, or its `vpn-relay-apply check` failed with an exit code other than
   `0`/`13`/`14` (13/14 — the relay cannot reach this server by itself — are judged by the hairpin
   probe instead): the agent part fails.

The verdict: 🔴 **down** — traffic through the relay does not reach this server (its keys do not
work); 🟡 **warn** — traffic passes, the agent does not (keys work, management does not);
🟢 **ok** — both. A relay without an agent is judged by its traffic alone.

- **UDP** (when `HYSTERIA2_ENABLED=true`): a QUIC packet with a reserved ("greasing") version,
  padded to 1200 bytes, to `<relay host>:HYSTERIA2_PORT` — every QUIC server answers an unknown
  version with version negotiation (RFC 9000 §6), so the answer proves the UDP DNAT end to end
  without any credentials. The same packet to `127.0.0.1` first is the control: when this host's
  own hysteria-server does not answer it either, UDP is "not judged", never "down". A relay is up
  when TCP passes and UDP did not fail.
- One probe never takes more than 10 s and never raises.
- One time-based latch **per relay** (`relays.id`) over the three levels: the relay moves to a
  level after one interval at it (two probes in a row). Every admin in `ADMIN_IDS` gets **exactly
  one message per change** — 🔴 / 🟡 / 🟢, naming the relay's label, name, host and the one-line
  reason — never two for one event (traffic and the agent failing together are ONE 🔴), never a
  repeat while nothing changes. A new relay starts healthy; a relay switched off or deleted loses its
  latch; one relay's state never affects another's. While an agent call (update, uninstall) runs on
  a relay, the loop does not ask its agent.
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
- **Issued subscriptions change only through the «в подписках» buttons.** «➕ Добавить в
  подписки» / «➖ Убрать из подписок» on a relay's page add or delete its members in every active
  subscription ([above](#in-subscriptions-an-action-on-every-subscription)); merely switching a
  disabled relay back on does not top them up. The bulk reconcile «🔗 All-in-One» is still there —
  see [docs/subscription.md](subscription.md#bringing-existing-bundles-in-line).
