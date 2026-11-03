# Relay ("via relay" keys)

A **relay** is a second entry point into this server: a small VPS (here: in Russia)
that forwards client traffic at L4 to the main server. A key issued "via relay" is an
ordinary key whose link points at the relay instead of the main host. There can be
**several relays**; they are managed in the bot's admin panel (**🛡 Админ-панель →
🛰 Управлять relay**) and stored in the `relays` table of `vpn.db`. With no relay in
the table the feature is invisible.

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
- The relay infrastructure itself (nftables rules, sysctl, the VPS) is **out of this
  repository**. Tracking it under `deploy/relay/` is a separate PR.

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

## Managing relays in the admin panel

SUPERADMIN only. **🛡 Админ-панель → 🛰 Управлять relay** lists every relay with its
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
4. **label** — the marker in key names, `^[a-z0-9-]{1,16}$`, unique per relay; the
   step offers `relay` while no other relay uses it.

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
  name** (the relay's label after the key's label:
  `<label>_<relay label>_<flag|circle>`, e.g. `xray_tcp_ab12c_relay_🇫🇮`). Port,
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
- **UDP is not probed.** The health monitor checks TCP/443 only; Hysteria2 through a
  relay is not monitored.
- **Ports are 1:1.** A relay must forward to the same port numbers the main server
  publishes.
- **The inbound is shared.** There is no per-relay inbound, tag or credential; the
  relay is visible only in the link the user holds.
- **The subscription URL stays on the main domain.** The sub-URL (`:2096` in the live
  deployment) is fetched from the main server's domain, not through a relay; only the
  links inside it point at relays.
- **Existing bundles gain relay members only through the admin reconcile.** Adding a relay
  or switching one on does not touch existing bundles by itself. Admin panel →
  «🔗 All-in-One» → «Дополнить все подписки по текущим настройкам» adds the members through
  every relay that is enabled and «в подписках» to every active bundle (or «Перевести все
  подписки в базовый вид», which also drops the XHTTP members) — see
  [docs/subscription.md](subscription.md#bringing-existing-bundles-in-line).
