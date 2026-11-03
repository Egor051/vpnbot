# Relay ("via relay" keys)

A **relay** is a second entry point into this server: a small VPS (here: in Russia)
that forwards client traffic at L4 to the main server. A key issued "via relay" is an
ordinary key whose link points at the relay instead of the main host. Disabled by
default (`RELAY_ENABLED=false`).

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

### DNS

Point a DNS name at the relay — e.g. `relay.anycastedge.net` — in Cloudflare with
**proxying off** (DNS only, grey cloud): Cloudflare's HTTP proxy cannot carry
REALITY or QUIC. Use that name as `RELAY_HOST`. Moving the relay to a new IP is then
an A-record change: links carry the name, so no key has to be re-issued.

## What a relay key is

Relay is an **attribute of a key** (`vpn_keys.relay`, `NULL` for a direct key), not a
new key type or transport:

- it is created through the same per-protocol path as a direct key and gets its own
  uuid / secret / label with the usual prefix (`xray_tcp_*`, `xray_http_<profile>_*`,
  `hy2_*`), so `hy2_auth`, Xray reconciliation (`XRAY_MANAGED_LABEL_RE`), traffic
  stats and the email-label scheme are untouched;
- its link differs from a direct key's in exactly two places: the **host**
  (`RELAY_HOST` instead of `XRAY_PUBLIC_HOST` / `HYSTERIA2_HOST`) and the **display
  name** (`_relay` after the label). Port, REALITY `sni`/`pbk`/`sid`/`spx`/`fp`,
  `flow`, XHTTP `path`/`mode`/`extra`, and Hysteria2's `sni` are the same — the relay
  forwards 1:1, so TLS still terminates on the main server with its own
  certificate / REALITY keys;
- the host is chosen in one place (`services.relay.relay_link_host`) for every path —
  config screen, QR, create wizard, cached `public_payload.link`, the subscription. A
  key whose relay is not the enabled `RELAY_NAME` is **refused**
  (`RelayUnavailable`), never silently pointed at the main host: a link that quietly
  bypasses the relay the user chose is the failure this guards against.

Users choose it in the create wizard: after the protocol (and XHTTP profile) step,
while `RELAY_ENABLED=true`, the bot asks **«Подключение: напрямую / через relay»**
(user and admin wizards alike; AmneziaWG never gets the step — it is not on 443).

All-in-one bundles created while the relay is enabled carry a relay copy of every
member after the direct ones (basic 2 → 4, extended 5 → 10) — see
[docs/subscription.md](subscription.md#two-kinds-of-all-in-one).

## Settings

Full reference: [Configuration → Relay](configuration.md#relay).

| Variable | Default | Meaning |
|---|---|---|
| `RELAY_ENABLED` | `false` | Offer relay keys / relay bundle members. |
| `RELAY_NAME` | `ru1` | Value stored in `vpn_keys.relay`. Do not rename once keys exist. |
| `RELAY_HOST` | — | DNS name (recommended) or IPv4 of the relay. Required when enabled. |
| `RELAY_SOURCE_IPS` | — | Relay egress IPv4/CIDR list. Required when enabled. |
| `RELAY_HEALTH_INTERVAL` | `300` | Health probe period, seconds; `0` = off. |
| `SERVER_FLAG_EMOJI` | `🇫🇮` | Flag in the display name of standalone keys and basic members. |

**There is no relay port setting**: the port in a relay link is the protocol's own
public port (`XRAY_PUBLIC_PORT`, `HYSTERIA2_PORT`), because the relay forwards 1:1.

## Health monitor

With `RELAY_ENABLED=true` and `RELAY_HEALTH_INTERVAL > 0` the bot runs a background
probe modelled on the WARP monitor: every interval it opens a TCP connection to
`RELAY_HOST:XRAY_PUBLIC_PORT` and completes a TLS handshake with
`server_hostname=XRAY_SNI`, **verifying the certificate**. The bot runs on the main
server, so the probe goes out to the relay and comes back in through its DNAT (a
hairpin); REALITY does not recognise it as a client and hands it to the decoy, whose
certificate is valid for `XRAY_SNI`. A passing probe therefore means "TCP/443 through
the relay reaches the main inbound end to end" (checked by hand: HTTP 200,
`verify=0`, TLS ≈ 0.29 s).

- One probe never takes more than 10 s and never raises.
- A time-based latch: the relay is reported **down** after one interval of continuous
  failure (two failed probes in a row) and **back** after one interval of continuous
  success. Every admin in `ADMIN_IDS` gets exactly one message per transition.
- A dead relay does **not** mark Xray degraded and does not block issuing keys.
- Each probe leaves one line like
  `REALITY: processed invalid connection from <relay IP>` in Xray's error log. That is
  expected — it is the probe being handed to the decoy.

## Limitations

- **Anomaly detection is IP-blind for relayed traffic, by design.** L4 without PROXY
  protocol means every relayed connection carries the relay's address; for Hysteria2
  over UDP there is no client address at all. `RELAY_SOURCE_IPS` are therefore never
  recorded (neither the IP nor its network/ASN). Because the inbound is shared, this
  takes the IP signal away from **any** key that is used through the relay — a direct
  key whose link a user re-points at the relay included. Hysteria2's `/online`
  connection count is unaffected.
- **UDP is not probed.** The health monitor checks TCP/443 only; Hysteria2 through the
  relay is not monitored.
- **Ports are 1:1.** The relay must forward to the same port numbers the main server
  publishes.
- **The inbound is shared.** There is no per-relay inbound, tag or credential; the
  relay is visible only in the link the user holds.
- **The subscription URL stays on the main domain.** The sub-URL (`:2096` in the live
  deployment) is fetched from the main server's domain, not through the relay; only
  the links inside it point at the relay.
- **Existing bundles do not gain relay members.** A bundle's composition is decided
  once, when it is created (there is no mechanism that tops up an existing bundle
  when a protocol is switched on later). Bundles created before `RELAY_ENABLED=true`
  keep their direct members only; to get relay members, create a new bundle.
- **Turning the relay off** makes relay keys' links unavailable (the bot shows an
  error instead of a link) and drops relay members from subscriptions (logged at
  WARNING); direct keys and direct members are unaffected. Turning it back on brings
  them back unchanged.
