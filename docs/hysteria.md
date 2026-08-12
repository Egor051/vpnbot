# Hysteria2 (apernet v2)

Optional third VPN key type alongside Xray VLESS Reality and AmneziaWG. The bot can issue,
revoke and delete Hysteria2 keys **with no data-plane restart**: a revoke takes effect on the
very next handshake. Hysteria2 is **disabled by default** (`HYSTERIA2_ENABLED=false`) and runs
as a **standalone data plane**, independent of the bot process.

This page is the topical entry point. The canonical references live where every other backend's
do:

- **Environment variables** → [Configuration → Hysteria2](configuration.md#hysteria2)
  (all `HYSTERIA2_*` and `ANOMALY_HYSTERIA2_MAX_CONN`, defaults, `HYSTERIA2_INSECURE`, and the
  Traffic Stats API).
- **Server-side install** → [Deployment → Hysteria2 data plane](deployment.md#hysteria2-data-plane-hy2_auth-endpoint).
- **Health, degraded meaning & recovery** → [Operations → Hysteria2 backend health & recovery](operations.md#hysteria2-backend-health--recovery).

## How it works

Three moving parts, only one of which is the bot:

1. **`hysteria` server** (apernet v2) — the actual data plane, configured with `auth: type: http`
   in `/etc/hysteria/config.yaml` (tracked source: `deploy/hysteria/config.yaml`, installed via
   `sudo bash deploy/hysteria/install-config.sh` — **never** a bare `cp`, since the tracked file's
   `trafficStats.secret` is a placeholder and the installer is what injects the real
   `HYSTERIA2_STATS_SECRET` from `.env`). Terminates plain-QUIC client sessions — no salamander
   obfuscation — on the public **UDP** port `HYSTERIA2_PORT` (default `443`; coexists with Xray
   REALITY on TCP/443), presenting a valid Let's Encrypt cert for the server's domain
   (issued/renewed by `acme.sh` outside this repo). Run `deploy/hysteria/preflight-udp443.sh`
   before restarting the service.
2. **`hy2_auth` endpoint** (`python -m hy2_auth`, `deploy/vpn-bot-hy2-auth.service`) — a small,
   **separate** process the `hysteria` server calls over loopback for every handshake. It opens
   `vpn.db` **read-only** and validates the per-key token in constant time
   (`hmac.compare_digest`), always replying HTTP 200 with `{"ok": <bool>, "id": "<label>"}` and
   failing **closed**. Because it reads the **live** database, a revoke/delete/expiry applies on
   the next handshake — there is no apply step and no restart. It never imports `bot`/`aiogram`
   and keeps working while `vpn-bot.service` is down.
   - Routes: `POST /auth` (handshake auth) and `GET /healthz` (`200 {"ok":true}` when the DB is
     readable, `503` otherwise — usable by a watchdog or `curl http://127.0.0.1:8444/healthz`).
3. **Traffic Stats API** (optional) — a loopback HTTP server exposed by `hysteria-server` itself
   (`trafficStats: {listen, secret}` in `config.yaml`). The bot only **reads** it (`GET /traffic`,
   `GET /online`) and POSTs `/kick`. It powers per-key traffic, the online-clients counter,
   anomaly detection by concurrent connections, and **immediate session termination on
   revoke/delete/expiry/block**. Gated on `HYSTERIA2_STATS_SECRET`: unset, the whole surface stays
   inert — hy2 keys show no traffic/online and a revoke blocks only new handshakes (the live
   session survives until reconnect).

The bot itself never binds any of these ports; it only reads the stats/health APIs (via
`adapters/hysteria_stats.py` / `adapters/hysteria_auth_health.py`) and writes `vpn_keys` rows
(`key_type='hysteria2'`, per-key secret in `payload_json`, stats label `hy2_<rnd>`).

### Masquerade decoy (static file)

`deploy/hysteria/config.yaml` enables Hysteria2's file-based masquerade
(`masquerade.type: file`, `masquerade.file.dir: /etc/hysteria/masq`): a probe that doesn't
complete the Hysteria2 handshake is served whatever static site sits in that directory instead
of a reset. `/etc/hysteria/masq` is **not** tracked in this repo — populated by hand on the
host, the same way as `tls.cert`/`tls.key`; `install-config.sh` does not manage it. No
`listenHTTP`/`listenHTTPS` are configured, since those would open separate plaintext TCP
`:80`/`:443` listeners and TCP/443 is already held by Xray REALITY on this host — the decoy is
served over the existing UDP/443 path instead.

### Per-client bandwidth ceiling (Brutal)

`deploy/hysteria/config.yaml` declares a rate ceiling:

```yaml
bandwidth:
  up: 95 mbps
  down: 95 mbps
```

Server-side values are a limit **per client**, not a total shaper for the host — each client is
held to this rate, they do not share it. The server's `up` is the client's **download** ceiling
and its `down` is the client's **upload** ceiling; the effective rate in each direction is
`min(client value, server value)`. Zero or an omitted value on either side means *no limit* for
that direction, so this block's absence would not be a conservative default — it would be no
ceiling at all. `ignoreClientBandwidth` is deliberately **not** set: it is the mutually
exclusive alternative, discarding the client's declared bandwidth outright and forcing the
non-Brutal controller, which makes the values above dead weight. As with every other key in the
file, a change takes effect only on the next `systemctl restart hysteria-server` — and that
restart drops live QUIC sessions, so do it in a quiet window.

**Turning on Brutal, client-side.** The `hysteria2://` links the bot issues carry no bandwidth
parameters, so out of the box every client runs the loss-responsive **BBR** controller. A user
who wants the **Brutal** sender instead adds a `bandwidth` section to their own client profile
(v2rayN / NekoBox / Happ all expose these fields) with **their own real line speed** — not the
server ceiling above:

```yaml
bandwidth:
  up: 20 mbps     # your real upload
  down: 100 mbps  # your real download
```

Per the official Hysteria 2 docs, higher is **not** better: Brutal does not measure the path, it
sends at the rate it was told and holds that rate through loss. A figure above what the
connection actually carries therefore backfires — congestion and an unstable connection, not
more speed. The server clamps anything above `95 mbps`, but it cannot correct an overstated
value below that.

### WARP egress marking (`vpnbot-hy2-warp-mark`)

When WARP split-tunnel is deployed, `vpnbot-hy2-warp-mark` fwmarks locally-generated
Hysteria2 packets (matched by owner-uid) into the WARP policy table so hy2 egress follows the
same split as the rest of WARP. It is a **tracked** helper (`scripts/vpnbot-hy2-warp-mark`) and
is **self-installed** by `scripts/deploy.sh` Phase 2 (`install_out_of_repo_helpers`), exactly
like the WARP helpers — a `sudo bash scripts/redeploy.sh` keeps
`/usr/local/sbin/vpnbot-hy2-warp-mark` in sync with the checkout, no hand-install after a deploy.
Its `iptables --sport` exemption is **derived from `HYSTERIA2_PORT`** (the single source of
truth), resolved from the bot `.env` and range-checked before touching the network (fails closed
on a missing/garbage/out-of-range value), so the marking port can never drift from the port
`hysteria-server` listens on. Because the port lives in `.env` (not git), deploy re-applies
`vpnbot-hy2-warp-mark.service` whenever it was active pre-deploy — so the exemption follows the
current `HYSTERIA2_PORT` even when the helper file is unchanged. See
[deploy/helpers/README.md](../deploy/helpers/README.md#vpnbot-hy2-warp-mark--hysteria2-egress--warp-port-from-hysteria2_port).

## Feature parity with Xray/AWG

When `HYSTERIA2_ENABLED=true`, Hysteria2 reaches operational parity with Xray/AWG:

| Capability | Requires | Notes |
|---|---|---|
| Issue / revoke / delete | `HYSTERIA2_HOST`, `HYSTERIA2_SNI` | Pure `vpn.db` writes; effective on the next handshake. |
| Admin **diagnostics** (`systemctl is-active`) | `HYSTERIA2_SERVICE_NAME`, `HYSTERIA2_AUTH_SERVICE_NAME` | Checks `hysteria-server` and `vpn-bot-hy2-auth`. |
| **Backend-health** `Hysteria2: OK/DEGRADED` | `HYSTERIA2_HEALTH_INTERVAL` (>0) | Data-plane liveness only — **never blocks** issue/revoke (unlike Xray/AWG). |
| Off-site **recovery bundle** | `OFFSITE_BACKUP_INCLUDE_CONFIGS=true` | Bundles `HYSTERIA2_CONFIG_PATH` (`/etc/hysteria/config.yaml`). |
| Per-key **traffic**, **online** count, revoke-**/kick**, concurrent-conn anomaly | `HYSTERIA2_STATS_SECRET` (+ `ANOMALY_HYSTERIA2_MAX_CONN` for anomaly) | Only obtainable from the Traffic Stats API; the bot cannot synthesise it. |

> **The one asymmetry that is by design:** a `Hysteria2: DEGRADED` mark is **informational** and
> never gates mutations, because Hysteria2 has no config-apply step — see
> [Operations → Hysteria2 backend health & recovery](operations.md#hysteria2-backend-health--recovery).

## Client apps

Hysteria2 keys are delivered as a **link-only** profile (no `.conf` file). Recommended GUI
clients: NekoBox / Hiddify / Happ / sing-box. See the in-bot FAQ («Помощь») for user-facing
guidance.
