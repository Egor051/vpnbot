# Hysteria2 (apernet v2)

Optional third VPN key type alongside Xray VLESS Reality and AmneziaWG. The bot can issue,
revoke and delete Hysteria2 keys **with no data-plane restart**: a revoke takes effect on the
very next handshake. Hysteria2 is **disabled by default** (`HYSTERIA2_ENABLED=false`) and runs
as a **standalone data plane**, independent of the bot process.

This page is the topical entry point. The canonical references live where every other backend's
do:

- **Environment variables** → [Configuration → Hysteria2](configuration.md#hysteria2)
  (all `HYSTERIA2_*` and `ANOMALY_HYSTERIA2_MAX_CONN`, defaults, the `HYSTERIA2_INSECURE` MITM
  tradeoff, and the Traffic Stats API).
- **Server-side install** → [Deployment → Hysteria2 data plane](deployment.md#hysteria2-data-plane-hy2_auth-endpoint).
- **Health, degraded meaning & recovery** → [Operations → Hysteria2 backend health & recovery](operations.md#hysteria2-backend-health--recovery).

## How it works

Three moving parts, only one of which is the bot:

1. **`hysteria` server** (apernet v2) — the actual data plane, configured with `auth: type: http`
   in `/etc/hysteria/config.yaml`. Terminates client QUIC/Salamander sessions on the public
   **UDP** port `HYSTERIA2_PORT` (default `15650`).
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
(`key_type='hysteria2'`, per-key secret in `payload_json`, stats label `hy2_<hex>`).

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
| Issue / revoke / delete | `HYSTERIA2_HOST`, `HYSTERIA2_SNI`, `HYSTERIA2_OBFS_PASSWORD` | Pure `vpn.db` writes; effective on the next handshake. |
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
