# Configuration Reference

Complete reference for every environment variable parsed by `config/settings.py`.

The copy-paste template lives in [`.env.example`](../.env.example) (every variable is
also documented inline there). Copy it to `.env` and replace placeholders with values
for your server. `BOT_TOKEN` and `ADMIN_IDS` are required for startup; fill the relevant
Xray or AWG values before issuing that key type.

Variables marked **Required** must be set before startup; variables not marked are
optional with the shown default.

> ⚠️ **Security-sensitive variables** are marked with 🔒. Never commit them; keep them on
> the server in `.env` (mode `0600`, root-only).

## Core

| Variable | Required | Default | Description | Example |
|---|---|---|---|---|
| `BOT_TOKEN` | **Yes** | — | Telegram Bot API token from BotFather. 🔒 | `123456:ABC-DEF...` |
| `ADMIN_IDS` | **Yes** | — | Comma-separated Telegram user IDs with **superadmin** access. Additional moderators are assigned in-bot by a superadmin (no env var). | `123456,789012` |
| `DB_PATH` | No | `/opt/vpn-service/data/vpn.db` | Path to the SQLite database file. | `/opt/vpn-service/data/vpn.db` |
| `SQLITE_SYNCHRONOUS` | No | `FULL` | SQLite synchronous mode: `FULL`, `NORMAL`, or `EXTRA`. `FULL` is safest. | `FULL` |
| `LOG_DIR` | No | `/opt/vpn-service/logs` | Directory for rotating log files. | `/opt/vpn-service/logs` |
| `BOT_LOCK_PATH` | No | `/run/vpn-bot/vpn-bot.lock` | Path to the single-instance PID lock file. | `/run/vpn-bot/vpn-bot.lock` |
| `BOT_DROP_PENDING_UPDATES` | No | `false` | Drop queued Telegram updates on startup. Useful after downtime. | `false` |
| `BOT_LANGUAGE` | No | `ru` | Bot UI language. Supported: `ru`, `en`. | `ru` |
| `AUDIT_RETENTION_DAYS` | No | `180` | Days to retain audit log entries (0 = forever, max 3650). | `180` |
| `CONFIG_BACKUP_KEEP_LAST` | No | `20` | Number of config backups to keep per backend (1–500). | `20` |

## Health Endpoint

| Variable | Required | Default | Description | Example |
|---|---|---|---|---|
| `HEALTH_HOST` | No | `127.0.0.1` | Host for the optional HTTP health endpoint. | `127.0.0.1` |
| `HEALTH_PORT` | No | _(disabled)_ | Port for the HTTP health endpoint. Omit to disable. | `8080` |

## Privilege Helpers (non-root deployment)

| Variable | Required | Default | Description | Example |
|---|---|---|---|---|
| `PRIVILEGE_HELPERS_ENABLED` | No | `false` | Enable non-root deployment via sudo helpers. Incompatible with `XRAY_APPLY_MODE=api`. | `false` |
| `HELPER_STAGING_ROOT` | No | `/run/vpn-bot` | Root directory for staging files passed to sudo helpers. | `/run/vpn-bot` |
| `SOCKS5_USER_HELPER_PATH` | No | `/usr/local/sbin/vpn-bot-socks5-user` | Absolute path to the SOCKS5 user management sudo helper. | `/usr/local/sbin/vpn-bot-socks5-user` |
| `XRAY_APPLY_HELPER_PATH` | No | `/usr/local/sbin/vpn-bot-xray-apply` | Absolute path to the Xray config apply sudo helper. | `/usr/local/sbin/vpn-bot-xray-apply` |
| `AWG_APPLY_HELPER_PATH` | No | `/usr/local/sbin/vpn-bot-awg-apply` | Absolute path to the AWG config apply sudo helper. | `/usr/local/sbin/vpn-bot-awg-apply` |
| `MTPROTO_APPLY_HELPER_PATH` | No | `/usr/local/sbin/vpn-bot-mtproxy-apply` | Absolute path to the MTProto apply sudo helper. | `/usr/local/sbin/vpn-bot-mtproxy-apply` |
| `XRAY_HELPER_STAGING_DIR` | No | `$HELPER_STAGING_ROOT/xray` | Staging directory for Xray helper files. | `/run/vpn-bot/xray` |
| `AWG_HELPER_STAGING_DIR` | No | `$HELPER_STAGING_ROOT/awg` | Staging directory for AWG helper files. | `/run/vpn-bot/awg` |
| `MTPROTO_HELPER_STAGING_DIR` | No | `$HELPER_STAGING_ROOT/mtproxy` | Staging directory for MTProto helper files. | `/run/vpn-bot/mtproxy` |

## Xray VLESS Reality

| Variable | Required | Default | Description | Example |
|---|---|---|---|---|
| `XRAY_CONFIG_PATH` | No | `/usr/local/etc/xray/config.json` | Path to the Xray config file. | `/usr/local/etc/xray/config.json` |
| `XRAY_SERVICE_NAME` | No | `xray` | systemd service name for Xray. | `xray` |
| `XRAY_APPLY_MODE` | No | `api` | How to apply Xray config changes: `restart`, `reload`, or `api`. Default `api` (root deployment, no connection drops). `api` requires root and is incompatible with helpers; use `restart`/`reload` with the non-root privilege-helper model. | `api` |
| `XRAY_INBOUND_TAG` | No* | _(first inbound)_ | Tag of the VLESS inbound in `config.json`. Required for `api` mode. | `vless-in` |
| `XRAY_PUBLIC_HOST` | No* | — | Public hostname/IP clients use to connect. Required to issue keys. | `vpn.example.com` |
| `XRAY_PUBLIC_PORT` | No | `443` | Public TCP port for VLESS connections. | `443` |
| `XRAY_REALITY_PUBLIC_KEY` | No* | — | Xray Reality public key (base64url). Required to issue keys. | `ABC123...` |
| `XRAY_SNI` | No* | — | SNI (Server Name Indication) for Reality. Required to issue keys. | `www.microsoft.com` |
| `XRAY_FLOW` | No | `xtls-rprx-vision` | VLESS flow control. | `xtls-rprx-vision` |
| `XRAY_FINGERPRINT` | No | `chrome` | Global fallback TLS fingerprint (the key-creation flow lets the user pick per key). One of: `chrome`, `firefox`, `safari`, `ios`, `android`, `edge`, `360`, `qq`, `random`, `randomized`, `randomizedalpn`, `randomizednoalpn`. | `chrome` |
| `XRAY_NETWORK_TYPE` | No | `tcp` | Network type: `tcp` or `raw`. | `tcp` |
| `XRAY_SHORT_ID` | No* | — | Hex short ID (≤16 chars). Required if `XRAY_MANAGE_SHORT_IDS=false`. | `abcd1234` |
| `XRAY_MANAGE_SHORT_IDS` | No | `false` | Let the bot manage short IDs automatically. | `false` |
| `XRAY_ALLOW_RESTART_ON_ROLLBACK` | No | `false` | Allow service restart during config rollback. | `false` |
| `XRAY_STATS_SERVER` | No* | — | Address of the Xray gRPC stats/API server. Required for `api` mode. | `127.0.0.1:10085` |
| `XRAY_STATS_INTERVAL` | No | `60` | Background Xray traffic stats sampling interval in seconds (0–3600; 0 disables). `statsquery` is read without `-reset` (non-destructive), so manual stat views poll it live; this loop only keeps the cache warm between them so the dashboard stays fresh without user interaction. | `60` |
| `XRAY_XHTTP_ENABLED` | No | `false` | Enable a second VLESS transport (XHTTP) reached via `vless-in`'s REALITY catch-all fallback to a loopback inbound. When on, key creation offers VLESS (TCP) / VLESS (HTTP). | `false` |
| `XRAY_XHTTP_INBOUND_TAG` | No* | `vless-xhttp-reality` | Tag of the loopback XHTTP fallback-dest inbound in `config.json` (must differ from `XRAY_INBOUND_TAG`). Required when `XRAY_XHTTP_ENABLED=true`. | `vless-xhttp-reality` |
| `XRAY_XHTTP_PORT` | No | `8443` | Retained for back-compat; **not** used to build VLESS (HTTP) links. The link rides `vless-in`'s public port (`XRAY_PUBLIC_PORT`); the XHTTP inbound listens on loopback as the REALITY fallback dest. | `8001` |
| `XRAY_XHTTP_PATH` | No | `/v1/messages/stream` | XHTTP path used in VLESS (HTTP) links; must match the inbound's `xhttpSettings.path` (validated on the inbound, not in the fallback). | `/v1/messages/stream` |
| `XRAY_XHTTP_MODE` | No | `stream-one` | Client-side XHTTP mode in VLESS (HTTP) links: `auto`, `packet-up`, `stream-up`, `stream-one`. Default `stream-one` (single full-duplex h2 session, cleanest for direct REALITY); `packet-up` is switchable for throttling on long sessions or CDN passthrough. | `stream-one` |
| `XRAY_SPIDER_X_POOL` | No | _(empty)_ | Per-key REALITY spiderX (`spx`) pool: comma-separated paths, each starting with `/`. Empty = `spx` not emitted (default). See the note below. | `/,/api,/blog/` |
| `XRAY_ACCESS_LOG_PATH` | No | _(empty)_ | Path to the Xray access log for anomaly detection. Leave empty to disable. | `/var/log/xray/access.log` |

_Legacy aliases accepted: `XRAY_SERVER_ADDRESS` (= `XRAY_PUBLIC_HOST`), `XRAY_SERVER_PORT` (= `XRAY_PUBLIC_PORT`), `XRAY_PUBLIC_KEY` (= `XRAY_REALITY_PUBLIC_KEY`), `XRAY_SERVER_NAME` (= `XRAY_SNI`)._

> The one-time, server-side topology for the VLESS (HTTP) transport is documented in
> [`xray-xhttp-inbound.md`](xray-xhttp-inbound.md). VLESS (HTTP) has no public port of its
> own: `vless-in` (`:443`) terminates REALITY and forwards via a **default catch-all**
> `fallback` to a loopback XHTTP inbound where the path is validated. A path-based fallback
> does **not** match HTTP/2 XHTTP (the h2 `:path` lives in HPACK), so the catch-all is
> mandatory.

> **Per-key transport profiles.** `XRAY_XHTTP_MODE` sets the client `mode` for the
> **base** profile only. The VLESS (HTTP) key-creation flow offers three client-side
> profiles — **base** / **antisib** (anti-blocking) / **multi** (multi-connection) —
> that override the mode and add `xhttpSettings.extra` tuning in the generated link
> (no server-side change; the profile is stored per key). See
> [`xray-xhttp-inbound.md`](xray-xhttp-inbound.md#client-transport-profiles-vless-http).

> **Per-key spiderX (`XRAY_SPIDER_X_POOL`).** spiderX is a purely **client-side**
> REALITY parameter: it is emitted into VLESS client links as `&spx=<url-encoded>`
> and is **never** written to the server inbound — `config.json` is untouched and
> xray is not restarted. XTLS recommends a value unique per client, so instead of a
> global constant each key draws a value from this pool, picked **deterministically**
> by hashing the key UUID (so it is stable across restarts and reproducible). The
> value is stored per key in the `vpn_keys.spider_x` column (nullable; `NULL` = not
> emitted, full backward compatibility with pre-existing keys). Leaving the variable
> empty or unset changes nothing. When set, existing xray keys are **backfilled** on
> the next startup (idempotent; already-assigned values are never overwritten), so it
> can be enabled at any time — not only at the initial v31 upgrade. Every entry must
> start with `/` (validated at startup).

## AmneziaWG

| Variable | Required | Default | Description | Example |
|---|---|---|---|---|
| `AWG_CONFIG_PATH` | No | `/etc/amnezia/amneziawg/awg0.conf` | Path to the AWG server config file. | `/etc/amnezia/amneziawg/awg0.conf` |
| `AWG_INTERFACE` | No | `awg0` | AWG/WireGuard network interface name. | `awg0` |
| `AWG_NETWORK` | No | `10.0.0.0/24` | IPv4 subnet for the VPN. | `10.0.0.0/24` |
| `AWG_SERVER_ADDRESS` | No | `10.0.0.1` | Server's IPv4 address inside the VPN subnet. | `10.0.0.1` |
| `AWG_ENDPOINT_HOST` | No* | — | Public hostname/IP for AWG endpoint. Required to issue keys. | `vpn.example.com` |
| `AWG_ENDPOINT_PORT` | No | `0` | Public UDP port for AWG endpoint. | `51820` |
| `AWG_SERVER_PUBLIC_KEY` | No | _(empty)_ | AWG server public key (base64). Shown in client configs. | `ABC123...` |
| `AWG_DNS` | No | `1.1.1.1` | DNS server for AWG clients. | `1.1.1.1` |
| `AWG_MTU` | No | _(auto)_ | MTU for AWG client interface (576–1500). Omit to let client decide. | `1280` |
| `AWG_ALLOWED_IPS` | No | `0.0.0.0/0, ::/0` | Allowed IPs for AWG client routing (full-tunnel by default). | `0.0.0.0/0, ::/0` |
| `AWG_PERSISTENT_KEEPALIVE` | No | `25` | Keepalive interval in seconds (0–86400). | `25` |
| `AWG_USE_PRESHARED_KEY` | No | `true` | Generate and include a preshared key per client. | `true` |
| `AWG_STATS_INTERVAL` | No | `60` | Background traffic stats sampling interval in seconds (0–3600). | `60` |

_Legacy alias: `AWG_CLIENT_DNS` (= `AWG_DNS`)._

## SOCKS5 / Dante

| Variable | Required | Default | Description | Example |
|---|---|---|---|---|
| `SOCKS5_ENABLED` | No | `false` | Enable SOCKS5 proxy backend. | `false` |
| `SOCKS5_HOST` | No* | _(empty)_ | Public host for SOCKS5 (required if `SOCKS5_ENABLED=true`). | `vpn.example.com` |
| `SOCKS5_PORT` | No | `31337` | Public port for SOCKS5 connections. | `31337` |
| `SOCKS5_LOGIN_PREFIX` | No | `vpn_socks_` | Prefix for all managed Linux users. Must be unique and non-generic. | `vpn_socks_` |
| `SOCKS5_SYSTEM_USER_SHELL` | No | `/usr/sbin/nologin` | Shell for managed SOCKS5 Linux users. | `/usr/sbin/nologin` |
| `SOCKS5_SERVICE_NAME` | No | `danted` | systemd service name for Dante. | `danted` |
| `SOCKS5_PUBLIC_NAME` | No | `SOCKS5 Proxy` | Display name shown in the bot UI. | `SOCKS5 Proxy` |
| `SOCKS5_NOTE` | No | `SOCKS5 Dante proxy on server` | Description shown in proxy access cards. | `SOCKS5 Dante proxy on server` |

## MTProto Proxy

| Variable | Required | Default | Description | Example |
|---|---|---|---|---|
| `MTPROTO_ENABLED` | No | `false` | Enable MTProto proxy backend. | `false` |
| `MTPROTO_MODE` | No | `static` | Proxy mode: `static` (shared secret) or `managed` (per-user secrets). | `static` |
| `MTPROTO_HOST` | No* | _(empty)_ | Public host for MTProto (required if `MTPROTO_ENABLED=true`). | `vpn.example.com` |
| `MTPROTO_PORT` | No | `8443` | Public port for MTProto connections. | `8443` |
| `MTPROTO_SECRET` | No* | _(empty)_ | 🔒 Shared MTProto secret (required if `MTPROTO_MODE=static` and enabled). | _(hex string)_ |
| `MTPROTO_PUBLIC_NAME` | No | `Telegram MTProto Proxy` | Display name shown in the bot UI. | `Telegram MTProto Proxy` |
| `MTPROTO_NOTE` | No | `MTProto proxy for Telegram` | Description shown in proxy access cards. | `MTProto proxy for Telegram` |
| `MTPROTO_STATS_URL` | No | _(empty)_ | URL for MTProto statistics endpoint. | `http://127.0.0.1:8888/stats` |
| `MTPROTO_SERVICE_NAME` | No | `mtproxy` | systemd service name for MTProxy. | `mtproxy` |
| `MTPROTO_BINARY_PATH` | No | `/usr/local/bin/mtproto-proxy` | Path to the MTProto proxy binary. | `/usr/local/bin/mtproto-proxy` |
| `MTPROTO_RUN_USER` | No | `mtproxy` | User to run the MTProto proxy process as. | `mtproxy` |
| `MTPROTO_RUN_GROUP` | No | `mtproxy` | Group to run the MTProto proxy process as. | `mtproxy` |
| `MTPROTO_CONFIG_DIR` | No | `/etc/mtproxy` | Directory containing MTProxy base config files. | `/etc/mtproxy` |
| `MTPROTO_PROXY_SECRET_PATH` | No | `/etc/mtproxy/proxy-secret` | Path to the MTProxy `proxy-secret` file. | `/etc/mtproxy/proxy-secret` |
| `MTPROTO_PROXY_MULTI_CONF_PATH` | No | `/etc/mtproxy/proxy-multi.conf` | Path to the MTProxy `proxy-multi.conf` file. | `/etc/mtproxy/proxy-multi.conf` |
| `MTPROTO_MANAGED_DIR` | No | `/etc/mtproxy/vpn-bot` | Directory for bot-managed MTProto files. | `/etc/mtproxy/vpn-bot` |
| `MTPROTO_MANAGED_SECRETS_PATH` | No | `$MTPROTO_MANAGED_DIR/managed-secrets.json` | 🔒 Path to managed secrets JSON. | `/etc/mtproxy/vpn-bot/managed-secrets.json` |
| `MTPROTO_MANAGED_ENV_PATH` | No | `$MTPROTO_MANAGED_DIR/mtproxy.env` | Path to managed MTProxy env file. | `/etc/mtproxy/vpn-bot/mtproxy.env` |
| `MTPROTO_MANAGED_WRAPPER_PATH` | No | `/opt/vpn-service/scripts/run-mtproxy-managed` | Path to the managed-mode wrapper script. | `/opt/vpn-service/scripts/run-mtproxy-managed` |
| `MTPROTO_BACKUP_DIR` | No | `$MTPROTO_MANAGED_DIR/backups` | Directory for MTProto managed-file backups. | `/etc/mtproxy/vpn-bot/backups` |
| `MTPROTO_INTERNAL_STATS_PORT` | No | `8888` | Internal MTProxy stats port (1–65535). | `8888` |
| `MTPROTO_WORKERS` | No | `1` | Number of MTProxy worker processes (1–1024). | `1` |
| `MTPROTO_APPLY_TIMEOUT_SECONDS` | No | `10` | Timeout in seconds for apply + health check (1–3600). | `10` |
| `MTPROTO_ROLLBACK_ON_APPLY_FAILURE` | No | `true` | Automatically restore backup on apply failure. | `true` |
| `MTPROTO_KEEP_LAST_BACKUPS` | No | `10` | Number of managed-file backups to retain (0–1000). | `10` |

## Hysteria2

Hysteria2 runs as a standalone data plane (the `hysteria` server plus the
separate `hy2_auth` endpoint), independent of the bot process. These variables
let the bot build client links and gate issuance. Hysteria2 runs plain QUIC on
UDP/443 (see `deploy/hysteria/config.yaml`) — salamander obfuscation was
dropped; `HYSTERIA2_OBFS_PASSWORD` is deprecated and ignored.

| Variable | Required | Default | Description | Example |
|---|---|---|---|---|
| `HYSTERIA2_ENABLED` | No | `false` | Enable Hysteria2 key issuance in the bot. The data plane runs regardless. | `true` |
| `HYSTERIA2_HOST` | No* | — | Public hostname/IP clients connect to. Required to issue keys. | `vpn.example.com` |
| `HYSTERIA2_PORT` | No | `443` | Public UDP port of the Hysteria2 server (1–65535). Coexists with Xray REALITY on TCP/443. | `443` |
| `HYSTERIA2_SNI` | No* | — | TLS SNI used in the client link. Must match the CN/SAN of the server's cert. Required to issue keys. | `anycastedge.duckdns.org` |
| `HYSTERIA2_OBFS_PASSWORD` | No | — | **Deprecated** — salamander obfuscation was dropped; the value is parsed (so an existing `.env` doesn't fail startup) but no longer used. 🔒 | _(unset)_ |
| `HYSTERIA2_INSECURE` | No | `false` | Set `insecure=1` in the link (skip TLS cert validation on the client). See below. | `false` |
| `HYSTERIA2_AUTH_LISTEN` | No | `127.0.0.1:8444` | Loopback `host:port` the `hy2_auth` endpoint binds. Host must be loopback. | `127.0.0.1:8444` |
| `HYSTERIA2_STATS_LISTEN` | No | `127.0.0.1:9999` | Loopback `host:port` of the Traffic Stats API. Must match `trafficStats.listen` in `config.yaml`; host must be loopback. | `127.0.0.1:9999` |
| `HYSTERIA2_STATS_SECRET` | No | — | Shared secret for the Traffic Stats API; MUST equal `trafficStats.secret` in `config.yaml`. Empty disables hy2 traffic/online/kick. 🔒 | `s3cret` |
| `HYSTERIA2_STATS_INTERVAL` | No | `60` | Background hy2 traffic-stats sampling interval in seconds (0–3600; 0 disables the loop). | `60` |
| `HYSTERIA2_SERVICE_NAME` | No | `hysteria-server` | systemd unit of the Hysteria2 server, checked by the admin health diagnostics (`systemctl is-active`). | `hysteria-server` |
| `HYSTERIA2_AUTH_SERVICE_NAME` | No | `vpn-bot-hy2-auth` | systemd unit of the `hy2_auth` endpoint, checked by the admin health diagnostics. | `vpn-bot-hy2-auth` |
| `HYSTERIA2_CONFIG_PATH` | No | `/etc/hysteria/config.yaml` | Path to the hysteria-server config, bundled into the offsite recovery archive (when recovery is enabled) so a rebuilt box can restore the data plane. A missing file is skipped. | `/etc/hysteria/config.yaml` |
| `HYSTERIA2_HEALTH_INTERVAL` | No | `60` | How often (seconds) to probe `hy2_auth` `GET /healthz` and reflect it in the dashboard/health **Hysteria2: OK/DEGRADED** entry (0–3600; 0 disables the probe). Only active when `HYSTERIA2_ENABLED`. | `60` |

### Backend health & diagnostics parity

When `HYSTERIA2_ENABLED=true` the bot brings Hysteria2 to parity with Xray/AWG for
operational visibility: the admin **diagnostics** panel runs `systemctl is-active`
on `HYSTERIA2_AUTH_SERVICE_NAME` and `HYSTERIA2_SERVICE_NAME`, and a background
loop polls `hy2_auth` `GET /healthz` every `HYSTERIA2_HEALTH_INTERVAL` seconds to
drive the **Hysteria2: OK/DEGRADED** backend-health entry on the dashboard. This
signal is data-plane liveness only — because Hysteria2 issuance/revocation are
pure `vpn.db` writes with no apply step, a `DEGRADED` mark never blocks issuing or
revoking keys (unlike Xray/AWG, where a degraded backend gates mutations).

> **Note — traffic, online-count and revoke-kick still require the Traffic Stats
> API** (`HYSTERIA2_STATS_SECRET`, below). That data is only obtainable from
> `hysteria-server`'s own Traffic Stats API, which the operator must enable in
> `config.yaml`; the bot cannot synthesise it from any other source. So full
> observability parity is *conditional* on configuring that API.

### Traffic Stats API (`HYSTERIA2_STATS_*`) — traffic, online, revoke-kick

Unlike `hy2_auth` (which only authenticates handshakes), per-key traffic
counters, the online-clients count and immediate session termination on revoke
are served by the Hysteria2 **Traffic Stats API** — a separate authenticated
HTTP server exposed by `hysteria-server` itself. Enable it in
`/etc/hysteria/config.yaml`:

```yaml
trafficStats:
  listen: 127.0.0.1:9999   # must equal HYSTERIA2_STATS_LISTEN (loopback only)
  secret: s3cret           # must equal HYSTERIA2_STATS_SECRET
```

The bot only *reads* it (`GET /traffic`, `GET /online`) and POSTs `/kick` when a
key is revoked/deleted/expired. Without `HYSTERIA2_STATS_SECRET` set, hy2 keys
show no traffic and no online count, and a revoke blocks only new handshakes
(the live session survives until the client reconnects) — the pre-Stats-API
behaviour. The `id` reported by the API is the key's stats label (`hy2_<hex>`),
the same id `hy2_auth` returns.

### `HYSTERIA2_INSECURE` — off by default (valid cert)

The server presents a valid Let's Encrypt certificate for `HYSTERIA2_SNI`,
issued and renewed by `acme.sh` (dns_duckdns) outside this repo — see
`deploy/hysteria/config.yaml`. With a real cert there is no need for clients to
skip TLS validation, so `HYSTERIA2_INSECURE` defaults to `false` and
`insecure=1` is not added to issued links at all.

Only flip it to `true` temporarily (e.g. the cert hasn't been provisioned yet
for a fresh domain). While `true`, the client skips TLS certificate validation;
this does not weaken the per-key auth secret, but a blind on-path attacker can
see and probe the handshake, though not decrypt QUIC application data or
authenticate without a valid per-key secret.

## Key Expiry and Trial Access

| Variable | Required | Default | Description | Example |
|---|---|---|---|---|
| `KEY_EXPIRY_CHECK_INTERVAL` | No | `1800` | How often (seconds) to check for expiring/expired keys (0–86400). | `1800` |
| `KEY_EXPIRY_NOTIFY_DAYS` | No | _(empty)_ | Comma-separated list of days before expiry to send user notifications. | `7,3,1` |
| `KEY_MAX_TRIAL_DAYS` | No | `365` | Maximum duration (days) for trial VPN keys (1–3650). | `30` |

> **Trial access flow.** An approved user without an active key can request a short-lived *trial* key; a superadmin or moderator approves/rejects it from the admin panel, and the granted key is capped at `KEY_MAX_TRIAL_DAYS`. Per-user trial eligibility is tracked (`users.trial_quota_reset_at`) so trials cannot be farmed; the requests live in the `trial_key_requests` table.

## All-in-One Subscription

| Variable | Required | Default | Description | Example |
|---|---|---|---|---|
| `SUBSCRIPTION_ENABLED` | No | `false` | Enable all-in-one subscription bundles: one parent record (`key_bundles`) owning several VPN keys so a single subscription URL carries every protocol at once. While `false` the bundle service refuses every operation. | `false` |

A bundle provisions **one child key per enabled protocol** — VLESS (TCP), each
VLESS (HTTP) profile (`base`, `antisib`, `multi`) and Hysteria2 — through the
same per-protocol create path a standalone key uses, so children keep the usual
`xray_tcp_*` / `xray_http_*` / `hy2_*` email labels and stay visible to
reconciliation and anomaly detection. AWG is excluded (WireGuard configs do not
ride a base64 v2ray subscription) and so are the SOCKS5/MTProto proxies (a
different entity). Every child of a bundle gets the same `expires_at`, so they
expire together.

Partial-provisioning policy: a protocol switched **off** (its `.env` flag or the
admin protocol-module toggle) is skipped silently and the resulting composition
is recorded in the audit log; a protocol that is **on but degraded** aborts the
whole creation, because a bundle that silently lacks a protocol stays defective
forever while an aborted creation is simply retried.

## Announcements

| Variable | Required | Default | Description | Example |
|---|---|---|---|---|
| `SCHEDULED_ANNOUNCEMENTS_INTERVAL` | No | `60` | How often (seconds) the background loop delivers due scheduled announcements (0–86400). `0` disables the loop; announcements can still be scheduled and are delivered after a restart. | `60` |

## Off-site Encrypted Backup

| Variable | Required | Default | Description | Example |
|---|---|---|---|---|
| `OFFSITE_BACKUP_ENCRYPTION_KEY` | No | _(disabled)_ | 🔒 Fernet key for encrypting off-site DB backups. Generate with: `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`. Leave empty to disable off-site backups. | _(44-char base64url)_ |
| `OFFSITE_BACKUP_INTERVAL` | No | `604800` | Interval (seconds) between off-site backup uploads (0 = disabled). Default is 7 days. | `604800` |
| `OFFSITE_BACKUP_INCLUDE_CONFIGS` | No | `true` | Also send a second encrypted **recovery bundle** (`.env` + Xray/AWG/Hysteria2/MTProto/WARP configs) alongside the DB backup so the service can be rebuilt on a clean server. Encrypted with the same key; delivered as `vpnbot_recovery_*.tar.gz.enc`. | `true` |
| `OFFSITE_BACKUP_ENV_PATH` | No | _(auto)_ | 🔒 Path to the `.env` placed in the recovery bundle. Empty = auto-detect the `.env` loaded at startup. | `/opt/vpn-service/.env` |

## Anomaly Detection

| Variable | Required | Default | Description | Example |
|---|---|---|---|---|
| `ANOMALY_CHECK_INTERVAL` | No | `300` | How often (seconds) to run the anomaly detection scan (0–86400). | `300` |
| `ANOMALY_WINDOW_SECONDS` | No | `3600` | Traffic observation window in seconds (60–86400). | `3600` |
| `ANOMALY_MIN_UNIQUE_IPS` | No | `3` | **Deprecated.** Retained only as the default for `ANOMALY_UNIQUE_NETS`; the detector no longer counts raw IPs (1–1000). | `3` |
| `ANOMALY_UNIQUE_NETS` | No | `ANOMALY_MIN_UNIQUE_IPS` | Alert threshold in **distinct networks** per key within the window (1–1000). Each source IP is normalized to its ASN (via the local iptoasn database at `IP2ASN_DB_PATH`, default `/opt/vpn-service/data/ip2asn-v4.tsv`) or, when the ASN is unknown, to its `/24`. Counting networks instead of raw IPs stops carrier IP rotation and mobile↔Wi-Fi switching for one legitimate user from raising false positives. Keep the database fresh with `deploy/vpn-bot-ip2asn.timer`. | `3` |
| `ANOMALY_AUTO_REVOKE` | No | `false` | Automatically revoke flagged keys without admin confirmation. For AWG/Xray (IP-based detection) auto-revoke only takes effect when `ANOMALY_CONCURRENT_WINDOW_SECONDS > 0` — see the note below. | `false` |
| `ANOMALY_COOLDOWN_SECONDS` | No | `7200` | Cooldown before re-flagging the same key (0–86400). | `7200` |
| `ANOMALY_CONCURRENT_WINDOW_SECONDS` | No | `600` | Window for concurrent-connection anomaly detection (0–86400). | `600` |
| `ANOMALY_HYSTERIA2_MAX_CONN` | No | `0` | Flag a Hysteria2 key with >= this many concurrent connections (via the Traffic Stats API `/online`). `0` disables the hy2 check; requires `HYSTERIA2_STATS_SECRET`. | `5` |

> **Auto-revoke gating.** Over the full observation window a single roaming/mobile
> user legitimately accumulates many IPs, so revoking on that signal alone would
> hit legitimate users. Therefore, for AWG/Xray, `ANOMALY_AUTO_REVOKE=true` only
> revokes when `ANOMALY_CONCURRENT_WINDOW_SECONDS > 0` (a concurrency signal is
> required); with the concurrent window at `0` the detector is alert-only and logs
> a warning at startup. Hysteria2 uses the inherently concurrent `/online` count,
> so its auto-revoke follows `ANOMALY_AUTO_REVOKE` directly regardless of the
> concurrent-window setting.

## WARP Outbound IP Masking

Operational details are in [`warp.md`](warp.md). Defaults match the provided sudoers
template paths. Changing `WARP_CONFIG_PATH` or `WARP_INTERFACE` requires matching updates
to `/etc/sudoers.d/vpn-bot` and the `vpn-bot-warp-*` helper scripts; mismatches cause silent
sudo failures. Change only if you know what you are doing.

| Variable | Default | Meaning |
| --- | --- | --- |
| `WARP_CONFIG_PATH` | `/etc/amnezia/out-warp.conf` | Installed tunnel config path |
| `WARP_INTERFACE` | `out-warp` | AmneziaWG interface name |
| `WARP_INSTALL_HELPER_PATH` | `/usr/local/sbin/vpn-bot-warp-install` | Config install helper |
| `WARP_IFACE_HELPER_PATH` | `/usr/local/sbin/vpn-bot-warp-iface` | Interface up/down helper |
| `WARP_ROUTES_HELPER_PATH` | `/usr/local/sbin/vpn-bot-warp-routes` | Route add/del helper |
| `WARP_STATUS_HELPER_PATH` | `/usr/local/sbin/vpn-bot-warp-status` | `awg show` helper |
| `WARP_HELPER_STAGING_DIR` | `/run/vpn-bot/warp` | Private dir for staged uploads |
| `WARP_PING_TARGET` | `162.159.140.245` | ICMP target the health monitor pings to decide tunnel up/down. Default is a Cloudflare anycast address present in typical WARP `AllowedIPs`. Override if your `AllowedIPs` does not cover this address, otherwise the monitor reports false failures. |
| `WARP_MONITOR_OBSERVER_MODE` | `true` | When true (default) the bot's health monitor only **observes** the tunnel (probes, DB state, admin notifications) and never touches the interface or routes — those are owned by systemd (`awg-quick@out-warp` + `warp-routes.service`). Set to `false` only to restore the legacy model where the bot itself brings the interface up/down and adds/removes the routes. |
| `WARP_MONITOR_FAIL_WINDOW_SECONDS` | `60` | Seconds of **continuous** no-response before the monitor declares the tunnel down (and notifies admins). A single answered probe resets the window, so one dropped ICMP probe never raises a false alarm. |
| `WARP_MONITOR_RECOVER_WINDOW_SECONDS` | `60` | Seconds of **continuous** success before the monitor declares the tunnel recovered. A single failed probe resets the window. |
| `WARP_MONITOR_INTERVAL_SECONDS` | `10` | Probe interval during normal operation. |
| `WARP_MONITOR_FAST_INTERVAL_SECONDS` | `3` | Faster probe interval used the moment a probe gets no response, so an outage (and the start of recovery) is detected quickly. |
| `WARP_SPLIT_LIST_PATH` | `/etc/vpn-bot/warp-split.list` | Path to the selective-split prefix list. The bot reads this file directly (0644); writes go exclusively via `WARP_SPLIT_APPLY_HELPER_PATH`. Change only if you relocate the file — update the sudoers grant to match. |
| `WARP_SPLIT_APPLY_HELPER_PATH` | `/usr/local/sbin/vpn-bot-warp-split-apply` | Privileged helper that validates, atomically writes the split list, and restarts `vpn-bot-warp-split`. Must be root:root 0755 with a `NOPASSWD` sudoers grant. |
| `WARP_SPLIT_STATE_HELPER_PATH` | `/usr/local/sbin/vpn-bot-warp-split-state` | Privileged on/off/restart/status helper for the split **routing** (table T). The On/Off/Restart buttons call it to retract/re-apply the per-prefix `dev out-warp` routes and write the disabled marker — it never touches `awg-quick@out-warp`. Must be root:root 0755 with pinned-verb `NOPASSWD` grants. |
| `WARP_SPLIT_DISABLED_MARKER_PATH` | `/etc/vpn-bot/warp-split.disabled` | Root-owned (0644) marker recording the "off" intent. When present, `vpn-bot-warp-split` reconciles table T to empty on every boot-apply, so an "off" state survives reboot. The bot reads it directly; only the state helper writes it. |
| `WARP_PROXY_EGRESS_ENABLED` | `false` | Route LOCAL proxy egress (Dante/Xray/MTProto) through the WARP tunnel too. When `true` the Xray config writer binds the freedom outbound's egress source to the tunnel IP (`sendThrough` = the config's `[Interface] Address`) so its traffic is diverted into the tunnel by `vpn-bot-warp-routes`. Off by default; flip on only as part of the manual [WARP proxy egress](warp.md#warp-proxy-egress-masking-the-proxies-outbound-ip) activation runbook. Legacy alias: `WARP_PROXY_EGRESS`. |

## Legacy / Compatibility

| Variable | Required | Default | Description |
|---|---|---|---|
| `DEFAULT_PROXY_TYPE` | No | _(empty)_ | Legacy proxy entry type (internal use only; does not drive user-facing proxy flow). |
| `DEFAULT_PROXY_HOST` | No | _(empty)_ | Legacy proxy host. |
| `DEFAULT_PROXY_PORT` | No | _(empty)_ | Legacy proxy port. |
| `DEFAULT_PROXY_LOGIN` | No | _(empty)_ | Legacy proxy login. |
| `DEFAULT_PROXY_PASSWORD` | No | _(empty)_ | 🔒 Legacy proxy password. |
| `DEFAULT_PROXY_NOTE` | No | _(empty)_ | Legacy proxy note. |

## Notes

- If `XRAY_INBOUND_TAG` is empty, the adapter uses the first inbound with `settings.clients`.
- If `XRAY_MANAGE_SHORT_IDS=false`, `XRAY_SHORT_ID` must be set.
- `XRAY_APPLY_MODE=api` is the default apply mode (root deployment; adds/removes keys without restarting Xray, so no connections drop). Use `restart`/`reload` only in the non-root privilege-helper model — the helper ignores `api`/`reload` and always restarts Xray.
- `XRAY_APPLY_MODE=api` is incompatible with `PRIVILEGE_HELPERS_ENABLED=true`. When privilege helpers are enabled the bot applies Xray config changes through the `vpn-bot-xray-apply` sudo helper, which always calls `systemctl restart xray` regardless of `XRAY_APPLY_MODE`. Use `restart` mode with privilege helpers; `reload` and `api` modes are not honoured by the helper. See [Deployment → Xray API Mode](deployment.md#xray-api-mode).
- `SQLITE_SYNCHRONOUS=FULL` is the safer default for this control-plane database. `NORMAL` is faster but can lose the last committed transactions on OS or power failure while VPN backend state has already changed.
- `AWG_CLIENT_DNS` is supported only as a legacy alias; use `AWG_DNS` for new deployments.
- `AWG_ENDPOINT_HOST` and `AWG_ENDPOINT_PORT` should point to the public AWG endpoint clients will use.
- `SOCKS5_ENABLED=true` requires `SOCKS5_HOST`, `SOCKS5_PORT`, and a safe `SOCKS5_LOGIN_PREFIX`. Dante must already be installed and listening; the bot only creates/locks/deletes managed Linux users with that prefix.
- `MTPROTO_ENABLED=true` requires `MTPROTO_HOST`. `MTPROTO_MODE=static` also requires `MTPROTO_SECRET`.
- `MTPROTO_MODE=static` is compatibility mode: the bot shows a shared MTProto secret and can only deactivate a user's SQLite record. True per-user server-side revoke is impossible in static mode without rotating the shared secret.
- `MTPROTO_MODE=managed` creates one unique secret per user. See [Proxy backends → MTProto managed mode](proxy.md) for the full operational model.
- `MTPROTO_SECRET`, SOCKS5 passwords, and real production endpoints with credentials must never be committed. `.env.example` intentionally keeps proxy secrets empty.
- `DEFAULT_PROXY_*` is legacy compatibility storage and does not drive the new user-facing proxy access flow.
