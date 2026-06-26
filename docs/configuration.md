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
| `ADMIN_IDS` | **Yes** | — | Comma-separated list of Telegram user IDs with full admin access. | `123456,789012` |
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
| `SOCKS5_USER_HELPER_PATH` | No | `/usr/local/sbin/vpnbot-socks5-user` | Absolute path to the SOCKS5 user management sudo helper. | `/usr/local/sbin/vpnbot-socks5-user` |
| `XRAY_APPLY_HELPER_PATH` | No | `/usr/local/sbin/vpnbot-xray-apply` | Absolute path to the Xray config apply sudo helper. | `/usr/local/sbin/vpnbot-xray-apply` |
| `AWG_APPLY_HELPER_PATH` | No | `/usr/local/sbin/vpnbot-awg-apply` | Absolute path to the AWG config apply sudo helper. | `/usr/local/sbin/vpnbot-awg-apply` |
| `MTPROTO_APPLY_HELPER_PATH` | No | `/usr/local/sbin/vpnbot-mtproxy-apply` | Absolute path to the MTProto apply sudo helper. | `/usr/local/sbin/vpnbot-mtproxy-apply` |
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
| `XRAY_ACCESS_LOG_PATH` | No | _(empty)_ | Path to the Xray access log for anomaly detection. Leave empty to disable. | `/var/log/xray/access.log` |

_Legacy aliases accepted: `XRAY_SERVER_ADDRESS` (= `XRAY_PUBLIC_HOST`), `XRAY_SERVER_PORT` (= `XRAY_PUBLIC_PORT`), `XRAY_PUBLIC_KEY` (= `XRAY_REALITY_PUBLIC_KEY`), `XRAY_SERVER_NAME` (= `XRAY_SNI`)._

> The one-time, server-side topology for the VLESS (HTTP) transport is documented in
> [`xray-xhttp-inbound.md`](xray-xhttp-inbound.md). VLESS (HTTP) has no public port of its
> own: `vless-in` (`:443`) terminates REALITY and forwards via a **default catch-all**
> `fallback` to a loopback XHTTP inbound where the path is validated. A path-based fallback
> does **not** match HTTP/2 XHTTP (the h2 `:path` lives in HPACK), so the catch-all is
> mandatory.

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
| `SOCKS5_NOTE` | No | `SOCKS5 Dante proxy on VDS` | Description shown in proxy access cards. | `SOCKS5 Dante proxy on VDS` |

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
| `MTPROTO_MANAGED_DIR` | No | `/etc/mtproxy/vpnbot` | Directory for bot-managed MTProto files. | `/etc/mtproxy/vpnbot` |
| `MTPROTO_MANAGED_SECRETS_PATH` | No | `$MTPROTO_MANAGED_DIR/managed-secrets.json` | 🔒 Path to managed secrets JSON. | `/etc/mtproxy/vpnbot/managed-secrets.json` |
| `MTPROTO_MANAGED_ENV_PATH` | No | `$MTPROTO_MANAGED_DIR/mtproxy.env` | Path to managed MTProxy env file. | `/etc/mtproxy/vpnbot/mtproxy.env` |
| `MTPROTO_MANAGED_WRAPPER_PATH` | No | `/opt/vpn-service/scripts/run-mtproxy-managed` | Path to the managed-mode wrapper script. | `/opt/vpn-service/scripts/run-mtproxy-managed` |
| `MTPROTO_BACKUP_DIR` | No | `$MTPROTO_MANAGED_DIR/backups` | Directory for MTProto managed-file backups. | `/etc/mtproxy/vpnbot/backups` |
| `MTPROTO_INTERNAL_STATS_PORT` | No | `8888` | Internal MTProxy stats port (1–65535). | `8888` |
| `MTPROTO_WORKERS` | No | `1` | Number of MTProxy worker processes (1–1024). | `1` |
| `MTPROTO_APPLY_TIMEOUT_SECONDS` | No | `10` | Timeout in seconds for apply + health check (1–3600). | `10` |
| `MTPROTO_ROLLBACK_ON_APPLY_FAILURE` | No | `true` | Automatically restore backup on apply failure. | `true` |
| `MTPROTO_KEEP_LAST_BACKUPS` | No | `10` | Number of managed-file backups to retain (0–1000). | `10` |

## Key Expiry and Trial Access

| Variable | Required | Default | Description | Example |
|---|---|---|---|---|
| `KEY_EXPIRY_CHECK_INTERVAL` | No | `1800` | How often (seconds) to check for expiring/expired keys (0–86400). | `1800` |
| `KEY_EXPIRY_NOTIFY_DAYS` | No | _(empty)_ | Comma-separated list of days before expiry to send user notifications. | `7,3,1` |
| `KEY_MAX_TRIAL_DAYS` | No | `365` | Maximum duration (days) for trial VPN keys (1–3650). | `30` |

## Off-site Encrypted Backup

| Variable | Required | Default | Description | Example |
|---|---|---|---|---|
| `OFFSITE_BACKUP_ENCRYPTION_KEY` | No | _(disabled)_ | 🔒 Fernet key for encrypting off-site DB backups. Generate with: `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`. Leave empty to disable off-site backups. | _(44-char base64url)_ |
| `OFFSITE_BACKUP_INTERVAL` | No | `604800` | Interval (seconds) between off-site backup uploads (0 = disabled). Default is 7 days. | `604800` |
| `OFFSITE_BACKUP_INCLUDE_CONFIGS` | No | `true` | Also send a second encrypted **recovery bundle** (`.env` + Xray/AWG/MTProto/WARP configs) alongside the DB backup so the service can be rebuilt on a clean server. Encrypted with the same key; delivered as `vpnbot_recovery_*.tar.gz.enc`. | `true` |
| `OFFSITE_BACKUP_ENV_PATH` | No | _(auto)_ | 🔒 Path to the `.env` placed in the recovery bundle. Empty = auto-detect the `.env` loaded at startup. | `/opt/vpn-service/.env` |

## Anomaly Detection

| Variable | Required | Default | Description | Example |
|---|---|---|---|---|
| `ANOMALY_CHECK_INTERVAL` | No | `300` | How often (seconds) to run the anomaly detection scan (0–86400). | `300` |
| `ANOMALY_WINDOW_SECONDS` | No | `3600` | Traffic observation window in seconds (60–86400). | `3600` |
| `ANOMALY_MIN_UNIQUE_IPS` | No | `3` | Minimum unique source IPs within the window to flag a key (1–1000). | `3` |
| `ANOMALY_AUTO_REVOKE` | No | `false` | Automatically revoke flagged keys without admin confirmation. | `false` |
| `ANOMALY_COOLDOWN_SECONDS` | No | `7200` | Cooldown before re-flagging the same key (0–86400). | `7200` |
| `ANOMALY_CONCURRENT_WINDOW_SECONDS` | No | `600` | Window for concurrent-connection anomaly detection (0–86400). | `600` |

## WARP Outbound IP Masking

Operational details are in [`warp.md`](warp.md). Defaults match the provided sudoers
template paths. Changing `WARP_CONFIG_PATH` or `WARP_INTERFACE` requires matching updates
to `/etc/sudoers.d/vpnbot` and the `vpnbot-warp-*` helper scripts; mismatches cause silent
sudo failures. Change only if you know what you are doing.

| Variable | Default | Meaning |
| --- | --- | --- |
| `WARP_CONFIG_PATH` | `/etc/amnezia/out-warp.conf` | Installed tunnel config path |
| `WARP_INTERFACE` | `out-warp` | AmneziaWG interface name |
| `WARP_INSTALL_HELPER_PATH` | `/usr/local/sbin/vpnbot-warp-install` | Config install helper |
| `WARP_IFACE_HELPER_PATH` | `/usr/local/sbin/vpnbot-warp-iface` | Interface up/down helper |
| `WARP_ROUTES_HELPER_PATH` | `/usr/local/sbin/vpnbot-warp-routes` | Route add/del helper |
| `WARP_STATUS_HELPER_PATH` | `/usr/local/sbin/vpnbot-warp-status` | `awg show` helper |
| `WARP_HELPER_STAGING_DIR` | `/run/vpn-bot/warp` | Private dir for staged uploads |
| `WARP_PING_TARGET` | `162.159.140.245` | ICMP target the health monitor pings to decide tunnel up/down. Default is a Cloudflare anycast address present in typical WARP `AllowedIPs`. Override if your `AllowedIPs` does not cover this address, otherwise the monitor reports false failures. |
| `WARP_MONITOR_OBSERVER_MODE` | `true` | When true (default) the bot's health monitor only **observes** the tunnel (probes, DB state, admin notifications) and never touches the interface or routes — those are owned by systemd (`awg-quick@out-warp` + `warp-routes.service`). Set to `false` only to restore the legacy model where the bot itself brings the interface up/down and adds/removes the routes. |
| `WARP_MONITOR_FAIL_WINDOW_SECONDS` | `60` | Seconds of **continuous** no-response before the monitor declares the tunnel down (and notifies admins). A single answered probe resets the window, so one dropped ICMP probe never raises a false alarm. |
| `WARP_MONITOR_RECOVER_WINDOW_SECONDS` | `60` | Seconds of **continuous** success before the monitor declares the tunnel recovered. A single failed probe resets the window. |
| `WARP_MONITOR_INTERVAL_SECONDS` | `10` | Probe interval during normal operation. |
| `WARP_MONITOR_FAST_INTERVAL_SECONDS` | `3` | Faster probe interval used the moment a probe gets no response, so an outage (and the start of recovery) is detected quickly. |
| `WARP_SPLIT_LIST_PATH` | `/etc/vpnbot/warp-split.list` | Path to the selective-split prefix list. The bot reads this file directly (0644); writes go exclusively via `WARP_SPLIT_APPLY_HELPER_PATH`. Change only if you relocate the file — update the sudoers grant to match. |
| `WARP_SPLIT_APPLY_HELPER_PATH` | `/usr/local/sbin/vpnbot-warp-split-apply` | Privileged helper that validates, atomically writes the split list, and restarts `vpnbot-warp-split`. Must be root:root 0755 with a `NOPASSWD` sudoers grant. |
| `WARP_SPLIT_STATE_HELPER_PATH` | `/usr/local/sbin/vpnbot-warp-split-state` | Privileged on/off/restart/status helper for the split **routing** (table T). The On/Off/Restart buttons call it to retract/re-apply the per-prefix `dev out-warp` routes and write the disabled marker — it never touches `awg-quick@out-warp`. Must be root:root 0755 with pinned-verb `NOPASSWD` grants. |
| `WARP_SPLIT_DISABLED_MARKER_PATH` | `/etc/vpnbot/warp-split.disabled` | Root-owned (0644) marker recording the "off" intent. When present, `vpnbot-warp-split` reconciles table T to empty on every boot-apply, so an "off" state survives reboot. The bot reads it directly; only the state helper writes it. |
| `WARP_PROXY_EGRESS` | `false` | Route LOCAL proxy egress (Dante/Xray/MTProto) through the WARP tunnel too. When `true` the Xray config writer binds the freedom outbound's egress source to the tunnel IP (`sendThrough` = the config's `[Interface] Address`) so its traffic is diverted into the tunnel by `vpnbot-warp-routes`. Off by default; flip on only as part of the manual [WARP proxy egress](warp.md#warp-proxy-egress-masking-the-proxies-outbound-ip) activation runbook. |

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
- `XRAY_APPLY_MODE=api` is incompatible with `PRIVILEGE_HELPERS_ENABLED=true`. When privilege helpers are enabled the bot applies Xray config changes through the `vpnbot-xray-apply` sudo helper, which always calls `systemctl restart xray` regardless of `XRAY_APPLY_MODE`. Use `restart` mode with privilege helpers; `reload` and `api` modes are not honoured by the helper. See [Deployment → Xray API Mode](deployment.md#xray-api-mode).
- `SQLITE_SYNCHRONOUS=FULL` is the safer default for this control-plane database. `NORMAL` is faster but can lose the last committed transactions on OS or power failure while VPN backend state has already changed.
- `AWG_CLIENT_DNS` is supported only as a legacy alias; use `AWG_DNS` for new deployments.
- `AWG_ENDPOINT_HOST` and `AWG_ENDPOINT_PORT` should point to the public AWG endpoint clients will use.
- `SOCKS5_ENABLED=true` requires `SOCKS5_HOST`, `SOCKS5_PORT`, and a safe `SOCKS5_LOGIN_PREFIX`. Dante must already be installed and listening; the bot only creates/locks/deletes managed Linux users with that prefix.
- `MTPROTO_ENABLED=true` requires `MTPROTO_HOST`. `MTPROTO_MODE=static` also requires `MTPROTO_SECRET`.
- `MTPROTO_MODE=static` is compatibility mode: the bot shows a shared MTProto secret and can only deactivate a user's SQLite record. True per-user server-side revoke is impossible in static mode without rotating the shared secret.
- `MTPROTO_MODE=managed` creates one unique secret per user. See [Proxy backends → MTProto managed mode](proxy.md) for the full operational model.
- `MTPROTO_SECRET`, SOCKS5 passwords, and real production endpoints with credentials must never be committed. `.env.example` intentionally keeps proxy secrets empty.
- `DEFAULT_PROXY_*` is legacy compatibility storage and does not drive the new user-facing proxy access flow.
