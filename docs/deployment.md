# Deployment

The supplied systemd unit expects the project in `/opt/vpn-service`. If you deploy
elsewhere, update `deploy/vpn-bot.service` before installing it.

There are two deployment models:

- **Root deployment (current default — `XRAY_APPLY_MODE=api`, `User=root`).** Zero-downtime
  key changes via the Xray gRPC API; no sudo helpers needed. This is what the shipped
  `deploy/vpn-bot.service` is configured for.
- **Non-root deployment (privilege-helper mode, `User=vpn-bot`).** Hardened: every
  privileged backend change goes through fixed sudo helpers. Opt in by editing the unit
  and setting `PRIVILEGE_HELPERS_ENABLED=true`.

> ⚠️ **`deploy/vpn-bot.service` is the authoritative source.**
> Every deploy copies it verbatim to `/etc/systemd/system/vpn-bot.service`. Manual edits to
> the system service file are overwritten on the next deploy. The current repo file runs the
> bot as `User=root` with `ProtectSystem=false` for `XRAY_APPLY_MODE=api`. If you switch
> deployment models, update `deploy/vpn-bot.service` first — do not edit the system file
> directly.

## Xray API Mode

> ⚠️ **`XRAY_APPLY_MODE=api` requires root and is incompatible with privilege helpers.**
> This is the **single canonical statement** of the api/root rule; the rest of the docs link
> here.
> - `XRAY_APPLY_MODE=api` is the **only** mode that adds/removes Xray keys without restarting
>   the Xray service. Without it, every key creation or deletion causes a full Xray restart,
>   which drops all active connections.
> - `XRAY_APPLY_MODE=api` is **incompatible** with `PRIVILEGE_HELPERS_ENABLED=true` — the bot
>   refuses to start if both are set simultaneously.
> - To use api mode, the bot **must run as root** (`User=root` in the service file) with
>   `PRIVILEGE_HELPERS_ENABLED=false`.
> - In the non-root privilege-helper model use `XRAY_APPLY_MODE=restart` (or `reload`); the
>   helper ignores `api`/`reload` and always restarts Xray.

For a hardened production deployment, prefer the non-root privilege-helper model: it keeps
the bot unprivileged at the cost of a brief Xray restart on each key change.

### Required `.env` variables for api mode

```dotenv
XRAY_APPLY_MODE=api
XRAY_INBOUND_TAG=vless-in          # must match the "tag" field on the VLESS inbound in config.json
XRAY_STATS_SERVER=127.0.0.1:10085  # must match the dokodemo-door api inbound port
```

Also set `PRIVILEGE_HELPERS_ENABLED=false` (or omit it) when using api mode.

### One-time server preparation

Before starting the bot in api mode, configure the Xray API inbound and tag the VLESS
inbound in `/usr/local/etc/xray/config.json`:

1. Add `"tag": "vless-in"` to your VLESS inbound object (use whatever tag you set as
   `XRAY_INBOUND_TAG`):

```json
{
  "inbounds": [
    {
      "tag": "vless-in",
      "port": 443,
      "protocol": "vless",
      "...": "..."
    }
  ]
}
```

2. Ensure the Xray API block and a `dokodemo-door` API inbound are present in
   `config.json`. The port must match `XRAY_STATS_SERVER`:

```json
{
  "api": {
    "tag": "api",
    "services": ["HandlerService", "StatsService", "LoggerService"]
  },
  "inbounds": [
    {
      "tag": "api-in",
      "listen": "127.0.0.1",
      "port": 10085,
      "protocol": "dokodemo-door",
      "settings": { "address": "127.0.0.1" }
    }
  ],
  "routing": {
    "rules": [
      { "inboundTag": ["api-in"], "outboundTag": "api", "type": "field" }
    ]
  }
}
```

3. Restart Xray once so the tag takes effect and verify the config:

```bash
sudo xray run -test -config /usr/local/etc/xray/config.json
sudo systemctl restart xray
sudo systemctl status xray --no-pager
```

4. Install the service file and start the bot:

```bash
sudo cp deploy/vpn-bot.service /etc/systemd/system/vpn-bot.service
sudo systemctl daemon-reload
sudo systemctl enable --now vpn-bot
sudo systemctl status vpn-bot
```

`deploy/vpn-bot.service` already contains `User=root`, `ProtectSystem=false`, and no
`ReadWritePaths` restrictions — no manual edits to the service file are needed.

## Root deployment model (api mode, `User=root`)

The repo service file is already configured for root+api mode. See [Xray API Mode](#xray-api-mode)
above for required `.env` variables and one-time Xray config preparation. There is no need to
create a `vpn-bot` system user or install sudo helpers for this model.

## Non-root deployment model (privilege-helper mode, `User=vpn-bot`)

Update `deploy/vpn-bot.service` to set `User=vpn-bot`, `Group=vpn-bot`,
`ProtectSystem=strict`, and restore `ReadWritePaths` before deploying. Then follow these
steps:

1. Keep `/opt/vpn-service`, deploy files, `.env`, and `.venv` owned by root/operator and not writable by `vpn-bot`.
2. Create the `vpn-bot:vpn-bot` system identity.
3. Grant `vpn-bot` write access only to runtime state: `/opt/vpn-service/data`, `/opt/vpn-service/logs` if file logs are enabled, and `/run/vpn-bot` created by systemd.
4. Install fixed helpers under `/usr/local/sbin` and install `/etc/sudoers.d/vpnbot` with only those helper entrypoints.
5. Enable `PRIVILEGE_HELPERS_ENABLED=true`.
6. Install `deploy/vpn-bot.service`; it is the non-root unit.

Use `XRAY_APPLY_MODE=restart` (or `reload`) in this model; api mode is not honoured by the
helper. The full privilege-separation architecture is documented in
[`security/privilege-separation-plan.md`](security/privilege-separation-plan.md) and the helper
contracts in [`../deploy/helpers/README.md`](../deploy/helpers/README.md).

Fresh install outline:

```bash
sudo install -o root -g root -m 0755 -d /opt/vpn-service
sudo git clone https://github.com/Egor051/vpnbot.git /opt/vpn-service
cd /opt/vpn-service

sudo python3 -m venv .venv
sudo /opt/vpn-service/.venv/bin/pip install --upgrade pip
sudo /opt/vpn-service/.venv/bin/pip install -r requirements.txt -c constraints.txt

sudo deploy/create-vpn-bot-user.sh
sudo install -o vpn-bot -g vpn-bot -m 0700 -d /opt/vpn-service/data /opt/vpn-service/logs
sudo install -o root -g root -m 0600 .env.example .env
sudoedit .env
```

Helper and sudoers install:

```bash
sudo install -o root -g root -m 0755 deploy/helpers/vpnbot-socks5-user /usr/local/sbin/vpnbot-socks5-user
sudo install -o root -g root -m 0755 deploy/helpers/vpnbot-xray-apply /usr/local/sbin/vpnbot-xray-apply
sudo install -o root -g root -m 0755 deploy/helpers/vpnbot-awg-apply /usr/local/sbin/vpnbot-awg-apply
sudo install -o root -g root -m 0755 deploy/helpers/vpnbot-mtproxy-apply /usr/local/sbin/vpnbot-mtproxy-apply
sudo install -o root -g root -m 0440 deploy/sudoers.d/vpnbot.example /etc/sudoers.d/vpnbot
sudo visudo -cf /etc/sudoers.d/vpnbot
```

Install and start the systemd service:

```bash
python deploy/check-nonroot-helper-mode.py
sudo cp deploy/vpn-bot.service /etc/systemd/system/vpn-bot.service
sudo systemctl daemon-reload
sudo systemctl enable --now vpn-bot
sudo systemctl status vpn-bot
python deploy/check-nonroot-helper-mode.py
```

Do not recursively chown the whole application tree to a login user for production. Do not
make the repository checkout, deploy files, or `.venv` writable by `vpn-bot`; a compromised
bot process must not be able to rewrite its own code, dependencies, units, or helper source.

If `MTPROTO_MODE=managed` is enabled, keep `/etc/mtproxy/vpnbot` root-owned and
helper-managed. Do not grant `vpn-bot.service` runtime write access to `/etc/systemd/system`
or broad write access to `/etc/mtproxy`; install or update the MTProxy drop-in and wrapper
manually during deploy, then run `systemctl daemon-reload` outside the bot runtime.

## Hysteria2 data plane (`hy2_auth` endpoint)

Hysteria2 support is **disabled by default** and runs as a standalone data plane,
independent of `vpn-bot.service`. The bot only writes key rows to the database;
the actual handshake authentication is done by a separate process,
`hy2_auth`, that the `hysteria` server calls over loopback HTTP. Because that
process reads the **live** database, a revoke or delete takes effect on the very
next handshake — there is no apply step and no data-plane restart.

You install three things: the `hysteria` server, its HTTP-auth pointing at
`hy2_auth`, and the `vpnbot-hy2-auth.service` systemd unit.

### 1. Install the `hy2_auth` systemd unit

```bash
sudo cp deploy/vpnbot-hy2-auth.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now vpnbot-hy2-auth
```

The unit runs `python -m hy2_auth` from the project venv, reads the same
`/opt/vpn-service/.env`, binds **loopback only** (`HYSTERIA2_AUTH_LISTEN`,
default `127.0.0.1:8444`), and opens the database **read-only** (`mode=ro`). It
runs no sudo helpers, so it is fully hardened (`NoNewPrivileges=yes`,
`ProtectSystem=strict`, a `@system-service` syscall filter, etc.) and must keep
running even when `vpn-bot.service` is down.

> **WAL / `ReadWritePaths` (required).** The bot keeps `vpn.db` in WAL mode, and a
> WAL *reader* must be able to write the shared-memory index (`-shm`) and the
> `-wal` sidecar — even though it only ever reads rows. The unit therefore grants
> `ReadWritePaths=/opt/vpn-service/data` (not `ReadOnlyPaths`); with a read-only
> data directory SQLite cannot open those sidecars and fails with
> `unable to open database file` / `SQLITE_CANTOPEN`, rejecting every handshake.
> This does **not** loosen the read-only guarantee on the data itself: the
> application opens the connection with `mode=ro`, so any write to the main DB
> still raises — the read-write grant only covers the WAL sidecars.

### 2. Point the `hysteria` server at the endpoint

In `/etc/hysteria/config.yaml`, use HTTP auth and the same listen address:

```yaml
auth:
  type: http
  http:
    url: http://127.0.0.1:8444/auth   # must match HYSTERIA2_AUTH_LISTEN
```

`HYSTERIA2_OBFS_PASSWORD` in `.env` must equal the salamander obfuscation
password in this file — a mismatch is a silent client timeout, not an error.
Start `hysteria-server.service` after `vpnbot-hy2-auth` (the unit declares
`Before=hysteria-server.service`).

### 2b. (Optional) Enable the Traffic Stats API — traffic, online, revoke-kick

Per-key traffic counters, the online-clients count and immediate session
termination on revoke require the Hysteria2 **Traffic Stats API** — a separate
authenticated HTTP server that `hysteria-server` exposes itself. Enable it in the
same `/etc/hysteria/config.yaml`:

```yaml
trafficStats:
  listen: 127.0.0.1:9999   # must equal HYSTERIA2_STATS_LISTEN (loopback only)
  secret: <random-secret>  # must equal HYSTERIA2_STATS_SECRET
```

Then set `HYSTERIA2_STATS_SECRET` (and, if you changed the port,
`HYSTERIA2_STATS_LISTEN`) in `.env`. The bot only *reads* this API and POSTs
`/kick` when a key is revoked/deleted/expired. Leave `HYSTERIA2_STATS_SECRET`
empty to keep this disabled — then hy2 keys simply show no traffic/online, and a
revoke blocks only new handshakes (the live session survives until reconnect).
See [Configuration → Hysteria2](configuration.md#hysteria2) for all
`HYSTERIA2_STATS_*` variables and `ANOMALY_HYSTERIA2_MAX_CONN`.

### 3. Fail-closed behaviour and health

- The endpoint **always replies HTTP 200** with `{"ok": <bool>, "id": "<label>"}`
  so `hysteria` never sees a 5xx. `ok` is `false` for an unknown/revoked token,
  a malformed body, or a database fault — it always fails **closed**.
- A wrong token is logged quietly (debug); a database fault (locked, corrupt) is
  logged at **error** with a failure counter, so a broken data plane is visible
  in `journalctl -u vpnbot-hy2-auth` instead of hiding behind benign rejections.
- `GET /healthz` runs a probe read: **200** `{"ok": true}` when the database is
  readable, **503** `{"ok": false}` when it is not — usable by a watchdog or a
  manual `curl http://127.0.0.1:8444/healthz`.

See [Configuration → Hysteria2](configuration.md#hysteria2) for the `.env`
variables, including the `HYSTERIA2_INSECURE=true` MITM tradeoff.

## Post-deploy smoke checklist

1. `python deploy/check-nonroot-helper-mode.py` passes.
2. `systemctl show vpn-bot -p User -p Group -p RuntimeDirectory -p NoNewPrivileges -p ReadWritePaths` shows `vpn-bot`, `vpn-bot`, `vpn-bot`, no enabled `NoNewPrivileges`, and only the expected writable paths.
3. `sudo -u vpn-bot test ! -w /opt/vpn-service/.venv && sudo -u vpn-bot test ! -w /opt/vpn-service/deploy`.
4. `sudo visudo -cf /etc/sudoers.d/vpnbot` passes and the file contains no `NOPASSWD: ALL`.
5. Issue/revoke one staging Xray or AWG key and one enabled proxy backend access, then check `journalctl -u vpn-bot -n 100 --no-pager` for helper errors or secret leakage.

> The `deploy/check-nonroot-helper-mode.py` checker is the **mandatory preflight and
> postflight** tool for the non-root privilege-helper model. In root+api mode it reports
> `FAIL: User=root`, which is expected — skip it and use `systemctl status vpn-bot` plus the
> bot's admin diagnostics instead. See [Operations → Healthcheck tool](operations.md).
