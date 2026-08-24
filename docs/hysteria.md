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
   before restarting the service. The renewal **fan-out** — copying the new chain into
   `/etc/hysteria/cert.pem`/`key.pem` with the `hysteria` owner and restarting the service — is
   the tracked `deploy/vpn-bot-acme-reload.sh` hook, wired as acme.sh's `--reloadcmd`
   ([Subscription → TLS termination](subscription.md#tls-termination)).
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

### Auth-unit name: repo vs host (a recorded, deliberate divergence)

The tracked unit file is `deploy/vpn-bot-hy2-auth.service`, but on a host provisioned before the
`vpnbot-*` → `vpn-bot-*` rename the **installed** unit is `vpnbot-hy2-auth.service`. That legacy
name is **kept on purpose** — like `vpnbot-hy2-warp-mark`, it is not tech debt and must not be
"fixed" by a rename; the two are the only survivors of the old spelling.

What bridges the two is `.env`: `HYSTERIA2_AUTH_SERVICE_NAME` is what the bot's admin diagnostics
actually call `systemctl is-active` on, so they follow whichever name the host uses. `.env.example`
ships the **`vpn-bot-hy2-auth`** default, so a host running the legacy unit **must** set the legacy
name in its own `.env` — otherwise diagnostics report the auth sidecar as inactive while handshakes
keep succeeding.

Two consequences in `scripts/deploy.sh` Phase 1 that are **expected output, not faults**:

- `UNIT_SET` collects the basename of every shipped `deploy/*.service`, so it contains
  `vpn-bot-hy2-auth.service`. On a legacy-named host that unit is `load=not-found`, and Phase 1
  reports it as *not installed / skipped*.
- The unit that really is serving handshakes, `vpnbot-hy2-auth.service`, enters `UNIT_SET` only
  through the `.env`-derived branch — i.e. **only because `HYSTERIA2_AUTH_SERVICE_NAME` names it**.
  Clear that key and the live sidecar silently stops being watched.

Read your host's actual state (read-only):

```bash
systemctl list-units --all 'vpn*hy2-auth*'
grep -n '^HYSTERIA2_AUTH_SERVICE_NAME' /opt/vpn-service/.env
```

### Masquerade decoy (reverse proxy)

`deploy/hysteria/config.yaml` enables Hysteria2's **proxy** masquerade
(`masquerade.type: proxy`, `masquerade.proxy.url: https://127.0.0.1:8443`): a probe that doesn't
complete the Hysteria2 handshake is reverse-proxied to a real local HTTPS listener and served a
real website instead of a reset. That listener is the *same* loopback vhost Xray REALITY uses as
its self-steal `target`, so both data planes serve one docroot with byte-identical content.

`rewriteHost: false` keeps the client's `Host` header, so the local server picks the same vhost it
would over TCP. `insecure: true` is correct rather than a weakening: the peer is `127.0.0.1`, a
certificate name can never match an address literal, and intercepting loopback already requires
root here.

The alternative layout, `masquerade.type: file` out of `/etc/hysteria/masq`, is what this host used
to run and is still supported by the tooling — see
[Keeping the decoy in step](#keeping-the-decoy-in-step-vpn-bot-decoy-freshensh) below. It is *not*
the shipped default, because it needs the docroot copied into a second directory and re-copied on
every edit: two trees to keep identical, and a stale one is exactly the fingerprint a decoy exists
to avoid. `install-config.sh` installs whichever layout the tracked config declares.

No `listenHTTP`/`listenHTTPS` are configured, since those would open separate plaintext TCP
`:80`/`:443` listeners and TCP/443 is already held by Xray REALITY on this host — the decoy is
served over the existing UDP/443 path instead.

### Keeping the decoy in step (`vpn-bot-decoy-freshen.sh`)

Two data planes on this host answer a probe with a website rather than a reset, and they must
answer with the **same** one:

| Plane | Port | Serves the decoy from |
|---|---|---|
| Xray REALITY (self-steal `target`) | TCP/443 → loopback vhost | the nginx docroot, `DECOY_ROOT` |
| Hysteria2 (`masquerade.type: proxy`, shipped) | UDP/443 QUIC | the same loopback vhost — one tree, nothing to mirror |
| Hysteria2 (`masquerade.type: file`, legacy) | UDP/443 QUIC | `MASQ_DIR` = `/etc/hysteria/masq` — a second tree |

Under the shipped proxy layout there is only one tree, so nothing can drift apart and
`deploy/vpn-bot-decoy-freshen.sh` does no mirroring at all: it reads `masquerade.type` out of
`HYSTERIA_CONF` and logs that it is skipping the step. Under the legacy `file` layout the two trees
are real and nothing keeps them in step on its own — Hysteria2 reads its copy as an unprivileged
user that has no business reading the nginx docroot — so the hook does the mirroring:
`rsync -a --delete` from `DECOY_ROOT` into `MASQ_DIR`, then `chown` to `MASQ_OWNER:MASQ_GROUP`.
**That is the answer to "who populates `/etc/hysteria/masq`" on a `type: file` host — it is not
placed there by hand.** The layout check is what stops the hook from leaving a stale second copy on
a host that no longer reads one.

It also drives a freshness pass. A static decoy whose "last updated" date is months old is a tell
on its own, so the site carries rolling timestamps and something has to advance them. That
rewriter is **deliberately not tracked here and cannot be**: it necessarily encodes the decoy's
own markup — which files, which patterns, which fake incident history — and that content is
unique per deployment and is the whole point of a decoy. It stays a deployment-local script that
this hook merely *calls*, via `DECOY_FRESHEN_HOOK`. Unset, the freshness pass is skipped; whether
anything is mirrored afterwards is decided by the layout above, not by this variable.

Install — no copy step, run it out of the checkout like `deploy/vpn-bot-acme-reload.sh`.
Deliberately **cron, not a systemd unit**: every `deploy/*.service` basename is enrolled into
deploy.sh's `UNIT_SET` ([`deploy/managed-units.list`](../deploy/managed-units.list)), so shipping
a unit for a job the host runs from cron would make Phase 1 report it not-installed on every
deploy — opening a new repo/host divergence instead of closing one.

```bash
sudo chmod 0755 /opt/vpn-service/deploy/vpn-bot-decoy-freshen.sh
# verify first, read-only, without waiting for the cron window
sudo DECOY_ROOT=/var/www/<DECOY_SITE> /opt/vpn-service/deploy/vpn-bot-decoy-freshen.sh --dry-run
sudo crontab -e
# pick an off-peak minute; nothing depends on the exact time
7 3 * * * DECOY_ROOT=/var/www/<DECOY_SITE> /opt/vpn-service/deploy/vpn-bot-decoy-freshen.sh >/dev/null 2>&1
```

> **Known host divergence — check yours.** On a host provisioned before this hook was tracked, both
> halves may already run from cron as an untracked local script (e.g.
> `/usr/local/sbin/site-freshen.sh`) that calls the rewriter and then rsyncs into `MASQ_DIR` itself.
> Adding the line above without removing that one leaves **two** jobs writing the same tree on
> their own schedules — and under the shipped `masquerade.type: proxy` layout the predecessor's
> mirror is not merely duplicated work, it is *dead* work that nothing reads, keeping alive exactly
> the stale second copy the proxy layout removed. Read your crontab before changing anything:
>
> ```bash
> sudo crontab -l
> ```
>
> Migrate in this order, so the freshness pass is never the thing that lapses:
>
> 1. Point `DECOY_FRESHEN_HOOK` at the **rewriter alone** (e.g. the `.py`), never at the wrapper —
>    a wrapper that also mirrors would redo step 2 unconditionally and defeat the layout check.
> 2. `chmod 0755` that rewriter. A script only ever invoked as `python3 rewriter.py` is typically
>    mode 0644, and this hook fails closed on a non-executable `DECOY_FRESHEN_HOOK` rather than
>    guessing an interpreter.
> 3. `--dry-run` this hook and confirm the log shows the rewriter running and the mirror skipped.
> 4. Only then replace the predecessor's crontab line with the one above.

`DECOY_ROOT` has **no default on purpose**. `rsync --delete` is destructive by design: pointed at
a missing or empty source it would faithfully empty `MASQ_DIR`, leaving Hysteria2 answering probes
with a bare 404 while nginx still answers with a site. A mismatch between the two planes is
exactly the tell this mechanism exists to avoid, so the script fail-loudly refuses before touching
anything if `DECOY_ROOT` is unset, absent, or has no `INDEX_NAME` in it.

nginx needs no reload here — it serves `DECOY_ROOT` from disk per request (`try_files`), so a
rewritten file is live immediately. It *does* need a reload after a **certificate** renewal, which
is [`deploy/vpn-bot-acme-reload.sh`](../deploy/vpn-bot-acme-reload.sh)'s job, not this one's.


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
