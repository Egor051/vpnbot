# All-in-one subscription endpoint

A **separate process** (`python -m subscription_server`, unit
`deploy/vpn-bot-subscription.service`) that serves one route — `GET /sub/{token}` — returning
the base64 subscription body for an all-in-one bundle: every child key of that bundle rendered
as its ordinary client link. It is **disabled by default** (`SUBSCRIPTION_ENABLED=false`, in
which case every request is answered with `404` and the bot shows nothing about bundles).

Canonical references live where every other feature's do:

- **Environment variables** → [Configuration → All-in-One Subscription](configuration.md#all-in-one-subscription).
- **Bundle semantics** (composition, revoke, delete) → the same section.

## How it works

1. A client fetches `https://<host>:<public-port>/sub/<token>`; the token is the bundle's
   secret (`key_bundles.token`, 256 bits, URL-safe) and is the **only** credential.
2. The endpoint reads `vpn.db` **read-only, live, through the ordinary repositories** — no
   cache. A revoke, a token rotation or a delete therefore takes effect on the very next fetch,
   with no restart, and the endpoint keeps serving while `vpn-bot.service` is down.
3. Every ACTIVE child of an ACTIVE bundle is rendered with the **same code path the single-key
   config view uses** (`XrayService._build_vless_link` for VLESS TCP/HTTP,
   `bot.formatters.format_hysteria2_link` for Hysteria2), joined by newlines and base64-encoded.
   Nothing else can ride the subscription: AWG and the SOCKS5/MTProto proxies are excluded from
   the bundle composition, so a row of any other type fails the render rather than being skipped.

### Fail-closed behaviour

Every rejection is the **same empty `404`** — unknown token, revoked bundle, deleted bundle, a
bundle with no active children, a malformed child row, an unreadable database, and the feature
flag being off. A caller therefore cannot tell a token that never existed from one that was
revoked, and never receives a partial configuration. The endpoint **never** emits a `5xx`: an
unexpected fault is caught and answered with the same `404`, so no traceback reaches the
internet. The one other status is `429` (with `Retry-After`) from the per-client rate limit,
which is applied before the database is touched.

### Response headers

| Header | Value |
|---|---|
| `Profile-Title` | The bundle's own label (`bundle_XXXXX`); `base64:`-wrapped only if a hand-edited label is not ASCII. |
| `Profile-Update-Interval` | `SUBSCRIPTION_UPDATE_INTERVAL_HOURS` (hours). |
| `Subscription-Userinfo` | `upload=`/`download=` summed from the traffic counters the bot actually collected for the children (omitted when nothing was ever measured), and `expire=` from the children's shared `expires_at` as unix seconds (omitted when the bundle has no expiry). The header itself is omitted when neither is available. |
| `Cache-Control` | `no-store` — the body is a live credential set. |

`total=` is deliberately **never** emitted: this deployment has no traffic quota, so any value
there would be invented, and clients read a fabricated quota as a hard limit.

### Logging

The token is a working credential, so it is never logged: aiohttp's access log (which prints the
request line, token included) is switched off in the runner, and every log line refers to a
bundle by `bundle_id` plus a 12-hex-character SHA-256 fingerprint of the token.

## Bot UI

Everything below appears **only while `SUBSCRIPTION_ENABLED=true`**. With the flag off the bot
is byte-identical to what it was before the feature: no option in «Create key», no group in «My
keys», and a `bundle:*` callback that arrives anyway (replayed, or hand-typed) is refused by a
guard before any service is reached. There is **no new button in the main menu**.

| Where | What |
|---|---|
| **Create key** | An «All-in-One» option next to VLESS / AmneziaWG / Hysteria2. It reuses the ordinary create wizard (note → expiry → confirm). The result screen lists what the bundle actually contains and names any protocol left out because its backend is off. |
| **My keys** | An «All-in-One» group next to the protocol groups (first page, up to 5 bundles; the total is stated when there are more). |
| **Bundle card** | The same five actions a key card has — Config · Stats · Revoke · Note · Delete — plus a line saying AmneziaWG is issued as a **separate key**. |

- **Config** shows `https://<host>[:<port>]/sub/<token>`. The host is **not a setting of its
  own**: it is `HYSTERIA2_SNI` (falling back to `HYSTERIA2_HOST`), because the endpoint
  terminates TLS with a copy of the certificate that domain already has — so the URL, the
  certificate and the hy2 links stay on one domain by construction. The port is
  `SUBSCRIPTION_PUBLIC_PORT`; with it at `0` (loopback-only) the screen says the endpoint is
  not published instead of showing an unreachable link. **No QR image** — there is no QR
  library in the dependency tree and this feature is not a reason to add one; the URL is a
  tap-to-copy `<code>` block. The token reaches the chat and nothing else: no log line
  formats it.
- **Stats** are the bundle total **plus a per-protocol split** (VLESS, Hysteria2). The numbers
  come from two different sources — Xray's stats API and the Hysteria2 trafficStats endpoint —
  either of which can be unavailable on its own, so the split is what makes a gap (or a spike)
  attributable. Per-key figures stay one tap away on each child key.
- **Revoke** confirms, then cascades to the children and rotates the token, so the URL the user
  already holds is dead. **Delete** confirms, then removes the children before the bundle row.
  **Note** reuses the per-key note wizard.

## TLS termination

**The process terminates TLS itself** (`ssl_context` on the public port). There is no reverse
proxy in this stack and this PR does not introduce one — adding nginx just to forward a single
route would be a new privileged daemon, a new config surface and a new restart dependency for
one endpoint.

- **Public port** — `SUBSCRIPTION_PUBLIC_PORT` (`0` = off, in which case the endpoint is
  loopback-only). TCP/443 is held by Xray REALITY and TCP/8443 by MTProxy, so pick a free port
  (e.g. `2096`) and open it with the tracked rule (below).
- **Cleartext is impossible off-loopback**: a public port without both TLS values makes the
  process refuse to start (`Settings.validate_subscription_ready`), and the loopback bind host is
  validated to be a loopback address.
- **Which key, read by whom** — the endpoint runs as the unprivileged **`vpn-bot`** user (same as
  `vpn-bot-hy2-auth.service`) and reads a **group-readable copy of the already-issued Let's
  Encrypt material** for the server's domain — the same certificate `acme.sh` installs for
  Hysteria2, *not* `/etc/hysteria/key.pem` itself. Copying the key into a dedicated directory
  keeps the Hysteria2 material untouched and gives this process exactly one readable secret:

```bash
sudo install -d -o root -g vpn-bot -m 0750 /etc/vpn-bot/tls
# Add a SECOND install target to the existing acme.sh --install-cert invocation
# (keep the hysteria one as-is) so renewals land here too and restart the unit:
sudo acme.sh --install-cert -d anycastedge.duckdns.org \
  --fullchain-file /etc/vpn-bot/tls/fullchain.pem \
  --key-file       /etc/vpn-bot/tls/privkey.pem \
  --reloadcmd      "chown root:vpn-bot /etc/vpn-bot/tls/fullchain.pem /etc/vpn-bot/tls/privkey.pem && \
                    chmod 0640 /etc/vpn-bot/tls/privkey.pem && \
                    chmod 0644 /etc/vpn-bot/tls/fullchain.pem && \
                    systemctl restart vpn-bot-subscription"
```

The key is read **once at startup**, so a renewal is picked up by that restart. The unit needs no
`ReadOnlyPaths` for it: `ProtectSystem=strict` makes `/etc` read-only, not invisible, and the
file mode is what actually gates access.

## Go-live (drift install, by hand)

`scripts/deploy.sh` auto-installs **only** `vpn-bot.service`; like every other unit in `deploy/`,
this one is reported as drift and installed by the operator. Phase 1 also prints an
informational line telling you whether the unit is installed/active and whether the configured
ports are listening — it is never fatal, since a host that has not deployed the endpoint is a
normal state, and it tolerates a unit that is up but has not finished binding yet (see
[Start-to-bind delay](#start-to-bind-delay)).

**The order below is the order.** The TLS material must exist before the `.env` names it, and the
firewall rule before the port answers; a public port whose TLS pair is missing does not start at
all (next section), so putting the `.env` first would only buy a failed restart.

```bash
# 1. TLS copy — a group-readable copy of the domain's existing Let's Encrypt
#    material, installed by acme.sh (full command + --reloadcmd: section above).
sudo install -d -o root -g vpn-bot -m 0750 /etc/vpn-bot/tls
sudo acme.sh --install-cert -d <domain> \
  --fullchain-file /etc/vpn-bot/tls/fullchain.pem \
  --key-file       /etc/vpn-bot/tls/privkey.pem \
  --reloadcmd      "... && systemctl restart vpn-bot-subscription"
ls -l /etc/vpn-bot/tls          # expect root:vpn-bot, privkey.pem 0640

# 2. .env — the flag, the ports and the TLS pair, in one edit
#    SUBSCRIPTION_ENABLED=true
#    SUBSCRIPTION_BIND_HOST=127.0.0.1
#    SUBSCRIPTION_BIND_PORT=8445          # loopback, NOT 8443 (taken by xhttp/mtproxy)
#    SUBSCRIPTION_PUBLIC_PORT=2096        # empty or 0 keeps it loopback-only
#    SUBSCRIPTION_TLS_CERT=/etc/vpn-bot/tls/fullchain.pem
#    SUBSCRIPTION_TLS_KEY=/etc/vpn-bot/tls/privkey.pem

# 3. Firewall (tracked rule — never a hand-typed `ufw allow`)
sudo bash deploy/ufw-subscription.sh          # reads the port from .env
#   ... and to close it again:
sudo bash deploy/ufw-subscription.sh --delete

# 4. Unit — drift-installed by hand; deploy.sh never installs it
sudo install -m0644 deploy/vpn-bot-subscription.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable vpn-bot-subscription

# 5. Restart BOTH processes — each reads .env once, at startup
sudo systemctl restart vpn-bot-subscription vpn-bot

# 6. Wait ~20s. The endpoint imports the link renderers before it binds, so the
#    sockets do not exist for roughly 20 seconds after the restart (see below).
sleep 25

# 7. Verify: sockets, then the journal
sudo ss -tlnp | grep -E '8445|2096'         # expect BOTH: loopback 8445 + public 2096
sudo journalctl -u vpn-bot-subscription -n 30 --no-pager
#    expect: "subscription endpoint listening on 127.0.0.1:8445 ..."
#        and "subscription endpoint listening on :2096 (HTTPS, cert=...)"

# 8. Smoke
curl -si http://127.0.0.1:8445/sub/definitely-not-a-real-token | head -1   # expect 404
curl -si https://<domain>:2096/sub/definitely-not-a-real-token | head -1   # expect 404 over TLS
#    then fetch a real bundle URL from the bot's «Config» screen — expect 200.
```

### A public port without a TLS pair is a refusal to start — by design

Setting `SUBSCRIPTION_PUBLIC_PORT` without **both** `SUBSCRIPTION_TLS_CERT` and
`SUBSCRIPTION_TLS_KEY` makes the process log `subscription endpoint refuses to start: ...` and
exit `1` (`Settings.validate_subscription_ready`, called from `subscription_server.config`).
Under `Restart=on-failure` systemd then retries and the unit ends up `failed`. **This is the
feature, not a bug**: the response body is a complete set of a user's client links, so the
only alternative — binding the public port in cleartext — is the one outcome that must not be
reachable by editing `.env`. If the unit will not come up after a `.env` change, read the
journal before touching anything else; that line names exactly which value is missing.

### Start-to-bind delay

The process needs **roughly 20 seconds** between `systemctl start` and holding its sockets: before
binding it imports `services.xray` and `bot.formatters` (the single source of truth for the
`vless://` and `hy2://` link formats, reused so subscription links stay byte-identical to the
per-key ones), and that chain pulls in `aiogram`, which is nearly all of the cost.

This is **not** worth "fixing" with a lazy import. `XrayService` is the base class of the link
renderer — a module-level subclass, so its import cannot move into a function — and
`services.xray` imports `bot.formatters` itself, so deferring only the formatters import in
`subscription_server/render.py` would save nothing. A genuinely fast bind means restructuring the
shared link-rendering code, and a divergence between subscription links and per-key links is not
a risk worth taking to save 20 seconds of startup.

Practical consequences:

- After a restart, `ss` shows nothing on `8445`/`2096` for ~20s. Wait it out before concluding
  anything is wrong — `journalctl -u vpn-bot-subscription` prints one `listening on ...` line per
  socket the moment each bind succeeds.
- `scripts/deploy.sh` Phase 1 re-checks the ports for up to `SUBSCRIPTION_BIND_WAIT` seconds
  (default `30`) while the unit is active, so a deploy that lands during a slow start does not
  report a false "NOT listening". The check is informational either way and **never** fails a
  deploy.
- The delay is startup-only. It costs nothing per request: `GET /sub/{token}` is served by an
  already-warm process.

Flipping `SUBSCRIPTION_ENABLED` needs a restart of **both** units — `systemctl restart
vpn-bot-subscription vpn-bot`: each process reads `.env` at startup, the endpoint for its routes
and the bot for its UI. The flag is a **live `.env` edit, never a commit**: the repository default
stays `false`. The unit stays active either way — with the flag off it keeps the
loopback socket and simply answers `404`, so its state does not flap with the feature flag — but
the **public listener is not started at all while the flag is off**, since a port that could only
ever answer `404` is attack surface with no function.
