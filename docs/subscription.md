# All-in-one subscription endpoint

A **separate process** (`python -m subscription_server`, unit
`deploy/vpn-bot-subscription.service`) that serves one route — `GET /sub/{token}` — returning
the base64 subscription body for an all-in-one bundle: every child key of that bundle rendered
as its ordinary client link. It is **disabled by default** (`SUBSCRIPTION_ENABLED=false`, in
which case every request is answered with `404`) and there is **no bot UI for it yet**.

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
  --fullchain-file /etc/vpn-bot/tls/sub-fullchain.pem \
  --key-file       /etc/vpn-bot/tls/sub-key.pem \
  --reloadcmd      "chown root:vpn-bot /etc/vpn-bot/tls/sub-*.pem && \
                    chmod 0640 /etc/vpn-bot/tls/sub-key.pem && \
                    chmod 0644 /etc/vpn-bot/tls/sub-fullchain.pem && \
                    systemctl restart vpn-bot-subscription"
```

The key is read **once at startup**, so a renewal is picked up by that restart. The unit needs no
`ReadOnlyPaths` for it: `ProtectSystem=strict` makes `/etc` read-only, not invisible, and the
file mode is what actually gates access.

## Install (drift, by hand)

`scripts/deploy.sh` auto-installs **only** `vpn-bot.service`; like every other unit in `deploy/`,
this one is reported as drift and installed by the operator. Phase 1 also prints an
informational line telling you whether the unit is installed/active and whether the configured
ports are listening — it is never fatal, since a host that has not deployed the endpoint is a
normal state.

```bash
# 1. .env: enable the feature and choose the ports
#    SUBSCRIPTION_ENABLED=true
#    SUBSCRIPTION_BIND_PORT=8445          # loopback, NOT 8443 (taken by xhttp/mtproxy)
#    SUBSCRIPTION_PUBLIC_PORT=2096        # 0 keeps it loopback-only
#    SUBSCRIPTION_TLS_CERT=/etc/vpn-bot/tls/sub-fullchain.pem
#    SUBSCRIPTION_TLS_KEY=/etc/vpn-bot/tls/sub-key.pem

# 2. Unit
sudo install -m0644 deploy/vpn-bot-subscription.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now vpn-bot-subscription

# 3. Firewall (tracked rule — never a hand-typed `ufw allow`)
sudo bash deploy/ufw-subscription.sh          # reads the port from .env
#   ... and to close it again:
sudo bash deploy/ufw-subscription.sh --delete

# 4. Verify
systemctl status vpn-bot-subscription --no-pager
sudo ss -tlnp | grep -E '8445|2096'
curl -si http://127.0.0.1:8445/sub/definitely-not-a-real-token | head -1   # expect 404
```

Flipping `SUBSCRIPTION_ENABLED` needs a `systemctl restart vpn-bot-subscription`: the process
reads `.env` at startup. The unit stays active either way — with the flag off it keeps the
loopback socket and simply answers `404`, so its state does not flap with the feature flag — but
the **public listener is not started at all while the flag is off**, since a port that could only
ever answer `404` is attack surface with no function.
