# Adding the VLESS (HTTP) inbound — `vless-xhttp-reality` (XHTTP fallback topology)

This runbook seeds the second VLESS transport (**XHTTP**) used by the **VLESS (HTTP)**
key type. It is a **one-time, server-side** operation performed by the operator on the
VDS — the bot never edits inbound topology itself; it only adds and removes *clients* in
the inbound identified by `XRAY_XHTTP_INBOUND_TAG`.

## XHTTP fallback topology

VLESS (HTTP) does **not** get its own public port. It rides `vless-in`'s public `:443`
REALITY via a **default catch-all fallback** to an internal, loopback-only XHTTP inbound:

```
client ──TLS / REALITY──▶  vless-in (:443, security: reality)
                               │  settings.fallbacks = [{ "dest": 8001, "xver": 0 }]
                               │      ↑ DEFAULT catch-all — no "path" field
                               ▼
                           vless-xhttp-reality (127.0.0.1:8001, security: none, network: xhttp)
                               path /v1/messages/stream is validated here, on the inbound
```

- `vless-in` (`:443`): `vless`, `security: reality`, `serverNames: ["googletagmanager.com"]`,
  `shortIds: ["ff69b6f523de0d17"]`, with a single **default catch-all** fallback
  `{ "dest": 8001, "xver": 0 }` (no `path`).
- `vless-xhttp-reality`: `listen: 127.0.0.1`, `port: 8001`, `vless`, `security: none`,
  `network: xhttp`, `xhttpSettings.path: /v1/messages/stream`, `mode: auto`. Empty
  `clients`, **no REALITY of its own** — it only holds the http `clients[]`; the bot
  adds/removes clients here by tag, and the VLESS (HTTP) link reuses `vless-in`'s REALITY
  (`pbk`/`sni`/`sid`/`fp`) and its public `:443`.

> ⚠️ **Gotcha — do NOT use a path-based fallback for XHTTP.** A path-based VLESS
> `fallback` (`{ "path": "/v1/messages/stream", "dest": 8001 }`) does **not** match an
> HTTP/2 XHTTP request: under h2 the request path lives in the HPACK-compressed `:path`
> pseudo-header, not in the HTTP/1 request-line that VLESS fallback `path` matching
> inspects. The only working layout is a **default catch-all** fallback
> (`{ "dest": 8001, "xver": 0 }`, no `path`) to the loopback XHTTP inbound; the path is
> validated downstream on the XHTTP inbound's `xhttpSettings.path`. Both `stream-one` and
> `packet-up` client modes are confirmed working through this fallback.

> ⚠️ Do this with the bot **stopped** so it cannot race the `ConfigFileLock`, and always
> keep the timestamped backup so you can roll back.

## 1. Seed the topology (bot stopped)

```bash
systemctl stop vpn-bot
cd /usr/local/etc/xray && cp -a config.json config.json.bak.$(date +%s)

jq '
  .inbounds |= (
    # 1) Add the DEFAULT catch-all fallback to vless-in (must stay the last/path-less
    #    entry so it is the default; any path-based fallbacks must precede it).
    map(
      if .tag == "vless-in"
      then .settings.fallbacks = ((.settings.fallbacks // []) + [{ "dest": 8001, "xver": 0 }])
      else .
      end
    )
    # 2) Append the loopback XHTTP inbound (the fallback dest), security: none, empty clients.
    + [
        {
          tag: "vless-xhttp-reality",
          listen: "127.0.0.1",
          port: 8001,
          protocol: "vless",
          settings: { clients: [], decryption: "none" },
          streamSettings: {
            security: "none",
            network: "xhttp",
            xhttpSettings: {
              path: "/v1/messages/stream",
              mode: "auto"
            }
          }
        }
      ]
  )
' config.json > /tmp/config.new.json

# Validate, then install with the same owner/mode as the live config (root-owned,
# group vpn-bot, 0640 — readable by the non-root bot, never world-readable).
xray run -test -config /tmp/config.new.json    # if the flag is rejected: xray -test -config /tmp/config.new.json
install -o nobody -g vpn-bot -m 0640 /tmp/config.new.json /usr/local/etc/xray/config.json

# No new firewall rule is needed: the XHTTP inbound listens on loopback only and the
# traffic enters through the already-open public :443.
systemctl restart xray && systemctl status xray --no-pager
# Leave vpn-bot stopped until the code with XRAY_XHTTP_ENABLED is deployed (step 2).
```

Sanity check that both inbounds exist, the new one is loopback + empty, and `vless-in`
carries the default catch-all fallback:

```bash
jq '.inbounds[] | {
      tag,
      listen,
      port,
      security: .streamSettings.security,
      network: .streamSettings.network,
      fallbacks: (.settings.fallbacks // []),
      n: (.settings.clients | length)
    }' /usr/local/etc/xray/config.json
```

> **Optional server-side tuning.** The XHTTP inbound can carry an `xhttpSettings.extra`
> block (e.g. `xPaddingBytes`, `scMaxEachPostBytes`, `keepAlivePeriod`, decoy `headers`).
> This is a purely server-side concern and is intentionally **not** placed in the
> generated client link.

## 2. Enable the feature in the bot

Add to the bot's `.env`:

```
XRAY_XHTTP_ENABLED=true
XRAY_XHTTP_INBOUND_TAG=vless-xhttp-reality
XRAY_XHTTP_PATH=/v1/messages/stream
XRAY_XHTTP_MODE=stream-one
```

- `XRAY_XHTTP_PATH` must match `xhttpSettings.path` on the inbound above (it is used only
  to build the client link).
- `XRAY_XHTTP_MODE` is the **client-side** mode written into the VLESS (HTTP) link. The
  default `stream-one` is the cleanest fit for direct REALITY — a single full-duplex
  HTTP/2 session — and is confirmed working through the catch-all fallback. Switch to
  `packet-up` when you want request throttling on long-lived sessions, or when fronting
  through a CDN (xmux rotates the underlying connections there). `stream-up` is the
  two-request variant for environments where a single-request full-duplex stream is
  unavailable; on direct REALITY it is not needed. The inbound's own `mode: auto` accepts
  any of these.
- `XRAY_XHTTP_PORT` is **not** used to build links anymore — the link rides `vless-in`'s
  public `:443` (`XRAY_PUBLIC_PORT`); the XHTTP inbound listens on loopback as the
  fallback dest. The setting is retained only for back-compat.

Deploy the new code, apply the DB migration (automatic on bootstrap; adds the
`transport` column, backfilling every existing key to `tcp`), then:

```bash
systemctl start vpn-bot
```

## 3. Verify

- Create a **VLESS (HTTP)** key from the bot and confirm the client landed **only** in the
  XHTTP inbound:

  ```bash
  jq '.inbounds[] | {tag, n: (.settings.clients|length)}' /usr/local/etc/xray/config.json
  ```

  The generated link must be `type=xhttp`, port `443` (the public REALITY port, not 8001),
  carry the REALITY parameters from `vless-in`, and carry **no** `flow`.
- Create a **VLESS (TCP)** key and confirm it landed **only** in `vless-in`.
- Delete both and confirm each disappears from its own inbound.
- Confirm an existing (legacy) key still works and is labelled `VLESS (TCP)`.

## Rollback

- **Code:** revert the deploy via git.
- **Xray config:** restore the timestamped backup and restart Xray:

  ```bash
  cp -a /usr/local/etc/xray/config.json.bak.<ts> /usr/local/etc/xray/config.json
  systemctl restart xray
  ```

  (No firewall rule to undo — the XHTTP inbound was loopback-only.)

- **Feature only (keep the inbound):** set `XRAY_XHTTP_ENABLED=false` and restart the bot —
  the **VLESS (HTTP)** option disappears and the bot ignores the XHTTP inbound. (Leave any
  already-issued HTTP keys/clients in place, or remove them from the bot first, before
  tearing the inbound down.)
- **DB:** the `transport` column is additive and harmless; restore from a DB backup only if
  a full rollback is required.

> The catch-all fallback forwards **all** non-matching REALITY traffic to the loopback
> XHTTP inbound. `vless-in` keeps terminating REALITY for VLESS (TCP) as before; only
> connections that fall through to the fallback reach the XHTTP inbound, where the path is
> validated.
