# Adding the VLESS (HTTP) inbound — `vless-xhttp-reality`

This runbook seeds the second VLESS transport (XHTTP+REALITY) inbound used by the
**VLESS (HTTP)** key type. It is a **one-time, server-side** operation performed by
the operator on the VDS — the bot never edits inbound topology itself; it only adds
and removes *clients* in the inbound identified by `XRAY_XHTTP_INBOUND_TAG`.

The new inbound reuses the **same** `realitySettings` as `vless-in` (same
`privateKey`, `target`, `serverNames`, `shortIds`). It differs only in `tag`,
`port` (8443) and `streamSettings` (`network=xhttp`). It starts with an empty
`clients` list.

> ⚠️ Do this with the bot **stopped** so it cannot race the `ConfigFileLock`, and
> always keep the timestamped backup so you can roll back.

## 1. Seed the inbound (bot stopped)

```bash
systemctl stop vpn-bot
cd /usr/local/etc/xray && cp -a config.json config.json.bak.$(date +%s)

jq '
  (.inbounds[] | select(.tag=="vless-in")) as $b
  | .inbounds += [ $b
      | .tag = "vless-xhttp-reality"
      | .port = 8443
      | .settings.clients = []
      | .streamSettings.network = "xhttp"
      | .streamSettings.xhttpSettings = {
          path: "/v1/messages/stream",
          mode: "packet-up",
          extra: {
            xPaddingBytes: "100-1000",
            scMaxEachPostBytes: "500-3000",
            scMinPostsIntervalMs: "0-200",
            scMaxBufferedPosts: 8,
            keepAlivePeriod: 30,
            headers: {
              "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36",
              "Accept": "application/json, text/plain, */*"
            }
          }
        } ]
' config.json > /tmp/config.new.json

# Validate, then install with the same owner/mode as the live config (root-owned,
# group vpn-bot, 0640 — readable by the non-root bot, never world-readable).
xray run -test -config /tmp/config.new.json    # if the flag is rejected: xray -test -config /tmp/config.new.json
install -o nobody -g vpn-bot -m 0640 /tmp/config.new.json /usr/local/etc/xray/config.json

ufw allow 8443/tcp
systemctl restart xray && systemctl status xray --no-pager
# Leave vpn-bot stopped until the code with XRAY_XHTTP_ENABLED is deployed (step 2).
```

Sanity check that both inbounds exist and the new one is empty:

```bash
jq '.inbounds[] | {tag, port, network: .streamSettings.network, n: (.settings.clients|length)}' \
  /usr/local/etc/xray/config.json
```

## 2. Enable the feature in the bot

Add to the bot's `.env`:

```
XRAY_XHTTP_ENABLED=true
XRAY_XHTTP_INBOUND_TAG=vless-xhttp-reality
XRAY_XHTTP_PORT=8443
XRAY_XHTTP_PATH=/v1/messages/stream
XRAY_XHTTP_MODE=packet-up
```

`XRAY_XHTTP_PATH` / `XRAY_XHTTP_MODE` must match `xhttpSettings.path` / `mode` in the
inbound above (they are used only to build the client link). The `extra` block is a
server-side concern and is intentionally **not** placed in the generated link.

Deploy the new code, apply the DB migration (automatic on bootstrap; adds the
`transport` column, backfilling every existing key to `tcp`), then:

```bash
systemctl start vpn-bot
```

## 3. Verify

- Create a **VLESS (HTTP)** key from the bot and confirm the client landed **only**
  in the XHTTP inbound:

  ```bash
  jq '.inbounds[] | {tag, n: (.settings.clients|length)}' /usr/local/etc/xray/config.json
  ```

  The generated link must be `type=xhttp`, port `8443`, and carry **no** `flow`.
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

- **Feature only (keep the inbound):** set `XRAY_XHTTP_ENABLED=false` and restart the
  bot — the **VLESS (HTTP)** option disappears and the bot ignores the XHTTP inbound.
  (Leave any already-issued HTTP keys/clients in place, or remove them from the bot
  first, before tearing the inbound down.)
- **DB:** the `transport` column is additive and harmless; restore from a DB backup
  only if a full rollback is required.

> The REALITY `privateKey` is shared between the two inbounds. Never print it to
> logs or paste it into links — only the public key (`pbk`) belongs in a client URI.
