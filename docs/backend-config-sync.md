# Backend config sync — the two co-owned data-plane configs

Hysteria2 ships a tracked, installable config (`deploy/hysteria/config.yaml` +
`deploy/hysteria/install-config.sh`). Xray and AmneziaWG do not — and for a long time
that looked like an oversight. It is not: it follows directly from **who writes the
file at runtime**.

This document covers the resulting mechanism: what is tracked for those two backends,
how the host is compared against it, and the one case where the repo can be pushed
back onto the host.

## Why the three backends are not treated the same

| Live file | Who writes it at runtime | Can the repo copy over it? |
|---|---|---|
| `/etc/hysteria/config.yaml` | **Operator only.** The bot writes database rows; `hy2_auth` authenticates handshakes against the live DB. Nothing rewrites this file. | **Yes** — `deploy/hysteria/install-config.sh`, which injects the stats secret so the placeholder never lands on disk. |
| `/usr/local/etc/xray/config.json` | **Co-owned.** The bot rewrites the whole file on every key issue/revoke (`adapters/xray_config.py`, `os.replace` at the end of the apply path). | **No.** A `cp` would delete every issued client and short ID. |
| `/etc/amnezia/amneziawg/awg0.conf` | **Co-owned.** The bot rewrites the whole file on every peer insert/remove (`adapters/awg_config.py`, via `backup.atomic_write_text`). | **No.** A `cp` would delete every issued peer. |

So for the two co-owned files the repo cannot track *the config*. What it can track —
and now does — is **their structure**, with every bot-owned region left empty:

- `deploy/xray/config.skeleton.json`
- `deploy/awg/awg0.conf.example`

Both ship placeholders (`<REALITY_PRIVATE_KEY>`, `<AWG_SERVER_PRIVATE_KEY>`, …) rather
than values, so they are safe to commit and safe to read on a shared host.

## The ownership split, exactly

This is the single definition everything else derives from. It is pinned by
`tests/test_backend_config_sync.py`, which drives the **real writers** and asserts the
checker classifies what they produced — so a writer that moves a client list or renames
a peer marker fails the suite instead of failing in production.

**Xray — the bot owns:**

| Region | Written by |
|---|---|
| `inbounds[*].settings.clients` | `XrayConfigAdapter._clients()` — one entry per issued VLESS / VLESS (HTTP) key |
| `inbounds[*].streamSettings.realitySettings.shortIds` | `XrayConfigAdapter._reality_settings()` |
| `outbounds[*].sendThrough` **on `protocol: freedom` only** | `apply_warp_send_through()`, re-asserted on *every* config write |

Everything else in `config.json` is operator structure: inbound tags and ports, the
REALITY `target` and `serverNames`, the fallback topology, `routing`, `dns`, `policy`,
`api`, `log`.

**AmneziaWG — the bot owns:**

| Region | Written by |
|---|---|
| `[Peer]` blocks delimited by `# vpn-bot peer start key_id=<N> owner=<UID>[ label=<L>]` … `# vpn-bot peer end key_id=<N>` | `AwgConfigAdapter._peer_block()` |

`[Interface]` is entirely operator-owned. The bot reads it (`read_server_config`) and
carries it through verbatim on every rewrite.

> ⚠️ The AmneziaWG obfuscation fingerprint — `Jc`/`Jmin`/`Jmax`, `S1`–`S4`, `H1`–`H4`,
> `I1`–`I5` — is part of the deployment's identity, not a tunable. The bot copies those
> values from `[Interface]` into every client config, and no handshake completes unless
> server and client agree byte for byte. Changing one on the server silently invalidates
> **every key already issued**.

## Checking the host: `check`

Read-only. Compares the live files against the tracked skeletons with every bot-owned
region excluded, so runtime state can never be reported as drift.

```bash
python3 deploy/backend-config-sync.py check
python3 deploy/backend-config-sync.py --selftest      # exercises the comparison logic
```

Defaults come from the same paths deploy.sh uses; `--repo-root`, `--xray-config` and
`--awg-config` override them.

What the comparison does:

- **Placeholders are wildcards.** `<REALITY_PRIVATE_KEY>` matches any value, so secrets
  never need to be in the repo for the check to work. For partly-literal values such as
  `PostUp`, the text *around* the placeholders is still asserted — a `MASQUERADE` → `SNAT`
  change is caught even though the subnet and interface are placeholders.
- **Inbounds are matched by `tag`, not position.** Xray does not care about inbound
  order, so neither does the checker.
- **Comparison is type-strict.** JSON `true` and `1` are different values; a config that
  drifted from one to the other is reported.
- **An absent backend is not drift.** A host running only Hysteria2 has no
  `config.json` — the checker reports it as INFO and exits 0. Same `absent-ok` policy as
  deploy.sh's out-of-repo helpers.
- **Bot state is reported, never compared.** The output carries a census (clients per
  inbound tag, peers total / bot-managed / hand-added) so the operator can see runtime
  state without it affecting the verdict.
- **A hand-added peer surfaces as INFO.** It is not a config error, but a `[Peer]` block
  with no `vpn-bot` marker is invisible to the bot while still holding an address out of
  `AWG_NETWORK`, so it never passes silently.

Exit codes — this is the contract with deploy.sh:

| Code | Meaning |
|---|---|
| `0` | No structural drift (or the backend is not deployed here). |
| `1` | **Fail-closed:** no verdict was reachable — unparseable live config, missing skeleton. |
| `2` | Usage error. |
| `3` | Structural drift found. |

## The Phase 1 gate

`scripts/deploy.sh` runs `check` during Phase 1, against the `origin/main` worktree
(`$WT`) rather than the local checkout — the same way unit drift is scanned. A PR that
legitimately reshapes the data plane is therefore caught **before** the restart, not
after.

Drift stops the deploy. When it fires, the checker cannot know which side is wrong, so
the report prints both routes:

```bash
# The HOST is wrong — the repo is the intent:
python3 deploy/backend-config-sync.py install-xray --dry-run   # review the merge
python3 deploy/backend-config-sync.py install-xray             # then apply
sudo systemctl restart xray                                    # pick the window yourself
# AWG has no installer on purpose — edit awg0.conf by hand (see below)

# The REPO is wrong — the host is the intent:
#   update deploy/xray/config.skeleton.json or deploy/awg/awg0.conf.example
```

`ALLOW_BACKEND_CONFIG_DRIFT=1` continues past the gate. Apply it consciously only — the
drift is known and safe, or you are deploying the very commit that makes the skeleton
match and will run `install-xray` immediately after. It is **never** a substitute for
updating the skeleton when the host is the correct side of the diff.

Exit code `1` is deliberately **not** bypassable by that knob: an unparseable
`config.json` is not drift to be waived, it is a broken data plane — the bot's own writer
would fail on it too.

> Because bot-owned regions are excluded from the comparison, a finding here is *always*
> operator-owned structure. Issuing or revoking keys can never turn Phase 1 red, which is
> what keeps the knob from becoming a reflex.

## Pushing the repo onto the host: `install-xray`

A merge, not a copy: the skeleton supplies the structure, the live file supplies every
bot-owned region and every operator secret.

```bash
python3 deploy/backend-config-sync.py install-xray --dry-run    # prints the merged config
python3 deploy/backend-config-sync.py install-xray
sudo systemctl restart xray
```

The safety properties, in the order they are enforced:

1. **Refuses if the live config is absent.** The REALITY private key exists *only* in the
   live file, so there is no bootstrap path here — a merge with nothing to merge into
   would write `<REALITY_PRIVATE_KEY>` into a load-bearing config.
2. **Refuses if the live config has no `clients` list.** That is not a config this tool
   understands, and guessing would cost keys.
3. **Placeholders resolve from `.env` first, then from the live value at the same path.**
   `.env` is the operator's intent (`XRAY_SNI`, `XRAY_XHTTP_PATH`); the live file is only
   the current state. A placeholder with neither source is a fail-closed refusal, never a
   literal `<...>` on disk.
4. **Clients, short IDs and `sendThrough` are re-injected by inbound `tag`, not index**,
   and the merged client count is asserted equal to the live count. A skeleton that names
   an inbound the host does not have would silently drop that inbound's keys; the
   assertion catches it before anything is written.
5. **`xray run -test` must accept the merged config.** If the binary is missing or rejects
   the result, nothing is written — an unvalidated config over a live one takes `:443`
   down on the next restart, and the bot's own writes then fail on a file it cannot parse.
6. **Mode and owner are preserved**, the previous config is kept as `config.json.pre-sync`,
   and the replacement is atomic (`os.replace`).
7. **Xray is never restarted.** Choosing the window is the operator's call.

At zero drift the merge is *semantically identical* to the live config — it changes
nothing but formatting. That is the property that makes the installer safe to reach for.

> Run it with the bot stopped, or during Phase 2 of a deploy (deploy.sh stops the bot
> unit before Phase 2), so the merge cannot race the bot's own `ConfigFileLock`.

### Why AmneziaWG has no installer

`[Interface]` is *all* operator-owned, and every value in it is either a secret or part
of the obfuscation fingerprint. There is nothing for a tool to merge: either the host is
right and the example needs updating, or the host is wrong and the fix is a hand edit
whose blast radius (every issued key) the operator must weigh personally. `check` still
reports the divergence; applying it is manual on purpose.

## Bootstrap on a fresh or migrated host

Neither skeleton is installed by a deploy — ever. These are one-time operator steps.

**Xray.** The skeleton is a starting point for `config.json`, not a drop-in: it has no
REALITY key pair and no `.env` yet.

```bash
umask 077
install -o root -g root -m 0600 deploy/xray/config.skeleton.json \
    /usr/local/etc/xray/config.json
xray x25519                                   # generate the REALITY key pair
# replace every <PLACEHOLDER>, then:
xray run -test -config /usr/local/etc/xray/config.json
sudo systemctl restart xray
```

The public half goes into `.env` as `XRAY_REALITY_PUBLIC_KEY`; the private half stays in
`config.json` and nowhere else. The rest of the one-time Xray setup — the API inbound, the
tag the bot looks for, and the single-config drop-in that upstream's installer owns — is
in [deployment.md](deployment.md#one-time-server-preparation); the XHTTP fallback topology
is in [xray-xhttp-inbound.md](xray-xhttp-inbound.md).

**AmneziaWG.** Never over a config that already has peers.

```bash
umask 077
install -o root -g root -m 0600 deploy/awg/awg0.conf.example \
    /etc/amnezia/amneziawg/awg0.conf
# server key pair, without ever putting the private half on disk unencrypted:
priv="$(awg genkey)"
printf 'PrivateKey = %s\n' "$priv"                          # -> [Interface].PrivateKey
printf 'AWG_SERVER_PUBLIC_KEY=%s\n' "$(printf %s "$priv" | awg pubkey)"   # -> .env
unset priv
# replace every <PLACEHOLDER>, then:
awg-quick strip awg0 >/dev/null && sudo systemctl start awg-quick@awg0
```

The public half goes into `.env` as `AWG_SERVER_PUBLIC_KEY`. The example ships **zero**
`[Peer]` blocks on purpose: peers are runtime state, and one written by hand here would be
invisible to the bot yet still occupy an address from `AWG_NETWORK`.

## What was already covered, and is not this mechanism's job

`scripts/deploy.sh` has always hashed both files before and after Phase 2 to decide
whether a backend needs restarting, and stages a copy of each into the deploy backup
(`stage_path`). **Recovery** was therefore never the gap — a bad deploy could already be
rolled back. What was missing was bootstrap, review of structural changes before they
ship, and any signal at all that the host and the repo had diverged. That is what this
mechanism adds.

## See also

- [deployment.md](deployment.md) — one-time Xray setup, both deployment models, the
  Hysteria2 data plane and its installable config.
- [xray-xhttp-inbound.md](xray-xhttp-inbound.md) — the VLESS (HTTP) fallback topology the
  skeleton encodes.
- [warp.md](warp.md) — what sets `sendThrough` on the freedom outbound, and the
  split-tunnel routing that sits on top of AWG's own NAT.
- [operations.md](operations.md) — health checks, backup/restore, degraded recovery.
