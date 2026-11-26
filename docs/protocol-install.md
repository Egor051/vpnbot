# Installing a protocol from the bot

After `scripts/install.sh` the bot runs with no protocol at all. Everything after that
happens in Telegram: **⚙️ Protocol modules** shows a protocol the bot can install and that is
not on the server as **📦 <protocol>** with **📦 Install**. The button starts a run of the
setup wizard's `protocol` mode ([wizard.md](wizard.md)): the plan with every change first,
then **✅ Apply** — TOTP before both — then apply → verify, and a rollback when either fails.

🇷🇺 Russian version: [protocol-install.ru.md](protocol-install.ru.md)

What the bot installs: **Xray (VLESS + REALITY) with the nginx self-steal**, **Hysteria2** and
**SOCKS5 (Dante)** — each following WARP when it is deployed — and it **reinstalls** a protocol
removed from the server (below). AmneziaWG and MTProto are not installed from the bot.

## Before you start

* **The bot's certificate.** The protocol serves the domain of the bot's certificate
  ([certificate.md](certificate.md)): «🔐 Сертификат и DNS» → issue or adopt it first. Without
  an adopted certificate with a valid key (7+ days left) the plan stops with that reason. The
  domain must point at this server (an A record).
* **`.env` as `install.sh` writes it.** The installer lays out the production layout:
  `XRAY_CONFIG_PATH=/usr/local/etc/xray/config.json`, `XRAY_SERVICE_NAME=xray`,
  `XRAY_PUBLIC_PORT=443`, `XRAY_INBOUND_TAG=vless-in`, `XRAY_XHTTP_INBOUND_TAG=vless-xhttp-reality`,
  `XRAY_STATS_SERVER=127.0.0.1:10085` (empty is fine; another value stops the plan — the
  generated config would not be the one `.env` describes).

## The root helper `vpn-bot-protocol-install`

`scripts/vpn-bot-protocol-install` (installed to `/usr/local/sbin` by `deploy.sh`,
`OUT_OF_REPO_HELPERS` policy `required`, role main; by `install.sh` on a fresh host,
`INSTALL_HELPERS`). It is never granted to the bot: the wizard's mode helper
`vpn-bot-wizard-protocol` runs it as root inside the run's own systemd unit.

| Verb | What |
|---|---|
| `manifest <proto> [--json]` | The manifest compiled into the helper (below). |
| `status [--json]` | Per protocol: `installed` / `partial` / `absent` / `uninstalled` (its marker), the state of its last journal. |
| `plan <proto> [--domain D] [--json]` | Read-only. Every change (`create`, `install`, `start`, `deploy`, `replace`, `set`, `remove`) and what is kept and why, the `.env` lines, what blocks, the release and its sha256, and the plan's own sha256. |
| `apply <proto> --expect-plan SHA [--domain D] [--json]` | The plan is computed again: another sha256 (the host changed) is refused, nothing changed. Then the backup, the steps, a journal; a failed step rolls every step back. |
| `verify <proto> [--domain D] [--json]` | Read-only: the protocol works (below). |
| `rollback <proto> [--json]` | The last apply's journal backwards. Refused once it is committed. |
| `commit <proto> [--json]` | The last apply is final: the wizard commits after a green verify. |

Exit codes: 0 ok · 2 usage · 3 refused (a blocking finding, a plan that changed, another
install or uninstall running, committed) · 4 verify failed · 5 cannot (a tool, a file, a
download) · 6 a step failed and the rollback succeeded · 7 a step failed and the rollback did
not fully succeed. Stdlib only; every command is an argv list; re-executed in PID 1's mount
namespace when run from another one. Log: `/var/log/vpn-bot-protocol-install.log` (redacted:
the REALITY private key never reaches it). One install at a time, and never next to an
uninstall (`/run/vpn-bot-protocol-install.lock` and the uninstall's lock).

### The manifest — symmetric to the uninstall

What the helper **owns** for a protocol is exactly what
[`vpn-bot-protocol-uninstall`](protocol-uninstall.md) removes for it, and nothing else:
`tests/test_protocol_install_helper.py` compares the two helpers' `manifest <proto>` (units,
unit files, paths, packages, users, the `<PROTO>_ENABLED` flag) and runs install → the real
uninstall → install again on one fake host. What a protocol needs but does not own is
**shared**: put in place when it is missing, never removed by an uninstall (its deny-list
protects every shared path — the same test checks it).

| Protocol | Owned (the uninstall removes it) | Shared (never removed) | `.env` |
|---|---|---|---|
| Xray | `xray.service` (enabled, started), `xray@.service`, `/etc/systemd/system/xray{,@}.service{,.d}`, `/usr/local/bin/xray`, `/usr/local/share/xray`, `/usr/local/etc/xray`, `/var/log/xray` | user `nobody`; nginx (the package, `/etc/nginx/conf.d/selfsteal.conf`, `/var/www/selfsteal`); the certificate's registry `/etc/vpn-bot/tls`; `/etc/logrotate.d/xray` (deploy.sh) | `XRAY_PUBLIC_HOST`, `XRAY_SNI`, `XRAY_REALITY_PUBLIC_KEY`, `XRAY_SHORT_ID`, `XRAY_INBOUND_TAG`, `XRAY_STATS_SERVER`, `XRAY_XHTTP_ENABLED`, `XRAY_XHTTP_INBOUND_TAG` — settings, inert after an uninstall (the marker), so it keeps them |
| Hysteria2 | `hysteria-server.service` (enabled; started by its certificate), `hysteria-server@.service`, `vpnbot-hy2-auth.service` (enabled, started), `vpnbot-hy2-warp-mark.service` and `/usr/local/sbin/vpnbot-hy2-warp-mark` (only where WARP is deployed), their unit files, `/usr/local/bin/hysteria`, `/etc/hysteria`; user `hysteria` (uid 992 — the `HYUID` `vpnbot-hy2-warp-mark` tags; another uid only without WARP) | nginx and the decoy site (the masquerade proxies to `https://127.0.0.1:8443`); `/etc/vpn-bot/tls`; user `vpn-bot` (`vpnbot-hy2-auth` runs as it; created like `deploy/create-vpn-bot-user.sh` when missing, then `vpn-bot-db-perms` hands `vpn.db` to it) | `HYSTERIA2_ENABLED=true` (the uninstall's `=false`); `HYSTERIA2_HOST`, `HYSTERIA2_SNI`, `HYSTERIA2_STATS_SECRET` (new, 48 hex) |
| SOCKS5 | `danted.service` (the package's; enabled, restarted), `/etc/systemd/system/danted.service.d` (`vpn-bot-warp.conf` = `deploy/danted-warp.conf`, the bytes of deploy.sh's `gate=SOCKS5` entry), the package `dante-server` | `/etc/danted.conf` — the package's conffile, written from `deploy/danted.conf.example` (port `SOCKS5_PORT`, `external:` the WARP tunnel address when `WARP_PROXY_EGRESS` is on, else the WAN device of the default route); `apt-get purge` removes it | `SOCKS5_ENABLED=true` (the uninstall's `=false`); `SOCKS5_HOST` |

The uninstall marker `/etc/vpn-bot/uninstalled/<proto>` that the uninstall writes last is
the one the install removes **last** (a reinstall).

### Apply, step by step

Each step writes its journal entry (`/var/lib/vpn-bot-protocol-install/<proto>.journal.json`,
root 0600) **before** it acts, so a failure — or a kill — half way is undone too. Every
existing path a step may change, `.env` included, is in the backup first:
`/var/backups/vpn-bot/install/<proto>-<UTC ts>.tar.gz` (root 0600, directory 0700), checked by
reading it back. What exists is never replaced: an installed `xray`, a `config.json` with its
clients, an operator's nginx vhost — the plan says `keep`.

| Step | What | Rolled back by |
|---|---|---|
| `nginx_pkg` | `apt-get install --no-install-recommends nginx` with `/usr/sbin/policy-rc.d` (exit 101) in place, so nginx does not start with its default site on `:80`; that default site (`sites-enabled/default`) is disabled. Only when nginx is not installed | purging exactly the packages this run installed; the link back |
| `nginx_start` | `systemctl enable --now nginx` — with no vhost of ours yet, it reads no certificate | stop / disable, as they were |
| `cert` | `vpn-bot-cert deploy`: nginx is a reader of the registry once its unit exists ([certificate.md](certificate.md#the-registry-of-readers)); the pair is laid out to `/etc/vpn-bot/tls` and nginx is reloaded | nothing — the registry's pair is shared (the subscription endpoint reads it too) |
| `nginx_site` | the decoy site `deploy/site/default` → `/var/www/selfsteal` (neutral, no brand), `deploy/nginx/selfsteal.conf` → `/etc/nginx/conf.d/selfsteal.conf` (`listen 127.0.0.1:8443 ssl http2`, `ssl_protocols TLSv1.3`, `server_name` the domain, the registry's pair), `nginx -t`, reload. An nginx that already serves `127.0.0.1:8443` from its own vhost keeps it (a warning) | the files removed, nginx reloaded |
| `xray_bin` | the official GitHub release of the **pinned** version (`XRAY_VERSION`, `Xray-linux-64.zip` / `Xray-linux-arm64-v8a.zip`): its sha256 must be the one pinned in the helper **and** the `SHA2-256` line of the release's own `.dgst`. `xray` → `/usr/local/bin` (0755), `geoip.dat` / `geosite.dat` → `/usr/local/share/xray` | removed |
| `xray_units` | `deploy/xray/xray.service`, `xray@.service` and the single-config drop-ins `10-donot_touch_single_conf.conf` — the upstream installer's units, byte for byte; `daemon-reload` | removed |
| `xray_logs` | `/var/log/xray` (`nobody:nogroup 0700`), `access.log`, `error.log` (0600) | removed |
| `xray_config` | `/usr/local/etc/xray/config.json`, `nobody:vpn-bot 0640` (`nobody:nogroup` without the `vpn-bot` group — the root model); generated from `deploy/xray/config.skeleton.json`: a fresh x25519 pair (`xray x25519`), one shortId, `serverNames` = the domain, REALITY `target` 127.0.0.1:8443, the XHTTP fallback inbound on 127.0.0.1:8001 (`XRAY_XHTTP_PATH`), the api inbound on 127.0.0.1:10085, `sendThrough` on the freedom outbound when WARP proxy egress is on (the bot's own rule). Checked with `xray run -test` **before** it is put in place | removed |
| `env` | the `XRAY_*` above: each key's last assignment replaced or the line appended — every other line byte for byte, owner and mode kept, written atomically | `.env` from the backup |
| `xray_start` | `systemctl enable xray`, `restart`, active | stop / disable |
| `marker` | `/etc/vpn-bot/uninstalled/<proto>` removed — LAST | the marker back |

The generated config is serialized exactly as the bot writes it
(`adapters/xray_config.py`), so the bot's reconcile changes nothing: the test runs the real
startup reconcile, the shortId check, the WARP re-assertion, the deploy's drift check against
the skeleton (`deploy/backend-config-sync.py check`) and `Settings.validate_xray_ready()` on
what the helper wrote, and compares the bytes.

### Verify

Read-only, every check an item of the run's report:

* `xray run -test -config /usr/local/etc/xray/config.json`;
* `xray.service` and `nginx.service` active;
* listeners (`ss -Hltn`): `0.0.0.0:443` (vless-in), `127.0.0.1:10085` (api), `127.0.0.1:8001`
  (XHTTP), `127.0.0.1:8443` (the self-steal);
* `serverNames` holds the domain, `XRAY_SHORT_ID` is a shortId of vless-in, and
  `XRAY_REALITY_PUBLIC_KEY` is the public half of the REALITY key (`xray x25519 -i`);
* `openssl s_client -connect 127.0.0.1:8443 -servername <domain> -alpn h2 -verify_hostname
  <domain>`: the domain's certificate verifies, TLS 1.3, ALPN h2;
* `curl --http2 --resolve <domain>:8443:127.0.0.1 https://<domain>:8443/` → 200.


### Hysteria2 and SOCKS5, step by step

**Hysteria2** — `nginx_pkg`, `nginx_start`, `cert`, `nginx_site` (the self-steal, as for Xray: the
masquerade proxies to it), then:

| Step | What | Rolled back by |
|---|---|---|
| `users` | `vpn-bot` when missing (system user and group, `/var/lib/vpn-bot`, nologin; `vpn-bot-db-perms` hands `vpn.db` to it — `vpnbot-hy2-auth` reads it); `hysteria` with uid 992, no home, nologin | `userdel` / `groupdel` of what this run created; `vpn.db`'s owner back |
| `hy2_bin` | the official release of the **pinned** version (`HY2_VERSION`, `hysteria-linux-amd64` / `-arm64`): sha256 pinned in the helper **and** equal to the release's `hashes.txt` line | removed |
| `hy2_units` | `deploy/hysteria/hysteria-server{,@}.service`, `deploy/vpnbot-hy2-auth.service` (byte for byte what deploy.sh installs while Hysteria2 is on); where WARP is deployed also `deploy/vpnbot-hy2-warp-mark.service` and `scripts/vpnbot-hy2-warp-mark`; `daemon-reload` | removed |
| `hy2_config` | `/etc/hysteria/config.yaml` = `deploy/hysteria/config.yaml` with a new `trafficStats.secret` (the one substitution `deploy/hysteria/install-config.sh` makes), `hysteria:hysteria 0600`. `.env` must keep the file's values (`HYSTERIA2_PORT=443`, auth `127.0.0.1:8444`, stats `127.0.0.1:9999`): the deploy's drift check compares every key of that file | removed |
| `env` | `HYSTERIA2_ENABLED=true`, `HYSTERIA2_HOST`, `HYSTERIA2_SNI`, `HYSTERIA2_STATS_SECRET` | `.env` from the backup |
| `marker` | `/etc/vpn-bot/uninstalled/hysteria2` removed — **before** the certificate: `vpn-bot-cert` lays nothing out to a reader whose uninstall marker is there | the marker back |
| `hy2_start` | `vpnbot-hy2-auth` enabled and started, `hysteria-server` enabled | stop / disable |
| `hy2_cert` | `vpn-bot-cert deploy`: the pair to `/etc/hysteria/{cert,key}.pem` (the `hysteria` reader), whose action restarts `hysteria-server` — it must be active then | the files go with `/etc/hysteria`; the unit stopped |
| `warp` | where WARP is deployed: `vpnbot-hy2-warp-mark` enabled and started (its `apply`: hysteria's packets, by uid, follow WARP's policy table) | stop / disable (its `ExecStop` clears the marks) |

Verify: both units active, UDP `:443`, `127.0.0.1:8444` and `127.0.0.1:9999` listening,
`vpnbot-hy2-auth` `/healthz` 200 (it can read `vpn.db`), `vpn-bot-cert status` says the
`hysteria` reader holds the bot's pair, the mark unit active where WARP is deployed, and the
self-steal checks.

**SOCKS5** — `socks_pkg` (`apt-get install dante-server`, `policy-rc.d` holding it; purged on a
rollback), `socks_config` (`/etc/danted.conf` from `deploy/danted.conf.example`, checked with
`danted -V`; an operator's own file is kept), `socks_dropin`, `env`, `marker`, `socks_start`
(`enable`, `restart`, active). Verify: `danted -V`, the unit active, `SOCKS5_PORT` listening.

### WARP

The protocols **follow** WARP; they never set it up. WARP is deployed when its AmneziaWG config
is on the host (`WARP_CONFIG_PATH`, put there by `vpn-bot-warp-install` from the bot's WARP panel)
and is owned by its helpers (`vpn-bot-warp-install` / `-iface` / `-routes` / `-split`,
`warp-failsafe`) — none of them is re-implemented or re-run here. What an install does when it
finds WARP: Xray's freedom outbound gets `sendThrough` = the tunnel address when
`WARP_PROXY_EGRESS` is on (the bot's rule); danted's `external:` is that address, and its
drop-in orders it after `awg-quick@out-warp` / `warp-routes`; Hysteria2 gets
`vpnbot-hy2-warp-mark` (the existing tracked helper), enabled and started, and its user must
have uid 992 (the plan refuses otherwise).

### Reinstall

A protocol removed by `vpn-bot-protocol-uninstall` (its marker) shows **♻️ Переустановить** in
«⚙️ Модули протоколов» instead of the locked «Включить»; pressing «Включить» on it explains and
offers the same. It is the same `protocol` run: the plan shows `marker: remove`, the marker is
removed as the last step of the install (for Hysteria2 before its certificate, see above), and
after the report the bot switches the module back on (`enable_protocol` — which converges the
firewall too).

## The wizard mode `protocol`

`scripts/wizard/vpn-bot-wizard-protocol`, parameters `proto` (`xray`, `hysteria2`, `socks5`) and `domain` (one DNS
name the certificate covers; empty = the certificate's own). Started from «⚙️ Модули
протоколов», not from the wizard's menu. Dangerous: TOTP before the plan and before apply.

* **plan** — the helper's plan as text: the changes, what is kept, the `.env` lines (old →
  new; the generated keys as `<generated>`), the warnings and what blocks, the release, the
  backup. Below it the steps, all ⚪. A plan with nothing to do ends the run (`succeeded`).
* **apply** — the helper's step events become the run's progress (⚪ 🔄 ✅ ❌ ⏭,
  `bot/progress.py`), in one message.
* **verify** — the checks above as green/red items; green: the install is committed and the
  bot is restarted (`systemctl try-restart --no-block vpn-bot`) — it reads `XRAY_*` at start.
  The run lives in its own unit; the new process of the bot reports it.
* **rollback** — the helper's journal backwards (a verify that failed leaves an applied
  journal: everything it installed goes again).

No step changes the host's network configuration: the firewall is
[`vpn-bot-ufw-apply`'s](host-state.md#the-firewall-ufw). Once a run succeeded, the bot runs
`vpn-bot-ufw-apply apply` before the report (the protocol is in the module set again — the
same as after an uninstall) and says so in the report.

## What the bot shows

* «⚙️ Модули протоколов»: a protocol the helper installs whose probes
  (`/usr/local/bin/xray`, `/etc/systemd/system/xray.service`, `/usr/local/etc/xray/config.json`
  — the helper's `status` and `services/protocol_install.py` read the same list, a test keeps
  them equal) are not all there and that has no uninstall marker: **📦 <protocol>** with
  **📦 Установить**.
* The run's message: the plan, then the steps with their state, then the report (the verify
  items, the result, the UFW line), «📄 Лог».

## Files of this feature

| File | |
|---|---|
| `scripts/vpn-bot-protocol-install` | the root helper |
| `scripts/wizard/vpn-bot-wizard-protocol` | the wizard mode |
| `deploy/xray/xray.service`, `xray@.service`, `xray{,@}.service.d/10-donot_touch_single_conf.conf` | the upstream units |
| `deploy/xray/config.skeleton.json` | the config's shape (also the deploy's drift check) |
| `deploy/nginx/selfsteal.conf` | the self-steal vhost template (`@DOMAIN@`, `@SITE_ROOT@`) |
| `deploy/site/default/` | the decoy site |
| `services/protocol_install.py`, `bot/handlers/admin_modules.py` | the bot's side |
