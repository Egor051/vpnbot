# The TLS certificate and the bot's DNS

The domain's certificate is issued and renewed by **acme.sh** (DNS-01 through Cloudflare); laying
it out to the services that read it is the **bot's** job — a fixed root helper,
`/usr/local/sbin/vpn-bot-cert`, with the list of those readers written down in code. The
Cloudflare token is the bot's (one per bot), the DNS records the bot keeps pointing somewhere are
listed in its database. This is the base the protocol installs from Telegram, the change of the
server's IP and the change of the domain build on.

🇷🇺 Russian version: [certificate.ru.md](certificate.ru.md)

## Why

acme.sh keeps **one** install-cert per domain: the paths it copies to and **one** `reloadcmd`. When
the host was moved once, that reloadcmd named only a part of the readers, and the others went on
serving a certificate that was about to expire. So the readers are no longer configuration on the
host: they are **the registry** of `scripts/vpn-bot-cert` (reviewed, tested), and the reloadcmd
acme.sh calls after every renewal is the helper itself:

```bash
acme.sh --install-cert -d <domain> [--ecc] --reloadcmd "/usr/local/sbin/vpn-bot-cert deploy"
```

with **no** `--cert-file` / `--key-file` / `--fullchain-file`: acme.sh writes nothing outside its
own directory; `deploy` lays the pair out, atomically, reader by reader.

## The registry of readers

| Reader | Files (source, owner, mode) | After an update | Active when |
|---|---|---|---|
| `hysteria` | `/etc/hysteria/cert.pem` (fullchain, `hysteria:hysteria 0644`), `/etc/hysteria/key.pem` (key, `hysteria:hysteria 0600`) | `systemctl restart hysteria-server`, then it must be active | the unit exists, `/etc/hysteria` exists, no `/etc/vpn-bot/uninstalled/hysteria2` |
| `nginx` (the REALITY self-steal on 127.0.0.1:8443) | `/etc/vpn-bot/tls/fullchain.pem`, `/etc/vpn-bot/tls/privkey.pem` (`root:vpn-bot 0640`) | `nginx -t`, then `systemctl reload nginx` | the unit exists |
| `subscription` (`:2096`, reads at start-up) | the same two files | `systemctl try-restart vpn-bot-subscription` (a stopped endpoint is never started) | the unit exists |

`/etc/vpn-bot/tls` itself is `root:root 0755`. These are exactly the ownerships the tracked hook
`deploy/vpn-bot-acme-reload.sh` re-asserts (measured on the main server); a test keeps the two in
step. On a host without the `vpn-bot` group (the root-legacy model) the two TLS files fall back to
group `root`. The status also says what each reader is **configured** to read — hysteria's
`tls.cert`/`tls.key`, `SUBSCRIPTION_TLS_CERT`/`_KEY`, nginx's `ssl_certificate` lines — and flags a
reader that reads something the registry does not lay out. For nginx it reads `nginx.conf` and every
file its `include` directives name (globs, relative to `/etc/nginx`, recursively), plus `conf.d/` and
`sites-enabled/`; a file out of `/etc/nginx` and `/usr/share/nginx` (where Debian / Ubuntu link the
module snippets) is never read — it is named, and the reader is **unverifiable**: the wizard's verify
fails rather than guess what such a reader serves (the same for hysteria with an unreadable config).

## `vpn-bot-cert`

| Verb | What |
|---|---|
| `status [--json]` | Read-only. Every acme.sh domain (SAN, expiry, key type, whether the key matches, reloadcmd, the Cloudflare credential it renews with — a fingerprint only), the bot's domain (the one whose reloadcmd is `vpn-bot-cert deploy`) or the domain to adopt, every reader (installed or why not, its files: present, equal to acme.sh's, owner and mode, the expiry on the copy), the bot's token (fingerprint), the cron line, and the **problems** with a level. The bot's screen and the self-check show these. Text of the host's own configuration (a hand-made reloadcmd may carry a health-check URL, a header or an API key) is shown **redacted** — `utils/redact`'s patterns plus any header, `NAME=value`, `--flag value` or `curl -u` named like a credential; the screen redacts it once more. |
| `deploy [--domain D] [--all] [--dry-run] [--json]` | THE reloadcmd (below). |
| `issue --names a,b --zone ZONE` | DNS-01 (`dns_cf`) with the bot's token, Let's Encrypt, the domain's key type (`ec-256` for a new one), `--force`; then the install-cert above, then deploy. acme.sh is installed first when it is missing. The certificate's name cannot change here (that is a domain change). |
| `renew --force [--zone ZONE]` | `acme.sh --renew --force` of the bot's domain — to prove a renewal works end to end. With the bot's token, the domain's saved `CF_Token` / `CF_Zone_ID` are set to it first (acme.sh sources the domain's conf on a renewal), so cron renews with the same token afterwards. Then deploy. |
| `adopt [--domain D] [--dry-run]` | The migration (below): the domain is taken as it is, only its install-cert is rewritten. With several domains naming `vpn-bot-cert deploy`, `--domain` picks the one that stays the bot's. Every **other** domain that still reaches the readers is **released**: a reloadcmd naming the helper is emptied, and so is every `Le_Real*` path into the registry (acme.sh copies to those itself after a renewal, without calling the helper); its other targets and its own reloadcmd stay. `issue` releases them the same way, and an adopted host with such a writer added by hand can be adopted again to release it. |
| `act` | Every installed reader's check and action on the files it has — nothing is written. The wizard's rollback uses it. |

`deploy`, `issue`, `renew` and `adopt` take `--expect-pair SHA` (16 hex of status' `pair_sha`): the
pair the run was planned on. When acme.sh holds another one by the time the run starts (cron renewed
between the plan and the confirmation) the run is refused, nothing changed — the plan no longer
describes it. `deploy` compares the very pair it lays out; the others check after the wait for a
running acme.sh, under the lock, before acme.sh or the conf is touched. `issue` and `adopt` also take
`--expect-release DIR[,DIR…]` (`""` = none): the domain directories the plan releases — refused the
same way when that set differs (the wizard backed up exactly those). `issue` also takes
`--expect-keylength KL`: the key type the plan showed (`ec-256` for a new domain) — refused when
acme.sh's conf names another one by then (a hand edit of `Le_Keylength`).

Exit codes: 0 ok; 1 a reader failed and its group was rolled back; 2 usage; 3 refused (nothing to
adopt, no token, a bad pair, another domain, a pair other than the planned one); 5 cannot (a tool or
a file).

### `deploy`: atomic, group by group

1. **The source** is acme.sh's own pair of the domain: `fullchain.cer` + `<domain>.key` in
   `/root/.acme.sh/<domain>[_ecc]/`. The domain is the one acme.sh names (`Le_Domain` and the working
   directory it runs the reloadcmd from), else the adopted one. The pair is checked first with
   `openssl`: the key matches the certificate (the same public key), the certificate has not
   expired, its SAN covers the domain's names. A bad pair stops everything before a file is touched.
2. Readers that share a file are **one group** (`nginx` + `subscription`; `hysteria` alone).
3. Per group, a changed file is written **next to** its target (`.<name>.vpn-bot-cert-new`, the same
   directory, owner and mode set before the data), and the staged pair is checked again with
   `openssl` as the reader will read it. Then the old copy is kept (`.<name>.vpn-bot-cert-old`) and
   the new files are renamed over the old ones, back to back.
4. The group's actions. A failed action — or a unit that is not active after its restart — puts the
   **old files back for that group** and runs its actions again on them. The other groups keep the
   new pair. Exit 1.
5. A reader is acted on only when its files changed or `/var/lib/vpn-bot-cert/state.json` says its
   last action ran on another pair (`--all`: every installed reader). A wrong owner or mode alone is
   repaired without a restart.

A reader rolled back keeps the old (still valid) certificate; acme.sh will not renew again for 60
days. The status shows it at once (its copy differs from acme.sh's, red when it expires within 7
days), the daily self-check alerts, and «📦 Разложить заново» — or the next renewal — lays it out
again.

acme.sh takes no lock of its own, and its cron (`acme.sh --cron` in root's crontab) does not take
`vpn-bot-cert`'s. So while the helper's own acme.sh works on a domain (`issue` / `renew` /
`adopt`), that domain's `Le_NextRenewTime` is pushed an hour ahead — `acme.sh --cron` renews only
a domain that is due, so a cron run that starts meanwhile skips it — and put back afterwards
unless acme.sh wrote a new one. Then the helper waits (up to 5 minutes, then refuses) for an
acme.sh that was already running. Together: no moment in which cron and the helper change one
domain at once, and root's crontab is never rewritten. A cron renewal's own `deploy` waits for
the helper's lock.

When acme.sh runs the reloadcmd from inside `issue` / `renew` / `adopt` (the environment variable
`VPN_BOT_CERT_NESTED` names the lock the parent holds), `deploy` defers: the parent deploys right
after acme.sh, with its own report.

## The Cloudflare token: one per bot

One file, `/etc/vpn-bot/dns_failover/cloudflare_token` (0600, owned by the bot's user): the fallback
mode switches its names with it, the bot writes its DNS records with it, and `vpn-bot-cert` hands it
to acme.sh for DNS-01 — as `CF_Token` in acme.sh's environment, never on a command line. Entered in
the bot only («🔑 Токен Cloudflare», or the fallback mode's «🔑 DNS API token» — the same file, the
same check): the message is **deleted** the moment it is read. Its permissions: **«Zone · Zone ·
Read»** and **«Zone · DNS · Edit»** on the zone — the bot and `vpn-bot-cert` find the zone by its name
(`GET /zones?name=`, which needs Zone Read), so a token with DNS Edit alone is refused at step 2.
Before it is stored the bot checks it through the API (`services/dns.py`):

1. `GET /user/tokens/verify` — active;
2. the zone of the names typed for «🆕 Выпустить» (else the certificate's name, else `HYSTERIA2_SNI`) is visible to it — on a fresh host with neither, the names are typed first;
3. its records can be read;
4. a TXT record `_vpn-bot-token-check.<zone>` is created **and deleted** — the only proof of
   «Zone · DNS · Edit» Cloudflare gives a token that may not read its own permissions (DNS-01 does
   exactly that).

A token that fails a step is refused with the step's reason, and nothing is stored. The audit
carries its fingerprint (8 hex of sha256), never the value. The status shows whether acme.sh renews
with the same token (fingerprints), and «🔄 Проверить продление» switches acme.sh to it. The token
may be replaced while a renewal runs (and asking Cloudflare for the zone's id takes a request):
`vpn-bot-cert` reads the file again after that request and again after writing acme.sh's conf, and
writes the newer token in its turn — the conf ends with the token the file holds (a token that keeps
changing is refused after three turns instead of being written half way).

A certificate's names must all be in one zone (`CF_Zone_ID` is one zone): issue and renew refuse
names from another zone while the run is built, before a plan is shown. For `issue` the bot passes
the zone's **name**; `vpn-bot-cert` asks Cloudflare for its id with the
token (`GET /zones?name=`) and gives acme.sh `CF_Zone_ID` — a zone id left in acme.sh's
`account.conf` by another setup is never used. (The id is not passed along: 32 hex characters are
masked as a secret by every redaction, the wizard's stored parameters included.)

## The DNS records the bot owns

`dns_records` (schema v48) is the **one** list of the A records the bot keeps: name, purpose
(`fallback_origin` — the hub's upstream, always the main server's IPv4; `host` — a name of this
server), the address last written, Cloudflare's ids, and whether the record existed before the bot
took it over (`adopted`). Every write goes through `DnsService.write_a`: the one record of the name
holds the address, **`proxied=false`**, TTL 60 — whatever the record was (a proxied record would put
the VPN behind Cloudflare's HTTP proxy). Several A records, or (where the caller says so) a record
pointing at an address that is not expected, are refused and nothing is written. `delete_a` deletes
only a record the bot owns **and created**; an adopted one loses its ownership and stays at
Cloudflare; a name the bot does not own is refused.

The fallback mode's origin used to be kept only implicitly (the hub's upstream). It is a row now:
«🛟 Сделать hub» writes it through `upsert_a(purpose="fallback_origin")`, and the v48 migration
backfills the origin of an existing hub (`adopted`, the database never recorded whether the bot
created it). The failover set (`failover_names`) is **not** ownership: those names are the server's
own domain — the bot switches their address through the same `write_a`, but never created them and
never deletes them.

## «🔐 Сертификат и DNS» in the wizard

The screen (SUPERADMIN): the certificate (name, key, until, days left, SAN), the reloadcmd
(✅ `vpn-bot-cert deploy` / 🟡 the old hook / 🔴 anything else), acme.sh and its cron line, every
reader, the token (and whether acme.sh renews with it), the bot's DNS records and the problems.
Buttons:

| Button | Run of the `cert` mode |
|---|---|
| «🔁 Принять текущий сертификат» — only before adoption; «🔁 Принять <domain>», one per domain, when several acme.sh domains could be the bot's — also when several already name `vpn-bot-cert deploy` (the plan lists the ones released) | `action=adopt` (`names` = the domain picked) |
| «🆕 Выпустить / перевыпустить» → «▶️ Составить план» («✏️ Другие имена» to type them) | `action=issue`, `names`, `zone` |
| «🔄 Проверить продление» — once adopted | `action=renew` (`zone` with the bot's token) |
| «📦 Разложить заново» — when a reader's copy differs, did not take it, or has the wrong owner / mode | `action=deploy` |
| «🔑 Токен Cloudflare» | — (set / delete, TOTP) |

Each run is the wizard's contract ([wizard.md](wizard.md)): the plan with the diff (the acme.sh conf
lines before → after, the certificate before → after, each reader and what happens to it), TOTP,
«✅ Применить», then apply (refused when acme.sh's pair is no longer the one the plan was made on, or
another domain started or stopped reaching the readers since, or — for issue — the key type
changed — the helper gets them as `--expect-pair` / `--expect-release` / `--expect-keylength` too; a backup of the acme.sh domain directory — and of every
domain the run releases —, every reader's files and the state, then the helper) → verify (`vpn-bot-cert status`: the domain is the bot's, reloadcmd ours,
no file targets, the pair valid for 7+ days and covering the names — and, for adopt / issue with hysteria
installed, `HYSTERIA2_SNI` (its clients check that name; an issue plan whose names miss it is refused
at once) —, every installed reader holds the
pair, took it and is configured to read the registry's files — not a pair of its own; hysteria
whose config cannot be read is unverified too; for issue / renew a NEW pair) → rollback on a failure (the backup restored — a
domain the run created is moved aside so acme.sh does not renew it —, then `vpn-bot-cert act`). One
global lock (the wizard's), the audit log (`wizard_*`, `dns_*`). No step changes the host's network:
no dead-man. The mode runs `vpn-bot-cert` in a process group of its own with a budget of 2400 s
(the wait for a running acme.sh, acme.sh's own 900 s, installing acme.sh, every reader's action)
under the mode's apply timeout of 2700 s; on a timeout the whole group — `vpn-bot-cert` and the
acme.sh it runs — is killed before the rollback starts (the helper does the same to every command
of its own), so a rollback never restores files under a renewal still in flight.

An rsa and an ecc directory of the same name: the one acme.sh runs the helper from, else the one
that is the bot's, else the one set up by hand for the readers, else the one whose pair is usable
(ecc only when that leaves both). The plan names the directory it acts on.

## Migrating production: adoption

The main server's acme.sh domain was set up by hand: `Le_RealFullChainPath` /
`Le_RealKeyPath` = `/etc/vpn-bot/tls/…`, a reloadcmd that is empty, the tracked hook, or a part of the
readers. **Adoption** takes it as it is:

1. Deploy this release. Nothing changes for acme.sh: a renewal before step 2 behaves as today.
2. «🧙 Мастер настройки → 🔐 Сертификат и DNS» shows the domain as the one to adopt and the problem
   («reloadcmd …»). «🔁 Принять текущий сертификат» → the plan shows the diff:

   ```
   - Le_RealKeyPath='/etc/vpn-bot/tls/privkey.pem'
   + Le_RealKeyPath=''
   - Le_RealFullChainPath='/etc/vpn-bot/tls/fullchain.pem'
   + Le_RealFullChainPath=''
   - Le_ReloadCmd='<what it was>'
   + Le_ReloadCmd='/usr/local/sbin/vpn-bot-cert deploy'
   ```

   and, per reader, whether its copy already is acme.sh's pair (then nothing is restarted) or not
   (then it gets the pair and its action — exactly the reader the old reloadcmd left behind).
3. «✅ Применить»: `acme.sh --install-cert -d <domain> [--ecc] --reloadcmd "/usr/local/sbin/vpn-bot-cert deploy"`
   (acme.sh saves every `Le_Real*` empty and the one reloadcmd), then deploy. The certificate is
   **not** reissued. verify, else rollback.
4. Optionally set the bot's token («🔑 Токен Cloudflare») and run «🔄 Проверить продление»: acme.sh
   then renews with the bot's token. Let's Encrypt allows 5 certificates for the same names a week.

The tracked hook `/usr/local/sbin/acme-reload.sh` stays installed and unchanged for a host not
adopted yet (its renewals keep working as before); the status shows it as 🟡 until adoption.

Back to the old setup (a release rollback does not need it: an older release leaves
`/usr/local/sbin/vpn-bot-cert` in place, so the adopted reloadcmd keeps working):

```bash
sudo /root/.acme.sh/acme.sh --install-cert -d <domain> --ecc \
  --fullchain-file /etc/vpn-bot/tls/fullchain.pem --key-file /etc/vpn-bot/tls/privkey.pem \
  --reloadcmd /usr/local/sbin/acme-reload.sh
```

## The self-check

The `certs` item of «🩺 Самопроверка» is `vpn-bot-cert status --json`: one item `cert:<key>` per
problem (red / yellow), a green `certs` when there is none. Red: < 7 days left (also on a reader's
stale copy), a reloadcmd that is neither `vpn-bot-cert deploy` nor the old hook, no acme.sh `--cron`
line, another acme.sh domain copying over the registry's files, a pair whose key does not match.
Yellow: < 21 days, the old hook (adopt it), a reader's copy differs or has the wrong owner / mode, a
reader that reads files the registry does not lay out, acme.sh renewing with another token, no bot
token. Without the helper (a host not deployed yet) the old per-file check runs.

## Installing acme.sh

`issue` on a host without acme.sh installs release **3.1.1**: `acme.sh` and `dnsapi/dns_cf.sh` from
`raw.githubusercontent.com/acmesh-official/acme.sh/3.1.1/`, each checked against its pinned sha256
(another copy is refused), then `acme.sh --install` (cron included) and
`--set-default-ca --server letsencrypt`.

## Where it lives

| Path | What |
|---|---|
| `/usr/local/sbin/vpn-bot-cert` | the root helper (`OUT_OF_REPO_HELPERS`, required on main; `INSTALL_HELPERS`) |
| `/usr/local/sbin/vpn-bot-wizard-cert` | the wizard mode |
| `/var/lib/vpn-bot-cert/state.json` | which pair each reader last took (root 0644) |
| `/run/vpn-bot-cert.lock` | one change at a time (acme.sh's cron and the wizard wait for each other) |
| `/etc/vpn-bot/dns_failover/cloudflare_token` | the bot's token (0600, the bot's user) |
| `dns_records` | the DNS records the bot owns |

In the helper-nonroot model the bot reads the status through one sudoers line
(`deploy/sudoers.d/vpn-bot.example`): `/usr/local/sbin/vpn-bot-cert status --json` — nothing else.

Test seam: `VPN_BOT_CERT_SELFTEST=1` needs `--root` (every host path under it), runs only stubs from
`VPN_BOT_CERT_SELFTEST_BIN` (or an absolute path under `--root`) and keeps owners in a sidecar file
instead of `chown`; deploy.sh runs the suite as root on the production host.
