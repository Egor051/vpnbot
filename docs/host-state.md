# Host state as code

[Русская версия](host-state.ru.md)

The checkout under `/opt/vpn-service` is not the whole deployment. A working host also carries
files outside it: kernel tuning, a log-rotation rule, an ssh port override, a certificate
fan-out hook, a scheduled reboot. When those live only on the host, a rebuilt or migrated server
has nothing to restore them from, and nobody notices a hand edit that drifted.

`scripts/deploy.sh` therefore owns a declared set of host files. It installs them, repairs them
when they drift, removes the ones that were retired — and in Phase 1 it reports every other file
in the scanned host directories that nothing accounts for.

## The five classes

Every file on a host is in exactly one of these:

| Class | Source of truth | Who writes it on the host |
|---|---|---|
| **repo-managed** | a byte-exact copy in the repo | `deploy.sh` (or, for `deploy/*.service` other than the bot, the operator after the drift gate) |
| **template + host values** | the repo holds the *shape*, the host the values | the operator / the bot, checked by a deploy gate |
| **backup-only** | not in the repo by design; listed in `deploy/host/known-unmanaged.list` | a third-party installer, the provider, or the operator — and the offsite backup |
| **retired** | a `class absent` entry: the file must *not* exist | `deploy.sh` removes it |
| **package default** | the package itself: a `class pristine` entry names `dpkg:<package>` or `ucf:<template>` | `deploy.sh`, and only back to the package default — [Package defaults](#package-defaults-class-pristine) |

`known-unmanaged.list` tags each backup-only entry with who writes it: `installer` (Xray-install,
get.hy2.sh, `setup-nonroot-helper-mode.sh`…), `provider` (the VPS image), `backup-only` (ours,
kept only by the offsite system bundle) or `deployment-local` (unique to this deployment by
design and cannot live in the repo).

## Every host file

The **Offsite backup** column names what carries the file off the box: an entry of
`DEFAULT_OFFSITE_SYSTEM_PATHS` (`config/settings.py`) for the system bundle, the *recovery
bundle*, or `—` for nothing (reinstalled by its installer, or retired). Config `*.bak*` copies
next to a listed file are left out on purpose — see
[What the system bundle leaves out](operations.md#what-the-system-bundle-leaves-out). The
bundle also carries state that is not a deployed file and so is not listed here: the decoy site
(`/var/www`), `/root/.acme.sh`, `/etc/sudoers.d`, `/etc/passwd` and `/etc/group` among others
([the full list](operations.md#what-the-system-bundle-covers)).

### main

| Path | Class | Installed by | Offsite backup | Notes |
|---|---|---|---|---|
| `/etc/logrotate.d/xray` | repo-managed (`logrotate`) | deploy.sh | `/etc/logrotate.d` | `copytruncate`: xray cannot reopen its logs, and writes them `O_APPEND` |
| `/etc/systemd/system/even-day-reboot.service` | repo-managed (`unit`) | deploy.sh | `/etc/systemd` | reboots the host — the deploy **never** starts it |
| `/etc/systemd/system/even-day-reboot.timer` | repo-managed (`unit`) | deploy.sh | `/etc/systemd` | days 5,10,…,30 at 01:00 UTC (04:00 MSK); `enable --now` only if it was enabled or did not exist |
| `/etc/sysctl.d/90-no-mptcp.conf` | repo-managed (`sysctl`) | deploy.sh | `/etc/sysctl.d` | MPTCP off until the kernel carries the fix for CVE-2026-98432; byte-identical to the host copy, so the reason lives here, not in the file |
| `/etc/sysctl.d/99-bbr.conf` | repo-managed (`sysctl`) | deploy.sh | `/etc/sysctl.d` | `fq` + BBR |
| `/etc/sysctl.d/99-network-buffers.conf` | repo-managed (`sysctl`) | deploy.sh | `/etc/sysctl.d` | socket buffers, backlog, dirty ratios |
| `/etc/sysctl.d/99-swap-tuning.conf` | repo-managed (`sysctl`) | deploy.sh | `/etc/sysctl.d` | |
| `/etc/sysctl.d/99-vpn-forwarding.conf` | repo-managed (`sysctl`) | deploy.sh | `/etc/sysctl.d` | the one `net.ipv4.ip_forward=1` |
| `/etc/systemd/journald.conf.d/10-vpn-bot.conf` | repo-managed (`journald`) | deploy.sh | `/etc/systemd` | `SystemMaxUse=500M`; replaces a hand edit of `journald.conf` |
| `/etc/systemd/journald.conf` | package default (`pristine`, `dpkg:systemd`) | the `systemd` package; deploy.sh puts the package default back | `/etc/systemd` | its old hand edit (`SystemMaxUse=500M`) only duplicates the drop-in: Phase 2 restores the stock file once Phase 1 has proven nothing effective changes, then restarts journald |
| `/etc/systemd/resolved.conf.d/10-vpn-bot.conf` | repo-managed (`resolved`) | deploy.sh | `/etc/systemd` | `DNS=1.1.1.1 8.8.8.8`, `FallbackDNS=1.0.0.1 8.8.4.4`; replaces a hand edit of `resolved.conf` — [DNS on the main server](#dns-on-the-main-server) |
| `/etc/systemd/resolved.conf` | package default (`pristine`, `dpkg:systemd-resolved`) | systemd-resolved's package; deploy.sh puts the package default back | `/etc/systemd` | its hand edit (`DNS=`, `FallbackDNS=`) duplicates the drop-in: restored like `journald.conf`, then reloaded as class `resolved` |
| `/etc/resolv.conf` | repo-managed (`plain`) | deploy.sh, from `deploy/host/dns/resolv.conf` | — (in the repo) | a plain file, not resolved's stub symlink; byte-identical to the host's; invariant `path-regular` |
| `/etc/systemd/networkd.conf.d/10-keep-foreign-rules.conf` | repo-managed (`networkd`) | deploy.sh | `/etc/systemd` | keeps networkd from flushing WARP's `ip rule`s; effective at networkd's next start |
| `/usr/local/sbin/acme-reload.sh` | repo-managed (`hook`, `when=/etc/vpn-bot/tls/fullchain.pem`) | deploy.sh, from `deploy/vpn-bot-acme-reload.sh` | `/usr/local/sbin` | acme.sh's `Le_ReloadCmd`; only where there is renewal material; [subscription.md](subscription.md#tls-termination) |
| `/etc/ssh/sshd_config.d/00-root-key-only.conf` | repo-managed (`ssh`) | deploy.sh | `/etc/ssh` | key-only root login; see [ALLOW_SSH_CHANGE](#allow_ssh_change-and-the-lockout-risk) |
| `/etc/systemd/system/ssh.socket.d/override.conf` | template + host values (`ssh`, `render=ssh-port`) | deploy.sh, rendered from `SSH_PORT` | `/etc/systemd` | `ListenStream` on `SSH_PORT` (IPv4 + IPv6); during a migration on both ports — [The SSH port](#the-ssh-port). For 54321 byte-identical to the old fixed file |
| `/etc/ssh/sshd_config.d/00-vpn-bot-port.conf` | template + host values (`ssh`, `render=ssh-port`) | deploy.sh, rendered from `SSH_PORT` | `/etc/ssh` | `Port SSH_PORT` (the fallback path: ssh.service without the socket) + `LogLevel VERBOSE` (the journal proof) |
| `/etc/systemd/system/vpn-bot-ssh-port.service` | repo-managed (`unit`) | deploy.sh | `/etc/systemd` | oneshot `vpn-bot-ssh-port advance`: phase 2 of a proven migration; pulled in by `vpn-bot-host-check.service` (`Wants=`), never enabled on its own |
| `/var/lib/vpn-bot/ssh-migration.json` | state | `vpn-bot-ssh-port` | — | the migration (`from`, `to`, `phase`, `since`, proof); atomic, `root` `0644`; read by the bot |
| `/etc/systemd/system/vpn-bot-ufw-deadman.service` | repo-managed (`unit`) | deploy.sh | `/etc/systemd` | oneshot `vpn-bot-ufw-apply deadman-check`: a UFW policy change nobody proved is kept or reverted after a reboot; pulled in by `vpn-bot-host-check.service` (`Wants=`), never enabled on its own — [The firewall (UFW)](#the-firewall-ufw) |
| `/etc/ufw/user.rules`, `/etc/ufw/user6.rules`, `/etc/default/ufw` | computed (`vpn-bot-ufw-apply`) | the deploy and the bot through `vpn-bot-ufw-apply`; never `ufw allow` by hand | `/etc/ufw/user.rules`, `/etc/ufw/user6.rules`, `/etc/default/ufw` | the set: module table + ssh + `deploy/host/ufw/extra.list`; policies from `deploy/host/ufw/policy` (routed untouched) |
| `/var/lib/vpn-bot/ufw-deadman.json` | state | `vpn-bot-ufw-apply` | — | a policy change under its dead-man (`pending`, `confirmed`, `reverted`); atomic, `root` `0644`; read by the bot |
| `/etc/ssh/sshd_config` | package default (`pristine`, `ucf:/usr/share/openssh/sshd_config`) | openssh-server (ucf); deploy.sh puts the template back | `/etc/ssh` | the provider image's active `PasswordAuthentication yes` / `PermitRootLogin yes` after the `Include` are a LATENT that stops Phase 1: restored once `sshd -T` is proven byte-for-byte the same — no `ALLOW_SSH_CHANGE` |
| `/etc/cloud/cloud-init.disabled` | repo-managed (`plain`) | deploy.sh, from `deploy/host/cloud/cloud-init.disabled` | — (in the repo) | empty marker: cloud-init stays off (it rewrote sshd and sudoers on a reboot) |
| `/etc/systemd/system/vpn-bot-host-check.service` | repo-managed (`unit`) | deploy.sh | `/etc/systemd` | oneshot: the host invariants check — [Effective state](#effective-state) |
| `/etc/systemd/system/vpn-bot-host-check.timer` | repo-managed (`unit`) | deploy.sh | `/etc/systemd` | 5 min after boot, then daily; `enable --now` like any registry timer |
| `/var/lib/vpn-bot-host-check/last.json` | state | `vpn-bot-host-check` | — | the last verdict (atomic, `root` `0644`); read by the bot |
| `/etc/systemd/system/danted.service.d/vpn-bot-warp.conf` | repo-managed (`unit`) | deploy.sh, from `deploy/danted-warp.conf` | `/etc/systemd` | ordering after the WARP interface |
| `/etc/systemd/system/mtproxy.service.d/vpn-bot-managed.conf` | repo-managed (`unit`, `gate=MTPROTO`) | deploy.sh, from `deploy/mtproxy-vpn-bot-managed.conf` | `/etc/systemd` | only while `MTPROTO_ENABLED=true`; a byte-identical old name `vpnbot-managed.conf` is renamed. With MTProxy off, a leftover drop-in is reported as an orphan |
| `/etc/systemd/system/vpn-bot.service` | repo-managed | deploy.sh, verbatim | `/etc/systemd` | the privilege-model gates apply |
| `/etc/systemd/system/<deploy/*.service, *.timer>` | repo-managed | the operator, by hand | `/etc/systemd` | Phase 1's unit-drift gate prints the install commands |
| `/usr/local/sbin/vpn-bot-warp-*`, `warp-failsafe`, `vpnbot-hy2-warp-mark`, `vpn-bot-db-perms`, `vpn-bot-host-check`, `vpn-bot-ssh-port`, `vpn-bot-ufw-apply` | repo-managed (`OUT_OF_REPO_HELPERS`) | deploy.sh | `/usr/local/sbin` | from `scripts/` |
| `/usr/local/sbin/vpn-bot-{xray,awg,mtproxy}-apply`, `vpn-bot-socks5-user` | backup-only (`installer`) | `deploy/setup-nonroot-helper-mode.sh` | `/usr/local/sbin` | source `deploy/helpers/` |
| `/usr/local/etc/xray/config.json` | template + host values | the bot (clients) / operator | recovery bundle | structure checked by `deploy/backend-config-sync.py` |
| `/etc/amnezia/amneziawg/awg0.conf` | template + host values | the bot (peers) / operator | recovery bundle; `/etc/amnezia` | same gate |
| `/etc/hysteria/config.yaml` | template + host values | `deploy/hysteria/install-config.sh` | recovery bundle (Hysteria2 on); `/etc/hysteria` | same gate |
| `/opt/vpn-service/.env` | template + host values | the operator | recovery bundle | `.env.example` |
| `/etc/vpn-bot/tls/*` | host values | acme.sh; modes by the hook | `/etc/vpn-bot` | dir `root:root 0755`, `fullchain.pem`/`privkey.pem` `root:vpn-bot 0640` |
| `/etc/systemd/system/xray*.service` (+ `.d/`), `/usr/local/bin/xray` | backup-only (`installer`) | Xray-install | units: `/etc/systemd`; binary: — (reinstalled) | |
| `/etc/systemd/system/hysteria-server*.service` (+ `.d/`), `/usr/local/bin/hysteria` | backup-only (`installer`) | get.hy2.sh | units: `/etc/systemd`; binary: — (reinstalled) | |
| `/usr/local/bin/wgcf`, `/usr/local/bin/qr` | backup-only (`installer`) | their own installers | — (reinstalled) | |
| `/etc/nginx/conf.d/*.conf` | backup-only | the operator | `/etc/nginx/conf.d` | decoy / self-steal vhost with the host's domain; a repo template is separate work |
| `/etc/netplan/*` | backup-only (`provider`) | the VPS image | `/etc/netplan` | not in the scanned set; listed for completeness |
| `/var/spool/cron/crontabs/root` | backup-only | acme.sh (`--cron` line) | `/var/spool/cron/crontabs` | |
| `/usr/local/sbin/site-freshen.py` | backup-only (`deployment-local`) | the operator | `/usr/local/sbin` | the decoy rewriter — by [design](hysteria.md#keeping-the-decoy-in-step-vpn-bot-decoy-freshensh) never in the repo, so the offsite system bundle is its only off-box copy |
| `/etc/sysctl.d/99-amneziawg.conf` | retired | — | — | a duplicate `ip_forward=1` |
| `/etc/systemd/system/warp-sample.timer` | retired | — | — | `disable --now`, then removed |
| `/etc/systemd/system/warp-sample.service` | retired | — | — | `disable --now`, then removed |
| `/usr/local/sbin/site-freshen.sh` | retired | — | — | its job is `deploy/vpn-bot-decoy-freshen.sh` now |
| `/etc/ssh/sshd_config.d/50-cloud-init.conf` | retired | — | — | cloud-init's `PasswordAuthentication yes`; removed by hand first, the entry keeps it from coming back (a removal reloads ssh) |
| `/etc/sudoers.d/90-cloud-init-users` | retired | — | — | cloud-init's `NOPASSWD:ALL` grant; removed by hand first |

### relay

The relay runs no bot, so it sends no offsite backup: its files come back from the repo, and
`90-vpn-relay.conf` is rendered again from the relay's `.env`.

| Path | Class | Installed by | Notes |
|---|---|---|---|
| `/etc/ssh/sshd_config.d/00-vpnrelay-keyonly.conf` | repo-managed (`ssh`) | deploy.sh | key-only login |
| `/etc/ssh/sshd_config` | package default (`pristine`, `ucf:/usr/share/openssh/sshd_config`) | openssh-server (ucf); deploy.sh puts the template back | as on main |
| `/usr/local/sbin/vpn-relay-apply` | repo-managed (`OUT_OF_REPO_HELPERS`) | deploy.sh | |
| `/usr/local/sbin/vpn-bot-host-check` | repo-managed (`OUT_OF_REPO_HELPERS`) | deploy.sh | the host invariants check |
| `/usr/local/sbin/vpn-bot-ssh-port` | repo-managed (`OUT_OF_REPO_HELPERS`) | deploy.sh | the SSH port migration — [The SSH port](#the-ssh-port) |
| `/etc/systemd/system/ssh.socket.d/override.conf`, `/etc/ssh/sshd_config.d/00-vpn-bot-port.conf` | template + host values (`ssh`, `render=ssh-port`) | deploy.sh, rendered from `SSH_PORT` | as on main; the relay had no override (the package's 22) — its first deploy starts the migration 22 → 54321 |
| `/etc/systemd/system/vpn-bot-ssh-port.service` | repo-managed (`unit`) | deploy.sh | as on main |
| `/var/lib/vpn-bot/ssh-migration.json` | state | `vpn-bot-ssh-port` | as on main (no bot reads it here) |
| `/etc/systemd/system/vpn-bot-host-check.service`, `.timer` | repo-managed (`unit`) | deploy.sh | as on main; the relay's verdict stays in its journal — [Between deploys](#between-deploys) |
| `/etc/cloud/cloud-init.disabled` | repo-managed (`plain`) | deploy.sh | cloud-init stays off |
| `/etc/ssh/sshd_config.d/50-cloud-init.conf`, `/etc/sudoers.d/90-cloud-init-users` | retired | — | cloud-init's password login and `NOPASSWD:ALL` grant |
| `/etc/systemd/system/vpn-relay.service` | repo-managed | deploy.sh, verbatim | |
| `/etc/sysctl.d/90-vpn-relay.conf` | template + host values | `vpn-relay-apply apply`, from the relay's `.env` | |

## How the deploy handles them

The registry is `MANAGED_HOST_FILES` in `scripts/deploy.sh`, one entry per file:

```text
"<src in checkout>|<dst>|<mode>|<owner:group>|<class>|<role>[|<opts>]"
```

`role` is `main` or `relay`: a host only ever sees the entries of its own role. For class
`pristine`, `src` is not a file of the checkout but where the package default comes from:
`dpkg:<package>` or `ucf:<template>`. `opts` is
optional: `gate=<PROTO>` makes the entry exist only while `<PROTO>_ENABLED` is on in `.env`,
`when=<path>` only on a host where `<path>` exists, and `legacy=<path>` names an older name of the
same file. A closed gate means the entry is neither installed nor checked. `render=ssh-port` makes
`src` a template: every line with `@SSH_PORT@` is written once per port the SSH port plan decided
([The SSH port](#the-ssh-port)), and the rendered copy is compared, validated and installed like
any repo file.

| class | Phase 1 validates the candidate with | Phase 2, after an actual change |
|---|---|---|
| `logrotate` | `logrotate -d` — no `^error` line | — |
| `sysctl` | every key exists under `/proc/sys` (an nf_conntrack / mptcp key whose module is not loaded only warns) | `sysctl -e -p <file>` |
| `unit` | `systemd-analyze verify` (advisory, same fatal patterns as for `vpn-bot.service`); a drop-in: `[Section]` structure | `daemon-reload`; a `*.timer` is `enable --now`'ed if it was enabled or did not exist. Services are never started or restarted |
| `journald` | a `[Journal]` section | `systemctl restart systemd-journald` |
| `networkd` | a `[Network]` section | — (takes effect at networkd's next start) |
| `hook` | `<candidate> --dry-run` exits 0 | — |
| `plain` | — (installed verbatim) | — (nothing is reloaded) |
| `resolved` | a `[Resolve]` section | `systemctl try-reload-or-restart systemd-resolved`, then `getent ahosts github.com` within 10 s — or the deploy rolls back (the rollback reloads too) |
| `ssh` | `sshd -t` on `sshd_config` with the candidate swapped into a copy of its drop-in directory; a socket drop-in must leave a `ListenStream` port | see [below](#allow_ssh_change-and-the-lockout-risk) |
| `absent` | nothing may still name it (below) | `disable --now` if it is a unit file, then removed; an `sshd_config.d` file is followed by `sshd -t` + reload + the port check, like an ssh change |
| `pristine` | the copy carries the package manager's md5; restoring it changes nothing effective (host check `--pristine`; for `sshd_config` also `sshd -T`) | installed atomically; `journald.conf` → restart journald, `resolved.conf` → as `resolved`, `sshd_config` → as `ssh` — [below](#package-defaults-class-pristine) |

**Phase 1** (read-only, also under `PHASE1_ONLY=1`) scans every entry against `origin/main` and
reports a state per file: `synced`, `absent` (will be installed), `drift` (will be reinstalled —
the diff is printed), `meta` (content right, mode/owner wrong — fixed in place), `rename`,
`present` / `gone` (retired files), `gated-off`, `cannot-restore` (a package default that could
not be obtained or verified: a WARN, never a stop). It validates every candidate Phase 2 would
install and **stops before any mutation** when a validator refuses one, when a retired file is
still referenced, when a legacy-named file differs from the repo, when an ssh file differs
without `ALLOW_SSH_CHANGE=1`, or when restoring a package default would change the effective
configuration.

**Phase 2** stages every path it may touch into the backup archive first, then installs,
repairs and removes, runs each class's post-action once for what actually changed, and rescans:
nothing may still be absent, drifted or present. Any failure takes the normal rollback, which
puts every staged file back — or removes it again when it did not exist — and re-applies the
restored state: unit enablement, the previous runtime sysctl values, journald, ssh.

## Package defaults (class pristine)

Some host files the repo must *not* carry are still the deploy's business: a dpkg conffile whose
hand edit only duplicates a repo drop-in (`journald.conf`'s `SystemMaxUse`, `resolved.conf`'s
`DNS=` / `FallbackDNS=`), and the ucf-managed `sshd_config`, where the provider image leaves
`PasswordAuthentication yes` / `PermitRootLogin yes` active after the `Include`. Those lines are a
LATENT on an sshd auth key — Phase 1 FAIL — on every new host built from that image. No manual
script: a `class pristine` entry makes the deploy put the **package default** back by itself, and
undo any later hand edit the same way.

```text
"dpkg:<package>|<dst>|0644|root:root|pristine|<role>"
"ucf:<template>|<dst>|0644|root:root|pristine|<role>"
```

**Where the copy comes from** (Phase 1, read-only on the host; every temporary file lives in the
deploy's private work directory, removed when it exits):

- `dpkg:<package>` — the version is `dpkg-query ${Version}` of the **installed** package (the
  second letter of `${db:Status-Abbrev}` is `i`: a held package, `hi`, counts). The
  `.deb` is taken from `/var/cache/apt/archives` first (an epoch's `:` is `%3a` in the file name),
  else `apt-get download <package>=<version>` fetches it into the work directory (bounded by
  `timeout`). `dpkg-deb --fsys-tarfile | tar -xO ./<dst>` takes the one file out, and its md5 must
  be the one `dpkg-query ${Conffiles}` records for `<dst>`. A host copy that already has that md5
  *is* the package default: nothing is fetched, the entry reads `synced`.
- `ucf:<template>` — the copy is the template the package ships. Its md5 must be the one dpkg
  records for it (the owning package's `md5sums`, `dpkg-query --control-path <pkg> md5sums`), and
  `<dst>` must be registered in `/var/lib/ucf/hashfile`. What ucf registered for `<dst>` is **not**
  what is restored: it is the template as the maintainer script rendered it at install, debconf
  answers included. On both hosts that md5 is `eb86be66…` — the template with
  `PermitRootLogin yes`, which openssh-server's postinst writes when
  `openssh-server/permit-root-login` is false, as the provider image preseeds it — while the
  template is `0a12ef5c…` (= dpkg's md5sums). The report prints both.
- No copy (not cached and not downloadable, a tool missing, the file not a conffile of that
  package, not registered by ucf) or a wrong md5 → `WARN … cannot restore: <why>`; the file is left
  exactly as it is and the deploy goes on.

**The effect proof** — Phase 1, before any mutation; it is the only way to know whether a hand
edit meant something:

- `scripts/vpn-bot-host-check --pre-install --pristine <dst>=<copy>` judges the host with the
  copy in place (the same overlay as for repo files) and compares the effective value of **every**
  key of the file's family — not only the repo's keys; for sshd also every directive inside `Match`
  blocks, the multi-value ones (`DenyUsers`, `AllowUsers`, …) included, each with every enclosing
  condition (a `Match` in a file included under a `Match` applies only where both hold) — with
  and without it. A package default for `/etc/systemd/<x>.conf` is judged as *the* main file,
  in place of a vendor one under `/usr/lib` (systemd reads the `/etc` file instead).
  For a systemd `*.conf` a value of the host copy that another file overrides with a *different*
  value is refused too: it is dead only if that setting really is last-wins, and a setting that
  accumulates (like `DNSStubListenerExtra=`) would lose it. Only an exact duplicate (the hand edit
  repeats the drop-in) or a modelled list setting passes. Both sides are the host as Phase 2 leaves it otherwise (repo files
  in, retired files gone), so only the restore itself is judged. Any difference is a `MISMATCH`
  of family `pristine` and a Phase 1 FAIL:
  `<file> sets <key>=<value> that no repo file carries — move it into a repo drop-in first`.
  No difference is an `OK pristine` row — the proof, printed in the log and the report; without
  that row Phase 1 fails too.
- `sshd_config` also: `sshd -T` on a private copy of the sshd tree with the host's `sshd_config`,
  and on one with the package default — the same drop-in directory on both sides, as Phase 2 will
  leave it, the drop-ins' own `Include`s of that directory pointed at the private copy too — must
  print byte for byte the same. This catches what the host check does not judge
  (`Port`, `ListenAddress` and the other multi-value keywords). A different output, an `sshd -T`
  that does not run, or no `sshd` → FAIL. Both sides carry the **rendered** Port drop-in
  (`00-vpn-bot-port.conf` for the ports Phase 2 leaves — [The SSH port](#the-ssh-port)), never the
  template. `Port` accumulates across files: a `Port` line in the host's `sshd_config` listens *in
  addition* to `SSH_PORT`, the package default does not have it, so the outputs differ and the
  FAIL says so — set `SSH_PORT` to that port, or drop the line (the SSH port is `SSH_PORT` now).
- That proof is the lockout guard for `sshd_config`, so restoring its package default does **not**
  need `ALLOW_SSH_CHANGE` — a deliberate, documented exception. The knob still guards every
  repo-managed ssh file.

**Phase 2**: the original is staged with every other host path; the copy is installed atomically
(a temporary file in the same directory, the entry's mode and owner, then `mv`); then the
family's post-action — `journald.conf`: `systemctl restart systemd-journald`; `resolved.conf`: as
class `resolved` (`try-reload-or-restart` + `getent ahosts` with retries); `sshd_config`: as class
`ssh` (`sshd -t`, reload, ssh active and listening). Then the normal Phase 2 host check. Any
failure is `rollback_now`: the original comes back and the post-action runs again on it.

**The conffile rule.** The deploy never writes a dpkg conffile (`CONFFILE_REPORT_PATHS` are only
reported) — with exactly one exception: a `class pristine` entry, and only with a copy the package
manager's own md5 vouches for. The deploy never puts content written in the repo into a conffile.
A locally modified conffile that has such an entry is `PENDING` in `--pre-install` ("Phase 2
restores the package default"), not WARN, and its WARN is gone after the install; one without an
entry stays a WARN.

**Retired files are guarded.** Before removing one, Phase 1 searches root's crontab and every
other file under `/var/spool/cron`, `/etc/crontab`, `/etc/cron.d`, the unit directories
`/etc/systemd/system` and `/usr/lib/systemd/system` (drop-ins included) and `.env` for the path
or its basename. A hit **fails** the deploy and names the file and line: remove the reference
first, or drop the retirement.

## Effective state

A registry entry guarantees that the repo's file lies on the host byte for byte, with its mode
and owner. It does **not** guarantee that the file is in effect. On the relay,
`00-vpnrelay-keyonly.conf` (`PasswordAuthentication no`) beat `50-cloud-init.conf` (`yes`) and
active `PasswordAuthentication yes` / `PermitRootLogin yes` lines in the main `sshd_config` only
by parse order — rename the file and the host silently takes passwords, while every deploy stays
green. The main server had the same with `00-root-key-only.conf`.

`scripts/vpn-bot-host-check` closes that class. It is strictly read-only — the one file it writes
is its own state file — and it is the single implementation: deploy Phase 1, deploy Phase 2 and
`vpn-bot-host-check.timer` all run it. Run it by hand with
`sudo /usr/local/sbin/vpn-bot-host-check --no-state`.

### Verdicts

| Verdict | Meaning | Deploy Phase 1 | Deploy Phase 2 | Bot (main) |
|---|---|---|---|---|
| **BEATEN** | a value a repo-managed file sets is not in effect: another file wins | FAIL | rollback | alert |
| **MISMATCH** | the live value (`sshd -T`, `sysctl -n`, `systemctl show`) differs from what the files give, for a key a repo file sets; a repo unit that is masked, waits for `daemon-reload`, or (a timer the deploy installs) is not enabled+active; an `invariants.list` line that does not hold; (`--pristine`) restoring a package default would change a key | FAIL | rollback | alert |
| **LATENT** | right now, but a loser that is neither repo-managed nor vendor holds another value: remove the winner and the value silently flips. The row names the winner, the losers and `winner gone -> <value> from <file>` | FAIL on an sshd auth key¹, else WARN | reported | alert when new |
| **ACCEPTED** | a LATENT listed in `deploy/host/accepted-overrides.list` | reported | reported | — |
| **WARN** | host state outside the repo worth a look (below) | WARN | reported | — |
| **PENDING** | Phase 1 only: the deploy changes it now; Phase 2 checks it (a modified conffile Phase 2 restores to its package default included) | reported | — | — |

¹ `PasswordAuthentication`, `KbdInteractiveAuthentication`, `PermitRootLogin`,
`PermitEmptyPasswords`, `PubkeyAuthentication`, `AuthenticationMethods`.

`PHASE1_ONLY=1` (`CHECK=1`) reports a FAIL instead of stopping, like the other drift gates. There
is **no knob** past a FAIL in a real deploy — fix the host, or the repo.

**Phase 1 judges the host as Phase 2 is about to leave it** (`--pre-install`): every repo file of
the role in place of its host copy (absent ones included), every retired file gone, a byte-equal
legacy name gone. So a repo file another file would outrank is caught before anything is
installed; a live value the deploy is about to change is PENDING. **Phase 2** runs it again
right after the host files and the role's unit are installed (on main: before the bot starts),
writes the state file, and rolls back on any BEATEN/MISMATCH — the same path as the ssh gate.
Both the `PHASE1_ONLY` report and `DEPLOY OK` carry the rows.

### The vendor rule

VENDOR = a file under `/usr/lib`, `/lib` or `/usr/local/lib`, **plus** a file under `/etc` that a
package owns (one batched `dpkg -S`) and that is not modified locally (its md5 equals its line in
`dpkg-query -W -f='${Conffiles}'`). A repo value over a vendor value is normal, not LATENT: on both
hosts `99-bbr.conf` overrides procps' unmodified `/etc/sysctl.d/10-bufferbloat.conf`, and the
provider's `99-cloudimg-ipv6.conf` overrides procps' unmodified `10-ipv6-privacy.conf`. A loser
that is a **modified** conffile is LATENT. A symlink is judged by its target.

`/etc/ssh/sshd_config` is managed by ucf, not a dpkg conffile: the conffile check cannot see it, so
it is never vendor — its lines are judged like any other file's.

### Precedence, family by family

- **sshd** — `/etc/ssh/sshd_config` walked the way sshd reads it: `Include` expanded in place
  (globs, C-locale order, a relative path is relative to `/etc/ssh`); the **first** value wins.
  The main file is a setter like any drop-in: its lines after the `Include` are losers too, its
  lines before it beat every drop-in. Keys inside `Match` (until the next `Match` or the end of
  that file) are left out and listed as INFO. Multi-value keywords are not judged: `Port`,
  `ListenAddress`, `HostKey`, `HostCertificate`, `AcceptEnv`, `SetEnv`, `Subsystem`, `AllowUsers`,
  `DenyUsers`, `AllowGroups`, `DenyGroups`. Aliases: `ChallengeResponseAuthentication` =
  `KbdInteractiveAuthentication`, `prohibit-password` = `without-password`. Live: `sshd -T`.
- **sysctl** — at boot, the order of `systemd-analyze cat-config sysctl.d`; the **last** value
  wins. The order of `sysctl --system` is measured, not assumed: `sysctl --system --dry-run`
  (procps ≥ 4.0.3; the hosts have 4.0.4; it writes nothing), its `* Applying <path>` lines.
  Measured on the hosts: `/etc/sysctl.conf` is applied once more at the very end, although it is
  already linked as `99-sysctl.conf`. A key whose boot winner differs from its `sysctl --system`
  winner is LATENT. Without `--dry-run` the order is assumed (the boot order, then
  `/etc/sysctl.conf`) and the report says so. A key with `/` and no `.` is normalised to dots; a
  leading `-` is dropped; spaces in a value are squeezed; a key with `*` is never compared with
  `/proc`. Live: `sysctl -n`.
- **systemd `*.conf` + `*.conf.d`** — `journald`, `networkd`, `resolved`, `logind`, `timesyncd`,
  `system`: the order of `systemd-analyze cat-config systemd/<x>.conf` (the main file, then the
  drop-ins by name), key = `Section.Key`, the **last** value wins. Except list settings —
  `Resolve.DNS`, `Resolve.FallbackDNS`, `Resolve.Domains`, `Resolve.DNSStubListenerExtra`, `Time.NTP`,
  `Time.FallbackNTP`: there
  the entries of every file add up and an empty assignment resets, so the accumulated list is
  compared (a server left in `resolved.conf` next to the drop-in's is BEATEN). There is no
  generic live readout for these, so they are judged on precedence only.
- **Units the repo installs**, by role, from the same sources as `UNIT_SET` and
  `MANAGED_HOST_FILES`: on main `deploy/vpn-bot.service`, every `deploy/*.service|*.timer` that is
  installed on the host, and the registry's units and drop-ins; on a relay `deploy/relay/*.service`
  and the registry's. Never a `*.example.*`. `FragmentPath` other than ours or a masked unit →
  BEATEN; `NeedDaemonReload=yes` → MISMATCH; our drop-in not in `DropInPaths` → BEATEN; a drop-in
  there that is neither ours nor vendor (`/etc`, `/run`, generators) → LATENT; a timer the deploy
  installs that is not `enabled` + `active` → MISMATCH. (The `deploy/*.timer` units the operator
  installs by hand belong to modular subsystems and are not required to run.) `systemctl show` is
  read line by line as `Key=Value`, never evaluated.

### What is expected

Only explicit lists — no "sensible" defaults:

- the **sysctl, sshd and systemd `*.conf` keys are derived from the repo files of the role**: add a
  file to `MANAGED_HOST_FILES` and its keys are checked from then on
  (`tests/test_host_check.py` pins this against the real registry);
- beyond that, **`deploy/host/invariants.list`**, one line per invariant:

  ```text
  <main|relay|all>|<probe>|<key>|<expected>|<reason, at least 20 characters>
  ```

  The probes are a closed set — no arbitrary commands: `sshd` (vs `sshd -T`), `sysctl` (vs
  `sysctl -n`), `systemd-conf:<x>` (vs the files), `unit-prop:<unit>:<Prop>` (`systemctl show`),
  `path-present`, `path-absent`, `path-regular` (exists and is **not** a symlink),
  `tcp-listen:<port>`. `~X` as the expected value means "contains X as a whole token"
  (`~22` matches `[::]:22 (Stream)`, not `:2222`). Seeded: on main `even-day-reboot.timer` is
  enabled and active, `/etc/resolv.conf` is a plain file; on a relay `ufw.service` is masked (its
  input filter is `table inet vpnrelay_input`, see [docs/relay.md](relay.md#the-input-filter)); on
  both `/etc/cloud/cloud-init.disabled` exists. The SSH port is **not** in the list (a fixed port
  would contradict `SSH_PORT` during and after a migration): family `ssh-port` judges it —
  [The SSH port](#the-ssh-port).

### Accepting a LATENT

A LATENT that is meant to stay goes into **`deploy/host/accepted-overrides.list`** — the only
sanctioned way; there is no `ALLOW_*` knob (`redeploy.sh` would not forward one anyway):

```text
<path>|<key>|<reason, at least 20 characters>
```

`path` is the file the row names (the loser, a foreign drop-in, or the file that wins at
`sysctl --system`), `key` the row's key (sysctl key, lower-case sshd keyword, `Section.Key`, or the
unit name for a drop-in). An entry turns exactly that row into ACCEPTED and nothing else; an
entry that matches nothing is listed as INFO. The format is checked by `tests/test_host_check.py`.
Under the vendor rule the list starts **empty**.

### WARN checks

Host state outside the repo, reported, never fatal, never a key or a password in the output:
cloud-init alive (no `/etc/cloud/cloud-init.disabled`); `logrotate -d /etc/logrotate.conf` lines
that **start** with `error:`, and `duplicate log entry` (never a substring "error": it is in paths
such as `error.log`); `NOPASSWD: ALL` in sudoers; a non-root account with a login shell and a
usable password (`passwd -S` = P, read from `/etc/shadow`) or a non-empty `authorized_keys`; a
locally modified dpkg conffile under `/etc/systemd`, `/etc/sysctl*`, `/etc/logrotate*`, `/etc/cloud`
or `/etc/sudoers*`, with the keys it sets (a setting that lives only in a modified conffile is host
state outside the repo). A conffile with a `class pristine` entry is `PENDING` instead in
`--pre-install` when the deploy has its package default, and its WARN is gone once Phase 2 restored
it — [Package defaults](#package-defaults-class-pristine).

The check never removes or edits a file that is not in the registry. What it finds is closed with
the registry: a file the repo should own gets an entry, a file that must not come back gets
`class absent` (cloud-init's `50-cloud-init.conf` and `90-cloud-init-users` on both roles), a
marker gets `class plain` (`/etc/cloud/cloud-init.disabled`).

### Between deploys

`vpn-bot-host-check.timer` (a registry unit of both roles) runs the check 5 minutes after every
boot and then daily (`RandomizedDelaySec=30min`, `Persistent=true`). The boot run matters most:
cloud-init, the provider and apt change a host on a reboot, and `even-day-reboot.timer` reboots it
only every 5 days. Each run — and every deploy's Phase 2 — atomically rewrites
`/var/lib/vpn-bot-host-check/last.json` (`root`, `0644`): the time, the role, the counts and the
rows. A BEATEN/MISMATCH makes the service exit 1, so the unit shows as failed and
`journalctl -u vpn-bot-host-check` has the rows.

On **main** the bot reads that file every `HOST_CHECK_INTERVAL` seconds and alerts the superadmins
(`ADMIN_IDS`, the same broadcast as the relay alerts) when a row turns BEATEN or MISMATCH, when a
LATENT is new, and once when the last BEATEN/MISMATCH is gone. Never twice for the same row: what
was reported is kept in the database, so a restart does not repeat it.

A **relay** runs no bot, and the bot has no channel to a relay — relays are rows in the database,
probed from outside by a TLS handshake through their DNAT — so none is built for this. A relay's
verdict is in its journal (`journalctl -u vpn-bot-host-check`, the failed unit) and in Phase 1 of
every relay deploy (`CHECK=1` shows it without deploying).

### DNS on the main server

- `/etc/resolv.conf` is a **plain file**, not systemd-resolved's stub symlink (rewritten on
  2026-08-25): `nameserver 1.1.1.1`, `nameserver 8.8.8.8`. It is `deploy/host/dns/resolv.conf`
  (class `plain`, byte-identical to the host's — `tests/test_deploy_host_state.py` pins its
  sha256), and the `path-regular` invariant fails if a symlink comes back.
- systemd-resolved still runs; its upstreams `DNS=1.1.1.1 8.8.8.8` and
  `FallbackDNS=1.0.0.1 8.8.4.4` lived only in a hand edit of the dpkg conffile
  `/etc/systemd/resolved.conf`. They are `deploy/host/resolved/10-vpn-bot.conf` now (class
  `resolved`): after a change, `systemctl try-reload-or-restart systemd-resolved`, then
  `getent ahosts github.com` must answer within 10 s, or the deploy rolls back (the rollback puts
  the old file back and reloads the same way).
- `/etc/systemd/resolved.conf` itself goes back to the package default through its `class
  pristine` entry — no manual script: Phase 1 proves that the effective `DNS=` / `FallbackDNS=`
  (the drop-in's) do not change, Phase 2 restores the stock file and reloads resolved like class
  `resolved`. Nothing effective changes: the drop-in carries the conffile's values and
  `resolv.conf` is synced.

## Files nothing accounts for

Phase 1 lists every file in these directories that is not installed by the deploy for this role,
not owned by a package (`dpkg -S`, one batched call) and not matched by
`deploy/host/known-unmanaged.list`:

`/etc/systemd/system` (files and `*.d/` drop-ins; `*.wants` links and symlinks are skipped),
`/etc/sysctl.d`, `/usr/local/sbin`, `/usr/local/bin`, `/etc/logrotate.d`, `/etc/cron.d`,
`/var/spool/cron/crontabs`, `/etc/ssh/sshd_config.d`, `/etc/nginx/conf.d`, `/etc/systemd/*.conf.d`.

Each one is a `WARN` with its mtime — never fatal. A drop-in whose unit does not exist is
called out as an **orphan drop-in for absent unit**. For each warning, decide: put it in the repo
(a registry entry), retire it (`class absent`), or record why it stays in
`known-unmanaged.list`:

```text
<absolute path-glob>  # <installer|provider|backup-only|deployment-local> — <reason, ≥ 20 characters>
```

## Adding a host file

1. Copy the host file into `deploy/host/<subsystem>/` **byte for byte**
   (`scp host:/etc/... deploy/host/...`, then compare `sha256sum` on both sides). A copy that
   differs is reinstalled on the next deploy — or, for `ssh`, refused.
2. Add the entry to `MANAGED_HOST_FILES` with the mode and owner the host file has now
   (`stat -c '%a %U:%G'`).
3. Add the path to the table above. `tests/test_deploy_host_state.py` checks that every source
   exists, every entry is well-formed and every destination is documented here; for files that
   must read `synced` on the first deploy, pin the host's sha256 there too.
4. `sudo CHECK=1 bash scripts/redeploy.sh` — the entry must show the state you expect before you
   deploy for real.

To retire a file, add `"-|<path>|-|-|absent|<role>"`. Its backup copy stays in the deploy
archives (`/var/backups/vpn-bot`, the last `BACKUP_KEEP`).

To put a package's own file back to its default, add
`"dpkg:<package>|<path>|0644|root:root|pristine|<role>"` (a dpkg conffile) or
`"ucf:<template>|<path>|0644|root:root|pristine|<role>"` (a ucf-managed file). The path must be
in a family the effect proof covers: `/etc/ssh/sshd_config`, `/etc/systemd/<x>.conf`, sysctl.
`tests/test_deploy_pristine.py` pins the form and that the path is that package's conffile.

## ALLOW_SSH_CHANGE and the lockout risk

A wrong `sshd_config.d` drop-in or `ListenStream` cuts off every new ssh connection. So for
class `ssh` the deploy never replaces a host copy that **differs** from the repo on its own:
Phase 1 prints the diff and stops, before anything is changed. (An *absent* ssh file is
installed — there is nothing to lose; a *synced* one is never touched.)

Decide which side is right:

- **the host is right** — copy its file into `deploy/host/ssh/` byte for byte and redeploy;
- **the repo is right** — open a **second ssh session** to the host and keep it open, then:

  ```bash
  sudo ALLOW_SSH_CHANGE=1 bash scripts/redeploy.sh
  ```

With the knob, Phase 2 installs the file and runs `sshd -t`. For a `ListenStream` change it
does `daemon-reload` + `systemctl restart ssh.socket` and, when sshd is running, also
`systemctl restart ssh` — a running sshd keeps the sockets it was started with, so the socket
alone would leave it on the old port (open sessions survive the restart). For an sshd_config
change it does `systemctl reload ssh`. Then the listening unit (`ssh.socket` where it is
active, otherwise `ssh.service`) must be active and every expected port must both listen and
**answer with an SSH banner** — a listener alone proves nothing under socket activation. If not,
the deploy rolls back: the old file is restored, `sshd -t` is run on it, and the socket / ssh is
restarted or reloaded the same way — **unless `sshd -t` fails on the restored config**, in which
case ssh is left alone and the rollback report says so in capitals.

The port check catches a dead port, not a key you can no longer log in with. The second session
is what saves you then: test a fresh login from it before closing anything.

`/etc/ssh/sshd_config` itself is not class `ssh`: it only ever goes back to its package default
(class `pristine`), after Phase 1 has proven `sshd -T` byte-for-byte unchanged — that proof is
the guard there, and the knob is neither needed nor read.

The **SSH port migration** needs no knob either: the two `render=ssh-port` files change without it
exactly when the host copy is the rendering of the ports ssh listens on now — a step of
[the migration](#the-ssh-port), guarded by listening on both ports and by a proof. A hand edit of
those files is a drift like any other and needs the knob.

## The SSH port

**One setting, both roles:** `SSH_PORT` in `/opt/vpn-service/.env` (main and relay; absent or
empty = **54321**). Validated before anything changes: a whole number 1..65535 without a leading
zero; not a TCP port of a service of this role — main: `XRAY_PUBLIC_PORT` (443), `XRAY_XHTTP_PORT`,
`SUBSCRIPTION_BIND_PORT`, `SUBSCRIPTION_PUBLIC_PORT`, `SOCKS5_PORT`, `MTPROTO_PORT`,
`MTPROTO_INTERNAL_STATS_PORT`, `HEALTH_PORT`; relay: `RELAY_FORWARD_TCP_PORTS` (443),
`RELAY_INPUT_EXTRA_TCP`, `RELAY_INPUT_CLOSED_TCP` — and not a port another process listens on
(`ss`). A refusal stops Phase 1: `ssh port: REFUSED — …; nothing was changed`.

With the default, the main server does not move (it already listens on 54321 through
`ssh.socket`; its override renders byte-identical) and an existing relay moves from the package's 22
to 54321 by itself, at its next deploy.

### Two files, rendered

| File | Template line | What it is for |
|---|---|---|
| `/etc/systemd/system/ssh.socket.d/override.conf` | `ListenStream=0.0.0.0:@SSH_PORT@`, `ListenStream=[::]:@SSH_PORT@` after a reset | the socket: what ssh listens on |
| `/etc/ssh/sshd_config.d/00-vpn-bot-port.conf` | `Port @SSH_PORT@`, plus `LogLevel VERBOSE` | the fallback: `ssh.service` started **without** `ssh.socket` binds `Port` itself — it listens where the socket does, not on 22 behind the firewall |

`scripts/vpn-bot-ssh-port render` writes each `@SSH_PORT@` line once per port, in ascending order.
Ubuntu 24.04's `sshd-socket-generator` turns the same `Port` lines into
`/run/systemd/generator/ssh.socket.d/addresses.conf` at every `daemon-reload` (measured with
openssh-server 1:9.6p1-3ubuntu13, it follows the `Include` into `sshd_config.d`); `override.conf`
sorts after `addresses.conf` and resets `ListenStream=`, so the repo file decides either way.

### The migration: two phases, each automatic

When the port ssh listens on (`systemctl show -p Listen ssh.socket`) is not `SSH_PORT`:

1. **Phase 1 — a deploy.** Both files are rendered for the old port(s) **and** `SSH_PORT`: ssh
   listens on both. The firewall follows: on a relay `table inet vpnrelay_input` takes the ssh ports
   from `ss` on its own (the deploy's restart of `vpn-relay` re-applies it; the changed set is
   confirmed by main's probe — [docs/relay.md](relay.md#the-input-filter)); on main the deploy opens
   `SSH_PORT` in UFW **before** the socket changes: `vpn-bot-ufw-apply apply` (installed on main —
   it owns the firewall, [The firewall (UFW)](#the-firewall-ufw)) puts both ports in the set; only
   where that helper is missing, a rule commented `vpn-bot:ssh-migration`. The old port is not touched. The state goes to
   `/var/lib/vpn-bot/ssh-migration.json` (`from`, `to`, `phase: 1`, `since`).
2. **Phase 2 — only after a proof** that `SSH_PORT` works **from outside**: the old port leaves the
   socket and the Port drop-in (`Port SSH_PORT` alone), and the firewall closes it — main: the
   rules that allow exactly the old port (`ufw show added`: `<port>[/tcp]`, `… port <port> [proto
   tcp]`) are deleted and the migration rule is relabelled `vpn-bot:ssh` in place (ufw updates a
   rule's comment without a gap); a rule without a protocol opens tcp **and** udp (ufw(8)), so it is
   split — the same rule for udp is added first, then the shared one is deleted, and a udp service
   on that number (Hysteria2, say) keeps its port; a rule this cannot remove (an app profile, a port list) is a note,
   never a failure — leaving a port open is the safe direction. Relay: the input filter is applied
   again (`vpn-relay-apply apply`, one nft transaction) and drops the old port. `phase: 2`.

**The proof** — any one, each later than the start of phase 1 (`since`):

| Proof | Role | Where it comes from |
|---|---|---|
| `relay-probe` | relay | main's probe (`POST /relay/ssh-probe`) connected to `SSH_PORT` through the input filter: `/etc/vpn-relay/input.confirmed` says `confirmed_by=main-probe`, its `tcp=` set holds `SSH_PORT`, `confirmed_at` ≥ `since` |
| `journal` | both | sshd logged a connection from a **non-local** address on `SSH_PORT` (`journalctl -u ssh.service --since @<since>`). openssh 9.6 writes `Connection from <raddr> port <rport> on <laddr> port <lport> rdomain ""` **only at `LogLevel VERBOSE`** — measured with the noble binary; at `INFO` the line does not exist, hence the `LogLevel VERBOSE` in the Port drop-in. Loopback, the host's own addresses (`ip -o addr`) and `raddr == laddr` prove nothing |
| `bot` | main | a superadmin pressed **«Подтвердить»** under the bot's message «SSH теперь и на порту N — подключись на него и нажми Подтвердить»; the bot runs `vpn-bot-ssh-port confirm --port N --since S --admin ID` (sudo, exact-path grant in `deploy/sudoers.d/vpn-bot.example`; under the non-root bot's `ProtectSystem=strict` the helper re-enters PID 1's mount namespace first, as the other helpers do) |

**Without a proof there is no phase 2, ever.** It is looked for by every deploy (Phase 1's plan; a
deploy that finds one performs phase 2 itself, with `rollback_now`), at boot and daily
(`vpn-bot-host-check.timer` → `vpn-bot-host-check.service` `Wants=` `vpn-bot-ssh-port.service` →
`vpn-bot-ssh-port advance`), right after every DEPLOY OK of a host in phase 1 (a relay whose filter
main's probe just confirmed finishes in the same run), and at once after «Подтвердить». `advance`
takes the deploy's lock (`/run/vpn-bot-deploy.lock`) or leaves the work to the running deploy; it
touches only files that are exactly what phase 1 left there.

The bot tells the superadmins once when phase 1 starts (with the button) and once when the
migration is done (`schema_meta` remembers it across restarts). A relay runs no bot: its state is in
its deploy report and journal. The deploy prints the state in Phase 1, in the report and in DEPLOY
OK, e.g.

```text
ssh port: migrating 22 -> 54321 (waiting for proof: main's probe of tcp 54321 (RELAY_CONFIRM_URL), or an ssh connection from outside on 54321 in the sshd log)
```

`SSH_PORT` changed again while waiting: a new phase 1 from the original port(s) to the new value
(the unproven port is dropped, the original never closed); `SSH_PORT` back on the original port: the
unproven one is dropped (`phase: 0`, called off).

### The post-check of each phase

`sshd -t` on the installed configuration; `daemon-reload`, `restart ssh.socket` and — when sshd
runs — `restart ssh` (a running sshd keeps the sockets it was started with); then `ssh.socket`
must be active, `systemctl show -p Listen ssh.socket` must hold **exactly** the planned ports,
every planned port must listen and answer with an SSH banner, and a port the step removed must no
longer listen. Any failure: in a deploy `rollback_now` — the previous files, the previous state
file, the UFW rule phase 1 opened removed again, the socket and ssh restarted on the restored set;
in `advance` its own revert to the previous set, the reason in the state file's `last_error`
(host check: a WARN).

**Open sessions survive.** Measured on the noble package: `ssh.socket` is `Accept=no`, enabling it
links `ssh.service.requires/ssh.socket`, so restarting the socket restarts `ssh.service` too — and
`ssh.service` has `KillMode=process`: only the listening sshd gets SIGTERM; each session is its own
sshd child (`sshd: user@pts/N`; openssh 9.6 has no `sshd-session` yet — 9.8+) holding its own TCP
connection, and stays. A session on the old port also survives phase 2: the firewall lets
established connections through (UFW's `ctstate RELATED,ESTABLISHED`, the relay filter's
`ct state established,related accept`). The deploy itself runs under `systemd-run`, outside any ssh
session.

### What the host check says (family `ssh-port`)

| Plan | Installed host (timer, Phase 2) | `--pre-install` (Phase 1) |
|---|---|---|
| on `SSH_PORT` | `OK ssh.socket`; `OK fallback` when `sshd -T` gives exactly `SSH_PORT`, else `MISMATCH fallback` (the Port drop-in is not in effect) | the same; the fallback `PENDING` while the deploy installs the drop-in |
| `SSH_PORT` ≠ listening, no migration | `MISMATCH migration` — the next deploy starts phase 1 | `PENDING` (this deploy starts it) |
| phase 1, no proof | `PENDING migration` with what it waits for | the same |
| phase 1, proven | `PENDING` (phase 2 next); a failed, reverted phase 2 adds a `WARN` | `PENDING` |
| `SSH_PORT` refused | `MISMATCH SSH_PORT` with the reason | the same (Phase 1 refuses anyway) |

## The firewall (UFW)

The main server's UFW is **computed**, never typed: `scripts/vpn-bot-ufw-apply` (installed by
deploy.sh, `OUT_OF_REPO_HELPERS`, `required` on main) derives the whole rule set from the repo and
`.env`, and converges the host on it. A relay has no UFW: its input filter is `vpnrelay_input`
([docs/relay.md](relay.md#the-input-filter)).

### The set

| Part | Where it comes from | Comment on the rule |
|---|---|---|
| modules | one table in the helper (`MODULE_TABLE`), also the only list of a module's rules anywhere: `xray` → `XRAY_PUBLIC_PORT/tcp` (`XRAY_SERVER_PORT`, 443); `hysteria2` → `HYSTERIA2_PORT/udp`; `socks5` → `SOCKS5_PORT/tcp`; `subscription` → `SUBSCRIPTION_PUBLIC_PORT/tcp`; `mtproto` → `MTPROTO_PORT/tcp`; `awg` → the AWG `ListenPort/udp` (`awg0.conf`, else `AWG_ENDPOINT_PORT`) + `route allow in on <AWG_INTERFACE> out on <WAN> from <AWG_NETWORK>` (WAN = the device of the IPv4 default route). A module is in the set only while `.env` enables it (`*_ENABLED`; Xray and AWG have no flag) **and** it has no uninstall marker (`/etc/vpn-bot/uninstalled/<module>`) | `vpn-bot:<module>` |
| ssh | `SSH_PORT` and, while a migration runs, its other port(s) — the [SSH port](#the-ssh-port) plan's `listen` set (the deploy passes it as `--ssh-ports`; otherwise the helper asks `vpn-bot-ssh-port plan`) | `vpn-bot:ssh` |
| extra | `deploy/host/ufw/extra.list`, `role\|rule\|reason` (reason ≥ 20 characters): every other rule, written as `ufw show added` prints it, and `closed <port>/<tcp\|udp>` for a listener closed on purpose. Measured 2026-11-12: empty — every rule of main is a module's or ssh's | `vpn-bot:extra` |
| policies | `deploy/host/ufw/policy`, `role\|incoming\|outgoing` lines; seeded from the measurement (`deny` / `allow`). **routed is never managed** (AWG and WARP forwarding live on route rules) — a `routed` line refuses the plan | — |

### `apply`

1. adds what is missing — a missing v4 or v6 copy too (`ufw allow` adds both; IPv6 counts only
   with `IPV6=yes` **and** a kernel with IPv6, ufw's own rule), and relabels (**adopts**) a
   matching rule without our comment: ufw updates the comment in place, the port never closes;
2. sets the outgoing policy; the incoming policy and enabling an inactive ufw under a dead-man
   (below);
3. deletes a rule with a `vpn-bot:` comment that is not in the set, and an **unmarked** rule that
   matches a rule of the table — a module switched off or removed, an old ssh port (22 is the
   package's; the migration's `from`). That is how the measured route rule of the removed AWG and
   the old `22/tcp` leave the host. A route rule goes with `ufw route delete …` (ufw 0.36 refuses
   `ufw delete route …`);
4. leaves every other unmarked rule alone — a `WARN`, never deleted;
5. reads the result back: anything still to add, relabel or delete is a failure (exit 4).

**Never a lockout.** A rule that opens the port sshd **really** listens on — the union of
`sshd -T`, `systemctl show -p Listen ssh.socket` and the `ss` rows of sshd (or of PID 1 for a
socket port) — is never deleted (`keep`); when none of them answers, nothing is deleted at all. A
module that is on but whose rule cannot be written down here (its port unknown, no default route)
keeps whatever is recognisably its own.

### The dead-man

Enabling an inactive ufw and changing the incoming policy are the two steps that can cut ssh off.
Both run under a dead-man, as the relay's input filter does (#328): `/var/lib/vpn-bot/ufw-deadman.json`
records what was before, a transient timer (`vpn-bot-ufw-deadman-watch`) runs
`vpn-bot-ufw-apply deadman-check` every minute, and the change stays only with a **proof that ssh
still answers from outside** — the proofs of the SSH port migration: a new connection from a
non-local address on an ssh port in the sshd log (`vpn-bot-ssh-port proof-journal`, `LogLevel
VERBOSE`), or «Подтвердить» under the bot's message (`vpn-bot-ufw-apply confirm`, sudo, exact-path
grant). Without one, 10 minutes after the change the previous incoming policy (and an inactive
ufw) comes back. A reboot ends the timer: `vpn-bot-ufw-deadman.service`, pulled in by
`vpn-bot-host-check.service` (5 min after boot, daily), re-arms it or reverts. A timer that cannot
be armed: the policy is not changed (exit 9). **An ordinary deploy changes no policy and arms no
dead-man.**

### Where it runs

| Who | When | How |
|---|---|---|
| deploy.sh Phase 1 | every deploy of main | `plan` from the checkout: the section «UFW» and the report. Stops (`PHASE1_ONLY=1`: reported) on a refused plan, a main server without ufw, and a public listener the set neither allows nor declares closed |
| deploy.sh Phase 2 | after the helpers | `save` of the UFW state (files, enabled or not, the dead-man state) before the SSH port opens anything |
| | after the host files and the SSH port state | `apply`, then `listeners`; either failing is `rollback_now`, and the rollback `restore`s the saved state |
| | DEPLOY OK | `status`, one line |
| the bot | a protocol switched on in «Модули протоколов»; a protocol removed from the host | `apply` (sudo, exact-path grant). `vpn-bot-protocol-uninstall` no longer touches ufw — its marker takes the module out of the set: **one owner of the rules** |
| `vpn-bot-ssh-port` | phase 1 / phase 2 of a migration | `firewall-open` / `firewall-close` run `apply` |

### Listeners

Every TCP `LISTEN` on a public or wildcard address must be allowed by the set or declared closed
(`main|closed <port>/tcp|<why>`). UDP is checked only on the UDP ports of the module table (and only
on a public or wildcard address); every other UDP socket is an `INFO` line, never an error: the
listen-port of an awg/wg interface (`awg show all listen-port` — kernel-owned, no process, random
at every start: out-warp's `*:32808` on the measured host; never hardcoded) and outgoing sockets on
a private address (`172.16.0.2:*` through WARP).

### What the host check says (family `ufw`)

| Finding | Installed host | `--pre-install` (Phase 1) |
|---|---|---|
| ufw not installed, the plan refused | `MISMATCH` | `MISMATCH` |
| ufw inactive | `MISMATCH` | `PENDING` (the deploy enables it, under a dead-man) |
| a policy that is not `deploy/host/ufw/policy`'s | `MISMATCH` | `PENDING` |
| a rule of the set missing, or one of its v4/v6 copies | `MISMATCH` | `PENDING` |
| a rule with a `vpn-bot:` comment that is not in the set | `MISMATCH` | `PENDING` |
| an unmarked rule that is not in the set | `LATENT` (`apply` deletes a table rule, WARNs about any other) | `PENDING` for a table rule, `LATENT` otherwise |
| a rule of the set without our comment | `INFO` (relabelled by `apply`) | `PENDING` |
| a rule kept because sshd listens on its port | `WARN` | `WARN` |
| a dead-man waiting / one that reverted | `PENDING` / `WARN` | the same |

By hand: `sudo /usr/local/sbin/vpn-bot-ufw-apply plan` (read-only, `key=value` lines),
`… apply`, `… status`. Never `ufw allow` — the next apply relabels or deletes it.
