# Host state as code

[Русская версия](host-state.ru.md)

The checkout under `/opt/vpn-service` is not the whole deployment. A working host also carries
files outside it: kernel tuning, a log-rotation rule, an ssh port override, a certificate
fan-out hook, a scheduled reboot. When those live only on the host, a rebuilt or migrated server
has nothing to restore them from, and nobody notices a hand edit that drifted.

`scripts/deploy.sh` therefore owns a declared set of host files. It installs them, repairs them
when they drift, removes the ones that were retired — and in Phase 1 it reports every other file
in the scanned host directories that nothing accounts for.

## The four classes

Every file on a host is in exactly one of these:

| Class | Source of truth | Who writes it on the host |
|---|---|---|
| **repo-managed** | a byte-exact copy in the repo | `deploy.sh` (or, for `deploy/*.service` other than the bot, the operator after the drift gate) |
| **template + host values** | the repo holds the *shape*, the host the values | the operator / the bot, checked by a deploy gate |
| **backup-only** | not in the repo by design; listed in `deploy/host/known-unmanaged.list` | a third-party installer, the provider, or the operator — and the offsite backup |
| **retired** | a `class absent` entry: the file must *not* exist | `deploy.sh` removes it |

`known-unmanaged.list` tags each backup-only entry with who writes it: `installer` (Xray-install,
get.hy2.sh, `setup-nonroot-helper-mode.sh`…), `provider` (the VPS image), `backup-only` (ours,
kept only by the offsite system bundle) or `deployment-local` (unique to this deployment by
design and cannot live in the repo).

## Every host file

### main

| Path | Class | Installed by | Notes |
|---|---|---|---|
| `/etc/logrotate.d/xray` | repo-managed (`logrotate`) | deploy.sh | `copytruncate`: xray cannot reopen its logs, and writes them `O_APPEND` |
| `/etc/systemd/system/even-day-reboot.service` | repo-managed (`unit`) | deploy.sh | reboots the host — the deploy **never** starts it |
| `/etc/systemd/system/even-day-reboot.timer` | repo-managed (`unit`) | deploy.sh | days 5,10,…,30 at 01:00 UTC (04:00 MSK); `enable --now` only if it was enabled or did not exist |
| `/etc/sysctl.d/90-no-mptcp.conf` | repo-managed (`sysctl`) | deploy.sh | MPTCP off until the kernel carries the fix for CVE-2026-98432; byte-identical to the host copy, so the reason lives here, not in the file |
| `/etc/sysctl.d/99-bbr.conf` | repo-managed (`sysctl`) | deploy.sh | `fq` + BBR |
| `/etc/sysctl.d/99-network-buffers.conf` | repo-managed (`sysctl`) | deploy.sh | socket buffers, backlog, dirty ratios |
| `/etc/sysctl.d/99-swap-tuning.conf` | repo-managed (`sysctl`) | deploy.sh | |
| `/etc/sysctl.d/99-vpn-forwarding.conf` | repo-managed (`sysctl`) | deploy.sh | the one `net.ipv4.ip_forward=1` |
| `/etc/systemd/journald.conf.d/10-vpn-bot.conf` | repo-managed (`journald`) | deploy.sh | `SystemMaxUse=500M`; replaces a hand edit of `journald.conf` |
| `/etc/systemd/journald.conf` | dpkg conffile | the `systemd` package | never written by the deploy; Phase 1 reports it **MODIFIED** while the old hand edit is still in it — restore the stock file by hand once the drop-in is live |
| `/etc/systemd/networkd.conf.d/10-keep-foreign-rules.conf` | repo-managed (`networkd`) | deploy.sh | keeps networkd from flushing WARP's `ip rule`s; effective at networkd's next start |
| `/usr/local/sbin/acme-reload.sh` | repo-managed (`hook`, `when=/etc/vpn-bot/tls/fullchain.pem`) | deploy.sh, from `deploy/vpn-bot-acme-reload.sh` | acme.sh's `Le_ReloadCmd`; only where there is renewal material; [subscription.md](subscription.md#tls-termination) |
| `/etc/ssh/sshd_config.d/00-root-key-only.conf` | repo-managed (`ssh`) | deploy.sh | key-only root login; see [ALLOW_SSH_CHANGE](#allow_ssh_change-and-the-lockout-risk) |
| `/etc/systemd/system/ssh.socket.d/override.conf` | repo-managed (`ssh`) | deploy.sh | `ListenStream` on 54321 (IPv4 + IPv6) |
| `/etc/systemd/system/danted.service.d/vpn-bot-warp.conf` | repo-managed (`unit`) | deploy.sh, from `deploy/danted-warp.conf` | ordering after the WARP interface |
| `/etc/systemd/system/mtproxy.service.d/vpn-bot-managed.conf` | repo-managed (`unit`, `gate=MTPROTO`) | deploy.sh, from `deploy/mtproxy-vpn-bot-managed.conf` | only while `MTPROTO_ENABLED=true`; a byte-identical old name `vpnbot-managed.conf` is renamed. With MTProxy off, a leftover drop-in is reported as an orphan |
| `/etc/systemd/system/vpn-bot.service` | repo-managed | deploy.sh, verbatim | the privilege-model gates apply |
| `/etc/systemd/system/<deploy/*.service, *.timer>` | repo-managed | the operator, by hand | Phase 1's unit-drift gate prints the install commands |
| `/usr/local/sbin/vpn-bot-warp-*`, `warp-failsafe`, `vpnbot-hy2-warp-mark`, `vpn-bot-db-perms` | repo-managed (`OUT_OF_REPO_HELPERS`) | deploy.sh | from `scripts/` |
| `/usr/local/sbin/vpn-bot-{xray,awg,mtproxy}-apply`, `vpn-bot-socks5-user` | backup-only (`installer`) | `deploy/setup-nonroot-helper-mode.sh` | source `deploy/helpers/` |
| `/usr/local/etc/xray/config.json` | template + host values | the bot (clients) / operator | structure checked by `deploy/backend-config-sync.py` |
| `/etc/amnezia/amneziawg/awg0.conf` | template + host values | the bot (peers) / operator | same gate |
| `/etc/hysteria/config.yaml` | template + host values | `deploy/hysteria/install-config.sh` | same gate |
| `/opt/vpn-service/.env` | template + host values | the operator | `.env.example` |
| `/etc/vpn-bot/tls/*` | host values | acme.sh; modes by the hook | dir `root:root 0755`, `fullchain.pem`/`privkey.pem` `root:vpn-bot 0640` |
| `/etc/systemd/system/xray*.service` (+ `.d/`), `/usr/local/bin/xray` | backup-only (`installer`) | Xray-install | |
| `/etc/systemd/system/hysteria-server*.service` (+ `.d/`), `/usr/local/bin/hysteria` | backup-only (`installer`) | get.hy2.sh | |
| `/usr/local/bin/wgcf`, `/usr/local/bin/qr` | backup-only (`installer`) | their own installers | |
| `/etc/nginx/conf.d/*.conf` | backup-only | the operator | decoy / self-steal vhost with the host's domain; a repo template is separate work |
| `/etc/netplan/*` | backup-only (`provider`) | the VPS image | not in the scanned set; listed for completeness |
| `/var/spool/cron/crontabs/root` | backup-only | acme.sh (`--cron` line) | |
| `/usr/local/sbin/site-freshen.py` | backup-only (`deployment-local`) | the operator | the decoy rewriter — by [design](hysteria.md#keeping-the-decoy-in-step-vpn-bot-decoy-freshensh) never in the repo; protected by the offsite system bundle (`DEFAULT_OFFSITE_SYSTEM_PATHS` in `config/settings.py` — the path is added there by the follow-up change; until then, back it up by hand) |
| `/etc/sysctl.d/99-amneziawg.conf` | retired | — | a duplicate `ip_forward=1` |
| `/etc/systemd/system/warp-sample.timer` | retired | — | `disable --now`, then removed |
| `/etc/systemd/system/warp-sample.service` | retired | — | `disable --now`, then removed |
| `/usr/local/sbin/site-freshen.sh` | retired | — | its job is `deploy/vpn-bot-decoy-freshen.sh` now |

### relay

| Path | Class | Installed by | Notes |
|---|---|---|---|
| `/etc/ssh/sshd_config.d/00-vpnrelay-keyonly.conf` | repo-managed (`ssh`) | deploy.sh | key-only login |
| `/usr/local/sbin/vpn-relay-apply` | repo-managed (`OUT_OF_REPO_HELPERS`) | deploy.sh | |
| `/etc/systemd/system/vpn-relay.service` | repo-managed | deploy.sh, verbatim | |
| `/etc/sysctl.d/90-vpn-relay.conf` | template + host values | `vpn-relay-apply apply`, from the relay's `.env` | |

## How the deploy handles them

The registry is `MANAGED_HOST_FILES` in `scripts/deploy.sh`, one entry per file:

```text
"<src in checkout>|<dst>|<mode>|<owner:group>|<class>|<role>[|<opts>]"
```

`role` is `main` or `relay`: a host only ever sees the entries of its own role. `opts` is
optional: `gate=<PROTO>` makes the entry exist only while `<PROTO>_ENABLED` is on in `.env`,
`when=<path>` only on a host where `<path>` exists, and `legacy=<path>` names an older name of the
same file. A closed gate means the entry is neither installed nor checked.

| class | Phase 1 validates the candidate with | Phase 2, after an actual change |
|---|---|---|
| `logrotate` | `logrotate -d` — no `^error` line | — |
| `sysctl` | every key exists under `/proc/sys` (an nf_conntrack / mptcp key whose module is not loaded only warns) | `sysctl -e -p <file>` |
| `unit` | `systemd-analyze verify` (advisory, same fatal patterns as for `vpn-bot.service`); a drop-in: `[Section]` structure | `daemon-reload`; a `*.timer` is `enable --now`'ed if it was enabled or did not exist. Services are never started or restarted |
| `journald` | a `[Journal]` section | `systemctl restart systemd-journald` |
| `networkd` | a `[Network]` section | — (takes effect at networkd's next start) |
| `hook` | `<candidate> --dry-run` exits 0 | — |
| `ssh` | `sshd -t` on `sshd_config` with the candidate swapped into a copy of its drop-in directory; a socket drop-in must leave a `ListenStream` port | see [below](#allow_ssh_change-and-the-lockout-risk) |
| `absent` | nothing may still name it (below) | `disable --now` if it is a unit file, then removed |

**Phase 1** (read-only, also under `PHASE1_ONLY=1`) scans every entry against `origin/main` and
reports a state per file: `synced`, `absent` (will be installed), `drift` (will be reinstalled —
the diff is printed), `meta` (content right, mode/owner wrong — fixed in place), `rename`,
`present` / `gone` (retired files), `gated-off`. It validates every candidate Phase 2 would
install and **stops before any mutation** when a validator refuses one, when a retired file is
still referenced, when a legacy-named file differs from the repo, or when an ssh file differs
without `ALLOW_SSH_CHANGE=1`.

**Phase 2** stages every path it may touch into the backup archive first, then installs,
repairs and removes, runs each class's post-action once for what actually changed, and rescans:
nothing may still be absent, drifted or present. Any failure takes the normal rollback, which
puts every staged file back — or removes it again when it did not exist — and re-applies the
restored state: unit enablement, the previous runtime sysctl values, journald, ssh.

**Retired files are guarded.** Before removing one, Phase 1 searches root's crontab and every
other file under `/var/spool/cron`, `/etc/crontab`, `/etc/cron.d`, the unit directories
`/etc/systemd/system` and `/usr/lib/systemd/system` (drop-ins included) and `.env` for the path
or its basename. A hit **fails** the deploy and names the file and line: remove the reference
first, or drop the retirement.

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
