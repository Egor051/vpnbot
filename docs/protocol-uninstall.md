# Removing a protocol from the server

**Protocol modules** in the admin panel offers two ways to switch a protocol off:

| Button | In the bot | On the server |
|---|---|---|
| **Disable only** | every client's access is revoked on the backend; Xray/AWG/Hysteria2 keys are deleted from the database (traffic archived), SOCKS5/MTProto proxy accesses are marked deleted (the rows stay); the module is switched off | the service, configs, binaries, units and firewall rules stay — **Enable** brings the protocol back |
| **Disable and remove from the server** | the same purge first | then the root helper `deploy/helpers/vpn-bot-protocol-uninstall` removes what its manifest names for the protocol — and nothing else |

A module that is already switched off (AWG and MTProto on the main server) gets a
**🗑 Remove from the server** button of its own: switching off never removed anything
from the host.

## The flow

1. **Plan.** The bot runs `vpn-bot-protocol-uninstall plan <proto>` (read-only) and
   shows: the units and what happens to each (stop / disable / mask), the files and
   directories with sizes, the packages, the users, what is **kept as
   shared** and why, what is **already absent**, the backup path. For Xray the bot
   adds a warning when relays exist — their VLESS keys stop working.
2. **Confirm.** The button carries the first 12 characters of the plan's sha256; an
   old plan message can never apply a newer plan nobody saw.
3. **Apply.**
   1. The helper plan is recomputed; a different sha256 (the host changed) is refused
      and the new plan is shown for a fresh confirmation.
   2. The existing per-client purge (`disable_protocol`). **If any record could not be
      revoked, nothing is removed from the server** — those clients may still be live.
   3. Backup of everything about to change (files, directories, unit files, drop-ins,
      enable/mask links, `.env`, conffiles of a purged package) plus `ufw status
      numbered`, `ufw show added`, the `getent` lines of the users to delete and the
      mangle table (Hysteria2), in `/var/backups/vpn-bot/uninstall/<proto>-<UTC
      ts>.tar.gz` (root 0600, directory 0700), checked with `tar -tzf`. No valid
      backup — nothing is touched.
   4. Units: stop → disable → (AWG: mask) → the manifest unit files and drop-ins →
      `daemon-reload` → `reset-failed`.
   5. Files and directories, one by one, each re-checked with `realpath` right before
      `rm` (a path or a parent that became a symlink stops the run).
   6. UFW: **nothing** — the helper never touches the firewall. `scripts/vpn-bot-ufw-apply`
      owns every rule ([host-state.md](host-state.md#the-firewall-ufw)): the marker of step 10
      takes the module out of its set, and the bot runs `vpn-bot-ufw-apply apply` right after
      a successful removal (its result is the last line of the report). One owner of the rules.
   7. `apt-get purge -y` of the manifest packages dpkg reports as `ii` (a purge that
      would drag other packages along is refused in the plan).
   8. `userdel` (never `-r`) of the manifest users, only when `find / -xdev -uid <uid>`
      finds nothing any more and no process runs as the user; otherwise the user is
      kept and the report says why.
   9. `.env`: `<PROTO>_ENABLED=false` for SOCKS5 / Hysteria2 / MTProto — exactly one
      line replaced (the last assignment) or appended, owner and mode kept.
   10. The marker `/etc/vpn-bot/uninstalled/<proto>` (JSON: ts, sha256, backup).

   A failure in steps 4–10 restores everything from the archive, reinstalls a purged
   package (`--force-confold`, so the restored conffile stays), recreates deleted
   users with their uid/gid and password hash, unmasks/re-enables/restarts the units
   that were enabled/active. The report says which step failed and whether the rollback was
   complete; UFW was never changed, so there is nothing of it to put back.
4. **Report**: removed / already absent / skipped / errors, the backup, the manual
   rollback command. A second apply on a removed protocol is "nothing to do".

Log: `/var/log/vpn-bot-uninstall.log`. Audit: `protocol_uninstalled`,
`protocol_uninstall_failed` (plan sha256, backup, step).

### What the plan hash covers

What the apply **decides**: which units, unit files, paths, packages and
users it acts on, the `.env` edit and the marker. Not: file sizes, active states,
the `*.bak` files inside a directory removed whole, the AWG files matched by the
pattern and the SOCKS5 users matched by prefix+shell — step 2 (the purge) creates
fresh backups and deletes exactly those users, by design.

## Manifests

Unit and path names `.env` can override are read by the helper itself (the same
tolerant reader as `scripts/vpnbot-hy2-warp-mark`), validated, and confined to the
protocol's prefix.

| Protocol | Units | Files and directories | Packages | Users | `.env` |
|---|---|---|---|---|---|
| Xray | `XRAY_SERVICE_NAME`.service, `@`.service + instances | `/etc/systemd/system/xray{,@}.service{,.d}`, `/usr/local/bin/xray`, `/usr/local/share/xray`, `/usr/local/etc/xray` (config, lock, every `.bak` with the REALITY key), `/var/log/xray` | — | — | — |
| AmneziaWG | `awg-quick@AWG_INTERFACE` (stop, disable, **mask**) | in `dirname(AWG_CONFIG_PATH)` only files matching `^\.?awg0\.conf(\.lock\|\..+\.bak\|\.bak\..+)?$` | — | — | — |
| SOCKS5 | `SOCKS5_SERVICE_NAME` | `/etc/systemd/system/<unit>.service.d/` | `dante-server` | prefix `SOCKS5_LOGIN_PREFIX` **and** shell `SOCKS5_SYSTEM_USER_SHELL` | `SOCKS5_ENABLED` |
| MTProto | `MTPROTO_SERVICE_NAME` | its unit file and `.service.d/`, `MTPROTO_BINARY_PATH`, `MTPROTO_CONFIG_DIR`, `/opt/vpn-service/scripts/run-mtproxy-managed` (untracked runtime copy; checked with `git ls-files`) | — | `mtproxy` | `MTPROTO_ENABLED` |
| Hysteria2 | `vpnbot-hy2-warp-mark` **first** (its ExecStop clears the fwmark rules; verified in the mangle table), `HYSTERIA2_SERVICE_NAME` + `@`, `HYSTERIA2_AUTH_SERVICE_NAME` | their unit files / drop-ins, `/usr/local/sbin/vpnbot-hy2-warp-mark`, `/usr/local/bin/hysteria`, `/etc/hysteria` | — | `hysteria` | `HYSTERIA2_ENABLED` |

The UFW rules of a protocol (its port, AWG's route rule of its clients) are no column here: they
are rows of the module table of `scripts/vpn-bot-ufw-apply`, computed from `.env`, and leave the
firewall with the marker.

The helper's own deny-list refuses, whatever a manifest says: `/`, `/etc`, `/usr`,
`/var`, `/etc/systemd/system`, `/etc/amnezia(/amneziawg)`, `/opt/vpn-service`, the
trees `/etc/nginx`, `/var/www`, `/etc/vpn-bot`, `/root`, `/home`, `/etc/ssh`,
`/etc/ufw`, `/etc/sysctl.d`, `/etc/letsencrypt`, the dpkg/apt state, anything named
`out-warp*` or `warp-*`; the units ssh, nginx, vpn-bot, systemd-*, warp-*,
awg-quick@out-warp; the users root, nobody, vpn-bot and every account outside the
dynamic system range 100–999. A file dpkg owns is skipped, as is a file tracked in
the repository.

## Deliberately NOT removed

| What | Why |
|---|---|
| user `nobody` | owns the Xray config and logs, but is a shared system account |
| nginx, `/etc/nginx`, `/var/www/anycastedge` | the REALITY self-steal / decoy site, shared with the host |
| `/etc/vpn-bot/tls`, `/root/.acme.sh`, `/usr/local/sbin/acme-reload.sh` | certificates and acme.sh also serve the subscription endpoint; the hook already skips the Hysteria2 copy without `/etc/hysteria` and the restart without the unit (pinned by `tests/test_deploy_uninstall_markers.py`) |
| `/etc/logrotate.d/xray` | installed by deploy.sh (`MANAGED_HOST_FILES`); `missingok`, inert without `/var/log/xray` |
| `/etc/amnezia`, `/etc/amnezia/amneziawg` (the directories) | they hold the WARP egress (`out-warp`) config too |
| `amneziawg/out-warp.conf` (symlink), `/etc/amnezia/out-warp*` | WARP egress, not the AWG server |
| `amneziawg*` packages, the kernel module, `awg`/`awg-quick` | `awg-quick@out-warp` needs them |
| `awg-quick@out-warp`, `warp-routes`, `vpn-bot-warp-routes` | WARP egress; `warp-routes` only `Wants=` the AWG unit, which stays **masked** so boot does not try to bring up an interface without a config; the routes helper passes without the awg0 client (skip-not-fail) |
| `/usr/lib/systemd/system/danted.service`, `/etc/danted.conf` | package files: removed by `apt-get purge dante-server`, not by hand |
| SOCKS5 users without the prefix or with another shell | not the bot's accounts |
| `/opt/vpn-service/scripts/vpnbot-hy2-warp-mark`, `/opt/vpn-service/deploy/run-mtproxy-managed` | tracked in the repository |
| the database, sshd, port 22 and the SSH port (`SSH_PORT`, default 54321), eth0, sysctl | global, never touched |

## After the removal

The marker is the source of truth. The bot reads it at start and after an apply:
startup reconcile, the Xray/AWG/Hysteria2 stats collectors, the Hysteria2 health
probe, the anomaly detector, the subscription composition and the protocol
availability skip the protocol; BackendHealth reports it as **UNINSTALLED** (never
degraded); **Enable** answers "the protocol was removed from the server; it has to
be reinstalled". `protocol_modules.uninstalled_*` mirrors the marker for the panel;
a mismatch at start is logged as a warning and the database follows the marker.

`scripts/deploy.sh` leaves the protocol's units out of `UNIT_SET` and the drift
scan, keeps its `MANAGED_HOST_FILES` gate shut (the danted drop-in is
`gate=SOCKS5`), skips its `OUT_OF_REPO_HELPERS` and `WARP_ONESHOTS` entries and
lists the removed protocols in the Phase 1 report.

## Manual rollback (runbook)

As root, from the backup named in the report (or the newest
`/var/backups/vpn-bot/uninstall/<proto>-*.tar.gz`):

```bash
A=/var/backups/vpn-bot/uninstall/<proto>-<ts>.tar.gz
tar -tzf "$A" | less                        # what is in it
tar -xzf "$A" -C /tmp vpn-bot-uninstall-meta # the metadata, next to nothing live
cat /tmp/vpn-bot-uninstall-meta/ROLLBACK.txt

# 1. files, unit files, drop-ins, enable links, .env — as they were
tar -xzf "$A" -C / --numeric-owner --preserve-permissions --xattrs --acls \
    --no-overwrite-dir --exclude=vpn-bot-uninstall-meta
# 2. a purged package (SOCKS5): the version is in packages.txt; the conffile is back already
apt-get install -y -o Dpkg::Options::=--force-confold dante-server=<version>
# 3. deleted users: getent-passwd.txt / getent-group.txt (uid, gid, home, shell)
groupadd -g <gid> <name>; useradd -u <uid> -g <gid> -d <home> -M -s <shell> <name>
# 4. units
systemctl unmask awg-quick@awg0.service      # AWG only
systemctl daemon-reload
systemctl enable --now <unit> ...            # units.txt says which were enabled/active
# 5. the bot: drop the marker and restart, then enable the module in the panel
rm -f /etc/vpn-bot/uninstalled/<proto>
systemctl restart vpn-bot
# 6. ufw: the module is in the set again — the protocol's rules come back by themselves
/usr/local/sbin/vpn-bot-ufw-apply apply
```

A **reinstall** without the archive works the same way at the end: install the
protocol by its own procedure, delete `/etc/vpn-bot/uninstalled/<proto>`, set
`<PROTO>_ENABLED=true` again where it has one, restart the bot, enable the module.

## Privileges

Both models. Root model (`PRIVILEGE_HELPERS_ENABLED=false`): the bot runs the
helper from its own checkout — the same code version as the bot, no installed copy
to drift. Helper mode: `sudo -n /usr/local/sbin/vpn-bot-protocol-uninstall`,
installed by `deploy/setup-nonroot-helper-mode.sh` and granted per protocol in
`deploy/sudoers.d/vpn-bot.example`. The helper re-enters PID 1's mount namespace
(`nsenter`) when it runs inside the bot's `ProtectSystem=strict` sandbox.
`PROTOCOL_UNINSTALL_HELPER_PATH` overrides the path in either model.
