# Production Operations Runbook

Operational procedures for running the bot in production: pre-deploy checks, health
checks, backup/restore, per-backend degraded recovery, rollback, and manual verification.

## Pre-deploy checklist

- `.env` exists, is not committed, and is readable only by the service operator/root.
- `DB_PATH` parent and `LOG_DIR` exist and are not world-readable.
- The installed systemd unit matches `deploy/vpn-bot.service`. In the default root+api configuration: `User=root`, `Group=root`, `ProtectSystem=false`, `RuntimeDirectory=vpn-bot`, `BOT_LOCK_PATH=/run/vpn-bot/vpn-bot.lock`.
- For root+api mode: `PRIVILEGE_HELPERS_ENABLED=false` (or absent), `XRAY_APPLY_MODE=api`, `XRAY_INBOUND_TAG` set, `XRAY_STATS_SERVER` pointing to the Xray API address. For non-root helper mode: `PRIVILEGE_HELPERS_ENABLED=true`, helper paths point to `/usr/local/sbin/vpn-bot-*`, and `/etc/sudoers.d/vpn-bot` validates with `visudo -cf`.
- `python deploy/check-nonroot-helper-mode.py` passes before the service restart (non-root mode).
- Xray config exists at `XRAY_CONFIG_PATH` and validates before the bot writes to it.
- AWG config/interface exist if AWG keys will be issued.
- Firewall rules are known before opening VPN ports.
- Backup destination exists and backup files are not world-readable.
- Code, deploy files, and `.venv` are not writable by `vpn-bot` or other untrusted users.
- If managed MTProto is enabled, `vpn-bot.service` does not have `ReadWritePaths=/etc/systemd/system`; the MTProxy wrapper/drop-in were installed manually and contain no raw secrets.
- If managed MTProto is enabled, `/etc/mtproxy/vpn-bot/managed-secrets.json`, `/etc/mtproxy/vpn-bot/mtproxy.env`, and `/etc/mtproxy/vpn-bot/backups/*` are readable only by root/service operators.

**Deploy entry point.** Deploy `origin/main` with the single wrapper — inspect first, then
deploy:

```bash
sudo CHECK=1 bash scripts/redeploy.sh    # read-only Phase 1 (PHASE1_ONLY=1) — read the report
sudo bash scripts/redeploy.sh            # deploy
```

`redeploy.sh` fetches `origin/main`, runs `deploy.sh` from tip-of-main detached under
systemd, and (in Phase 2) refreshes the out-of-repo `/usr/local/sbin` helpers automatically.
Run mutating deploys in a low-traffic window — see [Rollback after a bad
deploy](#rollback-after-a-bad-deploy) for why. Details in the [README Deploy
section](../README.md).

## General bot health check

```bash
cd /opt/vpn-service
python deploy/check-nonroot-helper-mode.py
sudo systemctl status vpn-bot --no-pager
sudo systemctl status vpn-bot-hy2-auth hysteria-server --no-pager  # if Hysteria2 is enabled
sudo journalctl -u vpn-bot -n 100 --no-pager
sqlite3 /opt/vpn-service/data/vpn.db "PRAGMA quick_check;"
.venv/bin/python -m compileall .
.venv/bin/python -m pytest
```

## Healthcheck tool — preflight, postflight, and admin diagnostics

> ⚠️ **Note:** `deploy/check-nonroot-helper-mode.py` is designed for the **non-root
> privilege-helper deployment model** (`User=vpn-bot` + `PRIVILEGE_HELPERS_ENABLED=true`). If
> you are running the **root+api mode** (`User=root` + `XRAY_APPLY_MODE=api`), this checker
> will report `FAIL: User=root` — that is expected and correct for root deployment. Skip this
> checker in root mode; use `systemctl status vpn-bot` and the bot's admin diagnostics panel
> instead.

`deploy/check-nonroot-helper-mode.py` is the **mandatory preflight and postflight** tool for
the non-root privilege-separated deployment. Run it before and after every deploy.

**Human-readable output (default):**

```bash
cd /opt/vpn-service
python deploy/check-nonroot-helper-mode.py
```

Exit codes:
- `0` — all checks passed (warnings are informational, not failures)
- `1` — one or more checks failed; address failures before starting or restarting the service

**Machine-readable JSON output (for automation/CI):**

```bash
python deploy/check-nonroot-helper-mode.py --json
```

JSON format: `{"overall": "ok|warning|failed", "failures": N, "warnings": N, "checks": [{"status": "ok|warning|failed", "message": "..."}]}`

**Pre-start mode (default — before `systemctl start vpn-bot`):**

```bash
python deploy/check-nonroot-helper-mode.py --mode pre-start
```

In `pre-start` mode, `/run/vpn-bot` absence is expected (systemd creates the
`RuntimeDirectory` when the service starts) and will produce a warning, not a failure.

**Post-start mode (after `systemctl start vpn-bot`):**

```bash
python deploy/check-nonroot-helper-mode.py --mode post-start
```

In `post-start` mode, `/run/vpn-bot` must exist and be writable by `vpn-bot`. Absence is a
failure.

**What the checker validates:**

- `vpn-bot.service` contains `User=vpn-bot`, `Group=vpn-bot`, `RuntimeDirectory=vpn-bot`, `RuntimeDirectoryMode=0700`, `ProtectSystem=strict`
- `vpn-bot.service` does not contain `User=root`, `Group=root`, `NoNewPrivileges=true`
- `/etc/sudoers.d/vpn-bot` is root:root 0440, grants the 4 fixed core helpers (and, when the WARP module is enabled, its `vpn-bot-warp-*` / `vpn-bot-warp-split-*` helpers), no broad grants (`NOPASSWD: ALL`, `ALL=(ALL)`)
- Helper binaries are root:root 0755
- `/opt/vpn-service`, `.venv`, `deploy` are not writable by `vpn-bot`
- `/run/vpn-bot` existence and writability (mode-dependent)
- `.env` is not world-readable and is readable by `vpn-bot`
- SQLite `PRAGMA quick_check`
- Xray config syntax test (`xray run -test -config`)
- AWG config strip (`awg-quick strip`)
- MTProxy managed files readable and structurally valid JSON
- `sudo -n <helper> status` calls succeed (verifies sudoers grants work end-to-end)
- `systemctl is-active` for: `vpn-bot`, `xray`, `awg-quick@awg0`, `danted`, `mtproxy`

**Admin diagnostics in the bot (on-demand):**

Open the admin panel in Telegram → *Диагностика backend*. This runs a live read-only health
check and shows:

```
Diagnostics  OK
2026-05-12 10:30:00 UTC

✓ Non-root OK (uid=1001)
✓ PRIVILEGE_HELPERS_ENABLED=true
✓ Xray: OK
✓ AWG: OK
✓ Hysteria2: OK        (shown when HYSTERIA2_ENABLED; data-plane liveness, never gates keys)
✓ SOCKS5: OK
✓ MTProto: OK
✓ SQLite PRAGMA quick_check: ok
✓ vpn-bot: active
✓ xray: active
✓ awg-quick@awg0: active
✓ vpn-bot-hy2-auth: active   (when Hysteria2 is enabled)
...
```

Overall status is `OK / WARNING / DEGRADED / FAILED`. Secrets, tokens, private keys, and raw
hex values are never shown — only the sanitised status and reason.

**Expected sudo log entries:**

When `PRIVILEGE_HELPERS_ENABLED=true`, every privileged operation (Xray/AWG config apply,
SOCKS5 user create/delete, MTProto secret apply) produces a sudo log entry like:

```
vpn-bot : TTY=... ; PWD=... ; USER=root ; COMMAND=/usr/local/sbin/vpn-bot-xray-apply apply ...
```

These entries are **expected and normal**. They confirm the least-privilege model is working
correctly.

**Signs that require rollback:**

- `FAIL: ... User=root` in checker output — the service is configured to run as root (expected and correct in root+api mode; only a failure in non-root helper mode)
- `FAIL: ... NOPASSWD: ALL` — broad sudo grant is present
- `FAIL: ... writable by vpn-bot` on code/venv/deploy directories
- SQLite `PRAGMA quick_check` returns anything other than `ok`
- Bot starts, issues one key, but Xray/AWG service is immediately DEGRADED with a config apply error
- `sudo -n <helper> status` returns permission errors — sudoers file is incorrect
- Any helper binary not root:root 0755 — must be fixed before the bot can use them

If rollback is needed, see [Rollback after a bad deploy](#rollback-after-a-bad-deploy) below.

## Deploy-gate sudoers audit: cloud-init `NOPASSWD: ALL` artifacts

`scripts/deploy.sh` audits the **whole** `/etc/sudoers.d/` directory during Phase 1
(`check_sudoers_dir`), not just `/etc/sudoers.d/vpn-bot`. Any *active* file that grants
`NOPASSWD: ALL` (or a generic shell/interpreter) is a hard failure that aborts the deploy:

```
[deploy][FAIL] /etc/sudoers.d/<file> contains a NOPASSWD: ALL grant
```

Files whose name contains a `.` or ends in `~` are inert (sudo ignores them) and downgrade to
a `WARN` instead — but one rename makes them live, so they are still flagged. Run the audit
read-only, without mutating anything, with `PHASE1_ONLY=1 sudo scripts/deploy.sh`.

**This is a correct finding, not a false positive. Do not relax the audit and do not
allowlist the offending file by name.**

### cloud-init writes `90-cloud-init-users`

On cloud-init–provisioned images, `/etc/sudoers.d/90-cloud-init-users` typically contains:

```
ubuntu ALL=(ALL) NOPASSWD:ALL
```

cloud-init **regenerates this file whenever its `users-groups` module runs at boot** — a
re-provision, or a first boot after the instance's cloud-init state is cleared. So even after
you delete it, a re-imaged/re-provisioned host brings it back: that is expected behaviour, not
a regression, and the audit will correctly fail again until the removal is re-applied. On a
static, long-lived VDS that is never re-imaged, the steps below make the removal stick.

### 1. Confirm the grant is inert before removing it

The `ubuntu` grant is only exploitable if someone can actually log in as `ubuntu`. Prove they
cannot:

```bash
# Password login must be locked ("L"). "P"/"NP" means a usable (or empty!) password.
sudo passwd -S ubuntu

# authorized_keys must be empty (0 bytes) or absent — no keys means key login can't succeed.
sudo stat -c '%s %n' /home/ubuntu/.ssh/authorized_keys 2>/dev/null || echo "no authorized_keys"

# sshd must not accept passwords and must not source keys from an unexpected location.
sudo sshd -T | grep -E '^(passwordauthentication|kbdinteractiveauthentication|challengeresponseauthentication|authorizedkeysfile|authorizedkeyscommand)\b'

# Shell (informational): a nologin/false shell is by itself proof no interactive login is possible.
getent passwd ubuntu
```

The grant is **inert** when *either* the account's shell is `nologin`/`false`, **or** all of
these hold together: password locked (`passwd -S` → `L`), `passwordauthentication no` and
keyboard-interactive/challenge-response off, `authorizedkeysfile` pointing only at the
empty/absent `~/.ssh/authorized_keys`, and no `authorizedkeyscommand` serving keys from
elsewhere. If any check fails (usable/empty password, non-empty `authorized_keys`, keys served
from another path, password auth on), treat the grant as **live** and revoke the login path
first (`sudo passwd -l ubuntu`, disable password auth, clear stray keys).

### 2. Remove the grant

The bot runs as root, so the `ubuntu` grant is unnecessary regardless of whether it is inert:

```bash
sudo rm -f /etc/sudoers.d/90-cloud-init-users
sudo visudo -c                          # remaining sudoers set still valid
PHASE1_ONLY=1 sudo scripts/deploy.sh    # audit is green again
```

### 3. Stop cloud-init from recreating it

**Preferred on a static, already-provisioned VDS — disable cloud-init entirely:**

```bash
sudo touch /etc/cloud/cloud-init.disabled
```

With that flag present cloud-init does nothing on subsequent boots, so it never rewrites
`90-cloud-init-users`. Trade-off: cloud-init then stops applying **any** boot-time config
(user/SSH-key seeding, network, mounts, growpart, etc.). For a host provisioned once long ago
and now managed by hand, that is the desired posture — cloud-init has no remaining job to do,
and freezing it removes a whole class of boot-time surprises. Do **not** set this flag on a
host that is re-imaged, autoscaled, or relies on cloud-init for network/SSH seeding.

**If you must keep cloud-init but stop only its user/sudo writes**, add a drop-in instead of
the global kill switch:

```bash
sudo tee /etc/cloud/cloud.cfg.d/99-no-users-sudo.cfg >/dev/null <<'EOF'
# Keep cloud-init active, but stop it managing users and re-writing the
# `ubuntu` NOPASSWD sudoers grant in /etc/sudoers.d/90-cloud-init-users.
users: []
disable_root: true
EOF
```

`users: []` leaves the existing `ubuntu` account untouched but tells cloud-init not to manage
any user, so the `users-groups` module no longer emits the sudoers file. (This also stops
cloud-init seeding SSH keys for cloud users — fine on a hand-managed host.) Re-run
`PHASE1_ONLY=1 sudo scripts/deploy.sh` after either change and, if practical, reboot once to
confirm the file does not come back.

> **Planned deploy-gate improvement (separate work).** A future change may make the audit
> *semantic* rather than pattern-only: a `NOPASSWD: ALL` grant is treated as safe **only** when
> the target user provably cannot log in interactively (nologin/false shell, **or** locked
> password **and** empty/absent `authorized_keys` **and** password auth off); any such grant for
> a user who *can* log in stays a hard failure. That is intentionally a deliberate, separate PR —
> not a shortcut to unblock a single deploy. Until it lands, remove the grant on the host as above.

## Maintenance mode (bot lockdown)

A superadmin can put the whole bot into maintenance from the admin panel (🛠 *Maintenance mode* → enable). While it is on, `MaintenanceModeMiddleware` drops every incoming update from non-superadmins and replies with the maintenance banner; only the superadmins in `ADMIN_IDS` keep full access. The state is persisted in the `maintenance_settings` table, so it **survives a bot restart** — turn it off from the panel when you are done. Use it as a bot-level lockdown for safe DB or backend edits; it is independent of the systemd unit and of backend DEGRADED state (which gates a single backend rather than the whole bot).

## Server status panel

The admin panel's server-status view shows a real-time snapshot (CPU, disk, network, online clients). A superadmin toggle enables the detailed view; the choice is persisted in `server_status_settings.detailed_enabled`. It is a read-only observability panel and never changes backend state.

## Anomaly detection: IP-to-ASN database

The anomaly detector flags a key when it sees too many **distinct networks** in the window (`ANOMALY_UNIQUE_NETS`). To turn a source IP into a network it uses a local copy of the iptoasn IPv4→ASN table at `/opt/vpn-service/data/ip2asn-v4.tsv` (override with `IP2ASN_DB_PATH`). Lookups are an in-memory `bisect`, so the detector never makes a network call. If the file is missing the detector still works — it falls back to `/24` grouping — but ASN grouping is more precise, so keep the file present and fresh.

Refresh it with the shipped units (runs unprivileged as `vpn-bot`, writes only `/opt/vpn-service/data`):

```bash
# One-off refresh (safe to run by hand):
sudo -u vpn-bot /opt/vpn-service/deploy/update-ip2asn.sh

# Install + enable the daily timer:
install -m 0644 /opt/vpn-service/deploy/vpn-bot-ip2asn.service /etc/systemd/system/
install -m 0644 /opt/vpn-service/deploy/vpn-bot-ip2asn.timer   /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now vpn-bot-ip2asn.timer
systemctl list-timers vpn-bot-ip2asn.timer   # confirm the next run
```

`update-ip2asn.sh` downloads to a temp file, validates it (≥100k rows, first/last row parse), and only then atomically renames it into place — any failure leaves the existing database untouched. The cache picks up the new file automatically (it watches the file's mtime/size), so no bot restart is needed.

## Backup

Back up at least these files before deploys, migrations, and manual backend edits:

```bash
sudo install -m 700 -d /root/vpn-service-backups
sudo tar --xattrs --acls -czf /root/vpn-service-backups/vpn-service-$(date -u +%Y%m%dT%H%M%SZ).tar.gz \
  /opt/vpn-service/.env \
  /opt/vpn-service/data/vpn.db \
  /usr/local/etc/xray/config.json \
  /etc/amnezia/amneziawg/awg0.conf \
  /etc/hysteria/config.yaml \
  /etc/mtproxy
sudo chmod 600 /root/vpn-service-backups/vpn-service-*.tar.gz
```

When Hysteria2 is enabled, keep `/etc/hysteria/config.yaml` in the list — it holds the
irreplaceable salamander/TLS/trafficStats secrets (the same file the off-site recovery
bundle preserves); drop the line on deployments without Hysteria2 so `tar` does not warn about
a missing path. Include `/opt/vpn-service/logs` only if operational logs are needed for incident
analysis.
Treat all backups as sensitive because they can contain Telegram tokens, VPN keys, Xray
UUIDs, AWG private/preshared keys, and server endpoints.

## Restore

```bash
sudo systemctl stop vpn-bot
sudo tar -xzf /root/vpn-service-backups/<backup>.tar.gz -C /
sudo xray run -test -config /usr/local/etc/xray/config.json
sudo awg-quick strip /etc/amnezia/amneziawg/awg0.conf >/dev/null
cd /opt/vpn-service
sudo install -o vpn-bot -g vpn-bot -m 0700 -d /opt/vpn-service/data /opt/vpn-service/logs
sudo chown -R vpn-bot:vpn-bot /opt/vpn-service/data /opt/vpn-service/logs
python deploy/check-nonroot-helper-mode.py
sudo systemctl start vpn-bot
sudo systemctl status vpn-bot
sudo journalctl -u vpn-bot -n 100 --no-pager
```

If `awg-quick` is unavailable but `wg-quick` is the intended tool on the server, run the
equivalent `wg-quick strip` check. Do not run `awg set`, `wg set`, `systemctl restart xray`,
or runtime-changing commands during restore validation until the config files have passed
read-only checks.

## Off-site backup coverage and recovery bundle

The scheduled off-site backup (`OFFSITE_BACKUP_ENCRYPTION_KEY`) delivers two encrypted
documents to admins via Telegram:

- `vpnbot_backup_*.db.enc` — full SQLite snapshot (users, keys, proxy accesses, traffic stats, settings). Per-client data is re-applied into the live configs on startup.
- `vpnbot_recovery_*.tar.gz.enc` — the **recovery bundle** (when `OFFSITE_BACKUP_INCLUDE_CONFIGS=true`): `.env`, Xray `config.json` (REALITY private key + shortIds), AWG `.conf` (interface private key), managed MTProto secrets, the WARP config, and (when Hysteria2 is enabled) the hysteria-server `config.yaml`. These are the irreplaceable server-side secrets that are **not** in the DB — without them a rebuilt server issues new keypairs and breaks every already-issued client. Unreadable/missing files are skipped and recorded in the bundle's `MANIFEST.json`.

To restore from the bundle on a clean server:

```bash
# Decrypt (KEY = OFFSITE_BACKUP_ENCRYPTION_KEY, stored OUTSIDE the bundle):
python -c "from cryptography.fernet import Fernet; open('recovery.tar.gz','wb').write(Fernet(b'KEY').decrypt(open('vpnbot_recovery_*.tar.gz.enc','rb').read()))"
tar xzf recovery.tar.gz            # MANIFEST.json lists each file's original absolute path
# Place each file back at its MANIFEST path, restore the .db.enc snapshot, validate
# configs (see Restore above), then start vpn-bot so startup reconciliation runs.
```

Because the bundle contains `.env` (which itself holds `OFFSITE_BACKUP_ENCRYPTION_KEY`), keep
the key in a separate secret store — otherwise the bundle cannot be decrypted.

## Firewall and exposed ports

- Keep SSH open only from trusted sources where possible.
- Open the public Xray TCP port, usually `443/tcp`.
- Open the public AWG endpoint UDP port from `AWG_ENDPOINT_PORT` or the AWG config `ListenPort`.
- If Hysteria2 is enabled, open the public Hysteria2 **UDP** port from `HYSTERIA2_PORT` (default `15650`). Keep the `hy2_auth` endpoint (`HYSTERIA2_AUTH_LISTEN`) and the Traffic Stats API (`HYSTERIA2_STATS_LISTEN`) bound to loopback only — never expose them to the internet.
- Open Dante/SOCKS only if a separate proxy is intentionally deployed and protected.
- Keep `XRAY_STATS_SERVER` bound to localhost only, for example `127.0.0.1:<port>`. Never expose the Xray stats API to the internet.
- If UFW default routed policy is `deny`, explicitly allow routed traffic required by AWG clients.

Example read-only checks:

```bash
sudo ufw status verbose
sudo ss -tulnp
```

## Read-only health checks

```bash
sudo systemctl status vpn-bot --no-pager
sudo systemctl status xray --no-pager
sudo systemctl status danted --no-pager
sudo ss -tlnp | grep 31337
sudo systemctl status mtproxy --no-pager
sudo ss -tlnp | grep 8443
sudo systemctl status hysteria-server vpn-bot-hy2-auth --no-pager   # if Hysteria2 is enabled
sudo ss -ulnp | grep 15650                                          # public Hysteria2 UDP port
curl -s http://127.0.0.1:8444/healthz                               # hy2_auth liveness (loopback)
sudo journalctl -u vpn-bot -n 100 --no-pager
sudo xray run -test -config /usr/local/etc/xray/config.json
sudo awg show
sudo awg-quick strip /etc/amnezia/amneziawg/awg0.conf >/dev/null
sqlite3 /opt/vpn-service/data/vpn.db "PRAGMA quick_check; SELECT status, key_type, COUNT(*) FROM vpn_keys GROUP BY status, key_type;"
```

If `XRAY_STATS_SERVER` is configured locally, query it only from the server or localhost.
Confirm that bot DB status, Xray config clients, AWG config peers, and AWG runtime peers agree
after create/revoke/delete operations.

## Degraded recovery

The bot marks a backend DEGRADED when reconciliation or post-apply compensation cannot prove
that SQLite and the server runtime are safe to mutate automatically. DEGRADED is
backend-specific — other backends keep working unless they are also DEGRADED.

### Xray degraded recovery

Xray DEGRADED blocks only Xray create/revoke/delete/manual reconcile. AWG, SOCKS5, and MTProto
continue unless separately degraded.

```bash
sudo systemctl status xray --no-pager
sudo xray run -test -config /usr/local/etc/xray/config.json
sudo jq '[.inbounds[]?.settings.clients[]? | {email}]' /usr/local/etc/xray/config.json
sqlite3 /opt/vpn-service/data/vpn.db "SELECT status, key_type, COUNT(*) FROM vpn_keys WHERE key_type='xray' GROUP BY status, key_type;"
sudo journalctl -u vpn-bot -n 150 --no-pager
```

Check for manual clients/orphans, failed pending statuses, and config syntax errors. Restore
from backup or remove only confirmed bot-managed drift, then restart `vpn-bot` and re-open
admin backend diagnostics.

### AWG degraded recovery

AWG DEGRADED blocks only AWG create/revoke/delete/manual reconcile. Xray, SOCKS5, and MTProto
continue unless separately degraded.

```bash
sudo systemctl status awg-quick@awg0 --no-pager
sudo awg show
sudo awk '/^# vpn-bot key_id=|^PublicKey =|^AllowedIPs =/{print}' /etc/amnezia/amneziawg/awg0.conf
sqlite3 /opt/vpn-service/data/vpn.db "SELECT status, key_type, COUNT(*) FROM vpn_keys WHERE key_type='awg' GROUP BY status, key_type;"
sudo journalctl -u vpn-bot -n 150 --no-pager
```

Do not print AWG private keys or preshared keys into tickets/chat. Compare public keys/client
IPs only, fix confirmed drift from backup or manual state, then restart `vpn-bot`.

### SOCKS5 degraded recovery

SOCKS5 DEGRADED blocks only SOCKS5 issue/revoke/delete. Xray, AWG, and MTProto continue unless
separately degraded.

```bash
sudo systemctl status danted --no-pager
getent passwd | awk -F: '$1 ~ /^vpn_socks_/ {print $1}'
sqlite3 /opt/vpn-service/data/vpn.db "SELECT status, access_type, COUNT(*) FROM proxy_accesses WHERE access_type='socks5' GROUP BY status, access_type;"
sudo journalctl -u vpn-bot -n 150 --no-pager
```

Check that every managed Linux user starts with `SOCKS5_LOGIN_PREFIX`; do not print SOCKS5
passwords. Lock/delete only confirmed bot-managed stray users, restore SQLite from backup if
needed, then restart `vpn-bot`.

### MTProto degraded recovery

MTProto DEGRADED blocks only MTProto issue/revoke/delete. Xray, AWG, and SOCKS5 continue unless
separately degraded.

```bash
sudo systemctl status mtproxy --no-pager
sudo jq '{secret_count: (.secrets | length), fingerprints: [.secrets[]?.fingerprint]}' /etc/mtproxy/vpn-bot/managed-secrets.json
sqlite3 /opt/vpn-service/data/vpn.db "SELECT status, access_type, COUNT(*) FROM proxy_accesses WHERE access_type='mtproto' GROUP BY status, access_type;"
sudo journalctl -u vpn-bot -n 150 --no-pager
```

Do not print raw MTProto secrets. In static mode, per-user server-side revoke is impossible;
rotate `MTPROTO_SECRET` if a copied shared secret must be invalidated. In managed mode, compare
counts/fingerprints, restore managed files from `/etc/mtproxy/vpn-bot/backups` if needed, restart
`mtproxy`, then restart `vpn-bot`.

### Hysteria2 backend health & recovery

Unlike Xray/AWG/SOCKS5/MTProto, a Hysteria2 `DEGRADED` mark is **informational only and never
blocks** issuing or revoking keys — Hysteria2 issuance/revocation are pure `vpn.db` writes with no
apply step, so there is nothing to gate. The `Hysteria2: OK/DEGRADED` entry reflects **data-plane
liveness** only: a background loop polls the `hy2_auth` `GET /healthz` endpoint every
`HYSTERIA2_HEALTH_INTERVAL` seconds. `DEGRADED` therefore means "the handshake-auth data plane is
unreachable", i.e. new handshakes are being rejected even though the bot's key rows are intact.

```bash
sudo systemctl status vpn-bot-hy2-auth --no-pager        # the loopback handshake-auth endpoint
sudo systemctl status hysteria-server --no-pager         # the Hysteria2 data plane itself
curl -s http://127.0.0.1:8444/healthz                    # 200 {"ok":true} when vpn.db is readable
sudo journalctl -u vpn-bot-hy2-auth -n 100 --no-pager    # DB faults are logged at ERROR here
sqlite3 /opt/vpn-service/data/vpn.db "SELECT status, COUNT(*) FROM vpn_keys WHERE key_type='hysteria2' GROUP BY status;"
```

Recovery is service-level, not config reconciliation: bring `vpn-bot-hy2-auth` (and, if needed,
`hysteria-server`) back to active — the endpoint reads the **live** database, so once it is
healthy again revokes/issues already reflect on the next handshake with no data-plane restart. If
`GET /healthz` returns `503`, the endpoint cannot read `vpn.db` (locked/corrupt or a missing WAL
`ReadWritePaths` grant — see [Deployment → Hysteria2 data plane](deployment.md#hysteria2-data-plane-hy2_auth-endpoint));
fix the database access first. Per-key traffic, the online count and revoke-`/kick` additionally
require the Traffic Stats API (`HYSTERIA2_STATS_SECRET`); when it is unset those stay blank but do
not affect handshake auth or the health entry.

## Rollback after a bad deploy

> ⚠️ **Back up first.** Always create a backup before rolling back code (see [Backup](#backup)).
> A code rollback does not roll back runtime state — SQLite, Xray config, and AWG config need
> separate restoration if the deploy already modified them.

> **Automated deploys (`scripts/redeploy.sh` → `scripts/deploy.sh`).** The deploy script rolls
> back automatically on a failed assertion, restoring code, venv, DB, configs, and the unit.
> Two things to know: it restores the DB snapshot taken *before* the new code started, so
> writes made while the new bot was live during the post-start health-check window are
> discarded; and it only performs a same-privilege-model deploy (a model switch is gated behind
> `ALLOW_MODEL_SWITCH=1` and a prior host migration — see the Deploy section in the
> [README](../README.md)). The manual steps below are for a hand-rollback when you are not
> using the script.

> ⏱️ **Rollback loses the health-poll data window — deploy mutating changes at low traffic.**
> Rollback restores the DB from the backup snapshot taken *before* the mutation. But the new
> bot is started and then health-polled for up to `HEALTH_TIMEOUT` (**~60 s** by default)
> before the deploy is verified. Any rows the new bot writes *inside that window* — a key
> issued, a payment recorded, a config handed out in that minute — are **not** in the
> pre-mutation snapshot, so a rollback **discards them**: the key issued in that minute simply
> vanishes. The window is short but not zero. The rule that follows: **run any mutating deploy
> in a low-traffic window**, so that if it does roll back, no freshly issued key or record is
> lost. (`scripts/redeploy.sh` with `CHECK=1` / `PHASE1_ONLY=1` is read-only and has no such
> window — only the real Phase 2 deploy does.)

**Step 1 — stop the service and back up runtime state:**

```bash
sudo systemctl stop vpn-bot
sudo tar --xattrs --acls -czf /root/vpn-service-backups/pre-rollback-$(date -u +%Y%m%dT%H%M%SZ).tar.gz \
  /opt/vpn-service/.env \
  /opt/vpn-service/data/vpn.db \
  /usr/local/etc/xray/config.json \
  /etc/amnezia/amneziawg/awg0.conf
sudo chmod 600 /root/vpn-service-backups/pre-rollback-*.tar.gz
```

**Step 2 — roll back the code:**

```bash
cd /opt/vpn-service
git log --oneline -5
git reset --hard <previous_commit>
.venv/bin/pip install -r requirements.txt -c constraints.txt
```

`git reset --hard` discards all local code changes on the server. Only use it when rolling
back an unwanted deploy.

> **`init_db.py` is for fresh installs only.** Do NOT run `init_db.py` during rollback — it
> requires `BOT_TOKEN`/`ADMIN_IDS` and will attempt forward migrations on the existing
> database. The bot bootstraps the schema on startup; if the previous version is
> schema-compatible, simply restarting the service is sufficient.

**Step 3 — restore runtime state from backup if the failed deploy modified it:**

```bash
# Restore SQLite DB if the failed deploy changed DB schema or data
sudo cp /root/vpn-service-backups/<backup>.tar.gz /tmp/
sudo tar -xzf /tmp/<backup>.tar.gz -C / opt/vpn-service/data/vpn.db

# Restore Xray config if changed
sudo tar -xzf /tmp/<backup>.tar.gz -C / usr/local/etc/xray/config.json
sudo xray run -test -config /usr/local/etc/xray/config.json

# Restore AWG config if changed
sudo tar -xzf /tmp/<backup>.tar.gz -C / etc/amnezia/amneziawg/awg0.conf
```

**Step 4 — restart and verify:**

```bash
sudo systemctl start vpn-bot
sudo systemctl status vpn-bot
sudo journalctl -u vpn-bot -n 100 --no-pager
```

## Maintenance — update from GitHub

```bash
cd /opt/vpn-service
sudo git pull --ff-only
sudo /opt/vpn-service/.venv/bin/pip install -r requirements.txt -c constraints.txt
python deploy/check-nonroot-helper-mode.py
sudo systemctl restart vpn-bot
python deploy/check-nonroot-helper-mode.py
```

**Managed MTProto: refresh the wrapper after every update.** The pull above updates
the tracked source `deploy/run-mtproxy-managed`, but the wrapper that systemd actually
runs is the installed runtime copy at `/opt/vpn-service/scripts/run-mtproxy-managed`
(`MTPROTO_MANAGED_WRAPPER_PATH`). That path is a gitignored install artifact: neither
`git pull`/`git reset` nor `scripts/deploy.sh` (which installs only `vpn-bot.service`)
refreshes it, so an updated wrapper — including security fixes such as the env-key
allowlist and port validation — does not reach the running proxy until you re-install
it explicitly. Skip this step and the proxy keeps running a stale wrapper.

```bash
# Refresh the managed-MTProto wrapper from its updated tracked source (root:root 0700).
sudo install -m 700 -o root -g root \
  deploy/run-mtproxy-managed /opt/vpn-service/scripts/run-mtproxy-managed
sudo systemctl restart mtproxy
sudo systemctl status mtproxy --no-pager
# Confirm the runtime copy now matches the source, and the tree stays clean:
sudo cmp deploy/run-mtproxy-managed /opt/vpn-service/scripts/run-mtproxy-managed \
  && echo "wrapper up to date"
git status --porcelain   # scripts/run-mtproxy-managed is gitignored -> not listed
```

Do not run production DB migrations as root against `/opt/vpn-service/data/vpn.db`. The
service bootstraps schema/migrations on startup as `vpn-bot`; if you must run `init_db.py`
manually, run it with the same non-root identity and environment as the service.

## Manual VDS verification after fixes

On a staging user before production use:

1. Create one Xray key, verify it is active in DB and present in Xray config.
2. Revoke and delete the Xray key, verify DB/config/runtime no longer allow access.
3. Create one AWG key, verify DB, `awg0.conf`, and `awg show` agree.
4. Revoke and delete the AWG key, verify peer removal from config and runtime.
5. (Hysteria2, when `HYSTERIA2_ENABLED`) Create one Hysteria2 key, verify it is active in DB (`key_type='hysteria2'`) and that a fresh client handshake authenticates — the accepted handshake is logged in `journalctl -u vpn-bot-hy2-auth`.
6. Revoke the Hysteria2 key and confirm the next handshake is rejected with **no data-plane restart** (the `hy2_auth` endpoint reads the live DB). With the Traffic Stats API enabled (`HYSTERIA2_STATS_SECRET`), confirm the already-live session is also torn down by the best-effort `/kick`.
7. Open "Прокси" as an approved test user, issue SOCKS5 after confirmation, and verify the message contains Host, Port, Login, Password, and URL.
8. Issue MTProto after confirmation and verify the plain Telegram link appears before the `dd` link.
9. In `MTPROTO_MODE=managed`, issue MTProto for test user A and record only the non-secret fingerprint/count from admin status.
10. Issue MTProto for test user B and confirm admin status shows two active managed MTProto accesses.
11. Hard-block or admin-revoke test user A, then confirm the managed secrets file no longer contains A's fingerprint while B's fingerprint remains active.
12. Confirm user B's Telegram MTProto link still works after user A is revoked.
13. Simulate a failed apply on staging, for example by temporarily pointing `MTPROTO_SERVICE_NAME` to a failing test unit or stopping the listener check path, then revoke/issue and confirm rollback restores the previous managed secrets/env files and `mtproxy` returns to active/listening.
14. In `MTPROTO_MODE=static`, block the user and confirm MTProto is deactivated only in SQLite.
15. Check that bot logs and audit output do not contain SOCKS5 passwords, `MTPROTO_SECRET`, or managed raw MTProto secrets.
16. Check `systemctl cat mtproxy`, `systemctl show mtproxy -p User -p Group -p ExecStart -p Environment`, and `journalctl -u mtproxy -n 100 --no-pager` for absence of raw MTProto secrets.
17. Check managed file permissions:
    ```bash
    sudo stat -c '%U:%G %a %n' /opt/vpn-service/scripts/run-mtproxy-managed /etc/mtproxy/vpn-bot/managed-secrets.json /etc/mtproxy/vpn-bot/mtproxy.env
    sudo find /etc/mtproxy/vpn-bot/backups -maxdepth 2 -printf '%u:%g %m %p\n'
    ```
18. Send an announcement with approved, pending, and blocked test users; only approved users and superadmins should receive it.
