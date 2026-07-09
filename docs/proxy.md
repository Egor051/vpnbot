# Proxy Backends (SOCKS5 / MTProto)

The bot does not install Dante or MTProxy. Prepare them on the VDS first, then enable the
relevant env flags (see [Configuration](configuration.md)).

## SOCKS5 / Dante

- Dante listens on the configured public host/port, for example `0.0.0.0:31337`.
- Authentication is Linux username/password.
- The bot process does not call account-management tools directly in production. It uses `sudo -n /usr/local/sbin/vpn-bot-socks5-user ...`; the helper is the only code allowed to call `getent`, `useradd`, `chpasswd`, `passwd -l`, and `userdel`.
- The bot refuses to manage Linux users whose login does not start with `SOCKS5_LOGIN_PREFIX`.

## MTProto static mode

- Set `MTPROTO_MODE=static` and provide `MTPROTO_SECRET`.
- MTProxy is managed outside the bot by its own systemd unit.
- The bot does not edit MTProxy files in static mode.
- User output always includes both Telegram links: plain secret first, then the `dd` random-padding variant.
- Static mode uses a shared secret; blocking one user only deactivates the bot record and does not revoke that user server-side.

## MTProto managed mode

- Set `MTPROTO_MODE=managed`; do not set a shared production secret in `MTPROTO_SECRET` for new users.
- MTProxy must already be installed and have valid `proxy-secret` and `proxy-multi.conf` files.
- Install the managed wrapper/drop-in once during deploy. The default model is the
  **root-wrapper** model: the wrapper runs as root. systemd starts the wrapper as root, the
  wrapper reads root-only managed env/secrets, and it starts `mtproto-proxy` with `-u mtproxy`
  from `MTPROTO_RUN_USER` so the proxy process drops privileges internally.
  ```bash
  sudo install -m 700 -d /opt/vpn-service/scripts
  sudo install -m 700 deploy/run-mtproxy-managed /opt/vpn-service/scripts/run-mtproxy-managed
  sudo install -m 700 -d /etc/systemd/system/mtproxy.service.d
  sudo install -m 600 deploy/mtproxy-vpn-bot-managed.conf /etc/systemd/system/mtproxy.service.d/vpn-bot-managed.conf
  sudo install -m 700 -d /etc/mtproxy/vpn-bot /etc/mtproxy/vpn-bot/backups
  sudo chown root:root /opt/vpn-service/scripts/run-mtproxy-managed /etc/mtproxy/vpn-bot /etc/mtproxy/vpn-bot/backups
  sudo /opt/vpn-service/.venv/bin/python - <<'PY'
  import json, secrets
  from pathlib import Path
  managed = Path("/etc/mtproxy/vpn-bot")
  placeholder = secrets.token_hex(16)
  (managed / "managed-secrets.json").write_text(json.dumps({
      "version": 1,
      "generation": 0,
      "managed_by": "vpn-bot",
      "secrets": [],
      "runtime_secrets": [{"secret": placeholder, "fingerprint": "empty-placeholder", "purpose": "empty-placeholder"}],
  }, indent=2, sort_keys=True) + "\n", encoding="utf-8")
  (managed / "mtproxy.env").write_text(
      "MTPROTO_BINARY_PATH=/usr/local/bin/mtproto-proxy\n"
      "MTPROTO_RUN_USER=mtproxy\n"
      "MTPROTO_RUN_GROUP=mtproxy\n"
      "MTPROTO_PROXY_SECRET_PATH=/etc/mtproxy/proxy-secret\n"
      "MTPROTO_PROXY_MULTI_CONF_PATH=/etc/mtproxy/proxy-multi.conf\n"
      "MTPROTO_MANAGED_SECRETS_PATH=/etc/mtproxy/vpn-bot/managed-secrets.json\n"
      "MTPROTO_PORT=8443\n"
      "MTPROTO_INTERNAL_STATS_PORT=8888\n"
      "MTPROTO_WORKERS=1\n",
      encoding="utf-8",
  )
  PY
  sudo chmod 600 /etc/mtproxy/vpn-bot/managed-secrets.json /etc/mtproxy/vpn-bot/mtproxy.env
  sudo chown root:root /etc/mtproxy/vpn-bot/managed-secrets.json /etc/mtproxy/vpn-bot/mtproxy.env
  sudo systemctl daemon-reload
  sudo systemctl restart mtproxy
  sudo systemctl status mtproxy --no-pager
  sudo ss -tlnp | grep 8443
  ```
- The drop-in clears any existing `User=`/`Group=` from `mtproxy.service`; `systemctl show mtproxy -p User -p Group -p ExecStart` should show empty `User`/`Group` and `ExecStart=/opt/vpn-service/scripts/run-mtproxy-managed`.
- If `MTPROTO_MANAGED_WRAPPER_PATH` or `MTPROTO_MANAGED_ENV_PATH` differs from the defaults, edit the installed wrapper/drop-in during deploy and run `systemctl daemon-reload` manually.
- Do not set `MTPROTO_MODE=managed` in `vpn-bot` until the placeholder managed baseline above has restarted successfully and `mtproxy` is active/listening. Bot issue/revoke refuses to proceed when `MTPROTO_MANAGED_SECRETS_PATH` or `MTPROTO_MANAGED_ENV_PATH` is missing, so the first helper apply always has known-good files to roll back to.
- At runtime the non-root bot stages MTProxy candidates under `/run/vpn-bot/mtproxy`. The `/usr/local/sbin/vpn-bot-mtproxy-apply` helper validates the staged files, writes `MTPROTO_MANAGED_SECRETS_PATH`, writes `MTPROTO_MANAGED_ENV_PATH`, maintains `MTPROTO_BACKUP_DIR/<backup-id>/`, restarts `mtproxy`, checks `systemctl is-active`, checks that `MTPROTO_PORT` is listening, and restores the previous managed files on apply failure.
- Normal issue/revoke does not write `/etc/systemd/system` and does not run `systemctl daemon-reload`; install or update the MTProxy unit/drop-in manually during deploy.
- Managed mode gives real per-user revoke by removing only that user's secret from the active MTProxy list. Other users' secrets remain in the managed file.
- Raw MTProto secrets are not shown in admin status, audit, logs, README, or `.env.example`; admin diagnostics use counts and fingerprints only.
- Managed secrets and env files are root:root `0600`; backup directories are root:root `0700`; backup files that may contain secrets are root:root `0600`; the wrapper is root:root `0700`; the systemd drop-in contains no secrets and can be root:root `0600`.

### MTProto managed mode visibility checks

- `systemctl cat mtproxy` and `systemctl show mtproxy -p User -p Group -p ExecStart -p Environment` should show only the wrapper/env paths, not raw secrets. In the default root-wrapper model, `User` and `Group` are empty at service level.
- `journalctl -u vpn-bot` and `journalctl -u mtproxy` should not contain raw MTProto secrets; the bot redacts audit/error details and the wrapper does not print secrets. If your MTProxy build logs accepted secrets or generated links, do not use managed mode until that logging is disabled or the binary is replaced.
- The official `mtproto-proxy` binary accepts client secrets as `-S <secret>` arguments. That means raw secrets can be visible in process argv to root, and to unprivileged users unless `/proc` is hardened. Restrict shell access, consider mounting `/proc` with `hidepid=2`, and do not enable managed mode with this binary if your requirement is "raw MTProto secrets are never visible to root-level process inspection".

### Manual rollback for managed MTProto

1. Stop `vpn-bot`.
2. Inspect `MTPROTO_BACKUP_DIR`, default `/etc/mtproxy/vpn-bot/backups`.
3. Restore the previous managed secrets/env files from the latest known-good backup if automatic rollback did not recover.
4. Run `sudo systemctl restart mtproxy`.
5. Check `sudo systemctl status mtproxy --no-pager` and `sudo ss -tlnp | grep 8443`.

## Proxy statistics

Proxy statistics are lifecycle/accounting stats from SQLite: issued, active,
revoked/deactivated, timestamps, status, reason, and error. The bot does not invent per-user
traffic for Dante or MTProxy. Without Dante per-login accounting or a safe aggregate MTProxy
stats endpoint, traffic is shown as unavailable.
