# Installing on a fresh server

`scripts/install.sh` turns a fresh Ubuntu 24.04 VDS into a running bot with one command.
It asks two questions — the mode and the bot token — and everything after that happens
in Telegram.

🇷🇺 Russian version: [install.ru.md](install.ru.md)

## The one-liner

Download the installer and its checksum from the latest GitHub release, verify, run:

```bash
curl -fsSLO https://github.com/Egor051/vpnbot/releases/latest/download/install.sh && curl -fsSLO https://github.com/Egor051/vpnbot/releases/latest/download/SHA256SUMS && sha256sum -c --ignore-missing SHA256SUMS && sudo bash install.sh
```

Both files are attached to every `v*` release by `.github/workflows/release-installer.yml`.
The checksum catches a truncated or mixed-up download; it does not protect against a
compromised GitHub account (nothing served from the same place can). Never pipe a script
from a branch into bash (`curl … | bash`): what you run must be a released file you have
checked.

> The first release that contains the installer and the claim is the one after `v3.0.0`.
> Until it is published, `latest` has no `install.sh`. Take `scripts/install.sh` at a fixed
> commit instead (`https://raw.githubusercontent.com/Egor051/vpnbot/<commit>/scripts/install.sh`)
> and run it with `INSTALL_REF=<the same commit>`; the installer refuses any ref whose code
> has no claim support.

## What it asks

1. **Mode** — `1) main server` or `2) relay`. Relay is not part of this version: the
   installer says so and exits with code `2` having changed nothing on disk.
2. **Bot token** from [@BotFather](https://t.me/BotFather), typed hidden. It must look like
   `123456789:AA…` and Telegram must accept it (`getMe`); three attempts. The token never
   appears in a process argv (curl reads it from a config on stdin), in the install log or
   on the screen.

## What it does

Preconditions first, all read-only: root, Ubuntu 24.04, `x86_64` or `aarch64`, systemd as
init, ≥ 2 GiB free under `/opt`, and that `github.com`, `pypi.org` and the Bot API are
reachable.

Then, for the main server:

| Step | Result |
|---|---|
| apt | `git python3-venv ca-certificates curl`, and `qrencode` if available |
| checkout | `/opt/vpn-service` at the **latest release tag** (`INSTALL_REF` overrides) |
| venv | `/opt/vpn-service/.venv` from `constraints-hashed.txt` with `--require-hashes` |
| `.env` | from `.env.example`: the token, `ADMIN_IDS=` (empty), every `*_ENABLED=false`; `root:root 0600` |
| data, logs | `/opt/vpn-service/data`, `/opt/vpn-service/logs`, `0700` |
| helper | `/usr/local/sbin/vpn-bot-db-perms` (the unit's `ExecStartPre`) |
| unit | `deploy/vpn-bot.service` verbatim → `/etc/systemd/system/vpn-bot.service`, enabled |
| claim | `/etc/vpn-bot/claim.json`, see below |

The privilege model is the one of `deploy/vpn-bot.service` (root, Xray API mode); the
installer does not change it and creates no `vpn-bot` user (the root model needs none). No
protocol is installed or switched on: Xray, AmneziaWG, Hysteria2, SOCKS5 and MTProto are
all off, and the bot starts cleanly without any of them.

**Readiness** is real, not a timer: the installer remembers the byte size of `bot.log`
before the start and waits — at most 90 s — for aiogram's `Run polling for bot @…` line
after that offset. A failed unit or an extra restart ends the wait at once. Then it scans
the same range for `ERROR`, `CRITICAL` and `Traceback`; any of them fails the install.

Finally it prints the claim link and a QR code.

## The first superadmin (claim)

`ADMIN_IDS` stays empty. Instead the installer draws a 128-bit code and prints

```
https://t.me/<your_bot>?start=claim_<code>
```

plus the same link as a QR code. Open it in Telegram **from the account that should become
the superadmin** and press Start. That account is now the superadmin; continue in the admin
panel (`/admin`).

- `/etc/vpn-bot/claim.json` (root, `0600`) holds only `sha256(code)` and an expiry —
  **30 minutes**. The code itself is shown once on your terminal and stored nowhere.
- The link works once, in a private chat, and only while the bot has **no superadmin at
  all** — none in `ADMIN_IDS`, none claimed, no user with the SUPERADMIN role. On a server
  with `ADMIN_IDS` set the claim is completely inert, `claim.json` or not.
- A wrong, expired or used link gets one generic answer, with no reason. Attempts are rate
  limited (5 per user per hour, 20 per hour overall). The code never reaches a log.
- The effective superadmins are `ADMIN_IDS` ∪ the claimed users (table
  `claimed_superadmins`). The claimed superadmin gets every alert at once, without a
  restart.

Link expired, or lost? Issue a new one — this does nothing else:

```bash
sudo bash install.sh --reclaim
```

With neither `ADMIN_IDS` nor a claimed superadmin nor a pending claim, the bot logs a loud
`NO SUPERADMIN` warning at every start.

## Atomic: rollback by manifest

Every directory, file, replaced file and unit the installer creates is appended to a
manifest **before** it exists. Any failure — a failing command, Ctrl‑C, `SIGTERM` — rolls
back strictly by that manifest in reverse order: the unit is stopped and disabled, the
files and `/opt/vpn-service` are removed, replaced files are put back. apt packages are
never removed (they may have been installed before); the rollback only logs them.

The log and the manifest stay for reference:

```
/var/log/vpn-bot-install.<timestamp>.log        # token and claim code redacted
/var/log/vpn-bot-install.<timestamp>.manifest
```

Only one installer runs at a time (`flock` on `/run/vpn-bot-install.lock`), and it refuses
to run while a deploy (`vpn-bot-deploy.service`) is in progress.

## Running it again: repair

On a server that already has `/opt/vpn-service` with a `.env`, the installer is a
**repair**:

- `.env` and the database are never written (the superadmin check opens the database
  read-only);
- the db-perms helper and the unit are reinstalled from the checkout, the bot is
  restarted and checked exactly like after an install;
- a new claim link is issued only if there is still no superadmin.

A failed repair rolls back the files it replaced and restarts the bot with them.

## Environment knobs

| Variable | Meaning |
|---|---|
| `INSTALL_REF` | Tag or commit to install instead of the latest release. |
| `INSTALL_REPO` | Git URL to clone from (default: this GitHub repository). |
| `TELEGRAM_API_BASE` | Bot API server (default `https://api.telegram.org`). A non-default value is also written to `.env`, so the bot uses the same server. |
| `INSTALL_SELFTEST=1` | Test seam: define every function and return (`tests/test_install_script.py`). |
| `INSTALL_INJECT_FAILURE=<step>` | Test seam for the CI rollback check. Never set it on a real install. |

Exit codes: `0` done · `1` failed (and rolled back) · `2` relay mode chosen (not available yet).

## After the install

The bot runs and you administer it from Telegram. The installer intentionally does **not**
install backends or host hardening. For the full production host (protocol backends, UFW,
the host check, the SSH port) follow [deployment.md](deployment.md); later updates go
through `scripts/redeploy.sh`, which deploys `origin/main`.

## How it is tested

- `tests/test_install_script.py` drives every function through `INSTALL_SELFTEST` against
  stubbed host tools: token handling, `.env`, the claim file in exactly the format the bot
  reads, the manifest and the rollback, readiness, the read-only superadmin check.
- The `installer-e2e` CI job runs the whole installer as root on a real ubuntu-24.04 VM
  with systemd, against a mock Bot API (`tests/e2e/`): relay mode changes nothing; a
  failure injected after the bot started leaves no manifest path behind; a real install is
  active with `NRestarts=0`; `/start claim_<code>` makes the operator superadmin and a
  second claim is refused; a re-run is a repair that leaves `.env` and `vpn.db`
  byte-for-byte unchanged.
