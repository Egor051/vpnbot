# The setup wizard and the TOTP second factor

The admin panel has two new sections, both **SUPERADMIN only**:

* **🧙 Мастер настройки** (setup wizard) — fixed, root-owned helper modes that run
  in their own systemd unit: a plan first, then apply → verify → rollback on failure.
* **🔐 Безопасность** (security) — the superadmin's TOTP second factor, asked before
  dangerous actions.

🇷🇺 Russian version: [wizard.ru.md](wizard.ru.md)

## What the bot can and cannot do

The bot never runs a command it was given and has no "shell" button. A mode is a fixed
set of helpers in [`scripts/wizard/`](../scripts/wizard/), installed to
`/usr/local/sbin` by `deploy.sh` (`OUT_OF_REPO_HELPERS`, policy `required`) and, on a
fresh host, by `scripts/install.sh` (`INSTALL_HELPERS`, the same files, rolled back with
the rest of a failed install):

| Installed helper | Role |
|---|---|
| `vpn-bot-wizard` | The only entry point the bot may call: `launch --mode M --run N --phase plan\|execute [--param k=v]...` |
| `vpn-bot-wizard-lib` | The shared library (mode table, status file, log, redaction, dead-man, backups) |
| `vpn-bot-wizard-selfcheck` | Mode «Самопроверка» |
| `vpn-bot-wizard-dump` | Mode «Диагностический дамп» |
| `vpn-bot-wizard-update` | Mode «Обновить бота» |
| `vpn-bot-wizard-cert` | Mode «Сертификат» (issue / renew / adopt / deploy through `vpn-bot-cert`, [certificate.md](certificate.md)) |
| `vpn-bot-wizard-protocol` | Mode «📦 Установка протокола» (plan / apply / verify / rollback of `vpn-bot-protocol-install`, [protocol-install.md](protocol-install.md)) |
| `vpn-bot-wizard-site` | Mode «🌐 Сайт» (plan / apply / verify / rollback of `vpn-bot-site`, the decoy site, [site.md](site.md)) |
| `vpn-bot-totp-reset` | The emergency TOTP reset (root CLI, never called by the bot) |

In the helper-nonroot model the bot reaches the launcher through one sudoers line
(`deploy/sudoers.d/vpn-bot.example`):

```
/usr/local/sbin/vpn-bot-wizard launch *
```

Run through sudo, the launcher inherits the bot's mount namespace — `ProtectSystem=strict`
in `deploy/vpn-bot.nonroot.example.service` makes `/run`, `/var/lib` and `/var/log`
read-only there — so `launch` first re-executes itself in PID 1's mount namespace
(`nsenter --mount=/proc/1/ns/mnt`), the same escape as `vpn-bot-ufw-apply`.

The launcher re-checks everything against its own table (`MODES` in
`vpn-bot-wizard-lib`): an unknown mode, a run id that is not a positive integer, an
unknown parameter, a value outside its type (integer range, `0`/`1`, enumeration) is
refused with exit 2 **before** anything runs. The bot validates the same parameters
first (`services/wizard_modes.py`); a test keeps the two tables identical.

## A run

1. The bot inserts a row into `wizard_runs` with `active = 1`. A UNIQUE index on
   `active` is the **global lock**: a second run cannot start while one is active
   (two quick taps cannot both win).
2. It asks the launcher to start a phase. The launcher refuses while any
   `vpn-bot-wizard-*` unit is active or `/run/vpn-bot-wizard.lock` is held, writes
   the first status line, then starts the phase **only** through
   `systemd-run --unit=vpn-bot-wizard-<id> --collect`. The run therefore survives a
   restart of the bot — which the `update` mode itself causes.
3. Inside the unit, `vpn-bot-wizard run` holds `/run/vpn-bot-wizard.lock` and drives
   the mode helper through its contract:

   | Phase | Steps | Outcome |
   |---|---|---|
   | `plan` | `<helper> plan` — a dry run that prints what would change | `planned` (waits for «✅ Применить» / «✖️ Отменить», 30 min) or `failed` |
   | `execute` | `<helper> apply`, then `<helper> verify`; on any failure `<helper> rollback` | `succeeded`, `rolled_back` or `failed` |

   A read-only mode skips the confirmation and goes straight to `execute`; its
   `rollback` only removes its own artifact and the run stays `failed`.
4. Progress is JSON lines in `/var/lib/vpn-bot-wizard/<id>.status` (root, 0644). The
   bot reads it every 3 s, edits **one** message with the progress, and turns it into
   the plan or the final report. The last line is always `{"event": "finished"}`; a
   unit that ended without it (killed) makes the run `failed`.
5. Every step's output goes, redacted, to `/var/log/vpn-bot-wizard/<id>.log`
   (root:vpn-bot 0640). «📄 Лог» sends it as a file (redacted again on the way out).

States in `wizard_runs.state`: `planned`, `running`, `verifying`, `succeeded`,
`rolled_back`, `failed`, and `cancelled` (a plan that was declined or expired).

### After a restart

At start the bot finds the active run, logs `Setup wizard: resuming run #N`, and
follows the status file and the unit to the end. The final report is sent exactly
once (`wizard_runs.reported_at`), also when the bot died between the end of the run
and the report. The monitor never writes a traceback to `bot.log`: it runs in the
very window in which `deploy.sh` scans the log after the restart it caused.

### History

«📜 История» lists the runs with their state; each run has its card, its log and —
for the dump — its file. Every action is in the audit log (entity `wizard`):
`wizard_run_started`, `wizard_plan_ready`, `wizard_run_confirmed`,
`wizard_run_finished`, `wizard_log_sent`, `wizard_schedule_changed`.

## The modes

### 🩺 Самопроверка (read-only)

Changes nothing. Each check is a green / yellow / red item:

| Check | Red | Yellow |
|---|---|---|
| `listeners` — `vpn-bot-ufw-apply listeners` | a public TCP listener the firewall set neither allows nor declares closed | no verdict / helper missing |
| `warp` — only when WARP is deployed (`WARP_CONFIG_PATH`, default `/etc/amnezia/out-warp.conf`, or `warp-routes` enabled); see [below](#the-warp-items-intent-against-fact) | WARP turned on but `out-warp` has no fwmark table; full tunnel without its default route | the split routes in table T do not match the intent |
| `warp:rule` — only while AWG is installed | no `ip rule from <AWG_NETWORK> lookup T` (selective / full tunnel) | the same with split off (harmless until it is turned on) |
| `warp:clients_nat` — only while AWG is installed and split is not off | no MASQUERADE/SNAT on `out-warp` for the client subnet: AWG clients leave into WARP without SNAT | nat table unreadable |
| `warp:egress` — per address xray (`sendThrough`) / danted (`external:`) send from | the address is not on an up `out-warp`; the probe leaves the wrong way; no SNAT for it on the WAN, or on `out-warp` for an address that is not the tunnel address | split off but it still leaves via `out-warp`; `WARP_PROXY_EGRESS` on and nobody bound to the tunnel address; the addresses, the WAN or the nat table unreadable |
| `failed_units` — `systemctl --failed` | any failed unit | — |
| `certs` — `vpn-bot-cert status --json` ([certificate.md](certificate.md#the-self-check)): the bot's acme.sh domain, every installed reader of the registry; one item `cert:<key>` per problem the helper reports. Without the helper (a host not deployed yet): every acme.sh certificate, `/etc/hysteria/cert.pem`, `SUBSCRIPTION_TLS_CERT` | < 7 days left (also on a reader's stale copy); reloadcmd neither `vpn-bot-cert deploy` nor the old hook; no acme.sh `--cron`; another domain copies over the registry's files | < 21 days left (acme.sh renews at 30); the old hook as reloadcmd (adopt it); a reader's copy differs from acme.sh's, or wrong owner/mode; acme.sh renews with another token |
| `helpers` — `OUT_OF_REPO_HELPERS` of this role vs the checkout | a `required` helper missing | an installed copy differs (the next deploy closes it) |
| `perms` — `DB_PATH` (0600) and its directory (0700), owner `vpn-bot` when it exists; `.env` root-owned, not world-accessible, not group-writable | any deviation | — |
| `disk` — `/`, `/var`, the checkout | < 1 GiB or < 5 % free | < 15 % free |
| `reboot` — `/var/run/reboot-required` | — | a reboot is required (with the packages) |
| `legacy_env` — the obsolete `RELAY_ENABLED` / `RELAY_NAME` / `RELAY_HOST` / `RELAY_SOURCE_IPS` in `.env` | — | they are still there: the bot does not read them (relays live in the database) — delete them ([relay.md](relay.md#the-obsolete-relay_-in-env)) |

Each item is shown in the reader's language: the helper writes `msg` and `args` next
to the English `text`, and the bot renders the i18n message `wizard_item_<msg>` with
them. `text` stays the log line and the fallback — a message the bot does not know,
or arguments that do not fill it, show the helper's English as before. The English
templates live in the helper (`MESSAGES`) and equal `i18n/en.py`; a test keeps the two
in step. Today the `warp` items use it; the other checks still write English only.

#### The `warp` items: intent against fact

The check looks for a **discrepancy between what the bot was told and what the kernel
routes**; it never demands one particular mode. Every source of intent is the one the
bot itself uses, read-only:

| Intent | Source |
|---|---|
| WARP on / off | `warp_settings.enabled` in `vpn.db` (`sqlite3` `mode=ro` — the bot owns the WAL; never written) |
| split off — **all direct** | the marker `WARP_SPLIT_DISABLED_MARKER_PATH` (default `/etc/vpn-bot/warp-split.disabled`), written by `vpn-bot-warp-split-state off` |
| split on — **selective** | no marker, a non-empty `WARP_SPLIT_LIST_PATH` (default `/etc/vpn-bot/warp-split.list`; IPv4, comments and `0.0.0.0/0` dropped, each network once) |
| **full tunnel** | no marker and no (or an empty) list: `vpn-bot-warp-split apply` then refuses to blackhole and leaves awg-quick's `default dev out-warp` in table T. The state of `vpn-bot-warp-split.service` is not intent: with a non-empty list the bot's own panel wants the list too (`n_table == n_list`), so a disabled unit that left the default behind is the same 🟡 the panel shows |
| AWG clients exist | no `/etc/vpn-bot/uninstalled/awg` (the marker `vpn-bot-protocol-uninstall` writes) |
| proxies egress through WARP | the live xray `config.json` (`XRAY_CONFIG_PATH`; `sendThrough` of every outbound) and `external:` in `/etc/danted.conf`; `WARP_PROXY_EGRESS(_ENABLED)` is what makes the bot emit `sendThrough` = the `[Interface] Address` of the WARP config |

The facts: `awg show <iface> fwmark` (table T), `ip -4 route show table T`, the
`n_table` of `vpn-bot-warp-split-state status` (its own count of `<prefix> dev
out-warp`), `ip -4 rule show`, `ip -4 -br addr show`, `ip -4 route show default` (the
WAN device — never assumed to be `eth0`), `ip -4 route get <probe> from <A>` (a FIB
lookup through the policy rules; no packet is sent; the probe is a TEST-NET address
outside the split list, `1.1.1.1` last) and `iptables -t nat -S POSTROUTING`. Nothing
else runs: no `-A`/`-D`, no `ip route add`.

`warp`:

| State | Verdict |
|---|---|
| WARP not deployed | 🟢 nothing to check |
| `warp_settings.enabled = 0` | 🟢 turned off by the administrator (noted when `out-warp` is up all the same — systemd keeps it in observer mode) |
| turned on (or `warp_settings` unreadable) and `out-warp` has no fwmark | 🔴 |
| split off | 🟢 when table T has **no** route via `out-warp` (the anti-loop route via the WAN stays); any route via `out-warp` → 🟡, a default via `out-warp` → 🟡 «off turned into a full tunnel» (the PR #274 class) |
| selective | 🟢 when the `dev out-warp` prefixes in T equal the list; another count → 🟡; a default via `out-warp` → 🟡 (full tunnel instead of selective) |
| full tunnel | 🟢 with a default via `out-warp`, 🔴 without |

`warp:rule` exists only while AWG is installed — without AWG there is no client subnet
and no rule to want. `warp:clients_nat` likewise, and only when split is not off (with
split off no client enters WARP): the client subnet's source is not WARP's address, so
entering the tunnel it needs a MASQUERADE/SNAT on `out-warp` (`-o out-warp -j
MASQUERADE`, installed by `warp-routes`); without one → 🔴 «AWG clients leave into WARP
without SNAT». Without AWG clients the item is not shown at all: whether the host still
matches the warp-routes recipe is the business of the host invariants / drift checks,
not of the egress self-check.

`warp:egress` — for every address A a proxy sends from, unless A sits on another
interface (a second public IP is not WARP's business). It runs whatever
`warp_settings` says: a proxy bound to the tunnel address uses `out-warp` either way.

| Check | Verdict |
|---|---|
| A is not on `out-warp`, or `out-warp` is down | 🔴 in **every** split mode: xray/danted cannot send a single packet |
| split off | the probe from A leaves via the WAN **and** a MASQUERADE/SNAT covers A there (`-s A/32 -o <wan>`, or a broader plain rule) → 🟢; no such rule → 🔴 (VLESS/SOCKS5 leave with A and no SNAT; hy2 may still work); still via `out-warp` → 🟡 |
| selective | a probe in the first listed prefix via `out-warp`, a probe outside the list as when split is off; any difference → 🔴 |
| full tunnel | the probe via `out-warp`, else 🔴 |
| through `out-warp` (selective / full tunnel) | A is the tunnel address (the `[Interface] Address` of the WARP config; unreadable → the address on `out-warp`): **no NAT required** — the source is the one WARP accepts, and `vpn-bot-warp-routes` installs none for source-bind proxies; the route and A on the interface are enough. Another address on `out-warp` needs `-o out-warp` MASQUERADE/SNAT, else 🔴 (WARP drops it) |
| `WARP_PROXY_EGRESS` on, nobody bound to the tunnel address | 🟡 (the proxies egress from the host IP) |

**Daily run.** «⏰ Ежедневная самопроверка» (stored in `schema_meta`,
`wizard_selfcheck_daily`) starts a self-check every 24 hours when nothing else runs.
It sends a message to every superadmin **only when** an item is yellow or red, or the
run itself failed; an all-green day is silent.

### 📦 Диагностический дамп (read-only)

Collects, into `/var/lib/vpn-bot-wizard/<id>.dump.txt` (root:vpn-bot 0640): versions
(OS, kernel, python3, xray, hysteria, systemd), the checkout (`HEAD`, last commit,
dirty or not), the live `schema_version` against the checkout's
`CURRENT_SCHEMA_VERSION`, the units, `systemctl --failed`, the listeners (`ss`),
`ip rule` / `ip -6 rule`, and the tail of `bot.log` and of Xray's `error.log`
(parameter `lines`, 20–1000, default 200).

A log tail is judged by the **timestamp of its last ERROR line** («last ERROR at …
(3 h ago)»), never by how many there are. `bot.log` stamps carry their UTC offset
(local time, `%z`) and are read with it; Xray's have none and are the host's local time;
both are shown in UTC.

Everything goes through the redaction patterns of `utils/redact.py` (bot tokens, keys,
passwords, `secret=`, URL credentials, long hex). `verify` re-scans the file and refuses
one that still matches a pattern; the bot redacts again before sending. The dump asks
for the TOTP code (it carries the host's topology off the box).

### ⬆️ Обновить бота

**One message, one confirmation.** The button edits THIS message: the deploy's steps ⚪ and
«✅ Подтвердить» / «✖️ Отменить» — no run exists yet. With TOTP the code prompt is in the same message
and the code is the confirmation (no «▶️ Продолжить», no second confirmation after the plan). The run
then starts *confirmed* (`WizardService.start(confirmed=True)`, `schema_meta` `wizard_confirmed_run`):
its plan — `CHECK=1` below — goes on to apply by itself, also across a restart of the bot. While it
runs the message carries only «📄 Лог»; «Состояние:» says what is: «⏳ выполняется (шаг: тесты)» from
the first step marker on — never «📝 план» while the steps move — then «✅ готово» / «❌ ошибка» with
«📄 Лог» and «⬅️ Назад». A second press while a run is active answers «уже идёт, запуск #N» and
changes nothing. The plan's steps stay ✅ while apply's deploy (its tests skipped by the Phase 1
stamp) gets to them again — no step goes back to ⚪.

A thin wrapper around the one supported redeploy path, `scripts/redeploy.sh`:

* **plan** — `git fetch origin main`; the commits `HEAD..origin/main`, the
  `CURRENT_SCHEMA_VERSION` of both and the live schema; then `CHECK=1 redeploy.sh`
  (deploy.sh `PHASE1_ONLY=1`: the whole read-only Phase 1, the test suite included).
  `HEAD` already **is** `origin/main` (full SHAs — deploy.sh's own test): nothing to do,
  the run ends there. A checkout *ahead* of `origin/main` (a local commit) is not a no-op:
  the plan warns that the deploy resets the checkout and those commits are gone.
  The plan records the exact `origin/main` revision it describes.
* **apply** (the run's one confirmation was given before it started) — only that revision: `git fetch origin main` again, and
  if `origin/main` moved since the plan (other commits, maybe another migration than the
  one confirmed) nothing is deployed and the run fails with "start the update again".
  Then `redeploy.sh`. `deploy.sh` stops and restarts the bot; the run keeps going in its
  own unit. A push in the seconds between this check and redeploy.sh's own fetch is
  reported by verify («deployed X, the plan was for Y»), never hidden.
* **verify** — `===== DEPLOY OK =====` in the output and `vpn-bot.service` active.
* **rollback** — `deploy.sh` rolls itself back (code, venv, DB, configs, unit) and
  prints `===== ROLLBACK REPORT =====`; the step reports it and checks that the bot
  runs (`rolled_back`). No report — deploy.sh stopped before Phase 2 (nothing changed)
  or never finished — is `failed`: read the log.

**Progress.** The plan lists the deploy's steps ⚪ (preflight, fetch, tests, checks, backup,
install, restart, verify) above «✅ Подтвердить». While `CHECK=1` and the deploy run, the helper reads
redeploy.sh's output as it comes and writes a `deploy` event into the status file every 2 s
(`deploy_progress` of the [step markers](deployment.md#step-and-result-markers): each step's state
and the tests — done of `[deploy:tests total=N]`); the bot's message shows ⚪ 🔄 ✅ ❌ ⏭, «N/M» and
the percentage, edited at most every 3 s. The deploy restarts the bot: the message id is in
`wizard_runs`, the new process reads the same status file — fed from the deploy's output — and
edits the same message on, then closes it with the result (✅, or ❌ with the cause below).

A failure — of the plan's `CHECK=1` or of the deploy — shows **its cause**, not just «failed»:
the reason deploy.sh reported in its [result line](deployment.md#step-and-result-markers)
(another deploy runs, `git fetch`, no ensurepip / test venv, the tests, a Phase 1 gate, a
Phase 2 step that was rolled back, …) in plain words, the step it stopped in, the lines of the
deploy log that tell it and the log's path on the server (`/root/deploy-<ts>.log`). The
helper's events carry `reason`, `fail_step`, `excerpt` and `deploy_log`; the classifier is the
DEPLOY VERDICT block it shares with the relay agent. A deploy that succeeded with a finding
(`[deploy:warn …]`) shows it under the report — among them `flaky_tests`: Phase 1's tests that
failed and passed when only they were run again ([deployment.md](deployment.md#flaky-tests-in-phase-1)).

The wizard calls `redeploy.sh` with `REDEPLOY_ATTACH=pipe`: `systemd-run --wait --pipe`
instead of `--pty` (there is no terminal) under `set -o pipefail`, so the wrapper waits
and exits with deploy.sh's code. The verdict is still read from the report text, as an
operator reads it. Parameter `force` (`0`/`1`) is `FORCE=1`.

### 🔐 Сертификат и DNS

The mode `cert` (helper `vpn-bot-wizard-cert`, parameters `action` = `issue` | `renew` | `adopt`
| `deploy`, `names` — a comma list of DNS names, `zone` — the Cloudflare zone's **name**). It has no
button of its own in the menu: «🔐 Сертификат и DNS» opens the certificate's screen, which works out
the parameters (the names the certificate has, the zone the bot's token was checked against) and
starts the run from there. A plan with the diff first (the acme.sh conf lines, the certificate before
and after, every reader of the registry and what happens to it), then «✅ Применить»; dangerous: TOTP
before the plan and before apply. apply takes a backup of everything it may touch (the acme.sh domain
directory, every reader's files, vpn-bot-cert's state) and runs the root helper; verify reads
`vpn-bot-cert status`; rollback restores the backup and acts on every reader again. No step changes
the host's network, so no dead-man is armed. Everything about it:
[certificate.md](certificate.md).

The zone travels as its name, not its id: 32 hex characters look like a secret to every redaction
(`utils/redact.py`, the run's stored parameters, the log) — vpn-bot-cert asks Cloudflare for the id
with the token itself.

### 📦 Установка протокола

The mode `protocol` (helper `vpn-bot-wizard-protocol`, parameters `proto` — the protocol, `domain` — one
DNS name the bot's certificate covers, empty = the certificate's own). No button of its own in the menu:
«⚙️ Модули протоколов» offers **📦 Установить** for a protocol that is not on the server and starts the
run from there. The plan is the root helper's (`vpn-bot-protocol-install plan`): every package, file, unit
and `.env` line, what is kept and why, what blocks; the steps of apply are shown with
`bot/progress.py`'s icons from the helper's `steps` events. Dangerous: TOTP before the plan and before
apply. Verify green → the install is committed and the bot restarted (it reads `XRAY_*` at start; the new
process reports the run); after the run's success the bot converges the firewall (`vpn-bot-ufw-apply
apply`) and says so in the report. No step changes the host's network, so no dead-man. Everything about
it: [protocol-install.md](protocol-install.md).

A status file may carry `{"event": "steps", "steps": {"<step>": "wait|run|ok|fail|skip", ...}}` — a mode
helper's own steps; the bot renders the last one (`install_step_<step>` labels).

### 🌐 Сайт

The mode `site` (helper `vpn-bot-wizard-site`, parameters `action` = `deploy` | `revert` and
`digest`, the first 16 hex of the uploaded archive's sha256; new parameter kind `digest` in both
mode tables). No button of its own in the menu: «🌐 Сайт» opens the decoy site's screen, which
receives the archive (a document, staged in the bot's RuntimeDirectory) and starts the run from
there. The plan is the root helper's (`vpn-bot-site plan`): the archive unpacked and checked in
isolation, the diff of files and pages, the spiderX pool before → after, the kept versions; apply
puts the new tree next to the docroot and swaps the two directories in one `renameat2` exchange;
verify GETs every page over HTTP/2 through nginx (ALPN h2, the domain's certificate), then commits
(the replaced tree kept, the last five). Dangerous: TOTP before the plan and before apply. After
the run's success the bot re-lays the keys whose stored spiderX left the pool. No step changes the
host's network (nor nginx's configuration, nor the certificate), so no dead-man. Everything about
it: [site.md](site.md).

### 🛰 Relay

Not a mode: the wizard's «🛰 Relay» opens the admin panel's ONE relay screen — see
[relay.md → Managing relays in the admin panel](relay.md#managing-relays-in-the-admin-panel).

### 🔑 SSH-порт relay

Not a mode either: every relay with an agent, its SSH port and its move to `SSH_PORT`. Per relay
«✅ Подтвердить закрытие …» / «Оставить …» (phase 1), «↩️ Вернуться к переезду» (held) and
«✏️ Сменить порт» (phase 1 to a new port at once, no deploy). All behind TOTP — see
[host-state.md → A relay's migration from the bot](host-state.md#a-relays-migration-from-the-bot).
A relay still on 22 or without its input filter (what the installer leaves a new relay with) shows
a warning and **«🛡 Довести до нормы»** there.

### 🛡 Входной фильтр relay

Not a mode: every relay with an agent and its input filter (`vpn-relay-apply input-status`), and
**«🛡 Довести: <relay>»** for each one not at the defaults (SSH on 22, the filter off) — the way back
after «Позже» under the bot's alert. «Довести» turns the filter on (confirmed by a new ssh session of
the bot), then moves SSH off 22, each step rolled back when it fails; TOTP (`relay_harden`) — see
[relay.md → Bringing a relay to the defaults](relay.md#bringing-a-relay-to-the-defaults).

## The helpers' library

`vpn-bot-wizard-lib` is what future modes (IP or domain change, restore) build on:

* **dead-man** — `deadman_arm(run, seconds, helper, params)` arms
  `systemd-run --unit=vpn-bot-wizard-<id>-deadman --on-active=<N> --collect <helper>
  rollback --run <id> --deadman`; `deadman_disarm` stops the timer. A step that touches
  the network arms it first, so a lost SSH session cannot be the end of the story. The
  modes of this release do not touch the network; `update` relies on deploy.sh's own
  rollback.
* **backup before a change** — `backup_paths(run, paths)` writes a tar.gz with a
  sha256 manifest to `/var/lib/vpn-bot-wizard/backups/<id>/` (0600);
  `restore_backup(archive)` puts the files back with their modes and owners.
* **log** — `/var/log/vpn-bot-wizard/<id>.log`, every line redacted.

Test seam: `VPN_BOT_WIZARD_SELFTEST=1` re-roots every path under
`VPN_BOT_WIZARD_ROOT` and refuses any command that is not a stub in
`VPN_BOT_WIZARD_SELFTEST_BIN`. Production never has these variables (sudo resets the
environment, systemd starts the unit with a clean one).

## TOTP

### Enabling

«🔐 Безопасность → 🔐 Включить TOTP», or the optional step the bot offers right after a
successful first-superadmin claim ([install.md](install.md)):

1. The bot shows the secret as a QR (`otpauth://totp/vpnbot:<user>?secret=…`, SHA1,
   6 digits, 30 s) and as base32 text with the same URI — for an app that cannot scan.
2. You send the current 6-digit code.
3. TOTP is on, and **10 one-time backup codes** are shown **once**.
4. «✅ Я сохранил коды» deletes the codes message. The secret and QR messages are
   deleted as soon as the code is accepted; every message carrying a code you typed is
   deleted as soon as the bot read it.

### Storage

* The secret is stored only Fernet-encrypted (`totp_credentials.secret_enc`). The key
  is `/etc/vpn-bot/totp.key` — created on the first enrollment, mode 0600, owned by the
  bot's user; the bot refuses a key file that is a symlink, not a regular file, or
  readable by anyone else. In the helper-nonroot model the bot cannot write
  `/etc/vpn-bot`; create the key once as root (a Fernet key is 32 random bytes,
  url-safe base64):

  ```bash
  python3 -c 'import base64, os; print(base64.urlsafe_b64encode(os.urandom(32)).decode())' | sudo install -o vpn-bot -g vpn-bot -m 0600 /dev/stdin /etc/vpn-bot/totp.key
  ```

* A key file that disappears while credentials exist is never replaced with a new one
  (that would hide the loss): the check fails closed and points at the reset below.
* Backup codes are stored only as `hashlib.scrypt` (N=2¹⁴, r=8, p=1, a 16-byte salt per
  code); a redeemed code has `used_at` and never matches again. «🔐 Безопасность» shows
  how many are left. «🔑 Перевыпустить резервные коды» needs a **TOTP** code (a backup
  code is not enough) and invalidates the old ones.
* `/etc/vpn-bot` is part of the offsite system bundle, so the key travels with the
  encrypted backups.

### Checking a code

* Window ±1 step (±30 s).
* Replay: the time-step of the last accepted code is stored (`last_used_step`); a code
  of that step or an older one is refused — also after a restart.
* 5 wrong codes in a row → input locked for 15 minutes and an alert to every
  superadmin. The counter and the lock are in the database: a restart does not lift
  them. A correct code resets the series.

### Where it is asked

Only when the superadmin has TOTP enabled (the factor is opt-in):

| Action | Where |
|---|---|
| removing a protocol from the server | «Модули протоколов → Удалить с сервера» (the final button) |
| disabling a protocol (deletes all its keys and accesses) | «Модули протоколов → Отключить» (the final button) |
| every change of a relay — on/off, «➕ Добавить в подписки» / «➖ Убрать из подписок», «👁 в базовых» (of a relay and of the main server), host, rename, source IPs, note, the source IP offer | the button on the relay's page or the relay list; «✅ Выполнить» under the subscriptions plan (a typed step checks the elevation again) |
| deleting a relay (record only included) / together with its keys | «Relay → Удалить» (the final button) |
| wizard: diagnostic dump | start, and the dump file from the history |
| wizard: update the bot | «✅ Подтвердить» of the plan — the code in the same message is the confirmation |
| Relay: issue a pairing code — a new relay or an agent for an existing one | «➕ Добавить relay», «🔗 Подключить агент» |
| Relay: complete a pairing | «🔌 Подключить» (the typed address checks the elevation again) |
| Relay: update a relay's agent | «⬆️ Обновить агент» — the code in the same message is the confirmation |
| Relay: move a foreign sshd override to `/root/attic` ([relay.md](relay.md#a-foreign-sshd-override)) | «🧹 Убрать чужой override» — the code in the same message |
| Relay: change a relay's ports / target | «⚙️ Порты / цель» (the typed step checks the elevation again) |
| Relay: disconnect the agent | «🔌 Отключить агент» |
| Relay: uninstall on the relay (delete of a relay with an agent, «🧹 Отключить и снять с relay») | the final button |
| Relay: the SSH port — close the old port, keep it, resume, change the port ([host-state.md](host-state.md#a-relays-migration-from-the-bot)) | «✅ Подтвердить закрытие …», «Оставить …», «↩️ Вернуться к переезду», «✏️ Сменить порт» (the typed port checks the elevation again) |
| Relay: bring a relay to the defaults — the input filter on, SSH off 22 ([relay.md](relay.md#bringing-a-relay-to-the-defaults)) | «🛡 Довести до нормы» (the plan) and «✅ Подтвердить» (the run) |
| Fallback mode: switch on / off / repeat ([docs/relay.md](relay.md#fallback-mode-hub)) | «✅ Да, …» of the confirmation, «🔁 Повторить» |
| Fallback mode: the hub role | «🛟 Сделать hub» (the typed origin checks the elevation again), «🛟 Снять роль hub» |
| Fallback mode: the DNS API token | «✏️ Задать токен» (the typed token checks the elevation again), «🗑 Удалить токен» |
| Certificate and DNS: a run of the `cert` mode — adopt, issue, renew, lay out ([certificate.md](certificate.md)) | «🔁 Принять текущий сертификат», «▶️ Составить план», «🔄 Проверить продление», «📦 Разложить заново»; «✅ Применить» of the plan |
| Protocol modules: install a protocol on the server ([protocol-install.md](protocol-install.md)) | «📦 Установить» (the run's plan) and «✅ Применить» of the plan |
| Site: deploy an archive / revert to the kept version ([site.md](site.md)) | «⬆️ Загрузить архив» (before the document; the document checks the elevation again), «↩️ Откатить на предыдущую», and «✅ Применить» of the plan |
| Certificate and DNS: the bot's Cloudflare token | «✏️ Задать токен» (the typed token checks the elevation again), «🗑 Удалить токен» |
| Fallback mode: names, addresses, direct links' host, `fallback-url` | each button; a typed value checks the elevation again |
| Fallback mode: broadcast of the new proxy address ([relay.md](relay.md#the-proxies-through-the-hub)) | «✅ Разослать» |

A correct code **elevates** the user for 5 minutes: inside that window nothing is asked
again. Elevations live in the bot process only — a restart drops them. The prompt
turns into «▶️ Продолжить», which presses the original button again. **In place**
(`require_totp_in_place`: «Обновить бота», «Обновить агент», «Убрать чужой override») the code is
asked in the same message as the plan, and a correct code starts the action right there — one
message, one confirmation; a wrong one keeps the screen and adds the error, «✖️ Отмена» drops the
prompt. Future dangerous
actions (rotations, IP/domain change, restore) register in `DANGEROUS_ACTIONS`
(`bot/totp_gate.py`). Audit (entity `security`): `totp_enrollment_started`,
`totp_enabled`, `totp_verified`, `totp_backup_code_used`, `totp_verify_failed`,
`totp_locked`, `totp_backup_codes_reissued`, `totp_disabled`, `totp_reset_cli`.

### Disabling

«🚫 Отключить TOTP» needs a TOTP code or a backup code.

### Emergency reset

Lost both the phone and the backup codes: on the host, as root,

```bash
sudo vpn-bot-totp-reset <telegram_id>
```

It asks for confirmation on a terminal (`--yes` skips it; without a terminal `--yes`
is required), deletes the user's TOTP and every backup code in one transaction and
writes the audit row `totp_reset_cli`. The database is `DB_PATH` from
`/opt/vpn-service/.env` (`--db PATH` overrides). The bot reads TOTP state from the
database on every check, so the reset is effective at once; an elevation it still holds
expires within 5 minutes (or `sudo systemctl restart vpn-bot`). Enable TOTP again from
«🔐 Безопасность».
