# The first setup («🧭 Первичная настройка»)

After `scripts/install.sh` the bot runs with no protocol. The **first setup** takes the
superadmin from there to a working server — in Telegram, step by step, through what the bot
already does elsewhere and never a second way.

🇷🇺 Russian version: [first-setup.ru.md](first-setup.ru.md)

## When it is offered

Right after a successful claim (`/start claim_<code>`, [install.md](install.md)) when no
protocol the bot installs is on the host (`services/protocol_install.py`: none of Xray,
Hysteria2, SOCKS5 is there or only removed) and no first setup has succeeded yet:
**🧭 Начать первичную настройку** / «Позже». At any time: «🧙 Мастер настройки →
🧭 Первичная настройка» — an open setup is resumed, not started again.

## The steps

| Step | What it checks first | What it does when that is not so |
|---|---|---|
| domain | — | asks the domain the server serves (typed into the chat) |
| token | the bot's Cloudflare token is set | asks it; checked against the domain's zone before it is stored — verify, zone read, a TXT probe written and deleted ([certificate.md](certificate.md#the-cloudflare-token-one-per-bot)); the message with it is **deleted the moment it is read** |
| dns | the domain resolves to an address of this host (`ip -4 addr show scope global`) | writes the A record → this host through the bot's DNS (`DnsService.upsert_a`, purpose `host`, proxied=false) |
| cert | the bot's certificate covers the domain (adopted, a usable key, 7+ days) | a run of the wizard's `cert` mode: **adopt** the acme.sh domain of that name, else **issue** one (DNS-01 with the bot's token) |
| protocols | — | the superadmin picks (☑️ VLESS REALITY and Hysteria2 by default, SOCKS5 offered); **✅ Продолжить** is the ONE confirmation of everything that follows — the TOTP code is asked here when it is on |
| install | a protocol already on the host | one run of the wizard's `protocol` mode per protocol ([protocol-install.md](protocol-install.md)) |
| ufw | — | `vpn-bot-ufw-apply apply` ([host-state.md](host-state.md#the-firewall-ufw)); a change of the incoming policy is under its own dead-man and is confirmed as usual |
| totp | TOTP is on for the superadmin | the existing enrollment (🔐 Включить TOTP), then «▶️ TOTP включён», or «Пропустить» |
| selfcheck | — | a run of the wizard's `selfcheck` mode; no red item ends the setup **succeeded** |

The certificate's and the installs' runs are started **confirmed** (the confirmation was the
one above): their plans go on to apply by themselves; each run's report arrives as a
message of its own, and the setup's message is sent again under it.

## Resumable

Every step is idempotent: it checks the host and the services first and only acts on what
is missing. The setup's progress — each step's state, the domain, the protocols, the run it
waits for — is one row of `wizard_runs` (mode `setup`; it does not hold the wizard's lock:
its steps are runs of other modes, which do; no schema change). An install restarts the bot:
at start the open setup is found and goes on (`WizardService` startup hook); a run it waited
for that finished meanwhile moves it on (`WizardService` finish listener). A failed step
waits for **🔁 Повторить**, which checks again and starts a new run where one is needed;
**✖️ Отменить настройку** ends it. A token typed into the chat never reaches the row, the
log or the audit (its fingerprint does).

## End to end in CI

The job `setup-e2e` (`.github/workflows/ci.yml`, `tests/e2e/run_setup_e2e.sh`) runs the whole
path on an ubuntu-24.04 runner with systemd: `install.sh` → the claim → the first setup driven
through the mock Bot API (`tests/e2e/drive_setup.py` presses the buttons the bot shows) with
a mock Cloudflare API (`tests/e2e/mock_cloudflare_api.py`, `CLOUDFLARE_API_BASE`), an acme.sh
home of a test CA trusted by the system (the setup adopts it) and the pinned release files in
the install helper's release cache (`/var/cache/vpn-bot-protocol-install` — a file of the
asset's name is used instead of a download, the pin still decides). While the setup runs the
network is **closed for root** (an iptables owner match): nginx comes from apt's cache, xray
and hysteria from the release cache. It ends with the real units active, the self-steal
serving h2 with the domain's certificate, no record left at the mock Cloudflare and a
self-check without red.
