# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- **XHTTP client transport profiles for VLESS (HTTP) keys.** Creating a VLESS (HTTP)
  key now has a third step — a client-side transport profile: **base** (universal,
  byte-for-byte the previous link), **antisib** (anti-blocking: single-channel xmux to
  survive TLS-handshake-count blocking) and **multi** (multi-connection: `packet-up`
  with split-post + rotating xmux for throttling-resistant long sessions). All three
  are clients on the same loopback XHTTP inbound (`mode: auto`), so nothing changes
  server-side — the profile only tunes `mode` / `xhttpSettings.extra` in the generated
  link and is immutable per key. `multi` needs Xray-core v25.3.6+ on the client
  (`hMaxReusableSecs`). Adds the `xhttp_profile` column (migration v28, backfilled to
  `base`) and rewrites existing Xray email labels into the transport/profile-aware
  scheme (`xray_tcp_<rnd>` / `xray_http_<profile>_<rnd>`; UUIDs are never touched).
  Documented in `docs/xray-xhttp-inbound.md`.
- **Hysteria2 documented in the in-bot FAQ ("Помощь").** The help section's
  protocol-related answers now cover Hysteria2 alongside AWG and Xray, so users
  who receive a Hysteria2 key get matching guidance. The *connect* tab recommends
  NekoBox/Hiddify and notes Hysteria2 is a link-only profile; the *choice* tab
  becomes a three-way AWG/Xray/Hysteria2 comparison (its button relabelled to
  "Какой протокол выбрать?" / "Which protocol to choose?"); *trouble* gains a
  Hysteria2/UDP block (client support, UDP throttling, no MTU/fingerprint knobs);
  and the *security* and *support* tabs list Hysteria2 too. No new FAQ topic was
  added — the existing tabs were adapted, with the `ru` and `en` locales updated
  in lockstep.
- **Hysteria2 operational parity: backend-health, diagnostics & recovery backup.**
  Closes the last non-Traffic-Stats-API gaps between Hysteria2 and Xray/AWG. (1) A
  new `adapters/hysteria_auth_health.py` probe polls the `hy2_auth` `GET /healthz`
  endpoint on a background loop (`HYSTERIA2_HEALTH_INTERVAL`, default 60 s) and
  reflects it as the **Hysteria2: OK/DEGRADED** entry in `BackendHealth` — the
  dashboard and health panel no longer report Hysteria2 permanently "OK" while its
  data plane is down. Because Hysteria2 issuance/revocation are pure `vpn.db` writes
  with no apply step, a degraded mark is informational only and never blocks
  mutations. (2) The admin **diagnostics** panel now runs `systemctl is-active` on
  the Hysteria2 units (`HYSTERIA2_AUTH_SERVICE_NAME`=`vpn-bot-hy2-auth`,
  `HYSTERIA2_SERVICE_NAME`=`hysteria-server`) when Hysteria2 is enabled. (3) The
  hysteria-server config (`HYSTERIA2_CONFIG_PATH`, default `/etc/hysteria/config.yaml`)
  is bundled into the offsite recovery archive, mirroring the Xray/AWG config backup.
  (4) `AnomalyDetectionService` is now wired to `BackendHealth`, so its
  skipped-revocation counter increments across all protocols. New settings:
  `HYSTERIA2_{HEALTH_INTERVAL,SERVICE_NAME,AUTH_SERVICE_NAME,CONFIG_PATH}`. Note:
  per-key traffic, the online count and revoke-kick remain gated on the Traffic
  Stats API (`HYSTERIA2_STATS_SECRET`) — that data is only obtainable from
  `hysteria-server` itself and cannot be synthesised by the bot.
- **Hysteria2 technical parity via the Traffic Stats API.** Hysteria2 keys now
  reach feature parity with Xray/AWG for observability and lifecycle. A new
  `adapters/hysteria_stats.py` (`HysteriaStatsAdapter`) reads the Hysteria2
  Traffic Stats API (`GET /traffic`, `GET /online`) over loopback and POSTs
  `/kick`, keyed by the same `hy2_<hex>` label the auth endpoint returns. This adds:
  per-key **traffic stats** (background `_hysteria_stats_loop` + on-demand views,
  non-destructive reads), the **online-clients** counter (Hy2 leg in the server
  status panel), **dashboard** per-protocol breakdown (active keys + traffic
  bytes), a **backend-health** entry, **anomaly detection** by concurrent-connection
  count (`ANOMALY_HYSTERIA2_MAX_CONN`, alert + optional auto-revoke), and
  **immediate session termination on revoke/delete/expiry/block** via a best-effort
  `/kick` (previously a live session survived until the client reconnected). New
  settings: `HYSTERIA2_STATS_{LISTEN,SECRET,INTERVAL}` and
  `ANOMALY_HYSTERIA2_MAX_CONN`. The whole surface stays inert unless
  `HYSTERIA2_STATS_SECRET` is set (which must equal `trafficStats.secret` in
  `/etc/hysteria/config.yaml`), so existing deployments are unaffected.
- **Hysteria2 (apernet v2) integration with `auth: type: http`.** The bot can now
  issue, revoke and delete Hysteria2 `vpn_key`s dynamically with **no data-plane
  restarts**. Authentication is handled by a new standalone process,
  `python -m hy2_auth`: Hysteria POSTs each handshake to a loopback endpoint that
  live-reads `vpn.db` read-only and validates the per-key token in constant time
  (`hmac.compare_digest`), returning `{"ok": …, "id": <label>}` and always HTTP 200.
  The endpoint is fully decoupled from the bot (it never imports `bot`/`aiogram`,
  binds loopback only, and keeps working while the bot is down). Per-key secrets
  (`secrets.token_hex(24)`) live only in `payload_json`; the stats label is
  `hy2_<hex>`. New settings: `HYSTERIA2_{ENABLED,HOST,PORT,SNI,OBFS_PASSWORD,INSECURE,AUTH_LISTEN}`
  (`HYSTERIA2_OBFS_PASSWORD` must match the salamander password in
  `/etc/hysteria/config.yaml`). A new `hysteria2` protocol module gates issuance in
  the admin panel, and `deploy/vpn-bot-hy2-auth.service` is provided for the operator.
  Includes a table-rebuild migration (schema v29) that widens the `vpn_keys.key_type`
  CHECK to allow `'hysteria2'` (idempotent; UUIDs of existing keys preserved).
- **Slash-command menu in Telegram (`set_my_commands`).** On startup the bot now
  publishes its commands so they appear in Telegram's command menu (the «/» button)
  with localized descriptions. Regular users see the public commands (`/start`,
  `/menu`, `/settings`, `/help`, `/faq`, `/cancel`); superadmins additionally see
  the privileged ones (`/admin`, `/moderator`, `/warp_split_*`) scoped to their own
  chat (`BotCommandScopeChat`) so they never leak into the public menu. Descriptions
  are served in ru/en plus the configured `BOT_LANGUAGE` fallback. A failed sync is
  logged and never blocks startup — commands still work by typing them.
- **WARP kill-switch (fail-closed) and config-installed state (schema v30).** The
  ⚙️ Settings sub-panel of the WARP («Outbound IP masking») panel gains a **🛡 kill-switch**
  toggle, persisted in `warp_settings.kill_switch` (migration v30, default off). When on **and**
  the health monitor runs in legacy (non-observer) mode, a tunnel-down now *keeps* the routes in
  place so masked traffic blackholes on the dead interface instead of falling back to the direct
  path and leaking the real server IP. It is a bot-side control and only enforces in legacy mode;
  in observer mode the routes are systemd-owned, so fail-closed there is `warp-failsafe`'s job.
  The same migration adds `warp_settings.config_installed`, decoupling "a config is installed"
  from `routes_count > 0` so a full-tunnel `AllowedIPs = 0.0.0.0/0` (whose routes the helper
  strips) no longer makes the module refuse to start; installs that already produced routes are
  backfilled to installed. Documented in `docs/warp.md` (Kill-switch).

### Changed

- **Dev-gate docs realigned with CI.** `README.md`, `README_RU.md` and
  `CONTRIBUTING.md` now show the exact gates CI (`.github/workflows/ci.yml`) and the
  `Makefile` run: `mypy --strict` also covers `db/ hy2_auth/ warp/`, and the pytest
  coverage floor is `--cov-fail-under=62` (both were previously documented as the
  shorter mypy set and 60%). Also documented the previously undocumented XHTTP
  client transport profiles and corrected the privilege-separation plan's sudoers
  entrypoint list to include the optional WARP helpers.
- **BREAKING: `vpnbot-*` → `vpn-bot-*` naming unified.** The privileged helpers,
  systemd units, sudoers file/aliases and the `/etc/vpnbot` + `/etc/mtproxy/vpnbot`
  config directories were renamed from the inconsistent `vpnbot` token to the
  hyphenated `vpn-bot` that already names the service, user and `/run/vpn-bot`.
  Helpers are now `/usr/local/sbin/vpn-bot-*`; the sudoers file installs to
  `/etc/sudoers.d/vpn-bot` with `VPN_BOT_*` aliases; units are
  `vpn-bot-hy2-auth.service` / `vpn-bot-warp-split.service`; config lives under
  `/etc/vpn-bot` and `/etc/mtproxy/vpn-bot`. `deploy/setup-nonroot-helper-mode.sh`
  migrates existing installs (moves the config dirs; removes the stale
  helpers/sudoers/unit/drop-in). The offsite backup filename prefixes
  (`vpnbot_backup_`/`vpnbot_recovery_`) and the GitHub repository name are
  intentionally unchanged.
- **deploy/ & scripts/ security-review hardening.** Closed a TOCTOU in the WARP
  config-install helper that could smuggle an `awg-quick` `PostUp` hook onto disk
  (root code-exec) by validating on a single `O_NOFOLLOW` read; run the MTProxy
  managed wrapper as root so it can read the root-owned managed files and drop the
  proxy via `-u`; gated security-critical env overrides behind sudo in the WARP
  split helpers; pinned the split-apply sudoers grant to zero arguments; made the
  WARP WAN device and endpoint dynamic (no hardcoded `eth0`/Cloudflare IP); and
  corrected docs that mislabelled the root+api unit as the non-root production unit.
- **Server status detailed block reordered, and its state resets on toggle-off.**
  In the "статус сервера" panel's detailed-metrics block the **uptime** («Аптайм»)
  now comes first and the **load average** («Средняя нагрузка») second (previously
  the reverse). Turning the detailed-metrics toggle off now fully resets the
  detailed state: alongside clearing the accumulated network history, the detailed
  fields are stripped off the cached samples so the block collapses to "no data"
  on the very next render instead of lingering on the last detailed reading until
  the sampler produces a fresh base one.
- **Documentation restructured into a short README plus topical `docs/`.** `README.md`
  and `README_RU.md` are now concise overviews (~260 lines each, down from ~1400) with a
  Quick Start, an architecture diagram, a key-variable table, and a documentation index.
  The deep content moved into bilingual (`*.md` + `*.ru.md`) guides under `docs/`:
  `configuration.md` (full env-var reference), `deployment.md`, `operations.md`,
  `proxy.md`, and `warp.md`. The repeated api/root warning is now stated once
  (`docs/deployment.md`), the env reference is no longer duplicated across README and
  `.env.example`, internal "Package N" labels were removed from the docs, and the
  documentation-drift guard tests now check the new canonical doc locations. Add
  screenshots to `docs/images/` (see that folder's README).
- **WARP auto-switch is now time-based with an adaptive ping cadence.** The health
  monitor no longer counts consecutive probes; it switches **warp → direct** only after
  60 s of *continuous* no-response and **direct → warp** only after 60 s of *continuous*
  success (a single opposite probe resets the running window). The probe interval is
  adaptive: 10 s during normal operation, speeding up to 3 s the moment a probe gets no
  response so an outage — and the start of recovery — is detected quickly. The windows
  and both intervals are tunable via `WARP_MONITOR_FAIL_WINDOW_SECONDS`,
  `WARP_MONITOR_RECOVER_WINDOW_SECONDS`, `WARP_MONITOR_INTERVAL_SECONDS` and
  `WARP_MONITOR_FAST_INTERVAL_SECONDS`. **Breaking:** the old count-based
  `WARP_MONITOR_FAIL_THRESHOLD` / `WARP_MONITOR_SUCCESS_THRESHOLD` env vars are removed.

### Fixed

- **Admin panel silently did nothing when issuing a key to a blocked user.** In
  `admin_issue_user_selected`, the callback query was answered (dismissing the
  loading spinner) *before* the blocked-user check ran; when that check then
  raised, the error handler tried to answer the same callback a second time with
  the alert, which Telegram silently ignores — the admin saw no feedback at all.
  The handler now validates the chosen user first and answers the callback exactly
  once, so the "Нельзя выдать ключ заблокированному пользователю" alert actually
  shows. The same guard was added to the issue-confirmation step to close a related
  race where a user could be blocked between selection and confirmation.
- **«Создать ключ» → «Назад» from the main menu now returns to the main menu.**
  The create-key screen's back button was hard-wired to «Мои ключи», so entering
  it from the main-menu **➕ Создать ключ** button and pressing back dropped the
  user into the key list instead of back where they came from. The main-menu entry
  now carries a `keys:create:menu` marker and the screen routes its back button to
  the correct origin (main menu vs. the «My keys» list); the reply-keyboard entry
  likewise returns to the main menu.
- **Clearer "1 key = 1 device" FAQ wording.** The `faq_device` answer said sharing
  one key across devices *may* cause problems; in practice it always does (devices
  keep dropping each other's connection). Both locales now state the problem is
  guaranteed and advise creating a separate key per device.
- **Standardised WARP split-routes pagination.** In the admin WARP tunnel
  → settings → split-routes panel, the prev/next controls were replaced by a «·»
  placeholder dot on the first/last page, breaking the look of every other paginated
  list. The pager now mirrors the main-menu FAQ pagination: the prev/next button is
  simply omitted at the edges (no dot) and the page counter stays centred.
- **Server-status sparkline starts fresh on every open.** The detailed network
  history (the sparkline plus the avg/peak/trend derived from the same window) was
  retained between viewings, so re-opening the **Статус сервера** panel showed stale
  columns from a previous session. Opening the panel now resets the network-history
  window (`ServerStatusService.reset_network_history`) before the first render;
  detailed mode and the live auto-refresh tick are untouched.
- **Corrected & expanded the "How to connect" FAQ.** It claimed AWG "typically uses
  a `.conf` file", which is inaccurate — depending on the client, both AWG and Xray
  keys can be added by link/profile *or* by config file. The answer now says so,
  recommends concrete apps (AmneziaVPN for AWG, v2RayTun / Hiddify / NekoBox for
  Xray), and adds a paragraph advising users to keep several keys across different
  protocols/transports so a single one degrading under blocking doesn't cut them off.
- **"All systems operational" reassurance on the main menu.** Between the server-restart
  warning and the "Choose an action" line, the main menu now shows a ✅ "Все системы
  работают в штатном режиме" / "All systems operational" status line, so a healthy bot
  visibly says so instead of only ever surfacing warnings.

## [2.1.0] — 2026-06-22

### Added

- **Off-site recovery bundle for full disaster recovery** — the scheduled off-site
  backup now sends a second encrypted document alongside the DB snapshot: a
  `vpnbot_recovery_*.tar.gz.enc` bundle containing `.env` plus the irreplaceable
  server-side secrets that are **not** in the database (Xray `config.json` with the
  REALITY private key + shortIds, the AWG `.conf` interface private key, managed
  MTProto secrets, and the WARP config). Without these a rebuilt server issues new
  keypairs and breaks every already-issued client. The bundle is assembled entirely
  in memory (no plaintext on disk), encrypted with the same `OFFSITE_BACKUP_ENCRYPTION_KEY`
  (so the existing 30-day TTL applies), and includes a `MANIFEST.json` recording each
  file's original absolute path, size, and sha256. Reads are best-effort: missing or
  unreadable sources are skipped and flagged in the manifest, so a partial bundle stays
  useful. Controlled by `OFFSITE_BACKUP_INCLUDE_CONFIGS` (default `true`) with an optional
  `OFFSITE_BACKUP_ENV_PATH` override; the existing `*.db.enc` backup format is unchanged.
  Both the scheduler and the admin **💾 Бэкап БД** button now deliver both artifacts.

- **Maintenance mode + banner for users during works** — a superadmin can put the
  bot into maintenance from the admin panel (**🛠 Режим обслуживания**). While it
  is on, every non-superadmin update is short-circuited by a new outer
  `MaintenanceModeMiddleware` (registered ahead of the blocked-user gate) that
  replies with a banner instead of handling the request; superadmins (identified
  by `ADMIN_IDS`) keep full access so they can carry out the works. Enabling
  prompts for an optional custom banner (FSM step; "No text" uses an i18n default),
  and both enabling and disabling push a one-off broadcast to all eligible users
  via the new best-effort `AnnouncementService.send_text_to_all` (same recipient
  pagination / rate-limiting as announcements). The flag is persisted in a new
  single-row `maintenance_settings` table (schema v25, mirrors
  `server_status_settings`) and restored into an in-memory snapshot at startup, so
  the gate survives restarts and costs zero DB reads while maintenance is off. The
  custom banner is HTML-escaped at a single choke point (`MaintenanceService.banner_text`)
  before it reaches any HTML-rendered surface. New i18n keys were added to both locales.

- **"Server status" panel shows the hypervisor's CPU share next to CPU usage** —
  the `⚙️ CPU` line now appends, in parentheses after the ordinary CPU%, the
  percentage of CPU time stolen by the hypervisor (the `/proc/stat` "steal"
  counter), e.g. `⚙️ CPU: 8.3% (гипервизор: 2.4%)`. The figure is sampled and
  smoothed alongside the regular CPU% (same averaging window and availability),
  defaults to 0.0% on bare metal / kernels without a steal field, and is hidden
  entirely when CPU is unavailable. It is shown only here — no other panel
  surfaces it. A new `server_status_cpu_hypervisor` i18n key was added to both
  locales.

- **"Server status" panel shows the snapshot time as a freshness indicator** —
  the title line now carries an italic "обновлено HH:MM:SS" ("updated HH:MM:SS")
  mark (UTC, matching the dashboard). The timestamp is stamped on the
  `ServerStatus` snapshot at *sampling* time by the background sampler (new
  injectable `wall_clock`), not computed at render time, so if the sampler stalls
  or Telegram stops delivering edits the mark freezes alongside the data instead
  of ticking on stale numbers. A new `server_status_updated_at` i18n key was added
  to both locales; a cold cache (no timestamp yet) renders no mark.

- **Live-updating "Server status" panel** — the admin **📊 Статус сервера** card
  now refreshes itself in place about once a second (`LiveRefreshManager`) so CPU,
  RAM, disk and network read in real time without tapping **Refresh**. Each open
  card is capped at one hour of auto-refresh; when the cap elapses the card falls
  back to the admin panel so an abandoned panel stops sampling `/proc` and editing
  the message. Navigating away (the card's **Back** button → `admin:panel`)
  cancels the loop immediately, and re-opening the panel restarts the timer. A new
  `edit_message_for_refresh` helper edits the card in place without ever
  re-posting a fresh message, so a deleted card simply ends its loop.

### Changed

- **"Server status" detailed view reworks the load-average line, the disk row
  and the network sparkline.** Three independent tweaks to the panel:
  - *Load average shown as percentages.* The `📈 Средняя нагрузка (1/5/15м)` line
    now renders all three figures as a percentage of total CPU capacity
    (`load ÷ cpu_count × 100`, so 100% == every core fully busy) instead of the
    raw kernel run-queue numbers, and the trailing `(N% / M CPU)` parenthetical is
    dropped — each window already carries its own percentage. When the CPU count
    is unknown it falls back to the raw figures.
  - *Disk progress bar removed.* The `💾 Диск` row keeps its "used / total" text
    but no longer draws the 10-cell usage bar (CPU and RAM bars are unchanged).
  - *Sparkline widened to 20 columns and re-bucketed per render.* The network
    sparkline is no longer a sliding-window downsample recomputed every sampler
    tick (which let one sampled second drift across several columns over time).
    Instead each Telegram render flushes one column: the per-second samples
    gathered since the previous render are averaged into a single bucket, frozen
    into a 20-wide rolling window, and the accumulator reset — so every sampled
    second feeds exactly one column. At the panel's 3s render cadence the 20
    columns span ≈ the last minute, matching the avg/peak/trend history window.
    The unused `_downsample` helper was removed.

- **"Server status" network avg/peak/trend now share the sparkline's window.**
  The detailed `📥/📤 сред … макс …` figures (and their `↑/↓/→` trend arrows) were
  computed from a separate per-second 60-sample history (`_history`) updated on
  every sampler tick, while the sparkline was rebuilt per Telegram render — so the
  two could describe slightly different minutes and update on different clocks.
  The avg/peak/trend are now derived per render from the **same** per-direction
  render buckets that build the sparkline (`net_in_avg`/`net_out_avg` as the bucket
  means, `…_peak` as the bucket maxima, trends over the bucket series), so all four
  read off one identical, render-synchronized ≈minute and move together on each
  refresh. The peak therefore matches the tallest sparkline column rather than a
  single un-bucketed second. The now-redundant `_history` deque and `_HISTORY_LEN`
  constant were removed; with no net-available column yet the block reads "no data".

- **First render of the "Server status" panel also honours Telegram 429
  back-off** — the panel's initial open goes through `safe_edit_message_text`
  (not the auto-refresh path), which previously caught only `TelegramBadRequest`
  and let `TelegramRetryAfter` (HTTP 429) escape to the callback error handler.
  It now waits the server-provided `retry_after` (clamped to the same 5s ceiling)
  and retries the edit once; if the flood persists it leaves the message
  unchanged and returns "not applied" rather than re-posting a duplicate card —
  the auto-refresh loop, which also honours 429, fills the original message in
  within ~1s. The existing `safe_edit_message_text` branches (not-modified,
  edit-unavailable re-post, raise) are unchanged.

- **"Server status" panel refreshes once a second and honours Telegram 429
  back-off** — the auto-refresh cadence (`LiveRefreshManager` default interval)
  drops from 2s to **1s**. The render no longer blocks (the snapshot is served
  from the background sampler's cache), so the only remaining limit is Telegram's
  edit rate. To make a 1s cadence safe, `edit_message_for_refresh` now catches
  `TelegramRetryAfter` (HTTP 429): it waits the server-provided `retry_after`
  (clamped to a 5s ceiling so a pathological value cannot park the loop), retries
  the edit exactly once, and — if the flood persists — keeps the card alive and
  lets the next tick try again instead of spinning on retries. Previously
  `TelegramRetryAfter` (a sibling of `TelegramBadRequest`, not a subclass) slipped
  past the helper into the loop's generic handler, so the back-off was ignored and
  the bot kept hammering the rate limit. The back-off stays local to the
  Telegram-specific helper; `LiveRefreshManager` remains generic. The panel
  lifetime cap (one hour) and the sampler interval (1s) are unchanged.

- **Continuous background sampling for the "Server status" panel** — host
  metrics are now collected by a single always-on sampler (`ServerStatusService.run`,
  started in `main.py`) instead of each render taking its own blocking two-reading
  sample. The previous design slept ~1s inside every `snapshot()` and measured only
  the `[t, t+1]` window per 2s refresh tick, so every other second of CPU/network
  activity went unobserved (a "blind second"). The sampler now reuses each reading
  as the next window's baseline, so measurement windows abut edge-to-edge with no
  gap, network speed is divided by the actually-elapsed Δt, and `snapshot()` returns
  the latest cached reading instantly (no blocking sleep on the render path). RAM and
  disk are read live each tick; before the first rate is available CPU/network render
  as "no data" while RAM/disk show immediately. Graceful degradation on unreadable
  `/proc` is unchanged, and no new dependencies were added (stdlib + `/proc` only).

- **Server-status disk metric now reports used space instead of free** — the
  **💾 Диск** line reads `{used} GB занято из {total} GB` (`{used} GB used of
  {total} GB` in English), derived from a new `ServerStatus.disk_used_gb`
  (`total − free`, clamped at zero), matching how operators expect disk usage to
  be shown.

## [2.0.0] — 2026-06-20

### Added

- **Background Xray traffic-stats collector** — a new `refresh_all_xray` loop
  keeps the dashboard's Xray traffic fresh, mirroring the existing AWG collector
  (`XRAY_STATS_INTERVAL`, default `60s`, `0` disables). `xray api statsquery` is
  read without `-reset` (whose Xray default is `false`), so the query is
  non-destructive: reading one key's counters never zeroes another's. Manual stat
  views (`refresh_for_actor`, `list_for_superadmin`) therefore poll Xray live, just
  like AWG, and stay fresh even when `XRAY_STATS_INTERVAL=0`; the loop only keeps
  the cache warm between manual views. Because `statsquery` returns the whole
  fleet's counters in one call, the loop still captures every key in a single
  `statsquery` per cycle (paginating the DB read into one `refresh_views` call).
  Concurrent refreshes are serialised on `_refresh_lock` so a stale snapshot can
  never overwrite a fresher one.

- **WARP split-routing on/off/restart toggle** — the **Enable / Disable /
  Restart** buttons in the «Outbound IP masking» panel now control the selective
  split **routes** in the dynamic tunnel table `T`, not the tunnel process or
  interface (which stay owned by systemd — the observer model is intact, so the
  previously no-op buttons gain real meaning). **Disable** reconciles table `T`
  to empty (retracts only the `<prefix> dev out-warp` routes → all traffic
  direct) and writes a root-owned marker; the saved list, the anti-loop endpoint
  route, `ip rules` and NAT/FORWARD are left untouched. **Enable** clears the
  marker and reconciles table `T` back to the saved list; **Restart** flushes
  then re-applies (final state: enabled). The state is persistent — a new
  `scripts/vpnbot-warp-split` boot-honour reconciles table `T` to empty whenever
  the marker is present, so an "off" state survives a reboot. All table-`T`
  mutation goes through a new privileged helper `scripts/vpnbot-warp-split-state`
  (`on|off|restart|status`, sudoers-pinned per verb, no wildcard); the bot never
  calls `ip`/`awg`/`iptables`. The panel's Tunnel (observer) and Routes (marker
  intent + actual table `T`) lines come from `WarpSplitManager.status()`, which
  never raises and surfaces an intent/reality drift as a warning. New settings
  `WARP_SPLIT_STATE_HELPER_PATH` / `WARP_SPLIT_DISABLED_MARKER_PATH`,
  `WarpSplitManager.enable()/disable()/restart_routes()/status()`, plus
  `tests/test_warp_split_state.py` and `tests/test_warp_panel_ui.py`.
- **WARP Split-routes entry moved into «WARP Settings»** — the **🌐 Split routes**
  button now lives in the ⚙️ Settings sub-panel (next to Replace/Delete config),
  not on the main WARP panel; the Split panel's Back button returns to Settings.
  The Split panel itself, its `/warp_split_*` commands and config-management
  buttons are unchanged.
- **WARP split-list GUI** — the selective-split prefix list can now be managed
  with inline buttons inside the existing **WARP tunnel** admin section, in
  addition to the `/warp_split_*` commands (which keep working unchanged). A new
  **🌐 Split routes** button opens a paginated panel (≈8 prefixes per page, each
  with a 🗑 button), plus **➕ Add** (FSM: send one or more IPv4 CIDRs by
  space/comma/newline, parsed per-line into added / dup / rejected reports),
  **🔄 Apply** (re-applies the current list), and per-prefix delete with a
  Yes/No confirmation step. Pure presentation: every mutation goes through
  `WarpSplitManager` (`process_*_tokens` + `apply_list`) exactly as the commands
  do — the UI adds no `ip`/`iptables`/file-write/helper logic. Every callback and
  the FSM input handler is superadmin-gated server-side (never relies on a hidden
  button), manager refusals (guard-reject, del-to-empty, helper failure) are
  shown in the panel without crashing, and the FSM state is always cleared after
  add/cancel. New components: `bot/handlers/admin_warp_split_ui.py`,
  `bot/keyboards/warp_split_keyboard.py`, the `WarpSplitStates` FSM group, the
  `btn_warp_split` i18n key (ru/en), and `tests/test_warp_split_ui.py`.

- **WARP split-list bot control** — admins can now manage the selective-split
  prefix list (`/etc/vpnbot/warp-split.list`) directly from Telegram without
  touching the server. Four new commands (superadmin-only):

  - `/warp_split_add <cidr…>` — add one or more IPv4 CIDRs; tokens may be
    separated by spaces, commas or newlines. Mask is mandatory (bare IPs are
    rejected with a `/32` hint). Host bits are silently corrected and the
    normalisation is reported (`1.2.3.4/24 → 1.2.3.0/24`). Guard-list rejects:
    `0.0.0.0/0` (suggests full-tunnel toggle), AWG client subnet (from
    `AWG_NETWORK`), WARP tunnel range `172.16.0.0/12`, loopback, link-local,
    multicast, server's own `eth0` subnet (runtime-detected). Duplicates are
    skipped. The entire batch is applied in one helper call (one service restart).

  - `/warp_split_del <cidr…>` — remove one or more CIDRs. Refuses if removal
    would empty the list (suggests using the WARP toggle or a sentinel prefix).

  - `/warp_split_list` — show current list sorted by network address + count.

  - `/warp_split_reload` — re-apply the current file without changing it
    (recovery after manual edits or after a service restart failure).

  **Architecture:** the bot is a thin controller — it reads the list file
  directly (0644) and writes exclusively via the new privileged helper
  `vpnbot-warp-split-apply` (root:root 0755, sudoers grant scoped to that
  binary only). The bot never calls `ip`/`iptables`/`awg-quick`.

  New components:
  - `scripts/vpnbot-warp-split-apply` — privileged helper: reads CIDR list
    from stdin, validates every non-comment line with `python3 ipaddress`
    (IPv4-only, mask required, strict CIDR), writes `/etc/vpnbot/warp-split.list`
    atomically (temp + `mv` rename, same fs), restarts `vpnbot-warp-split`.
    Empty stdin or any invalid line → `exit 1`, nothing written.
  - `warp/split_manager.py` — `WarpSplitManager` class: reads list, validates
    tokens (normalisation + guards), computes add/del diffs, calls the helper
    via `PrivilegedHelperRunner` (always sudo).
  - `bot/handlers/admin_warp_split.py` — four command handlers.
  - `deploy/sudoers.d/vpnbot.example` updated: new `VPNBOT_WARP_SPLIT` alias
    scoped to `/usr/local/sbin/vpnbot-warp-split-apply` (no wildcards needed —
    list goes over stdin).
  - `deploy/setup-nonroot-helper-mode.sh` updated: installs the new helper to
    `/usr/local/sbin/`.
  - `deploy/check-nonroot-helper-mode.py` updated: `vpnbot-warp-split-apply`
    added to `WARP_HELPERS` so the preflight checker flags a missing install.
  - Two new settings: `WARP_SPLIT_LIST_PATH` (default
    `/etc/vpnbot/warp-split.list`) and `WARP_SPLIT_APPLY_HELPER_PATH` (default
    `/usr/local/sbin/vpnbot-warp-split-apply`).
  - `pyproject.toml`: `pythonpath = ["."]` added to `[tool.pytest.ini_options]`
    so project-module imports work when running `pytest` directly (not only via
    `python -m pytest`).

  **Tests** (`tests/test_warp_split_bot_control.py`, 52 cases):
  - CIDR parsing/normalisation/guard/dedup matrix
  - Helper: valid list, empty stdin abort, garbage-line abort, IPv6 abort, bare-IP
    abort, comments/blanks pass-through, atomicity (no temp file leaked), overwrite
  - Sudoers: grant present, NOPASSWD set, no wildcards on the helper
  - check-nonroot expects the helper
  - Invariant: no `subprocess.run(["ip"…])` in `bot/` or `warp/` code

- **WARP post-activation layer: selective-split and boot-failsafe** — two additive
  scripts and systemd units on top of the full-tunnel base from #160, codified from
  the server-tested configuration:
  - `scripts/vpnbot-warp-split` / `deploy/vpnbot-warp-split.service` — selective
    routing: instead of a single `default dev out-warp` in the tunnel table, the
    script removes that default and adds one `ip route replace <prefix> dev out-warp
    table T` per line in `/etc/vpnbot/warp-split.list`; unlisted traffic egresses
    directly via `eth0`. An explicit `/32` anti-loop pin for the WARP endpoint is
    always installed in table T. Direct-path NAT (`MASQUERADE -s <client_net|proxy>
    -o eth0`) and the awg0↔eth0 FORWARD rules are added on apply and removed on
    revert. The script is safe-by-default: it aborts without touching any routes when
    the list is empty/missing or the fwmark is off (`tunnel down?`). `ip rule` entries
    remain owned by `warp-routes` — this script never touches them. The unit is
    `Type=oneshot RemainAfterExit PartOf=warp-routes.service` and requires the list
    file to exist (`ConditionPathExists`). Rollback to full-tunnel: `systemctl disable
    --now vpnbot-warp-split` + reboot.
  - `scripts/warp-failsafe` / `deploy/warp-failsafe.service` — boot watchdog: waits
    `WARP_FAILSAFE_DELAY` seconds (default 75) for the tunnel to settle, then checks
    whether host egress is on `eth0`; if not (the flip broke SSH), it stops
    `warp-routes.service` + `awg-quick@out-warp.service`, brings the interface down,
    and strips the host-bypass rules so the host falls back to the direct path and SSH
    returns. No-op when healthy (logs "healthy, no action"). `Type=oneshot
    After=warp-routes.service`.
  - `deploy/warp-split.list.example` — representative list with Telegram, Google,
    GitHub, and Cloudflare broad ranges; comments explain why narrow `/32` picks miss
    round-robin CDNs and why the WARP endpoint must not be listed.
  - `deploy/setup-nonroot-helper-mode.sh` updated: installs both scripts to
    `/usr/local/sbin`, both unit files to `/etc/systemd/system`, reloads daemon,
    manages the danted drop-in (`vpnbot-warp.conf`), removes the stale
    `10-after-warp.conf`, and creates `/etc/vpnbot/` — but does NOT auto-enable
    either unit (operator enables via the WARP activation runbook in README).
  All env-knobs (`WARP_IFACE`, `WAN_DEV`, `WARP_PROXY_SRC`, `WARP_CLIENT_NET`,
  `WARP_ENDPOINT_IP`, `WARP_SPLIT_LIST`, `WARP_FAILSAFE_DELAY`) are the only
  points of configuration. Code from #160 is untouched.

- **WARP proxy egress: the local proxies (Dante/Xray/MTProto) can now egress
  through the tunnel too, masking their outbound IP like the AWG clients'** — a
  local proxy cannot be matched by source subnet (its packets carry the host's real
  IP, and `MASQUERADE -o out-warp` does not rewrite locally-generated,
  fwmark-rerouted packets), so the inner source is made equal to the tunnel IP
  (read from the config's `[Interface] Address`, never hardcoded) two ways:
  - **Source-bind daemons** (Dante `external`, Xray `sendThrough`) already egress
    with `src == tunnel-ip`; `vpnbot-warp-routes` adds a single
    `ip rule from <tunnel-ip> lookup <T>` (priority `999`) and needs **no** NAT.
  - **MTProto/mtg** cannot source-bind, so it is cgroup-marked (`fwmark 0x2`,
    priority `998`) and given an **explicit SNAT** to the tunnel IP, inserted
    *above* the broad `out-warp` MASQUERADE. The step runs only when the mtproxy
    unit exists and is idempotent/safe when it is absent; the cgroup-match (which
    needs the running cgroup) is re-asserted from the unit drop-in
    `deploy/mtproxy-warp.conf` via a privileged `ExecStartPost` once mtg is up.
  Xray's `config.json` is rewritten by the bot, so the freedom outbound's
  `"sendThrough": "<tunnel-ip>"` is re-emitted on **every** config write (gated by
  the new `WARP_PROXY_EGRESS` flag; only the outbound is touched, so the hybrid
  REALITY/XHTTP inbounds are unaffected, and non-WARP deploys are unchanged). Dante's
  `external:` is a manual `danted.conf` prerequisite (it is not bot-managed);
  `deploy/danted-warp.conf` and `deploy/mtproxy-warp.conf` order the daemons after
  the tunnel is up. `vpnbot-warp-routes` gains idempotent `proxy-add`/`proxy-del`
  sub-actions. Activation is a deliberate, reboot-guarded manual runbook (see
  README "WARP proxy egress"); the host is never placed in the tunnel.

- **WARP egress now diverts the AmneziaWG client subnet through the tunnel via
  the production-proven `Table = auto` recipe** — `vpnbot-warp-routes` was
  rewritten to match the manually-debugged working scheme and replace the previous
  table-`200` policy-routing implementation, which created a routing loop (the
  server hung). The tunnel is now brought up by `awg-quick@out-warp` with
  `Table = auto` (the install helper forces it; the old `Table = off` is what broke
  routing), which sets an fwmark on the WG socket and creates a **dynamic** routing
  table (read at runtime from `awg show out-warp fwmark`, never hardcoded). `add`
  then: strips the awg-quick host-bypass immediately so the host (SSH, the bot,
  apt) never enters the tunnel; installs a single narrow `from 10.0.0.0/24 lookup
  <T>` rule (priority 1000); pins the WARP endpoint (read at runtime) to the real
  WAN gateway in both the main and the tunnel table (anti-loop); swaps the NAT to
  `MASQUERADE -o out-warp` (dropping any direct client masquerade); inserts the
  `FORWARD` accepts above UFW; and sets `rp_filter=2`. It finishes with a
  self-check (host egress NOT tunneled + client routed via `out-warp`) and rolls
  back to direct client egress on failure. `del` reverses everything, restores the
  direct WAN masquerade for the client subnet and is safe on a clean system; it
  never restores the host-bypass. The install helper also symlinks
  `/etc/amnezia/amneziawg/out-warp.conf` so `awg-quick@out-warp` resolves the
  config by name, and `deploy/setup-nonroot-helper-mode.sh` now installs the four
  WARP helpers (previously omitted, so a `git reset` deploy left a stale
  `/usr/local/sbin/vpnbot-warp-routes`). `deploy/warp-routes.service` (oneshot,
  bound to `awg-quick@out-warp`, ordered after `awg-quick@awg0`) applies it at
  boot. Every add step is idempotent. Forwarding Dante/Xray/MTProto through WARP is
  intentionally out of scope here — only AmneziaWG clients are diverted.
- **Second VLESS transport — VLESS (HTTP) over XHTTP+REALITY** — key creation now
  has two steps: choose protocol (`AmneziaWG 2.0` / `VLESS`), then for VLESS choose
  transport (`VLESS (TCP)` / `VLESS (HTTP)`). `VLESS (TCP)` keys live only in the
  existing `vless-in` inbound (raw/TCP, `flow=xtls-rprx-vision`, port 443);
  `VLESS (HTTP)` keys live only in a separate `vless-xhttp-reality` inbound (XHTTP,
  no flow, port 8443). Each key belongs to exactly one inbound; deletion and link
  regeneration are routed by the key's saved transport. The XHTTP client link uses
  `type=xhttp` with the same REALITY `pbk`/`sni`/`sid` and never carries `flow`.
  Existing keys are labelled `VLESS (TCP)` and keep working unchanged. Gated behind
  `XRAY_XHTTP_ENABLED` (default off) — when disabled the bot behaves exactly as
  before. Adds settings `XRAY_XHTTP_ENABLED`, `XRAY_XHTTP_INBOUND_TAG`,
  `XRAY_XHTTP_PORT`, `XRAY_XHTTP_PATH`, `XRAY_XHTTP_MODE`, a `transport` column on
  `vpn_keys` (migration v23, backfilled to `tcp`), and a second `XrayConfigAdapter`
  bound to the XHTTP inbound tag. Server-side inbound seeding is documented in
  `docs/xray-xhttp-inbound.md`.

### Changed

- **WARP interface and routes now have a single owner (systemd); the bot's health
  monitor became a pure observer** — previously both `warp-routes.service` (at boot)
  and the bot's `WarpHealthMonitor` managed the same `ip rule`/`ip route` entries, so
  a flaky ICMP probe in the monitor would tear down routes the service had installed,
  producing a recovered → add → fail → del → down flap every ~30–60 s and spamming
  admins. A new **observer mode** (`WARP_MONITOR_OBSERVER_MODE`, default `true`) makes
  the monitor only probe the tunnel, persist state and notify admins on a real
  up→down/down→up change — it never runs `awg-quick`, `ip route` or `ip rule`.
  Enabling/disabling the WARP toggle now starts/stops only the observer monitor, so
  toggling it off no longer drops the tunnel or wipes the routes. The interface is
  brought up by `awg-quick@out-warp.service`; `warp-routes.service` is now bound to it
  (`Requires=`/`After=`/`PartOf=awg-quick@out-warp.service`) so routes are applied only
  after the interface is up and re-applied on restart. The fail threshold is now
  configurable and raised to `4` (`WARP_MONITOR_FAIL_THRESHOLD`, plus
  `WARP_MONITOR_SUCCESS_THRESHOLD`, default `3`) so a single dropped probe can't raise
  a false alarm. Set `WARP_MONITOR_OBSERVER_MODE=false` to restore the legacy
  bot-managed behaviour.

- **VLESS (HTTP) now rides vless-in's REALITY via an XHTTP fallback dest** — the
  XHTTP transport was retopologised on the server: `vless-in` (:443) terminates
  REALITY/TLS and forwards by path to an internal `vless-xhttp-reality` inbound,
  which is the fallback dest and now carries `security: none` (no REALITY of its
  own, only the http `clients[]`). The http-key code is realigned to that layout:
  the VLESS (HTTP) link is a hybrid of the TCP link — same `pbk`/`sni`/`sid`/`fp`
  and the same public `:443` (`XRAY_PUBLIC_PORT`), differing only in `type=xhttp` /
  `path` / `mode=stream-one` and never carrying `flow`. The XHTTP `XrayConfigAdapter`
  is now built from VLESS *presence* (not REALITY) and runs with `require_reality=
  False`: it provisions/revokes UUIDs only in `vless-xhttp-reality`'s `clients[]`
  (never `vless-in`) and never manages REALITY shortIds there. `XRAY_XHTTP_PORT` is
  retained for back-compat but no longer used to build links; `XRAY_XHTTP_MODE`
  default is now `stream-one`. TCP and AWG key issuance/revocation are unchanged.
- **WARP module repositioned as outbound-IP masking (was "Telegram routing")** —
  the optional WARP module is now presented as a way to hide the server's outbound
  IP for selected "spy" applications (chosen via the config's `AllowedIPs`), not as
  a Telegram-only feature. All Telegram wording was removed from the module's UI
  (panel title `📡 Сокрытие outbound IP` / `📡 Outbound IP masking`, intro and
  upload prompt), docstrings, READMEs, `.env.example`, sudoers/helper docs. The
  interface and file paths were renamed `tg-warp` → `out-warp`
  (`/etc/amnezia/out-warp.conf`, `/etc/amnezia/out-warp-routes.list`), updating the
  helper scripts, the `VPNBOT_WARP` sudoers alias, the `warp_settings` defaults
  (schema/migration v20 docs), and the `WARP_CONFIG_PATH`/`WARP_INTERFACE` defaults.
  **Breaking for existing deployments that adopt the new names:** reinstall the
  `vpnbot-warp-*` helpers, update `/etc/sudoers.d/vpnbot` to the new `out-warp`
  entries, and re-upload the WARP config. Deployments that keep their current
  sudoers and stored `interface_name`/`config_path` (still `tg-warp`) continue to
  work unchanged.
- **AWG config file lifecycle** — the «Показать конфиг» button no longer sends a
  duplicate `.conf` file when one is already on screen for that key (it shows a
  «Файл конфигурации уже отправлен.» toast instead), and tapping any other button
  on the key card now removes the previously sent config-file message. A new
  `ConfigDocumentCleanupMiddleware` performs the cleanup for every callback except
  «show config», and the just-sent file is tracked in FSM state by the create,
  admin-issue, and show-config flows.
- **VLESS (HTTP) management decoupled from the feature flag** — managing an
  already-issued `VLESS (HTTP)` key (revoke / delete / reconcile) no longer depends
  on `XRAY_XHTTP_ENABLED`. The second `XrayConfigAdapter` is now built from the
  actual presence of the XHTTP inbound in `config.json`, so turning the flag back
  off can never strand live http keys as unrevocable. `XRAY_XHTTP_ENABLED` now
  gates only the issuance of *new* http keys (the UI button + a create guard), and
  with XHTTP disabled the VLESS button goes straight to TCP key creation instead of
  a single-option transport step. With the flag off and no XHTTP inbound the bot
  behaves exactly as before.
- **Unified VLESS key label** — the config header and stored `display_name` now read
  `VLESS (TCP)` / `VLESS (HTTP)` (matching the key list) instead of `Xray`.

### Removed

- **Legacy `tg-warp` cleanup** — the WARP interface and its on-disk files were
  renamed `tg-warp` → `out-warp` (the active path is `awg-quick@out-warp` + the
  `vpnbot-warp-routes`/`-split`/`warp-failsafe` layer from #160/#161, and every
  repo helper already targets `out-warp`). Servers upgraded across that rename
  still carried orphaned `/etc/amnezia/tg-warp.conf` (with a stale `PrivateKey`)
  and `tg-warp-routes.list`. `deploy/setup-nonroot-helper-mode.sh` now removes
  both with an idempotent `rm -if-exists` (modelled on the existing danted
  `10-after-warp.conf` cleanup). The active `out-warp.conf` (+ its
  `amneziawg/out-warp.conf` symlink and `.WORKING` backup) and `out-warp-routes.list`
  are never touched. The remaining `tg-warp` mentions in this changelog are
  historical and intentionally kept.

### Fixed

- **WARP selective-split: removed prefixes kept routing through WARP until reboot**
  — `vpnbot-warp-split apply` was additive: it added a `<prefix> dev out-warp` route
  in the dynamic tunnel table for every listed prefix but never removed the ones
  that had been deleted from `/etc/vpnbot/warp-split.list`. So `/warp_split_del`
  dropped the prefix from the file and restarted the service, yet the stale route
  lingered (`restart` = `revert` + `apply`, and neither flushed it). `apply` now
  reconciles the table against the list: it enumerates the script-managed per-prefix
  routes (`<prefix> dev out-warp`) in the tunnel table and `ip route del`s the ones
  no longer listed, then `ip route replace`s the wanted ones (idempotent, no flap on
  still-listed prefixes). Only `dev out-warp` per-prefix routes are touched — the
  anti-loop endpoint pin (`162.159.195.1/32 via <gw> dev eth0`), `ip rule`s, NAT and
  FORWARD rules from the full-tunnel layer are left untouched, and the dynamic table
  number is still read from `awg show out-warp fwmark`. An empty/missing list still
  aborts safely (refuses to blackhole).

- `XRAY_XHTTP_INBOUND_TAG` colliding with `XRAY_INBOUND_TAG` (or left empty) while
  `XRAY_XHTTP_ENABLED=true` is now rejected at startup in `load_settings` instead of
  lazily on the first key issuance. A startup diagnostic also logs loudly when
  `VLESS (HTTP)` keys exist in the DB but their XHTTP inbound is absent, so the
  operator knows they are unmanageable until the inbound is restored.

### Security

- **Upgraded `aiohttp` 3.13.5 → 3.14.1, `aiogram` 3.27.0 → 3.29.0, and
  `cryptography` 46.0.7 → 48.0.1 to clear all outstanding `pip-audit` advisories.**
  `aiohttp` 3.14.1 fixes nine CVEs (CVE-2026-50269, -54273, -54276, -54277,
  -54278, -54279, -54280, plus the two previously VEX-deferred CVE-2026-34993 /
  CVE-2026-47265); adopting it required raising the `aiogram` cap, which 3.29.0
  does (`aiohttp<3.15`). `cryptography` 48.0.1 fixes GHSA-537c-gmf6-5ccf (High —
  OpenSSL out-of-bounds read bundled in the wheels). The `PIP_AUDIT_IGNORES` VEX
  list in the `Makefile` is now removed — `make audit` runs with no exceptions and
  reports no known vulnerabilities. Hashed constraint sets were regenerated and the
  un-hashed mirror re-synced.

## [1.3.0] — 2026-06-04

### Added

- **Live admin dashboard** — new «📊 Дашборд» button in the admin panel opens a
  single auto-refreshable message with six stat blocks: 👥 Users (role breakdown,
  new in 7/30 d, active keys, pending requests), 🔑 VPN keys (active Xray/AWG,
  expiring in 7/30 d, stale, average per user), 📊 Traffic (totals Xray/AWG,
  per-key average, Top-5 users), 🌐 Proxy (active SOCKS5/MTProto, stale), ⚙️
  System (backend status, WARP, DB size, last backup time), 📋 Activity (audit
  24 h/7 d, announcements in 30 d, last 3 actions). All 17 data sources are
  queried in parallel via `asyncio.gather`. Adds `repositories/dashboard.py`,
  `services/dashboard.py`, and `bot/handlers/admin_dashboard.py`. (#132)
- **WARP tunnel Telegram alerts** — `WarpHealthMonitor` now fires optional
  `on_tunnel_down` / `on_tunnel_recovered` callbacks on every route-state
  transition; `WarpManager` wires them to send a dismissible inline alert to all
  admins (🔴 tunnel down / 🟢 recovered). The alert message is deleted when the
  admin taps «✅ Понял». (#134)

### Changed

- **Usage rules formatting** — removed the blank line between the «ПРАВИЛА
  ПОЛЬЗОВАНИЯ:» header and the first prohibition icon, making the block more
  compact. (#133)
- **Dashboard layout** — Top-5 traffic users and recent audit actions are now
  displayed in a column (one entry per line) instead of a pipe-separated single
  line. (#148)
- **Server restart notice** — schedule wording updated from «по чётным числам» to
  «по числам, кратным пяти», and the expected downtime from «несколько минут» to
  «несколько десятков секунд». (#149)

### Fixed

- **AWG keys hide IP on listing page** — `key_list_card` no longer shows the
  assigned IP for AmneziaWG keys (IP is meaningful in the config file, not as a
  display label); Xray keys are unaffected. (#145)
- **Deleted-key traffic preserved in dashboard totals** — `hard_delete_with_stats`
  previously removed both the key row and its `vpn_key_traffic_stats` entry,
  silently dropping lifetime bytes from the dashboard. A new
  `deleted_key_traffic_archive` table (schema version 22) captures the byte counts
  at deletion time within the same transaction; `traffic_totals()` and
  `top_users_by_traffic()` `UNION ALL` the archive so lifetime traffic is always
  reflected. (#146)
- **Deleted-key traffic archive consistency** — follow-up to #146: migration v22
  is now properly wired into the versioned ladder (`_migrate_v22`,
  `CURRENT_SCHEMA_VERSION = 22`); dashboard `avg_per_key_bytes` is now computed
  over the same live-plus-archive dataset as `total_bytes` so `avg × keys = total`;
  `top_users_by_traffic` username is deterministic (`MAX(username)`); covering
  indexes added on the archive table for index-only aggregation scans. (#147)
- **Dependency audit set realigned with the installed set** — `constraints.txt`
  (scanned by `pip-audit`) had drifted from `constraints-hashed.txt` (installed
  with `--require-hashes`): five transitive pins disagreed (`aiohappyeyeballs`,
  `certifi`, `idna`, `propcache`, `yarl`) and `cffi`/`pycparser` were missing
  entirely. `constraints.txt` is now generated as the un-hashed mirror of
  `constraints-hashed.txt` via `scripts/sync-constraints.py` (wired into
  `make update-hashes`), so the audited and installed sets can no longer diverge.
  (#141)
- **i18n key parity** — removed the orphan `btn_proxy_stats` key that existed only
  in the English catalogue, restoring ru/en parity; `i18n.t()` now falls back to
  the base (ru) string before the raw identifier when a key is missing in the
  active locale. Added `tests/test_i18n_parity.py` (key/placeholder/HTML parity)
  and `tests/test_env_settings_drift.py` (settings ↔ .env.example/README drift).
  (#141)
- **Documentation drift** — documented the WARP Telegram routing module and
  `WARP_PING_TARGET` in `README_RU.md` (previously English-only) and in
  `.env.example`; fixed the `BOT_LOCK_PATH` default and the `XRAY_FINGERPRINT`
  value list in `README.md`; refreshed the database-table list in both READMEs;
  surfaced previously undocumented tunables (`ANOMALY_*`, `KEY_EXPIRY_*`,
  `BOT_LANGUAGE`, staging dirs, …) in `.env.example`; aligned `CONTRIBUTING.md`
  with the actual CI gates. (#141)

### Security

- **WARP root-RCE via config hooks closed** — `awg-quick` executes
  `PreUp/PostUp/PreDown/PostDown` as root; both the bot-side
  `warp/config_validator.py` and the `vpnbot-warp-install` root boundary now
  reject any of these directives (case-insensitive). (#140)
- **AWG arbitrary root file-write and rollback corruption fixed** — `vpnbot-awg-apply`
  wrote the stripped config into the bot-writable staging directory via a plain
  `open("wb")`, allowing a symlink to redirect the write to any root-owned path;
  rollback aliased the canonical config, causing self-truncation. The helper now
  stages the strip-input in the root-owned canonical directory with
  `O_CREAT|O_EXCL|O_NOFOLLOW`. (#140)
- **Default-route guard extended** — `vpnbot-warp-routes` now skips any
  default-equivalent route (`default`, prefix length 0 or 1, including the
  two-`/1` split-default trick); `vpnbot-warp-install` validates every
  `AllowedIPs` token as a real CIDR at the root boundary. (#140)
- **Privileged-process zombie on timeout prevented** — `shell_runner.py` now
  launches subprocesses in a new session and sends `SIGKILL` to the entire process
  group on timeout, ensuring grandchild processes (e.g. `awg`) are also reaped;
  `xray_config._apply_helper` no longer retries on timeout to avoid a concurrent
  double-apply race. (#139)
- **Adapter injection vectors closed** — AWG config `label` field rejects
  whitespace/control characters; `dante_users` validates the password for `\n`,
  `\r`, `\x00`, and `:` at the adapter boundary (not only in the helper); the
  `email_label` field in `xray_config.add_client` is validated against
  `_EMAIL_SAFE_RE`. (#139)
- **Secrets no longer leak through ShellResult or logs** — `ShellResult.stderr` is
  now stored redacted; redaction happens before truncation so secrets cannot appear
  in the tail of a long error output. REALITY inbound API config (containing the
  private key) is written with `umask 0600` + `fsync` instead of to `/tmp`. (#139)
- **Staging symlink attacks prevented** — `privileged_helpers.py` enforces 0700 on
  an already-existing staging directory, forbids symlink staging roots, correctly
  removes symlinks on cleanup, and rejects `..` and symlinks in the helper path;
  `vpnbot-warp-install` rejects a symlinked source file and operates on `realpath`.
  (#139, #140)
- **Moderator-initiated block now revokes all backend access** — `block_user` was
  reachable by moderators but the wired revokers required superadmin, leaving every
  VPN key and proxy access active on the backend after a moderator block. The block
  flow now uses system revokers (`revoke_*_system`) with correct audit attribution.
  (#137)
- **`disable_protocol` no longer orphans live backend access** — it previously
  hard-deleted database rows without revoking the corresponding Xray client / AWG
  peer / Dante user / MTProto secret. It now revokes each key/access through the
  full delete pipeline, enforces superadmin, writes an audit record, and refuses to
  run if purge handlers are not wired. (#137)
- **Concurrent trial approval no longer double-issues keys** — `approve_trial_request`
  provisioned the key before atomically claiming the request, allowing two
  concurrent approvals to each create a key. A decision lock and fresh status
  re-check now guarantee exactly one provisioning. (#137)
- **Trial flow rejects blocked users** — `create_trial_request` and the trial
  request handlers now reject blocked users; `/start` no longer offers the trial
  button to blocked users. (#136, #137)
- **IDOR in key detail view fixed** — `open_key` now cross-checks the `owner` from
  callback data against the key's real owner, matching the behaviour of `revoke`
  and `delete`. (#136)
- **HTML truncation and escaping fixes** — `cap_telegram_html` now closes
  `i`/`u`/`s`/`blockquote` tags (not just `b`/`code`/`pre`) on truncation and
  drops a trailing half-cut HTML entity; the user note in the admin «edit note»
  prompt is now HTML-escaped (every other note render already escaped it). (#136)
- **`RateLimiter` eviction bypass fixed** — throttled entries are now kept
  most-recently-used so they cannot be evicted (which would reset the cooldown)
  under high churn. (#136)
- **Secrets excluded from `repr()` and tracebacks** — `Settings.bot_token` and
  `Settings.default_proxy_password` are marked `repr=False`; `VpnKey`, `ProxyAccess`,
  and `ProxyEntry` DTOs have redacting `__repr__` so `payload`/`password` fields
  do not appear in logs or tracebacks. (#135, #138)
- **Central log redaction** — a redaction formatter is applied to every log handler
  so secrets are masked in every record even if the call site omits `redact()`;
  log files remain `0600` after rotation via a secure `RotatingFileHandler`. (#135)
- **Config validation hardened** — control characters are now banned in network
  values (host/SNI/DNS/AllowedIPs/flow) to prevent injection into configs and
  links; Fernet key is validated to decode to exactly 32 bytes; non-positive
  `ADMIN_IDS` are rejected; empty `HEALTH_HOST` defaults to `127.0.0.1` instead of
  binding all interfaces. (#135)
- **DB file created mode 0600** — the database file is created with `0600`
  permissions before `aiosqlite` opens it, closing the world-readable window; WAL
  checkpoint (`TRUNCATE`) added to `close()` to limit WAL growth; FK enforcement
  after migration v16 fixed (raw connection + `commit()` before `finally`). (#138)
- **Dashboard timestamp timezone consistency** — dashboard cutoffs now use the same
  `+00:00` format as stored values, eliminating boundary skew in
  `keys_summary`/`count_new_users_since`/`count_announcements_since`; the audit
  prune and `count_audit_since` queries now use `idx_audit_log_created_at` again
  (the `REPLACE()` that prevented index use was removed). (#138)
- **CI action pinning** — `actions/checkout` and `actions/setup-python` are now
  pinned by commit SHA (with version comments) instead of mutable tags; `push`
  CI is scoped to `main`. (#141)
- **Lint suppressions scoped** — the project-wide `S608` (SQL injection) and
  `S603`/`S607`/`S404` (subprocess) ruff ignores are now scoped to the
  directories that legitimately need them (`db/`, `repositories/`, `deploy/`,
  `tests/`), so the rest of the tree is guarded against new violations. Added
  `*-wal`/`*-shm`/`*-journal` ignores and a vulnerability-response timeframe to
  `SECURITY.md`. (#141)
- **aiohttp advisories triaged (VEX)** — `pip-audit` now runs via `make audit`
  with a documented `--ignore-vuln` list for `CVE-2026-34993` and
  `CVE-2026-47265`. Both are fixed only in aiohttp 3.14.0, which the tree cannot
  adopt while `aiogram` (≤3.28.2) caps `aiohttp<3.14`, and neither applies to the
  bot's client-only, trusted-host usage. To be revisited when `aiogram` raises the
  cap. (#141)

## [1.2.0] — 2026-06-01

### Added

- **WARP Telegram routing module** — optional server-side AmneziaWG (`tg-warp`) tunnel that routes traffic defined by the uploaded config's `AllowedIPs` through a dedicated tunnel interface, with automatic health-based fallback to the direct path on tunnel loss. Disabled by default; managed from a new admin panel tab (📡 WARP-туннель) with config upload, enable/disable/restart, settings and delete. An asyncio health monitor pings the tunnel every 10 s, removing routes after 2 consecutive failures and restoring them after 3 consecutive successes. The bot stays unprivileged: all root actions go through new `vpnbot-warp-install` / `-iface` / `-routes` / `-status` sudo helpers. `AllowedIPs` is never modified; the server DNS resolver and default route are never touched. Adds the `warp_settings` table (schema version 20), the `warp/` package, `bot/handlers/admin_warp.py`, `bot/keyboards/warp_keyboard.py` and `scripts/vpnbot-warp-*`. (#118)
- **Protocol modules management** — new «⚙️ Модули протоколов» tab in the admin panel lets superadmins enable or disable any protocol (Xray, AWG, SOCKS5, MTProto) independently. Disabling a protocol requires two-step confirmation and hard-deletes all related keys and proxy entries from the database; the bot UI hides all buttons and menus for the disabled protocol. Re-enabling restores access in one click (historical data is not recovered). Server-side configs and Linux accounts are unaffected. Adds the `protocol_modules` table (schema version 21). (#125)
- **Usage rules on main menu** — the main menu screen now displays a usage rules block warning users that MAX messenger and torrent traffic through VPN are strictly prohibited. (#128)

### Changed

- **Admin panel proxy tab unified** — «Статус прокси» and «Статистика прокси» tabs merged into a single «🌐 Прокси: статус и статистика» tab. The new combined view shows service configuration, lifecycle counters, and the per-user table in one message; zero-value fields are hidden to reduce noise. (#124)
- **Admin panel button order and emojis** — admin panel buttons are now sorted from most to least frequently used and all labels carry emojis (📋 Заявки, 👥 Пользователи, 🔑 Выдать ключ, 🧪 Пробные доступы, 📊 Статистика ключей, 🌐 Прокси, 📢 Объявление, 📡 WARP-туннель, ⚙️ Модули протоколов, 🔍 Диагностика, 📜 Логи, 🔄 Восстановление, 💾 Бэкап). (#126)
- **WARP ping target configurable** — `PING_TARGET` default switched from `149.154.167.50` to `162.159.140.245` (Cloudflare anycast, reliably responds to ICMP and present in typical WARP `AllowedIPs`). Deployments with Telegram-only `AllowedIPs` can override via the new `WARP_PING_TARGET` env variable to prevent false health-monitor failures. (#130)
- **Health diagnostics severity** — running as root and `PRIVILEGE_HELPERS_ENABLED=false` are now reported as `warning` (⚠) instead of `failed` (✗); the overall backend diagnostics status no longer shows FAILED in these configurations. (#129)

### Fixed

- **WARP config delete removes files from disk** — `delete_config` now calls the new `vpnbot-warp-install remove` sub-command to delete `/etc/amnezia/tg-warp.conf` and `/etc/amnezia/tg-warp-routes.list`, preventing the PrivateKey from persisting after config deletion. A helper failure is propagated as `WarpError` so the database is kept intact if the removal fails. (#119)
- **WARP config install uses secure temp files** — `vpnbot-warp-install` now creates mode-600 temp files with `install -m 600 /dev/null` before writing any content, then atomically `mv`s them into place, eliminating the window where an intermediate file containing the PrivateKey could be world-readable. (#119)
- **WARP DB migration version counter** — `_apply_migrations` was missing the `version = 20` assignment after `_set_schema_version(20)`, breaking the consistent pattern used by every other migration block. (#119)
- **WARP routes skip default routes** — `vpnbot-warp-routes` now skips `0.0.0.0/0` and `::/0` entries from `AllowedIPs` with a warning to stderr, preventing accidental capture of the default route and host isolation. The `del` branch mirrors this symmetrically. (#120)
- **WARP cap_net_raw probe on startup** — `WarpManager._start_locked` now runs one test ping immediately after the interface comes up and logs a `WARNING` pointing the operator to `getcap $(which ping)` if it fails, before the health monitor starts its loop. (#120)
- **WARP upload size validated after download** — `warp_upload_receive` now checks `len(buffer.getvalue())` after `bot.download()` completes to enforce the 64 KB limit on actual downloaded bytes rather than relying solely on the client-reported `file_size`. (#120)
- **WARP CIDR validation** — `validate_amnezia_config` now validates each `AllowedIPs` token via `ipaddress.ip_network(strict=False)` and raises `WarpConfigError` for invalid CIDRs, preventing bogus route-count inflation. (#121)
- **WARP upload rate-limit** — `warp_upload_receive` now enforces the same per-user rate-limit as other WARP admin actions (30 s cooldown). (#121)
- **AWG client traffic NATted through tg-warp** — `vpnbot-warp-routes` now adds an `iptables -t nat POSTROUTING MASQUERADE` rule for traffic leaving via `tg-warp`, so AWG clients (source `10.0.0.x`) reach the WARP endpoint correctly. The rule is idempotent (`-C` check before `-A`) and removed symmetrically in the `del` branch. (#122)
- **FORWARD rules for awg0↔tg-warp** — `vpnbot-warp-routes` now manages two iptables `FORWARD` rules: allow `awg0→tg-warp` and allow `tg-warp→awg0 RELATED,ESTABLISHED`, ensuring bidirectional packet forwarding for VPN clients routed through the WARP tunnel. (#123)
- **WARP upload prompt deleted on success** — the upload prompt message is now saved to FSM state and deleted after a config is successfully installed, consistent with the behaviour in other bot input flows. Validation errors leave the prompt intact so the user can retry. (#127)
- **Anomaly dismiss i18n** — hardcoded `«✅ Я прочитал»` string in `services/anomaly_detection.py` replaced with the new `btn_anomaly_dismiss` i18n key (ru + en); dead `anomaly_dismiss_keyboard()` helper removed from `bot/keyboards/admin.py`. (#121)

### Security

- **WARP PrivateKey protection** — config install now writes exclusively through mode-600 temp files and config delete propagates helper errors rather than silently clearing the database, preventing PrivateKey material from being exposed in world-readable intermediate files or from persisting on disk after deletion. (#119)

## [1.1.0] — 2026-05-30

### Added

- **Xray TLS fingerprint selection** — a new step in the Xray key creation flow lets users (and admins) choose a TLS fingerprint right after the note prompt; the selected value is embedded in the VLESS link (`fp=`) and stored in the key payload. Ten fingerprints are supported: `firefox` (default), `chrome`, `safari`, `ios`, `android`, `edge`, `360`, `qq`, `random`, `randomized`. Legacy keys without a stored fingerprint transparently fall back to the global `XRAY_FINGERPRINT` env variable. (#115)
- **Per-key fingerprint editing** — the key detail card for active Xray keys now includes a «Изменить Fingerprint» button that opens an inline keyboard to change the fingerprint; the VLESS link is regenerated and the detail card updated immediately. (#115)
- **Anomaly alert dismiss button** — anomaly alert messages now include an inline «✅ Я прочитал» button; clicking it silently deletes the alert only from that admin's chat, leaving other admins' copies intact. (#116)

## [1.0.2] — 2026-05-28

### Fixed

- **AWG key detail** — removed IP and public key fields from the AmneziaWG key detail card; MTU is now displayed instead. Config hint after showing an AWG config updated from «AmneziaWG» to «AmneziaVPN» in both locales. (#106)
- **Offsite backup timer** — weekly backup timer no longer resets after a bot reboot. The last-backup timestamp is now persisted in `schema_meta`; on startup the loop sleeps only for the remaining interval, or sends immediately if 7+ days have elapsed. (#112)

### Changed

- **Prompt message cleanup** — the inline-keyboard prompt message shown when the bot awaits a text reply (note or custom MTU) is now deleted before the next message is sent, reducing chat clutter. Covers all key-creation and note-editing flows for both users and admins. (#107)
- **Python version declaration** — declared Python support narrowed to `>=3.12,<3.13` in `pyproject.toml` and updated in `README.md`, `README_RU.md`, `CONTRIBUTING.md` to reflect that only Python 3.12.x is tested and verified. (#111)
- **Docstrings** — added concise one-line docstrings to all public methods and functions across `services/`, `adapters/`, `repositories/`, `bot/handlers/`, `bot/keyboards/`, and `bot/middlewares/`. (#110)

## [1.0.1] — 2026-05-25

### Fixed

- **Xray API mode** — `xray api adu` / `xray api rmu` silently fail for VLESS in Xray 26.3.27 (exit 0, «Added 0 user(s)»). Replaced both with `_api_reload_inbound`: reads the target inbound from the on-disk config, then calls `rmi` + `adi` to atomically replace it in the running Xray process. `rmi` errors on first run (inbound not yet loaded) are logged at DEBUG and ignored; an exception is raised only when `adi` fails. Rollback in `_install_candidate_api` now also goes through `_api_reload_inbound` after restoring the backup, falling back to `systemctl reload/restart` only if `adi` itself fails. (#103)

### Changed

- **Protocol selection menu** — menu heading «Выберите тип ключа:» renamed to «Выберите протокол:» (ru/en); button labels updated: «Xray» → «Xray (VLESS+XReality)», «AWG» → «AmneziaWG 2.0» across all three keyboards. (#104)

## [1.0.0] — 2026-05-23

### Added

#### Core bot
- Telegram bot (aiogram 3) with user registration and access approval flow (pending → approved/blocked).
- Role-based access control: `SUPERADMIN`, `MODERATOR`, `APPROVED_USER`, `PENDING_USER`, `BLOCKED_USER`.
- `MODERATOR` role between `APPROVED_USER` and `SUPERADMIN`; moderators can approve/block pending users without full admin access.
- Bot UI language support via `BOT_LANGUAGE` (`ru` / `en`).
- Single-instance lock (`utils/single_instance.py`).
- Optional HTTP health endpoint (`adapters/health_server.py`, `HEALTH_HOST` / `HEALTH_PORT`).

#### Xray VLESS Reality
- Key creation, VLESS link + JSON config delivery, revocation, deletion.
- Startup reconciliation between SQLite and live Xray config.
- Traffic stats via Xray gRPC stats API (`XRAY_STATS_SERVER`).
- `XRAY_APPLY_MODE=api` — applies config changes through the Xray management API without restarting the service; incompatible with `PRIVILEGE_HELPERS_ENABLED=true` (validated at startup).
- `XRAY_MANAGE_SHORT_IDS` — optional automatic per-client short-ID management.

#### AmneziaWG
- Key creation, client config delivery (INI format), revocation, deletion.
- `amnezia://` deep-link alongside the INI config; MTU selectable during key creation.
- IPAM (automatic IP allocation within `AWG_NETWORK`), preshared key support.
- Startup reconciliation between SQLite, `awg0.conf`, and AWG runtime.
- Background traffic accounting: periodic transfer-counter sampling under the refresh lock.

#### Proxy backends
- **SOCKS5/Dante** — per-user Linux account management (create, lock, delete) via `vpnbot-socks5-user` sudo helper. `SOCKS5_LOGIN_PREFIX` enforcement prevents managing arbitrary system users.
- **MTProto** — `static` mode (shared secret) and `managed` mode (per-user secrets, atomic apply, backup/rollback via `vpnbot-mtproxy-apply` sudo helper). Output always includes plain and `dd` random-padding Telegram links.
- Proxy access lifecycle: issue, revoke, delete, per-user stats from SQLite.

#### Admin panel
- Pending request queue, user management (approve, block, view), key issuance per user.
- Audit log viewer with recursive secret masking; configurable retention via `AUDIT_RETENTION_DAYS`.
- Traffic stats (Xray via gRPC, AWG via background sampler).
- Backend diagnostics: per-backend `OK` / `DEGRADED` status with sanitised reason.
- Announcements to all approved users.
- Scheduled announcements: future delivery time set by admin; background scheduler dispatches at the configured moment.
- User notes: free-text memos attached to any user card, stored per-user.

#### Key lifecycle extras
- Key expiry notifications — `KEY_EXPIRY_NOTIFY_DAYS` controls how many days before expiry users are notified.
- Trial access — time-limited VPN keys for `PENDING_USER` and `BLOCKED_USER`; trial state tracked in DB with admin reset capability.
- User self-service key management — approved users can revoke or delete their own VPN keys without admin intervention.

#### Anomaly detection
- Background monitor flags keys with suspiciously high traffic or concurrent-connection patterns.
- Configurable window, IP threshold, cooldown, and optional auto-revoke (`ANOMALY_AUTO_REVOKE`).
- Flagged keys appear in the admin panel.

#### Off-site encrypted backups
- Periodic DB snapshots encrypted with `cryptography` (Fernet, `OFFSITE_BACKUP_ENCRYPTION_KEY`) and uploaded to a configured Telegram chat.

#### Storage
- SQLite via `aiosqlite` with schema bootstrap and migrations (`db/schema.sql`).
- Tables: `users`, `access_requests`, `vpn_keys`, `trial_key_requests`, `proxy_entries`, `proxy_accesses`, `audit_log`, `vpn_key_traffic_stats`.
- `SQLITE_SYNCHRONOUS` setting; configurable DB path via `DB_PATH`.

#### Deployment
- **Root + api mode** (default): `User=root`, `PRIVILEGE_HELPERS_ENABLED=false`, `XRAY_APPLY_MODE=api` — bot writes Xray config and applies changes directly via gRPC API; no sudo helpers required.
- **Non-root privilege-helper mode**: bot runs as `vpn-bot:vpn-bot`; root-only operations go through four fixed sudo helpers (`vpnbot-socks5-user`, `vpnbot-xray-apply`, `vpnbot-awg-apply`, `vpnbot-mtproxy-apply`) with restricted sudoers grants.
- `deploy/vpn-bot.service` — authoritative systemd unit; overwrites the system service file on every deploy.
- `deploy/check-nonroot-helper-mode.py` — preflight and postflight healthcheck with human-readable and JSON output, pre-start and post-start modes.
- `deploy/create-vpn-bot-user.sh` — helper to create the `vpn-bot` system account.
- Rotating file logs via `LOG_DIR`.
- Config backup with retention policy (`CONFIG_BACKUP_KEEP_LAST`).

#### CI and quality
- GitHub Actions: `dependency-audit` (pip_audit) → `tests` (ruff, compileall, mypy --strict, pytest ≥ 60 % coverage) on Python 3.12.
- Hashed constraints files (`constraints-hashed.txt`, `constraints-dev-hashed.txt`) installed with `--require-hashes` to guard against supply-chain tampering.
- Dependabot for pip and GitHub Actions.
- `CONTRIBUTING.md` — development setup, code quality gates, commit format, branch naming, security considerations, PR process.
- `CODE_OF_CONDUCT.md` — Contributor Covenant 2.1.
- `.github/ISSUE_TEMPLATE/` — bug report, feature request, security hardening templates; blank issues disabled.
- `.github/SECURITY.md` — security policy and responsible disclosure guide.

### Security
- Privilege separation: all root operations go through four fixed-path sudo entrypoints; bot process runs unprivileged in non-root mode.
- `SOCKS5_LOGIN_PREFIX` enforcement prevents the bot from managing arbitrary Linux users.
- Secret redaction in all audit records, error messages, and log output.
- Config writes are atomic: staged file → validate → swap, with backup and automatic rollback on apply failure.
- Managed MTProto secrets and env files are `root:root 0600`; backup directories are `root:root 0700`.
- `XRAY_APPLY_MODE=api` + `PRIVILEGE_HELPERS_ENABLED=true` combination rejected at startup.

[2.1.0]: https://github.com/Egor051/vpnbot/compare/v2.0.0...v2.1.0
[2.0.0]: https://github.com/Egor051/vpnbot/compare/v1.3.0...v2.0.0
[1.3.0]: https://github.com/Egor051/vpnbot/compare/v1.2.0...v1.3.0
[1.2.0]: https://github.com/Egor051/vpnbot/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/Egor051/vpnbot/compare/v1.0.2...v1.1.0
[1.0.2]: https://github.com/Egor051/vpnbot/compare/v1.0.1...v1.0.2
[1.0.1]: https://github.com/Egor051/vpnbot/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/Egor051/vpnbot/releases/tag/v1.0.0
