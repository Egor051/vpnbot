# The decoy site from the bot

The decoy site is the static site nginx serves on `127.0.0.1:8443`. Xray's REALITY forwards
every TLS client that is not its own there (`realitySettings.target`), and Hysteria2's
masquerade proxies to the same listener (`deploy/hysteria/config.yaml`, `type: proxy`). A
probe therefore sees a real site on TCP and on UDP. **«🧙 Мастер настройки → 🌐 Сайт»**
replaces it with an archive sent to the bot, or puts the previous version back. Before this
change it was a hand-run script.

🇷🇺 Russian version: [site.ru.md](site.ru.md)

The nginx configuration and the certificate are only read, never written. nginx is not
reloaded: it reads the files on every request.

## The screen

SUPERADMIN only. The screen reads `vpn-bot-site status --json` and shows:

* **where the site is**: the docroot and the domain;
* **the live version**: the sha256 of its tree (12 hex), when and by which run the bot
  deployed it (or *not deployed by the bot*, with the date of its newest file), pages,
  files and size. A tree that changed after the deploy is marked 🟡. This is expected
  when `deploy/vpn-bot-decoy-freshen.sh` advances the site's timestamps;
* **the kept versions** and which one «Откатить» brings back;
* **spiderX**: whether `XRAY_SPIDER_X_POOL` names pages of the site (below);
* **Hysteria2**: whether its masquerade shows the same site.

Buttons:

| Button | What |
|---|---|
| **⬆️ Загрузить архив** | TOTP, then send the archive as a **document**. The bot stages it for root and starts a run of the wizard's `site` mode. The run's plan unpacks and checks the archive in isolation and shows what changes. **✅ Применить** (TOTP again) deploys it. |
| **↩️ Откатить на предыдущую** | The same run with the newest kept version instead of an archive. |
| **📄 Список страниц** | The pages of the live site (`/`, `/about.html`, `/blog/` for `blog/index.html`), 40 per screen. |

Every run is in «📜 История» with its log. The audit log records `wizard_run_*` (entity
`wizard`) and `site_spider_x_relayout` (the keys the run re-laid).

## Where the site is

The docroot is not hard-coded. It is the `root` of the nginx vhost that listens on
`127.0.0.1:8443` (`/etc/nginx/conf.d/*.conf`, `/etc/nginx/sites-enabled/*`):

* `/var/www/selfsteal` on a host where the bot installed Xray
  ([protocol-install.md](protocol-install.md), `deploy/nginx/selfsteal.conf`);
* `/var/www/anycastedge` (or whatever its vhost names) on a host set up by hand. The
  protocol install keeps such a vhost.

The domain is the vhost's `server_name`, or `HYSTERIA2_SNI` when the vhost has none. It is
the SNI of every check. The helper refuses, and the screen says why, when:

* no vhost listens there, or more than one does;
* the `root` is missing, more than one, has a variable, or is not a directory below
  `/var/www/`;
* the docroot is a symlink;
* the vhost expects the PROXY protocol (`listen … proxy_protocol`, Xray's `xver`): the
  checks on loopback could not reach it;
* the docroot's parent is not owned by root, or can be written by anyone else.

## The archive

**zip** or **tar.gz**, told by the first bytes and not by the name, up to **20 MiB** (the
Bot API's download limit; the bot refuses a bigger document before downloading it). Root
unpacks it into `/var/lib/vpn-bot-site/work/<run>/` (root 0700). Nothing reaches the site
before **every** entry has passed these checks:

| Rule | Refused |
|---|---|
| regular files and directories only | a symlink, a hard link, a device, a FIFO, a sparse or an encrypted member |
| a relative path of plain names `[A-Za-z0-9_][A-Za-z0-9._~-]*` | an absolute path, `..`, `.`, a backslash, a NUL, a hidden name (`.htaccess`, `.git/`) |
| at most 12 levels, 512 characters | deeper or longer |
| static files only: `.html .htm .css .js .mjs .xml .txt .svg .png .jpg .jpeg .gif .webp .avif .ico .bmp .woff .woff2 .ttf .otf .eot` | anything else (`.php`, `.sh`, a file without an extension) |
| at most 1000 files, 16 MiB each, 64 MiB unpacked | more. The bytes are counted while they are read, not taken from the headers, so a decompression bomb is cut off |
| each name once | a name twice, a file and a directory of the same name |
| `index.html` at the top | missing |

One folder that holds everything (`site/index.html`, …) is unwrapped. `__MACOSX/`,
`.DS_Store` and `Thumbs.db` are skipped. Files are written 0644 and directories 0755,
`root:root`; the modes and owners in the archive are ignored.

The bot writes the document to `/run/vpn-bot/site/upload.bin` (its RuntimeDirectory, 0600).
The run's parameter `digest` is the first 16 hex of the document's sha256 (16, because a
longer hex string looks like a secret to `utils/redact.py`). The plan opens the directory
with `O_NOFOLLOW` and the file relative to it, also with `O_NOFOLLOW`. It takes the upload
only when its sha256 starts with the digest, copies it into the run's directory and removes
the bot's copy. After that, nothing reads what the bot can change. `HELPER_STAGING_ROOT`
therefore stays `/run/vpn-bot`, as it must for the xray staging.

## The run

The mode `site` (helper `scripts/wizard/vpn-bot-wizard-site`, root helper
`scripts/vpn-bot-site`, both `OUT_OF_REPO_HELPERS` required on main, `INSTALL_HELPERS`).
The parameters are `action` (`deploy` | `revert`) and `digest`. It is dangerous: TOTP
before the plan and before apply. It follows the wizard's contract
([wizard.md](wizard.md)):

| Step | What |
|---|---|
| **plan** | First `vpn-bot-site recover`: an apply whose unit was killed is rolled back (the wizard's lock means an open journal belongs to no live run). Then the plan: the archive unpacked and checked, the **diff** (files `+` / `−` / `~`, pages before → after), the spiderX pool before → after and how many keys follow it, the kept versions (which one is dropped), how Hysteria2 sees the site. The plan also checks the self-steal **before** the change (nginx active, ALPN h2 and the domain's certificate, `GET /`). A broken certificate blocks the plan, because a failed verify would otherwise roll back a site that was not the problem. The plan's sha256 is recorded. |
| **apply** | The plan is computed again; another sha256 (the site, the archive or the pool changed) is refused and nothing changes. Then three journaled steps. **site_stage**: the new tree next to the docroot (`/var/www/.<name>.vpn-bot-site-<run>`). **site_swap**: one `renameat2(RENAME_EXCHANGE)` of the two directories, so nginx serves the old site or the new one and never half of each. A filesystem without it gets two renames, and the result says so. **site_env**: `XRAY_SPIDER_X_POOL` of `.env`, backed up first, owner and mode kept, every other line byte for byte. A failed step undoes every step. |
| **verify** | The docroot is the planned tree; nginx is active; ALPN h2 and the domain's certificate (`openssl s_client`, SNI = the domain); **`GET /` and every page answer 200 over HTTP/2** (`curl --resolve <domain>:8443:127.0.0.1`, one connection per 40 pages); the pool is the planned one. If all are green, **commit**: the replaced tree is kept (`/var/lib/vpn-bot-site/releases/<UTC>-<sha12>/`, the last **5**) and `state.json` records what is live. When the pool changed, `vpn-bot-subscription` and the bot restart to read it (`--no-block` for the bot: the new process reports the run). |
| **rollback** | The journal backwards: the old tree back in place, `.env` and `state.json` as they were. This covers a failed verify and a failed commit. |

No step touches the network, nginx's configuration or the certificate, so no dead-man is
armed. A step that overruns is killed by the runner and rolled back.

**Kept versions.** A deploy keeps the tree it replaced as *previous*. «Откатить» brings back
the newest *previous* one and keeps the reverted tree as *rolled back*, so a second
«Откатить» goes one version further back, never forth. A hand-made site is kept like any
other: the first deploy on a production host keeps the site that was there, with its
symlinks, modes and owners.

## spiderX follows the site

REALITY's spiderX is the path a client's "spider" asks the real site for. A path the site
does not have would answer 404, a tell of its own. While `XRAY_SPIDER_X_POOL` is **in use**
(not empty), a deploy sets it to the **pages of the new site**: `/`, every `*.html`, and
`dir/` for `dir/index.html`, at most 64, safe characters only. A path the new site no longer
has leaves the pool. **An empty pool stays empty**: spx off is the operator's choice, and a
deploy does not turn it on. A pool that already names exactly the new site's pages is not
rewritten.

After a run that succeeded, the bot (the database's only writer) gives every xray key whose
**stored** `vpn_keys.spider_x` is no longer in the pool the pick a fresh key would get
(`utils.spider_x.pick_spider_x`: the SHA-256 of its UUID over the new pool). A key whose
value is still in the pool keeps it, and its link does not change. The report says how many
keys moved. The plan already counts them: the helper reads the database read-only
(`mode=ro`). The rotation of subscription children (`XRAY_SPIDER_X_ROTATION_HOURS`) is
computed from the pool when a link is rendered, so it follows with the restart.

The every-start backfill is **not** this step. It fills a NULL `spider_x` only and never
overwrites an assigned value (`tests/test_schema_upgrade_row_fidelity.py`). The re-layout is
an explicit consequence of a site run. Changing `XRAY_SPIDER_X_POOL` by hand still re-lays
nothing.

## Hysteria2

With the shipped `masquerade.type: proxy` to `https://127.0.0.1:8443`, Hysteria2 shows the
same site, and there is nothing to mirror. A host on `type: file` reads its own copy: the plan
warns that the new site reaches it only through `deploy/vpn-bot-decoy-freshen.sh` (its cron
mirrors the docroot).

## Files

| Path | What |
|---|---|
| `/usr/local/sbin/vpn-bot-site` | The root helper: `status`, `plan deploy\|revert`, `apply`, `verify`, `commit`, `rollback`, `recover` |
| `/usr/local/sbin/vpn-bot-wizard-site` | The wizard's mode helper |
| `/var/lib/vpn-bot-site/state.json` | 0644: what is live (tree, archive, when, which run) and what is kept |
| `/var/lib/vpn-bot-site/journal.json` | 0600: the last apply, step by step |
| `/var/lib/vpn-bot-site/releases/<id>/` | 0700: the kept trees |
| `/var/lib/vpn-bot-site/work/<run>/` | 0700: the run's archive, its unpacked tree, the plan, the `.env` backup. Removed at the end of the run; a cancelled plan's directory goes with the next plan |
| `/run/vpn-bot/site/upload.bin` | the bot's copy of the document until the plan takes it |
| `/var/log/vpn-bot-site.log` | the helper's log (redacted) |

No host configuration file is added, so `MANAGED_HOST_FILES` is unchanged. The sudoers
example grants the bot exactly `/usr/local/sbin/vpn-bot-site status --json`; every change
goes through `vpn-bot-wizard launch`.

## Tests

`tests/test_site_helper.py` (the root helper on a fake host: every evil archive refused with
nothing changed, deploy / keep / revert, every failed step and a failed verify or commit
rolled back, with and without `RENAME_EXCHANGE`, the pool following the site),
`tests/test_wizard_site_mode.py` (the mode through the launcher) and
`tests/test_site_bot.py` (the screen, the upload, the re-layout, also on a database
upgraded from the newest production snapshot). There is no network: `curl`, `openssl` and
`systemctl` are stubs (`tests/site_fakes.py`).
