-- Baseline TABLES + post-migration snapshot, hand-maintained.
--
-- This file serves two roles: (1) it is the version-1 BASELINE executed by
-- Database.bootstrap() on a fresh DB (the programmatic migrations in
-- db/database.py are NOT self-sufficient — they assume these baseline tables
-- exist); and (2) it must stay in sync with the state produced by all
-- migrations up to CURRENT_SCHEMA_VERSION. Keep every object below consistent
-- with db/database.py; tests/test_schema_drift.py enforces this parity.
--
-- TABLES AND SEED ROWS ONLY — indexes live in db/indexes.sql.
-- This file runs BEFORE the migrations, so on an existing database every
-- `CREATE TABLE IF NOT EXISTS` here is a no-op and the columns a later migration
-- adds are simply absent while this script executes. Any statement that
-- REFERENCES a column (an index, a trigger, a view) therefore cannot live here:
-- it would raise "no such column" on an old database before the migration that
-- adds the column ever runs. Column comments below still document the migration
-- each column mirrors, because CREATE TABLE only ever declares its own columns.
-- tests/test_schema_drift.py fails the build if a CREATE INDEX reappears here.
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS schema_meta (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
  telegram_user_id INTEGER PRIMARY KEY,
  username TEXT,
  first_name TEXT,
  role TEXT NOT NULL CHECK(role IN ('SUPERADMIN','MODERATOR','APPROVED_USER','PENDING_USER','BLOCKED_USER')),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  blocked_at TEXT,
  trial_quota_reset_at TEXT DEFAULT NULL,
  note TEXT DEFAULT NULL,
  -- Per-user language override: NULL follows the global BOT_LANGUAGE default,
  -- otherwise 'ru'/'en'. Mirrors _migrate_v26.
  language TEXT DEFAULT NULL,
  -- Opt-out toggle for "key expires in N days" reminders (1 = receive).
  -- Mirrors _migrate_v26.
  expiry_notifications_enabled INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS access_requests (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  telegram_user_id INTEGER NOT NULL REFERENCES users(telegram_user_id) ON DELETE CASCADE,
  username TEXT,
  status TEXT NOT NULL CHECK(status IN ('pending','approved','rejected')),
  requested_at TEXT NOT NULL,
  -- decided_by intentionally has NO FK (legacy actor ids may predate the users
  -- table); orphans are validated at bootstrap by _validate_reference_integrity.
  decided_by INTEGER,
  decided_at TEXT,
  decision_note TEXT
);

CREATE TABLE IF NOT EXISTS vpn_keys (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  owner_user_id INTEGER NOT NULL REFERENCES users(telegram_user_id) ON DELETE CASCADE,
  username TEXT,
  key_type TEXT NOT NULL CHECK(key_type IN ('xray','awg','hysteria2')),
  status TEXT NOT NULL CHECK(status IN ('pending_apply','active','apply_failed','pending_revoke','revoked','pending_delete','delete_failed','deleted','failed')),
  note TEXT,
  uuid TEXT,
  email_label TEXT,
  public_key TEXT,
  client_ip TEXT,
  payload_json TEXT NOT NULL,
  public_payload_json TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  revoked_at TEXT,
  expires_at TEXT DEFAULT NULL,
  expiry_notified_days TEXT DEFAULT NULL,
  -- VLESS transport: 'tcp' (vless-in) or 'http' (vless-xhttp-reality). Always
  -- 'tcp' for AWG keys and pre-XHTTP legacy rows. Mirrors _migrate_v23.
  transport TEXT NOT NULL DEFAULT 'tcp',
  -- XHTTP client transport profile: 'base' | 'multi' | 'antisib'. Meaningful only
  -- for http keys; 'base' for tcp/AWG keys and legacy rows. Mirrors _migrate_v28.
  xhttp_profile TEXT NOT NULL DEFAULT 'base',
  -- Per-key REALITY spiderX (spx) emitted into the VLESS client link. NULL means
  -- spx is not emitted (default, full backward compat). Client-side only: never
  -- written to the server inbound. Nullable by design. Mirrors _migrate_v31.
  spider_x TEXT,
  deleted_at TEXT,
  -- created_by/revoked_by/deleted_by intentionally have NO foreign key (unlike
  -- proxy_accesses): users are NEVER hard-deleted (only blocked via role), so
  -- these actor references cannot dangle in practice. owner_user_id keeps its
  -- ON DELETE CASCADE. If a hard-delete path for users is ever added, these
  -- columns must be handled (otherwise _validate_reference_integrity fails at
  -- the next bootstrap on created_by, which is validated as non-nullable).
  created_by INTEGER NOT NULL,
  revoked_by INTEGER,
  deleted_by INTEGER,
  -- All-in-one subscription bundle this key belongs to. NULL = standalone key
  -- (the default and every pre-v32 row). ON DELETE RESTRICT is deliberate: a
  -- bundle can never be deleted while a child key still points at it — PR-2's
  -- service must first revoke the backend credentials and clear/delete the
  -- children, and only then the bundle row. CASCADE would silently drop the
  -- children and leave orphaned Xray/hysteria credentials behind. Mirrors
  -- _migrate_v32.
  bundle_id INTEGER REFERENCES key_bundles(id) ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS key_bundles (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(telegram_user_id) ON DELETE CASCADE,
  label TEXT NOT NULL UNIQUE,
  note TEXT,
  status TEXT NOT NULL CHECK(status IN ('active','pending_revoke','revoked','pending_delete','delete_failed','deleted')),
  -- Secret embedded in the subscription sub-URL. Stored in plain text on purpose,
  -- consistent with how the child keys' vless uuid / hy2 auth already live in this
  -- table, and because the "Config" button must be able to re-render the sub-URL
  -- later. UNIQUE so a token maps to exactly one bundle. Mirrors _migrate_v32.
  token TEXT NOT NULL UNIQUE,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  revoked_at TEXT,
  deleted_at TEXT,
  -- The number shown to the user as «All-in-One #N», reserved out of the vpn_keys
  -- id space so bundles and keys share ONE running count (see
  -- VpnKeyRepository.reserve_display_number). Without it `id` restarted at 1 and
  -- the first subscription read «#1» next to keys numbered «#176».
  -- Nullable only because ADD COLUMN cannot add a NOT NULL column without a
  -- constant default; _migrate_v33 backfills every existing row and the
  -- repository always writes it, so NULL never survives a bootstrap.
  display_no INTEGER
);

CREATE TABLE IF NOT EXISTS trial_key_requests (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  telegram_user_id INTEGER NOT NULL REFERENCES users(telegram_user_id) ON DELETE CASCADE,
  -- hysteria2 joined the list in _migrate_v36. The trial wizard has offered a
  -- Hysteria2 button since the protocol shipped, and the approval path in
  -- services/trial_access.py has always known how to provision one — only this
  -- CHECK did not, so tapping the button raised IntegrityError on INSERT.
  key_type TEXT NOT NULL CHECK(key_type IN ('xray','awg','hysteria2')),
  status TEXT NOT NULL CHECK(status IN ('pending','approved','rejected')),
  key_id INTEGER REFERENCES vpn_keys(id) ON DELETE SET NULL,
  requested_at TEXT NOT NULL,
  decided_by INTEGER REFERENCES users(telegram_user_id) ON DELETE SET NULL,
  decided_at TEXT
);

CREATE TABLE IF NOT EXISTS proxy_entries (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  proxy_type TEXT NOT NULL CHECK(proxy_type IN ('socks5','socks4','http','https')),
  host TEXT NOT NULL,
  port INTEGER NOT NULL,
  login TEXT,
  password TEXT,
  note TEXT,
  status TEXT NOT NULL CHECK(status IN ('active','disabled')),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS proxy_accesses (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  owner_user_id INTEGER NOT NULL REFERENCES users(telegram_user_id) ON DELETE CASCADE,
  username TEXT,
  access_type TEXT NOT NULL CHECK(access_type IN ('socks5','mtproto')),
  status TEXT NOT NULL CHECK(status IN (
    'pending_apply','active','apply_failed','pending_revoke','revoked','revoke_failed','inactive',
    'pending_delete','delete_failed','deleted'
  )),
  secret_fingerprint TEXT,
  apply_generation INTEGER NOT NULL DEFAULT 0,
  payload_json TEXT NOT NULL,
  public_payload_json TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  activated_at TEXT,
  last_apply_at TEXT,
  last_shown_at TEXT,
  revoked_at TEXT,
  deleted_at TEXT,
  created_by INTEGER NOT NULL REFERENCES users(telegram_user_id) ON DELETE RESTRICT,
  revoked_by INTEGER REFERENCES users(telegram_user_id) ON DELETE SET NULL,
  deleted_by INTEGER REFERENCES users(telegram_user_id) ON DELETE SET NULL,
  reason TEXT,
  error TEXT
);

CREATE TABLE IF NOT EXISTS audit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  actor_user_id INTEGER,
  action TEXT NOT NULL,
  entity_type TEXT NOT NULL,
  entity_id TEXT,
  details_json TEXT,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS vpn_key_traffic_stats (
  key_id INTEGER PRIMARY KEY,
  downloaded_bytes INTEGER NOT NULL DEFAULT 0,
  uploaded_bytes INTEGER NOT NULL DEFAULT 0,
  last_raw_downloaded_bytes INTEGER,
  last_raw_uploaded_bytes INTEGER,
  last_success_at TEXT,
  last_attempt_at TEXT,
  available INTEGER NOT NULL DEFAULT 0,
  unavailable_reason TEXT,
  source TEXT,
  FOREIGN KEY(key_id) REFERENCES vpn_keys(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS deleted_key_traffic_archive (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  key_id INTEGER NOT NULL,
  owner_user_id INTEGER NOT NULL,
  key_type TEXT NOT NULL,
  downloaded_bytes INTEGER NOT NULL DEFAULT 0,
  uploaded_bytes INTEGER NOT NULL DEFAULT 0,
  deleted_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS announcement_batches (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  actor_user_id INTEGER NOT NULL REFERENCES users(telegram_user_id) ON DELETE RESTRICT,
  from_chat_id INTEGER NOT NULL,
  message_id INTEGER NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('pending','sending','completed','failed','cancelled','scheduled')),
  total_count INTEGER NOT NULL DEFAULT 0,
  success_count INTEGER NOT NULL DEFAULT 0,
  failed_count INTEGER NOT NULL DEFAULT 0,
  skipped_count INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  completed_at TEXT,
  scheduled_at TEXT,
  -- Segmentation filter (roles/protocols/transports as JSON) for targeted
  -- broadcasts; NULL means an unsegmented "send to all" batch. Mirrors _migrate_v27.
  recipient_filter_json TEXT
);

CREATE TABLE IF NOT EXISTS announcement_deliveries (
  announcement_id INTEGER NOT NULL REFERENCES announcement_batches(id) ON DELETE CASCADE,
  user_id INTEGER NOT NULL REFERENCES users(telegram_user_id) ON DELETE CASCADE,
  status TEXT NOT NULL CHECK(status IN ('pending','sent','failed','skipped')),
  error_text TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (announcement_id, user_id)
);

CREATE TABLE IF NOT EXISTS protocol_modules (
    name        TEXT PRIMARY KEY,
    enabled     INTEGER NOT NULL DEFAULT 1,
    disabled_at TEXT,
    disabled_by INTEGER REFERENCES users(telegram_user_id) ON DELETE SET NULL
);
INSERT OR IGNORE INTO protocol_modules (name, enabled) VALUES ('xray', 1);
INSERT OR IGNORE INTO protocol_modules (name, enabled) VALUES ('awg', 1);
INSERT OR IGNORE INTO protocol_modules (name, enabled) VALUES ('socks5', 1);
INSERT OR IGNORE INTO protocol_modules (name, enabled) VALUES ('mtproto', 1);
INSERT OR IGNORE INTO protocol_modules (name, enabled) VALUES ('hysteria2', 1);

CREATE TABLE IF NOT EXISTS warp_settings (
  id              INTEGER PRIMARY KEY DEFAULT 1,
  enabled         INTEGER NOT NULL DEFAULT 0,
  config_path     TEXT    NOT NULL DEFAULT '/etc/amnezia/out-warp.conf',
  interface_name  TEXT    NOT NULL DEFAULT 'out-warp',
  routes_count    INTEGER NOT NULL DEFAULT 0,
  tunnel_up       INTEGER NOT NULL DEFAULT 0,
  routes_active   INTEGER NOT NULL DEFAULT 0,
  fail_streak     INTEGER NOT NULL DEFAULT 0,
  success_streak  INTEGER NOT NULL DEFAULT 0,
  last_handshake  INTEGER NOT NULL DEFAULT 0,
  last_check_ts   INTEGER NOT NULL DEFAULT 0,
  kill_switch     INTEGER NOT NULL DEFAULT 0,
  config_installed INTEGER NOT NULL DEFAULT 0,
  updated_at      INTEGER NOT NULL DEFAULT 0
);
INSERT OR IGNORE INTO warp_settings (id) VALUES (1);

-- WARP selective-split prefix feeds. Mirrors _migrate_v34.
--
-- The routed list itself lives in /etc/vpn-bot/warp-split.list (root-owned,
-- written only by vpn-bot-warp-split-apply). These tables are the INPUT side:
-- where prefixes come from and which ones the operator has vetoed. The file
-- remains the single source of truth for what is actually routed.
CREATE TABLE IF NOT EXISTS warp_split_sources (
  id                   INTEGER PRIMARY KEY AUTOINCREMENT,
  slug                 TEXT    NOT NULL UNIQUE,
  title                TEXT    NOT NULL,
  url                  TEXT    NOT NULL,
  kind                 TEXT    NOT NULL CHECK(kind IN ('cidr_text','google_json')),
  -- 'add' contributes prefixes to the union; 'subtract' removes them. A subtract
  -- source with scope_slug set applies to that one source's contribution only;
  -- with scope_slug NULL it applies to the whole merged set.
  mode                 TEXT    NOT NULL DEFAULT 'add' CHECK(mode IN ('add','subtract')),
  scope_slug           TEXT,
  -- enabled = "fetch it and use it in the computation"; include_in_list = "its
  -- prefixes may reach the routed list". They are separate because a subtract
  -- operand must be downloaded without ever being routed. include_in_list is
  -- meaningless for mode='subtract' and is ignored there.
  enabled              INTEGER NOT NULL DEFAULT 0,
  include_in_list      INTEGER NOT NULL DEFAULT 1,
  refresh_interval_sec INTEGER NOT NULL DEFAULT 21600,
  last_attempt_ts      INTEGER NOT NULL DEFAULT 0,
  last_success_ts      INTEGER NOT NULL DEFAULT 0,
  last_etag            TEXT,
  last_modified        TEXT,
  last_status          TEXT,
  prefix_count         INTEGER NOT NULL DEFAULT 0,
  last_error           TEXT,
  -- Consecutive failed fetches. Any success (including a 304) resets it, so the
  -- alert threshold means "this feed has been dead N runs running" rather than
  -- "this feed has failed N times ever".
  fail_streak          INTEGER NOT NULL DEFAULT 0,
  -- Defence in depth for two of the three recursion rules the service also
  -- enforces with a readable message (warp.split_merge.validate_source_relations):
  -- a scope only means something for a subtract source, and no source may
  -- subtract from itself. The third rule (no chains) needs a lookup, so it lives
  -- in the service alone.
  CHECK (mode = 'subtract' OR scope_slug IS NULL),
  CHECK (scope_slug IS NULL OR scope_slug <> slug)
);

-- What each origin currently contributes. origin is 'manual' for hand-typed
-- prefixes, or a warp_split_sources.slug for feed-derived ones. Feed rows are
-- rewritten wholesale after each successful refresh, so this table always
-- describes the last known contribution of every origin — which is what lets the
-- panel label a routed prefix without re-parsing a 112 KB feed document.
CREATE TABLE IF NOT EXISTS warp_split_prefixes (
  origin   TEXT    NOT NULL,
  prefix   TEXT    NOT NULL,
  added_at INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (origin, prefix)
);

-- Prefixes the operator subtracted from a feed by hand. Deleting a feed prefix
-- outright would be pointless — the next refresh brings it straight back — so the
-- panel's trash button records an exclusion instead. Applied at the same step as
-- a global subtract source.
CREATE TABLE IF NOT EXISTS warp_split_exclusions (
  prefix     TEXT PRIMARY KEY,
  created_at INTEGER NOT NULL DEFAULT 0
);

-- Seed sources. Telegram is enabled because it is small, stable, and exactly the
-- set a split tunnel wants. Both Google rows ship DISABLED: goog.json on its own
-- routes every GCP customer range through the tunnel, and cloud.json only means
-- anything once goog.json is on — so turning them on is a deliberate two-step act
-- that the panel walks the operator through.
INSERT OR IGNORE INTO warp_split_sources (slug, title, url, kind, mode, scope_slug, enabled, include_in_list)
VALUES ('telegram-cidr', 'Telegram', 'https://core.telegram.org/resources/cidr.txt', 'cidr_text', 'add', NULL, 1, 1);
INSERT OR IGNORE INTO warp_split_sources (slug, title, url, kind, mode, scope_slug, enabled, include_in_list)
VALUES ('google-goog', 'Google (all announced ranges)', 'https://www.gstatic.com/ipranges/goog.json', 'google_json', 'add', NULL, 0, 1);
INSERT OR IGNORE INTO warp_split_sources (slug, title, url, kind, mode, scope_slug, enabled, include_in_list)
VALUES ('google-cloud', 'Google Cloud (GCP customer ranges)', 'https://www.gstatic.com/ipranges/cloud.json', 'google_json', 'subtract', 'google-goog', 0, 0);

-- Address coverage of the last state that was actually APPLIED, one row per
-- source plus one for the merged list (scope = 'list'). This is the comparison
-- point for the unattended-refresh guards: a feed that loses 5% of its coverage
-- on each of four runs is caught on the fourth, because it is still being
-- measured against the state a human last accepted. The counts are addresses,
-- not prefixes, because collapse changes the prefix count without changing a
-- single routed address (108 → 106 on this host, zero coverage difference).
--
-- Written ONLY when an apply actually happened. A rejected candidate must not
-- move it, or the ratchet degrades into "compare against last time", which is
-- exactly the guard being avoided.
CREATE TABLE IF NOT EXISTS warp_split_baseline (
  scope       TEXT PRIMARY KEY,   -- source slug, or 'list' for the merged result
  addresses   INTEGER NOT NULL DEFAULT 0,
  prefixes    INTEGER NOT NULL DEFAULT 0,
  list_hash   TEXT,               -- set for scope='list' only
  applied_ts  INTEGER NOT NULL DEFAULT 0
);

-- The single candidate awaiting an admin's decision. One row by construction
-- (CHECK id = 1): a queue of pending routing policies is a queue of chances to
-- apply the wrong one, so a newer candidate replaces the older outright and the
-- admin always decides about the current state of the world.
--
-- list_text is stored so the card can show the full list without recomputing,
-- and list_hash so that pressing "Apply" on a card the world has moved past is
-- detected rather than obeyed.
CREATE TABLE IF NOT EXISTS warp_split_pending (
  id          INTEGER PRIMARY KEY CHECK (id = 1),
  ts          INTEGER NOT NULL DEFAULT 0,
  list_hash   TEXT    NOT NULL,
  list_text   TEXT    NOT NULL,
  reason      TEXT    NOT NULL DEFAULT '',
  deltas_json TEXT    NOT NULL DEFAULT '{}'
);

-- One row per unattended run, whatever the outcome. This is the evidence base
-- for the decision the whole feature exists to support: after a fortnight in
-- review mode, "were all the changes safe?" must be answerable from data rather
-- than from memory. Trimmed to the most recent 200 rows by the same run that
-- writes them.
CREATE TABLE IF NOT EXISTS warp_split_runs (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  ts           INTEGER NOT NULL DEFAULT 0,
  mode         TEXT    NOT NULL,
  -- applied | queued | nochange | rejected | failed. 'nochange' means the host
  -- was not touched: either there was no delta, or the confirmation streak has
  -- not been reached yet.
  decision     TEXT    NOT NULL,
  reason       TEXT    NOT NULL DEFAULT '',
  list_hash    TEXT    NOT NULL DEFAULT '',
  sources_json TEXT    NOT NULL DEFAULT '[]',
  metrics_json TEXT    NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS server_status_settings (
  id               INTEGER PRIMARY KEY DEFAULT 1,
  detailed_enabled INTEGER NOT NULL DEFAULT 0,
  updated_at       INTEGER NOT NULL DEFAULT 0
);
INSERT OR IGNORE INTO server_status_settings (id) VALUES (1);

CREATE TABLE IF NOT EXISTS maintenance_settings (
  id         INTEGER PRIMARY KEY DEFAULT 1,
  enabled    INTEGER NOT NULL DEFAULT 0,
  message    TEXT,
  started_at INTEGER NOT NULL DEFAULT 0,
  started_by INTEGER,
  updated_at INTEGER NOT NULL DEFAULT 0
);
INSERT OR IGNORE INTO maintenance_settings (id) VALUES (1);
