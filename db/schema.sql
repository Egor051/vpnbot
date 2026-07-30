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
  -- XHTTP client transport profile: 'base' | 'antisib' | 'multi'. Meaningful only
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
  key_type TEXT NOT NULL CHECK(key_type IN ('xray','awg')),
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
