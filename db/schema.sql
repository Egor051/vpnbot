-- Baseline schema + post-migration snapshot, hand-maintained.
--
-- This file serves two roles: (1) it is the version-1 BASELINE executed by
-- Database.bootstrap() on a fresh DB (the programmatic migrations in
-- db/database.py are NOT self-sufficient — they assume these baseline tables
-- exist); and (2) it must stay in sync with the state produced by all
-- migrations up to CURRENT_SCHEMA_VERSION. Keep every object below consistent
-- with db/database.py; tests/test_schema_drift.py enforces this parity.
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
  note TEXT DEFAULT NULL
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
  key_type TEXT NOT NULL CHECK(key_type IN ('xray','awg')),
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
  deleted_at TEXT,
  -- created_by/revoked_by/deleted_by intentionally have NO foreign key (unlike
  -- proxy_accesses): users are NEVER hard-deleted (only blocked via role), so
  -- these actor references cannot dangle in practice. owner_user_id keeps its
  -- ON DELETE CASCADE. If a hard-delete path for users is ever added, these
  -- columns must be handled (otherwise _validate_reference_integrity fails at
  -- the next bootstrap on created_by, which is validated as non-nullable).
  created_by INTEGER NOT NULL,
  revoked_by INTEGER,
  deleted_by INTEGER
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
  scheduled_at TEXT
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

CREATE TABLE IF NOT EXISTS warp_settings (
  id              INTEGER PRIMARY KEY DEFAULT 1,
  enabled         INTEGER NOT NULL DEFAULT 0,
  config_path     TEXT    NOT NULL DEFAULT '/etc/amnezia/tg-warp.conf',
  interface_name  TEXT    NOT NULL DEFAULT 'tg-warp',
  routes_count    INTEGER NOT NULL DEFAULT 0,
  tunnel_up       INTEGER NOT NULL DEFAULT 0,
  routes_active   INTEGER NOT NULL DEFAULT 0,
  fail_streak     INTEGER NOT NULL DEFAULT 0,
  success_streak  INTEGER NOT NULL DEFAULT 0,
  last_handshake  INTEGER NOT NULL DEFAULT 0,
  last_check_ts   INTEGER NOT NULL DEFAULT 0,
  updated_at      INTEGER NOT NULL DEFAULT 0
);
INSERT OR IGNORE INTO warp_settings (id) VALUES (1);

CREATE INDEX IF NOT EXISTS idx_users_role ON users(role);
CREATE INDEX IF NOT EXISTS idx_users_active_role ON users(role) WHERE blocked_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_access_requests_user_status ON access_requests(telegram_user_id, status);
CREATE INDEX IF NOT EXISTS idx_access_requests_pending_created ON access_requests(status, requested_at);
CREATE INDEX IF NOT EXISTS idx_vpn_keys_owner ON vpn_keys(owner_user_id);
CREATE INDEX IF NOT EXISTS idx_vpn_keys_type_status ON vpn_keys(key_type, status);
CREATE INDEX IF NOT EXISTS idx_vpn_keys_status_type ON vpn_keys(status, key_type);
CREATE UNIQUE INDEX IF NOT EXISTS idx_vpn_keys_uuid ON vpn_keys(uuid) WHERE uuid IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS idx_vpn_keys_email_label ON vpn_keys(email_label) WHERE email_label IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS idx_vpn_keys_public_key ON vpn_keys(public_key) WHERE public_key IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_vpn_keys_short_id ON vpn_keys(json_extract(payload_json, '$.short_id')) WHERE key_type = 'xray' AND json_valid(payload_json) AND json_extract(payload_json, '$.short_id') IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_vpn_keys_owner_type_status ON vpn_keys(owner_user_id, key_type, status);
CREATE INDEX IF NOT EXISTS idx_proxy_accesses_owner ON proxy_accesses(owner_user_id);
CREATE INDEX IF NOT EXISTS idx_proxy_accesses_owner_type_status ON proxy_accesses(owner_user_id, access_type, status);
CREATE INDEX IF NOT EXISTS idx_proxy_accesses_status_type ON proxy_accesses(status, access_type);
CREATE INDEX IF NOT EXISTS idx_proxy_accesses_login ON proxy_accesses(json_extract(payload_json, '$.login')) WHERE access_type = 'socks5';
CREATE INDEX IF NOT EXISTS idx_proxy_accesses_mtproto_fingerprint ON proxy_accesses(secret_fingerprint) WHERE access_type = 'mtproto' AND secret_fingerprint IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS idx_proxy_accesses_one_live_per_user_type
ON proxy_accesses(owner_user_id, access_type)
WHERE status IN ('pending_apply','active','pending_revoke');
CREATE INDEX IF NOT EXISTS idx_audit_log_created_at ON audit_log(created_at);
CREATE INDEX IF NOT EXISTS idx_audit_log_entity ON audit_log(entity_type, entity_id, created_at);
CREATE INDEX IF NOT EXISTS idx_vpn_key_traffic_stats_success ON vpn_key_traffic_stats(last_success_at);
CREATE INDEX IF NOT EXISTS idx_trial_requests_user ON trial_key_requests(telegram_user_id, status);
CREATE INDEX IF NOT EXISTS idx_announcement_batches_status ON announcement_batches(status, updated_at);
CREATE INDEX IF NOT EXISTS idx_announcement_batches_scheduled ON announcement_batches(scheduled_at) WHERE status = 'scheduled' AND scheduled_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_announcement_deliveries_status ON announcement_deliveries(announcement_id, status, user_id);

-- Intentionally NOT created here (created by migrations instead). bootstrap()
-- runs THIS file BEFORE the migrations, so an index that depends on data
-- cleanup or on a column added by a later migration cannot live in the
-- baseline — creating it on a dirty/old legacy DB would raise before the
-- relevant migration runs:
--   idx_access_requests_one_pending   (UNIQUE, migration v4 — after duplicate-pending collapse)
--   idx_vpn_keys_client_ip_reserved   (UNIQUE, migrations v5/v6 — after AWG client_ip repair)
--   idx_trial_requests_one_pending    (UNIQUE, migration v18 — after duplicate-pending collapse)
--   idx_vpn_keys_expires_at           (migration v13 — depends on the expires_at column it adds)
-- tests/test_schema_drift.py asserts this exact set is the ONLY difference
-- between schema.sql and a fully migrated database.
