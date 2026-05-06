PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS schema_meta (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
  telegram_user_id INTEGER PRIMARY KEY,
  username TEXT,
  first_name TEXT,
  role TEXT NOT NULL CHECK(role IN (
    'SUPERADMIN','APPROVED_USER','PENDING_USER','BLOCKED_USER',
    'superadmin','super_admin','approved','approved_user','pending','pending_user',
    'blocked','blocked_user','banned','ban','revoked'
  )),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  blocked_at TEXT
);

CREATE TABLE IF NOT EXISTS access_requests (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  telegram_user_id INTEGER NOT NULL REFERENCES users(telegram_user_id) ON DELETE CASCADE,
  username TEXT,
  status TEXT NOT NULL CHECK(status IN ('pending','approved','rejected')),
  requested_at TEXT NOT NULL,
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
  deleted_at TEXT,
  created_by INTEGER NOT NULL,
  revoked_by INTEGER,
  deleted_by INTEGER
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

CREATE TABLE IF NOT EXISTS announcement_batches (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  actor_user_id INTEGER NOT NULL REFERENCES users(telegram_user_id) ON DELETE RESTRICT,
  from_chat_id INTEGER NOT NULL,
  message_id INTEGER NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('pending','sending','completed','failed','cancelled')),
  total_count INTEGER NOT NULL DEFAULT 0,
  success_count INTEGER NOT NULL DEFAULT 0,
  failed_count INTEGER NOT NULL DEFAULT 0,
  skipped_count INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  completed_at TEXT
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

CREATE INDEX IF NOT EXISTS idx_users_role ON users(role);
CREATE INDEX IF NOT EXISTS idx_access_requests_user_status ON access_requests(telegram_user_id, status);
CREATE INDEX IF NOT EXISTS idx_access_requests_pending_created ON access_requests(status, requested_at);
CREATE INDEX IF NOT EXISTS idx_vpn_keys_owner ON vpn_keys(owner_user_id);
CREATE INDEX IF NOT EXISTS idx_vpn_keys_type_status ON vpn_keys(key_type, status);
CREATE INDEX IF NOT EXISTS idx_vpn_keys_status_type ON vpn_keys(status, key_type);
CREATE UNIQUE INDEX IF NOT EXISTS idx_vpn_keys_uuid ON vpn_keys(uuid) WHERE uuid IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS idx_vpn_keys_email_label ON vpn_keys(email_label) WHERE email_label IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS idx_vpn_keys_public_key ON vpn_keys(public_key) WHERE public_key IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_vpn_keys_owner_type_status ON vpn_keys(owner_user_id, key_type, status);
CREATE INDEX IF NOT EXISTS idx_proxy_accesses_owner ON proxy_accesses(owner_user_id);
CREATE INDEX IF NOT EXISTS idx_proxy_accesses_owner_type_status ON proxy_accesses(owner_user_id, access_type, status);
CREATE INDEX IF NOT EXISTS idx_proxy_accesses_status_type ON proxy_accesses(status, access_type);
CREATE INDEX IF NOT EXISTS idx_proxy_accesses_login ON proxy_accesses(json_extract(payload_json, '$.login')) WHERE access_type = 'socks5';
CREATE INDEX IF NOT EXISTS idx_proxy_accesses_mtproto_fingerprint ON proxy_accesses(secret_fingerprint) WHERE access_type = 'mtproto' AND secret_fingerprint IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_audit_log_created_at ON audit_log(created_at);
CREATE INDEX IF NOT EXISTS idx_vpn_key_traffic_stats_success ON vpn_key_traffic_stats(last_success_at);
CREATE INDEX IF NOT EXISTS idx_announcement_batches_status ON announcement_batches(status, updated_at);
CREATE INDEX IF NOT EXISTS idx_announcement_deliveries_status ON announcement_deliveries(announcement_id, status, user_id);
