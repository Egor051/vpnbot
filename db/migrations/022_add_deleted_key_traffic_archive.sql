CREATE TABLE IF NOT EXISTS deleted_key_traffic_archive (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  key_id INTEGER NOT NULL,
  owner_user_id INTEGER NOT NULL,
  key_type TEXT NOT NULL,
  downloaded_bytes INTEGER NOT NULL DEFAULT 0,
  uploaded_bytes INTEGER NOT NULL DEFAULT 0,
  deleted_at TEXT NOT NULL
);
