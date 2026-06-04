-- Migration 022: Deleted-key traffic archive.
--
-- When a VPN key is hard-deleted its row in vpn_key_traffic_stats is removed,
-- which used to drop that key's bytes from the dashboard's lifetime totals.
-- This table preserves the accumulated bytes at deletion time so traffic_totals
-- and top_users_by_traffic keep counting traffic from keys that no longer exist.
--
-- The covering indexes let the dashboard aggregations run as index-only scans.
-- Mirrors db/database.py::_migrate_v22 (applied to legacy databases) and the
-- baseline declaration in db/schema.sql (re-ensured on every bootstrap).

CREATE TABLE IF NOT EXISTS deleted_key_traffic_archive (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  key_id INTEGER NOT NULL,
  owner_user_id INTEGER NOT NULL,
  key_type TEXT NOT NULL,
  downloaded_bytes INTEGER NOT NULL DEFAULT 0,
  uploaded_bytes INTEGER NOT NULL DEFAULT 0,
  deleted_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_deleted_key_traffic_archive_type
  ON deleted_key_traffic_archive(key_type, downloaded_bytes, uploaded_bytes);
CREATE INDEX IF NOT EXISTS idx_deleted_key_traffic_archive_owner
  ON deleted_key_traffic_archive(owner_user_id, downloaded_bytes, uploaded_bytes);
