-- Migration 024: server-status panel settings.
--
-- This project applies migrations programmatically from db/database.py
-- (schema_version bumped to 24, see Database._migrate_v24). This file documents
-- migration 024 as a standalone, reviewable artifact and is kept in sync with
-- both _migrate_v24 and db/schema.sql. The number is the next one in sequence
-- after the existing schema version (23 -> 24).
--
-- Single-row table (id = 1). Holds the "detailed metrics" toggle for the
-- real-time server-status panel (load average, uptime, network smoothing /
-- trend / peak / sparkline). Disabled by default so the background sampler
-- does no extra work until an admin turns it on.

CREATE TABLE IF NOT EXISTS server_status_settings (
    id               INTEGER PRIMARY KEY DEFAULT 1,
    detailed_enabled INTEGER NOT NULL DEFAULT 0,
    updated_at       INTEGER NOT NULL DEFAULT 0
);
INSERT OR IGNORE INTO server_status_settings (id) VALUES (1);
