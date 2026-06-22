-- Migration 025: maintenance-mode settings.
--
-- This project applies migrations programmatically from db/database.py
-- (schema_version bumped to 25, see Database._migrate_v25). This file documents
-- migration 025 as a standalone, reviewable artifact and is kept in sync with
-- both _migrate_v25 and db/schema.sql. The number is the next one in sequence
-- after the existing schema version (24 -> 25).
--
-- Single-row table (id = 1). Holds the global maintenance toggle, an optional
-- custom banner message shown to non-admin users while works are in progress,
-- and who/when turned it on. Disabled by default so the bot behaves normally
-- until an admin enables maintenance.

CREATE TABLE IF NOT EXISTS maintenance_settings (
    id         INTEGER PRIMARY KEY DEFAULT 1,
    enabled    INTEGER NOT NULL DEFAULT 0,
    message    TEXT,
    started_at INTEGER NOT NULL DEFAULT 0,
    started_by INTEGER,
    updated_at INTEGER NOT NULL DEFAULT 0
);
INSERT OR IGNORE INTO maintenance_settings (id) VALUES (1);
