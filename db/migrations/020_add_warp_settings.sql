-- Migration 020: WARP Telegram routing module settings.
--
-- This project applies migrations programmatically from db/database.py
-- (schema_version bumped to 20, see Database._migrate_v20). This file documents
-- migration 020 as a standalone, reviewable artifact and is kept in sync with
-- both _migrate_v20 and db/schema.sql. The number is the next one in sequence
-- after the existing schema version (19 -> 20).
--
-- Single-row table (id = 1). The module is disabled by default; the runtime
-- columns mirror the live tunnel state and are reset on every bot restart.

CREATE TABLE IF NOT EXISTS warp_settings (
    id              INTEGER PRIMARY KEY DEFAULT 1,
    enabled         INTEGER NOT NULL DEFAULT 0,
    config_path     TEXT    NOT NULL DEFAULT '/etc/amnezia/tg-warp.conf',
    interface_name  TEXT    NOT NULL DEFAULT 'tg-warp',
    routes_count    INTEGER NOT NULL DEFAULT 0,   -- number of CIDRs from the config
    -- runtime state (reset on bot restart)
    tunnel_up       INTEGER NOT NULL DEFAULT 0,
    routes_active   INTEGER NOT NULL DEFAULT 0,
    fail_streak     INTEGER NOT NULL DEFAULT 0,
    success_streak  INTEGER NOT NULL DEFAULT 0,
    last_handshake  INTEGER NOT NULL DEFAULT 0,
    last_check_ts   INTEGER NOT NULL DEFAULT 0,
    updated_at      INTEGER NOT NULL DEFAULT 0
);
INSERT OR IGNORE INTO warp_settings (id) VALUES (1);
