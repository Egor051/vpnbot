-- Migration 026: per-user language and expiry-notification opt-out.
--
-- This project applies migrations programmatically from db/database.py
-- (schema_version bumped to 26, see Database._migrate_v26). This file documents
-- migration 026 as a standalone, reviewable artifact and is kept in sync with
-- both _migrate_v26 and db/schema.sql. The number is the next one in sequence
-- after the existing schema version (25 -> 26).
--
-- Two new columns on the users table:
--   * language: NULL follows the global BOT_LANGUAGE default; 'ru'/'en' override
--     it for that user (selected from the in-bot Settings tab).
--   * expiry_notifications_enabled: opt-out toggle for the "key expires in N days"
--     reminders (1 = receive, the default). The "key expired — access revoked"
--     notice is unaffected and always delivered.

ALTER TABLE users ADD COLUMN language TEXT DEFAULT NULL;
ALTER TABLE users ADD COLUMN expiry_notifications_enabled INTEGER NOT NULL DEFAULT 1;
