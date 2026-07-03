-- Migration 027: segmented-announcement recipient filter.
--
-- This project applies migrations programmatically from db/database.py
-- (schema_version bumped to 27, see Database._migrate_v27). This file documents
-- migration 027 as a standalone, reviewable artifact and is kept in sync with
-- both _migrate_v27 and db/schema.sql. The number is the next one in sequence
-- after the existing schema version (26 -> 27).
--
-- Adds recipient_filter_json to announcement_batches: the audience filter
-- (roles/protocols/transports as JSON) persisted per batch so scheduled/resumed
-- sends re-validate against the chosen segment instead of the default
-- approved-users audience. NULL means an unsegmented (legacy "send to all")
-- batch. Idempotent: _migrate_v27 only runs the ALTER when the column is absent.
-- Mirrors the baseline declaration in db/schema.sql (re-ensured on every bootstrap).

ALTER TABLE announcement_batches ADD COLUMN recipient_filter_json TEXT;
