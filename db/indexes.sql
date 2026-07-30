-- Index DDL, hand-maintained. Executed by Database.bootstrap() AFTER the
-- migration chain in db/database.py has run to CURRENT_SCHEMA_VERSION.
--
-- WHY THIS FILE IS SEPARATE FROM schema.sql
-- db/schema.sql is the version-1 BASELINE and therefore runs BEFORE the
-- migrations. On an existing database its `CREATE TABLE IF NOT EXISTS` statements
-- are no-ops, so anything in it that references a column added by a migration
-- fails — before the migration that adds the column ever runs. That is not a
-- hypothetical: a UNIQUE index on key_bundles(display_no) in the baseline
-- crash-looped the bot on every live v32 database with "no such column:
-- display_no", while every test (all of which build from a clean DB, where
-- CREATE TABLE does create the column) stayed green.
--
-- Indexes live here instead, where two things are true no matter which path the
-- database took to get here:
--   * every column exists (the migrations have finished), so an index can freely
--     reference a migration-added column — no exception list to remember;
--   * the data has been cleaned up (v4/v5/v6/v18 collapse duplicates), so even the
--     UNIQUE partial indexes are safe to create.
-- Both properties are what previously forced five indexes to be created ONLY by
-- their migration and deliberately left out of the baseline. They are back here
-- now, which also means they are re-ensured on every bootstrap: an index dropped
-- by hand, or lost because a table-rebuild migration (v16/v17/v29 drop and
-- recreate their table) forgot to recreate it, comes back on the next start.
--
-- tests/test_schema_drift.py asserts this file and a fully migrated database agree
-- exactly, and that no CREATE INDEX ever creeps back into schema.sql.
CREATE INDEX IF NOT EXISTS idx_users_role ON users(role);
CREATE INDEX IF NOT EXISTS idx_users_active_role ON users(role) WHERE blocked_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_access_requests_user_status ON access_requests(telegram_user_id, status);
CREATE INDEX IF NOT EXISTS idx_access_requests_pending_created ON access_requests(status, requested_at);
-- UNIQUE partial, created by migration v4 after the duplicate-pending collapse.
CREATE UNIQUE INDEX IF NOT EXISTS idx_access_requests_one_pending ON access_requests(telegram_user_id) WHERE status = 'pending';

CREATE INDEX IF NOT EXISTS idx_vpn_keys_owner ON vpn_keys(owner_user_id);
CREATE INDEX IF NOT EXISTS idx_vpn_keys_type_status ON vpn_keys(key_type, status);
CREATE INDEX IF NOT EXISTS idx_vpn_keys_status_type ON vpn_keys(status, key_type);
CREATE UNIQUE INDEX IF NOT EXISTS idx_vpn_keys_uuid ON vpn_keys(uuid) WHERE uuid IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS idx_vpn_keys_email_label ON vpn_keys(email_label) WHERE email_label IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS idx_vpn_keys_public_key ON vpn_keys(public_key) WHERE public_key IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_vpn_keys_short_id ON vpn_keys(json_extract(payload_json, '$.short_id')) WHERE key_type = 'xray' AND json_valid(payload_json) AND json_extract(payload_json, '$.short_id') IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_vpn_keys_owner_type_status ON vpn_keys(owner_user_id, key_type, status);
-- UNIQUE partial, created by migrations v5/v6 after the AWG client_ip repair.
CREATE UNIQUE INDEX IF NOT EXISTS idx_vpn_keys_client_ip_reserved ON vpn_keys(client_ip) WHERE client_ip IS NOT NULL AND key_type = 'awg' AND status IN ('pending_apply','active','apply_failed','pending_revoke','pending_delete','delete_failed');
-- Depends on vpn_keys.expires_at, added by migration v13.
CREATE INDEX IF NOT EXISTS idx_vpn_keys_expires_at ON vpn_keys(expires_at) WHERE expires_at IS NOT NULL AND status = 'active';
-- Depends on vpn_keys.bundle_id, added by migration v32.
CREATE INDEX IF NOT EXISTS idx_vpn_keys_bundle_id ON vpn_keys(bundle_id) WHERE bundle_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_key_bundles_user_id ON key_bundles(user_id);
CREATE INDEX IF NOT EXISTS idx_key_bundles_status ON key_bundles(status);
-- Depends on key_bundles.display_no, added by migration v33. This is the index
-- whose presence in the baseline crash-looped the bot on live v32 databases.
CREATE UNIQUE INDEX IF NOT EXISTS idx_key_bundles_display_no ON key_bundles(display_no);

CREATE INDEX IF NOT EXISTS idx_trial_requests_user ON trial_key_requests(telegram_user_id, status);
-- UNIQUE partial, created by migration v18 after the duplicate-pending collapse.
CREATE UNIQUE INDEX IF NOT EXISTS idx_trial_requests_one_pending ON trial_key_requests(telegram_user_id) WHERE status = 'pending';

CREATE INDEX IF NOT EXISTS idx_proxy_accesses_owner ON proxy_accesses(owner_user_id);
CREATE INDEX IF NOT EXISTS idx_proxy_accesses_owner_type_status ON proxy_accesses(owner_user_id, access_type, status);
CREATE INDEX IF NOT EXISTS idx_proxy_accesses_status_type ON proxy_accesses(status, access_type);
CREATE INDEX IF NOT EXISTS idx_proxy_accesses_login ON proxy_accesses(json_extract(payload_json, '$.login')) WHERE access_type = 'socks5';
-- Depends on proxy_accesses.secret_fingerprint, added by the v9 table rebuild.
CREATE INDEX IF NOT EXISTS idx_proxy_accesses_mtproto_fingerprint ON proxy_accesses(secret_fingerprint) WHERE access_type = 'mtproto' AND secret_fingerprint IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS idx_proxy_accesses_one_live_per_user_type ON proxy_accesses(owner_user_id, access_type) WHERE status IN ('pending_apply','active','pending_revoke');

CREATE INDEX IF NOT EXISTS idx_audit_log_created_at ON audit_log(created_at);
CREATE INDEX IF NOT EXISTS idx_audit_log_entity ON audit_log(entity_type, entity_id, created_at);

CREATE INDEX IF NOT EXISTS idx_vpn_key_traffic_stats_success ON vpn_key_traffic_stats(last_success_at);
CREATE INDEX IF NOT EXISTS idx_deleted_key_traffic_archive_type ON deleted_key_traffic_archive(key_type, downloaded_bytes, uploaded_bytes);
CREATE INDEX IF NOT EXISTS idx_deleted_key_traffic_archive_owner ON deleted_key_traffic_archive(owner_user_id, downloaded_bytes, uploaded_bytes);

CREATE INDEX IF NOT EXISTS idx_announcement_batches_status ON announcement_batches(status, updated_at);
-- Depends on announcement_batches.scheduled_at, added by the v16 table rebuild.
CREATE INDEX IF NOT EXISTS idx_announcement_batches_scheduled ON announcement_batches(scheduled_at) WHERE status = 'scheduled' AND scheduled_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_announcement_deliveries_status ON announcement_deliveries(announcement_id, status, user_id);
