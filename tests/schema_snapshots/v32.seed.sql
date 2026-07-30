-- Seed data for the v32 snapshot (hand-written; loaded by the upgrade harness
-- right after v32.sql). Rows exist so the upgrade path runs migrations against a
-- POPULATED database, not an empty one: an ALTER/backfill that only works on an
-- empty table is a real failure mode, and bootstrap()'s closing
-- _validate_reference_integrity / _validate_enum_values checks are no-ops without
-- rows to validate.
--
-- Shaped for the v33 renumbering in particular: vpn_keys ids run up to 176, so a
-- bundle numbered out of the key id space must come out ABOVE 176 — the whole
-- point of display_no. Two bundles with distinct created_at pin the
-- oldest-first order the backfill promises.
INSERT INTO users (telegram_user_id, username, first_name, role, created_at, updated_at)
VALUES
  (1001, 'owner', 'Owner', 'SUPERADMIN', '2025-01-01T00:00:00+00:00', '2025-01-01T00:00:00+00:00'),
  (1002, 'member', 'Member', 'APPROVED_USER', '2025-01-02T00:00:00+00:00', '2025-01-02T00:00:00+00:00');

INSERT INTO vpn_keys (
  id, owner_user_id, username, key_type, status, uuid, payload_json, public_payload_json,
  created_at, updated_at, created_by
)
VALUES
  (1, 1001, 'owner', 'xray', 'active', '11111111-1111-4111-8111-111111111111', '{}', '{}',
   '2025-01-03T00:00:00+00:00', '2025-01-03T00:00:00+00:00', 1001),
  (176, 1002, 'member', 'hysteria2', 'active', NULL, '{}', '{}',
   '2025-02-01T00:00:00+00:00', '2025-02-01T00:00:00+00:00', 1001);

INSERT INTO key_bundles (id, user_id, label, note, status, token, created_at, updated_at)
VALUES
  (1, 1002, 'All-in-One older', NULL, 'active', 'tok-older', '2025-02-02T00:00:00+00:00', '2025-02-02T00:00:00+00:00'),
  (2, 1002, 'All-in-One newer', NULL, 'active', 'tok-newer', '2025-02-03T00:00:00+00:00', '2025-02-03T00:00:00+00:00');

UPDATE vpn_keys SET bundle_id = 1 WHERE id = 176;
