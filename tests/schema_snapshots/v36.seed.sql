-- Seed data for the v36 snapshot (hand-written; loaded by the upgrade harness
-- right after v36.sql). Rows exist so the v37 migration runs against a POPULATED
-- database: it adds vpn_keys.relay (nullable) and key_bundles.kind (NOT NULL
-- DEFAULT 'extended') with ALTER TABLE, and the claim that matters is about the
-- rows a deployed host already has — every existing key must come out as a
-- DIRECT key (relay IS NULL) and every existing bundle as an EXTENDED one, so
-- their links and subscriptions render exactly as before the upgrade.
--
-- Shaped like a live host: a standalone VLESS (TCP) key, a standalone Hysteria2
-- key, and one all-in-one bundle owning a VLESS (TCP) and a Hysteria2 child.
INSERT INTO users (telegram_user_id, username, first_name, role, created_at, updated_at)
VALUES
  (2001, 'owner', 'Owner', 'SUPERADMIN', '2026-01-01T00:00:00+00:00', '2026-01-01T00:00:00+00:00'),
  (2002, 'member', 'Member', 'APPROVED_USER', '2026-01-02T00:00:00+00:00', '2026-01-02T00:00:00+00:00');

INSERT INTO key_bundles (id, user_id, label, note, status, token, created_at, updated_at, display_no)
VALUES
  (1, 2002, 'bundle_Ab12C', NULL, 'active', 'tok-v36', '2026-02-01T00:00:00+00:00', '2026-02-01T00:00:00+00:00', 13);

INSERT INTO vpn_keys (
  id, owner_user_id, username, key_type, status, uuid, email_label, payload_json, public_payload_json,
  created_at, updated_at, created_by, transport, xhttp_profile, bundle_id
)
VALUES
  (10, 2002, 'member', 'xray', 'active', '22222222-2222-4222-8222-222222222222', 'xray_tcp_Aa111',
   '{"uuid":"22222222-2222-4222-8222-222222222222","email_label":"xray_tcp_Aa111","short_id":"abcd"}',
   '{"email_label":"xray_tcp_Aa111","short_id":"abcd"}',
   '2026-01-10T00:00:00+00:00', '2026-01-10T00:00:00+00:00', 2002, 'tcp', 'base', NULL),
  (11, 2002, 'member', 'hysteria2', 'active', NULL, 'hy2_Bb222',
   '{"secret":"00ff","email_label":"hy2_Bb222"}', '{"email_label":"hy2_Bb222"}',
   '2026-01-11T00:00:00+00:00', '2026-01-11T00:00:00+00:00', 2002, 'tcp', 'base', NULL),
  (14, 2002, 'member', 'xray', 'active', '33333333-3333-4333-8333-333333333333', 'xray_tcp_Cc333',
   '{"uuid":"33333333-3333-4333-8333-333333333333","email_label":"xray_tcp_Cc333","short_id":"abcd"}',
   '{"email_label":"xray_tcp_Cc333","short_id":"abcd"}',
   '2026-02-01T00:00:00+00:00', '2026-02-01T00:00:00+00:00', 2002, 'tcp', 'base', 1),
  (15, 2002, 'member', 'hysteria2', 'active', NULL, 'hy2_Dd444',
   '{"secret":"11ee","email_label":"hy2_Dd444"}', '{"email_label":"hy2_Dd444"}',
   '2026-02-01T00:00:00+00:00', '2026-02-01T00:00:00+00:00', 2002, 'tcp', 'base', 1);
