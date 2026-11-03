-- Seed data for the v37 snapshot (hand-written; loaded by the upgrade harness
-- right after v37.sql). Rows exist so the v38 migration runs against a POPULATED
-- database shaped like a host that already used the .env relay: v38 only adds
-- the `relays` table and must leave every vpn_keys.relay value exactly as it was
-- — the relay is seeded from RELAY_* at bot startup, not by the migration, and
-- its keys must still carry the name it will be seeded under.
--
-- A direct VLESS (TCP) key, a relay VLESS (TCP) key and a relay Hysteria2 key,
-- plus one basic bundle with a direct and a relay child.
INSERT INTO users (telegram_user_id, username, first_name, role, created_at, updated_at)
VALUES
  (3001, 'owner', 'Owner', 'SUPERADMIN', '2026-01-01T00:00:00+00:00', '2026-01-01T00:00:00+00:00'),
  (3002, 'member', 'Member', 'APPROVED_USER', '2026-01-02T00:00:00+00:00', '2026-01-02T00:00:00+00:00');

INSERT INTO key_bundles (id, user_id, label, note, status, token, created_at, updated_at, display_no, kind)
VALUES
  (1, 3002, 'bundle_Rr12C', NULL, 'active', 'tok-v37', '2026-03-01T00:00:00+00:00', '2026-03-01T00:00:00+00:00', 23, 'basic');

INSERT INTO vpn_keys (
  id, owner_user_id, username, key_type, status, uuid, email_label, payload_json, public_payload_json,
  created_at, updated_at, created_by, transport, xhttp_profile, bundle_id, relay
)
VALUES
  (20, 3002, 'member', 'xray', 'active', '44444444-4444-4444-8444-444444444444', 'xray_tcp_Ee555',
   '{"uuid":"44444444-4444-4444-8444-444444444444","email_label":"xray_tcp_Ee555","short_id":"abcd"}',
   '{"email_label":"xray_tcp_Ee555","short_id":"abcd"}',
   '2026-02-10T00:00:00+00:00', '2026-02-10T00:00:00+00:00', 3002, 'tcp', 'base', NULL, NULL),
  (21, 3002, 'member', 'xray', 'active', '55555555-5555-4555-8555-555555555555', 'xray_tcp_Ff666',
   '{"uuid":"55555555-5555-4555-8555-555555555555","email_label":"xray_tcp_Ff666","short_id":"abcd"}',
   '{"email_label":"xray_tcp_Ff666","short_id":"abcd"}',
   '2026-02-11T00:00:00+00:00', '2026-02-11T00:00:00+00:00', 3002, 'tcp', 'base', NULL, 'ru1'),
  (22, 3002, 'member', 'hysteria2', 'active', NULL, 'hy2_Gg777',
   '{"secret":"22dd","email_label":"hy2_Gg777"}', '{"email_label":"hy2_Gg777"}',
   '2026-02-12T00:00:00+00:00', '2026-02-12T00:00:00+00:00', 3002, 'tcp', 'base', NULL, 'ru1'),
  (24, 3002, 'member', 'xray', 'active', '66666666-6666-4666-8666-666666666666', 'xray_tcp_Hh888',
   '{"uuid":"66666666-6666-4666-8666-666666666666","email_label":"xray_tcp_Hh888","short_id":"abcd"}',
   '{"email_label":"xray_tcp_Hh888","short_id":"abcd"}',
   '2026-03-01T00:00:00+00:00', '2026-03-01T00:00:00+00:00', 3002, 'tcp', 'base', 1, NULL),
  (25, 3002, 'member', 'xray', 'active', '77777777-7777-4777-8777-777777777777', 'xray_tcp_Ii999',
   '{"uuid":"77777777-7777-4777-8777-777777777777","email_label":"xray_tcp_Ii999","short_id":"abcd"}',
   '{"email_label":"xray_tcp_Ii999","short_id":"abcd"}',
   '2026-03-01T00:00:00+00:00', '2026-03-01T00:00:00+00:00', 3002, 'tcp', 'base', 1, 'ru1');
