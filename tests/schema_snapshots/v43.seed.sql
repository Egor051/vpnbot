-- Seed data for the v43 snapshot (hand-written; loaded by the upgrade harness right
-- after v43.sql). The production host as it stood before the relay model became one:
-- relay ru1, created by the legacy RELAY_* seed (label 'relay', no agent — relay_agents
-- is EMPTY), carrying 13 keys (outside status 'deleted'): single VLESS TCP / XHTTP and
-- Hysteria2 keys, members of two all-in-one bundles and a revoked one, plus a deleted
-- one and a direct key. v44 only adds the agent columns to relays (all NULL here) and
-- drops the empty relay_agents: every relays and vpn_keys value — name, label, host,
-- source IPs, each key's relay — must come out byte-identical
-- (tests/test_relay_unified.py checks it value by value).
INSERT INTO users (telegram_user_id, username, first_name, role, created_at, updated_at)
VALUES
  (4301, 'owner', 'Owner', 'SUPERADMIN', '2026-01-01T00:00:00+00:00', '2026-01-01T00:00:00+00:00'),
  (4302, 'member', 'Member', 'APPROVED_USER', '2026-01-02T00:00:00+00:00', '2026-01-02T00:00:00+00:00');

INSERT INTO relays (id, name, label, host, source_ips, enabled, in_subscriptions, note, created_at, updated_at, created_by, updated_by)
VALUES
  (1, 'ru1', 'relay', 'relay.anycastedge.net', '198.51.100.7/32,203.0.113.0/28', 1, 1, NULL,
   '2026-08-01T00:00:00+00:00', '2026-08-01T00:00:00+00:00', NULL, NULL);

INSERT INTO key_bundles (id, user_id, label, note, status, token, created_at, updated_at, display_no, kind)
VALUES
  (1, 4302, 'bundle_Rr43A', NULL, 'active', 'tok-v43-a', '2026-09-01T00:00:00+00:00', '2026-09-01T00:00:00+00:00', 4350, 'basic'),
  (2, 4302, 'bundle_Rr43B', 'phone', 'active', 'tok-v43-b', '2026-09-02T00:00:00+00:00', '2026-09-02T00:00:00+00:00', 4351, 'basic');

INSERT INTO vpn_keys (
  id, owner_user_id, username, key_type, status, uuid, email_label, payload_json, public_payload_json,
  created_at, updated_at, created_by, transport, xhttp_profile, bundle_id, relay, revoked_at, deleted_at
)
VALUES
  (4310, 4302, 'member', 'xray', 'active', '00004310-4343-4343-8343-000000004310', 'xray_tcp_RA310',
   '{"uuid":"00004310-4343-4343-8343-000000004310","email_label":"xray_tcp_RA310","short_id":"ab43"}', '{"email_label":"xray_tcp_RA310","short_id":"ab43"}',
   '2026-09-01T00:00:00+00:00', '2026-09-01T00:00:00+00:00', 4301, 'tcp', 'base', NULL, 'ru1', NULL, NULL),
  (4311, 4302, 'member', 'xray', 'active', '00004311-4343-4343-8343-000000004311', 'xray_tcp_RB311',
   '{"uuid":"00004311-4343-4343-8343-000000004311","email_label":"xray_tcp_RB311","short_id":"ab43"}', '{"email_label":"xray_tcp_RB311","short_id":"ab43"}',
   '2026-09-01T00:00:00+00:00', '2026-09-01T00:00:00+00:00', 4301, 'tcp', 'base', NULL, 'ru1', NULL, NULL),
  (4312, 4302, 'member', 'xray', 'active', '00004312-4343-4343-8343-000000004312', 'xray_http_multi_RC312',
   '{"uuid":"00004312-4343-4343-8343-000000004312","email_label":"xray_http_multi_RC312","short_id":"ab43"}', '{"email_label":"xray_http_multi_RC312","short_id":"ab43"}',
   '2026-09-01T00:00:00+00:00', '2026-09-01T00:00:00+00:00', 4301, 'http', 'multi', NULL, 'ru1', NULL, NULL),
  (4313, 4302, 'member', 'hysteria2', 'active', NULL, 'hy2_RD313',
   '{"secret":"10d9","email_label":"hy2_RD313"}', '{"email_label":"hy2_RD313"}',
   '2026-09-01T00:00:00+00:00', '2026-09-01T00:00:00+00:00', 4301, 'tcp', 'base', NULL, 'ru1', NULL, NULL),
  (4314, 4302, 'member', 'hysteria2', 'active', NULL, 'hy2_RE314',
   '{"secret":"10da","email_label":"hy2_RE314"}', '{"email_label":"hy2_RE314"}',
   '2026-09-01T00:00:00+00:00', '2026-09-01T00:00:00+00:00', 4301, 'tcp', 'base', NULL, 'ru1', NULL, NULL),
  (4315, 4302, 'member', 'xray', 'active', '00004315-4343-4343-8343-000000004315', 'xray_tcp_RF315',
   '{"uuid":"00004315-4343-4343-8343-000000004315","email_label":"xray_tcp_RF315","short_id":"ab43"}', '{"email_label":"xray_tcp_RF315","short_id":"ab43"}',
   '2026-09-01T00:00:00+00:00', '2026-09-01T00:00:00+00:00', 4301, 'tcp', 'base', 1, NULL, NULL, NULL),
  (4316, 4302, 'member', 'hysteria2', 'active', NULL, 'hy2_RG316',
   '{"secret":"10dc","email_label":"hy2_RG316"}', '{"email_label":"hy2_RG316"}',
   '2026-09-01T00:00:00+00:00', '2026-09-01T00:00:00+00:00', 4301, 'tcp', 'base', 1, NULL, NULL, NULL),
  (4317, 4302, 'member', 'xray', 'active', '00004317-4343-4343-8343-000000004317', 'xray_tcp_RH317',
   '{"uuid":"00004317-4343-4343-8343-000000004317","email_label":"xray_tcp_RH317","short_id":"ab43"}', '{"email_label":"xray_tcp_RH317","short_id":"ab43"}',
   '2026-09-01T00:00:00+00:00', '2026-09-01T00:00:00+00:00', 4301, 'tcp', 'base', 1, 'ru1', NULL, NULL),
  (4318, 4302, 'member', 'hysteria2', 'active', NULL, 'hy2_RJ318',
   '{"secret":"10de","email_label":"hy2_RJ318"}', '{"email_label":"hy2_RJ318"}',
   '2026-09-01T00:00:00+00:00', '2026-09-01T00:00:00+00:00', 4301, 'tcp', 'base', 1, 'ru1', NULL, NULL),
  (4319, 4302, 'member', 'xray', 'active', '00004319-4343-4343-8343-000000004319', 'xray_tcp_RK319',
   '{"uuid":"00004319-4343-4343-8343-000000004319","email_label":"xray_tcp_RK319","short_id":"ab43"}', '{"email_label":"xray_tcp_RK319","short_id":"ab43"}',
   '2026-09-01T00:00:00+00:00', '2026-09-01T00:00:00+00:00', 4301, 'tcp', 'base', 2, 'ru1', NULL, NULL),
  (4320, 4302, 'member', 'hysteria2', 'active', NULL, 'hy2_RL320',
   '{"secret":"10e0","email_label":"hy2_RL320"}', '{"email_label":"hy2_RL320"}',
   '2026-09-01T00:00:00+00:00', '2026-09-01T00:00:00+00:00', 4301, 'tcp', 'base', 2, 'ru1', NULL, NULL),
  (4321, 4302, 'member', 'xray', 'active', '00004321-4343-4343-8343-000000004321', 'xray_http_antisib_RM321',
   '{"uuid":"00004321-4343-4343-8343-000000004321","email_label":"xray_http_antisib_RM321","short_id":"ab43"}', '{"email_label":"xray_http_antisib_RM321","short_id":"ab43"}',
   '2026-09-01T00:00:00+00:00', '2026-09-01T00:00:00+00:00', 4301, 'http', 'antisib', NULL, 'ru1', NULL, NULL),
  (4322, 4302, 'member', 'xray', 'active', '00004322-4343-4343-8343-000000004322', 'xray_tcp_RN322',
   '{"uuid":"00004322-4343-4343-8343-000000004322","email_label":"xray_tcp_RN322","short_id":"ab43"}', '{"email_label":"xray_tcp_RN322","short_id":"ab43"}',
   '2026-09-01T00:00:00+00:00', '2026-09-01T00:00:00+00:00', 4301, 'tcp', 'base', NULL, 'ru1', NULL, NULL),
  (4323, 4302, 'member', 'xray', 'revoked', '00004323-4343-4343-8343-000000004323', 'xray_tcp_RP323',
   '{"uuid":"00004323-4343-4343-8343-000000004323","email_label":"xray_tcp_RP323","short_id":"ab43"}', '{"email_label":"xray_tcp_RP323","short_id":"ab43"}',
   '2026-09-01T00:00:00+00:00', '2026-09-01T00:00:00+00:00', 4301, 'tcp', 'base', NULL, 'ru1', '2026-09-01T00:00:00+00:00', NULL),
  (4324, 4302, 'member', 'hysteria2', 'deleted', NULL, 'hy2_RQ324',
   '{"secret":"10e4","email_label":"hy2_RQ324"}', '{"email_label":"hy2_RQ324"}',
   '2026-09-01T00:00:00+00:00', '2026-09-01T00:00:00+00:00', 4301, 'tcp', 'base', NULL, 'ru1', NULL, '2026-09-01T00:00:00+00:00'),
  (4325, 4302, 'member', 'hysteria2', 'active', NULL, 'hy2_RR325',
   '{"secret":"10e5","email_label":"hy2_RR325"}', '{"email_label":"hy2_RR325"}',
   '2026-09-01T00:00:00+00:00', '2026-09-01T00:00:00+00:00', 4301, 'tcp', 'base', NULL, 'ru1', NULL, NULL),
  (4326, 4302, 'member', 'xray', 'active', '00004326-4343-4343-8343-000000004326', 'xray_tcp_RS326',
   '{"uuid":"00004326-4343-4343-8343-000000004326","email_label":"xray_tcp_RS326","short_id":"ab43"}', '{"email_label":"xray_tcp_RS326","short_id":"ab43"}',
   '2026-09-01T00:00:00+00:00', '2026-09-01T00:00:00+00:00', 4301, 'tcp', 'base', NULL, NULL, NULL, NULL);
