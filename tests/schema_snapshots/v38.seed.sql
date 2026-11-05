-- Seed data for the v38 snapshot (hand-written; loaded by the upgrade harness
-- right after v38.sql). Rows exist so the v39 migration runs against a host that
-- has been collecting traffic: v39 only adds the traffic_hourly table, and must
-- leave the lifetime totals (vpn_key_traffic_stats) and the deleted-key archive
-- exactly as they were. Nothing is backfilled into traffic_hourly — the totals
-- say how much, not when.
--
-- One live key per protocol, each with accumulated totals and the raw counters
-- the next poll diffs against, plus two archived deleted keys.
INSERT INTO users (telegram_user_id, username, first_name, role, created_at, updated_at)
VALUES
  (3801, 'owner', 'Owner', 'SUPERADMIN', '2026-01-01T00:00:00+00:00', '2026-01-01T00:00:00+00:00'),
  (3802, 'member', 'Member', 'APPROVED_USER', '2026-01-02T00:00:00+00:00', '2026-01-02T00:00:00+00:00');

INSERT INTO vpn_keys (
  id, owner_user_id, username, key_type, status, uuid, email_label, public_key, client_ip,
  payload_json, public_payload_json, created_at, updated_at, created_by, transport, xhttp_profile
)
VALUES
  (30, 3802, 'member', 'xray', 'active', '38383838-3838-4838-8838-383838383838', 'xray_tcp_Jj111', NULL, NULL,
   '{"uuid":"38383838-3838-4838-8838-383838383838","email_label":"xray_tcp_Jj111","short_id":"abcd"}',
   '{"email_label":"xray_tcp_Jj111","short_id":"abcd"}',
   '2026-02-01T00:00:00+00:00', '2026-02-01T00:00:00+00:00', 3802, 'tcp', 'base'),
  (31, 3802, 'member', 'awg', 'active', NULL, NULL, 'awgPubKeyV38seed000000000000000000000000000=', '10.8.0.38',
   '{"public_key":"awgPubKeyV38seed000000000000000000000000000="}', '{}',
   '2026-02-02T00:00:00+00:00', '2026-02-02T00:00:00+00:00', 3802, 'tcp', 'base'),
  (32, 3802, 'member', 'hysteria2', 'active', NULL, 'hy2_Kk222', NULL, NULL,
   '{"secret":"38ee","email_label":"hy2_Kk222"}', '{"email_label":"hy2_Kk222"}',
   '2026-02-03T00:00:00+00:00', '2026-02-03T00:00:00+00:00', 3802, 'tcp', 'base');

INSERT INTO vpn_key_traffic_stats (
  key_id, downloaded_bytes, uploaded_bytes, last_raw_downloaded_bytes, last_raw_uploaded_bytes,
  last_success_at, last_attempt_at, available, unavailable_reason, source
)
VALUES
  (30, 5000000, 700000, 4000, 900, '2026-10-01T00:00:00+00:00', '2026-10-01T00:00:00+00:00', 1, NULL, 'xray statsquery'),
  (31, 9000000, 1100000, 8000, 1200, '2026-10-01T00:00:00+00:00', '2026-10-01T00:00:00+00:00', 1, NULL, 'awg/wg transfer'),
  (32, 3000000, 400000, 2000, 300, '2026-10-01T00:00:00+00:00', '2026-10-01T00:00:00+00:00', 1, NULL, 'hysteria2 trafficStats');

INSERT INTO deleted_key_traffic_archive (id, key_id, owner_user_id, key_type, downloaded_bytes, uploaded_bytes, deleted_at)
VALUES
  (1, 27, 3802, 'xray', 1500000, 250000, '2026-09-01T00:00:00+00:00'),
  (2, 28, 3801, 'awg', 2500000, 350000, '2026-09-15T00:00:00+00:00');
