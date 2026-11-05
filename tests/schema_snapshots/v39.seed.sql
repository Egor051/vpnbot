-- Seed data for the v39 snapshot (hand-written; loaded by the upgrade harness
-- right after v39.sql). The host as measured on 2026-11-05: AWG and MTProto were
-- switched off from the panel, the other three are on. v40 only ADDs the three
-- uninstall columns to protocol_modules; every existing toggle must survive the
-- upgrade unchanged and no module may come out marked as removed from the host
-- (the marker file in /etc/vpn-bot/uninstalled is the truth, not a migration).
INSERT INTO users (telegram_user_id, username, first_name, role, created_at, updated_at)
VALUES
  (3901, 'owner', 'Owner', 'SUPERADMIN', '2026-01-01T00:00:00+00:00', '2026-01-01T00:00:00+00:00');

INSERT INTO protocol_modules (name, enabled, disabled_at, disabled_by) VALUES
  ('xray', 1, NULL, NULL),
  ('awg', 0, '2026-08-01T10:00:00+00:00', 3901),
  ('socks5', 1, NULL, NULL),
  ('mtproto', 0, '2026-07-30T10:39:00+00:00', 3901),
  ('hysteria2', 1, NULL, NULL);
