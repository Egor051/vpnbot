-- Seed data for the v44 snapshot (hand-written; loaded by the upgrade harness right
-- after v44.sql). Two relays as the production host held them before v45: ru1 in
-- subscriptions (the old default), ru2 kept out of them. v45 only adds
-- relays.basic_visible (NOT NULL DEFAULT 1): both rows must come out with
-- basic_visible = 1 and every other value — in_subscriptions above all — unchanged
-- (tests/test_relay_subscriptions.py checks it).
INSERT INTO users (telegram_user_id, username, first_name, role, created_at, updated_at)
VALUES
  (4401, 'owner', 'Owner', 'SUPERADMIN', '2026-01-01T00:00:00+00:00', '2026-01-01T00:00:00+00:00');

INSERT INTO relays (id, name, label, host, source_ips, enabled, in_subscriptions, note, created_at, updated_at, created_by, updated_by)
VALUES
  (1, 'ru1', 'relay', 'relay.example.net', '198.51.100.7/32', 1, 1, NULL,
   '2026-08-01T00:00:00+00:00', '2026-08-01T00:00:00+00:00', 4401, 4401),
  (2, 'ru2', 'ru2', 'relay2.example.net', '198.51.100.8/32', 1, 0, 'kept out',
   '2026-08-02T00:00:00+00:00', '2026-08-02T00:00:00+00:00', 4401, 4401);
