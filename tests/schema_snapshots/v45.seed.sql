-- Seed data for the v45 snapshot (hand-written; loaded by the upgrade harness right
-- after v45.sql). The production shape before the fallback mode (v46): two relays
-- the bot manages through their agents, both forwarding to the main server's DNS
-- name — ru1 (relay.example.net) and he2 (fallback.example.net) — plus one relay set
-- up by hand. v46 adds relays.role (NOT NULL DEFAULT 'edge') and the failover_names
-- table: every row must come out as role 'edge' with every other value unchanged,
-- and the new table empty (tests/test_fallback_mode.py checks it).
INSERT INTO users (telegram_user_id, username, first_name, role, created_at, updated_at)
VALUES
  (4501, 'owner', 'Owner', 'SUPERADMIN', '2026-01-01T00:00:00+00:00', '2026-01-01T00:00:00+00:00');

INSERT INTO relays (id, name, label, host, source_ips, enabled, in_subscriptions, note, created_at, updated_at,
                    created_by, updated_by, ssh_host, ssh_port, host_key, target_host, tcp_ports, udp_ports,
                    agent_version, agent_paired_at, agent_status_json, agent_status_at, basic_visible)
VALUES
  (1, 'ru1', 'relay', 'relay.example.net', '198.51.100.7/32', 1, 1, NULL,
   '2026-08-01T00:00:00+00:00', '2026-08-01T00:00:00+00:00', 4501, 4501,
   '198.51.100.7', 22, 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOv0', 'example.net', '443', '443',
   '1', '2026-08-01T00:00:00+00:00', '{"agent":"1"}', '2026-08-01T00:00:00+00:00', 1),
  (2, 'he2', 'he2', 'fallback.example.net', '203.0.113.20/32', 1, 0, 'paired by the bot',
   '2026-08-02T00:00:00+00:00', '2026-08-02T00:00:00+00:00', 4501, 4501,
   '203.0.113.20', 22, 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOv1', 'example.net', '443', '443',
   '1', '2026-08-02T00:00:00+00:00', NULL, NULL, 0),
  (3, 'manual', 'manual', '192.0.2.30', '192.0.2.30/32', 0, 0, 'set up by hand',
   '2026-08-03T00:00:00+00:00', '2026-08-03T00:00:00+00:00', 4501, 4501,
   NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 1);
