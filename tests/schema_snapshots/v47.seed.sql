-- Seed data for the v47 snapshot (hand-written; loaded by the upgrade harness right
-- after v47.sql). The production shape before the bot owned its DNS records (v48): the
-- fallback mode set up — he1 is THE hub and forwards to the origin name
-- origin.example.net (the record the bot created through the DNS API when it gave
-- the role, docs/relay.md «Режим фолбэка») — and the failover set holds the main
-- domain. v48 adds dns_records, the ONE list of the A records the bot owns: the hub's
-- origin must arrive there as purpose 'fallback_origin', adopted (the database never
-- recorded whether the bot created it), and failover_names must stay exactly as it
-- is (tests/test_dns_records.py checks both).
INSERT INTO users (telegram_user_id, username, first_name, role, created_at, updated_at)
VALUES
  (4701, 'owner', 'Owner', 'SUPERADMIN', '2026-01-01T00:00:00+00:00', '2026-01-01T00:00:00+00:00');

INSERT INTO relays (id, name, label, host, source_ips, enabled, in_subscriptions, note, created_at, updated_at,
                    created_by, updated_by, ssh_host, ssh_port, host_key, target_host, tcp_ports, udp_ports,
                    agent_version, agent_paired_at, agent_status_json, agent_status_at, basic_visible, role, via_hub)
VALUES
  (1, 'he1', 'he1', 'he1.example.net', '203.0.113.9/32', 1, 0, 'the hub',
   '2026-10-01T00:00:00+00:00', '2026-10-01T00:00:00+00:00', 4701, 4701,
   '203.0.113.9', 22, 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOv9', 'origin.example.net', '443,2096', '443',
   '1', '2026-10-01T00:00:00+00:00', NULL, NULL, 1, 'hub', 0),
  (2, 'ru1', 'relay', 'relay.example.net', '198.51.100.7/32', 1, 1, NULL,
   '2026-08-01T00:00:00+00:00', '2026-08-01T00:00:00+00:00', 4701, 4701,
   '198.51.100.7', 22, 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOv0', 'example.net', '443', '443',
   '1', '2026-08-01T00:00:00+00:00', NULL, NULL, 1, 'edge', 1);

INSERT INTO failover_names (id, name, applied, applied_ipv4, applied_at, last_error, created_at, created_by)
VALUES
  (1, 'example.net', 'normal', '198.51.100.1', '2026-10-02T00:00:00+00:00', NULL, '2026-10-01T00:00:00+00:00', 4701);
