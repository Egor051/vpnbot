-- Seed data for the v34 snapshot (hand-written; loaded by the upgrade harness
-- right after v34.sql). Rows exist so the v35 migration runs against a POPULATED
-- database: the migration adds warp_split_sources.fail_streak with ALTER TABLE,
-- and "works on an empty table" is not the same claim as "works on the table a
-- deployed host actually has".
--
-- Shaped like the live host at the time of the bump: three sources (one enabled
-- add feed, the Google add/subtract pair) with stored contributions and one
-- operator exclusion, so the new columns are added next to real state and the
-- closing _validate_reference_integrity / _validate_enum_values checks have rows
-- to validate.
INSERT INTO warp_split_sources
  (id, slug, title, url, kind, mode, scope_slug, enabled, include_in_list,
   refresh_interval_sec, last_attempt_ts, last_success_ts, last_status, prefix_count)
VALUES
  (1, 'telegram-cidr', 'Telegram', 'https://core.telegram.org/resources/cidr.txt',
   'cidr_text', 'add', NULL, 1, 1, 21600, 1754400000, 1754400000, 'ok', 12),
  (2, 'google-goog', 'Google (all announced ranges)',
   'https://www.gstatic.com/ipranges/goog.json', 'google_json', 'add', NULL, 1, 1,
   21600, 1754400000, 1754400000, 'not-modified', 99),
  (3, 'google-cloud', 'Google Cloud (GCP customer ranges)',
   'https://www.gstatic.com/ipranges/cloud.json', 'google_json', 'subtract',
   'google-goog', 1, 0, 21600, 1754400000, 1754400000, 'ok', 900);

INSERT INTO warp_split_prefixes (origin, prefix, added_at)
VALUES
  ('manual', '203.0.113.0/24', 1754400000),
  ('telegram-cidr', '91.108.4.0/22', 1754400000),
  ('google-goog', '8.8.8.0/24', 1754400000),
  ('google-cloud', '8.8.8.0/25', 1754400000);

INSERT INTO warp_split_exclusions (prefix, created_at)
VALUES ('198.51.100.0/24', 1754400000);
