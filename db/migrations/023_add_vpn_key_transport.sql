-- Migration 023: VLESS transport selector on vpn_keys.
--
-- Adds a `transport` column distinguishing the two VLESS inbounds a key lives in:
--   'tcp'  -> inbound vless-in            (REALITY over raw/TCP, flow=xtls-rprx-vision)
--   'http' -> inbound vless-xhttp-reality (REALITY over XHTTP, no flow)
--
-- NOT NULL DEFAULT 'tcp' backfills every existing row to 'tcp': all pre-XHTTP keys
-- are TCP, and AWG keys keep a harmless 'tcp' (transport only applies to VLESS).
-- Idempotent: db/database.py::_migrate_v23 only runs the ALTER when the column is
-- absent. Mirrors the baseline declaration in db/schema.sql (re-ensured on every
-- bootstrap).

ALTER TABLE vpn_keys ADD COLUMN transport TEXT NOT NULL DEFAULT 'tcp';
