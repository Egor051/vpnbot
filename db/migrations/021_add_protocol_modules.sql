-- Migration 021: Protocol modules table.
--
-- Stores enable/disable state for each VPN/proxy protocol.
-- All protocols are enabled by default (seeded on first run).
-- Disabling a protocol hard-deletes all related bot-side data.
-- The runtime state is NOT touched — server-side cleanup is manual.

CREATE TABLE IF NOT EXISTS protocol_modules (
    name        TEXT PRIMARY KEY,
    enabled     INTEGER NOT NULL DEFAULT 1,
    disabled_at TEXT,
    disabled_by INTEGER REFERENCES users(telegram_user_id) ON DELETE SET NULL
);

INSERT OR IGNORE INTO protocol_modules (name, enabled) VALUES ('xray', 1);
INSERT OR IGNORE INTO protocol_modules (name, enabled) VALUES ('awg', 1);
INSERT OR IGNORE INTO protocol_modules (name, enabled) VALUES ('socks5', 1);
INSERT OR IGNORE INTO protocol_modules (name, enabled) VALUES ('mtproto', 1);
