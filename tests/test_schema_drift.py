
import asyncio
import sqlite3
from pathlib import Path

import aiosqlite
import pytest

from db.database import CURRENT_SCHEMA_VERSION, Database

SCHEMA_PATH = Path(__file__).resolve().parents[1] / "db" / "schema.sql"

# Indexes that are intentionally created by migrations only and NOT by the
# schema.sql baseline, because bootstrap() runs schema.sql BEFORE the migrations
# and these depend on data cleanup (UNIQUE partials) or on a column added by a
# later migration (expires_at). Kept in sync with the comment block at the end
# of db/schema.sql.
MIGRATION_ONLY_INDEXES = frozenset(
    {
        "idx_access_requests_one_pending",
        "idx_vpn_keys_client_ip_reserved",
        "idx_trial_requests_one_pending",
        "idx_vpn_keys_expires_at",
        "idx_vpn_keys_bundle_id",
    }
)


async def _named_indexes(conn: aiosqlite.Connection) -> set[str]:
    cursor = await conn.execute(
        "SELECT name FROM sqlite_master WHERE type = 'index' AND name LIKE 'idx_%'"
    )
    return {str(row[0]) for row in await cursor.fetchall()}


async def _table_names(conn: aiosqlite.Connection) -> set[str]:
    cursor = await conn.execute(
        "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
    )
    return {str(row[0]) for row in await cursor.fetchall()}


# name -> (type, notnull, default, pk). Keyed by column name so a legitimate
# column-ORDER divergence (an ALTER appends at the end while schema.sql lists the
# column mid-table — e.g. spider_x, bundle_id) is not treated as drift, while any
# type / nullability / default / primary-key difference still is.
async def _column_details(conn: aiosqlite.Connection, table: str) -> dict[str, tuple[str, int, object, int]]:
    cursor = await conn.execute(f"PRAGMA table_info({table})")
    return {
        str(row[1]): (str(row[2]).upper(), int(row[3]), row[4], int(row[5]))
        for row in await cursor.fetchall()
    }


# Set of (from_col, parent_table, to_col, on_update, on_delete) so ON DELETE
# actions (e.g. bundle_id RESTRICT vs user_id CASCADE) are compared regardless of
# the order SQLite reports the foreign keys in.
async def _foreign_keys(conn: aiosqlite.Connection, table: str) -> set[tuple[str, str, str, str, str]]:
    cursor = await conn.execute(f"PRAGMA foreign_key_list({table})")
    return {
        (str(row[3]), str(row[2]), str(row[4]), str(row[5]), str(row[6]))
        for row in await cursor.fetchall()
    }


async def _schema_shape(conn: aiosqlite.Connection) -> tuple[
    dict[str, dict[str, tuple[str, int, object, int]]],
    dict[str, set[tuple[str, str, str, str, str]]],
]:
    tables = await _table_names(conn)
    columns = {table: await _column_details(conn, table) for table in tables}
    fks = {table: await _foreign_keys(conn, table) for table in tables}
    return columns, fks


def test_schema_sql_matches_fully_migrated_database(tmp_path: Path) -> None:
    """A fully migrated DB and executescript(schema.sql) must agree on the schema —
    tables, columns, types, defaults, nullability, primary keys, and foreign keys
    (including ON DELETE actions) — except for the documented migration-only index
    set. This is the main guard against schema.sql drifting from the migrations."""

    async def run() -> None:
        boot = Database(tmp_path / "boot.db")
        await boot.connect()
        try:
            await boot.bootstrap()
            boot_indexes = await _named_indexes(boot._raw_conn())
            boot_tables = await _table_names(boot._raw_conn())
            boot_columns, boot_fks = await _schema_shape(boot._raw_conn())
            version_row = await boot.conn.execute_fetchone(
                "SELECT value FROM schema_meta WHERE key = 'schema_version'"
            )
        finally:
            await boot.close()
        assert version_row is not None
        assert int(version_row["value"]) == CURRENT_SCHEMA_VERSION

        async with aiosqlite.connect(tmp_path / "schema_only.db") as conn:
            await conn.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))
            await conn.commit()
            schema_indexes = await _named_indexes(conn)
            schema_tables = await _table_names(conn)
            schema_columns, schema_fks = await _schema_shape(conn)

        # schema.sql must never contain an index the migrated DB lacks.
        assert schema_indexes - boot_indexes == set()
        # The only indexes the migrated DB has beyond schema.sql are the
        # documented migration-only ones.
        assert boot_indexes - schema_indexes == MIGRATION_ONLY_INDEXES
        # Baseline tables come exclusively from schema.sql; both paths agree.
        assert boot_tables == schema_tables
        # Columns (name/type/notnull/default/pk) and foreign keys (incl. ON DELETE)
        # must be identical per table across both construction paths.
        for table in sorted(boot_tables):
            assert boot_columns[table] == schema_columns[table], f"column drift in {table}"
            assert boot_fks[table] == schema_fks[table], f"foreign-key drift in {table}"

    asyncio.run(run())


def test_schema_only_objects_are_reensured_on_every_bootstrap(tmp_path: Path) -> None:
    """schema.sql is executed on every bootstrap, so even if a schema-only index
    is dropped on an existing DB it is recreated on the next startup (this is why
    no backfill migration is needed for objects that live only in schema.sql)."""

    schema_only = frozenset(
        {
            "idx_vpn_keys_uuid",
            "idx_vpn_keys_email_label",
            "idx_vpn_keys_public_key",
            "idx_vpn_keys_owner",
            "idx_audit_log_created_at",
            "idx_audit_log_entity",
        }
    )

    async def run() -> None:
        db_path = tmp_path / "vpn.db"
        db = Database(db_path)
        await db.connect()
        try:
            await db.bootstrap()
            for name in schema_only:
                await db.conn.execute(f"DROP INDEX IF EXISTS {name}")
            await db.commit()
            assert schema_only & await _named_indexes(db._raw_conn()) == set()
        finally:
            await db.close()

        db = Database(db_path)
        await db.connect()
        try:
            await db.bootstrap()
            assert schema_only <= await _named_indexes(db._raw_conn())
        finally:
            await db.close()

    asyncio.run(run())


def test_v30_backfills_config_installed_from_routes_count(tmp_path: Path) -> None:
    """P8-013: _migrate_v30 backfills config_installed=1 for a pre-v30 row that
    already produced routes (existing installs keep their "config present" state),
    adds kill_switch defaulting off, and is idempotent."""

    async def run() -> None:
        db = Database(tmp_path / "vpn.db")
        await db.connect()
        try:
            # Pre-v30 warp_settings: no kill_switch / config_installed columns, with
            # an installed config (routes_count>0).
            await db.conn.execute("DROP TABLE IF EXISTS warp_settings")
            await db.conn.execute(
                "CREATE TABLE warp_settings (id INTEGER PRIMARY KEY DEFAULT 1, "
                "routes_count INTEGER NOT NULL DEFAULT 0)"
            )
            await db.conn.execute("INSERT INTO warp_settings (id, routes_count) VALUES (1, 5)")
            await db.commit()

            await db._migrate_v30()
            await db.commit()

            row = await db.conn.execute_fetchone(
                "SELECT config_installed, kill_switch FROM warp_settings WHERE id = 1"
            )
            assert row is not None
            assert int(row["config_installed"]) == 1  # backfilled from routes_count>0
            assert int(row["kill_switch"]) == 0        # defaults off

            # Idempotent: a second run must not raise (columns already present).
            await db._migrate_v30()
        finally:
            await db.close()

    asyncio.run(run())


def test_foreign_keys_enforced_after_bootstrap(tmp_path: Path) -> None:
    """After bootstrap (which rewrites tables with FK toggled off in v16/v17),
    foreign-key enforcement must be back ON."""

    async def run() -> None:
        db = Database(tmp_path / "vpn.db")
        await db.connect()
        try:
            await db.bootstrap()
            cursor = await db.conn.execute("PRAGMA foreign_keys")
            row = await cursor.fetchone()
            assert row[0] == 1
            # Inserting a key for a non-existent owner must be rejected by the FK.
            with pytest.raises(sqlite3.IntegrityError):
                await db.conn.execute(
                    """
                    INSERT INTO vpn_keys (
                      owner_user_id, username, key_type, status,
                      payload_json, public_payload_json, created_at, updated_at, created_by
                    )
                    VALUES (999999, 'ghost', 'xray', 'active', '{}', '{}', 'now', 'now', 999999)
                    """
                )
        finally:
            await db.close()

    asyncio.run(run())
