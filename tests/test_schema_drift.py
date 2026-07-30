
import asyncio
import re
import sqlite3
from pathlib import Path

import aiosqlite
import pytest
from conftest import assert_same_shape, named_indexes, schema_shape

from db.database import CURRENT_SCHEMA_VERSION, Database, _split_sql_statements

SCHEMA_PATH = Path(__file__).resolve().parents[1] / "db" / "schema.sql"
INDEXES_PATH = Path(__file__).resolve().parents[1] / "db" / "indexes.sql"


def test_schema_sql_matches_fully_migrated_database(tmp_path: Path) -> None:
    """A fully migrated DB and the two SQL files must agree on the schema — tables,
    columns, types, defaults, nullability, primary keys, foreign keys (including ON
    DELETE actions) and indexes. This is the main guard against the files drifting
    from the migrations.

    There is no exception list any more. Five indexes used to be created by their
    migration only and deliberately left out of the baseline (they depend on a
    migration-added column, or on a data cleanup only a migration performs); now
    that indexes.sql runs AFTER the migrations, both conditions hold for every
    index and the two construction paths must match exactly.
    """

    async def run() -> None:
        boot = Database(tmp_path / "boot.db")
        await boot.connect()
        try:
            await boot.bootstrap()
            boot_shape = await schema_shape(boot._raw_conn())
            version_row = await boot.conn.execute_fetchone(
                "SELECT value FROM schema_meta WHERE key = 'schema_version'"
            )
        finally:
            await boot.close()
        assert version_row is not None
        assert int(version_row["value"]) == CURRENT_SCHEMA_VERSION

        async with aiosqlite.connect(tmp_path / "schema_only.db") as conn:
            await conn.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))
            await conn.executescript(INDEXES_PATH.read_text(encoding="utf-8"))
            await conn.commit()
            file_shape = await schema_shape(conn)

        assert_same_shape(boot_shape, file_shape, "bootstrap vs schema.sql+indexes.sql")

    asyncio.run(run())


def test_baseline_schema_declares_no_indexes() -> None:
    """schema.sql runs BEFORE the migrations, so a statement in it that references a
    column — an index, a trigger, a view — raises "no such column" on any database
    old enough to be missing that column, before the migration that adds it ever
    runs. That is what crash-looped the bot on live v32 databases
    (idx_key_bundles_display_no vs _migrate_v33). The baseline stays tables + seed
    rows; anything that references a column belongs in indexes.sql.
    """
    baseline = SCHEMA_PATH.read_text(encoding="utf-8")
    offenders = re.findall(
        r"^\s*CREATE\s+(?:UNIQUE\s+)?(?:INDEX|TRIGGER|VIEW)\b.*",
        baseline,
        re.IGNORECASE | re.MULTILINE,
    )
    assert offenders == [], f"db/schema.sql must not create indexes/triggers/views: {offenders}"


def test_indexes_file_contains_only_index_ddl() -> None:
    """The converse guard: indexes.sql runs AFTER the migrations, so a CREATE TABLE
    hidden in it would create a table the migration chain never got to see."""
    statements = [s for s in re.split(r";\s*\n", INDEXES_PATH.read_text(encoding="utf-8")) if s.strip()]
    for statement in statements:
        body = "\n".join(
            line for line in statement.splitlines() if not line.lstrip().startswith("--")
        ).strip()
        if not body:
            continue
        assert re.match(r"^CREATE\s+(UNIQUE\s+)?INDEX\s+IF\s+NOT\s+EXISTS\b", body, re.IGNORECASE), (
            f"db/indexes.sql may only contain CREATE INDEX IF NOT EXISTS statements, got: {body[:80]!r}"
        )


def test_split_sql_statements_respects_quoting_and_comments() -> None:
    """indexes.sql is executed statement by statement (executescript would COMMIT
    the migrations behind bootstrap's back), so the splitter must not cut on a
    semicolon inside a string literal, and must keep leading comments attached to
    the statement they document."""
    statements = _split_sql_statements(
        "-- leading comment\n"
        "CREATE INDEX IF NOT EXISTS idx_a ON t(c) WHERE c = 'a;b';\n"
        "\n"
        "CREATE INDEX IF NOT EXISTS idx_b ON t(d);\n"
        "-- trailing comment, nothing to execute\n"
    )
    assert len(statements) == 2
    assert statements[0].startswith("-- leading comment")
    assert "'a;b'" in statements[0]
    assert statements[1] == "CREATE INDEX IF NOT EXISTS idx_b ON t(d);"


def test_split_sql_statements_rejects_an_unterminated_statement() -> None:
    """A missing `;` must fail loudly instead of silently dropping the statement —
    a quietly skipped CREATE INDEX is exactly the kind of thing that only shows up
    as a slow query months later."""
    with pytest.raises(RuntimeError, match="Незавершённый"):
        _split_sql_statements("CREATE INDEX IF NOT EXISTS idx_a ON t(c)\n")


def test_indexes_file_splits_into_one_statement_per_index() -> None:
    """Sanity-check the real file against the splitter: every statement it yields
    is a CREATE INDEX, and none was merged or lost."""
    text = INDEXES_PATH.read_text(encoding="utf-8")
    statements = _split_sql_statements(text)
    assert statements
    # Every statement in the file begins a line (prose mentions of CREATE live in
    # `--` comments, which never start one).
    assert len(statements) == len(re.findall(r"(?m)^CREATE ", text))
    for statement in statements:
        assert statement.rstrip().endswith(";")
        assert "CREATE " in statement


def test_every_index_is_reensured_on_every_bootstrap(tmp_path: Path) -> None:
    """indexes.sql is executed on every bootstrap, so an index dropped on an
    existing DB — by hand, or by a table-rebuild migration that forgot to recreate
    it — is back on the next startup. Before the split this held only for the
    indexes that lived in the baseline: the migration-only ones were created once
    by a version-gated migration, so losing one was permanent."""

    async def run() -> None:
        db_path = tmp_path / "vpn.db"
        db = Database(db_path)
        await db.connect()
        try:
            await db.bootstrap()
            all_indexes = await named_indexes(db._raw_conn())
            assert all_indexes, "bootstrap created no idx_* indexes at all"
            for name in all_indexes:
                await db.conn.execute(f"DROP INDEX IF EXISTS {name}")
            await db.commit()
            assert await named_indexes(db._raw_conn()) == set()
        finally:
            await db.close()

        db = Database(db_path)
        await db.connect()
        try:
            await db.bootstrap()
            assert await named_indexes(db._raw_conn()) == all_indexes
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
