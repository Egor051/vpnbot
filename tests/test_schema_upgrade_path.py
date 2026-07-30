"""Upgrade-path coverage: replay real old on-disk schemas through bootstrap().

Every other schema test builds its database from the CURRENT code — schema.sql
plus the full migration chain from version 0 — so the only path CI ever exercised
was "fresh DB". The path every production deploy actually takes, "existing DB at
version N-1 meets new code", had no coverage at all. That hole let a baseline DDL
statement referencing a column added by a migration (the UNIQUE index on
``key_bundles.display_no``, added by ``_migrate_v33``) pass CI twice and then
crash-loop the bot on a live v32 database: ``executescript(schema.sql)`` runs
BEFORE the migrations, ``CREATE TABLE IF NOT EXISTS key_bundles`` was a no-op on
the existing table, and the index then failed with "no such column: display_no" —
before ``_migrate_v33`` ever got the chance to add it.

The harness here is deliberately version-agnostic. For every snapshot artifact in
``tests/schema_snapshots/`` it materialises that exact historical schema, seeds it
(when a ``.seed.sql`` companion exists), runs ``bootstrap()`` and asserts the
result is indistinguishable from a fresh bootstrap. Adding the next migration
means adding one snapshot file — see ``scripts/dump_schema_snapshot.py`` — and
``test_previous_version_snapshot_exists`` fails the build if that step is skipped,
so the next schema bump cannot repeat this history.
"""

from __future__ import annotations

import asyncio
import re
from pathlib import Path

import aiosqlite
import pytest
from conftest import SchemaShape, assert_same_shape, schema_shape

from db.database import CURRENT_SCHEMA_VERSION, Database


SNAPSHOT_DIR = Path(__file__).resolve().parent / "schema_snapshots"
_SNAPSHOT_RE = re.compile(r"^v(\d+)\.sql$")


def _snapshot_versions() -> list[int]:
    return sorted(
        int(match.group(1))
        for path in SNAPSHOT_DIR.glob("v*.sql")
        if (match := _SNAPSHOT_RE.match(path.name)) is not None
    )


async def _materialise(db_path: Path, version: int) -> dict[str, int]:
    """Write the version-`version` database to `db_path` and return its row counts.

    The snapshot is the DDL of a real database at that version; the seed (optional)
    is hand-written data. schema_version is stamped last so bootstrap() enters the
    migration chain exactly where a production database of that vintage would.
    """
    snapshot = (SNAPSHOT_DIR / f"v{version}.sql").read_text(encoding="utf-8")
    seed_path = SNAPSHOT_DIR / f"v{version}.seed.sql"
    async with aiosqlite.connect(db_path) as conn:
        await conn.execute("PRAGMA foreign_keys = ON")
        await conn.executescript(snapshot)
        if seed_path.exists():
            await conn.executescript(seed_path.read_text(encoding="utf-8"))
        await conn.execute(
            "INSERT OR REPLACE INTO schema_meta (key, value) VALUES ('schema_version', ?)",
            (str(version),),
        )
        await conn.commit()
        cursor = await conn.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
        )
        tables = [str(row[0]) for row in await cursor.fetchall()]
        counts: dict[str, int] = {}
        for table in tables:
            count_cursor = await conn.execute(f"SELECT COUNT(*) FROM {table}")  # noqa: S608
            row = await count_cursor.fetchone()
            counts[table] = int(row[0]) if row is not None else 0
    return counts


async def _bootstrap_and_read(db_path: Path) -> tuple[int, SchemaShape]:
    db = Database(db_path)
    await db.connect()
    try:
        await db.bootstrap()
        row = await db.conn.execute_fetchone(
            "SELECT value FROM schema_meta WHERE key = 'schema_version'"
        )
        assert row is not None
        return int(row["value"]), await schema_shape(db._raw_conn())
    finally:
        await db.close()


async def _row_counts(db_path: Path, tables: dict[str, int]) -> dict[str, int]:
    counts: dict[str, int] = {}
    async with aiosqlite.connect(db_path) as conn:
        for table in tables:
            cursor = await conn.execute(f"SELECT COUNT(*) FROM {table}")  # noqa: S608
            row = await cursor.fetchone()
            counts[table] = int(row[0]) if row is not None else 0
    return counts


async def _fresh_shape(db_path: Path) -> SchemaShape:
    db = Database(db_path)
    await db.connect()
    try:
        await db.bootstrap()
        return await schema_shape(db._raw_conn())
    finally:
        await db.close()


@pytest.mark.parametrize("version", _snapshot_versions())
def test_bootstrap_upgrades_snapshot_to_current_schema(version: int, tmp_path: Path) -> None:
    """A database at version N survives bootstrap() and comes out structurally
    identical to a fresh one — same tables, columns, foreign keys and indexes —
    with its data intact.

    This is the assertion that fails on the pre-fix tree for the v32 snapshot:
    bootstrap() raises ``sqlite3.OperationalError: no such column: display_no``
    from the baseline script, exactly as the bot did on the box.
    """

    async def run() -> None:
        upgraded = tmp_path / "upgraded.db"
        before = await _materialise(upgraded, version)

        after_version, upgraded_shape = await _bootstrap_and_read(upgraded)
        assert after_version == CURRENT_SCHEMA_VERSION

        fresh_shape = await _fresh_shape(tmp_path / "fresh.db")
        assert_same_shape(upgraded_shape, fresh_shape, f"v{version} -> v{CURRENT_SCHEMA_VERSION}")

        # No migration may LOSE rows: a table-rebuild that drops data (v16/v17/v29
        # copy row by row) would otherwise pass every structural check above.
        # Growth is legitimate and expected — bootstrap re-seeds the lookup and
        # singleton tables (protocol_modules, warp_settings, …) with
        # INSERT OR IGNORE on every start.
        after = await _row_counts(upgraded, before)
        lost = {table: (before[table], after[table]) for table in before if after[table] < before[table]}
        assert not lost, f"v{version}: rows lost across the upgrade (before, after): {lost}"

    asyncio.run(run())


@pytest.mark.parametrize("version", _snapshot_versions())
def test_upgraded_database_bootstraps_again_unchanged(version: int, tmp_path: Path) -> None:
    """Restarting the bot on an already-upgraded database is a no-op.

    Every migration is guarded, but the guards are only exercised if something
    re-runs them on a migrated DB — which is what the second and every subsequent
    start of a deployed bot does.
    """

    async def run() -> None:
        db_path = tmp_path / "upgraded.db"
        await _materialise(db_path, version)
        _, first = await _bootstrap_and_read(db_path)
        second_version, second = await _bootstrap_and_read(db_path)
        assert second_version == CURRENT_SCHEMA_VERSION
        assert_same_shape(second, first, f"v{version} re-bootstrap")

    asyncio.run(run())


def test_previous_version_snapshot_exists() -> None:
    """The forcing function: bumping CURRENT_SCHEMA_VERSION without capturing the
    version you are leaving is what removes upgrade coverage, so it fails here.

    Nothing above can catch a missing snapshot on its own — a version with no
    artifact simply is not parametrised, and the suite goes green with the upgrade
    path untested (which is precisely how v32 -> v33 shipped).
    """
    previous = CURRENT_SCHEMA_VERSION - 1
    assert previous in _snapshot_versions(), (
        f"no tests/schema_snapshots/v{previous}.sql — the upgrade path into "
        f"v{CURRENT_SCHEMA_VERSION} is untested. Check out the tree that still has "
        f"CURRENT_SCHEMA_VERSION = {previous}, run `python scripts/dump_schema_snapshot.py`, "
        "and commit the artifact it writes."
    )


def test_snapshots_are_older_than_current_version() -> None:
    """A snapshot at or above CURRENT_SCHEMA_VERSION is not an upgrade fixture —
    it is either a stale artifact or a forgotten version bump."""
    assert all(v < CURRENT_SCHEMA_VERSION for v in _snapshot_versions())


def test_v33_renumbers_bundles_out_of_the_key_id_space(tmp_path: Path) -> None:
    """Per-migration data assertion on top of the generic structural harness.

    The v32 seed has vpn_keys ids up to 176 and two bundles created oldest-first.
    _migrate_v33 must renumber both out of the vpn_keys id space (so the merged
    list the user reads has ONE running count) rather than leaving them on their
    own AUTOINCREMENT sequence, which is what showed «All-in-One #1» next to keys
    numbered «#176».
    """

    async def run() -> None:
        db_path = tmp_path / "upgraded.db"
        await _materialise(db_path, 32)
        version, _ = await _bootstrap_and_read(db_path)
        assert version == CURRENT_SCHEMA_VERSION

        async with aiosqlite.connect(db_path) as conn:
            conn.row_factory = aiosqlite.Row
            cursor = await conn.execute("SELECT id, display_no FROM key_bundles ORDER BY id")
            rows = [(int(r["id"]), r["display_no"]) for r in await cursor.fetchall()]

        assert [r[1] for r in rows] == [177, 178], rows

    asyncio.run(run())
