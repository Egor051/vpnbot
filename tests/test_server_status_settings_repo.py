import asyncio
from pathlib import Path

from db.database import CURRENT_SCHEMA_VERSION, Database
from repositories.server_status_settings import ServerStatusSettingsRepository


def test_default_is_disabled_and_persists(tmp_path: Path) -> None:
    async def run() -> None:
        db = Database(tmp_path / "vpn.db")
        await db.connect()
        try:
            await db.bootstrap()
            repo = ServerStatusSettingsRepository(db)
            # Seed row defaults to disabled.
            assert await repo.get() is False
            await repo.set_detailed(True)
            assert await repo.get() is True
            await repo.set_detailed(False)
            assert await repo.get() is False
        finally:
            await db.close()

    asyncio.run(run())


def test_setting_survives_reconnect(tmp_path: Path) -> None:
    db_path = tmp_path / "vpn.db"

    async def run() -> None:
        db = Database(db_path)
        await db.connect()
        try:
            await db.bootstrap()
            await ServerStatusSettingsRepository(db).set_detailed(True)
        finally:
            await db.close()

        db2 = Database(db_path)
        await db2.connect()
        try:
            await db2.bootstrap()
            assert await ServerStatusSettingsRepository(db2).get() is True
        finally:
            await db2.close()

    asyncio.run(run())


def test_migration_creates_table_and_bumps_version(tmp_path: Path) -> None:
    async def run() -> None:
        db = Database(tmp_path / "vpn.db")
        await db.connect()
        try:
            await db.bootstrap()
            row = await db.conn.execute_fetchone(
                "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'server_status_settings'"
            )
            assert row is not None
            version_row = await db.conn.execute_fetchone(
                "SELECT value FROM schema_meta WHERE key = 'schema_version'"
            )
            assert version_row is not None
            assert int(version_row["value"]) == CURRENT_SCHEMA_VERSION
            assert CURRENT_SCHEMA_VERSION >= 24
        finally:
            await db.close()

    asyncio.run(run())
