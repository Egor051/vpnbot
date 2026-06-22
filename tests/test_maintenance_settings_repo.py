import asyncio
from pathlib import Path

from db.database import CURRENT_SCHEMA_VERSION, Database
from repositories.maintenance_settings import MaintenanceSettingsRepository


def test_default_is_disabled(tmp_path: Path) -> None:
    async def run() -> None:
        db = Database(tmp_path / "vpn.db")
        await db.connect()
        try:
            await db.bootstrap()
            repo = MaintenanceSettingsRepository(db)
            state = await repo.get()
            assert state.enabled is False
            assert state.message is None
            assert state.started_at == 0
            assert state.started_by is None
        finally:
            await db.close()

    asyncio.run(run())


def test_enable_persists_message_and_actor(tmp_path: Path) -> None:
    async def run() -> None:
        db = Database(tmp_path / "vpn.db")
        await db.connect()
        try:
            await db.bootstrap()
            repo = MaintenanceSettingsRepository(db)
            await repo.set_state(enabled=True, message="back at 5pm", started_by=42)
            state = await repo.get()
            assert state.enabled is True
            assert state.message == "back at 5pm"
            assert state.started_at > 0
            assert state.started_by == 42

            # Disabling clears the message and started_at.
            await repo.set_state(enabled=False, message=None, started_by=42)
            state = await repo.get()
            assert state.enabled is False
            assert state.message is None
            assert state.started_at == 0
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
            await MaintenanceSettingsRepository(db).set_state(enabled=True, message="hi", started_by=7)
        finally:
            await db.close()

        db2 = Database(db_path)
        await db2.connect()
        try:
            await db2.bootstrap()
            state = await MaintenanceSettingsRepository(db2).get()
            assert state.enabled is True
            assert state.message == "hi"
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
                "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'maintenance_settings'"
            )
            assert row is not None
            version_row = await db.conn.execute_fetchone(
                "SELECT value FROM schema_meta WHERE key = 'schema_version'"
            )
            assert version_row is not None
            assert int(version_row["value"]) == CURRENT_SCHEMA_VERSION
            assert CURRENT_SCHEMA_VERSION >= 25
        finally:
            await db.close()

    asyncio.run(run())
