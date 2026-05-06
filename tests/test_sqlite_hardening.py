from __future__ import annotations

import asyncio
import sqlite3
from pathlib import Path

import aiosqlite
import pytest

import init_db
from db.database import CURRENT_SCHEMA_VERSION, Database
from models.dto import TelegramUserProfile
from models.enums import UserRole
from repositories.users import UserRepository
from repositories.vpn_keys import VpnKeyRepository


async def _create_user(db: Database, user_id: int = 100) -> None:
    await UserRepository(db).upsert_profile(TelegramUserProfile(user_id, "user", "User"), UserRole.PENDING_USER, "now")


def test_existing_schema_version_7_bootstrap_and_init_db_succeed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    db_path = tmp_path / "vpn-v7.db"

    async def seed_and_bootstrap() -> None:
        async with aiosqlite.connect(db_path) as conn:
            schema_path = Path(__file__).resolve().parents[1] / "db" / "schema.sql"
            await conn.executescript(schema_path.read_text(encoding="utf-8"))
            await conn.execute(
                """
                INSERT INTO schema_meta (key, value)
                VALUES ('schema_version', '7')
                ON CONFLICT(key) DO UPDATE SET value = excluded.value
                """
            )
            await conn.commit()

        db = Database(db_path)
        await db.connect()
        try:
            await db.bootstrap()
            cursor = await db.conn.execute("SELECT value FROM schema_meta WHERE key = 'schema_version'")
            row = await cursor.fetchone()
            assert row is not None
            assert int(row["value"]) == CURRENT_SCHEMA_VERSION == 9
        finally:
            await db.close()

    asyncio.run(seed_and_bootstrap())

    monkeypatch.setenv("BOT_TOKEN", "123456:TEST")
    monkeypatch.setenv("ADMIN_IDS", "100")
    monkeypatch.setenv("DB_PATH", str(db_path))
    monkeypatch.setenv("LOG_DIR", str(tmp_path / "logs"))
    monkeypatch.setenv("BOT_LOCK_PATH", str(tmp_path / "bot.lock"))

    asyncio.run(init_db.main())

    assert f"SQLite schema is ready: {db_path}" in capsys.readouterr().out


def test_read_waits_for_other_task_transaction_and_does_not_see_rollback(tmp_path: Path) -> None:
    async def run() -> None:
        db = Database(tmp_path / "vpn.db")
        await db.connect()
        try:
            await db.bootstrap()
            await _create_user(db)
            started = asyncio.Event()
            release = asyncio.Event()

            async def writer() -> None:
                async with db.transaction():
                    await db.conn.execute(
                        "UPDATE users SET role = ? WHERE telegram_user_id = ?",
                        (UserRole.APPROVED_USER.value, 100),
                    )
                    started.set()
                    await release.wait()
                    raise RuntimeError("rollback")

            writer_task = asyncio.create_task(writer())
            await started.wait()
            reader_task = asyncio.create_task(UserRepository(db).get_by_id(100))
            await asyncio.sleep(0.05)
            assert not reader_task.done()
            release.set()
            with pytest.raises(RuntimeError, match="rollback"):
                await writer_task
            user = await reader_task
            assert user is not None
            assert user.role == UserRole.PENDING_USER
        finally:
            await db.close()

    asyncio.run(run())


def test_database_applies_sqlite_synchronous_mode(tmp_path: Path) -> None:
    async def run() -> None:
        db = Database(tmp_path / "vpn.db", synchronous="EXTRA")
        await db.connect()
        try:
            cursor = await db.conn.execute("PRAGMA synchronous")
            row = await cursor.fetchone()
            assert row[0] == 3
        finally:
            await db.close()

    asyncio.run(run())


def test_orphan_traffic_stats_detected_on_bootstrap(tmp_path: Path) -> None:
    async def run() -> None:
        db_path = tmp_path / "vpn.db"
        db = Database(db_path)
        await db.connect()
        try:
            await db.bootstrap()
        finally:
            await db.close()

        async with aiosqlite.connect(db_path) as conn:
            await conn.execute("PRAGMA foreign_keys = OFF")
            await conn.execute(
                """
                INSERT INTO vpn_key_traffic_stats (
                  key_id, downloaded_bytes, uploaded_bytes, last_attempt_at, available
                )
                VALUES (999, 0, 0, 'now', 0)
                """
            )
            await conn.commit()

        db = Database(db_path)
        await db.connect()
        try:
            with pytest.raises(RuntimeError, match="orphan-записи traffic stats"):
                await db.bootstrap()
        finally:
            await db.close()

    asyncio.run(run())


def test_valid_reference_validation_passes_for_nullable_legacy_fields(tmp_path: Path) -> None:
    async def run() -> None:
        db = Database(tmp_path / "vpn.db")
        await db.connect()
        try:
            await db.bootstrap()
            await _create_user(db)
            await db.conn.execute(
                """
                INSERT INTO access_requests (telegram_user_id, username, status, requested_at, decided_by)
                VALUES (100, 'user', 'pending', 'now', NULL)
                """
            )
            await db.commit()
            await db.bootstrap()
        finally:
            await db.close()

    asyncio.run(run())


def test_invalid_user_role_rejected_on_new_db(tmp_path: Path) -> None:
    async def run() -> None:
        db = Database(tmp_path / "vpn.db")
        await db.connect()
        try:
            await db.bootstrap()
            with pytest.raises(sqlite3.IntegrityError):
                await db.conn.execute(
                    """
                    INSERT INTO users (telegram_user_id, username, first_name, role, created_at, updated_at)
                    VALUES (100, 'user', 'User', 'bad_role', 'now', 'now')
                    """
                )
        finally:
            await db.close()

    asyncio.run(run())


def test_invalid_vpn_key_status_rejected_on_new_db(tmp_path: Path) -> None:
    async def run() -> None:
        db = Database(tmp_path / "vpn.db")
        await db.connect()
        try:
            await db.bootstrap()
            await _create_user(db)
            with pytest.raises(sqlite3.IntegrityError):
                await db.conn.execute(
                    """
                    INSERT INTO vpn_keys (
                      owner_user_id, username, key_type, status, payload_json, public_payload_json,
                      created_at, updated_at, created_by
                    )
                    VALUES (100, 'user', 'xray', 'bad_status', '{}', '{}', 'now', 'now', 100)
                    """
                )
        finally:
            await db.close()

    asyncio.run(run())


def test_corrupted_legacy_vpn_key_enum_gives_controlled_error(tmp_path: Path) -> None:
    async def run() -> None:
        db_path = tmp_path / "legacy.db"
        async with aiosqlite.connect(db_path) as conn:
            await conn.executescript(
                """
                CREATE TABLE vpn_keys (
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  owner_user_id INTEGER NOT NULL,
                  username TEXT,
                  key_type TEXT NOT NULL,
                  status TEXT NOT NULL,
                  note TEXT,
                  uuid TEXT,
                  email_label TEXT,
                  public_key TEXT,
                  client_ip TEXT,
                  payload_json TEXT NOT NULL,
                  public_payload_json TEXT NOT NULL,
                  created_at TEXT NOT NULL,
                  updated_at TEXT NOT NULL,
                  revoked_at TEXT,
                  deleted_at TEXT,
                  created_by INTEGER NOT NULL,
                  revoked_by INTEGER,
                  deleted_by INTEGER
                );
                INSERT INTO vpn_keys (
                  owner_user_id, username, key_type, status, payload_json, public_payload_json,
                  created_at, updated_at, created_by
                )
                VALUES (100, 'user', 'xray', 'bad_status', '{}', '{}', 'now', 'now', 100);
                """
            )
            await conn.commit()

        db = Database(db_path)
        await db.connect()
        try:
            with pytest.raises(RuntimeError, match="vpn_keys.status"):
                await VpnKeyRepository(db).get_by_id(1)
        finally:
            await db.close()

    asyncio.run(run())


def test_duplicate_awg_client_ip_reserved_statuses_rejected(tmp_path: Path) -> None:
    async def run() -> None:
        db = Database(tmp_path / "vpn.db")
        await db.connect()
        try:
            await db.bootstrap()
            await _create_user(db)
            for status in ("active", "pending_delete"):
                params = (100, "user", "awg", status, "10.0.0.2", "{}", "{}", "now", "now", 100)
                if status == "pending_delete":
                    with pytest.raises(sqlite3.IntegrityError):
                        await db.conn.execute(
                            """
                            INSERT INTO vpn_keys (
                              owner_user_id, username, key_type, status, client_ip,
                              payload_json, public_payload_json, created_at, updated_at, created_by
                            )
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                            """,
                            params,
                        )
                else:
                    await db.conn.execute(
                        """
                        INSERT INTO vpn_keys (
                          owner_user_id, username, key_type, status, client_ip,
                          payload_json, public_payload_json, created_at, updated_at, created_by
                        )
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        params,
                    )
                    await db.commit()
        finally:
            await db.close()

    asyncio.run(run())


def test_duplicate_awg_client_ip_deleted_and_revoked_allowed(tmp_path: Path) -> None:
    async def run() -> None:
        db = Database(tmp_path / "vpn.db")
        await db.connect()
        try:
            await db.bootstrap()
            await _create_user(db)
            for status in ("revoked", "deleted"):
                await db.conn.execute(
                    """
                    INSERT INTO vpn_keys (
                      owner_user_id, username, key_type, status, client_ip,
                      payload_json, public_payload_json, created_at, updated_at, created_by
                    )
                    VALUES (100, 'user', 'awg', ?, '10.0.0.2', '{}', '{}', 'now', 'now', 100)
                    """,
                    (status,),
                )
            await db.commit()
        finally:
            await db.close()

    asyncio.run(run())


def test_existing_duplicate_reserved_awg_client_ip_detected_before_index_creation(tmp_path: Path) -> None:
    async def run() -> None:
        db_path = tmp_path / "vpn.db"
        db = Database(db_path)
        await db.connect()
        try:
            await db.bootstrap()
            await _create_user(db)
            await db.conn.execute("DROP INDEX IF EXISTS idx_vpn_keys_client_ip_reserved")
            await db.conn.execute("UPDATE schema_meta SET value = '4' WHERE key = 'schema_version'")
            for status in ("active", "pending_delete"):
                await db.conn.execute(
                    """
                    INSERT INTO vpn_keys (
                      owner_user_id, username, key_type, status, client_ip,
                      payload_json, public_payload_json, created_at, updated_at, created_by
                    )
                    VALUES (100, 'user', 'awg', ?, '10.0.0.2', '{}', '{}', 'now', 'now', 100)
                    """,
                    (status,),
                )
            await db.commit()
        finally:
            await db.close()

        db = Database(db_path)
        await db.connect()
        try:
            with pytest.raises(RuntimeError, match="дубли AWG client_ip"):
                await db.bootstrap()
        finally:
            await db.close()

    asyncio.run(run())
