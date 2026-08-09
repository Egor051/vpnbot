"""A Hysteria2 trial request must reach the database (schema v36).

The trial wizard has drawn a Hysteria2 button ever since the protocol shipped,
and ``services/trial_access.py`` has always branched on
``VpnKeyType.HYSTERIA2`` to provision the key on approval. Only the CHECK on
``trial_key_requests.key_type``, written back in _migrate_v13, still listed
``('xray','awg')`` — so tapping the button died with IntegrityError on the
INSERT that records the request, before any of that ran.

``_migrate_v36`` widens the CHECK. The structural half of that (a migrated
v35 database ending up identical to a fresh one, CHECK constraints included) is
covered by tests/test_schema_upgrade_path.py; this file covers the behaviour the
CHECK was blocking, on both construction paths.
"""
from __future__ import annotations

import asyncio
from pathlib import Path

import aiosqlite
import pytest

from db.database import CURRENT_SCHEMA_VERSION, Database
from models.dto import TelegramUserProfile
from models.enums import UserRole, VpnKeyType
from repositories.trial_requests import TrialKeyRequestRepository
from repositories.users import UserRepository

SNAPSHOT_V35 = Path(__file__).resolve().parent / "schema_snapshots" / "v35.sql"


async def _seeded(db: Database) -> TrialKeyRequestRepository:
    await UserRepository(db).upsert_profile(
        TelegramUserProfile(100, "user", "User"), UserRole.APPROVED_USER, "now"
    )
    return TrialKeyRequestRepository(db)


def test_a_fresh_database_accepts_a_hysteria2_trial_request(tmp_path: Path) -> None:
    async def run() -> None:
        db = Database(tmp_path / "vpn.db")
        await db.connect()
        try:
            await db.bootstrap()
            repo = await _seeded(db)
            req = await repo.create(
                telegram_user_id=100, key_type=VpnKeyType.HYSTERIA2, requested_at="now"
            )
            assert req.key_type == VpnKeyType.HYSTERIA2
            assert req.status == "pending"
            # And it reads back through the enum decoder, not just as raw text.
            stored = await repo.get_by_id(req.id)
            assert stored is not None and stored.key_type == VpnKeyType.HYSTERIA2
        finally:
            await db.close()

    asyncio.run(run())


def test_an_upgraded_v35_database_accepts_a_hysteria2_trial_request(tmp_path: Path) -> None:
    """The path every production deploy takes: an existing DB meets the new code."""

    async def run() -> None:
        db_path = tmp_path / "vpn.db"
        async with aiosqlite.connect(db_path) as conn:
            await conn.execute("PRAGMA foreign_keys = ON")
            await conn.executescript(SNAPSHOT_V35.read_text(encoding="utf-8"))
            await conn.execute(
                "INSERT OR REPLACE INTO schema_meta (key, value) VALUES ('schema_version', '35')"
            )
            await conn.commit()

        db = Database(db_path)
        await db.connect()
        try:
            await db.bootstrap()
            version = await db.get_meta("schema_version")
            assert int(version or "0") == CURRENT_SCHEMA_VERSION

            repo = await _seeded(db)
            req = await repo.create(
                telegram_user_id=100, key_type=VpnKeyType.HYSTERIA2, requested_at="now"
            )
            assert req.key_type == VpnKeyType.HYSTERIA2
        finally:
            await db.close()

    asyncio.run(run())


def test_the_widened_check_still_rejects_an_unknown_protocol(tmp_path: Path) -> None:
    """Widening is not removing: the CHECK must still be a CHECK."""

    async def run() -> None:
        db = Database(tmp_path / "vpn.db")
        await db.connect()
        try:
            await db.bootstrap()
            await _seeded(db)
            with pytest.raises(aiosqlite.IntegrityError):
                await db.conn.execute(
                    "INSERT INTO trial_key_requests (telegram_user_id, key_type, status, requested_at) "
                    "VALUES (100, 'wireguard', 'pending', 'now')"
                )
        finally:
            await db.close()

    asyncio.run(run())


def test_the_rebuild_keeps_the_pending_guard_and_existing_rows(tmp_path: Path) -> None:
    """The rebuild drops the table, so both indexes have to come back with it.

    idx_trial_requests_one_pending is the DB-level guard against double-granting a
    trial; losing it in the rebuild would be a silent regression that no structural
    column check would notice.
    """

    async def run() -> None:
        db_path = tmp_path / "vpn.db"
        async with aiosqlite.connect(db_path) as conn:
            await conn.execute("PRAGMA foreign_keys = ON")
            await conn.executescript(SNAPSHOT_V35.read_text(encoding="utf-8"))
            await conn.execute(
                "INSERT INTO users (telegram_user_id, username, first_name, role, created_at, updated_at) "
                "VALUES (100, 'user', 'User', 'APPROVED_USER', 'now', 'now')"
            )
            await conn.execute(
                "INSERT INTO trial_key_requests (id, telegram_user_id, key_type, status, requested_at) "
                "VALUES (7, 100, 'awg', 'approved', 'then')"
            )
            await conn.execute(
                "INSERT OR REPLACE INTO schema_meta (key, value) VALUES ('schema_version', '35')"
            )
            await conn.commit()

        db = Database(db_path)
        await db.connect()
        try:
            await db.bootstrap()
            repo = TrialKeyRequestRepository(db)

            # The pre-existing row survived the rebuild with its id and columns.
            carried = await repo.get_by_id(7)
            assert carried is not None
            assert carried.key_type == VpnKeyType.AWG
            assert carried.status == "approved"
            assert carried.requested_at == "then"

            # The partial unique index is back: a second pending row is refused.
            await repo.create(telegram_user_id=100, key_type=VpnKeyType.HYSTERIA2, requested_at="now")
            with pytest.raises(aiosqlite.IntegrityError):
                await repo.create(telegram_user_id=100, key_type=VpnKeyType.XRAY, requested_at="now")
        finally:
            await db.close()

    asyncio.run(run())
