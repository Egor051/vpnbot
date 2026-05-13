
import asyncio
from pathlib import Path

import pytest

from db.database import Database
from models.dto import TelegramUserProfile
from models.enums import UserRole, VpnKeyType
from repositories.users import UserRepository
from repositories.vpn_keys import VpnKeyRepository
from services.errors import InvalidTransition


def test_double_revoke_raises_invalid_transition(tmp_path: Path) -> None:
    async def run() -> None:
        db = Database(tmp_path / "vpn.db")
        await db.connect()
        try:
            await db.bootstrap()
            await UserRepository(db).upsert_profile(
                TelegramUserProfile(100, "user", "User"), UserRole.APPROVED_USER, "2026-01-01T00:00:00"
            )
            repo = VpnKeyRepository(db)
            key = await repo.create_pending(
                owner_user_id=100,
                username="user",
                key_type=VpnKeyType.XRAY,
                note=None,
                payload={},
                public_payload={},
                created_by=100,
                now="2026-01-01T00:00:00",
                uuid="00000000-0000-4000-8000-000000000001",
                email_label="label",
            )

            await repo.mark_revoked(key.id, actor_user_id=100, now="2026-01-01T01:00:00")

            with pytest.raises(InvalidTransition):
                await repo.mark_revoked(key.id, actor_user_id=100, now="2026-01-01T02:00:00")
        finally:
            await db.close()

    asyncio.run(run())


def test_revoke_already_deleted_key_raises_invalid_transition(tmp_path: Path) -> None:
    async def run() -> None:
        db = Database(tmp_path / "vpn.db")
        await db.connect()
        try:
            await db.bootstrap()
            await UserRepository(db).upsert_profile(
                TelegramUserProfile(100, "user", "User"), UserRole.APPROVED_USER, "2026-01-01T00:00:00"
            )
            repo = VpnKeyRepository(db)
            key = await repo.create_pending(
                owner_user_id=100,
                username="user",
                key_type=VpnKeyType.XRAY,
                note=None,
                payload={},
                public_payload={},
                created_by=100,
                now="2026-01-01T00:00:00",
                uuid="00000000-0000-4000-8000-000000000002",
                email_label="label2",
            )

            await repo.mark_deleted(key.id, actor_user_id=100, now="2026-01-01T01:00:00")

            with pytest.raises(InvalidTransition):
                await repo.mark_revoked(key.id, actor_user_id=100, now="2026-01-01T02:00:00")
        finally:
            await db.close()

    asyncio.run(run())
