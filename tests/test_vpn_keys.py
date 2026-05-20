
import asyncio
from pathlib import Path

import pytest

from db.database import Database
from models.dto import TelegramUserProfile
from models.enums import UserRole, VpnKeyType
from repositories.trial_requests import TrialKeyRequestRepository
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


def test_list_active_trial_by_owner_excludes_regular_keys_with_expires_at(tmp_path: Path) -> None:
    """Keys with expires_at but no approved trial_key_requests entry must NOT appear."""

    async def run() -> None:
        db = Database(tmp_path / "vpn.db")
        await db.connect()
        try:
            await db.bootstrap()
            await UserRepository(db).upsert_profile(
                TelegramUserProfile(100, "user", "User"), UserRole.PENDING_USER, "2026-01-01T00:00:00"
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
                expires_at="2099-01-01T00:00:00",
            )
            await repo.mark_active(key.id, "2026-01-01T00:01:00")

            result = await repo.list_active_trial_by_owner(100)
            assert result == [], "regular key with expires_at must not appear without approved trial request"
        finally:
            await db.close()

    asyncio.run(run())


def test_list_active_trial_by_owner_returns_approved_trial_key(tmp_path: Path) -> None:
    """Key linked to an approved trial_key_request must appear."""

    async def run() -> None:
        db = Database(tmp_path / "vpn.db")
        await db.connect()
        try:
            await db.bootstrap()
            await UserRepository(db).upsert_profile(
                TelegramUserProfile(100, "user", "User"), UserRole.PENDING_USER, "2026-01-01T00:00:00"
            )
            await UserRepository(db).upsert_profile(
                TelegramUserProfile(1, "admin", "Admin"), UserRole.SUPERADMIN, "2026-01-01T00:00:00"
            )
            vpn_repo = VpnKeyRepository(db)
            trial_repo = TrialKeyRequestRepository(db)

            trial_req = await trial_repo.create(
                telegram_user_id=100,
                key_type=VpnKeyType.XRAY,
                requested_at="2026-01-01T00:00:00",
            )
            key = await vpn_repo.create_pending(
                owner_user_id=100,
                username="user",
                key_type=VpnKeyType.XRAY,
                note=None,
                payload={},
                public_payload={},
                created_by=1,
                now="2026-01-01T00:01:00",
                expires_at="2099-01-01T00:00:00",
            )
            await vpn_repo.mark_active(key.id, "2026-01-01T00:02:00")
            await trial_repo.approve(
                request_id=trial_req.id,
                key_id=key.id,
                decided_by=1,
                decided_at="2026-01-01T00:02:00",
            )

            result = await vpn_repo.list_active_trial_by_owner(100)
            assert len(result) == 1
            assert result[0].id == key.id
        finally:
            await db.close()

    asyncio.run(run())


def test_list_active_trial_by_owner_ignores_other_owners(tmp_path: Path) -> None:
    """Trial keys owned by a different user must not be returned."""

    async def run() -> None:
        db = Database(tmp_path / "vpn.db")
        await db.connect()
        try:
            await db.bootstrap()
            for uid, name in [(100, "alice"), (200, "bob")]:
                await UserRepository(db).upsert_profile(
                    TelegramUserProfile(uid, name, name.capitalize()), UserRole.PENDING_USER, "2026-01-01T00:00:00"
                )
            await UserRepository(db).upsert_profile(
                TelegramUserProfile(1, "admin", "Admin"), UserRole.SUPERADMIN, "2026-01-01T00:00:00"
            )
            vpn_repo = VpnKeyRepository(db)
            trial_repo = TrialKeyRequestRepository(db)

            trial_req = await trial_repo.create(
                telegram_user_id=200,
                key_type=VpnKeyType.XRAY,
                requested_at="2026-01-01T00:00:00",
            )
            key = await vpn_repo.create_pending(
                owner_user_id=200,
                username="bob",
                key_type=VpnKeyType.XRAY,
                note=None,
                payload={},
                public_payload={},
                created_by=1,
                now="2026-01-01T00:01:00",
                expires_at="2099-01-01T00:00:00",
            )
            await vpn_repo.mark_active(key.id, "2026-01-01T00:02:00")
            await trial_repo.approve(
                request_id=trial_req.id,
                key_id=key.id,
                decided_by=1,
                decided_at="2026-01-01T00:02:00",
            )

            assert await vpn_repo.list_active_trial_by_owner(100) == []
            assert len(await vpn_repo.list_active_trial_by_owner(200)) == 1
        finally:
            await db.close()

    asyncio.run(run())
