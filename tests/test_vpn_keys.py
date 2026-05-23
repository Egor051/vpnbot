
import asyncio
from pathlib import Path

import pytest

from db.database import Database
from models.dto import TelegramUserProfile
from models.enums import UserRole, VpnKeyStatus, VpnKeyType
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


def test_mark_revoked_clears_client_ip(tmp_path: Path) -> None:
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
                key_type=VpnKeyType.AWG,
                note=None,
                payload={},
                public_payload={},
                created_by=100,
                now="2026-01-01T00:00:00",
                client_ip="10.0.0.1",
            )
            await repo.mark_active(key.id, "2026-01-01T00:01:00")
            await repo.mark_revoked(key.id, actor_user_id=100, now="2026-01-01T01:00:00")
            refreshed = await repo.get_by_id(key.id)
            assert refreshed is not None
            assert refreshed.client_ip is None
        finally:
            await db.close()

    asyncio.run(run())


def test_migrate_v19_nulls_only_conflicting_revoked_ips(tmp_path: Path) -> None:
    async def run() -> None:
        db = Database(tmp_path / "vpn.db")
        await db.connect()
        try:
            await db.bootstrap()
            await UserRepository(db).upsert_profile(
                TelegramUserProfile(100, "user", "User"), UserRole.APPROVED_USER, "2026-01-01T00:00:00"
            )
            repo = VpnKeyRepository(db)

            # Active AWG key claiming IP 10.0.0.2 (will be in the partial unique index)
            active_key = await repo.create_pending(
                owner_user_id=100,
                username="user",
                key_type=VpnKeyType.AWG,
                note=None,
                payload={},
                public_payload={},
                created_by=100,
                now="2026-01-01T00:00:00",
                client_ip="10.0.0.2",
            )
            await repo.mark_active(active_key.id, "2026-01-01T00:01:00")

            # Insert dirty data: revoked key sharing IP with the active key.
            # status='revoked' is outside the partial unique index, so this insert succeeds.
            raw = db._raw_conn()
            cur = await raw.execute(
                "INSERT INTO vpn_keys "
                "(owner_user_id, username, key_type, status, payload_json, public_payload_json, "
                "created_at, updated_at, created_by, client_ip) "
                "VALUES (100, 'user', 'awg', 'revoked', '{}', '{}', "
                "'2026-01-01T00:00:00', '2026-01-01T01:00:00', 100, '10.0.0.2')"
            )
            conflicting_id = cur.lastrowid

            # Insert revoked key with an IP not claimed by any active/pending key (must not be touched)
            cur2 = await raw.execute(
                "INSERT INTO vpn_keys "
                "(owner_user_id, username, key_type, status, payload_json, public_payload_json, "
                "created_at, updated_at, created_by, client_ip) "
                "VALUES (100, 'user', 'awg', 'revoked', '{}', '{}', "
                "'2026-01-01T00:00:00', '2026-01-01T01:00:00', 100, '10.0.0.99')"
            )
            non_conflicting_id = cur2.lastrowid
            await raw.commit()

            await db._migrate_v19()
            await db.commit()

            cur3 = await raw.execute("SELECT client_ip FROM vpn_keys WHERE id = ?", (conflicting_id,))
            row3 = await cur3.fetchone()
            assert row3 is not None and row3[0] is None, "conflicting revoked key's IP should be NULL"

            cur4 = await raw.execute("SELECT client_ip FROM vpn_keys WHERE id = ?", (non_conflicting_id,))
            row4 = await cur4.fetchone()
            assert row4 is not None and row4[0] == "10.0.0.99", "non-conflicting revoked key must keep its IP"
        finally:
            await db.close()

    asyncio.run(run())


def test_delete_revoked_key_after_migration_no_integrity_error(tmp_path: Path) -> None:
    async def run() -> None:
        db = Database(tmp_path / "vpn.db")
        await db.connect()
        try:
            await db.bootstrap()
            await UserRepository(db).upsert_profile(
                TelegramUserProfile(100, "user", "User"), UserRole.APPROVED_USER, "2026-01-01T00:00:00"
            )
            repo = VpnKeyRepository(db)

            # Active AWG key with IP 10.0.0.5
            active_key = await repo.create_pending(
                owner_user_id=100,
                username="user",
                key_type=VpnKeyType.AWG,
                note=None,
                payload={},
                public_payload={},
                created_by=100,
                now="2026-01-01T00:00:00",
                client_ip="10.0.0.5",
            )
            await repo.mark_active(active_key.id, "2026-01-01T00:01:00")

            # Simulate dirty data: revoked key sharing the same IP (pre-fix scenario)
            raw = db._raw_conn()
            cur = await raw.execute(
                "INSERT INTO vpn_keys "
                "(owner_user_id, username, key_type, status, payload_json, public_payload_json, "
                "created_at, updated_at, created_by, client_ip) "
                "VALUES (100, 'user', 'awg', 'revoked', '{}', '{}', "
                "'2026-01-01T00:00:00', '2026-01-01T01:00:00', 100, '10.0.0.5')"
            )
            revoked_id = cur.lastrowid
            await raw.commit()

            # Migration repairs the dirty data
            await db._migrate_v19()
            await db.commit()

            # Transitioning the revoked key to pending_delete must not raise IntegrityError
            await repo.set_status(revoked_id, VpnKeyStatus.PENDING_DELETE, "2026-01-01T02:00:00")
        finally:
            await db.close()

    asyncio.run(run())
