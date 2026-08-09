"""The personal cabinet and the dashboard must not answer different questions.

They used to. The cabinet summed ↓ over an owner's non-deleted keys; the
dashboard summed ↓ + ↑ over every key plus the deleted-key archive. Neither was
wrong and neither said what it was counting, so the same account read as two
different gigabyte figures depending on the screen — and the difference resolved
with a remainder of exactly zero once both were written out.

There is now one query behind both (:mod:`repositories.traffic_scope`), taking
the scope as a parameter, and every screen prints the scope it is showing.
"""
from __future__ import annotations

import asyncio
from pathlib import Path
from types import SimpleNamespace

import pytest

from db.database import Database
from models.dto import TelegramUserProfile
from models.enums import UserRole, VpnKeyStatus, VpnKeyType
from repositories.dashboard import DashboardRepository
from repositories.traffic_scope import ALL_TIME, CURRENT_KEYS, TrafficScope
from repositories.users import UserRepository
from repositories.vpn_keys import VpnKeyRepository
from services.vpn_keys import VpnKeyQueryService


class _Users:
    """Minimal UserService stand-in: everyone is an approved user of themselves."""

    def __init__(self, role: UserRole = UserRole.APPROVED_USER) -> None:
        self._role = role

    async def require_approved_or_admin(self, user_id: int) -> object:
        return SimpleNamespace(telegram_user_id=user_id, role=self._role)


async def _key_with_traffic(
    repo: VpnKeyRepository,
    db: Database,
    *,
    owner: int,
    uuid: str,
    label: str,
    down: int,
    up: int,
    key_type: VpnKeyType = VpnKeyType.XRAY,
) -> int:
    key = await repo.create_pending(
        owner_user_id=owner,
        username="user",
        key_type=key_type,
        note=None,
        payload={},
        public_payload={},
        created_by=owner,
        now="now",
        uuid=uuid,
        email_label=label,
    )
    await db.conn.execute(
        "INSERT INTO vpn_key_traffic_stats (key_id, downloaded_bytes, uploaded_bytes) VALUES (?, ?, ?)",
        (key.id, down, up),
    )
    await db.commit()
    return key.id


async def _fixture(tmp_path: Path) -> tuple[Database, VpnKeyRepository]:
    """An owner with an active key, a status='deleted' key and an archive row.

    Active:   1000 ↓ / 400 ↑
    Deleted:  70 ↓ / 30 ↑   — a vpn_keys row parked in status='deleted'
    Archived: 500 ↓ / 100 ↑ — a key that no longer exists at all
    """
    db = Database(tmp_path / "vpn.db")
    await db.connect()
    await db.bootstrap()
    await UserRepository(db).upsert_profile(
        TelegramUserProfile(100, "user", "User"), UserRole.APPROVED_USER, "now"
    )
    repo = VpnKeyRepository(db)

    await _key_with_traffic(
        repo, db, owner=100, uuid="00000000-0000-4000-8000-000000000001",
        label="active", down=1000, up=400,
    )
    doomed = await _key_with_traffic(
        repo, db, owner=100, uuid="00000000-0000-4000-8000-000000000002",
        label="doomed", down=500, up=100, key_type=VpnKeyType.AWG,
    )
    await repo.hard_delete_with_stats(doomed, "2026-01-01T00:00:00+00:00")

    # A key left in status='deleted' WITH a stats row — the state the anti
    # double-count guard exists for. It is not what the archive covers, and no
    # scope may count it.
    soft = await _key_with_traffic(
        repo, db, owner=100, uuid="00000000-0000-4000-8000-000000000003",
        label="soft-deleted", down=70, up=30,
    )
    await db.conn.execute(
        "UPDATE vpn_keys SET status = ? WHERE id = ?", (VpnKeyStatus.DELETED.value, soft)
    )
    await db.commit()
    return db, repo


def test_current_keys_scope_excludes_the_archive_and_deleted_keys(tmp_path: Path) -> None:
    async def run() -> None:
        db, repo = await _fixture(tmp_path)
        try:
            down, up = await repo.sum_traffic_for_owner(100, CURRENT_KEYS)
            assert (down, up) == (1000, 400)
        finally:
            await db.close()

    asyncio.run(run())


def test_all_time_scope_is_current_keys_plus_the_archive(tmp_path: Path) -> None:
    async def run() -> None:
        db, repo = await _fixture(tmp_path)
        try:
            current_down, current_up = await repo.sum_traffic_for_owner(100, CURRENT_KEYS)
            all_down, all_up = await repo.sum_traffic_for_owner(100, ALL_TIME)
            # Archive holds 500/100 on top of the current keys.
            assert (all_down, all_up) == (current_down + 500, current_up + 100)
            # And the soft-deleted key (70/30) is in neither: counting it in the
            # all-time scope would double it against the archive.
            assert all_down == 1500 and all_up == 500
        finally:
            await db.close()

    asyncio.run(run())


def test_the_personal_cabinet_agrees_with_the_shared_query(tmp_path: Path) -> None:
    """The cabinet's figure IS the shared query's figure — same code path, both scopes."""

    async def run() -> None:
        db, repo = await _fixture(tmp_path)
        try:
            service = VpnKeyQueryService(vpn_keys=repo, users=_Users())  # type: ignore[arg-type]
            _x, _a, _h, traffic = await service.personal_summary_for_actor(100)

            assert (
                traffic.current_keys.downloaded_bytes,
                traffic.current_keys.uploaded_bytes,
            ) == await repo.sum_traffic_for_owner(100, CURRENT_KEYS)
            assert (
                traffic.all_time.downloaded_bytes,
                traffic.all_time.uploaded_bytes,
            ) == await repo.sum_traffic_for_owner(100, ALL_TIME)
            # The sum shown next to each scope is exactly ↓ + ↑.
            assert traffic.current_keys.total_bytes == 1400
            assert traffic.all_time.total_bytes == 2000
        finally:
            await db.close()

    asyncio.run(run())


def test_the_admin_card_aggregate_is_not_capped_by_the_key_list_page(tmp_path: Path) -> None:
    """11+ keys: the list is paginated, the total is not."""

    async def run() -> None:
        db = Database(tmp_path / "vpn.db")
        await db.connect()
        try:
            await db.bootstrap()
            await UserRepository(db).upsert_profile(
                TelegramUserProfile(100, "user", "User"), UserRole.APPROVED_USER, "now"
            )
            await UserRepository(db).upsert_profile(
                TelegramUserProfile(1, "root", "Root"), UserRole.SUPERADMIN, "now"
            )
            repo = VpnKeyRepository(db)
            for index in range(11):
                await _key_with_traffic(
                    repo, db, owner=100,
                    uuid=f"00000000-0000-4000-8000-0000000001{index:02d}",
                    label=f"key-{index}", down=100, up=10,
                )

            service = VpnKeyQueryService(vpn_keys=repo, users=_Users(UserRole.SUPERADMIN))  # type: ignore[arg-type]
            traffic = await service.traffic_summary_for_actor(1, 100)

            # 11 keys, 110 bytes each. The old code summed the ten keys the card lists.
            assert traffic.current_keys.total_bytes == 11 * 110
            listed = await service.list_for_actor(1, owner_user_id=100, limit=10)
            assert len(listed) == 10, "the displayed list is still capped"
        finally:
            await db.close()

    asyncio.run(run())


def test_dashboard_totals_and_top_run_the_same_query_as_the_cabinet(tmp_path: Path) -> None:
    async def run() -> None:
        db, repo = await _fixture(tmp_path)
        try:
            dash = DashboardRepository(db)

            top = await dash.top_users_by_traffic(limit=5)
            owner_all_time = await repo.sum_traffic_for_owner(100, ALL_TIME)
            assert [(entry.user_id, entry.total_bytes) for entry in top] == [
                (100, sum(owner_all_time))
            ]

            totals = await dash.traffic_totals()
            # Same dataset for the sum and the average: 1400 (live xray) + 600
            # (archived awg) over two rows.
            assert totals.total_bytes == 2000
            assert totals.xray_bytes == 1400
            assert totals.awg_bytes == 600
            assert totals.avg_per_key_bytes == 1000
            assert totals.avg_per_key_bytes * 2 == totals.total_bytes
        finally:
            await db.close()

    asyncio.run(run())


def test_the_double_counting_scope_cannot_be_constructed() -> None:
    """Counting the archive AND status='deleted' rows would count deleted bytes twice."""
    with pytest.raises(ValueError, match="double-count"):
        TrafficScope(include_archive=True, include_deleted_keys=True)
