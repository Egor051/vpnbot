
import asyncio
from pathlib import Path

from db.database import Database
from models.dto import TelegramUserProfile
from models.enums import UserRole, VpnKeyType
from repositories.dashboard import DashboardRepository
from repositories.users import UserRepository
from repositories.vpn_keys import VpnKeyRepository


async def _make_key(repo: VpnKeyRepository, db: Database, *, owner: int, username: str,
                    key_type: VpnKeyType, uuid: str, label: str, down: int, up: int) -> int:
    key = await repo.create_pending(
        owner_user_id=owner,
        username=username,
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


def test_traffic_totals_include_archived_and_avg_is_consistent(tmp_path: Path) -> None:
    async def run() -> None:
        db = Database(tmp_path / "vpn.db")
        await db.connect()
        try:
            await db.bootstrap()
            users = UserRepository(db)
            await users.upsert_profile(TelegramUserProfile(100, "user", "User"), UserRole.APPROVED_USER, "now")
            repo = VpnKeyRepository(db)
            dash = DashboardRepository(db)

            live = await _make_key(
                repo, db, owner=100, username="user", key_type=VpnKeyType.XRAY,
                uuid="00000000-0000-4000-8000-000000000001", label="live", down=100, up=50,
            )
            doomed = await _make_key(
                repo, db, owner=100, username="user", key_type=VpnKeyType.AWG,
                uuid="00000000-0000-4000-8000-000000000002", label="doomed", down=300, up=50,
            )

            # Hard-delete the AWG key: its 350 bytes must survive in the archive.
            await repo.hard_delete_with_stats(doomed, "2024-01-01T00:00:00")

            totals = await dash.traffic_totals()
            # 150 (live xray) + 350 (archived awg) must still be counted.
            assert totals.xray_bytes == 150
            assert totals.awg_bytes == 350
            assert totals.total_bytes == 500
            # avg must stay consistent with the total: 500 bytes over 2 keys = 250.
            assert totals.avg_per_key_bytes == 250
            assert totals.avg_per_key_bytes * 2 == totals.total_bytes

            assert live  # silence unused warning; key id is meaningful for setup
        finally:
            await db.close()

    asyncio.run(run())


def test_top_users_by_traffic_include_archived_and_username_is_deterministic(tmp_path: Path) -> None:
    async def run() -> None:
        db = Database(tmp_path / "vpn.db")
        await db.connect()
        try:
            await db.bootstrap()
            users = UserRepository(db)
            await users.upsert_profile(TelegramUserProfile(100, "alice", "Alice"), UserRole.APPROVED_USER, "now")
            await users.upsert_profile(TelegramUserProfile(200, "bob", "Bob"), UserRole.APPROVED_USER, "now")
            repo = VpnKeyRepository(db)
            dash = DashboardRepository(db)

            # Alice: one live key (150) + one deleted key (350) = 500 total.
            await _make_key(
                repo, db, owner=100, username="alice", key_type=VpnKeyType.XRAY,
                uuid="00000000-0000-4000-8000-000000000001", label="a-live", down=100, up=50,
            )
            a_doomed = await _make_key(
                repo, db, owner=100, username="alice", key_type=VpnKeyType.AWG,
                uuid="00000000-0000-4000-8000-000000000002", label="a-doomed", down=300, up=50,
            )
            await repo.hard_delete_with_stats(a_doomed, "2024-01-01T00:00:00")

            # Bob: a single live key (100) — fewer bytes than Alice.
            await _make_key(
                repo, db, owner=200, username="bob", key_type=VpnKeyType.XRAY,
                uuid="00000000-0000-4000-8000-000000000003", label="b-live", down=60, up=40,
            )

            top = await dash.top_users_by_traffic(limit=5)
            assert [(u.user_id, u.total_bytes) for u in top] == [(100, 500), (200, 100)]
            # Username is resolved deterministically from the users table.
            assert top[0].username == "alice"
            assert top[1].username == "bob"
        finally:
            await db.close()

    asyncio.run(run())
