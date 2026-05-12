
import asyncio
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest
from aiogram.enums import ChatType

from adapters.clock import ClockProvider
from adapters.ip_allocator import IpAllocator
from bot.fsm.states import AdminCreateKeyStates, CreateKeyStates
from bot.handlers.admin import admin_announcement_message, admin_announcement_send, admin_announcement_start, admin_issue_confirm
from bot.handlers.keys import create_key_confirm
from bot.keyboards.keys import keys_list_keyboard
from bot.rate_limit import RateLimitExceeded
from config.settings import Settings
from db.database import Database
from models.dto import TelegramUserProfile, User, VpnKey
from models.enums import UserRole, VpnKeyStatus, VpnKeyType
from repositories.users import UserRepository
from repositories.announcements import AnnouncementRepository
from repositories.vpn_keys import VpnKeyRepository
from services.announcements import AnnouncementService
from services.awg import AwgService
from services.errors import AccessDenied, InvalidOperation, NotFound
from services.xray import XrayService


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        bot_token="token",
        admin_ids=frozenset({1}),
        db_path=tmp_path / "vpn.db",
        log_dir=tmp_path / "logs",
        bot_lock_path=tmp_path / "vpn.lock",
        bot_drop_pending_updates=False,
        xray_config_path=tmp_path / "xray.json",
        xray_service_name="xray",
        xray_apply_mode="reload",
        xray_inbound_tag="",
        xray_public_host="vpn.example.com",
        xray_public_port=443,
        xray_reality_public_key="public",
        xray_sni="example.com",
        xray_flow="xtls-rprx-vision",
        xray_fingerprint="chrome",
        xray_network_type="tcp",
        xray_short_id="abcd",
        xray_manage_short_ids=False,
        xray_allow_restart_on_rollback=False,
        xray_stats_server="",
        awg_config_path=tmp_path / "awg.conf",
        awg_interface="awg0",
        awg_network="10.0.0.0/24",
        awg_server_address="10.0.0.1",
        awg_endpoint_host="vpn.example.com",
        awg_endpoint_port=443,
        awg_server_public_key="server-public",
        awg_client_dns="1.1.1.1",
        awg_mtu=None,
        awg_allowed_ips="0.0.0.0/0, ::/0",
        awg_persistent_keepalive=25,
        awg_use_preshared_key=True,
        default_proxy_type="",
        default_proxy_host="",
        default_proxy_port=None,
        default_proxy_login="",
        default_proxy_password="",
        default_proxy_note="",
        audit_retention_days=180,
        config_backup_keep_last=20,
    )


def _key(key_type: VpnKeyType, status: VpnKeyStatus = VpnKeyStatus.ACTIVE) -> VpnKey:
    return VpnKey(
        id=10,
        owner_user_id=100,
        username="user",
        key_type=key_type,
        status=status,
        note=None,
        uuid="00000000-0000-4000-8000-000000000000" if key_type == VpnKeyType.XRAY else None,
        email_label="label",
        public_key="public" if key_type == VpnKeyType.AWG else None,
        client_ip="10.0.0.2" if key_type == VpnKeyType.AWG else None,
        payload={},
        public_payload={},
        created_at="now",
        updated_at="now",
        revoked_at=None,
        deleted_at=None,
        created_by=100,
        revoked_by=None,
        deleted_by=None,
    )


class MemoryKeyRepo:
    def __init__(self, key: VpnKey) -> None:
        self.key: VpnKey | None = key
        self.hard_deleted = False

    async def get_by_id(self, key_id: int) -> VpnKey | None:
        return self.key if self.key is not None and key_id == self.key.id else None

    async def set_status(self, key_id: int, status: VpnKeyStatus, now: str) -> None:
        if self.key is not None:
            self.key = replace(self.key, status=status, updated_at=now)

    async def mark_revoked(self, key_id: int, actor_user_id: int, now: str) -> None:
        if self.key is not None:
            self.key = replace(self.key, status=VpnKeyStatus.REVOKED, revoked_at=now, revoked_by=actor_user_id)

    async def hard_delete_with_stats(self, key_id: int) -> None:
        self.hard_deleted = True
        self.key = None


class Users:
    async def require_approved_or_admin(self, actor_user_id: int) -> User:
        return User(actor_user_id, "user", "User", UserRole.APPROVED_USER, "now", "now", None)

    async def require_superadmin(self, actor_user_id: int) -> User:
        return User(actor_user_id, "admin", "Admin", UserRole.SUPERADMIN, "now", "now", None)


class SuperadminOnlyUsers:
    async def require_superadmin(self, actor_user_id: int) -> User:
        if actor_user_id != 1:
            raise AccessDenied("Недостаточно прав")
        return User(actor_user_id, "admin", "Admin", UserRole.SUPERADMIN, "now", "now", None)


class Audit:
    def __init__(self) -> None:
        self.actions: list[str] = []

    async def write(self, *, action: str, **kwargs: object) -> None:
        self.actions.append(action)


class FailingAudit(Audit):
    async def write(self, *, action: str, **kwargs: object) -> None:
        self.actions.append(action)
        raise RuntimeError("audit failed")


class XrayAdapter:
    def __init__(self, fail: bool = False) -> None:
        self.fail = fail
        self.removed = False
        self.remove_calls = 0

    async def remove_client(self, **kwargs: object) -> None:
        self.removed = True
        self.remove_calls += 1
        if self.fail:
            raise RuntimeError("remove failed")


class AwgAdapter:
    def __init__(self, fail: bool = False) -> None:
        self.fail = fail
        self.removed = False
        self.remove_calls = 0

    async def remove_peer(self, **kwargs: object) -> None:
        self.removed = True
        self.remove_calls += 1
        if self.fail:
            raise RuntimeError("remove failed")


def test_xray_create_succeeds_when_post_apply_audit_fails(tmp_path: Path) -> None:
    class Adapter:
        async def add_client(self, **kwargs: object) -> None:
            return None

    class Ids:
        def uuid4(self) -> str:
            return "00000000-0000-4000-8000-000000000001"

        def generated_key_name(self, prefix: str) -> str:
            return f"{prefix}_Ab3dE"

    async def run() -> None:
        db = Database(tmp_path / "vpn.db")
        await db.connect()
        try:
            await db.bootstrap()
            await UserRepository(db).upsert_profile(TelegramUserProfile(100, "user", "User"), UserRole.APPROVED_USER, "now")
            repo = VpnKeyRepository(db)
            audit = FailingAudit()
            service = XrayService(
                vpn_keys=repo,
                users=Users(),  # type: ignore[arg-type]
                adapter=Adapter(),  # type: ignore[arg-type]
                settings=_settings(tmp_path),
                clock=ClockProvider(),
                ids=Ids(),  # type: ignore[arg-type]
                audit=audit,  # type: ignore[arg-type]
            )

            result = await service.create_xray_key(100, TelegramUserProfile(100, "user", "User"), None)

            assert result.key.status == VpnKeyStatus.ACTIVE
            assert audit.actions == ["xray_key_created"]
        finally:
            await db.close()

    asyncio.run(run())


def test_awg_create_succeeds_when_post_apply_audit_fails(tmp_path: Path) -> None:
    class Adapter:
        def read_server_config(self) -> SimpleNamespace:
            return SimpleNamespace(listen_port=443, public_key="server-public", interface_options={})

        def client_interface_options(self) -> dict[str, str]:
            return {}

        async def generate_private_key(self) -> str:
            return "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="

        async def generate_public_key(self, private_key: str) -> str:
            return "public"

        async def generate_preshared_key(self) -> str:
            return "psk"

        async def add_peer(self, **kwargs: object) -> None:
            return None

    class Allocator:
        async def next_free_ip(self) -> str:
            return "10.0.0.2"

    class Ids:
        def generated_key_name(self, prefix: str) -> str:
            return f"{prefix}_Ab3dE"

    async def run() -> None:
        db = Database(tmp_path / "vpn.db")
        await db.connect()
        try:
            await db.bootstrap()
            await UserRepository(db).upsert_profile(TelegramUserProfile(100, "user", "User"), UserRole.APPROVED_USER, "now")
            repo = VpnKeyRepository(db)
            audit = FailingAudit()
            service = AwgService(
                vpn_keys=repo,
                users=Users(),  # type: ignore[arg-type]
                adapter=Adapter(),  # type: ignore[arg-type]
                ip_allocator=Allocator(),  # type: ignore[arg-type]
                settings=_settings(tmp_path),
                clock=ClockProvider(),
                ids=Ids(),  # type: ignore[arg-type]
                audit=audit,  # type: ignore[arg-type]
            )

            result = await service.create_awg_key(100, TelegramUserProfile(100, "user", "User"), None)

            assert result.key.status == VpnKeyStatus.ACTIVE
            assert audit.actions == ["awg_key_created"]
        finally:
            await db.close()

    asyncio.run(run())


def test_hard_delete_with_stats_removes_key_and_stats(tmp_path: Path) -> None:
    async def run() -> None:
        db = Database(tmp_path / "vpn.db")
        await db.connect()
        try:
            await db.bootstrap()
            users = UserRepository(db)
            await users.upsert_profile(TelegramUserProfile(100, "user", "User"), UserRole.APPROVED_USER, "now")
            repo = VpnKeyRepository(db)
            key = await repo.create_pending(
                owner_user_id=100,
                username="user",
                key_type=VpnKeyType.XRAY,
                note=None,
                payload={},
                public_payload={},
                created_by=100,
                now="now",
                uuid="00000000-0000-4000-8000-000000000000",
                email_label="label",
            )
            await db.conn.execute(
                """
                INSERT INTO vpn_key_traffic_stats (key_id, downloaded_bytes, uploaded_bytes)
                VALUES (?, 123, 45)
                """,
                (key.id,),
            )
            await db.commit()

            await repo.hard_delete_with_stats(key.id)

            assert await repo.get_by_id(key.id) is None
            cursor = await db.conn.execute("SELECT COUNT(*) AS cnt FROM vpn_key_traffic_stats WHERE key_id = ?", (key.id,))
            row = await cursor.fetchone()
            assert row["cnt"] == 0
        finally:
            await db.close()

    asyncio.run(run())


@pytest.mark.parametrize("key_type", [VpnKeyType.XRAY, VpnKeyType.AWG])
def test_hard_delete_active_key_removes_server_access(key_type: VpnKeyType, tmp_path: Path) -> None:
    async def run() -> None:
        repo = MemoryKeyRepo(_key(key_type))
        audit = Audit()
        if key_type == VpnKeyType.XRAY:
            adapter = XrayAdapter()
            service = XrayService(
                vpn_keys=repo,  # type: ignore[arg-type]
                users=Users(),  # type: ignore[arg-type]
                adapter=adapter,  # type: ignore[arg-type]
                settings=_settings(tmp_path),
                clock=ClockProvider(),
                ids=object(),  # type: ignore[arg-type]
                audit=audit,  # type: ignore[arg-type]
            )
            await service.delete_xray_key(100, 10)
        else:
            adapter = AwgAdapter()
            service = AwgService(
                vpn_keys=repo,  # type: ignore[arg-type]
                users=Users(),  # type: ignore[arg-type]
                adapter=adapter,  # type: ignore[arg-type]
                ip_allocator=object(),  # type: ignore[arg-type]
                settings=_settings(tmp_path),
                clock=ClockProvider(),
                ids=object(),  # type: ignore[arg-type]
                audit=audit,  # type: ignore[arg-type]
            )
            await service.delete_awg_key(100, 10)

        assert adapter.removed is True
        assert repo.hard_deleted is True
        assert repo.key is None

    asyncio.run(run())


@pytest.mark.parametrize("key_type", [VpnKeyType.XRAY, VpnKeyType.AWG])
def test_hard_delete_apply_failed_key_still_attempts_server_cleanup(key_type: VpnKeyType, tmp_path: Path) -> None:
    async def run() -> None:
        repo = MemoryKeyRepo(_key(key_type, status=VpnKeyStatus.APPLY_FAILED))
        audit = Audit()
        if key_type == VpnKeyType.XRAY:
            adapter = XrayAdapter()
            service = XrayService(
                vpn_keys=repo,  # type: ignore[arg-type]
                users=Users(),  # type: ignore[arg-type]
                adapter=adapter,  # type: ignore[arg-type]
                settings=_settings(tmp_path),
                clock=ClockProvider(),
                ids=object(),  # type: ignore[arg-type]
                audit=audit,  # type: ignore[arg-type]
            )
            await service.delete_xray_key(100, 10)
        else:
            adapter = AwgAdapter()
            service = AwgService(
                vpn_keys=repo,  # type: ignore[arg-type]
                users=Users(),  # type: ignore[arg-type]
                adapter=adapter,  # type: ignore[arg-type]
                ip_allocator=object(),  # type: ignore[arg-type]
                settings=_settings(tmp_path),
                clock=ClockProvider(),
                ids=object(),  # type: ignore[arg-type]
                audit=audit,  # type: ignore[arg-type]
            )
            await service.delete_awg_key(100, 10)

        assert adapter.removed is True
        assert repo.hard_deleted is True
        assert repo.key is None

    asyncio.run(run())


def test_delete_keeps_key_delete_failed_when_server_removal_fails(tmp_path: Path) -> None:
    async def run() -> None:
        repo = MemoryKeyRepo(_key(VpnKeyType.AWG))
        service = AwgService(
            vpn_keys=repo,  # type: ignore[arg-type]
            users=Users(),  # type: ignore[arg-type]
            adapter=AwgAdapter(fail=True),  # type: ignore[arg-type]
            ip_allocator=object(),  # type: ignore[arg-type]
            settings=_settings(tmp_path),
            clock=ClockProvider(),
            ids=object(),  # type: ignore[arg-type]
            audit=Audit(),  # type: ignore[arg-type]
        )

        with pytest.raises(RuntimeError, match="remove failed"):
            await service.delete_awg_key(100, 10)

        assert repo.hard_deleted is False
        assert repo.key is not None
        assert repo.key.status == VpnKeyStatus.DELETE_FAILED

    asyncio.run(run())


def test_awg_delete_failed_and_pending_cleanup_statuses_reserve_ip(tmp_path: Path) -> None:
    async def run() -> None:
        db = Database(tmp_path / "vpn.db")
        await db.connect()
        try:
            users = UserRepository(db)
            await db.bootstrap()
            await users.upsert_profile(TelegramUserProfile(100, "user", "User"), UserRole.APPROVED_USER, "now")
            repo = VpnKeyRepository(db)
            key = await repo.create_pending(
                owner_user_id=100,
                username="user",
                key_type=VpnKeyType.AWG,
                note=None,
                payload={},
                public_payload={},
                created_by=100,
                now="now",
                public_key="delete-failed-public",
                client_ip="10.0.0.2",
            )
            await repo.set_status(key.id, VpnKeyStatus.DELETE_FAILED, "now")
            pending_delete = await repo.create_pending(
                owner_user_id=100,
                username="user",
                key_type=VpnKeyType.AWG,
                note=None,
                payload={},
                public_payload={},
                created_by=100,
                now="now",
                public_key="pending-delete-public",
                client_ip="10.0.0.3",
            )
            await repo.set_status(pending_delete.id, VpnKeyStatus.PENDING_DELETE, "now")
            pending_revoke = await repo.create_pending(
                owner_user_id=100,
                username="user",
                key_type=VpnKeyType.AWG,
                note=None,
                payload={},
                public_payload={},
                created_by=100,
                now="now",
                public_key="pending-revoke-public",
                client_ip="10.0.0.4",
            )
            await repo.set_status(pending_revoke.id, VpnKeyStatus.PENDING_REVOKE, "now")
            apply_failed = await repo.create_pending(
                owner_user_id=100,
                username="user",
                key_type=VpnKeyType.AWG,
                note=None,
                payload={},
                public_payload={},
                created_by=100,
                now="now",
                public_key="apply-failed-public",
                client_ip="10.0.0.5",
            )
            await repo.set_status(apply_failed.id, VpnKeyStatus.APPLY_FAILED, "now")

            occupied = await repo.get_occupied_awg_ips()
            allocator = IpAllocator(repo, "10.0.0.0/29", "10.0.0.1")

            assert {"10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5"}.issubset(occupied)
            assert await allocator.next_free_ip() == "10.0.0.6"
        finally:
            await db.close()

    asyncio.run(run())


def test_awg_apply_failed_ip_is_reusable_after_safe_final_status(tmp_path: Path) -> None:
    async def run() -> None:
        db = Database(tmp_path / "vpn.db")
        await db.connect()
        try:
            await db.bootstrap()
            users = UserRepository(db)
            await users.upsert_profile(TelegramUserProfile(100, "user", "User"), UserRole.APPROVED_USER, "now")
            repo = VpnKeyRepository(db)
            key = await repo.create_pending(
                owner_user_id=100,
                username="user",
                key_type=VpnKeyType.AWG,
                note=None,
                payload={},
                public_payload={},
                created_by=100,
                now="now",
                public_key="public",
                client_ip="10.0.0.2",
            )
            await repo.set_status(key.id, VpnKeyStatus.APPLY_FAILED, "now")
            allocator = IpAllocator(repo, "10.0.0.0/29", "10.0.0.1")

            assert await allocator.next_free_ip() == "10.0.0.3"

            await repo.set_status(key.id, VpnKeyStatus.REVOKED, "now")

            assert await allocator.next_free_ip() == "10.0.0.2"
        finally:
            await db.close()

    asyncio.run(run())


def test_successful_hard_delete_frees_awg_ip_for_reuse(tmp_path: Path) -> None:
    async def run() -> None:
        db = Database(tmp_path / "vpn.db")
        await db.connect()
        try:
            await db.bootstrap()
            users = UserRepository(db)
            await users.upsert_profile(TelegramUserProfile(100, "user", "User"), UserRole.APPROVED_USER, "now")
            repo = VpnKeyRepository(db)
            key = await repo.create_pending(
                owner_user_id=100,
                username="user",
                key_type=VpnKeyType.AWG,
                note=None,
                payload={},
                public_payload={},
                created_by=100,
                now="now",
                public_key="public",
                client_ip="10.0.0.2",
            )
            await repo.set_status(key.id, VpnKeyStatus.ACTIVE, "now")
            await db.conn.execute(
                """
                INSERT INTO vpn_key_traffic_stats (key_id, downloaded_bytes, uploaded_bytes)
                VALUES (?, 123, 45)
                """,
                (key.id,),
            )
            await db.commit()

            assert "10.0.0.2" in await repo.get_occupied_awg_ips()

            await repo.hard_delete_with_stats(key.id)

            assert await repo.get_by_id(key.id) is None
            cursor = await db.conn.execute("SELECT COUNT(*) AS cnt FROM vpn_key_traffic_stats WHERE key_id = ?", (key.id,))
            row = await cursor.fetchone()
            assert row["cnt"] == 0
            assert "10.0.0.2" not in await repo.get_occupied_awg_ips()
            allocator = IpAllocator(repo, "10.0.0.0/29", "10.0.0.1")
            assert await allocator.next_free_ip() == "10.0.0.2"
        finally:
            await db.close()

    asyncio.run(run())


@pytest.mark.parametrize("key_type", [VpnKeyType.XRAY, VpnKeyType.AWG])
def test_delete_succeeds_when_post_hard_delete_audit_fails(key_type: VpnKeyType, tmp_path: Path) -> None:
    async def run() -> None:
        db = Database(tmp_path / "vpn.db")
        await db.connect()
        try:
            users = UserRepository(db)
            await db.bootstrap()
            await users.upsert_profile(TelegramUserProfile(100, "user", "User"), UserRole.APPROVED_USER, "now")
            repo = VpnKeyRepository(db)
            key = await repo.create_pending(
                owner_user_id=100,
                username="user",
                key_type=key_type,
                note=None,
                payload={"short_id_managed": False} if key_type == VpnKeyType.XRAY else {},
                public_payload={},
                created_by=100,
                now="now",
                uuid="00000000-0000-4000-8000-000000000001" if key_type == VpnKeyType.XRAY else None,
                email_label="label",
                public_key="public" if key_type == VpnKeyType.AWG else None,
                client_ip="10.0.0.2" if key_type == VpnKeyType.AWG else None,
            )
            await repo.set_status(key.id, VpnKeyStatus.ACTIVE, "now")
            await db.conn.execute(
                """
                INSERT INTO vpn_key_traffic_stats (key_id, downloaded_bytes, uploaded_bytes)
                VALUES (?, 10, 20)
                """,
                (key.id,),
            )
            await db.commit()
            audit = FailingAudit()
            if key_type == VpnKeyType.XRAY:
                service = XrayService(
                    vpn_keys=repo,
                    users=Users(),  # type: ignore[arg-type]
                    adapter=XrayAdapter(),  # type: ignore[arg-type]
                    settings=_settings(tmp_path),
                    clock=ClockProvider(),
                    ids=object(),  # type: ignore[arg-type]
                    audit=audit,  # type: ignore[arg-type]
                )
                await service.delete_xray_key(100, key.id)
            else:
                service = AwgService(
                    vpn_keys=repo,
                    users=Users(),  # type: ignore[arg-type]
                    adapter=AwgAdapter(),  # type: ignore[arg-type]
                    ip_allocator=object(),  # type: ignore[arg-type]
                    settings=_settings(tmp_path),
                    clock=ClockProvider(),
                    ids=object(),  # type: ignore[arg-type]
                    audit=audit,  # type: ignore[arg-type]
                )
                await service.delete_awg_key(100, key.id)

            assert await repo.get_by_id(key.id) is None
            cursor = await db.conn.execute("SELECT COUNT(*) AS cnt FROM vpn_key_traffic_stats WHERE key_id = ?", (key.id,))
            row = await cursor.fetchone()
            assert row["cnt"] == 0
            assert audit.actions == [f"{key_type.value}_key_hard_deleted"]
        finally:
            await db.close()

    asyncio.run(run())


@pytest.mark.parametrize("key_type", [VpnKeyType.XRAY, VpnKeyType.AWG])
def test_startup_hard_delete_audit_failure_does_not_mark_cleanup_failed(key_type: VpnKeyType, tmp_path: Path) -> None:
    async def run() -> None:
        db = Database(tmp_path / "vpn.db")
        await db.connect()
        try:
            await db.bootstrap()
            users = UserRepository(db)
            await users.upsert_profile(TelegramUserProfile(100, "user", "User"), UserRole.APPROVED_USER, "now")
            repo = VpnKeyRepository(db)
            keys = []
            for index, status in enumerate((VpnKeyStatus.PENDING_DELETE, VpnKeyStatus.DELETE_FAILED), start=1):
                key = await repo.create_pending(
                    owner_user_id=100,
                    username="user",
                    key_type=key_type,
                    note=None,
                    payload={"short_id_managed": False} if key_type == VpnKeyType.XRAY else {},
                    public_payload={},
                    created_by=100,
                    now=f"now-{index}",
                    uuid=f"00000000-0000-4000-8000-00000000000{index}" if key_type == VpnKeyType.XRAY else None,
                    email_label=f"label-{index}",
                    public_key=f"public-{index}" if key_type == VpnKeyType.AWG else None,
                    client_ip=f"10.0.0.{index + 1}" if key_type == VpnKeyType.AWG else None,
                )
                await repo.set_status(key.id, status, f"status-{index}")
                keys.append(key)

            audit = FailingAudit()
            if key_type == VpnKeyType.XRAY:
                adapter = XrayAdapter()
                service = XrayService(
                    vpn_keys=repo,
                    users=Users(),  # type: ignore[arg-type]
                    adapter=adapter,  # type: ignore[arg-type]
                    settings=_settings(tmp_path),
                    clock=ClockProvider(),
                    ids=object(),  # type: ignore[arg-type]
                    audit=audit,  # type: ignore[arg-type]
                )
                summary = await service.startup_reconcile()
                expected_action = "xray_startup_delete_completed"
            else:
                adapter = AwgAdapter()
                service = AwgService(
                    vpn_keys=repo,
                    users=Users(),  # type: ignore[arg-type]
                    adapter=adapter,  # type: ignore[arg-type]
                    ip_allocator=object(),  # type: ignore[arg-type]
                    settings=_settings(tmp_path),
                    clock=ClockProvider(),
                    ids=object(),  # type: ignore[arg-type]
                    audit=audit,  # type: ignore[arg-type]
                )
                summary = await service.startup_reconcile()
                expected_action = "awg_startup_delete_completed"

            assert summary == {"checked": 2, "recovered": 2, "failed": 0}
            assert adapter.remove_calls == 2
            assert audit.actions == [expected_action, expected_action]
            for key in keys:
                assert await repo.get_by_id(key.id) is None
        finally:
            await db.close()

    asyncio.run(run())


def test_revoke_still_leaves_key_revoked_in_db(tmp_path: Path) -> None:
    async def run() -> None:
        repo = MemoryKeyRepo(_key(VpnKeyType.AWG))
        adapter = AwgAdapter()
        service = AwgService(
            vpn_keys=repo,  # type: ignore[arg-type]
            users=Users(),  # type: ignore[arg-type]
            adapter=adapter,  # type: ignore[arg-type]
            ip_allocator=object(),  # type: ignore[arg-type]
            settings=_settings(tmp_path),
            clock=ClockProvider(),
            ids=object(),  # type: ignore[arg-type]
            audit=Audit(),  # type: ignore[arg-type]
        )

        result = await service.revoke_awg_key(100, 10)

        assert adapter.removed is True
        assert repo.hard_deleted is False
        assert result.status == VpnKeyStatus.REVOKED
        assert repo.key is not None
        assert repo.key.status == VpnKeyStatus.REVOKED

    asyncio.run(run())


@pytest.mark.parametrize("key_type", [VpnKeyType.XRAY, VpnKeyType.AWG])
def test_revoke_succeeds_when_post_revoke_audit_fails(key_type: VpnKeyType, tmp_path: Path) -> None:
    async def run() -> None:
        repo = MemoryKeyRepo(_key(key_type))
        audit = FailingAudit()
        if key_type == VpnKeyType.XRAY:
            adapter = XrayAdapter()
            service = XrayService(
                vpn_keys=repo,  # type: ignore[arg-type]
                users=Users(),  # type: ignore[arg-type]
                adapter=adapter,  # type: ignore[arg-type]
                settings=_settings(tmp_path),
                clock=ClockProvider(),
                ids=object(),  # type: ignore[arg-type]
                audit=audit,  # type: ignore[arg-type]
            )
            result = await service.revoke_xray_key(100, 10)
        else:
            adapter = AwgAdapter()
            service = AwgService(
                vpn_keys=repo,  # type: ignore[arg-type]
                users=Users(),  # type: ignore[arg-type]
                adapter=adapter,  # type: ignore[arg-type]
                ip_allocator=object(),  # type: ignore[arg-type]
                settings=_settings(tmp_path),
                clock=ClockProvider(),
                ids=object(),  # type: ignore[arg-type]
                audit=audit,  # type: ignore[arg-type]
            )
            result = await service.revoke_awg_key(100, 10)

        assert adapter.removed is True
        assert result.status == VpnKeyStatus.REVOKED
        assert repo.key is not None
        assert repo.key.status == VpnKeyStatus.REVOKED
        assert audit.actions == [f"{key_type.value}_key_revoked"]

    asyncio.run(run())


def test_keys_list_keyboard_target_page_labels() -> None:
    keyboard = keys_list_keyboard([_key(VpnKeyType.XRAY)], page=1, has_next=True, total_pages=4)
    buttons = [button for row in keyboard.inline_keyboard for button in row]
    by_text = {button.text: button.callback_data for button in buttons}

    assert by_text["Назад 1/4"] == "keys:list:0"
    assert by_text["Далее 3/4"] == "keys:list:2"


def test_announcement_waits_for_confirmation_before_sending() -> None:
    class State:
        def __init__(self) -> None:
            self.data: dict[str, object] = {}
            self.state: object = None

        async def update_data(self, **kwargs: object) -> None:
            self.data.update(kwargs)

        async def set_state(self, state: object) -> None:
            self.state = state

        async def clear(self) -> None:
            self.data.clear()
            self.state = None

    class Announcements:
        def __init__(self) -> None:
            self.send_called = False

        async def count_recipients(self, actor_user_id: int) -> int:
            return 2

        async def send_to_all(self, **kwargs: object) -> None:
            self.send_called = True

    class Message:
        def __init__(self) -> None:
            self.from_user = SimpleNamespace(id=1)
            self.chat = SimpleNamespace(id=1, type=ChatType.PRIVATE)
            self.message_id = 55
            self.answers: list[tuple[str, object]] = []

        async def answer(self, text: str, reply_markup: object = None) -> None:
            self.answers.append((text, reply_markup))

    async def run() -> None:
        state = State()
        announcements = Announcements()
        services = SimpleNamespace(users=Users(), announcements=announcements)
        message = Message()

        await admin_announcement_message(message, state, services)  # type: ignore[arg-type]

        assert announcements.send_called is False
        assert state.data == {"from_chat_id": 1, "message_id": 55}
        assert message.answers
        assert "Получателей среди одобренных пользователей: 2" in message.answers[0][0]

    asyncio.run(run())


def test_regular_user_cannot_start_announcement(monkeypatch: pytest.MonkeyPatch) -> None:
    async def allow_private_callback(callback: object, text: str = "") -> bool:
        return True

    monkeypatch.setattr("bot.handlers.admin.ensure_private_callback", allow_private_callback)

    class Callback:
        def __init__(self) -> None:
            self.from_user = SimpleNamespace(id=2)
            self.message = SimpleNamespace(chat=SimpleNamespace(type=ChatType.PRIVATE), edit_text=self.edit_text)
            self.data = "admin:announce"
            self.answers: list[tuple[str, bool | None]] = []
            self.edits: list[object] = []

        async def answer(self, text: str | None = None, show_alert: bool | None = None, **kwargs: object) -> None:
            self.answers.append((text or "", show_alert))

        async def edit_text(self, text: str, reply_markup: object = None) -> None:
            self.edits.append((text, reply_markup))

    class State:
        async def clear(self) -> None:
            raise AssertionError("state should not be cleared")

        async def set_state(self, state: object) -> None:
            raise AssertionError("state should not be set")

    async def run() -> None:
        callback = Callback()
        services = SimpleNamespace(users=SuperadminOnlyUsers())

        await admin_announcement_start(callback, State(), services)  # type: ignore[arg-type]

        assert callback.edits == []
        assert callback.answers[-1] == ("Недостаточно прав", True)

    asyncio.run(run())


def test_create_key_confirm_keeps_fsm_data_when_rate_limited(monkeypatch: pytest.MonkeyPatch) -> None:
    async def allow_private_callback(callback: object) -> bool:
        return True

    edits: list[tuple[str, object]] = []

    async def fake_edit(message: object, text: str, reply_markup: object = None, **kwargs: object) -> None:
        edits.append((text, reply_markup))

    monkeypatch.setattr("bot.handlers.keys.ensure_private_callback", allow_private_callback)
    monkeypatch.setattr("bot.handlers.keys.safe_edit_message_text", fake_edit)

    class State:
        def __init__(self) -> None:
            self.current_state = CreateKeyStates.confirming
            self.data = {"key_type": VpnKeyType.XRAY.value, "note": "work laptop"}

        async def get_data(self) -> dict[str, object]:
            return dict(self.data)

        async def clear(self) -> None:
            self.current_state = None
            self.data.clear()

    class Callback:
        def __init__(self) -> None:
            self.from_user = SimpleNamespace(id=100, username="user", first_name="User")
            self.message = SimpleNamespace()
            self.data = "create:confirm"
            self.answers: list[tuple[str, bool | None]] = []

        async def answer(self, text: str | None = None, show_alert: bool | None = None, **kwargs: object) -> None:
            self.answers.append((text or "", show_alert))

    class RateLimiter:
        def __init__(self) -> None:
            self.calls = 0

        def check(self, user_id: int, action: str, cooldown_seconds: float) -> None:
            self.calls += 1
            if self.calls == 1:
                raise RateLimitExceeded(7)

    class Xray:
        def __init__(self) -> None:
            self.created_notes: list[str | None] = []

        async def create_xray_key(self, user_id: int, profile: TelegramUserProfile, note: str | None) -> SimpleNamespace:
            self.created_notes.append(note)
            return SimpleNamespace(key=_key(VpnKeyType.XRAY), config_text="xray config")

    class Users:
        async def require_approved_or_admin(self, user_id: int) -> User:
            return User(
                telegram_user_id=user_id,
                username="user",
                first_name="User",
                role=UserRole.APPROVED_USER,
                created_at="2026-01-01T00:00:00+00:00",
                updated_at="2026-01-01T00:00:00+00:00",
                blocked_at=None,
            )

    async def run() -> None:
        state = State()
        callback = Callback()
        rate_limiter = RateLimiter()
        xray = Xray()
        services = SimpleNamespace(users=Users(), xray=xray, awg=SimpleNamespace())

        await create_key_confirm(callback, state, services, rate_limiter)  # type: ignore[arg-type]

        assert state.current_state == CreateKeyStates.confirming
        assert state.data == {"key_type": VpnKeyType.XRAY.value, "note": "work laptop"}
        assert callback.answers == [("Слишком часто. Повторите через 7 сек.", True)]
        assert xray.created_notes == []
        assert edits == []

        await create_key_confirm(callback, state, services, rate_limiter)  # type: ignore[arg-type]

        assert state.current_state is None
        assert state.data == {}
        assert callback.answers[-1] == ("Создаю ключ...", None)
        assert xray.created_notes == ["work laptop"]
        assert edits and edits[-1][0] == "xray config"

    asyncio.run(run())


def test_admin_issue_confirm_validates_owner_before_rate_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    async def allow_private_callback(callback: object, text: str = "") -> bool:
        return True

    monkeypatch.setattr("bot.handlers.admin.ensure_private_callback", allow_private_callback)

    class State:
        def __init__(self) -> None:
            self.current_state = AdminCreateKeyStates.confirming
            self.data = {"owner_user_id": 404, "key_type": VpnKeyType.XRAY.value, "note": "admin note"}

        async def get_data(self) -> dict[str, object]:
            return dict(self.data)

        async def clear(self) -> None:
            self.current_state = None
            self.data.clear()

    class Callback:
        def __init__(self) -> None:
            self.from_user = SimpleNamespace(id=1, username="admin", first_name="Admin")
            self.message = SimpleNamespace()
            self.data = "admin:cconfirm"
            self.answers: list[tuple[str, bool | None]] = []

        async def answer(self, text: str | None = None, show_alert: bool | None = None, **kwargs: object) -> None:
            self.answers.append((text or "", show_alert))

    class Users:
        async def get_user(self, telegram_user_id: int) -> User:
            raise NotFound("Пользователь не найден")

    class RateLimiter:
        def check(self, user_id: int, action: str, cooldown_seconds: float) -> None:
            raise AssertionError("rate limiter should not run before owner validation")

    async def run() -> None:
        state = State()
        callback = Callback()
        services = SimpleNamespace(users=Users(), xray=SimpleNamespace(), awg=SimpleNamespace())

        await admin_issue_confirm(callback, state, services, RateLimiter())  # type: ignore[arg-type]

        assert state.current_state == AdminCreateKeyStates.confirming
        assert state.data == {"owner_user_id": 404, "key_type": VpnKeyType.XRAY.value, "note": "admin note"}
        assert callback.answers == [("Пользователь не найден", True)]

    asyncio.run(run())


def test_admin_issue_confirm_keeps_fsm_data_when_rate_limited_after_owner_validation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def allow_private_callback(callback: object, text: str = "") -> bool:
        return True

    monkeypatch.setattr("bot.handlers.admin.ensure_private_callback", allow_private_callback)

    class State:
        def __init__(self) -> None:
            self.current_state = AdminCreateKeyStates.confirming
            self.data = {"owner_user_id": 200, "key_type": VpnKeyType.XRAY.value, "note": "admin note"}

        async def get_data(self) -> dict[str, object]:
            return dict(self.data)

        async def clear(self) -> None:
            self.current_state = None
            self.data.clear()

    class Callback:
        def __init__(self) -> None:
            self.from_user = SimpleNamespace(id=1, username="admin", first_name="Admin")
            self.message = SimpleNamespace()
            self.data = "admin:cconfirm"
            self.answers: list[tuple[str, bool | None]] = []

        async def answer(self, text: str | None = None, show_alert: bool | None = None, **kwargs: object) -> None:
            self.answers.append((text or "", show_alert))

    class Users:
        def __init__(self) -> None:
            self.calls = 0

        async def get_user(self, telegram_user_id: int) -> User:
            self.calls += 1
            return User(
                telegram_user_id=telegram_user_id,
                username="target",
                first_name="Target",
                role=UserRole.APPROVED_USER,
                created_at="2026-01-01T00:00:00+00:00",
                updated_at="2026-01-01T00:00:00+00:00",
                blocked_at=None,
            )

        async def require_superadmin(self, telegram_user_id: int) -> User:
            return User(
                telegram_user_id=telegram_user_id,
                username="admin",
                first_name="Admin",
                role=UserRole.SUPERADMIN,
                created_at="2026-01-01T00:00:00+00:00",
                updated_at="2026-01-01T00:00:00+00:00",
                blocked_at=None,
            )

        async def require_approved_or_admin(self, telegram_user_id: int) -> User:
            return await self.get_user(telegram_user_id)

    class RateLimiter:
        def __init__(self) -> None:
            self.calls = 0

        def check(self, user_id: int, action: str, cooldown_seconds: float) -> None:
            self.calls += 1
            raise RateLimitExceeded(9)

    class Xray:
        async def create_xray_key(self, user_id: int, profile: TelegramUserProfile, note: str | None) -> SimpleNamespace:
            raise AssertionError("key should not be created while rate limited")

    async def run() -> None:
        state = State()
        callback = Callback()
        users = Users()
        rate_limiter = RateLimiter()
        services = SimpleNamespace(users=users, xray=Xray(), awg=SimpleNamespace())

        await admin_issue_confirm(callback, state, services, rate_limiter)  # type: ignore[arg-type]

        assert users.calls == 2
        assert rate_limiter.calls == 1
        assert state.current_state == AdminCreateKeyStates.confirming
        assert state.data == {"owner_user_id": 200, "key_type": VpnKeyType.XRAY.value, "note": "admin note"}
        assert callback.answers == [("Слишком часто. Повторите через 9 сек.", True)]

    asyncio.run(run())


def test_announcement_confirm_keeps_fsm_data_when_rate_limited(monkeypatch: pytest.MonkeyPatch) -> None:
    async def allow_private_callback(callback: object, text: str = "") -> bool:
        return True

    monkeypatch.setattr("bot.handlers.admin.ensure_private_callback", allow_private_callback)

    class State:
        def __init__(self) -> None:
            self.current_state = object()
            self.data = {"from_chat_id": 1, "message_id": 77}

        async def get_data(self) -> dict[str, object]:
            return dict(self.data)

        async def clear(self) -> None:
            self.current_state = None
            self.data.clear()

    class Callback:
        def __init__(self) -> None:
            self.from_user = SimpleNamespace(id=1)
            self.message = SimpleNamespace()
            self.answers: list[tuple[str, bool | None]] = []

        async def answer(self, text: str | None = None, show_alert: bool | None = None, **kwargs: object) -> None:
            self.answers.append((text or "", show_alert))

    class RateLimiter:
        def __init__(self) -> None:
            self.calls = 0

        def check(self, user_id: int, action: str, cooldown_seconds: float) -> None:
            self.calls += 1
            if self.calls == 1:
                raise RateLimitExceeded(5)

    class Announcements:
        def __init__(self) -> None:
            self.calls = 0

        async def send_to_all(self, **kwargs: object) -> SimpleNamespace:
            self.calls += 1
            return SimpleNamespace(total=1, success=1, failed=0)

    async def fake_edit(message: object, text: str, reply_markup: object = None, **kwargs: object) -> bool:
        message.text = text
        return True

    monkeypatch.setattr("bot.handlers.admin.safe_edit_message_text", fake_edit)

    async def run() -> None:
        state = State()
        callback = Callback()
        announcements = Announcements()
        rate_limiter = RateLimiter()
        services = SimpleNamespace(users=Users(), announcements=announcements)

        await admin_announcement_send(callback, state, services, object(), rate_limiter)  # type: ignore[arg-type]

        assert state.current_state is not None
        assert state.data == {"from_chat_id": 1, "message_id": 77}
        assert callback.answers == [("Слишком часто. Повторите через 5 сек.", True)]
        assert announcements.calls == 0

        await admin_announcement_send(callback, state, services, object(), rate_limiter)  # type: ignore[arg-type]

        assert state.current_state is None
        assert state.data == {}
        assert announcements.calls == 1
        assert callback.answers[-1] == ("Отправляю...", None)

    asyncio.run(run())


def test_group_chat_announcement_message_does_not_start_or_send() -> None:
    class State:
        async def update_data(self, **kwargs: object) -> None:
            raise AssertionError("state should not be updated")

        async def set_state(self, state: object) -> None:
            raise AssertionError("state should not be set")

        async def clear(self) -> None:
            raise AssertionError("state should not be cleared")

    class Announcements:
        async def count_recipients(self, actor_user_id: int) -> int:
            raise AssertionError("recipients should not be counted")

        async def send_to_all(self, **kwargs: object) -> None:
            raise AssertionError("announcement should not be sent")

    class Message:
        def __init__(self) -> None:
            self.from_user = SimpleNamespace(id=1)
            self.chat = SimpleNamespace(id=-100, type=ChatType.SUPERGROUP)
            self.message_id = 55
            self.answers: list[str] = []

        async def answer(self, text: str, reply_markup: object = None) -> None:
            self.answers.append(text)

    async def run() -> None:
        message = Message()
        services = SimpleNamespace(users=Users(), announcements=Announcements())

        await admin_announcement_message(message, State(), services)  # type: ignore[arg-type]

        assert message.answers == ["Админ-панель доступна только в личном чате с ботом."]

    asyncio.run(run())


def test_announcement_uses_copy_message_without_text_additions(tmp_path: Path) -> None:
    class UsersRepo:
        def __init__(self) -> None:
            self.users = [
                User(1, "admin", "Admin", UserRole.SUPERADMIN, "now", "now", None),
                User(2, "user", "User", UserRole.APPROVED_USER, "now", "now", None),
            ]

        async def count_announcement_recipients(self) -> int:
            raise AssertionError("send_to_all should not count recipients")

        async def list_announcement_recipients_after(self, *, last_seen_id: int | None, limit: int) -> list[User]:
            return [
                user
                for user in self.users
                if last_seen_id is None or user.telegram_user_id > last_seen_id
            ][:limit]

        async def list_announcement_recipients(self, *, limit: int, offset: int) -> list[User]:
            raise AssertionError("send_to_all should not use OFFSET pagination")

    class Bot:
        def __init__(self) -> None:
            self.copies: list[dict[str, int]] = []
            self.sent_messages: list[object] = []

        async def copy_message(self, *, chat_id: int, from_chat_id: int, message_id: int) -> None:
            self.copies.append({"chat_id": chat_id, "from_chat_id": from_chat_id, "message_id": message_id})

        async def send_message(self, *args: object, **kwargs: object) -> None:
            self.sent_messages.append((args, kwargs))

    async def run() -> None:
        service = AnnouncementService(
            users=Users(),  # type: ignore[arg-type]
            users_repo=UsersRepo(),  # type: ignore[arg-type]
            audit=Audit(),  # type: ignore[arg-type]
            delay_seconds=0,
        )
        bot = Bot()

        result = await service.send_to_all(actor_user_id=1, bot=bot, from_chat_id=1, message_id=77)  # type: ignore[arg-type]

        assert result.total == 2
        assert result.success == 2
        assert result.failed == 0
        assert bot.copies == [
            {"chat_id": 1, "from_chat_id": 1, "message_id": 77},
            {"chat_id": 2, "from_chat_id": 1, "message_id": 77},
        ]
        assert bot.sent_messages == []

    asyncio.run(run())


def test_announcement_creates_durable_batch_and_deliveries(tmp_path: Path) -> None:
    class AuditWithClock:
        def __init__(self) -> None:
            self.clock = ClockProvider()
            self.writes: list[dict[str, object]] = []

        async def write(self, **kwargs: object) -> None:
            self.writes.append(kwargs)

    class Bot:
        def __init__(self) -> None:
            self.copied: list[int] = []

        async def copy_message(self, *, chat_id: int, from_chat_id: int, message_id: int) -> None:
            self.copied.append(chat_id)

    async def run() -> None:
        db = Database(tmp_path / "vpn.db")
        await db.connect()
        try:
            await db.bootstrap()
            users_repo = UserRepository(db)
            await users_repo.upsert_profile(TelegramUserProfile(1, "admin", "Admin"), UserRole.SUPERADMIN, "now")
            await users_repo.upsert_profile(TelegramUserProfile(2, "approved", "Approved"), UserRole.APPROVED_USER, "now")
            await users_repo.upsert_profile(TelegramUserProfile(3, "pending", "Pending"), UserRole.PENDING_USER, "now")
            audit = AuditWithClock()
            service = AnnouncementService(
                users=Users(),  # type: ignore[arg-type]
                users_repo=users_repo,
                announcements=AnnouncementRepository(db),
                audit=audit,  # type: ignore[arg-type]
                delay_seconds=0,
            )
            bot = Bot()

            result = await service.send_to_all(actor_user_id=1, bot=bot, from_chat_id=1, message_id=77)  # type: ignore[arg-type]

            assert result.announcement_id is not None
            assert result.total == 2
            assert result.success == 2
            assert result.failed == 0
            assert bot.copied == [1, 2]
            cursor = await db.conn.execute(
                "SELECT status, total_count, success_count FROM announcement_batches WHERE id = ?",
                (result.announcement_id,),
            )
            batch = await cursor.fetchone()
            assert batch is not None
            assert batch["status"] == "completed"
            assert batch["total_count"] == 2
            assert batch["success_count"] == 2
            cursor = await db.conn.execute(
                "SELECT user_id, status FROM announcement_deliveries WHERE announcement_id = ? ORDER BY user_id",
                (result.announcement_id,),
            )
            rows = await cursor.fetchall()
            assert [(row["user_id"], row["status"]) for row in rows] == [(1, "sent"), (2, "sent")]
            assert audit.writes[-1]["details"]["announcement_id"] == result.announcement_id
        finally:
            await db.close()

    asyncio.run(run())


def test_announcement_resume_does_not_duplicate_already_sent_recipients(tmp_path: Path) -> None:
    class AuditWithClock:
        def __init__(self) -> None:
            self.clock = ClockProvider()

        async def write(self, **kwargs: object) -> None:
            return None

    class Bot:
        pass

    async def run() -> None:
        db = Database(tmp_path / "vpn.db")
        await db.connect()
        try:
            await db.bootstrap()
            users_repo = UserRepository(db)
            for user_id in (1, 2, 3):
                await users_repo.upsert_profile(
                    TelegramUserProfile(user_id, f"user{user_id}", f"User {user_id}"),
                    UserRole.SUPERADMIN if user_id == 1 else UserRole.APPROVED_USER,
                    "now",
                )
            service = AnnouncementService(
                users=Users(),  # type: ignore[arg-type]
                users_repo=users_repo,
                announcements=AnnouncementRepository(db),
                audit=AuditWithClock(),  # type: ignore[arg-type]
                delay_seconds=0,
            )
            calls: list[int] = []
            crashed = False

            async def copy_once(_bot: object, target_id: int, from_chat_id: int, message_id: int) -> tuple[bool, str | None]:
                nonlocal crashed
                calls.append(target_id)
                if target_id == 3 and not crashed:
                    crashed = True
                    raise RuntimeError("crash")
                return True, None

            service._copy_message = copy_once  # type: ignore[method-assign]

            with pytest.raises(RuntimeError, match="crash"):
                await service.send_to_all(actor_user_id=1, bot=Bot(), from_chat_id=1, message_id=77)  # type: ignore[arg-type]

            cursor = await db.conn.execute("SELECT id FROM announcement_batches ORDER BY id DESC LIMIT 1")
            row = await cursor.fetchone()
            assert row is not None
            result = await service.resume_batch(actor_user_id=1, bot=Bot(), announcement_id=int(row["id"]))  # type: ignore[arg-type]

            assert result.success == 3
            assert result.failed == 0
            assert calls == [1, 2, 3, 3]
            assert calls.count(1) == 1
            assert calls.count(2) == 1
        finally:
            await db.close()

    asyncio.run(run())


def test_announcement_cancel_sending_stops_before_next_recipient_and_stays_cancelled(tmp_path: Path) -> None:
    class AuditWithClock:
        def __init__(self) -> None:
            self.clock = ClockProvider()

        async def write(self, **kwargs: object) -> None:
            return None

    class Bot:
        pass

    async def run() -> None:
        db = Database(tmp_path / "vpn.db")
        await db.connect()
        try:
            await db.bootstrap()
            users_repo = UserRepository(db)
            for user_id in (1, 2, 3):
                await users_repo.upsert_profile(
                    TelegramUserProfile(user_id, f"user{user_id}", f"User {user_id}"),
                    UserRole.SUPERADMIN if user_id == 1 else UserRole.APPROVED_USER,
                    "now",
                )
            announcements = AnnouncementRepository(db)
            service = AnnouncementService(
                users=Users(),  # type: ignore[arg-type]
                users_repo=users_repo,
                announcements=announcements,
                audit=AuditWithClock(),  # type: ignore[arg-type]
                delay_seconds=0,
            )
            calls: list[int] = []

            async def copy_and_cancel(_bot: object, target_id: int, from_chat_id: int, message_id: int) -> tuple[bool, str | None]:
                calls.append(target_id)
                if len(calls) == 1:
                    cursor = await db.conn.execute("SELECT id FROM announcement_batches ORDER BY id DESC LIMIT 1")
                    row = await cursor.fetchone()
                    assert row is not None
                    await announcements.mark_cancelled(int(row["id"]), "cancelled")
                return True, None

            service._copy_message = copy_and_cancel  # type: ignore[method-assign]

            result = await service.send_to_all(actor_user_id=1, bot=Bot(), from_chat_id=1, message_id=77)  # type: ignore[arg-type]

            assert result.cancelled is True
            assert result.success == 1
            assert result.failed == 0
            assert calls == [1]
            assert result.announcement_id is not None
            batch = await announcements.get_batch(result.announcement_id)
            assert batch is not None
            assert batch.status == "cancelled"
            cursor = await db.conn.execute(
                "SELECT user_id, status FROM announcement_deliveries WHERE announcement_id = ? ORDER BY user_id",
                (result.announcement_id,),
            )
            rows = await cursor.fetchall()
            assert [(row["user_id"], row["status"]) for row in rows] == [(1, "sent"), (2, "pending"), (3, "pending")]
            with pytest.raises(InvalidOperation, match="отменено"):
                await service.resume_batch(actor_user_id=1, bot=Bot(), announcement_id=result.announcement_id)  # type: ignore[arg-type]
            assert await service.list_incomplete_batches(1) == []
        finally:
            await db.close()

    asyncio.run(run())


def test_announcement_resume_rejects_completed_batch(tmp_path: Path) -> None:
    class AuditWithClock:
        def __init__(self) -> None:
            self.clock = ClockProvider()

        async def write(self, **kwargs: object) -> None:
            return None

    class Bot:
        pass

    async def run() -> None:
        db = Database(tmp_path / "vpn.db")
        await db.connect()
        try:
            await db.bootstrap()
            users_repo = UserRepository(db)
            await users_repo.upsert_profile(TelegramUserProfile(1, "admin", "Admin"), UserRole.SUPERADMIN, "now")
            announcements = AnnouncementRepository(db)
            batch = await announcements.create_batch(
                actor_user_id=1,
                from_chat_id=1,
                message_id=77,
                recipient_ids=[1],
                now="now",
            )
            await announcements.set_batch_status(batch.id, "completed", "done", completed=True)
            service = AnnouncementService(
                users=Users(),  # type: ignore[arg-type]
                users_repo=users_repo,
                announcements=announcements,
                audit=AuditWithClock(),  # type: ignore[arg-type]
                delay_seconds=0,
            )

            with pytest.raises(InvalidOperation, match="уже завершено"):
                await service.resume_batch(actor_user_id=1, bot=Bot(), announcement_id=batch.id)  # type: ignore[arg-type]
        finally:
            await db.close()

    asyncio.run(run())


def test_announcement_records_failed_recipient(tmp_path: Path) -> None:
    class AuditWithClock:
        def __init__(self) -> None:
            self.clock = ClockProvider()

        async def write(self, **kwargs: object) -> None:
            return None

    class Bot:
        async def copy_message(self, *, chat_id: int, from_chat_id: int, message_id: int) -> None:
            if chat_id == 2:
                raise RuntimeError("telegram forbidden token=secret")

    async def run() -> None:
        db = Database(tmp_path / "vpn.db")
        await db.connect()
        try:
            await db.bootstrap()
            users_repo = UserRepository(db)
            await users_repo.upsert_profile(TelegramUserProfile(1, "admin", "Admin"), UserRole.SUPERADMIN, "now")
            await users_repo.upsert_profile(TelegramUserProfile(2, "approved", "Approved"), UserRole.APPROVED_USER, "now")
            service = AnnouncementService(
                users=Users(),  # type: ignore[arg-type]
                users_repo=users_repo,
                announcements=AnnouncementRepository(db),
                audit=AuditWithClock(),  # type: ignore[arg-type]
                delay_seconds=0,
            )

            result = await service.send_to_all(actor_user_id=1, bot=Bot(), from_chat_id=1, message_id=77)  # type: ignore[arg-type]

            assert result.success == 1
            assert result.failed == 1
            cursor = await db.conn.execute(
                """
                SELECT status, error_text FROM announcement_deliveries
                WHERE announcement_id = ? AND user_id = 2
                """,
                (result.announcement_id,),
            )
            delivery = await cursor.fetchone()
            assert delivery is not None
            assert delivery["status"] == "failed"
            assert delivery["error_text"] == "RuntimeError"
        finally:
            await db.close()

    asyncio.run(run())


def test_announcement_count_uses_count_query_not_list() -> None:
    class UsersRepo:
        def __init__(self) -> None:
            self.count_called = False

        async def count_announcement_recipients(self) -> int:
            self.count_called = True
            return 3

        async def list_announcement_recipients(self, *, limit: int, offset: int) -> list[User]:
            raise AssertionError("count_recipients should not list recipients")

    async def run() -> None:
        repo = UsersRepo()
        service = AnnouncementService(
            users=Users(),  # type: ignore[arg-type]
            users_repo=repo,  # type: ignore[arg-type]
            audit=Audit(),  # type: ignore[arg-type]
            delay_seconds=0,
        )

        assert await service.count_recipients(1) == 3
        assert repo.count_called is True

    asyncio.run(run())


def test_announcement_batches_and_single_send_failure_does_not_abort() -> None:
    class UsersRepo:
        def __init__(self) -> None:
            self.last_seen_ids: list[int | None] = []
            self.users = [
                User(1, "admin", "Admin", UserRole.SUPERADMIN, "now", "now", None),
                User(2, "bad", "Bad", UserRole.APPROVED_USER, "now", "now", None),
                User(3, "pending", "Pending", UserRole.PENDING_USER, "now", "now", None),
                User(4, "ok", "Ok", UserRole.APPROVED_USER, "now", "now", None),
                User(5, "ok2", "Ok2", UserRole.APPROVED_USER, "now", "now", None),
            ]

        async def count_announcement_recipients(self) -> int:
            return len(self.users)

        async def list_announcement_recipients_after(self, *, last_seen_id: int | None, limit: int) -> list[User]:
            self.last_seen_ids.append(last_seen_id)
            return [
                user
                for user in self.users
                if last_seen_id is None or user.telegram_user_id > last_seen_id
            ][:limit]

        async def list_announcement_recipients(self, *, limit: int, offset: int) -> list[User]:
            raise AssertionError("send_to_all should not use OFFSET pagination")

    class Bot:
        def __init__(self) -> None:
            self.copied: list[int] = []

        async def copy_message(self, *, chat_id: int, from_chat_id: int, message_id: int) -> None:
            if chat_id == 2:
                raise RuntimeError("blocked")
            self.copied.append(chat_id)

    async def run() -> None:
        repo = UsersRepo()
        service = AnnouncementService(
            users=Users(),  # type: ignore[arg-type]
            users_repo=repo,  # type: ignore[arg-type]
            audit=Audit(),  # type: ignore[arg-type]
            delay_seconds=0,
            batch_size=2,
        )
        bot = Bot()

        result = await service.send_to_all(actor_user_id=1, bot=bot, from_chat_id=1, message_id=77)  # type: ignore[arg-type]

        assert result.total == 5
        assert result.success == 4
        assert result.failed == 1
        assert result.last_seen_id == 5
        assert result.delivered_user_ids == (1, 3, 4, 5)
        assert result.failed_user_ids == (2,)
        assert result.skipped_user_ids == ()
        assert repo.last_seen_ids == [None, 2, 4, 5]
        assert bot.copied == [1, 3, 4, 5]

    asyncio.run(run())


def test_announcement_keyset_pagination_does_not_duplicate_when_lower_ids_change_between_batches() -> None:
    class UsersRepo:
        def __init__(self) -> None:
            self.last_seen_ids: list[int | None] = []
            self.users = [
                User(10, "u10", "User 10", UserRole.APPROVED_USER, "now", "now", None),
                User(20, "u20", "User 20", UserRole.APPROVED_USER, "now", "now", None),
                User(30, "u30", "User 30", UserRole.APPROVED_USER, "now", "now", None),
                User(40, "u40", "User 40", UserRole.APPROVED_USER, "now", "now", None),
            ]

        async def count_announcement_recipients(self) -> int:
            return len(self.users)

        async def list_announcement_recipients_after(self, *, last_seen_id: int | None, limit: int) -> list[User]:
            self.last_seen_ids.append(last_seen_id)
            result = [
                user
                for user in sorted(self.users, key=lambda item: item.telegram_user_id)
                if last_seen_id is None or user.telegram_user_id > last_seen_id
            ][:limit]
            if last_seen_id is None:
                self.users = [
                    User(15, "new", "New", UserRole.APPROVED_USER, "now", "now", None),
                    User(20, "u20", "User 20", UserRole.APPROVED_USER, "now", "now", None),
                    User(30, "u30", "User 30", UserRole.APPROVED_USER, "now", "now", None),
                    User(40, "u40", "User 40", UserRole.APPROVED_USER, "now", "now", None),
                ]
            return result

        async def list_announcement_recipients(self, *, limit: int, offset: int) -> list[User]:
            raise AssertionError("send_to_all should not use OFFSET pagination")

    class Bot:
        def __init__(self) -> None:
            self.copied: list[int] = []

        async def copy_message(self, *, chat_id: int, from_chat_id: int, message_id: int) -> None:
            self.copied.append(chat_id)

    async def run() -> None:
        repo = UsersRepo()
        service = AnnouncementService(
            users=Users(),  # type: ignore[arg-type]
            users_repo=repo,  # type: ignore[arg-type]
            audit=Audit(),  # type: ignore[arg-type]
            delay_seconds=0,
            batch_size=2,
        )
        bot = Bot()

        result = await service.send_to_all(actor_user_id=1, bot=bot, from_chat_id=1, message_id=77)  # type: ignore[arg-type]

        assert repo.last_seen_ids == [None, 20, 40]
        assert bot.copied == [10, 20, 30, 40]
        assert len(bot.copied) == len(set(bot.copied))
        assert result.total == 4
        assert result.success == 4
        assert result.failed == 0

    asyncio.run(run())
