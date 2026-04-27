from __future__ import annotations

import asyncio
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest
from aiogram.enums import ChatType

from adapters.clock import ClockProvider
from bot.handlers.admin import admin_announcement_message
from bot.keyboards.keys import keys_list_keyboard
from config.settings import Settings
from db.database import Database
from models.dto import TelegramUserProfile, User, VpnKey
from models.enums import UserRole, VpnKeyStatus, VpnKeyType
from repositories.users import UserRepository
from repositories.vpn_keys import VpnKeyRepository
from services.announcements import AnnouncementService
from services.awg import AwgService
from services.xray import XrayService


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        bot_token="token",
        admin_ids=frozenset({1}),
        db_path=tmp_path / "vpn.db",
        log_dir=tmp_path / "logs",
        bot_lock_path=tmp_path / "vpn.lock",
        xray_config_path=tmp_path / "xray.json",
        xray_service_name="xray",
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


class Audit:
    def __init__(self) -> None:
        self.actions: list[str] = []

    async def write(self, *, action: str, **kwargs: object) -> None:
        self.actions.append(action)


class XrayAdapter:
    def __init__(self, fail: bool = False) -> None:
        self.fail = fail
        self.removed = False

    async def remove_client(self, **kwargs: object) -> None:
        self.removed = True
        if self.fail:
            raise RuntimeError("remove failed")


class AwgAdapter:
    def __init__(self, fail: bool = False) -> None:
        self.fail = fail
        self.removed = False

    async def remove_peer(self, **kwargs: object) -> None:
        self.removed = True
        if self.fail:
            raise RuntimeError("remove failed")


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
        assert "Получателей: 2" in message.answers[0][0]

    asyncio.run(run())


def test_announcement_uses_copy_message_without_text_additions(tmp_path: Path) -> None:
    class UsersRepo:
        async def list_announcement_recipients(self) -> list[User]:
            return [
                User(1, "admin", "Admin", UserRole.SUPERADMIN, "now", "now", None),
                User(2, "user", "User", UserRole.APPROVED_USER, "now", "now", None),
            ]

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
