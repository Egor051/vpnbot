
import asyncio
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest
from aiogram.enums import ChatType
from aiogram.types import CallbackQuery, Chat, Message, User as TgUser

from adapters.clock import ClockProvider
from bot.handlers.callbacks import cancel_callback
from bot.handlers.common import help_command, menu_callback, menu_command
from bot.handlers.keys import create_key_choose, create_key_confirm, show_key_config
from bot.handlers.proxy import proxy_get_prompt
from bot.handlers.start import start_command
from bot.middlewares.access import BlockedUserMiddleware
from config.settings import Settings
from i18n import t
from db.database import Database
from models.dto import TelegramUserProfile, User, VpnKey
from models.enums import AccessRequestStatus, AuditEntityType, UserRole, VpnKeyStatus, VpnKeyType
from repositories.access_requests import AccessRequestRepository
from repositories.audit_log import AuditLogRepository
from repositories.users import UserRepository
from repositories.vpn_keys import VpnKeyRepository
from services.access_approval import AccessApprovalService
from services.audit import AuditService
from services.errors import AccessDenied, InvalidOperation, NotFound
from services.users import UserService


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
        socks5_enabled=True,
        socks5_host="127.0.0.1",
        socks5_port=1080,
        mtproto_enabled=True,
        mtproto_host="127.0.0.1",
        mtproto_secret="0123456789abcdef0123456789abcdef",
    )


class _State:
    def __init__(self, data: dict[str, object] | None = None) -> None:
        self.data = data or {}
        self.state: object | None = None
        self.cleared = False

    async def get_data(self) -> dict[str, object]:
        return dict(self.data)

    async def set_state(self, state: object) -> None:
        self.state = state

    async def update_data(self, **kwargs: object) -> None:
        self.data.update(kwargs)

    async def clear(self) -> None:
        self.cleared = True
        self.data.clear()
        self.state = None


class _Callback:
    def __init__(self, data: str, user_id: int = 100) -> None:
        self.from_user = SimpleNamespace(id=user_id, username="user", first_name="User")
        self.message = SimpleNamespace(edits=[])
        self.data = data
        self.answers: list[tuple[str, bool | None]] = []

    async def answer(self, text: str | None = None, show_alert: bool | None = None, **kwargs: object) -> None:
        self.answers.append((text or "", show_alert))


class _RateLimiter:
    def __init__(self) -> None:
        self.calls = 0

    def check(self, *args: object) -> None:
        self.calls += 1


def _active_key(key_id: int = 10, owner_user_id: int = 100, status: VpnKeyStatus = VpnKeyStatus.ACTIVE) -> VpnKey:
    return VpnKey(
        id=key_id,
        owner_user_id=owner_user_id,
        username="user",
        key_type=VpnKeyType.XRAY,
        status=status,
        note=None,
        uuid="00000000-0000-4000-8000-000000000010",
        email_label="xray_10",
        public_key=None,
        client_ip=None,
        payload={"short_id_managed": False},
        public_payload={},
        created_at="now",
        updated_at="now",
        revoked_at=None,
        deleted_at=None,
        created_by=owner_user_id,
        revoked_by=None,
        deleted_by=None,
    )


async def _allow_private(*args: object, **kwargs: object) -> bool:
    return True


def test_start_in_group_does_not_create_user_request_or_notify_admins() -> None:
    class MessageStub:
        def __init__(self) -> None:
            self.from_user = SimpleNamespace(id=200, username="groupuser", first_name="Group")
            self.chat = SimpleNamespace(id=-100, type=ChatType.SUPERGROUP)
            self.answers: list[str] = []

        async def answer(self, text: str, **kwargs: object) -> None:
            self.answers.append(text)

    class Access:
        async def create_or_get_request(self, profile: object) -> object:
            raise AssertionError("group /start must not touch access requests")

    class Bot:
        async def send_message(self, *args: object, **kwargs: object) -> None:
            raise AssertionError("group /start must not notify admins")

    async def run() -> None:
        message = MessageStub()
        await start_command(message, SimpleNamespace(access=Access()), Bot())  # type: ignore[arg-type]
        assert len(message.answers) == 1
        assert "личном чате" in message.answers[0]

    asyncio.run(run())


def test_common_group_messages_do_not_mutate_state_or_call_services() -> None:
    class MessageStub:
        def __init__(self, text: str) -> None:
            self.from_user = SimpleNamespace(id=200, username="user", first_name="User")
            self.chat = SimpleNamespace(id=-100, type=ChatType.GROUP)
            self.text = text
            self.answers: list[str] = []

        async def answer(self, text: str, **kwargs: object) -> None:
            self.answers.append(text)

    class State:
        async def clear(self) -> None:
            raise AssertionError("group /cancel must not clear FSM state")

    class Users:
        async def require_approved_or_admin(self, user_id: int) -> User:
            raise AssertionError("group /menu must not query RBAC")

    async def run() -> None:
        help_message = MessageStub("/help")
        await help_command(help_message, SimpleNamespace())  # type: ignore[arg-type]

        menu_message = MessageStub("/menu")
        await menu_command(menu_message, SimpleNamespace(users=Users()))  # type: ignore[arg-type]

        cancel_message = MessageStub("/cancel")
        await cancel_callback(SimpleNamespace(message=cancel_message, answer=cancel_message.answer), State())  # type: ignore[arg-type]

        assert help_message.answers and "личном чате" in help_message.answers[0]
        assert menu_message.answers and "личном чате" in menu_message.answers[0]
        assert cancel_message.answers and "личном чате" in cancel_message.answers[0]

    asyncio.run(run())


def test_common_callback_in_group_does_not_render_menu(monkeypatch: pytest.MonkeyPatch) -> None:
    answers: list[tuple[str, bool | None]] = []

    async def fake_answer(self: CallbackQuery, text: str | None = None, show_alert: bool | None = None, **kwargs: object) -> None:
        answers.append((text or "", show_alert))

    async def fail_edit(*args: object, **kwargs: object) -> None:
        raise AssertionError("group callback must not edit a menu into the group")

    monkeypatch.setattr(CallbackQuery, "answer", fake_answer)
    monkeypatch.setattr("bot.handlers.common.safe_edit_message_text", fail_edit)

    async def run() -> None:
        callback = CallbackQuery(
            id="cb",
            from_user=TgUser(id=100, is_bot=False, first_name="User"),
            chat_instance="ci",
            message=Message(message_id=1, date=datetime.now(timezone.utc), chat=Chat(id=-100, type=ChatType.SUPERGROUP)),
            data="menu:main",
        )
        await menu_callback(callback, SimpleNamespace())  # type: ignore[arg-type]
        assert answers == [("Эта операция доступна только в личном чате с ботом.", True)]

    asyncio.run(run())


def test_block_user_sets_blocked_role_and_clears_state_before_revocation(tmp_path: Path) -> None:
    async def run() -> None:
        db = Database(tmp_path / "vpn.db")
        await db.connect()
        try:
            await db.bootstrap()
            settings = _settings(tmp_path)
            users_repo = UserRepository(db)
            keys_repo = VpnKeyRepository(db)
            audit = AuditService(AuditLogRepository(db), ClockProvider())
            await users_repo.upsert_profile(TelegramUserProfile(1, "admin", "Admin"), UserRole.SUPERADMIN, "now")
            await users_repo.upsert_profile(TelegramUserProfile(100, "user", "User"), UserRole.APPROVED_USER, "now")
            key = await keys_repo.create_pending(
                owner_user_id=100,
                username="user",
                key_type=VpnKeyType.XRAY,
                note=None,
                payload={"short_id_managed": False},
                public_payload={},
                created_by=100,
                now="2026-05-08T00:00:00+00:00",
                uuid="00000000-0000-4000-8000-000000000001",
                email_label="xray_block_order",
            )
            await keys_repo.mark_active(key.id, "2026-05-08T00:00:01+00:00")
            service = UserService(users=users_repo, settings=settings, clock=ClockProvider(), audit=audit)
            events: list[str] = []

            async def clear_state(user_id: int) -> None:
                refreshed = await users_repo.get_by_id(user_id)
                assert refreshed is not None and refreshed.role == UserRole.BLOCKED_USER
                events.append("clear_state")

            async def revoke(actor_user_id: int, key_id: int) -> VpnKey:
                refreshed = await users_repo.get_by_id(100)
                assert refreshed is not None and refreshed.role == UserRole.BLOCKED_USER
                events.append("revoke")
                await keys_repo.mark_revoked(key_id, actor_user_id, "2026-05-08T00:00:02+00:00")
                revoked = await keys_repo.get_by_id(key_id)
                assert revoked is not None
                return revoked

            service.attach_state_clearer(clear_state)
            service.attach_key_management(keys_repo, {VpnKeyType.XRAY: revoke})

            result = await service.block_user(1, 100)

            assert result.user.role == UserRole.BLOCKED_USER
            assert events == ["clear_state", "revoke"]
        finally:
            await db.close()

    asyncio.run(run())


def test_backend_revoke_failure_leaves_user_blocked(tmp_path: Path) -> None:
    async def run() -> None:
        db = Database(tmp_path / "vpn.db")
        await db.connect()
        try:
            await db.bootstrap()
            settings = _settings(tmp_path)
            users_repo = UserRepository(db)
            keys_repo = VpnKeyRepository(db)
            audit = AuditService(AuditLogRepository(db), ClockProvider())
            await users_repo.upsert_profile(TelegramUserProfile(1, "admin", "Admin"), UserRole.SUPERADMIN, "now")
            await users_repo.upsert_profile(TelegramUserProfile(100, "user", "User"), UserRole.APPROVED_USER, "now")
            key = await keys_repo.create_pending(
                owner_user_id=100,
                username="user",
                key_type=VpnKeyType.XRAY,
                note=None,
                payload={"short_id_managed": False},
                public_payload={},
                created_by=100,
                now="2026-05-08T00:00:00+00:00",
                uuid="00000000-0000-4000-8000-000000000002",
                email_label="xray_block_failure",
            )
            await keys_repo.mark_active(key.id, "2026-05-08T00:00:01+00:00")
            service = UserService(users=users_repo, settings=settings, clock=ClockProvider(), audit=audit)

            async def revoke(actor_user_id: int, key_id: int) -> VpnKey:
                raise RuntimeError("backend down")

            service.attach_key_management(keys_repo, {VpnKeyType.XRAY: revoke})
            result = await service.block_user(1, 100)
            refreshed = await users_repo.get_by_id(100)

            assert len(result.errors) == 1
            assert refreshed is not None
            assert refreshed.role == UserRole.BLOCKED_USER
            with pytest.raises(AccessDenied):
                await service.require_approved_or_admin(100)
        finally:
            await db.close()

    asyncio.run(run())


def test_blocked_user_cannot_use_approved_message_or_stale_callback(monkeypatch: pytest.MonkeyPatch) -> None:
    message_answers: list[str] = []
    callback_answers: list[tuple[str, bool | None]] = []

    async def fake_message_answer(self: Message, text: str, **kwargs: object) -> None:
        message_answers.append(text)

    async def fake_callback_answer(self: CallbackQuery, text: str | None = None, show_alert: bool | None = None, **kwargs: object) -> None:
        callback_answers.append((text or "", show_alert))

    monkeypatch.setattr(Message, "answer", fake_message_answer)
    monkeypatch.setattr(CallbackQuery, "answer", fake_callback_answer)

    class Users:
        async def get_user(self, telegram_user_id: int) -> User:
            return User(telegram_user_id, "blocked", "Blocked", UserRole.BLOCKED_USER, "now", "now", "now")

    class State:
        def __init__(self) -> None:
            self.cleared = 0

        async def clear(self) -> None:
            self.cleared += 1

    async def run() -> None:
        middleware = BlockedUserMiddleware(Users())  # type: ignore[arg-type]
        user = TgUser(id=100, is_bot=False, first_name="Blocked", username="blocked")
        state = State()
        calls = 0

        async def handler(event: object, data: dict[str, object]) -> None:
            nonlocal calls
            calls += 1

        message = Message(
            message_id=1,
            date=datetime.now(timezone.utc),
            chat=Chat(id=100, type=ChatType.PRIVATE),
            from_user=user,
            text="Создать ключ",
        )
        await middleware(handler, message, {"event_from_user": user, "state": state})

        callback = CallbackQuery(
            id="cb",
            from_user=user,
            chat_instance="ci",
            message=Message(message_id=2, date=datetime.now(timezone.utc), chat=Chat(id=100, type=ChatType.PRIVATE)),
            data="key:show:10",
        )
        await middleware(handler, callback, {"event_from_user": user, "state": state})

        assert calls == 0
        assert state.cleared == 2
        assert message_answers == [t("blocked_message")]
        assert callback_answers == [(t("blocked_callback"), True)]

    asyncio.run(run())


@pytest.mark.parametrize("callback_data", ["keys:create:xray", "keys:create:awg"])
def test_pending_user_cannot_enter_key_create_fsm(callback_data: str, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("bot.handlers.keys.ensure_private_callback", _allow_private)

    class Users:
        async def require_approved_or_admin(self, actor_user_id: int) -> User:
            raise AccessDenied("Доступ не одобрен", key="access_not_approved")

    async def run() -> None:
        state = _State()
        callback = _Callback(callback_data)
        await create_key_choose(callback, state, SimpleNamespace(users=Users()))  # type: ignore[arg-type]
        assert state.state is None
        assert state.data == {}
        assert callback.answers == [("Доступ ещё не одобрен. Дождитесь решения администратора.", True)]

    asyncio.run(run())


@pytest.mark.parametrize("callback_data", ["proxy:get:socks5", "proxy:get:mtproto"])
def test_pending_user_cannot_issue_proxy(callback_data: str, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("bot.handlers.proxy.ensure_private_callback", _allow_private)

    class Proxy:
        async def list_user_accesses(self, actor_user_id: int) -> list[object]:
            raise AccessDenied("Доступ не одобрен", key="access_not_approved")

    async def run() -> None:
        state = _State()
        callback = _Callback(callback_data)
        services = SimpleNamespace(proxy=Proxy(), settings=SimpleNamespace(socks5_enabled=True, mtproto_enabled=True))
        await proxy_get_prompt(callback, state, services)  # type: ignore[arg-type]
        assert state.state is None
        assert callback.answers == [("Доступ ещё не одобрен. Дождитесь решения администратора.", True)]

    asyncio.run(run())


def test_pending_user_cannot_confirm_old_key_create_state(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("bot.handlers.keys.ensure_private_callback", _allow_private)

    class Users:
        async def require_approved_or_admin(self, actor_user_id: int) -> User:
            raise AccessDenied("Доступ не одобрен", key="access_not_approved")

    async def run() -> None:
        state = _State({"key_type": VpnKeyType.XRAY.value, "note": "old"})
        callback = _Callback("create:confirm")
        rate_limiter = _RateLimiter()
        services = SimpleNamespace(users=Users(), xray=SimpleNamespace(), awg=SimpleNamespace())
        await create_key_confirm(callback, state, services, rate_limiter)  # type: ignore[arg-type]
        assert state.cleared is False
        assert state.data == {"key_type": VpnKeyType.XRAY.value, "note": "old"}
        assert rate_limiter.calls == 0
        assert callback.answers == [("Доступ ещё не одобрен. Дождитесь решения администратора.", True)]

    asyncio.run(run())


def test_approval_does_not_demote_superadmin(tmp_path: Path) -> None:
    async def run() -> None:
        db = Database(tmp_path / "vpn.db")
        await db.connect()
        try:
            await db.bootstrap()
            settings = _settings(tmp_path)
            users_repo = UserRepository(db)
            requests_repo = AccessRequestRepository(db)
            audit = AuditService(AuditLogRepository(db), ClockProvider())
            users = UserService(users=users_repo, settings=settings, clock=ClockProvider(), audit=audit)
            await users.bootstrap_admins()
            request = await requests_repo.create(1, "admin", "2026-05-08T00:00:00+00:00")
            service = AccessApprovalService(requests=requests_repo, users=users, clock=ClockProvider(), audit=audit)

            _request, changed = await service.approve(1, request.id)
            refreshed = await users_repo.get_by_id(1)

            assert changed is True
            assert refreshed is not None
            assert refreshed.role == UserRole.SUPERADMIN
        finally:
            await db.close()

    asyncio.run(run())


def test_stale_approval_for_blocked_user_is_rejected_without_role_change(tmp_path: Path) -> None:
    async def run() -> None:
        db = Database(tmp_path / "vpn.db")
        await db.connect()
        try:
            await db.bootstrap()
            settings = _settings(tmp_path)
            users_repo = UserRepository(db)
            requests_repo = AccessRequestRepository(db)
            audit = AuditService(AuditLogRepository(db), ClockProvider())
            users = UserService(users=users_repo, settings=settings, clock=ClockProvider(), audit=audit)
            await users.bootstrap_admins()
            await users_repo.upsert_profile(TelegramUserProfile(100, "user", "User"), UserRole.PENDING_USER, "2026-05-08T00:00:00+00:00")
            request = await requests_repo.create(100, "user", "2026-05-08T00:00:01+00:00")
            await users_repo.set_role(100, UserRole.BLOCKED_USER, "2026-05-08T00:00:02+00:00", blocked_at="2026-05-08T00:00:02+00:00")
            service = AccessApprovalService(requests=requests_repo, users=users, clock=ClockProvider(), audit=audit)

            with pytest.raises(InvalidOperation, match="Сначала разблокируйте"):
                await service.approve(1, request.id)

            refreshed_request = await requests_repo.get_by_id(request.id)
            refreshed_user = await users_repo.get_by_id(100)
            assert refreshed_request is not None
            assert refreshed_request.status == AccessRequestStatus.PENDING
            assert refreshed_user is not None
            assert refreshed_user.role == UserRole.BLOCKED_USER
        finally:
            await db.close()

    asyncio.run(run())


def test_stale_rejection_does_not_demote_approved_user(tmp_path: Path) -> None:
    async def run() -> None:
        db = Database(tmp_path / "vpn.db")
        await db.connect()
        try:
            await db.bootstrap()
            settings = _settings(tmp_path)
            users_repo = UserRepository(db)
            requests_repo = AccessRequestRepository(db)
            audit = AuditService(AuditLogRepository(db), ClockProvider())
            users = UserService(users=users_repo, settings=settings, clock=ClockProvider(), audit=audit)
            await users.bootstrap_admins()
            await users_repo.upsert_profile(TelegramUserProfile(100, "user", "User"), UserRole.APPROVED_USER, "2026-05-08T00:00:00+00:00")
            request = await requests_repo.create(100, "user", "2026-05-08T00:00:01+00:00")
            service = AccessApprovalService(requests=requests_repo, users=users, clock=ClockProvider(), audit=audit)

            _request, changed = await service.reject(1, request.id)
            refreshed = await users_repo.get_by_id(100)

            assert changed is True
            assert refreshed is not None
            assert refreshed.role == UserRole.APPROVED_USER
        finally:
            await db.close()

    asyncio.run(run())


def test_repeated_approval_callback_is_idempotent(tmp_path: Path) -> None:
    async def run() -> None:
        db = Database(tmp_path / "vpn.db")
        await db.connect()
        try:
            await db.bootstrap()
            settings = _settings(tmp_path)
            users_repo = UserRepository(db)
            requests_repo = AccessRequestRepository(db)
            audit = AuditService(AuditLogRepository(db), ClockProvider())
            users = UserService(users=users_repo, settings=settings, clock=ClockProvider(), audit=audit)
            await users.bootstrap_admins()
            await users_repo.upsert_profile(TelegramUserProfile(100, "user", "User"), UserRole.PENDING_USER, "2026-05-08T00:00:00+00:00")
            request = await requests_repo.create(100, "user", "2026-05-08T00:00:01+00:00")
            service = AccessApprovalService(requests=requests_repo, users=users, clock=ClockProvider(), audit=audit)

            first, first_changed = await service.approve(1, request.id)
            second, second_changed = await service.approve(1, request.id)

            assert first.status == AccessRequestStatus.APPROVED
            assert first_changed is True
            assert second.status == AccessRequestStatus.APPROVED
            assert second_changed is False
            assert (await users_repo.get_by_id(100)).role == UserRole.APPROVED_USER  # type: ignore[union-attr]
        finally:
            await db.close()

    asyncio.run(run())


def test_old_key_config_callback_after_revoke_is_safely_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("bot.handlers.keys.ensure_private_callback", _allow_private)

    class VpnKeys:
        async def get_for_actor(self, actor_user_id: int, key_id: int) -> VpnKey:
            return _active_key(key_id, status=VpnKeyStatus.REVOKED)

    class Xray:
        async def get_xray_key_config(self, actor_user_id: int, key_id: int) -> str:
            raise InvalidOperation("Конфигурация доступна только для активного ключа")

    async def run() -> None:
        callback = _Callback("key:show:10")
        await show_key_config(
            callback,
            _State(),
            SimpleNamespace(vpn_keys=VpnKeys(), xray=Xray(), awg=SimpleNamespace()),
            _RateLimiter(),
            None,
        )  # type: ignore[arg-type]
        assert callback.answers == [
            ("", None),
            ("Конфигурация доступна только для активного ключа", True),
        ]

    asyncio.run(run())
