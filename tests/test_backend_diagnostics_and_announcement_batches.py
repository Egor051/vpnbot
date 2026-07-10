
import asyncio
from types import SimpleNamespace

import pytest

from adapters.clock import ClockProvider
from bot.formatters import backend_diagnostics_text
from bot.handlers.admin import admin_announcement_batches, admin_backend_diagnostics
from bot.keyboards.keys import key_actions_keyboard, keys_list_keyboard
from db.database import Database
from models.dto import TelegramUserProfile, User, VpnKey
from models.enums import ProxyAccessType, UserRole, VpnKeyStatus, VpnKeyType
from repositories.announcements import AnnouncementBatch, AnnouncementRepository
from repositories.users import UserRepository
from services.announcements import AnnouncementService
from services.backend_health import BackendHealth
from services.errors import AccessDenied
from services.xray import XrayService


def _key(owner_user_id: int = 100) -> VpnKey:
    return VpnKey(
        id=10,
        owner_user_id=owner_user_id,
        username="user",
        key_type=VpnKeyType.XRAY,
        status=VpnKeyStatus.ACTIVE,
        note=None,
        uuid="00000000-0000-4000-8000-000000000000",
        email_label="label",
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


def _callbacks(markup: object) -> list[str | None]:
    return [button.callback_data for row in markup.inline_keyboard for button in row]


class _StrictUsers:
    async def require_approved_or_admin(self, actor_user_id: int) -> User:
        role = UserRole.SUPERADMIN if actor_user_id == 1 else UserRole.APPROVED_USER
        return User(actor_user_id, "user", "User", role, "now", "now", None)

    async def require_superadmin(self, actor_user_id: int) -> User:
        if actor_user_id != 1:
            raise AccessDenied("Недостаточно прав")
        return User(actor_user_id, "admin", "Admin", UserRole.SUPERADMIN, "now", "now", None)


class _Callback:
    def __init__(self, data: str, user_id: int = 1) -> None:
        self.from_user = SimpleNamespace(id=user_id, username="user", first_name="User")
        self.message = _Message()
        self.data = data
        self.answers: list[tuple[str, bool | None]] = []

    async def answer(self, text: str | None = None, show_alert: bool | None = None, **kwargs: object) -> None:
        self.answers.append((text or "", show_alert))


class _Message:
    def __init__(self) -> None:
        self.edits: list[tuple[str, object]] = []

    async def edit_text(self, text: str, reply_markup: object = None) -> None:
        self.edits.append((text, reply_markup))

    async def answer(self, text: str, reply_markup: object = None) -> None:
        self.edits.append((text, reply_markup))


class _AuditWithClock:
    def __init__(self) -> None:
        self.clock = ClockProvider()

    async def write(self, **kwargs: object) -> None:
        return None


def test_regular_key_keyboards_show_revoke_and_delete_actions() -> None:
    callbacks = _callbacks(keys_list_keyboard([_key()]))
    detail_callbacks = _callbacks(key_actions_keyboard(_key()))

    assert "key:show:10" in callbacks
    assert "key:stats:10" in callbacks
    assert "key:note:10" in callbacks
    assert "key:revoke:10" in callbacks
    assert "key:delete:10" in callbacks
    assert "key:revoke:10" in detail_callbacks
    assert "key:delete:10" in detail_callbacks


def test_admin_key_keyboards_keep_revoke_and_delete_actions() -> None:
    callbacks = _callbacks(keys_list_keyboard([_key(owner_user_id=200)], owner_user_id=200))
    detail_callbacks = _callbacks(key_actions_keyboard(_key(owner_user_id=200), owner_user_id=200))

    assert "key:revoke:10:200:0" in callbacks
    assert "key:delete:10:200:0" in callbacks
    assert "key:revoke:10:200:0" in detail_callbacks
    assert "key:delete:10:200:0" in detail_callbacks


def test_user_cannot_revoke_or_delete_another_users_key_service(tmp_path) -> None:
    class Repo:
        async def get_by_id(self, key_id: int) -> VpnKey:
            return _key(owner_user_id=999)  # key belongs to user 999

    service = XrayService(
        vpn_keys=Repo(),  # type: ignore[arg-type]
        users=_StrictUsers(),  # type: ignore[arg-type]
        adapter=object(),  # type: ignore[arg-type]
        settings=object(),  # type: ignore[arg-type]
        clock=ClockProvider(),
        ids=object(),  # type: ignore[arg-type]
        audit=object(),  # type: ignore[arg-type]
    )

    async def run() -> None:
        with pytest.raises(AccessDenied, match="Нельзя управлять чужим ключом"):
            await service.revoke_xray_key(100, 10)  # user 100 tries to manage key owned by 999
        with pytest.raises(AccessDenied, match="Нельзя управлять чужим ключом"):
            await service.delete_xray_key(100, 10)

    asyncio.run(run())


def test_backend_diagnostics_redacts_secret_like_reason() -> None:
    health = BackendHealth()
    raw_secret = "0123456789abcdef0123456789abcdef"
    health.mark_degraded(VpnKeyType.XRAY, f"apply failed token=bot-token secret={raw_secret} password=hunter2")
    health.mark_degraded(ProxyAccessType.MTPROTO, "startup reconciliation failed")

    text = backend_diagnostics_text(health.snapshot(), mtproto_mode="static")

    assert "Xray" in text
    assert "DEGRADED" in text
    assert "MTProto" in text
    assert raw_secret not in text
    assert "bot-token" not in text
    assert "hunter2" not in text
    assert "static/shared" in text


def test_backend_diagnostics_handler_is_admin_only(monkeypatch: pytest.MonkeyPatch) -> None:
    async def allow_private(*args: object, **kwargs: object) -> bool:
        return True

    monkeypatch.setattr("bot.handlers.admin.ensure_private_callback", allow_private)

    async def run() -> None:
        callback = _Callback("admin:diagnostics", user_id=100)
        services = SimpleNamespace(
            users=_StrictUsers(),
            backend_health=BackendHealth(),
            settings=SimpleNamespace(mtproto_mode="managed"),
        )

        await admin_backend_diagnostics(callback, services)  # type: ignore[arg-type]

        assert callback.message.edits == []
        assert callback.answers[-1] == ("Недостаточно прав", True)

    asyncio.run(run())


def test_announcement_incomplete_batches_are_listed_and_cancelled(tmp_path) -> None:
    async def run() -> None:
        db = Database(tmp_path / "vpn.db")
        await db.connect()
        try:
            await db.bootstrap()
            users_repo = UserRepository(db)
            await users_repo.upsert_profile(TelegramUserProfile(1, "admin", "Admin"), UserRole.SUPERADMIN, "now")
            await users_repo.upsert_profile(TelegramUserProfile(2, "user", "User"), UserRole.APPROVED_USER, "now")
            repo = AnnouncementRepository(db)
            batch = await repo.create_batch(
                actor_user_id=1,
                from_chat_id=1,
                message_id=77,
                recipient_ids=[1, 2],
                now="2026-05-08T10:00:00+00:00",
            )
            await repo.mark_delivery(batch.id, 1, "sent", "2026-05-08T10:01:00+00:00")
            await repo.set_batch_status(batch.id, "failed", "2026-05-08T10:02:00+00:00")
            service = AnnouncementService(
                users=_StrictUsers(),  # type: ignore[arg-type]
                users_repo=users_repo,
                announcements=repo,
                audit=_AuditWithClock(),  # type: ignore[arg-type]
                delay_seconds=0,
            )

            batches = await service.list_incomplete_batches(1)
            assert [item.id for item in batches] == [batch.id]
            assert batches[0].success_count == 1

            with pytest.raises(AccessDenied):
                await service.list_incomplete_batches(100)

            result = await service.cancel_batch(actor_user_id=1, announcement_id=batch.id)
            assert result.changed is True
            assert result.batch.status == "cancelled"
            repeat = await service.cancel_batch(actor_user_id=1, announcement_id=batch.id)
            assert repeat.changed is False
            assert repeat.batch.status == "cancelled"
            assert await service.list_incomplete_batches(1) == []
        finally:
            await db.close()

    asyncio.run(run())


def test_admin_announcement_batches_handler_lists_actions(monkeypatch: pytest.MonkeyPatch) -> None:
    async def allow_private(*args: object, **kwargs: object) -> bool:
        return True

    monkeypatch.setattr("bot.handlers.admin.ensure_private_callback", allow_private)

    batch = AnnouncementBatch(
        id=7,
        actor_user_id=1,
        from_chat_id=1,
        message_id=77,
        status="failed",
        total_count=3,
        success_count=1,
        failed_count=1,
        skipped_count=0,
        created_at="2026-05-08T10:00:00+00:00",
        updated_at="2026-05-08T10:02:00+00:00",
        completed_at=None,
    )

    class Announcements:
        async def list_incomplete_batches(self, actor_user_id: int, *, limit: int) -> list[AnnouncementBatch]:
            assert actor_user_id == 1
            assert limit == 10
            return [batch]

    async def run() -> None:
        callback = _Callback("admin:announce_batches", user_id=1)
        services = SimpleNamespace(users=_StrictUsers(), announcements=Announcements())

        await admin_announcement_batches(callback, services)  # type: ignore[arg-type]

        text, markup = callback.message.edits[-1]
        callbacks = _callbacks(markup)
        assert "Незавершённые объявления" in text
        assert "Batch #7" in text
        assert "admin:announce:retry:7" in callbacks
        assert "admin:announce:cancelbatch:7" in callbacks

    asyncio.run(run())
