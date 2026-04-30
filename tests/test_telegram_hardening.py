from __future__ import annotations

import asyncio
from types import SimpleNamespace

from bot.fsm.states import AdminCreateKeyStates, CreateKeyStates
from bot.handlers.admin import admin_issue_type_selected
from bot.handlers.keys import confirm_key_action, create_key_choose, create_key_menu
from bot.handlers.start import start_command
from bot.keyboards.common import main_menu
from bot.keyboards.keys import keys_list_keyboard
from models.dto import User, VpnKey
from models.enums import UserRole, VpnKeyStatus, VpnKeyType
from services.errors import AccessDenied, NotFound


def _key(key_id: int, owner_user_id: int = 200) -> VpnKey:
    return VpnKey(
        id=key_id,
        owner_user_id=owner_user_id,
        username="owner",
        key_type=VpnKeyType.XRAY,
        status=VpnKeyStatus.ACTIVE,
        note=None,
        uuid=f"uuid-{key_id}",
        email_label=f"xray_{key_id:05d}",
        public_key=None,
        client_ip=None,
        payload={},
        public_payload={},
        created_at="now",
        updated_at="now",
        revoked_at=None,
        deleted_at=None,
        created_by=owner_user_id,
        revoked_by=None,
        deleted_by=None,
    )


class _Callback:
    def __init__(self, data: str, user_id: int = 1) -> None:
        self.from_user = SimpleNamespace(id=user_id, username="user", first_name="User")
        self.message = SimpleNamespace()
        self.data = data
        self.answers: list[tuple[str, bool | None]] = []

    async def answer(self, text: str | None = None, show_alert: bool | None = None, **kwargs: object) -> None:
        self.answers.append((text or "", show_alert))


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


async def _allow_private(*args: object, **kwargs: object) -> bool:
    return True


def _main_menu_buttons(is_admin: bool = False) -> list[tuple[str, str | None]]:
    markup = main_menu(is_admin)
    return [(button.text, button.callback_data) for row in markup.inline_keyboard for button in row]


def test_main_menu_regular_user_uses_inline_buttons() -> None:
    assert _main_menu_buttons() == [
        ("Мои ключи", "keys:list"),
        ("Создать ключ", "keys:create"),
        ("Прокси", "proxy:show"),
        ("Помощь", "help"),
    ]


def test_main_menu_admin_has_admin_button_and_complete_create_key_text() -> None:
    buttons = _main_menu_buttons(is_admin=True)

    assert len(buttons) == 5
    assert ("Создать ключ", "keys:create") in buttons
    assert ("Создать клю", "keys:create") not in buttons
    assert buttons[-1] == ("Админ-панель", "admin:panel")


def test_start_command_sends_inline_main_menu_for_approved_users() -> None:
    class Message:
        def __init__(self) -> None:
            self.from_user = SimpleNamespace(id=100, username="user", first_name="User")
            self.answers: list[tuple[str, object]] = []

        async def answer(self, text: str, reply_markup: object = None) -> None:
            self.answers.append((text, reply_markup))

    class Access:
        async def create_or_get_request(self, profile: object) -> SimpleNamespace:
            return SimpleNamespace(
                user=User(100, "user", "User", UserRole.APPROVED_USER, "now", "now", None),
                request=None,
                created=False,
            )

    class Users:
        async def get_user(self, user_id: int) -> User:
            return User(user_id, "user", "User", UserRole.APPROVED_USER, "now", "now", None)

    async def run() -> None:
        message = Message()
        services = SimpleNamespace(access=Access(), users=Users())
        await start_command(message, services, SimpleNamespace())  # type: ignore[arg-type]
        assert len(message.answers) == 1
        markup = message.answers[0][1]
        assert hasattr(markup, "inline_keyboard")
        assert not hasattr(markup, "keyboard")
        assert [(button.text, button.callback_data) for row in markup.inline_keyboard for button in row] == [
            ("Мои ключи", "keys:list"),
            ("Создать ключ", "keys:create"),
            ("Прокси", "proxy:show"),
            ("Помощь", "help"),
        ]

    asyncio.run(run())


def test_admin_issue_type_stale_owner_mismatch_clears_state(monkeypatch) -> None:
    edits: list[str] = []

    async def fake_edit(message: object, text: str, **kwargs: object) -> None:
        edits.append(text)

    monkeypatch.setattr("bot.handlers.admin.ensure_private_callback", _allow_private)
    monkeypatch.setattr("bot.handlers.admin.safe_edit_message_text", fake_edit)

    class Users:
        async def require_superadmin(self, telegram_user_id: int) -> User:
            return User(telegram_user_id, "admin", "Admin", UserRole.SUPERADMIN, "now", "now", None)

    async def run() -> None:
        state = _State({"owner_user_id": 200})
        callback = _Callback("admin:ctype:xray:201")
        await admin_issue_type_selected(callback, state, SimpleNamespace(users=Users()))  # type: ignore[arg-type]

        assert state.cleared is True
        assert callback.answers == [("Действие устарело, начните выдачу заново", True)]
        assert edits == ["Действие устарело, начните выдачу заново."]

    asyncio.run(run())


def test_admin_issue_type_matching_owner_enters_note_state(monkeypatch) -> None:
    edits: list[str] = []

    async def fake_edit(message: object, text: str, **kwargs: object) -> None:
        edits.append(text)

    monkeypatch.setattr("bot.handlers.admin.ensure_private_callback", _allow_private)
    monkeypatch.setattr("bot.handlers.admin.safe_edit_message_text", fake_edit)

    class Users:
        async def require_superadmin(self, telegram_user_id: int) -> User:
            return User(telegram_user_id, "admin", "Admin", UserRole.SUPERADMIN, "now", "now", None)

    async def run() -> None:
        state = _State({"owner_user_id": 200})
        callback = _Callback("admin:ctype:awg:200")
        await admin_issue_type_selected(callback, state, SimpleNamespace(users=Users()))  # type: ignore[arg-type]

        assert state.state == AdminCreateKeyStates.waiting_note
        assert state.data["owner_user_id"] == 200
        assert state.data["key_type"] == "awg"
        assert callback.answers == [("", None)]
        assert edits

    asyncio.run(run())


def test_pending_user_cannot_open_create_menu(monkeypatch) -> None:
    monkeypatch.setattr("bot.handlers.keys.ensure_private_callback", _allow_private)

    class Users:
        async def require_approved_or_admin(self, actor_user_id: int) -> User:
            raise AccessDenied("Доступ не одобрен")

    async def run() -> None:
        callback = _Callback("keys:create", user_id=100)
        await create_key_menu(callback, SimpleNamespace(users=Users()))  # type: ignore[arg-type]
        assert callback.answers == [("Доступ ещё не одобрен. Дождитесь решения администратора.", True)]

    asyncio.run(run())


def test_unknown_user_cannot_enter_create_fsm(monkeypatch) -> None:
    monkeypatch.setattr("bot.handlers.keys.ensure_private_callback", _allow_private)

    class Users:
        async def require_approved_or_admin(self, actor_user_id: int) -> User:
            raise NotFound("Пользователь не найден")

    async def run() -> None:
        state = _State()
        callback = _Callback("keys:create:xray", user_id=100)
        await create_key_choose(callback, state, SimpleNamespace(users=Users()))  # type: ignore[arg-type]
        assert state.state is None
        assert callback.answers == [("Сначала отправьте /start, чтобы создать заявку на доступ", True)]

    asyncio.run(run())


def test_admin_delete_callbacks_preserve_owner_and_page_context() -> None:
    key = _key(10, owner_user_id=200)
    markup = keys_list_keyboard([key], page=2, owner_user_id=200)
    callbacks = [button.callback_data for row in markup.inline_keyboard for button in row]

    assert "key:open:10:200:2" in callbacks
    assert "key:delete:10:200:2" in callbacks


def test_admin_delete_returns_same_page_when_still_valid(monkeypatch) -> None:
    edits: list[tuple[str, object]] = []

    async def fake_edit(message: object, text: str, **kwargs: object) -> None:
        edits.append((text, kwargs.get("reply_markup")))

    monkeypatch.setattr("bot.handlers.keys.ensure_private_callback", _allow_private)
    monkeypatch.setattr("bot.handlers.keys.safe_edit_message_text", fake_edit)

    class VpnKeys:
        async def get_for_actor(self, actor_user_id: int, key_id: int) -> VpnKey:
            return _key(key_id, owner_user_id=200)

        async def count_for_actor(self, actor_user_id: int, owner_user_id: int | None = None) -> int:
            return 11

        async def list_for_actor(self, actor_user_id: int, owner_user_id: int | None, limit: int, offset: int) -> list[VpnKey]:
            assert owner_user_id == 200
            assert offset == 10
            return [_key(30, owner_user_id=200)]

    class Xray:
        def __init__(self) -> None:
            self.deleted: list[int] = []

        async def delete_xray_key(self, actor_user_id: int, key_id: int) -> None:
            self.deleted.append(key_id)

    class RateLimiter:
        def check(self, *args: object) -> None:
            return None

    async def run() -> None:
        xray = Xray()
        callback = _Callback("confirm:delete:10:200:2")
        await confirm_key_action(
            callback,
            SimpleNamespace(vpn_keys=VpnKeys(), xray=xray, awg=SimpleNamespace()),
            RateLimiter(),
        )  # type: ignore[arg-type]

        assert xray.deleted == [10]
        assert "страница 3" in edits[-1][0]

    asyncio.run(run())


def test_admin_delete_last_key_returns_previous_valid_page(monkeypatch) -> None:
    edits: list[str] = []

    async def fake_edit(message: object, text: str, **kwargs: object) -> None:
        edits.append(text)

    monkeypatch.setattr("bot.handlers.keys.ensure_private_callback", _allow_private)
    monkeypatch.setattr("bot.handlers.keys.safe_edit_message_text", fake_edit)

    class VpnKeys:
        async def get_for_actor(self, actor_user_id: int, key_id: int) -> VpnKey:
            return _key(key_id, owner_user_id=200)

        async def count_for_actor(self, actor_user_id: int, owner_user_id: int | None = None) -> int:
            return 10

        async def list_for_actor(self, actor_user_id: int, owner_user_id: int | None, limit: int, offset: int) -> list[VpnKey]:
            assert owner_user_id == 200
            assert offset == 5
            return [_key(20, owner_user_id=200)]

    class Xray:
        async def delete_xray_key(self, actor_user_id: int, key_id: int) -> None:
            return None

    class RateLimiter:
        def check(self, *args: object) -> None:
            return None

    async def run() -> None:
        callback = _Callback("confirm:delete:10:200:2")
        await confirm_key_action(
            callback,
            SimpleNamespace(vpn_keys=VpnKeys(), xray=Xray(), awg=SimpleNamespace()),
            RateLimiter(),
        )  # type: ignore[arg-type]

        assert "страница 2" in edits[-1]

    asyncio.run(run())
