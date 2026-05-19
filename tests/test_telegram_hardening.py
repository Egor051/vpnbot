
import asyncio
from types import SimpleNamespace

from aiogram.enums import ChatType
from aiogram.exceptions import TelegramBadRequest

from bot.fsm.states import AdminCreateKeyStates, CreateKeyStates
from bot.handlers.admin import (
    admin_access_decision_confirm,
    admin_approve,
    admin_block_user,
    admin_block_user_confirm,
    admin_issue_type_selected,
    admin_unblock_user,
    admin_unblock_user_confirm,
)
from bot.handlers.keys import confirm_key_action, create_key_choose, create_key_menu
from bot.handlers.start import start_command
from bot.keyboards.common import main_menu
from bot.keyboards.keys import keys_list_keyboard
from models.dto import AccessRequest, UnblockUserWarning, User, VpnKey
from models.enums import AccessRequestStatus, UserRole, VpnKeyStatus, VpnKeyType
from services.errors import AccessDenied, NotFound


class _FakeTrialAccess:
    async def can_request_trial(self, user_id: int) -> bool:
        return False


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
            self.chat = SimpleNamespace(type=ChatType.PRIVATE)
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


def test_admin_block_first_callback_only_shows_confirmation(monkeypatch) -> None:
    edits: list[tuple[str, object]] = []

    async def fake_edit(message: object, text: str, **kwargs: object) -> None:
        edits.append((text, kwargs.get("reply_markup")))

    monkeypatch.setattr("bot.handlers.admin.ensure_private_callback", _allow_private)
    monkeypatch.setattr("bot.handlers.admin.safe_edit_message_text", fake_edit)

    class Users:
        def __init__(self) -> None:
            self.block_calls = 0

        async def require_superadmin(self, telegram_user_id: int) -> User:
            return User(telegram_user_id, "admin", "Admin", UserRole.SUPERADMIN, "now", "now", None)

        async def get_user(self, telegram_user_id: int) -> User:
            return User(telegram_user_id, "target", "Target", UserRole.APPROVED_USER, "now", "now", None)

        async def count_keys_for_users(self, actor_user_id: int, user_ids: list[int]) -> dict[int, int]:
            return {200: 2}

        async def block_user(self, *args: object, **kwargs: object) -> None:
            self.block_calls += 1

    async def run() -> None:
        users = Users()
        callback = _Callback("admin:block:200")
        await admin_block_user(callback, SimpleNamespace(users=users))  # type: ignore[arg-type]

        assert users.block_calls == 0
        assert "Подтвердите блокировку пользователя" in edits[-1][0]
        markup = edits[-1][1]
        callbacks = [button.callback_data for row in markup.inline_keyboard for button in row]
        assert callbacks == ["admin:block:confirm:200", "admin:user:200"]

    asyncio.run(run())


def test_admin_block_confirm_performs_block(monkeypatch) -> None:
    edits: list[str] = []

    async def fake_edit(message: object, text: str, **kwargs: object) -> None:
        edits.append(text)

    monkeypatch.setattr("bot.handlers.admin.ensure_private_callback", _allow_private)
    monkeypatch.setattr("bot.handlers.admin.safe_edit_message_text", fake_edit)

    class Users:
        def __init__(self) -> None:
            self.block_calls = 0

        async def require_superadmin(self, telegram_user_id: int) -> User:
            return User(telegram_user_id, "admin", "Admin", UserRole.SUPERADMIN, "now", "now", None)

        async def get_user(self, telegram_user_id: int) -> User:
            return User(telegram_user_id, "target", "Target", UserRole.APPROVED_USER, "now", "now", None)

        async def block_user(self, actor_user_id: int, user_id: int, revoke_active_keys: bool = True) -> SimpleNamespace:
            self.block_calls += 1
            return SimpleNamespace(revoked_key_ids=(10,), errors=())

    async def run() -> None:
        users = Users()
        callback = _Callback("admin:block:confirm:200")
        await admin_block_user_confirm(callback, SimpleNamespace(users=users, trial_access=_FakeTrialAccess()))  # type: ignore[arg-type]

        assert users.block_calls == 1
        assert "Пользователь заблокирован." in edits[-1]

    asyncio.run(run())


def test_admin_block_confirm_already_blocked_does_not_block_again(monkeypatch) -> None:
    edits: list[str] = []

    async def fake_edit(message: object, text: str, **kwargs: object) -> None:
        edits.append(text)

    monkeypatch.setattr("bot.handlers.admin.ensure_private_callback", _allow_private)
    monkeypatch.setattr("bot.handlers.admin.safe_edit_message_text", fake_edit)

    class Users:
        def __init__(self) -> None:
            self.block_calls = 0

        async def require_superadmin(self, telegram_user_id: int) -> User:
            return User(telegram_user_id, "admin", "Admin", UserRole.SUPERADMIN, "now", "now", None)

        async def get_user(self, telegram_user_id: int) -> User:
            return User(telegram_user_id, "target", "Target", UserRole.BLOCKED_USER, "now", "now", "blocked")

        async def block_user(self, *args: object, **kwargs: object) -> None:
            self.block_calls += 1

    async def run() -> None:
        users = Users()
        callback = _Callback("admin:block:confirm:200")
        await admin_block_user_confirm(callback, SimpleNamespace(users=users, trial_access=_FakeTrialAccess()))  # type: ignore[arg-type]

        assert users.block_calls == 0
        assert edits == ["Пользователь уже заблокирован."]

    asyncio.run(run())


def test_admin_unblock_first_callback_shows_warning_confirmation(monkeypatch) -> None:
    edits: list[tuple[str, object]] = []

    async def fake_edit(message: object, text: str, **kwargs: object) -> None:
        edits.append((text, kwargs.get("reply_markup")))

    monkeypatch.setattr("bot.handlers.admin.ensure_private_callback", _allow_private)
    monkeypatch.setattr("bot.handlers.admin.safe_edit_message_text", fake_edit)

    blocked_user = User(200, "target", "Target", UserRole.BLOCKED_USER, "now", "now", "blocked")

    class Users:
        def __init__(self) -> None:
            self.unblock_calls = 0

        async def inspect_unblock_risk(self, actor_user_id: int, user_id: int) -> UnblockUserWarning:
            return UnblockUserWarning(
                user=blocked_user,
                has_warning=True,
                active_or_problem_key_count=1,
                previous_revoke_error_count=1,
                last_block_error_at="now",
                reasons=("предыдущая блокировка завершилась с ошибками отзыва: 1",),
            )

        async def unblock_user(self, *args: object, **kwargs: object) -> None:
            self.unblock_calls += 1

    async def run() -> None:
        users = Users()
        callback = _Callback("admin:unblock:200")
        await admin_unblock_user(callback, SimpleNamespace(users=users))  # type: ignore[arg-type]

        assert users.unblock_calls == 0
        assert "Подтвердите разблокировку пользователя" in edits[-1][0]
        assert "Требуется ручная проверка VPN" in edits[-1][0]
        markup = edits[-1][1]
        callbacks = [button.callback_data for row in markup.inline_keyboard for button in row]
        assert callbacks == ["admin:unblock:confirm:200", "admin:user:200"]

    asyncio.run(run())


def test_admin_unblock_confirm_after_warning_includes_manual_check(monkeypatch) -> None:
    edits: list[str] = []

    async def fake_edit(message: object, text: str, **kwargs: object) -> None:
        edits.append(text)

    monkeypatch.setattr("bot.handlers.admin.ensure_private_callback", _allow_private)
    monkeypatch.setattr("bot.handlers.admin.safe_edit_message_text", fake_edit)

    blocked_user = User(200, "target", "Target", UserRole.BLOCKED_USER, "now", "now", "blocked")
    approved_user = User(200, "target", "Target", UserRole.APPROVED_USER, "now", "now", None)

    class Users:
        def __init__(self) -> None:
            self.unblock_calls = 0

        async def inspect_unblock_risk(self, actor_user_id: int, user_id: int) -> UnblockUserWarning:
            return UnblockUserWarning(
                user=blocked_user,
                has_warning=True,
                active_or_problem_key_count=1,
                previous_revoke_error_count=2,
                last_block_error_at="now",
                reasons=("ключей в статусах, где VPN-доступ мог сохраниться: 1",),
            )

        async def unblock_user(self, actor_user_id: int, user_id: int) -> User:
            self.unblock_calls += 1
            return approved_user

    async def run() -> None:
        users = Users()
        callback = _Callback("admin:unblock:confirm:200")
        await admin_unblock_user_confirm(callback, SimpleNamespace(users=users, trial_access=_FakeTrialAccess()))  # type: ignore[arg-type]

        assert users.unblock_calls == 1
        assert "Пользователь разблокирован" in edits[-1]
        assert "Проверьте Xray/AWG runtime" in edits[-1]

    asyncio.run(run())


def test_admin_unblock_confirm_without_warning_uses_normal_success_text(monkeypatch) -> None:
    edits: list[str] = []

    async def fake_edit(message: object, text: str, **kwargs: object) -> None:
        edits.append(text)

    monkeypatch.setattr("bot.handlers.admin.ensure_private_callback", _allow_private)
    monkeypatch.setattr("bot.handlers.admin.safe_edit_message_text", fake_edit)

    blocked_user = User(200, "target", "Target", UserRole.BLOCKED_USER, "now", "now", "blocked")
    approved_user = User(200, "target", "Target", UserRole.APPROVED_USER, "now", "now", None)

    class Users:
        async def inspect_unblock_risk(self, actor_user_id: int, user_id: int) -> UnblockUserWarning:
            return UnblockUserWarning(
                user=blocked_user,
                has_warning=False,
                active_or_problem_key_count=0,
                previous_revoke_error_count=0,
                last_block_error_at=None,
                reasons=(),
            )

        async def unblock_user(self, actor_user_id: int, user_id: int) -> User:
            return approved_user

    async def run() -> None:
        callback = _Callback("admin:unblock:confirm:200")
        await admin_unblock_user_confirm(callback, SimpleNamespace(users=Users(), trial_access=_FakeTrialAccess()))  # type: ignore[arg-type]

        assert "Пользователь разблокирован" in edits[-1]
        assert "Проверьте Xray/AWG runtime" not in edits[-1]

    asyncio.run(run())


def test_admin_unblock_non_superadmin_is_rejected(monkeypatch) -> None:
    errors: list[str] = []

    async def fake_error(callback: object, exc: Exception) -> None:
        errors.append(str(exc))

    monkeypatch.setattr("bot.handlers.admin.ensure_private_callback", _allow_private)
    monkeypatch.setattr("bot.handlers.admin.answer_callback_error", fake_error)

    class Users:
        async def inspect_unblock_risk(self, actor_user_id: int, user_id: int) -> UnblockUserWarning:
            raise AccessDenied("Недостаточно прав")

    async def run() -> None:
        callback = _Callback("admin:unblock:200", user_id=2)
        await admin_unblock_user(callback, SimpleNamespace(users=Users()))  # type: ignore[arg-type]

        assert errors == ["Недостаточно прав"]

    asyncio.run(run())


def test_admin_approve_first_callback_only_shows_confirmation(monkeypatch) -> None:
    edits: list[tuple[str, object]] = []

    async def fake_edit(message: object, text: str, **kwargs: object) -> None:
        edits.append((text, kwargs.get("reply_markup")))

    monkeypatch.setattr("bot.handlers.admin.ensure_private_callback", _allow_private)
    monkeypatch.setattr("bot.handlers.admin.safe_edit_message_text", fake_edit)

    class Access:
        def __init__(self) -> None:
            self.approve_calls = 0

        async def get_request(self, actor_user_id: int, request_id: int) -> AccessRequest:
            return AccessRequest(request_id, 200, "target", AccessRequestStatus.PENDING, "now", None, None, None)

        async def approve(self, *args: object, **kwargs: object) -> None:
            self.approve_calls += 1

    async def run() -> None:
        access = Access()
        callback = _Callback("admin:approve:5")
        await admin_approve(callback, SimpleNamespace(access=access), SimpleNamespace())  # type: ignore[arg-type]

        assert access.approve_calls == 0
        assert "Подтвердите действие" in edits[-1][0]
        markup = edits[-1][1]
        callbacks = [button.callback_data for row in markup.inline_keyboard for button in row]
        assert callbacks == ["admin:approve:confirm:5", "admin:req:5"]

    asyncio.run(run())


def test_admin_access_confirm_approve_changes_pending_request_and_notifies(monkeypatch) -> None:
    edits: list[str] = []

    async def fake_edit(message: object, text: str, **kwargs: object) -> None:
        edits.append(text)

    monkeypatch.setattr("bot.handlers.admin.ensure_private_callback", _allow_private)
    monkeypatch.setattr("bot.handlers.admin.safe_edit_message_text", fake_edit)

    class Access:
        def __init__(self) -> None:
            self.approve_calls = 0

        async def get_request(self, actor_user_id: int, request_id: int) -> AccessRequest:
            return AccessRequest(request_id, 200, "target", AccessRequestStatus.PENDING, "now", None, None, None)

        async def approve(self, actor_user_id: int, request_id: int) -> tuple[AccessRequest, bool]:
            self.approve_calls += 1
            return AccessRequest(request_id, 200, "target", AccessRequestStatus.APPROVED, "now", 1, "now", None), True

    class Bot:
        def __init__(self) -> None:
            self.sent: list[tuple[int, str]] = []

        async def send_message(self, user_id: int, text: str) -> None:
            self.sent.append((user_id, text))

    async def run() -> None:
        access = Access()
        bot = Bot()
        callback = _Callback("admin:approve:confirm:5")
        await admin_access_decision_confirm(callback, SimpleNamespace(access=access), bot)  # type: ignore[arg-type]

        assert access.approve_calls == 1
        assert bot.sent == [(200, "Ваша заявка одобрена. Отправьте /start, чтобы открыть меню.")]
        assert edits == ["Заявка одобрена."]

    asyncio.run(run())


def test_admin_access_confirm_reject_changes_pending_request_and_notifies(monkeypatch) -> None:
    edits: list[str] = []

    async def fake_edit(message: object, text: str, **kwargs: object) -> None:
        edits.append(text)

    monkeypatch.setattr("bot.handlers.admin.ensure_private_callback", _allow_private)
    monkeypatch.setattr("bot.handlers.admin.safe_edit_message_text", fake_edit)

    class Access:
        def __init__(self) -> None:
            self.reject_calls = 0

        async def get_request(self, actor_user_id: int, request_id: int) -> AccessRequest:
            return AccessRequest(request_id, 200, "target", AccessRequestStatus.PENDING, "now", None, None, None)

        async def reject(self, actor_user_id: int, request_id: int) -> tuple[AccessRequest, bool]:
            self.reject_calls += 1
            return AccessRequest(request_id, 200, "target", AccessRequestStatus.REJECTED, "now", 1, "now", None), True

    class Bot:
        def __init__(self) -> None:
            self.sent: list[tuple[int, str]] = []

        async def send_message(self, user_id: int, text: str) -> None:
            self.sent.append((user_id, text))

    async def run() -> None:
        access = Access()
        bot = Bot()
        callback = _Callback("admin:reject:confirm:5")
        await admin_access_decision_confirm(callback, SimpleNamespace(access=access), bot)  # type: ignore[arg-type]

        assert access.reject_calls == 1
        assert bot.sent == [(200, "Ваша заявка отклонена.")]
        assert edits == ["Заявка отклонена."]

    asyncio.run(run())


def test_admin_access_confirm_processed_request_does_not_change_again(monkeypatch) -> None:
    edits: list[str] = []

    async def fake_edit(message: object, text: str, **kwargs: object) -> None:
        edits.append(text)

    monkeypatch.setattr("bot.handlers.admin.ensure_private_callback", _allow_private)
    monkeypatch.setattr("bot.handlers.admin.safe_edit_message_text", fake_edit)

    class Access:
        def __init__(self) -> None:
            self.reject_calls = 0

        async def get_request(self, actor_user_id: int, request_id: int) -> AccessRequest:
            return AccessRequest(request_id, 200, "target", AccessRequestStatus.APPROVED, "now", 1, "now", None)

        async def reject(self, *args: object, **kwargs: object) -> None:
            self.reject_calls += 1

    async def run() -> None:
        access = Access()
        callback = _Callback("admin:reject:confirm:5")
        await admin_access_decision_confirm(callback, SimpleNamespace(access=access), SimpleNamespace())  # type: ignore[arg-type]

        assert access.reject_calls == 0
        assert edits == ["Заявка уже была обработана."]

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


def test_create_key_menu_ignores_stale_callback_answer(monkeypatch) -> None:
    edits: list[str] = []

    async def fake_edit(message: object, text: str, **kwargs: object) -> None:
        edits.append(text)

    monkeypatch.setattr("bot.handlers.keys.ensure_private_callback", _allow_private)
    monkeypatch.setattr("bot.handlers.keys.safe_edit_message_text", fake_edit)

    class Users:
        async def require_approved_or_admin(self, actor_user_id: int) -> User:
            return User(actor_user_id, "user", "User", UserRole.APPROVED_USER, "now", "now", None)

    class Callback(_Callback):
        def __init__(self) -> None:
            super().__init__("keys:create", user_id=100)
            self.answer_calls = 0

        async def answer(self, text: str | None = None, show_alert: bool | None = None, **kwargs: object) -> None:
            self.answer_calls += 1
            raise TelegramBadRequest(
                method=SimpleNamespace(),
                message="Bad Request: query is too old and response timeout expired or query ID is invalid",
            )

    async def run() -> None:
        callback = Callback()
        await create_key_menu(callback, SimpleNamespace(users=Users()))  # type: ignore[arg-type]

        assert callback.answer_calls == 1
        assert len(edits) == 1
        assert "Выберите тип ключа:" in edits[0]

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
