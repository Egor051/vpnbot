
from aiogram.types import InlineKeyboardButton, InlineKeyboardMarkup

from models.access import is_blocked_user
from models.dto import AccessRequest, User
from models.enums import UserRole
from repositories.announcements import AnnouncementBatch
from utils.formatting import format_user_display


def access_request_keyboard(request_id: int) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [
                InlineKeyboardButton(text="Одобрить", callback_data=f"admin:approve:{request_id}"),
                InlineKeyboardButton(text="Отклонить", callback_data=f"admin:reject:{request_id}"),
            ]
        ]
    )


def access_request_decision_confirm_keyboard(request_id: int, action: str) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [InlineKeyboardButton(text="Подтвердить", callback_data=f"admin:{action}:confirm:{request_id}")],
            [InlineKeyboardButton(text="Отмена", callback_data=f"admin:req:{request_id}")],
        ]
    )


def moderator_panel_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [InlineKeyboardButton(text="Заявки на доступ", callback_data="admin:reqs")],
            [InlineKeyboardButton(text="Пользователи", callback_data="admin:users")],
            [InlineKeyboardButton(text="В меню", callback_data="menu:main")],
        ]
    )


def admin_panel_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [InlineKeyboardButton(text="Заявки на доступ", callback_data="admin:reqs")],
            [InlineKeyboardButton(text="Пользователи", callback_data="admin:users")],
            [InlineKeyboardButton(text="Статистика ключей", callback_data="admin:stats")],
            [InlineKeyboardButton(text="Статус прокси", callback_data="admin:proxy")],
            [InlineKeyboardButton(text="Диагностика backend", callback_data="admin:diagnostics")],
            [InlineKeyboardButton(text="📊 Статистика прокси", callback_data="admin:proxy_stats")],
            [InlineKeyboardButton(text="Логи действий", callback_data="admin:audit")],
            [InlineKeyboardButton(text="Выдать ключ пользователю", callback_data="admin:issue")],
            [InlineKeyboardButton(text="Пробные доступы", callback_data="admin:trial")],
            [InlineKeyboardButton(text="Объявление", callback_data="admin:announce")],
            [InlineKeyboardButton(text="Восстановление объявлений", callback_data="admin:announce_batches")],
            [InlineKeyboardButton(text="Бэкап БД", callback_data="admin:backup")],
            [InlineKeyboardButton(text="В меню", callback_data="menu:main")],
        ]
    )


def announcement_confirm_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [InlineKeyboardButton(text="Отправить сейчас", callback_data="admin:announce:send")],
            [InlineKeyboardButton(text="Запланировать", callback_data="admin:announce:schedule")],
            [InlineKeyboardButton(text="Отмена", callback_data="admin:announce:cancel")],
        ]
    )


def announcement_batches_keyboard(batches: list[AnnouncementBatch]) -> InlineKeyboardMarkup:
    rows: list[list[InlineKeyboardButton]] = []
    for batch in batches:
        actions: list[InlineKeyboardButton] = []
        if batch.status == "scheduled":
            actions.append(InlineKeyboardButton(text=f"Отправить сейчас #{batch.id}", callback_data=f"admin:announce:resume:{batch.id}"))
        if batch.status in {"pending", "sending"}:
            actions.append(InlineKeyboardButton(text=f"Продолжить #{batch.id}", callback_data=f"admin:announce:resume:{batch.id}"))
        if batch.status == "failed":
            actions.append(InlineKeyboardButton(text=f"Повторить ошибки #{batch.id}", callback_data=f"admin:announce:retry:{batch.id}"))
        if actions:
            rows.append(actions)
        rows.append([InlineKeyboardButton(text=f"Отменить #{batch.id}", callback_data=f"admin:announce:cancelbatch:{batch.id}")])
    rows.append([InlineKeyboardButton(text="Обновить", callback_data="admin:announce_batches")])
    rows.append([InlineKeyboardButton(text="Админ-панель", callback_data="admin:panel")])
    return InlineKeyboardMarkup(inline_keyboard=rows)


def pending_requests_keyboard(requests: list[AccessRequest], page: int = 0, has_next: bool = False) -> InlineKeyboardMarkup:
    rows: list[list[InlineKeyboardButton]] = []
    for request in requests:
        title = request.username or str(request.telegram_user_id)
        rows.append([InlineKeyboardButton(text=f"{title} · #{request.id}", callback_data=f"admin:req:{request.id}")])
        rows.append(
            [
                InlineKeyboardButton(text="Одобрить", callback_data=f"admin:approve:{request.id}"),
                InlineKeyboardButton(text="Отклонить", callback_data=f"admin:reject:{request.id}"),
            ]
        )
    nav: list[InlineKeyboardButton] = []
    if page > 0:
        nav.append(InlineKeyboardButton(text="Назад", callback_data=f"admin:reqs:{page - 1}"))
    if has_next:
        nav.append(InlineKeyboardButton(text="Дальше", callback_data=f"admin:reqs:{page + 1}"))
    if nav:
        rows.append(nav)
    rows.append([InlineKeyboardButton(text="Админ-панель", callback_data="admin:panel")])
    return InlineKeyboardMarkup(inline_keyboard=rows)


def users_keyboard(
    users: list[User],
    page: int = 0,
    has_next: bool = False,
    prefix: str = "admin:user",
    nav_prefix: str = "admin:users",
) -> InlineKeyboardMarkup:
    rows: list[list[InlineKeyboardButton]] = []
    for user in users:
        title = format_user_display(user.telegram_user_id, user.username)
        rows.append(
            [
                InlineKeyboardButton(
                    text=title,
                    callback_data=f"{prefix}:{user.telegram_user_id}",
                )
            ]
        )
    nav: list[InlineKeyboardButton] = []
    if page > 0:
        nav.append(InlineKeyboardButton(text="Назад", callback_data=f"{nav_prefix}:{page - 1}"))
    if has_next:
        nav.append(InlineKeyboardButton(text="Дальше", callback_data=f"{nav_prefix}:{page + 1}"))
    if nav:
        rows.append(nav)
    rows.append([InlineKeyboardButton(text="Админ-панель", callback_data="admin:panel")])
    return InlineKeyboardMarkup(inline_keyboard=rows)


def user_actions_keyboard(
    user: User,
    *,
    has_used_trial: bool = False,
    actor_role: UserRole = UserRole.SUPERADMIN,
) -> InlineKeyboardMarkup:
    rows: list[list[InlineKeyboardButton]] = []
    blocked = is_blocked_user(user)
    is_moderator_actor = actor_role == UserRole.MODERATOR

    if not is_moderator_actor and user.role not in {UserRole.APPROVED_USER, UserRole.MODERATOR} and not blocked:
        rows.append([InlineKeyboardButton(text="Одобрить пользователя", callback_data=f"admin:userapprove:{user.telegram_user_id}")])
    if not blocked:
        rows.append([InlineKeyboardButton(text="Заблокировать", callback_data=f"admin:block:{user.telegram_user_id}")])
    if blocked:
        rows.append([InlineKeyboardButton(text="Разблокировать", callback_data=f"admin:unblock:{user.telegram_user_id}")])
    if not is_moderator_actor:
        if user.role in {UserRole.APPROVED_USER, UserRole.MODERATOR, UserRole.SUPERADMIN, UserRole.PENDING_USER} and not blocked:
            rows.append([InlineKeyboardButton(text="Выдать ключ", callback_data=f"admin:issue:{user.telegram_user_id}")])
        if has_used_trial:
            rows.append([InlineKeyboardButton(text="Сбросить пробный доступ", callback_data=f"admin:trial:reset:{user.telegram_user_id}")])
        rows.append([InlineKeyboardButton(text="Ключи пользователя", callback_data=f"admin:ukeys:{user.telegram_user_id}:0")])
        rows.append([InlineKeyboardButton(text="Редактировать заметку", callback_data=f"admin:unote:{user.telegram_user_id}")])
    if not is_moderator_actor and not blocked and user.role == UserRole.APPROVED_USER:
        rows.append([InlineKeyboardButton(text="Назначить модератором", callback_data=f"admin:setmoderator:{user.telegram_user_id}")])
    if not is_moderator_actor and user.role == UserRole.MODERATOR:
        rows.append([InlineKeyboardButton(text="Снять роль модератора", callback_data=f"admin:setmoderator:{user.telegram_user_id}")])
    rows.append([InlineKeyboardButton(text="К пользователям", callback_data="admin:users")])
    return InlineKeyboardMarkup(inline_keyboard=rows)


def block_user_confirm_keyboard(user: User) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [InlineKeyboardButton(text="Подтвердить блокировку", callback_data=f"admin:block:confirm:{user.telegram_user_id}")],
            [InlineKeyboardButton(text="Отмена", callback_data=f"admin:user:{user.telegram_user_id}")],
        ]
    )


def unblock_user_confirm_keyboard(user: User) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [InlineKeyboardButton(text="Подтвердить разблокировку", callback_data=f"admin:unblock:confirm:{user.telegram_user_id}")],
            [InlineKeyboardButton(text="Отмена", callback_data=f"admin:user:{user.telegram_user_id}")],
        ]
    )


def admin_key_type_keyboard(user_id: int) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [InlineKeyboardButton(text="Xray", callback_data=f"admin:ctype:xray:{user_id}")],
            [InlineKeyboardButton(text="AWG", callback_data=f"admin:ctype:awg:{user_id}")],
            [InlineKeyboardButton(text="Отмена", callback_data="cancel")],
        ]
    )


def trial_request_keyboard(request_id: int) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [
                InlineKeyboardButton(text="Одобрить", callback_data=f"admin:trial:approve:{request_id}"),
                InlineKeyboardButton(text="Отклонить", callback_data=f"admin:trial:reject:{request_id}"),
            ]
        ]
    )


def admin_issue_users_keyboard(users: list[User], page: int = 0, has_next: bool = False) -> InlineKeyboardMarkup:
    rows: list[list[InlineKeyboardButton]] = []
    for user in users:
        title = format_user_display(user.telegram_user_id, user.username)
        rows.append([InlineKeyboardButton(text=title, callback_data=f"admin:issue:{user.telegram_user_id}")])
    nav: list[InlineKeyboardButton] = []
    if page > 0:
        nav.append(InlineKeyboardButton(text="Назад", callback_data=f"admin:issuepage:{page - 1}"))
    if has_next:
        nav.append(InlineKeyboardButton(text="Дальше", callback_data=f"admin:issuepage:{page + 1}"))
    if nav:
        rows.append(nav)
    rows.append([InlineKeyboardButton(text="Админ-панель", callback_data="admin:panel")])
    return InlineKeyboardMarkup(inline_keyboard=rows)
