from __future__ import annotations

from aiogram.types import InlineKeyboardButton, InlineKeyboardMarkup

from models.dto import AccessRequest, User
from models.enums import UserRole
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


def admin_panel_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [InlineKeyboardButton(text="Заявки на доступ", callback_data="admin:reqs")],
            [InlineKeyboardButton(text="Пользователи", callback_data="admin:users")],
            [InlineKeyboardButton(text="Статистика ключей", callback_data="admin:stats")],
            [InlineKeyboardButton(text="Логи действий", callback_data="admin:audit")],
            [InlineKeyboardButton(text="Выдать ключ пользователю", callback_data="admin:issue")],
            [InlineKeyboardButton(text="Объявление", callback_data="admin:announce")],
            [InlineKeyboardButton(text="В меню", callback_data="menu:main")],
        ]
    )


def announcement_confirm_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [InlineKeyboardButton(text="Отправить", callback_data="admin:announce:send")],
            [InlineKeyboardButton(text="Отмена", callback_data="admin:announce:cancel")],
        ]
    )


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


def user_actions_keyboard(user: User) -> InlineKeyboardMarkup:
    rows: list[list[InlineKeyboardButton]] = []
    if user.role != UserRole.APPROVED_USER:
        rows.append([InlineKeyboardButton(text="Одобрить пользователя", callback_data=f"admin:userapprove:{user.telegram_user_id}")])
    if user.role != UserRole.BLOCKED_USER:
        rows.append([InlineKeyboardButton(text="Заблокировать", callback_data=f"admin:block:{user.telegram_user_id}")])
    if user.role == UserRole.BLOCKED_USER:
        rows.append([InlineKeyboardButton(text="Разблокировать", callback_data=f"admin:unblock:{user.telegram_user_id}")])
    rows.append([InlineKeyboardButton(text="Выдать ключ", callback_data=f"admin:issue:{user.telegram_user_id}")])
    rows.append([InlineKeyboardButton(text="Ключи пользователя", callback_data=f"admin:ukeys:{user.telegram_user_id}:0")])
    rows.append([InlineKeyboardButton(text="К пользователям", callback_data="admin:users")])
    return InlineKeyboardMarkup(inline_keyboard=rows)


def admin_key_type_keyboard(user_id: int) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [InlineKeyboardButton(text="Xray", callback_data=f"admin:ctype:xray:{user_id}")],
            [InlineKeyboardButton(text="AWG", callback_data=f"admin:ctype:awg:{user_id}")],
            [InlineKeyboardButton(text="Отмена", callback_data="cancel")],
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
