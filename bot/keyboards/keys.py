from __future__ import annotations

from aiogram.types import InlineKeyboardButton, InlineKeyboardMarkup

from bot.formatters import status_text
from models.dto import VpnKey
from models.enums import VpnKeyStatus, VpnKeyType


def create_key_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [InlineKeyboardButton(text="Xray", callback_data="keys:create:xray")],
            [InlineKeyboardButton(text="AWG", callback_data="keys:create:awg")],
            [InlineKeyboardButton(text="Назад", callback_data="menu:main")],
        ]
    )


def keys_list_keyboard(keys: list[VpnKey], page: int = 0, has_next: bool = False, owner_user_id: int | None = None) -> InlineKeyboardMarkup:
    rows: list[list[InlineKeyboardButton]] = []
    for key in keys:
        prefix = "Xray" if key.key_type == VpnKeyType.XRAY else "AWG"
        rows.append([InlineKeyboardButton(text=f"{prefix} #{key.id} · {status_text(key.status)}", callback_data=f"key:open:{key.id}")])
        if key.status == VpnKeyStatus.ACTIVE:
            rows.append(
                [
                    InlineKeyboardButton(text="Конфиг", callback_data=f"key:show:{key.id}"),
                    InlineKeyboardButton(text="Статистика", callback_data=f"key:stats:{key.id}"),
                    InlineKeyboardButton(text="Отозвать", callback_data=f"key:revoke:{key.id}"),
                ]
            )
        else:
            rows.append([InlineKeyboardButton(text="Статистика", callback_data=f"key:stats:{key.id}")])
        if key.status != VpnKeyStatus.DELETED:
            rows.append(
                [
                    InlineKeyboardButton(text="Заметка", callback_data=f"key:note:{key.id}"),
                    InlineKeyboardButton(text="Удалить", callback_data=f"key:delete:{key.id}"),
                ]
            )

    prev_page = page - 1
    next_page = page + 1
    page_prefix = f"admin:ukeys:{owner_user_id}" if owner_user_id is not None else "keys:list"
    nav: list[InlineKeyboardButton] = []
    if page > 0:
        nav.append(InlineKeyboardButton(text="Назад", callback_data=f"{page_prefix}:{prev_page}"))
    if has_next:
        nav.append(InlineKeyboardButton(text="Дальше", callback_data=f"{page_prefix}:{next_page}"))
    if nav:
        rows.append(nav)

    create_callback = f"admin:issue:{owner_user_id}" if owner_user_id is not None else "keys:create"
    rows.append([InlineKeyboardButton(text="Создать ключ", callback_data=create_callback)])
    rows.append([InlineKeyboardButton(text="В меню", callback_data="menu:main")])
    return InlineKeyboardMarkup(inline_keyboard=rows)


def key_actions_keyboard(key: VpnKey, owner_user_id: int | None = None) -> InlineKeyboardMarkup:
    rows: list[list[InlineKeyboardButton]] = []
    if key.status == VpnKeyStatus.ACTIVE:
        rows.append([InlineKeyboardButton(text="Показать конфиг", callback_data=f"key:show:{key.id}")])
        rows.append([InlineKeyboardButton(text="Отозвать", callback_data=f"key:revoke:{key.id}")])
    rows.append([InlineKeyboardButton(text="Статистика", callback_data=f"key:stats:{key.id}")])
    if key.status != VpnKeyStatus.DELETED:
        rows.append([InlineKeyboardButton(text="Редактировать заметку", callback_data=f"key:note:{key.id}")])
        rows.append([InlineKeyboardButton(text="Удалить", callback_data=f"key:delete:{key.id}")])
    back_data = f"admin:ukeys:{owner_user_id}:0" if owner_user_id is not None else "keys:list"
    rows.append([InlineKeyboardButton(text="К списку", callback_data=back_data)])
    return InlineKeyboardMarkup(inline_keyboard=rows)


def confirm_keyboard(action: str, key_id: int) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [InlineKeyboardButton(text="Подтвердить", callback_data=f"confirm:{action}:{key_id}")],
            [InlineKeyboardButton(text="Отмена", callback_data=f"key:open:{key_id}")],
        ]
    )


def after_key_created_keyboard(key: VpnKey) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [InlineKeyboardButton(text="Открыть ключ", callback_data=f"key:open:{key.id}")],
            [InlineKeyboardButton(text="Мои ключи", callback_data="keys:list")],
            [InlineKeyboardButton(text="В меню", callback_data="menu:main")],
        ]
    )
