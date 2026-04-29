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


def keys_list_keyboard(
    keys: list[VpnKey],
    page: int = 0,
    has_next: bool = False,
    owner_user_id: int | None = None,
    total_pages: int = 1,
) -> InlineKeyboardMarkup:
    rows: list[list[InlineKeyboardButton]] = []
    for key in keys:
        prefix = "Xray" if key.key_type == VpnKeyType.XRAY else "AWG"
        open_data = f"key:open:{key.id}"
        if owner_user_id is not None:
            open_data = f"key:open:{key.id}:{owner_user_id}:{page}"
        rows.append([InlineKeyboardButton(text=f"{prefix} #{key.id} · {status_text(key.status)}", callback_data=open_data)])
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
            note_buttons: list[InlineKeyboardButton] = []
            if owner_user_id is None:
                note_buttons.append(InlineKeyboardButton(text="Заметка", callback_data=f"key:note:{key.id}"))
            delete_data = f"key:delete:{key.id}"
            if owner_user_id is not None:
                delete_data = f"key:delete:{key.id}:{owner_user_id}:{page}"
            note_buttons.append(InlineKeyboardButton(text="Удалить", callback_data=delete_data))
            rows.append(note_buttons)

    prev_page = page - 1
    next_page = page + 1
    page_prefix = f"admin:ukeys:{owner_user_id}" if owner_user_id is not None else "keys:list"
    nav: list[InlineKeyboardButton] = []
    if page > 0:
        nav.append(InlineKeyboardButton(text=f"Назад {page}/{total_pages}", callback_data=f"{page_prefix}:{prev_page}"))
    if has_next:
        nav.append(InlineKeyboardButton(text=f"Далее {page + 2}/{total_pages}", callback_data=f"{page_prefix}:{next_page}"))
    if nav:
        rows.append(nav)

    create_callback = f"admin:issue:{owner_user_id}" if owner_user_id is not None else "keys:create"
    rows.append([InlineKeyboardButton(text="Создать ключ", callback_data=create_callback)])
    rows.append([InlineKeyboardButton(text="В меню", callback_data="menu:main")])
    return InlineKeyboardMarkup(inline_keyboard=rows)


def key_actions_keyboard(key: VpnKey, owner_user_id: int | None = None, page: int = 0) -> InlineKeyboardMarkup:
    rows: list[list[InlineKeyboardButton]] = []
    if key.status == VpnKeyStatus.ACTIVE:
        rows.append([InlineKeyboardButton(text="Показать конфиг", callback_data=f"key:show:{key.id}")])
        rows.append([InlineKeyboardButton(text="Отозвать", callback_data=f"key:revoke:{key.id}")])
    rows.append([InlineKeyboardButton(text="Статистика", callback_data=f"key:stats:{key.id}")])
    if key.status != VpnKeyStatus.DELETED:
        if owner_user_id is None:
            rows.append([InlineKeyboardButton(text="Редактировать заметку", callback_data=f"key:note:{key.id}")])
        delete_data = f"key:delete:{key.id}"
        if owner_user_id is not None:
            delete_data = f"key:delete:{key.id}:{owner_user_id}:{page}"
        rows.append([InlineKeyboardButton(text="Удалить", callback_data=delete_data)])
    back_data = f"admin:ukeys:{owner_user_id}:{page}" if owner_user_id is not None else "keys:list"
    rows.append([InlineKeyboardButton(text="К списку", callback_data=back_data)])
    return InlineKeyboardMarkup(inline_keyboard=rows)


def confirm_keyboard(action: str, key_id: int, owner_user_id: int | None = None, page: int = 0) -> InlineKeyboardMarkup:
    confirm_data = f"confirm:{action}:{key_id}"
    cancel_data = f"key:open:{key_id}"
    if owner_user_id is not None:
        confirm_data = f"{confirm_data}:{owner_user_id}:{page}"
        cancel_data = f"{cancel_data}:{owner_user_id}:{page}"
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [InlineKeyboardButton(text="Подтвердить", callback_data=confirm_data)],
            [InlineKeyboardButton(text="Отмена", callback_data=cancel_data)],
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


def after_key_deleted_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [InlineKeyboardButton(text="Мои ключи", callback_data="keys:list")],
            [InlineKeyboardButton(text="В меню", callback_data="menu:main")],
        ]
    )
