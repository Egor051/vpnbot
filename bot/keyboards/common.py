from __future__ import annotations

from aiogram.types import InlineKeyboardButton, InlineKeyboardMarkup, KeyboardButton, ReplyKeyboardMarkup


def main_menu(is_admin: bool = False) -> InlineKeyboardMarkup:
    rows = [
        [InlineKeyboardButton(text="Мои ключи", callback_data="keys:list")],
        [InlineKeyboardButton(text="Создать ключ", callback_data="keys:create")],
        [InlineKeyboardButton(text="Прокси", callback_data="proxy:show")],
        [InlineKeyboardButton(text="Помощь", callback_data="help")],
    ]
    if is_admin:
        rows.append([InlineKeyboardButton(text="Админ-панель", callback_data="admin:panel")])
    return InlineKeyboardMarkup(inline_keyboard=rows)


def main_reply_keyboard(is_admin: bool = False) -> ReplyKeyboardMarkup:
    rows = [
        [KeyboardButton(text="Мои ключи"), KeyboardButton(text="Создать ключ")],
        [KeyboardButton(text="Прокси"), KeyboardButton(text="Помощь")],
    ]
    if is_admin:
        rows.append([KeyboardButton(text="Админ-панель")])
    return ReplyKeyboardMarkup(keyboard=rows, resize_keyboard=True, input_field_placeholder="Выберите действие")


def back_to_menu() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        inline_keyboard=[[InlineKeyboardButton(text="В меню", callback_data="menu:main")]]
    )


def faq_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [InlineKeyboardButton(text="Как подключиться?", callback_data="faq:connect")],
            [InlineKeyboardButton(text="1 ключ = 1 устройство?", callback_data="faq:device")],
            [InlineKeyboardButton(text="Что выбрать: AWG или Xray?", callback_data="faq:choice")],
            [InlineKeyboardButton(text="Почему не работает?", callback_data="faq:trouble")],
            [InlineKeyboardButton(text="Видит ли кто-нибудь мои заметки?", callback_data="faq:notes")],
            [InlineKeyboardButton(text="Техподдержка", callback_data="faq:support")],
            [InlineKeyboardButton(text="В меню", callback_data="menu:main")],
        ]
    )


def faq_answer_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [InlineKeyboardButton(text="К вопросам", callback_data="help")],
            [InlineKeyboardButton(text="В меню", callback_data="menu:main")],
        ]
    )


def cancel_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        inline_keyboard=[[InlineKeyboardButton(text="Отмена", callback_data="cancel")]]
    )


def confirm_cancel_keyboard(confirm_data: str, cancel_data: str = "cancel") -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [InlineKeyboardButton(text="Подтвердить", callback_data=confirm_data)],
            [InlineKeyboardButton(text="Отмена", callback_data=cancel_data)],
        ]
    )


def pagination_keyboard(
    *,
    prev_data: str | None,
    next_data: str | None,
    back_data: str,
) -> InlineKeyboardMarkup:
    rows: list[list[InlineKeyboardButton]] = []
    nav: list[InlineKeyboardButton] = []
    if prev_data:
        nav.append(InlineKeyboardButton(text="Назад", callback_data=prev_data))
    if next_data:
        nav.append(InlineKeyboardButton(text="Дальше", callback_data=next_data))
    if nav:
        rows.append(nav)
    rows.append([InlineKeyboardButton(text="В меню", callback_data=back_data)])
    return InlineKeyboardMarkup(inline_keyboard=rows)
