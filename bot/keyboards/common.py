
from aiogram.types import InlineKeyboardButton, InlineKeyboardMarkup, KeyboardButton, ReplyKeyboardMarkup

from i18n import t


def main_menu(is_admin: bool = False) -> InlineKeyboardMarkup:
    rows = [
        [InlineKeyboardButton(text=t("btn_my_keys"), callback_data="keys:list")],
        [InlineKeyboardButton(text=t("btn_create_key"), callback_data="keys:create")],
        [InlineKeyboardButton(text=t("btn_proxy"), callback_data="proxy:show")],
        [InlineKeyboardButton(text=t("btn_help"), callback_data="help")],
    ]
    if is_admin:
        rows.append([InlineKeyboardButton(text=t("btn_admin_panel"), callback_data="admin:panel")])
    return InlineKeyboardMarkup(inline_keyboard=rows)


def main_reply_keyboard(is_admin: bool = False) -> ReplyKeyboardMarkup:
    rows = [
        [KeyboardButton(text=t("btn_my_keys")), KeyboardButton(text=t("btn_create_key"))],
        [KeyboardButton(text=t("btn_proxy")), KeyboardButton(text=t("btn_help"))],
    ]
    if is_admin:
        rows.append([KeyboardButton(text=t("btn_admin_panel"))])
    return ReplyKeyboardMarkup(keyboard=rows, resize_keyboard=True, input_field_placeholder=t("btn_keyboard_placeholder"))


def back_to_menu() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        inline_keyboard=[[InlineKeyboardButton(text=t("btn_back_to_menu"), callback_data="menu:main")]]
    )


def faq_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [InlineKeyboardButton(text=t("btn_faq_connect"), callback_data="faq:connect")],
            [InlineKeyboardButton(text=t("btn_faq_device"), callback_data="faq:device")],
            [InlineKeyboardButton(text=t("btn_faq_choice"), callback_data="faq:choice")],
            [InlineKeyboardButton(text=t("btn_faq_trouble"), callback_data="faq:trouble")],
            [InlineKeyboardButton(text=t("btn_faq_notes"), callback_data="faq:notes")],
            [InlineKeyboardButton(text=t("btn_faq_support"), callback_data="faq:support")],
            [InlineKeyboardButton(text=t("btn_back_to_menu"), callback_data="menu:main")],
        ]
    )


def faq_answer_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [InlineKeyboardButton(text=t("btn_back_to_faq"), callback_data="help")],
            [InlineKeyboardButton(text=t("btn_back_to_menu"), callback_data="menu:main")],
        ]
    )


def cancel_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        inline_keyboard=[[InlineKeyboardButton(text=t("btn_cancel"), callback_data="cancel")]]
    )


def confirm_cancel_keyboard(confirm_data: str, cancel_data: str = "cancel") -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [InlineKeyboardButton(text=t("btn_confirm"), callback_data=confirm_data)],
            [InlineKeyboardButton(text=t("btn_cancel"), callback_data=cancel_data)],
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
        nav.append(InlineKeyboardButton(text=t("btn_prev"), callback_data=prev_data))
    if next_data:
        nav.append(InlineKeyboardButton(text=t("btn_next"), callback_data=next_data))
    if nav:
        rows.append(nav)
    rows.append([InlineKeyboardButton(text=t("btn_back_to_menu"), callback_data=back_data)])
    return InlineKeyboardMarkup(inline_keyboard=rows)
