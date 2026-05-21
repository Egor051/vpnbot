
from aiogram.types import InlineKeyboardButton, InlineKeyboardMarkup

from i18n import t
from models.dto import ProxyAccess
from models.enums import ProxyAccessType


def proxy_menu_keyboard(
    accesses: list[ProxyAccess],
    *,
    socks5_enabled: bool,
    mtproto_enabled: bool,
) -> InlineKeyboardMarkup:
    active_types = {access.access_type for access in accesses}
    rows: list[list[InlineKeyboardButton]] = []
    if socks5_enabled and ProxyAccessType.SOCKS5 not in active_types:
        rows.append([InlineKeyboardButton(text=t("btn_get_socks5"), callback_data="proxy:get:socks5")])
    if mtproto_enabled and ProxyAccessType.MTPROTO not in active_types:
        rows.append([InlineKeyboardButton(text=t("btn_get_mtproto"), callback_data="proxy:get:mtproto")])
    rows.append([InlineKeyboardButton(text=t("btn_go_back"), callback_data="proxy:back")])
    return InlineKeyboardMarkup(inline_keyboard=rows)


def proxy_confirm_keyboard(access_type: str, nonce: str) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [InlineKeyboardButton(text=t("btn_confirm"), callback_data=f"proxy:confirm:{access_type}:{nonce}")],
            [InlineKeyboardButton(text=t("btn_cancel"), callback_data="proxy:cancel")],
        ]
    )


def proxy_back_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        inline_keyboard=[[InlineKeyboardButton(text=t("btn_back_to_proxy"), callback_data="proxy:show")]]
    )
