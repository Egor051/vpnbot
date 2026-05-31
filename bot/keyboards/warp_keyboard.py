
from aiogram.types import InlineKeyboardButton, InlineKeyboardMarkup

from i18n import t
from warp.state import WarpState


def warp_main_keyboard(state: WarpState) -> InlineKeyboardMarkup:
    """Build the main WARP screen keyboard for the current module state."""
    rows: list[list[InlineKeyboardButton]] = []
    if not state.config_present:
        rows.append([InlineKeyboardButton(text=t("btn_warp_upload"), callback_data="admin:warp:upload")])
    elif state.enabled:
        rows.append(
            [
                InlineKeyboardButton(text=t("btn_warp_disable"), callback_data="admin:warp:disable"),
                InlineKeyboardButton(text=t("btn_warp_restart"), callback_data="admin:warp:restart"),
            ]
        )
        rows.append([InlineKeyboardButton(text=t("btn_warp_settings"), callback_data="admin:warp:settings")])
    else:
        rows.append([InlineKeyboardButton(text=t("btn_warp_enable"), callback_data="admin:warp:enable")])
        rows.append([InlineKeyboardButton(text=t("btn_warp_settings"), callback_data="admin:warp:settings")])
    rows.append([InlineKeyboardButton(text=t("btn_back"), callback_data="admin:panel")])
    return InlineKeyboardMarkup(inline_keyboard=rows)


def warp_settings_keyboard() -> InlineKeyboardMarkup:
    """Build the WARP settings screen keyboard."""
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [InlineKeyboardButton(text=t("btn_warp_replace"), callback_data="admin:warp:upload")],
            [InlineKeyboardButton(text=t("btn_warp_delete"), callback_data="admin:warp:delete")],
            [InlineKeyboardButton(text=t("btn_back"), callback_data="admin:warp")],
        ]
    )


def warp_upload_keyboard() -> InlineKeyboardMarkup:
    """Build the keyboard shown while waiting for a config upload."""
    return InlineKeyboardMarkup(
        inline_keyboard=[[InlineKeyboardButton(text=t("btn_back"), callback_data="admin:warp")]]
    )


def warp_delete_confirm_keyboard() -> InlineKeyboardMarkup:
    """Build the confirm/cancel keyboard for deleting the WARP config."""
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [InlineKeyboardButton(text=t("btn_confirm"), callback_data="admin:warp:delete:confirm")],
            [InlineKeyboardButton(text=t("btn_cancel"), callback_data="admin:warp:settings")],
        ]
    )
