
from aiogram.types import InlineKeyboardButton, InlineKeyboardMarkup

from i18n import t
from warp.split_manager import SplitStatus
from warp.state import WarpState


def warp_main_keyboard(state: WarpState, split_status: SplitStatus) -> InlineKeyboardMarkup:
    """Build the main WARP screen keyboard.

    The On/Off/Restart row operates on the split ROUTES (table T) via the
    WarpSplitManager — never on the awg-quick@out-warp interface/process. The
    toggle label flips on the route intent (marker), not on the tunnel-module flag.
    Config upload/Split-list management live one level down in «Настройки WARP».
    """
    rows: list[list[InlineKeyboardButton]] = []
    if not state.config_present:
        rows.append([InlineKeyboardButton(text=t("btn_warp_upload"), callback_data="admin:warp:upload")])
    else:
        if split_status.intended_state == "on":
            toggle = InlineKeyboardButton(text=t("btn_warp_disable"), callback_data="admin:warp:disable")
        else:
            toggle = InlineKeyboardButton(text=t("btn_warp_enable"), callback_data="admin:warp:enable")
        rows.append(
            [
                toggle,
                InlineKeyboardButton(text=t("btn_warp_restart"), callback_data="admin:warp:restart"),
            ]
        )
    # Settings is always reachable — it hosts config management and the Split-list
    # GUI entry point (which is independent of the tunnel-module state).
    rows.append([InlineKeyboardButton(text=t("btn_warp_settings"), callback_data="admin:warp:settings")])
    rows.append([InlineKeyboardButton(text=t("btn_back"), callback_data="admin:panel")])
    return InlineKeyboardMarkup(inline_keyboard=rows)


def warp_settings_keyboard() -> InlineKeyboardMarkup:
    """Build the WARP settings screen keyboard.

    Hosts config management (replace/delete — unchanged) plus the entry point to
    the selective-split list GUI, which moved here from the main WARP panel.
    """
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [InlineKeyboardButton(text=t("btn_warp_replace"), callback_data="admin:warp:upload")],
            [InlineKeyboardButton(text=t("btn_warp_delete"), callback_data="admin:warp:delete")],
            [InlineKeyboardButton(text=t("btn_warp_split"), callback_data="wsplit:p:0")],
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
