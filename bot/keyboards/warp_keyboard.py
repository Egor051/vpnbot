
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
    elif split_status.intended_state == "on":
        # Both actions change what traffic does, so each opens a confirmation.
        # «Перезапустить» exists only while the routes are on: the restart verb
        # always ends ON, so on a switched-off WARP it used to switch the routes
        # back on under the label of a restart.
        rows.append(
            [
                InlineKeyboardButton(text=t("btn_warp_disable"), callback_data="admin:warp:disable"),
                InlineKeyboardButton(text=t("btn_warp_restart"), callback_data="admin:warp:restart"),
            ]
        )
    else:
        rows.append([InlineKeyboardButton(text=t("btn_warp_enable"), callback_data="admin:warp:enable")])
    # Settings is always reachable — it hosts config management and the Split-list
    # GUI entry point (which is independent of the tunnel-module state).
    rows.append([InlineKeyboardButton(text=t("btn_warp_settings"), callback_data="admin:warp:settings")])
    rows.append([InlineKeyboardButton(text=t("btn_back"), callback_data="admin:grp:infra")])
    return InlineKeyboardMarkup(inline_keyboard=rows)


def warp_settings_keyboard(state: WarpState) -> InlineKeyboardMarkup:
    """Build the WARP settings screen keyboard.

    Hosts config management (replace/delete — unchanged), the kill-switch toggle
    (fail-closed on tunnel-down instead of leaking the real IP), plus the entry
    point to the selective-split list GUI, which moved here from the main WARP panel.
    """
    kill_label = (
        t("btn_warp_killswitch_disable") if state.kill_switch else t("btn_warp_killswitch_enable")
    )
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [InlineKeyboardButton(text=t("btn_warp_replace"), callback_data="admin:warp:replace")],
            [InlineKeyboardButton(text=t("btn_warp_delete"), callback_data="admin:warp:delete")],
            [InlineKeyboardButton(text=kill_label, callback_data="admin:warp:killswitch:toggle")],
            [InlineKeyboardButton(text=t("btn_warp_split"), callback_data="wsplit:p:0")],
            [InlineKeyboardButton(text=t("btn_back"), callback_data="admin:warp")],
        ]
    )


def warp_upload_keyboard(back_data: str = "admin:warp") -> InlineKeyboardMarkup:
    """Build the keyboard shown while waiting for a config upload.

    «Назад» returns to where the upload was started: the WARP screen for a first
    upload, the WARP settings for «Заменить конфиг».
    """
    return InlineKeyboardMarkup(
        inline_keyboard=[[InlineKeyboardButton(text=t("btn_back"), callback_data=back_data)]]
    )


def warp_action_confirm_keyboard(action: str) -> InlineKeyboardMarkup:
    """Confirm ``admin:warp:<action>`` (disable / restart / killswitch:toggle)."""
    cancel = "admin:warp:settings" if action == "killswitch:toggle" else "admin:warp"
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [InlineKeyboardButton(text=t("btn_confirm"), callback_data=f"admin:warp:{action}:ok")],
            [InlineKeyboardButton(text=t("btn_cancel"), callback_data=cancel)],
        ]
    )


def warp_delete_confirm_keyboard() -> InlineKeyboardMarkup:
    """Build the confirm/cancel keyboard for deleting the WARP config."""
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [InlineKeyboardButton(text=t("btn_confirm"), callback_data="admin:warp:delete:confirm")],
            [InlineKeyboardButton(text=t("btn_cancel"), callback_data="admin:warp:settings")],
        ]
    )
