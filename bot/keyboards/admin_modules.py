
from aiogram.types import InlineKeyboardButton, InlineKeyboardMarkup

from i18n import t
from repositories.protocol_modules import PROTOCOL_DISPLAY, ProtocolModule


def modules_panel_keyboard(modules: list[ProtocolModule]) -> InlineKeyboardMarkup:
    rows: list[list[InlineKeyboardButton]] = []
    by_name = {m.name: m for m in modules}
    for name in ("xray", "awg", "socks5", "mtproto"):
        module = by_name.get(name)
        enabled = module.enabled if module else True
        label = PROTOCOL_DISPLAY.get(name, name)
        icon = "✅" if enabled else "❌"
        action = "disable" if enabled else "enable"
        action_label = t("btn_module_disable") if enabled else t("btn_module_enable")
        rows.append([
            InlineKeyboardButton(text=f"{icon} {label}", callback_data="noop"),
            InlineKeyboardButton(text=action_label, callback_data=f"admin:module:{action}:{name}"),
        ])
    rows.append([InlineKeyboardButton(text=t("btn_admin_panel"), callback_data="admin:panel")])
    return InlineKeyboardMarkup(inline_keyboard=rows)


def module_disable_confirm1_keyboard(name: str) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [InlineKeyboardButton(text=t("btn_module_disable_step1"), callback_data=f"admin:module:disable:{name}:2")],
            [InlineKeyboardButton(text=t("btn_cancel"), callback_data="admin:modules")],
        ]
    )


def module_disable_confirm2_keyboard(name: str) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [InlineKeyboardButton(text=t("btn_module_disable_step2"), callback_data=f"admin:module:disable:{name}:exec")],
            [InlineKeyboardButton(text=t("btn_cancel"), callback_data="admin:modules")],
        ]
    )


def module_enable_confirm_keyboard(name: str) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [InlineKeyboardButton(text=t("btn_module_enable_confirm"), callback_data=f"admin:module:enable:{name}:exec")],
            [InlineKeyboardButton(text=t("btn_cancel"), callback_data="admin:modules")],
        ]
    )


def modules_back_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        inline_keyboard=[[InlineKeyboardButton(text=t("btn_modules_back"), callback_data="admin:modules")]]
    )
