
from aiogram.types import InlineKeyboardButton, InlineKeyboardMarkup

import i18n
from i18n import t


def settings_menu_keyboard(*, expiry_notifications_enabled: bool) -> InlineKeyboardMarkup:
    """Build the settings panel: cabinet entry plus language and notification toggles."""
    lang_name = t("lang_name_en") if i18n.resolve_locale() == "en" else t("lang_name_ru")
    notify_icon = "✅" if expiry_notifications_enabled else "❌"
    rows = [
        [InlineKeyboardButton(text=t("btn_settings_cabinet"), callback_data="settings:cabinet")],
        [InlineKeyboardButton(text=t("btn_settings_language", lang=lang_name), callback_data="settings:lang:toggle")],
        [InlineKeyboardButton(
            text=f"{notify_icon} {t('btn_settings_notifications')}",
            callback_data="settings:notify:toggle",
        )],
        [InlineKeyboardButton(text=t("btn_back_to_menu"), callback_data="menu:main")],
    ]
    return InlineKeyboardMarkup(inline_keyboard=rows)


def personal_cabinet_keyboard() -> InlineKeyboardMarkup:
    """Build the personal cabinet keyboard with back-to-settings and back-to-menu."""
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [InlineKeyboardButton(text=t("btn_back_to_settings"), callback_data="settings:open")],
            [InlineKeyboardButton(text=t("btn_back_to_menu"), callback_data="menu:main")],
        ]
    )
