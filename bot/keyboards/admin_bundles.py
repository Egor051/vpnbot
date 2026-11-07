"""Keyboards of the admin «All-in-One» section (``admin:aio*`` callbacks).

Two bulk operations over every active bundle, each a plan screen followed by a
confirmation: switch every bundle to the basic kind, or top every bundle up to
what the current settings would give a new one.
"""

from aiogram.types import InlineKeyboardButton, InlineKeyboardMarkup

from i18n import t

# The two bulk modes, as they appear in callback data.
MODE_BASIC = "basic"
MODE_TOP_UP = "top"
RECONCILE_MODES: tuple[str, ...] = (MODE_BASIC, MODE_TOP_UP)


def admin_bundles_panel_keyboard() -> InlineKeyboardMarkup:
    """The section screen: the two bulk operations and the way back."""
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [InlineKeyboardButton(text=t("btn_aio_to_basic"), callback_data=f"admin:aio:plan:{MODE_BASIC}")],
            [InlineKeyboardButton(text=t("btn_aio_top_up"), callback_data=f"admin:aio:plan:{MODE_TOP_UP}")],
            [InlineKeyboardButton(text=t("btn_back"), callback_data="admin:grp:infra")],
        ]
    )


def admin_bundles_confirm_keyboard(mode: str) -> InlineKeyboardMarkup:
    """Run / cancel under a plan that has something to change."""
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [InlineKeyboardButton(text=t("btn_aio_run"), callback_data=f"admin:aio:run:{mode}")],
            [InlineKeyboardButton(text=t("btn_cancel"), callback_data="admin:aio")],
        ]
    )


def admin_bundles_back_keyboard() -> InlineKeyboardMarkup:
    """Back to the section, or to the admin panel — under a plan or a final report."""
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [InlineKeyboardButton(text=t("btn_aio_back"), callback_data="admin:aio")],
            [InlineKeyboardButton(text=t("btn_admin_panel"), callback_data="admin:panel")],
        ]
    )
