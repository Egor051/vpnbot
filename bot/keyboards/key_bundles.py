"""Keyboards for the all-in-one subscription bundle screens.

Kept apart from ``bot/keyboards/keys.py`` because a bundle is a different entity
with its own callback namespace (``bundle:*``): sharing the key builders would
have meant threading an "is this a bundle?" flag through every one of them, and
the whole point of the flag gate is that these rows simply do not exist while
``SUBSCRIPTION_ENABLED`` is false.
"""

from aiogram.types import InlineKeyboardButton, InlineKeyboardMarkup

from bot.bundles import bundle_status_text
from i18n import t
from models.dto import KeyBundle
from models.enums import KeyBundleStatus

# The bundle is usable (and revocable) only while it is active; a revoked one
# keeps stats/note/delete exactly like a revoked key does.
_LIVE_STATUSES = frozenset({KeyBundleStatus.ACTIVE})


def bundle_list_rows(bundles: list[KeyBundle]) -> list[list[InlineKeyboardButton]]:
    """Rows for the «All-in-One» group of the «My keys» keyboard.

    Same shape as the per-key rows next to it: a title row that opens the card,
    then the action buttons the bundle's status allows.
    """
    rows: list[list[InlineKeyboardButton]] = []
    for bundle in bundles:
        rows.append(
            [
                InlineKeyboardButton(
                    text=f"{t('bundle_title', id=bundle.id)} · {bundle_status_text(bundle.status)}",
                    callback_data=f"bundle:open:{bundle.id}",
                )
            ]
        )
        if bundle.status in _LIVE_STATUSES:
            rows.append(
                [
                    InlineKeyboardButton(text=t("btn_config"), callback_data=f"bundle:show:{bundle.id}"),
                    InlineKeyboardButton(text=t("btn_stats"), callback_data=f"bundle:stats:{bundle.id}"),
                    InlineKeyboardButton(text=t("btn_revoke"), callback_data=f"bundle:revoke:{bundle.id}"),
                ]
            )
        else:
            rows.append([InlineKeyboardButton(text=t("btn_stats"), callback_data=f"bundle:stats:{bundle.id}")])
        rows.append(
            [
                InlineKeyboardButton(text=t("btn_note"), callback_data=f"bundle:note:{bundle.id}"),
                InlineKeyboardButton(text=t("btn_delete"), callback_data=f"bundle:delete:{bundle.id}"),
            ]
        )
    return rows


def bundle_actions_keyboard(bundle: KeyBundle) -> InlineKeyboardMarkup:
    """The five bundle actions: config · stats · revoke · note · delete."""
    rows: list[list[InlineKeyboardButton]] = []
    if bundle.status in _LIVE_STATUSES:
        rows.append([InlineKeyboardButton(text=t("btn_config"), callback_data=f"bundle:show:{bundle.id}")])
    rows.append([InlineKeyboardButton(text=t("btn_stats"), callback_data=f"bundle:stats:{bundle.id}")])
    if bundle.status in _LIVE_STATUSES:
        rows.append([InlineKeyboardButton(text=t("btn_revoke"), callback_data=f"bundle:revoke:{bundle.id}")])
    rows.append([InlineKeyboardButton(text=t("btn_note"), callback_data=f"bundle:note:{bundle.id}")])
    rows.append([InlineKeyboardButton(text=t("btn_delete"), callback_data=f"bundle:delete:{bundle.id}")])
    rows.append([InlineKeyboardButton(text=t("btn_to_list"), callback_data="keys:list")])
    return InlineKeyboardMarkup(inline_keyboard=rows)


def bundle_confirm_keyboard(action: str, bundle_id: int) -> InlineKeyboardMarkup:
    """Confirm/cancel for a destructive bundle action, like the per-key one."""
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [InlineKeyboardButton(text=t("btn_confirm"), callback_data=f"bundle:confirm:{action}:{bundle_id}")],
            [InlineKeyboardButton(text=t("btn_cancel"), callback_data=f"bundle:open:{bundle_id}")],
        ]
    )
