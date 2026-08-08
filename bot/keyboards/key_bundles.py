"""Keyboards for the all-in-one subscription bundle screens.

Kept apart from ``bot/keyboards/keys.py`` because a bundle is a different entity
with its own callback namespace (``bundle:*``): sharing the key builders would
have meant threading an "is this a bundle?" flag through every one of them, and
the whole point of the flag gate is that these rows simply do not exist while
``SUBSCRIPTION_ENABLED`` is false.
"""

from aiogram.types import InlineKeyboardButton, InlineKeyboardMarkup

from bot.formatters import bundle_status_text, bundle_title
from i18n import t
from models.dto import KeyBundle
from models.enums import KeyBundleStatus

# The bundle is usable (and revocable) only while it is active; a revoked one
# keeps stats/note/delete exactly like a revoked key does.
_LIVE_STATUSES = frozenset({KeyBundleStatus.ACTIVE})


def bundle_list_row(bundle: KeyBundle) -> list[InlineKeyboardButton]:
    """The bundle's row in the «My keys» keyboard: one button that opens its card.

    Singular, and only the title button. The list used to repeat every action
    (config · revoke · note · delete) under each entry — the same ones that
    :func:`bundle_actions_keyboard` already offers one tap away — which cost three
    keyboard rows per bundle and made a page of entries unreadable. Management
    happens on the item's own screen; the list only navigates to it.
    """
    return [
        InlineKeyboardButton(
            text=f"{bundle_title(bundle)} · {bundle_status_text(bundle.status)}",
            callback_data=f"bundle:open:{bundle.id}",
        )
    ]


def bundle_actions_keyboard(bundle: KeyBundle, *, has_vless: bool = False) -> InlineKeyboardMarkup:
    """The bundle actions, in the one order every manageable entity uses:
    config · note · fingerprint · revoke · delete — the same rows, in the same
    places, as :func:`bot.keyboards.keys.key_actions_keyboard`.

    ``has_vless`` says whether the bundle actually holds a VLESS child, since the
    fingerprint is a VLESS setting: a bundle provisioned while the Xray module was
    off has nothing to apply it to, and offering the row there would be a button
    whose only outcome is an error. It defaults to False so a caller that has not
    looked at the children never shows the row on a guess.

    There is no «Статистика» row — the traffic is on the bundle screen itself.
    """
    rows: list[list[InlineKeyboardButton]] = []
    if bundle.status in _LIVE_STATUSES:
        rows.append([InlineKeyboardButton(text=t("btn_config"), callback_data=f"bundle:show:{bundle.id}")])
    rows.append([InlineKeyboardButton(text=t("btn_edit_note_key"), callback_data=f"bundle:note:{bundle.id}")])
    if bundle.status in _LIVE_STATUSES and has_vless:
        rows.append([InlineKeyboardButton(text=t("btn_change_fp"), callback_data=f"bundle:fp:{bundle.id}")])
    if bundle.status in _LIVE_STATUSES:
        rows.append([InlineKeyboardButton(text=t("btn_revoke"), callback_data=f"bundle:revoke:{bundle.id}")])
    rows.append([InlineKeyboardButton(text=t("btn_delete"), callback_data=f"bundle:delete:{bundle.id}")])
    rows.append([InlineKeyboardButton(text=t("btn_to_list"), callback_data="keys:list")])
    return InlineKeyboardMarkup(inline_keyboard=rows)


def bundle_awg_ack_keyboard() -> InlineKeyboardMarkup:
    """The single «Понятно» button under the AmneziaWG notice that opens the wizard.

    Deliberately one button and nothing else: the notice is not a decision, it is
    the one thing a user must have read before ordering a set that will not contain
    the protocol some of them came for. Acknowledging it *is* continuing.
    """
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [InlineKeyboardButton(text=t("btn_understood"), callback_data="keys:create:bundle:ack")]
        ]
    )


def bundle_confirm_keyboard(action: str, bundle_id: int) -> InlineKeyboardMarkup:
    """Confirm/cancel for a destructive bundle action, like the per-key one."""
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [InlineKeyboardButton(text=t("btn_confirm"), callback_data=f"bundle:confirm:{action}:{bundle_id}")],
            [InlineKeyboardButton(text=t("btn_cancel"), callback_data=f"bundle:open:{bundle_id}")],
        ]
    )
